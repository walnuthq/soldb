use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use revm::bytecode::opcode::OpCode;
use revm::context::{ContextTr, JournalTr, TxEnv};
use revm::database::{CacheDB, WrapDatabaseRef};
use revm::database_interface::DBErrorMarker;
use revm::inspector::inspectors::GasInspector;
use revm::interpreter::interpreter_types::{Jumps, LoopControl, MemoryTr};
use revm::interpreter::Interpreter;
use revm::primitives::{hardfork::SpecId, Address, Bytes, TxKind, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::{
    Context, DatabaseRef, ExecuteCommitEvm, InspectEvm, Inspector, MainBuilder, MainContext,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soldb_core::{SoldbError, SoldbResult, TraceStep, TransactionTrace};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcConfig {
    pub url: String,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8545".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpJsonRpcClient {
    endpoint: HttpEndpoint,
    timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceBackend {
    DebugRpc,
    Replay,
}

impl TraceBackend {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DebugRpc => "debug-rpc",
            Self::Replay => "replay",
        }
    }
}

pub trait TransactionTraceBackend {
    fn trace_transaction(&self, tx_hash: &str) -> SoldbResult<TransactionTrace>;
}

pub struct DebugRpcBackend<'a> {
    client: &'a HttpJsonRpcClient,
}

impl<'a> DebugRpcBackend<'a> {
    #[must_use]
    pub fn new(client: &'a HttpJsonRpcClient) -> Self {
        Self { client }
    }
}

impl TransactionTraceBackend for DebugRpcBackend<'_> {
    fn trace_transaction(&self, tx_hash: &str) -> SoldbResult<TransactionTrace> {
        trace_transaction_with_client(self.client, tx_hash)
    }
}

pub struct ReplayBackend<'a> {
    client: &'a HttpJsonRpcClient,
}

impl<'a> ReplayBackend<'a> {
    #[must_use]
    pub fn new(client: &'a HttpJsonRpcClient) -> Self {
        Self { client }
    }
}

impl TransactionTraceBackend for ReplayBackend<'_> {
    fn trace_transaction(&self, tx_hash: &str) -> SoldbResult<TransactionTrace> {
        replay_transaction_with_client(self.client, tx_hash)
    }
}

impl HttpJsonRpcClient {
    pub fn new(url: &str) -> SoldbResult<Self> {
        Ok(Self {
            endpoint: HttpEndpoint::parse(url)?,
            timeout: Duration::from_secs(30),
        })
    }

    pub fn request<T: DeserializeOwned>(&self, method: &str, params: Value) -> SoldbResult<T> {
        let response = self.request_value(method, params)?;
        serde_json::from_value(response)
            .map_err(|error| SoldbError::Message(format!("Invalid response for {method}: {error}")))
    }

    pub fn request_value(&self, method: &str, params: Value) -> SoldbResult<Value> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let body = payload.to_string();
        if self.endpoint.scheme == HttpScheme::Https {
            return self.request_value_with_curl(method, &body);
        }

        self.request_value_with_tcp(method, &body)
    }

    fn request_value_with_tcp(&self, method: &str, body: &str) -> SoldbResult<Value> {
        let mut stream = TcpStream::connect(self.endpoint.socket_addr()).map_err(|error| {
            SoldbError::Message(format!(
                "Failed to connect to {}: {error}",
                self.endpoint.url()
            ))
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| SoldbError::Message(format!("Failed to set read timeout: {error}")))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| {
                SoldbError::Message(format!("Failed to set write timeout: {error}"))
            })?;

        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.endpoint.path,
            self.endpoint.host_header(),
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| SoldbError::Message(format!("Failed to send RPC request: {error}")))?;

        let mut response = String::new();
        stream.read_to_string(&mut response).map_err(|error| {
            SoldbError::Message(format!("Failed to read RPC response: {error}"))
        })?;
        parse_http_json_response(method, &response)
    }

    fn request_value_with_curl(&self, method: &str, body: &str) -> SoldbResult<Value> {
        let output = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                &self.timeout.as_secs().to_string(),
                "--header",
                "Content-Type: application/json",
                "--data",
                body,
                &self.endpoint.url(),
            ])
            .output()
            .map_err(|error| {
                SoldbError::Message(format!(
                    "Failed to start curl for HTTPS RPC {}: {error}",
                    self.endpoint.url()
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SoldbError::Message(format!(
                "HTTPS RPC request {method} failed for {}: {}",
                self.endpoint.url(),
                stderr.trim()
            )));
        }

        let body = String::from_utf8(output.stdout).map_err(|error| {
            SoldbError::Message(format!(
                "Invalid UTF-8 HTTPS RPC response for {method}: {error}"
            ))
        })?;
        parse_json_rpc_body(method, &body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpEndpoint {
    scheme: HttpScheme,
    host: String,
    port: u16,
    path: String,
}

impl HttpEndpoint {
    fn parse(url: &str) -> SoldbResult<Self> {
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
            (HttpScheme::Http, rest)
        } else if let Some(rest) = url.strip_prefix("https://") {
            (HttpScheme::Https, rest)
        } else {
            return Err(SoldbError::Message(format!(
                "Only http:// and https:// RPC URLs are supported by the Rust client: {url}"
            )));
        };

        let (authority, path) = rest
            .split_once('/')
            .map_or((rest, "/".to_owned()), |(authority, path)| {
                (authority, format!("/{path}"))
            });
        if authority.is_empty() {
            return Err(SoldbError::Message(format!("Invalid RPC URL: {url}")));
        }

        let (host, port) = authority.rsplit_once(':').map_or(
            (authority.to_owned(), scheme.default_port()),
            |(host, port)| {
                let parsed_port = port
                    .parse::<u16>()
                    .unwrap_or_else(|_| scheme.default_port());
                (host.to_owned(), parsed_port)
            },
        );

        if host.is_empty() {
            return Err(SoldbError::Message(format!("Invalid RPC URL: {url}")));
        }

        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.clone()
        } else {
            self.socket_addr()
        }
    }

    fn url(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.host_header(),
            self.path
        )
    }
}

fn parse_http_json_response(method: &str, response: &str) -> SoldbResult<Value> {
    let (headers, body) = response.split_once("\r\n\r\n").ok_or_else(|| {
        SoldbError::Message(format!(
            "Malformed HTTP response for {method}: missing body"
        ))
    })?;
    let status_line = headers.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(SoldbError::Message(format!(
            "RPC request {method} failed: {status_line}"
        )));
    }

    parse_json_rpc_body(method, body)
}

fn parse_json_rpc_body(method: &str, body: &str) -> SoldbResult<Value> {
    let value = serde_json::from_str::<Value>(body.trim()).map_err(|error| {
        SoldbError::Message(format!("Invalid JSON response for {method}: {error}"))
    })?;
    if let Some(error) = value.get("error") {
        return Err(SoldbError::Message(format!(
            "RPC method {method} returned error: {error}"
        )));
    }

    value.get("result").cloned().ok_or_else(|| {
        SoldbError::Message(format!("RPC response for {method} did not contain result"))
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructLog {
    pub pc: u64,
    pub op: String,
    pub gas: u64,
    #[serde(rename = "gasCost", default)]
    pub gas_cost: u64,
    pub depth: u64,
    #[serde(default)]
    pub stack: Vec<String>,
    #[serde(default)]
    pub memory: Vec<String>,
    #[serde(default)]
    pub storage: BTreeMap<String, String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl StructLog {
    #[must_use]
    pub fn into_trace_step(self) -> TraceStep {
        TraceStep {
            pc: self.pc,
            op: self.op,
            gas: self.gas,
            gas_cost: self.gas_cost,
            depth: self.depth,
            stack: self.stack,
            memory: Some(self.memory.join("")),
            storage: Some(self.storage),
            error: self.error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugTraceResult {
    #[serde(rename = "structLogs", default)]
    pub struct_logs: Vec<StructLog>,
    #[serde(rename = "returnValue", default)]
    pub return_value: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub failed: bool,
    #[serde(default)]
    pub gas: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcTransaction {
    pub hash: String,
    #[serde(rename = "from")]
    pub from_addr: String,
    pub to: Option<String>,
    #[serde(default)]
    pub value: String,
    #[serde(default, alias = "input")]
    pub input_data: String,
    #[serde(default)]
    pub gas: Option<String>,
    #[serde(default, rename = "gasPrice")]
    pub gas_price: Option<String>,
    #[serde(default, rename = "maxFeePerGas")]
    pub max_fee_per_gas: Option<String>,
    #[serde(default, rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default, rename = "blockNumber")]
    pub block_number: Option<String>,
    #[serde(default, rename = "transactionIndex")]
    pub transaction_index: Option<String>,
    #[serde(default, rename = "type")]
    pub transaction_type: Option<String>,
    #[serde(default, rename = "chainId")]
    pub chain_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReceipt {
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    pub status: Option<String>,
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<String>,
    #[serde(default)]
    pub logs: Vec<RpcLog>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcLog {
    pub address: String,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RpcBlockHeader {
    #[serde(default)]
    hash: Option<String>,
    timestamp: String,
    #[serde(rename = "gasLimit")]
    gas_limit: String,
    #[serde(default, rename = "baseFeePerGas")]
    base_fee_per_gas: Option<String>,
    #[serde(default)]
    difficulty: Option<String>,
    #[serde(default, rename = "mixHash")]
    mix_hash: Option<String>,
    #[serde(default, rename = "prevRandao")]
    prevrandao: Option<String>,
    #[serde(default)]
    miner: Option<String>,
    #[serde(default)]
    beneficiary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RpcBlockWithTransactions {
    #[serde(flatten)]
    header: RpcBlockHeader,
    #[serde(default)]
    transactions: Vec<RpcTransaction>,
}

impl DebugTraceResult {
    #[must_use]
    pub fn steps(&self) -> Vec<TraceStep> {
        self.struct_logs
            .iter()
            .cloned()
            .map(StructLog::into_trace_step)
            .collect()
    }

    #[must_use]
    pub fn failure_message(&self) -> Option<String> {
        if let Some(error) = &self.error {
            return Some(error.clone());
        }

        if self.failed {
            return decode_revert_reason(&self.return_value)
                .or_else(|| {
                    (!self.return_value.is_empty()).then(|| {
                        let data = self.return_value.trim_start_matches("0x");
                        format!("Reverted with data: 0x{data}")
                    })
                })
                .or_else(|| Some("Execution reverted".to_owned()));
        }

        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEnvelope {
    pub tx_hash: Option<String>,
    pub from_addr: String,
    pub to_addr: Option<String>,
    pub value: String,
    pub input_data: String,
    pub gas_used: u64,
    pub success: bool,
    pub contract_address: Option<String>,
    pub debug_trace_available: bool,
    pub debug_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulateCallRequest {
    pub from_addr: String,
    pub to_addr: String,
    pub calldata: String,
    pub value: String,
    pub block: Option<u64>,
    pub tx_index: Option<u64>,
}

pub fn build_transaction_trace(
    envelope: TraceEnvelope,
    debug_result: &DebugTraceResult,
) -> TransactionTrace {
    let failure = debug_result.failure_message();
    let success = envelope.success && failure.is_none();
    let error = failure.or(envelope.debug_error.clone());

    TransactionTrace {
        tx_hash: envelope.tx_hash,
        from_addr: envelope.from_addr,
        to_addr: envelope.to_addr,
        value: envelope.value,
        input_data: envelope.input_data,
        gas_used: envelope.gas_used,
        output: normalize_hex_output(&debug_result.return_value),
        success,
        error,
        debug_trace_available: envelope.debug_trace_available,
        contract_address: envelope.contract_address,
        steps: debug_result.steps(),
    }
}

pub fn trace_transaction(rpc_url: &str, tx_hash: &str) -> SoldbResult<TransactionTrace> {
    let client = HttpJsonRpcClient::new(rpc_url)?;
    trace_transaction_with_client_and_backend(&client, tx_hash, TraceBackend::DebugRpc)
}

pub fn trace_transaction_with_backend(
    rpc_url: &str,
    tx_hash: &str,
    backend: TraceBackend,
) -> SoldbResult<TransactionTrace> {
    let client = HttpJsonRpcClient::new(rpc_url)?;
    trace_transaction_with_client_and_backend(&client, tx_hash, backend)
}

pub fn trace_transaction_with_client_and_backend(
    client: &HttpJsonRpcClient,
    tx_hash: &str,
    backend: TraceBackend,
) -> SoldbResult<TransactionTrace> {
    match backend {
        TraceBackend::DebugRpc => DebugRpcBackend::new(client).trace_transaction(tx_hash),
        TraceBackend::Replay => ReplayBackend::new(client).trace_transaction(tx_hash),
    }
}

pub fn simulate_call(
    rpc_url: &str,
    request: &SimulateCallRequest,
) -> SoldbResult<TransactionTrace> {
    let client = HttpJsonRpcClient::new(rpc_url)?;
    simulate_call_with_client(&client, request)
}

pub fn transaction_logs(rpc_url: &str, tx_hash: &str) -> SoldbResult<Vec<RpcLog>> {
    let client = HttpJsonRpcClient::new(rpc_url)?;
    transaction_logs_with_client(&client, tx_hash)
}

pub fn trace_transaction_with_client(
    client: &HttpJsonRpcClient,
    tx_hash: &str,
) -> SoldbResult<TransactionTrace> {
    let tx = client
        .request::<Option<RpcTransaction>>("eth_getTransactionByHash", json!([tx_hash]))?
        .ok_or_else(|| SoldbError::Message(format!("Transaction not found: {tx_hash}")))?;

    let receipt = client
        .request::<Option<RpcReceipt>>("eth_getTransactionReceipt", json!([tx_hash]))?
        .ok_or_else(|| SoldbError::Message(format!("Transaction receipt not found: {tx_hash}")))?;

    let debug_result = client.request::<DebugTraceResult>(
        "debug_traceTransaction",
        json!([
            tx_hash,
            {
                "disableStorage": false,
                "disableMemory": false,
                "enableMemory": true,
            }
        ]),
    )?;

    let envelope = TraceEnvelope {
        tx_hash: Some(tx.hash),
        from_addr: tx.from_addr,
        to_addr: tx.to,
        value: tx.value,
        input_data: normalize_hex_output(&tx.input_data),
        gas_used: parse_quantity(&receipt.gas_used)?,
        success: receipt.status.as_deref().is_none_or(quantity_is_one),
        contract_address: receipt.contract_address,
        debug_trace_available: true,
        debug_error: None,
    };
    Ok(build_transaction_trace(envelope, &debug_result))
}

pub fn transaction_logs_with_client(
    client: &HttpJsonRpcClient,
    tx_hash: &str,
) -> SoldbResult<Vec<RpcLog>> {
    let receipt = client
        .request::<Option<RpcReceipt>>("eth_getTransactionReceipt", json!([tx_hash]))?
        .ok_or_else(|| SoldbError::Message(format!("Transaction receipt not found: {tx_hash}")))?;
    Ok(receipt.logs)
}

pub fn simulate_call_with_client(
    client: &HttpJsonRpcClient,
    request: &SimulateCallRequest,
) -> SoldbResult<TransactionTrace> {
    let mut trace_config = json!({
        "disableStorage": false,
        "disableMemory": false,
        "enableMemory": true,
    });
    if let Some(tx_index) = request.tx_index {
        trace_config["txIndex"] = Value::String(format_quantity(tx_index));
    }

    let call_object = json!({
        "from": request.from_addr,
        "to": request.to_addr,
        "data": normalize_hex_output(&request.calldata),
        "value": parse_value_quantity(&request.value)?,
    });
    let block = request.block.map_or_else(
        || Value::String("latest".to_owned()),
        |block| Value::String(format_quantity(block)),
    );
    let debug_result = client.request::<DebugTraceResult>(
        "debug_traceCall",
        json!([call_object, block, trace_config]),
    )?;

    let failure = debug_result.failure_message();
    Ok(TransactionTrace {
        tx_hash: None,
        from_addr: request.from_addr.clone(),
        to_addr: Some(request.to_addr.clone()),
        value: parse_value_quantity(&request.value)?,
        input_data: normalize_hex_output(&request.calldata),
        gas_used: debug_result.gas.unwrap_or(0),
        output: normalize_hex_output(&debug_result.return_value),
        success: failure.is_none(),
        error: failure,
        debug_trace_available: true,
        contract_address: None,
        steps: debug_result.steps(),
    })
}

fn replay_transaction_with_client(
    client: &HttpJsonRpcClient,
    tx_hash: &str,
) -> SoldbResult<TransactionTrace> {
    let tx = client
        .request::<Option<RpcTransaction>>("eth_getTransactionByHash", json!([tx_hash]))?
        .ok_or_else(|| SoldbError::Message(format!("Transaction not found: {tx_hash}")))?;

    let receipt = client
        .request::<Option<RpcReceipt>>("eth_getTransactionReceipt", json!([tx_hash]))?
        .ok_or_else(|| SoldbError::Message(format!("Transaction receipt not found: {tx_hash}")))?;

    let debug_result = replay_debug_trace(client, &tx)?;
    let envelope = TraceEnvelope {
        tx_hash: Some(tx.hash),
        from_addr: tx.from_addr,
        to_addr: tx.to,
        value: tx.value,
        input_data: normalize_hex_output(&tx.input_data),
        gas_used: parse_quantity(&receipt.gas_used)?,
        success: receipt.status.as_deref().is_none_or(quantity_is_one),
        contract_address: receipt.contract_address,
        debug_trace_available: true,
        debug_error: None,
    };
    Ok(build_transaction_trace(envelope, &debug_result))
}

fn replay_debug_trace(
    client: &HttpJsonRpcClient,
    tx: &RpcTransaction,
) -> SoldbResult<DebugTraceResult> {
    let block_number = tx
        .block_number
        .as_deref()
        .ok_or_else(|| {
            SoldbError::Message("Replay backend requires a mined transaction".to_owned())
        })
        .and_then(parse_quantity)?;
    if block_number == 0 {
        return Err(SoldbError::Message(
            "Replay backend cannot use parent state for block 0".to_owned(),
        ));
    }

    let target_index = tx
        .transaction_index
        .as_deref()
        .map(parse_quantity)
        .transpose()?
        .unwrap_or(0) as usize;

    let block_tag = format_quantity(block_number);
    let block = client
        .request::<Option<RpcBlockWithTransactions>>(
            "eth_getBlockByNumber",
            json!([block_tag, true]),
        )?
        .ok_or_else(|| SoldbError::Message(format!("Block {block_number} not found")))?;
    let target_index = replay_target_index(&block.transactions, target_index, &tx.hash)?;
    let parent_block_tag = format_quantity(block_number - 1);
    let chain_id = client
        .request::<String>("eth_chainId", json!([]))
        .ok()
        .as_deref()
        .map(parse_quantity)
        .transpose()?
        .or_else(|| {
            tx.chain_id
                .as_deref()
                .map(parse_quantity)
                .transpose()
                .ok()
                .flatten()
        })
        .unwrap_or(1);

    let state_db = RpcStateDb {
        client: client.clone(),
        block_tag: parent_block_tag,
    };
    let cache_db = CacheDB::new(WrapDatabaseRef(state_db));
    let mut context = Context::mainnet()
        .with_db(cache_db)
        .modify_block_chained(|block_env| {
            block_env.number = U256::from(block_number);
            block_env.timestamp = U256::from(parse_quantity(&block.header.timestamp).unwrap_or(0));
            block_env.gas_limit = parse_quantity(&block.header.gas_limit).unwrap_or(u64::MAX);
            block_env.basefee = block
                .header
                .base_fee_per_gas
                .as_deref()
                .map(parse_quantity)
                .transpose()
                .unwrap_or(None)
                .unwrap_or_default();
            block_env.difficulty = block
                .header
                .difficulty
                .as_deref()
                .map(parse_u256_quantity)
                .transpose()
                .unwrap_or(None)
                .unwrap_or_default();
            block_env.prevrandao = block
                .header
                .prevrandao
                .as_deref()
                .or(block.header.mix_hash.as_deref())
                .map(parse_b256)
                .transpose()
                .unwrap_or(None);
            block_env.beneficiary = block
                .header
                .beneficiary
                .as_deref()
                .or(block.header.miner.as_deref())
                .map(parse_address)
                .transpose()
                .unwrap_or(None)
                .unwrap_or(Address::ZERO);
        })
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.spec = SpecId::PRAGUE;
            cfg.disable_eip3607 = true;
            cfg.disable_block_gas_limit = true;
            cfg.disable_base_fee = true;
        });

    if target_index > 0 {
        let mut evm = context.build_mainnet();
        for (index, prior_tx) in block.transactions.iter().take(target_index).enumerate() {
            let tx_env = tx_env_from_rpc_transaction(prior_tx, chain_id)?;
            evm.transact_commit(tx_env).map_err(|error| {
                SoldbError::Message(format!(
                    "Replay backend failed while replaying prior block transaction {index} ({}): {error:?}",
                    prior_tx.hash
                ))
            })?;
        }
        context = evm.ctx;
    }

    let tx_env = tx_env_from_rpc_transaction(tx, chain_id)?;
    let mut inspector = ReplayStepInspector::default();
    let mut evm = context.build_mainnet_with_inspector(&mut inspector);
    let result = evm.inspect_one_tx(tx_env).map_err(|error| {
        SoldbError::Message(format!("Replay backend execution failed: {error:?}"))
    })?;

    let return_value = result
        .output()
        .map_or_else(String::new, |output| bytes_to_hex(output.as_ref()));
    let error = match &result {
        revm::context::result::ExecutionResult::Success { .. } => None,
        revm::context::result::ExecutionResult::Revert { output, .. } => {
            let encoded = bytes_to_hex(output.as_ref());
            decode_revert_reason(&encoded)
                .or_else(|| Some(format!("Reverted with data: 0x{encoded}")))
        }
        revm::context::result::ExecutionResult::Halt { reason, .. } => Some(format!("{reason:?}")),
    };

    Ok(DebugTraceResult {
        struct_logs: inspector.into_struct_logs(),
        return_value,
        error,
        failed: !result.is_success(),
        gas: Some(result.gas_used()),
    })
}

fn replay_target_index(
    transactions: &[RpcTransaction],
    expected_index: usize,
    tx_hash: &str,
) -> SoldbResult<usize> {
    if transactions.is_empty() {
        return Err(SoldbError::Message(
            "Replay backend requires eth_getBlockByNumber with full transaction objects".to_owned(),
        ));
    }

    if transactions
        .get(expected_index)
        .is_some_and(|tx| tx.hash.eq_ignore_ascii_case(tx_hash))
    {
        return Ok(expected_index);
    }

    transactions
        .iter()
        .position(|tx| tx.hash.eq_ignore_ascii_case(tx_hash))
        .ok_or_else(|| {
            SoldbError::Message(format!(
                "Replay backend could not find transaction {tx_hash} in its block"
            ))
        })
}

#[derive(Debug, Clone)]
struct RpcStateDb {
    client: HttpJsonRpcClient,
    block_tag: String,
}

#[derive(Debug, Clone)]
struct ReplayDbError(String);

impl fmt::Display for ReplayDbError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ReplayDbError {}

impl DBErrorMarker for ReplayDbError {}

impl From<SoldbError> for ReplayDbError {
    fn from(error: SoldbError) -> Self {
        Self(error.to_string())
    }
}

impl RpcStateDb {
    fn request_at_block<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, ReplayDbError> {
        self.client
            .request(method, params)
            .map_err(ReplayDbError::from)
    }
}

impl DatabaseRef for RpcStateDb {
    type Error = ReplayDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let address = address.to_string();
        let block = self.block_tag.clone();
        let balance: String =
            self.request_at_block("eth_getBalance", json!([address, block.clone()]))?;
        let nonce: String =
            self.request_at_block("eth_getTransactionCount", json!([address, block.clone()]))?;
        let code: String = self.request_at_block("eth_getCode", json!([address, block]))?;

        let code_bytes = hex_to_bytes(code.trim_start_matches("0x")).ok_or_else(|| {
            ReplayDbError(format!(
                "Invalid bytecode returned for account {address}: {code}"
            ))
        })?;
        let bytecode = Bytecode::new_raw(Bytes::from(code_bytes));
        let code_hash = bytecode.hash_slow();
        Ok(Some(AccountInfo::new(
            parse_u256_quantity(&balance).map_err(ReplayDbError::from)?,
            parse_quantity(&nonce).map_err(ReplayDbError::from)?,
            code_hash,
            bytecode,
        )))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let value: String = self.request_at_block(
            "eth_getStorageAt",
            json!([
                address.to_string(),
                format_u256_quantity(index),
                self.block_tag
            ]),
        )?;
        parse_u256_quantity(&value).map_err(ReplayDbError::from)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let block = self
            .request_at_block::<Option<RpcBlockHeader>>(
                "eth_getBlockByNumber",
                json!([format_quantity(number), false]),
            )?
            .ok_or_else(|| ReplayDbError(format!("Block {number} not found")))?;
        let hash = block
            .hash
            .as_deref()
            .ok_or_else(|| ReplayDbError(format!("Block {number} did not include a hash")))?;
        parse_b256(hash).map_err(ReplayDbError::from)
    }
}

#[derive(Debug, Default)]
struct ReplayStepInspector {
    gas: GasInspector,
    pending: Option<StructLog>,
    struct_logs: Vec<StructLog>,
}

impl ReplayStepInspector {
    fn into_struct_logs(self) -> Vec<StructLog> {
        self.struct_logs
    }
}

impl<CTX: ContextTr> Inspector<CTX> for ReplayStepInspector {
    fn initialize_interp(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        self.gas.initialize_interp(&interp.gas);
    }

    fn step(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        self.gas.step(&interp.gas);
        let opcode = interp.bytecode.opcode();
        let op = OpCode::new(opcode).map_or_else(
            || format!("UNKNOWN(0x{opcode:02x})"),
            |op| op.as_str().to_owned(),
        );
        let stack = interp
            .stack
            .data()
            .iter()
            .map(|value| format_u256_quantity(*value))
            .collect();
        let memory = bytes_to_hex(interp.memory.slice(0..interp.memory.size()).as_ref());
        self.pending = Some(StructLog {
            pc: interp.bytecode.pc() as u64,
            op,
            gas: interp.gas.remaining(),
            gas_cost: 0,
            depth: context.journal_mut().depth() as u64,
            stack,
            memory: memory
                .is_empty()
                .then(Vec::new)
                .unwrap_or_else(|| vec![memory]),
            storage: BTreeMap::new(),
            error: None,
        });
    }

    fn step_end(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        self.gas.step_end(&interp.gas);
        if let Some(mut log) = self.pending.take() {
            log.gas_cost = self.gas.last_gas_cost();
            log.error = interp
                .bytecode
                .action()
                .as_ref()
                .and_then(|action| action.instruction_result())
                .map(|result| format!("{result:?}"));
            self.struct_logs.push(log);
        }
    }
}

fn tx_env_from_rpc_transaction(tx: &RpcTransaction, chain_id: u64) -> SoldbResult<TxEnv> {
    let gas_limit = tx
        .gas
        .as_deref()
        .map(parse_quantity)
        .transpose()?
        .unwrap_or(30_000_000);
    let gas_price = tx
        .max_fee_per_gas
        .as_deref()
        .or(tx.gas_price.as_deref())
        .map(parse_u128_quantity)
        .transpose()?
        .unwrap_or_default();
    let gas_priority_fee = tx
        .max_priority_fee_per_gas
        .as_deref()
        .map(parse_u128_quantity)
        .transpose()?;
    let nonce = tx
        .nonce
        .as_deref()
        .map(parse_quantity)
        .transpose()?
        .unwrap_or_default();
    let mut builder = TxEnv::builder()
        .caller(parse_address(&tx.from_addr)?)
        .gas_limit(gas_limit)
        .gas_price(gas_price)
        .value(parse_u256_quantity(&tx.value)?)
        .data(Bytes::from(
            hex_to_bytes(tx.input_data.trim_start_matches("0x")).ok_or_else(|| {
                SoldbError::Message(format!("Invalid transaction input: {}", tx.input_data))
            })?,
        ))
        .nonce(nonce)
        .chain_id(Some(chain_id));

    if let Some(priority_fee) = gas_priority_fee {
        builder = builder.gas_priority_fee(Some(priority_fee));
    }

    builder = match tx.to.as_deref() {
        Some(to) => builder.kind(TxKind::Call(parse_address(to)?)),
        None => builder.create(),
    };

    if let Some(tx_type) = tx.transaction_type.as_deref() {
        builder = builder.tx_type(Some(parse_quantity(tx_type)? as u8));
    }

    builder.build().map_err(|error| {
        SoldbError::Message(format!("Failed to build replay transaction: {error}"))
    })
}

#[must_use]
pub fn decode_revert_reason(return_value: &str) -> Option<String> {
    let data = return_value.trim_start_matches("0x");
    if !data.starts_with("08c379a0") || data.len() < 8 + 64 + 64 {
        return None;
    }

    let payload = &data[8..];
    let length_hex = payload.get(64..128)?;
    let length = usize::from_str_radix(length_hex, 16).ok()?;
    let string_start = 128;
    let string_end = string_start + length.checked_mul(2)?;
    let string_hex = payload.get(string_start..string_end)?;
    let bytes = hex_to_bytes(string_hex)?;
    String::from_utf8(bytes).ok()
}

fn normalize_hex_output(value: &str) -> String {
    if value.is_empty() {
        "0x".to_owned()
    } else if value.starts_with("0x") {
        value.to_owned()
    } else {
        format!("0x{value}")
    }
}

fn parse_quantity(value: &str) -> SoldbResult<u64> {
    let hex = value.trim_start_matches("0x");
    u64::from_str_radix(hex, 16)
        .map_err(|error| SoldbError::Message(format!("Invalid RPC quantity '{value}': {error}")))
}

fn parse_u128_quantity(value: &str) -> SoldbResult<u128> {
    let hex = value.trim_start_matches("0x");
    u128::from_str_radix(hex, 16)
        .map_err(|error| SoldbError::Message(format!("Invalid RPC quantity '{value}': {error}")))
}

fn parse_u256_quantity(value: &str) -> SoldbResult<U256> {
    let hex = value.trim_start_matches("0x");
    if hex.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(hex, 16)
        .map_err(|error| SoldbError::Message(format!("Invalid RPC quantity '{value}': {error}")))
}

fn quantity_is_one(value: &str) -> bool {
    parse_quantity(value).is_ok_and(|quantity| quantity == 1)
}

fn parse_value_quantity(value: &str) -> SoldbResult<String> {
    if value.starts_with("0x") {
        parse_quantity(value)?;
        Ok(value.to_owned())
    } else {
        let parsed = value.parse::<u64>().map_err(|error| {
            SoldbError::Message(format!("Invalid call value '{value}': {error}"))
        })?;
        Ok(format_quantity(parsed))
    }
}

fn format_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

fn format_u256_quantity(value: U256) -> String {
    if value == U256::ZERO {
        return "0x0".to_owned();
    }
    let bytes = value.to_be_bytes::<32>();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    format!("0x{}", bytes_to_hex(&bytes[first_non_zero..]))
}

fn parse_address(value: &str) -> SoldbResult<Address> {
    let bytes = hex_to_bytes(value.trim_start_matches("0x"))
        .ok_or_else(|| SoldbError::Message(format!("Invalid address '{value}'")))?;
    if bytes.len() != 20 {
        return Err(SoldbError::Message(format!(
            "Invalid address '{value}': expected 20 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(Address::from_slice(&bytes))
}

fn parse_b256(value: &str) -> SoldbResult<B256> {
    let bytes = hex_to_bytes(value.trim_start_matches("0x"))
        .ok_or_else(|| SoldbError::Message(format!("Invalid bytes32 value '{value}'")))?;
    if bytes.len() != 32 {
        return Err(SoldbError::Message(format!(
            "Invalid bytes32 value '{value}': expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).ok())
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use super::{
        build_transaction_trace, decode_revert_reason, replay_target_index, simulate_call,
        trace_transaction, trace_transaction_with_backend, transaction_logs, DebugTraceResult,
        HttpEndpoint, HttpScheme, RpcTransaction, SimulateCallRequest, StructLog, TraceBackend,
        TraceEnvelope,
    };
    use serde_json::json;

    #[test]
    fn parses_struct_logs_into_trace_steps() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "2a",
            "structLogs": [
                {
                    "pc": 0,
                    "op": "PUSH1",
                    "gas": 100,
                    "gasCost": 3,
                    "depth": 0,
                    "stack": ["0x01"],
                    "memory": ["aa", "bb"],
                    "storage": {"0x00": "0x2a"}
                },
                {"pc": 2, "op": "STOP", "gas": 97, "depth": 0}
            ]
        }))
        .expect("debug trace");

        let steps = result.steps();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].memory.as_deref(), Some("aabb"));
        assert_eq!(steps[0].storage.as_ref().expect("storage")["0x00"], "0x2a");
        assert_eq!(steps[1].gas_cost, 0);
    }

    #[test]
    fn decodes_standard_error_string_reverts() {
        let reason = "boom";
        let encoded_reason = format!("{:0<64}", bytes_to_hex(reason.as_bytes()));
        let return_value = format!(
            "0x08c379a0{offset:064x}{length:064x}{encoded_reason}",
            offset = 32,
            length = reason.len(),
        );

        assert_eq!(decode_revert_reason(&return_value).as_deref(), Some("boom"));
    }

    #[test]
    fn builds_transaction_trace_from_debug_result() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "",
            "failed": false,
            "structLogs": [{"pc": 0, "op": "STOP", "gas": 1, "depth": 0}]
        }))
        .expect("debug trace");
        let envelope = TraceEnvelope {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 21_000,
            success: true,
            contract_address: None,
            debug_trace_available: true,
            debug_error: None,
        };

        let trace = build_transaction_trace(envelope, &result);
        assert!(trace.success);
        assert_eq!(trace.output, "0x");
        assert_eq!(trace.steps[0].op, "STOP");
    }

    #[test]
    fn fallback_debug_errors_do_not_override_receipt_success() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "",
            "structLogs": []
        }))
        .expect("debug trace");
        let envelope = TraceEnvelope {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 21_000,
            success: true,
            contract_address: None,
            debug_trace_available: false,
            debug_error: Some("debug_traceTransaction not available".to_owned()),
        };

        let trace = build_transaction_trace(envelope, &result);
        assert!(trace.success);
        assert_eq!(
            trace.error.as_deref(),
            Some("debug_traceTransaction not available")
        );
    }

    #[test]
    fn failed_debug_result_prefers_explicit_error() {
        let result = DebugTraceResult {
            struct_logs: Vec::<StructLog>::new(),
            return_value: String::new(),
            error: Some("bad opcode".to_owned()),
            failed: true,
            gas: None,
        };

        assert_eq!(result.failure_message().as_deref(), Some("bad opcode"));
    }

    #[test]
    fn failed_debug_result_reports_raw_revert_data() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "deadbeef",
            "failed": true
        }))
        .expect("debug trace");

        assert_eq!(
            result.failure_message().as_deref(),
            Some("Reverted with data: 0xdeadbeef")
        );
    }

    #[test]
    fn parses_http_and_https_rpc_endpoints() {
        let http = HttpEndpoint::parse("http://localhost:8545").expect("http endpoint");
        assert_eq!(http.scheme, HttpScheme::Http);
        assert_eq!(http.host_header(), "localhost:8545");
        assert_eq!(http.url(), "http://localhost:8545/");

        let https = HttpEndpoint::parse("https://rpc.example.com/v1/key").expect("https endpoint");
        assert_eq!(https.scheme, HttpScheme::Https);
        assert_eq!(https.host_header(), "rpc.example.com");
        assert_eq!(https.socket_addr(), "rpc.example.com:443");
        assert_eq!(https.url(), "https://rpc.example.com/v1/key");

        let https_with_port =
            HttpEndpoint::parse("https://127.0.0.1:9443/rpc").expect("https port endpoint");
        assert_eq!(https_with_port.host_header(), "127.0.0.1:9443");
        assert_eq!(https_with_port.url(), "https://127.0.0.1:9443/rpc");
    }

    #[test]
    fn parses_direct_json_rpc_bodies_for_https_transport() {
        let result = super::parse_json_rpc_body(
            "web3_clientVersion",
            r#"{"jsonrpc":"2.0","id":1,"result":"anvil"}"#,
        )
        .expect("result");
        assert_eq!(result, json!("anvil"));

        let error = super::parse_json_rpc_body(
            "web3_clientVersion",
            r#"{"jsonrpc":"2.0","id":1,"error":{"message":"boom"}}"#,
        )
        .expect_err("rpc error");
        assert!(error.to_string().contains("returned error"));
    }

    #[test]
    fn traces_transaction_through_http_json_rpc_client() {
        let rpc_url = start_trace_server(3);
        let trace = trace_transaction(&rpc_url, "0xabc").expect("trace");

        assert_eq!(trace.tx_hash.as_deref(), Some("0xabc"));
        assert_eq!(trace.from_addr, "0x1");
        assert_eq!(trace.to_addr.as_deref(), Some("0x2"));
        assert_eq!(trace.gas_used, 21_000);
        assert!(trace.success);
        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.steps[0].op, "PUSH1");
        assert_eq!(trace.steps[1].memory.as_deref(), Some("aabb"));
    }

    #[test]
    fn trace_backend_names_are_stable() {
        assert_eq!(TraceBackend::DebugRpc.as_str(), "debug-rpc");
        assert_eq!(TraceBackend::Replay.as_str(), "replay");
    }

    #[test]
    fn traces_transaction_through_explicit_debug_rpc_backend() {
        let rpc_url = start_trace_server(3);
        let trace = trace_transaction_with_backend(&rpc_url, "0xabc", TraceBackend::DebugRpc)
            .expect("trace");

        assert_eq!(trace.tx_hash.as_deref(), Some("0xabc"));
        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.steps[0].op, "PUSH1");
    }

    #[test]
    fn replay_backend_requires_mined_transaction() {
        let rpc_url = start_trace_server(2);
        let error = trace_transaction_with_backend(&rpc_url, "0xabc", TraceBackend::Replay)
            .expect_err("unmined mock transaction should fail replay");

        assert!(error
            .to_string()
            .contains("Replay backend requires a mined transaction"));
    }

    #[test]
    fn replay_target_index_uses_rpc_index_or_hash_fallback() {
        let transactions = vec![mock_rpc_transaction("0xaaa"), mock_rpc_transaction("0xbbb")];

        assert_eq!(
            replay_target_index(&transactions, 1, "0xbbb").expect("target by index"),
            1
        );
        assert_eq!(
            replay_target_index(&transactions, 9, "0xaaa").expect("target by hash"),
            0
        );
        assert!(replay_target_index(&transactions, 0, "0xccc")
            .expect_err("missing tx")
            .to_string()
            .contains("could not find transaction"));
    }

    #[test]
    fn simulates_call_through_http_json_rpc_client() {
        let rpc_url = start_trace_server(1);
        let trace = simulate_call(
            &rpc_url,
            &SimulateCallRequest {
                from_addr: "0x1".to_owned(),
                to_addr: "0x2".to_owned(),
                calldata: "0x1234".to_owned(),
                value: "0".to_owned(),
                block: Some(10),
                tx_index: Some(1),
            },
        )
        .expect("simulate");

        assert_eq!(trace.tx_hash, None);
        assert_eq!(trace.from_addr, "0x1");
        assert_eq!(trace.to_addr.as_deref(), Some("0x2"));
        assert_eq!(trace.value, "0x0");
        assert_eq!(trace.input_data, "0x1234");
        assert_eq!(trace.gas_used, 42_000);
        assert!(trace.success);
        assert_eq!(trace.steps[1].op, "CALLDATASIZE");
    }

    #[test]
    fn fetches_transaction_logs_from_receipt() {
        let rpc_url = start_trace_server(1);
        let logs = transaction_logs(&rpc_url, "0xabc").expect("logs");

        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0].address, "0x2");
        assert_eq!(
            logs[0].topics[0],
            "0x3cf8b50771c17d723f2cb711ca7dadde485b222e13c84ba0730a14093fad6d5c"
        );
        assert!(logs[0].data.ends_with("04"));
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn start_trace_server(request_count: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc server");
        let address = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            for _ in 0..request_count {
                let (stream, _) = listener.accept().expect("accept rpc request");
                respond_to_rpc_request(stream);
            }
        });
        format!("http://{address}")
    }

    fn respond_to_rpc_request(mut stream: TcpStream) {
        let request = read_http_request(&mut stream);
        let response = if request.contains("\"eth_getTransactionByHash\"") {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "hash": "0xabc",
                    "from": "0x1",
                    "to": "0x2",
                    "value": "0x0",
                    "input": "0x1234"
                }
            })
        } else if request.contains("\"eth_getTransactionReceipt\"") {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "gasUsed": "0x5208",
                    "status": "0x1",
                    "contractAddress": null,
                    "logs": [
                        event_log("0x2", "04"),
                        event_log("0x2", "05"),
                        event_log("0x2", "06")
                    ]
                }
            })
        } else if request.contains("\"debug_traceTransaction\"") {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "returnValue": "",
                    "structLogs": [
                        {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                        {"pc": 2, "op": "MSTORE", "gas": 97, "gasCost": 3, "depth": 0, "memory": ["aa", "bb"]},
                        {"pc": 3, "op": "STOP", "gas": 94, "gasCost": 0, "depth": 0}
                    ]
                }
            })
        } else if request.contains("\"debug_traceCall\"") {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "gas": 42000,
                    "returnValue": "2a",
                    "failed": false,
                    "structLogs": [
                        {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                        {"pc": 1, "op": "CALLDATASIZE", "gas": 97, "gasCost": 2, "depth": 0, "stack": ["0x01"]},
                        {"pc": 2, "op": "STOP", "gas": 95, "gasCost": 0, "depth": 0}
                    ]
                }
            })
        } else {
            json!({"jsonrpc": "2.0", "id": 1, "error": {"message": "unknown method"}})
        };

        let body = response.to_string();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(http_response.as_bytes())
            .expect("write response");
    }

    fn mock_rpc_transaction(hash: &str) -> RpcTransaction {
        RpcTransaction {
            hash: hash.to_owned(),
            from_addr: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_owned(),
            to: Some("0x5fbdb2315678afecb367f032d93f642f64180aa3".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas: Some("0x5208".to_owned()),
            gas_price: Some("0x1".to_owned()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: Some("0x0".to_owned()),
            block_number: Some("0x1".to_owned()),
            transaction_index: Some("0x0".to_owned()),
            transaction_type: Some("0x0".to_owned()),
            chain_id: Some("0x1".to_owned()),
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..read]);

            if let Some(header_end) = find_header_end(&data) {
                let headers = String::from_utf8_lossy(&data[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let body_len = data.len().saturating_sub(header_end + 4);
                if body_len >= content_length {
                    break;
                }
            }
        }
        String::from_utf8(data).expect("utf8 request")
    }

    fn find_header_end(data: &[u8]) -> Option<usize> {
        data.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn event_log(address: &str, data_suffix: &str) -> serde_json::Value {
        json!({
            "address": address,
            "topics": ["0x3cf8b50771c17d723f2cb711ca7dadde485b222e13c84ba0730a14093fad6d5c"],
            "data": format!("0x{}{}", "0".repeat(62), data_suffix),
        })
    }
}
