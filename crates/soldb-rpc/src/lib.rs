use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::rc::Rc;
use std::time::Duration;

use revm::bytecode::opcode::OpCode;
use revm::context::{ContextTr, JournalEntry, JournalTr, TxEnv};
use revm::database::{CacheDB, WrapDatabaseRef};
use revm::database_interface::DBErrorMarker;
use revm::inspector::inspectors::GasInspector;
use revm::inspector::JournalExt;
use revm::interpreter::interpreter_types::{Jumps, LoopControl, MemoryTr};
use revm::interpreter::{
    CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, Interpreter,
};
use revm::primitives::{hardfork::SpecId, Address, Bytes, TxKind, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::{
    Context, DatabaseRef, ExecuteCommitEvm, InspectEvm, Inspector, MainBuilder, MainContext,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soldb_core::{
    AccountChange, ContractCreation, ExecutionCall, ExecutionLog, GasSummary, SoldbError,
    SoldbResult, StepSnapshot, StorageChange, TraceArtifacts, TraceCapabilities, TraceStep,
    TransactionTrace,
};

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
    Auto,
    DebugRpc,
    Replay,
}

impl TraceBackend {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::DebugRpc => "debug-rpc",
            Self::Replay => "replay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTransactionTrace {
    pub trace: TransactionTrace,
    pub backend: TraceBackend,
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
        self.into_trace_step_with_previous_storage(&BTreeMap::new())
    }

    #[must_use]
    pub fn into_trace_step_with_previous_storage(
        self,
        previous_storage: &BTreeMap<String, String>,
    ) -> TraceStep {
        let memory = Some(self.memory.join(""));
        let storage = self.storage.clone();
        let snapshot = StepSnapshot {
            stack: self.stack.clone(),
            memory: memory.clone(),
            storage: storage.clone(),
            storage_diff: if storage.is_empty() {
                BTreeMap::new()
            } else {
                storage_diff(previous_storage, &storage)
            },
        };
        TraceStep {
            pc: self.pc,
            op: self.op,
            gas: self.gas,
            gas_cost: self.gas_cost,
            depth: self.depth,
            stack: self.stack,
            memory,
            storage: Some(self.storage),
            error: self.error,
            snapshot,
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
    #[serde(default)]
    pub artifacts: TraceArtifacts,
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
    transactions: Vec<RpcBlockTransaction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum RpcBlockTransaction {
    Full(Box<RpcTransaction>),
    Hash(String),
}

impl DebugTraceResult {
    #[must_use]
    pub fn steps(&self) -> Vec<TraceStep> {
        let mut previous_storage = BTreeMap::<String, String>::new();
        self.struct_logs
            .iter()
            .cloned()
            .map(|log| {
                let step = log
                    .clone()
                    .into_trace_step_with_previous_storage(&previous_storage);
                previous_storage = log.storage;
                step
            })
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

fn storage_diff(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> BTreeMap<String, StorageChange> {
    let mut diff = BTreeMap::new();
    for key in before.keys().chain(after.keys()) {
        if diff.contains_key(key) {
            continue;
        }
        let before_value = before.get(key).cloned();
        let after_value = after.get(key).cloned();
        if before_value != after_value {
            diff.insert(
                key.clone(),
                StorageChange {
                    before: before_value,
                    after: after_value,
                },
            );
        }
    }
    diff
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
    pub backend: Option<String>,
    pub capabilities: TraceCapabilities,
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
    let output = normalize_hex_output(&debug_result.return_value);
    let mut artifacts = debug_result.artifacts.clone();
    if artifacts.gas.is_none() {
        if let Some(used) = debug_result.gas {
            artifacts.gas = Some(GasSummary {
                used,
                spent: None,
                refunded: None,
                remaining: None,
                limit: None,
            });
        }
    }
    if artifacts.revert_data.is_none() && !success && output != "0x" {
        artifacts.revert_data = Some(output.clone());
    }

    TransactionTrace {
        tx_hash: envelope.tx_hash,
        from_addr: envelope.from_addr,
        to_addr: envelope.to_addr,
        value: envelope.value,
        input_data: envelope.input_data,
        gas_used: envelope.gas_used,
        output,
        success,
        error,
        debug_trace_available: envelope.debug_trace_available,
        contract_address: envelope.contract_address,
        backend: envelope.backend,
        capabilities: envelope.capabilities,
        artifacts,
        steps: debug_result.steps(),
    }
}

pub fn trace_transaction(rpc_url: &str, tx_hash: &str) -> SoldbResult<TransactionTrace> {
    let client = HttpJsonRpcClient::new(rpc_url)?;
    trace_transaction_with_client_and_backend(&client, tx_hash, TraceBackend::Auto)
}

pub fn trace_transaction_with_backend(
    rpc_url: &str,
    tx_hash: &str,
    backend: TraceBackend,
) -> SoldbResult<TransactionTrace> {
    let client = HttpJsonRpcClient::new(rpc_url)?;
    trace_transaction_with_client_and_backend(&client, tx_hash, backend)
}

pub fn trace_transaction_with_resolved_backend(
    rpc_url: &str,
    tx_hash: &str,
    backend: TraceBackend,
) -> SoldbResult<ResolvedTransactionTrace> {
    let client = HttpJsonRpcClient::new(rpc_url)?;
    trace_transaction_with_client_and_resolved_backend(&client, tx_hash, backend)
}

pub fn trace_transaction_with_client_and_backend(
    client: &HttpJsonRpcClient,
    tx_hash: &str,
    backend: TraceBackend,
) -> SoldbResult<TransactionTrace> {
    trace_transaction_with_client_and_resolved_backend(client, tx_hash, backend)
        .map(|resolved| resolved.trace)
}

pub fn trace_transaction_with_client_and_resolved_backend(
    client: &HttpJsonRpcClient,
    tx_hash: &str,
    backend: TraceBackend,
) -> SoldbResult<ResolvedTransactionTrace> {
    resolve_trace_backend(
        backend,
        || DebugRpcBackend::new(client).trace_transaction(tx_hash),
        || ReplayBackend::new(client).trace_transaction(tx_hash),
    )
}

fn resolve_trace_backend(
    backend: TraceBackend,
    debug_trace: impl FnOnce() -> SoldbResult<TransactionTrace>,
    replay_trace: impl FnOnce() -> SoldbResult<TransactionTrace>,
) -> SoldbResult<ResolvedTransactionTrace> {
    match backend {
        TraceBackend::Auto => match debug_trace() {
            Ok(trace) => Ok(ResolvedTransactionTrace {
                trace,
                backend: TraceBackend::DebugRpc,
            }),
            Err(error) if debug_trace_unavailable(&error) => {
                replay_trace().map(|trace| ResolvedTransactionTrace {
                    trace,
                    backend: TraceBackend::Replay,
                })
            }
            Err(error) => Err(error),
        },
        TraceBackend::DebugRpc => debug_trace().map(|trace| ResolvedTransactionTrace {
            trace,
            backend: TraceBackend::DebugRpc,
        }),
        TraceBackend::Replay => replay_trace().map(|trace| ResolvedTransactionTrace {
            trace,
            backend: TraceBackend::Replay,
        }),
    }
}

fn debug_rpc_capabilities(result: &DebugTraceResult) -> TraceCapabilities {
    let has_steps = !result.struct_logs.is_empty();
    let has_storage = result
        .struct_logs
        .iter()
        .any(|step| !step.storage.is_empty());
    let has_storage_diff = result
        .steps()
        .iter()
        .any(|step| !step.snapshot.storage_diff.is_empty());
    let mut notes = Vec::new();
    if has_steps && !has_storage {
        notes.push("debug-rpc node did not return per-step storage".to_owned());
    }

    TraceCapabilities {
        opcode_steps: has_steps,
        stack: has_steps,
        memory: has_steps,
        storage: has_storage,
        storage_diff: has_storage_diff,
        call_trace: false,
        contract_creation: false,
        logs: false,
        revert_data: result.failed && !result.return_value.is_empty(),
        gas_details: result.gas.is_some(),
        account_changes: false,
        notes,
    }
}

fn replay_capabilities() -> TraceCapabilities {
    TraceCapabilities {
        opcode_steps: true,
        stack: true,
        memory: true,
        storage: true,
        storage_diff: true,
        call_trace: true,
        contract_creation: true,
        logs: true,
        revert_data: true,
        gas_details: true,
        account_changes: true,
        notes: Vec::new(),
    }
}

fn debug_trace_unavailable(error: &SoldbError) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("debug_tracetransaction")
        && (message.contains("-32601")
            || message.contains("method not found")
            || message.contains("method does not exist")
            || message.contains("does not exist/is not available")
            || message.contains("not available")
            || message.contains("not supported")
            || message.contains("unsupported"))
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
        backend: Some(TraceBackend::DebugRpc.as_str().to_owned()),
        capabilities: debug_rpc_capabilities(&debug_result),
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
        backend: Some(TraceBackend::DebugRpc.as_str().to_owned()),
        capabilities: debug_rpc_capabilities(&debug_result),
        artifacts: {
            let mut artifacts = debug_result.artifacts.clone();
            if artifacts.gas.is_none() {
                artifacts.gas = Some(GasSummary {
                    used: debug_result.gas.unwrap_or(0),
                    spent: None,
                    refunded: None,
                    remaining: None,
                    limit: None,
                });
            }
            artifacts
        },
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
        backend: Some(TraceBackend::Replay.as_str().to_owned()),
        capabilities: replay_capabilities(),
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
    let parent_block_tag = format_quantity(block_number - 1);
    let chain_id = replay_chain_id(client, tx)?;
    let block = client
        .request::<Option<RpcBlockWithTransactions>>(
            "eth_getBlockByNumber",
            json!([block_tag, true]),
        )
        .map_err(|error| {
            SoldbError::Message(format!(
                "Replay backend preflight failed: could not load block {block_number} with full transactions: {error}",
            ))
        })?
        .ok_or_else(|| SoldbError::Message(format!("Block {block_number} not found")))?;
    let transactions = replay_full_block_transactions(block_number, &block.transactions)?;
    let target_index = replay_target_index(&transactions, target_index, &tx.hash)?;
    let block_timestamp = parse_quantity(&block.header.timestamp).unwrap_or(0);
    let spec = replay_spec_for_chain(chain_id, block_number, block_timestamp);

    let state_provider = RpcReplayStateProvider::new(client.clone(), parent_block_tag);
    replay_preflight_parent_state(&state_provider, tx)?;
    let state_db = RpcStateDb::new(state_provider);
    let cache_db = CacheDB::new(WrapDatabaseRef(state_db));
    let mut context = Context::mainnet()
        .with_db(cache_db)
        .modify_block_chained(|block_env| {
            block_env.number = U256::from(block_number);
            block_env.timestamp = U256::from(block_timestamp);
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
            cfg.set_spec_and_mainnet_gas_params(spec);
            cfg.disable_eip3607 = true;
            cfg.disable_block_gas_limit = true;
            cfg.disable_base_fee = true;
        });

    if target_index > 0 {
        let mut evm = context.build_mainnet();
        for (index, prior_tx) in transactions.iter().take(target_index).enumerate() {
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
    let (struct_logs, mut artifacts) = inspector.into_parts();
    if artifacts.logs.is_empty() {
        artifacts.logs = result
            .logs()
            .iter()
            .enumerate()
            .map(|(index, log)| log_artifact(index, 0, log))
            .collect();
    }
    artifacts.gas = Some(gas_summary_from_result(&result));
    if !result.is_success() && !return_value.is_empty() {
        artifacts.revert_data = Some(bytes_to_prefixed_hex(
            result
                .output()
                .map_or([].as_slice(), |output| output.as_ref()),
        ));
    }

    Ok(DebugTraceResult {
        struct_logs,
        return_value,
        error,
        failed: !result.is_success(),
        gas: Some(result.gas_used()),
        artifacts,
    })
}

fn replay_spec_for_chain(chain_id: u64, block_number: u64, block_timestamp: u64) -> SpecId {
    match chain_id {
        1 => ethereum_mainnet_spec(block_number, block_timestamp),
        11_155_111 => timestamp_scheduled_spec(
            block_number,
            block_timestamp,
            TimestampForks {
                base: SpecId::LONDON,
                merge_block: Some(1_735_371),
                shanghai_time: Some(1_677_557_088),
                cancun_time: Some(1_706_655_072),
                prague_time: Some(1_741_159_776),
                osaka_time: Some(1_760_427_360),
            },
        ),
        17_000 => timestamp_scheduled_spec(
            block_number,
            block_timestamp,
            TimestampForks {
                base: SpecId::MERGE,
                merge_block: Some(0),
                shanghai_time: Some(1_696_000_704),
                cancun_time: Some(1_707_305_664),
                prague_time: Some(1_740_434_112),
                osaka_time: Some(1_759_308_480),
            },
        ),
        560_048 => timestamp_scheduled_spec(
            block_number,
            block_timestamp,
            TimestampForks {
                base: SpecId::MERGE,
                merge_block: Some(0),
                shanghai_time: Some(0),
                cancun_time: Some(0),
                prague_time: Some(1_742_999_832),
                osaka_time: Some(1_761_677_592),
            },
        ),
        1_337 | 31_337 => SpecId::PRAGUE,
        _ => SpecId::PRAGUE,
    }
}

fn ethereum_mainnet_spec(block_number: u64, block_timestamp: u64) -> SpecId {
    let pre_merge = [
        (15_537_394, SpecId::MERGE),
        (15_050_000, SpecId::GRAY_GLACIER),
        (13_773_000, SpecId::ARROW_GLACIER),
        (12_965_000, SpecId::LONDON),
        (12_244_000, SpecId::BERLIN),
        (9_200_000, SpecId::MUIR_GLACIER),
        (9_069_000, SpecId::ISTANBUL),
        (7_280_000, SpecId::PETERSBURG),
        (4_370_000, SpecId::BYZANTIUM),
        (2_675_000, SpecId::SPURIOUS_DRAGON),
        (2_463_000, SpecId::TANGERINE),
        (1_920_000, SpecId::DAO_FORK),
        (1_150_000, SpecId::HOMESTEAD),
        (200_000, SpecId::FRONTIER_THAWING),
    ];

    if block_number < 15_537_394 {
        return pre_merge
            .iter()
            .find_map(|(fork_block, spec)| (block_number >= *fork_block).then_some(*spec))
            .unwrap_or(SpecId::FRONTIER);
    }

    timestamp_scheduled_spec(
        block_number,
        block_timestamp,
        TimestampForks {
            base: SpecId::MERGE,
            merge_block: Some(15_537_394),
            shanghai_time: Some(1_681_338_455),
            cancun_time: Some(1_710_338_135),
            prague_time: Some(1_746_612_311),
            osaka_time: Some(1_764_798_551),
        },
    )
}

#[derive(Debug, Clone, Copy)]
struct TimestampForks {
    base: SpecId,
    merge_block: Option<u64>,
    shanghai_time: Option<u64>,
    cancun_time: Option<u64>,
    prague_time: Option<u64>,
    osaka_time: Option<u64>,
}

fn timestamp_scheduled_spec(
    block_number: u64,
    block_timestamp: u64,
    forks: TimestampForks,
) -> SpecId {
    if forks
        .osaka_time
        .is_some_and(|fork_time| block_timestamp >= fork_time)
    {
        return SpecId::OSAKA;
    }
    if forks
        .prague_time
        .is_some_and(|fork_time| block_timestamp >= fork_time)
    {
        return SpecId::PRAGUE;
    }
    if forks
        .cancun_time
        .is_some_and(|fork_time| block_timestamp >= fork_time)
    {
        return SpecId::CANCUN;
    }
    if forks
        .shanghai_time
        .is_some_and(|fork_time| block_timestamp >= fork_time)
    {
        return SpecId::SHANGHAI;
    }
    if forks
        .merge_block
        .is_some_and(|fork_block| block_number >= fork_block)
    {
        return SpecId::MERGE;
    }
    forks.base
}

fn replay_chain_id(client: &HttpJsonRpcClient, tx: &RpcTransaction) -> SoldbResult<u64> {
    match client.request::<String>("eth_chainId", json!([])) {
        Ok(chain_id) => parse_quantity(&chain_id).map_err(|error| {
            SoldbError::Message(format!(
                "Replay backend preflight failed: could not parse eth_chainId response {chain_id}: {error}",
            ))
        }),
        Err(error) => {
            let Some(tx_chain_id) = tx.chain_id.as_deref() else {
                return Err(SoldbError::Message(format!(
                    "Replay backend preflight failed: chain id is required, eth_chainId failed, and the transaction has no chainId. Original error: {error}",
                )));
            };
            parse_quantity(tx_chain_id).map_err(|parse_error| {
                SoldbError::Message(format!(
                    "Replay backend preflight failed: could not parse transaction chainId {tx_chain_id}: {parse_error}",
                ))
            })
        }
    }
}

fn replay_full_block_transactions(
    block_number: u64,
    transactions: &[RpcBlockTransaction],
) -> SoldbResult<Vec<RpcTransaction>> {
    if transactions.is_empty() {
        return Err(SoldbError::Message(format!(
            "Replay backend preflight failed: block {block_number} has no transactions in eth_getBlockByNumber response",
        )));
    }

    transactions
        .iter()
        .map(|transaction| match transaction {
            RpcBlockTransaction::Full(transaction) => Ok(transaction.as_ref().clone()),
            RpcBlockTransaction::Hash(hash) => Err(SoldbError::Message(format!(
                "Replay backend preflight failed: block {block_number} returned transaction hash {hash} instead of full transaction objects; replay requires eth_getBlockByNumber(block, true)",
            ))),
        })
        .collect()
}

fn replay_preflight_parent_state(
    provider: &RpcReplayStateProvider,
    tx: &RpcTransaction,
) -> SoldbResult<()> {
    let from = parse_address(&tx.from_addr).map_err(|error| {
        SoldbError::Message(format!(
            "Replay backend preflight failed: invalid sender address {}: {error}",
            tx.from_addr
        ))
    })?;
    provider
        .account(from)
        .map_err(|error| replay_parent_state_error("sender account", error))?;

    let storage_probe_address = if let Some(to) = tx.to.as_deref() {
        let to = parse_address(to).map_err(|error| {
            SoldbError::Message(format!(
                "Replay backend preflight failed: invalid recipient address {to}: {error}",
            ))
        })?;
        provider
            .account(to)
            .map_err(|error| replay_parent_state_error("recipient account", error))?;
        to
    } else {
        from
    };

    provider
        .storage(storage_probe_address, U256::ZERO)
        .map_err(|error| replay_parent_state_error("storage slot 0", error))?;
    Ok(())
}

fn replay_parent_state_error(context: &str, error: ReplayDbError) -> SoldbError {
    SoldbError::Message(format!(
        "Replay backend preflight failed: parent-block state is not readable while checking {context}. {error}",
    ))
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
    provider: RpcReplayStateProvider,
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
    fn new(provider: RpcReplayStateProvider) -> Self {
        Self { provider }
    }
}

trait ReplayStateProvider {
    fn account(&self, address: Address) -> Result<AccountInfo, ReplayDbError>;
    fn storage(&self, address: Address, index: U256) -> Result<U256, ReplayDbError>;
    fn block_hash(&self, number: u64) -> Result<B256, ReplayDbError>;
}

#[derive(Debug, Clone)]
struct RpcReplayStateProvider {
    inner: Rc<RefCell<RpcReplayStateProviderInner>>,
}

#[derive(Debug)]
struct RpcReplayStateProviderInner {
    client: HttpJsonRpcClient,
    block_tag: String,
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    block_hashes: HashMap<u64, B256>,
}

impl RpcReplayStateProvider {
    fn new(client: HttpJsonRpcClient, block_tag: String) -> Self {
        Self {
            inner: Rc::new(RefCell::new(RpcReplayStateProviderInner {
                client,
                block_tag,
                accounts: HashMap::new(),
                storage: HashMap::new(),
                block_hashes: HashMap::new(),
            })),
        }
    }
}

impl ReplayStateProvider for RpcReplayStateProvider {
    fn account(&self, address: Address) -> Result<AccountInfo, ReplayDbError> {
        if let Some(account) = self.inner.borrow().accounts.get(&address).cloned() {
            return Ok(account);
        }

        let mut inner = self.inner.borrow_mut();
        let account = inner.fetch_account(address)?;
        inner.accounts.insert(address, account.clone());
        Ok(account)
    }

    fn storage(&self, address: Address, index: U256) -> Result<U256, ReplayDbError> {
        if let Some(value) = self.inner.borrow().storage.get(&(address, index)).copied() {
            return Ok(value);
        }

        let mut inner = self.inner.borrow_mut();
        let value = inner.fetch_storage(address, index)?;
        inner.storage.insert((address, index), value);
        Ok(value)
    }

    fn block_hash(&self, number: u64) -> Result<B256, ReplayDbError> {
        if let Some(hash) = self.inner.borrow().block_hashes.get(&number).copied() {
            return Ok(hash);
        }

        let mut inner = self.inner.borrow_mut();
        let hash = inner.fetch_block_hash(number)?;
        inner.block_hashes.insert(number, hash);
        Ok(hash)
    }
}

impl RpcReplayStateProviderInner {
    fn request_at_block<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, ReplayDbError> {
        self.client.request(method, params).map_err(|error| {
            ReplayDbError(format!(
                "Replay backend could not read historical state with {method} at block {}; use an archive-capable RPC endpoint or a local node with the needed state history. Original error: {error}",
                self.block_tag
            ))
        })
    }

    fn fetch_account(&self, address: Address) -> Result<AccountInfo, ReplayDbError> {
        let address_text = address.to_string();
        let block = self.block_tag.clone();
        let balance: String =
            self.request_at_block("eth_getBalance", json!([address_text, block.clone()]))?;
        let nonce: String = self.request_at_block(
            "eth_getTransactionCount",
            json!([address_text, block.clone()]),
        )?;
        let code: String = self.request_at_block("eth_getCode", json!([address_text, block]))?;

        let code_bytes = hex_to_bytes(code.trim_start_matches("0x")).ok_or_else(|| {
            ReplayDbError(format!(
                "Invalid bytecode returned for account {address}: {code}"
            ))
        })?;
        let bytecode = Bytecode::new_raw(Bytes::from(code_bytes));
        let code_hash = bytecode.hash_slow();
        Ok(AccountInfo::new(
            parse_u256_quantity(&balance).map_err(ReplayDbError::from)?,
            parse_quantity(&nonce).map_err(ReplayDbError::from)?,
            code_hash,
            bytecode,
        ))
    }

    fn fetch_storage(&self, address: Address, index: U256) -> Result<U256, ReplayDbError> {
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

    fn fetch_block_hash(&self, number: u64) -> Result<B256, ReplayDbError> {
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

impl DatabaseRef for RpcStateDb {
    type Error = ReplayDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.provider.account(address).map(Some)
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.provider.storage(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.provider.block_hash(number)
    }
}

#[derive(Debug, Default)]
struct ReplayStepInspector {
    gas: GasInspector,
    pending: Option<StructLog>,
    struct_logs: Vec<StructLog>,
    artifacts: TraceArtifacts,
    call_stack: Vec<usize>,
    create_stack: Vec<usize>,
    journal_entries_seen: usize,
}

impl ReplayStepInspector {
    fn into_parts(self) -> (Vec<StructLog>, TraceArtifacts) {
        (self.struct_logs, self.artifacts)
    }
}

impl<CTX> Inspector<CTX> for ReplayStepInspector
where
    CTX: ContextTr,
    CTX::Journal: JournalExt,
{
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
            record_replay_storage_touch(&mut log, interp);
            self.struct_logs.push(log);
        }
    }

    fn log_full(
        &mut self,
        _interp: &mut Interpreter,
        context: &mut CTX,
        log: revm::primitives::Log,
    ) {
        let index = self.artifacts.logs.len();
        self.artifacts
            .logs
            .push(log_artifact(index, context.journal().depth() as u64, &log));
        self.record_journal_changes(context);
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let id = self.artifacts.calls.len();
        let parent_id = self.call_stack.last().copied();
        let depth = context.journal().depth() as u64 + 1;
        let input = bytes_to_prefixed_hex(inputs.input.bytes(context).as_ref());
        self.artifacts.calls.push(ExecutionCall {
            id,
            parent_id,
            depth,
            call_type: call_scheme_name(inputs.scheme).to_owned(),
            from: address_hex(inputs.caller),
            to: address_hex(inputs.target_address),
            bytecode_address: address_hex(inputs.bytecode_address),
            value: format_u256_quantity(inputs.call_value()),
            input,
            gas_limit: inputs.gas_limit,
            gas_used: None,
            output: None,
            success: None,
            error: None,
        });
        self.call_stack.push(id);
        self.record_journal_changes(context);
        None
    }

    fn call_end(&mut self, context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        if let Some(id) = self.call_stack.pop() {
            if let Some(call) = self.artifacts.calls.get_mut(id) {
                let result = *outcome.instruction_result();
                call.gas_used = Some(outcome.gas().used());
                call.output = Some(bytes_to_prefixed_hex(outcome.output().as_ref()));
                call.success = Some(result.is_ok());
                call.error = (!result.is_ok()).then(|| format!("{result:?}"));
            }
        }
        self.record_journal_changes(context);
    }

    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        let id = self.artifacts.creations.len();
        let parent_id = self.call_stack.last().copied();
        self.artifacts.creations.push(ContractCreation {
            id,
            parent_id,
            depth: context.journal().depth() as u64 + 1,
            create_type: create_scheme_name(inputs.scheme()).to_owned(),
            caller: address_hex(inputs.caller()),
            address: None,
            value: format_u256_quantity(inputs.value()),
            init_code: bytes_to_prefixed_hex(inputs.init_code().as_ref()),
            gas_limit: inputs.gas_limit(),
            gas_used: None,
            output: None,
            success: None,
            error: None,
        });
        self.create_stack.push(id);
        self.record_journal_changes(context);
        None
    }

    fn create_end(
        &mut self,
        context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if let Some(id) = self.create_stack.pop() {
            if let Some(create) = self.artifacts.creations.get_mut(id) {
                let result = *outcome.instruction_result();
                create.address = outcome.address.map(address_hex);
                create.gas_used = Some(outcome.gas().used());
                create.output = Some(bytes_to_prefixed_hex(outcome.output().as_ref()));
                create.success = Some(result.is_ok());
                create.error = (!result.is_ok()).then(|| format!("{result:?}"));
            }
        }
        self.record_journal_changes(context);
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        self.artifacts.account_changes.push(AccountChange {
            depth: 0,
            kind: "selfdestruct".to_owned(),
            address: Some(address_hex(contract)),
            from: Some(address_hex(contract)),
            to: Some(address_hex(target)),
            value: Some(format_u256_quantity(value)),
            key: None,
            previous_value: None,
            previous_nonce: None,
        });
    }
}

impl ReplayStepInspector {
    fn record_journal_changes<CTX>(&mut self, context: &mut CTX)
    where
        CTX: ContextTr,
        CTX::Journal: JournalExt,
    {
        let journal = context.journal().journal();
        for entry in journal.iter().skip(self.journal_entries_seen) {
            if let Some(change) =
                account_change_from_journal_entry(context.journal().depth() as u64, entry)
            {
                self.artifacts.account_changes.push(change);
            }
        }
        self.journal_entries_seen = journal.len();
    }
}

fn log_artifact(index: usize, depth: u64, log: &revm::primitives::Log) -> ExecutionLog {
    ExecutionLog {
        index,
        depth,
        address: address_hex(log.address),
        topics: log
            .data
            .topics()
            .iter()
            .map(|topic| b256_hex(*topic))
            .collect(),
        data: bytes_to_prefixed_hex(log.data.data.as_ref()),
    }
}

fn account_change_from_journal_entry(depth: u64, entry: &JournalEntry) -> Option<AccountChange> {
    let base = |kind: &str| AccountChange {
        depth,
        kind: kind.to_owned(),
        address: None,
        from: None,
        to: None,
        value: None,
        key: None,
        previous_value: None,
        previous_nonce: None,
    };

    match entry {
        JournalEntry::AccountDestroyed {
            had_balance,
            address,
            target,
            ..
        } => {
            let mut change = base("account_destroyed");
            change.address = Some(address_hex(*address));
            change.from = Some(address_hex(*address));
            change.to = Some(address_hex(*target));
            change.value = Some(format_u256_quantity(*had_balance));
            Some(change)
        }
        JournalEntry::AccountTouched { address } => {
            let mut change = base("account_touched");
            change.address = Some(address_hex(*address));
            Some(change)
        }
        JournalEntry::BalanceChange {
            old_balance,
            address,
        } => {
            let mut change = base("balance_change");
            change.address = Some(address_hex(*address));
            change.previous_value = Some(format_u256_quantity(*old_balance));
            Some(change)
        }
        JournalEntry::BalanceTransfer { balance, from, to } => {
            let mut change = base("balance_transfer");
            change.from = Some(address_hex(*from));
            change.to = Some(address_hex(*to));
            change.value = Some(format_u256_quantity(*balance));
            Some(change)
        }
        JournalEntry::NonceChange {
            address,
            previous_nonce,
        } => {
            let mut change = base("nonce_change");
            change.address = Some(address_hex(*address));
            change.previous_nonce = Some(*previous_nonce);
            Some(change)
        }
        JournalEntry::NonceBump { address } => {
            let mut change = base("nonce_bump");
            change.address = Some(address_hex(*address));
            Some(change)
        }
        JournalEntry::AccountCreated { address, .. } => {
            let mut change = base("account_created");
            change.address = Some(address_hex(*address));
            Some(change)
        }
        JournalEntry::StorageChanged {
            address,
            key,
            had_value,
        } => {
            let mut change = base("storage_change");
            change.address = Some(address_hex(*address));
            change.key = Some(format_u256_quantity(*key));
            change.previous_value = Some(format_u256_quantity(*had_value));
            Some(change)
        }
        JournalEntry::TransientStorageChange {
            address,
            key,
            had_value,
        } => {
            let mut change = base("transient_storage_change");
            change.address = Some(address_hex(*address));
            change.key = Some(format_u256_quantity(*key));
            change.previous_value = Some(format_u256_quantity(*had_value));
            Some(change)
        }
        JournalEntry::CodeChange { address } => {
            let mut change = base("code_change");
            change.address = Some(address_hex(*address));
            Some(change)
        }
        JournalEntry::AccountWarmed { .. } | JournalEntry::StorageWarmed { .. } => None,
    }
}

fn call_scheme_name(scheme: CallScheme) -> &'static str {
    match scheme {
        CallScheme::Call => "CALL",
        CallScheme::CallCode => "CALLCODE",
        CallScheme::DelegateCall => "DELEGATECALL",
        CallScheme::StaticCall => "STATICCALL",
    }
}

fn create_scheme_name(scheme: revm::context_interface::CreateScheme) -> &'static str {
    match scheme {
        revm::context_interface::CreateScheme::Create => "CREATE",
        revm::context_interface::CreateScheme::Create2 { .. } => "CREATE2",
        revm::context_interface::CreateScheme::Custom { .. } => "CUSTOM_CREATE",
    }
}

fn record_replay_storage_touch(log: &mut StructLog, interp: &Interpreter) {
    match log.op.as_str() {
        "SLOAD" => {
            let Some(slot) = log.stack.last().cloned() else {
                return;
            };
            let value = interp
                .stack
                .data()
                .last()
                .copied()
                .map(format_u256_quantity)
                .unwrap_or_else(|| "0x0".to_owned());
            log.storage.insert(normalize_storage_key(&slot), value);
        }
        "SSTORE" => {
            let Some(slot) = log.stack.last().cloned() else {
                return;
            };
            let Some(value) = log.stack.get(log.stack.len().saturating_sub(2)).cloned() else {
                return;
            };
            log.storage
                .insert(normalize_storage_key(&slot), normalize_hex_output(&value));
        }
        _ => {}
    }
}

fn normalize_storage_key(value: &str) -> String {
    let value = normalize_hex_output(value);
    let trimmed = value.trim_start_matches("0x").trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{}", trimmed.to_ascii_lowercase())
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
    let value = value.trim();
    if value.starts_with("0x") {
        Ok(format_u256_quantity(parse_u256_quantity(value)?))
    } else if let Some(ether_value) = strip_ether_suffix(value) {
        Ok(format_u256_quantity(parse_ether_value(ether_value)?))
    } else {
        let parsed = U256::from_str_radix(value, 10).map_err(|error| {
            SoldbError::Message(format!("Invalid call value '{value}': {error}"))
        })?;
        Ok(format_u256_quantity(parsed))
    }
}

fn strip_ether_suffix(value: &str) -> Option<&str> {
    value
        .get(..value.len().checked_sub("ether".len())?)
        .filter(|_| value.to_ascii_lowercase().ends_with("ether"))
        .map(str::trim)
}

fn parse_ether_value(value: &str) -> SoldbResult<U256> {
    let value = value.trim();
    let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty() && fractional.is_empty() {
        return Err(SoldbError::Message("Invalid call value 'ether'".to_owned()));
    }
    if fractional.len() > 18 {
        return Err(SoldbError::Message(format!(
            "Invalid call value '{value}ether': too many decimal places"
        )));
    }
    if (!whole.is_empty() && !whole.chars().all(|ch| ch.is_ascii_digit()))
        || (!fractional.is_empty() && !fractional.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(SoldbError::Message(format!(
            "Invalid call value '{value}ether': expected decimal ether amount"
        )));
    }

    let ether = U256::from(1_000_000_000_000_000_000u64);
    let whole_wei = if whole.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(whole, 10)
            .map_err(|error| {
                SoldbError::Message(format!("Invalid call value '{value}ether': {error}"))
            })?
            .checked_mul(ether)
            .ok_or_else(|| {
                SoldbError::Message(format!("Invalid call value '{value}ether': overflow"))
            })?
    };

    let fractional_wei = if fractional.is_empty() {
        U256::ZERO
    } else {
        let mut padded = fractional.to_owned();
        padded.extend(std::iter::repeat_n('0', 18 - fractional.len()));
        U256::from_str_radix(&padded, 10).map_err(|error| {
            SoldbError::Message(format!("Invalid call value '{value}ether': {error}"))
        })?
    };

    whole_wei
        .checked_add(fractional_wei)
        .ok_or_else(|| SoldbError::Message(format!("Invalid call value '{value}ether': overflow")))
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
    let hex = bytes_to_hex(&bytes[first_non_zero..]);
    format!("0x{}", hex.trim_start_matches('0'))
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

fn bytes_to_prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", bytes_to_hex(bytes))
}

fn address_hex(address: Address) -> String {
    bytes_to_prefixed_hex(address.as_slice())
}

fn b256_hex(value: B256) -> String {
    bytes_to_prefixed_hex(value.as_slice())
}

fn gas_summary_from_result(result: &revm::context::result::ExecutionResult) -> GasSummary {
    let gas = result.gas();
    GasSummary {
        used: gas.used(),
        spent: Some(gas.spent()),
        refunded: Some(gas.final_refunded()),
        remaining: Some(gas.remaining()),
        limit: Some(gas.limit()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    use revm::primitives::{B256, U256};
    use revm::DatabaseRef;

    use super::{
        build_transaction_trace, debug_rpc_capabilities, decode_revert_reason, parse_address,
        parse_value_quantity, replay_chain_id, replay_full_block_transactions,
        replay_preflight_parent_state, replay_spec_for_chain, replay_target_index,
        resolve_trace_backend, simulate_call, trace_transaction, trace_transaction_with_backend,
        transaction_logs, DebugTraceResult, HttpEndpoint, HttpJsonRpcClient, HttpScheme,
        RpcBlockTransaction, RpcReplayStateProvider, RpcStateDb, RpcTransaction,
        SimulateCallRequest, SpecId, StructLog, TraceArtifacts, TraceBackend, TraceCapabilities,
        TraceEnvelope,
    };
    use serde_json::json;
    use soldb_core::TransactionTrace;

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
        assert_eq!(steps[0].snapshot.stack, ["0x01"]);
        assert_eq!(steps[0].snapshot.memory.as_deref(), Some("aabb"));
        assert_eq!(steps[0].snapshot.storage["0x00"], "0x2a");
        assert_eq!(
            steps[0].snapshot.storage_diff["0x00"].after.as_deref(),
            Some("0x2a")
        );
        assert_eq!(steps[1].gas_cost, 0);
        assert!(steps[1].snapshot.storage_diff.is_empty());
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
            "gas": 7,
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
            backend: Some(TraceBackend::DebugRpc.as_str().to_owned()),
            capabilities: debug_rpc_capabilities(&result),
        };

        let trace = build_transaction_trace(envelope, &result);
        assert!(trace.success);
        assert_eq!(trace.output, "0x");
        assert_eq!(trace.backend.as_deref(), Some("debug-rpc"));
        assert!(trace.capabilities.opcode_steps);
        assert!(trace.capabilities.stack);
        assert!(trace.capabilities.memory);
        assert!(trace.capabilities.gas_details);
        assert_eq!(trace.artifacts.gas.as_ref().map(|gas| gas.used), Some(7));
        assert_eq!(trace.steps[0].op, "STOP");
    }

    #[test]
    fn debug_rpc_capabilities_reflect_returned_trace_data() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "08c379a0",
            "failed": true,
            "gas": 9,
            "structLogs": [
                {
                    "pc": 0,
                    "op": "SSTORE",
                    "gas": 100,
                    "gasCost": 3,
                    "depth": 0,
                    "stack": ["0x2a", "0x0"],
                    "storage": {"0x0": "0x2a"}
                }
            ]
        }))
        .expect("debug trace");

        let capabilities = debug_rpc_capabilities(&result);

        assert!(capabilities.opcode_steps);
        assert!(capabilities.stack);
        assert!(capabilities.memory);
        assert!(capabilities.storage);
        assert!(capabilities.storage_diff);
        assert!(capabilities.revert_data);
        assert!(capabilities.gas_details);
        assert!(capabilities.notes.is_empty());
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
            backend: Some(TraceBackend::Auto.as_str().to_owned()),
            capabilities: TraceCapabilities::default(),
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
            artifacts: TraceArtifacts::default(),
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
        assert_eq!(trace.backend.as_deref(), Some("debug-rpc"));
        assert!(trace.capabilities.opcode_steps);
        assert!(trace.capabilities.stack);
        assert!(trace.capabilities.memory);
        assert!(trace.capabilities.gas_details);
        assert!(!trace.capabilities.storage);
        assert!(trace
            .capabilities
            .notes
            .iter()
            .any(|note| note.contains("per-step storage")));
        assert_eq!(
            trace.artifacts.gas.as_ref().map(|gas| gas.used),
            Some(21_000)
        );
        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.steps[0].op, "PUSH1");
        assert_eq!(trace.steps[1].memory.as_deref(), Some("aabb"));
    }

    #[test]
    fn trace_backend_names_are_stable() {
        assert_eq!(TraceBackend::Auto.as_str(), "auto");
        assert_eq!(TraceBackend::DebugRpc.as_str(), "debug-rpc");
        assert_eq!(TraceBackend::Replay.as_str(), "replay");
    }

    #[test]
    fn auto_backend_prefers_debug_rpc_when_available() {
        let resolved = resolve_trace_backend(
            TraceBackend::Auto,
            || Ok(sample_transaction_trace("debug-rpc")),
            || -> soldb_core::SoldbResult<TransactionTrace> {
                panic!("auto should not call replay when debug-rpc succeeds")
            },
        )
        .expect("resolved trace");

        assert_eq!(resolved.backend, TraceBackend::DebugRpc);
        assert_eq!(resolved.trace.output, "debug-rpc");
    }

    #[test]
    fn auto_backend_falls_back_when_debug_rpc_is_unavailable() {
        let resolved = resolve_trace_backend(
            TraceBackend::Auto,
            || {
                Err(soldb_core::SoldbError::Message(
                    r#"RPC method debug_traceTransaction returned error: {"code":-32601,"message":"method not found"}"#.to_owned(),
                ))
            },
            || Ok(sample_transaction_trace("replay")),
        )
        .expect("fallback trace");

        assert_eq!(resolved.backend, TraceBackend::Replay);
        assert_eq!(resolved.trace.output, "replay");
    }

    #[test]
    fn auto_backend_does_not_fallback_for_transaction_errors() {
        let error = resolve_trace_backend(
            TraceBackend::Auto,
            || {
                Err(soldb_core::SoldbError::Message(
                    "Transaction not found: 0xabc".to_owned(),
                ))
            },
            || -> soldb_core::SoldbResult<TransactionTrace> {
                panic!("auto should not fallback on transaction lookup errors")
            },
        )
        .expect_err("transaction lookup should stay fatal");

        assert!(error.to_string().contains("Transaction not found"));
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
    fn replay_chain_id_requires_rpc_or_transaction_chain_id() {
        let rpc_url = start_chain_id_error_server();
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let mut tx = mock_rpc_transaction("0xabc");
        tx.chain_id = None;

        let error = replay_chain_id(&client, &tx).expect_err("missing chain id should fail");
        let message = error.to_string();
        assert!(message.contains("chain id is required"), "{message}");
        assert!(message.contains("eth_chainId failed"), "{message}");
    }

    #[test]
    fn replay_chain_id_uses_transaction_chain_id_when_rpc_fails() {
        let rpc_url = start_chain_id_error_server();
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let mut tx = mock_rpc_transaction("0xabc");
        tx.chain_id = Some("0x7a69".to_owned());

        assert_eq!(replay_chain_id(&client, &tx).expect("chain id"), 31_337);
    }

    #[test]
    fn replay_full_block_transactions_rejects_hash_only_blocks() {
        let error =
            replay_full_block_transactions(12, &[RpcBlockTransaction::Hash("0xabc".to_owned())])
                .expect_err("hash-only block should fail preflight");
        let message = error.to_string();
        assert!(message.contains("full transaction objects"), "{message}");
        assert!(message.contains("block 12"), "{message}");

        let transactions = replay_full_block_transactions(
            12,
            &[RpcBlockTransaction::Full(Box::new(mock_rpc_transaction(
                "0xabc",
            )))],
        )
        .expect("full transaction");
        assert_eq!(transactions[0].hash, "0xabc");
    }

    #[test]
    fn replay_preflight_parent_state_reads_account_and_storage() {
        let (rpc_url, rx) = start_replay_state_server(7);
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let provider = RpcReplayStateProvider::new(client, "0x10".to_owned());

        replay_preflight_parent_state(&provider, &mock_rpc_transaction("0xabc"))
            .expect("preflight");

        let methods: Vec<String> = rx.try_iter().collect();
        assert_eq!(count_method(&methods, "eth_getBalance"), 2, "{methods:?}");
        assert_eq!(
            count_method(&methods, "eth_getTransactionCount"),
            2,
            "{methods:?}"
        );
        assert_eq!(count_method(&methods, "eth_getCode"), 2, "{methods:?}");
        assert_eq!(count_method(&methods, "eth_getStorageAt"), 1, "{methods:?}");
    }

    #[test]
    fn replay_preflight_parent_state_reports_archive_hint() {
        let rpc_url = start_replay_state_error_server();
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let provider = RpcReplayStateProvider::new(client, "0x10".to_owned());

        let error = replay_preflight_parent_state(&provider, &mock_rpc_transaction("0xabc"))
            .expect_err("preflight should report state access failures");
        let message = error.to_string();
        assert!(
            message.contains("parent-block state is not readable"),
            "{message}"
        );
        assert!(message.contains("sender account"), "{message}");
        assert!(message.contains("archive-capable RPC"), "{message}");
    }

    #[test]
    fn replay_state_provider_caches_account_storage_and_block_hash_reads() {
        let (rpc_url, rx) = start_replay_state_server(5);
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let db = RpcStateDb::new(RpcReplayStateProvider::new(client, "0x10".to_owned()));
        let address = parse_address("0x5fbdb2315678afecb367f032d93f642f64180aa3").expect("address");

        assert!(db.basic_ref(address).expect("account").is_some());
        assert!(db.basic_ref(address).expect("cached account").is_some());
        assert_eq!(
            db.storage_ref(address, U256::from(1)).expect("storage"),
            U256::from(42)
        );
        assert_eq!(
            db.storage_ref(address, U256::from(1))
                .expect("cached storage"),
            U256::from(42)
        );
        assert_ne!(db.block_hash_ref(7).expect("block hash"), B256::ZERO);
        assert_eq!(
            db.block_hash_ref(7).expect("cached block hash"),
            db.block_hash_ref(7).expect("cached block hash again")
        );

        let methods: Vec<String> = rx.try_iter().collect();
        assert_eq!(count_method(&methods, "eth_getBalance"), 1, "{methods:?}");
        assert_eq!(
            count_method(&methods, "eth_getTransactionCount"),
            1,
            "{methods:?}"
        );
        assert_eq!(count_method(&methods, "eth_getCode"), 1, "{methods:?}");
        assert_eq!(count_method(&methods, "eth_getStorageAt"), 1, "{methods:?}");
        assert_eq!(
            count_method(&methods, "eth_getBlockByNumber"),
            1,
            "{methods:?}"
        );
    }

    #[test]
    fn replay_state_provider_reports_archive_state_hint() {
        let rpc_url = start_replay_state_error_server();
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let db = RpcStateDb::new(RpcReplayStateProvider::new(client, "0x10".to_owned()));
        let address = parse_address("0x5fbdb2315678afecb367f032d93f642f64180aa3").expect("address");

        let error = db
            .basic_ref(address)
            .expect_err("state read should report contextual replay failure");
        let message = error.to_string();
        assert!(message.contains("historical state"), "{message}");
        assert!(message.contains("archive-capable RPC"), "{message}");
        assert!(message.contains("eth_getBalance"), "{message}");
        assert!(message.contains("0x10"), "{message}");
    }

    #[test]
    fn selects_mainnet_specs_by_block_and_timestamp() {
        assert_eq!(replay_spec_for_chain(1, 0, 0), SpecId::FRONTIER);
        assert_eq!(
            replay_spec_for_chain(1, 200_000, 0),
            SpecId::FRONTIER_THAWING
        );
        assert_eq!(replay_spec_for_chain(1, 1_150_000, 0), SpecId::HOMESTEAD);
        assert_eq!(replay_spec_for_chain(1, 12_965_000, 0), SpecId::LONDON);
        assert_eq!(replay_spec_for_chain(1, 15_537_394, 0), SpecId::MERGE);
        assert_eq!(
            replay_spec_for_chain(1, 17_034_870, 1_681_338_455),
            SpecId::SHANGHAI
        );
        assert_eq!(
            replay_spec_for_chain(1, 19_426_587, 1_710_338_135),
            SpecId::CANCUN
        );
        assert_eq!(
            replay_spec_for_chain(1, 22_431_084, 1_746_612_311),
            SpecId::PRAGUE
        );
        assert_eq!(
            replay_spec_for_chain(1, 24_800_000, 1_764_798_551),
            SpecId::OSAKA
        );
    }

    #[test]
    fn selects_common_testnet_and_dev_specs() {
        assert_eq!(
            replay_spec_for_chain(11_155_111, 5_000_000, 1_706_655_072),
            SpecId::CANCUN
        );
        assert_eq!(
            replay_spec_for_chain(11_155_111, 5_000_000, 1_741_159_776),
            SpecId::PRAGUE
        );
        assert_eq!(
            replay_spec_for_chain(17_000, 1, 1_759_308_480),
            SpecId::OSAKA
        );
        assert_eq!(
            replay_spec_for_chain(560_048, 1, 1_742_999_831),
            SpecId::CANCUN
        );
        assert_eq!(
            replay_spec_for_chain(560_048, 1, 1_742_999_832),
            SpecId::PRAGUE
        );
        assert_eq!(
            replay_spec_for_chain(31_337, 1, 1_818_000_000),
            SpecId::PRAGUE
        );
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
        assert_eq!(trace.backend.as_deref(), Some("debug-rpc"));
        assert!(trace.capabilities.gas_details);
        assert_eq!(
            trace.artifacts.gas.as_ref().map(|gas| gas.used),
            Some(42_000)
        );
        assert_eq!(trace.steps[1].op, "CALLDATASIZE");
    }

    #[test]
    fn parses_simulation_value_quantities() {
        assert_eq!(parse_value_quantity("0").expect("zero"), "0x0");
        assert_eq!(parse_value_quantity("42").expect("decimal wei"), "0x2a");
        assert_eq!(parse_value_quantity("0x2a").expect("hex wei"), "0x2a");
        assert_eq!(
            parse_value_quantity("1ether").expect("one ether"),
            "0xde0b6b3a7640000"
        );
        assert_eq!(
            parse_value_quantity("0.1ether").expect("decimal ether"),
            "0x16345785d8a0000"
        );
        assert_eq!(
            parse_value_quantity(".5ether").expect("fractional ether"),
            "0x6f05b59d3b20000"
        );
        assert!(parse_value_quantity("0.0000000000000000001ether").is_err());
        assert!(parse_value_quantity("nope").is_err());
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

    fn start_replay_state_server(request_count: usize) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay state server");
        let address = listener.local_addr().expect("local addr");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for _ in 0..request_count {
                let (stream, _) = listener.accept().expect("accept rpc request");
                respond_to_replay_state_request(stream, &tx);
            }
        });
        (format!("http://{address}"), rx)
    }

    fn start_replay_state_error_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay state error server");
        let address = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept rpc request");
            respond_to_replay_state_error_request(stream);
        });
        format!("http://{address}")
    }

    fn start_chain_id_error_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind chain id error server");
        let address = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept rpc request");
            respond_to_chain_id_error_request(stream);
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
                    "gas": 21000,
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

    fn respond_to_replay_state_request(mut stream: TcpStream, tx: &mpsc::Sender<String>) {
        let request = read_http_request(&mut stream);
        let (method, result) = if request.contains("\"eth_getBalance\"") {
            ("eth_getBalance", json!("0x2a"))
        } else if request.contains("\"eth_getTransactionCount\"") {
            ("eth_getTransactionCount", json!("0x3"))
        } else if request.contains("\"eth_getCode\"") {
            ("eth_getCode", json!("0x60016000"))
        } else if request.contains("\"eth_getStorageAt\"") {
            ("eth_getStorageAt", json!("0x2a"))
        } else if request.contains("\"eth_getBlockByNumber\"") {
            (
                "eth_getBlockByNumber",
                json!({
                    "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "timestamp": "0x1",
                    "gasLimit": "0x1c9c380",
                    "baseFeePerGas": "0x1"
                }),
            )
        } else {
            ("unknown", json!(null))
        };
        tx.send(method.to_owned()).expect("record method");

        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result
        });
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

    fn respond_to_replay_state_error_request(mut stream: TcpStream) {
        let _request = read_http_request(&mut stream);
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32000,
                "message": "missing trie node"
            }
        });
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

    fn respond_to_chain_id_error_request(mut stream: TcpStream) {
        let _request = read_http_request(&mut stream);
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32601,
                "message": "method not found"
            }
        });
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

    fn count_method(methods: &[String], method: &str) -> usize {
        methods
            .iter()
            .filter(|entry| entry.as_str() == method)
            .count()
    }

    fn sample_transaction_trace(output: &str) -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 21_000,
            output: output.to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some(output.to_owned()),
            capabilities: TraceCapabilities::default(),
            artifacts: TraceArtifacts::default(),
            steps: Vec::new(),
        }
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
