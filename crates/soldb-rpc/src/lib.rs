//! Ethereum JSON-RPC transport and the execution backends built on it.
//!
//! This is the only crate that talks to a node. It provides the HTTP/HTTPS JSON-RPC
//! client, transaction and receipt lookups, log retrieval, `debug_traceCall`
//! simulation, and the two ways of producing an execution trace:
//!
//! - the `debug-rpc` backend, which asks the node to replay the transaction through
//!   `debug_traceTransaction`, and
//! - the `replay` backend, which reads the state a transaction touched over ordinary
//!   RPC, re-executes any earlier transactions in the block, and then runs the target
//!   through REVM with inspectors attached.
//!
//! Both backends produce the same [`soldb_core::TransactionTrace`], and each reports
//! what it was able to capture through `TraceCapabilities` so callers never have to
//! branch on the backend name. Backend-specific quirks belong here rather than in the
//! frontends.
//!
//! The replay backend lives in the `replay` module behind the cargo feature of the same
//! name, on by default, because it is the only part of the crate that links REVM. A
//! build without it keeps the transport, the `debug-rpc` backend, and the pure trace
//! assembly ([`debug_rpc_transaction_trace`], [`debug_rpc_simulation_trace`]), which is
//! what a WebAssembly host needs; asking it for the replay backend reports that the
//! feature is off rather than failing obscurely.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use ruint::aliases::U256;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soldb_core::{
    ExecutionLog, GasSummary, SoldbError, SoldbResult, StepSnapshot, StorageChange, TraceArtifacts,
    TraceCapabilities, TraceStep, TransactionTrace,
};

#[cfg(feature = "replay")]
mod replay;
#[cfg(test)]
mod test_support;

#[cfg(feature = "replay")]
pub use replay::{
    replay_debug_trace_with_state, replay_prefix_with_state, replay_simulation_trace,
    replay_target_with_state, replay_transaction_trace, simulate_call_with_replay, AccountState,
    PrefetchedReplayState, ReplayBackend, ReplayDbError, ReplayInputs, ReplayPrefix,
    ReplayStateProvider, RpcBlockHeader, RpcBlockTransaction, RpcBlockWithTransactions,
    RpcReplayStateProvider, StateBatch, StateRequest,
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
        let response_body = self.request_body(method, &body)?;
        parse_json_rpc_body(method, &response_body)
    }

    fn request_body(&self, method: &str, body: &str) -> SoldbResult<String> {
        if self.endpoint.scheme == HttpScheme::Https {
            return self.request_body_with_curl(method, body);
        }

        self.request_body_with_tcp(method, body)
    }

    fn request_body_with_tcp(&self, method: &str, body: &str) -> SoldbResult<String> {
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
        parse_http_response_body(method, &response)
    }

    fn request_body_with_curl(&self, method: &str, body: &str) -> SoldbResult<String> {
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
        Ok(body)
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

fn parse_http_response_body(method: &str, response: &str) -> SoldbResult<String> {
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

    Ok(body.to_owned())
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

/// Joins a `structLogs` memory array into one unprefixed hex string.
///
/// Nodes disagree on whether the words carry a `0x` prefix. Joining prefixed words
/// verbatim produces `0x..0x..0x..`, which is neither valid hex nor indexable by byte
/// offset, and it makes this backend disagree with the replay backend, which emits one
/// unprefixed string. A step's memory is documented to be a flat byte sequence, and
/// byte-offset lookups such as memory-located variable decoding assume exactly that.
fn joined_memory(words: &[String]) -> String {
    words
        .iter()
        .map(|word| {
            word.strip_prefix("0x")
                .or_else(|| word.strip_prefix("0X"))
                .unwrap_or(word)
        })
        .collect()
}

impl StructLog {
    #[must_use]
    pub fn into_trace_step(self) -> TraceStep {
        self.into_trace_step_with_previous_storage(&BTreeMap::new())
    }

    /// Builds a [`TraceStep`] from a borrowed log.
    ///
    /// Prefer this when walking a whole trace: the owning version cannot be used without
    /// first cloning the log, which doubles the per-step copying for no benefit.
    ///
    /// A `TraceStep` records its stack, memory, and storage twice — once in the flat
    /// fields and once in the snapshot — so two copies of each are unavoidable here. That
    /// is the floor, and this function stays at it.
    #[must_use]
    pub fn to_trace_step_with_previous_storage(
        &self,
        previous_storage: &BTreeMap<String, String>,
    ) -> TraceStep {
        let memory = joined_memory(&self.memory);
        let snapshot = StepSnapshot {
            stack: self.stack.clone(),
            memory: Some(memory.clone()),
            storage: self.storage.clone(),
            storage_diff: if self.storage.is_empty() {
                BTreeMap::new()
            } else {
                storage_diff(previous_storage, &self.storage)
            },
        };
        TraceStep {
            pc: self.pc,
            op: self.op.clone(),
            gas: self.gas,
            gas_cost: self.gas_cost,
            depth: self.depth,
            stack: self.stack.clone(),
            memory: Some(memory),
            storage: Some(self.storage.clone()),
            error: self.error.clone(),
            snapshot,
        }
    }

    #[must_use]
    pub fn into_trace_step_with_previous_storage(
        self,
        previous_storage: &BTreeMap<String, String>,
    ) -> TraceStep {
        let memory = joined_memory(&self.memory);
        // Clone into the snapshot first, then move the originals into the flat fields.
        let snapshot = StepSnapshot {
            stack: self.stack.clone(),
            memory: Some(memory.clone()),
            storage: self.storage.clone(),
            storage_diff: if self.storage.is_empty() {
                BTreeMap::new()
            } else {
                storage_diff(previous_storage, &self.storage)
            },
        };
        TraceStep {
            pc: self.pc,
            op: self.op,
            gas: self.gas,
            gas_cost: self.gas_cost,
            depth: self.depth,
            stack: self.stack,
            memory: Some(memory),
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

impl DebugTraceResult {
    #[must_use]
    pub fn steps(&self) -> Vec<TraceStep> {
        static EMPTY_STORAGE: BTreeMap<String, String> = BTreeMap::new();

        // Borrow the previous log's storage rather than copying it forward: this runs once
        // per EVM step, and a trace can have hundreds of thousands of them.
        let mut previous_storage = &EMPTY_STORAGE;
        self.struct_logs
            .iter()
            .map(|log| {
                let step = log.to_trace_step_with_previous_storage(previous_storage);
                previous_storage = &log.storage;
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

/// Assembles the `debug-rpc` trace of a mined transaction from the node's responses to
/// `eth_getTransactionByHash`, `eth_getTransactionReceipt`, and `debug_traceTransaction`.
///
/// This is the whole of the `debug-rpc` backend once the three requests have been
/// answered, so a host that fetches them itself, such as a WebAssembly client, produces
/// the identical trace to [`trace_transaction_with_client`].
pub fn debug_rpc_transaction_trace(
    tx: RpcTransaction,
    receipt: RpcReceipt,
    debug_result: &DebugTraceResult,
) -> SoldbResult<TransactionTrace> {
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
        capabilities: debug_rpc_capabilities(debug_result),
    };
    let mut trace = build_transaction_trace(envelope, debug_result);
    if !receipt.logs.is_empty() && trace.artifacts.logs.is_empty() {
        trace.artifacts.logs = receipt_logs_to_artifacts(&receipt.logs);
        trace.capabilities.logs = true;
    }
    Ok(trace)
}

/// Assembles the trace of a simulated call from the request that was sent and the node's
/// `debug_traceCall` response.
///
/// The request's `block` and `tx_index` only shape the RPC call, so they do not appear in
/// the trace. See [`debug_rpc_transaction_trace`] for why this is separate from the
/// networked [`simulate_call_with_client`].
pub fn debug_rpc_simulation_trace(
    request: &SimulateCallRequest,
    debug_result: &DebugTraceResult,
) -> SoldbResult<TransactionTrace> {
    simulation_trace(
        TraceBackend::DebugRpc,
        debug_rpc_capabilities(debug_result),
        request,
        debug_result,
    )
}

/// The one place a simulated call becomes a trace, whichever backend executed it.
pub(crate) fn simulation_trace(
    backend: TraceBackend,
    capabilities: TraceCapabilities,
    request: &SimulateCallRequest,
    debug_result: &DebugTraceResult,
) -> SoldbResult<TransactionTrace> {
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
        backend: Some(backend.as_str().to_owned()),
        capabilities,
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
        || replay_trace_transaction(client, tx_hash),
    )
}

/// Whether the `replay` backend was compiled into this build.
///
/// The backend sits behind the `replay` cargo feature (on by default) because it links
/// REVM. A build without it, such as the WebAssembly package, still has the JSON-RPC
/// transport, the `debug-rpc` backend, and trace assembly.
#[must_use]
pub fn replay_backend_available() -> bool {
    cfg!(feature = "replay")
}

#[cfg(feature = "replay")]
fn replay_trace_transaction(
    client: &HttpJsonRpcClient,
    tx_hash: &str,
) -> SoldbResult<TransactionTrace> {
    ReplayBackend::new(client).trace_transaction(tx_hash)
}

#[cfg(not(feature = "replay"))]
fn replay_trace_transaction(
    _client: &HttpJsonRpcClient,
    _tx_hash: &str,
) -> SoldbResult<TransactionTrace> {
    Err(replay_unavailable())
}

/// The error every path that would need REVM reports when the `replay` feature is off.
#[cfg(not(feature = "replay"))]
fn replay_unavailable() -> SoldbError {
    SoldbError::Message(
        "the `replay` backend is not available in this build; enable the `replay` feature of `soldb-rpc`"
            .to_owned(),
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
    // Whether any step reports a storage change, read straight off the logs. Calling
    // `steps()` here would build the entire trace a second time — hundreds of thousands of
    // steps, each with a copy of the stack and of all of memory — and then throw it away to
    // answer a boolean. This mirrors what `to_trace_step_with_previous_storage` computes:
    // a step has a diff when its own storage is non-empty and differs from the previous
    // step's.
    let has_storage_diff = {
        static EMPTY_STORAGE: BTreeMap<String, String> = BTreeMap::new();
        let mut previous = &EMPTY_STORAGE;
        result.struct_logs.iter().any(|log| {
            let changed = !log.storage.is_empty() && *previous != log.storage;
            previous = &log.storage;
            changed
        })
    };
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

/// Simulates a call through the chosen backend: `debug_traceCall` on the node, or a
/// local replay over the node's state for nodes that cannot trace. `Auto` means
/// `debug_traceCall`, since a call has no mined result to fall back on.
pub fn simulate_call_with_backend(
    rpc_url: &str,
    request: &SimulateCallRequest,
    backend: TraceBackend,
) -> SoldbResult<TransactionTrace> {
    let client = HttpJsonRpcClient::new(rpc_url)?;
    match backend {
        TraceBackend::Auto | TraceBackend::DebugRpc => simulate_call_with_client(&client, request),
        TraceBackend::Replay => replay_simulate_call(&client, request),
    }
}

#[cfg(feature = "replay")]
fn replay_simulate_call(
    client: &HttpJsonRpcClient,
    request: &SimulateCallRequest,
) -> SoldbResult<TransactionTrace> {
    replay::simulate_call_with_replay(client, request)
}

#[cfg(not(feature = "replay"))]
fn replay_simulate_call(
    _client: &HttpJsonRpcClient,
    _request: &SimulateCallRequest,
) -> SoldbResult<TransactionTrace> {
    Err(replay_unavailable())
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

    debug_rpc_transaction_trace(tx, receipt, &debug_result)
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

    debug_rpc_simulation_trace(request, &debug_result)
}

fn receipt_logs_to_artifacts(logs: &[RpcLog]) -> Vec<ExecutionLog> {
    logs.iter()
        .enumerate()
        .map(|(index, log)| ExecutionLog {
            index,
            depth: 0,
            address: log.address.clone(),
            topics: log.topics.clone(),
            data: normalize_hex_output(&log.data),
        })
        .collect()
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

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    // Hex strings reach us from RPC responses and CLI arguments, so they are not
    // guaranteed to be ASCII. Slicing by byte offset would panic on a multi-byte
    // character whose boundary falls inside a pair; decode over bytes instead.
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }

    pairs
        .iter()
        .map(|[high, low]| {
            let high = char::from(*high).to_digit(16)?;
            let low = char::from(*low).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Fill an ASCII byte buffer and validate it once. `String::push` re-runs UTF-8
    // encoding for every character, which is measurable when the replay inspector encodes
    // the whole of EVM memory.
    let mut encoded = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)]);
        encoded.push(HEX[usize::from(byte & 0x0f)]);
    }
    // `HEX` holds only ASCII, so the buffer is valid UTF-8 by construction.
    String::from_utf8(encoded).expect("hex digits are ASCII")
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use soldb_core::TransactionTrace;

    use super::{
        build_transaction_trace, debug_rpc_capabilities, debug_rpc_simulation_trace,
        debug_rpc_transaction_trace, decode_revert_reason, parse_value_quantity,
        resolve_trace_backend, simulate_call, trace_transaction, trace_transaction_with_backend,
        transaction_logs, DebugTraceResult, HttpEndpoint, HttpScheme, RpcReceipt, RpcTransaction,
        SimulateCallRequest, StructLog, TraceArtifacts, TraceBackend, TraceCapabilities,
        TraceEnvelope,
    };
    use crate::test_support::{event_log, sample_transaction_trace, start_trace_server};

    #[cfg(not(feature = "replay"))]
    #[test]
    fn replay_backend_reports_that_it_is_not_compiled_in() {
        assert!(!super::replay_backend_available());

        // No request is made: the backend is rejected before the client is used.
        let error =
            trace_transaction_with_backend("http://127.0.0.1:1", "0xabc", TraceBackend::Replay)
                .expect_err("replay is compiled out");
        assert!(error.to_string().contains("`replay` feature"), "{error}");

        // `auto` falls back to replay only when `debug_traceTransaction` is unavailable;
        // without the feature that fallback reports the same guidance instead of
        // pretending a backend exists.
        let client = super::HttpJsonRpcClient::new("http://127.0.0.1:1").expect("client");
        let error = resolve_trace_backend(
            TraceBackend::Auto,
            || {
                Err(soldb_core::SoldbError::Message(
                    r#"RPC method debug_traceTransaction returned error: {"code":-32601,"message":"method not found"}"#.to_owned(),
                ))
            },
            || super::replay_trace_transaction(&client, "0xabc"),
        )
        .expect_err("no fallback without the feature");
        assert!(error.to_string().contains("`replay` feature"), "{error}");
    }

    fn canned_debug_result() -> DebugTraceResult {
        serde_json::from_value(json!({
            "gas": 21000,
            "returnValue": "",
            "structLogs": [
                {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                {"pc": 2, "op": "MSTORE", "gas": 97, "gasCost": 3, "depth": 0, "memory": ["aa", "bb"]},
                {"pc": 3, "op": "STOP", "gas": 94, "gasCost": 0, "depth": 0}
            ]
        }))
        .expect("debug result")
    }

    #[test]
    fn debug_rpc_transaction_trace_assembles_the_node_responses() {
        let tx: RpcTransaction = serde_json::from_value(json!({
            "hash": "0xabc",
            "from": "0x1",
            "to": "0x2",
            "value": "0x0",
            "input": "1234"
        }))
        .expect("transaction");
        let receipt: RpcReceipt = serde_json::from_value(json!({
            "gasUsed": "0x5208",
            "status": "0x1",
            "contractAddress": null,
            "logs": [event_log("0x2", "04"), event_log("0x2", "05")]
        }))
        .expect("receipt");

        let trace =
            debug_rpc_transaction_trace(tx, receipt, &canned_debug_result()).expect("trace");

        assert_eq!(trace.tx_hash.as_deref(), Some("0xabc"));
        assert_eq!(trace.from_addr, "0x1");
        assert_eq!(trace.to_addr.as_deref(), Some("0x2"));
        assert_eq!(trace.input_data, "0x1234");
        assert_eq!(trace.gas_used, 21000);
        assert!(trace.success);
        assert_eq!(trace.error, None);
        assert!(trace.debug_trace_available);
        assert_eq!(
            trace.backend.as_deref(),
            Some(TraceBackend::DebugRpc.as_str())
        );
        assert!(trace.capabilities.opcode_steps);
        // Receipt logs stand in for the logs `debug_traceTransaction` never returns.
        assert!(trace.capabilities.logs);
        assert_eq!(trace.artifacts.logs.len(), 2);
        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.steps[1].memory.as_deref(), Some("aabb"));
    }

    #[test]
    fn debug_rpc_transaction_trace_reports_a_reverted_receipt() {
        let tx: RpcTransaction = serde_json::from_value(json!({
            "hash": "0xabc",
            "from": "0x1",
            "to": "0x2"
        }))
        .expect("transaction");
        let receipt: RpcReceipt = serde_json::from_value(json!({
            "gasUsed": "0x5208",
            "status": "0x0"
        }))
        .expect("receipt");

        let trace =
            debug_rpc_transaction_trace(tx, receipt, &canned_debug_result()).expect("trace");

        assert!(!trace.success);
        assert!(!trace.capabilities.logs);
        assert!(trace.artifacts.logs.is_empty());
    }

    #[test]
    fn debug_rpc_transaction_trace_rejects_a_malformed_gas_quantity() {
        let tx: RpcTransaction = serde_json::from_value(json!({
            "hash": "0xabc",
            "from": "0x1",
            "to": "0x2"
        }))
        .expect("transaction");
        let receipt: RpcReceipt = serde_json::from_value(json!({
            "gasUsed": "not-a-quantity",
            "status": "0x1"
        }))
        .expect("receipt");

        assert!(debug_rpc_transaction_trace(tx, receipt, &canned_debug_result()).is_err());
    }

    #[test]
    fn debug_rpc_simulation_trace_carries_the_request_and_the_result() {
        let request = SimulateCallRequest {
            from_addr: "0x1".to_owned(),
            to_addr: "0x2".to_owned(),
            calldata: "0x1234".to_owned(),
            value: "0x0".to_owned(),
            block: Some(7),
            tx_index: Some(3),
        };
        let debug_result: DebugTraceResult = serde_json::from_value(json!({
            "gas": 42000,
            "returnValue": "2a",
            "failed": false,
            "structLogs": [
                {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                {"pc": 2, "op": "STOP", "gas": 95, "gasCost": 0, "depth": 0}
            ]
        }))
        .expect("debug result");

        let trace = debug_rpc_simulation_trace(&request, &debug_result).expect("trace");

        assert_eq!(trace.tx_hash, None);
        assert_eq!(trace.from_addr, "0x1");
        assert_eq!(trace.to_addr.as_deref(), Some("0x2"));
        assert_eq!(trace.input_data, "0x1234");
        assert_eq!(trace.output, "0x2a");
        assert_eq!(trace.gas_used, 42000);
        assert!(trace.success);
        assert_eq!(
            trace.backend.as_deref(),
            Some(TraceBackend::DebugRpc.as_str())
        );
        assert_eq!(
            trace.artifacts.gas.as_ref().map(|gas| gas.used),
            Some(42000)
        );
        assert_eq!(trace.steps.len(), 2);
    }

    #[test]
    fn debug_rpc_simulation_trace_surfaces_the_failure_message() {
        let request = SimulateCallRequest {
            from_addr: "0x1".to_owned(),
            to_addr: "0x2".to_owned(),
            calldata: "0x".to_owned(),
            value: "0x0".to_owned(),
            block: None,
            tx_index: None,
        };
        let debug_result: DebugTraceResult = serde_json::from_value(json!({
            "failed": true,
            "returnValue": "",
            "structLogs": [
                {"pc": 0, "op": "REVERT", "gas": 100, "gasCost": 0, "depth": 0, "error": "execution reverted"}
            ]
        }))
        .expect("debug result");

        let trace = debug_rpc_simulation_trace(&request, &debug_result).expect("trace");

        assert!(!trace.success);
        assert!(trace.error.is_some(), "failure must be reported");
        assert_eq!(trace.gas_used, 0);
    }

    #[test]
    fn storage_diff_capability_matches_the_materialized_steps() {
        // `debug_rpc_capabilities` reads the storage-diff flag off the raw logs instead of
        // building every step. Pin it against the definition it replaces.
        let log = |storage: &[(&str, &str)]| StructLog {
            pc: 0,
            op: "SSTORE".to_owned(),
            gas: 0,
            gas_cost: 0,
            depth: 0,
            stack: Vec::new(),
            memory: Vec::new(),
            storage: storage
                .iter()
                .map(|(slot, value)| ((*slot).to_owned(), (*value).to_owned()))
                .collect(),
            error: None,
        };

        let cases = [
            Vec::new(),
            vec![log(&[])],
            vec![log(&[("0x00", "0x01")])],
            vec![log(&[("0x00", "0x01")]), log(&[("0x00", "0x01")])],
            vec![log(&[("0x00", "0x01")]), log(&[("0x00", "0x02")])],
            vec![log(&[("0x00", "0x01")]), log(&[])],
            vec![log(&[]), log(&[("0x00", "0x01")])],
        ];

        for struct_logs in cases {
            let result = DebugTraceResult {
                struct_logs,
                return_value: String::new(),
                error: None,
                failed: false,
                gas: None,
                artifacts: TraceArtifacts::default(),
            };
            let materialized = result
                .steps()
                .iter()
                .any(|step| !step.snapshot.storage_diff.is_empty());
            assert_eq!(
                super::debug_rpc_capabilities(&result).storage_diff,
                materialized,
                "logs: {:?}",
                result.struct_logs
            );
        }
    }

    #[test]
    fn hex_decoding_rejects_non_ascii_without_panicking() {
        // Hex strings arrive from RPC responses and CLI arguments. Slicing them by byte
        // offset panicked when a multi-byte character straddled a digit pair.
        assert_eq!(super::hex_to_bytes("\u{20ac}\u{20ac}"), None);
        assert_eq!(super::hex_to_bytes("0\u{20ac}"), None);
        assert_eq!(super::hex_to_bytes("zz"), None);
        assert_eq!(super::hex_to_bytes("abc"), None);
        assert_eq!(super::hex_to_bytes("0a1B"), Some(vec![0x0a, 0x1b]));
        assert_eq!(super::hex_to_bytes(""), Some(Vec::new()));
    }

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
                    "memory": ["0xaa", "bb"],
                    "storage": {"0x00": "0x2a"}
                },
                {"pc": 2, "op": "STOP", "gas": 97, "depth": 0}
            ]
        }))
        .expect("debug trace");

        let steps = result.steps();
        assert_eq!(steps.len(), 2);
        // Memory words are normalized to one unprefixed hex string whether or not the node
        // prefixed them, so byte-offset lookups stay valid and both backends agree.
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
}
