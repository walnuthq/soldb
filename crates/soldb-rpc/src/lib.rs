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
//! Execution itself lives in `soldb-evm`: the node data shapes, the trace assembly, and
//! the REVM engine. This crate re-exports that surface so a caller sees one crate, and
//! adds what needs a socket: the client, the lookups, and the `replay` module, which
//! gathers a transaction's inputs and reads parent-block state lazily over RPC. The
//! module sits behind the `replay` cargo feature, on by default, which also turns on the
//! engine; a build without it keeps the transport and the `debug-rpc` backend, and asking
//! it for the replay backend reports that the feature is off rather than failing
//! obscurely.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_evm::{format_quantity, normalize_hex_output, parse_value_quantity};

pub use soldb_evm::{
    build_transaction_trace, debug_rpc_simulation_trace, debug_rpc_transaction_trace,
    decode_revert_reason, DebugTraceResult, RpcLog, RpcReceipt, RpcTransaction,
    SimulateCallRequest, StructLog, TraceBackend, TraceEnvelope,
};

#[cfg(feature = "replay")]
mod replay;
#[cfg(test)]
mod test_support;

#[cfg(feature = "replay")]
pub use replay::{simulate_call_with_replay, ReplayBackend, RpcReplayStateProvider};
#[cfg(feature = "replay")]
pub use soldb_evm::{
    replay_debug_trace_with_state, replay_prefix_with_state, replay_simulation_trace,
    replay_target_with_state, replay_transaction_trace, AccountState, LocalChain,
    PrefetchedReplayState, ReplayDbError, ReplayInputs, ReplayPrefix, ReplayStateProvider,
    RpcBlockHeader, RpcBlockTransaction, RpcBlockWithTransactions, StateBatch, StateRequest,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use soldb_core::TransactionTrace;
    use soldb_evm::{SimulateCallRequest, TraceBackend};

    use super::{
        resolve_trace_backend, simulate_call, trace_transaction, trace_transaction_with_backend,
        transaction_logs, HttpEndpoint, HttpScheme,
    };
    use crate::test_support::{sample_transaction_trace, start_trace_server};

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
}
