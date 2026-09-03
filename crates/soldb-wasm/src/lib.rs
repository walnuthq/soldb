//! WebAssembly bindings for the debugger.
//!
//! This is a frontend in the same sense as the CLI and the DAP server: it composes the
//! library crates and owns no logic of its own. The exported surface is deliberately
//! small and crosses the boundary as JSON strings, so a browser or Node.js host uses the
//! documents this workspace already specifies rather than a second, JavaScript-shaped
//! type system.
//!
//! The host is responsible for I/O. A `wasm32-unknown-unknown` module has no network and
//! no filesystem, and the node is the execution oracle, so the host calls JSON-RPC and
//! reads ETHDebug artifacts itself, then hands the results to these functions. Anything
//! that must talk to a node or a compiler stays in the native binaries.
//!
//! Each export is a thin wrapper over [`pipeline`], which is where the behavior lives and
//! where it is tested natively.

use wasm_bindgen::prelude::{wasm_bindgen, JsError};

pub mod pipeline;

fn js_error(error: soldb_core::SoldbError) -> JsError {
    JsError::new(&error.to_string())
}

/// The version of the debugger this module was built from.
#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Builds a `debug-rpc` trace from the `result` fields of `debug_traceTransaction`,
/// `eth_getTransactionByHash`, and `eth_getTransactionReceipt`, returned as trace JSON.
#[wasm_bindgen(js_name = buildTransactionTrace)]
pub fn build_transaction_trace(
    debug_trace_json: &str,
    transaction_json: &str,
    receipt_json: &str,
) -> Result<String, JsError> {
    pipeline::build_transaction_trace(debug_trace_json, transaction_json, receipt_json)
        .map_err(js_error)
}

/// Builds the trace of a simulated call from the call that was sent and the `result`
/// field of `debug_traceCall`, returned as trace JSON.
#[wasm_bindgen(js_name = buildSimulationTrace)]
pub fn build_simulation_trace(
    from: &str,
    to: &str,
    calldata: &str,
    value: &str,
    debug_trace_json: &str,
) -> Result<String, JsError> {
    pipeline::build_simulation_trace(from, to, calldata, value, debug_trace_json).map_err(js_error)
}

/// Renders trace JSON as the versioned web document from `docs/json.md`.
///
/// `contracts_json` maps contract address to a contract artifacts object (see
/// [`pipeline::ContractArtifacts`]) and fills the document's `contracts` section the way
/// `--ethdebug-dir` does for the CLI. Omit it to leave that section empty.
#[wasm_bindgen(js_name = traceToWebJson)]
pub fn trace_to_web_json(
    trace_json: &str,
    contracts_json: Option<String>,
) -> Result<String, JsError> {
    pipeline::trace_to_web_json(trace_json, contracts_json.as_deref()).map_err(js_error)
}

/// Renders simulation trace JSON as the versioned web document from `docs/json.md`.
/// `contracts_json` is as for [`trace_to_web_json`].
#[wasm_bindgen(js_name = simulateToWebJson)]
pub fn simulate_to_web_json(
    trace_json: &str,
    function_name: &str,
    contracts_json: Option<String>,
) -> Result<String, JsError> {
    pipeline::simulate_to_web_json(trace_json, function_name, contracts_json.as_deref())
        .map_err(js_error)
}

/// A source-level debug session over one trace.
///
/// Construct it with [`DebugSession::new`] for opcode-level steps, or with
/// [`DebugSession::with_ethdebug`] to attach the contract's ETHDebug artifacts and get
/// source spans, enclosing functions, and decoded variables per step.
#[wasm_bindgen]
pub struct DebugSession {
    inner: soldb_debugger::DebugSession,
}

#[wasm_bindgen]
impl DebugSession {
    /// Opens a session over trace JSON with no debug info attached.
    #[wasm_bindgen(constructor)]
    pub fn new(trace_json: &str) -> Result<DebugSession, JsError> {
        pipeline::open_session(trace_json)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    /// Opens a session with ETHDebug attached.
    ///
    /// `artifacts_json` is a contract artifacts object (see
    /// [`pipeline::ContractArtifacts`]): the contract `name`, the parsed global resource
    /// file as `metadata`, the parsed `<Contract>_ethdebug-runtime.json` as `program`, and
    /// optionally `sources` mapping source ids to contents.
    #[wasm_bindgen(js_name = withEthdebug)]
    pub fn with_ethdebug(trace_json: &str, artifacts_json: &str) -> Result<DebugSession, JsError> {
        pipeline::open_session_with_ethdebug(trace_json, artifacts_json)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    /// Number of opcode steps in the trace.
    #[wasm_bindgen(js_name = stepCount)]
    #[must_use]
    pub fn step_count(&self) -> usize {
        self.inner.trace.steps.len()
    }

    /// One step as JSON: program counter, opcode, gas, source span, enclosing function,
    /// machine state, and decoded variables. `undefined` past the end of the trace.
    pub fn step(&self, index: usize) -> Result<Option<String>, JsError> {
        pipeline::step_json(&self.inner, index).map_err(js_error)
    }
}
