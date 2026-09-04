//! WebAssembly bindings for the debugger.
//!
//! This is a frontend in the same sense as the CLI and the DAP server: it composes the
//! library crates and owns no logic of its own. The exported surface is one handle,
//! [`Trace`], plus [`version`]. Inputs and outputs cross the boundary as JSON strings, so
//! a browser or Node.js host uses the documents this workspace already specifies rather
//! than a second, JavaScript-shaped type system, while the trace itself stays in
//! WebAssembly memory between calls and is never re-parsed.
//!
//! The host is responsible for I/O. A `wasm32-unknown-unknown` module has no network and
//! no filesystem, and the node is the execution oracle, so the host calls JSON-RPC and
//! reads ETHDebug artifacts itself, then hands the results to these functions. Anything
//! that must talk to a node or a compiler stays in the native binaries, and the REVM
//! replay backend is not linked at all.
//!
//! Each export is a thin wrapper over [`pipeline`] and, with the `replay` feature,
//! [`replay`], which is where the behavior lives and where it is tested natively.
//!
//! Two packages are built from this crate: a lean one without REVM, and a replay-capable
//! one that adds [`Replay`], a host-driven re-execution of a transaction for nodes that
//! do not answer `debug_traceTransaction`. [`replay_available`] tells a host which it
//! loaded.

use wasm_bindgen::prelude::{wasm_bindgen, JsError};

pub mod pipeline;
#[cfg(feature = "replay")]
pub mod replay;

fn js_error(error: soldb_core::SoldbError) -> JsError {
    JsError::new(&error.to_string())
}

/// The version of the debugger this module was built from.
#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Whether this build of the module carries the REVM replay backend, and so exports
/// `Replay`. The lean package reports `false`.
#[wasm_bindgen(js_name = replayAvailable)]
#[must_use]
pub fn replay_available() -> bool {
    cfg!(feature = "replay")
}

/// A transaction or simulation trace held in WebAssembly memory.
///
/// Build it once with one of the `from…` constructors, optionally attach the contract's
/// ETHDebug artifacts, then step through it or render documents from it as often as
/// needed; nothing is copied or re-parsed between calls. Call `free()` when done, since
/// the trace lives outside the JavaScript heap.
#[wasm_bindgen]
pub struct Trace {
    inner: pipeline::Trace,
}

#[wasm_bindgen]
impl Trace {
    /// Builds a `debug-rpc` trace from the `result` fields of `debug_traceTransaction`,
    /// `eth_getTransactionByHash`, and `eth_getTransactionReceipt`.
    #[wasm_bindgen(js_name = fromTransaction)]
    pub fn from_transaction(
        debug_trace_json: &str,
        transaction_json: &str,
        receipt_json: &str,
    ) -> Result<Trace, JsError> {
        pipeline::Trace::from_transaction(debug_trace_json, transaction_json, receipt_json)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    /// Builds the trace of a simulated call from the call that was sent and the `result`
    /// field of `debug_traceCall`.
    #[wasm_bindgen(js_name = fromSimulation)]
    pub fn from_simulation(
        from: &str,
        to: &str,
        calldata: &str,
        value: &str,
        debug_trace_json: &str,
    ) -> Result<Trace, JsError> {
        pipeline::Trace::from_simulation(from, to, calldata, value, debug_trace_json)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    /// Loads trace JSON produced by `toJson()` or saved by the native CLI.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(trace_json: &str) -> Result<Trace, JsError> {
        pipeline::Trace::from_json(trace_json)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    /// Attaches a contract artifacts object (see [`pipeline::ContractArtifacts`]): the
    /// contract `name`, the parsed global resource file as `metadata`, the parsed
    /// `<Contract>_ethdebug-runtime.json` as `program`, and optionally `sources` mapping
    /// source ids to contents. Replaces whatever was attached before.
    #[wasm_bindgen(js_name = attachEthdebug)]
    pub fn attach_ethdebug(&mut self, artifacts_json: &str) -> Result<(), JsError> {
        self.inner.attach_ethdebug(artifacts_json).map_err(js_error)
    }

    /// Whether debug info is attached, so steps carry source spans and variables.
    #[wasm_bindgen(js_name = hasEthdebug)]
    #[must_use]
    pub fn has_ethdebug(&self) -> bool {
        self.inner.has_ethdebug()
    }

    /// Number of opcode steps in the trace.
    #[wasm_bindgen(js_name = stepCount)]
    #[must_use]
    pub fn step_count(&self) -> usize {
        self.inner.step_count()
    }

    /// One step as JSON: program counter, opcode, gas, source span, enclosing function,
    /// machine state, and decoded variables. `undefined` past the end of the trace.
    pub fn step(&self, index: usize) -> Result<Option<String>, JsError> {
        self.inner.step_json(index).map_err(js_error)
    }

    /// The trace's header as JSON (see [`pipeline::TraceSummary`]): hash, parties,
    /// gas, status, backend, capabilities, step count, and the attached debug info.
    pub fn summary(&self) -> Result<String, JsError> {
        self.inner.summary_json().map_err(js_error)
    }

    /// The trace as JSON, the input `fromJson` accepts.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsError> {
        self.inner.to_json().map_err(js_error)
    }

    /// Renders the versioned web document from `docs/json.md`.
    ///
    /// `contracts_json` maps contract address to a contract artifacts object and fills
    /// the document's `contracts` section the way `--ethdebug-dir` does for the CLI.
    /// Omit it to leave that section empty.
    #[wasm_bindgen(js_name = toWebJson)]
    pub fn to_web_json(&self, contracts_json: Option<String>) -> Result<String, JsError> {
        self.inner
            .to_web_json(contracts_json.as_deref())
            .map_err(js_error)
    }

    /// Renders the simulation form of the web document, as `soldb simulate --json` does.
    /// `contracts_json` is as for `toWebJson`.
    #[wasm_bindgen(js_name = toSimulationWebJson)]
    pub fn to_simulation_web_json(
        &self,
        function_name: &str,
        contracts_json: Option<String>,
    ) -> Result<String, JsError> {
        self.inner
            .to_simulation_web_json(function_name, contracts_json.as_deref())
            .map_err(js_error)
    }
}

/// A host-driven replay of a mined transaction, for nodes without `debug_traceTransaction`.
///
/// REVM runs inside the module but cannot fetch state itself, so the host works in
/// rounds: `status()` lists the parent-block state the next run needs, the host fetches
/// it with `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`,
/// `eth_getStorageAt`, and `eth_getBlockByNumber` at the block `status()` names, passes
/// the results to `provideState()`, and calls `run()`. Missing values default to empty
/// and are recorded, so a run either completes or reports exactly what it still lacks;
/// the loop converges in a few rounds. The transactions before the target in its block
/// run only until they run clean, after which each round re-executes the target alone.
/// `finish()` then yields the `Trace`, and `exportState()` the state it depended on.
#[cfg(feature = "replay")]
#[wasm_bindgen]
pub struct Replay {
    inner: replay::Replay,
}

#[cfg(feature = "replay")]
#[wasm_bindgen]
impl Replay {
    /// Prepares a replay from the `result` fields of `eth_getTransactionByHash`,
    /// `eth_getTransactionReceipt`, and `eth_getBlockByNumber(number, true)` for the
    /// transaction's block, plus the `eth_chainId` result.
    pub fn prepare(
        transaction_json: &str,
        receipt_json: &str,
        block_json: &str,
        chain_id: &str,
    ) -> Result<Replay, JsError> {
        replay::Replay::prepare(transaction_json, receipt_json, block_json, chain_id)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    /// Prepares a call against the chain as it stood at a block: a fork, without a node
    /// that can fork. `block_json` is the `result` of `eth_getBlockByNumber` for the fork
    /// point; with `tx_index` the call runs inside that block after the transactions
    /// before the index (fetch the block with full transactions), otherwise on top of
    /// it. The rest of the loop is the same as for a transaction.
    #[wasm_bindgen(js_name = prepareCall)]
    pub fn prepare_call(
        from: &str,
        to: &str,
        calldata: &str,
        value: &str,
        block_json: &str,
        chain_id: &str,
        tx_index: Option<u32>,
    ) -> Result<Replay, JsError> {
        replay::Replay::prepare_call(
            from,
            to,
            calldata,
            value,
            block_json,
            chain_id,
            tx_index.map(u64::from),
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    /// Where the replay stands, as JSON (see [`replay::ReplayStatus`]): `complete`, or
    /// `needsState` with the `block` to read at and the `requests` to answer.
    pub fn status(&self) -> Result<String, JsError> {
        self.inner.status_json().map_err(js_error)
    }

    /// Supplies parent-block state as JSON (see `soldb_evm::StateBatch`): `accounts`
    /// keyed by address with `balance`, `nonce`, and `code`; `storage` keyed by address
    /// then slot; `blockHashes` keyed by block number.
    #[wasm_bindgen(js_name = provideState)]
    pub fn provide_state(&mut self, batch_json: &str) -> Result<(), JsError> {
        self.inner.provide_state(batch_json).map_err(js_error)
    }

    /// Runs the replay against the state supplied so far and returns the new status as
    /// JSON. A failure is reported only when nothing was missing, so it is real.
    pub fn run(&mut self) -> Result<String, JsError> {
        self.inner.run_json().map_err(js_error)
    }

    /// Whether the last run completed with nothing missing.
    #[wasm_bindgen(js_name = isComplete)]
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    /// Exactly the parent-block state the completed replay depended on, as the JSON
    /// `provideState()` accepts. Keep it to replay the same transaction again in one
    /// run, offline, or share it so someone else can.
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Result<String, JsError> {
        self.inner.export_state_json().map_err(js_error)
    }

    /// Takes the completed replay as a `Trace`. Consumes this object.
    pub fn finish(self) -> Result<Trace, JsError> {
        self.inner
            .finish()
            .map(|inner| Trace { inner })
            .map_err(js_error)
    }
}
