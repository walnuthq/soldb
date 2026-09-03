//! The in-memory trace handle behind the WebAssembly exports.
//!
//! Every export takes the node's or the compiler's output as a string and returns a
//! string, but the trace itself is parsed once and then read in place: stepping,
//! summaries, and the web document borrow it, so a large trace is never serialized and
//! parsed again on the way to a result. Serialization happens exactly once per output
//! the host asks for. That matters because a mainnet transaction is easily hundreds of
//! thousands of steps, each carrying a stack and all of memory.
//!
//! Nothing here depends on a `wasm-bindgen` type, so the same code runs natively under
//! `cargo test`, which is where its behavior is covered, and the bindings in the crate
//! root stay thin.
//!
//! A WebAssembly host has neither network nor filesystem, and the node is the execution
//! oracle, so the host fetches the JSON-RPC responses and the ETHDebug artifacts itself
//! and hands them over. What comes out is the same [`TransactionTrace`] and the same
//! web document the CLI produces from the same inputs.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soldb_core::{SoldbError, SoldbResult, TraceCapabilities, TransactionTrace};
use soldb_debugger::DebugSession;
use soldb_ethdebug::{read_compilation_source, EthdebugInfo};
use soldb_rpc::{DebugTraceResult, RpcReceipt, RpcTransaction, SimulateCallRequest};
use soldb_serializer::WebContractMetadata;

/// One contract's compiler output, as the host supplies it.
///
/// This is the JSON shape behind every export that takes debug info: one object attaches
/// to a [`Trace`], and a map from contract address to one of these fills the `contracts`
/// section of the web document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContractArtifacts {
    /// The contract name, as in `<name>_ethdebug-runtime.json`.
    pub name: String,
    /// The parsed global ETHDebug resource file: `ethdebug.json` from older compilers,
    /// `ethdebug_resources.json` from modern ones.
    pub metadata: Value,
    /// The parsed program artifact the trace executed, normally
    /// `<name>_ethdebug-runtime.json`.
    pub program: Value,
    /// Source id to file contents. Ids left out fall back to the sources embedded in
    /// `metadata`, when the compiler inlined them.
    #[serde(default)]
    pub sources: BTreeMap<u64, String>,
    /// The contract ABI, copied into the web document when present.
    #[serde(default)]
    pub abi: Option<Value>,
}

/// What a host can learn about a trace without walking its steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(rename_all = "camelCase")]
pub struct TraceSummary {
    pub tx_hash: Option<String>,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub input_data: String,
    pub gas_used: u64,
    pub output: String,
    pub success: bool,
    pub error: Option<String>,
    pub backend: Option<String>,
    pub capabilities: TraceCapabilities,
    pub step_count: usize,
    /// Present once debug info is attached.
    pub debug_info: Option<DebugInfoSummary>,
}

/// The debug info attached to a trace, summarized so a host can tell what it will get.
///
/// `pcs_with_variables` is the number of program counters the artifact declares
/// variables at. Compilers that do not emit variable locations yet leave it at zero, in
/// which case every step's `variables` list is empty by design rather than by fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(rename_all = "camelCase")]
pub struct DebugInfoSummary {
    pub contract: String,
    pub sources: BTreeMap<u64, String>,
    pub instructions: usize,
    pub pcs_with_variables: usize,
}

/// The debug info and source contents a set of artifacts describes.
struct LoadedArtifacts {
    info: EthdebugInfo,
    sources: BTreeMap<u64, String>,
    abi: Option<Value>,
}

/// A trace held in memory, with debug info attached on request.
///
/// Construct it once from the node's responses, a simulated call, or saved trace JSON;
/// every other operation borrows the trace rather than copying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    session: DebugSession,
}

/// Parses one JSON argument, naming it in the error so a caller with several string
/// arguments can tell which one was malformed.
pub(crate) fn parse_json<T: DeserializeOwned>(what: &str, input: &str) -> SoldbResult<T> {
    serde_json::from_str(input)
        .map_err(|error| SoldbError::Message(format!("invalid {what} JSON: {error}")))
}

pub(crate) fn to_json<T: Serialize>(value: &T) -> SoldbResult<String> {
    serde_json::to_string(value).map_err(|error| SoldbError::Message(error.to_string()))
}

fn load_artifacts(artifacts: ContractArtifacts) -> SoldbResult<LoadedArtifacts> {
    let ContractArtifacts {
        name,
        metadata,
        program,
        mut sources,
        abi,
    } = artifacts;
    let info = EthdebugInfo::from_artifacts(&name, "runtime", &metadata, &program)?;
    for source_id in info.sources.keys() {
        if sources.contains_key(source_id) {
            continue;
        }
        if let Some(contents) = read_compilation_source(&info.compilation, *source_id) {
            sources.insert(*source_id, contents);
        }
    }
    Ok(LoadedArtifacts { info, sources, abi })
}

/// Builds the `contracts` section from a map of contract address to
/// [`ContractArtifacts`].
///
/// Addresses are lowercased so a lookup does not depend on checksum casing, and an entry
/// with nothing to report is left out, both as the CLI does for `--ethdebug-dir`.
fn web_contracts(
    contracts_json: Option<&str>,
) -> SoldbResult<BTreeMap<String, WebContractMetadata>> {
    let Some(contracts_json) = contracts_json.filter(|json| !json.trim().is_empty()) else {
        return Ok(BTreeMap::new());
    };
    let contracts = parse_json::<BTreeMap<String, ContractArtifacts>>("contracts", contracts_json)?;

    let mut web_contracts = BTreeMap::new();
    for (address, artifacts) in contracts {
        let loaded = load_artifacts(artifacts)
            .map_err(|error| SoldbError::Message(format!("contract `{address}`: {error}")))?;
        let metadata =
            WebContractMetadata::from_ethdebug(&loaded.info, &loaded.sources, loaded.abi);
        if metadata.is_empty() {
            continue;
        }
        web_contracts.insert(address.to_ascii_lowercase(), metadata);
    }
    Ok(web_contracts)
}

impl Trace {
    /// Builds a `debug-rpc` trace from the `result` fields of the node's responses to
    /// `debug_traceTransaction`, `eth_getTransactionByHash`, and
    /// `eth_getTransactionReceipt`.
    pub fn from_transaction(
        debug_trace_json: &str,
        transaction_json: &str,
        receipt_json: &str,
    ) -> SoldbResult<Self> {
        let debug_result =
            parse_json::<DebugTraceResult>("`debug_traceTransaction` result", debug_trace_json)?;
        let transaction =
            parse_json::<RpcTransaction>("`eth_getTransactionByHash` result", transaction_json)?;
        let receipt = parse_json::<RpcReceipt>("`eth_getTransactionReceipt` result", receipt_json)?;
        let trace = soldb_rpc::debug_rpc_transaction_trace(transaction, receipt, &debug_result)?;
        Ok(Self::from_trace(trace))
    }

    /// Builds the trace of a simulated call from the call that was sent and the `result`
    /// field of the node's `debug_traceCall` response.
    ///
    /// `value` accepts the same forms as `soldb simulate --value`: a hex quantity, a
    /// decimal wei amount, or an ether amount with a unit suffix.
    pub fn from_simulation(
        from: &str,
        to: &str,
        calldata: &str,
        value: &str,
        debug_trace_json: &str,
    ) -> SoldbResult<Self> {
        let debug_result =
            parse_json::<DebugTraceResult>("`debug_traceCall` result", debug_trace_json)?;
        let request = SimulateCallRequest {
            from_addr: from.to_owned(),
            to_addr: to.to_owned(),
            calldata: calldata.to_owned(),
            value: value.to_owned(),
            block: None,
            tx_index: None,
        };
        let trace = soldb_rpc::debug_rpc_simulation_trace(&request, &debug_result)?;
        Ok(Self::from_trace(trace))
    }

    /// Loads a trace serialized by [`Trace::to_json`] or saved by the native CLI.
    pub fn from_json(trace_json: &str) -> SoldbResult<Self> {
        let trace = parse_json::<TransactionTrace>("trace", trace_json)?;
        Ok(Self::from_trace(trace))
    }

    pub(crate) fn from_trace(trace: TransactionTrace) -> Self {
        Self {
            session: DebugSession::new(trace),
        }
    }

    /// Attaches one contract's [`ContractArtifacts`], replacing any attached before.
    ///
    /// The trace stays in place; only the debug info changes.
    pub fn attach_ethdebug(&mut self, artifacts_json: &str) -> SoldbResult<()> {
        let artifacts = parse_json::<ContractArtifacts>("contract artifacts", artifacts_json)?;
        let loaded = load_artifacts(artifacts)?;
        self.session.attach_ethdebug(loaded.info, loaded.sources);
        Ok(())
    }

    #[must_use]
    pub fn has_ethdebug(&self) -> bool {
        self.session.ethdebug.is_some()
    }

    #[must_use]
    pub fn step_count(&self) -> usize {
        self.session.trace.steps.len()
    }

    /// Serializes one step, or returns `None` past the end of the trace.
    ///
    /// With debug info attached the step carries its source span, enclosing function,
    /// and decoded variables; without it, opcode-level state only.
    pub fn step_json(&self, index: usize) -> SoldbResult<Option<String>> {
        self.session
            .step(index)
            .map(|step| to_json(&step))
            .transpose()
    }

    #[must_use]
    pub fn summary(&self) -> TraceSummary {
        let trace = &self.session.trace;
        TraceSummary {
            tx_hash: trace.tx_hash.clone(),
            from: trace.from_addr.clone(),
            to: trace.to_addr.clone(),
            value: trace.value.clone(),
            input_data: trace.input_data.clone(),
            gas_used: trace.gas_used,
            output: trace.output.clone(),
            success: trace.success,
            error: trace.error.clone(),
            backend: trace.backend.clone(),
            capabilities: trace.capabilities.clone(),
            step_count: trace.steps.len(),
            debug_info: self.session.ethdebug.as_ref().map(|info| DebugInfoSummary {
                contract: info.contract_name.clone(),
                sources: info.sources.clone(),
                instructions: info.instructions.len(),
                pcs_with_variables: info.variable_locations.len(),
            }),
        }
    }

    pub fn summary_json(&self) -> SoldbResult<String> {
        to_json(&self.summary())
    }

    /// The trace as JSON: the input [`Trace::from_json`] accepts, and the shape the
    /// native CLI reads and writes as a trace file.
    pub fn to_json(&self) -> SoldbResult<String> {
        to_json(&self.session.trace)
    }

    /// Renders the versioned web document specified in `docs/json.md`.
    ///
    /// `contracts_json` maps contract address to [`ContractArtifacts`] and fills the
    /// document's `contracts` section the way `--ethdebug-dir` does for the CLI; `None`
    /// or an empty string leaves it empty.
    pub fn to_web_json(&self, contracts_json: Option<&str>) -> SoldbResult<String> {
        let contracts = web_contracts(contracts_json)?;
        soldb_serializer::trace_to_web_json_with_contracts(&self.session.trace, contracts)
    }

    /// Renders the simulation form of the web document, as `soldb simulate --json` does.
    /// `contracts_json` is as for [`Trace::to_web_json`].
    pub fn to_simulation_web_json(
        &self,
        function_name: &str,
        contracts_json: Option<&str>,
    ) -> SoldbResult<String> {
        let contracts = web_contracts(contracts_json)?;
        soldb_serializer::simulate_to_web_json_with_contracts(
            &self.session.trace,
            function_name,
            contracts,
        )
    }

    /// The underlying session, for callers that want the typed model.
    #[must_use]
    pub fn session(&self) -> &DebugSession {
        &self.session
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{json, Value};
    use soldb_core::TransactionTrace;
    use soldb_debugger::{DebugStep, DebugValueStatus};

    use super::{Trace, TraceSummary};

    const SOURCE: &str = "contract Counter {\n    uint256 public count;\n\n    function increment() public {\n        count += 1;\n    }\n}\n";
    const SENDER: &str = "0x1111111111111111111111111111111111111111";

    fn debug_trace_json() -> String {
        json!({
            "gas": 21000,
            "returnValue": "",
            "structLogs": [
                {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 1, "stack": []},
                {"pc": 2, "op": "MSTORE", "gas": 97, "gasCost": 3, "depth": 1, "stack": ["0x80", "0x40"], "memory": ["aa", "bb"]},
                {"pc": 3, "op": "STOP", "gas": 94, "gasCost": 0, "depth": 1}
            ]
        })
        .to_string()
    }

    fn transaction_json() -> String {
        json!({
            "hash": "0xabc",
            "from": "0x1",
            "to": "0x2",
            "value": "0x0",
            // `increment()` selector followed by one ABI word holding `SENDER`.
            "input": format!("0xd09de08a000000000000000000000000{}", &SENDER[2..])
        })
        .to_string()
    }

    fn receipt_json() -> String {
        json!({
            "gasUsed": "0x5208",
            "status": "0x1",
            "contractAddress": null,
            "logs": [{
                "address": "0x2",
                "topics": ["0x3cf8b50771c17d723f2cb711ca7dadde485b222e13c84ba0730a14093fad6d5c"],
                "data": format!("0x{}", "0".repeat(64))
            }]
        })
        .to_string()
    }

    fn metadata(embed_source: bool) -> Value {
        let mut source = json!({"id": 0, "path": "Counter.sol"});
        if embed_source {
            source["contents"] = Value::String(SOURCE.to_owned());
        }
        json!({"compilation": {"sources": [source]}, "types": {}, "pointers": {}})
    }

    fn program() -> Value {
        let statement = SOURCE.find("count += 1").expect("statement offset");
        json!({
            "environment": "runtime",
            "instructions": [
                {
                    "offset": 0,
                    "operation": {"mnemonic": "PUSH1", "arguments": ["0x80"]},
                    "context": {"code": {"source": {"id": 0}, "range": {"offset": 0, "length": SOURCE.len()}}}
                },
                {
                    "offset": 2,
                    "operation": {"mnemonic": "MSTORE"},
                    "context": {
                        "code": {"source": {"id": 0}, "range": {"offset": statement, "length": 10}},
                        "variables": [
                            {"name": "count", "type": "uint256", "location": {"type": "stack", "offset": 1}},
                            {"name": "sender", "type": "address", "location": {"type": "calldata", "offset": 4}}
                        ]
                    }
                },
                {"offset": 3, "operation": {"mnemonic": "STOP"}}
            ]
        })
    }

    /// The artifacts object a host would build for the counter contract.
    fn artifacts(embed_source: bool, sources: Option<Value>) -> Value {
        let mut artifacts = json!({
            "name": "Counter",
            "metadata": metadata(embed_source),
            "program": program(),
            "abi": [{"type": "function", "name": "increment", "inputs": [], "outputs": []}]
        });
        if let Some(sources) = sources {
            artifacts["sources"] = sources;
        }
        artifacts
    }

    fn counter_artifacts() -> String {
        artifacts(false, Some(json!({"0": SOURCE}))).to_string()
    }

    fn trace() -> Trace {
        Trace::from_transaction(&debug_trace_json(), &transaction_json(), &receipt_json())
            .expect("trace")
    }

    fn step_at(trace: &Trace, index: usize) -> DebugStep {
        serde_json::from_str(&trace.step_json(index).expect("step").expect("in range"))
            .expect("step JSON")
    }

    fn document(json: &str) -> Value {
        serde_json::from_str(json).expect("document")
    }

    #[test]
    fn from_transaction_assembles_the_node_responses() {
        let trace = trace();
        let inner = &trace.session().trace;

        assert_eq!(inner.tx_hash.as_deref(), Some("0xabc"));
        assert_eq!(inner.from_addr, "0x1");
        assert_eq!(inner.to_addr.as_deref(), Some("0x2"));
        assert!(inner.input_data.starts_with("0xd09de08a"));
        assert_eq!(inner.gas_used, 21000);
        assert!(inner.success);
        assert_eq!(inner.error, None);
        assert_eq!(inner.backend.as_deref(), Some("debug-rpc"));
        assert!(inner.capabilities.opcode_steps);
        assert!(inner.capabilities.stack);
        assert!(inner.capabilities.memory);
        assert!(inner.capabilities.gas_details);
        assert_eq!(inner.steps.len(), 3);
        assert_eq!(inner.steps[1].memory.as_deref(), Some("aabb"));
        assert_eq!(trace.step_count(), 3);
        assert!(!trace.has_ethdebug());
    }

    #[test]
    fn from_transaction_takes_logs_from_the_receipt() {
        let trace = trace();
        let inner = &trace.session().trace;

        // `debug_traceTransaction` never returns logs, so the receipt supplies them.
        assert!(inner.capabilities.logs);
        assert_eq!(inner.artifacts.logs.len(), 1);
        assert_eq!(inner.artifacts.logs[0].address, "0x2");
    }

    #[test]
    fn from_transaction_reports_a_reverted_receipt() {
        let receipt = json!({"gasUsed": "0x5208", "status": "0x0"}).to_string();
        let trace = Trace::from_transaction(&debug_trace_json(), &transaction_json(), &receipt)
            .expect("trace");

        assert!(!trace.summary().success);
        assert!(!trace.session().trace.capabilities.logs);
    }

    #[test]
    fn from_transaction_rejects_a_malformed_gas_quantity() {
        let receipt = json!({"gasUsed": "lots", "status": "0x1"}).to_string();
        let error = Trace::from_transaction(&debug_trace_json(), &transaction_json(), &receipt)
            .expect_err("gas quantity");
        assert!(error.to_string().contains("lots"), "{error}");
    }

    #[test]
    fn from_simulation_carries_the_call_and_its_result() {
        let debug_trace = json!({
            "gas": 42000,
            "returnValue": "2a",
            "failed": false,
            "structLogs": [
                {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 1, "stack": []},
                {"pc": 2, "op": "STOP", "gas": 95, "gasCost": 0, "depth": 1}
            ]
        })
        .to_string();

        let trace =
            Trace::from_simulation("0x1", "0x2", "0xd09de08a", "0x0", &debug_trace).expect("trace");
        let summary = trace.summary();

        assert_eq!(summary.tx_hash, None);
        assert_eq!(summary.from, "0x1");
        assert_eq!(summary.to.as_deref(), Some("0x2"));
        assert_eq!(summary.input_data, "0xd09de08a");
        assert_eq!(summary.output, "0x2a");
        assert_eq!(summary.gas_used, 42000);
        assert!(summary.success);
        assert_eq!(summary.backend.as_deref(), Some("debug-rpc"));
        assert_eq!(summary.step_count, 2);
        assert_eq!(
            trace
                .session()
                .trace
                .artifacts
                .gas
                .as_ref()
                .map(|gas| gas.used),
            Some(42000)
        );
    }

    #[test]
    fn from_simulation_normalizes_every_value_form() {
        let debug_trace = json!({"structLogs": []}).to_string();
        for (value, expected) in [
            ("0x0", "0x0"),
            ("42", "0x2a"),
            ("0x2a", "0x2a"),
            ("1ether", "0xde0b6b3a7640000"),
            ("0.5 ether", "0x6f05b59d3b20000"),
        ] {
            let trace =
                Trace::from_simulation("0x1", "0x2", "0x", value, &debug_trace).expect(value);
            assert_eq!(trace.summary().value, expected, "{value}");
        }
        assert!(Trace::from_simulation("0x1", "0x2", "0x", "many", &debug_trace).is_err());
    }

    #[test]
    fn from_simulation_surfaces_the_failure_message() {
        let debug_trace = json!({
            "failed": true,
            "returnValue": "",
            "structLogs": [
                {"pc": 0, "op": "REVERT", "gas": 100, "gasCost": 0, "depth": 1, "error": "execution reverted"}
            ]
        })
        .to_string();

        let trace = Trace::from_simulation("0x1", "0x2", "0x", "0x0", &debug_trace).expect("trace");
        let summary = trace.summary();

        assert!(!summary.success);
        assert!(summary.error.is_some(), "failure must be reported");
        assert_eq!(summary.gas_used, 0);
    }

    #[test]
    fn to_json_round_trips_through_from_json() {
        let original = trace();
        let json = original.to_json().expect("json");
        let reloaded = Trace::from_json(&json).expect("reloaded");

        assert_eq!(reloaded, original);
        assert_eq!(reloaded.to_json().expect("json"), json);
        // Compact on purpose: this crosses the host boundary as one string.
        assert!(!json.contains('\n'));
    }

    #[test]
    fn to_json_is_the_trace_file_format() {
        let trace = trace();
        let parsed: TransactionTrace =
            serde_json::from_str(&trace.to_json().expect("json")).expect("trace file");
        assert_eq!(&parsed, &trace.session().trace);

        // The pretty-printed file the native CLI writes loads the same way.
        let pretty = soldb_serializer::trace_to_json(&trace.session().trace).expect("pretty");
        assert_eq!(Trace::from_json(&pretty).expect("from pretty"), trace);
    }

    #[test]
    fn steps_without_debug_info_carry_machine_state_only() {
        let trace = trace();

        let step = step_at(&trace, 1);
        assert_eq!(step.index, 1);
        assert_eq!(step.pc, 2);
        assert_eq!(step.op, "MSTORE");
        assert_eq!(step.gas, 97);
        assert_eq!(step.gas_cost, 3);
        assert_eq!(step.depth, 1);
        assert_eq!(step.source, None);
        assert_eq!(step.function, None);
        assert_eq!(step.snapshot.stack, ["0x80", "0x40"]);
        assert_eq!(step.snapshot.memory.as_deref(), Some("aabb"));
        assert!(step.variables.is_empty());

        let pcs: Vec<u64> = (0..trace.step_count())
            .map(|index| step_at(&trace, index).pc)
            .collect();
        assert_eq!(pcs, [0, 2, 3]);
    }

    #[test]
    fn step_past_the_end_is_none() {
        let trace = trace();
        assert_eq!(trace.step_json(3).expect("step"), None);
        assert_eq!(trace.step_json(usize::MAX).expect("step"), None);
    }

    #[test]
    fn attaching_ethdebug_adds_source_spans_and_functions() {
        let mut trace = trace();
        trace.attach_ethdebug(&counter_artifacts()).expect("attach");
        assert!(trace.has_ethdebug());

        let step = step_at(&trace, 1);
        let span = step.source.expect("source span");
        assert_eq!(span.source_id, 0);
        assert_eq!(span.path, "Counter.sol");
        assert_eq!(
            span.offset as usize,
            SOURCE.find("count += 1").expect("offset")
        );
        assert_eq!(span.length, 10);
        assert_eq!(span.line, 5);
        assert_eq!(span.column, 9);
        assert_eq!(
            step.function
                .as_ref()
                .map(|function| function.name.as_str()),
            Some("increment")
        );

        // The whole-file span on the preamble resolves to line 1 and no function.
        let step = step_at(&trace, 0);
        assert_eq!(step.source.map(|span| span.line), Some(1));
        assert_eq!(step.function, None);

        // An instruction without a location reports none rather than guessing.
        assert_eq!(step_at(&trace, 2).source, None);
    }

    #[test]
    fn attaching_ethdebug_decodes_variables_from_the_declared_locations() {
        let mut trace = trace();
        trace.attach_ethdebug(&counter_artifacts()).expect("attach");

        let step = step_at(&trace, 1);
        assert_eq!(step.variables.len(), 2);
        assert_eq!(step.variables[0].name, "count");
        assert_eq!(step.variables[0].value.display, "64");
        assert_eq!(step.variables[0].value.status, DebugValueStatus::Decoded);
        assert_eq!(step.variables[1].name, "sender");
        assert_eq!(step.variables[1].value.display, SENDER);
        assert_eq!(step.variables[1].value.status, DebugValueStatus::Decoded);

        // Variables are scoped to the program counter they were declared at.
        assert!(step_at(&trace, 0).variables.is_empty());
        assert!(step_at(&trace, 2).variables.is_empty());
    }

    #[test]
    fn attaching_ethdebug_falls_back_to_sources_embedded_in_the_metadata() {
        let mut trace = trace();
        trace
            .attach_ethdebug(&artifacts(true, None).to_string())
            .expect("attach");

        assert_eq!(trace.session().source_contents[&0], SOURCE);
        assert_eq!(step_at(&trace, 1).source.map(|span| span.line), Some(5));
    }

    #[test]
    fn attaching_ethdebug_prefers_explicit_sources_over_embedded_ones() {
        let mut trace = trace();
        let artifacts = artifacts(true, Some(json!({"0": "contract Other {}"}))).to_string();
        trace.attach_ethdebug(&artifacts).expect("attach");

        assert_eq!(trace.session().source_contents[&0], "contract Other {}");
        assert_eq!(step_at(&trace, 1).function, None);
    }

    #[test]
    fn attaching_ethdebug_without_sources_still_maps_offsets() {
        let mut trace = trace();
        trace
            .attach_ethdebug(&artifacts(false, None).to_string())
            .expect("attach");

        let span = step_at(&trace, 1).source.expect("span");
        assert_eq!(span.path, "Counter.sol");
        // Without the file contents there is no line to compute, and none is invented.
        assert_eq!(span.line, 0);
        assert_eq!(span.column, 0);
    }

    #[test]
    fn attaching_ethdebug_again_replaces_the_previous_artifacts() {
        let mut trace = trace();
        trace.attach_ethdebug(&counter_artifacts()).expect("attach");
        assert_eq!(step_at(&trace, 1).source.map(|span| span.line), Some(5));

        let other = json!({"name": "Other", "metadata": {}, "program": {}}).to_string();
        trace.attach_ethdebug(&other).expect("attach again");

        assert!(trace.has_ethdebug());
        assert_eq!(
            trace.summary().debug_info.map(|info| info.contract),
            Some("Other".to_owned())
        );
        assert_eq!(step_at(&trace, 1).source, None);
        assert!(step_at(&trace, 1).variables.is_empty());
    }

    #[test]
    fn attaching_ethdebug_leaves_the_trace_untouched() {
        let mut trace = trace();
        let before = trace.to_json().expect("json");
        let count = trace.step_count();

        trace.attach_ethdebug(&counter_artifacts()).expect("attach");

        assert_eq!(trace.to_json().expect("json"), before);
        assert_eq!(trace.step_count(), count);
        assert_eq!(step_at(&trace, 1).snapshot.stack, ["0x80", "0x40"]);
    }

    #[test]
    fn attaching_ethdebug_names_what_is_malformed() {
        let mut trace = trace();

        let error = trace.attach_ethdebug("not json").expect_err("malformed");
        assert!(
            error
                .to_string()
                .contains("invalid contract artifacts JSON"),
            "{error}"
        );
        assert!(!trace.has_ethdebug());

        let error = trace
            .attach_ethdebug(&json!({"name": "Counter"}).to_string())
            .expect_err("missing fields");
        assert!(
            error
                .to_string()
                .contains("invalid contract artifacts JSON"),
            "{error}"
        );

        let error = trace
            .attach_ethdebug(&artifacts(false, Some(json!([1, 2]))).to_string())
            .expect_err("sources not a map");
        assert!(
            error
                .to_string()
                .contains("invalid contract artifacts JSON"),
            "{error}"
        );

        let broken = json!({"name": "Broken", "metadata": {}, "program": {"instructions": [{"operation": {}}]}});
        let error = trace
            .attach_ethdebug(&broken.to_string())
            .expect_err("malformed program");
        assert!(error.to_string().contains("`instructions`"), "{error}");
        assert!(
            !trace.has_ethdebug(),
            "a failed attach leaves nothing behind"
        );
    }

    #[test]
    fn summary_reflects_the_trace_and_the_attached_debug_info() {
        let mut trace = trace();
        let summary = trace.summary();

        assert_eq!(summary.tx_hash.as_deref(), Some("0xabc"));
        assert_eq!(summary.from, "0x1");
        assert_eq!(summary.to.as_deref(), Some("0x2"));
        assert_eq!(summary.value, "0x0");
        assert_eq!(summary.gas_used, 21000);
        assert_eq!(summary.output, "0x");
        assert!(summary.success);
        assert_eq!(summary.error, None);
        assert_eq!(summary.backend.as_deref(), Some("debug-rpc"));
        assert_eq!(summary.capabilities, trace.session().trace.capabilities);
        assert_eq!(summary.step_count, 3);
        assert_eq!(summary.debug_info, None);

        trace.attach_ethdebug(&counter_artifacts()).expect("attach");
        let info = trace.summary().debug_info.expect("debug info");
        assert_eq!(info.contract, "Counter");
        assert_eq!(
            info.sources,
            BTreeMap::from([(0, "Counter.sol".to_owned())])
        );
        assert_eq!(info.instructions, 3);
        assert_eq!(info.pcs_with_variables, 1);
    }

    #[test]
    fn summary_json_uses_camel_case_and_round_trips() {
        let mut trace = trace();
        trace.attach_ethdebug(&counter_artifacts()).expect("attach");

        let json = trace.summary_json().expect("summary");
        let value = document(&json);
        assert_eq!(value["txHash"], "0xabc");
        assert_eq!(value["gasUsed"], 21000);
        assert_eq!(value["stepCount"], 3);
        assert_eq!(value["inputData"], trace.session().trace.input_data);
        assert_eq!(value["debugInfo"]["contract"], "Counter");
        assert_eq!(value["debugInfo"]["pcsWithVariables"], 1);
        assert_eq!(value["capabilities"]["opcode_steps"], true);

        let parsed: TraceSummary = serde_json::from_str(&json).expect("summary round trip");
        assert_eq!(parsed, trace.summary());
    }

    #[test]
    fn web_document_without_contracts_matches_the_serializer() {
        let trace = trace();
        let json = trace.to_web_json(None).expect("web JSON");

        let expected = soldb_serializer::trace_to_web_json_with_contracts(
            &trace.session().trace,
            BTreeMap::new(),
        )
        .expect("serializer");
        assert_eq!(json, expected);

        let value = document(&json);
        assert_eq!(
            value["schemaVersion"],
            soldb_serializer::WEB_JSON_SCHEMA_VERSION
        );
        assert_eq!(value["status"], "success");
        assert_eq!(value["backend"], "debug-rpc");
        assert_eq!(value["steps"].as_array().map(Vec::len), Some(3));
        assert_eq!(value["contracts"], json!({}));
    }

    #[test]
    fn web_document_treats_blank_contracts_as_none() {
        let trace = trace();
        let expected = trace.to_web_json(None).expect("web JSON");
        assert_eq!(trace.to_web_json(Some("")).expect("empty"), expected);
        assert_eq!(trace.to_web_json(Some("   \n")).expect("blank"), expected);
    }

    #[test]
    fn web_document_fills_the_contracts_section_from_artifacts() {
        let trace = trace();
        let contracts = json!({
            "0xABCDEF": artifacts(false, Some(json!({"0": SOURCE}))),
            "0x2": artifacts(true, None)
        })
        .to_string();

        let value = document(&trace.to_web_json(Some(&contracts)).expect("web JSON"));
        let statement = SOURCE.find("count += 1").expect("offset");

        // Keys are lowercased, exactly as the CLI keys `--ethdebug-dir` addresses.
        let contract = &value["contracts"]["0xabcdef"];
        assert_eq!(
            contract["pcToSourceMappings"],
            json!({"0": format!("0:{}:0", SOURCE.len()), "2": format!("{statement}:10:0")})
        );
        assert_eq!(contract["sourcePaths"], json!({"0": "Counter.sol"}));
        assert_eq!(contract["sources"]["0"], SOURCE);
        assert_eq!(contract["debugAvailable"], true);
        assert_eq!(contract["abi"][0]["name"], "increment");

        // Sources embedded in the metadata serve a contract the host gave no sources for.
        assert_eq!(value["contracts"]["0x2"]["sources"]["0"], SOURCE);
        assert_eq!(value["contracts"].as_object().map(|map| map.len()), Some(2));
    }

    #[test]
    fn web_document_contracts_match_the_serializer_projection() {
        let mut trace = trace();
        trace.attach_ethdebug(&counter_artifacts()).expect("attach");
        let contracts = json!({"0x2": artifacts(false, Some(json!({"0": SOURCE})))}).to_string();

        let session = trace.session();
        let expected = soldb_serializer::WebContractMetadata::from_ethdebug(
            session.ethdebug.as_ref().expect("info"),
            &session.source_contents,
            Some(json!([{"type": "function", "name": "increment", "inputs": [], "outputs": []}])),
        );
        let value = document(&trace.to_web_json(Some(&contracts)).expect("web JSON"));

        assert_eq!(
            value["contracts"]["0x2"],
            serde_json::to_value(&expected).expect("metadata value")
        );
    }

    #[test]
    fn web_document_leaves_out_contracts_with_nothing_to_report() {
        let trace = trace();
        let contracts = json!({
            "0x1": {"name": "Bare", "metadata": {}, "program": {}},
            "0x2": {"name": "AbiOnly", "metadata": {}, "program": {}, "abi": []}
        })
        .to_string();

        let value = document(&trace.to_web_json(Some(&contracts)).expect("web JSON"));

        assert_eq!(value["contracts"].as_object().map(|map| map.len()), Some(1));
        assert_eq!(value["contracts"]["0x2"]["debugAvailable"], false);
        assert_eq!(value["contracts"]["0x2"]["abi"], json!([]));
    }

    #[test]
    fn web_document_names_malformed_contracts() {
        let trace = trace();

        let error = trace.to_web_json(Some("[1]")).expect_err("not a map");
        assert!(
            error.to_string().contains("invalid contracts JSON"),
            "{error}"
        );

        let broken = json!({"0x1": {"name": "Broken", "metadata": {}, "program": {"instructions": [{"operation": {}}]}}});
        let error = trace
            .to_web_json(Some(&broken.to_string()))
            .expect_err("malformed program inside contracts");
        assert!(error.to_string().starts_with("contract `0x1`:"), "{error}");
        assert!(error.to_string().contains("`instructions`"), "{error}");
    }

    #[test]
    fn simulation_web_document_carries_the_function_name_and_contracts() {
        let trace = trace();
        let contracts = json!({"0x2": artifacts(true, None)}).to_string();

        let value = document(
            &trace
                .to_simulation_web_json("increment", Some(&contracts))
                .expect("web JSON"),
        );
        assert_eq!(
            value["schemaVersion"],
            soldb_serializer::WEB_JSON_SCHEMA_VERSION
        );
        assert_eq!(value["status"], "success");
        assert_eq!(value["function_name"], "increment");
        assert_eq!(value["contracts"]["0x2"]["debugAvailable"], true);

        let expected = soldb_serializer::simulate_to_web_json_with_contracts(
            &trace.session().trace,
            "increment",
            BTreeMap::new(),
        )
        .expect("serializer");
        assert_eq!(
            trace
                .to_simulation_web_json("increment", None)
                .expect("web JSON"),
            expected
        );
    }

    #[test]
    fn names_the_malformed_constructor_argument() {
        let error = Trace::from_transaction("{", &transaction_json(), &receipt_json())
            .expect_err("malformed debug trace");
        assert!(
            error
                .to_string()
                .contains("`debug_traceTransaction` result"),
            "{error}"
        );

        let error = Trace::from_transaction(&debug_trace_json(), "[]", &receipt_json())
            .expect_err("malformed transaction");
        assert!(
            error
                .to_string()
                .contains("`eth_getTransactionByHash` result"),
            "{error}"
        );

        let error = Trace::from_transaction(&debug_trace_json(), &transaction_json(), "null")
            .expect_err("malformed receipt");
        assert!(
            error
                .to_string()
                .contains("`eth_getTransactionReceipt` result"),
            "{error}"
        );

        let error = Trace::from_simulation("0x1", "0x2", "0x", "0x0", "nope")
            .expect_err("malformed call trace");
        assert!(
            error.to_string().contains("`debug_traceCall` result"),
            "{error}"
        );

        let error = Trace::from_json("not json").expect_err("malformed trace");
        assert!(error.to_string().contains("invalid trace JSON"), "{error}");
    }
}
