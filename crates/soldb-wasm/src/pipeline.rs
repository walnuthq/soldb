//! JSON-in, JSON-out entry points behind the WebAssembly exports.
//!
//! Every function here takes the node's or the compiler's output as strings and returns
//! a string, so the same logic runs natively under `cargo test` and behind the
//! `wasm-bindgen` glue in the crate root. Keeping the bindings that thin is what lets
//! this code count toward native coverage, and it is why nothing here depends on a
//! `wasm-bindgen` type.
//!
//! A WebAssembly host has neither network nor filesystem, and the node is the execution
//! oracle, so the host fetches the JSON-RPC responses and the ETHDebug artifacts itself
//! and hands them over as strings. What comes out is the same
//! [`TransactionTrace`] and the same web document the CLI produces from the same inputs.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_debugger::DebugSession;
use soldb_ethdebug::{read_compilation_source, EthdebugInfo};
use soldb_rpc::{DebugTraceResult, RpcReceipt, RpcTransaction, SimulateCallRequest};
use soldb_serializer::WebContractMetadata;

/// One contract's compiler output, as the host supplies it.
///
/// This is the JSON shape behind every export that takes debug info: one object opens a
/// source-level debug session, and a map from contract address to one of these fills the
/// `contracts` section of the web document.
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

/// The debug info and source contents a set of artifacts describes.
struct LoadedArtifacts {
    info: EthdebugInfo,
    sources: BTreeMap<u64, String>,
    abi: Option<Value>,
}

/// Parses one JSON argument, naming it in the error so a caller with several string
/// arguments can tell which one was malformed.
fn parse_json<T: DeserializeOwned>(what: &str, input: &str) -> SoldbResult<T> {
    serde_json::from_str(input)
        .map_err(|error| SoldbError::Message(format!("invalid {what} JSON: {error}")))
}

fn to_json<T: serde::Serialize>(value: &T) -> SoldbResult<String> {
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

/// Builds a `debug-rpc` trace from the `result` fields of the node's responses to
/// `debug_traceTransaction`, `eth_getTransactionByHash`, and
/// `eth_getTransactionReceipt`.
///
/// Returns the [`TransactionTrace`] serialized as JSON, which is what every other entry
/// point here accepts as a trace.
pub fn build_transaction_trace(
    debug_trace_json: &str,
    transaction_json: &str,
    receipt_json: &str,
) -> SoldbResult<String> {
    let debug_result =
        parse_json::<DebugTraceResult>("`debug_traceTransaction` result", debug_trace_json)?;
    let transaction =
        parse_json::<RpcTransaction>("`eth_getTransactionByHash` result", transaction_json)?;
    let receipt = parse_json::<RpcReceipt>("`eth_getTransactionReceipt` result", receipt_json)?;
    let trace = soldb_rpc::debug_rpc_transaction_trace(transaction, receipt, &debug_result)?;
    to_json(&trace)
}

/// Builds the trace of a simulated call from the call that was sent and the `result`
/// field of the node's `debug_traceCall` response.
///
/// `value` accepts the same forms as `soldb simulate --value`: a hex quantity, a decimal
/// wei amount, or an ether amount with a unit suffix.
pub fn build_simulation_trace(
    from: &str,
    to: &str,
    calldata: &str,
    value: &str,
    debug_trace_json: &str,
) -> SoldbResult<String> {
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
    to_json(&trace)
}

/// Renders a trace as the versioned web document specified in `docs/json.md`.
///
/// `contracts_json` maps contract address to [`ContractArtifacts`] and fills the
/// document's `contracts` section the way `--ethdebug-dir` does for the CLI; `None` or an
/// empty string leaves it empty.
pub fn trace_to_web_json(trace_json: &str, contracts_json: Option<&str>) -> SoldbResult<String> {
    let trace = parse_json::<TransactionTrace>("trace", trace_json)?;
    let contracts = web_contracts(contracts_json)?;
    soldb_serializer::trace_to_web_json_with_contracts(&trace, contracts)
}

/// Renders a simulation trace as the versioned web document, as `soldb simulate --json`
/// does. `contracts_json` is as for [`trace_to_web_json`].
pub fn simulate_to_web_json(
    trace_json: &str,
    function_name: &str,
    contracts_json: Option<&str>,
) -> SoldbResult<String> {
    let trace = parse_json::<TransactionTrace>("trace", trace_json)?;
    let contracts = web_contracts(contracts_json)?;
    soldb_serializer::simulate_to_web_json_with_contracts(&trace, function_name, contracts)
}

/// Opens a debug session over a trace with no debug info: steps carry opcode-level state
/// and no source spans.
pub fn open_session(trace_json: &str) -> SoldbResult<DebugSession> {
    let trace = parse_json::<TransactionTrace>("trace", trace_json)?;
    Ok(DebugSession::new(trace))
}

/// Opens a source-level debug session over a trace from one contract's
/// [`ContractArtifacts`].
pub fn open_session_with_ethdebug(
    trace_json: &str,
    artifacts_json: &str,
) -> SoldbResult<DebugSession> {
    let trace = parse_json::<TransactionTrace>("trace", trace_json)?;
    let artifacts = parse_json::<ContractArtifacts>("contract artifacts", artifacts_json)?;
    let loaded = load_artifacts(artifacts)?;
    Ok(DebugSession::with_ethdebug(
        trace,
        loaded.info,
        loaded.sources,
    ))
}

/// Serializes one step of a session, or returns `None` past the end of the trace.
pub fn step_json(session: &DebugSession, index: usize) -> SoldbResult<Option<String>> {
    session.step(index).map(|step| to_json(&step)).transpose()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use soldb_core::TransactionTrace;
    use soldb_debugger::DebugStep;

    use super::{
        build_simulation_trace, build_transaction_trace, open_session, open_session_with_ethdebug,
        simulate_to_web_json, step_json, trace_to_web_json,
    };

    const SOURCE: &str = "contract Counter {\n    uint256 public count;\n\n    function increment() public {\n        count += 1;\n    }\n}\n";

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
            "input": "0xd09de08a"
        })
        .to_string()
    }

    fn receipt_json() -> String {
        json!({
            "gasUsed": "0x5208",
            "status": "0x1",
            "contractAddress": null,
            "logs": []
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
        // Offset 95 is `count += 1;` inside `increment`; offset 0 is the whole file.
        json!({
            "environment": "runtime",
            "instructions": [
                {
                    "offset": 0,
                    "operation": {"mnemonic": "PUSH1", "arguments": ["0x80"]},
                    "context": {"code": {"source": {"id": 0}, "range": {"offset": 0, "length": 110}}}
                },
                {
                    "offset": 2,
                    "operation": {"mnemonic": "MSTORE"},
                    "context": {"code": {"source": {"id": 0}, "range": {"offset": 95, "length": 10}}}
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

    fn built_trace() -> String {
        build_transaction_trace(&debug_trace_json(), &transaction_json(), &receipt_json())
            .expect("trace")
    }

    fn step_at(session: &soldb_debugger::DebugSession, index: usize) -> DebugStep {
        serde_json::from_str(&step_json(session, index).expect("step").expect("in range"))
            .expect("step JSON")
    }

    #[test]
    fn builds_a_transaction_trace_from_node_responses() {
        let trace: TransactionTrace = serde_json::from_str(&built_trace()).expect("trace JSON");

        assert_eq!(trace.tx_hash.as_deref(), Some("0xabc"));
        assert_eq!(trace.from_addr, "0x1");
        assert_eq!(trace.to_addr.as_deref(), Some("0x2"));
        assert_eq!(trace.input_data, "0xd09de08a");
        assert_eq!(trace.gas_used, 21000);
        assert!(trace.success);
        assert_eq!(trace.backend.as_deref(), Some("debug-rpc"));
        assert!(trace.capabilities.opcode_steps);
        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.steps[1].memory.as_deref(), Some("aabb"));
    }

    #[test]
    fn builds_a_simulation_trace_from_the_call_and_its_result() {
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

        let trace_json =
            build_simulation_trace("0x1", "0x2", "0xd09de08a", "0x0", &debug_trace).expect("trace");
        let trace: TransactionTrace = serde_json::from_str(&trace_json).expect("trace JSON");

        assert_eq!(trace.tx_hash, None);
        assert_eq!(trace.to_addr.as_deref(), Some("0x2"));
        assert_eq!(trace.output, "0x2a");
        assert_eq!(trace.gas_used, 42000);
        assert!(trace.success);
        assert_eq!(trace.steps.len(), 2);
    }

    #[test]
    fn renders_the_versioned_web_documents_without_contracts() {
        let document: Value =
            serde_json::from_str(&trace_to_web_json(&built_trace(), None).expect("web JSON"))
                .expect("document");
        assert_eq!(
            document["schemaVersion"],
            soldb_serializer::WEB_JSON_SCHEMA_VERSION
        );
        assert_eq!(document["status"], "success");
        assert_eq!(document["backend"], "debug-rpc");
        assert_eq!(document["steps"].as_array().map(Vec::len), Some(3));
        assert_eq!(document["contracts"], json!({}));

        let document: Value = serde_json::from_str(
            &simulate_to_web_json(&built_trace(), "increment", Some("")).expect("web JSON"),
        )
        .expect("document");
        assert_eq!(
            document["schemaVersion"],
            soldb_serializer::WEB_JSON_SCHEMA_VERSION
        );
        assert_eq!(document["status"], "success");
        assert_eq!(document["contracts"], json!({}));
    }

    #[test]
    fn fills_the_contracts_section_from_artifacts() {
        let contracts = json!({
            "0xABCDEF": artifacts(false, Some(json!({"0": SOURCE}))),
            "0x2": artifacts(true, None)
        })
        .to_string();

        let document: Value = serde_json::from_str(
            &trace_to_web_json(&built_trace(), Some(&contracts)).expect("web JSON"),
        )
        .expect("document");

        // Keys are lowercased, exactly as the CLI keys `--ethdebug-dir` addresses.
        let contract = &document["contracts"]["0xabcdef"];
        assert_eq!(
            contract["pcToSourceMappings"],
            json!({"0": "0:110:0", "2": "95:10:0"})
        );
        assert_eq!(contract["sourcePaths"], json!({"0": "Counter.sol"}));
        assert_eq!(contract["sources"]["0"], SOURCE);
        assert_eq!(contract["debugAvailable"], true);
        assert_eq!(contract["abi"][0]["name"], "increment");

        // Sources embedded in the metadata serve a contract the host gave no sources for.
        assert_eq!(document["contracts"]["0x2"]["sources"]["0"], SOURCE);

        let document: Value = serde_json::from_str(
            &simulate_to_web_json(&built_trace(), "increment", Some(&contracts)).expect("web JSON"),
        )
        .expect("document");
        assert_eq!(document["contracts"]["0x2"]["debugAvailable"], true);
    }

    #[test]
    fn leaves_out_contracts_with_nothing_to_report() {
        let contracts = json!({
            "0x1": {"name": "Bare", "metadata": {}, "program": {}},
            "0x2": {"name": "AbiOnly", "metadata": {}, "program": {}, "abi": []}
        })
        .to_string();

        let document: Value = serde_json::from_str(
            &trace_to_web_json(&built_trace(), Some(&contracts)).expect("web JSON"),
        )
        .expect("document");

        assert_eq!(
            document["contracts"].as_object().map(|map| map.len()),
            Some(1)
        );
        assert_eq!(document["contracts"]["0x2"]["debugAvailable"], false);
        assert_eq!(document["contracts"]["0x2"]["abi"], json!([]));
    }

    #[test]
    fn opens_a_session_without_debug_info() {
        let session = open_session(&built_trace()).expect("session");

        assert_eq!(session.trace.steps.len(), 3);
        assert!(session.ethdebug.is_none());
        let step = step_at(&session, 1);
        assert_eq!(step.pc, 2);
        assert_eq!(step.op, "MSTORE");
        assert_eq!(step.source, None);
        assert_eq!(step.snapshot.stack, ["0x80", "0x40"]);
        assert_eq!(step_json(&session, 3).expect("step"), None);
    }

    #[test]
    fn opens_a_source_level_session_from_artifacts_and_sources() {
        let artifacts = artifacts(false, Some(json!({"0": SOURCE}))).to_string();
        let session = open_session_with_ethdebug(&built_trace(), &artifacts).expect("session");

        let info = session.ethdebug.as_ref().expect("ethdebug attached");
        assert_eq!(info.contract_name, "Counter");
        assert_eq!(info.sources[&0], "Counter.sol");

        let step = step_at(&session, 1);
        let span = step.source.expect("source span");
        assert_eq!(span.path, "Counter.sol");
        assert_eq!(span.offset, 95);
        assert_eq!(span.line, 5);
        assert_eq!(
            step.function
                .as_ref()
                .map(|function| function.name.as_str()),
            Some("increment")
        );
        assert_eq!(step.variables, Vec::new());

        assert_eq!(step_at(&session, 2).source, None);
    }

    #[test]
    fn falls_back_to_sources_embedded_in_the_metadata() {
        let artifacts = artifacts(true, None).to_string();
        let session = open_session_with_ethdebug(&built_trace(), &artifacts).expect("session");

        assert_eq!(session.source_contents[&0], SOURCE);
        assert_eq!(step_at(&session, 1).source.map(|span| span.line), Some(5));
    }

    #[test]
    fn explicit_sources_take_precedence_over_embedded_ones() {
        let artifacts = artifacts(true, Some(json!({"0": "contract Other {}"}))).to_string();
        let session = open_session_with_ethdebug(&built_trace(), &artifacts).expect("session");

        assert_eq!(session.source_contents[&0], "contract Other {}");
    }

    #[test]
    fn names_the_malformed_argument() {
        let error = build_transaction_trace("{", &transaction_json(), &receipt_json())
            .expect_err("malformed debug trace");
        assert!(
            error
                .to_string()
                .contains("`debug_traceTransaction` result"),
            "{error}"
        );

        let error = build_transaction_trace(&debug_trace_json(), "[]", &receipt_json())
            .expect_err("malformed transaction");
        assert!(
            error
                .to_string()
                .contains("`eth_getTransactionByHash` result"),
            "{error}"
        );

        let error = build_transaction_trace(&debug_trace_json(), &transaction_json(), "null")
            .expect_err("malformed receipt");
        assert!(
            error
                .to_string()
                .contains("`eth_getTransactionReceipt` result"),
            "{error}"
        );

        let error = trace_to_web_json("not json", None).expect_err("malformed trace");
        assert!(error.to_string().contains("invalid trace JSON"), "{error}");

        let error =
            trace_to_web_json(&built_trace(), Some("[1]")).expect_err("malformed contracts");
        assert!(
            error.to_string().contains("invalid contracts JSON"),
            "{error}"
        );

        let broken = json!({"0x1": {"name": "Broken", "metadata": {}, "program": {"instructions": [{"operation": {}}]}}});
        let error = trace_to_web_json(&built_trace(), Some(&broken.to_string()))
            .expect_err("malformed program inside contracts");
        assert!(error.to_string().starts_with("contract `0x1`:"), "{error}");
        assert!(error.to_string().contains("`instructions`"), "{error}");

        let error = open_session_with_ethdebug(&built_trace(), "{\"name\": \"Counter\"}")
            .expect_err("artifacts missing fields");
        assert!(
            error
                .to_string()
                .contains("invalid contract artifacts JSON"),
            "{error}"
        );

        let sources_not_a_map = artifacts(false, Some(json!([1, 2]))).to_string();
        let error = open_session_with_ethdebug(&built_trace(), &sources_not_a_map)
            .expect_err("malformed sources");
        assert!(
            error
                .to_string()
                .contains("invalid contract artifacts JSON"),
            "{error}"
        );
    }
}
