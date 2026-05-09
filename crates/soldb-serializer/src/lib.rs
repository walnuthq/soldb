use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::json;
use soldb_core::{
    ContractCreation, ExecutionCall, SoldbResult, TraceArtifacts, TraceCapabilities,
    TransactionTrace,
};

pub const WEB_JSON_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct WebContractMetadata {
    #[serde(rename = "pcToSourceMappings")]
    pub pc_to_source_mappings: BTreeMap<u64, String>,
    #[serde(rename = "sourcePaths")]
    pub source_paths: BTreeMap<u64, String>,
    pub sources: BTreeMap<u64, String>,
    #[serde(rename = "debugAvailable")]
    pub debug_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<serde_json::Value>,
}

pub fn trace_to_json(trace: &TransactionTrace) -> SoldbResult<String> {
    serde_json::to_string_pretty(trace)
        .map_err(|err| soldb_core::SoldbError::Message(err.to_string()))
}

pub fn trace_to_web_json(trace: &TransactionTrace) -> SoldbResult<String> {
    trace_to_web_json_with_contracts(trace, BTreeMap::new())
}

pub fn trace_to_web_json_with_contracts(
    trace: &TransactionTrace,
    contracts: BTreeMap<String, WebContractMetadata>,
) -> SoldbResult<String> {
    let response = TraceWebResponse {
        schema_version: WEB_JSON_SCHEMA_VERSION,
        status: if trace.success { "success" } else { "reverted" },
        error: trace.error.as_deref(),
        backend: trace.backend.as_deref(),
        capabilities: &trace.capabilities,
        artifacts: &trace.artifacts,
        trace_call: trace_call_for_trace(trace),
        steps: web_steps(trace),
        contracts,
    };

    serde_json::to_string_pretty(&response)
        .map_err(|err| soldb_core::SoldbError::Message(err.to_string()))
}

pub fn simulate_to_web_json(trace: &TransactionTrace, function_name: &str) -> SoldbResult<String> {
    simulate_to_web_json_with_contracts(trace, function_name, BTreeMap::new())
}

pub fn simulate_to_web_json_with_contracts(
    trace: &TransactionTrace,
    function_name: &str,
    contracts: BTreeMap<String, WebContractMetadata>,
) -> SoldbResult<String> {
    let response = SimulateWebResponse {
        schema_version: WEB_JSON_SCHEMA_VERSION,
        status: if trace.success { "success" } else { "reverted" },
        error: trace.error.as_deref(),
        backend: trace.backend.as_deref(),
        capabilities: &trace.capabilities,
        artifacts: &trace.artifacts,
        trace_call: trace_call_for_simulation(trace, function_name),
        steps: web_steps(trace),
        function_name,
        is_verified: false,
        contracts,
    };

    serde_json::to_string_pretty(&response)
        .map_err(|err| soldb_core::SoldbError::Message(err.to_string()))
}

fn web_steps(trace: &TransactionTrace) -> Vec<serde_json::Value> {
    let ranges = artifact_step_ranges(&trace.artifacts);
    trace
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            json!({
                "step": index,
                "pc": step.pc,
                "traceCallIndex": trace_call_index_for_step(index, &ranges).unwrap_or(0),
                "op": step.op,
                "gas": step.gas,
                "gasCost": step.gas_cost,
                "depth": step.depth,
                "stack": step.stack,
                "snapshot": step.normalized_snapshot(),
            })
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct TraceCallWeb {
    #[serde(rename = "type")]
    ty: String,
    #[serde(rename = "callId")]
    call_id: u64,
    #[serde(rename = "parentCallId", skip_serializing_if = "Option::is_none")]
    parent_call_id: Option<u64>,
    #[serde(rename = "childrenCallIds")]
    children_call_ids: Vec<u64>,
    #[serde(rename = "functionName", skip_serializing_if = "Option::is_none")]
    function_name: Option<String>,
    from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    value: String,
    gas: u64,
    #[serde(rename = "gasUsed")]
    gas_used: u64,
    input: String,
    output: String,
    #[serde(rename = "isRevertedFrame")]
    is_reverted_frame: bool,
    calls: Vec<TraceCallWeb>,
}

fn trace_call_for_trace(trace: &TransactionTrace) -> TraceCallWeb {
    trace_call_from_artifacts(trace).unwrap_or_else(|| {
        fallback_trace_call(
            trace,
            if trace.contract_address.is_some() {
                "CREATE"
            } else {
                "CALL"
            },
            Some("runtime_dispatcher"),
        )
    })
}

fn trace_call_for_simulation(trace: &TransactionTrace, function_name: &str) -> TraceCallWeb {
    trace_call_from_artifacts(trace)
        .unwrap_or_else(|| fallback_trace_call(trace, "ENTRY", Some(function_name)))
}

fn fallback_trace_call(
    trace: &TransactionTrace,
    ty: &str,
    function_name: Option<&str>,
) -> TraceCallWeb {
    TraceCallWeb {
        ty: ty.to_owned(),
        call_id: 0,
        parent_call_id: None,
        children_call_ids: Vec::new(),
        function_name: function_name.map(str::to_owned),
        from: trace.from_addr.clone(),
        to: trace
            .to_addr
            .clone()
            .or_else(|| trace.contract_address.clone()),
        value: trace.value.clone(),
        gas: trace.steps.first().map_or(0, |step| step.gas),
        gas_used: trace.gas_used,
        input: trace.input_data.clone(),
        output: trace.output.clone(),
        is_reverted_frame: !trace.success,
        calls: Vec::new(),
    }
}

#[derive(Debug, Clone)]
struct ArtifactCallNode {
    ty: String,
    call_id: u64,
    parent_call_id: Option<u64>,
    from: String,
    to: Option<String>,
    value: String,
    gas: u64,
    gas_used: u64,
    input: String,
    output: String,
    is_reverted_frame: bool,
}

fn trace_call_from_artifacts(trace: &TransactionTrace) -> Option<TraceCallWeb> {
    let nodes = artifact_call_nodes(trace);
    let root_id = nodes
        .iter()
        .find(|node| node.parent_call_id.is_none())
        .or_else(|| nodes.first())
        .map(|node| node.call_id)?;
    let by_id = nodes
        .into_iter()
        .map(|node| (node.call_id, node))
        .collect::<BTreeMap<_, _>>();
    Some(build_trace_call_node(root_id, &by_id))
}

fn build_trace_call_node(call_id: u64, by_id: &BTreeMap<u64, ArtifactCallNode>) -> TraceCallWeb {
    let node = by_id
        .get(&call_id)
        .expect("trace call tree references a missing node");
    let child_ids = by_id
        .values()
        .filter(|candidate| candidate.parent_call_id == Some(call_id))
        .map(|candidate| candidate.call_id)
        .collect::<Vec<_>>();
    let calls = child_ids
        .iter()
        .map(|child_id| build_trace_call_node(*child_id, by_id))
        .collect();
    TraceCallWeb {
        ty: node.ty.clone(),
        call_id: node.call_id,
        parent_call_id: node.parent_call_id,
        children_call_ids: child_ids,
        function_name: None,
        from: node.from.clone(),
        to: node.to.clone(),
        value: node.value.clone(),
        gas: node.gas,
        gas_used: node.gas_used,
        input: node.input.clone(),
        output: node.output.clone(),
        is_reverted_frame: node.is_reverted_frame,
        calls,
    }
}

fn artifact_call_nodes(trace: &TransactionTrace) -> Vec<ArtifactCallNode> {
    let call_nodes = trace
        .artifacts
        .calls
        .iter()
        .map(call_node)
        .collect::<Vec<_>>();
    let creation_base = call_nodes
        .iter()
        .map(|node| node.call_id)
        .max()
        .map_or(0, |call_id| call_id + 1);
    let creation_nodes = trace
        .artifacts
        .creations
        .iter()
        .map(|creation| creation_node(creation, creation_base));
    call_nodes.into_iter().chain(creation_nodes).collect()
}

fn call_node(call: &ExecutionCall) -> ArtifactCallNode {
    ArtifactCallNode {
        ty: call.call_type.to_ascii_uppercase(),
        call_id: call.id as u64,
        parent_call_id: call.parent_id.map(|id| id as u64),
        from: call.from.clone(),
        to: Some(call.to.clone()),
        value: call.value.clone(),
        gas: call.gas_limit,
        gas_used: call.gas_used.unwrap_or(0),
        input: call.input.clone(),
        output: call.output.clone().unwrap_or_else(|| "0x".to_owned()),
        is_reverted_frame: call.success == Some(false) || call.error.is_some(),
    }
}

fn creation_node(creation: &ContractCreation, base_call_id: u64) -> ArtifactCallNode {
    ArtifactCallNode {
        ty: creation.create_type.to_ascii_uppercase(),
        call_id: base_call_id + creation.id as u64,
        parent_call_id: creation.parent_id.map(|id| id as u64),
        from: creation.caller.clone(),
        to: creation.address.clone(),
        value: creation.value.clone(),
        gas: creation.gas_limit,
        gas_used: creation.gas_used.unwrap_or(0),
        input: creation.init_code.clone(),
        output: creation.output.clone().unwrap_or_else(|| "0x".to_owned()),
        is_reverted_frame: creation.success == Some(false) || creation.error.is_some(),
    }
}

#[derive(Debug, Clone, Copy)]
struct ArtifactStepRange {
    call_id: u64,
    depth: u64,
    entry_step: usize,
    exit_step: Option<usize>,
}

fn artifact_step_ranges(artifacts: &TraceArtifacts) -> Vec<ArtifactStepRange> {
    let call_ranges = artifacts.calls.iter().filter_map(|call| {
        Some(ArtifactStepRange {
            call_id: call.id as u64,
            depth: call.depth,
            entry_step: call.entry_step?,
            exit_step: call.exit_step,
        })
    });
    let creation_base = artifacts
        .calls
        .iter()
        .map(|call| call.id as u64)
        .max()
        .map_or(0, |call_id| call_id + 1);
    let creation_ranges = artifacts.creations.iter().filter_map(|creation| {
        Some(ArtifactStepRange {
            call_id: creation_base + creation.id as u64,
            depth: creation.depth,
            entry_step: creation.entry_step?,
            exit_step: creation.exit_step,
        })
    });
    call_ranges.chain(creation_ranges).collect()
}

fn trace_call_index_for_step(step_index: usize, ranges: &[ArtifactStepRange]) -> Option<u64> {
    ranges
        .iter()
        .filter(|range| {
            range.entry_step <= step_index && range.exit_step.is_none_or(|exit| step_index < exit)
        })
        .max_by_key(|range| (range.depth, range.entry_step))
        .map(|range| range.call_id)
}

#[derive(Debug, Serialize)]
struct TraceWebResponse<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    status: &'static str,
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<&'a str>,
    capabilities: &'a TraceCapabilities,
    artifacts: &'a TraceArtifacts,
    #[serde(rename = "traceCall")]
    trace_call: TraceCallWeb,
    steps: Vec<serde_json::Value>,
    contracts: BTreeMap<String, WebContractMetadata>,
}

#[derive(Debug, Serialize)]
struct SimulateWebResponse<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    status: &'static str,
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<&'a str>,
    capabilities: &'a TraceCapabilities,
    artifacts: &'a TraceArtifacts,
    #[serde(rename = "traceCall")]
    trace_call: TraceCallWeb,
    steps: Vec<serde_json::Value>,
    function_name: &'a str,
    #[serde(rename = "isVerified")]
    is_verified: bool,
    contracts: BTreeMap<String, WebContractMetadata>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use soldb_core::{ExecutionCall, TraceArtifacts, TraceStep, TransactionTrace};

    use super::{
        simulate_to_web_json, trace_to_web_json, trace_to_web_json_with_contracts,
        WebContractMetadata,
    };

    #[test]
    fn serializes_trace_to_web_shape() {
        let trace = sample_trace();

        let json = trace_to_web_json(&trace).expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        assert!(json.contains("\"status\": \"success\""));
        assert!(json.contains("\"traceCall\""));
        assert!(json.contains("\"gasUsed\": 21000"));
        assert!(json.contains("\"contracts\""));
        assert!(json.contains("\"snapshot\""));
        assert!(json.contains("\"backend\": \"debug-rpc\""));
        assert!(json.contains("\"capabilities\""));
        assert!(json.contains("\"artifacts\""));
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["error"], serde_json::Value::Null);
        assert_eq!(value["traceCall"]["callId"], 0);
        assert_eq!(value["traceCall"]["functionName"], "runtime_dispatcher");
        assert_eq!(value["traceCall"]["childrenCallIds"], serde_json::json!([]));
        assert_eq!(value["traceCall"]["calls"], serde_json::json!([]));
        assert_eq!(value["steps"][0]["traceCallIndex"], 0);
    }

    #[test]
    fn serializes_simulation_to_web_shape() {
        let trace = sample_trace();

        let json = simulate_to_web_json(&trace, "raw_data").expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        assert!(json.contains("\"type\": \"ENTRY\""));
        assert!(json.contains("\"callId\": 0"));
        assert!(json.contains("\"function_name\": \"raw_data\""));
        assert!(json.contains("\"isVerified\": false"));
        assert!(json.contains("\"backend\": \"debug-rpc\""));
        assert!(json.contains("\"capabilities\""));
        assert!(json.contains("\"artifacts\""));
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["traceCall"]["functionName"], "raw_data");
        assert_eq!(value["steps"][0]["traceCallIndex"], 0);
    }

    #[test]
    fn serializes_nested_artifact_calls_and_step_indexes() {
        let mut trace = sample_trace();
        trace.artifacts = TraceArtifacts {
            calls: vec![
                ExecutionCall {
                    id: 0,
                    parent_id: None,
                    depth: 0,
                    entry_step: Some(0),
                    exit_step: Some(3),
                    call_type: "call".to_owned(),
                    from: "0x1".to_owned(),
                    to: "0x2".to_owned(),
                    bytecode_address: "0x2".to_owned(),
                    value: "0x0".to_owned(),
                    input: "0x1234".to_owned(),
                    gas_limit: 100,
                    gas_used: Some(80),
                    output: Some("0x".to_owned()),
                    success: Some(true),
                    error: None,
                },
                ExecutionCall {
                    id: 1,
                    parent_id: Some(0),
                    depth: 1,
                    entry_step: Some(1),
                    exit_step: Some(2),
                    call_type: "delegatecall".to_owned(),
                    from: "0x2".to_owned(),
                    to: "0x3".to_owned(),
                    bytecode_address: "0x3".to_owned(),
                    value: "0x0".to_owned(),
                    input: "0xabcdef".to_owned(),
                    gas_limit: 50,
                    gas_used: Some(20),
                    output: Some("0x01".to_owned()),
                    success: Some(true),
                    error: None,
                },
            ],
            ..Default::default()
        };
        trace.steps.push(TraceStep {
            pc: 1,
            op: "CALL".to_owned(),
            gas: 90,
            gas_cost: 40,
            depth: 0,
            stack: Vec::new(),
            memory: None,
            storage: None,
            error: None,
            snapshot: Default::default(),
        });
        trace.steps.push(TraceStep {
            pc: 2,
            op: "STOP".to_owned(),
            gas: 50,
            gas_cost: 0,
            depth: 0,
            stack: Vec::new(),
            memory: None,
            storage: None,
            error: None,
            snapshot: Default::default(),
        });

        let json = trace_to_web_json(&trace).expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        assert_eq!(value["traceCall"]["callId"], 0);
        assert_eq!(
            value["traceCall"]["childrenCallIds"],
            serde_json::json!([1])
        );
        assert_eq!(value["traceCall"]["calls"][0]["callId"], 1);
        assert_eq!(value["traceCall"]["calls"][0]["type"], "DELEGATECALL");
        assert_eq!(value["steps"][0]["traceCallIndex"], 0);
        assert_eq!(value["steps"][1]["traceCallIndex"], 1);
        assert_eq!(value["steps"][2]["traceCallIndex"], 0);
    }

    #[test]
    fn serializes_contract_debug_payload() {
        let trace = sample_trace();
        let mut contracts = BTreeMap::new();
        contracts.insert(
            "0x2".to_owned(),
            WebContractMetadata {
                pc_to_source_mappings: BTreeMap::from([(10, "4:8:0".to_owned())]),
                source_paths: BTreeMap::from([(0, "Counter.sol".to_owned())]),
                sources: BTreeMap::from([(0, "contract Counter {}".to_owned())]),
                debug_available: true,
                abi: Some(serde_json::json!([
                    {"type": "function", "name": "set", "inputs": []}
                ])),
            },
        );

        let json = trace_to_web_json_with_contracts(&trace, contracts).expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        assert_eq!(
            value["contracts"]["0x2"]["pcToSourceMappings"]["10"],
            "4:8:0"
        );
        assert_eq!(
            value["contracts"]["0x2"]["sources"]["0"],
            "contract Counter {}"
        );
        assert_eq!(value["contracts"]["0x2"]["sourcePaths"]["0"], "Counter.sol");
        assert_eq!(value["contracts"]["0x2"]["debugAvailable"], true);
        assert_eq!(value["contracts"]["0x2"]["abi"][0]["name"], "set");
    }

    fn sample_trace() -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x1234".to_owned(),
            gas_used: 21_000,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some("debug-rpc".to_owned()),
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: vec![TraceStep {
                pc: 0,
                op: "PUSH1".to_owned(),
                gas: 100,
                gas_cost: 3,
                depth: 0,
                stack: vec!["0x01".to_owned()],
                memory: Some("aa".to_owned()),
                storage: Some(BTreeMap::new()),
                error: None,
                snapshot: Default::default(),
            }],
        }
    }
}
