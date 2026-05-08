use serde::Serialize;
use serde_json::json;
use soldb_core::{SoldbResult, TraceArtifacts, TraceCapabilities, TransactionTrace};

pub fn trace_to_json(trace: &TransactionTrace) -> SoldbResult<String> {
    serde_json::to_string_pretty(trace)
        .map_err(|err| soldb_core::SoldbError::Message(err.to_string()))
}

pub fn trace_to_web_json(trace: &TransactionTrace) -> SoldbResult<String> {
    let steps = trace
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            json!({
                "step": index,
                "pc": step.pc,
                "op": step.op,
                "gas": step.gas,
                "gasCost": step.gas_cost,
                "depth": step.depth,
                "stack": step.stack,
                "snapshot": step.normalized_snapshot(),
            })
        })
        .collect::<Vec<_>>();

    let response = TraceWebResponse {
        status: if trace.success { "success" } else { "reverted" },
        backend: trace.backend.as_deref(),
        capabilities: &trace.capabilities,
        artifacts: &trace.artifacts,
        trace_call: TraceCallWeb {
            ty: if trace.contract_address.is_some() {
                "CREATE"
            } else {
                "CALL"
            },
            from: &trace.from_addr,
            to: trace.to_addr.as_deref(),
            value: &trace.value,
            gas: trace.steps.first().map_or(0, |step| step.gas),
            gas_used: trace.gas_used,
            input: &trace.input_data,
            output: &trace.output,
            call_id: None,
        },
        steps,
        contracts: json!({}),
    };

    serde_json::to_string_pretty(&response)
        .map_err(|err| soldb_core::SoldbError::Message(err.to_string()))
}

pub fn simulate_to_web_json(trace: &TransactionTrace, function_name: &str) -> SoldbResult<String> {
    let steps = trace
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            json!({
                "step": index,
                "pc": step.pc,
                "op": step.op,
                "gas": step.gas,
                "gasCost": step.gas_cost,
                "depth": step.depth,
                "stack": step.stack,
                "snapshot": step.normalized_snapshot(),
            })
        })
        .collect::<Vec<_>>();

    let response = SimulateWebResponse {
        status: if trace.success { "success" } else { "reverted" },
        backend: trace.backend.as_deref(),
        capabilities: &trace.capabilities,
        artifacts: &trace.artifacts,
        trace_call: TraceCallWeb {
            ty: "ENTRY",
            from: &trace.from_addr,
            to: trace.to_addr.as_deref(),
            value: &trace.value,
            gas: trace.steps.first().map_or(0, |step| step.gas),
            gas_used: trace.gas_used,
            input: &trace.input_data,
            output: &trace.output,
            call_id: Some(0),
        },
        steps,
        function_name,
        is_verified: false,
    };

    serde_json::to_string_pretty(&response)
        .map_err(|err| soldb_core::SoldbError::Message(err.to_string()))
}

#[derive(Debug, Serialize)]
struct TraceCallWeb<'a> {
    #[serde(rename = "type")]
    ty: &'a str,
    from: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'a str>,
    value: &'a str,
    gas: u64,
    #[serde(rename = "gasUsed")]
    gas_used: u64,
    input: &'a str,
    output: &'a str,
    #[serde(rename = "callId", skip_serializing_if = "Option::is_none")]
    call_id: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TraceWebResponse<'a> {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<&'a str>,
    capabilities: &'a TraceCapabilities,
    artifacts: &'a TraceArtifacts,
    #[serde(rename = "traceCall")]
    trace_call: TraceCallWeb<'a>,
    steps: Vec<serde_json::Value>,
    contracts: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SimulateWebResponse<'a> {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<&'a str>,
    capabilities: &'a TraceCapabilities,
    artifacts: &'a TraceArtifacts,
    #[serde(rename = "traceCall")]
    trace_call: TraceCallWeb<'a>,
    steps: Vec<serde_json::Value>,
    function_name: &'a str,
    #[serde(rename = "isVerified")]
    is_verified: bool,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use soldb_core::{TraceStep, TransactionTrace};

    use super::{simulate_to_web_json, trace_to_web_json};

    #[test]
    fn serializes_trace_to_web_shape() {
        let trace = sample_trace();

        let json = trace_to_web_json(&trace).expect("json");
        assert!(json.contains("\"status\": \"success\""));
        assert!(json.contains("\"traceCall\""));
        assert!(json.contains("\"gasUsed\": 21000"));
        assert!(json.contains("\"contracts\""));
        assert!(json.contains("\"snapshot\""));
        assert!(json.contains("\"backend\": \"debug-rpc\""));
        assert!(json.contains("\"capabilities\""));
        assert!(json.contains("\"artifacts\""));
    }

    #[test]
    fn serializes_simulation_to_web_shape() {
        let trace = sample_trace();

        let json = simulate_to_web_json(&trace, "raw_data").expect("json");
        assert!(json.contains("\"type\": \"ENTRY\""));
        assert!(json.contains("\"callId\": 0"));
        assert!(json.contains("\"function_name\": \"raw_data\""));
        assert!(json.contains("\"isVerified\": false"));
        assert!(json.contains("\"backend\": \"debug-rpc\""));
        assert!(json.contains("\"capabilities\""));
        assert!(json.contains("\"artifacts\""));
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
