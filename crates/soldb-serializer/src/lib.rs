use serde_json::json;
use soldb_core::{SoldbResult, TransactionTrace};

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
            })
        })
        .collect::<Vec<_>>();

    let response = json!({
        "status": if trace.success { "success" } else { "reverted" },
        "traceCall": {
            "type": if trace.contract_address.is_some() { "CREATE" } else { "CALL" },
            "from": trace.from_addr,
            "to": trace.to_addr,
            "value": trace.value,
            "gas": trace.steps.first().map_or(0, |step| step.gas),
            "gasUsed": trace.gas_used,
            "input": trace.input_data,
            "output": trace.output,
        },
        "steps": steps,
        "contracts": {},
    });

    serde_json::to_string_pretty(&response)
        .map_err(|err| soldb_core::SoldbError::Message(err.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use soldb_core::{TraceStep, TransactionTrace};

    use super::trace_to_web_json;

    #[test]
    fn serializes_trace_to_web_shape() {
        let trace = TransactionTrace {
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
            }],
        };

        let json = trace_to_web_json(&trace).expect("json");
        assert!(json.contains("\"status\": \"success\""));
        assert!(json.contains("\"traceCall\""));
        assert!(json.contains("\"gasUsed\": 21000"));
        assert!(json.contains("\"contracts\""));
    }
}
