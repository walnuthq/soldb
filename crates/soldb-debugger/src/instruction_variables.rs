//! Structured ETHDebug locals in the postcondition of the previously executed instruction.
//!
//! Resolve pointers using recorded machine state and the compiler's type documents. The actual
//! previous trace step selects the context, including taken jumps and loop backedges; looking
//! up the preceding bytecode address would use the wrong path. Crossing an external frame
//! boundary discards the old context. Legacy location records retain their input-state API.

use soldb_core::{opcode, StepView, TransactionTrace};
use soldb_ethdebug::{
    parse_word, EthdebugInfo, Location, Machine, Resources, TypeDocument, VariableLocation, Word,
};

use crate::{
    decode_variable, root_calls,
    state::{code_from_hex, composed},
    DebugLocation, DebugValue, DebugValueStatus, DebugVariable,
};

/// Recovers locals at a trace position, using shared resource tables when available.
#[must_use]
pub fn variables_for_step_at(
    trace: &TransactionTrace,
    info: &EthdebugInfo,
    resources: Option<&Resources>,
    index: usize,
) -> Vec<DebugVariable> {
    let Some(step) = trace.steps.get(index) else {
        return Vec::new();
    };
    let legacy = info
        .variables_at_pc(step.pc())
        .into_iter()
        .filter(|variable| variable.context.is_none())
        .collect::<Vec<_>>();
    let previous = index
        .checked_sub(1)
        .and_then(|previous| trace.steps.get(previous))
        .filter(|previous| previous.depth() == step.depth() && previous.error().is_none());
    let structured = match previous {
        Some(previous) if is_successor(previous, step) => info
            .variables_at_pc(previous.pc())
            .into_iter()
            .filter(|variable| variable.context.is_some())
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    if legacy.is_empty() && structured.is_empty() {
        return Vec::new();
    }
    let roots = root_calls(trace);
    let calldata = crate::stepping::calldata_for_step(trace, &roots, index);
    let mut variables = legacy
        .into_iter()
        .map(|variable| decode_variable(step, calldata, variable))
        .collect::<Vec<_>>();
    let machine = RecordedMachine { step, calldata };
    variables.extend(
        structured
            .into_iter()
            .map(|variable| structured_variable(resources, &machine, variable)),
    );
    variables
}

fn is_successor(previous: StepView<'_>, current: StepView<'_>) -> bool {
    let op = previous.op();
    if matches!(
        op,
        opcode::STOP | opcode::RETURN | opcode::REVERT | opcode::INVALID | opcode::SELFDESTRUCT
    ) {
        return false;
    }
    if matches!(op, opcode::JUMP | opcode::JUMPI) {
        let stack = previous.stack();
        let taken = if op == opcode::JUMPI {
            let Some(condition) = stack.peek(1) else {
                return false;
            };
            condition.as_bytes().iter().any(|&byte| byte != 0)
        } else {
            true
        };
        if !taken {
            return previous.pc().checked_add(1) == Some(current.pc());
        }
        return stack.top().and_then(|word| {
            word.as_bytes().iter().try_fold(0u64, |value, &byte| {
                value.checked_mul(256)?.checked_add(byte.into())
            })
        }) == Some(current.pc());
    }
    let immediate = match op {
        0x60..=0x7f => u64::from(op - 0x5f), // PUSH1 through PUSH32.
        0xe6..=0xe8 => 1,                    // DUPN, SWAPN and EXCHANGE.
        _ => 0,
    };
    previous.pc().checked_add(1 + immediate) == Some(current.pc())
}

fn structured_variable(
    resources: Option<&Resources>,
    machine: &dyn Machine,
    variable: &VariableLocation,
) -> DebugVariable {
    let context = variable.context.as_ref().expect("structured variable");
    let empty = Resources::default();
    let resources = resources.unwrap_or(&empty);
    let ty = context.type_reference().ok().flatten();
    let pointer = context.parsed_pointer().ok().flatten();
    let value = match (&ty, &pointer) {
        (Some(ty), Some(pointer)) => match resources.read_variable(ty, pointer, machine) {
            Ok(values)
                if matches!(resources.resolve(ty), Ok(TypeDocument::Array { .. }))
                    && !values.is_empty() =>
            {
                composed(&values, None)
            }
            Ok(values) => composed(&values, resources.resolve(ty).ok()),
            Err(error) => DebugValue {
                display: format!("<unavailable: {error}>"),
                raw: None,
                status: DebugValueStatus::Unavailable,
            },
        },
        _ => DebugValue {
            display: "<unavailable>".to_owned(),
            raw: None,
            status: DebugValueStatus::Unavailable,
        },
    };
    DebugVariable {
        name: variable.name.clone(),
        ty: ty
            .as_ref()
            .map_or_else(|| "<unknown type>".to_owned(), |ty| resources.label(ty)),
        location: DebugLocation {
            kind: if variable.scopes.is_empty() {
                "pointer".to_owned()
            } else {
                format!("pointer ({})", variable.scopes.join(" / "))
            },
            offset: 0,
        },
        value,
    }
}

struct RecordedMachine<'a> {
    step: StepView<'a>,
    calldata: &'a str,
}

impl Machine for RecordedMachine<'_> {
    fn word(&self, location: Location, slot: &Word) -> Option<Word> {
        match location {
            Location::Stack => {
                let index = slot.iter().try_fold(0usize, |index, &byte| {
                    index.checked_mul(256)?.checked_add(byte.into())
                })?;
                self.step.stack().peek(index).map(|word| *word.as_bytes())
            }
            Location::Storage => self.step.storage().iter().find_map(|(key, value)| {
                (parse_word(key).ok().as_ref() == Some(slot))
                    .then(|| parse_word(value).ok())
                    .flatten()
            }),
            _ => None,
        }
    }
    fn bytes(&self, location: Location, offset: u64, length: u64) -> Option<Vec<u8>> {
        if length == 0 {
            return Some(Vec::new());
        }
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(length).ok()?)?;
        match location {
            Location::Memory => self.step.memory()?.get(start..end).map(<[u8]>::to_vec),
            Location::Calldata => code_from_hex(self.calldata)?
                .get(start..end)
                .map(<[u8]>::to_vec),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use soldb_core::{decode_hex, Bytes, StepSnapshot, TraceStep};

    use super::*;

    fn make_trace(steps: Vec<TraceStep>) -> TransactionTrace {
        TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 0,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: steps.into(),
        }
    }

    fn step(pc: u64, depth: u64, stack: &[&str], memory: Option<String>) -> TraceStep {
        TraceStep::new(
            pc,
            if pc == 100 {
                "JUMP".into()
            } else {
                "MSTORE".into()
            },
            1000,
            8,
            depth,
            None,
            StepSnapshot::new(
                stack.iter().map(|value| (*value).into()).collect(),
                memory.map(|memory| Bytes::from(decode_hex(&memory).expect("test memory is hex"))),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        )
    }

    #[test]
    fn layout_templates_read_recorded_memory_and_calldata() {
        let tables = serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../test/fixtures/ethdebug-layouts/ethdebug_resources.json"
        ))
        .unwrap();
        let snapshot = serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../test/fixtures/ethdebug-layouts/snapshot.json"
        ))
        .unwrap();
        let resources = Resources::parse(&tables).unwrap();
        let type_id = tables["types"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, document)| document["definition"]["name"] == "Record")
            .unwrap()
            .0;
        let output = decode_hex(snapshot["output"].as_str().unwrap()).unwrap();
        let memory_base = u64::from_be_bytes(output[24..32].try_into().unwrap());
        let variables = [("memory", memory_base), ("calldata", 36)].map(|(layout, offset)| {
            json!({"identifier": layout, "type": {"id": type_id}, "pointer": {
                "define": {"offset": offset}, "in": {"template": format!("{layout}-{type_id}")}
            }})
        });
        let program = json!({"instructions": [{"offset": 9, "operation": {"mnemonic": "MSTORE"},
            "context": {"variables": variables}}]});
        let info = EthdebugInfo::from_artifacts("Layouts", "call", &tables, &program).unwrap();
        let mut trace = make_trace(vec![
            step(9, 1, &[], None),
            step(
                10,
                1,
                &[],
                Some(snapshot["memory"].as_str().unwrap().to_owned()),
            ),
        ]);
        trace.input_data = snapshot["calldata"].as_str().unwrap().to_owned();
        let variables = variables_for_step_at(&trace, &info, Some(&resources), 1);
        assert_eq!(variables.len(), 2);
        assert_eq!(variables[0].value, variables[1].value);
        assert_eq!(variables[0].value.status, DebugValueStatus::Decoded);
        assert_eq!(variables[0].value.display,
            "{ point: { x: 7, y: -3 }, values: [11, 513], text: \"hello\", tag: 0x12345678, price: 42, color: Color.Green, callback: 0x1111111111111111111111111111111111111111abcdef01 }");
    }

    #[test]
    fn structured_postconditions_follow_taken_jumps() {
        let tables = json!({"types": {"u": {"kind": "uint", "bits": 256}, "b": {"kind": "bytes"}}, "pointers": {}});
        let resources = Resources::parse(&tables).unwrap();
        let program = json!({"instructions": [{"offset": 100, "operation": {"mnemonic": "JUMP"}, "context": {"gather": [{"name": "inline:bump:1", "gather": [{"name": "scope:block", "variables": [
            {"identifier": "x", "type": {"id": "u"}, "pointer": {"location": "stack", "slot": 0}},
            {"identifier": "buffer", "type": {"id": "b"}, "pointer": {"group": [
                {"name": "address", "location": "stack", "slot": 1},
                {"name": "length", "location": "memory", "offset": {"~read": "address"}, "length": 32},
                {"name": "data", "location": "memory", "offset": {"~sum": [{"~read": "address"}, 32]}, "length": {"~read": "length"}}
            ]}}
        ]}]}]}}, {"offset": 20, "operation": {"mnemonic": "JUMPDEST"}, "context": {}}]});
        let info = EthdebugInfo::from_artifacts("C", "call", &tables, &program).unwrap();
        let memory = format!("{}{:064x}{}", "00".repeat(128), 3, "616263");
        let trace = make_trace(vec![
            step(100, 1, &["0x80", "0x2a", "0x14"], None),
            step(20, 1, &["0x80", "0x2a"], Some(memory)),
        ]);
        let variables = variables_for_step_at(&trace, &info, Some(&resources), 1);
        assert_eq!(variables.len(), 2);
        assert_eq!(variables[0].value.display, "42");
        assert_eq!(variables[0].ty, "uint256");
        assert_eq!(
            variables[0].location.kind,
            "pointer (inline:bump:1 / scope:block)"
        );
        assert_eq!(variables[1].value.display, "0x616263");
        assert!(variables
            .iter()
            .all(|variable| variable.value.status == DebugValueStatus::Decoded));
        assert!(variables_for_step_at(&trace, &info, Some(&resources), 0).is_empty());
        let mut steps = trace.steps.to_steps();
        steps[0].depth = 2;
        let crossed = make_trace(steps);
        assert!(variables_for_step_at(&crossed, &info, Some(&resources), 1).is_empty());
        let mut steps = trace.steps.to_steps();
        steps[1].pc = 21;
        let gap = make_trace(steps);
        assert!(variables_for_step_at(&gap, &info, Some(&resources), 1).is_empty());
    }

    #[test]
    fn spill_words_and_unavailable_values_use_typed_pointers() {
        let tables = json!({"types": {"i": {"kind": "int", "bits": 16}}, "pointers": {}});
        let resources = Resources::parse(&tables).unwrap();
        let program = json!({"instructions": [{"offset": 9, "operation": {"mnemonic": "JUMP"}, "context": {"variables": [
            {"identifier": "signed", "type": {"id": "i"}, "pointer": {"location": "memory", "offset": 94, "length": 2}},
            {"identifier": "lost", "type": {"id": "i"}}
        ]}}]});
        let info = EthdebugInfo::from_artifacts("C", "call", &tables, &program).unwrap();
        let trace = make_trace(vec![
            step(9, 1, &[], None),
            step(10, 1, &[], Some(format!("{}fffd", "00".repeat(94)))),
        ]);
        let variables = variables_for_step_at(&trace, &info, Some(&resources), 1);
        assert_eq!(variables[0].value.display, "-3");
        assert_eq!(variables[1].value.status, DebugValueStatus::Unavailable);
        let mut steps = trace.steps.to_steps();
        steps[1].snapshot.memory = None;
        let missing = make_trace(steps);
        assert_eq!(
            variables_for_step_at(&missing, &info, Some(&resources), 1)[0]
                .value
                .status,
            DebugValueStatus::Unavailable
        );
    }

    #[test]
    fn alternative_scopes_are_not_combined_and_malformed_pointers_fail() {
        let program = json!({"instructions": [{"offset": 0, "operation": {"mnemonic": "JUMP"}, "context": {"pick": [
            {"name": "left", "variables": [{"identifier": "x", "pointer": {"location": "stack", "slot": 0}}]},
            {"name": "right", "variables": [{"identifier": "x", "pointer": {"location": "stack", "slot": 1}}]}
        ]}}]});
        let info = EthdebugInfo::from_artifacts("C", "call", &json!({}), &program).unwrap();
        assert!(!info.has_variable_locations());
        let malformed = json!({"instructions": [{"offset": 0, "operation": {"mnemonic": "JUMP"}, "context": {"variables": [{"identifier": "x", "pointer": {"location": "made-up"}}]}}]});
        assert!(EthdebugInfo::from_artifacts("C", "call", &json!({}), &malformed).is_err());
    }
}
