//! The top-level calls of a trace.
//!
//! A transaction has one root call. A test runner such as Foundry records several in one
//! trace (the deployment, `setUp`, the test, an invariant sequence), one after another at
//! the root depth. Each is a call or creation the backend recorded with no parent that
//! starts at the root depth; a trace without such records has the one root its own fields
//! describe.

use soldb_core::{SoldbError, SoldbResult, TransactionTrace};

/// One top-level call: where it starts, and the record that describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootCall {
    /// The step the call starts at.
    pub entry_step: usize,
    pub record: RootRecord,
    /// What the call is, when the trace says, such as Foundry's `setup`.
    pub kind: Option<String>,
}

/// Where a top-level call is recorded in its trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootRecord {
    /// The trace's own fields, for a trace without a record starting at its first step.
    Trace,
    /// An index into `artifacts.calls`.
    Call(usize),
    /// An index into `artifacts.creations`.
    Creation(usize),
}

impl RootCall {
    /// The address whose code the call runs; `None` for a creation whose address is
    /// unknown.
    #[must_use]
    pub fn address<'a>(&self, trace: &'a TransactionTrace) -> Option<&'a str> {
        match self.record {
            RootRecord::Trace => trace
                .to_addr
                .as_deref()
                .or(trace.contract_address.as_deref()),
            RootRecord::Call(index) => trace
                .artifacts
                .calls
                .get(index)
                .map(|call| call.bytecode_address.as_str()),
            RootRecord::Creation(index) => trace
                .artifacts
                .creations
                .get(index)
                .and_then(|creation| creation.address.as_deref()),
        }
    }

    /// The hash of the code the call runs, when the backend recorded it.
    #[must_use]
    pub fn code_hash<'a>(&self, trace: &'a TransactionTrace) -> Option<&'a str> {
        match self.record {
            RootRecord::Trace => None,
            RootRecord::Call(index) => trace
                .artifacts
                .calls
                .get(index)
                .and_then(|call| call.code_hash.as_deref()),
            RootRecord::Creation(index) => trace
                .artifacts
                .creations
                .get(index)
                .and_then(|creation| creation.code_hash.as_deref()),
        }
    }

    /// Whether the call runs creation code.
    #[must_use]
    pub fn creation(&self, trace: &TransactionTrace) -> bool {
        match self.record {
            RootRecord::Trace => trace.to_addr.is_none() && trace.contract_address.is_some(),
            RootRecord::Call(_) => false,
            RootRecord::Creation(_) => true,
        }
    }

    /// The calldata of a call, or the init code of a creation.
    #[must_use]
    pub fn input<'a>(&self, trace: &'a TransactionTrace) -> &'a str {
        match self.record {
            RootRecord::Trace => &trace.input_data,
            RootRecord::Call(index) => trace
                .artifacts
                .calls
                .get(index)
                .map_or("", |call| call.input.as_str()),
            RootRecord::Creation(index) => trace
                .artifacts
                .creations
                .get(index)
                .map_or("", |creation| creation.init_code.as_str()),
        }
    }
}

/// The top-level calls of `trace`, in execution order. Never empty.
#[must_use]
pub fn root_calls(trace: &TransactionTrace) -> Vec<RootCall> {
    let mut roots = Vec::new();
    for (index, call) in trace.artifacts.calls.iter().enumerate() {
        if call.parent_id.is_some() {
            continue;
        }
        let Some(entry_step) = root_entry(trace, call.entry_step, call.exit_step) else {
            continue;
        };
        roots.push(RootCall {
            entry_step,
            record: RootRecord::Call(index),
            kind: None,
        });
    }
    for (index, creation) in trace.artifacts.creations.iter().enumerate() {
        if creation.parent_id.is_some() {
            continue;
        }
        let Some(entry_step) = root_entry(trace, creation.entry_step, creation.exit_step) else {
            continue;
        };
        roots.push(RootCall {
            entry_step,
            record: RootRecord::Creation(index),
            kind: None,
        });
    }
    roots.sort_by_key(|root| root.entry_step);
    // Without a record starting at the first step, the trace's own fields describe it.
    if roots.first().is_none_or(|root| root.entry_step != 0) {
        roots.insert(
            0,
            RootCall {
                entry_step: 0,
                record: RootRecord::Trace,
                kind: None,
            },
        );
    }
    for root in &mut roots {
        let kind = trace
            .artifacts
            .root_kinds
            .iter()
            .find(|kind| kind.entry_step == root.entry_step);
        root.kind = kind.map(|kind| kind.kind.clone());
    }
    roots
}

/// The entry step of a record that starts a top-level call. A record that ran no steps,
/// such as a call to an account without code, is not a frame in the trace, and one
/// entered deeper than the first step is a nested call.
fn root_entry(
    trace: &TransactionTrace,
    entry: Option<usize>,
    exit: Option<usize>,
) -> Option<usize> {
    let entry = entry?;
    if exit.is_some_and(|exit| exit <= entry) {
        return None;
    }
    let root_depth = trace.steps.first().map_or(0, |step| step.depth());
    let step = trace.steps.get(entry)?;
    (step.depth() == root_depth).then_some(entry)
}

/// Fails when two top-level calls start at one step, which no execution produces.
pub fn check_root_calls(trace: &TransactionTrace) -> SoldbResult<()> {
    let roots = root_calls(trace);
    let Some(pair) = roots
        .windows(2)
        .find(|pair| pair[0].entry_step == pair[1].entry_step)
    else {
        return Ok(());
    };
    Err(SoldbError::Message(format!(
        "invalid trace: two top-level calls start at step {}\n\
         the trace records more than one call or creation without a parent entered there",
        pair[0].entry_step
    )))
}

/// The index in `roots` of the top-level call `step` belongs to.
#[must_use]
pub fn root_index(roots: &[RootCall], step: usize) -> usize {
    let position = roots.partition_point(|root| root.entry_step <= step);
    position.saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use soldb_core::{
        ContractCreation, ExecutionCall, RootKind, StepSnapshot, TraceStep, TransactionTrace,
    };

    use super::{check_root_calls, root_calls, root_index, RootCall, RootRecord};

    fn step(depth: u64) -> TraceStep {
        TraceStep::new(0, "STOP".into(), 0, 0, depth, None, StepSnapshot::default())
    }

    fn trace(depths: &[u64]) -> TransactionTrace {
        TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: Some("0xaa".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x01".to_owned(),
            gas_used: 0,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: depths.iter().map(|depth| step(*depth)).collect(),
        }
    }

    fn call(parent_id: Option<usize>, entry: usize, exit: usize, address: &str) -> ExecutionCall {
        ExecutionCall {
            id: 0,
            parent_id,
            depth: 1,
            entry_step: Some(entry),
            exit_step: Some(exit),
            call_type: "CALL".to_owned(),
            from: "0x1".to_owned(),
            to: address.to_owned(),
            bytecode_address: address.to_owned(),
            value: "0x0".to_owned(),
            input: format!("0x{entry:02x}"),
            gas_limit: 0,
            gas_used: None,
            output: None,
            success: Some(true),
            error: None,
            code_hash: None,
        }
    }

    #[test]
    fn without_records_the_trace_fields_are_the_root() {
        let trace = trace(&[1, 1]);
        let roots = root_calls(&trace);
        assert_eq!(
            roots,
            vec![RootCall {
                entry_step: 0,
                record: RootRecord::Trace,
                kind: None,
            }]
        );
        assert_eq!(roots[0].address(&trace), Some("0xaa"));
        assert!(!roots[0].creation(&trace));
        assert_eq!(roots[0].input(&trace), "0x01");
    }

    #[test]
    fn top_level_records_are_roots_in_execution_order() {
        let mut trace = trace(&[1, 1, 2, 1, 1]);
        trace.artifacts.calls = vec![
            call(None, 3, 5, "0xbb"),
            call(None, 0, 3, "0xaa"),
            // Nested under the first call.
            call(Some(1), 2, 3, "0xcc"),
            // No parent recorded, but entered deeper than the root.
            call(None, 2, 3, "0xdd"),
            // Ran no steps.
            call(None, 5, 5, "0xee"),
        ];
        let roots = root_calls(&trace);
        let entries = roots.iter().map(|root| root.entry_step).collect::<Vec<_>>();
        assert_eq!(entries, vec![0, 3]);
        assert_eq!(roots[root_index(&roots, 2)].address(&trace), Some("0xaa"));
        assert_eq!(roots[root_index(&roots, 4)].input(&trace), "0x03");
    }

    #[test]
    fn two_roots_starting_at_one_step_are_invalid() {
        let mut trace = trace(&[1, 1, 1, 1]);
        trace.artifacts.calls = vec![
            call(None, 0, 1, "0xaa"),
            call(None, 1, 2, "0xbb"),
            call(None, 2, 4, "0xdd"),
        ];
        assert!(check_root_calls(&trace).is_ok());
        trace.artifacts.calls.push(call(None, 1, 2, "0xcc"));
        let error = check_root_calls(&trace).expect_err("two roots at step 1");
        assert!(error
            .to_string()
            .starts_with("invalid trace: two top-level calls start at step 1\n"));
    }

    #[test]
    fn a_later_root_creation_follows_the_trace_root() {
        let mut trace = trace(&[1, 1]);
        trace.artifacts.creations.push(ContractCreation {
            id: 0,
            parent_id: None,
            depth: 1,
            entry_step: Some(1),
            exit_step: None,
            create_type: "CREATE".to_owned(),
            caller: "0x1".to_owned(),
            address: Some("0xcc".to_owned()),
            value: "0x0".to_owned(),
            init_code: "0x6000".to_owned(),
            gas_limit: 0,
            gas_used: None,
            output: None,
            success: Some(true),
            error: None,
            code_hash: None,
        });
        let roots = root_calls(&trace);
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].input(&trace), "0x01");
        assert!(roots[1].creation(&trace));
        assert_eq!(roots[1].address(&trace), Some("0xcc"));
        assert_eq!(roots[1].input(&trace), "0x6000");
    }

    #[test]
    fn roots_carry_the_kind_recorded_at_their_entry_step() {
        let mut trace = trace(&[1, 1, 1]);
        trace.artifacts.calls = vec![call(None, 0, 2, "0xaa"), call(None, 2, 3, "0xbb")];
        trace.artifacts.root_kinds = vec![
            RootKind {
                entry_step: 2,
                kind: "execution".to_owned(),
            },
            RootKind {
                entry_step: 0,
                kind: "setup".to_owned(),
            },
            // Not where any root starts.
            RootKind {
                entry_step: 1,
                kind: "deployment".to_owned(),
            },
        ];
        let kinds = root_calls(&trace)
            .into_iter()
            .map(|root| root.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![Some("setup".to_owned()), Some("execution".to_owned())]
        );
    }
}
