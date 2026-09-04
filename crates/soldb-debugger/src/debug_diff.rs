//! Differential testing for the source-level debugging experience.
//!
//! Compilers need not emit the same bytecode for the same source, so comparing raw
//! source maps or program counters says little about what a user sees. This module maps
//! each execution through [`StepMap`], records the source stops exposed by `step`, and
//! compares those normalized traces. The result is suitable for a test harness: it is
//! deterministic, serializable, and separates execution differences from debug-info
//! differences.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use soldb_core::TransactionTrace;

use crate::{source_path_matches, ContractDebugInfo, StepMap};

/// How strictly two source-level traces are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugDiffMode {
    /// Compare ordered source lines, functions, frame depth, and frame entries.
    Steps,
    /// Compare steps and their exact source ranges and generated-code attribution.
    Spans,
    /// Compare the set of source lines and functions reached, ignoring order and depth.
    Coverage,
}

/// The execution result whose debug information was captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugExecution {
    pub creation: bool,
    pub input: String,
    pub value: String,
    pub success: bool,
    pub output: String,
}

/// Aggregate mapping quality for one side of a comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugTraceSummary {
    pub instructions: usize,
    pub mapped_instructions: usize,
    pub source_steps: usize,
    pub frame_entries: usize,
}

/// One user-visible source stop in an execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugTraceEvent {
    /// Instruction index in the original execution trace, for diagnostics only.
    pub instruction: usize,
    /// Program counter in that execution, for diagnostics only.
    pub pc: u64,
    pub contract: String,
    pub source: String,
    pub line: u64,
    pub column: u64,
    pub offset: u64,
    pub length: u64,
    pub function: Option<String>,
    pub frame_depth: u32,
    pub frame_entry: bool,
    pub generated: bool,
    /// Legacy source-map modifier depth, when the artifact carries it.
    pub modifier_depth: Option<i64>,
}

/// A compiler-independent view of one execution's debugging experience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugTrace {
    pub execution: DebugExecution,
    pub summary: DebugTraceSummary,
    pub events: Vec<DebugTraceEvent>,
}

/// The kind of one sampled difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugDifferenceKind {
    Changed,
    Missing,
    Unexpected,
}

/// One difference between the reference and candidate source traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugDifference {
    pub kind: DebugDifferenceKind,
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<DebugTraceEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<DebugTraceEvent>,
}

/// Serializable result of a source-level differential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugDiffReport {
    pub schema_version: u32,
    pub mode: DebugDiffMode,
    pub equivalent: bool,
    pub comparable: bool,
    pub diagnostics: Vec<String>,
    pub execution_equivalent: bool,
    pub execution_differences: Vec<String>,
    pub reference: DebugTraceSummary,
    pub candidate: DebugTraceSummary,
    pub difference_count: usize,
    pub differences: Vec<DebugDifference>,
    pub differences_truncated: bool,
}

/// Maps one execution to the source stops a debugger exposes.
#[must_use]
pub fn capture_debug_trace(
    trace: &TransactionTrace,
    contracts: Vec<ContractDebugInfo>,
) -> DebugTrace {
    let map = StepMap::new(trace, contracts);
    let mut mapped_instructions = 0;
    let mut frame_entries = 0;
    let mut events = Vec::new();

    for instruction in 0..map.step_count() {
        if map.line_key(instruction).is_some() {
            mapped_instructions += 1;
        }
        if map.is_frame_entry(instruction) {
            frame_entries += 1;
        }
        if !map.is_line_start(instruction) {
            continue;
        }

        let Some(location) = map.location(instruction) else {
            continue;
        };
        let Some(step) = trace.steps.get(instruction) else {
            continue;
        };
        let modifier_depth = map
            .contract_at_step(instruction)
            .and_then(|contract| contract.modifier_depth_at_pc(step.pc));
        events.push(DebugTraceEvent {
            instruction,
            pc: step.pc,
            contract: location.contract_name,
            source: normalize_source_path(&location.path),
            line: location.line,
            column: location.column,
            offset: location.offset,
            length: location.length,
            function: location.function_name,
            frame_depth: map.frame_depth(instruction).unwrap_or(0),
            frame_entry: map.is_frame_entry(instruction),
            generated: location.generated,
            modifier_depth,
        });
    }

    DebugTrace {
        execution: DebugExecution {
            creation: trace.to_addr.is_none(),
            input: normalize_hex_data(&trace.input_data),
            value: normalize_quantity(&trace.value),
            success: trace.success,
            output: normalize_hex_data(&trace.output),
        },
        summary: DebugTraceSummary {
            instructions: map.step_count(),
            mapped_instructions,
            source_steps: events.len(),
            frame_entries,
        },
        events,
    }
}

/// Compares two captured debugging experiences and samples at most `difference_limit`
/// differences for display.
#[must_use]
pub fn compare_debug_traces(
    reference: &DebugTrace,
    candidate: &DebugTrace,
    mode: DebugDiffMode,
    difference_limit: usize,
) -> DebugDiffReport {
    let mut diagnostics = Vec::new();
    if reference.events.is_empty() {
        diagnostics.push("reference trace has no source steps".to_owned());
    }
    if candidate.events.is_empty() {
        diagnostics.push("candidate trace has no source steps".to_owned());
    }
    let execution_differences = compare_execution(&reference.execution, &candidate.execution);
    let (difference_count, differences) = match mode {
        DebugDiffMode::Steps | DebugDiffMode::Spans => {
            compare_ordered_events(&reference.events, &candidate.events, mode, difference_limit)
        }
        DebugDiffMode::Coverage => {
            compare_coverage(&reference.events, &candidate.events, difference_limit)
        }
    };
    let comparable = diagnostics.is_empty();
    let execution_equivalent = execution_differences.is_empty();

    DebugDiffReport {
        schema_version: 1,
        mode,
        equivalent: comparable && execution_equivalent && difference_count == 0,
        comparable,
        diagnostics,
        execution_equivalent,
        execution_differences,
        reference: reference.summary.clone(),
        candidate: candidate.summary.clone(),
        difference_count,
        differences_truncated: difference_count > differences.len(),
        differences,
    }
}

fn compare_execution(reference: &DebugExecution, candidate: &DebugExecution) -> Vec<String> {
    let mut differences = Vec::new();
    if reference.creation != candidate.creation {
        differences.push("execution kind differs".to_owned());
    }
    if reference.input != candidate.input {
        differences.push("calldata differs".to_owned());
    }
    if reference.value != candidate.value {
        differences.push("call value differs".to_owned());
    }
    if reference.success != candidate.success {
        differences.push("success status differs".to_owned());
    }
    // Creation returns compiler-specific runtime bytecode, so differing output is not a
    // behavioral mismatch between the constructors.
    if !reference.creation && !candidate.creation && reference.output != candidate.output {
        differences.push("return data differs".to_owned());
    }
    differences
}

fn compare_ordered_events(
    reference: &[DebugTraceEvent],
    candidate: &[DebugTraceEvent],
    mode: DebugDiffMode,
    limit: usize,
) -> (usize, Vec<DebugDifference>) {
    let mut difference_count = 0;
    let mut differences = Vec::new();
    for index in 0..reference.len().max(candidate.len()) {
        let left = reference.get(index);
        let right = candidate.get(index);
        if matches!((left, right), (Some(left), Some(right)) if events_match(left, right, mode)) {
            continue;
        }

        difference_count += 1;
        if differences.len() == limit {
            continue;
        }
        differences.push(DebugDifference {
            kind: match (left, right) {
                (Some(_), Some(_)) => DebugDifferenceKind::Changed,
                (Some(_), None) => DebugDifferenceKind::Missing,
                (None, Some(_)) => DebugDifferenceKind::Unexpected,
                (None, None) => continue,
            },
            index,
            reference: left.cloned(),
            candidate: right.cloned(),
        });
    }
    (difference_count, differences)
}

fn compare_coverage(
    reference: &[DebugTraceEvent],
    candidate: &[DebugTraceEvent],
    limit: usize,
) -> (usize, Vec<DebugDifference>) {
    let reference = unique_coverage(reference);
    let candidate = unique_coverage(candidate);
    let mut candidate_by_core = BTreeMap::<CoverageCore<'_>, Vec<usize>>::new();
    for (index, event) in candidate.iter().enumerate() {
        candidate_by_core
            .entry(CoverageCore::new(event))
            .or_default()
            .push(index);
    }
    let mut matched_candidate = BTreeSet::new();
    let mut differences = Vec::new();
    let mut difference_count = 0;

    for (index, left) in reference.iter().enumerate() {
        let right = candidate_by_core
            .get(&CoverageCore::new(left))
            .into_iter()
            .flatten()
            .find_map(|candidate_index| {
                let right = candidate[*candidate_index];
                (!matched_candidate.contains(candidate_index)
                    && source_path_matches(&left.source, &right.source))
                .then_some((*candidate_index, right))
            });
        if let Some((candidate_index, _)) = right {
            matched_candidate.insert(candidate_index);
            continue;
        }
        difference_count += 1;
        if differences.len() < limit {
            differences.push(DebugDifference {
                kind: DebugDifferenceKind::Missing,
                index,
                reference: Some((*left).clone()),
                candidate: None,
            });
        }
    }

    for (index, right) in candidate.iter().enumerate() {
        if matched_candidate.contains(&index) {
            continue;
        }
        difference_count += 1;
        if differences.len() < limit {
            differences.push(DebugDifference {
                kind: DebugDifferenceKind::Unexpected,
                index,
                reference: None,
                candidate: Some((*right).clone()),
            });
        }
    }

    (difference_count, differences)
}

fn unique_coverage(events: &[DebugTraceEvent]) -> Vec<&DebugTraceEvent> {
    let mut keys = BTreeSet::new();
    let mut unique = Vec::new();
    for event in events {
        if keys.insert((&event.contract, &event.source, event.line, &event.function)) {
            unique.push(event);
        }
    }
    unique
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CoverageCore<'a> {
    contract: &'a str,
    line: u64,
    function: Option<&'a str>,
}

impl<'a> CoverageCore<'a> {
    fn new(event: &'a DebugTraceEvent) -> Self {
        Self {
            contract: &event.contract,
            line: event.line,
            function: event.function.as_deref(),
        }
    }
}

fn events_match(
    reference: &DebugTraceEvent,
    candidate: &DebugTraceEvent,
    mode: DebugDiffMode,
) -> bool {
    let source_step = reference.contract == candidate.contract
        && source_path_matches(&reference.source, &candidate.source)
        && reference.line == candidate.line
        && reference.function == candidate.function;
    if mode == DebugDiffMode::Coverage {
        return source_step;
    }

    source_step
        && reference.frame_depth == candidate.frame_depth
        && reference.frame_entry == candidate.frame_entry
        && (mode != DebugDiffMode::Spans
            || (reference.column == candidate.column
                && reference.offset == candidate.offset
                && reference.length == candidate.length
                && reference.generated == candidate.generated
                && reference.modifier_depth == candidate.modifier_depth))
}

fn normalize_source_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    path.strip_prefix("./").unwrap_or(&path).to_owned()
}

fn normalize_hex_data(value: &str) -> String {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    format!("0x{}", value.to_ascii_lowercase())
}

fn normalize_quantity(value: &str) -> String {
    if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        let value = value.trim_start_matches('0');
        return format!("0x{}", if value.is_empty() { "0" } else { value });
    }
    let value = value.trim_start_matches('0');
    if value.is_empty() {
        "0".to_owned()
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use soldb_core::{TraceStep, TransactionTrace};
    use soldb_ethdebug::{EthdebugInfo, Instruction};

    use super::{capture_debug_trace, compare_debug_traces, DebugDiffMode, DebugDifferenceKind};
    use crate::ContractDebugInfo;

    const SOURCE: &str = "contract C {\n    function f() external {\n        uint256 x = 1;\n        x++;\n    }\n}\n";

    fn trace(pcs: &[u64], output: &str) -> TransactionTrace {
        TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x26121ff0".to_owned(),
            gas_used: 0,
            output: output.to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: pcs
                .iter()
                .map(|pc| TraceStep {
                    pc: *pc,
                    op: "JUMPDEST".into(),
                    gas: 0,
                    gas_cost: 0,
                    depth: 0,
                    stack: Vec::new(),
                    memory: None,
                    storage: None,
                    error: None,
                    snapshot: Default::default(),
                })
                .collect(),
        }
    }

    fn contract(pcs: &[u64], offsets: &[usize], path: &str) -> ContractDebugInfo {
        let instructions = pcs
            .iter()
            .zip(offsets)
            .map(|(pc, offset)| Instruction {
                offset: *pc,
                operation: json!({"mnemonic": "JUMPDEST"}),
                context: Some(json!({
                    "code": {
                        "source": {"id": 0},
                        "range": {"offset": offset, "length": 1}
                    }
                })),
            })
            .collect();
        let info = EthdebugInfo {
            compilation: json!({}),
            contract_name: "C".to_owned(),
            environment: "call".to_owned(),
            instructions,
            sources: BTreeMap::from([(0, path.to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        ContractDebugInfo::new(None, "C", info, BTreeMap::from([(0, SOURCE.to_owned())]))
    }

    #[test]
    fn different_bytecode_with_the_same_source_steps_matches() {
        let first = SOURCE.find("uint256").expect("statement");
        let second = SOURCE.find("x++").expect("statement");
        let reference = capture_debug_trace(
            &trace(&[0, 1], "0x01"),
            vec![contract(&[0, 1], &[first, second], "src/C.sol")],
        );
        let candidate = capture_debug_trace(
            &trace(&[20, 24], "0x01"),
            vec![contract(&[20, 24], &[first, second], "/checkout/src/C.sol")],
        );

        let report = compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8);

        assert!(report.equivalent);
        assert_eq!(report.difference_count, 0);
    }

    #[test]
    fn changed_steps_and_execution_are_reported_separately() {
        let first = SOURCE.find("uint256").expect("statement");
        let second = SOURCE.find("x++").expect("statement");
        let reference = capture_debug_trace(
            &trace(&[0, 1], "0x01"),
            vec![contract(&[0, 1], &[first, second], "C.sol")],
        );
        let candidate = capture_debug_trace(
            &trace(&[20, 24], "0x02"),
            vec![contract(&[20, 24], &[second, first], "C.sol")],
        );

        let report = compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 1);

        assert!(!report.equivalent);
        assert!(!report.execution_equivalent);
        assert_eq!(report.execution_differences, ["return data differs"]);
        assert_eq!(report.difference_count, 2);
        assert_eq!(report.differences.len(), 1);
        assert!(report.differences_truncated);
        assert_eq!(report.differences[0].kind, DebugDifferenceKind::Changed);
    }

    #[test]
    fn coverage_ignores_order_and_repetition() {
        let first = SOURCE.find("uint256").expect("statement");
        let second = SOURCE.find("x++").expect("statement");
        let reference = capture_debug_trace(
            &trace(&[0, 0, 1, 1], "0x"),
            vec![contract(&[0, 1], &[first, second], "C.sol")],
        );
        let candidate = capture_debug_trace(
            &trace(&[20, 20, 24, 24], "0x"),
            vec![contract(&[20, 24], &[second, first], "C.sol")],
        );

        let report = compare_debug_traces(&reference, &candidate, DebugDiffMode::Coverage, 8);

        assert!(report.equivalent);
    }

    #[test]
    fn empty_source_traces_are_not_comparable() {
        let reference = capture_debug_trace(&trace(&[99], "0x"), Vec::new());
        let candidate = capture_debug_trace(&trace(&[100], "0x"), Vec::new());

        let report = compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8);

        assert!(!report.equivalent);
        assert!(!report.comparable);
        assert_eq!(report.diagnostics.len(), 2);
    }

    #[test]
    fn span_mode_checks_exact_ranges_and_modifier_depth() {
        let offset = SOURCE.find("uint256").expect("statement");
        let reference =
            capture_debug_trace(&trace(&[0], "0x"), vec![contract(&[0], &[offset], "C.sol")]);
        let mut candidate = reference.clone();
        candidate.events[0].length += 1;
        candidate.events[0].modifier_depth = Some(1);

        assert!(compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8).equivalent);
        assert!(!compare_debug_traces(&reference, &candidate, DebugDiffMode::Spans, 8).equivalent);
    }

    #[test]
    fn execution_comparison_normalizes_hex_spelling() {
        let offset = SOURCE.find("uint256").expect("statement");
        let reference = capture_debug_trace(
            &trace(&[0], "0xAB"),
            vec![contract(&[0], &[offset], "C.sol")],
        );
        let mut candidate_trace = trace(&[20], "0Xab");
        candidate_trace.value = "0x00".to_owned();
        let candidate =
            capture_debug_trace(&candidate_trace, vec![contract(&[20], &[offset], "C.sol")]);

        assert!(compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8).equivalent);
    }
}
