//! Differential testing for the source-level debugging experience.
//!
//! Compilers need not emit the same bytecode for the same source, so comparing raw
//! source maps or program counters says little about what a user sees. This module maps
//! each execution through [`StepMap::for_debug_diff`], keeping single-instruction
//! source stops that interactive stepping can smooth over, and compares the traces.
//! The result is suitable for a test harness: it is
//! deterministic, serializable, and separates execution differences from debug-info
//! differences.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_ethdebug::{keccak256, parse_word, word_hex};

use crate::{ContractDebugInfo, StepMap};

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
    /// ABI-encoded arguments supplied separately from compiler-specific initcode.
    #[serde(default)]
    pub constructor_args: Option<String>,
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

/// One compiler-mapped source stop in an execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugTraceEvent {
    /// Instruction index in the original execution trace, for diagnostics only.
    pub instruction: usize,
    /// Program counter in that execution, for diagnostics only.
    pub pc: u64,
    pub contract: String,
    pub source: String,
    /// Keccak-256 of the exact source bytes, independent of checkout location.
    #[serde(default)]
    pub source_hash: Option<[u8; 32]>,
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
    /// Artifact or trace inconsistencies that make a comparison inconclusive.
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

/// A source stop required by a test, independent of compiler-generated entry steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugCheckpoint {
    pub source: String,
    /// One-based source line.
    pub line: u64,
}

impl DebugTrace {
    /// Restricts comparison to explicit test checkpoints and diagnoses unreached ones.
    ///
    /// This is a test expectation, not source recovery: only existing mapped stops can
    /// satisfy a checkpoint. Each side must reach every checkpoint at least once.
    pub fn retain_checkpoints(&mut self, checkpoints: &[DebugCheckpoint]) {
        let mut by_line = BTreeMap::<u64, Vec<(usize, String)>>::new();
        for (index, checkpoint) in checkpoints.iter().enumerate() {
            by_line
                .entry(checkpoint.line)
                .or_default()
                .push((index, normalize_source_path(&checkpoint.source)));
        }
        let mut reached = BTreeSet::new();
        self.events.retain(|event| {
            let mut matched = false;
            for (index, source) in by_line.get(&event.line).into_iter().flatten() {
                if source_paths_match(&event.source, source) {
                    reached.insert(*index);
                    matched = true;
                }
            }
            matched
        });
        for (index, checkpoint) in checkpoints.iter().enumerate() {
            if !reached.contains(&index) {
                self.diagnostics.push(format!(
                    "checkpoint {}:{} was not reached",
                    checkpoint.source, checkpoint.line
                ));
            }
        }
        self.summary.source_steps = self.events.len();
    }

    /// Supplies encoded constructor arguments when comparing creation executions.
    ///
    /// Their boundary cannot be recovered from source maps: initcode contains embedded
    /// runtime code and data too. The caller must supply the known ABI payload.
    pub fn set_constructor_args(&mut self, arguments: &str) -> SoldbResult<()> {
        let arguments = normalize_hex_data(arguments);
        let hex = arguments.strip_prefix("0x").unwrap_or(&arguments);
        if !self.execution.creation
            || !hex.len().is_multiple_of(2)
            || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !self.execution.input.ends_with(hex)
        {
            return Err(SoldbError::Message(
                "constructor arguments must be hex matching the end of creation input".to_owned(),
            ));
        }
        self.execution.constructor_args = Some(arguments);
        Ok(())
    }
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

/// Maps one execution to source stops without interactive line smoothing.
#[must_use]
pub fn capture_debug_trace(
    trace: &TransactionTrace,
    contracts: Vec<ContractDebugInfo>,
) -> DebugTrace {
    let mut diagnostics = BTreeSet::new();
    let source_hashes = contracts
        .iter()
        .enumerate()
        .flat_map(|(index, contract)| {
            contract
                .source_contents
                .iter()
                .map(move |(source, content)| ((index, *source), keccak256(content.as_bytes())))
        })
        .collect::<BTreeMap<_, _>>();
    for contract in &contracts {
        let mut pcs = BTreeSet::new();
        for instruction in &contract.info.instructions {
            if !pcs.insert(instruction.offset) {
                diagnostics.insert(format!(
                    "duplicate instruction at PC {} in `{}`",
                    instruction.offset, contract.name
                ));
            }
            for source in instruction.source_locations() {
                let valid = contract
                    .source_contents
                    .get(&source.source_id)
                    .is_some_and(|text| {
                        source
                            .offset
                            .checked_add(source.length)
                            .is_some_and(|end| end <= text.len() as u64)
                    });
                if !valid {
                    diagnostics.insert(format!(
                        "missing source or invalid source range at PC {} in `{}`",
                        instruction.offset, contract.name
                    ));
                }
            }
        }
    }
    let map = StepMap::for_debug_diff(trace, contracts);
    let mut mapped_instructions = 0;
    let mut frame_entries = 0;
    let mut events = Vec::new();

    for instruction in 0..map.step_count() {
        let step = &trace.steps[instruction];
        if let Some(contract) = map.contract_at_step(instruction) {
            let opcode = contract
                .instruction_at_pc(step.pc)
                .and_then(|inst| inst.mnemonic());
            if !opcode.is_some_and(|opcode| opcodes_match(opcode, &step.op)) {
                diagnostics.insert(format!(
                    "trace opcode `{}` at PC {} disagrees with artifact `{}` in `{}`",
                    step.op,
                    step.pc,
                    opcode.unwrap_or("<missing>"),
                    contract.name
                ));
            }
        } else {
            diagnostics.insert("trace has steps without a matching contract artifact".to_owned());
        }
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
        let modifier_depth = map
            .contract_at_step(instruction)
            .and_then(|contract| contract.modifier_depth_at_pc(step.pc));
        events.push(DebugTraceEvent {
            instruction,
            pc: step.pc,
            contract: location.contract_name,
            source: normalize_source_path(&location.path),
            source_hash: source_hashes
                .get(&(location.key.contract, location.key.source_id))
                .copied(),
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
            value: match parse_word(&trace.value) {
                Ok(value) => word_hex(&value),
                Err(error) => {
                    diagnostics.insert(format!("invalid call value: {error}"));
                    trace.value.clone()
                }
            },
            success: trace.success,
            output: normalize_hex_data(&trace.output),
            constructor_args: None,
        },
        summary: DebugTraceSummary {
            instructions: map.step_count(),
            mapped_instructions,
            source_steps: events.len(),
            frame_entries,
        },
        events,
        diagnostics: diagnostics.into_iter().collect(),
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
    for (side, trace) in [("reference", reference), ("candidate", candidate)] {
        diagnostics.extend(
            trace
                .diagnostics
                .iter()
                .map(|message| format!("{side}: {message}")),
        );
        if trace.events.iter().any(|event| event.source_hash.is_none()) {
            diagnostics.push(format!("{side}: source identity is unavailable"));
        }
    }
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
    if reference.creation && candidate.creation {
        match (&reference.constructor_args, &candidate.constructor_args) {
            (Some(left), Some(right)) if left != right => {
                differences.push("constructor arguments differ".to_owned());
            }
            (Some(_), Some(_)) => {}
            _ => differences.push("encoded constructor arguments were not supplied".to_owned()),
        }
    } else if reference.input != candidate.input {
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
    let deployed =
        reference.creation && candidate.creation && reference.success && candidate.success;
    if !deployed && reference.output != candidate.output {
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
                    && source_paths_match(&left.source, &right.source)
                    && left.source_hash == right.source_hash)
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
        if keys.insert((
            &event.contract,
            &event.source,
            event.source_hash,
            event.line,
            &event.function,
        )) {
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
        && source_paths_match(&reference.source, &candidate.source)
        && reference.source_hash == candidate.source_hash
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

fn source_paths_match(left: &str, right: &str) -> bool {
    let absolute = |path: &str| path.starts_with('/') || path.as_bytes().get(1) == Some(&b':');
    let suffix = |long: &str, short: &str| {
        long.strip_suffix(short)
            .is_some_and(|prefix| prefix.ends_with('/'))
    };
    left == right
        || (absolute(left) != absolute(right) && (suffix(left, right) || suffix(right, left)))
}

fn opcodes_match(left: &str, right: &str) -> bool {
    let canonical = |opcode| match opcode {
        "DIFFICULTY" => "PREVRANDAO",
        "SHA3" => "KECCAK256",
        other => other,
    };
    canonical(left).eq_ignore_ascii_case(canonical(right))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use soldb_core::{TraceStep, TransactionTrace};
    use soldb_ethdebug::{EthdebugInfo, Instruction};

    use super::{
        capture_debug_trace, compare_debug_traces, DebugCheckpoint, DebugDiffMode,
        DebugDifferenceKind,
    };
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
        assert!(report
            .diagnostics
            .iter()
            .any(|message| message == "reference trace has no source steps"));
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

    #[test]
    fn mismatched_opcodes_and_missing_programs_cannot_pass() {
        let offset = SOURCE.find("uint256").expect("statement");
        let reference =
            capture_debug_trace(&trace(&[0], "0x"), vec![contract(&[0], &[offset], "C.sol")]);
        let mut wrong = trace(&[0], "0x");
        wrong.steps[0].op = "INVALID".into();
        let candidate = capture_debug_trace(&wrong, vec![contract(&[0], &[offset], "C.sol")]);
        let report = compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8);
        assert!(!report.equivalent);
        assert!(!report.comparable);
        assert_eq!(report.difference_count, 0);
        assert!(report.diagnostics[0].contains("trace opcode `INVALID`"));
    }

    #[test]
    fn source_paths_and_contents_both_participate_in_identity() {
        let offset = SOURCE.find("uint256").expect("statement");
        let reference = capture_debug_trace(
            &trace(&[0], "0x"),
            vec![contract(&[0], &[offset], "a/C.sol")],
        );
        let candidate = capture_debug_trace(
            &trace(&[0], "0x"),
            vec![contract(&[0], &[offset], "b/C.sol")],
        );
        for mode in [DebugDiffMode::Steps, DebugDiffMode::Coverage] {
            assert!(!compare_debug_traces(&reference, &candidate, mode, 8).equivalent);
        }
        let mut changed = contract(&[0], &[offset], "a/C.sol");
        changed
            .source_contents
            .insert(0, SOURCE.replace("x = 1", "x = 2"));
        let candidate = capture_debug_trace(&trace(&[0], "0x"), vec![changed]);
        assert!(!compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8).equivalent);
    }

    #[test]
    fn constructors_compare_arguments_and_revert_data_not_initcode() {
        let offset = SOURCE.find("uint256").expect("statement");
        let mut left = trace(&[0], "0x6000");
        left.to_addr = None;
        left.input_data = "0x60000042".to_owned();
        let mut right = left.clone();
        right.input_data = "0x60010042".to_owned();
        right.output = "0x6001".to_owned();
        let mut reference = capture_debug_trace(&left, vec![contract(&[0], &[offset], "C.sol")]);
        let mut candidate = capture_debug_trace(&right, vec![contract(&[0], &[offset], "C.sol")]);
        assert!(!compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8).equivalent);
        assert!(candidate.set_constructor_args("0x99").is_err());
        reference.set_constructor_args("0x0042").expect("arguments");
        candidate.set_constructor_args("0x0042").expect("arguments");
        assert!(compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8).equivalent);
        reference.execution.success = false;
        candidate.execution.success = false;
        assert!(
            !compare_debug_traces(&reference, &candidate, DebugDiffMode::Steps, 8)
                .execution_equivalent
        );
    }

    #[test]
    fn checkpoints_cannot_hide_an_unreached_statement() {
        let first = SOURCE.find("uint256").expect("statement");
        let second = SOURCE.find("x++").expect("statement");
        let mut reference = capture_debug_trace(
            &trace(&[0, 1], "0x"),
            vec![contract(&[0, 1], &[first, second], "C.sol")],
        );
        let mut candidate =
            capture_debug_trace(&trace(&[0], "0x"), vec![contract(&[0], &[first], "C.sol")]);
        let checkpoints = [DebugCheckpoint {
            source: "C.sol".to_owned(),
            line: 4,
        }];
        reference.retain_checkpoints(&checkpoints);
        candidate.retain_checkpoints(&checkpoints);
        let report = compare_debug_traces(&reference, &candidate, DebugDiffMode::Coverage, 8);
        assert!(!report.equivalent);
        assert!(!report.comparable);
        assert_eq!(reference.events.len(), 1);
        assert_eq!(candidate.events.len(), 0);
        assert!(report
            .diagnostics
            .iter()
            .any(|message| message == "candidate: checkpoint C.sol:4 was not reached"));
    }

    #[test]
    fn partial_artifacts_and_invalid_ranges_cannot_pass() {
        let offset = SOURCE.find("uint256").expect("statement");
        let reference =
            capture_debug_trace(&trace(&[0], "0x"), vec![contract(&[0], &[offset], "C.sol")]);
        let partial = capture_debug_trace(
            &trace(&[0, 99], "0x"),
            vec![contract(&[0], &[offset], "C.sol")],
        );
        assert!(!compare_debug_traces(&reference, &partial, DebugDiffMode::Steps, 8).comparable);
        let invalid = capture_debug_trace(
            &trace(&[0], "0x"),
            vec![contract(&[0], &[SOURCE.len() + 1], "C.sol")],
        );
        assert!(!compare_debug_traces(&reference, &invalid, DebugDiffMode::Steps, 8).comparable);
    }

    #[test]
    fn a_single_instruction_body_is_not_smoothed_out() {
        let declaration = SOURCE.find("function").expect("declaration");
        let statement = SOURCE.find("uint256").expect("statement");
        let mut captured = capture_debug_trace(
            &trace(&[0, 1, 2], "0x"),
            vec![contract(
                &[0, 1, 2],
                &[declaration, statement, declaration],
                "C.sol",
            )],
        );
        captured.retain_checkpoints(&[DebugCheckpoint {
            source: "C.sol".to_owned(),
            line: 3,
        }]);
        assert!(captured.diagnostics.is_empty());
        assert_eq!(captured.events.len(), 1);
        assert_eq!(captured.events[0].pc, 1);
    }
}
