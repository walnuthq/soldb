//! The `Call Stack:` block of a summary: every call the trace made, nested under its
//! caller, with the arguments it was called with and what it returned or reverted with,
//! and where a failed transaction's revert started.
//!
//! The frames are [`StepMap::call_tree`]'s, so they are the frames `backtrace` shows at
//! any step inside them; this module only words them.

use soldb_core::TransactionTrace;
use soldb_debugger::{
    CallExit, CallNode, ContractDebugInfo, FrameArgument, SourceFunction, StepMap,
};
use soldb_ethdebug::ErrorRegistry;

use crate::{
    decode_calldata_word, descriptor_from_source_function, dim, error_color, format_decoded_call,
    format_raw_stack, format_source_prototype, function_color, info, number_color, CallDescriptor,
    DecodedCallParam,
};

/// What the summary needs besides the trace and its map.
pub(crate) struct CallTreeContext<'a> {
    pub(crate) errors: &'a ErrorRegistry,
    /// The top-level call as the command line or an ABI describes it, for a root whose
    /// code has no debug info.
    pub(crate) root_call: Option<CallDescriptor>,
    /// What to call a root whose code has no debug info.
    pub(crate) root_name: &'a str,
}

/// One printed line: its nesting, whether it gets a frame number, and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    level: usize,
    numbered: bool,
    text: String,
}

/// The call tree's lines, then where a failed transaction's revert started.
pub(crate) fn call_tree_lines(
    trace: &TransactionTrace,
    map: &StepMap,
    context: &CallTreeContext,
) -> Vec<String> {
    let nodes = map.call_tree(trace);
    let origin = map.revert_origin(trace, &nodes);
    let tree = Tree {
        trace,
        map,
        nodes: &nodes,
        context,
        children: children_of(&nodes),
        origin_node: origin.and_then(|step| innermost_node(&nodes, step)),
        origin,
    };
    let mut lines = Vec::new();
    for root in (0..nodes.len()).filter(|&index| nodes[index].parent.is_none()) {
        lines.extend(tree.root(root));
    }
    let mut number = 0;
    let mut output = lines
        .into_iter()
        .map(|line| {
            let indent = "  ".repeat(line.level);
            if !line.numbered {
                return format!("{indent}{}", line.text);
            }
            number += 1;
            format!(
                "{indent}{} {}",
                dim(format!("#{}", number - 1)),
                function_color(&line.text)
            )
        })
        .collect::<Vec<_>>();
    if let Some(step) = origin {
        output.extend(backtrace_lines(map, step));
    }
    output
}

struct Tree<'a> {
    trace: &'a TransactionTrace,
    map: &'a StepMap,
    nodes: &'a [CallNode],
    context: &'a CallTreeContext<'a>,
    children: Vec<Vec<usize>>,
    origin: Option<usize>,
    /// The innermost frame the revert started in.
    origin_node: Option<usize>,
}

impl Tree<'_> {
    /// A top-level call: its dispatcher, then the function it selected, level with it,
    /// and the function's callees under it.
    fn root(&self, index: usize) -> Vec<Line> {
        let node = &self.nodes[index];
        let name = node
            .frame
            .contract_name
            .clone()
            .unwrap_or_else(|| self.context.root_name.to_owned());
        let mut lines = vec![numbered(0, format!("{name}::runtime_dispatcher"))];
        let input = self.map.call_input(self.trace, node);
        let selected = self.selected_function(index);
        match selected {
            Some(function) => {
                let line = self.function_line(function, input.as_deref(), false);
                lines.push(numbered(0, line));
                lines.extend(self.body(function, 1));
            }
            None => {
                if let Some(call) = &self.context.root_call {
                    lines.push(numbered(0, format_decoded_call(&call.name, &call.params)));
                }
                lines.extend(self.body(index, 1));
            }
        }
        lines.extend(self.exit_lines(index, selected, 1));
        lines
    }

    /// The function an external call's dispatcher handed it to: the frame's only callee,
    /// when that is a function of its own code.
    fn selected_function(&self, index: usize) -> Option<usize> {
        let [only] = self.children[index].as_slice() else {
            return None;
        };
        let callee = &self.nodes[*only];
        (!callee.frame.external && self.source_function(*only).is_some()).then_some(*only)
    }

    /// What a frame did, one level in: its callees, and the revert that started in it.
    fn body(&self, index: usize, level: usize) -> Vec<Line> {
        let mut lines = self.callees(index, level);
        if self.origin_node == Some(index) {
            lines.push(plain(level, self.origin_line()));
        }
        lines
    }

    /// The calls `index` made, at `level`, with identical calls in a row shown once.
    fn callees(&self, index: usize, level: usize) -> Vec<Line> {
        let mut blocks = Vec::<(Vec<Line>, usize)>::new();
        for &callee in &self.children[index] {
            let block = self.callee(callee, level);
            let leaf = self.children[callee].is_empty();
            match blocks.last_mut() {
                Some((last, count)) if leaf && *last == block => *count += 1,
                _ => blocks.push((block, 1)),
            }
        }
        blocks
            .into_iter()
            .flat_map(|(mut block, count)| {
                if count > 1 {
                    block[0].text.push_str(&format!(" × {count}"));
                }
                block
            })
            .collect()
    }

    fn callee(&self, index: usize, level: usize) -> Vec<Line> {
        let node = &self.nodes[index];
        if !node.frame.external {
            return self.internal_function(index, level);
        }
        let input = self.map.call_input(self.trace, node);
        let selected = self.selected_function(index);
        let mut lines = match selected {
            Some(function) => {
                let line = self.function_line(function, input.as_deref(), false);
                let contract = node.frame.contract_name.as_deref().unwrap_or("");
                let mut lines = vec![numbered(level, format!("{contract}::{line}"))];
                lines.extend(self.body(function, level + 1));
                lines
            }
            None => {
                let mut lines = vec![numbered(level, self.unknown_call(index, input.as_deref()))];
                lines.extend(self.body(index, level + 1));
                lines
            }
        };
        lines.extend(self.exit_lines(index, selected, level + 1));
        lines
    }

    /// A function entered by a jump: its line, the entry stack when its arguments could
    /// not be read, its callees, and what it returned.
    fn internal_function(&self, index: usize, level: usize) -> Vec<Line> {
        let node = &self.nodes[index];
        let mut lines = vec![numbered(level, self.function_line(index, None, true))];
        let has_params = self
            .source_function(index)
            .is_some_and(|(_, function)| !function.params.is_empty());
        if has_params && node.frame.arguments.is_empty() {
            if let Some(entry) = self.trace.steps.get(node.frame.entry_step) {
                lines.push(plain(
                    level,
                    format!(
                        "  {} {}",
                        info("raw entry stack:"),
                        number_color(format_raw_stack(&entry.stack().to_vec()))
                    ),
                ));
            }
        }
        lines.extend(self.body(index, level + 1));
        if let Some(returned) = self.returned_line(index) {
            lines.push(plain(level + 1, returned));
        }
        lines
    }

    /// A function's line: its name and arguments, `[internal]` for one entered by a jump,
    /// and where it is declared.
    fn function_line(&self, index: usize, input: Option<&str>, internal: bool) -> String {
        let node = &self.nodes[index];
        let Some((contract, function)) = self.source_function(index) else {
            return node
                .frame
                .function_name
                .clone()
                .unwrap_or_else(|| "<unknown>".to_owned());
        };
        let call = match input {
            Some(input) => {
                let call = descriptor_from_source_function(function, input);
                format_decoded_call(&call.name, &call.params)
            }
            None if !node.frame.arguments.is_empty() => {
                format_decoded_call(&function.name, &arguments(&node.frame.arguments))
            }
            None => format_source_prototype(&function.name, &function.params),
        };
        let internal = if internal {
            format!(" {}", dim("[internal]"))
        } else {
            String::new()
        };
        let location = contract
            .source_path(function.source_id)
            .map(|path| dim(format!(" at {path}:{}", function.declaration_line)))
            .unwrap_or_default();
        format!("{call}{internal}{location}")
    }

    /// A call into code without debug info: the account and the selector it was called
    /// with.
    fn unknown_call(&self, index: usize, input: Option<&str>) -> String {
        let frame = &self.nodes[index].frame;
        let account = frame
            .contract_name
            .clone()
            .or_else(|| frame.address.clone())
            .unwrap_or_else(|| "<unknown>".to_owned());
        let selector = input
            .and_then(|input| input.trim_start_matches("0x").get(..8))
            .map(|selector| format!("0x{selector}"));
        match (selector, frame.contract_name.is_some()) {
            (Some(selector), _) => format!("{account}::{selector}"),
            (None, true) => format!("{account}::runtime_dispatcher"),
            (None, false) => account,
        }
    }

    /// How an external call ended, decoded against the function it ran when it is known.
    fn exit_lines(&self, index: usize, selected: Option<usize>, level: usize) -> Vec<Line> {
        let node = &self.nodes[index];
        let declared = selected.and_then(|selected| self.source_function(selected));
        let text = match self.map.call_exit(self.trace, node) {
            CallExit::Returned(data) => {
                let data = data.unwrap_or_default();
                let empty = data.trim_start_matches("0x").is_empty();
                match declared {
                    Some((contract, function)) if !function.returns.is_empty() => {
                        format!("← return ({})", decoded_returns(contract, function, &data))
                    }
                    _ if empty => return Vec::new(),
                    _ => format!("← return {data}"),
                }
            }
            CallExit::Reverted(data) => match data {
                Some(data) => match self.context.errors.decode(&data) {
                    Some(decoded) => error_color(format!("← revert {decoded}")),
                    None if data.trim_start_matches("0x").is_empty() => {
                        error_color("← revert".to_owned())
                    }
                    None => error_color(format!("← revert {data}")),
                },
                None => error_color("← revert".to_owned()),
            },
            CallExit::Failed(error) => error_color(format!("← failed: {error}")),
            CallExit::Unfinished => dim("← the recording ends inside this call".to_owned()),
        };
        vec![plain(level, text)]
    }

    /// What an internal function returned, when it returned at all.
    fn returned_line(&self, index: usize) -> Option<String> {
        let (contract, function) = self.source_function(index)?;
        if function.returns.is_empty() {
            return None;
        }
        let values = self.map.returned_values(self.trace, &self.nodes[index])?;
        let shown = if values.len() == function.returns.len() {
            values
                .iter()
                .map(|value| labelled(&value.ty, &value.name, Some(&value.value.display)))
                .collect::<Vec<_>>()
        } else {
            function
                .returns
                .iter()
                .map(|value| {
                    labelled(
                        &value.ty,
                        contract.return_name(function, value).unwrap_or_default(),
                        None,
                    )
                })
                .collect()
        };
        Some(format!("← return ({})", shown.join(", ")))
    }

    /// Where the revert of a failed transaction started.
    fn origin_line(&self) -> String {
        let location = self
            .origin
            .and_then(|step| self.map.location(step))
            .map(|location| format!(" at {}:{}", location.path, location.line))
            .unwrap_or_default();
        error_color(format!("← revert started here{location}"))
    }

    /// The parsed declaration of the function a frame runs, with the contract it is in.
    fn source_function(&self, index: usize) -> Option<(&ContractDebugInfo, &SourceFunction)> {
        let id = self.nodes[index].function?;
        let contract = self.map.contracts().get(id.contract)?;
        Some((contract, contract.functions.get(id.function)?))
    }
}

/// Each node's callees, in the order they were entered.
fn children_of(nodes: &[CallNode]) -> Vec<Vec<usize>> {
    let mut children = vec![Vec::new(); nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        if let Some(parent) = node.parent {
            children[parent].push(index);
        }
    }
    children
}

/// The deepest frame `step` ran in.
fn innermost_node(nodes: &[CallNode], step: usize) -> Option<usize> {
    nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.frame.entry_step <= step && step <= node.end_step)
        .max_by_key(|(_, node)| node.frame.depth)
        .map(|(index, _)| index)
}

/// The frames at the step the revert started at, innermost first, as Foundry's
/// `Backtrace:` lists them.
fn backtrace_lines(map: &StepMap, step: usize) -> Vec<String> {
    let frames = map.frames(step);
    let mut lines = vec![info("Backtrace:")];
    for (position, frame) in frames.iter().enumerate() {
        // A dispatcher frame is shown only when no function of its code was running.
        let inner_function = position
            .checked_sub(1)
            .and_then(|inner| frames.get(inner))
            .is_some_and(|inner| !inner.external);
        if frame.function_name.is_none() && inner_function {
            continue;
        }
        let account = frame
            .contract_name
            .clone()
            .or_else(|| frame.address.clone())
            .unwrap_or_else(|| "<unknown>".to_owned());
        let name = match &frame.function_name {
            Some(function) => format!("{account}.{function}"),
            None => account,
        };
        let location = frame
            .location
            .as_ref()
            .map(|location| dim(format!(" ({}:{})", location.path, location.line)))
            .unwrap_or_default();
        lines.push(format!("  at {}{location}", function_color(name)));
    }
    lines
}

/// A function's return values decoded from ABI-encoded data.
fn decoded_returns(contract: &ContractDebugInfo, function: &SourceFunction, data: &str) -> String {
    // The return data is ABI-encoded like calldata without a selector.
    let encoded = format!("0x00000000{}", data.trim_start_matches("0x"));
    function
        .returns
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let decoded = decode_calldata_word(&encoded, index, &value.ty);
            let name = contract.return_name(function, value).unwrap_or_default();
            labelled(
                &value.ty,
                name,
                decoded.as_ref().map(|word| word.value.as_str()),
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `type name = value`, leaving out what is missing.
fn labelled(ty: &str, name: &str, value: Option<&str>) -> String {
    let label = [ty, name]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    match value {
        Some(value) => format!("{label} = {value}"),
        None => label,
    }
}

fn arguments(arguments: &[FrameArgument]) -> Vec<DecodedCallParam> {
    arguments
        .iter()
        .map(|argument| DecodedCallParam {
            name: argument.name.clone(),
            ty: Some(argument.ty.clone()),
            value: argument.value.display.clone(),
            raw: false,
        })
        .collect()
}

fn numbered(level: usize, text: String) -> Line {
    Line {
        level,
        numbered: true,
        text,
    }
}

fn plain(level: usize, text: String) -> Line {
    Line {
        level,
        numbered: false,
        text,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use soldb_core::{Bytes, StepSnapshot, TraceStep, TransactionTrace};
    use soldb_debugger::{ContractDebugInfo, StepMap};
    use soldb_ethdebug::{
        encode_function_call, function_selector, source_range, ErrorRegistry, EthdebugInfo,
        Instruction,
    };

    use super::{call_tree_lines, CallTreeContext};

    const SOURCE: &str = "\
contract C {
    function run(uint256 a) public returns (uint256) {
        uint256 f = fee(a);
        return f;
    }
    function fee(uint256 a) internal pure returns (uint256 f) {
        f = a / 100;
    }
}
";
    const ROOT: &str = "0xaaaa000000000000000000000000000000000001";
    const CALLEE: &str = "0xbbbb000000000000000000000000000000000002";

    fn span(needle: &str) -> (u64, u64) {
        let start = SOURCE.find(needle).expect(needle);
        let end = if needle.starts_with("function") {
            start + SOURCE[start..].find("\n    }").expect("function end") + 6
        } else {
            start + needle.len()
        };
        (start as u64, (end - start) as u64)
    }

    fn contract(address: &str) -> ContractDebugInfo {
        let whole = (0, SOURCE.len() as u64);
        let at = |pc: u64, (offset, length): (u64, u64)| {
            Instruction::new(
                pc,
                "JUMPDEST",
                Some(serde_json::json!({"code": source_range(0, offset, length)})),
            )
        };
        let call_fee = span("uint256 f = fee(a);");
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "C".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![
                at(0, whole),
                at(1, whole),
                at(10, span("function run")),
                at(12, call_fee),
                at(13, call_fee),
                at(14, span("return f;")),
                at(15, span("return f;")),
                at(20, span("function fee")),
                at(21, span("f = a / 100;")),
                at(22, span("f = a / 100;")),
            ],
            sources: BTreeMap::from([(0, "C.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        ContractDebugInfo::new(
            Some(address),
            "C",
            info,
            BTreeMap::from([(0, SOURCE.to_owned())]),
        )
    }

    fn step(pc: u64, depth: u64, op: &str, stack: &[&str], memory: &[u8]) -> TraceStep {
        TraceStep::new(
            pc,
            Arc::from(op),
            0,
            0,
            depth,
            None,
            StepSnapshot::new(
                stack.iter().map(|word| Arc::from(*word)).collect(),
                Some(Bytes::copy_from_slice(memory)),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        )
    }

    fn hex_bytes(data: &str) -> Vec<u8> {
        let data = data.trim_start_matches("0x");
        (0..data.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&data[index..index + 2], 16).expect("hex"))
            .collect()
    }

    fn word(value: u8) -> Vec<u8> {
        let mut word = vec![0; 31];
        word.push(value);
        word
    }

    /// `run(100)` calls `fee`, then makes `calls` external calls to `run(7)` on the callee,
    /// each running `callee` steps and halting with `halt`, then the root halts with
    /// `root_halt`.
    fn trace(
        callee: &[(u64, &str, &[&str])],
        halt: (&str, &[u8]),
        calls: usize,
        root_halt: (&str, &[u8]),
    ) -> TransactionTrace {
        let input =
            hex_bytes(&encode_function_call("run(uint256)", &["7".to_owned()]).expect("calldata"));
        let address = format!("0x{}", CALLEE.trim_start_matches("0x"));
        let call_stack = [
            "0x0",
            "0x0",
            "0x24",
            "0x0",
            "0x0",
            address.as_str(),
            "0xffff",
        ];
        let mut steps = vec![
            step(0, 1, "PUSH1", &[], &[]),
            step(1, 1, "JUMP", &["0xa"], &[]),
            step(10, 1, "JUMPDEST", &["0x64"], &[]),
            step(12, 1, "JUMP", &["0x64", "0xd", "0x64", "0x14"], &[]),
            step(20, 1, "JUMPDEST", &["0x64", "0xd", "0x64"], &[]),
            step(21, 1, "DIV", &["0x64", "0xd", "0x64"], &[]),
            step(22, 1, "JUMP", &["0x64", "0x1", "0xd"], &[]),
            step(13, 1, "JUMPDEST", &["0x64", "0x1"], &[]),
        ];
        for _ in 0..calls {
            steps.push(step(14, 1, "CALL", &call_stack, &input));
            for (pc, op, stack) in callee {
                steps.push(step(*pc, 2, op, stack, &[]));
            }
            if !callee.is_empty() {
                let size = format!("{:#x}", halt.1.len());
                steps.push(step(15, 2, halt.0, &[&size, "0x0"], halt.1));
            }
            steps.push(step(15, 1, "POP", &["0x64", "0x1", "0x1"], &[]));
        }
        let size = format!("{:#x}", root_halt.1.len());
        steps.push(step(15, 1, root_halt.0, &[&size, "0x0"], root_halt.1));
        TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: Some(ROOT.to_owned()),
            value: "0x0".to_owned(),
            input_data: encode_function_call("run(uint256)", &["100".to_owned()])
                .expect("calldata"),
            gas_used: 0,
            output: "0x".to_owned(),
            success: root_halt.0 != "REVERT",
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: steps.into(),
        }
    }

    fn lines(trace: &TransactionTrace, contracts: Vec<ContractDebugInfo>) -> Vec<String> {
        let map = StepMap::new(trace, contracts);
        let errors = ErrorRegistry::default();
        call_tree_lines(
            trace,
            &map,
            &CallTreeContext {
                errors: &errors,
                root_call: None,
                root_name: "Root",
            },
        )
    }

    const CALLEE_RUNS: &[(u64, &str, &[&str])] = &[
        (0, "PUSH1", &[]),
        (1, "JUMP", &["0xa"]),
        (10, "JUMPDEST", &["0x7"]),
    ];

    #[test]
    fn a_revert_is_decoded_where_it_started_and_backtraced() {
        let reason =
            hex_bytes(&encode_function_call("Error(string)", &["no".to_owned()]).expect("data"));
        let trace = trace(CALLEE_RUNS, ("REVERT", &reason), 1, ("REVERT", &reason));
        assert_eq!(
            lines(&trace, vec![contract(ROOT), contract(CALLEE)]),
            [
                "#0 C::runtime_dispatcher",
                "#1 run(uint256 a = 100) at C.sol:2",
                "  #2 fee(uint256 a = 100) [internal] at C.sol:6",
                "    ← return (uint256 f = 1)",
                "  #3 C::run(uint256 a = 7) at C.sol:2",
                "    ← revert started here at C.sol:4",
                "    ← revert no",
                "  ← revert no",
                "Backtrace:",
                "  at C.run (C.sol:4)",
                "  at C.run (C.sol:4)",
            ]
        );
    }

    #[test]
    fn a_return_is_decoded_against_the_function_that_ran() {
        let trace = trace(CALLEE_RUNS, ("RETURN", &word(42)), 1, ("RETURN", &word(1)));
        assert_eq!(
            lines(&trace, vec![contract(ROOT), contract(CALLEE)])[4..],
            [
                "  #3 C::run(uint256 a = 7) at C.sol:2",
                "    ← return (uint256 = 42)",
                "  ← return (uint256 = 1)",
            ]
        );
    }

    #[test]
    fn calls_without_debug_info_show_the_account_and_selector() {
        // The callee runs code nobody described; then the same call to an account
        // without code twice in a row is shown once.
        let selector = function_selector("run(uint256)").expect("selector");
        let selector = format!("0x{}", soldb_core::encode_hex(&selector));
        let with_code = trace(CALLEE_RUNS, ("RETURN", &word(42)), 1, ("RETURN", &word(1)));
        let shown = lines(&with_code, vec![contract(ROOT)]);
        assert_eq!(shown[4], format!("  #3 {CALLEE}::{selector}"));
        assert_eq!(
            shown[5],
            format!("    ← return 0x{}", soldb_core::encode_hex(&word(42)))
        );

        let codeless = trace(&[], ("STOP", &[]), 2, ("RETURN", &word(1)));
        let shown = lines(&codeless, vec![contract(ROOT)]);
        assert_eq!(
            shown[4..],
            [
                format!("  #3 {CALLEE}::{selector} × 2"),
                "  ← return (uint256 = 1)".to_owned(),
            ]
        );
    }

    #[test]
    fn a_trace_without_debug_info_names_the_root_as_told() {
        let trace = trace(&[], ("STOP", &[]), 0, ("STOP", &[]));
        assert_eq!(lines(&trace, Vec::new()), ["#0 Root::runtime_dispatcher"]);
    }
}
