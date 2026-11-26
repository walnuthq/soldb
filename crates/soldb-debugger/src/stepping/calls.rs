//! The call tree of a trace: every frame as it was entered and left, with what it was
//! called with and how it ended.
//!
//! [`StepMap::frames`] answers for one step; the tree answers for the whole run, from the
//! same walk over the same frame depths, so a frame in the tree is the frame `backtrace`
//! shows at any step inside it.

use std::collections::BTreeSet;

use soldb_core::{opcode, TransactionTrace};

use super::{
    call_target, calldata_for_step, hex_bytes, parameter_slots, parameter_stack_slots,
    source_selector, Frame, FrameRecord, FunctionId, JumpMarker, StepMap,
};
use crate::roots::root_index;
use crate::{decode_arguments, ArgumentLayout, FrameArgument, FrameState, SourceParam};

/// One frame of a trace's call tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallNode {
    /// The frame as it stands at its last step, with the arguments it was entered with
    /// when they are known.
    pub frame: Frame,
    /// The function the frame ran: the one whose entry point it was entered at, otherwise
    /// the one its last step is in. A function can end in code the compiler placed in
    /// another's span, such as an inlined modifier's, so where it ends does not name it.
    pub function: Option<FunctionId>,
    /// The index of the frame that made the call; `None` for a top-level call.
    pub parent: Option<usize>,
    /// The last step of the frame and of everything it called.
    pub end_step: usize,
    /// A call to an account that ran no code, such as a precompile or an account without
    /// code. It has no steps; its `entry_step` is the call instruction.
    pub codeless: bool,
    /// Not a call: code of `function` that the compiler laid out in line in the frame
    /// `parent`, which ran into it at `entry_step`. Nothing in the recording says where it
    /// ends or what it was passed, so it has no steps of its own, no callees, and no
    /// arguments, and a function is listed once in the frame it ran in. Code of another
    /// function that a jump landed on is not listed at all: see [`StepMap::call_tree`].
    pub inlined: bool,
}

/// How an external call ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallExit {
    /// `RETURN`, `STOP`, or `SELFDESTRUCT`, with the data returned when the recording
    /// shows it.
    Returned(Option<String>),
    /// `REVERT`, with the revert data when the recording shows it.
    Reverted(Option<String>),
    /// An exceptional halt, such as running out of gas, as the backend named it.
    Failed(String),
    /// The recording ends inside the call.
    Unfinished,
}

impl CallExit {
    /// Whether the call's effects were undone.
    #[must_use]
    pub fn failed(&self) -> bool {
        matches!(self, Self::Reverted(_) | Self::Failed(_))
    }

    /// The returned or revert data, as `0x`-prefixed hex.
    #[must_use]
    pub fn data(&self) -> Option<&str> {
        match self {
            Self::Returned(data) | Self::Reverted(data) => data.as_deref(),
            Self::Failed(_) | Self::Unfinished => None,
        }
    }
}

impl StepMap {
    /// Every call of the trace in the order it was entered, each after the frame that
    /// made it: the external calls, the functions a jump called, the function an external
    /// call's dispatcher selected, and the modifiers that ran around a function.
    ///
    /// Code the compiler laid out in line is not a call, whichever function its span
    /// names, and whichever pipeline compiled it: it stays in the frame it runs in, and
    /// its callees are that frame's. Where the frame ran straight into it, an
    /// [`CallNode::inlined`] entry lists the function. Where a jump landed on it, it is
    /// a branch or a block the optimizer shares between functions, credited to one of
    /// them, and it is not listed. [`StepMap::frames`] still shows either at a step
    /// inside it.
    #[must_use]
    pub fn call_tree(&self, trace: &TransactionTrace) -> Vec<CallNode> {
        let Some(last) = self.steps.len().checked_sub(1) else {
            return Vec::new();
        };
        let mut records = Vec::<(usize, FrameRecord, bool)>::new();
        let open = self.walk_frames(last, |depth, record| records.push((depth, record, false)));
        records.extend(
            open.into_iter()
                .enumerate()
                .map(|(depth, record)| (depth, record, false)),
        );
        // A call into an account without code leaves no steps, so no frame depth shows it.
        for (index, step) in trace.steps.iter().enumerate() {
            let entered = self
                .steps
                .get(index + 1)
                .is_some_and(|next| next.evm_depth > self.steps[index].evm_depth);
            if opcode::is_call(step.op()) && !entered && index < last {
                let record = FrameRecord {
                    entry_step: index,
                    last_step: index,
                    external: true,
                };
                records.push((self.steps[index].frame_depth as usize + 1, record, true));
            }
        }
        // A caller is entered no later than its callees, and where several frames begin at
        // one step the outer one comes first.
        records.sort_by_key(|(depth, record, _)| (record.entry_step, *depth));

        let mut nodes = Vec::<CallNode>::with_capacity(records.len());
        let mut callers = Vec::<usize>::new();
        for (depth, record, codeless) in records {
            while callers
                .last()
                .is_some_and(|&caller| nodes[caller].frame.depth as usize >= depth)
            {
                callers.pop();
            }
            let frame = if codeless {
                self.codeless_frame(trace, depth, record.entry_step)
            } else {
                self.with_arguments(trace, self.frame_of(depth, record))
            };
            let function = (!codeless)
                .then(|| self.entered_function(record.entry_step))
                .flatten()
                .or_else(|| {
                    frame
                        .location
                        .as_ref()
                        .and_then(|location| location.function)
                });
            nodes.push(CallNode {
                frame,
                function,
                parent: callers.last().copied(),
                end_step: record.last_step,
                codeless,
                inlined: false,
            });
            callers.push(nodes.len() - 1);
        }
        // The function an external call selected runs in the first frame under it. Where
        // the compiler laid the body out in line, that frame was not entered at an entry
        // point, and the call's own calldata names the function instead.
        let mut has_callee = vec![false; nodes.len()];
        let mut selected = vec![false; nodes.len()];
        for index in 0..nodes.len() {
            let Some(parent) = nodes[index].parent else {
                continue;
            };
            let first = !std::mem::replace(&mut has_callee[parent], true);
            let entry = nodes[index].frame.entry_step;
            selected[index] = first && !nodes[index].frame.external && nodes[parent].frame.external;
            if selected[index] && self.entered_function(entry).is_none() {
                if let Some(selected) = self.selected_function(trace, &nodes[parent], entry) {
                    nodes[index].function = Some(selected);
                }
            }
        }
        // Callees come after their callers, so one backward pass carries every end up.
        for index in (0..nodes.len()).rev() {
            if let Some(parent) = nodes[index].parent {
                nodes[parent].end_step = nodes[parent].end_step.max(nodes[index].end_step);
            }
        }
        // What is left out hands its callees to the nearest frame above that stays.
        let shown = (0..nodes.len())
            .map(|index| {
                let node = &nodes[index];
                node.frame.external
                    || selected[index]
                    || self.is_modifier(node.function)
                    || self.entered_by_call(trace, node.frame.entry_step)
            })
            .collect::<Vec<_>>();
        let parents = nodes.iter().map(|node| node.parent).collect::<Vec<_>>();
        // The nearest frame that stays, from `parent` up.
        let staying = |mut parent: Option<usize>| {
            while let Some(above) = parent.filter(|above| !shown[*above]) {
                parent = parents[above];
            }
            parent
        };
        // A modifier ends where the body of the function it runs around begins: the
        // first code under it, laid out in line, whose span is that function's. What
        // runs from there on is the function's, not the modifier's.
        let mut handover = vec![None::<(usize, usize)>; nodes.len()];
        // Where the body of each function begins, when modifiers ran before it.
        let mut bodies = vec![None::<usize>; nodes.len()];
        for index in 0..nodes.len() {
            if shown[index] || nodes[index].function.is_none() {
                continue;
            }
            let mut around = Vec::new();
            let mut owner = staying(parents[index]);
            while let Some(modifier) =
                owner.filter(|above| self.is_modifier(nodes[*above].function))
            {
                around.push(modifier);
                owner = staying(parents[modifier]);
            }
            let Some(owner) = owner.filter(|owner| nodes[*owner].function == nodes[index].function)
            else {
                continue;
            };
            let body = nodes[index].frame.entry_step;
            bodies[owner].get_or_insert(body);
            for modifier in around {
                handover[modifier].get_or_insert((body, owner));
            }
        }
        for (index, node) in nodes.iter_mut().enumerate() {
            if let Some((body, _)) = handover[index] {
                node.end_step = node.end_step.min(body.saturating_sub(1));
            }
        }
        let functions = nodes.iter().map(|node| node.function).collect::<Vec<_>>();
        let mut position = vec![None; nodes.len()];
        let mut leading = vec![None::<(usize, usize)>; nodes.len()];
        // The functions already listed as laid out in line, by the frame they ran in.
        let mut listed = BTreeSet::<(Option<usize>, FunctionId)>::new();
        let mut calls = Vec::with_capacity(nodes.len());
        for (index, mut node) in nodes.into_iter().enumerate() {
            let entry = node.frame.entry_step;
            let mut owner = staying(parents[index]);
            while let Some((_, body_owner)) = owner
                .and_then(|above| handover[above])
                .filter(|(body, _)| entry >= *body)
            {
                owner = Some(body_owner);
            }
            // What a function's leading modifier called before the body is the modifier's.
            let parent = owner.and_then(|above| {
                leading[above]
                    .filter(|(body, _)| entry < *body)
                    .map(|(_, modifier)| modifier)
                    .or(position[above])
            });
            if !shown[index] {
                // Code laid out in line. The frame's own function coming back after
                // another's code is not listed: it is the frame.
                let Some(function) = node.function else {
                    continue;
                };
                let own = owner.and_then(|above| functions[above]) == Some(function);
                if own || !self.fell_into(trace, entry) || !listed.insert((parent, function)) {
                    continue;
                }
                node.parent = parent;
                node.end_step = entry;
                node.inlined = true;
                node.frame.arguments.clear();
                calls.push(node);
                continue;
            }
            node.parent = parent;
            position[index] = Some(calls.len());
            let lead = selected[index].then(|| self.leading_frame(&node)).flatten();
            calls.push(node);
            let Some(mut lead) = lead else {
                continue;
            };
            lead.parent = position[index];
            if self.is_modifier(lead.function) {
                // Without a step that shows where the body starts, nothing says where the
                // modifier ends, and it gets no frame.
                if let Some(body) = bodies[index].filter(|body| *body > entry) {
                    lead.end_step = body - 1;
                    leading[index] = Some((body, calls.len()));
                    calls.push(lead);
                }
            } else if let Some(function) = lead.function.filter(|_| self.fell_into(trace, entry)) {
                lead.inlined = true;
                listed.insert((position[index], function));
                calls.push(lead);
            }
        }
        calls
    }

    /// A frame for the function whose code the call `call` begins in, when that is not
    /// the function the call runs. A function laid out in line with its modifiers begins
    /// in the first one's code, and one laid out with a callee can begin in the callee's.
    fn leading_frame(&self, call: &CallNode) -> Option<CallNode> {
        let entry = call.frame.entry_step;
        let location = self.steps.get(entry)?.location?;
        let function = Some(FunctionId {
            contract: location.key.contract,
            function: location.function?,
        });
        if function == call.function {
            return None;
        }
        let record = FrameRecord {
            entry_step: entry,
            last_step: entry,
            external: false,
        };
        Some(CallNode {
            frame: self.frame_of(call.frame.depth as usize + 1, record),
            function,
            parent: None,
            end_step: entry,
            codeless: false,
            inlined: false,
        })
    }

    /// Whether execution reached the code at `step` by running into it: from the
    /// instruction before it in its EVM frame, or back from a call that instruction made.
    ///
    /// That is what laid out in line means. Code a jump lands on is somewhere else in the
    /// bytecode: a branch, or a block the optimizer shares between functions and the
    /// source map credits to one of them, and nothing says which.
    fn fell_into(&self, trace: &TransactionTrace, step: usize) -> bool {
        let Some(before) = step.checked_sub(1) else {
            return false;
        };
        let (Some(here), Some(previous)) = (self.steps.get(step), self.steps.get(before)) else {
            return false;
        };
        if here.starts_root || previous.evm_depth < here.evm_depth {
            return false;
        }
        if previous.evm_depth > here.evm_depth {
            return true;
        }
        match trace.steps.step(before).op() {
            opcode::JUMP => false,
            opcode::JUMPI => self.pcs[step] == self.pcs[before] + 1,
            _ => true,
        }
    }

    /// Whether a jump called the frame entered at `step`: one in its own EVM frame that
    /// the artifact marks as a call, or that lands on a function's entry point.
    fn entered_by_call(&self, trace: &TransactionTrace, step: usize) -> bool {
        let Some(before) = step.checked_sub(1) else {
            return false;
        };
        let (Some(here), Some(previous)) = (self.steps.get(step), self.steps.get(before)) else {
            return false;
        };
        if here.starts_root
            || here.evm_depth != previous.evm_depth
            || trace.steps.step(before).op() != opcode::JUMP
        {
            return false;
        }
        let marked = previous
            .contract
            .and_then(|contract| self.contracts.get(contract))
            .is_some_and(|contract| {
                contract.jump_marker_at_pc(self.pcs[before]) == JumpMarker::Call
            });
        marked || self.entered_function(step).is_some()
    }

    /// Whether `function` is a modifier: it runs in line around the function that names
    /// it, so no jump calls it, and it is still a frame of its own in the source.
    fn is_modifier(&self, function: Option<FunctionId>) -> bool {
        function
            .and_then(|id| self.contracts.get(id.contract)?.functions.get(id.function))
            .is_some_and(|function| function.placeholder.is_some())
    }

    /// The function whose entry point `step` is at, in the code the step runs.
    fn entered_function(&self, step: usize) -> Option<FunctionId> {
        let contract = self.steps.get(step)?.contract?;
        let function = self
            .contracts
            .get(contract)?
            .function_entry_at_pc(self.pcs[step])?;
        Some(FunctionId { contract, function })
    }

    /// The function of the code at `step` that the calldata of `call` selects, when exactly
    /// one of its functions has that selector. A modifier is never called by calldata.
    fn selected_function(
        &self,
        trace: &TransactionTrace,
        call: &CallNode,
        step: usize,
    ) -> Option<FunctionId> {
        let input = self.call_input(trace, call)?;
        let selector = input.trim_start_matches("0x").get(..8)?;
        let contract = self.steps.get(step)?.contract?;
        let mut selected = self
            .contracts
            .get(contract)?
            .functions
            .iter()
            .enumerate()
            .filter(|(_, function)| function.placeholder.is_none())
            .filter(|(_, function)| {
                source_selector(function)
                    .is_some_and(|bytes| hex_bytes(&bytes).eq_ignore_ascii_case(selector))
            })
            .map(|(function, _)| FunctionId { contract, function });
        let only = selected.next()?;
        selected.next().is_none().then_some(only)
    }

    /// The frame of a call that ran no code, at the call instruction.
    fn codeless_frame(&self, trace: &TransactionTrace, depth: usize, step: usize) -> Frame {
        let address = trace.steps.get(step).and_then(call_target);
        Frame {
            depth: depth as u32,
            external: true,
            contract_name: address.as_deref().and_then(|address| {
                self.contracts
                    .iter()
                    .find(|contract| contract.address.as_deref() == Some(address))
                    .map(|contract| contract.name.clone())
            }),
            address,
            function_name: None,
            entry_step: step,
            step,
            pc: self.pcs[step],
            location: None,
            arguments: Vec::new(),
            kind: None,
        }
    }

    /// The input an external call was made with, as `0x`-prefixed hex: the top-level
    /// call's input for a root, else what the caller passed. `None` for an internal
    /// function, a creation, or a call whose input the recording does not show.
    #[must_use]
    pub fn call_input(&self, trace: &TransactionTrace, node: &CallNode) -> Option<String> {
        if !node.frame.external {
            return None;
        }
        let entry = node.frame.entry_step;
        if node.parent.is_none() {
            let root = self.roots.get(root_index(&self.roots, entry))?;
            return (!root.creation(trace)).then(|| prefixed(root.input(trace)));
        }
        if node.codeless {
            return trace.steps.get(entry)?.call_input();
        }
        // The backend's record of the call when it kept one, as the argument proof reads it.
        let recorded = calldata_for_step(trace, &self.roots, entry);
        if !recorded.is_empty() {
            return Some(prefixed(recorded));
        }
        trace.steps.get(entry.checked_sub(1)?)?.call_input()
    }

    /// How an external call ended. Meaningless for an internal function, which ends
    /// where its caller resumes; see [`StepMap::returned_values`].
    #[must_use]
    pub fn call_exit(&self, trace: &TransactionTrace, node: &CallNode) -> CallExit {
        if node.codeless {
            // The call pushes whether it succeeded, and leaves what it returned.
            let Some(after) = trace.steps.get(node.frame.entry_step + 1) else {
                return CallExit::Unfinished;
            };
            let data = after.return_data().map(prefixed);
            return match after.stack().peek(0).map(|word| word.is_zero()) {
                Some(false) => CallExit::Returned(data),
                Some(true) => CallExit::Reverted(data),
                None => CallExit::Unfinished,
            };
        }
        let end = node.end_step;
        let Some(step) = trace.steps.get(end) else {
            return CallExit::Unfinished;
        };
        let last_root = node.parent.is_none() && end + 1 == trace.steps.len();
        let data = || {
            step.halt_data().or_else(|| {
                if last_root {
                    Some(prefixed(&trace.output))
                } else {
                    trace
                        .steps
                        .get(end + 1)
                        .and_then(|after| after.return_data())
                        .map(prefixed)
                }
            })
        };
        // The halting instruction decides: a backend may put the instruction's own
        // result, such as `Return`, in a halting step's error.
        match step.op() {
            opcode::RETURN => CallExit::Returned(data()),
            opcode::REVERT => CallExit::Reverted(data()),
            opcode::STOP | opcode::SELFDESTRUCT => CallExit::Returned(Some("0x".to_owned())),
            _ if step.error().is_some() => {
                CallExit::Failed(step.error().unwrap_or_default().to_owned())
            }
            // The backend saw the transaction fail past its last recorded step.
            _ if last_root && !trace.success => CallExit::Failed(
                trace
                    .error
                    .clone()
                    .unwrap_or_else(|| "execution failed".to_owned()),
            ),
            _ => CallExit::Unfinished,
        }
    }

    /// What an internal function returned, read off its caller's stack where it resumes.
    /// `None` when it did not return to its caller.
    ///
    /// The values are the top words there only when the stack height shows it: the
    /// caller's height at the entry, less the return address and the parameters, plus
    /// the return values. A function with several return values reports none, since
    /// nothing in the trace proves which word is which the way calldata proves the order
    /// of parameters; neither does a frame whose heights disagree. Both report an empty
    /// list.
    #[must_use]
    pub fn returned_values(
        &self,
        trace: &TransactionTrace,
        node: &CallNode,
    ) -> Option<Vec<FrameArgument>> {
        if node.frame.external || node.codeless {
            return None;
        }
        let last = node.frame.step;
        let landing = last + 1;
        let caller = self.steps.get(landing)?;
        let own = self.steps.get(last)?;
        let returned = trace.steps.get(last)?.op() == opcode::JUMP
            && caller.evm_depth == own.evm_depth
            && caller.frame_depth + 1 == node.frame.depth;
        if !returned {
            return None;
        }
        let function_id = node.frame.location.as_ref()?.function?;
        let contract = self.contracts.get(function_id.contract)?;
        let function = contract.functions.get(function_id.function)?;
        let returns = function
            .returns
            .iter()
            .map(|value| SourceParam {
                name: contract
                    .return_name(function, value)
                    .unwrap_or_default()
                    .to_owned(),
                ty: value.ty.clone(),
                location: value.location.clone(),
            })
            .collect::<Vec<_>>();
        let [_] = returns.as_slice() else {
            return Some(Vec::new());
        };
        let entry = trace.steps.get(node.frame.entry_step)?.stack().len();
        let resumed = trace.steps.get(landing)?;
        let height = resumed.stack().len();
        let return_slots = returns.iter().map(parameter_stack_slots).sum::<usize>();
        if height + 1 + parameter_slots(&function.params) != entry + return_slots {
            return Some(Vec::new());
        }
        let stack = resumed.stack().to_vec();
        Some(decode_arguments(
            &returns,
            FrameState {
                stack: &stack,
                memory: resumed.memory(),
            },
            // One value is on top whatever order several would be in.
            ArgumentLayout::TopWords,
            &contract.types,
            contract
                .types
                .scope_at(function.source_id, function.declaration_start),
        ))
    }

    /// The step a failed top-level call's failure started at: the innermost call whose
    /// revert was passed up unchanged, call by call, to the top. `None` when the last
    /// top-level call did not fail.
    ///
    /// A frame passes a revert up when the call that reverted was the last one it made;
    /// one that made another call after it, or failed with data of its own, caught it,
    /// so its own failure is where the revert started.
    #[must_use]
    pub fn revert_origin(&self, trace: &TransactionTrace, nodes: &[CallNode]) -> Option<usize> {
        let mut current = nodes.iter().rposition(|node| node.parent.is_none())?;
        let mut exit = self.call_exit(trace, &nodes[current]);
        if !exit.failed() {
            return None;
        }
        loop {
            let callees = nodes
                .iter()
                .enumerate()
                .skip(current + 1)
                .take_while(|(_, node)| node.frame.entry_step <= nodes[current].end_step);
            let Some(callee) = callees
                .filter(|(index, node)| {
                    node.frame.external && external_caller(nodes, *index) == Some(current)
                })
                .map(|(index, _)| index)
                .last()
            else {
                break;
            };
            let callee_exit = self.call_exit(trace, &nodes[callee]);
            if !callee_exit.failed() {
                break;
            }
            if let (Some(own), Some(passed)) = (exit.data(), callee_exit.data()) {
                if own != passed {
                    break;
                }
            }
            current = callee;
            exit = callee_exit;
        }
        Some(nodes[current].end_step)
    }
}

/// The nearest external frame above `index`: the call whose code made it.
fn external_caller(nodes: &[CallNode], index: usize) -> Option<usize> {
    let mut parent = nodes[index].parent;
    while let Some(caller) = parent {
        if nodes[caller].frame.external {
            return Some(caller);
        }
        parent = nodes[caller].parent;
    }
    None
}

/// `data` as `0x`-prefixed hex.
fn prefixed(data: &str) -> String {
    format!("0x{}", data.trim_start_matches("0x"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use soldb_core::{Bytes, StepSnapshot, TraceStep, TransactionTrace};
    use soldb_ethdebug::{function_selector, source_range, EthdebugInfo, Instruction};

    use super::CallExit;
    use crate::{CodeGenerator, ContractDebugInfo, StepMap};

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

    /// The span of `needle`, or of the whole function it begins when it is a declaration.
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
                at(11, call_fee),
                at(12, call_fee),
                at(13, call_fee),
                at(14, span("return f;")),
                at(15, span("return f;")),
                at(20, span("function fee")),
                at(21, span("f = a / 100;")),
                at(22, span("f = a / 100;")),
                at(30, whole),
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

    fn step(pc: u64, depth: u64, op: &str, stack: &[&str]) -> TraceStep {
        TraceStep::new(
            pc,
            Arc::from(op),
            0,
            0,
            depth,
            None,
            StepSnapshot::new(
                stack.iter().map(|word| Arc::from(*word)).collect(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        )
    }

    fn with_memory(mut step: TraceStep, memory: &[u8]) -> TraceStep {
        step.snapshot.memory = Some(Bytes::copy_from_slice(memory));
        step
    }

    fn run_calldata(argument: u8) -> Vec<u8> {
        let mut data = function_selector("run(uint256)")
            .expect("selector")
            .to_vec();
        data.extend([0; 31]);
        data.push(argument);
        data
    }

    fn hex(bytes: &[u8]) -> String {
        format!("0x{}", soldb_core::encode_hex(bytes))
    }

    /// `run(100)` calls `fee(100)`, which returns 1, then calls `run(7)` on the callee,
    /// which halts with `callee_halt`; the root then halts with `root_halt`. A `None`
    /// callee halt makes the callee an account without code that returns `0x2a`.
    fn pay_trace(callee_halt: Option<(&str, &[u8])>, root_halt: (&str, &[u8])) -> TransactionTrace {
        let address_word = format!("0x{}", CALLEE.trim_start_matches("0x"));
        let mut steps = vec![
            step(0, 1, "PUSH1", &[]),
            step(1, 1, "JUMP", &["0xa"]),
            step(10, 1, "JUMPDEST", &["0x64"]),
            step(11, 1, "PUSH1", &["0x64"]),
            // Into `fee`: the return address, the argument, then the target.
            step(12, 1, "JUMP", &["0x64", "0xd", "0x64", "0x14"]),
            step(20, 1, "JUMPDEST", &["0x64", "0xd", "0x64"]),
            step(21, 1, "DIV", &["0x64", "0xd", "0x64"]),
            // Back out with `f` under the return address.
            step(22, 1, "JUMP", &["0x64", "0x1", "0xd"]),
            step(13, 1, "JUMPDEST", &["0x64", "0x1"]),
            // CALL: gas, address, value, input offset and size, output offset and size,
            // listed bottom first.
            with_memory(
                step(
                    14,
                    1,
                    "CALL",
                    &[
                        "0x64",
                        "0x1",
                        "0x0",
                        "0x0",
                        "0x24",
                        "0x0",
                        "0x0",
                        &address_word,
                        "0xffff",
                    ],
                ),
                &run_calldata(7),
            ),
        ];
        match callee_halt {
            Some((op, data)) => {
                steps.extend([
                    step(0, 2, "PUSH1", &[]),
                    step(1, 2, "JUMP", &["0xa"]),
                    step(10, 2, "JUMPDEST", &["0x7"]),
                    with_memory(
                        step(14, 2, op, &[&format!("{:#x}", data.len()), "0x0"]),
                        data,
                    ),
                ]);
                steps.push(step(15, 1, "POP", &["0x64", "0x1", "0x0"]));
            }
            None => {
                let mut after = step(15, 1, "POP", &["0x64", "0x1", "0x1"]);
                after.snapshot.return_data = Some(Arc::from("2a"));
                steps.push(after);
            }
        }
        let (op, data) = root_halt;
        steps.push(with_memory(
            step(15, 1, op, &[&format!("{:#x}", data.len()), "0x0"]),
            data,
        ));
        TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: Some(ROOT.to_owned()),
            value: "0x0".to_owned(),
            input_data: hex(&run_calldata(100)),
            gas_used: 0,
            output: hex(root_halt.1),
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

    fn map(trace: &TransactionTrace) -> StepMap {
        StepMap::new(trace, vec![contract(ROOT), contract(CALLEE)])
    }

    const GUARDED: &str = "\
contract G {
    uint256 count;
    modifier guard() {
        require(msg.sender != address(0));
        _;
        count += 1;
    }
    function run(uint256 a) public guard returns (uint256) {
        return a;
    }
}
";

    /// `run` with its modifier laid out in line around its body: the entry point at 10,
    /// the modifier's check at 11, the body at 12, and the modifier's tail at 13.
    fn guarded_contract() -> ContractDebugInfo {
        let at = |pc: u64, needle: &str| {
            let start = GUARDED.find(needle).expect(needle);
            let length = if needle.starts_with("function") {
                GUARDED[start..].find("\n    }").expect("function end") + 6
            } else {
                needle.len()
            };
            Instruction::new(
                pc,
                "JUMPDEST",
                Some(serde_json::json!({"code": source_range(0, start as u64, length as u64)})),
            )
        };
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "G".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![
                at(0, "contract G"),
                at(1, "contract G"),
                at(10, "function run"),
                at(11, "require(msg.sender != address(0));"),
                at(12, "return a;"),
                at(13, "count += 1;"),
            ],
            sources: BTreeMap::from([(0, "G.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        ContractDebugInfo::new(
            Some(ROOT),
            "G",
            info,
            BTreeMap::from([(0, GUARDED.to_owned())]),
        )
    }

    /// The root frame of `guarded_contract` running `pcs`, called with `input`.
    fn guarded_trace(pcs: &[u64], input: &[u8]) -> TransactionTrace {
        let steps = pcs
            .iter()
            .map(|pc| {
                let op = if *pc == 1 { "JUMP" } else { "JUMPDEST" };
                step(*pc, 1, op, &["0x7", "0xa"])
            })
            .collect::<Vec<_>>();
        TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: Some(ROOT.to_owned()),
            value: "0".to_owned(),
            input_data: hex(input),
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

    /// The name of the function the first frame under the root ran, and of the one its
    /// last step is in.
    fn first_function(trace: &TransactionTrace) -> (Option<String>, Option<String>) {
        let contract = guarded_contract();
        let map = StepMap::new(trace, vec![contract.clone()]);
        let node = map.call_tree(trace).swap_remove(1);
        let ran = node
            .function
            .map(|id| contract.functions[id.function].name.clone());
        (ran, node.frame.function_name)
    }

    #[test]
    fn a_frame_entered_at_an_entry_point_is_that_function_wherever_it_ends() {
        // Entered by a jump onto `run`, and left in code no source describes.
        let trace = guarded_trace(&[0, 1, 10, 30], &run_calldata(7));
        assert_eq!(first_function(&trace), (Some("run".to_owned()), None));
    }

    #[test]
    fn a_function_laid_out_in_line_is_the_one_the_calldata_selected() {
        // No jump onto an entry point: the modifier's check, the body, the modifier's
        // tail. The frame ends in the modifier, and the calldata says it is `run`.
        let pcs = [0, 11, 12, 13];
        let trace = guarded_trace(&pcs, &run_calldata(7));
        assert_eq!(
            first_function(&trace),
            (Some("run".to_owned()), Some("guard".to_owned()))
        );

        // Calldata that selects none of the contract's functions proves nothing, and
        // neither does a modifier's own name.
        let guard = function_selector("guard()").expect("selector");
        for input in [&[0xde, 0xad, 0xbe, 0xef][..], &guard[..], &[]] {
            let trace = guarded_trace(&pcs, input);
            assert_eq!(first_function(&trace).0, first_function(&trace).1);
        }
    }

    /// An entry of the tree: the function, its parent, the steps it spans, and whether it
    /// is code laid out in line rather than a frame.
    type Entry = (Option<String>, Option<usize>, usize, usize, bool);

    /// Every entry of the tree `contract` gives `trace`.
    fn shape(trace: &TransactionTrace, contract: ContractDebugInfo) -> Vec<Entry> {
        let map = StepMap::new(trace, vec![contract.clone()]);
        map.call_tree(trace)
            .into_iter()
            .map(|node| {
                let name = node
                    .function
                    .map(|id| contract.functions[id.function].name.clone());
                (
                    name,
                    node.parent,
                    node.frame.entry_step,
                    node.end_step,
                    node.inlined,
                )
            })
            .collect()
    }

    #[test]
    fn code_laid_out_in_line_is_listed_in_its_frame_and_is_not_a_call() {
        let root = |end| (None, None, 0, end, false);
        let run = |end| (Some("run".to_owned()), Some(0), 1, end, false);
        let fee = |entry| (Some("fee".to_owned()), Some(1), entry, entry, true);

        // `run`'s body runs straight into `fee`'s: the optimizer put `fee` in line.
        // Nothing called it, and it is listed once however often its code comes back.
        let once = guarded_trace(&[0, 11, 21, 30], &run_calldata(7));
        assert_eq!(shape(&once, contract(ROOT)), [root(3), run(2), fee(2)]);
        let twice = guarded_trace(&[0, 11, 21, 11, 21, 30], &run_calldata(7));
        assert_eq!(shape(&twice, contract(ROOT)), [root(5), run(4), fee(2)]);

        // The pipeline does not decide it: the same code from via-IR reads the same.
        let via_ir = contract(ROOT).with_code_generator(Some(CodeGenerator::ViaIr));
        assert_eq!(shape(&once, via_ir), [root(3), run(2), fee(2)]);

        // A jump that lands in `fee`'s code away from its entry point is not a call
        // either, and the code is somewhere else in the bytecode: a branch, or a block
        // the optimizer shares and the source map credits to `fee`. It is not listed.
        let jumped = guarded_trace(&[0, 11, 1, 21, 30], &run_calldata(7));
        assert_eq!(shape(&jumped, contract(ROOT)), [root(4), run(3)]);
    }

    #[test]
    fn a_modifier_is_a_frame_of_its_own_around_the_body() {
        let run = |parent, entry, end| (Some("run".to_owned()), Some(parent), entry, end, false);
        let guard =
            |parent, entry, end| (Some("guard".to_owned()), Some(parent), entry, end, false);

        // Entered by a jump: the modifier's check, the body, the modifier's tail.
        let called = guarded_trace(&[0, 1, 10, 11, 12, 13], &run_calldata(7));
        assert_eq!(
            shape(&called, guarded_contract()),
            [
                (None, None, 0, 5, false),
                run(0, 2, 5),
                guard(1, 3, 3),
                guard(1, 5, 5)
            ]
        );

        // Laid out in line, the call begins in the modifier's code: the function is the
        // one the calldata selected, and the modifier ends where the body begins.
        let inline = guarded_trace(&[0, 11, 12, 13], &run_calldata(7));
        assert_eq!(
            shape(&inline, guarded_contract()),
            [(None, None, 0, 3, false), run(0, 1, 3), guard(1, 1, 1)]
        );

        // Without a step of the body nothing says where the modifier ends.
        let only_modifier = guarded_trace(&[0, 11, 13], &run_calldata(7));
        assert_eq!(
            shape(&only_modifier, guarded_contract()),
            [(None, None, 0, 2, false), run(0, 1, 2)]
        );
    }

    const FAILURE: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

    #[test]
    fn a_function_that_returned_is_a_sibling_of_the_calls_after_it() {
        let trace = pay_trace(Some(("REVERT", FAILURE)), ("REVERT", FAILURE));
        let map = map(&trace);
        let nodes = map.call_tree(&trace);
        let shape = nodes
            .iter()
            .map(|node| {
                (
                    node.frame.function_name.as_deref(),
                    node.frame.address.as_deref(),
                    node.frame.external,
                    node.parent,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            shape,
            [
                (None, Some(ROOT), true, None),
                (Some("run"), Some(ROOT), false, Some(0)),
                (Some("fee"), Some(ROOT), false, Some(1)),
                (None, Some(CALLEE), true, Some(1)),
                (Some("run"), Some(CALLEE), false, Some(3)),
            ]
        );
        assert_eq!(nodes[0].end_step, trace.steps.len() - 1);
        assert_eq!(nodes[3].end_step, 13);
        // Every frame is the one `backtrace` shows at a step inside it.
        let at_callee = map.frames(12);
        assert_eq!(at_callee.len(), 4);
        for (frame, node) in at_callee.iter().rev().zip([0, 1, 3, 4]) {
            assert_eq!(frame.entry_step, nodes[node].frame.entry_step);
            assert_eq!(frame.depth, nodes[node].frame.depth);
        }
    }

    #[test]
    fn arguments_and_return_values_are_read_where_the_trace_proves_them() {
        let trace = pay_trace(Some(("REVERT", FAILURE)), ("REVERT", FAILURE));
        let map = map(&trace);
        let nodes = map.call_tree(&trace);
        let values = |arguments: &[crate::FrameArgument]| {
            arguments
                .iter()
                .map(|argument| {
                    format!(
                        "{} {} = {}",
                        argument.ty, argument.name, argument.value.display
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(values(&nodes[1].frame.arguments), ["uint256 a = 100"]);
        assert_eq!(values(&nodes[2].frame.arguments), ["uint256 a = 100"]);
        // The callee's argument order is proven by the input read from the caller's
        // memory, since this backend recorded no calls.
        assert_eq!(values(&nodes[4].frame.arguments), ["uint256 a = 7"]);
        assert_eq!(
            map.call_input(&trace, &nodes[3]).as_deref(),
            Some(hex(&run_calldata(7)).as_str())
        );
        assert_eq!(
            map.call_input(&trace, &nodes[0]).as_deref(),
            Some(hex(&run_calldata(100)).as_str())
        );
        assert_eq!(map.call_input(&trace, &nodes[2]), None);
        // `fee` returned 1 to `run`; `run` in the callee never returned.
        let returned = map
            .returned_values(&trace, &nodes[2])
            .expect("fee returned");
        assert_eq!(values(&returned), ["uint256 f = 1"]);
        assert_eq!(map.returned_values(&trace, &nodes[4]), None);
        assert_eq!(map.returned_values(&trace, &nodes[3]), None);
    }

    #[test]
    fn a_return_value_is_not_read_when_the_stack_heights_disagree() {
        let mut steps = pay_trace(Some(("REVERT", FAILURE)), ("REVERT", FAILURE))
            .steps
            .to_steps();
        // The landing keeps a word the call should have consumed.
        steps[8] = step(13, 1, "JUMPDEST", &["0x64", "0x64", "0x1"]);
        let mut trace = pay_trace(Some(("REVERT", FAILURE)), ("REVERT", FAILURE));
        trace.steps = steps.into();
        let map = map(&trace);
        let nodes = map.call_tree(&trace);
        assert_eq!(nodes[2].frame.function_name.as_deref(), Some("fee"));
        assert_eq!(map.returned_values(&trace, &nodes[2]), Some(Vec::new()));
    }

    #[test]
    fn a_revert_passed_up_unchanged_started_in_the_innermost_call() {
        let trace = pay_trace(Some(("REVERT", FAILURE)), ("REVERT", FAILURE));
        let map = map(&trace);
        let nodes = map.call_tree(&trace);
        assert_eq!(
            map.call_exit(&trace, &nodes[3]),
            CallExit::Reverted(Some(hex(FAILURE)))
        );
        assert_eq!(
            map.call_exit(&trace, &nodes[0]),
            CallExit::Reverted(Some(hex(FAILURE)))
        );
        assert_eq!(map.revert_origin(&trace, &nodes), Some(13));
    }

    #[test]
    fn a_frame_that_reverts_with_its_own_data_caught_the_revert_below() {
        let trace = pay_trace(Some(("REVERT", FAILURE)), ("REVERT", &[1, 2, 3, 4]));
        let map = map(&trace);
        let nodes = map.call_tree(&trace);
        assert_eq!(
            map.revert_origin(&trace, &nodes),
            Some(trace.steps.len() - 1)
        );
    }

    #[test]
    fn a_successful_transaction_has_no_revert_origin() {
        let word = [0x2a; 32];
        let trace = pay_trace(Some(("RETURN", &word)), ("RETURN", &word));
        let map = map(&trace);
        let nodes = map.call_tree(&trace);
        assert_eq!(
            map.call_exit(&trace, &nodes[3]),
            CallExit::Returned(Some(hex(&word)))
        );
        assert!(!map.call_exit(&trace, &nodes[0]).failed());
        assert_eq!(map.revert_origin(&trace, &nodes), None);
    }

    #[test]
    fn a_call_into_an_account_without_code_is_a_leaf() {
        let trace = pay_trace(None, ("STOP", &[]));
        let map = map(&trace);
        let nodes = map.call_tree(&trace);
        let codeless = nodes.iter().find(|node| node.codeless).expect("leaf");
        assert_eq!(codeless.frame.address.as_deref(), Some(CALLEE));
        assert_eq!(codeless.frame.contract_name.as_deref(), Some("C"));
        assert_eq!(codeless.frame.entry_step, 9);
        assert_eq!(
            nodes[codeless.parent.expect("caller")]
                .frame
                .function_name
                .as_deref(),
            Some("run")
        );
        assert_eq!(
            map.call_input(&trace, codeless).as_deref(),
            Some(hex(&run_calldata(7)).as_str())
        );
        assert_eq!(
            map.call_exit(&trace, codeless),
            CallExit::Returned(Some("0x2a".to_owned()))
        );
        assert_eq!(
            map.call_exit(&trace, &nodes[0]),
            CallExit::Returned(Some("0x".to_owned()))
        );
    }
}
