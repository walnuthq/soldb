//! The interactive debugger: its command language, its state machine, and its answers.
//!
//! [`DebuggerCommand::parse`] turns a typed line into a command; a [`Session`] runs it
//! and answers with [`Output`] values, which [`Renderer`] turns into text and serde into
//! JSON. Underneath, [`DebuggerState`] holds the trace, the breakpoints, and the
//! position, and [`DebuggerState::apply_command`] applies the commands that move or
//! change breakpoints, returning a [`StepOutcome`].
//!
//! This crate performs no I/O: it neither reads stdin nor prints. The frontend owns the
//! terminal — a line-oriented REPL, a full-screen view, an editor over DAP, a script —
//! and renders what the session answers, which is what makes stepping, breakpoints,
//! command parsing, and the answers themselves testable without a terminal or a node.
//!
//! The trace is a complete recording, so every movement is a search over it, forward or
//! backward, and a breakpoint is a predicate on a step: a program counter, the start of
//! a source line, the entry of a function, a storage write, a revert, a call, an opcode.
//! Source-level movement comes from [`soldb_debugger::StepMap`], which every frontend
//! shares, so `next` means the same thing in the terminal and in an editor.

use std::cell::RefCell;

use soldb_core::{ExecutionCall, TraceStep, TransactionTrace};

mod command;
mod render;
mod response;
mod session;

pub use command::{
    command_spec, CommandGroup, CommandSpec, DebuggerCommand, DebuggerInfoCommand, COMMANDS,
};
pub use render::{shorten_hex, Renderer};
pub use response::{
    ArgumentInfo, BreakpointEvent, BreakpointInfo, FrameInfo, Level, ListedLine, LoadedContract,
    MemoryInfo, MemoryWord, Output, ResourceInfo, SlotInfo, StateInfo, Stop, StopLocation,
    StopReason, ValueStatus, VariableInfo,
};
pub use session::{
    breakpoint_lines, Session, FRAME_ARGUMENTS_NOTE, FRAME_ARGUMENTS_WARNING, LISTING_RADIUS,
};
use soldb_debugger::{
    call_target, normalize_address, variables_for_step, ChainStorage, Condition, ConditionContext,
    ContractDebugInfo, DebugVariable, Evaluation, Frame, FrameState, LocalsStatus,
    ResolvedFunction, ResolvedLine, SourceListing, StepLocation, StepMap, StorageLayout,
    StorageTape, StorageWords,
};

/// Where a step's variables came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariablesOrigin {
    /// Variable locations the compiler emitted in the ETHDebug artifact.
    Ethdebug,
    /// A reading of the stack following solc's legacy layout; the frontend should say so
    /// once, with [`soldb_debugger::INFERRED_LOCALS_WARNING`].
    Inferred,
}

/// The variables of the function executing at a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepVariables {
    pub variables: Vec<DebugVariable>,
    pub origin: VariablesOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayMode {
    Source,
    Assembly,
}

impl DisplayMode {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "source" | "src" => Some(Self::Source),
            "asm" | "assembly" => Some(Self::Assembly),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Assembly => "asm",
        }
    }
}

/// What the user asked to break on, before it is resolved against the trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointTarget {
    Pc(u64),
    SourceLine(SourceBreakpointTarget),
    /// A function by name, optionally qualified as `Contract.function`.
    Function(String),
    /// A write to one storage slot, given in decimal or hex.
    Storage(String),
    /// A write to a state variable, named the way `print` names it: `counter`,
    /// `balances[0xabc…]`, `config.limit`.
    State(String),
    /// Any `REVERT`, or any step the backend marked as failing.
    Revert,
    /// A call, to one address or to any.
    Call(Option<String>),
    /// Every execution of one opcode.
    Opcode(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBreakpointTarget {
    pub file: Option<String>,
    pub line: u64,
}

/// A breakpoint as set, with a stable number the user can delete it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breakpoint {
    pub id: u32,
    pub kind: BreakpointKind,
    /// Stops only when this holds at a step the kind matched.
    pub condition: Option<Condition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointKind {
    Pc(u64),
    /// Hits when execution enters one of these lines.
    Line(Vec<ResolvedLine>),
    /// Hits when execution enters one of these functions.
    Function(Vec<ResolvedFunction>),
    /// Hits on an `SSTORE` to this slot, normalized to lowercase hex without leading
    /// zeros.
    Storage(String),
    /// The same, for a slot named as a state variable: the path the user wrote and the
    /// slot the storage layout put it at.
    StateWrite {
        path: String,
        slot: String,
    },
    Revert,
    /// Hits on a call instruction, to this lowercase address or to any.
    Call(Option<String>),
    /// Hits on every execution of this uppercase mnemonic.
    Opcode(String),
}

impl Breakpoint {
    /// How the frontend names this breakpoint to the user.
    #[must_use]
    pub fn label(&self) -> String {
        let target = match &self.kind {
            BreakpointKind::Pc(pc) => format!("PC {pc}"),
            BreakpointKind::Line(lines) => unique(lines.iter().map(|line| {
                if line.requested_line == line.key.line {
                    format!("{}:{}", line.path, line.key.line)
                } else {
                    format!(
                        "{}:{} (the statement containing line {})",
                        line.path, line.key.line, line.requested_line
                    )
                }
            }))
            .join(", "),
            BreakpointKind::Function(functions) => unique(functions.iter().map(|function| {
                format!(
                    "function {}.{} at {}:{}",
                    function.contract_name, function.name, function.path, function.line
                )
            }))
            .join(", "),
            BreakpointKind::Storage(slot) => format!("storage slot 0x{slot}"),
            BreakpointKind::StateWrite { path, slot } => {
                format!("a write to `{path}` (storage slot 0x{slot})")
            }
            BreakpointKind::Revert => "revert".to_owned(),
            BreakpointKind::Call(Some(address)) => format!("call to {address}"),
            BreakpointKind::Call(None) => "any call".to_owned(),
            BreakpointKind::Opcode(mnemonic) => format!("opcode {mnemonic}"),
        };
        match &self.condition {
            Some(condition) => format!("{target} if {}", condition.text()),
            None => target,
        }
    }
}

/// The distinct names in order of first appearance. A contract's creation and deployed
/// programs resolve the same source line or function to one target each, which the user
/// should read once.
fn unique(names: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = Vec::new();
    for name in names {
        if !seen.contains(&name) {
            seen.push(name);
        }
    }
    seen
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    NoTrace,
    Moved {
        step: usize,
        pc: u64,
        op: String,
    },
    BreakpointHit {
        step: usize,
        pc: u64,
        breakpoint: Breakpoint,
    },
    AtEnd {
        step: usize,
    },
    /// A backward step was asked for at the first step of the trace.
    AtStart {
        step: usize,
    },
    InvalidStep {
        requested: usize,
        max_step: Option<usize>,
    },
    ModeChanged(DisplayMode),
    BreakpointSet(Breakpoint),
    BreakpointCleared(Breakpoint),
    /// No breakpoint matched what the user asked to clear; the text names the target.
    BreakpointMissing(String),
    /// The target could not be resolved; the text says why.
    BreakpointError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebuggerState {
    pub current_step: usize,
    pub display_mode: DisplayMode,
    breakpoints: Vec<Breakpoint>,
    next_breakpoint_id: u32,
    trace: Option<TransactionTrace>,
    step_map: Option<StepMap>,
    storage_tape: Option<StorageTape>,
    /// Something the frontend should tell the user, kept until it does: a breakpoint that
    /// cannot be hit, or a condition that could not be evaluated. Both are silent traps
    /// otherwise.
    note: RefCell<Option<String>>,
}

impl Default for DebuggerState {
    fn default() -> Self {
        Self {
            current_step: 0,
            display_mode: DisplayMode::Source,
            breakpoints: Vec::new(),
            next_breakpoint_id: 1,
            trace: None,
            step_map: None,
            storage_tape: None,
            note: RefCell::new(None),
        }
    }
}

impl DebuggerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a trace and maps its call structure. Source lines arrive with
    /// [`DebuggerState::attach_debug_info`]; until then stepping is by instruction.
    pub fn load_trace(&mut self, trace: TransactionTrace) {
        let map = StepMap::new(&trace, Vec::new());
        self.storage_tape = Some(StorageTape::new(&trace, &map));
        self.step_map = Some(map);
        self.trace = Some(trace);
        self.current_step = 0;
    }

    /// Maps every step through the contracts' debug info, enabling source-level stepping,
    /// line and function breakpoints, and source locations in frames.
    pub fn attach_debug_info(&mut self, contracts: Vec<ContractDebugInfo>) {
        if let Some(trace) = &self.trace {
            let map = StepMap::new(trace, contracts);
            self.storage_tape = Some(StorageTape::new(trace, &map));
            self.step_map = Some(map);
        }
    }

    /// The storage words known at the current step, in the storage context it runs in.
    #[must_use]
    pub fn storage_words(&self) -> Option<StorageWords<'_>> {
        let map = self.step_map.as_ref()?;
        Some(self.storage_tape.as_ref()?.at_step(map, self.current_step))
    }

    /// The same words, with a chain the frontend can read slots the transaction never
    /// touched from.
    #[must_use]
    pub fn storage_words_with_chain<'a>(
        &'a self,
        chain: Option<&'a dyn ChainStorage>,
    ) -> Option<StorageWords<'a>> {
        Some(self.storage_words()?.with_chain(chain))
    }

    /// The account whose storage the current step reads and writes.
    #[must_use]
    pub fn storage_address(&self) -> Option<&str> {
        self.step_map.as_ref()?.storage_address(self.current_step)
    }

    /// The storage layout of the contract executing at the current step, when it was
    /// compiled with one.
    #[must_use]
    pub fn storage_layout(&self) -> Option<&StorageLayout> {
        self.step_map
            .as_ref()?
            .contract_at_step(self.current_step)?
            .storage_layout
            .as_ref()
    }

    pub fn trace(&self) -> Option<&TransactionTrace> {
        self.trace.as_ref()
    }

    #[must_use]
    pub fn step_map(&self) -> Option<&StepMap> {
        self.step_map.as_ref()
    }

    /// Whether any step maps to a source line, which is what source-level stepping needs.
    #[must_use]
    pub fn has_source(&self) -> bool {
        self.step_map.as_ref().is_some_and(StepMap::has_source)
    }

    pub fn current_step_data(&self) -> Option<&TraceStep> {
        self.trace
            .as_ref()
            .and_then(|trace| trace.steps.get(self.current_step))
    }

    /// The source location of the current step, when it has one.
    #[must_use]
    pub fn location(&self) -> Option<StepLocation> {
        self.step_map.as_ref()?.location(self.current_step)
    }

    pub fn step_count(&self) -> usize {
        self.trace
            .as_ref()
            .map(|trace| trace.steps.len())
            .unwrap_or(0)
    }

    #[must_use]
    pub fn breakpoints(&self) -> &[Breakpoint] {
        &self.breakpoints
    }

    pub fn set_display_mode(&mut self, mode: DisplayMode) -> StepOutcome {
        self.display_mode = mode;
        StepOutcome::ModeChanged(mode)
    }

    pub fn next_instruction(&mut self) -> StepOutcome {
        let Some(trace) = &self.trace else {
            return StepOutcome::NoTrace;
        };
        if self.current_step >= trace.steps.len().saturating_sub(1) {
            return StepOutcome::AtEnd {
                step: self.current_step,
            };
        }

        self.current_step += 1;
        self.outcome_for_current_step()
    }

    /// Moves to the start of the next source line in this frame or a caller's, stopping
    /// early at a breakpoint in code it steps over. Without source information this is
    /// one instruction.
    pub fn next_source(&mut self) -> StepOutcome {
        if !self.has_source() {
            return self.next_instruction();
        }
        let target = self
            .step_map
            .as_ref()
            .and_then(|map| map.next_source(self.current_step));
        self.advance_to(target)
    }

    /// Moves to the start of the next source line anywhere, entering calls.
    pub fn step_into(&mut self) -> StepOutcome {
        if !self.has_source() {
            return self.next_instruction();
        }
        let target = self
            .step_map
            .as_ref()
            .and_then(|map| map.step_into(self.current_step));
        self.advance_to(target)
    }

    /// Runs until the current frame has returned to its caller, or to the end of the
    /// recording when there is no caller.
    pub fn finish(&mut self) -> StepOutcome {
        if self.trace.is_none() {
            return StepOutcome::NoTrace;
        }
        let target = self
            .step_map
            .as_ref()
            .and_then(|map| map.finish(self.current_step));
        self.advance_to(target)
    }

    pub fn continue_execution(&mut self) -> StepOutcome {
        if self.trace.is_none() {
            return StepOutcome::NoTrace;
        }
        self.advance_to(None)
    }

    /// Steps back one instruction. The trace is a complete recording, so moving
    /// backward is as cheap and exact as moving forward.
    pub fn previous_instruction(&mut self) -> StepOutcome {
        if self.trace.is_none() {
            return StepOutcome::NoTrace;
        }
        if self.current_step == 0 {
            return StepOutcome::AtStart { step: 0 };
        }
        self.current_step -= 1;
        self.outcome_for_current_step()
    }

    /// Moves back to the start of the previous source line in this frame or a caller's,
    /// skipping over calls it made and stopping at a breakpoint on the way.
    pub fn previous_source(&mut self) -> StepOutcome {
        if !self.has_source() {
            return self.previous_instruction();
        }
        let target = self
            .step_map
            .as_ref()
            .and_then(|map| map.previous_source(self.current_step));
        self.retreat_to(target)
    }

    /// Moves back to the start of the previous source line anywhere, entering calls.
    pub fn reverse_step_into(&mut self) -> StepOutcome {
        if !self.has_source() {
            return self.previous_instruction();
        }
        let target = self
            .step_map
            .as_ref()
            .and_then(|map| map.reverse_step_into(self.current_step));
        self.retreat_to(target)
    }

    /// Runs backward to the step in the caller that entered the current frame, or to the
    /// first step when there is no caller.
    pub fn reverse_finish(&mut self) -> StepOutcome {
        if self.trace.is_none() {
            return StepOutcome::NoTrace;
        }
        let target = self
            .step_map
            .as_ref()
            .and_then(|map| map.reverse_finish(self.current_step));
        self.retreat_to(target)
    }

    /// Runs backward to the nearest earlier breakpoint, or to the first step.
    pub fn reverse_continue(&mut self) -> StepOutcome {
        if self.trace.is_none() {
            return StepOutcome::NoTrace;
        }
        self.retreat_to(None)
    }

    /// Walks forward to `target`, or to the end without one, stopping at the first
    /// breakpoint on the way.
    fn advance_to(&mut self, target: Option<usize>) -> StepOutcome {
        let Some(trace) = &self.trace else {
            return StepOutcome::NoTrace;
        };
        let last = trace.steps.len().saturating_sub(1);
        if self.current_step >= last {
            return StepOutcome::AtEnd {
                step: self.current_step,
            };
        }
        let target = target.unwrap_or(last).min(last);
        while self.current_step < target {
            self.current_step += 1;
            if let Some(breakpoint) = self.breakpoint_hit(self.current_step) {
                return StepOutcome::BreakpointHit {
                    step: self.current_step,
                    pc: self.pc_at(self.current_step),
                    breakpoint,
                };
            }
        }
        if target == last {
            return StepOutcome::AtEnd { step: last };
        }
        self.outcome_for_current_step()
    }

    /// Walks backward to `target`, or to the first step without one, stopping at the
    /// first breakpoint on the way.
    fn retreat_to(&mut self, target: Option<usize>) -> StepOutcome {
        if self.trace.is_none() {
            return StepOutcome::NoTrace;
        }
        if self.current_step == 0 {
            return StepOutcome::AtStart { step: 0 };
        }
        let target = target.unwrap_or(0);
        while self.current_step > target {
            self.current_step -= 1;
            if let Some(breakpoint) = self.breakpoint_hit(self.current_step) {
                return StepOutcome::BreakpointHit {
                    step: self.current_step,
                    pc: self.pc_at(self.current_step),
                    breakpoint,
                };
            }
        }
        if target == 0 {
            return StepOutcome::AtStart { step: 0 };
        }
        self.outcome_for_current_step()
    }

    pub fn goto_step(&mut self, step: usize) -> StepOutcome {
        let Some(trace) = &self.trace else {
            return StepOutcome::NoTrace;
        };
        if step >= trace.steps.len() {
            return StepOutcome::InvalidStep {
                requested: step,
                max_step: trace.steps.len().checked_sub(1),
            };
        }
        self.current_step = step;
        self.outcome_for_current_step()
    }

    /// Sets a breakpoint on a program counter.
    pub fn set_breakpoint(&mut self, pc: u64) -> StepOutcome {
        self.add_breakpoint(BreakpointKind::Pc(pc), None)
    }

    /// Clears the breakpoint on a program counter.
    pub fn clear_breakpoint(&mut self, pc: u64) -> StepOutcome {
        self.remove_breakpoint(&BreakpointKind::Pc(pc), &format!("PC {pc}"))
    }

    /// Resolves a target against the trace and its debug info and sets a breakpoint on
    /// it.
    pub fn set_breakpoint_target(&mut self, target: &BreakpointTarget) -> StepOutcome {
        self.set_conditional_breakpoint_target(target, None)
    }

    /// Sets a breakpoint that only stops when `condition` holds there.
    pub fn set_conditional_breakpoint_target(
        &mut self,
        target: &BreakpointTarget,
        condition: Option<&str>,
    ) -> StepOutcome {
        let condition = match condition.map(Condition::parse).transpose() {
            Ok(condition) => condition,
            Err(message) => return StepOutcome::BreakpointError(message),
        };
        match self.resolve_target(target) {
            Ok(kind) => {
                if !self.matches_any_step(&kind) {
                    let label = Breakpoint {
                        id: 0,
                        kind: kind.clone(),
                        condition: None,
                    }
                    .label();
                    self.push_note(format!(
                        "no step of this trace reaches {label}, so this breakpoint cannot be hit"
                    ));
                }
                self.add_breakpoint(kind, condition)
            }
            Err(message) => StepOutcome::BreakpointError(message),
        }
    }

    /// Clears the breakpoint that `target` resolves to.
    pub fn clear_breakpoint_target(&mut self, target: &BreakpointTarget) -> StepOutcome {
        match self.resolve_target(target) {
            Ok(kind) => {
                let label = Breakpoint {
                    id: 0,
                    kind: kind.clone(),
                    condition: None,
                }
                .label();
                self.remove_breakpoint(&kind, &label)
            }
            Err(message) => StepOutcome::BreakpointError(message),
        }
    }

    /// Removes a breakpoint by its number.
    pub fn delete_breakpoint(&mut self, id: u32) -> StepOutcome {
        match self
            .breakpoints
            .iter()
            .position(|breakpoint| breakpoint.id == id)
        {
            Some(index) => StepOutcome::BreakpointCleared(self.breakpoints.remove(index)),
            None => StepOutcome::BreakpointMissing(format!("#{id}")),
        }
    }

    fn add_breakpoint(
        &mut self,
        kind: BreakpointKind,
        condition: Option<Condition>,
    ) -> StepOutcome {
        if let Some(existing) = self
            .breakpoints
            .iter()
            .find(|breakpoint| breakpoint.kind == kind && breakpoint.condition == condition)
        {
            return StepOutcome::BreakpointSet(existing.clone());
        }
        let breakpoint = Breakpoint {
            id: self.next_breakpoint_id,
            kind,
            condition,
        };
        self.next_breakpoint_id += 1;
        self.breakpoints.push(breakpoint.clone());
        StepOutcome::BreakpointSet(breakpoint)
    }

    fn remove_breakpoint(&mut self, kind: &BreakpointKind, label: &str) -> StepOutcome {
        match self
            .breakpoints
            .iter()
            .position(|breakpoint| breakpoint.kind == *kind)
        {
            Some(index) => StepOutcome::BreakpointCleared(self.breakpoints.remove(index)),
            None => StepOutcome::BreakpointMissing(label.to_owned()),
        }
    }

    /// A state variable's slot, for stopping where it is written.
    fn resolve_state_target(&self, path: &str) -> Result<BreakpointKind, String> {
        let map = self.source_map_for("state breakpoints")?;
        let layouts = map
            .contracts()
            .iter()
            .filter_map(|contract| contract.storage_layout.as_ref());
        let mut failure = None;
        for layout in layouts {
            match layout.resolve(path) {
                Ok(reference) => {
                    let slot = soldb_debugger::short_hex(&reference.slot);
                    return Ok(BreakpointKind::StateWrite {
                        path: reference.path,
                        slot: slot.trim_start_matches("0x").to_owned(),
                    });
                }
                Err(error) => failure = Some(error.to_string()),
            }
        }
        Err(failure.unwrap_or_else(|| {
            "no storage layout is loaded, so state variables cannot be named; compile with `--storage-layout`".to_owned()
        }))
    }

    fn resolve_target(&self, target: &BreakpointTarget) -> Result<BreakpointKind, String> {
        match target {
            BreakpointTarget::Pc(pc) => Ok(BreakpointKind::Pc(*pc)),
            BreakpointTarget::SourceLine(target) => {
                let map = self.source_map_for("source breakpoints")?;
                map.resolve_line(target.file.as_deref(), target.line)
                    .map(BreakpointKind::Line)
            }
            BreakpointTarget::Function(name) => {
                let map = self.source_map_for("function breakpoints")?;
                match map.resolve_function(name) {
                    Ok(functions) => Ok(BreakpointKind::Function(functions)),
                    // A name that is not a function may be a state variable: `break
                    // counter` stops where the counter is written.
                    Err(error) => self.resolve_state_target(name).map_err(|state_error| {
                        if state_error.contains("no storage layout") {
                            error
                        } else {
                            format!("{error}; and {state_error}")
                        }
                    }),
                }
            }
            BreakpointTarget::State(path) => self.resolve_state_target(path),
            BreakpointTarget::Storage(slot) => normalize_slot(slot)
                .map(BreakpointKind::Storage)
                .ok_or_else(|| format!("invalid storage slot `{slot}`; expected decimal or hex")),
            BreakpointTarget::Revert => Ok(BreakpointKind::Revert),
            BreakpointTarget::Call(None) => Ok(BreakpointKind::Call(None)),
            BreakpointTarget::Call(Some(address)) => {
                let normalized = normalize_address(address);
                let hex = &normalized[2..];
                if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(format!(
                        "invalid address `{address}`; expected 20 bytes of hex"
                    ));
                }
                Ok(BreakpointKind::Call(Some(normalized)))
            }
            BreakpointTarget::Opcode(mnemonic) => {
                Ok(BreakpointKind::Opcode(mnemonic.to_ascii_uppercase()))
            }
        }
    }

    fn source_map_for(&self, what: &str) -> Result<&StepMap, String> {
        if self.trace.is_none() {
            return Err("no trace is loaded".to_owned());
        }
        self.step_map
            .as_ref()
            .filter(|map| !map.contracts().is_empty())
            .ok_or_else(|| {
                format!("{what} require compiler debug metadata; start the session with `--ethdebug-dir <address>:<contract>:<dir>`")
            })
    }

    /// The first breakpoint that `step` triggers.
    #[must_use]
    pub fn breakpoint_hit(&self, step: usize) -> Option<Breakpoint> {
        let trace_step = self.trace.as_ref()?.steps.get(step)?;
        self.breakpoints
            .iter()
            .filter(|breakpoint| self.kind_matches(&breakpoint.kind, step, trace_step))
            // A condition is checked only where the target matched, so the cost falls on
            // the handful of steps that got that far, not on every step passed through.
            .find(|breakpoint| match &breakpoint.condition {
                Some(condition) => {
                    matches!(self.evaluate_condition(condition, step), Evaluation::True)
                }
                None => true,
            })
            .cloned()
    }

    /// Whether a breakpoint's target matches this step, before any condition.
    fn kind_matches(&self, kind: &BreakpointKind, step: usize, trace_step: &TraceStep) -> bool {
        let map = self.step_map.as_ref();
        match kind {
            BreakpointKind::Pc(pc) => trace_step.pc == *pc,
            BreakpointKind::Line(lines) => map.is_some_and(|map| {
                map.is_line_start(step)
                    && map
                        .line_key(step)
                        .is_some_and(|key| lines.iter().any(|line| line.key == key))
            }),
            BreakpointKind::Function(functions) => map.is_some_and(|map| {
                map.is_frame_entry(step)
                    && map
                        .function_id(step)
                        .is_some_and(|id| functions.iter().any(|function| function.id == id))
            }),
            BreakpointKind::Storage(slot) | BreakpointKind::StateWrite { slot, .. } => {
                &*trace_step.op == "SSTORE"
                    && trace_step
                        .snapshot_ref()
                        .stack
                        .last()
                        .and_then(|word| normalize_slot(word))
                        .is_some_and(|written| written == *slot)
            }
            BreakpointKind::Revert => &*trace_step.op == "REVERT" || trace_step.error.is_some(),
            BreakpointKind::Call(address) => {
                let target = call_target(trace_step);
                match address {
                    Some(address) => target.as_deref() == Some(address.as_str()),
                    None => target.is_some() || is_call_opcode(&trace_step.op),
                }
            }
            BreakpointKind::Opcode(mnemonic) => trace_step.op.eq_ignore_ascii_case(mnemonic),
        }
    }

    /// Whether any step of the loaded trace matches this target.
    ///
    /// A trace is a finished recording, so a breakpoint that matches nothing in it will
    /// never fire, and saying that when it is set beats leaving the user to wonder why
    /// `continue` ran to the end. It happens for real reasons: a line that this
    /// transaction did not execute, and a function of a base contract, whose code solc
    /// currently attributes to the deriving contract's own file.
    fn matches_any_step(&self, kind: &BreakpointKind) -> bool {
        let Some(trace) = &self.trace else {
            return true;
        };
        trace
            .steps
            .iter()
            .enumerate()
            .any(|(step, trace_step)| self.kind_matches(kind, step, trace_step))
    }

    /// Evaluates a breakpoint condition at `step`.
    ///
    /// A condition that cannot be read there — an untouched slot, an unknown name — does
    /// not stop, and the reason is kept for [`DebuggerState::take_note`].
    #[must_use]
    pub fn evaluate_condition(&self, condition: &Condition, step: usize) -> Evaluation {
        let (Some(map), Some(trace)) = (&self.step_map, &self.trace) else {
            return Evaluation::Unavailable("no trace is loaded".to_owned());
        };
        let Some(trace_step) = trace.steps.get(step) else {
            return Evaluation::Unavailable(format!("step {step} is outside the trace"));
        };
        let words = self
            .storage_tape
            .as_ref()
            .map(|tape| tape.at_step(map, step));
        let frames = self.frames_at(step);
        let frame = frames.iter().find(|frame| !frame.arguments.is_empty());
        let context = ConditionContext::new(map, step, trace_step, words)
            .with_frame(frame)
            .with_trace(trace);
        let outcome = condition.evaluate(&context);
        if let Evaluation::Unavailable(reason) = &outcome {
            self.push_note(format!(
                "`{}` could not be evaluated: {reason}",
                condition.text()
            ));
        }
        outcome
    }

    /// Records something for the frontend to report, keeping the first of several.
    fn push_note(&self, note: String) {
        let mut slot = self.note.borrow_mut();
        if slot.is_none() {
            *slot = Some(note);
        }
    }

    /// Takes what the frontend should tell the user since the last call: a breakpoint that
    /// cannot be hit, or a condition that could not be evaluated.
    #[must_use]
    pub fn take_note(&self) -> Option<String> {
        self.note.borrow_mut().take()
    }

    /// The call structure at any step, with each frame's arguments.
    #[must_use]
    pub fn frames_at(&self, step: usize) -> Vec<Frame> {
        let (Some(map), Some(trace)) = (&self.step_map, &self.trace) else {
            return Vec::new();
        };
        let mut frames = map.frames(step);
        for frame in &mut frames {
            let Some(entry) = trace.steps.get(frame.entry_step) else {
                continue;
            };
            let snapshot = entry.snapshot_ref();
            frame.arguments = map.frame_arguments(
                frame,
                FrameState {
                    stack: snapshot.stack,
                    memory: snapshot.memory,
                },
            );
        }
        frames
    }

    /// The call structure at the current step, innermost frame first.
    #[must_use]
    pub fn frames(&self) -> Vec<Frame> {
        self.frames_at(self.current_step)
    }

    /// Source lines around the current step.
    #[must_use]
    pub fn source_listing(&self, radius: u64) -> Option<SourceListing> {
        self.step_map
            .as_ref()?
            .source_listing(self.current_step, radius)
    }

    /// The variables of the function executing at the current step, or why there are
    /// none: the artifact's ETHDebug variable locations when it carries any, otherwise
    /// the legacy stack layout when the contract's code generator keeps one.
    pub fn variables(&self) -> Result<StepVariables, String> {
        let (Some(map), Some(trace)) = (&self.step_map, &self.trace) else {
            return Err("no trace is loaded".to_owned());
        };
        let Some(step) = trace.steps.get(self.current_step) else {
            return Err(format!("step {} is outside the trace", self.current_step));
        };
        let Some(contract) = map.contract_at_step(self.current_step) else {
            return Err("no sources matched the contract executing at this step".to_owned());
        };
        if contract.info.has_variable_locations() {
            return Ok(StepVariables {
                variables: variables_for_step(trace, &contract.info, step),
                origin: VariablesOrigin::Ethdebug,
            });
        }
        match map.locals_at(self.current_step) {
            LocalsStatus::Inferred(_) => {
                // Storage pointers among the locals read the words the trace recorded.
                let words = self
                    .storage_tape
                    .as_ref()
                    .map(|tape| tape.at_step(map, self.current_step));
                Ok(StepVariables {
                    variables: map.inferred_variables(trace, self.current_step, words.as_ref()),
                    origin: VariablesOrigin::Inferred,
                })
            }
            LocalsStatus::Unavailable(reason) => Err(reason.to_owned()),
        }
    }

    /// The value of `path` at the current step when its first name is a local variable
    /// in scope: the variable itself, or a member, element, mapping entry, or `length`
    /// reached from it, such as `item.tags[1]` or `stored.owners[0xabc]`. `None` when no
    /// local has that name, so the caller can look the path up as a state variable.
    #[must_use]
    pub fn local_path(&self, path: &str) -> Option<Result<DebugVariable, String>> {
        let (Some(map), Some(trace)) = (&self.step_map, &self.trace) else {
            return None;
        };
        let words = self
            .storage_tape
            .as_ref()
            .map(|tape| tape.at_step(map, self.current_step));
        map.local_path(trace, self.current_step, words.as_ref(), path)
    }

    /// The innermost recorded call that contains the current step, when the backend
    /// recorded calls.
    #[must_use]
    pub fn current_call(&self) -> Option<&ExecutionCall> {
        let trace = self.trace.as_ref()?;
        trace
            .artifacts
            .calls
            .iter()
            .filter(|call| {
                call.entry_step
                    .is_some_and(|entry| entry <= self.current_step)
                    && call.exit_step.is_none_or(|exit| self.current_step < exit)
            })
            .max_by_key(|call| call.depth)
    }

    /// The calldata the current frame was called with: the transaction's input at the
    /// root, the recorded call's input in a nested frame, or nothing when the backend did
    /// not record calls.
    #[must_use]
    pub fn calldata(&self) -> Option<String> {
        let trace = self.trace.as_ref()?;
        let step = trace.steps.get(self.current_step)?;
        let root_depth = trace.steps.first().map_or(0, |first| first.depth);
        if step.depth == root_depth {
            return Some(trace.input_data.clone());
        }
        self.current_call().map(|call| call.input.clone())
    }

    pub fn apply_command(&mut self, command: DebuggerCommand) -> Option<StepOutcome> {
        match command {
            DebuggerCommand::Next => Some(self.next_source()),
            DebuggerCommand::NextInstruction => Some(self.next_instruction()),
            DebuggerCommand::Step => Some(self.step_into()),
            DebuggerCommand::Continue => Some(self.continue_execution()),
            DebuggerCommand::Finish => Some(self.finish()),
            DebuggerCommand::ReverseNext => Some(self.previous_source()),
            DebuggerCommand::ReverseNextInstruction => Some(self.previous_instruction()),
            DebuggerCommand::ReverseStep => Some(self.reverse_step_into()),
            DebuggerCommand::ReverseContinue => Some(self.reverse_continue()),
            DebuggerCommand::ReverseFinish => Some(self.reverse_finish()),
            DebuggerCommand::Goto(step) => Some(self.goto_step(step)),
            DebuggerCommand::Mode(Some(mode)) => Some(self.set_display_mode(mode)),
            DebuggerCommand::Break(target, condition) => {
                Some(self.set_conditional_breakpoint_target(&target, condition.as_deref()))
            }
            DebuggerCommand::Clear(target) => Some(self.clear_breakpoint_target(&target)),
            DebuggerCommand::Delete(id) => Some(self.delete_breakpoint(id)),
            DebuggerCommand::Empty
            | DebuggerCommand::Help(_)
            | DebuggerCommand::Info(_)
            | DebuggerCommand::Backtrace
            | DebuggerCommand::List
            | DebuggerCommand::Memory { .. }
            | DebuggerCommand::Calldata
            | DebuggerCommand::Stack { .. }
            | DebuggerCommand::Mode(None)
            | DebuggerCommand::Print(_)
            | DebuggerCommand::Tui
            | DebuggerCommand::Quit
            | DebuggerCommand::Unknown(_)
            | DebuggerCommand::Vars => None,
        }
    }

    fn pc_at(&self, step: usize) -> u64 {
        self.trace
            .as_ref()
            .and_then(|trace| trace.steps.get(step))
            .map_or(0, |step| step.pc)
    }

    fn outcome_for_current_step(&self) -> StepOutcome {
        let Some(step) = self.current_step_data() else {
            return StepOutcome::NoTrace;
        };
        if let Some(breakpoint) = self.breakpoint_hit(self.current_step) {
            return StepOutcome::BreakpointHit {
                step: self.current_step,
                pc: step.pc,
                breakpoint,
            };
        }
        StepOutcome::Moved {
            step: self.current_step,
            pc: step.pc,
            op: step.op.to_string(),
        }
    }
}

fn is_call_opcode(op: &str) -> bool {
    matches!(op, "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL")
}

/// A storage slot as lowercase hex without `0x` or leading zeros, from decimal or hex
/// input; `None` when the text is neither.
fn normalize_slot(input: &str) -> Option<String> {
    let input = input.trim();
    let hex = if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        hex.to_ascii_lowercase()
    } else {
        format!("{:x}", input.parse::<u128>().ok()?)
    };
    let trimmed = hex.trim_start_matches('0');
    Some(if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use soldb_core::{StepSnapshot, TraceStep, TransactionTrace};
    use soldb_debugger::{
        CodeGenerator, ContractDebugInfo, FunctionId, LineKey, ResolvedFunction, ResolvedLine,
    };
    use soldb_ethdebug::{EthdebugInfo, Instruction};

    use super::{
        Breakpoint, BreakpointKind, BreakpointTarget, DebuggerCommand, DebuggerInfoCommand,
        DebuggerState, DisplayMode, SourceBreakpointTarget, StepOutcome, VariablesOrigin,
    };

    #[test]
    fn parses_repl_commands_and_aliases() {
        assert_eq!(DebuggerCommand::parse(""), DebuggerCommand::Empty);
        assert_eq!(DebuggerCommand::parse("n"), DebuggerCommand::Next);
        assert_eq!(
            DebuggerCommand::parse("stepi"),
            DebuggerCommand::NextInstruction
        );
        assert_eq!(DebuggerCommand::parse("s"), DebuggerCommand::Step);
        assert_eq!(DebuggerCommand::parse("c"), DebuggerCommand::Continue);
        assert_eq!(DebuggerCommand::parse("finish"), DebuggerCommand::Finish);
        assert_eq!(DebuggerCommand::parse("fin"), DebuggerCommand::Finish);
        assert_eq!(DebuggerCommand::parse("goto 2"), DebuggerCommand::Goto(2));
        assert_eq!(DebuggerCommand::parse("vars"), DebuggerCommand::Vars);
        assert_eq!(DebuggerCommand::parse("LOCALS"), DebuggerCommand::Vars);
        assert_eq!(
            DebuggerCommand::parse("print balance"),
            DebuggerCommand::Print("balance".to_owned())
        );
        assert_eq!(
            DebuggerCommand::parse("p   balance  "),
            DebuggerCommand::Print("balance".to_owned())
        );
        assert_eq!(
            DebuggerCommand::parse("print"),
            DebuggerCommand::Print(String::new())
        );
        assert_eq!(
            DebuggerCommand::parse("info resources"),
            DebuggerCommand::Info(DebuggerInfoCommand::Resources { json: false })
        );
        assert_eq!(
            DebuggerCommand::parse("info resources --json"),
            DebuggerCommand::Info(DebuggerInfoCommand::Resources { json: true })
        );
        assert_eq!(
            DebuggerCommand::parse("info breakpoints"),
            DebuggerCommand::Info(DebuggerInfoCommand::Breakpoints)
        );
        assert_eq!(
            DebuggerCommand::parse("i b"),
            DebuggerCommand::Info(DebuggerInfoCommand::Breakpoints)
        );
        assert_eq!(
            DebuggerCommand::parse("info storage"),
            DebuggerCommand::Info(DebuggerInfoCommand::Storage)
        );
        assert_eq!(
            DebuggerCommand::parse("storage"),
            DebuggerCommand::Info(DebuggerInfoCommand::Storage)
        );
        assert_eq!(
            DebuggerCommand::parse("mode assembly"),
            DebuggerCommand::Mode(Some(DisplayMode::Assembly))
        );
        assert_eq!(
            DebuggerCommand::parse("break 0x10"),
            DebuggerCommand::Break(BreakpointTarget::Pc(16), None)
        );
        assert_eq!(
            DebuggerCommand::parse("break Counter.sol:7"),
            DebuggerCommand::Break(
                BreakpointTarget::SourceLine(SourceBreakpointTarget {
                    file: Some("Counter.sol".to_owned()),
                    line: 7
                }),
                None
            )
        );
        assert_eq!(
            DebuggerCommand::parse("break line 7"),
            DebuggerCommand::Break(
                BreakpointTarget::SourceLine(SourceBreakpointTarget {
                    file: None,
                    line: 7
                }),
                None
            )
        );
        assert_eq!(
            DebuggerCommand::parse("break increment"),
            DebuggerCommand::Break(BreakpointTarget::Function("increment".to_owned()), None)
        );
        assert_eq!(
            DebuggerCommand::parse("b Counter.increment"),
            DebuggerCommand::Break(
                BreakpointTarget::Function("Counter.increment".to_owned()),
                None
            )
        );
        assert_eq!(
            DebuggerCommand::parse("break storage 0x0"),
            DebuggerCommand::Break(BreakpointTarget::Storage("0x0".to_owned()), None)
        );
        assert_eq!(
            DebuggerCommand::parse("break revert"),
            DebuggerCommand::Break(BreakpointTarget::Revert, None)
        );
        assert_eq!(
            DebuggerCommand::parse("break call"),
            DebuggerCommand::Break(BreakpointTarget::Call(None), None)
        );
        assert_eq!(
            DebuggerCommand::parse("break call 0xabc"),
            DebuggerCommand::Break(BreakpointTarget::Call(Some("0xabc".to_owned())), None)
        );
        assert_eq!(
            DebuggerCommand::parse("break op sstore"),
            DebuggerCommand::Break(BreakpointTarget::Opcode("sstore".to_owned()), None)
        );
        assert_eq!(
            DebuggerCommand::parse("break"),
            DebuggerCommand::Unknown("break".to_owned())
        );
        assert_eq!(
            DebuggerCommand::parse("break 12abc"),
            DebuggerCommand::Unknown("break 12abc".to_owned())
        );
        assert_eq!(
            DebuggerCommand::parse("clear 8"),
            DebuggerCommand::Clear(BreakpointTarget::Pc(8))
        );
        assert_eq!(
            DebuggerCommand::parse("delete 3"),
            DebuggerCommand::Delete(3)
        );
        assert_eq!(DebuggerCommand::parse("d #3"), DebuggerCommand::Delete(3));
        assert_eq!(DebuggerCommand::parse("bt"), DebuggerCommand::Backtrace);
        assert_eq!(DebuggerCommand::parse("where"), DebuggerCommand::Backtrace);
        assert_eq!(DebuggerCommand::parse("l"), DebuggerCommand::List);
        assert_eq!(
            DebuggerCommand::parse("memory"),
            DebuggerCommand::Memory {
                offset: None,
                length: None
            }
        );
        assert_eq!(
            DebuggerCommand::parse("mem 0x40 32"),
            DebuggerCommand::Memory {
                offset: Some(64),
                length: Some(32)
            }
        );
        assert_eq!(
            DebuggerCommand::parse("mem 1 2 3"),
            DebuggerCommand::Unknown("mem 1 2 3".to_owned())
        );
        assert_eq!(
            DebuggerCommand::parse("calldata"),
            DebuggerCommand::Calldata
        );
        assert_eq!(
            DebuggerCommand::parse("stack"),
            DebuggerCommand::Stack { limit: None }
        );
        assert_eq!(
            DebuggerCommand::parse("help mode"),
            DebuggerCommand::Help(Some("mode".to_owned()))
        );
        assert_eq!(DebuggerCommand::parse("q"), DebuggerCommand::Quit);
        assert_eq!(
            DebuggerCommand::parse("wat"),
            DebuggerCommand::Unknown("wat".to_owned())
        );
    }

    #[test]
    fn loads_trace_and_steps_instruction_by_instruction() {
        let mut state = DebuggerState::new();
        assert_eq!(state.next_instruction(), StepOutcome::NoTrace);
        assert_eq!(state.next_source(), StepOutcome::NoTrace);
        assert_eq!(state.finish(), StepOutcome::NoTrace);

        state.load_trace(sample_trace());
        assert_eq!(state.step_count(), 4);
        assert_eq!(&*state.current_step_data().expect("step").op, "PUSH1");
        assert!(!state.has_source());

        assert_eq!(
            state.next_instruction(),
            StepOutcome::Moved {
                step: 1,
                pc: 2,
                op: "MSTORE".into()
            }
        );
        assert_eq!(state.current_step, 1);
        // Without source information `next` and `step` are one instruction each.
        assert!(matches!(
            state.next_source(),
            StepOutcome::Moved { step: 2, .. }
        ));
        assert!(matches!(
            state.step_into(),
            StepOutcome::Moved { step: 3, .. }
        ));
        assert!(matches!(
            state.previous_source(),
            StepOutcome::Moved { step: 2, .. }
        ));
        assert!(matches!(
            state.reverse_step_into(),
            StepOutcome::Moved { step: 1, .. }
        ));
    }

    #[test]
    fn continues_until_breakpoint_or_end() {
        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());
        let set = state.set_breakpoint(3);
        let StepOutcome::BreakpointSet(breakpoint) = &set else {
            panic!("{set:?}");
        };
        assert_eq!(breakpoint.id, 1);
        assert_eq!(breakpoint.kind, BreakpointKind::Pc(3));
        assert_eq!(breakpoint.label(), "PC 3");
        // Setting it again returns the same breakpoint instead of a duplicate.
        assert_eq!(state.set_breakpoint(3), set);
        assert_eq!(state.breakpoints().len(), 1);

        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 2, pc: 3, .. }
        ));
        assert_eq!(state.current_step, 2);

        assert!(matches!(
            state.clear_breakpoint(3),
            StepOutcome::BreakpointCleared(_)
        ));
        assert_eq!(
            state.clear_breakpoint(3),
            StepOutcome::BreakpointMissing("PC 3".to_owned())
        );
        assert_eq!(state.continue_execution(), StepOutcome::AtEnd { step: 3 });
        assert_eq!(state.continue_execution(), StepOutcome::AtEnd { step: 3 });
    }

    #[test]
    fn numbered_breakpoints_can_be_deleted() {
        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());
        state.set_breakpoint(2);
        state.set_breakpoint(3);
        assert_eq!(
            state
                .breakpoints()
                .iter()
                .map(|breakpoint| breakpoint.id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(matches!(
            state.delete_breakpoint(1),
            StepOutcome::BreakpointCleared(breakpoint) if breakpoint.kind == BreakpointKind::Pc(2)
        ));
        assert_eq!(
            state.delete_breakpoint(1),
            StepOutcome::BreakpointMissing("#1".to_owned())
        );
        // Numbers are never reused.
        assert!(matches!(
            state.set_breakpoint(4),
            StepOutcome::BreakpointSet(breakpoint) if breakpoint.id == 3
        ));
    }

    #[test]
    fn goto_validates_trace_bounds() {
        let mut state = DebuggerState::new();
        assert_eq!(state.goto_step(1), StepOutcome::NoTrace);

        state.load_trace(sample_trace());
        assert_eq!(
            state.goto_step(3),
            StepOutcome::Moved {
                step: 3,
                pc: 4,
                op: "CALL".into()
            }
        );
        assert_eq!(
            state.goto_step(99),
            StepOutcome::InvalidStep {
                requested: 99,
                max_step: Some(3)
            }
        );
    }

    #[test]
    fn parses_reverse_commands_and_aliases() {
        for alias in ["reverse-next", "rnext", "rn"] {
            assert_eq!(DebuggerCommand::parse(alias), DebuggerCommand::ReverseNext);
        }
        for alias in [
            "reverse-nexti",
            "rnexti",
            "rni",
            "reverse-stepi",
            "rsi",
            "back",
        ] {
            assert_eq!(
                DebuggerCommand::parse(alias),
                DebuggerCommand::ReverseNextInstruction,
                "{alias}"
            );
        }
        for alias in ["reverse-step", "rstep", "rs"] {
            assert_eq!(DebuggerCommand::parse(alias), DebuggerCommand::ReverseStep);
        }
        for alias in ["reverse-continue", "rcontinue", "rc", "RC"] {
            assert_eq!(
                DebuggerCommand::parse(alias),
                DebuggerCommand::ReverseContinue
            );
        }
        for alias in ["reverse-finish", "rfinish", "rfin"] {
            assert_eq!(
                DebuggerCommand::parse(alias),
                DebuggerCommand::ReverseFinish
            );
        }
    }

    #[test]
    fn steps_backward_over_the_recording_like_a_tape() {
        let mut state = DebuggerState::new();
        assert_eq!(state.previous_instruction(), StepOutcome::NoTrace);
        assert_eq!(state.reverse_continue(), StepOutcome::NoTrace);

        state.load_trace(sample_trace());
        assert_eq!(
            state.previous_instruction(),
            StepOutcome::AtStart { step: 0 }
        );

        // Forward then back lands on the same step every time.
        state.goto_step(2);
        assert!(matches!(
            state.previous_instruction(),
            StepOutcome::Moved { step: 1, .. }
        ));
        assert!(matches!(
            state.previous_instruction(),
            StepOutcome::Moved { step: 0, .. }
        ));
        assert_eq!(
            state.previous_instruction(),
            StepOutcome::AtStart { step: 0 }
        );
        assert_eq!(state.current_step, 0);

        // Rewinding to any step is a jump; it does not have to walk.
        assert!(matches!(
            state.goto_step(2),
            StepOutcome::Moved { step: 2, .. }
        ));
        assert_eq!(
            state.apply_command(DebuggerCommand::ReverseNextInstruction),
            Some(StepOutcome::Moved {
                step: 1,
                pc: sample_trace().steps[1].pc,
                op: sample_trace().steps[1].op.to_string(),
            })
        );
    }

    #[test]
    fn reverse_continue_stops_at_earlier_breakpoints_then_the_start() {
        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());
        let last = state.step_count() - 1;
        state.goto_step(last);
        let breakpoint_pc = sample_trace().steps[1].pc;
        state.set_breakpoint(breakpoint_pc);

        assert!(matches!(
            state.reverse_continue(),
            StepOutcome::BreakpointHit { step: 1, pc, .. } if pc == breakpoint_pc
        ));
        assert_eq!(state.reverse_continue(), StepOutcome::AtStart { step: 0 });
        assert_eq!(state.current_step, 0);
        assert_eq!(
            state.apply_command(DebuggerCommand::ReverseContinue),
            Some(StepOutcome::AtStart { step: 0 })
        );

        // A breakpoint on the current step is not "earlier": it is passed over.
        state.goto_step(1);
        assert_eq!(state.reverse_continue(), StepOutcome::AtStart { step: 0 });
    }

    #[test]
    fn applies_state_changing_commands() {
        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());

        assert_eq!(
            state.apply_command(DebuggerCommand::Mode(Some(DisplayMode::Assembly))),
            Some(StepOutcome::ModeChanged(DisplayMode::Assembly))
        );
        assert_eq!(state.display_mode.as_str(), "asm");
        assert!(matches!(
            state.apply_command(DebuggerCommand::Break(BreakpointTarget::Pc(2), None)),
            Some(StepOutcome::BreakpointSet(_))
        ));
        assert!(matches!(
            state.apply_command(DebuggerCommand::NextInstruction),
            Some(StepOutcome::BreakpointHit { step: 1, pc: 2, .. })
        ));
        assert_eq!(state.apply_command(DebuggerCommand::Help(None)), None);
        assert_eq!(state.apply_command(DebuggerCommand::Backtrace), None);
        assert_eq!(state.apply_command(DebuggerCommand::Quit), None);
    }

    #[test]
    fn a_state_variable_can_be_named_where_a_slot_would_go() {
        // `break counter` is parsed as a name; without a layout it stays a function
        // breakpoint error, and with one it becomes a write to that variable's slot.
        assert_eq!(
            DebuggerCommand::parse("break counter"),
            DebuggerCommand::Break(BreakpointTarget::Function("counter".to_owned()), None)
        );
        assert_eq!(
            DebuggerCommand::parse("break balances[0xabc]"),
            DebuggerCommand::Break(BreakpointTarget::State("balances[0xabc]".to_owned()), None)
        );
        assert_eq!(
            DebuggerCommand::parse("break config.limit"),
            DebuggerCommand::Break(BreakpointTarget::Function("config.limit".to_owned()), None)
        );

        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());
        // No debug info at all: the message is about the missing metadata.
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::State("counter".to_owned())),
            StepOutcome::BreakpointError(message) if message.contains("metadata")
        ));
    }

    #[test]
    fn a_condition_gates_a_breakpoint_and_says_when_it_cannot_be_read() {
        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());

        // `pc` and `gas` are facts about the step, so they need no debug info.
        assert!(matches!(
            state.set_conditional_breakpoint_target(
                &BreakpointTarget::Opcode("sstore".to_owned()),
                Some("pc == 3")
            ),
            StepOutcome::BreakpointSet(breakpoint)
                if breakpoint.label() == "opcode SSTORE if pc == 3"
        ));
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 2, .. }
        ));

        // The same target with a condition that never holds runs to the end.
        state.goto_step(0);
        state.delete_breakpoint(1);
        assert!(matches!(
            state.set_conditional_breakpoint_target(
                &BreakpointTarget::Opcode("sstore".to_owned()),
                Some("pc == 999")
            ),
            StepOutcome::BreakpointSet(_)
        ));
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::AtEnd { .. }
        ));
        assert_eq!(state.take_note(), None);

        // `&&` and `||`, and a bare value.
        state.goto_step(0);
        state.delete_breakpoint(2);
        assert!(matches!(
            state.set_conditional_breakpoint_target(
                &BreakpointTarget::Opcode("sstore".to_owned()),
                Some("pc == 999 || gas >= 94 && depth == 1")
            ),
            StepOutcome::BreakpointSet(_)
        ));
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 2, .. }
        ));

        // A name nothing defines cannot be read: the breakpoint does not stop, and the
        // reason is kept for the frontend to report rather than failing silently.
        state.goto_step(0);
        state.delete_breakpoint(3);
        assert!(matches!(
            state.set_conditional_breakpoint_target(
                &BreakpointTarget::Opcode("sstore".to_owned()),
                Some("counter > 1")
            ),
            StepOutcome::BreakpointSet(_)
        ));
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::AtEnd { .. }
        ));
        let note = state.take_note().expect("a reason");
        assert!(
            note.contains("`counter > 1` could not be evaluated"),
            "{note}"
        );
        assert_eq!(state.take_note(), None, "the note is taken once");

        // A condition that does not parse is refused when the breakpoint is set.
        assert!(matches!(
            state.set_conditional_breakpoint_target(
                &BreakpointTarget::Opcode("sstore".to_owned()),
                Some("pc ==")
            ),
            StepOutcome::BreakpointError(_)
        ));
    }

    #[test]
    fn tape_breakpoints_search_the_recording() {
        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());

        // The storage write at step 2 is an SSTORE to slot 0; a call to 0x..02 at step 3.
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::Storage("0x00".to_owned())),
            StepOutcome::BreakpointSet(breakpoint)
                if breakpoint.kind == BreakpointKind::Storage("0".to_owned())
                    && breakpoint.label() == "storage slot 0x0"
        ));
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 2, .. }
        ));
        assert_eq!(
            state.set_breakpoint_target(&BreakpointTarget::Storage("zz".to_owned())),
            StepOutcome::BreakpointError(
                "invalid storage slot `zz`; expected decimal or hex".to_owned()
            )
        );
        assert!(matches!(
            state.clear_breakpoint_target(&BreakpointTarget::Storage("0".to_owned())),
            StepOutcome::BreakpointCleared(_)
        ));

        state.goto_step(0);
        let callee = "0x0000000000000000000000000000000000000002";
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::Call(Some(callee.to_owned()))),
            StepOutcome::BreakpointSet(breakpoint) if breakpoint.label() == format!("call to {callee}")
        ));
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 3, .. }
        ));
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::Call(Some("0x12".to_owned()))),
            StepOutcome::BreakpointError(message) if message.contains("20 bytes")
        ));
        state.goto_step(0);
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::Opcode("mstore".to_owned())),
            StepOutcome::BreakpointSet(breakpoint) if breakpoint.label() == "opcode MSTORE"
        ));
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 1, .. }
        ));
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::Revert),
            StepOutcome::BreakpointSet(breakpoint) if breakpoint.label() == "revert"
        ));
        // The last step carries an error, so `revert` hits there.
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 3, .. }
        ));
        assert_eq!(state.breakpoints().len(), 3);

        // Line and function breakpoints need debug info.
        assert_eq!(
            state.set_breakpoint_target(&BreakpointTarget::Function("f".to_owned())),
            StepOutcome::BreakpointError(
                "function breakpoints require compiler debug metadata; start the session with `--ethdebug-dir <address>:<contract>:<dir>`"
                    .to_owned()
            )
        );
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: None,
                line: 1
            })),
            StepOutcome::BreakpointError(message) if message.starts_with("source breakpoints require")
        ));
    }

    #[test]
    fn calldata_and_frames_without_debug_info() {
        let mut state = DebuggerState::new();
        assert!(state.frames().is_empty());
        assert_eq!(state.calldata(), None);
        state.load_trace(sample_trace());
        assert_eq!(state.calldata().as_deref(), Some("0xabcd"));
        let frames = state.frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].address.as_deref(), Some("0x2"));
        assert!(state.location().is_none());
        assert!(state.source_listing(2).is_none());
        assert!(state.current_call().is_none());
    }

    // A contract whose `outer` calls `inner` internally, mapped onto a trace whose steps
    // are: dispatcher (0, 1), outer's declaration (2), line 3 (3), line 4 before the call
    // (4), inner's declaration (5), inner's line 8 (6, 7), back on line 4 (8), line 5 (9),
    // dispatcher (10).
    const SOURCE: &str = "\
contract C {
    function outer(uint256 a) public {
        uint256 b = a + 1;
        inner(b);
        b = 0;
    }
    function inner(uint256 x) internal {
        x += 1;
    }
}
";

    fn source_state() -> DebuggerState {
        let offset = |needle: &str| SOURCE.find(needle).expect(needle) as u64;
        let whole = SOURCE.len() as u64;
        let instruction = |pc: u64, offset: u64, length: u64| -> Instruction {
            serde_json::from_value(json!({
                "offset": pc,
                "operation": {"mnemonic": "JUMPDEST"},
                "context": {"code": {"source": {"id": 0}, "range": {"offset": offset, "length": length}}}
            }))
            .expect("instruction")
        };
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "C".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![
                instruction(0, 0, whole),
                instruction(1, 0, whole),
                instruction(10, offset("function outer"), 90),
                instruction(11, offset("uint256 b = a + 1;"), 18),
                instruction(12, offset("inner(b);"), 9),
                instruction(13, offset("inner(b);"), 9),
                instruction(14, offset("b = 0;"), 6),
                instruction(20, offset("function inner"), 50),
                instruction(21, offset("x += 1;"), 7),
                instruction(30, 0, whole),
            ],
            sources: BTreeMap::from([(0, "C.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        let contract =
            ContractDebugInfo::new(None, "C", info, BTreeMap::from([(0, SOURCE.to_owned())]));
        let pcs = [0, 1, 10, 11, 12, 20, 21, 21, 13, 14, 30];
        let mut trace = sample_trace();
        trace.steps = pcs.iter().map(|pc| step(*pc, "JUMPDEST", 0, &[])).collect();
        trace.steps[6].op = "SSTORE".into();
        trace.steps[6].stack = vec!["0x2a".into(), "0x5".into()];
        let mut state = DebuggerState::new();
        state.load_trace(trace);
        state.attach_debug_info(vec![contract]);
        state
    }

    #[test]
    fn source_stepping_moves_by_line_and_frame() {
        let mut state = source_state();
        assert!(state.has_source());
        assert!(matches!(
            state.next_source(),
            StepOutcome::Moved { step: 2, .. }
        ));
        assert_eq!(state.location().expect("location").line, 2);
        assert!(matches!(
            state.next_source(),
            StepOutcome::Moved { step: 3, .. }
        ));
        assert!(matches!(
            state.next_source(),
            StepOutcome::Moved { step: 4, .. }
        ));
        // `next` steps over the internal call; `step` enters it.
        assert!(matches!(
            state.next_source(),
            StepOutcome::Moved { step: 9, .. }
        ));
        state.goto_step(4);
        assert!(matches!(
            state.step_into(),
            StepOutcome::Moved { step: 5, .. }
        ));
        assert_eq!(
            state.location().expect("location").function_name.as_deref(),
            Some("inner")
        );
        assert!(matches!(
            state.step_into(),
            StepOutcome::Moved { step: 6, .. }
        ));
        // `finish` returns to the call site in outer; `reverse-finish` goes back to it too.
        assert!(matches!(state.finish(), StepOutcome::Moved { step: 8, .. }));
        state.goto_step(6);
        assert!(matches!(
            state.reverse_finish(),
            StepOutcome::Moved { step: 4, .. }
        ));
        // Reverse stepping mirrors forward stepping.
        state.goto_step(9);
        assert!(matches!(
            state.previous_source(),
            StepOutcome::Moved { step: 4, .. }
        ));
        assert!(matches!(
            state.reverse_step_into(),
            StepOutcome::Moved { step: 3, .. }
        ));
        state.goto_step(9);
        assert!(matches!(
            state.reverse_step_into(),
            StepOutcome::Moved { step: 8, .. }
        ));
        // Running off either end reports it.
        state.goto_step(10);
        assert_eq!(state.next_source(), StepOutcome::AtEnd { step: 10 });
        assert_eq!(state.finish(), StepOutcome::AtEnd { step: 10 });
        state.goto_step(9);
        assert_eq!(state.finish(), StepOutcome::AtEnd { step: 10 });
        state.goto_step(0);
        assert_eq!(state.reverse_finish(), StepOutcome::AtStart { step: 0 });
        state.goto_step(1);
        assert_eq!(state.previous_source(), StepOutcome::AtStart { step: 0 });

        let frames = state.frames();
        assert_eq!(frames.len(), 1);
        state.goto_step(6);
        let frames = state.frames();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].function_name.as_deref(), Some("inner"));
        assert_eq!(frames[1].function_name.as_deref(), Some("outer"));
        let listing = state.source_listing(1).expect("listing");
        assert_eq!(listing.current_line, 8);
    }

    #[test]
    fn a_breakpoint_names_each_target_once() {
        // A contract's creation and deployed programs resolve the same line and the same
        // function to one target each; the user reads the name once.
        let line = |contract: usize| ResolvedLine {
            key: LineKey {
                contract,
                source_id: 0,
                line: 4,
            },
            path: "C.sol".to_owned(),
            requested_line: 4,
        };
        let lines = Breakpoint {
            id: 1,
            kind: BreakpointKind::Line(vec![line(0), line(1)]),
            condition: None,
        };
        assert_eq!(lines.label(), "C.sol:4");

        let function = |contract: usize| ResolvedFunction {
            id: FunctionId {
                contract,
                function: 1,
            },
            name: "inner".to_owned(),
            contract_name: "C".to_owned(),
            path: "C.sol".to_owned(),
            line: 7,
        };
        let functions = Breakpoint {
            id: 2,
            kind: BreakpointKind::Function(vec![function(0), function(1)]),
            condition: None,
        };
        assert_eq!(functions.label(), "function C.inner at C.sol:7");

        // Distinct targets are all named.
        let mut other = line(1);
        other.key.line = 1;
        other.requested_line = 10;
        let mixed = Breakpoint {
            id: 3,
            kind: BreakpointKind::Line(vec![line(0), other]),
            condition: None,
        };
        assert_eq!(
            mixed.label(),
            "C.sol:4, C.sol:1 (the statement containing line 10)"
        );
    }

    #[test]
    fn variables_are_inferred_from_the_stack_when_the_artifact_has_no_locations() {
        let source = "contract C {\n    function f(uint256 a) public {\n        uint256 b = a;\n        b = 0;\n    }\n}\n";
        let offset = |needle: &str| source.find(needle).expect(needle) as u64;
        let instruction = |pc: u64, needle: &str| -> Instruction {
            serde_json::from_value(json!({
                "offset": pc,
                "operation": {"mnemonic": "JUMPDEST"},
                "context": {"code": {"source": {"id": 0}, "range": {"offset": offset(needle), "length": needle.len()}}}
            }))
            .expect("instruction")
        };
        let contract = |code_generator: Option<CodeGenerator>| {
            let info = EthdebugInfo {
                compilation: serde_json::Value::Null,
                contract_name: "C".to_owned(),
                environment: "call".to_owned(),
                instructions: vec![
                    instruction(0, "contract C"),
                    instruction(1, "function f"),
                    instruction(2, "uint256 b"),
                    instruction(3, "b = 0"),
                ],
                sources: BTreeMap::from([(0, "C.sol".to_owned())]),
                variable_locations: BTreeMap::new(),
            };
            ContractDebugInfo::new(None, "C", info, BTreeMap::from([(0, source.to_owned())]))
                .with_code_generator(code_generator)
        };
        let mut trace = sample_trace();
        trace.steps = vec![
            step(0, "PUSH1", 0, &[]),
            step(1, "JUMPDEST", 0, &["0x9", "0x5"]),
            step(2, "PUSH0", 0, &["0x9", "0x5"]),
            step(3, "POP", 0, &["0x9", "0x5", "0x5"]),
        ];

        let mut state = DebuggerState::new();
        state.load_trace(trace.clone());
        state.attach_debug_info(vec![contract(Some(CodeGenerator::Legacy))]);
        assert_eq!(
            state.variables().unwrap_err(),
            "no function is executing at this step"
        );
        state.goto_step(3);
        let variables = state.variables().expect("inferred");
        assert_eq!(variables.origin, VariablesOrigin::Inferred);
        assert_eq!(
            variables
                .variables
                .iter()
                .map(|variable| (variable.name.as_str(), variable.value.display.as_str()))
                .collect::<Vec<_>>(),
            [("a", "5"), ("b", "5")]
        );

        // The via-IR pipeline keeps no layout to read.
        let mut state = DebuggerState::new();
        state.load_trace(trace);
        state.attach_debug_info(vec![contract(Some(CodeGenerator::ViaIr))]);
        state.goto_step(3);
        assert!(state.variables().unwrap_err().contains("via-IR pipeline"));
    }

    #[test]
    fn line_and_function_breakpoints_stop_on_entry() {
        let mut state = source_state();
        let set =
            state.set_breakpoint_target(&BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: Some("C.sol".to_owned()),
                line: 4,
            }));
        let StepOutcome::BreakpointSet(breakpoint) = &set else {
            panic!("{set:?}");
        };
        assert_eq!(breakpoint.label(), "C.sol:4");
        // The line is entered once at step 4; returning into it at step 8 does not count.
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 4, .. }
        ));
        assert_eq!(state.continue_execution(), StepOutcome::AtEnd { step: 10 });
        // `next` stops at a breakpoint inside the code it steps over.
        state.goto_step(3);
        assert!(matches!(
            state.next_source(),
            StepOutcome::BreakpointHit { step: 4, .. }
        ));
        assert!(matches!(
            state.clear_breakpoint_target(&BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: None,
                line: 4,
            })),
            StepOutcome::BreakpointCleared(_)
        ));
        assert_eq!(
            state.set_breakpoint_target(&BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: Some("Other.sol".to_owned()),
                line: 4,
            })),
            StepOutcome::BreakpointError("source file not found: Other.sol".to_owned())
        );
        // A line inside a statement resolves to the statement and says so.
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: None,
                line: 10,
            })),
            StepOutcome::BreakpointSet(breakpoint)
                if breakpoint.label() == "C.sol:1 (the statement containing line 10)"
        ));

        state.goto_step(0);
        let set = state.set_breakpoint_target(&BreakpointTarget::Function("inner".to_owned()));
        let StepOutcome::BreakpointSet(breakpoint) = &set else {
            panic!("{set:?}");
        };
        assert_eq!(breakpoint.label(), "function C.inner at C.sol:7");
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 5, .. }
        ));
        // `reverse-continue` finds it again from later on.
        state.goto_step(10);
        assert!(matches!(
            state.reverse_continue(),
            StepOutcome::BreakpointHit { step: 5, .. }
        ));
        assert!(matches!(
            state.set_breakpoint_target(&BreakpointTarget::Function("nothing".to_owned())),
            StepOutcome::BreakpointError(message) if message.contains("no function named")
        ));
        assert!(matches!(
            state.clear_breakpoint_target(&BreakpointTarget::Function("C.inner".to_owned())),
            StepOutcome::BreakpointCleared(_)
        ));
        assert!(matches!(
            state.clear_breakpoint_target(&BreakpointTarget::Function("C.inner".to_owned())),
            StepOutcome::BreakpointMissing(label) if label == "function C.inner at C.sol:7"
        ));
    }

    #[test]
    fn a_breakpoint_condition_reads_an_inferred_local() {
        let source = "contract C {\n    enum Mode { Off, On }\n    function f(uint256 a, Mode m) public {\n        uint256 b = a;\n        b = 0;\n    }\n}\n";
        let offset = |needle: &str| source.find(needle).expect(needle) as u64;
        let instruction = |pc: u64, needle: &str| -> Instruction {
            serde_json::from_value(json!({
                "offset": pc,
                "operation": {"mnemonic": "JUMPDEST"},
                "context": {"code": {"source": {"id": 0}, "range": {"offset": offset(needle), "length": needle.len()}}}
            }))
            .expect("instruction")
        };
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "C".to_owned(),
            environment: "call".to_owned(),
            instructions: vec![
                instruction(0, "contract C"),
                instruction(1, "function f"),
                instruction(2, "uint256 b"),
                instruction(3, "b = 0"),
            ],
            sources: BTreeMap::from([(0, "C.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        let contract =
            ContractDebugInfo::new(None, "C", info, BTreeMap::from([(0, source.to_owned())]))
                .with_code_generator(Some(CodeGenerator::Legacy));
        let mut trace = sample_trace();
        trace.steps = vec![
            step(0, "PUSH1", 0, &[]),
            step(1, "JUMPDEST", 0, &["0x9", "0x5", "0x1"]),
            step(2, "PUSH0", 0, &["0x9", "0x5", "0x1"]),
            step(3, "POP", 0, &["0x9", "0x5", "0x1", "0x5"]),
        ];
        let mut state = DebuggerState::new();
        state.load_trace(trace);
        state.attach_debug_info(vec![contract]);

        // The local is read off its slot, the enum parameter by name and against an enum
        // literal; a condition that does not hold there does not stop.
        let hit = |condition: &str| -> (Option<usize>, Option<String>) {
            let mut state = state.clone();
            let DebuggerCommand::Break(target, condition) =
                DebuggerCommand::parse(&format!("break C.sol:5 if {condition}"))
            else {
                panic!("break command");
            };
            state.set_conditional_breakpoint_target(&target, condition.as_deref());
            let step = match state.continue_execution() {
                StepOutcome::BreakpointHit { .. } => Some(state.current_step),
                _ => None,
            };
            (step, state.take_note())
        };
        assert_eq!(hit("b == 5"), (Some(3), None));
        assert_eq!(hit("b == a"), (Some(3), None));
        assert_eq!(hit("m == Mode.On"), (Some(3), None));
        assert_eq!(hit("m == Mode.Off").0, None);
        assert_eq!(hit("b > 5").0, None);
        // An unknown name says what was looked for.
        let (step, note) = hit("c == 5");
        assert_eq!(step, None);
        let note = note.expect("note");
        assert!(note.contains("`c == 5` could not be evaluated"), "{note}");
        assert!(
            note.contains("`c` is not a step value, a local, or an argument here"),
            "{note}"
        );
    }

    fn sample_trace() -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0xabcd".to_owned(),
            gas_used: 21_000,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some("debug-rpc".to_owned()),
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: vec![
                step(0, "PUSH1", 100, &[]),
                step(2, "MSTORE", 97, &[]),
                step(3, "SSTORE", 94, &["0x2a", "0x0"]),
                {
                    let mut last = step(
                        4,
                        "CALL",
                        92,
                        &[
                            "0x0",
                            "0x0",
                            "0x0",
                            "0x0",
                            "0x0",
                            "0x0000000000000000000000000000000000000000000000000000000000000002",
                            "0x5208",
                        ],
                    );
                    last.error = Some("execution reverted".to_owned());
                    last
                },
            ],
        }
    }

    fn step(pc: u64, op: &str, gas: u64, stack: &[&str]) -> TraceStep {
        TraceStep {
            pc,
            op: op.into(),
            gas,
            gas_cost: 1,
            depth: 1,
            stack: stack
                .iter()
                .map(|word| soldb_core::Word::from(*word))
                .collect(),
            memory: None,
            storage: Some(BTreeMap::new()),
            error: None,
            snapshot: StepSnapshot::default(),
        }
    }
}
