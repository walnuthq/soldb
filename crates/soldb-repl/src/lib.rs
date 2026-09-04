//! The interactive debugger's command parser and state machine.
//!
//! [`DebuggerCommand::parse`] turns a typed line into a command, and
//! [`DebuggerState::apply_command`] applies the ones that move the debugger or change its
//! breakpoints, returning a [`StepOutcome`] describing what happened.
//!
//! This crate performs no I/O: it neither reads stdin nor prints. The frontend owns the
//! terminal and renders outcomes, which is what makes stepping, breakpoints, and command
//! parsing testable without a terminal or a node. Commands that only display something
//! (`vars`, `backtrace`, `list`, `info`) return `None` from `apply_command`; the frontend
//! reads the data it needs through the state's accessors and formats it.
//!
//! The trace is a complete recording, so every movement is a search over it, forward or
//! backward, and a breakpoint is a predicate on a step: a program counter, the start of
//! a source line, the entry of a function, a storage write, a revert, a call, an opcode.
//! Source-level movement comes from [`soldb_debugger::StepMap`], which every frontend
//! shares, so `next` means the same thing in the terminal and in an editor.

use soldb_core::{ExecutionCall, TraceStep, TransactionTrace};
use soldb_debugger::{
    call_target, normalize_address, ContractDebugInfo, Frame, ResolvedFunction, ResolvedLine,
    SourceListing, StepLocation, StepMap, StorageLayout, StorageTape, StorageWords,
};

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
        match &self.kind {
            BreakpointKind::Pc(pc) => format!("PC {pc}"),
            BreakpointKind::Line(lines) => lines
                .iter()
                .map(|line| {
                    if line.requested_line == line.key.line {
                        format!("{}:{}", line.path, line.key.line)
                    } else {
                        format!(
                            "{}:{} (the statement containing line {})",
                            line.path, line.key.line, line.requested_line
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
            BreakpointKind::Function(functions) => functions
                .iter()
                .map(|function| {
                    format!(
                        "function {}.{} at {}:{}",
                        function.contract_name, function.name, function.path, function.line
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
            BreakpointKind::Storage(slot) => format!("storage slot 0x{slot}"),
            BreakpointKind::Revert => "revert".to_owned(),
            BreakpointKind::Call(Some(address)) => format!("call to {address}"),
            BreakpointKind::Call(None) => "any call".to_owned(),
            BreakpointKind::Opcode(mnemonic) => format!("opcode {mnemonic}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerCommand {
    Next,
    NextInstruction,
    Step,
    Continue,
    /// Run until the current frame returns to its caller.
    Finish,
    /// Step back to the previous source step.
    ReverseNext,
    /// Step back one EVM instruction.
    ReverseNextInstruction,
    /// Step back into the previous instruction, the mirror of `step`.
    ReverseStep,
    /// Run backward until a breakpoint or the first step.
    ReverseContinue,
    /// Run backward to the step that entered the current frame.
    ReverseFinish,
    Goto(usize),
    /// List every source variable ETHDebug reports as live at the current program counter.
    Vars,
    /// Print one source variable by name at the current program counter.
    ///
    /// An empty name means the user typed `print` with no argument; the frontend reports
    /// the usage rather than treating it as an unknown command.
    Print(String),
    Info(DebuggerInfoCommand),
    /// The call structure at the current step.
    Backtrace,
    /// The source around the current step.
    List,
    /// Memory at the current step, optionally one range of it.
    Memory {
        offset: Option<u64>,
        length: Option<u64>,
    },
    /// The calldata of the current call frame.
    Calldata,
    /// The stack at the current step.
    Stack,
    Mode(Option<DisplayMode>),
    Break(BreakpointTarget),
    Clear(BreakpointTarget),
    /// Remove a breakpoint by number.
    Delete(u32),
    Help(Option<String>),
    Quit,
    Empty,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerInfoCommand {
    Resources { json: bool },
    Breakpoints,
    Storage,
}

impl DebuggerCommand {
    pub fn parse(line: &str) -> Self {
        let line = line.trim();
        if line.is_empty() {
            return Self::Empty;
        }

        let mut parts = line.split_whitespace();
        let command = parts.next().unwrap_or_default().to_ascii_lowercase();
        let rest = parts.collect::<Vec<_>>().join(" ");
        match command.as_str() {
            "next" | "n" => Self::Next,
            "nexti" | "ni" | "stepi" | "si" => Self::NextInstruction,
            "step" | "s" => Self::Step,
            "continue" | "c" => Self::Continue,
            "finish" | "fin" => Self::Finish,
            "reverse-next" | "rnext" | "rn" => Self::ReverseNext,
            "reverse-nexti" | "rnexti" | "rni" | "reverse-stepi" | "rsi" | "back" => {
                Self::ReverseNextInstruction
            }
            "reverse-step" | "rstep" | "rs" => Self::ReverseStep,
            "reverse-continue" | "rcontinue" | "rc" => Self::ReverseContinue,
            "reverse-finish" | "rfinish" | "rfin" => Self::ReverseFinish,
            "vars" | "locals" => Self::Vars,
            "print" | "p" => Self::Print(rest),
            "backtrace" | "bt" | "where" => Self::Backtrace,
            "list" | "l" => Self::List,
            "memory" | "mem" => {
                parse_memory_command(&rest).unwrap_or_else(|| Self::Unknown(line.to_owned()))
            }
            "calldata" => Self::Calldata,
            "stack" => Self::Stack,
            "storage" => Self::Info(DebuggerInfoCommand::Storage),
            "goto" => rest
                .parse::<usize>()
                .map(Self::Goto)
                .unwrap_or_else(|_| Self::Unknown(line.to_owned())),
            "info" | "i" => parse_info_command(&rest)
                .map(Self::Info)
                .unwrap_or_else(|| Self::Unknown(line.to_owned())),
            "mode" => Self::Mode(
                (!rest.is_empty())
                    .then(|| DisplayMode::parse(&rest))
                    .flatten(),
            ),
            "break" | "b" => parse_breakpoint_target(&rest)
                .map(Self::Break)
                .unwrap_or_else(|| Self::Unknown(line.to_owned())),
            "clear" => parse_breakpoint_target(&rest)
                .map(Self::Clear)
                .unwrap_or_else(|| Self::Unknown(line.to_owned())),
            "delete" | "d" => rest
                .trim()
                .trim_start_matches('#')
                .parse::<u32>()
                .map(Self::Delete)
                .unwrap_or_else(|_| Self::Unknown(line.to_owned())),
            "help" => Self::Help((!rest.is_empty()).then_some(rest)),
            "exit" | "quit" | "q" => Self::Quit,
            _ => Self::Unknown(line.to_owned()),
        }
    }
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
        self.add_breakpoint(BreakpointKind::Pc(pc))
    }

    /// Clears the breakpoint on a program counter.
    pub fn clear_breakpoint(&mut self, pc: u64) -> StepOutcome {
        self.remove_breakpoint(&BreakpointKind::Pc(pc), &format!("PC {pc}"))
    }

    /// Resolves a target against the trace and its debug info and sets a breakpoint on
    /// it.
    pub fn set_breakpoint_target(&mut self, target: &BreakpointTarget) -> StepOutcome {
        match self.resolve_target(target) {
            Ok(kind) => self.add_breakpoint(kind),
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

    fn add_breakpoint(&mut self, kind: BreakpointKind) -> StepOutcome {
        if let Some(existing) = self
            .breakpoints
            .iter()
            .find(|breakpoint| breakpoint.kind == kind)
        {
            return StepOutcome::BreakpointSet(existing.clone());
        }
        let breakpoint = Breakpoint {
            id: self.next_breakpoint_id,
            kind,
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
                map.resolve_function(name).map(BreakpointKind::Function)
            }
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
        let map = self.step_map.as_ref();
        self.breakpoints
            .iter()
            .find(|breakpoint| match &breakpoint.kind {
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
                BreakpointKind::Storage(slot) => {
                    trace_step.op == "SSTORE"
                        && trace_step
                            .snapshot_ref()
                            .stack
                            .last()
                            .and_then(|word| normalize_slot(word))
                            .is_some_and(|written| written == *slot)
                }
                BreakpointKind::Revert => trace_step.op == "REVERT" || trace_step.error.is_some(),
                BreakpointKind::Call(address) => {
                    let target = call_target(trace_step);
                    match address {
                        Some(address) => target.as_deref() == Some(address.as_str()),
                        None => target.is_some() || is_call_opcode(&trace_step.op),
                    }
                }
                BreakpointKind::Opcode(mnemonic) => trace_step.op.eq_ignore_ascii_case(mnemonic),
            })
            .cloned()
    }

    /// The call structure at the current step, innermost frame first.
    #[must_use]
    pub fn frames(&self) -> Vec<Frame> {
        self.step_map
            .as_ref()
            .map(|map| map.frames(self.current_step))
            .unwrap_or_default()
    }

    /// Source lines around the current step.
    #[must_use]
    pub fn source_listing(&self, radius: u64) -> Option<SourceListing> {
        self.step_map
            .as_ref()?
            .source_listing(self.current_step, radius)
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
            DebuggerCommand::Break(target) => Some(self.set_breakpoint_target(&target)),
            DebuggerCommand::Clear(target) => Some(self.clear_breakpoint_target(&target)),
            DebuggerCommand::Delete(id) => Some(self.delete_breakpoint(id)),
            DebuggerCommand::Empty
            | DebuggerCommand::Help(_)
            | DebuggerCommand::Info(_)
            | DebuggerCommand::Backtrace
            | DebuggerCommand::List
            | DebuggerCommand::Memory { .. }
            | DebuggerCommand::Calldata
            | DebuggerCommand::Stack
            | DebuggerCommand::Mode(None)
            | DebuggerCommand::Print(_)
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
            op: step.op.clone(),
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

fn parse_info_command(input: &str) -> Option<DebuggerInfoCommand> {
    match input.trim() {
        "resources" => Some(DebuggerInfoCommand::Resources { json: false }),
        "resources --json" | "resources json" => {
            Some(DebuggerInfoCommand::Resources { json: true })
        }
        "breakpoints" | "break" | "b" => Some(DebuggerInfoCommand::Breakpoints),
        "storage" => Some(DebuggerInfoCommand::Storage),
        _ => None,
    }
}

fn parse_memory_command(input: &str) -> Option<DebuggerCommand> {
    let mut parts = input.split_whitespace();
    let offset = match parts.next() {
        Some(text) => Some(parse_u64_arg(text)?),
        None => None,
    };
    let length = match parts.next() {
        Some(text) => Some(parse_u64_arg(text)?),
        None => None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some(DebuggerCommand::Memory { offset, length })
}

fn parse_u64_arg(input: &str) -> Option<u64> {
    let input = input.trim();
    if let Some(hex) = input.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        input.parse::<u64>().ok()
    }
}

fn parse_breakpoint_target(input: &str) -> Option<BreakpointTarget> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let mut parts = input.splitn(2, char::is_whitespace);
    let head = parts.next().unwrap_or_default();
    let rest = parts.next().map(str::trim).unwrap_or_default();
    match head.to_ascii_lowercase().as_str() {
        "storage" | "slot" => {
            (!rest.is_empty()).then(|| BreakpointTarget::Storage(rest.to_owned()))
        }
        "revert" if rest.is_empty() => Some(BreakpointTarget::Revert),
        "call" => Some(BreakpointTarget::Call(
            (!rest.is_empty()).then(|| rest.to_owned()),
        )),
        "op" | "opcode" => (!rest.is_empty() && !rest.contains(char::is_whitespace))
            .then(|| BreakpointTarget::Opcode(rest.to_owned())),
        _ => {
            if let Some(target) = parse_source_breakpoint_target(input) {
                return Some(BreakpointTarget::SourceLine(target));
            }
            if let Some(pc) = parse_u64_arg(input) {
                return Some(BreakpointTarget::Pc(pc));
            }
            is_function_name(input).then(|| BreakpointTarget::Function(input.to_owned()))
        }
    }
}

fn is_function_name(input: &str) -> bool {
    let mut segments = input.split('.');
    segments.all(|segment| {
        let mut bytes = segment.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn parse_source_breakpoint_target(input: &str) -> Option<SourceBreakpointTarget> {
    let input = input.trim();
    if let Some(line) = input.strip_prefix("line ") {
        return parse_source_line_number(line)
            .map(|line| SourceBreakpointTarget { file: None, line });
    }

    let (file, line) = input.rsplit_once(':')?;
    let file = file.trim();
    if file.is_empty() {
        return None;
    }
    parse_source_line_number(line).map(|line| SourceBreakpointTarget {
        file: Some(file.to_owned()),
        line,
    })
}

fn parse_source_line_number(input: &str) -> Option<u64> {
    input.trim().parse::<u64>().ok().filter(|line| *line > 0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use soldb_core::{StepSnapshot, TraceStep, TransactionTrace};
    use soldb_debugger::ContractDebugInfo;
    use soldb_ethdebug::{EthdebugInfo, Instruction};

    use super::{
        BreakpointKind, BreakpointTarget, DebuggerCommand, DebuggerInfoCommand, DebuggerState,
        DisplayMode, SourceBreakpointTarget, StepOutcome,
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
            DebuggerCommand::Break(BreakpointTarget::Pc(16))
        );
        assert_eq!(
            DebuggerCommand::parse("break Counter.sol:7"),
            DebuggerCommand::Break(BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: Some("Counter.sol".to_owned()),
                line: 7
            }))
        );
        assert_eq!(
            DebuggerCommand::parse("break line 7"),
            DebuggerCommand::Break(BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: None,
                line: 7
            }))
        );
        assert_eq!(
            DebuggerCommand::parse("break increment"),
            DebuggerCommand::Break(BreakpointTarget::Function("increment".to_owned()))
        );
        assert_eq!(
            DebuggerCommand::parse("b Counter.increment"),
            DebuggerCommand::Break(BreakpointTarget::Function("Counter.increment".to_owned()))
        );
        assert_eq!(
            DebuggerCommand::parse("break storage 0x0"),
            DebuggerCommand::Break(BreakpointTarget::Storage("0x0".to_owned()))
        );
        assert_eq!(
            DebuggerCommand::parse("break revert"),
            DebuggerCommand::Break(BreakpointTarget::Revert)
        );
        assert_eq!(
            DebuggerCommand::parse("break call"),
            DebuggerCommand::Break(BreakpointTarget::Call(None))
        );
        assert_eq!(
            DebuggerCommand::parse("break call 0xabc"),
            DebuggerCommand::Break(BreakpointTarget::Call(Some("0xabc".to_owned())))
        );
        assert_eq!(
            DebuggerCommand::parse("break op sstore"),
            DebuggerCommand::Break(BreakpointTarget::Opcode("sstore".to_owned()))
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
        assert_eq!(DebuggerCommand::parse("stack"), DebuggerCommand::Stack);
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
        assert_eq!(state.current_step_data().expect("step").op, "PUSH1");
        assert!(!state.has_source());

        assert_eq!(
            state.next_instruction(),
            StepOutcome::Moved {
                step: 1,
                pc: 2,
                op: "MSTORE".to_owned()
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
                op: "CALL".to_owned()
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
                op: sample_trace().steps[1].op.clone(),
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
            state.apply_command(DebuggerCommand::Break(BreakpointTarget::Pc(2))),
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
        trace.steps[6].op = "SSTORE".to_owned();
        trace.steps[6].stack = vec!["0x2a".to_owned(), "0x5".to_owned()];
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
            op: op.to_owned(),
            gas,
            gas_cost: 1,
            depth: 1,
            stack: stack.iter().map(|word| (*word).to_owned()).collect(),
            memory: None,
            storage: Some(BTreeMap::new()),
            error: None,
            snapshot: StepSnapshot::default(),
        }
    }
}
