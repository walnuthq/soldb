use std::collections::BTreeSet;

use soldb_core::{TraceStep, TransactionTrace};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerCommand {
    Next,
    NextInstruction,
    Step,
    Continue,
    Goto(usize),
    Mode(Option<DisplayMode>),
    Break(u64),
    Clear(u64),
    Help(Option<String>),
    Quit,
    Empty,
    Unknown(String),
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
            "goto" => rest
                .parse::<usize>()
                .map(Self::Goto)
                .unwrap_or_else(|_| Self::Unknown(line.to_owned())),
            "mode" => Self::Mode(
                (!rest.is_empty())
                    .then(|| DisplayMode::parse(&rest))
                    .flatten(),
            ),
            "break" | "b" => parse_u64_arg(&rest)
                .map(Self::Break)
                .unwrap_or_else(|| Self::Unknown(line.to_owned())),
            "clear" => parse_u64_arg(&rest)
                .map(Self::Clear)
                .unwrap_or_else(|| Self::Unknown(line.to_owned())),
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
    },
    AtEnd {
        step: usize,
    },
    InvalidStep {
        requested: usize,
        max_step: Option<usize>,
    },
    ModeChanged(DisplayMode),
    BreakpointSet(u64),
    BreakpointCleared(u64),
    BreakpointMissing(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebuggerState {
    pub current_step: usize,
    pub display_mode: DisplayMode,
    pub breakpoints: BTreeSet<u64>,
    trace: Option<TransactionTrace>,
}

impl Default for DebuggerState {
    fn default() -> Self {
        Self {
            current_step: 0,
            display_mode: DisplayMode::Source,
            breakpoints: BTreeSet::new(),
            trace: None,
        }
    }
}

impl DebuggerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_trace(&mut self, trace: TransactionTrace) {
        self.trace = Some(trace);
        self.current_step = 0;
    }

    pub fn trace(&self) -> Option<&TransactionTrace> {
        self.trace.as_ref()
    }

    pub fn current_step_data(&self) -> Option<&TraceStep> {
        self.trace
            .as_ref()
            .and_then(|trace| trace.steps.get(self.current_step))
    }

    pub fn step_count(&self) -> usize {
        self.trace
            .as_ref()
            .map(|trace| trace.steps.len())
            .unwrap_or(0)
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

    pub fn next_source(&mut self) -> StepOutcome {
        self.next_instruction()
    }

    pub fn step_into(&mut self) -> StepOutcome {
        self.next_instruction()
    }

    pub fn continue_execution(&mut self) -> StepOutcome {
        let Some(trace) = &self.trace else {
            return StepOutcome::NoTrace;
        };
        if self.current_step >= trace.steps.len().saturating_sub(1) {
            return StepOutcome::AtEnd {
                step: self.current_step,
            };
        }

        while self.current_step < trace.steps.len().saturating_sub(1) {
            self.current_step += 1;
            let step = &trace.steps[self.current_step];
            if self.breakpoints.contains(&step.pc) {
                return StepOutcome::BreakpointHit {
                    step: self.current_step,
                    pc: step.pc,
                };
            }
        }

        StepOutcome::AtEnd {
            step: self.current_step,
        }
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

    pub fn set_breakpoint(&mut self, pc: u64) -> StepOutcome {
        self.breakpoints.insert(pc);
        StepOutcome::BreakpointSet(pc)
    }

    pub fn clear_breakpoint(&mut self, pc: u64) -> StepOutcome {
        if self.breakpoints.remove(&pc) {
            StepOutcome::BreakpointCleared(pc)
        } else {
            StepOutcome::BreakpointMissing(pc)
        }
    }

    pub fn apply_command(&mut self, command: DebuggerCommand) -> Option<StepOutcome> {
        match command {
            DebuggerCommand::Next => Some(self.next_source()),
            DebuggerCommand::NextInstruction => Some(self.next_instruction()),
            DebuggerCommand::Step => Some(self.step_into()),
            DebuggerCommand::Continue => Some(self.continue_execution()),
            DebuggerCommand::Goto(step) => Some(self.goto_step(step)),
            DebuggerCommand::Mode(Some(mode)) => Some(self.set_display_mode(mode)),
            DebuggerCommand::Break(pc) => Some(self.set_breakpoint(pc)),
            DebuggerCommand::Clear(pc) => Some(self.clear_breakpoint(pc)),
            DebuggerCommand::Empty
            | DebuggerCommand::Help(_)
            | DebuggerCommand::Mode(None)
            | DebuggerCommand::Quit
            | DebuggerCommand::Unknown(_) => None,
        }
    }

    fn outcome_for_current_step(&self) -> StepOutcome {
        let Some(step) = self.current_step_data() else {
            return StepOutcome::NoTrace;
        };
        if self.breakpoints.contains(&step.pc) {
            return StepOutcome::BreakpointHit {
                step: self.current_step,
                pc: step.pc,
            };
        }
        StepOutcome::Moved {
            step: self.current_step,
            pc: step.pc,
            op: step.op.clone(),
        }
    }
}

fn parse_u64_arg(input: &str) -> Option<u64> {
    let input = input.trim();
    if let Some(hex) = input.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        input.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{DebuggerCommand, DebuggerState, DisplayMode, StepOutcome};
    use soldb_core::{TraceStep, TransactionTrace};

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
        assert_eq!(DebuggerCommand::parse("goto 2"), DebuggerCommand::Goto(2));
        assert_eq!(
            DebuggerCommand::parse("mode assembly"),
            DebuggerCommand::Mode(Some(DisplayMode::Assembly))
        );
        assert_eq!(
            DebuggerCommand::parse("break 0x10"),
            DebuggerCommand::Break(16)
        );
        assert_eq!(DebuggerCommand::parse("clear 8"), DebuggerCommand::Clear(8));
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

        state.load_trace(sample_trace());
        assert_eq!(state.step_count(), 4);
        assert_eq!(state.current_step_data().expect("step").op, "PUSH1");

        assert_eq!(
            state.next_instruction(),
            StepOutcome::Moved {
                step: 1,
                pc: 2,
                op: "MSTORE".to_owned()
            }
        );
        assert_eq!(state.current_step, 1);
    }

    #[test]
    fn continues_until_breakpoint_or_end() {
        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());
        assert_eq!(state.set_breakpoint(3), StepOutcome::BreakpointSet(3));

        assert_eq!(
            state.continue_execution(),
            StepOutcome::BreakpointHit { step: 2, pc: 3 }
        );
        assert_eq!(state.current_step, 2);

        assert_eq!(state.clear_breakpoint(3), StepOutcome::BreakpointCleared(3));
        assert_eq!(state.clear_breakpoint(3), StepOutcome::BreakpointMissing(3));
        assert_eq!(state.continue_execution(), StepOutcome::AtEnd { step: 3 });
        assert_eq!(state.continue_execution(), StepOutcome::AtEnd { step: 3 });
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
                op: "STOP".to_owned()
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
    fn applies_state_changing_commands() {
        let mut state = DebuggerState::new();
        state.load_trace(sample_trace());

        assert_eq!(
            state.apply_command(DebuggerCommand::Mode(Some(DisplayMode::Assembly))),
            Some(StepOutcome::ModeChanged(DisplayMode::Assembly))
        );
        assert_eq!(state.display_mode.as_str(), "asm");
        assert_eq!(
            state.apply_command(DebuggerCommand::Break(2)),
            Some(StepOutcome::BreakpointSet(2))
        );
        assert_eq!(
            state.apply_command(DebuggerCommand::NextInstruction),
            Some(StepOutcome::BreakpointHit { step: 1, pc: 2 })
        );
        assert_eq!(state.apply_command(DebuggerCommand::Help(None)), None);
        assert_eq!(state.apply_command(DebuggerCommand::Quit), None);
    }

    fn sample_trace() -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
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
                step(0, "PUSH1", 100),
                step(2, "MSTORE", 97),
                step(3, "CALLDATASIZE", 94),
                step(4, "STOP", 92),
            ],
        }
    }

    fn step(pc: u64, op: &str, gas: u64) -> TraceStep {
        TraceStep {
            pc,
            op: op.to_owned(),
            gas,
            gas_cost: 1,
            depth: 0,
            stack: Vec::new(),
            memory: None,
            storage: Some(BTreeMap::new()),
            error: None,
            snapshot: Default::default(),
        }
    }
}
