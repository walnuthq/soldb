//! A debugging session: commands in, [`Output`] out.
//!
//! The session owns the [`DebuggerState`] and answers every command with data, never
//! text, so the terminal REPL, the full-screen view, an editor, and a script all run
//! the same commands and see the same answers. What is said once a session — that
//! locals are inferred, that frame arguments are read off the stack — is remembered
//! here, so it is said once whichever frontend asks first.

use soldb_debugger::{
    state_value, state_variables, ChainStorage, DebugValueStatus, DebugVariable, StateSource,
    StateVariable, StorageWords, INFERRED_LOCALS_WARNING,
};

use crate::command::{command_spec, CommandGroup, COMMANDS};
use crate::response::{
    ArgumentInfo, BreakpointEvent, BreakpointInfo, FrameInfo, Level, ListedLine, LoadedContract,
    MemoryInfo, MemoryWord, Output, ResourceInfo, SlotInfo, StateInfo, Stop, StopLocation,
    StopReason, ValueStatus, VariableInfo,
};
use crate::{
    BreakpointKind, DebuggerCommand, DebuggerInfoCommand, DebuggerState, DisplayMode, StepOutcome,
    VariablesOrigin,
};

/// What `backtrace` says once about arguments read off the stack.
pub const FRAME_ARGUMENTS_WARNING: &str = "frame arguments are read off the stack, not from \
compiler-reported variable locations";

/// The note under [`FRAME_ARGUMENTS_WARNING`].
pub const FRAME_ARGUMENTS_NOTE: &str = "the calling convention was proved from this trace's \
calldata; ETHDebug variable locations will replace this once the compiler emits them";

/// How many lines `list` shows on each side of the current one.
pub const LISTING_RADIUS: u64 = 5;

/// A debugging session over one trace.
pub struct Session {
    state: DebuggerState,
    chain: Option<Box<dyn ChainStorage>>,
    locals_warning_shown: bool,
    arguments_warning_shown: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("step", &self.state.current_step)
            .field(
                "chain",
                &self.chain.as_ref().map(|chain| chain.label().to_owned()),
            )
            .finish_non_exhaustive()
    }
}

impl Session {
    #[must_use]
    pub fn new(state: DebuggerState) -> Self {
        Self {
            state,
            chain: None,
            locals_warning_shown: false,
            arguments_warning_shown: false,
        }
    }

    /// Reads storage slots the trace never touched from `chain`.
    #[must_use]
    pub fn with_chain(mut self, chain: Option<Box<dyn ChainStorage>>) -> Self {
        self.chain = chain;
        self
    }

    #[must_use]
    pub fn state(&self) -> &DebuggerState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut DebuggerState {
        &mut self.state
    }

    /// The storage words known at the current step, read from the chain for slots the
    /// trace never touched when a chain is attached.
    #[must_use]
    pub fn storage_words(&self) -> Option<StorageWords<'_>> {
        self.state.storage_words_with_chain(self.chain.as_deref())
    }

    /// What was loaded: the trace's size and the contracts with sources.
    #[must_use]
    pub fn loaded(&self) -> Output {
        let mut contracts = Vec::<LoadedContract>::new();
        for contract in self.state.step_map().map_or(&[][..], |map| map.contracts()) {
            if contract.info.instructions.is_empty() && contract.source_contents.is_empty() {
                continue;
            }
            let entry = LoadedContract {
                name: contract.name.clone(),
                address: contract.address.clone(),
            };
            if !contracts.contains(&entry) {
                contracts.push(entry);
            }
        }
        Output::Loaded {
            steps: self.state.step_count(),
            contracts,
        }
    }

    /// Where the session is now, as the first stop.
    #[must_use]
    pub fn initial_stop(&self) -> Vec<Output> {
        match self.stop(StopReason::Initial) {
            Some(stop) => vec![Output::Stop(stop)],
            None => vec![message(Level::Warning, "No trace loaded.")],
        }
    }

    /// Runs one command and answers it.
    pub fn execute(&mut self, command: DebuggerCommand) -> Vec<Output> {
        match command {
            DebuggerCommand::Empty => Vec::new(),
            DebuggerCommand::Quit => vec![message(Level::Info, "Exiting debugger."), Output::Quit],
            DebuggerCommand::Tui => vec![Output::Tui],
            DebuggerCommand::Help(topic) => vec![Self::help(topic.as_deref())],
            DebuggerCommand::Mode(None) => vec![message(
                Level::Info,
                format!("Mode: {}", self.state.display_mode.as_str()),
            )],
            DebuggerCommand::Info(DebuggerInfoCommand::Resources { json }) => {
                vec![self.resources(json)]
            }
            DebuggerCommand::Info(DebuggerInfoCommand::Breakpoints) => vec![self.breakpoints()],
            DebuggerCommand::Info(DebuggerInfoCommand::Storage) => vec![self.storage()],
            DebuggerCommand::Vars => vec![self.variables(None)],
            DebuggerCommand::Print(name) => {
                let name = name.trim();
                if name.is_empty() {
                    vec![message(Level::Warning, "Usage: print <variable>")]
                } else {
                    vec![self.variables(Some(name))]
                }
            }
            DebuggerCommand::Backtrace => vec![self.backtrace()],
            DebuggerCommand::List => vec![self.listing(LISTING_RADIUS)],
            DebuggerCommand::Memory { offset, length } => vec![self.memory(offset, length)],
            DebuggerCommand::Calldata => vec![self.calldata()],
            DebuggerCommand::Stack { limit } => vec![self.stack(limit)],
            DebuggerCommand::Unknown(text) => vec![message(
                Level::Warning,
                format!("Unknown command: {text}; type `help` for the list"),
            )],
            command => {
                let mut outputs = match self.state.apply_command(command) {
                    Some(outcome) => self.outcome(outcome),
                    None => Vec::new(),
                };
                if let Some(note) = self.state.take_note() {
                    match outputs.last_mut() {
                        Some(Output::Stop(stop)) => stop.note = Some(note),
                        _ => outputs.push(Output::Message {
                            level: Level::Note,
                            text: note,
                            note: None,
                        }),
                    }
                }
                outputs
            }
        }
    }

    /// What a movement or breakpoint command did.
    fn outcome(&self, outcome: StepOutcome) -> Vec<Output> {
        let stop = |reason: StopReason| -> Vec<Output> {
            match self.stop(reason) {
                Some(stop) => vec![Output::Stop(stop)],
                None => vec![message(Level::Warning, "No trace loaded.")],
            }
        };
        match outcome {
            StepOutcome::NoTrace => vec![message(Level::Warning, "No trace loaded.")],
            StepOutcome::Moved { .. } => stop(StopReason::Moved),
            StepOutcome::BreakpointHit { breakpoint, .. } => stop(StopReason::Breakpoint {
                id: breakpoint.id,
                label: breakpoint.label(),
            }),
            StepOutcome::AtEnd { .. } => stop(StopReason::End),
            StepOutcome::AtStart { .. } => stop(StopReason::Start),
            StepOutcome::InvalidStep {
                requested,
                max_step,
            } => vec![message(
                Level::Warning,
                match max_step {
                    Some(max_step) => format!("Invalid step {requested}; max step is {max_step}"),
                    None => format!("Invalid step {requested}; trace is empty"),
                },
            )],
            StepOutcome::ModeChanged(mode) => {
                vec![message(Level::Info, format!("Mode: {}", mode.as_str()))]
            }
            StepOutcome::BreakpointSet(breakpoint) => vec![Output::Breakpoint {
                event: BreakpointEvent::Set,
                id: breakpoint.id,
                label: breakpoint.label(),
            }],
            StepOutcome::BreakpointCleared(breakpoint) => vec![Output::Breakpoint {
                event: BreakpointEvent::Cleared,
                id: breakpoint.id,
                label: breakpoint.label(),
            }],
            StepOutcome::BreakpointMissing(label) => vec![message(
                Level::Warning,
                format!("No breakpoint set at {label}"),
            )],
            StepOutcome::BreakpointError(text) => vec![message(
                Level::Warning,
                format!("Could not set breakpoint: {text}"),
            )],
        }
    }

    /// The current step as a stop, or `None` without a trace.
    #[must_use]
    pub fn stop(&self, reason: StopReason) -> Option<Stop> {
        let step = self.state.current_step_data()?;
        let location = self.state.location().map(|location| StopLocation {
            text: self
                .state
                .step_map()
                .and_then(|map| map.contracts().get(location.key.contract))
                .and_then(|contract| contract.line_text(location.key.source_id, location.line))
                .map(str::to_owned),
            path: location.path,
            line: location.line,
            function: location.function_name,
            generated: location.generated,
        });
        let address = self
            .state
            .step_map()
            .and_then(|map| map.executing_address(self.state.current_step))
            .map(str::to_owned);
        let stack = (self.state.display_mode == DisplayMode::Assembly).then(|| {
            step.snapshot_ref()
                .stack
                .iter()
                .rev()
                .map(|word| word.to_string())
                .collect()
        });
        Some(Stop {
            reason,
            step: self.state.current_step,
            last_step: self.state.step_count().saturating_sub(1),
            pc: step.pc,
            op: step.op.to_string(),
            gas: step.gas,
            location,
            address,
            has_source: self.state.has_source(),
            stack,
            note: None,
        })
    }

    #[must_use]
    pub fn breakpoints(&self) -> Output {
        Output::Breakpoints {
            breakpoints: self
                .state
                .breakpoints()
                .iter()
                .map(|breakpoint| BreakpointInfo {
                    id: breakpoint.id,
                    label: breakpoint.label(),
                })
                .collect(),
        }
    }

    /// The call structure at the current step, innermost frame first.
    pub fn backtrace(&mut self) -> Output {
        let frames = self.state.frames();
        if frames.is_empty() {
            return message(Level::Warning, "No trace loaded.");
        }
        let show_warning =
            !self.arguments_warning_shown && frames.iter().any(|frame| !frame.arguments.is_empty());
        let (warning, note) = if show_warning {
            self.arguments_warning_shown = true;
            (
                Some(FRAME_ARGUMENTS_WARNING.to_owned()),
                Some(FRAME_ARGUMENTS_NOTE.to_owned()),
            )
        } else {
            (None, None)
        };
        let frames = frames
            .iter()
            .enumerate()
            .map(|(index, frame)| FrameInfo {
                index,
                name: frame
                    .function_name
                    .clone()
                    .or_else(|| frame.contract_name.clone())
                    .or_else(|| frame.address.clone())
                    .unwrap_or_else(|| "<unknown>".to_owned()),
                arguments: frame
                    .arguments
                    .iter()
                    .map(|argument| ArgumentInfo {
                        name: argument.name.clone(),
                        value: argument.value.display.clone(),
                    })
                    .collect(),
                location: frame
                    .location
                    .as_ref()
                    .map(|location| format!("{}:{}", location.path, location.line)),
                address: (frame.external && frame.function_name.is_some())
                    .then(|| frame.address.clone())
                    .flatten(),
                step: frame.step,
                pc: frame.pc,
            })
            .collect();
        Output::Backtrace {
            warning,
            note,
            frames,
        }
    }

    /// `radius` lines of source on each side of the current step's line.
    #[must_use]
    pub fn listing(&self, radius: u64) -> Output {
        let Some(listing) = self.state.source_listing(radius) else {
            return if self.state.has_source() {
                message(Level::Warning, "No source for this step.")
            } else {
                message(
                    Level::Warning,
                    "Cannot list source: no ETHDebug metadata is loaded; start the session with \
                     `--ethdebug-dir <address>:<contract>:<dir>`",
                )
            };
        };
        Output::Listing {
            path: listing.path,
            current_line: listing.current_line,
            lines: listing
                .lines
                .into_iter()
                .map(|(line, text)| ListedLine {
                    line,
                    text,
                    current: line == listing.current_line,
                })
                .collect(),
        }
    }

    /// Memory at the current step in 32-byte words, the whole of it or one range.
    #[must_use]
    pub fn memory(&self, offset: Option<u64>, length: Option<u64>) -> Output {
        let Some(step) = self.state.current_step_data() else {
            return message(Level::Warning, "No trace loaded.");
        };
        let Some(memory) = step.snapshot_ref().memory else {
            let captured = self
                .state
                .trace()
                .is_some_and(|trace| trace.capabilities.memory);
            return if captured {
                message(Level::Info, "Memory is empty at this step.")
            } else {
                message(Level::Warning, "Memory was not captured by this backend.")
            };
        };
        let hex = memory.trim_start_matches("0x");
        if hex.is_empty() {
            return message(Level::Info, "Memory is empty at this step.");
        }
        if !hex.is_ascii() {
            return message(Level::Info, format!("Memory: {hex}"));
        }
        let total = hex.len() / 2;
        let start = usize::try_from(offset.unwrap_or(0)).unwrap_or(usize::MAX);
        if start >= total {
            return message(
                Level::Warning,
                format!("Nothing to show: memory is {total} bytes; offset {start} is past the end"),
            );
        }
        let end = length
            .and_then(|length| usize::try_from(length).ok())
            .and_then(|length| start.checked_add(length))
            .map_or(total, |end| end.min(total));
        let bytes = hex.as_bytes();
        let mut words = Vec::new();
        let mut word_start = start;
        while word_start < end {
            let word_end = word_start.saturating_add(32).min(end);
            words.push(MemoryWord {
                offset: word_start,
                hex: std::str::from_utf8(&bytes[word_start * 2..word_end * 2])
                    .unwrap_or("")
                    .to_owned(),
            });
            word_start = word_end;
        }
        Output::Memory(MemoryInfo {
            total,
            start,
            end,
            words,
        })
    }

    /// Every slot whose value is known at the current step: what the transaction has read
    /// or written so far in this frame's storage.
    #[must_use]
    pub fn storage(&self) -> Output {
        let Some(step) = self.state.current_step_data() else {
            return message(Level::Warning, "No trace loaded.");
        };
        let captured = self
            .state
            .trace()
            .is_some_and(|trace| trace.capabilities.storage);
        if !captured {
            return message(
                Level::Warning,
                "Storage was not captured by this backend; no per-step storage was recorded.",
            );
        }
        let known = self
            .state
            .storage_words()
            .map(|words| words.known())
            .unwrap_or_default();
        // The slots this step itself changed, so a stop at an `SSTORE` shows what moved.
        let changed = step.snapshot_ref().storage_diff;
        let slots = known
            .into_iter()
            .map(|(slot, value)| {
                let slot = soldb_debugger::short_hex(&slot);
                let was = changed
                    .iter()
                    .find(|(candidate, _)| normalize_storage_slot(candidate) == slot)
                    .map(|(_, change)| change.before.clone().unwrap_or_else(|| "0x0".to_owned()));
                SlotInfo {
                    slot,
                    value: soldb_debugger::short_hex(&value),
                    was,
                }
            })
            .collect();
        Output::Storage {
            address: self.state.storage_address().map(str::to_owned),
            slots,
        }
    }

    #[must_use]
    pub fn calldata(&self) -> Output {
        if self.state.trace().is_none() {
            return message(Level::Warning, "No trace loaded.");
        }
        match self.state.calldata() {
            Some(data) => Output::Calldata {
                bytes: data.trim_start_matches("0x").len() / 2,
                data,
            },
            None => message(
                Level::Warning,
                "Calldata for this frame was not recorded by the backend; only the root frame's \
                 is known.",
            ),
        }
    }

    /// The stack at the current step, all of it or the top `limit` words.
    #[must_use]
    pub fn stack(&self, limit: Option<usize>) -> Output {
        let Some(step) = self.state.current_step_data() else {
            return message(Level::Warning, "No trace loaded.");
        };
        let words = step
            .snapshot_ref()
            .stack
            .iter()
            .map(|word| word.to_string())
            .collect::<Vec<_>>();
        let shown = limit.map_or(words.len(), |limit| limit.min(words.len()));
        Output::Stack { words, shown }
    }

    /// The variables in scope at the current step, or the one named by `filter`, which
    /// may be a path into a local or a state variable.
    pub fn variables(&mut self, filter: Option<&str>) -> Output {
        let Some(step) = self.state.current_step_data() else {
            return message(Level::Warning, "Cannot read variables: no trace is loaded");
        };
        let pc = step.pc;
        // No contract sources loaded at all: the same "load debug info" answer `list`
        // gives, rather than a per-step "no variables here".
        let no_metadata = self.state.step_map().is_none_or(|map| {
            map.contracts()
                .iter()
                .all(|c| c.info.instructions.is_empty())
        });
        if no_metadata {
            return message(
                Level::Warning,
                "Cannot read variables: no ETHDebug metadata is loaded; start the session with \
                 `--ethdebug-dir <address>:<contract>:<dir>`",
            );
        }
        let variables = self.state.variables();
        let warning = match &variables {
            Ok(step_variables)
                if step_variables.origin == VariablesOrigin::Inferred
                    && !self.locals_warning_shown =>
            {
                self.locals_warning_shown = true;
                Some(INFERRED_LOCALS_WARNING.to_owned())
            }
            _ => None,
        };
        let (locals, unavailable) = match variables {
            Ok(step_variables) => (step_variables.variables, None),
            Err(reason) => (Vec::new(), Some(reason)),
        };
        let words = self.storage_words();
        let layout = self.state.storage_layout();
        let chain_label = words.as_ref().and_then(StorageWords::chain_label);

        if let Some(name) = filter {
            if let Some(variable) = locals.iter().find(|variable| variable.name == name) {
                return Output::Variable {
                    warning,
                    variable: local_info(variable),
                };
            }
            // A path through a local: `item.tags[1]`, `stored.owners[0xabc]`, `blob.length`.
            match self.state.local_path(name) {
                Some(Ok(variable)) => {
                    return Output::Variable {
                        warning,
                        variable: local_info(&variable),
                    }
                }
                Some(Err(reason)) => {
                    return message(Level::Warning, format!("Cannot read variable: {reason}"))
                }
                None => {}
            }
            let (Some(layout), Some(words)) = (layout, words.as_ref()) else {
                return message(
                    Level::Warning,
                    format!(
                        "No such variable: `{name}` is not in scope at PC {pc}; state variables \
                         need a storage layout, compile with `--storage-layout`"
                    ),
                );
            };
            return match state_value(layout, words, name) {
                Ok(variable) => Output::Variable {
                    warning,
                    variable: state_info(&variable, chain_label),
                },
                Err(error) => Output::Message {
                    level: Level::Warning,
                    text: format!("No such variable: `{name}` is not in scope at PC {pc}; {error}"),
                    note: unavailable.map(|reason| {
                        format!(
                            "locals are unavailable here: {reason}, so a local of that name \
                             cannot be looked up"
                        )
                    }),
                },
            };
        }

        let state = match (layout, words.as_ref()) {
            (Some(layout), _) if layout.variables.is_empty() => StateInfo::None,
            (Some(layout), Some(words)) => StateInfo::Variables {
                variables: state_variables(layout, words)
                    .iter()
                    .map(|variable| state_info(variable, chain_label))
                    .collect(),
            },
            (Some(_), None) => StateInfo::NoStorage,
            (None, _) => StateInfo::NoLayout,
        };
        Output::Variables {
            warning,
            pc,
            locals: locals.iter().map(local_info).collect(),
            unavailable,
            state,
        }
    }

    /// The contracts whose debug resources are loaded.
    #[must_use]
    pub fn resources(&self, json: bool) -> Output {
        let contracts = self
            .state
            .step_map()
            .map_or(&[][..], |map| map.contracts())
            .iter()
            .filter(|contract| !contract.info.instructions.is_empty())
            .map(|contract| ResourceInfo {
                name: contract.name.clone(),
                address: contract.address.clone(),
                environment: contract.info.environment.clone(),
                sources: contract.info.sources.values().cloned().collect(),
            })
            .collect();
        Output::Resources { contracts, json }
    }

    /// The command list, or one command's details.
    #[must_use]
    pub fn help(topic: Option<&str>) -> Output {
        let lines = match topic.map(str::trim).filter(|topic| !topic.is_empty()) {
            Some(topic) => match command_spec(topic) {
                Some(spec) => {
                    let mut lines = vec![format!("{}  {}", spec.usage, spec.summary)];
                    if !spec.aliases.is_empty() {
                        lines.push(format!("aliases: {}", spec.aliases.join(", ")));
                    }
                    lines.extend(spec.details.iter().map(|line| (*line).to_owned()));
                    lines
                }
                None => vec![format!("No help for `{topic}`; type `help` for the list")],
            },
            None => {
                let width = COMMANDS
                    .iter()
                    .map(|spec| spec.usage.len())
                    .max()
                    .unwrap_or(0);
                let mut lines = Vec::new();
                for group in CommandGroup::ALL {
                    lines.push(format!("{}:", group.title()));
                    for spec in COMMANDS.iter().filter(|spec| spec.group == group) {
                        lines.push(format!(
                            "  {:<width$}  {}",
                            spec.usage,
                            spec.summary,
                            width = width
                        ));
                    }
                }
                lines.push("Aliases: n s ni fin c | rn rs rni rfin rc | b d i | bt l mem | p | h q; `help <command>` says more.".to_owned());
                lines
            }
        };
        Output::Help { lines }
    }
}

fn message(level: Level, text: impl Into<String>) -> Output {
    Output::Message {
        level,
        text: text.into(),
        note: None,
    }
}

fn status(status: DebugValueStatus) -> ValueStatus {
    match status {
        DebugValueStatus::Decoded => ValueStatus::Decoded,
        DebugValueStatus::Raw => ValueStatus::Raw,
        DebugValueStatus::Unavailable => ValueStatus::Unavailable,
    }
}

/// A local, parameter, or return value with the stack slot it was read from, or without
/// one when it could not be read.
fn local_info(variable: &DebugVariable) -> VariableInfo {
    VariableInfo {
        name: variable.name.clone(),
        ty: variable.ty.clone(),
        value: variable.value.display.clone(),
        raw: variable.value.raw.clone(),
        status: status(variable.value.status),
        place: (variable.value.status != DebugValueStatus::Unavailable)
            .then(|| format!("{}+{}", variable.location.kind, variable.location.offset)),
    }
}

fn state_info(variable: &StateVariable, chain_label: Option<&str>) -> VariableInfo {
    let mut place = if variable.offset == 0 {
        format!("slot {}", variable.slot)
    } else {
        format!("slot {} + {}", variable.slot, variable.offset)
    };
    if variable.source == StateSource::Chain {
        place.push_str(&format!(", from {}", chain_label.unwrap_or("the chain")));
    }
    VariableInfo {
        name: variable.name.clone(),
        ty: variable.ty.clone(),
        value: variable.value.display.clone(),
        raw: variable.value.raw.clone(),
        status: status(variable.value.status),
        place: Some(place),
    }
}

/// A recorded slot the way `storage` prints it: `0x`-prefixed, no leading zeros.
fn normalize_storage_slot(slot: &str) -> String {
    let digits = slot.trim_start_matches("0x").trim_start_matches('0');
    if digits.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{}", digits.to_ascii_lowercase())
    }
}

/// Whether a breakpoint stops on a source line, for a view that marks lines.
#[must_use]
pub fn breakpoint_lines(state: &DebuggerState) -> Vec<(String, u64)> {
    state
        .breakpoints()
        .iter()
        .flat_map(|breakpoint| match &breakpoint.kind {
            BreakpointKind::Line(lines) => lines
                .iter()
                .map(|line| (line.path.clone(), line.key.line))
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}
