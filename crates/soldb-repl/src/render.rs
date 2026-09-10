//! Text for a terminal, from [`Output`].
//!
//! One line says where the debugger is: the source position, then the step, program
//! counter, opcode, and gas in parentheses, so a person reads the location first and a
//! script finds the numbers in one place. Everything is plain text unless colors are
//! asked for, and nothing is printed twice.

use std::fmt::Write as _;

use crate::response::{
    BreakpointEvent, Level, Output, StateInfo, Stop, StopReason, ValueStatus, VariableInfo,
};

/// Renders [`Output`] as lines of text.
#[derive(Debug, Clone, Copy, Default)]
pub struct Renderer {
    /// Whether to color the text with ANSI escapes.
    pub color: bool,
}

impl Renderer {
    #[must_use]
    pub const fn new(color: bool) -> Self {
        Self { color }
    }

    /// The text for one item, each line ended by a newline; empty for items that print
    /// nothing.
    #[must_use]
    pub fn render(&self, output: &Output) -> String {
        let mut text = String::new();
        for line in self.lines(output) {
            text.push_str(&line);
            text.push('\n');
        }
        text
    }

    /// The lines for one item.
    #[must_use]
    pub fn lines(&self, output: &Output) -> Vec<String> {
        match output {
            Output::Loaded { steps, contracts } => {
                let mut lines = vec![format!("Loaded trace with {} steps.", self.number(steps))];
                if contracts.is_empty() {
                    lines.push(self.dim(
                        "No sources matched the executed contracts; stepping is by instruction.",
                    ));
                } else {
                    let listed = contracts
                        .iter()
                        .map(|contract| match &contract.address {
                            Some(address) => {
                                format!("{} ({})", self.name(&contract.name), self.dim(address))
                            }
                            None => self.name(&contract.name),
                        })
                        .collect::<Vec<_>>();
                    lines.push(format!(
                        "{} {}",
                        self.info("Sources loaded for:"),
                        listed.join(", ")
                    ));
                }
                lines
            }
            Output::Stop(stop) => self.stop_lines(stop),
            Output::Message { level, text, note } => {
                let mut lines = vec![match level {
                    Level::Info => self.info_message(text),
                    Level::Warning => self.warning(text),
                    Level::Note => format!("{} {text}", self.dim("note:")),
                }];
                if let Some(note) = note {
                    lines.push(format!("{} {note}", self.dim("note:")));
                }
                lines
            }
            Output::Breakpoint { event, id, label } => vec![match event {
                BreakpointEvent::Set => format!(
                    "{} {label}",
                    self.success(format!("Breakpoint #{id} set at"))
                ),
                BreakpointEvent::Cleared => format!(
                    "{} {label}",
                    self.info(format!("Breakpoint #{id} cleared at"))
                ),
            }],
            Output::Breakpoints { breakpoints } => {
                if breakpoints.is_empty() {
                    vec![self.dim("No breakpoints set.")]
                } else {
                    breakpoints
                        .iter()
                        .map(|breakpoint| {
                            format!("#{} {}", self.number(breakpoint.id), breakpoint.label)
                        })
                        .collect()
                }
            }
            Output::Backtrace { warning, frames } => {
                let mut lines = Vec::new();
                if let Some(warning) = warning {
                    lines.push(self.warning(format!("warning: {warning}")));
                }
                for frame in frames {
                    let mut line = format!("#{:<2} {}", frame.index, self.name(&frame.name));
                    if !frame.arguments.is_empty() {
                        let arguments = frame
                            .arguments
                            .iter()
                            .map(|argument| format!("{} = {}", argument.name, argument.value))
                            .collect::<Vec<_>>()
                            .join(", ");
                        let _ = write!(line, "({arguments})");
                    }
                    if let Some(location) = &frame.location {
                        let _ = write!(line, " at {location}");
                    }
                    if let Some(address) = &frame.address {
                        let _ = write!(line, " ({})", self.address(address));
                    }
                    line.push_str(&self.dim(format!("  step {}, PC {}", frame.step, frame.pc)));
                    lines.push(line);
                }
                lines
            }
            Output::Listing {
                path,
                current_line,
                lines,
            } => {
                let mut out = vec![format!("{}:{}", self.info(path), self.number(current_line))];
                for line in lines {
                    if line.current {
                        out.push(format!(
                            "{} {}",
                            self.bold(format!("=> {:>5} |", line.line)),
                            self.bold(&line.text)
                        ));
                    } else {
                        out.push(format!(
                            "{} {}",
                            self.dim(format!("   {:>5} |", line.line)),
                            line.text
                        ));
                    }
                }
                out
            }
            Output::Stack { words, shown } => {
                if words.is_empty() {
                    return vec![self.dim("Stack: empty")];
                }
                let mut lines = vec![format!(
                    "{} {} words, top first",
                    self.info("Stack:"),
                    self.number(words.len())
                )];
                for (index, word) in words.iter().enumerate().rev().take(*shown) {
                    lines.push(format!("  [{index}] {}", self.number(word)));
                }
                if *shown < words.len() {
                    lines.push(self.dim(format!("  ... {} more below", words.len() - shown)));
                }
                lines
            }
            Output::Memory(memory) => {
                let range = if memory.start > 0 || memory.end < memory.total {
                    format!(", showing bytes {}..{}", memory.start, memory.end)
                } else {
                    String::new()
                };
                let mut lines = vec![format!(
                    "{} {} bytes{range}",
                    self.info("Memory:"),
                    self.number(memory.total)
                )];
                for word in &memory.words {
                    lines.push(format!(
                        "{} {}",
                        self.dim(format!("0x{:04x}:", word.offset)),
                        word.hex
                    ));
                }
                lines
            }
            Output::Storage { address, slots } => {
                if slots.is_empty() {
                    return vec![self.dim("Storage: no slots read or written yet.")];
                }
                let mut lines = vec![match address {
                    Some(address) => {
                        format!(
                            "{} {}",
                            self.info("Storage:"),
                            self.dim(format!("of {address}"))
                        )
                    }
                    None => self.info("Storage:"),
                }];
                for slot in slots {
                    let was = slot
                        .was
                        .as_ref()
                        .map(|was| self.dim(format!("  (was {was})")))
                        .unwrap_or_default();
                    lines.push(format!("  {} = {}{was}", slot.slot, slot.value));
                }
                lines
            }
            Output::Calldata { bytes, data } => vec![
                format!("{} {} bytes", self.info("Calldata:"), self.number(bytes)),
                data.clone(),
            ],
            Output::Variables {
                warning,
                pc,
                locals,
                unavailable,
                state,
            } => {
                let mut lines = Vec::new();
                if let Some(warning) = warning {
                    lines.push(self.warning(format!("warning: {warning}")));
                }
                if locals.is_empty() {
                    // The difference matters: locals that cannot be read here at all is
                    // not the same as none being live at this program counter.
                    lines.push(match unavailable {
                        Some(reason) => format!(
                            "{} locals are unavailable here: {reason}",
                            self.dim("Variables:")
                        ),
                        None => format!(
                            "{} no variables in scope at PC {}",
                            self.dim("Variables:"),
                            self.number(pc)
                        ),
                    });
                }
                for variable in locals {
                    lines.push(self.variable(variable));
                }
                match state {
                    StateInfo::Variables { variables } => {
                        lines.push(self.dim("State:"));
                        for variable in variables {
                            lines.push(self.variable(variable));
                        }
                    }
                    StateInfo::None => {
                        lines.push(self.dim("State: this contract declares no state variables"));
                    }
                    StateInfo::NoLayout => lines.push(self.dim(
                        "State: no storage layout loaded; compile with `--storage-layout` to \
                         read state variables",
                    )),
                    StateInfo::NoStorage => {
                        lines.push(self.dim("State: no storage was recorded for this step"));
                    }
                }
                lines
            }
            Output::Variable { warning, variable } => {
                let mut lines = Vec::new();
                if let Some(warning) = warning {
                    lines.push(self.warning(format!("warning: {warning}")));
                }
                lines.push(self.variable(variable));
                lines
            }
            Output::Resources { contracts, json } => {
                if *json {
                    let document = serde_json::json!({ "contracts": contracts });
                    return serde_json::to_string_pretty(&document)
                        .unwrap_or_default()
                        .lines()
                        .map(str::to_owned)
                        .collect();
                }
                if contracts.is_empty() {
                    return vec![self.warning("No contract sources are loaded.")];
                }
                let mut lines = Vec::new();
                for contract in contracts {
                    lines.push(format!(
                        "{} {} {}",
                        self.name(&contract.name),
                        self.dim(contract.address.as_deref().unwrap_or("<any address>")),
                        self.dim(format!("[{}]", contract.environment))
                    ));
                    for path in &contract.sources {
                        lines.push(format!("  {path}"));
                    }
                }
                lines
            }
            Output::Help { lines } => lines.clone(),
            Output::Tui | Output::Quit => Vec::new(),
        }
    }

    /// The stop: the reason when there is one, then the location line and the source
    /// line, or the stack in assembly mode.
    fn stop_lines(&self, stop: &Stop) -> Vec<String> {
        let mut lines = Vec::new();
        match &stop.reason {
            StopReason::Initial | StopReason::Moved => {}
            StopReason::Breakpoint { id, label } => lines.push(format!(
                "{} {}, {label}",
                self.success(format!("Breakpoint #{id} hit at step")),
                self.number(stop.step)
            )),
            StopReason::End => lines.push(format!(
                "{} {}",
                self.info("End of trace at step"),
                self.number(stop.step)
            )),
            StopReason::Start => lines.push(format!(
                "{} {}",
                self.info("Start of trace at step"),
                self.number(stop.step)
            )),
        }
        let status = format!(
            "step {}/{}, pc {}, {}, gas {}",
            self.number(stop.step),
            self.number(stop.last_step),
            self.number(stop.pc),
            self.opcode(&stop.op),
            self.number(stop.gas)
        );
        match &stop.location {
            Some(location) => {
                let function = location
                    .function
                    .as_deref()
                    .map(|name| format!(" in {}", self.name(name)))
                    .unwrap_or_default();
                let generated = if location.generated {
                    self.dim("  (compiler-generated code for this line)")
                } else {
                    String::new()
                };
                lines.push(format!(
                    "{}:{}{function}{generated}  {}",
                    self.info(&location.path),
                    self.number(location.line),
                    self.dim(format!("({status})"))
                ));
                if stop.stack.is_none() {
                    if let Some(text) = &location.text {
                        lines.push(format!(
                            "{} {text}",
                            self.dim(format!("{:>5} |", location.line))
                        ));
                    }
                }
            }
            None if stop.has_source => {
                let address = stop
                    .address
                    .as_deref()
                    .map(|address| format!(" in {}", self.address(address)))
                    .unwrap_or_default();
                lines.push(format!(
                    "{}  {}",
                    self.dim(format!("no source for this step{address}")),
                    self.dim(format!("({status})"))
                ));
            }
            None => lines.push(status),
        }
        if let Some(stack) = &stop.stack {
            lines.push(format!(
                "{} {}",
                self.info("Stack:"),
                self.stack_summary(stack)
            ));
        }
        if let Some(note) = &stop.note {
            lines.push(format!("{} {note}", self.dim("note:")));
        }
        lines
    }

    /// The top of the stack on one line, the words numbered from the bottom.
    fn stack_summary(&self, top_first: &[String]) -> String {
        if top_first.is_empty() {
            return self.dim("empty");
        }
        let total = top_first.len();
        let mut parts = top_first
            .iter()
            .take(4)
            .enumerate()
            .map(|(offset, word)| {
                format!(
                    "{} {}",
                    self.dim(format!("[{}]", total - 1 - offset)),
                    self.number(shorten_hex(word))
                )
            })
            .collect::<Vec<_>>();
        if total > 4 {
            parts.push(self.dim(format!("... +{} more", total - 4)));
        }
        parts.join(" ")
    }

    fn variable(&self, variable: &VariableInfo) -> String {
        let value = match variable.status {
            ValueStatus::Unavailable => self.warning(&variable.value),
            _ => self.success(&variable.value),
        };
        let place = variable
            .place
            .as_ref()
            .map(|place| self.dim(format!(" [{place}]")))
            .unwrap_or_default();
        format!(
            "{} {} = {value}{place}",
            self.info(&variable.ty),
            self.bold(&variable.name)
        )
    }

    fn info_message(&self, text: &str) -> String {
        // `Label: rest` colors the label; a bare sentence is printed as it is.
        match text.split_once(": ") {
            Some((label, rest)) if !label.contains(' ') || label.starts_with("Mode") => {
                format!("{} {rest}", self.info(format!("{label}:")))
            }
            _ => self.info(text),
        }
    }

    fn paint(&self, text: impl std::fmt::Display, code: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "1")
    }

    fn dim(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "2")
    }

    fn info(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "96")
    }

    fn success(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "92")
    }

    fn warning(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "93")
    }

    fn number(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "93")
    }

    fn opcode(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "94")
    }

    fn name(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "95")
    }

    fn address(&self, text: impl std::fmt::Display) -> String {
        self.paint(text, "95")
    }
}

/// A long hex word as its first digits: `0x1234...`.
#[must_use]
pub fn shorten_hex(value: &str) -> String {
    let Some(digits) = value.strip_prefix("0x") else {
        return value.to_owned();
    };
    if value.len() <= 10 {
        return value.to_owned();
    }
    let head = digits.chars().take(4).collect::<String>();
    format!("0x{head}...")
}

#[cfg(test)]
mod tests {
    use super::{shorten_hex, Renderer};
    use crate::response::{Level, Output, Stop, StopLocation, StopReason};

    #[test]
    fn a_stop_is_one_location_line_and_the_source_line() {
        let renderer = Renderer::new(false);
        let stop = Stop {
            reason: StopReason::Breakpoint {
                id: 1,
                label: "Counter.sol:7".to_owned(),
            },
            step: 12,
            last_step: 99,
            pc: 34,
            op: "PUSH1".to_owned(),
            gas: 5000,
            location: Some(StopLocation {
                path: "Counter.sol".to_owned(),
                line: 7,
                function: Some("increment".to_owned()),
                generated: false,
                text: Some("        count += 1;".to_owned()),
            }),
            address: None,
            has_source: true,
            stack: None,
            note: Some("something".to_owned()),
        };
        assert_eq!(
            renderer.render(&Output::Stop(stop)),
            "Breakpoint #1 hit at step 12, Counter.sol:7\n\
             Counter.sol:7 in increment  (step 12/99, pc 34, PUSH1, gas 5000)\n    \
             7 |         count += 1;\n\
             note: something\n"
        );
        let bare = Stop {
            reason: StopReason::Moved,
            step: 0,
            last_step: 3,
            pc: 0,
            op: "PUSH1".to_owned(),
            gas: 1,
            location: None,
            address: Some("0xabc".to_owned()),
            has_source: false,
            stack: Some(vec!["0x2".to_owned(), "0x1".to_owned()]),
            note: None,
        };
        assert_eq!(
            renderer.render(&Output::Stop(bare)),
            "step 0/3, pc 0, PUSH1, gas 1\nStack: [1] 0x2 [0] 0x1\n"
        );
    }

    #[test]
    fn messages_and_hex_are_plain_without_color() {
        let renderer = Renderer::new(false);
        assert_eq!(
            renderer.render(&Output::Message {
                level: Level::Warning,
                text: "Unknown command: x".to_owned(),
                note: Some("try help".to_owned()),
            }),
            "Unknown command: x\nnote: try help\n"
        );
        assert_eq!(shorten_hex("0x1234"), "0x1234");
        assert_eq!(shorten_hex("0x123456789abcdef0"), "0x1234...");
        assert_eq!(shorten_hex("plain"), "plain");
        assert!(Renderer::new(true)
            .render(&Output::Help {
                lines: vec!["x".to_owned()]
            })
            .starts_with('x'));
    }
}
