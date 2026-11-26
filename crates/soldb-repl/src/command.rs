//! The command language of the debugger: what a typed line means.
//!
//! One table, [`COMMANDS`], describes every command once — its name, its aliases, its
//! usage, and its help — and both the parser and `help` are built from it, so the two
//! cannot drift apart. Parsing never fails loudly: a line that is not a command becomes
//! [`DebuggerCommand::Unknown`], which the session answers with a message, the way a
//! shell does.

use soldb_debugger::FormatterCommand;

use crate::{BreakpointTarget, DisplayMode, SourceBreakpointTarget};

/// A command as typed, with its arguments parsed.
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
    /// List every variable in scope at the current step, and the state variables.
    Vars,
    /// Print one variable, or a path into one, at the current step.
    ///
    /// An empty name means the user typed `print` with no argument; the session reports
    /// the usage rather than treating it as an unknown command.
    Print(String),
    /// `print/<format> <path>`: one variable with every number in it written in a
    /// format, as typed, such as `x` or `decimals:6`.
    PrintAs {
        format: String,
        path: String,
    },
    /// A `type format` or `type summary` command, or why the line is not one.
    Type(Result<FormatterCommand, String>),
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
    /// The return data buffer at the current step.
    ReturnData,
    /// The stack at the current step, all of it or the top `limit` words.
    Stack {
        limit: Option<usize>,
    },
    Mode(Option<DisplayMode>),
    /// Set a breakpoint, optionally one that stops only when a condition holds.
    Break(BreakpointTarget, Option<String>),
    Clear(BreakpointTarget),
    /// Remove a breakpoint by number.
    Delete(u32),
    Help(Option<String>),
    /// Open the full-screen view.
    Tui,
    Quit,
    Empty,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerInfoCommand {
    Resources { json: bool },
    Breakpoints,
    Storage,
    TransientStorage,
}

/// What a command is for, which is how `help` groups them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandGroup {
    Stepping,
    Reverse,
    Breakpoints,
    Inspection,
    Variables,
    Session,
}

impl CommandGroup {
    /// Every group, in the order `help` lists them.
    pub const ALL: [Self; 6] = [
        Self::Stepping,
        Self::Reverse,
        Self::Breakpoints,
        Self::Inspection,
        Self::Variables,
        Self::Session,
    ];

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Stepping => "Stepping",
            Self::Reverse => "Reverse",
            Self::Breakpoints => "Breakpoints",
            Self::Inspection => "Inspection",
            Self::Variables => "Variables",
            Self::Session => "Session",
        }
    }
}

/// One command's description: what `help` prints, and what the parser answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    /// The command with its arguments, as typed.
    pub usage: &'static str,
    /// One line saying what it does.
    pub summary: &'static str,
    /// Further lines `help <command>` prints.
    pub details: &'static [&'static str],
    pub group: CommandGroup,
}

impl CommandSpec {
    /// The name followed by its aliases in parentheses, as `help` lists it.
    #[must_use]
    pub fn names(&self) -> String {
        if self.aliases.is_empty() {
            self.name.to_owned()
        } else {
            format!("{} ({})", self.name, self.aliases.join(", "))
        }
    }

    fn answers_to(&self, word: &str) -> bool {
        self.name == word || self.aliases.contains(&word)
    }
}

/// Every command, in the order `help` lists them.
pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "next",
        aliases: &["n"],
        usage: "next",
        summary: "run to the next source line, stepping over calls",
        details: &["Without debug info, moves one instruction."],
        group: CommandGroup::Stepping,
    },
    CommandSpec {
        name: "step",
        aliases: &["s"],
        usage: "step",
        summary: "run to the next source line, entering calls",
        details: &["Without debug info, moves one instruction."],
        group: CommandGroup::Stepping,
    },
    CommandSpec {
        name: "nexti",
        aliases: &["ni", "stepi", "si"],
        usage: "nexti",
        summary: "execute one EVM instruction",
        details: &[],
        group: CommandGroup::Stepping,
    },
    CommandSpec {
        name: "finish",
        aliases: &["fin"],
        usage: "finish",
        summary: "run until the current frame returns",
        details: &[],
        group: CommandGroup::Stepping,
    },
    CommandSpec {
        name: "continue",
        aliases: &["c"],
        usage: "continue",
        summary: "run to the next breakpoint, or the end of the trace",
        details: &[],
        group: CommandGroup::Stepping,
    },
    CommandSpec {
        name: "goto",
        aliases: &[],
        usage: "goto <step>",
        summary: "jump to a step of the recording",
        details: &[],
        group: CommandGroup::Stepping,
    },
    CommandSpec {
        name: "reverse-next",
        aliases: &["rn", "rnext"],
        usage: "reverse-next",
        summary: "back to the previous source line, stepping over calls",
        details: &[],
        group: CommandGroup::Reverse,
    },
    CommandSpec {
        name: "reverse-step",
        aliases: &["rs", "rstep"],
        usage: "reverse-step",
        summary: "back to the previous source line, entering calls",
        details: &[],
        group: CommandGroup::Reverse,
    },
    CommandSpec {
        name: "reverse-nexti",
        aliases: &["rni", "back", "rnexti", "reverse-stepi", "rsi"],
        usage: "reverse-nexti",
        summary: "back one EVM instruction",
        details: &[],
        group: CommandGroup::Reverse,
    },
    CommandSpec {
        name: "reverse-finish",
        aliases: &["rfin", "rfinish"],
        usage: "reverse-finish",
        summary: "back to the step that entered the current frame",
        details: &[],
        group: CommandGroup::Reverse,
    },
    CommandSpec {
        name: "reverse-continue",
        aliases: &["rc", "rcontinue"],
        usage: "reverse-continue",
        summary: "back to the previous breakpoint, or the start of the trace",
        details: &[],
        group: CommandGroup::Reverse,
    },
    CommandSpec {
        name: "break",
        aliases: &["b"],
        usage: "break <target> [if <condition>]",
        summary: "stop at a place, or there only when a condition holds",
        details: &[
            "Targets:",
            "  <pc>                        a program counter",
            "  <file>:<line>, line <line>  entering a source line",
            "  <function>, <Contract>.<f>  entering a function",
            "  <state variable>            a write to it: counter, balances[0xabc], config.limit",
            "  storage <slot>              an SSTORE to a slot",
            "  revert                      a REVERT, or a failing step",
            "  call [<address>]            a call, to one address or to any",
            "  op <OPCODE>                 every execution of an opcode",
            "A condition compares locals and paths into them (item.tags[1]), state variables,",
            "the frame's arguments, enum literals (Color.Blue), and pc, gas, depth, op, step,",
            "with == != < <= > >=, joined with && and ||:",
            "  break Shop.sol:40 if price > 10 && item.color == Color.Blue",
        ],
        group: CommandGroup::Breakpoints,
    },
    CommandSpec {
        name: "clear",
        aliases: &[],
        usage: "clear <target>",
        summary: "remove the breakpoint set with that target",
        details: &[],
        group: CommandGroup::Breakpoints,
    },
    CommandSpec {
        name: "delete",
        aliases: &["d"],
        usage: "delete <n>",
        summary: "remove breakpoint number n",
        details: &[],
        group: CommandGroup::Breakpoints,
    },
    CommandSpec {
        name: "info",
        aliases: &["i"],
        usage: "info breakpoints|storage|transient|resources",
        summary: "the breakpoints, the storage or transient storage known here, or the loaded debug resources",
        details: &[
            "info breakpoints (i b)   every breakpoint with its number",
            "info storage             every storage slot known at this step",
            "info transient           every transient storage slot known at this step",
            "info resources [--json]  the contracts whose sources are loaded, as text or JSON",
        ],
        group: CommandGroup::Breakpoints,
    },
    CommandSpec {
        name: "backtrace",
        aliases: &["bt", "where"],
        usage: "backtrace",
        summary: "the call frames at the current step, innermost first",
        details: &[
            "Each frame names its function, or the contract or address executing, where it",
            "is, and the step and program counter it sits at. A frame entered at its function's",
            "entry point shows the arguments it was entered with.",
        ],
        group: CommandGroup::Inspection,
    },
    CommandSpec {
        name: "list",
        aliases: &["l"],
        usage: "list",
        summary: "the source around the current step",
        details: &[],
        group: CommandGroup::Inspection,
    },
    CommandSpec {
        name: "stack",
        aliases: &[],
        usage: "stack [<n>]",
        summary: "the EVM stack at the current step, top first, all of it or the top n words",
        details: &[
            "Each word is shown with its index from the bottom of the stack, which is the",
            "index `vars` reports a variable's slot as.",
        ],
        group: CommandGroup::Inspection,
    },
    CommandSpec {
        name: "memory",
        aliases: &["mem"],
        usage: "memory [<offset> [<length>]]",
        summary: "memory at the current step, in 32-byte words",
        details: &[],
        group: CommandGroup::Inspection,
    },
    CommandSpec {
        name: "storage",
        aliases: &[],
        usage: "storage",
        summary: "every storage slot known at the current step",
        details: &["The same as `info storage`."],
        group: CommandGroup::Inspection,
    },
    CommandSpec {
        name: "transient",
        aliases: &[],
        usage: "transient",
        summary: "every transient storage slot known at the current step",
        details: &[
            "The slots `TLOAD` and `TSTORE` touched so far in this frame's account, read",
            "from the trace. A slot not listed is zero: transient storage starts empty in",
            "every transaction. The same as `info transient`.",
        ],
        group: CommandGroup::Inspection,
    },
    CommandSpec {
        name: "calldata",
        aliases: &[],
        usage: "calldata",
        summary: "the calldata of the current frame",
        details: &[],
        group: CommandGroup::Inspection,
    },
    CommandSpec {
        name: "returndata",
        aliases: &[],
        usage: "returndata",
        summary: "the return data buffer at the current step",
        details: &[
            "What the frame's last call or create returned or reverted with, which",
            "`RETURNDATASIZE` and `RETURNDATACOPY` read. Empty until the frame makes a call.",
        ],
        group: CommandGroup::Inspection,
    },
    CommandSpec {
        name: "vars",
        aliases: &["locals"],
        usage: "vars",
        summary: "the variables in scope at the current step, and every state variable",
        details: &[
            "Locals come from the artifact's ETHDebug variable locations when it carries any.",
            "For solc's legacy pipeline they are read off the stack through the fixed layout",
            "its code generator keeps, which the first `vars` of a session says: values can",
            "be wrong under the optimizer inside one basic block, and a frame that could not",
            "be placed, or a function the optimizer inlined, shows as unavailable. State",
            "variables are read through the storage layout of `solc --storage-layout`.",
        ],
        group: CommandGroup::Variables,
    },
    CommandSpec {
        name: "print",
        aliases: &["p"],
        usage: "print[/<format>] <path>",
        summary: "one variable, or a path into one: item.tags[1], balances[0xabc], stored.owner",
        details: &[
            "A path follows struct members, array elements, mapping entries, and `length`",
            "from a local or a state variable, in any chain.",
            "With a format, every number in the value is written in it, whatever `type format`",
            "set: p/x slot, p/decimals:6 amount, p/timestamp deadline. See `help type`.",
        ],
        group: CommandGroup::Variables,
    },
    CommandSpec {
        name: "type",
        aliases: &[],
        usage: "type format|summary <subcommand>",
        summary: "choose how values are shown: token decimals, hex, dates, one-line summaries",
        details: &[
            "type format add -f <format> [<type>...] [--var <name>]... [--all] [--contract <name>]",
            "type summary add -s <template> [<type>...] [--var <name>]... [--all] [--contract <name>]",
            "type format|summary list | delete <n> | clear",
            "A rule applies to values of the types named (uint256, UD60x18, Pool.Position) and",
            "to values shown under the names given: a variable, a struct member, or a mapping",
            "or array whose entries it is. Names and types take * and ? wildcards, and --all",
            "is every name. With --contract, only in that contract's code. The rule added last",
            "wins, so a narrower rule after a broad one makes the exceptions to it.",
            "Formats: decimal (d), hex (x), binary (t), decimals:<n>, decimals:@<state variable>,",
            "  ether and wad (decimals:18), gwei (decimals:9), ray (decimals:27), bps, q<bits>,",
            "  timestamp, duration, string (s), default.",
            "A summary is a template: ${var} is the value, ${var.member} or ${member} a part of",
            "it, and %<format> writes a part in a format: \"${var.amount%decimals:6} USDC\".",
            "  type format add -f decimals:6 --var balances --var totalSupply --contract USDC",
            "  type format add -f decimals:@decimals --var amount --var value",
            "  type summary add -s \"${liquidity%wad} in [${tickLower}, ${tickUpper}]\" Position",
            "Put these in .soldbinit to have them in every session.",
        ],
        group: CommandGroup::Variables,
    },
    CommandSpec {
        name: "mode",
        aliases: &[],
        usage: "mode [source|asm]",
        summary: "show or switch what a stop prints: the source line, or the stack",
        details: &[],
        group: CommandGroup::Session,
    },
    CommandSpec {
        name: "tui",
        aliases: &[],
        usage: "tui",
        summary: "open the full-screen view; q returns to this prompt",
        details: &[],
        group: CommandGroup::Session,
    },
    CommandSpec {
        name: "help",
        aliases: &["h", "?"],
        usage: "help [<command>]",
        summary: "this list, or one command's details",
        details: &[],
        group: CommandGroup::Session,
    },
    CommandSpec {
        name: "quit",
        aliases: &["q", "exit"],
        usage: "quit",
        summary: "leave the debugger",
        details: &[],
        group: CommandGroup::Session,
    },
];

/// The command a word names, by name or alias.
#[must_use]
pub fn command_spec(word: &str) -> Option<&'static CommandSpec> {
    let word = word.trim().to_ascii_lowercase();
    COMMANDS.iter().find(|spec| spec.answers_to(&word))
}

impl DebuggerCommand {
    /// Parses one typed line.
    #[must_use]
    pub fn parse(line: &str) -> Self {
        let line = line.trim();
        if line.is_empty() {
            return Self::Empty;
        }
        let mut parts = line.split_whitespace();
        let word = parts.next().unwrap_or_default();
        let rest = parts.collect::<Vec<_>>().join(" ");
        if let Some((name, format)) = word.split_once('/') {
            return match command_spec(name) {
                Some(spec) if spec.name == "print" && !format.is_empty() => Self::PrintAs {
                    format: format.to_owned(),
                    path: rest,
                },
                _ => Self::Unknown(line.to_owned()),
            };
        }
        let Some(spec) = command_spec(word) else {
            return Self::Unknown(line.to_owned());
        };
        let unknown = || Self::Unknown(line.to_owned());
        match spec.name {
            "next" => Self::Next,
            "nexti" => Self::NextInstruction,
            "step" => Self::Step,
            "continue" => Self::Continue,
            "finish" => Self::Finish,
            "reverse-next" => Self::ReverseNext,
            "reverse-nexti" => Self::ReverseNextInstruction,
            "reverse-step" => Self::ReverseStep,
            "reverse-continue" => Self::ReverseContinue,
            "reverse-finish" => Self::ReverseFinish,
            "goto" => rest.parse::<usize>().map_or_else(|_| unknown(), Self::Goto),
            "vars" => Self::Vars,
            "print" => Self::Print(rest),
            "backtrace" => Self::Backtrace,
            "list" => Self::List,
            "memory" => parse_memory_command(&rest).unwrap_or_else(unknown),
            "calldata" => Self::Calldata,
            "returndata" => Self::ReturnData,
            "stack" => {
                if rest.is_empty() {
                    Self::Stack { limit: None }
                } else {
                    rest.parse::<usize>()
                        .map_or_else(|_| unknown(), |limit| Self::Stack { limit: Some(limit) })
                }
            }
            "storage" => Self::Info(DebuggerInfoCommand::Storage),
            "transient" => Self::Info(DebuggerInfoCommand::TransientStorage),
            "info" => parse_info_command(&rest).map_or_else(unknown, Self::Info),
            "mode" => Self::Mode(
                (!rest.is_empty())
                    .then(|| DisplayMode::parse(&rest))
                    .flatten(),
            ),
            "break" => {
                // `break <target> if <condition>`: the condition is everything after the
                // first ` if `, so a target containing `if` in a name still parses.
                let (target, condition) = split_condition(&rest);
                parse_breakpoint_target(target)
                    .map_or_else(unknown, |target| Self::Break(target, condition))
            }
            "clear" => parse_breakpoint_target(&rest).map_or_else(unknown, Self::Clear),
            "delete" => rest
                .trim()
                .trim_start_matches('#')
                .parse::<u32>()
                .map_or_else(|_| unknown(), Self::Delete),
            "help" => Self::Help((!rest.is_empty()).then_some(rest)),
            // The words after `type`, quotes kept: a summary template may hold spaces.
            "type" => Self::Type(FormatterCommand::parse(&line[word.len()..])),
            "tui" => Self::Tui,
            "quit" => Self::Quit,
            _ => unknown(),
        }
    }
}

fn parse_info_command(input: &str) -> Option<DebuggerInfoCommand> {
    match input.trim() {
        "resources" => Some(DebuggerInfoCommand::Resources { json: false }),
        "resources --json" | "resources json" => {
            Some(DebuggerInfoCommand::Resources { json: true })
        }
        "breakpoints" | "break" | "b" => Some(DebuggerInfoCommand::Breakpoints),
        "storage" => Some(DebuggerInfoCommand::Storage),
        "transient" => Some(DebuggerInfoCommand::TransientStorage),
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
            if is_function_name(input) {
                return Some(BreakpointTarget::Function(input.to_owned()));
            }
            // `balances[0xabc…]` and the like: a place in storage, named the way `print`
            // names it.
            is_state_path(input).then(|| BreakpointTarget::State(input.to_owned()))
        }
    }
}

/// Splits `<target> if <condition>` at the first ` if `, which cannot appear inside a
/// target: a file name, a function name, a slot, and an opcode all lack spaces.
fn split_condition(input: &str) -> (&str, Option<String>) {
    let input = input.trim();
    match input.find(" if ") {
        Some(index) => {
            let condition = input[index + 4..].trim();
            (
                input[..index].trim(),
                (!condition.is_empty()).then(|| condition.to_owned()),
            )
        }
        None => (input, None),
    }
}

/// Whether the text looks like a state variable path: a name followed by any number of
/// `[key]` and `.member` steps.
fn is_state_path(input: &str) -> bool {
    let head = input.split(['[', '.']).next().unwrap_or_default();
    !head.is_empty() && is_function_name(head) && input.len() > head.len()
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
    use soldb_debugger::FormatterKind;

    use super::{command_spec, CommandGroup, DebuggerCommand, FormatterCommand, COMMANDS};

    #[test]
    fn type_commands_parse_options_and_quoted_templates() {
        assert_eq!(
            DebuggerCommand::parse(
                "type format add -f decimals:18 uint256 --var amount -v '*Amount' --contract=Token"
            ),
            DebuggerCommand::Type(Ok(FormatterCommand::Add {
                kind: FormatterKind::Format,
                rule: "decimals:18".to_owned(),
                types: vec!["uint256".to_owned()],
                vars: vec!["amount".to_owned(), "*Amount".to_owned()],
                contract: Some("Token".to_owned()),
            }))
        );
        assert_eq!(
            DebuggerCommand::parse(r#"type summary add -s "${a}  of \"${b}\"" Pool.Position"#),
            DebuggerCommand::Type(Ok(FormatterCommand::Add {
                kind: FormatterKind::Summary,
                rule: r#"${a}  of "${b}""#.to_owned(),
                types: vec!["Pool.Position".to_owned()],
                vars: Vec::new(),
                contract: None,
            }))
        );
        assert_eq!(
            DebuggerCommand::parse("type format add -f decimals:@decimals --all --contract USDC"),
            DebuggerCommand::Type(Ok(FormatterCommand::Add {
                kind: FormatterKind::Format,
                rule: "decimals:@decimals".to_owned(),
                types: Vec::new(),
                vars: vec!["*".to_owned()],
                contract: Some("USDC".to_owned()),
            }))
        );
        assert_eq!(
            DebuggerCommand::parse("type summary list"),
            DebuggerCommand::Type(Ok(FormatterCommand::List(FormatterKind::Summary)))
        );
        assert_eq!(
            DebuggerCommand::parse("type format delete #2"),
            DebuggerCommand::Type(Ok(FormatterCommand::Delete(FormatterKind::Format, 2)))
        );
        assert_eq!(
            DebuggerCommand::parse("type format clear"),
            DebuggerCommand::Type(Ok(FormatterCommand::Clear(FormatterKind::Format)))
        );
        for (line, expected) in [
            ("type", "needs `format` or `summary`"),
            ("type filter add", "`type filter` is not a command"),
            ("type format", "needs `add`, `list`"),
            ("type format add uint256", "needs `-f <format>`"),
            ("type summary add -f hex uint256", "unknown option `-f`"),
            ("type format add -f", "`-f` needs a value"),
            ("type format delete x", "needs the number"),
            ("type summary add -s \"${var}", "is not closed"),
        ] {
            match DebuggerCommand::parse(line) {
                DebuggerCommand::Type(Err(reason)) => {
                    assert!(reason.contains(expected), "{line}: {reason}");
                }
                other => panic!("{line}: {other:?}"),
            }
        }
    }

    #[test]
    fn print_takes_a_format_after_a_slash() {
        assert_eq!(
            DebuggerCommand::parse("p/x slot"),
            DebuggerCommand::PrintAs {
                format: "x".to_owned(),
                path: "slot".to_owned()
            }
        );
        assert_eq!(
            DebuggerCommand::parse("print/decimals:6 balances[0xabc]"),
            DebuggerCommand::PrintAs {
                format: "decimals:6".to_owned(),
                path: "balances[0xabc]".to_owned()
            }
        );
        assert!(matches!(
            DebuggerCommand::parse("print/ x"),
            DebuggerCommand::Unknown(_)
        ));
        assert!(matches!(
            DebuggerCommand::parse("next/x"),
            DebuggerCommand::Unknown(_)
        ));
    }

    #[test]
    fn info_help_offers_json_only_for_resources() {
        let info = command_spec("info").expect("info is a command");
        assert!(!info.usage.contains("--json"));

        let resources = DebuggerCommand::parse("info resources --json");
        assert!(!matches!(resources, DebuggerCommand::Unknown(_)));

        let storage = DebuggerCommand::parse("info storage --json");
        assert!(matches!(storage, DebuggerCommand::Unknown(_)));
    }

    #[test]
    fn every_command_is_named_once_and_parses_by_each_alias() {
        let mut seen = Vec::new();
        for spec in COMMANDS {
            for word in std::iter::once(&spec.name).chain(spec.aliases) {
                assert!(!seen.contains(word), "`{word}` names two commands");
                seen.push(word);
                assert_eq!(command_spec(word).map(|found| found.name), Some(spec.name));
            }
            assert!(!spec.summary.is_empty());
            assert!(spec.usage.starts_with(spec.name), "{}", spec.usage);
        }
        assert_eq!(
            CommandGroup::ALL.len(),
            6,
            "every group must be listed for help"
        );
        assert_eq!(
            DebuggerCommand::parse("STACK 4"),
            DebuggerCommand::Stack { limit: Some(4) }
        );
        assert_eq!(DebuggerCommand::parse("tui"), DebuggerCommand::Tui);
        assert_eq!(DebuggerCommand::parse("?"), DebuggerCommand::Help(None));
        assert_eq!(
            DebuggerCommand::parse("help break"),
            DebuggerCommand::Help(Some("break".to_owned()))
        );
        assert_eq!(
            DebuggerCommand::parse("frobnicate"),
            DebuggerCommand::Unknown("frobnicate".to_owned())
        );
    }
}
