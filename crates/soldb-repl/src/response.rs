//! What a command answers with, as data.
//!
//! A session never prints. It answers each command with [`Output`] values, which a
//! frontend renders as text ([`crate::Renderer`]), as JSON (every `Output` serializes,
//! one object per item, tagged by `kind`), or into the panes of a full-screen view.
//! The same data reaches the terminal, an editor, and a script, so they cannot
//! disagree about what happened.

use serde::Serialize;

/// One item of a command's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Output {
    /// What was loaded, said once when a session starts.
    Loaded {
        steps: usize,
        /// The contracts whose sources are loaded, name and address.
        contracts: Vec<LoadedContract>,
    },
    /// Where the debugger stopped, and why.
    Stop(Stop),
    /// A one-line message, with an optional note under it.
    Message {
        level: Level,
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// A breakpoint was set or cleared.
    Breakpoint {
        event: BreakpointEvent,
        id: u32,
        label: String,
    },
    Breakpoints {
        breakpoints: Vec<BreakpointInfo>,
    },
    Backtrace {
        /// Said once a session, when frames carry arguments read off the stack.
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
        frames: Vec<FrameInfo>,
    },
    Listing {
        path: String,
        current_line: u64,
        lines: Vec<ListedLine>,
    },
    Stack {
        /// The whole stack, bottom first: index `i` is what `vars` calls `stack+i`.
        words: Vec<String>,
        /// How many words, from the top, the user asked to see.
        shown: usize,
    },
    Memory(MemoryInfo),
    Storage {
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        slots: Vec<SlotInfo>,
    },
    Calldata {
        bytes: usize,
        data: String,
    },
    /// The variables in scope, and the state variables.
    Variables {
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
        pc: u64,
        locals: Vec<VariableInfo>,
        /// Why no locals could be read, when none could.
        #[serde(skip_serializing_if = "Option::is_none")]
        unavailable: Option<String>,
        state: StateInfo,
    },
    /// One variable, from `print`.
    Variable {
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
        variable: VariableInfo,
    },
    /// The contracts whose debug resources are loaded.
    Resources {
        contracts: Vec<ResourceInfo>,
        /// Whether the user asked for JSON, so a text renderer prints it as such.
        json: bool,
    },
    Help {
        lines: Vec<String>,
    },
    /// The user asked for the full-screen view.
    Tui,
    /// The user asked to leave.
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Info,
    Warning,
    /// Something worth knowing about what a command did, said under it.
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadedContract {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// Why the debugger stopped where it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum StopReason {
    /// The session started here.
    Initial,
    /// A stepping command ended here.
    Moved,
    Breakpoint {
        id: u32,
        label: String,
    },
    /// The end of the recording.
    End,
    /// The start of the recording, reached backward.
    Start,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Stop {
    #[serde(flatten)]
    pub reason: StopReason,
    pub step: usize,
    /// The last step of the recording.
    pub last_step: usize,
    pub pc: u64,
    pub op: String,
    pub gas: u64,
    /// Where the step is in the source, when the loaded sources say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<StopLocation>,
    /// The address executing, said when there is no source for the step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Whether sources are loaded at all, so a step without one can be told from a
    /// session without any.
    pub has_source: bool,
    /// The stack, top first, when the display mode is assembly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<Vec<String>>,
    /// Something the movement turned up: a condition that could not be evaluated, a
    /// breakpoint that can never be hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StopLocation {
    pub path: String,
    pub line: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Compiler-generated code attributed to this line.
    pub generated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakpointEvent {
    Set,
    Cleared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BreakpointInfo {
    pub id: u32,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameInfo {
    pub index: usize,
    /// The function, or the contract or address executing.
    pub name: String,
    pub arguments: Vec<ArgumentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The address, for an external frame whose function is named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub step: usize,
    pub pc: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArgumentInfo {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListedLine {
    pub line: u64,
    pub text: String,
    pub current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryInfo {
    /// The size of memory at the step.
    pub total: usize,
    pub start: usize,
    pub end: usize,
    /// Each word as its offset and its hex.
    pub words: Vec<MemoryWord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryWord {
    pub offset: usize,
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlotInfo {
    pub slot: String,
    pub value: String,
    /// The value before this step changed it, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub was: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VariableInfo {
    pub name: String,
    pub ty: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    pub status: ValueStatus,
    /// Where the value was read from: `stack+2`, `slot 0x0`, `slot 0x1 + 16, from the
    /// chain at block 42`. Absent when the value could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueStatus {
    Decoded,
    Raw,
    Unavailable,
}

/// The state variables at a step, or why there are none to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StateInfo {
    Variables {
        variables: Vec<VariableInfo>,
    },
    /// The contract has a layout that declares no state variables.
    None,
    /// No storage layout is loaded for the contract.
    NoLayout,
    /// The backend recorded no storage to read them from.
    NoStorage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub environment: String,
    pub sources: Vec<String>,
}
