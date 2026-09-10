//! Source-level stepping over a recorded trace.
//!
//! A trace is a list of EVM instructions. A source-level debugger needs to know, for each
//! of them, which source line it belongs to and how deep in the call structure it runs,
//! and then answer questions such as "where does the next line start?" in both
//! directions. [`StepMap`] computes that once, in one pass over the trace, and every
//! frontend asks it the same questions, so `next` means the same thing in the terminal
//! and in an editor.
//!
//! Depth has two parts. The EVM depth changes on `CALL` and friends; the code address a
//! frame executes is read off the caller's stack at the call, which is how steps inside
//! another contract map through that contract's debug info. Inside one contract,
//! Solidity's internal calls are plain jumps, so the map keeps a virtual stack of the
//! source functions a frame passes through. A jump is a call when the artifact marks it
//! as one (legacy source maps mark calls and returns; ETHDebug's `invoke` and `return`
//! context does the same once a compiler emits it) or when it lands on a parsed
//! function's entry point, and that holds even when the function is already active, so
//! recursion and mutual recursion count. A marked return pops the frame. Otherwise the
//! function a span lands in decides: one not on the stack is entered, one on the stack
//! is returned to.
//!
//! Two habits of solc's output shape the model. Generated helpers (checked arithmetic,
//! `require` reverts, storage updates) carry the whole-contract span, the same one the
//! dispatcher has, so a step outside every function is read as generated code belonging
//! to the statement that was executing, unless no function follows it in its frame, in
//! which case it is the dispatcher finishing up and the frame's functions have returned.
//! And a lone instruction attributed to another line between two runs of one line is
//! treated as part of that line, so `next` does not stop on it.
//!
//! Everything here is a search over the recording. Nothing re-executes.

use std::collections::{BTreeMap, HashMap};

use soldb_core::{TransactionTrace, Word as StackWord};
use soldb_ethdebug::{
    function_selector, parse_path, CodeGenerator, EthdebugInfo, FunctionExit, Instruction,
    PathSegment, SourceLocation, StorageLayout,
};

use crate::condition::Value;
use crate::decode::{Place, ValueReader};
use crate::state::StorageWords;
use crate::types::SourceTypes;
use crate::{
    decode_arguments, is_value_type, parse_source_functions, readable_parameter, ArgumentLayout,
    ArgumentOrder, ByteRange, DebugLocation, DebugValue, DebugValueStatus, DebugVariable,
    FrameArgument, FrameState, SourceFunction, SourceParam,
};

/// The warning a frontend shows once when it presents inferred local variables.
pub const INFERRED_LOCALS_WARNING: &str = "local variables are inferred from the legacy source \
map and the stack layout of solc's legacy code generator, not from compiler-reported \
variable locations";

/// The note that accompanies [`INFERRED_LOCALS_WARNING`].
pub const INFERRED_LOCALS_NOTE: &str = "values can be wrong under the optimizer, and a \
variable whose frame could not be placed shows as unavailable; ETHDebug variable \
information will replace this once compilers emit it";

const CALL_OPCODES: [&str; 4] = ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"];

/// One contract's debug information, prepared for stepping: the ETHDebug metadata, the
/// source text, the functions parsed from it, and the indexes that make per-step lookups
/// constant time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractDebugInfo {
    /// The deployed address this info describes, lowercase, when known.
    pub address: Option<String>,
    pub name: String,
    pub info: EthdebugInfo,
    pub source_contents: BTreeMap<u64, String>,
    pub functions: Vec<SourceFunction>,
    /// The struct, enum, and user-defined value type declarations of the sources, which
    /// say how a variable of such a type is shown.
    pub types: SourceTypes,
    /// Where the contract's state variables live, when it was compiled with
    /// `--storage-layout`.
    pub storage_layout: Option<StorageLayout>,
    /// Which code generator produced the program, when the artifact or the host says.
    /// Decides whether local variables can be inferred from the stack; see
    /// [`StepMap::locals_at`].
    pub code_generator: Option<CodeGenerator>,
    /// Byte offsets at which each line of each source starts.
    line_starts: BTreeMap<u64, Vec<usize>>,
    /// Instruction index by program counter.
    pc_index: HashMap<u64, usize>,
    /// The program counter each parsed function is entered at: its first `JUMPDEST`
    /// carrying the declaration's span.
    function_entries: HashMap<u64, usize>,
}

/// Which of a contract's two programs a frame executes: the creation code, run once by a
/// `CREATE`, or the deployed code, run by every call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeEnvironment {
    Create,
    Call,
}

/// What an artifact says about the jump an instruction makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpMarker {
    None,
    /// The jump enters a function.
    Call,
    /// The jump returns from one.
    Return,
}

impl ContractDebugInfo {
    /// Prepares one contract's debug info. Functions are parsed from the source text,
    /// which serves ETHDebug and legacy source maps alike: both attach byte ranges of the
    /// same sources to instructions.
    #[must_use]
    pub fn new(
        address: Option<&str>,
        name: &str,
        info: EthdebugInfo,
        source_contents: BTreeMap<u64, String>,
    ) -> Self {
        let functions = source_contents
            .iter()
            .flat_map(|(source_id, source)| parse_source_functions(*source_id, source))
            .collect::<Vec<SourceFunction>>();
        let mut types = SourceTypes::default();
        for (source_id, source) in &source_contents {
            types.add_source(*source_id, source);
        }
        let line_starts = source_contents
            .iter()
            .map(|(source_id, source)| (*source_id, line_starts(source)))
            .collect();
        let pc_index = info
            .instructions
            .iter()
            .enumerate()
            .map(|(index, instruction)| (instruction.offset, index))
            .collect();
        let function_entries = functions
            .iter()
            .enumerate()
            .filter_map(|(function_index, function)| {
                info.instructions
                    .iter()
                    .filter(|instruction| instruction.mnemonic() == Some("JUMPDEST"))
                    .filter(|instruction| {
                        instruction.source_location().is_some_and(|location| {
                            location.source_id == function.source_id
                                && location.offset == function.declaration_start
                        })
                    })
                    .map(|instruction| instruction.offset)
                    .min()
                    .map(|pc| (pc, function_index))
            })
            .collect();
        Self {
            address: address.map(normalize_address),
            name: name.to_owned(),
            info,
            source_contents,
            functions,
            types,
            storage_layout: None,
            code_generator: None,
            line_starts,
            pc_index,
            function_entries,
        }
    }

    /// Records which code generator produced the program.
    #[must_use]
    pub const fn with_code_generator(mut self, code_generator: Option<CodeGenerator>) -> Self {
        self.code_generator = code_generator;
        self
    }

    /// Attaches the contract's storage layout, so state variables can be read by name.
    /// The sources' enum declarations are handed to it, so an enum in storage shows by
    /// its variant's name.
    #[must_use]
    pub fn with_storage_layout(mut self, storage_layout: Option<StorageLayout>) -> Self {
        self.storage_layout = storage_layout.map(|mut layout| {
            layout.enum_variants = self.types.enum_variants_by_name();
            layout
        });
        self
    }

    /// The program this info describes, when the artifact says: ETHDebug programs and legacy
    /// source maps name their environment `create` or `call`. `None` describes either.
    fn code_environment(&self) -> Option<CodeEnvironment> {
        match self.info.environment.as_str() {
            "create" => Some(CodeEnvironment::Create),
            "call" => Some(CodeEnvironment::Call),
            _ => None,
        }
    }

    /// The function whose entry point `pc` is, when it is one.
    #[must_use]
    pub fn function_entry_at_pc(&self, pc: u64) -> Option<usize> {
        self.function_entries.get(&pc).copied()
    }

    /// Whether the instruction at `pc` is a `JUMPDEST`.
    #[must_use]
    pub fn is_jumpdest(&self, pc: u64) -> bool {
        self.pc_index
            .get(&pc)
            .and_then(|index| self.info.instructions.get(*index))
            .is_some_and(|instruction| instruction.mnemonic() == Some("JUMPDEST"))
    }

    /// What the artifact says about the jump the instruction at `pc` makes.
    #[must_use]
    pub fn jump_marker_at_pc(&self, pc: u64) -> JumpMarker {
        let Some(instruction) = self
            .pc_index
            .get(&pc)
            .and_then(|index| self.info.instructions.get(*index))
        else {
            return JumpMarker::None;
        };
        if !instruction.function_invocations().is_empty() {
            JumpMarker::Call
        } else if instruction.function_exit() == Some(FunctionExit::Return) {
            JumpMarker::Return
        } else {
            JumpMarker::None
        }
    }

    #[must_use]
    pub fn source_path(&self, source_id: u64) -> Option<&str> {
        self.info.sources.get(&source_id).map(String::as_str)
    }

    /// The one-based line a byte offset falls on, when the source text is available.
    #[must_use]
    pub fn line_of(&self, source_id: u64, offset: u64) -> Option<u64> {
        let starts = self.line_starts.get(&source_id)?;
        let offset = usize::try_from(offset).ok()?;
        Some(starts.partition_point(|start| *start <= offset) as u64)
    }

    #[must_use]
    pub fn column_of(&self, source_id: u64, offset: u64) -> Option<u64> {
        let starts = self.line_starts.get(&source_id)?;
        let line = self.line_of(source_id, offset)?;
        let line_start = *starts.get(usize::try_from(line).ok()?.checked_sub(1)?)?;
        Some(offset.saturating_sub(line_start as u64) + 1)
    }

    #[must_use]
    pub fn line_count(&self, source_id: u64) -> Option<u64> {
        self.line_starts
            .get(&source_id)
            .map(|starts| starts.len() as u64)
    }

    /// The text of one line, without its line ending.
    #[must_use]
    pub fn line_text(&self, source_id: u64, line: u64) -> Option<&str> {
        let source = self.source_contents.get(&source_id)?;
        let index = usize::try_from(line).ok()?.checked_sub(1)?;
        source.lines().nth(index)
    }

    /// The source span the compiler attached to the instruction at `pc`.
    #[must_use]
    pub fn location_at_pc(&self, pc: u64) -> Option<SourceLocation> {
        let index = *self.pc_index.get(&pc)?;
        self.info.instructions.get(index)?.source_location()
    }

    /// The compiler's instruction at `pc`, using the prepared index.
    #[must_use]
    pub fn instruction_at_pc(&self, pc: u64) -> Option<&Instruction> {
        self.info.instructions.get(*self.pc_index.get(&pc)?)
    }

    /// Legacy source-map modifier depth at `pc`, when the artifact carries it.
    #[must_use]
    pub fn modifier_depth_at_pc(&self, pc: u64) -> Option<i64> {
        let index = *self.pc_index.get(&pc)?;
        self.info.instructions.get(index)?.modifier_depth()
    }

    /// The narrowest parsed function whose declaration contains the span.
    #[must_use]
    pub fn function_for_location(&self, location: &SourceLocation) -> Option<usize> {
        self.functions
            .iter()
            .enumerate()
            .filter(|(_, function)| {
                function.source_id == location.source_id
                    && function.declaration_start <= location.offset
                    && location.offset <= function.body_end
            })
            .min_by_key(|(_, function)| {
                function.body_end.saturating_sub(function.declaration_start)
            })
            .map(|(index, _)| index)
    }

    #[must_use]
    pub fn function_at_pc(&self, pc: u64) -> Option<&SourceFunction> {
        let location = self.location_at_pc(pc)?;
        self.function_for_location(&location)
            .and_then(|index| self.functions.get(index))
    }

    /// The line a breakpoint on `line` of `source_id` resolves to: the line itself when
    /// the compiler generated code that begins there, otherwise the first line of the
    /// narrowest statement that contains it, or nothing when no code maps to the line.
    ///
    /// Ranking matters because solc attaches the whole-contract span to the dispatcher,
    /// and that span intersects every line in the file.
    #[must_use]
    pub fn effective_line(&self, source_id: u64, line: u64) -> Option<u64> {
        if line == 0 || line > self.line_count(source_id)? {
            return None;
        }
        let mut narrowest = None::<(u64, u64)>;
        for instruction in &self.info.instructions {
            let Some(location) = instruction.source_location() else {
                continue;
            };
            if location.source_id != source_id {
                continue;
            }
            let start = self.line_of(source_id, location.offset)?;
            let end = self.line_of(
                source_id,
                location
                    .offset
                    .saturating_add(location.length.saturating_sub(1)),
            )?;
            if start > line || line > end {
                continue;
            }
            if start == line {
                return Some(line);
            }
            if narrowest.is_none_or(|(length, _)| location.length < length) {
                narrowest = Some((location.length, start));
            }
        }
        narrowest.map(|(_, start)| start)
    }
}

/// Lowercases an address and gives it a `0x` prefix, so addresses from the command line,
/// from a manifest, and from the stack compare equal.
#[must_use]
pub fn normalize_address(value: &str) -> String {
    let hex = value.trim_start_matches("0x").trim_start_matches("0X");
    format!("0x{}", hex.to_ascii_lowercase())
}

/// Whether a source path from the compiler matches what a user or an editor asked for:
/// the whole path, a trailing part of either (an editor sends absolute paths where the
/// compiler recorded relative ones), or just the file name.
#[must_use]
pub fn source_path_matches(source_path: &str, requested: &str) -> bool {
    fn ends_with_path(longer: &str, shorter: &str) -> bool {
        longer.ends_with(shorter)
            && longer
                .as_bytes()
                .get(longer.len() - shorter.len() - 1)
                .is_none_or(|byte| *byte == b'/')
    }
    fn file_name(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }
    source_path == requested
        || ends_with_path(source_path, requested)
        || ends_with_path(requested, source_path)
        || (!requested.is_empty() && file_name(source_path) == file_name(requested))
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    starts.extend(
        source
            .bytes()
            .enumerate()
            .filter(|(_, byte)| *byte == b'\n')
            .map(|(index, _)| index + 1),
    );
    starts
}

/// Identifies a source line across every contract in a [`StepMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LineKey {
    pub contract: usize,
    pub source_id: u64,
    pub line: u64,
}

/// Identifies a parsed source function across every contract in a [`StepMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FunctionId {
    pub contract: usize,
    pub function: usize,
}

/// Where one step is in the source, as a frontend shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepLocation {
    pub key: LineKey,
    /// True when the instruction itself is compiler-generated helper code and the
    /// location shown is the statement it was generated for.
    pub generated: bool,
    pub contract_name: String,
    pub path: String,
    pub offset: u64,
    pub length: u64,
    pub line: u64,
    pub column: u64,
    pub function: Option<FunctionId>,
    pub function_name: Option<String>,
}

/// A line breakpoint target resolved against the loaded sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLine {
    pub key: LineKey,
    pub path: String,
    /// The line the user asked for, which may sit inside the statement that `key` names.
    pub requested_line: u64,
}

/// A function breakpoint target resolved against the parsed sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFunction {
    pub id: FunctionId,
    pub name: String,
    pub contract_name: String,
    pub path: String,
    pub line: u64,
}

/// One frame of the call structure at a step, innermost first in [`StepMap::frames`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Zero for the transaction's root frame.
    pub depth: u32,
    /// True for a frame the EVM entered with a call or a creation; false for a Solidity
    /// internal function inferred from the source spans.
    pub external: bool,
    pub address: Option<String>,
    pub contract_name: Option<String>,
    pub function_name: Option<String>,
    /// The step the frame was entered at.
    pub entry_step: usize,
    /// The step the frame is at: the current step for the innermost frame, the call site
    /// for every frame above it.
    pub step: usize,
    pub pc: u64,
    pub location: Option<StepLocation>,
    /// The arguments the function was entered with, when the frame was entered at its
    /// entry point and the contract's argument order is known. Filled in by
    /// [`StepMap::frame_arguments`]; empty otherwise.
    pub arguments: Vec<FrameArgument>,
}

/// Lines of source around a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceListing {
    pub path: String,
    pub current_line: u64,
    /// One-based line numbers with their text.
    pub lines: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocationRef {
    key: LineKey,
    offset: u64,
    length: u64,
    function: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StepInfo {
    /// The location shown for the step: its own span, or the statement generated code
    /// belongs to.
    location: Option<LocationRef>,
    /// True when `location` is inherited from the executing statement.
    generated: bool,
    /// The line the step counts as for stepping and breakpoints. `None` for steps without
    /// source and for the dispatcher, which belongs to no line a user steps through.
    key: Option<LineKey>,
    /// Which contract's code this step executes, when known.
    contract: Option<usize>,
    /// Index into the address table, when the executing address is known.
    address: Option<usize>,
    /// Index into the address table of the account whose storage this step reads and
    /// writes: the executing address, or the caller's for a `DELEGATECALL`.
    storage: Option<usize>,
    /// EVM depth, zero at the root.
    evm_depth: u32,
    /// EVM depth plus the inferred internal-function depth, zero at the root.
    frame_depth: u32,
    /// True when this step enters a frame: an external call, or an internal function.
    frame_entry: bool,
    /// True when this step begins a run of one source line at its depth, skipping over
    /// deeper frames it calls into.
    line_start: bool,
}

/// Per-step source locations and frame depths over one trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepMap {
    contracts: Vec<ContractDebugInfo>,
    steps: Vec<StepInfo>,
    addresses: Vec<String>,
    pcs: Vec<u64>,
    /// Every EVM frame that reverted, as the step it was entered at and the step it
    /// reverted on, innermost first.
    reverted: Vec<(usize, usize)>,
    /// What this trace proved about where each contract's compiler leaves function
    /// parameters on the stack.
    argument_layouts: Vec<Evidence>,
    /// Per contract, whether local variables can be inferred, or why not.
    locals_support: Vec<Result<(), &'static str>>,
    /// Every distinct variable layout some step has, so a run of steps sharing one holds
    /// an index rather than a copy.
    variable_layouts: Vec<Vec<InferredVariable>>,
    /// Per step, the index into `variable_layouts`, or `NO_LAYOUT`.
    step_variables: Vec<u32>,
}

const NO_LAYOUT: u32 = u32::MAX;
/// The layout of a frame the optimizer inlined: its variables have no slots of their own.
const INLINED_LAYOUT: u32 = u32::MAX - 1;

/// What a variable is to the function whose frame holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableKind {
    Parameter,
    Return,
    Local,
}

/// A variable of the executing function, with the stack slot inferred for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredVariable {
    pub name: String,
    /// The declared type, with its data location.
    pub ty: String,
    pub kind: VariableKind,
    /// The slot, counted from the bottom of the stack, of the variable's first word;
    /// `None` when the variable is in scope but its frame could not be placed.
    pub slot: Option<usize>,
    /// How many stack words the variable takes: two for a `calldata` slice, whose words
    /// are its offset and its length, one for everything else.
    pub words: usize,
}

/// Whether local variables are known at a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalsStatus<'a> {
    /// The executing function's variables, inferred from the legacy stack layout.
    Inferred(&'a [InferredVariable]),
    /// Nothing can be inferred here, and why.
    Unavailable(&'static str),
}

/// What a trace has shown about one contract's argument passing. Only a proof is used;
/// a contradiction disables arguments for the contract entirely, because it means the
/// entry point we detect is not where the parameters are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// Nothing in the trace said either way.
    Unknown,
    /// A frame whose arguments we knew did not have them on top of its entry stack.
    Contradicted,
    /// The parameters are the top words; the order was not established.
    TopWords,
    /// The parameters are the top words, in this order.
    Ordered(ArgumentOrder),
}

impl Evidence {
    /// Keeps the stronger of two observations, and a contradiction over everything: one
    /// frame that disagrees is enough to stop guessing for the whole contract.
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Contradicted, _) | (_, Self::Contradicted) => Self::Contradicted,
            (Self::Ordered(order), _) | (_, Self::Ordered(order)) => Self::Ordered(order),
            (Self::TopWords, _) | (_, Self::TopWords) => Self::TopWords,
            _ => Self::Unknown,
        }
    }

    fn layout(self) -> Option<ArgumentLayout> {
        match self {
            Self::Ordered(order) => Some(ArgumentLayout::Ordered(order)),
            Self::TopWords => Some(ArgumentLayout::TopWords),
            Self::Unknown | Self::Contradicted => None,
        }
    }
}

/// What the first pass records about a step: its EVM frame and its own span.
#[derive(Debug, Clone, Copy)]
struct FramedStep {
    evm_depth: u32,
    frame_id: u32,
    contract: Option<usize>,
    address: Option<usize>,
    storage: Option<usize>,
    location: Option<LocationRef>,
    /// The function this step's program counter is the entry point of.
    entry: Option<usize>,
    /// What the artifact says about the jump this step makes.
    marker: JumpMarker,
}

struct EvmFrame {
    id: u32,
    contract: Option<usize>,
    address: Option<usize>,
    /// The account whose storage the frame reads and writes.
    storage: Option<usize>,
    /// The step the frame was entered at.
    entry_step: usize,
}

/// What is known about an EVM frame as it is entered.
struct FrameEntered {
    /// The address whose code the frame runs; `None` when nothing recorded it, or for a
    /// creation whose address the backend did not report.
    address: Option<String>,
    environment: CodeEnvironment,
    /// Whether the frame runs against its caller's storage.
    delegated: bool,
}

impl FrameEntered {
    /// The call or creation the backend recorded as entered at `step`, when it recorded
    /// calls at all. A call that ran no steps, such as one to a precompile, ends at the
    /// step it started and is not a frame in the trace.
    fn recorded(trace: &TransactionTrace, step: usize) -> Option<Self> {
        let spans_steps = |entry: Option<usize>, exit: Option<usize>| {
            entry == Some(step) && exit.is_none_or(|exit| exit > step)
        };
        let artifacts = &trace.artifacts;
        if let Some(call) = artifacts
            .calls
            .iter()
            .find(|call| spans_steps(call.entry_step, call.exit_step))
        {
            return Some(Self {
                address: Some(call.bytecode_address.clone()),
                environment: CodeEnvironment::Call,
                delegated: matches!(call.call_type.as_str(), "DELEGATECALL" | "CALLCODE"),
            });
        }
        let creation = artifacts
            .creations
            .iter()
            .find(|creation| spans_steps(creation.entry_step, creation.exit_step))?;
        Some(Self {
            address: creation.address.clone(),
            environment: CodeEnvironment::Create,
            delegated: false,
        })
    }

    /// What the call instruction at `caller` says about the frame it entered.
    fn from_call(trace: &TransactionTrace, caller: Option<usize>) -> Self {
        let op = caller.map(|caller| &*trace.steps[caller].op);
        Self {
            address: caller.and_then(|caller| call_target(&trace.steps[caller])),
            environment: if matches!(op, Some("CREATE" | "CREATE2")) {
                CodeEnvironment::Create
            } else {
                CodeEnvironment::Call
            },
            delegated: matches!(op, Some("DELEGATECALL" | "CALLCODE")),
        }
    }
}

/// One internal frame: a function, or a placeholder for a compiler-generated helper
/// entered through a marked call, which absorbs the matching marked return and counts as
/// no frame of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameEntry {
    function: Option<usize>,
    /// Where the frame returns to: the tag the caller pushed before the arguments, read
    /// off the stack at the call. A jump landing there is the return, whatever function
    /// it lands in, which is what tells a return from a recursive call apart from
    /// staying in the function.
    return_pc: Option<u64>,
    /// The frame's variables, tracked when the contract's code generator keeps them at
    /// fixed stack slots.
    variables: Option<FrameVariables>,
}

/// The stack slots of one frame's variables, following solc's legacy code generator.
///
/// That generator keeps every variable at a fixed slot: the parameters are the words
/// below the height the function was entered at, the return parameters are reserved right
/// above them at entry, and each local takes the next free slot when its declaration
/// executes and gives it back at the end of its block. So once the frame's base is known,
/// a live local's slot is the locals base plus the number of locals declared before it
/// that are still in scope, which the source alone decides.
///
/// The base is the calling convention's: the parameters are the top words at the entry
/// of the function's body, whether an internal call or the dispatcher jumped there, and
/// the optimizer keeps that whatever it does inside a block. When the entry was not seen
/// the frame is placed by whichever comes first: the first return parameter's
/// reservation, or the first local's, or the first instruction of the body; those read
/// single instructions, which the optimizer may reorder.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameVariables {
    /// The slot of the first parameter, once established.
    params_base: Option<usize>,
    /// The slot of each return parameter, once known.
    returns: Vec<Option<usize>>,
    /// The slot the first live local occupies, once established.
    locals_base: Option<usize>,
    /// Whether a step of the function body has been seen.
    body_seen: bool,
    /// The layout last computed for the frame, which steps without a location of their
    /// own in the function inherit.
    layout: Option<u32>,
    /// The stack slots the function's modifiers hold below its body's locals: their
    /// parameters, and the locals each has declared by its `_`. `None` when a modifier's
    /// declaration was not found, so the body's first instruction places the locals.
    modifier_slots: Option<usize>,
    /// Whether the frame was reached without a jump onto the function's entry: the
    /// optimizer inlined the call, and the function's variables have no slots of their
    /// own — its parameters are the caller's expressions, its results the caller's
    /// temporaries.
    inlined: bool,
}

impl FrameVariables {
    fn new(
        function: &SourceFunction,
        params_base: Option<usize>,
        modifier_slots: Option<usize>,
    ) -> Self {
        Self {
            params_base,
            returns: vec![None; function.returns.len()],
            locals_base: None,
            body_seen: false,
            layout: None,
            modifier_slots,
            inlined: false,
        }
    }

    /// Places the return parameters and the locals from known parameters: the returns
    /// sit right above the parameters, the locals above those and the modifiers' slots.
    fn place_from_parameters(&mut self, function: &SourceFunction) {
        let Some(base) = self.params_base else {
            return;
        };
        let returns_base = base + parameter_slots(&function.params);
        for (index, slot) in self.returns.iter_mut().enumerate() {
            slot.get_or_insert(returns_base + index);
        }
        if self.locals_base.is_none() {
            if let Some(modifier_slots) = self.modifier_slots {
                self.locals_base = Some(returns_base + function.returns.len() + modifier_slots);
            }
        }
    }

    /// Follows the frame's variables through one step of its function's own code, at
    /// `span` with the stack `height` high, and returns the layout after it.
    fn track(
        &mut self,
        function: &SourceFunction,
        span: ByteRange,
        height: usize,
        layouts: &mut Vec<Vec<InferredVariable>>,
    ) -> u32 {
        if self.inlined {
            self.layout = Some(INLINED_LAYOUT);
            return INLINED_LAYOUT;
        }
        let length = span.end - span.start;
        let param_slots = parameter_slots(&function.params);
        // Known parameters place everything else before any instruction is read.
        self.place_from_parameters(function);
        // The body's first instruction runs right above whatever was reserved before it:
        // the first local goes there, and without modifiers in between that is right
        // above the parameters and the return parameters. A modifier resumed after its
        // `_` is not at its beginning.
        let at_beginning = function
            .placeholder
            .is_none_or(|placeholder| span.start < placeholder);
        if !self.body_seen
            && at_beginning
            && span.start >= function.body_start
            && span.start < function.body_end
        {
            self.body_seen = true;
            if self.locals_base.is_none() {
                self.locals_base = Some(height);
            }
            if self.params_base.is_none() && !function.has_modifiers {
                self.params_base = height.checked_sub(param_slots + function.returns.len());
            }
        }
        // A return parameter's reservation runs at entry, before any modifier, so the
        // first one's slot also says where the parameters end.
        for (index, parameter) in function.returns.iter().enumerate() {
            if self.returns[index].is_none() && parameter.declaration.covers(span.start, length) {
                self.returns[index] = Some(height);
                if index == 0 && self.params_base.is_none() {
                    self.params_base = height.checked_sub(param_slots);
                }
            }
        }
        // The first local reservation seen places every local, which is what places them
        // when a modifier's slots sit between the parameters and the body.
        if self.locals_base.is_none() {
            if let Some((index, _)) = function
                .locals
                .iter()
                .enumerate()
                .find(|(_, local)| local.statement.covers(span.start, length))
            {
                self.locals_base = height.checked_sub(live_index(function, index, span.start));
            }
        }
        // Parameters a reservation just placed place the rest.
        self.place_from_parameters(function);

        let mut layout = Vec::new();
        if let Some(base) = self.params_base {
            let mut slot = base;
            for parameter in &function.params {
                let size = parameter_stack_slots(parameter);
                layout.push(InferredVariable {
                    name: parameter.name.clone(),
                    ty: match &parameter.location {
                        Some(location) => format!("{} {location}", parameter.ty),
                        None => parameter.ty.clone(),
                    },
                    kind: VariableKind::Parameter,
                    slot: Some(slot),
                    words: size,
                });
                slot += size;
            }
        }
        for (index, parameter) in function.returns.iter().enumerate() {
            layout.push(InferredVariable {
                name: parameter.name.clone(),
                ty: parameter.declared_type(),
                kind: VariableKind::Return,
                slot: self.returns[index],
                words: 1,
            });
        }
        for (index, local) in function.locals.iter().enumerate() {
            if local.scope.contains(span.start) {
                layout.push(InferredVariable {
                    name: local.name.clone(),
                    ty: local.declared_type(),
                    kind: VariableKind::Local,
                    slot: self
                        .locals_base
                        .map(|base| base + live_index(function, index, span.start)),
                    words: 1,
                });
            }
        }
        let id = match self.layout {
            Some(id) if layouts[id as usize] == layout => id,
            _ => {
                layouts.push(layout);
                (layouts.len() - 1) as u32
            }
        };
        self.layout = Some(id);
        id
    }
}

/// How many of the function's locals declared before `index` are in scope at `offset`:
/// the slots the legacy code generator has taken for locals at that point.
fn live_index(function: &SourceFunction, index: usize, offset: u64) -> usize {
    let declaration = function.locals[index].declaration.start;
    function
        .locals
        .iter()
        .filter(|other| other.scope.contains(offset) && other.declaration.start < declaration)
        .count()
}

/// The calldata of the frame executing `step`: the transaction's input at the root, the
/// recorded call's input in a nested frame.
fn calldata_for_step(trace: &TransactionTrace, step: usize) -> &str {
    let root_depth = trace.steps.first().map_or(0, |first| first.depth);
    let depth = trace
        .steps
        .get(step)
        .map_or(root_depth, |current| current.depth);
    if depth == root_depth {
        return &trace.input_data;
    }
    trace
        .artifacts
        .calls
        .iter()
        .filter(|call| {
            call.entry_step.is_some_and(|entry| entry <= step)
                && call.exit_step.is_none_or(|exit| step < exit)
        })
        .max_by_key(|call| call.depth)
        .map_or("", |call| call.input.as_str())
}

/// How many stack words a parameter takes: a `calldata` slice of a dynamic type is an
/// offset and a length, an external function is an address and a selector, and
/// everything else is one word.
fn parameter_stack_slots(parameter: &SourceParam) -> usize {
    let dynamic =
        parameter.ty == "bytes" || parameter.ty == "string" || parameter.ty.ends_with("[]");
    if parameter.location.as_deref() == Some("calldata") && dynamic
        || parameter.ty.starts_with("function")
    {
        2
    } else {
        1
    }
}

fn parameter_slots(parameters: &[SourceParam]) -> usize {
    parameters.iter().map(parameter_stack_slots).sum()
}

/// The stack slots the first `count` modifiers of `function` hold while the code they
/// wrap runs: each modifier's parameters, and the locals it has declared by its `_`.
/// `None` when a modifier's declaration is not among the parsed functions (a base
/// contract's source that was not loaded, or a base constructor call in the header).
fn modifier_slots(
    contract: &ContractDebugInfo,
    function: &SourceFunction,
    count: usize,
) -> Option<usize> {
    let mut slots = 0;
    for name in function.modifiers.iter().take(count) {
        let modifier = contract.functions.iter().find(|candidate| {
            candidate.placeholder.is_some()
                && candidate.name == *name
                && candidate.source_id == function.source_id
        });
        let modifier = modifier.or_else(|| {
            contract
                .functions
                .iter()
                .find(|candidate| candidate.placeholder.is_some() && candidate.name == *name)
        })?;
        let placeholder = modifier.placeholder?;
        let live = modifier
            .locals
            .iter()
            .filter(|local| {
                local.declaration.start < placeholder && local.scope.contains(placeholder)
            })
            .count();
        slots += parameter_slots(&modifier.params) + live;
    }
    Some(slots)
}

/// Whether a contract's variables can be inferred from the stack, or why not.
fn locals_support(contract: &ContractDebugInfo, evidence: Evidence) -> Result<(), &'static str> {
    match (contract.code_generator, evidence.layout()) {
        (_, Some(ArgumentLayout::Ordered(ArgumentOrder::FirstOnTop))) => Err(
            "this trace shows the via-IR calling convention, whose stack layout cannot be \
             recovered without compiler-reported variable locations",
        ),
        (Some(CodeGenerator::ViaIr), _) => Err(
            "this contract was compiled through the via-IR pipeline, whose stack layout cannot \
             be recovered without compiler-reported variable locations",
        ),
        (Some(CodeGenerator::Legacy), _) | (None, Some(ArgumentLayout::Ordered(_))) => Ok(()),
        (None, _) => Err(
            "the code generator is not known; only solc's legacy pipeline keeps variables at \
             fixed stack slots",
        ),
    }
}

/// The inferred Solidity state of one EVM frame.
#[derive(Default)]
struct InternalFrame {
    /// The frames active in this EVM frame, innermost last.
    functions: Vec<FrameEntry>,
    /// The last real statement executed in this frame, which generated code belongs to.
    statement: Option<LocationRef>,
    /// The variables of frames that were left without returning, by function: a modifier
    /// hands over to the body it wraps and resumes after it with its slots still there.
    remembered: HashMap<usize, FrameVariables>,
}

impl InternalFrame {
    /// The innermost function, looking past helper placeholders.
    fn active(&self) -> Option<usize> {
        self.functions.iter().rev().find_map(|entry| entry.function)
    }

    fn is_active(&self, function: usize) -> bool {
        self.active() == Some(function)
    }

    fn push_function(
        &mut self,
        function: usize,
        return_pc: Option<u64>,
        variables: Option<FrameVariables>,
    ) {
        self.functions.push(FrameEntry {
            function: Some(function),
            return_pc,
            variables,
        });
    }

    fn push_placeholder(&mut self) {
        self.functions.push(FrameEntry {
            function: None,
            return_pc: None,
            variables: None,
        });
    }

    /// Whether a jump landing on `pc` returns from the innermost frame.
    fn returns_to(&self, pc: u64) -> bool {
        self.functions
            .last()
            .is_some_and(|entry| entry.return_pc == Some(pc))
    }
}

/// Places the parameters of `function` when the step at `index` lands on a `JUMPDEST`
/// carrying its declaration with the decoded parameters as the top words of the stack:
/// its body's entry tag, jumped to by the dispatcher (`from_call`), or the dispatcher's
/// landing back from the decoder, which is where the body follows directly when the
/// optimizer inlined it. That is the calling convention, which the optimizer keeps. The
/// frame's calldata, when it names this function, must agree with those words, or
/// nothing is placed; nor is anything placed once the body has run, which rules out the
/// dispatcher's return tag.
#[allow(clippy::too_many_arguments)]
fn place_at_entry_landing(
    frame: &mut InternalFrame,
    contract: &ContractDebugInfo,
    function: usize,
    trace: &TransactionTrace,
    index: usize,
    own: LocationRef,
    height: usize,
    from_call: bool,
) {
    let Some(declared) = contract.functions.get(function) else {
        return;
    };
    let at_declaration =
        contract.is_jumpdest(trace.steps[index].pc) && own.offset == declared.declaration_start;
    let from_dispatcher =
        !from_call || (index > 0 && framed_declaration(trace, contract, index - 1, declared));
    if !at_declaration || !from_dispatcher {
        return;
    }
    let entry = frame
        .functions
        .iter_mut()
        .rev()
        .find(|entry| entry.function == Some(function));
    let Some(variables) = entry.and_then(|entry| entry.variables.as_mut()) else {
        return;
    };
    if variables.params_base.is_some() || variables.body_seen {
        return;
    }
    let stack = trace.steps[index].snapshot_ref().stack;
    let calldata = calldata_for_step(trace, index);
    if argument_evidence(declared, calldata, stack) == Evidence::Contradicted {
        return;
    }
    variables.params_base = height.checked_sub(parameter_slots(&declared.params));
}

/// Whether the step at `index` is a `JUMP` attributed to the declaration of `function`
/// as a whole: the dispatcher's jump into its body.
fn framed_declaration(
    trace: &TransactionTrace,
    contract: &ContractDebugInfo,
    index: usize,
    function: &SourceFunction,
) -> bool {
    if &*trace.steps[index].op != "JUMP" {
        return false;
    }
    contract
        .location_at_pc(trace.steps[index].pc)
        .is_some_and(|location| {
            location.source_id == function.source_id
                && location.offset == function.declaration_start
        })
}

/// The slot of the first parameter of the modifier `function`, from the placed function
/// it runs for: above that function's parameters and return parameters, and the slots of
/// the modifiers invoked before it.
fn modifier_base(
    frame: &InternalFrame,
    contract: &ContractDebugInfo,
    function: usize,
) -> Option<usize> {
    let modifier = contract.functions.get(function)?;
    modifier.placeholder?;
    let parent = frame
        .functions
        .iter()
        .rev()
        .find(|entry| entry.function.is_some())?;
    let parent_function = contract.functions.get(parent.function?)?;
    let position = parent_function
        .modifiers
        .iter()
        .position(|name| *name == modifier.name)?;
    let parent_base = parent.variables.as_ref()?.params_base?;
    let before = modifier_slots(contract, parent_function, position)?;
    Some(
        parent_base
            + parameter_slots(&parent_function.params)
            + parent_function.returns.len()
            + before,
    )
}

impl StepMap {
    /// Maps every step of `trace` through the contracts' debug info.
    ///
    /// The root frame executes the transaction's target, or the created contract for a
    /// deployment. A contract given with an address describes any frame that executes
    /// it; when only one contract is given, it also describes the root whatever address
    /// it names, so a single `--ethdebug-dir` applies to the transaction it was passed for.
    #[must_use]
    pub fn new(trace: &TransactionTrace, contracts: Vec<ContractDebugInfo>) -> Self {
        Self::build(trace, contracts, true)
    }

    /// Keeps single-instruction source stops when testing compiler debug information.
    ///
    /// Interactive stepping smooths brief line excursions. A compiler regression test
    /// must observe them: an optimized getter can map its entire body to one `SLOAD`.
    #[must_use]
    pub fn for_debug_diff(trace: &TransactionTrace, contracts: Vec<ContractDebugInfo>) -> Self {
        Self::build(trace, contracts, false)
    }

    fn build(trace: &TransactionTrace, contracts: Vec<ContractDebugInfo>, smooth: bool) -> Self {
        let mut addresses = Vec::<String>::new();
        let mut address_index = HashMap::<String, usize>::new();
        let mut intern = |address: &str| -> usize {
            let address = normalize_address(address);
            *address_index.entry(address.clone()).or_insert_with(|| {
                addresses.push(address);
                addresses.len() - 1
            })
        };
        // The contract describing the code a frame at `address` runs. A contract's creation
        // and deployed programs are separate artifacts at the same address, so the one for
        // the frame's environment is preferred, and one that names no environment describes
        // both. When only the other program is loaded it still names the address's sources,
        // and is used as before.
        let contract_for =
            |address: Option<&str>, environment: CodeEnvironment, root: bool| -> Option<usize> {
                let address = address.map(normalize_address);
                if let Some(address) = &address {
                    let mut at_address = contracts
                        .iter()
                        .enumerate()
                        .filter(|(_, contract)| contract.address.as_deref() == Some(address));
                    let exact = at_address.clone().find(|(_, contract)| {
                        contract
                            .code_environment()
                            .is_none_or(|candidate| candidate == environment)
                    });
                    if let Some((index, _)) = exact.or_else(|| at_address.next()) {
                        return Some(index);
                    }
                }
                (root && contracts.len() == 1).then_some(0)
            };

        // Pass 1: EVM frames, executing addresses, and each step's own span.
        let root_address = trace
            .to_addr
            .as_deref()
            .or(trace.contract_address.as_deref());
        let root_environment = if trace.to_addr.is_none() && trace.contract_address.is_some() {
            CodeEnvironment::Create
        } else {
            CodeEnvironment::Call
        };
        let root_depth = trace.steps.first().map_or(0, |step| step.depth);
        let mut next_frame_id = 1_u32;
        let root_storage = root_address.map(&mut intern);
        let mut evm_frames = vec![EvmFrame {
            id: 0,
            contract: contract_for(root_address, root_environment, true),
            address: root_storage,
            storage: root_storage,
            entry_step: 0,
        }];
        let mut reverted = Vec::new();
        let mut framed = Vec::with_capacity(trace.steps.len());
        for (index, step) in trace.steps.iter().enumerate() {
            let evm_depth = step.depth.saturating_sub(root_depth) as usize;
            evm_frames.truncate(evm_depth + 1);
            while evm_frames.len() <= evm_depth {
                // A new EVM frame. The backend's record of the call or creation entered at
                // this step names the code it runs; without one, the callee's code address
                // is on the caller's stack at the call instruction, the step before this
                // one, and a `CREATE` leaves no address there at all.
                let call = (evm_frames.len() == evm_depth)
                    .then(|| index.checked_sub(1))
                    .flatten();
                let entered = FrameEntered::recorded(trace, index)
                    .filter(|_| evm_frames.len() == evm_depth)
                    .unwrap_or_else(|| FrameEntered::from_call(trace, call));
                let address = entered.address.as_deref().map(&mut intern);
                // A `DELEGATECALL` or `CALLCODE` runs the callee's code against the
                // caller's storage; every other call has the callee's own.
                let storage = if entered.delegated {
                    evm_frames.last().and_then(|frame| frame.storage)
                } else {
                    address
                };
                evm_frames.push(EvmFrame {
                    id: next_frame_id,
                    contract: contract_for(entered.address.as_deref(), entered.environment, false),
                    address,
                    storage,
                    entry_step: index,
                });
                next_frame_id += 1;
            }
            if &*step.op == "REVERT" || step.error.is_some() {
                let entry_step = evm_frames
                    .last()
                    .expect("the root frame is never popped")
                    .entry_step;
                reverted.push((entry_step, index));
            }
            let frame = evm_frames.last().expect("the root frame is never popped");
            let location = frame.contract.and_then(|contract_index| {
                let contract = &contracts[contract_index];
                let location = contract.location_at_pc(step.pc)?;
                let line = contract.line_of(location.source_id, location.offset)?;
                Some(LocationRef {
                    key: LineKey {
                        contract: contract_index,
                        source_id: location.source_id,
                        line,
                    },
                    offset: location.offset,
                    length: location.length,
                    function: contract.function_for_location(&location),
                })
            });
            let contract = frame.contract.map(|index| &contracts[index]);
            framed.push(FramedStep {
                evm_depth: evm_depth as u32,
                frame_id: frame.id,
                contract: frame.contract,
                address: frame.address,
                storage: frame.storage,
                location,
                entry: contract.and_then(|contract| contract.function_entry_at_pc(step.pc)),
                marker: contract.map_or(JumpMarker::None, |contract| {
                    contract.jump_marker_at_pc(step.pc)
                }),
            });
        }

        // Pass 2: a step outside every function is generated code for the statement that
        // is executing, unless no function runs later in its EVM frame; then it is the
        // dispatcher finishing up after the function returned.
        let structured = |contract: Option<usize>| {
            contract.is_some_and(|index| !contracts[index].functions.is_empty())
        };
        let mut function_follows = std::collections::HashSet::<u32>::new();
        let mut epilogue = vec![false; framed.len()];
        for (index, step) in framed.iter().enumerate().rev() {
            match step.location.map(|location| location.function) {
                Some(Some(_)) => {
                    function_follows.insert(step.frame_id);
                }
                Some(None) if structured(step.contract) => {
                    epilogue[index] = !function_follows.contains(&step.frame_id);
                }
                _ => {}
            }
        }

        let argument_layouts = prove_argument_layouts(trace, &contracts, &framed);
        let locals_support = contracts
            .iter()
            .zip(&argument_layouts)
            .map(|(contract, evidence)| locals_support(contract, *evidence))
            .collect::<Vec<_>>();

        // Pass 3: the virtual function stack per EVM frame, frame depths, the line each
        // step counts as, and the variables of the frame executing it.
        let mut internal = Vec::<InternalFrame>::new();
        let mut steps = Vec::with_capacity(framed.len());
        let mut pcs = Vec::with_capacity(framed.len());
        let mut variable_layouts = Vec::<Vec<InferredVariable>>::new();
        let mut step_variables = Vec::with_capacity(framed.len());
        for (index, step) in framed.iter().enumerate() {
            let height = trace.steps[index].snapshot_ref().stack.len();
            // Variables are tracked for a frame whose contract keeps them at fixed slots.
            // A frame entered by a jump from inside another function has its parameters
            // on top of the stack at entry, which places them; a public function entered
            // from the dispatcher is placed later, by its first reservation.
            let frame_variables = |function: usize| -> Option<FrameVariables> {
                let contract_index = step.contract?;
                locals_support[contract_index].ok()?;
                let contract = &contracts[contract_index];
                let function = contract.functions.get(function)?;
                let landed_from_function = index > 0
                    && framed[index - 1].evm_depth == step.evm_depth
                    && &*trace.steps[index - 1].op == "JUMP"
                    && framed[index - 1]
                        .location
                        .is_some_and(|location| location.function.is_some());
                let params_base = landed_from_function
                    .then(|| height.checked_sub(parameter_slots(&function.params)))
                    .flatten();
                Some(FrameVariables::new(
                    function,
                    params_base,
                    modifier_slots(contract, function, function.modifiers.len()),
                ))
            };
            let contract_info = step.contract.map(|index| &contracts[index]);
            let evm_depth = step.evm_depth as usize;
            let mut frame_entry = false;
            internal.truncate(evm_depth + 1);
            while internal.len() <= evm_depth {
                internal.push(InternalFrame::default());
                frame_entry = true;
            }
            let frame = internal.last_mut().expect("the root frame is never popped");

            // A step reached by a `JUMP` from the same EVM frame is a landing: the jump's
            // marker, or landing on a function's entry point, says whether it was a call.
            let landed_by_jump = index > 0
                && framed[index - 1].evm_depth == step.evm_depth
                && &*trace.steps[index - 1].op == "JUMP";
            // Whether the previous step ran another function's own code in this EVM
            // frame, as opposed to the dispatcher's.
            let from_function_code = index > 0
                && framed[index - 1].evm_depth == step.evm_depth
                && framed[index - 1].location.is_some_and(|location| {
                    location.function.is_some()
                        && location.function != step.location.and_then(|own| own.function)
                });
            let previous_marker = if landed_by_jump {
                framed[index - 1].marker
            } else {
                JumpMarker::None
            };
            let structured = structured(step.contract);
            let mut generated = false;
            // A return pops whatever the matching call pushed, wherever it lands: the
            // artifact marks it, or the jump lands on the return address recorded at the
            // call. A marked call is resolved once the landing's function is known.
            let mut pending_call = false;
            if landed_by_jump {
                let pc = trace.steps[index].pc;
                match previous_marker {
                    JumpMarker::Call => pending_call = true,
                    JumpMarker::Return => {
                        frame.functions.pop();
                    }
                    JumpMarker::None if frame.returns_to(pc) => {
                        frame.functions.pop();
                    }
                    JumpMarker::None => {}
                }
            }
            // The return address a call being made here would come back to, read off
            // the caller's stack at the jump: the tag pushed before the arguments.
            let return_address = |function: usize| -> Option<u64> {
                if !landed_by_jump {
                    return None;
                }
                let contract = &contracts[step.contract?];
                let arguments = contract.functions.get(function)?.params.len();
                let stack = trace.steps[index - 1].snapshot_ref().stack;
                let word = stack.get(stack.len().checked_sub(2 + arguments)?)?;
                let pc = u64::from_str_radix(word.trim_start_matches("0x"), 16).ok()?;
                contract.is_jumpdest(pc).then_some(pc)
            };
            let (location, key) = match step.location {
                None => {
                    // Code without source, such as a generated helper: a marked call into
                    // it gets a placeholder its marked return pops.
                    if pending_call {
                        frame.push_placeholder();
                    }
                    (None, None)
                }
                Some(own) if !structured => {
                    // No parsed functions: every mapped step is a line of its own.
                    frame.statement = Some(own);
                    (Some(own), Some(own.key))
                }
                Some(own) => match own.function {
                    Some(function) => {
                        let entering = landed_by_jump && step.entry == Some(function);
                        // Back from the decoder in the function's own frame: the
                        // parameters are on top, whether a jump to the body follows or
                        // the body was inlined here.
                        if landed_by_jump
                            && previous_marker == JumpMarker::Return
                            && frame.is_active(function)
                        {
                            if let Some(contract) = contract_info {
                                place_at_entry_landing(
                                    frame, contract, function, trace, index, own, height, false,
                                );
                            }
                        }
                        if entering || (pending_call && !frame.is_active(function)) {
                            // A call: onto the entry point, or marked and into a function
                            // other than the active one.
                            frame.push_function(
                                function,
                                return_address(function),
                                frame_variables(function),
                            );
                            frame_entry = true;
                        } else if pending_call {
                            // A marked call into the active function away from its entry
                            // point: recursion always enters at the entry point, so this
                            // is the dispatcher jumping to the body of the function whose
                            // parameters it decoded, which places them, or a generated
                            // helper whose span is the calling line.
                            if let Some(contract) = contract_info {
                                place_at_entry_landing(
                                    frame, contract, function, trace, index, own, height, true,
                                );
                            }
                            frame.push_placeholder();
                        } else if !frame.is_active(function) {
                            match frame
                                .functions
                                .iter()
                                .rposition(|entry| entry.function == Some(function))
                            {
                                Some(position) => {
                                    // A modifier handing over to the body keeps its slots;
                                    // remember them for when it resumes.
                                    for left in frame.functions.drain(position + 1..) {
                                        if let (Some(function), Some(variables)) =
                                            (left.function, left.variables)
                                        {
                                            frame.remembered.insert(function, variables);
                                        }
                                    }
                                }
                                None => {
                                    let mut variables = frame.remembered.remove(&function);
                                    if variables.is_none() {
                                        variables = frame_variables(function);
                                        if let (Some(variables), Some(contract)) =
                                            (variables.as_mut(), contract_info)
                                        {
                                            let declared = &contract.functions[function];
                                            if declared.placeholder.is_some() {
                                                // A modifier's parameters sit right above
                                                // the parameters and return parameters of
                                                // the function it runs for, and the slots
                                                // of the modifiers before it; a placed
                                                // function places its modifiers.
                                                if variables.params_base.is_none() {
                                                    variables.params_base =
                                                        modifier_base(frame, contract, function);
                                                }
                                            } else if declared.name != "constructor"
                                                && from_function_code
                                                && step.entry != Some(function)
                                            {
                                                // A function reached from inside another
                                                // without a jump onto its entry: the
                                                // optimizer inlined the call.
                                                variables.inlined = true;
                                            }
                                        }
                                    }
                                    frame.push_function(function, None, variables);
                                    frame_entry = true;
                                }
                            }
                        }
                        frame.statement = Some(own);
                        (Some(own), Some(own.key))
                    }
                    None if epilogue[index] => {
                        frame.functions.clear();
                        frame.statement = None;
                        (Some(own), None)
                    }
                    None => {
                        if pending_call {
                            frame.push_placeholder();
                        }
                        match frame.statement {
                            Some(statement) => {
                                generated = true;
                                (Some(statement), Some(statement.key))
                            }
                            // The dispatcher before any function: shown as it is, stepped
                            // through as no line at all.
                            None => (Some(own), None),
                        }
                    }
                },
            };
            // The variables of the innermost function frame: followed through a step of
            // the function's own code, inherited by any other step.
            let layout = {
                let frame = internal.last_mut().expect("the root frame is never popped");
                let contract = step.contract.map(|index| &contracts[index]);
                let active = frame
                    .functions
                    .iter()
                    .rposition(|entry| entry.function.is_some());
                match (active, step.location, contract) {
                    (Some(position), Some(own), Some(contract))
                        if own.function.is_some()
                            && own.function == frame.functions[position].function =>
                    {
                        let function_index = own.function.unwrap_or_default();
                        let function = &contract.functions[function_index];
                        let span = ByteRange {
                            start: own.offset,
                            end: own.offset + own.length,
                        };
                        let (below, rest) = frame.functions.split_at_mut(position);
                        let entry = &mut rest[0];
                        let layout = entry.variables.as_mut().map(|variables| {
                            variables.track(function, span, height, &mut variable_layouts)
                        });
                        // A modifier's parameters sit right above the function's
                        // parameters and return parameters and the slots of the modifiers
                        // before it, so placing the modifier places the function it runs
                        // for when nothing else has.
                        let modifier_base = entry
                            .variables
                            .as_ref()
                            .and_then(|variables| variables.params_base);
                        let parent = below
                            .iter_mut()
                            .rev()
                            .find(|entry| entry.function.is_some());
                        if let (Some(modifier_base), Some(parent)) = (modifier_base, parent) {
                            let parent_function =
                                &contract.functions[parent.function.unwrap_or_default()];
                            let position = parent_function
                                .modifiers
                                .iter()
                                .position(|name| *name == function.name);
                            if let (Some(position), Some(variables)) =
                                (position, parent.variables.as_mut())
                            {
                                if variables.params_base.is_none() {
                                    variables.params_base =
                                        modifier_slots(contract, parent_function, position)
                                            .and_then(|before| {
                                                modifier_base.checked_sub(
                                                    parameter_slots(&parent_function.params)
                                                        + parent_function.returns.len()
                                                        + before,
                                                )
                                            });
                                }
                            }
                        }
                        layout
                    }
                    (Some(position), _, _) => frame.functions[position]
                        .variables
                        .as_ref()
                        .and_then(|variables| variables.layout),
                    _ => None,
                }
            };
            step_variables.push(layout.unwrap_or(NO_LAYOUT));
            let internal_total = internal
                .iter()
                .map(|frame| {
                    frame
                        .functions
                        .iter()
                        .filter(|entry| entry.function.is_some())
                        .count()
                })
                .sum::<usize>();
            steps.push(StepInfo {
                location,
                generated,
                key,
                contract: step.contract,
                address: step.address,
                storage: step.storage,
                evm_depth: step.evm_depth,
                frame_depth: (evm_depth + internal_total) as u32,
                frame_entry,
                line_start: false,
            });
            pcs.push(trace.steps[index].pc);
        }

        let mut map = Self {
            contracts,
            steps,
            addresses,
            pcs,
            reverted,
            argument_layouts,
            locals_support,
            variable_layouts,
            step_variables,
        };
        if smooth {
            map.smooth_single_step_excursions();
        }
        map.mark_line_starts();
        map
    }

    /// A lone instruction attributed to another line, between two runs of the same line
    /// at the same depth, counts as that line. solc emits such instructions at function
    /// entry, and stopping on them would show a later line before an earlier one.
    fn smooth_single_step_excursions(&mut self) {
        let neighbours =
            |steps: &[StepInfo], index: usize, forward: bool| -> Option<Option<LineKey>> {
                let depth = steps[index].frame_depth;
                let range: Box<dyn Iterator<Item = usize>> = if forward {
                    Box::new((index + 1)..steps.len())
                } else {
                    Box::new((0..index).rev())
                };
                for candidate in range {
                    let step = &steps[candidate];
                    if step.frame_depth > depth {
                        continue;
                    }
                    if step.frame_depth < depth {
                        return None;
                    }
                    if step.key.is_some() {
                        return Some(step.key);
                    }
                }
                None
            };
        let mut smoothed = Vec::new();
        for index in 0..self.steps.len() {
            let Some(key) = self.steps[index].key else {
                continue;
            };
            let Some(before) = neighbours(&self.steps, index, false) else {
                continue;
            };
            let Some(after) = neighbours(&self.steps, index, true) else {
                continue;
            };
            if before == after && before.is_some() && before != Some(key) {
                smoothed.push((index, before));
            }
        }
        for (index, key) in smoothed {
            self.steps[index].key = key;
        }
    }

    /// Marks the steps that begin a run of one line at their depth. Deeper frames and
    /// steps without a line do not end a run.
    fn mark_line_starts(&mut self) {
        let mut last_key_at_or_below = Vec::<Option<LineKey>>::new();
        for step in &mut self.steps {
            let depth = step.frame_depth as usize;
            if last_key_at_or_below.len() <= depth {
                last_key_at_or_below.resize(depth + 1, None);
            }
            let Some(key) = step.key else {
                step.line_start = false;
                continue;
            };
            step.line_start = last_key_at_or_below[depth] != Some(key);
            for entry in last_key_at_or_below.iter_mut().skip(depth) {
                *entry = Some(key);
            }
        }
    }

    #[must_use]
    pub fn contracts(&self) -> &[ContractDebugInfo] {
        &self.contracts
    }

    /// The contract whose code the step executes, when its debug info was loaded.
    #[must_use]
    pub fn contract_at_step(&self, step: usize) -> Option<&ContractDebugInfo> {
        self.contracts.get(self.steps.get(step)?.contract?)
    }

    #[must_use]
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Whether any step maps to a source line at all.
    #[must_use]
    pub fn has_source(&self) -> bool {
        self.steps.iter().any(|step| step.location.is_some())
    }

    /// The line a step counts as for stepping and breakpoints.
    #[must_use]
    pub fn line_key(&self, step: usize) -> Option<LineKey> {
        self.steps.get(step)?.key
    }

    #[must_use]
    pub fn frame_depth(&self, step: usize) -> Option<u32> {
        self.steps.get(step).map(|step| step.frame_depth)
    }

    #[must_use]
    pub fn is_line_start(&self, step: usize) -> bool {
        self.steps.get(step).is_some_and(|step| step.line_start)
    }

    #[must_use]
    pub fn is_frame_entry(&self, step: usize) -> bool {
        self.steps.get(step).is_some_and(|step| step.frame_entry)
    }

    /// The function the step runs in, including generated code for one of its statements.
    #[must_use]
    pub fn function_id(&self, step: usize) -> Option<FunctionId> {
        let location = self.steps.get(step)?.location?;
        location.function.map(|function| FunctionId {
            contract: location.key.contract,
            function,
        })
    }

    /// The address whose code the step executes, when it could be determined.
    #[must_use]
    pub fn executing_address(&self, step: usize) -> Option<&str> {
        let index = self.steps.get(step)?.address?;
        self.addresses.get(index).map(String::as_str)
    }

    /// The account whose storage the step reads and writes: the executing address, or
    /// the caller's under a `DELEGATECALL`.
    #[must_use]
    pub fn storage_address(&self, step: usize) -> Option<&str> {
        let index = self.storage_context_index(step)?;
        self.addresses.get(index).map(String::as_str)
    }

    /// An opaque identifier for that account, for indexing storage by context.
    #[must_use]
    pub fn storage_context_index(&self, step: usize) -> Option<usize> {
        self.steps.get(step)?.storage
    }

    /// Every EVM frame that reverted, as the step it was entered at and the step it
    /// reverted on. A frame's writes, and its callees', do not survive it.
    #[must_use]
    pub fn reverted_spans(&self) -> &[(usize, usize)] {
        &self.reverted
    }

    /// What this trace proved about where a contract's compiler leaves function
    /// parameters on the stack. `None` when the trace carried no frame that could show
    /// it, or when a frame contradicted it.
    #[must_use]
    pub fn argument_layout(&self, contract: usize) -> Option<ArgumentLayout> {
        self.argument_layouts.get(contract).copied()?.layout()
    }

    /// The variables of the function executing at `step`, inferred from the stack, or why
    /// none can be.
    ///
    /// Inference follows solc's legacy code generator, which keeps every variable at a
    /// fixed stack slot: the parameters below the entry height, and each return parameter
    /// and local at the slot the frame had when its declaration executed. A contract known
    /// to come from the via-IR pipeline, or whose trace shows that pipeline's calling
    /// convention, is not inferred. The result is a reading of the stack, not of compiler
    /// variable locations, and a frontend should say so; see [`INFERRED_LOCALS_WARNING`].
    #[must_use]
    pub fn locals_at(&self, step: usize) -> LocalsStatus<'_> {
        let Some(info) = self.steps.get(step) else {
            return LocalsStatus::Unavailable("the step is outside the trace");
        };
        let Some(contract) = info.contract else {
            return LocalsStatus::Unavailable(
                "no sources matched the contract executing at this step",
            );
        };
        if let Err(reason) = self.locals_support[contract] {
            return LocalsStatus::Unavailable(reason);
        }
        match self.step_variables.get(step).copied() {
            Some(INLINED_LAYOUT) => LocalsStatus::Unavailable(
                "this function was inlined by the optimizer, so its variables have no stack \
                 slots of their own",
            ),
            Some(id) if id != NO_LAYOUT => {
                LocalsStatus::Inferred(&self.variable_layouts[id as usize])
            }
            _ => LocalsStatus::Unavailable("no function is executing at this step"),
        }
    }

    /// The contract whose code declares the function executing at `step`: where a bare
    /// type name written in that function resolves.
    pub(crate) fn scope_at_step(&self, step: usize) -> Option<&str> {
        let info = self.steps.get(step)?;
        let contract = self.contracts.get(info.contract?)?;
        let function = contract.functions.get(info.location?.function?)?;
        contract
            .types
            .scope_at(function.source_id, function.declaration_start)
    }

    /// The value of `path` at `step`: a local variable in scope, or a member, element,
    /// mapping entry, or `length` reached from one, such as `item.tags[1]` or
    /// `stored.owners[0xabc]`. `None` when no local in scope has the path's first name,
    /// so the caller can look it up as a state variable instead; `Some(Err)` says why a
    /// local's path could not be followed.
    #[must_use]
    pub fn local_path(
        &self,
        trace: &TransactionTrace,
        step: usize,
        words: Option<&StorageWords<'_>>,
        path: &str,
    ) -> Option<Result<DebugVariable, String>> {
        let found = match self.local_place(trace, step, words, path)? {
            Ok(found) => found,
            Err(reason) => return Some(Err(reason)),
        };
        let (reader, slot, place) = found;
        let (ty, value) = match place {
            Ok(place) => (place.ty(), reader.show(&place)),
            Err((ty, shown)) => (ty, shown),
        };
        Some(Ok(DebugVariable {
            name: path.trim().to_owned(),
            ty,
            location: DebugLocation {
                kind: "stack".to_owned(),
                offset: slot as u64,
            },
            value,
        }))
    }

    /// The value of `path` as a breakpoint condition compares it; see
    /// [`StepMap::local_path`].
    #[must_use]
    pub fn local_condition_value(
        &self,
        trace: &TransactionTrace,
        step: usize,
        words: Option<&StorageWords<'_>>,
        path: &str,
    ) -> Option<Result<Value, String>> {
        let (reader, _, place) = match self.local_place(trace, step, words, path)? {
            Ok(found) => found,
            Err(reason) => return Some(Err(reason)),
        };
        Some(match place {
            Ok(place) => reader.condition_value(&place, path.trim()),
            Err((_, shown)) => Err(format!("`{}` is {}", path.trim(), shown.display)),
        })
    }

    /// Follows `path` from the local its first name names. The place is `Err` with the
    /// value to show when the variable's own words lead nowhere readable (memory the
    /// backend did not capture, a storage pointer without a layout), so a bare name still
    /// shows what `vars` would.
    #[allow(clippy::type_complexity)]
    fn local_place<'a>(
        &'a self,
        trace: &'a TransactionTrace,
        step: usize,
        words: Option<&'a StorageWords<'a>>,
        path: &str,
    ) -> Option<Result<(ValueReader<'a>, usize, Result<Place, (String, DebugValue)>), String>> {
        let LocalsStatus::Inferred(layout) = self.locals_at(step) else {
            return None;
        };
        let segments = parse_path(path).ok()?;
        let Some(PathSegment::Name(name)) = segments.first() else {
            return None;
        };
        // The last declared wins, as the innermost scope's does in the language.
        let variable = layout
            .iter()
            .rev()
            .find(|variable| variable.name == *name)?;
        let contract = self.contract_at_step(step)?;
        let snapshot = trace
            .steps
            .get(step)
            .map(soldb_core::TraceStep::snapshot_ref);
        let stack = snapshot.map_or(&[][..], |snapshot| snapshot.stack);
        let reader = ValueReader {
            memory: snapshot.and_then(|snapshot| snapshot.memory),
            calldata: calldata_for_step(trace, step),
            storage: words,
            layout: contract.storage_layout.as_ref(),
            types: &contract.types,
            scope: self.scope_at_step(step),
        };
        let Some(slot) = variable.slot else {
            return Some(Err(format!(
                "`{name}` is in scope but its stack slot could not be placed here"
            )));
        };
        let Some(stack_words) = stack.get(slot..slot + variable.words) else {
            return Some(Err(format!(
                "`{name}` is in scope but its stack slot is above the stack here"
            )));
        };
        let stack_words = stack_words.iter().map(|word| &**word).collect::<Vec<_>>();
        let mut place = match reader.root(&variable.ty, &stack_words) {
            Ok(place) => place,
            Err(shown) if segments.len() == 1 => {
                return Some(Ok((reader, slot, Err((variable.ty.clone(), shown)))));
            }
            Err(shown) => return Some(Err(format!("`{name}` is {}", shown.display))),
        };
        let mut so_far = name.clone();
        for segment in &segments[1..] {
            place = match reader.follow(place, segment, &so_far) {
                Ok(place) => place,
                Err(reason) => return Some(Err(reason)),
            };
            match segment {
                PathSegment::Member(member) => so_far = format!("{so_far}.{member}"),
                PathSegment::Index(key) => so_far = format!("{so_far}[{key}]"),
                PathSegment::Name(_) => {}
            }
        }
        Some(Ok((reader, slot, Ok(place))))
    }

    /// The inferred variables at `step`, read off its stack and decoded by type: a value
    /// type from its word, a reference type through the memory, storage, or calldata its
    /// word points into. `words` are the storage words known at the step, for storage
    /// pointers; without them a storage pointer is shown as its slot.
    ///
    /// A variable whose slot is not known, or lies above the stack, is reported as
    /// unavailable rather than as a wrong word.
    #[must_use]
    pub fn inferred_variables(
        &self,
        trace: &TransactionTrace,
        step: usize,
        words: Option<&StorageWords<'_>>,
    ) -> Vec<DebugVariable> {
        let LocalsStatus::Inferred(layout) = self.locals_at(step) else {
            return Vec::new();
        };
        let Some(contract) = self.contract_at_step(step) else {
            return Vec::new();
        };
        let snapshot = trace
            .steps
            .get(step)
            .map(soldb_core::TraceStep::snapshot_ref);
        let stack = snapshot.map_or(&[][..], |snapshot| snapshot.stack);
        let reader = ValueReader {
            memory: snapshot.and_then(|snapshot| snapshot.memory),
            calldata: calldata_for_step(trace, step),
            storage: words,
            layout: contract.storage_layout.as_ref(),
            types: &contract.types,
            scope: self.scope_at_step(step),
        };
        let unavailable = || DebugValue {
            display: "<unavailable>".to_owned(),
            raw: None,
            status: DebugValueStatus::Unavailable,
        };
        layout
            .iter()
            .map(|variable| {
                let words = variable
                    .slot
                    .and_then(|slot| stack.get(slot..slot + variable.words))
                    .map(|words| words.iter().map(|word| &**word).collect::<Vec<_>>());
                let value = match words {
                    Some(words) => reader.variable(&variable.ty, &words),
                    None => unavailable(),
                };
                DebugVariable {
                    name: variable.name.clone(),
                    ty: variable.ty.clone(),
                    location: DebugLocation {
                        kind: "stack".to_owned(),
                        offset: variable.slot.unwrap_or_default() as u64,
                    },
                    value,
                }
            })
            .collect()
    }

    /// The arguments `frame` was entered with, given the stack at its entry step.
    ///
    /// Only a frame entered at its function's entry point carries them, and only once
    /// this trace has shown that the compiler leaves them there: which word is which
    /// parameter depends on the code generator, and a legacy public function is entered
    /// through a dispatcher wrapper that has not decoded them yet. See
    /// [`StepMap::argument_layout`].
    #[must_use]
    pub fn frame_arguments(&self, frame: &Frame, state: FrameState<'_>) -> Vec<FrameArgument> {
        let Some(info) = self.steps.get(frame.entry_step) else {
            return Vec::new();
        };
        let Some(location) = info.location else {
            return Vec::new();
        };
        let Some(function_index) = location.function else {
            return Vec::new();
        };
        let Some(contract) = self.contracts.get(location.key.contract) else {
            return Vec::new();
        };
        if contract.function_entry_at_pc(self.pcs[frame.entry_step]) != Some(function_index) {
            return Vec::new();
        }
        let Some(function) = contract.functions.get(function_index) else {
            return Vec::new();
        };
        let Some(layout) = self.argument_layout(location.key.contract) else {
            return Vec::new();
        };
        decode_arguments(
            &function.params,
            state,
            layout,
            &contract.types,
            contract
                .types
                .scope_at(function.source_id, function.declaration_start),
        )
    }

    #[must_use]
    pub fn location(&self, step: usize) -> Option<StepLocation> {
        let info = self.steps.get(step)?;
        self.describe(&info.location?, info.generated)
    }

    fn describe(&self, location: &LocationRef, generated: bool) -> Option<StepLocation> {
        let contract = self.contracts.get(location.key.contract)?;
        let function = location
            .function
            .and_then(|index| contract.functions.get(index));
        Some(StepLocation {
            key: location.key,
            generated,
            contract_name: contract.name.clone(),
            path: contract
                .source_path(location.key.source_id)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("source:{}", location.key.source_id)),
            offset: location.offset,
            length: location.length,
            line: location.key.line,
            column: contract
                .column_of(location.key.source_id, location.offset)
                .unwrap_or(0),
            function: location.function.map(|function| FunctionId {
                contract: location.key.contract,
                function,
            }),
            function_name: function.map(|function| function.name.clone()),
        })
    }

    /// The step where the next source line begins at this frame or a caller's, stepping
    /// over calls. `None` when the recording ends first.
    ///
    /// Steps the compiler attached no source to, such as generated helper code, never
    /// stop a line step at the same depth: they belong to whatever line is executing.
    ///
    /// From code outside every function, such as the dispatcher, this enters the function
    /// it jumps to instead of stepping over it: there is no caller to come back to, and
    /// a user at the first step wants to reach the first line, not the last.
    #[must_use]
    pub fn next_source(&self, step: usize) -> Option<usize> {
        let current = *self.steps.get(step)?;
        if self.outside_functions(&current) {
            return self.step_into(step);
        }
        let key = current.key;
        ((step + 1)..self.steps.len()).find(|&index| {
            let candidate = &self.steps[index];
            if candidate.frame_depth > current.frame_depth {
                return false;
            }
            candidate.frame_depth < current.frame_depth
                || candidate
                    .key
                    .is_some_and(|candidate| Some(candidate) != key)
        })
    }

    /// The step where the next source line begins anywhere, entering calls. A call into
    /// code without source stops at its first step, so the user sees where they are.
    #[must_use]
    pub fn step_into(&self, step: usize) -> Option<usize> {
        let current = *self.steps.get(step)?;
        let key = current.key;
        ((step + 1)..self.steps.len()).find(|&index| {
            let candidate = &self.steps[index];
            candidate.frame_depth != current.frame_depth
                || candidate
                    .key
                    .is_some_and(|candidate| Some(candidate) != key)
        })
    }

    /// The step where the current frame has returned to its caller.
    #[must_use]
    pub fn finish(&self, step: usize) -> Option<usize> {
        let current = *self.steps.get(step)?;
        ((step + 1)..self.steps.len())
            .find(|&index| self.steps[index].frame_depth < current.frame_depth)
    }

    /// The start of the previous source line at this frame or a caller's, skipping the
    /// calls it made. From the middle of a line this is the start of that line. From code
    /// outside every function it enters the function that just returned, the mirror of
    /// [`StepMap::next_source`].
    #[must_use]
    pub fn previous_source(&self, step: usize) -> Option<usize> {
        let current = *self.steps.get(step)?;
        if self.outside_functions(&current) {
            return self.reverse_step_into(step);
        }
        self.previous_line_start(step, true)
    }

    /// The start of the previous source line anywhere, entering the calls it made.
    #[must_use]
    pub fn reverse_step_into(&self, step: usize) -> Option<usize> {
        self.steps.get(step)?;
        self.previous_line_start(step, false)
    }

    fn previous_line_start(&self, step: usize, skip_deeper: bool) -> Option<usize> {
        let current = self.steps[step];
        // From a step without a line, the previous line is the nearest step with one.
        let anchor = if current.key.is_some() {
            step
        } else {
            self.previous_mapped(step, current.frame_depth, skip_deeper)?
        };
        let start = self.run_start(anchor, skip_deeper);
        if start < step {
            return Some(start);
        }
        let previous = self.previous_mapped(start, current.frame_depth, skip_deeper)?;
        Some(self.run_start(previous, skip_deeper))
    }

    /// The step in the caller that entered the current frame.
    #[must_use]
    pub fn reverse_finish(&self, step: usize) -> Option<usize> {
        let current = *self.steps.get(step)?;
        (0..step)
            .rev()
            .find(|&index| self.steps[index].frame_depth < current.frame_depth)
    }

    /// The first step of the run of one line that `step` belongs to. With `skip_deeper`,
    /// steps in frames the line called into do not break the run; steps without source at
    /// the same depth never do.
    fn run_start(&self, step: usize, skip_deeper: bool) -> usize {
        let info = self.steps[step];
        let key = info.key;
        let mut current = step;
        while let Some(previous) = self.previous_mapped(current, info.frame_depth, skip_deeper) {
            let candidate = self.steps[previous];
            if candidate.frame_depth != info.frame_depth || candidate.key != key {
                break;
            }
            current = previous;
        }
        current
    }

    /// Whether a step is in code that belongs to no line: the dispatcher before the
    /// function it jumps to, or after that function returned.
    fn outside_functions(&self, info: &StepInfo) -> bool {
        info.location.is_some() && info.key.is_none()
    }

    /// The nearest earlier step with a source location at `depth` or, with `skip_deeper`,
    /// at most `depth`; without it, the nearest earlier mapped step at any depth.
    fn previous_mapped(&self, step: usize, depth: u32, skip_deeper: bool) -> Option<usize> {
        (0..step).rev().find(|&index| {
            let candidate = &self.steps[index];
            candidate.key.is_some() && (!skip_deeper || candidate.frame_depth <= depth)
        })
    }

    /// Resolves a `file:line` breakpoint against every loaded source. With no file, the
    /// line must be unambiguous across the loaded sources.
    pub fn resolve_line(&self, file: Option<&str>, line: u64) -> Result<Vec<ResolvedLine>, String> {
        let mut sources = Vec::<(usize, u64, String)>::new();
        for (contract_index, contract) in self.contracts.iter().enumerate() {
            for (source_id, path) in &contract.info.sources {
                if file.is_none_or(|file| source_path_matches(path, file)) {
                    sources.push((contract_index, *source_id, path.clone()));
                }
            }
        }
        if sources.is_empty() {
            return Err(match file {
                Some(file) => format!("source file not found: {file}"),
                None => "no source files are available".to_owned(),
            });
        }
        if file.is_none() {
            let mut paths = sources.iter().map(|(_, _, path)| path).collect::<Vec<_>>();
            paths.sort();
            paths.dedup();
            if paths.len() > 1 {
                return Err("line breakpoint is ambiguous; use break <file>:<line>".to_owned());
            }
        }

        let mut resolved = sources
            .into_iter()
            .filter_map(|(contract_index, source_id, path)| {
                let effective = self.contracts[contract_index].effective_line(source_id, line)?;
                Some(ResolvedLine {
                    key: LineKey {
                        contract: contract_index,
                        source_id,
                        line: effective,
                    },
                    path,
                    requested_line: line,
                })
            })
            .collect::<Vec<_>>();
        if resolved.is_empty() {
            return Err(match file {
                Some(file) => format!("no instruction maps to {file}:{line}"),
                None => format!("no instruction maps to line {line}"),
            });
        }
        // A contract's creation and deployed programs share their sources but map different
        // lines: a constructor body has code only in the creation program. Where any program
        // maps the line itself, the others' fallback to the statement containing it would
        // stop somewhere the user did not ask for, so only the exact matches are kept.
        if resolved.iter().any(|candidate| candidate.key.line == line) {
            resolved.retain(|candidate| candidate.key.line == line);
        }
        Ok(resolved)
    }

    /// Resolves a function breakpoint by name, optionally qualified as
    /// `Contract.function`.
    pub fn resolve_function(&self, name: &str) -> Result<Vec<ResolvedFunction>, String> {
        let (contract_name, function_name) = match name.rsplit_once('.') {
            Some((contract, function)) => (Some(contract), function),
            None => (None, name),
        };
        let resolved = self
            .contracts
            .iter()
            .enumerate()
            .filter(|(_, contract)| contract_name.is_none_or(|name| contract.name == name))
            .flat_map(|(contract_index, contract)| {
                contract
                    .functions
                    .iter()
                    .enumerate()
                    .filter(move |(_, function)| function.name == function_name)
                    .map(move |(function_index, function)| ResolvedFunction {
                        id: FunctionId {
                            contract: contract_index,
                            function: function_index,
                        },
                        name: function.name.clone(),
                        contract_name: contract.name.clone(),
                        path: contract
                            .source_path(function.source_id)
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!("source:{}", function.source_id)),
                        line: function.declaration_line,
                    })
            })
            .collect::<Vec<_>>();
        if resolved.is_empty() {
            return Err(format!("no function named `{name}` in the loaded sources"));
        }
        Ok(resolved)
    }

    /// The call structure at `step`, innermost frame first.
    #[must_use]
    pub fn frames(&self, step: usize) -> Vec<Frame> {
        struct Record {
            entry_step: usize,
            last_step: usize,
            external: bool,
        }
        if step >= self.steps.len() {
            return Vec::new();
        }
        let mut stack = Vec::<Record>::new();
        for (index, info) in self.steps.iter().enumerate().take(step + 1) {
            let depth = info.frame_depth as usize;
            stack.truncate(depth + 1);
            // Frames entered at this step. When an external call and a function both begin
            // here, the outer one is the call.
            let entered_call = index == 0 || info.evm_depth > self.steps[index - 1].evm_depth;
            let mut first_new = true;
            while stack.len() <= depth {
                stack.push(Record {
                    entry_step: index,
                    last_step: index,
                    external: first_new && entered_call,
                });
                first_new = false;
            }
            if let Some(top) = stack.last_mut() {
                top.last_step = index;
            }
        }

        stack
            .iter()
            .enumerate()
            .rev()
            .map(|(depth, record)| {
                let info = self.steps[record.last_step];
                let location = info
                    .location
                    .and_then(|location| self.describe(&location, info.generated));
                Frame {
                    depth: depth as u32,
                    external: record.external,
                    address: info
                        .address
                        .and_then(|index| self.addresses.get(index))
                        .cloned(),
                    contract_name: info
                        .contract
                        .and_then(|index| self.contracts.get(index))
                        .map(|contract| contract.name.clone()),
                    function_name: location
                        .as_ref()
                        .and_then(|location| location.function_name.clone()),
                    entry_step: record.entry_step,
                    step: record.last_step,
                    pc: self.pcs[record.last_step],
                    location,
                    arguments: Vec::new(),
                }
            })
            .collect()
    }

    /// The source around `step`: `radius` lines on each side of its line.
    #[must_use]
    pub fn source_listing(&self, step: usize, radius: u64) -> Option<SourceListing> {
        let location = self.steps.get(step)?.location?;
        let contract = self.contracts.get(location.key.contract)?;
        let count = contract.line_count(location.key.source_id)?;
        let first = location.key.line.saturating_sub(radius).max(1);
        let last = location.key.line.saturating_add(radius).min(count);
        let lines = (first..=last)
            .filter_map(|line| {
                contract
                    .line_text(location.key.source_id, line)
                    .map(|text| (line, text.to_owned()))
            })
            .collect();
        Some(SourceListing {
            path: contract
                .source_path(location.key.source_id)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("source:{}", location.key.source_id)),
            current_line: location.key.line,
            lines,
        })
    }
}

/// Proves, per contract, whether its compiler leaves function parameters on top of the
/// stack at a function's entry point, and in which order.
///
/// The evidence is a frame whose arguments the trace already tells us: the first function
/// entered in an EVM frame whose calldata is known is the function that calldata selected,
/// so its arguments are the calldata words. Comparing those with the words on the entry
/// stack shows whether the parameters are there at all, and with more than one parameter,
/// which end the first one is at. Only frames whose parameters are all value types are
/// used, since each is then exactly one word.
///
/// A frame that disagrees contradicts the whole contract: solc's legacy pipeline enters a
/// public function through a dispatcher wrapper that has not decoded the arguments yet, so
/// the words on top there are not the parameters, and nothing about that contract's frames
/// can be trusted to hold them.
fn prove_argument_layouts(
    trace: &TransactionTrace,
    contracts: &[ContractDebugInfo],
    framed: &[FramedStep],
) -> Vec<Evidence> {
    let mut evidence = vec![Evidence::Unknown; contracts.len()];
    if contracts.is_empty() || framed.is_empty() {
        return evidence;
    }
    // The calldata each EVM frame was entered with: the transaction's input at the root,
    // and the recorded input of a call for a nested frame.
    let mut calldata_by_entry = HashMap::<usize, &str>::new();
    calldata_by_entry.insert(0, trace.input_data.as_str());
    for call in &trace.artifacts.calls {
        if let Some(entry_step) = call.entry_step {
            calldata_by_entry.insert(entry_step, call.input.as_str());
        }
    }

    let mut examined = std::collections::HashSet::<u32>::new();
    let mut frame_calldata = HashMap::<u32, &str>::new();
    for (index, step) in framed.iter().enumerate() {
        let entered = index == 0 || framed[index - 1].frame_id != step.frame_id;
        if entered {
            if let Some(calldata) = calldata_by_entry.get(&index) {
                frame_calldata.insert(step.frame_id, calldata);
            }
        }
        let (Some(contract_index), Some(function_index)) = (step.contract, step.entry) else {
            continue;
        };
        // Only the first function entered in an EVM frame: a later one was called from
        // inside the code, not by this calldata.
        if !examined.insert(step.frame_id) {
            continue;
        }
        let Some(calldata) = frame_calldata.get(&step.frame_id) else {
            continue;
        };
        let Some(function) = contracts[contract_index].functions.get(function_index) else {
            continue;
        };
        let stack = trace.steps[index].snapshot_ref().stack;
        let observed = argument_evidence(function, calldata, stack);
        evidence[contract_index] = evidence[contract_index].merge(observed);
    }
    evidence
}

/// What one frame's entry stack says, given the calldata that selected its function.
///
/// Every parameter takes one head word in the calldata and one word on the stack, so the
/// two line up position by position. Only the value-type positions can be compared — a
/// reference parameter is a calldata offset in one and a memory pointer in the other —
/// and that is enough as long as one of them sits at a different depth under the two
/// orders.
fn argument_evidence(function: &SourceFunction, calldata: &str, stack: &[StackWord]) -> Evidence {
    let count = function.params.len();
    if count == 0 || stack.len() < count {
        return Evidence::Unknown;
    }
    // A parameter whose width is uncertain would misalign every position after it.
    if !function.params.iter().all(readable_parameter) {
        return Evidence::Unknown;
    }
    let signature = format!(
        "{}({})",
        function.name,
        function
            .params
            .iter()
            .map(|param| canonical_value_type(&param.ty))
            .collect::<Vec<_>>()
            .join(",")
    );
    let Ok(selector) = function_selector(&signature) else {
        return Evidence::Unknown;
    };
    let data = calldata.trim_start_matches("0x");
    let Some((encoded_selector, arguments)) = data.split_at_checked(8) else {
        return Evidence::Unknown;
    };
    // A different function's calldata says nothing about this frame.
    if encoded_selector.to_ascii_lowercase() != hex_bytes(&selector) {
        return Evidence::Unknown;
    }
    let expected = (0..count)
        .map(|index| {
            arguments
                .get(index * 64..(index + 1) * 64)
                .map(str::to_ascii_lowercase)
        })
        .collect::<Option<Vec<_>>>();
    let Some(expected) = expected else {
        return Evidence::Unknown;
    };
    // The positions whose calldata word is the argument itself, rather than an offset to
    // it.
    let checkable = (0..count)
        .filter(|index| is_value_type(&function.params[*index].ty))
        .collect::<Vec<_>>();
    if checkable.is_empty() {
        return Evidence::Unknown;
    }
    let matches = |order: ArgumentOrder| {
        checkable.iter().all(|index| {
            let candidate = &stack[order.word_index(*index, count, stack.len())];
            normalize_word(candidate) == expected[*index]
        })
    };
    // A position at the same depth under both orders proves nothing about the order.
    let distinguishing = checkable.iter().any(|index| {
        ArgumentOrder::FirstOnTop.word_index(*index, count, stack.len())
            != ArgumentOrder::LastOnTop.word_index(*index, count, stack.len())
    });
    let first = matches(ArgumentOrder::FirstOnTop);
    let last = matches(ArgumentOrder::LastOnTop);
    match (first, last) {
        // Both orders agree where they could be told apart: the arguments are on top, but
        // which is which is still open.
        (true, true) => Evidence::TopWords,
        (true, false) if distinguishing => Evidence::Ordered(ArgumentOrder::FirstOnTop),
        (false, true) if distinguishing => Evidence::Ordered(ArgumentOrder::LastOnTop),
        // One order matched only because the other was never tested where they differ.
        (true, false) | (false, true) => Evidence::TopWords,
        // The arguments are not on the entry stack: this is not where they live.
        (false, false) => Evidence::Contradicted,
    }
}

/// The ABI name of a value type as written in the source: the bare integer names are
/// their 256-bit forms, and `address payable` encodes as `address`.
fn canonical_value_type(ty: &str) -> String {
    match ty {
        "uint" => "uint256".to_owned(),
        "int" => "int256".to_owned(),
        "address payable" => "address".to_owned(),
        other => other.to_owned(),
    }
}

/// A stack word as 64 lowercase hex digits, however the backend spelled it.
fn normalize_word(word: &str) -> String {
    let digits = word.trim_start_matches("0x").trim_start_matches('0');
    format!("{:0>64}", digits.to_ascii_lowercase())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The code address a call instruction targets, read off its stack.
#[must_use]
pub fn call_target(step: &soldb_core::TraceStep) -> Option<String> {
    if !CALL_OPCODES.contains(&&*step.op) {
        return None;
    }
    let stack = step.snapshot_ref().stack;
    let word = stack.get(stack.len().checked_sub(2)?)?;
    address_from_word(word)
}

/// The address in the low 20 bytes of a stack word, or `None` for the zero address or a
/// word that is not hex.
#[must_use]
pub fn address_from_word(word: &str) -> Option<String> {
    let hex = word.trim_start_matches("0x");
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let padded = format!("{hex:0>40}");
    let address = padded.get(padded.len() - 40..)?;
    if address.bytes().all(|byte| byte == b'0') {
        return None;
    }
    Some(format!("0x{}", address.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use soldb_core::{ContractCreation, ExecutionCall, StepSnapshot, TraceStep, TransactionTrace};
    use soldb_ethdebug::{function_selector, CodeGenerator, EthdebugInfo, Instruction};

    use soldb_core::Word as StackWord;

    use crate::FrameState;

    use super::{
        address_from_word, normalize_address, ArgumentLayout, ArgumentOrder, ContractDebugInfo,
        InferredVariable, JumpMarker, LineKey, LocalsStatus, StepMap, VariableKind,
    };

    // Two functions; `outer` calls `inner` internally. Line numbers are one-based.
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

    fn offset_of(needle: &str) -> u64 {
        SOURCE.find(needle).expect(needle) as u64
    }

    fn instruction(pc: u64, offset: u64, length: u64) -> Instruction {
        instruction_with(pc, offset, length, json!({}))
    }

    /// An instruction with extra ETHDebug context, such as a jump marker.
    fn instruction_with(
        pc: u64,
        offset: u64,
        length: u64,
        extra: serde_json::Value,
    ) -> Instruction {
        let mut context =
            json!({"code": {"source": {"id": 0}, "range": {"offset": offset, "length": length}}});
        for (key, value) in extra.as_object().expect("object") {
            context[key] = value.clone();
        }
        serde_json::from_value(json!({
            "offset": pc,
            "operation": {"mnemonic": "JUMPDEST"},
            "context": context
        }))
        .expect("instruction")
    }

    fn contract(address: Option<&str>) -> ContractDebugInfo {
        let whole = SOURCE.len() as u64;
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "C".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![
                // Dispatcher: the whole-contract span.
                instruction(0, 0, whole),
                instruction(1, 0, whole),
                // outer's declaration, then its three statements.
                instruction(10, offset_of("function outer"), 90),
                instruction(11, offset_of("uint256 b = a + 1;"), 18),
                instruction(12, offset_of("inner(b);"), 9),
                instruction(13, offset_of("inner(b);"), 9),
                instruction(14, offset_of("b = 0;"), 6),
                // inner's declaration and body.
                instruction(20, offset_of("function inner"), 50),
                instruction(21, offset_of("x += 1;"), 7),
                // Back in the dispatcher.
                instruction(30, 0, whole),
                // A generated helper, carrying the whole-contract span like the dispatcher.
                instruction(40, 0, whole),
            ],
            sources: BTreeMap::from([(0, "C.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        ContractDebugInfo::new(address, "C", info, BTreeMap::from([(0, SOURCE.to_owned())]))
    }

    fn step(pc: u64, depth: u64, op: &str, stack: &[&str]) -> TraceStep {
        TraceStep {
            pc,
            op: op.into(),
            gas: 0,
            gas_cost: 0,
            depth,
            stack: stack.iter().map(|word| StackWord::from(*word)).collect(),
            memory: None,
            storage: None,
            error: None,
            snapshot: StepSnapshot::default(),
        }
    }

    fn trace(steps: Vec<TraceStep>) -> TransactionTrace {
        TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: Some("0xAAaa000000000000000000000000000000000001".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 0,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps,
        }
    }

    // Steps: dispatcher (0,1), outer decl (2), line 3 (3), line 4 before the call (4),
    // inner decl (5), inner line 8 (6, 7), back on line 4 (8), line 5 (9), dispatcher (10).
    fn outer_calls_inner() -> TransactionTrace {
        trace(vec![
            step(0, 1, "PUSH1", &[]),
            step(1, 1, "JUMPI", &[]),
            step(10, 1, "JUMPDEST", &[]),
            step(11, 1, "ADD", &[]),
            step(12, 1, "PUSH1", &[]),
            step(20, 1, "JUMPDEST", &[]),
            step(21, 1, "ADD", &[]),
            step(21, 1, "SWAP1", &[]),
            step(13, 1, "JUMPDEST", &[]),
            step(14, 1, "POP", &[]),
            step(30, 1, "STOP", &[]),
        ])
    }

    // A contract whose functions take two parameters, so the order they are passed in
    // can be told apart.
    const PAY_SOURCE: &str = "\
contract P {
    function pay(address to, uint256 amount) public {
        total(to, amount);
    }
    function total(address to, uint256 amount) internal {
        amount += 1;
    }
}
";

    fn pay_contract() -> ContractDebugInfo {
        let whole = PAY_SOURCE.len() as u64;
        let at = |needle: &str| PAY_SOURCE.find(needle).expect(needle) as u64;
        let span = |pc: u64, offset: u64, length: u64| {
            serde_json::from_value::<Instruction>(json!({
                "offset": pc,
                "operation": {"mnemonic": "JUMPDEST"},
                "context": {"code": {
                    "source": {"id": 0},
                    "range": {"offset": offset, "length": length}
                }}
            }))
            .expect("instruction")
        };
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "P".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![
                span(0, 0, whole),
                span(10, at("function pay"), 80),
                span(11, at("total(to, amount);"), 18),
                span(20, at("function total"), 70),
                span(21, at("amount += 1;"), 12),
            ],
            sources: BTreeMap::from([(0, "P.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        ContractDebugInfo::new(
            None,
            "P",
            info,
            BTreeMap::from([(0, PAY_SOURCE.to_owned())]),
        )
    }

    fn word_of(value: &str) -> StackWord {
        StackWord::from(format!("0x{:0>64}", value.trim_start_matches("0x")).as_str())
    }

    /// A call to `pay(to, amount)` that calls `total(to, amount)` internally, with the
    /// entry stacks the caller chooses, bottom-first as a backend reports them.
    fn pay_trace(entry_stack: &[StackWord], inner_stack: &[StackWord]) -> TransactionTrace {
        let selector = soldb_ethdebug::function_selector("pay(address,uint256)").expect("selector");
        let calldata = format!(
            "0x{}{}{}",
            selector
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            &word_of(PAY_TO)[2..],
            &word_of(PAY_AMOUNT)[2..]
        );
        fn borrow(stack: &[StackWord]) -> Vec<&str> {
            stack.iter().map(|word| &**word).collect()
        }
        let mut trace = trace(vec![
            step(0, 1, "PUSH1", &[]),
            step(10, 1, "JUMPDEST", &borrow(entry_stack)),
            step(11, 1, "JUMP", &borrow(inner_stack)),
            step(20, 1, "JUMPDEST", &borrow(inner_stack)),
            step(21, 1, "ADD", &[]),
        ]);
        trace.input_data = calldata;
        trace
    }

    const PAY_TO: &str = "00000000000000000000000000000000000000aa";
    const PAY_AMOUNT: &str = "7";

    #[test]
    fn the_trace_proves_which_end_the_first_argument_is_at() {
        let to = word_of(PAY_TO);
        let amount = word_of(PAY_AMOUNT);
        let tag = word_of("2a");

        // via-IR pushes the parameters right to left, so the first is on top.
        let first_on_top = [tag.clone(), amount.clone(), to.clone()];
        let trace = pay_trace(&first_on_top, &first_on_top);
        let map = StepMap::new(&trace, vec![pay_contract()]);
        assert_eq!(
            map.argument_layout(0),
            Some(ArgumentLayout::Ordered(ArgumentOrder::FirstOnTop))
        );
        let frames = map.frames(4);
        let inner = frames.first().expect("innermost frame");
        assert_eq!(inner.function_name.as_deref(), Some("total"));
        let arguments = map.frame_arguments(
            inner,
            FrameState {
                stack: &first_on_top,
                memory: None,
            },
        );
        assert_eq!(
            arguments
                .iter()
                .map(|argument| format!("{} = {}", argument.name, argument.value.display))
                .collect::<Vec<_>>(),
            [
                "to = 0x00000000000000000000000000000000000000aa".to_owned(),
                "amount = 7".to_owned()
            ]
        );

        // The legacy pipeline pushes them left to right, so the last is on top.
        let last_on_top = [tag.clone(), to.clone(), amount.clone()];
        let trace = pay_trace(&last_on_top, &last_on_top);
        let map = StepMap::new(&trace, vec![pay_contract()]);
        assert_eq!(
            map.argument_layout(0),
            Some(ArgumentLayout::Ordered(ArgumentOrder::LastOnTop))
        );
        let frames = map.frames(4);
        let arguments = map.frame_arguments(
            frames.first().expect("frame"),
            FrameState {
                stack: &last_on_top,
                memory: None,
            },
        );
        assert_eq!(
            arguments[0].value.display,
            "0x00000000000000000000000000000000000000aa"
        );
        assert_eq!(arguments[1].value.display, "7");

        // A frame entered through a dispatcher wrapper does not hold the arguments yet.
        // That contradicts the whole contract: nothing is reported for any frame of it.
        let wrapper = [tag.clone(), word_of("dead"), word_of("beef")];
        let trace = pay_trace(&wrapper, &first_on_top);
        let map = StepMap::new(&trace, vec![pay_contract()]);
        assert_eq!(map.argument_layout(0), None);
        let frames = map.frames(4);
        assert!(map
            .frame_arguments(
                frames.first().expect("frame"),
                FrameState {
                    stack: &first_on_top,
                    memory: None
                }
            )
            .is_empty());

        // Without the calldata to compare against, nothing is proven and nothing shown.
        let mut unknown = pay_trace(&first_on_top, &first_on_top);
        unknown.input_data = "0x".to_owned();
        let map = StepMap::new(&unknown, vec![pay_contract()]);
        assert_eq!(map.argument_layout(0), None);
        let frames = map.frames(4);
        assert!(map
            .frame_arguments(
                frames.first().expect("frame"),
                FrameState {
                    stack: &first_on_top,
                    memory: None
                }
            )
            .is_empty());
    }

    #[test]
    fn one_parameter_is_on_top_under_either_order() {
        // `outer(uint256 a)` takes one parameter: matching it against the calldata shows
        // the arguments are on the entry stack, which is all a one-parameter frame needs.
        let mut trace = outer_calls_inner();
        let selector = soldb_ethdebug::function_selector("outer(uint256)").expect("selector");
        let amount = word_of("5");
        trace.input_data = format!(
            "0x{}{}",
            selector
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            &amount[2..]
        );
        let stack = [word_of("2a"), amount.clone()];
        trace.steps[2].snapshot =
            StepSnapshot::new(stack.to_vec(), None, BTreeMap::new(), BTreeMap::new());
        let map = StepMap::new(&trace, vec![contract(None)]);
        assert_eq!(map.argument_layout(0), Some(ArgumentLayout::TopWords));
        let frames = map.frames(3);
        let outer = frames
            .iter()
            .find(|frame| frame.function_name.as_deref() == Some("outer"))
            .expect("outer frame");
        let arguments = map.frame_arguments(
            outer,
            FrameState {
                stack: &stack,
                memory: None,
            },
        );
        assert_eq!(arguments.len(), 1);
        assert_eq!(arguments[0].name, "a");
        assert_eq!(arguments[0].value.display, "5");

        // Two parameters need the order, which one parameter cannot show.
        let map = StepMap::new(&trace, vec![pay_contract()]);
        assert_eq!(map.argument_layout(0), None);
    }

    fn key(line: u64) -> Option<LineKey> {
        Some(LineKey {
            contract: 0,
            source_id: 0,
            line,
        })
    }

    #[test]
    fn maps_steps_to_lines_and_infers_internal_frames() {
        let map = StepMap::new(&outer_calls_inner(), vec![contract(None)]);
        assert!(map.has_source());
        // The dispatcher shows its span but counts as no line.
        assert_eq!(map.line_key(0), None);
        assert_eq!(map.location(0).expect("location").line, 1);
        assert!(!map.location(0).expect("location").generated);
        assert_eq!(map.line_key(2), key(2));
        assert_eq!(map.line_key(3), key(3));
        assert_eq!(map.line_key(4), key(4));
        assert_eq!(map.line_key(5), key(7));
        assert_eq!(map.line_key(6), key(8));
        assert_eq!(map.line_key(8), key(4));
        assert_eq!(map.line_key(10), None);

        // Dispatcher at depth 0, outer at 1, inner at 2, then back down.
        let depths = (0..11)
            .map(|step| map.frame_depth(step).expect("depth"))
            .collect::<Vec<_>>();
        assert_eq!(depths, vec![0, 0, 1, 1, 1, 2, 2, 2, 1, 1, 0]);
        assert!(map.is_frame_entry(2));
        assert!(map.is_frame_entry(5));
        assert!(!map.is_frame_entry(8));
        assert_eq!(
            map.location(6).expect("location").function_name.as_deref(),
            Some("inner")
        );
        assert_eq!(map.location(6).expect("location").path, "C.sol");
        assert_eq!(map.location(6).expect("location").column, 9);
    }

    #[test]
    fn next_steps_over_calls_and_step_enters_them() {
        let map = StepMap::new(&outer_calls_inner(), vec![contract(None)]);
        // From the dispatcher, the next line is outer's declaration.
        assert_eq!(map.next_source(0), Some(2));
        assert_eq!(map.next_source(2), Some(3));
        // Line 4 calls inner; `next` lands on line 5, `step` lands in inner.
        assert_eq!(map.next_source(4), Some(9));
        assert_eq!(map.step_into(4), Some(5));
        assert_eq!(map.step_into(5), Some(6));
        // Inside inner, `next` at its last line returns to the caller mid-line 4.
        assert_eq!(map.next_source(6), Some(8));
        assert_eq!(map.finish(6), Some(8));
        // Leaving outer lands in the dispatcher; nothing follows the last step.
        assert_eq!(map.next_source(9), Some(10));
        assert_eq!(map.finish(9), Some(10));
        assert_eq!(map.next_source(10), None);
        assert_eq!(map.finish(10), None);
    }

    #[test]
    fn reverse_stepping_lands_on_line_starts() {
        let map = StepMap::new(&outer_calls_inner(), vec![contract(None)]);
        // From line 5, reverse-next goes to the start of line 4, over the call.
        assert_eq!(map.previous_source(9), Some(4));
        // From the middle of a line, first to its start.
        assert_eq!(map.previous_source(7), Some(6));
        assert_eq!(map.previous_source(6), Some(5));
        // Reverse-step from line 5 enters inner's last line instead of skipping it.
        assert_eq!(map.reverse_step_into(9), Some(8));
        assert_eq!(map.reverse_step_into(8), Some(6));
        // Reverse-finish from inside inner returns to the call site.
        assert_eq!(map.reverse_finish(6), Some(4));
        assert_eq!(map.reverse_finish(0), None);
        assert_eq!(map.previous_source(0), None);
        // From the dispatcher after outer returned, reverse-next enters outer's last line
        // rather than skipping the whole function as one call.
        assert_eq!(map.previous_source(10), Some(9));
    }

    #[test]
    fn line_starts_skip_returns_into_the_middle_of_a_line() {
        let map = StepMap::new(&outer_calls_inner(), vec![contract(None)]);
        assert!(map.is_line_start(3));
        assert!(map.is_line_start(4));
        assert!(map.is_line_start(6));
        assert!(!map.is_line_start(7));
        // Step 8 resumes line 4 after inner returned: not a fresh entry to the line.
        assert!(!map.is_line_start(8));
        assert!(map.is_line_start(9));
    }

    #[test]
    fn resolves_line_and_function_breakpoints() {
        let map = StepMap::new(&outer_calls_inner(), vec![contract(None)]);
        let resolved = map.resolve_line(Some("C.sol"), 4).expect("line 4");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].key, key(4).unwrap());
        assert_eq!(resolved[0].path, "C.sol");
        // Without a file the single source is unambiguous.
        assert_eq!(
            map.resolve_line(None, 8).expect("line 8")[0].key,
            key(8).unwrap()
        );
        // A line with no code of its own resolves to the statement containing it: the
        // whole-contract span is the only one covering line 10, so it wins with line 1.
        assert_eq!(
            map.resolve_line(None, 10).expect("line 10")[0].key,
            key(1).unwrap()
        );
        assert_eq!(
            map.resolve_line(None, 99).expect_err("past the end"),
            "no instruction maps to line 99"
        );
        assert_eq!(
            map.resolve_line(Some("D.sol"), 1)
                .expect_err("unknown file"),
            "source file not found: D.sol"
        );

        let inner = map.resolve_function("inner").expect("inner");
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].line, 7);
        assert_eq!(inner[0].contract_name, "C");
        assert_eq!(
            map.resolve_function("C.outer").expect("qualified")[0].line,
            2
        );
        assert!(map.resolve_function("D.outer").is_err());
        assert!(map.resolve_function("missing").is_err());
    }

    #[test]
    fn frames_list_the_call_structure_innermost_first() {
        let map = StepMap::new(&outer_calls_inner(), vec![contract(None)]);
        let frames = map.frames(6);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].function_name.as_deref(), Some("inner"));
        assert_eq!(frames[0].depth, 2);
        assert!(!frames[0].external);
        assert_eq!(frames[0].step, 6);
        assert_eq!(frames[1].function_name.as_deref(), Some("outer"));
        assert_eq!(
            frames[1].location.as_ref().map(|location| location.line),
            Some(4)
        );
        assert_eq!(frames[1].step, 4);
        assert!(frames[2].external);
        assert_eq!(frames[2].depth, 0);
        assert_eq!(
            frames[2].address.as_deref(),
            Some("0xaaaa000000000000000000000000000000000001")
        );
        assert!(map.frames(99).is_empty());

        let listing = map.source_listing(6, 1).expect("listing");
        assert_eq!(listing.current_line, 8);
        assert_eq!(listing.lines.len(), 3);
        assert_eq!(listing.lines[1].0, 8);
        assert_eq!(listing.lines[1].1.trim(), "x += 1;");
    }

    #[test]
    fn external_calls_map_through_the_callee_contract() {
        // The root contract calls a second one; the callee's steps map through its info.
        let callee = "0xbbbb000000000000000000000000000000000002";
        let word = format!("0x{:0>64}", callee.trim_start_matches("0x"));
        let steps = vec![
            step(0, 1, "PUSH1", &[]),
            step(
                12,
                1,
                "CALL",
                &["0x0", "0x0", "0x0", "0x0", "0x0", &word, "0x0"],
            ),
            step(21, 2, "JUMPDEST", &[]),
            step(21, 2, "ADD", &[]),
            step(13, 1, "JUMPDEST", &[]),
            step(30, 1, "STOP", &[]),
        ];
        let root = contract(Some("0xAAAA000000000000000000000000000000000001"));
        let map = StepMap::new(&trace(steps), vec![root, contract(Some(callee))]);
        assert_eq!(
            map.executing_address(1),
            Some("0xaaaa000000000000000000000000000000000001")
        );
        assert_eq!(map.executing_address(2), Some(callee));
        assert_eq!(
            map.line_key(2),
            Some(LineKey {
                contract: 1,
                source_id: 0,
                line: 8
            })
        );
        assert_eq!(map.frame_depth(1), Some(1));
        // The callee has no dispatcher step here, so inner is entered straight away.
        assert_eq!(map.frame_depth(2), Some(3));
        assert!(map.is_frame_entry(2));
        assert_eq!(map.frame_depth(4), Some(1));
        // `next` over the external call skips the callee entirely.
        assert_eq!(map.next_source(1), Some(5));
        assert_eq!(map.step_into(1), Some(2));
        let frames = map.frames(2);
        assert_eq!(frames.len(), 4);
        assert!(frames[1].external);
        assert_eq!(frames[1].address.as_deref(), Some(callee));
        assert_eq!(frames[0].function_name.as_deref(), Some("inner"));
    }

    /// A program at `address` for one environment, mapping each listed program counter to
    /// the span of a source snippet.
    fn program(address: &str, environment: &str, spans: &[(u64, &str)]) -> ContractDebugInfo {
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "C".to_owned(),
            environment: environment.to_owned(),
            instructions: spans
                .iter()
                .map(|(pc, needle)| instruction(*pc, offset_of(needle), needle.len() as u64))
                .collect(),
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

    const ROOT: &str = "0xaaaa000000000000000000000000000000000001";
    const CREATED: &str = "0xcccc000000000000000000000000000000000003";

    fn creation(entry_step: usize, exit_step: usize, address: Option<&str>) -> ContractCreation {
        ContractCreation {
            id: 0,
            parent_id: None,
            depth: 2,
            entry_step: Some(entry_step),
            exit_step: Some(exit_step),
            create_type: "CREATE".to_owned(),
            caller: ROOT.to_owned(),
            address: address.map(str::to_owned),
            value: "0x0".to_owned(),
            init_code: "0x".to_owned(),
            gas_limit: 0,
            gas_used: None,
            output: None,
            success: Some(address.is_some()),
            error: None,
        }
    }

    fn call(
        id: usize,
        entry_step: usize,
        exit_step: usize,
        call_type: &str,
        bytecode_address: &str,
    ) -> ExecutionCall {
        ExecutionCall {
            id,
            parent_id: None,
            depth: 2,
            entry_step: Some(entry_step),
            exit_step: Some(exit_step),
            call_type: call_type.to_owned(),
            from: ROOT.to_owned(),
            to: ROOT.to_owned(),
            bytecode_address: bytecode_address.to_owned(),
            value: "0x0".to_owned(),
            input: "0x".to_owned(),
            gas_limit: 0,
            gas_used: None,
            output: None,
            success: Some(true),
            error: None,
        }
    }

    /// The root creates a contract, then calls it: steps 2 and 3 run the creation code,
    /// step 6 the deployed code.
    fn root_creates_then_calls() -> TransactionTrace {
        let word = format!("0x{:0>64}", CREATED.trim_start_matches("0x"));
        let mut trace = trace(vec![
            step(0, 1, "PUSH1", &[]),
            // A `CREATE` leaves no code address on the stack.
            step(12, 1, "CREATE", &["0x0", "0x0", "0x0"]),
            step(21, 2, "JUMPDEST", &[]),
            step(21, 2, "RETURN", &[]),
            step(13, 1, "JUMPDEST", &[]),
            step(
                14,
                1,
                "CALL",
                &["0x0", "0x0", "0x0", "0x0", "0x0", &word, "0x0"],
            ),
            step(21, 2, "JUMPDEST", &[]),
            step(30, 1, "STOP", &[]),
        ]);
        trace
            .artifacts
            .creations
            .push(creation(2, 4, Some(CREATED)));
        trace.artifacts.calls.push(call(0, 6, 7, "CALL", CREATED));
        trace
    }

    #[test]
    fn creations_map_through_the_created_contracts_creation_program() {
        let trace = root_creates_then_calls();
        // The creation program maps pc 21 into `inner`, the deployed program into `outer`,
        // so which one a step went through shows in its line. The order they are given in
        // does not decide it: the environment does.
        let deployed = program(CREATED, "call", &[(21, "b = 0;")]);
        let creation = program(CREATED, "create", &[(21, "x += 1;")]);
        let map = StepMap::new(&trace, vec![contract(Some(ROOT)), deployed, creation]);

        assert_eq!(map.executing_address(2), Some(CREATED));
        assert_eq!(map.storage_address(2), Some(CREATED));
        assert_eq!(
            map.line_key(2).map(|key| (key.contract, key.line)),
            Some((2, 8))
        );
        assert_eq!(
            map.line_key(6).map(|key| (key.contract, key.line)),
            Some((1, 5))
        );
        // Innermost first: `inner`, then the creation frame that entered it.
        let frames = map.frames(2);
        assert_eq!(frames[0].function_name.as_deref(), Some("inner"));
        assert!(frames[1].external);
        assert_eq!(frames[1].address.as_deref(), Some(CREATED));
        assert_eq!(map.frame_depth(4), Some(1));
    }

    #[test]
    fn a_line_resolves_only_in_the_programs_that_map_it() {
        // Both programs of the created contract see `C.sol`; only the creation program has
        // code on line 8, and the deployed program's whole-contract span must not turn the
        // breakpoint into a stop on line 1.
        let trace = root_creates_then_calls();
        let whole = SOURCE.len() as u64;
        let mut deployed = program(CREATED, "call", &[(21, "b = 0;")]);
        deployed.info.instructions.push(instruction(20, 0, whole));
        let mut creation = program(CREATED, "create", &[(21, "x += 1;")]);
        creation.info.instructions.push(instruction(20, 0, whole));
        let map = StepMap::new(&trace, vec![deployed, creation]);
        let resolved = map.resolve_line(Some("C.sol"), 8).expect("line 8");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].key.contract, 1);
        assert_eq!(resolved[0].key.line, 8);
        // A line no program maps still resolves to the statements containing it.
        let resolved = map.resolve_line(Some("C.sol"), 10).expect("line 10");
        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().all(|line| line.key.line == 1));
    }

    #[test]
    fn a_creation_uses_the_only_program_at_its_address() {
        // Only the deployed program is loaded: it still names the address's sources, and
        // describes the creation frame the way it did before environments were told apart.
        let trace = root_creates_then_calls();
        let deployed = program(CREATED, "call", &[(21, "b = 0;")]);
        let map = StepMap::new(&trace, vec![contract(Some(ROOT)), deployed]);
        assert_eq!(
            map.line_key(2).map(|key| (key.contract, key.line)),
            Some((1, 5))
        );
    }

    #[test]
    fn a_creation_the_backend_did_not_record_has_no_contract() {
        let mut trace = root_creates_then_calls();
        trace.artifacts.creations.clear();
        let creation = program(CREATED, "create", &[(21, "x += 1;")]);
        let map = StepMap::new(&trace, vec![contract(Some(ROOT)), creation]);
        assert_eq!(map.executing_address(2), None);
        assert_eq!(map.line_key(2), None);
        // The call is still resolved from the stack.
        assert_eq!(map.executing_address(6), Some(CREATED));
    }

    #[test]
    fn a_deployment_root_prefers_the_creation_program() {
        let mut trace = trace(vec![step(21, 1, "JUMPDEST", &[]), step(30, 1, "STOP", &[])]);
        trace.to_addr = None;
        trace.contract_address = Some(CREATED.to_owned());
        let deployed = program(CREATED, "call", &[(21, "b = 0;")]);
        let creation = program(CREATED, "create", &[(21, "x += 1;")]);
        let map = StepMap::new(&trace, vec![deployed, creation]);
        assert_eq!(
            map.line_key(0).map(|key| (key.contract, key.line)),
            Some((1, 8))
        );
    }

    #[test]
    fn frames_are_resolved_from_recorded_calls_before_the_stack() {
        let callee = "0xbbbb000000000000000000000000000000000002";
        let precompile = "0x0000000000000000000000000000000000000001";
        // No stack was recorded, so nothing can be read off the call instructions.
        let mut trace = trace(vec![
            step(0, 1, "PUSH1", &[]),
            step(11, 1, "STATICCALL", &[]),
            step(12, 1, "DELEGATECALL", &[]),
            step(21, 2, "JUMPDEST", &[]),
            step(21, 2, "ADD", &[]),
            step(13, 1, "JUMPDEST", &[]),
        ]);
        // The precompile ran no steps: it starts and ends at the caller's next step, and is
        // not the frame entered there.
        trace
            .artifacts
            .calls
            .push(call(0, 2, 2, "STATICCALL", precompile));
        trace
            .artifacts
            .calls
            .push(call(1, 3, 5, "DELEGATECALL", callee));
        let map = StepMap::new(&trace, vec![contract(Some(ROOT)), contract(Some(callee))]);

        assert_eq!(map.executing_address(2), Some(ROOT));
        assert_eq!(map.frame_depth(2), Some(1));
        assert_eq!(map.executing_address(3), Some(callee));
        assert_eq!(map.line_key(3).map(|key| key.contract), Some(1));
        // A delegated frame keeps its caller's storage.
        assert_eq!(map.storage_address(3), Some(ROOT));
    }

    /// A contract whose functions declare parameters, returns, block locals, and a
    /// modifier, laid out the way solc's legacy code generator attributes them.
    const LEGACY_SOURCE: &str = "contract L {
    uint256 total;
    modifier tracked(uint256 tag) {
        uint256 before = total;
        _;
        total = before + tag;
    }
    function outer(uint256 a) public returns (uint256 sum) {
        uint256 twice = a * 2;
        if (twice > 2) {
            uint256 inner = twice - 2;
            sum = inner;
        }
        sum = twice + helper(twice);
    }
    function helper(uint256 x) internal pure returns (uint256 r) {
        uint256 y = x + 1;
        r = y;
    }
    function guarded(uint256 v) public tracked(9) {
        uint256 kept = v;
        total = kept;
    }
    function set(uint256 v) public {
        total = v;
    }
    function take(bytes calldata data, uint256[] calldata items, uint256 n) public {
        total = n;
    }
}
";

    fn legacy_offset(needle: &str) -> u64 {
        LEGACY_SOURCE.find(needle).expect(needle) as u64
    }

    /// The program of `LEGACY_SOURCE`: each program counter carries the span of one
    /// source snippet, the way the compiler attributes reservations to declarations,
    /// initialisers to their expressions, and function entries to their headers.
    fn legacy_contract(code_generator: Option<CodeGenerator>) -> ContractDebugInfo {
        let spans: &[(u64, &str)] = &[
            (0, "contract L"),
            // outer: entry, the return's reservation, the local's, its initialiser,
            // the block's local, a statement after the block, the call, and the return.
            (10, "function outer"),
            (11, "uint256 sum"),
            (12, "uint256 twice"),
            (13, "a * 2"),
            (14, "twice > 2"),
            (15, "uint256 inner"),
            (16, "sum = inner"),
            (17, "helper(twice)"),
            (18, "sum = twice + helper(twice)"),
            (19, "function outer"),
            // helper: entry, its local, the assignment, its return, and the exit.
            (20, "function helper"),
            (21, "uint256 y"),
            (22, "r = y"),
            (23, "function helper"),
            (24, "uint256 r"),
            // guarded and its modifier: entry, the modifier's local, the body's, the
            // body's statement, the modifier's statement after `_`, and the dispatcher's
            // jump to the body tag with the body tag itself.
            (30, "function guarded"),
            (31, "uint256 before"),
            (32, "uint256 kept"),
            (33, "total = kept"),
            (34, "total = before + tag"),
            (35, "function guarded"),
            (36, "function guarded"),
            // set: entry, its only statement, and the dispatcher's jump to the body tag
            // with the body tag itself.
            (40, "function set"),
            (41, "total = v"),
            (42, "function set"),
            (43, "function set"),
            // take: entry and its only statement.
            (50, "function take"),
            (51, "total = n"),
        ];
        let instructions = spans
            .iter()
            .map(|(pc, needle)| {
                // The dispatcher's jump into a body is marked as a call.
                if matches!(pc, 35 | 42) {
                    instruction_with(
                        *pc,
                        legacy_offset(needle),
                        needle.len() as u64,
                        json!({"invoke": {}}),
                    )
                } else {
                    instruction(*pc, legacy_offset(needle), needle.len() as u64)
                }
            })
            .collect();
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "L".to_owned(),
            environment: "call".to_owned(),
            instructions,
            sources: BTreeMap::from([(0, "L.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        ContractDebugInfo::new(
            Some(ROOT),
            "L",
            info,
            BTreeMap::from([(0, LEGACY_SOURCE.to_owned())]),
        )
        .with_code_generator(code_generator)
    }

    /// `outer(5)` entered from the dispatcher: the return is reserved, `twice` declared,
    /// the block entered and left, `helper` called, and the frame returned from.
    fn outer_trace() -> TransactionTrace {
        let ret = "0x9";
        trace(vec![
            step(0, 1, "PUSH1", &[]),
            step(10, 1, "JUMPDEST", &[ret, "0x5"]),
            step(11, 1, "PUSH0", &[ret, "0x5"]),
            step(12, 1, "PUSH0", &[ret, "0x5", "0x0"]),
            step(13, 1, "MUL", &[ret, "0x5", "0x0", "0x0"]),
            step(14, 1, "GT", &[ret, "0x5", "0x0", "0xa"]),
            step(15, 1, "PUSH0", &[ret, "0x5", "0x0", "0xa"]),
            step(16, 1, "DUP1", &[ret, "0x5", "0x0", "0xa", "0x8"]),
            step(18, 1, "DUP2", &[ret, "0x5", "0x8", "0xa"]),
            step(17, 1, "JUMP", &[ret, "0x5", "0x8", "0xa", "0x12", "0xa"]),
            step(
                20,
                1,
                "JUMPDEST",
                &[ret, "0x5", "0x8", "0xa", "0x12", "0xa"],
            ),
            step(24, 1, "PUSH0", &[ret, "0x5", "0x8", "0xa", "0x12", "0xa"]),
            step(
                21,
                1,
                "PUSH0",
                &[ret, "0x5", "0x8", "0xa", "0x12", "0xa", "0x0"],
            ),
            step(
                22,
                1,
                "DUP1",
                &[ret, "0x5", "0x8", "0xa", "0x12", "0xa", "0x0", "0xb"],
            ),
            step(23, 1, "JUMP", &[ret, "0x5", "0x8", "0xa", "0xb", "0x12"]),
            step(18, 1, "ADD", &[ret, "0x5", "0x8", "0xa", "0xb"]),
            step(19, 1, "JUMP", &[ret, "0x5", "0x15", "0xa"]),
            step(0, 1, "STOP", &[]),
        ])
    }

    fn named(variables: &[InferredVariable]) -> Vec<(&str, VariableKind, Option<usize>)> {
        variables
            .iter()
            .map(|variable| (variable.name.as_str(), variable.kind, variable.slot))
            .collect()
    }

    #[test]
    fn locals_are_inferred_from_the_legacy_stack_layout() {
        let map = StepMap::new(
            &outer_trace(),
            vec![legacy_contract(Some(CodeGenerator::Legacy))],
        );
        let trace = outer_trace();

        // The dispatcher runs no function.
        assert_eq!(
            map.locals_at(0),
            LocalsStatus::Unavailable("no function is executing at this step")
        );
        // At entry from the dispatcher nothing is placed yet: the return parameter is in
        // scope but unreserved, and the parameters are found by its reservation, one
        // word above them.
        let LocalsStatus::Inferred(at_entry) = map.locals_at(1) else {
            panic!("{:?}", map.locals_at(1));
        };
        assert_eq!(named(at_entry), [("sum", VariableKind::Return, None)]);
        let LocalsStatus::Inferred(at_return) = map.locals_at(2) else {
            panic!("{:?}", map.locals_at(2));
        };
        assert_eq!(
            named(at_return),
            [
                ("a", VariableKind::Parameter, Some(1)),
                ("sum", VariableKind::Return, Some(2))
            ]
        );
        // `twice` takes the next slot at its reservation and reads back once assigned.
        let LocalsStatus::Inferred(at_twice) = map.locals_at(5) else {
            panic!("{:?}", map.locals_at(5));
        };
        assert_eq!(
            named(at_twice),
            [
                ("a", VariableKind::Parameter, Some(1)),
                ("sum", VariableKind::Return, Some(2)),
                ("twice", VariableKind::Local, Some(3))
            ]
        );
        let values = map.inferred_variables(&trace, 5, None);
        assert_eq!(values[0].value.display, "5");
        assert_eq!(values[2].value.display, "10");
        assert_eq!(values[2].location.offset, 3);
        // The block's local is in scope inside the block and released after it.
        let LocalsStatus::Inferred(in_block) = map.locals_at(7) else {
            panic!("{:?}", map.locals_at(7));
        };
        assert_eq!(
            named(in_block).last(),
            Some(&("inner", VariableKind::Local, Some(4)))
        );
        assert_eq!(
            map.inferred_variables(&trace, 7, None)[3].value.display,
            "8"
        );
        let LocalsStatus::Inferred(after_block) = map.locals_at(8) else {
            panic!("{:?}", map.locals_at(8));
        };
        assert_eq!(after_block.len(), 3);
        assert_eq!(
            map.inferred_variables(&trace, 8, None)[1].value.display,
            "8"
        );

        // `helper` is entered by a jump from `outer`, which places its parameter at
        // once and its return parameter above; a slot above the stack reads as
        // unavailable until it is pushed. The local follows once declared, and the
        // caller's variables are back after the return.
        let LocalsStatus::Inferred(helper_entry) = map.locals_at(10) else {
            panic!("{:?}", map.locals_at(10));
        };
        assert_eq!(
            named(helper_entry),
            [
                ("x", VariableKind::Parameter, Some(5)),
                ("r", VariableKind::Return, Some(6))
            ]
        );
        let at_entry = map.inferred_variables(&trace, 10, None);
        assert_eq!(
            at_entry[1].value.status,
            crate::DebugValueStatus::Unavailable
        );
        let helper_values = map.inferred_variables(&trace, 13, None);
        assert_eq!(
            helper_values
                .iter()
                .map(|variable| (variable.name.as_str(), variable.value.display.as_str()))
                .collect::<Vec<_>>(),
            [("x", "10"), ("r", "0"), ("y", "11")]
        );
        assert_eq!(helper_values[2].location.offset, 7);
        let LocalsStatus::Inferred(back) = map.locals_at(15) else {
            panic!("{:?}", map.locals_at(15));
        };
        assert_eq!(named(back).len(), 3);
        assert_eq!(
            map.inferred_variables(&trace, 15, None)[2].value.display,
            "10"
        );
    }

    #[test]
    fn a_modifier_places_itself_and_the_function_it_runs_for() {
        let ret = "0x9";
        let trace = trace(vec![
            step(30, 1, "JUMPDEST", &[ret, "0x7"]),
            // The modifier runs first, its argument pushed above the parameter; its own
            // local is reserved above that.
            step(31, 1, "PUSH0", &[ret, "0x7", "0x9"]),
            // Then the body, whose local sits above the modifier's.
            step(32, 1, "PUSH0", &[ret, "0x7", "0x9", "0x3"]),
            step(33, 1, "SSTORE", &[ret, "0x7", "0x9", "0x3", "0x7"]),
            // The modifier resumes after the body with its slots still in place.
            step(34, 1, "SSTORE", &[ret, "0x7", "0x9", "0x3"]),
        ]);
        let map = StepMap::new(&trace, vec![legacy_contract(Some(CodeGenerator::Legacy))]);
        let LocalsStatus::Inferred(modifier) = map.locals_at(1) else {
            panic!("{:?}", map.locals_at(1));
        };
        assert_eq!(
            named(modifier),
            [
                ("tag", VariableKind::Parameter, Some(2)),
                ("before", VariableKind::Local, Some(3))
            ]
        );
        // The function's parameter sits right below the modifier's, and its body's local
        // right above the modifier's slots.
        let LocalsStatus::Inferred(body) = map.locals_at(3) else {
            panic!("{:?}", map.locals_at(3));
        };
        assert_eq!(
            named(body),
            [
                ("v", VariableKind::Parameter, Some(1)),
                ("kept", VariableKind::Local, Some(4))
            ]
        );
        assert_eq!(
            map.inferred_variables(&trace, 3, None)[1].value.display,
            "7"
        );
        let LocalsStatus::Inferred(resumed) = map.locals_at(4) else {
            panic!("{:?}", map.locals_at(4));
        };
        assert_eq!(
            named(resumed),
            [
                ("tag", VariableKind::Parameter, Some(2)),
                ("before", VariableKind::Local, Some(3))
            ]
        );
        assert_eq!(
            map.inferred_variables(&trace, 4, None)[1].value.display,
            "3"
        );
    }

    #[test]
    fn calldata_slices_read_the_frames_calldata() {
        // `take("ab", [3, 4], 5)` as the legacy decoder leaves it: each slice is an offset
        // into the calldata and a length, the offset pointing at the data itself. The
        // elements of `items` follow the selector at offset 0x4, and the bytes "ab" follow
        // them at 0x44.
        let ret = "0x9";
        let mut trace = trace(vec![
            step(
                50,
                1,
                "JUMPDEST",
                &[ret, "0x44", "0x2", "0x4", "0x2", "0x5"],
            ),
            step(51, 1, "PUSH0", &[ret, "0x44", "0x2", "0x4", "0x2", "0x5"]),
        ]);
        trace.input_data = format!(
            "0xaabbccdd{}{}6162",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000004"
        );
        let map = StepMap::new(&trace, vec![legacy_contract(Some(CodeGenerator::Legacy))]);
        let LocalsStatus::Inferred(layout) = map.locals_at(1) else {
            panic!("{:?}", map.locals_at(1));
        };
        assert_eq!(
            layout
                .iter()
                .map(|variable| (variable.name.as_str(), variable.slot, variable.words))
                .collect::<Vec<_>>(),
            [
                ("data", Some(1), 2),
                ("items", Some(3), 2),
                ("n", Some(5), 1)
            ]
        );
        let values = map.inferred_variables(&trace, 1, None);
        assert_eq!(
            values
                .iter()
                .map(|variable| (variable.name.as_str(), variable.value.display.as_str()))
                .collect::<Vec<_>>(),
            [("data", "0x6162"), ("items", "[3, 4]"), ("n", "5")]
        );
        assert_eq!(values[0].value.raw.as_deref(), Some("0x6162"));
    }

    #[test]
    fn parameters_are_placed_by_the_first_statement_of_a_body_without_locals() {
        // Entered from the dispatcher, with neither a return parameter nor a local to
        // reserve a slot: the body's first instruction still runs right above the
        // parameter.
        let trace = trace(vec![
            step(40, 1, "JUMPDEST", &["0x9", "0x7"]),
            step(41, 1, "DUP1", &["0x9", "0x7"]),
            step(41, 1, "SSTORE", &["0x9", "0x7", "0x7", "0x0"]),
        ]);
        let map = StepMap::new(&trace, vec![legacy_contract(Some(CodeGenerator::Legacy))]);
        let LocalsStatus::Inferred(at_entry) = map.locals_at(0) else {
            panic!("{:?}", map.locals_at(0));
        };
        assert!(at_entry.is_empty());
        let LocalsStatus::Inferred(in_body) = map.locals_at(2) else {
            panic!("{:?}", map.locals_at(2));
        };
        assert_eq!(named(in_body), [("v", VariableKind::Parameter, Some(1))]);
        assert_eq!(
            map.inferred_variables(&trace, 2, None)[0].value.display,
            "7"
        );
    }

    #[test]
    fn the_dispatchers_jump_to_the_body_places_a_public_function() {
        // The dispatcher enters the function's declaration before decoding, then jumps to
        // its body with the decoded parameter on top of the return tag. The optimizer
        // has hoisted a temporary above it before the first statement, which would
        // misplace a frame read off that statement's height.
        let selector = "0x9c";
        let mut trace = trace(vec![
            step(0, 1, "PUSH1", &[]),
            step(40, 1, "JUMPDEST", &[selector]),
            step(42, 1, "JUMP", &[selector, "0x9", "0x7", "0x2b"]),
            step(43, 1, "JUMPDEST", &[selector, "0x9", "0x7"]),
            step(41, 1, "SSTORE", &[selector, "0x9", "0x7", "0x0"]),
        ]);
        let map = StepMap::new(&trace, vec![legacy_contract(Some(CodeGenerator::Legacy))]);
        let LocalsStatus::Inferred(at_entry) = map.locals_at(1) else {
            panic!("{:?}", map.locals_at(1));
        };
        assert!(at_entry.is_empty());
        let LocalsStatus::Inferred(in_body) = map.locals_at(4) else {
            panic!("{:?}", map.locals_at(4));
        };
        assert_eq!(named(in_body), [("v", VariableKind::Parameter, Some(2))]);
        assert_eq!(
            map.inferred_variables(&trace, 4, None)[0].value.display,
            "7"
        );

        // Calldata that selects the function but disagrees with the words at the body
        // tag says this is not where the parameters are: the placement is left to the
        // body's first statement, as before.
        let selector = super::hex_bytes(&function_selector("set(uint256)").expect("selector"));
        trace.input_data = format!("0x{selector}{:064x}", 8);
        let map = StepMap::new(&trace, vec![legacy_contract(Some(CodeGenerator::Legacy))]);
        let LocalsStatus::Inferred(in_body) = map.locals_at(4) else {
            panic!("{:?}", map.locals_at(4));
        };
        assert_eq!(named(in_body), [("v", VariableKind::Parameter, Some(3))]);
        // Calldata that agrees confirms it.
        trace.input_data = format!("0x{selector}{:064x}", 7);
        let map = StepMap::new(&trace, vec![legacy_contract(Some(CodeGenerator::Legacy))]);
        let LocalsStatus::Inferred(in_body) = map.locals_at(4) else {
            panic!("{:?}", map.locals_at(4));
        };
        assert_eq!(named(in_body), [("v", VariableKind::Parameter, Some(2))]);
    }

    #[test]
    fn a_placed_function_places_its_modifiers() {
        // The optimizer merged the modifier's argument with its local's reservation, so
        // the first instruction attributed to the modifier runs with both already on
        // the stack; read off that height the modifier would land one slot too high.
        // The function was placed at its body tag, and the modifier's parameter sits
        // right above the function's, whatever the modifier's own instructions say.
        let selector = "0x9c";
        let ret = "0x9";
        let trace = trace(vec![
            step(0, 1, "PUSH1", &[]),
            step(30, 1, "JUMPDEST", &[selector]),
            step(35, 1, "JUMP", &[selector, ret, "0x5", "0x24"]),
            step(36, 1, "JUMPDEST", &[selector, ret, "0x5"]),
            step(31, 1, "DUP1", &[selector, ret, "0x5", "0x9", "0x9"]),
            step(32, 1, "PUSH0", &[selector, ret, "0x5", "0x9", "0x9"]),
            step(
                33,
                1,
                "SSTORE",
                &[selector, ret, "0x5", "0x9", "0x9", "0x5"],
            ),
            step(34, 1, "SSTORE", &[selector, ret, "0x5", "0x9", "0x9"]),
        ]);
        let map = StepMap::new(&trace, vec![legacy_contract(Some(CodeGenerator::Legacy))]);
        let LocalsStatus::Inferred(modifier) = map.locals_at(4) else {
            panic!("{:?}", map.locals_at(4));
        };
        assert_eq!(
            named(modifier),
            [
                ("tag", VariableKind::Parameter, Some(3)),
                ("before", VariableKind::Local, Some(4))
            ]
        );
        let LocalsStatus::Inferred(body) = map.locals_at(6) else {
            panic!("{:?}", map.locals_at(6));
        };
        assert_eq!(
            named(body),
            [
                ("v", VariableKind::Parameter, Some(2)),
                ("kept", VariableKind::Local, Some(5))
            ]
        );
        assert_eq!(
            map.inferred_variables(&trace, 6, None)[1].value.display,
            "5"
        );
        let LocalsStatus::Inferred(resumed) = map.locals_at(7) else {
            panic!("{:?}", map.locals_at(7));
        };
        assert_eq!(
            named(resumed),
            [
                ("tag", VariableKind::Parameter, Some(3)),
                ("before", VariableKind::Local, Some(4))
            ]
        );
        let values = map.inferred_variables(&trace, 7, None);
        assert_eq!(values[0].value.display, "9");
        assert_eq!(values[1].value.display, "9");
    }

    #[test]
    fn a_function_reached_by_fallthrough_was_inlined_and_has_no_slots() {
        // `helper`'s body runs inside `outer` without a jump onto its entry: the
        // optimizer inlined the call. The frame is shown, its variables are not read,
        // and the caller's own placement survives the excursion.
        let ret = "0x9";
        let trace = trace(vec![
            step(0, 1, "PUSH1", &[]),
            step(10, 1, "JUMPDEST", &[ret, "0x5"]),
            step(11, 1, "PUSH0", &[ret, "0x5"]),
            step(12, 1, "PUSH0", &[ret, "0x5", "0x0"]),
            step(21, 1, "PUSH0", &[ret, "0x5", "0x0", "0xa"]),
            step(22, 1, "DUP1", &[ret, "0x5", "0x0", "0xa", "0xb"]),
            step(18, 1, "ADD", &[ret, "0x5", "0x0", "0xa", "0xb"]),
        ]);
        let map = StepMap::new(&trace, vec![legacy_contract(Some(CodeGenerator::Legacy))]);
        assert_eq!(
            map.location(4).and_then(|location| location.function_name),
            Some("helper".to_owned())
        );
        assert_eq!(
            map.locals_at(4),
            LocalsStatus::Unavailable(
                "this function was inlined by the optimizer, so its variables have no stack \
                 slots of their own"
            )
        );
        assert_eq!(
            map.location(6).and_then(|location| location.function_name),
            Some("outer".to_owned())
        );
        let LocalsStatus::Inferred(back) = map.locals_at(6) else {
            panic!("{:?}", map.locals_at(6));
        };
        assert_eq!(
            named(back),
            [
                ("a", VariableKind::Parameter, Some(1)),
                ("sum", VariableKind::Return, Some(2)),
                ("twice", VariableKind::Local, Some(3))
            ]
        );
    }

    #[test]
    fn locals_are_not_inferred_for_the_via_ir_pipeline_or_an_unknown_one() {
        let via_ir = StepMap::new(
            &outer_trace(),
            vec![legacy_contract(Some(CodeGenerator::ViaIr))],
        );
        assert!(matches!(
            via_ir.locals_at(5),
            LocalsStatus::Unavailable(reason) if reason.contains("via-IR pipeline")
        ));
        assert!(via_ir
            .inferred_variables(&outer_trace(), 5, None)
            .is_empty());
        let unknown = StepMap::new(&outer_trace(), vec![legacy_contract(None)]);
        assert!(matches!(
            unknown.locals_at(5),
            LocalsStatus::Unavailable(reason) if reason.contains("not known")
        ));
    }

    #[test]
    fn steps_without_debug_info_have_no_location() {
        let map = StepMap::new(&outer_calls_inner(), Vec::new());
        assert!(!map.has_source());
        assert_eq!(map.line_key(3), None);
        assert_eq!(map.frame_depth(3), Some(0));
        // Without lines there is nothing to stop at in either direction.
        assert_eq!(map.next_source(3), None);
        assert_eq!(map.previous_source(3), None);
        assert!(map.resolve_line(None, 3).is_err());
        assert_eq!(map.frames(3).len(), 1);
    }

    #[test]
    fn steps_without_source_are_transparent_to_line_stepping() {
        // Line 3 runs, then a generated helper with no span, then line 3 again.
        let map = StepMap::new(
            &trace(vec![
                step(0, 1, "PUSH1", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(11, 1, "ADD", &[]),
                step(99, 1, "MUL", &[]),
                step(11, 1, "SWAP1", &[]),
                step(14, 1, "POP", &[]),
                step(30, 1, "STOP", &[]),
            ]),
            vec![contract(None)],
        );
        assert_eq!(map.line_key(3), None);
        assert_eq!(map.frame_depth(3), Some(1));
        // The helper neither stops `next` nor starts line 3 over again.
        assert_eq!(map.next_source(2), Some(5));
        assert_eq!(map.step_into(2), Some(5));
        assert!(!map.is_line_start(3));
        assert!(!map.is_line_start(4));
        // Reverse stepping treats the interrupted run as one line.
        assert_eq!(map.previous_source(5), Some(2));
        assert_eq!(map.previous_source(4), Some(2));
        assert_eq!(map.previous_source(3), Some(2));
        assert_eq!(map.previous_source(2), Some(1));
    }

    #[test]
    fn generated_code_belongs_to_the_statement_and_the_epilogue_pops_the_function() {
        // Line 3 runs, then a helper carrying the whole-contract span (pc 40), then line 3
        // again, then line 5; the trailing dispatcher step is the epilogue.
        let map = StepMap::new(
            &trace(vec![
                step(0, 1, "PUSH1", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(11, 1, "ADD", &[]),
                step(40, 1, "JUMPDEST", &[]),
                step(40, 1, "SSTORE", &[]),
                step(11, 1, "SWAP1", &[]),
                step(14, 1, "POP", &[]),
                step(30, 1, "STOP", &[]),
            ]),
            vec![contract(None)],
        );
        let helper = map.location(4).expect("location");
        assert!(helper.generated);
        assert_eq!(helper.line, 3);
        assert_eq!(helper.function_name.as_deref(), Some("outer"));
        assert_eq!(map.line_key(4), key(3));
        assert_eq!(map.function_id(4).map(|id| id.function), Some(0));
        assert!(!map.is_line_start(4));
        assert!(!map.is_line_start(5));
        // The helper does not pop outer; the epilogue does.
        assert_eq!(map.frame_depth(4), Some(1));
        assert_eq!(map.frame_depth(7), Some(0));
        assert_eq!(map.line_key(7), None);
        assert!(!map.location(7).expect("location").generated);
        assert_eq!(map.next_source(2), Some(6));
        assert_eq!(map.finish(2), Some(7));
        assert_eq!(map.reverse_finish(4), Some(0));
        assert_eq!(map.previous_source(6), Some(2));
    }

    #[test]
    fn a_lone_instruction_on_another_line_belongs_to_the_line_around_it() {
        // outer's entry, one instruction attributed to line 4, outer's declaration again,
        // then line 3: `next` from the entry reaches line 3 without stopping on the blip.
        let map = StepMap::new(
            &trace(vec![
                step(0, 1, "PUSH1", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(12, 1, "PUSH2", &[]),
                step(10, 1, "SWAP1", &[]),
                step(11, 1, "ADD", &[]),
                step(14, 1, "POP", &[]),
                step(30, 1, "STOP", &[]),
            ]),
            vec![contract(None)],
        );
        assert_eq!(map.line_key(2), key(2));
        assert_eq!(map.location(2).expect("location").line, 4);
        assert!(!map.is_line_start(2));
        assert!(!map.is_line_start(3));
        assert_eq!(map.next_source(1), Some(4));
        assert_eq!(map.previous_source(4), Some(1));
        // A real line of one instruction between two different lines is kept.
        assert_eq!(map.line_key(5), key(5));
        assert!(map.is_line_start(5));
    }

    #[test]
    fn a_jump_onto_a_function_entry_is_a_call_even_when_it_is_active() {
        // outer calls inner, inner calls outer again, and both return: mutual recursion.
        // The entry points (pc 10 for outer, pc 20 for inner) make every jump onto them
        // a call, where landing in an active function used to read as a return.
        let map = StepMap::new(
            &trace(vec![
                step(0, 1, "PUSH1", &[]),
                step(1, 1, "JUMP", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(12, 1, "JUMP", &[]),
                step(20, 1, "JUMPDEST", &[]),
                step(21, 1, "JUMP", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(14, 1, "JUMP", &[]),
                step(21, 1, "SWAP1", &[]),
                step(21, 1, "JUMP", &[]),
                step(13, 1, "JUMPDEST", &[]),
                step(14, 1, "POP", &[]),
                step(30, 1, "STOP", &[]),
            ]),
            vec![contract(None)],
        );
        let contract = &map.contracts()[0];
        assert_eq!(contract.function_entry_at_pc(10), Some(0));
        assert_eq!(contract.function_entry_at_pc(20), Some(1));
        assert_eq!(contract.function_entry_at_pc(11), None);
        let depths = (0..13)
            .map(|step| map.frame_depth(step).expect("depth"))
            .collect::<Vec<_>>();
        assert_eq!(depths, vec![0, 0, 1, 1, 2, 2, 3, 3, 2, 2, 1, 1, 0]);
        assert!(map.is_frame_entry(6));
        let frames = map.frames(6);
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.function_name.as_deref().unwrap_or("-"))
                .collect::<Vec<_>>(),
            vec!["outer", "inner", "outer", "-"]
        );
        assert_eq!(map.finish(6), Some(8));
        assert_eq!(map.reverse_finish(6), Some(5));
        assert_eq!(map.finish(4), Some(10));
    }

    #[test]
    fn a_recursive_call_returns_at_the_address_read_off_the_stack() {
        // outer calls outer: the jump at pc 12 carries [return tag 13, argument, entry 10]
        // on its stack. Landing on the entry point pushes a second outer frame; the jump
        // that lands on pc 13 is its return, which no span could tell apart from staying
        // in outer.
        let map = StepMap::new(
            &trace(vec![
                step(0, 1, "PUSH1", &[]),
                step(1, 1, "JUMP", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(12, 1, "JUMP", &["0xd", "0x1", "0xa"]),
                step(10, 1, "JUMPDEST", &["0x1"]),
                step(11, 1, "ADD", &["0x2"]),
                step(14, 1, "JUMP", &["0xd"]),
                step(13, 1, "JUMPDEST", &[]),
                step(14, 1, "POP", &[]),
                step(30, 1, "STOP", &[]),
            ]),
            vec![contract(None)],
        );
        let depths = (0..10)
            .map(|step| map.frame_depth(step).expect("depth"))
            .collect::<Vec<_>>();
        assert_eq!(depths, vec![0, 0, 1, 1, 2, 2, 2, 1, 1, 0]);
        assert!(map.is_frame_entry(4));
        assert_eq!(map.finish(4), Some(7));
        assert_eq!(map.frames(5).len(), 3);
        assert_eq!(map.frames(7).len(), 2);
        assert!(map.contracts()[0].is_jumpdest(13));
        assert!(!map.contracts()[0].is_jumpdest(99));
    }

    #[test]
    fn jump_markers_decide_calls_and_returns_without_entry_points() {
        // The jump at pc 12 is marked as a call and lands mid-outer (pc 11): a helper
        // whose span is the calling line, since recursion would enter at pc 10. It gets
        // a placeholder frame the marked return at pc 14 pops, so outer stays on the
        // stack throughout and its depth never moves.
        let whole = SOURCE.len() as u64;
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "C".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![
                instruction(0, 0, whole),
                instruction(1, 0, whole),
                instruction(10, offset_of("function outer"), 90),
                instruction(11, offset_of("uint256 b = a + 1;"), 18),
                instruction_with(
                    12,
                    offset_of("inner(b);"),
                    9,
                    json!({"invoke": {"identifier": "outer"}}),
                ),
                instruction(13, offset_of("inner(b);"), 9),
                instruction_with(14, offset_of("b = 0;"), 6, json!({"return": {}})),
                instruction(30, 0, whole),
            ],
            sources: BTreeMap::from([(0, "C.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        let marked =
            ContractDebugInfo::new(None, "C", info, BTreeMap::from([(0, SOURCE.to_owned())]));
        assert_eq!(marked.jump_marker_at_pc(12), JumpMarker::Call);
        assert_eq!(marked.jump_marker_at_pc(14), JumpMarker::Return);
        assert_eq!(marked.jump_marker_at_pc(13), JumpMarker::None);
        let map = StepMap::new(
            &trace(vec![
                step(0, 1, "PUSH1", &[]),
                step(1, 1, "JUMP", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(12, 1, "JUMP", &[]),
                step(11, 1, "ADD", &[]),
                step(14, 1, "JUMP", &[]),
                step(13, 1, "JUMPDEST", &[]),
                step(14, 1, "POP", &[]),
                step(30, 1, "STOP", &[]),
            ]),
            vec![marked],
        );
        let depths = (0..9)
            .map(|step| map.frame_depth(step).expect("depth"))
            .collect::<Vec<_>>();
        assert_eq!(depths, vec![0, 0, 1, 1, 1, 1, 1, 1, 0]);
        assert!(!map.is_frame_entry(4));
        assert_eq!(map.frames(4).len(), 2);
        assert_eq!(map.finish(4), Some(8));
        // A marked call from outer that lands on inner's entry point is a real call.
        let map = StepMap::new(
            &trace(vec![
                step(0, 1, "PUSH1", &[]),
                step(1, 1, "JUMP", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(12, 1, "JUMP", &[]),
                step(20, 1, "JUMPDEST", &[]),
                step(21, 1, "JUMP", &[]),
                step(13, 1, "JUMPDEST", &[]),
                step(30, 1, "STOP", &[]),
            ]),
            vec![contract(None)],
        );
        assert_eq!(map.frame_depth(4), Some(2));
        assert_eq!(map.frame_depth(6), Some(1));
    }

    #[test]
    fn marked_jumps_into_generated_helpers_do_not_pop_the_function() {
        // Inside outer, a marked call jumps to helper code with the whole-contract span
        // (pc 40) and a marked return comes back: outer stays on the stack throughout,
        // and the helper counts as no frame the user steps by.
        let whole = SOURCE.len() as u64;
        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "C".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![
                instruction(0, 0, whole),
                instruction(1, 0, whole),
                instruction(10, offset_of("function outer"), 90),
                instruction_with(
                    11,
                    offset_of("uint256 b = a + 1;"),
                    18,
                    json!({"invoke": {}}),
                ),
                instruction_with(40, 0, whole, json!({"return": {}})),
                instruction(14, offset_of("b = 0;"), 6),
                instruction(30, 0, whole),
            ],
            sources: BTreeMap::from([(0, "C.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        let contract =
            ContractDebugInfo::new(None, "C", info, BTreeMap::from([(0, SOURCE.to_owned())]));
        let map = StepMap::new(
            &trace(vec![
                step(0, 1, "PUSH1", &[]),
                step(1, 1, "JUMP", &[]),
                step(10, 1, "JUMPDEST", &[]),
                step(11, 1, "JUMP", &[]),
                step(40, 1, "JUMPDEST", &[]),
                step(40, 1, "JUMP", &[]),
                step(14, 1, "JUMPDEST", &[]),
                step(30, 1, "STOP", &[]),
            ]),
            vec![contract],
        );
        let depths = (0..8)
            .map(|step| map.frame_depth(step).expect("depth"))
            .collect::<Vec<_>>();
        assert_eq!(depths, vec![0, 0, 1, 1, 1, 1, 1, 0]);
        assert!(map.location(4).expect("location").generated);
        assert_eq!(
            map.location(6).expect("location").function_name.as_deref(),
            Some("outer")
        );
        assert_eq!(map.next_source(3), Some(6));
        assert_eq!(map.finish(3), Some(7));
    }

    #[test]
    fn contract_info_indexes_lines_and_functions() {
        let contract = contract(Some("0xABCD"));
        assert_eq!(contract.address.as_deref(), Some("0xabcd"));
        assert_eq!(contract.line_of(0, 0), Some(1));
        assert_eq!(
            contract.line_of(0, SOURCE.find("inner(b)").unwrap() as u64),
            Some(4)
        );
        assert_eq!(contract.line_count(0), Some(11));
        assert_eq!(contract.line_text(0, 8).map(str::trim), Some("x += 1;"));
        assert_eq!(contract.line_text(0, 99), None);
        assert_eq!(
            contract.function_at_pc(21).map(|f| f.name.as_str()),
            Some("inner")
        );
        assert_eq!(contract.function_at_pc(0), None);
        assert_eq!(contract.function_at_pc(999), None);
        assert_eq!(contract.functions[0].declaration_line, 2);
        assert_eq!(contract.effective_line(0, 3), Some(3));
        assert_eq!(contract.effective_line(0, 6), Some(1));
        assert_eq!(contract.effective_line(0, 0), None);
        assert_eq!(contract.effective_line(0, 12), None);
        assert_eq!(contract.effective_line(7, 1), None);

        assert_eq!(normalize_address("0XAbC"), "0xabc");
        assert_eq!(
            address_from_word("0x000000000000000000000000AAAA000000000000000000000000000000000001"),
            Some("0xaaaa000000000000000000000000000000000001".to_owned())
        );
        assert_eq!(address_from_word("0x0"), None);
        assert_eq!(address_from_word("zz"), None);
    }
}
