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
    function_selector, EthdebugInfo, FunctionExit, SourceLocation, StorageLayout,
};

use crate::{
    decode_arguments, is_value_type, parse_source_functions, readable_parameter, ArgumentLayout,
    ArgumentOrder, FrameArgument, FrameState, SourceFunction,
};

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
    /// Where the contract's state variables live, when it was compiled with
    /// `--storage-layout`.
    pub storage_layout: Option<StorageLayout>,
    /// Byte offsets at which each line of each source starts.
    line_starts: BTreeMap<u64, Vec<usize>>,
    /// Instruction index by program counter.
    pc_index: HashMap<u64, usize>,
    /// The program counter each parsed function is entered at: its first `JUMPDEST`
    /// carrying the declaration's span.
    function_entries: HashMap<u64, usize>,
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
            storage_layout: None,
            line_starts,
            pc_index,
            function_entries,
        }
    }

    /// Attaches the contract's storage layout, so state variables can be read by name.
    #[must_use]
    pub fn with_storage_layout(mut self, storage_layout: Option<StorageLayout>) -> Self {
        self.storage_layout = storage_layout;
        self
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

/// One internal frame: a function, or a placeholder for a compiler-generated helper
/// entered through a marked call, which absorbs the matching marked return and counts as
/// no frame of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameEntry {
    function: Option<usize>,
    /// Where the frame returns to: the tag the caller pushed before the arguments, read
    /// off the stack at the call. A jump landing there is the return, whatever function
    /// it lands in, which is what tells a return from a recursive call apart from
    /// staying in the function.
    return_pc: Option<u64>,
}

/// The inferred Solidity state of one EVM frame.
#[derive(Default)]
struct InternalFrame {
    /// The frames active in this EVM frame, innermost last.
    functions: Vec<FrameEntry>,
    /// The last real statement executed in this frame, which generated code belongs to.
    statement: Option<LocationRef>,
}

impl InternalFrame {
    /// The innermost function, looking past helper placeholders.
    fn active(&self) -> Option<usize> {
        self.functions.iter().rev().find_map(|entry| entry.function)
    }

    fn is_active(&self, function: usize) -> bool {
        self.active() == Some(function)
    }

    fn push_function(&mut self, function: usize, return_pc: Option<u64>) {
        self.functions.push(FrameEntry {
            function: Some(function),
            return_pc,
        });
    }

    fn push_placeholder(&mut self) {
        self.functions.push(FrameEntry {
            function: None,
            return_pc: None,
        });
    }

    /// Whether a jump landing on `pc` returns from the innermost frame.
    fn returns_to(&self, pc: u64) -> bool {
        self.functions
            .last()
            .is_some_and(|entry| entry.return_pc == Some(pc))
    }
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
        let mut addresses = Vec::<String>::new();
        let mut address_index = HashMap::<String, usize>::new();
        let mut intern = |address: &str| -> usize {
            let address = normalize_address(address);
            *address_index.entry(address.clone()).or_insert_with(|| {
                addresses.push(address);
                addresses.len() - 1
            })
        };
        let contract_for = |address: Option<&str>, root: bool| -> Option<usize> {
            let address = address.map(normalize_address);
            if let Some(address) = &address {
                if let Some(index) = contracts
                    .iter()
                    .position(|contract| contract.address.as_deref() == Some(address))
                {
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
        let root_depth = trace.steps.first().map_or(0, |step| step.depth);
        let mut next_frame_id = 1_u32;
        let root_storage = root_address.map(&mut intern);
        let mut evm_frames = vec![EvmFrame {
            id: 0,
            contract: contract_for(root_address, true),
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
                // A new EVM frame: the callee's code address is on the caller's stack at
                // the call instruction, the step before this one.
                let call = (evm_frames.len() == evm_depth)
                    .then(|| index.checked_sub(1))
                    .flatten();
                let target = call.and_then(|caller| call_target(&trace.steps[caller]));
                let address = target.as_deref().map(&mut intern);
                // A `DELEGATECALL` or `CALLCODE` runs the callee's code against the
                // caller's storage; every other call has the callee's own.
                let delegated = call.is_some_and(|caller| {
                    matches!(&*trace.steps[caller].op, "DELEGATECALL" | "CALLCODE")
                });
                let storage = if delegated {
                    evm_frames.last().and_then(|frame| frame.storage)
                } else {
                    address
                };
                evm_frames.push(EvmFrame {
                    id: next_frame_id,
                    contract: contract_for(target.as_deref(), false),
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

        // Pass 3: the virtual function stack per EVM frame, frame depths, and the line
        // each step counts as.
        let mut internal = Vec::<InternalFrame>::new();
        let mut steps = Vec::with_capacity(framed.len());
        let mut pcs = Vec::with_capacity(framed.len());
        for (index, step) in framed.iter().enumerate() {
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
                        if entering || (pending_call && !frame.is_active(function)) {
                            // A call: onto the entry point, or marked and into a function
                            // other than the active one.
                            frame.push_function(function, return_address(function));
                            frame_entry = true;
                        } else if pending_call {
                            // A marked call into the active function away from its entry
                            // point is a generated helper whose span is the calling line:
                            // recursion always enters at the entry point.
                            frame.push_placeholder();
                        } else if !frame.is_active(function) {
                            match frame
                                .functions
                                .iter()
                                .rposition(|entry| entry.function == Some(function))
                            {
                                Some(position) => frame.functions.truncate(position + 1),
                                None => {
                                    frame.push_function(function, None);
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

        let argument_layouts = prove_argument_layouts(trace, &contracts, &framed);
        let mut map = Self {
            contracts,
            steps,
            addresses,
            pcs,
            reverted,
            argument_layouts,
        };
        map.smooth_single_step_excursions();
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
        decode_arguments(&function.params, state, layout)
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

        let resolved = sources
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
    use soldb_core::{StepSnapshot, TraceStep, TransactionTrace};
    use soldb_ethdebug::{EthdebugInfo, Instruction};

    use soldb_core::Word as StackWord;

    use crate::FrameState;

    use super::{
        address_from_word, normalize_address, ArgumentLayout, ArgumentOrder, ContractDebugInfo,
        JumpMarker, LineKey, StepMap,
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
