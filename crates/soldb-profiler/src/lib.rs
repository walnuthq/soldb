//! Gas profiling over execution traces and ETHDebug programs.
//!
//! The profiler combines the dynamic cost recorded in a [`TransactionTrace`] with the
//! compiler-authored source context in one or more [`EthdebugInfo`] programs. It never
//! guesses which contract owns a program counter: runtime instructions are keyed by code
//! address and creation/runtime environment, and nested steps without call identity stay
//! visibly unmapped. Functions the program's contexts leave unnamed are named by the
//! debugger's [`StepMap`], so a profile and a backtrace agree on them.
//!
//! This crate performs no file I/O, RPC, or presentation. A frontend supplies traces and
//! programs, then renders the returned [`ProfileReport`] as text, JSON, folded stacks, or
//! a flame graph.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use soldb_core::{opcode, SoldbError, SoldbResult, StepView, TransactionTrace};
use soldb_debugger::{ContractDebugInfo, SourceFunction, StepMap};
use soldb_ethdebug::{EthdebugInfo, FunctionExit, FunctionIdentity, SourceLocation};

const PROFILE_SCHEMA_VERSION: u32 = 1;
/// `G_create`: the base cost of `CREATE` and `CREATE2`, below which no creation's own cost falls.
const CREATE_GAS: u64 = 32_000;

/// Whether a program describes contract creation or deployed runtime bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProgramEnvironment {
    Create,
    Call,
}

impl ProgramEnvironment {
    #[must_use]
    pub fn from_ethdebug(value: &str) -> Option<Self> {
        match value {
            "create" | "creation" => Some(Self::Create),
            "call" | "runtime" => Some(Self::Call),
            _ => None,
        }
    }
}

/// One compiler program and the source text referenced by its ETHDebug contexts.
#[derive(Debug)]
pub struct ProfileProgram {
    address: Option<String>,
    /// The keccak-256 hash of the code the program describes, when known; it tells apart
    /// programs run at one address.
    code_hash: Option<String>,
    contract_name: String,
    environment: ProgramEnvironment,
    debug: ContractDebugInfo,
    source_indexes: HashMap<u64, SourceTextIndex>,
    functions: Vec<ProfileFunction>,
    /// The entry in `functions` for each function the debugger parsed, by its index there.
    source_functions: Vec<usize>,
    pc_contexts: HashMap<u64, ProgramCounterContext>,
}

impl ProfileProgram {
    /// Builds the indexes used by the trace hot loop.
    pub fn new(
        address: Option<String>,
        info: EthdebugInfo,
        source_contents: BTreeMap<u64, String>,
    ) -> SoldbResult<Self> {
        let environment =
            ProgramEnvironment::from_ethdebug(&info.environment).ok_or_else(|| {
                SoldbError::Message(format!(
                    "unknown ETHDebug program environment `{}`",
                    info.environment
                ))
            })?;
        let contract_name = info.contract_name.clone();
        let source_indexes = source_contents
            .iter()
            .map(|(source_id, source)| (*source_id, SourceTextIndex::new(source)))
            .collect::<HashMap<_, _>>();
        let mut pc_contexts = HashMap::with_capacity(info.instructions.len());
        let mut functions = Vec::new();
        let mut function_indexes = HashMap::new();

        for instruction in &info.instructions {
            let sources = instruction
                .source_locations()
                .into_iter()
                .filter_map(|location| index_source_location(&source_indexes, location))
                .collect();
            let invokes = instruction
                .function_invocations()
                .into_iter()
                .map(|identity| {
                    if let Some(index) = function_indexes.get(&identity).copied() {
                        index
                    } else {
                        let index = functions.len();
                        functions.push(ProfileFunction {
                            identity: identity.clone(),
                        });
                        function_indexes.insert(identity, index);
                        index
                    }
                })
                .collect();
            if pc_contexts
                .insert(
                    instruction.offset,
                    ProgramCounterContext {
                        opcode: instruction.mnemonic().map(str::to_owned),
                        sources,
                        invokes,
                        exit: instruction.function_exit(),
                    },
                )
                .is_some()
            {
                return Err(SoldbError::Message(format!(
                    "duplicate ETHDebug instruction at PC {} for `{contract_name}`",
                    instruction.offset
                )));
            }
        }

        let address = address.map(|address| normalize_address(&address));
        let debug =
            ContractDebugInfo::new(address.as_deref(), &contract_name, info, source_contents);
        let source_functions = debug
            .functions
            .iter()
            .map(|function| source_function_index(&mut functions, function))
            .collect();

        Ok(Self {
            address,
            code_hash: None,
            contract_name,
            environment,
            debug,
            source_indexes,
            functions,
            source_functions,
            pc_contexts,
        })
    }

    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Records the hash of the code this program describes, so frames that record the hash
    /// of the code they run only map through matching programs.
    #[must_use]
    pub fn with_code_hash(mut self, code_hash: Option<&str>) -> Self {
        self.code_hash = code_hash.map(normalize_address);
        self.debug = self.debug.with_code_hash(code_hash);
        self
    }

    #[must_use]
    pub fn code_hash(&self) -> Option<&str> {
        self.code_hash.as_deref()
    }

    #[must_use]
    pub fn contract_name(&self) -> &str {
        &self.contract_name
    }

    #[must_use]
    pub fn environment(&self) -> ProgramEnvironment {
        self.environment
    }

    /// The parsed function the debugger places a step in, when it is this program's.
    fn traced_function(
        &self,
        step_map: &StepMap,
        step: usize,
        program_index: usize,
    ) -> Option<usize> {
        let id = step_map
            .function_id(step)
            .filter(|id| id.contract == program_index)?;
        self.source_functions.get(id.function).copied()
    }

    /// The function a step runs in: the compiler's when it is named, otherwise the one the
    /// debugger traced into. An unnamed compiler function the debugger cannot place is a
    /// generated helper, charged to the function that called it, or to none when the
    /// dispatcher did.
    fn named_function(
        &self,
        invoked: Option<usize>,
        traced: Option<usize>,
        caller: Option<usize>,
    ) -> Option<usize> {
        let named =
            invoked.filter(|function| self.functions[*function].identity.identifier.is_some());
        if named.is_some() {
            return named;
        }
        if traced.is_some() {
            return traced;
        }
        invoked.and(caller)
    }

    fn source_for_function(
        &self,
        context: &ProgramCounterContext,
        function: Option<usize>,
    ) -> Option<IndexedSource> {
        if let [source] = context.sources.as_slice() {
            return Some(*source);
        }
        let declaration = function
            .and_then(|function| self.functions.get(function))
            .and_then(|function| function.identity.declaration.as_ref())?;
        let mut matches = context
            .sources
            .iter()
            .copied()
            .filter(|source| source.is_within(declaration));
        let source = matches.next()?;
        matches.next().is_none().then_some(source)
    }
}

/// The entry for a function the debugger parsed: the compiler's own when it names the same
/// declaration, otherwise a new one named from the source.
fn source_function_index(functions: &mut Vec<ProfileFunction>, function: &SourceFunction) -> usize {
    let declaration = SourceLocation {
        source_id: function.source_id,
        offset: function.declaration_start,
        length: function
            .body_end
            .saturating_add(1)
            .saturating_sub(function.declaration_start),
    };
    let existing = functions.iter().position(|candidate| {
        candidate.identity.identifier.is_some()
            && candidate
                .identity
                .declaration
                .as_ref()
                .is_some_and(|candidate| {
                    candidate.source_id == declaration.source_id
                        && candidate.offset == declaration.offset
                })
    });
    if let Some(index) = existing {
        return index;
    }
    functions.push(ProfileFunction {
        identity: FunctionIdentity {
            identifier: Some(function.name.clone()),
            declaration: Some(declaration),
            activation: None,
        },
    });
    functions.len() - 1
}

fn index_source_location(
    source_indexes: &HashMap<u64, SourceTextIndex>,
    location: SourceLocation,
) -> Option<IndexedSource> {
    let end = location.offset.checked_add(location.length)?;
    let index = source_indexes.get(&location.source_id)?;
    if end > index.len {
        return None;
    }
    let position = index.position(location.offset);
    Some(IndexedSource {
        source_id: location.source_id,
        offset: location.offset,
        length: location.length,
        line: position.map(|position| position.0),
        column: position.map(|position| position.1),
    })
}

#[derive(Debug, Clone)]
struct ProfileFunction {
    identity: FunctionIdentity,
}

impl ProfileFunction {
    fn name(&self) -> &str {
        self.identity.identifier.as_deref().unwrap_or("<anonymous>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileReport {
    pub schema_version: u32,
    pub transaction: ProfileTransaction,
    pub totals: ProfileTotals,
    pub contracts: Vec<ContractProfile>,
    pub functions: Vec<FunctionProfile>,
    pub source_lines: Vec<SourceLineProfile>,
    pub opcodes: Vec<OpcodeProfile>,
    pub hotspots: Vec<InstructionProfile>,
    pub folded_stacks: Vec<FoldedStack>,
}

impl ProfileReport {
    /// Serializes samples in Brendan Gregg's folded-stack interchange format.
    #[must_use]
    pub fn folded_text(&self) -> String {
        let mut output = String::new();
        for stack in &self.folded_stacks {
            if stack.gas == 0 || stack.frames.is_empty() {
                continue;
            }
            let frames = stack
                .frames
                .iter()
                .map(|frame| sanitize_folded_frame(frame))
                .collect::<Vec<_>>()
                .join(";");
            output.push_str(&frames);
            output.push(' ');
            output.push_str(&stack.gas.to_string());
            output.push('\n');
        }
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileTransaction {
    pub hash: Option<String>,
    pub backend: Option<String>,
    pub success: bool,
    pub gas_used: u64,
    pub steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileTotals {
    /// Sum of the gas each opcode step spent itself; a call's forwarded gas is not counted.
    pub step_gas: u64,
    /// Step gas assigned to a known creation or runtime program.
    pub program_gas: u64,
    /// Step gas whose program instruction carries a source range.
    pub source_gas: u64,
    /// Step gas for which the executing program could not be identified.
    pub unmapped_gas: u64,
    /// Program gas whose instruction carries no source range.
    pub sourceless_gas: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractProfile {
    pub address: Option<String>,
    pub contract: String,
    pub environment: ProgramEnvironment,
    pub gas: u64,
    pub hits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionProfile {
    pub address: Option<String>,
    pub contract: String,
    pub environment: ProgramEnvironment,
    pub function: String,
    pub source: Option<String>,
    pub line: Option<u64>,
    pub gas: u64,
    pub hits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLineProfile {
    pub address: Option<String>,
    pub contract: String,
    pub source: String,
    pub line: u64,
    pub text: Option<String>,
    pub gas: u64,
    pub hits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpcodeProfile {
    pub opcode: String,
    pub gas: u64,
    pub hits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstructionProfile {
    pub address: Option<String>,
    pub contract: String,
    pub environment: ProgramEnvironment,
    pub pc: u64,
    pub opcode: String,
    pub function: Option<String>,
    pub source: Option<ProfileSourceLocation>,
    pub gas: u64,
    pub hits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSourceLocation {
    pub path: String,
    pub offset: u64,
    pub length: u64,
    pub line: Option<u64>,
    pub column: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FoldedStack {
    pub frames: Vec<String>,
    pub gas: u64,
    pub hits: u64,
}

/// Profiles one transaction without copying step snapshots or scanning instructions.
pub fn profile_transaction(
    trace: &TransactionTrace,
    programs: &[ProfileProgram],
) -> SoldbResult<ProfileReport> {
    let program_lookup = build_program_lookup(programs)?;
    let root_environment = if trace.to_addr.is_some() {
        ProgramEnvironment::Call
    } else {
        ProgramEnvironment::Create
    };
    let root_address = trace
        .to_addr
        .as_deref()
        .or(trace.contract_address.as_deref());
    let root_program = lookup_program(
        root_address,
        None,
        root_environment,
        programs,
        &program_lookup,
    );
    let root_depth = trace.steps.first().map_or(0, |step| step.depth());
    let root_label = root_program.map_or_else(
        || {
            root_address.map_or_else(
                || "transaction".to_owned(),
                |address| format!("contract {}", normalize_address(address)),
            )
        },
        |program| program_label(&programs[program]),
    );

    let frames = build_execution_frames(trace, programs, &program_lookup);
    // Names the functions a program's own contexts leave anonymous or unmarked.
    let step_map = StepMap::new(
        trace,
        programs
            .iter()
            .map(|program| program.debug.clone())
            .collect(),
    );
    let events = build_frame_events(&frames);
    let mut frame_cursor = FrameCursor::new(events);
    let mut paths = vec![Vec::new()];
    let mut current_path = 0;
    let mut function_stacks = HashMap::<FunctionFrameKey, Vec<usize>>::new();
    let mut function_paths = vec![Vec::new()];
    let mut function_path_lookup = HashMap::from([(Vec::new(), 0)]);
    let mut function_path_ids = HashMap::<FunctionFrameKey, usize>::new();
    // Per entry of `function_stacks`, the function of the step that invoked it.
    let mut function_callers = HashMap::<FunctionFrameKey, Vec<Option<usize>>>::new();

    let mut step_metrics = Metrics::default();
    let mut program_metrics = Metrics::default();
    let mut source_metrics = Metrics::default();
    let mut contracts = HashMap::<usize, Metrics>::new();
    let mut functions = HashMap::<FunctionKey, Metrics>::new();
    let mut source_lines = HashMap::<SourceLineKey, Metrics>::new();
    let mut opcodes = HashMap::<&str, Metrics>::new();
    let mut hotspots = HashMap::<HotspotKey, HotspotMetrics<'_>>::new();
    let mut folded = HashMap::<FoldedKey, Metrics>::new();

    for (step_index, step) in trace.steps.iter().enumerate() {
        if frame_cursor.advance(step_index, &frames) {
            paths.push(frame_cursor.active.clone());
            current_path = paths.len() - 1;
        }

        let next = trace.steps.get(step_index + 1);
        let gas_cost = own_gas_cost(step, next);
        step_metrics.add(gas_cost, "total step gas")?;
        opcodes
            .entry(step.mnemonic())
            .or_default()
            .add(gas_cost, "opcode gas")?;

        let active_frame = frame_cursor.current_index(&frames, step.depth());
        let program_index = active_frame
            .and_then(|frame| frames[frame].program)
            .or_else(|| {
                (active_frame.is_none() && step.depth() == root_depth)
                    .then_some(root_program)
                    .flatten()
            });
        let Some(program_index) = program_index else {
            folded
                .entry(FoldedKey {
                    path: current_path,
                    program: None,
                    function_path: 0,
                    source: None,
                    unmapped_depth: Some(step.depth()),
                })
                .or_default()
                .add(gas_cost, "folded-stack gas")?;
            continue;
        };

        let program = &programs[program_index];
        let context = program.pc_contexts.get(&step.pc()).filter(|context| {
            context
                .opcode
                .as_deref()
                .is_none_or(|opcode| opcode.eq_ignore_ascii_case(step.mnemonic()))
        });
        let function_frame = active_frame.map_or(
            FunctionFrameKey::Root(step.depth()),
            FunctionFrameKey::External,
        );
        let invoked = function_stacks
            .get(&function_frame)
            .and_then(|stack| stack.last().copied());
        // A step whose opcode contradicts the program is not the program's code.
        let traced =
            context.and_then(|_| program.traced_function(&step_map, step_index, program_index));
        let caller = function_callers
            .get(&function_frame)
            .and_then(|callers| callers.last().copied())
            .flatten();
        let function = program.named_function(invoked, traced, caller);
        let function_path = function_path_ids.get(&function_frame).copied().unwrap_or(0);
        let source = context.and_then(|context| program.source_for_function(context, function));
        program_metrics.add(gas_cost, "program gas")?;
        contracts
            .entry(program_index)
            .or_default()
            .add(gas_cost, "contract gas")?;

        let function_key = FunctionKey {
            program: program_index,
            function,
            has_source: function.is_none() && source.is_some(),
        };
        functions
            .entry(function_key)
            .or_default()
            .add(gas_cost, "function gas")?;

        let source_key = source.map(|source| FlameSourceKey {
            source_id: source.source_id,
            line: source.line,
            offset: source.line.is_none().then_some(source.offset),
        });
        if let Some(source) = source {
            source_metrics.add(gas_cost, "source gas")?;
            if let Some(line) = source.line {
                source_lines
                    .entry(SourceLineKey {
                        program: program_index,
                        source_id: source.source_id,
                        line,
                    })
                    .or_default()
                    .add(gas_cost, "source-line gas")?;
            }
        }

        let hotspot = hotspots
            .entry(HotspotKey {
                program: program_index,
                pc: step.pc(),
                source,
            })
            .or_insert_with(|| HotspotMetrics {
                opcode: step.mnemonic(),
                context_matches: context.is_some(),
                function,
                functions_agree: true,
                metrics: Metrics::default(),
            });
        hotspot.context_matches &= context.is_some();
        hotspot.functions_agree &= hotspot.function == function;
        hotspot.metrics.add(gas_cost, "instruction gas")?;

        folded
            .entry(FoldedKey {
                path: current_path,
                program: Some(program_index),
                function_path,
                source: source_key,
                unmapped_depth: None,
            })
            .or_default()
            .add(gas_cost, "folded-stack gas")?;

        let caller_function = function;
        if let Some(function) = context.and_then(|context| match context.invokes.as_slice() {
            [function] => Some(*function),
            _ => None,
        }) {
            function_callers
                .entry(function_frame)
                .or_default()
                .push(caller_function);
            let stack = function_stacks.entry(function_frame).or_default();
            stack.push(function);
            let path = intern_function_path(stack, &mut function_paths, &mut function_path_lookup);
            function_path_ids.insert(function_frame, path);
        }
        if context.and_then(|context| context.exit).is_some() {
            if let Some(callers) = function_callers.get_mut(&function_frame) {
                callers.pop();
            }
            if let Some(stack) = function_stacks.get_mut(&function_frame) {
                stack.pop();
                let path =
                    intern_function_path(stack, &mut function_paths, &mut function_path_lookup);
                function_path_ids.insert(function_frame, path);
            }
        }
    }

    let contract_rows = contract_rows(programs, contracts);
    let function_rows = function_rows(programs, functions);
    let source_line_rows = source_line_rows(programs, source_lines);
    let opcode_rows = opcode_rows(opcodes);
    let hotspot_rows = hotspot_rows(programs, hotspots);
    let folded_stacks = folded_rows(
        programs,
        &frames,
        &paths,
        &function_paths,
        &root_label,
        root_program,
        folded,
    )?;
    let unmapped_gas = step_metrics
        .gas
        .checked_sub(program_metrics.gas)
        .ok_or_else(|| {
            SoldbError::Message("profile program gas exceeds total step gas".to_owned())
        })?;
    let sourceless_gas = program_metrics
        .gas
        .checked_sub(source_metrics.gas)
        .ok_or_else(|| SoldbError::Message("profile source gas exceeds program gas".to_owned()))?;

    Ok(ProfileReport {
        schema_version: PROFILE_SCHEMA_VERSION,
        transaction: ProfileTransaction {
            hash: trace.tx_hash.clone(),
            backend: trace.backend.clone(),
            success: trace.success,
            gas_used: trace.gas_used,
            steps: u64::try_from(trace.steps.len()).map_err(|_| {
                SoldbError::Message("profile step count does not fit in `u64`".to_owned())
            })?,
        },
        totals: ProfileTotals {
            step_gas: step_metrics.gas,
            program_gas: program_metrics.gas,
            source_gas: source_metrics.gas,
            unmapped_gas,
            sourceless_gas,
        },
        contracts: contract_rows,
        functions: function_rows,
        source_lines: source_line_rows,
        opcodes: opcode_rows,
        hotspots: hotspot_rows,
        folded_stacks,
    })
}

/// Returns a step's gas without the gas a call forwards, which the callee's steps already count.
///
/// The callee starts with the forwarded gas plus any stipend, and the stipend comes back to the
/// caller unless spent, so the whole `next.gas` comes off. A call with no steps lost `step.gas -
/// next.gas`.
fn own_gas_cost(step: StepView<'_>, next: Option<StepView<'_>>) -> u64 {
    let gas_cost = step.gas_cost();
    let base_cost = match step.op() {
        opcode::CALL | opcode::CALLCODE | opcode::DELEGATECALL | opcode::STATICCALL => 0,
        opcode::CREATE | opcode::CREATE2 => CREATE_GAS,
        _ => return gas_cost,
    };
    if step.error().is_some() {
        return gas_cost;
    }
    let Some(next) = next else {
        return gas_cost;
    };
    // Deeper than one frame when the callee ran no steps but called on, as a cheatcode does.
    if next.depth() > step.depth() {
        // geth leaves a creation's forwarded gas out of its `gas_cost`, so less than the base
        // cost would remain.
        let Some(own) = gas_cost.checked_sub(next.gas()) else {
            return gas_cost;
        };
        return if own >= base_cost { own } else { gas_cost };
    }
    if next.depth() == step.depth() {
        let Some(lost) = step.gas().checked_sub(next.gas()) else {
            return gas_cost;
        };
        return lost.min(gas_cost);
    }
    gas_cost
}

#[derive(Debug, Clone)]
struct ProgramCounterContext {
    opcode: Option<String>,
    sources: Vec<IndexedSource>,
    invokes: Vec<usize>,
    exit: Option<FunctionExit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IndexedSource {
    source_id: u64,
    offset: u64,
    length: u64,
    line: Option<u64>,
    column: Option<u64>,
}

impl IndexedSource {
    fn is_within(self, declaration: &SourceLocation) -> bool {
        if self.source_id != declaration.source_id || self.offset < declaration.offset {
            return false;
        }
        match (
            self.offset.checked_add(self.length),
            declaration.offset.checked_add(declaration.length),
        ) {
            (Some(end), Some(declaration_end)) => end <= declaration_end,
            _ => false,
        }
    }
}

#[derive(Debug)]
struct SourceTextIndex {
    line_starts: Vec<u64>,
    len: u64,
}

impl SourceTextIndex {
    fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            source
                .bytes()
                .enumerate()
                .filter(|(_, byte)| *byte == b'\n')
                .filter_map(|(index, _)| u64::try_from(index).ok()?.checked_add(1)),
        );
        Self {
            line_starts,
            len: u64::try_from(source.len()).unwrap_or(u64::MAX),
        }
    }

    fn position(&self, offset: u64) -> Option<(u64, u64)> {
        if offset > self.len {
            return None;
        }
        let line_index = self.line_starts.partition_point(|start| *start <= offset);
        let line_index = line_index.saturating_sub(1);
        let line_start = self.line_starts.get(line_index).copied().unwrap_or(0);
        Some((
            u64::try_from(line_index)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
            offset.saturating_sub(line_start).saturating_add(1),
        ))
    }

    fn line<'a>(&self, source: &'a str, line: u64) -> Option<&'a str> {
        let index = usize::try_from(line.checked_sub(1)?).ok()?;
        let start = usize::try_from(*self.line_starts.get(index)?).ok()?;
        let end = self
            .line_starts
            .get(index.checked_add(1)?)
            .and_then(|end| end.checked_sub(1))
            .and_then(|end| usize::try_from(end).ok())
            .unwrap_or(source.len());
        source
            .get(start..end)
            .map(|line| line.trim_end_matches('\r'))
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Metrics {
    gas: u64,
    hits: u64,
}

impl Metrics {
    fn add(&mut self, gas: u64, label: &str) -> SoldbResult<()> {
        self.gas = self
            .gas
            .checked_add(gas)
            .ok_or_else(|| SoldbError::Message(format!("{label} overflow")))?;
        self.hits = self
            .hits
            .checked_add(1)
            .ok_or_else(|| SoldbError::Message(format!("{label} hit count overflow")))?;
        Ok(())
    }

    fn merge(&mut self, other: Self, label: &str) -> SoldbResult<()> {
        self.gas = self
            .gas
            .checked_add(other.gas)
            .ok_or_else(|| SoldbError::Message(format!("{label} overflow")))?;
        self.hits = self
            .hits
            .checked_add(other.hits)
            .ok_or_else(|| SoldbError::Message(format!("{label} hit count overflow")))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProgramKey {
    address: String,
    environment: ProgramEnvironment,
    code_hash: Option<String>,
}

fn build_program_lookup(programs: &[ProfileProgram]) -> SoldbResult<HashMap<ProgramKey, usize>> {
    let mut lookup = HashMap::with_capacity(programs.len());
    for (index, program) in programs.iter().enumerate() {
        let Some(address) = &program.address else {
            continue;
        };
        let key = ProgramKey {
            address: address.clone(),
            environment: program.environment,
            code_hash: program.code_hash.clone(),
        };
        if lookup.insert(key, index).is_some() {
            return Err(SoldbError::Message(format!(
                "duplicate {:?} ETHDebug program for `{address}`",
                program.environment
            )));
        }
    }
    Ok(lookup)
}

/// The program a frame at `address` runs. A frame that records `code_hash` takes the program
/// with that hash, else one without a hash; a frame without one takes the program without a
/// hash, else the only program at the address.
fn lookup_program(
    address: Option<&str>,
    code_hash: Option<&str>,
    environment: ProgramEnvironment,
    programs: &[ProfileProgram],
    lookup: &HashMap<ProgramKey, usize>,
) -> Option<usize> {
    if let Some(address) = address {
        let address = normalize_address(address);
        let key = |code_hash: Option<String>| ProgramKey {
            address: address.clone(),
            environment,
            code_hash,
        };
        if let Some(code_hash) = code_hash {
            if let Some(index) = lookup.get(&key(Some(normalize_address(code_hash)))) {
                return Some(*index);
            }
        }
        if let Some(index) = lookup.get(&key(None)) {
            return Some(*index);
        }
        if code_hash.is_some() {
            return None;
        }
        let mut at_address = programs.iter().enumerate().filter(|(_, program)| {
            program.environment == environment
                && program.address.as_deref() == Some(address.as_str())
        });
        let candidate = at_address.next().map(|(index, _)| index)?;
        return at_address.next().is_none().then_some(candidate);
    }

    let mut candidates = programs
        .iter()
        .enumerate()
        .filter(|(_, program)| program.environment == environment);
    let candidate = candidates.next().map(|(index, _)| index)?;
    candidates.next().is_none().then_some(candidate)
}

#[derive(Debug)]
struct ExecutionFrame {
    entry: usize,
    exit: usize,
    depth: u64,
    program: Option<usize>,
    label: String,
}

fn build_execution_frames(
    trace: &TransactionTrace,
    programs: &[ProfileProgram],
    lookup: &HashMap<ProgramKey, usize>,
) -> Vec<ExecutionFrame> {
    let step_count = trace.steps.len();
    let calls = trace.artifacts.calls.iter().filter_map(|call| {
        let entry = call.entry_step?;
        let exit = call.exit_step.unwrap_or(step_count).min(step_count);
        (entry < exit && entry < step_count).then(|| {
            let program = lookup_program(
                Some(&call.bytecode_address),
                call.code_hash.as_deref(),
                ProgramEnvironment::Call,
                programs,
                lookup,
            );
            let target = program.map_or_else(
                || normalize_address(&call.bytecode_address),
                |index| program_label(&programs[index]),
            );
            ExecutionFrame {
                entry,
                exit,
                depth: call.depth,
                program,
                label: format!("{} {target}", call.call_type),
            }
        })
    });
    let creations = trace.artifacts.creations.iter().filter_map(|creation| {
        let entry = creation.entry_step?;
        let exit = creation.exit_step.unwrap_or(step_count).min(step_count);
        (entry < exit && entry < step_count).then(|| {
            let program = lookup_program(
                creation.address.as_deref(),
                creation.code_hash.as_deref(),
                ProgramEnvironment::Create,
                programs,
                lookup,
            );
            let target = program.map_or_else(
                || {
                    creation
                        .address
                        .as_deref()
                        .map_or_else(|| "<unknown>".to_owned(), normalize_address)
                },
                |index| program_label(&programs[index]),
            );
            ExecutionFrame {
                entry,
                exit,
                depth: creation.depth,
                program,
                label: format!("{} {target}", creation.create_type),
            }
        })
    });
    calls.chain(creations).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameEventKind {
    End,
    Start,
}

#[derive(Debug, Clone, Copy)]
struct FrameEvent {
    step: usize,
    frame: usize,
    kind: FrameEventKind,
}

fn build_frame_events(frames: &[ExecutionFrame]) -> Vec<FrameEvent> {
    let mut events = Vec::with_capacity(frames.len().saturating_mul(2));
    for (frame, record) in frames.iter().enumerate() {
        events.push(FrameEvent {
            step: record.entry,
            frame,
            kind: FrameEventKind::Start,
        });
        events.push(FrameEvent {
            step: record.exit,
            frame,
            kind: FrameEventKind::End,
        });
    }
    events.sort_by_key(|event| (event.step, matches!(event.kind, FrameEventKind::Start)));
    events
}

#[derive(Debug)]
struct FrameCursor {
    events: Vec<FrameEvent>,
    next_event: usize,
    active: Vec<usize>,
}

impl FrameCursor {
    fn new(events: Vec<FrameEvent>) -> Self {
        Self {
            events,
            next_event: 0,
            active: Vec::new(),
        }
    }

    fn advance(&mut self, step: usize, frames: &[ExecutionFrame]) -> bool {
        let start = self.next_event;
        while let Some(event) = self.events.get(self.next_event).copied() {
            if event.step > step {
                break;
            }
            match event.kind {
                FrameEventKind::End => self.active.retain(|frame| *frame != event.frame),
                FrameEventKind::Start => self.active.push(event.frame),
            }
            self.next_event += 1;
        }
        if self.next_event != start {
            self.active.sort_by_key(|frame| frames[*frame].depth);
            true
        } else {
            false
        }
    }

    fn current_index(&self, frames: &[ExecutionFrame], step_depth: u64) -> Option<usize> {
        self.active
            .iter()
            .rev()
            .copied()
            .find(|frame| frames[*frame].depth == step_depth)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FunctionFrameKey {
    Root(u64),
    External(usize),
}

fn intern_function_path(
    stack: &[usize],
    paths: &mut Vec<Vec<usize>>,
    lookup: &mut HashMap<Vec<usize>, usize>,
) -> usize {
    if let Some(path) = lookup.get(stack).copied() {
        return path;
    }
    let path = paths.len();
    let stack = stack.to_vec();
    paths.push(stack.clone());
    lookup.insert(stack, path);
    path
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FunctionKey {
    program: usize,
    function: Option<usize>,
    has_source: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SourceLineKey {
    program: usize,
    source_id: u64,
    line: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HotspotKey {
    program: usize,
    pc: u64,
    source: Option<IndexedSource>,
}

#[derive(Debug)]
struct HotspotMetrics<'a> {
    opcode: &'a str,
    context_matches: bool,
    /// The function of the first sample; named only if every sample ran in it, since a
    /// helper shared by several functions belongs to none of them.
    function: Option<usize>,
    functions_agree: bool,
    metrics: Metrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlameSourceKey {
    source_id: u64,
    line: Option<u64>,
    offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FoldedKey {
    path: usize,
    program: Option<usize>,
    function_path: usize,
    source: Option<FlameSourceKey>,
    unmapped_depth: Option<u64>,
}

fn contract_rows(
    programs: &[ProfileProgram],
    metrics: HashMap<usize, Metrics>,
) -> Vec<ContractProfile> {
    let mut rows = metrics
        .into_iter()
        .map(|(program, metrics)| {
            let program = &programs[program];
            ContractProfile {
                address: program.address.clone(),
                contract: program.contract_name.clone(),
                environment: program.environment,
                gas: metrics.gas,
                hits: metrics.hits,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| (Reverse(row.gas), Reverse(row.hits), row.contract.clone()));
    rows
}

fn function_rows(
    programs: &[ProfileProgram],
    metrics: HashMap<FunctionKey, Metrics>,
) -> Vec<FunctionProfile> {
    let mut rows = metrics
        .into_iter()
        .map(|(key, metrics)| {
            let program = &programs[key.program];
            let function = key.function.map(|function| &program.functions[function]);
            let declaration = function.and_then(|function| function.identity.declaration.as_ref());
            let source_id = declaration.map(|declaration| declaration.source_id);
            let source = source_id.and_then(|source_id| program.debug.info.sources.get(&source_id));
            let line = declaration.and_then(|declaration| {
                program
                    .source_indexes
                    .get(&declaration.source_id)
                    .and_then(|index| index.position(declaration.offset))
                    .map(|position| position.0)
            });
            FunctionProfile {
                address: program.address.clone(),
                contract: program.contract_name.clone(),
                environment: program.environment,
                function: function.map_or_else(
                    || {
                        if key.has_source {
                            "<contract>".to_owned()
                        } else {
                            "<no source>".to_owned()
                        }
                    },
                    |function| function.name().to_owned(),
                ),
                source: source.cloned(),
                line,
                gas: metrics.gas,
                hits: metrics.hits,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| {
        (
            Reverse(row.gas),
            Reverse(row.hits),
            row.contract.clone(),
            row.function.clone(),
        )
    });
    rows
}

fn source_line_rows(
    programs: &[ProfileProgram],
    metrics: HashMap<SourceLineKey, Metrics>,
) -> Vec<SourceLineProfile> {
    let mut rows = metrics
        .into_iter()
        .filter_map(|(key, metrics)| {
            let program = &programs[key.program];
            let path = program.debug.info.sources.get(&key.source_id)?.clone();
            let text = program
                .debug
                .source_contents
                .get(&key.source_id)
                .and_then(|source| {
                    program
                        .source_indexes
                        .get(&key.source_id)?
                        .line(source, key.line)
                })
                .map(|line| line.trim().to_owned());
            Some(SourceLineProfile {
                address: program.address.clone(),
                contract: program.contract_name.clone(),
                source: path,
                line: key.line,
                text,
                gas: metrics.gas,
                hits: metrics.hits,
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| {
        (
            Reverse(row.gas),
            Reverse(row.hits),
            row.source.clone(),
            row.line,
        )
    });
    rows
}

fn opcode_rows(metrics: HashMap<&str, Metrics>) -> Vec<OpcodeProfile> {
    let mut rows = metrics
        .into_iter()
        .map(|(opcode, metrics)| OpcodeProfile {
            opcode: opcode.to_owned(),
            gas: metrics.gas,
            hits: metrics.hits,
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| (Reverse(row.gas), Reverse(row.hits), row.opcode.clone()));
    rows
}

fn hotspot_rows(
    programs: &[ProfileProgram],
    metrics: HashMap<HotspotKey, HotspotMetrics<'_>>,
) -> Vec<InstructionProfile> {
    let mut rows = metrics
        .into_iter()
        .map(|(key, hotspot)| {
            let program = &programs[key.program];
            InstructionProfile {
                address: program.address.clone(),
                contract: program.contract_name.clone(),
                environment: program.environment,
                pc: key.pc,
                opcode: hotspot.opcode.to_owned(),
                function: (hotspot.context_matches && hotspot.functions_agree)
                    .then_some(hotspot.function)
                    .flatten()
                    .map(|function| program.functions[function].name().to_owned()),
                source: hotspot
                    .context_matches
                    .then_some(key.source)
                    .flatten()
                    .and_then(|source| profile_source_location(program, &source)),
                gas: hotspot.metrics.gas,
                hits: hotspot.metrics.hits,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| {
        (
            Reverse(row.gas),
            Reverse(row.hits),
            row.contract.clone(),
            row.pc,
        )
    });
    rows
}

fn profile_source_location(
    program: &ProfileProgram,
    source: &IndexedSource,
) -> Option<ProfileSourceLocation> {
    Some(ProfileSourceLocation {
        path: program.debug.info.sources.get(&source.source_id)?.clone(),
        offset: source.offset,
        length: source.length,
        line: source.line,
        column: source.column,
    })
}

fn folded_rows(
    programs: &[ProfileProgram],
    frames: &[ExecutionFrame],
    paths: &[Vec<usize>],
    function_paths: &[Vec<usize>],
    root_label: &str,
    root_program: Option<usize>,
    metrics: HashMap<FoldedKey, Metrics>,
) -> SoldbResult<Vec<FoldedStack>> {
    let mut merged = BTreeMap::<Vec<String>, Metrics>::new();
    for (key, metrics) in metrics {
        let mut labels = vec![root_label.to_owned()];
        if let Some(path) = paths.get(key.path) {
            labels.extend(
                path.iter()
                    .filter_map(|frame| frames.get(*frame).map(|frame| frame.label.clone())),
            );
        }

        if let Some(program_index) = key.program {
            let program = &programs[program_index];
            let program_name = program_label(program);
            let path_has_program = paths.get(key.path).is_some_and(|path| {
                path.iter().any(|frame| {
                    frames
                        .get(*frame)
                        .is_some_and(|frame| frame.program == Some(program_index))
                })
            });
            if root_program != Some(program_index) && !path_has_program {
                labels.push(program_name);
            }
            let functions = function_paths
                .get(key.function_path)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if functions.is_empty() {
                labels.push(format!("{}::<generated>", program.contract_name));
            } else {
                labels.extend(functions.iter().map(|&function| {
                    format!(
                        "{}::{}",
                        program.contract_name,
                        program.functions[function].name()
                    )
                }));
            }
            if let Some(source) = key.source {
                let path = program
                    .debug
                    .info
                    .sources
                    .get(&source.source_id)
                    .cloned()
                    .unwrap_or_else(|| format!("source: {}", source.source_id));
                labels.push(source.line.map_or_else(
                    || format!("{path}@{}", source.offset.unwrap_or(0)),
                    |line| format!("{path}:{line}"),
                ));
            } else {
                labels.push("[no source]".to_owned());
            }
        } else {
            labels.push(format!(
                "[unmapped depth {}]",
                key.unmapped_depth.unwrap_or(0)
            ));
        }
        merged
            .entry(labels)
            .or_default()
            .merge(metrics, "folded-stack gas")?;
    }

    let mut rows = merged
        .into_iter()
        .map(|(frames, metrics)| FoldedStack {
            frames,
            gas: metrics.gas,
            hits: metrics.hits,
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| (Reverse(row.gas), Reverse(row.hits), row.frames.clone()));
    Ok(rows)
}

fn program_label(program: &ProfileProgram) -> String {
    program.address.as_ref().map_or_else(
        || program.contract_name.clone(),
        |address| format!("{} [{address}]", program.contract_name),
    )
}

fn normalize_address(address: &str) -> String {
    let address = address.trim();
    if address.starts_with("0x") || address.starts_with("0X") {
        format!("0x{}", address[2..].to_ascii_lowercase())
    } else {
        format!("0x{}", address.to_ascii_lowercase())
    }
}

fn sanitize_folded_frame(frame: &str) -> String {
    frame
        .chars()
        .map(|character| {
            if matches!(character, ';' | '\n' | '\r') {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use soldb_core::{
        ContractCreation, ExecutionCall, StepSnapshot, TraceArtifacts, TraceCapabilities,
        TraceStep, TransactionTrace,
    };
    use soldb_ethdebug::{source_range, EthdebugInfo, Instruction};

    use super::{profile_transaction, ProfileProgram, ProfileReport};

    #[test]
    fn attributes_gas_to_source_functions_and_opcodes() {
        let source =
            "contract Counter {\n    function add() external {\n        uint x = 1;\n    }\n}\n";
        let offset = source.find("uint x").expect("statement offset") as u64;
        let program = program_with_function(
            Some("0xCAFE"),
            "Counter",
            "call",
            source,
            &[(0, "PUSH1", offset), (2, "ADD", offset)],
            "add",
        );
        let trace = trace(
            Some("0xcafe"),
            vec![step(0, "PUSH1", 3, 0), step(2, "ADD", 5, 0)],
        );

        let report = profile_transaction(&trace, &[program]).expect("profile");

        assert_eq!(report.totals.step_gas, 8);
        assert_eq!(report.totals.program_gas, 8);
        assert_eq!(report.totals.source_gas, 8);
        assert_eq!(report.totals.unmapped_gas, 0);
        assert_eq!(report.contracts[0].contract, "Counter");
        assert_eq!(report.functions[0].function, "add");
        assert_eq!(report.source_lines[0].line, 3);
        assert_eq!(report.source_lines[0].text.as_deref(), Some("uint x = 1;"));
        assert_eq!(report.opcodes[0].opcode, "ADD");
        assert_eq!(report.hotspots[0].pc, 2);
        assert!(report.folded_text().contains("Counter::add"));
        assert!(report.folded_text().contains("Counter.sol:3"));
    }

    #[test]
    fn names_functions_the_program_does_not_mark() {
        let source =
            "contract Counter {\n    function add() external {\n        uint x = 1;\n    }\n}\n";
        let offset = source.find("uint x").expect("statement offset") as u64;
        let program = program(
            Some("0xcafe"),
            "Counter",
            "call",
            source,
            &[(0, "PUSH1", offset)],
        );
        let trace = trace(Some("0xcafe"), vec![step(0, "PUSH1", 3, 0)]);

        let report = profile_transaction(&trace, &[program]).expect("profile");

        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].function, "add");
        assert_eq!(report.functions[0].line, Some(2));
    }

    #[test]
    fn names_anonymous_functions_and_charges_their_helpers_to_them() {
        let source =
            "contract Counter {\n    function add() external {\n        uint x = 1;\n    }\n}\n";
        let offset = source.find("uint x").expect("statement offset") as u64;
        let code = source_range(0, offset, 1);
        // A legacy map's jump into a function carries no name, and its helpers no source.
        let program = program_from_contexts(
            "Counter",
            source,
            &[
                (0, "JUMP", json!({"code": code, "invoke": {}})),
                (1, "PUSH1", json!({"code": code})),
                (3, "JUMP", json!({"invoke": {}})),
                (4, "ADD", json!({})),
            ],
        );
        let trace = trace(
            Some("0xcafe"),
            vec![
                step(0, "JUMP", 8, 0),
                step(1, "PUSH1", 3, 0),
                step(3, "JUMP", 8, 0),
                step(4, "ADD", 3, 0),
            ],
        );

        let report = profile_transaction(&trace, &[program]).expect("profile");

        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].function, "add");
        assert_eq!(report.functions[0].gas, 22);
    }

    #[test]
    fn does_not_charge_dispatcher_helpers_to_a_returned_function() {
        let source =
            "contract Counter {\n    function add() external {\n        uint x = 1;\n    }\n}\n";
        let offset = source.find("uint x").expect("statement offset") as u64;
        let code = source_range(0, offset, 1);
        // After `add` returns, the dispatcher jumps into an unnamed encoder helper.
        let program = program_from_contexts(
            "Counter",
            source,
            &[
                (0, "PUSH1", json!({"code": code})),
                (2, "JUMP", json!({"return": {}})),
                (3, "JUMP", json!({"invoke": {}})),
                (10, "ADD", json!({})),
            ],
        );
        let trace = trace(
            Some("0xcafe"),
            vec![
                step(0, "PUSH1", 3, 0),
                step(2, "JUMP", 8, 0),
                step(3, "JUMP", 8, 0),
                step(10, "ADD", 3, 0),
            ],
        );

        let report = profile_transaction(&trace, &[program]).expect("profile");

        let add = report
            .functions
            .iter()
            .find(|row| row.function == "add")
            .expect("add row");
        assert_eq!(add.gas, 3);
    }

    #[test]
    fn keeps_one_hotspot_for_a_helper_shared_by_functions() {
        let source = "contract Counter {\n    function add() external { uint x = 1; }\n    function sub() external { uint y = 2; }\n}\n";
        let add = source.find("uint x").expect("add statement") as u64;
        let sub = source.find("uint y").expect("sub statement") as u64;
        let add = source_range(0, add, 1);
        let sub = source_range(0, sub, 1);
        let program = program_from_contexts(
            "Counter",
            source,
            &[
                (0, "PUSH1", json!({"code": add})),
                (2, "JUMP", json!({"code": add, "invoke": {}})),
                (3, "PUSH1", json!({"code": sub})),
                (5, "JUMP", json!({"code": sub, "invoke": {}})),
                (10, "ADD", json!({})),
                (11, "JUMP", json!({"return": {}})),
            ],
        );
        let trace = trace(
            Some("0xcafe"),
            vec![
                step(0, "PUSH1", 3, 0),
                step(2, "JUMP", 8, 0),
                step(10, "ADD", 3, 0),
                step(11, "JUMP", 8, 0),
                step(3, "PUSH1", 3, 0),
                step(5, "JUMP", 8, 0),
                step(10, "ADD", 3, 0),
                step(11, "JUMP", 8, 0),
            ],
        );

        let report = profile_transaction(&trace, &[program]).expect("profile");

        let helper = report
            .hotspots
            .iter()
            .filter(|hotspot| hotspot.pc == 10)
            .collect::<Vec<_>>();
        assert_eq!(helper.len(), 1);
        assert_eq!(helper[0].gas, 6);
        assert_eq!(helper[0].function, None);
        let functions = report
            .functions
            .iter()
            .map(|row| (row.function.as_str(), row.gas))
            .collect::<Vec<_>>();
        assert_eq!(functions, vec![("add", 22), ("sub", 22)]);
    }

    #[test]
    fn resolves_shared_code_from_function_context() {
        let source = "contract Shared {\n    function add() external { total = 1; }\n    function calculate() external { total = 1; }\n}\n";
        let add_statement = source.find("total = 1").expect("add statement") as u64;
        let calculate_declaration = source.find("function calculate").expect("declaration") as u64;
        let calculate_statement = source
            .get(calculate_declaration as usize..)
            .and_then(|tail| tail.find("total = 1"))
            .map(|offset| calculate_declaration + offset as u64)
            .expect("calculate statement");
        let declaration_length = source.len() as u64 - calculate_declaration;
        let instructions = vec![
            Instruction::new(
                0,
                "JUMPDEST",
                Some(json!({
                    "invoke": {
                        "identifier": "calculate",
                        "declaration": source_range(0, calculate_declaration, declaration_length),
                        "jump": true
                    }
                })),
            ),
            Instruction::new(
                1,
                "SSTORE",
                Some(json!({
                    "pick": [
                        {"code": source_range(0, add_statement, 10)},
                        {"code": source_range(0, calculate_statement, 10)}
                    ]
                })),
            ),
            Instruction::new(2, "STOP", Some(json!({"return": {}}))),
        ];
        let program = ProfileProgram::new(
            Some("0x1".to_owned()),
            EthdebugInfo {
                compilation: json!({}),
                contract_name: "Shared".to_owned(),
                environment: "call".to_owned(),
                instructions,
                sources: BTreeMap::from([(0, "Shared.sol".to_owned())]),
                variable_locations: BTreeMap::new(),
            },
            BTreeMap::from([(0, source.to_owned())]),
        )
        .expect("profile program");
        let trace = trace(
            Some("0x1"),
            vec![
                step(0, "JUMPDEST", 1, 0),
                step(1, "SSTORE", 100, 0),
                step(2, "STOP", 0, 0),
            ],
        );

        let report = profile_transaction(&trace, &[program]).expect("profile");

        assert!(report
            .functions
            .iter()
            .any(|row| row.function == "calculate" && row.gas == 100));
        let hotspot = report
            .hotspots
            .iter()
            .find(|row| row.pc == 1)
            .expect("shared hotspot");
        assert_eq!(hotspot.function.as_deref(), Some("calculate"));
        assert_eq!(
            hotspot.source.as_ref().map(|source| source.offset),
            Some(calculate_statement)
        );
        assert!(!report.folded_text().contains("Shared::add"));
        assert!(report.folded_text().contains("Shared::calculate"));
    }

    #[test]
    fn uses_replay_call_ranges_for_nested_contracts() {
        let root = program(
            Some("0x1"),
            "Root",
            "call",
            "contract Root { function run() external {} }",
            &[(0, "CALL", 16)],
        );
        let child = program(
            Some("0x2"),
            "Child",
            "call",
            "contract Child { function work() external {} }",
            &[(0, "SLOAD", 17)],
        );
        let mut trace = trace(
            Some("0x1"),
            vec![
                step(0, "CALL", 10, 0),
                step(0, "SLOAD", 100, 1),
                step(0, "CALL", 10, 0),
            ],
        );
        trace.capabilities.call_trace = true;
        trace.artifacts.calls.push(ExecutionCall {
            id: 0,
            parent_id: None,
            depth: 1,
            entry_step: Some(1),
            exit_step: Some(2),
            call_type: "CALL".to_owned(),
            from: "0x1".to_owned(),
            to: "0x2".to_owned(),
            bytecode_address: "0x2".to_owned(),
            value: "0".to_owned(),
            input: "0x".to_owned(),
            gas_limit: 100_000,
            gas_used: Some(100),
            output: Some("0x".to_owned()),
            success: Some(true),
            error: None,
            code_hash: None,
        });

        let report = profile_transaction(&trace, &[root, child]).expect("profile");

        assert_eq!(report.contracts.len(), 2);
        assert_eq!(report.contracts[0].contract, "Child");
        assert_eq!(report.contracts[0].gas, 100);
        assert!(report.folded_stacks.iter().any(|stack| stack
            .frames
            .iter()
            .any(|frame| frame.contains("CALL Child"))));
    }

    #[test]
    fn maps_programs_at_one_address_by_code_hash() {
        // Two programs run at 0x2, as after a test replaces the code there.
        let root = program(
            Some("0x1"),
            "Root",
            "call",
            "contract Root { function run() external {} }",
            &[(0, "CALL", 16)],
        );
        let original = program(
            Some("0x2"),
            "Original",
            "call",
            "contract Original { function work() external {} }",
            &[(0, "SLOAD", 20)],
        )
        .with_code_hash(Some("0x0A"));
        let replaced = program(
            Some("0x2"),
            "Replaced",
            "call",
            "contract Replaced { function work() external {} }",
            &[(0, "SSTORE", 20)],
        )
        .with_code_hash(Some("0x0b"));
        let mut trace = trace(
            Some("0x1"),
            vec![
                step(0, "CALL", 10, 0),
                step(0, "SLOAD", 100, 1),
                step(0, "CALL", 10, 0),
                step(0, "SSTORE", 200, 1),
                step(0, "STOP", 0, 0),
            ],
        );
        trace.capabilities.call_trace = true;
        for (id, entry_step, code_hash) in [(0, 1, "0x0a"), (1, 3, "0x0B")] {
            trace.artifacts.calls.push(ExecutionCall {
                id,
                parent_id: None,
                depth: 1,
                entry_step: Some(entry_step),
                exit_step: Some(entry_step + 1),
                call_type: "CALL".to_owned(),
                from: "0x1".to_owned(),
                to: "0x2".to_owned(),
                bytecode_address: "0x2".to_owned(),
                value: "0".to_owned(),
                input: "0x".to_owned(),
                gas_limit: 100_000,
                gas_used: Some(100),
                output: Some("0x".to_owned()),
                success: Some(true),
                error: None,
                code_hash: Some(code_hash.to_owned()),
            });
        }

        let report = profile_transaction(&trace, &[root, original, replaced]).expect("profile");

        let gas = |name: &str| {
            report
                .contracts
                .iter()
                .find(|contract| contract.contract == name)
                .map(|contract| contract.gas)
        };
        assert_eq!(gas("Original"), Some(100));
        assert_eq!(gas("Replaced"), Some(200));
    }

    #[test]
    fn leaves_unidentified_nested_debug_rpc_steps_unmapped() {
        let root = program(
            Some("0x1"),
            "Root",
            "call",
            "contract Root { function run() external {} }",
            &[(0, "CALL", 16)],
        );
        let trace = trace(
            Some("0x1"),
            vec![step(0, "CALL", 10, 0), step(0, "SLOAD", 100, 1)],
        );

        let report = profile_transaction(&trace, &[root]).expect("profile");

        assert_eq!(report.totals.step_gas, 110);
        assert_eq!(report.totals.program_gas, 10);
        assert_eq!(report.totals.unmapped_gas, 100);
    }

    #[test]
    fn leaves_replay_calls_without_programs_unmapped() {
        let root = program(
            Some("0x1"),
            "Root",
            "call",
            "contract Root { function run() external {} }",
            &[(0, "CALL", 16)],
        );
        let mut trace = trace(
            Some("0x1"),
            vec![step(0, "CALL", 10, 0), step(0, "SLOAD", 100, 1)],
        );
        trace.artifacts.calls.push(ExecutionCall {
            id: 0,
            parent_id: None,
            depth: 1,
            entry_step: Some(1),
            exit_step: Some(2),
            call_type: "CALL".to_owned(),
            from: "0x1".to_owned(),
            to: "0x2".to_owned(),
            bytecode_address: "0x2".to_owned(),
            value: "0".to_owned(),
            input: "0x".to_owned(),
            gas_limit: 100_000,
            gas_used: Some(100),
            output: Some("0x".to_owned()),
            success: Some(true),
            error: None,
            code_hash: None,
        });

        let report = profile_transaction(&trace, &[root]).expect("profile");

        assert_eq!(report.totals.program_gas, 10);
        assert_eq!(report.totals.unmapped_gas, 100);
        assert!(report.folded_text().contains("CALL 0x2"));
    }

    #[test]
    fn rejects_gas_overflow() {
        let trace = trace(
            Some("0x1"),
            vec![step(0, "ADD", u64::MAX, 0), step(1, "ADD", 1, 0)],
        );
        let error = profile_transaction(&trace, &[]).expect_err("overflow");
        assert!(error.to_string().contains("total step gas overflow"));
    }

    #[test]
    fn profiles_creation_programs_at_root_and_nested_depths() {
        let creation = program(
            Some("0x3"),
            "Created",
            "create",
            "contract Created { constructor() {} }",
            &[(0, "PUSH1", 19)],
        );
        let mut root_creation = trace(None, vec![step(0, "PUSH1", 7, 0)]);
        root_creation.contract_address = Some("0x3".to_owned());

        let report = profile_transaction(&root_creation, &[creation]).expect("root creation");
        assert_eq!(report.contracts[0].contract, "Created");
        assert_eq!(
            report.contracts[0].environment,
            super::ProgramEnvironment::Create
        );

        let root = program(
            Some("0x1"),
            "Factory",
            "call",
            "contract Factory { function deploy() external {} }",
            &[(0, "CREATE", 19)],
        );
        let creation = program(
            Some("0x3"),
            "Created",
            "create",
            "contract Created { constructor() {} }",
            &[(0, "PUSH1", 19)],
        );
        let mut nested = trace(
            Some("0x1"),
            vec![step(0, "CREATE", 32_000, 0), step(0, "PUSH1", 3, 1)],
        );
        nested.artifacts.creations.push(ContractCreation {
            id: 0,
            parent_id: None,
            depth: 1,
            entry_step: Some(1),
            exit_step: Some(2),
            create_type: "CREATE".to_owned(),
            caller: "0x1".to_owned(),
            address: Some("0x3".to_owned()),
            value: "0".to_owned(),
            init_code: "0x60".to_owned(),
            gas_limit: 100_000,
            gas_used: Some(3),
            output: Some("0x".to_owned()),
            success: Some(true),
            error: None,
            code_hash: None,
        });

        let report = profile_transaction(&nested, &[root, creation]).expect("nested creation");
        assert_eq!(report.contracts.len(), 2);
        assert!(report.folded_stacks.iter().any(|stack| stack
            .frames
            .iter()
            .any(|frame| frame.contains("CREATE Created"))));
    }

    #[test]
    fn rejects_duplicate_program_addresses() {
        let first = program(Some("0x1"), "First", "call", "contract First {}", &[]);
        let second = program(Some("0x1"), "Second", "call", "contract Second {}", &[]);
        let error = profile_transaction(&trace(Some("0x1"), Vec::new()), &[first, second])
            .expect_err("duplicate program");
        assert!(error
            .to_string()
            .contains("duplicate Call ETHDebug program"));
    }

    #[test]
    fn rejects_invalid_program_metadata() {
        let invalid_environment = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Counter".to_owned(),
            environment: "unknown".to_owned(),
            instructions: Vec::new(),
            sources: BTreeMap::new(),
            variable_locations: BTreeMap::new(),
        };
        let error = ProfileProgram::new(None, invalid_environment, BTreeMap::new())
            .expect_err("invalid environment");
        assert!(error
            .to_string()
            .contains("unknown ETHDebug program environment"));

        let instruction = Instruction::new(0, "STOP", None);
        let duplicate_instructions = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Counter".to_owned(),
            environment: "call".to_owned(),
            instructions: vec![instruction.clone(), instruction],
            sources: BTreeMap::new(),
            variable_locations: BTreeMap::new(),
        };
        let error = ProfileProgram::new(None, duplicate_instructions, BTreeMap::new())
            .expect_err("duplicate PC");
        assert!(error.to_string().contains("duplicate ETHDebug instruction"));
    }

    #[test]
    fn does_not_source_map_mismatched_opcodes() {
        let source = "contract Counter { function add() external {} }";
        let program = program(Some("0x1"), "Counter", "call", source, &[(0, "ADD", 19)]);
        let trace = trace(Some("0x1"), vec![step(0, "SUB", 3, 0)]);

        let report = profile_transaction(&trace, &[program]).expect("profile");

        assert_eq!(report.totals.program_gas, 3);
        assert_eq!(report.totals.source_gas, 0);
        assert_eq!(report.functions[0].function, "<no source>");
        assert!(report.source_lines.is_empty());
        assert_eq!(report.hotspots[0].source, None);
    }

    #[test]
    fn does_not_count_gas_forwarded_to_a_call() {
        // The CALL reports 618: 118 its own and 500 forwarded, of which the callee spends 3.
        let trace = trace(
            Some("0x1"),
            vec![
                gas_step("PUSH1", 1_000, 3, 1),
                gas_step("CALL", 997, 618, 1),
                gas_step("PUSH1", 500, 3, 2),
                gas_step("STOP", 497, 0, 2),
                gas_step("STOP", 876, 0, 1),
            ],
        );

        let report = profile_transaction(&trace, &[]).expect("profile");

        assert_eq!(opcode_gas(&report, "CALL"), 118);
        // Each step is counted once, so the total is what the caller lost.
        assert_eq!(report.totals.step_gas, 1_000 - 876);
    }

    #[test]
    fn does_not_count_gas_forwarded_to_nested_calls_and_creations() {
        let trace = trace(
            Some("0x1"),
            vec![
                gas_step("CALL", 100_000, 90_100, 1),
                gas_step("CREATE", 90_000, 82_032, 2),
                gas_step("STOP", 50_000, 0, 3),
                gas_step("STOP", 57_968, 0, 2),
                gas_step("STOP", 67_868, 0, 1),
            ],
        );

        let report = profile_transaction(&trace, &[]).expect("profile");

        assert_eq!(opcode_gas(&report, "CALL"), 100);
        assert_eq!(opcode_gas(&report, "CREATE"), 32_032);
        assert_eq!(report.totals.step_gas, 100_000 - 67_868);
    }

    #[test]
    fn charges_a_value_call_net_of_the_stipend() {
        // A `CALL` sending 1 wei: 9,100 its own, of which the 2,300 stipend comes back.
        let trace = trace(
            Some("0x1"),
            vec![
                gas_step("CALL", 29_548, 29_229, 1),
                gas_step("PUSH1", 22_429, 3, 2),
                gas_step("SSTORE", 22_426, 22_100, 2),
                gas_step("STOP", 326, 0, 2),
                gas_step("STOP", 645, 0, 1),
            ],
        );

        let report = profile_transaction(&trace, &[]).expect("profile");

        assert_eq!(opcode_gas(&report, "CALL"), 6_800);
        assert_eq!(report.totals.step_gas, 29_548 - 645);
    }

    #[test]
    fn does_not_count_gas_forwarded_through_a_frame_without_steps() {
        // A cheatcode runs no steps and forwards everything to the creation it makes.
        let trace = trace(
            Some("0x1"),
            vec![
                gas_step("CALL", 100_000, 98_600, 1),
                gas_step("STOP", 96_000, 0, 3),
                gas_step("STOP", 97_400, 0, 1),
            ],
        );

        let report = profile_transaction(&trace, &[]).expect("profile");

        assert_eq!(opcode_gas(&report, "CALL"), 2_600);
    }

    #[test]
    fn keeps_a_creation_cost_reported_without_forwarded_gas() {
        // geth reports 32,000 and forwards the 7,875 left after the 1/64 it keeps.
        let trace = trace(
            Some("0x1"),
            vec![
                gas_step("CREATE", 40_000, 32_000, 1),
                gas_step("STOP", 7_875, 0, 2),
                gas_step("STOP", 8_000, 0, 1),
            ],
        );

        let report = profile_transaction(&trace, &[]).expect("profile");

        assert_eq!(opcode_gas(&report, "CREATE"), 32_000);
    }

    #[test]
    fn charges_a_call_without_steps_what_the_caller_lost() {
        // A precompile runs no steps: 118 for the call and 100 for the precompile.
        let trace = trace(
            Some("0x1"),
            vec![
                gas_step("STATICCALL", 1_000, 700, 1),
                gas_step("STOP", 782, 0, 1),
            ],
        );

        let report = profile_transaction(&trace, &[]).expect("profile");

        assert_eq!(opcode_gas(&report, "STATICCALL"), 218);
    }

    #[test]
    fn keeps_call_costs_reported_without_forwarded_gas() {
        let mut failed = gas_step("CALL", 1_000, 1_000, 1);
        failed.error = Some("OutOfGas".to_owned());
        let trace = trace(
            Some("0x1"),
            vec![
                gas_step("CALL", 2_000, 118, 1),
                gas_step("STOP", 500, 0, 2),
                failed,
            ],
        );

        let report = profile_transaction(&trace, &[]).expect("profile");

        assert_eq!(opcode_gas(&report, "CALL"), 1_118);
    }

    #[test]
    fn rejects_out_of_bounds_source_ranges() {
        let program = program(
            Some("0x1"),
            "Counter;Unsafe\nName",
            "call",
            "contract Counter {}",
            &[(0, "STOP", 1_000)],
        );
        let trace = trace(Some("0x1"), vec![step(0, "STOP", 1, 0)]);

        let report = profile_transaction(&trace, &[program]).expect("profile");

        assert_eq!(report.totals.source_gas, 0);
        assert!(report.source_lines.is_empty());
        assert_eq!(report.hotspots[0].source, None);
        assert!(report.folded_text().contains("Counter Unsafe Name"));
    }

    fn program(
        address: Option<&str>,
        name: &str,
        environment: &str,
        source: &str,
        instructions: &[(u64, &str, u64)],
    ) -> ProfileProgram {
        make_program(address, name, environment, source, instructions, None)
    }

    fn program_with_function(
        address: Option<&str>,
        name: &str,
        environment: &str,
        source: &str,
        instructions: &[(u64, &str, u64)],
        function: &str,
    ) -> ProfileProgram {
        make_program(
            address,
            name,
            environment,
            source,
            instructions,
            Some(function),
        )
    }

    fn program_from_contexts(
        name: &str,
        source: &str,
        instructions: &[(u64, &str, serde_json::Value)],
    ) -> ProfileProgram {
        let instructions = instructions
            .iter()
            .map(|(pc, opcode, context)| Instruction::new(*pc, opcode, Some(context.clone())))
            .collect();
        ProfileProgram::new(
            Some("0xcafe".to_owned()),
            EthdebugInfo {
                compilation: json!({}),
                contract_name: name.to_owned(),
                environment: "call".to_owned(),
                instructions,
                sources: BTreeMap::from([(0, format!("{name}.sol"))]),
                variable_locations: BTreeMap::new(),
            },
            BTreeMap::from([(0, source.to_owned())]),
        )
        .expect("profile program")
    }

    fn make_program(
        address: Option<&str>,
        name: &str,
        environment: &str,
        source: &str,
        instructions: &[(u64, &str, u64)],
        function: Option<&str>,
    ) -> ProfileProgram {
        let instructions = instructions
            .iter()
            .enumerate()
            .map(|(index, (pc, opcode, offset))| {
                let mut context = json!({"code": source_range(0, *offset, 1)});
                if index == 0 {
                    if let Some(function) = function {
                        context["invoke"] = json!({
                            "identifier": function,
                            "declaration": source_range(0, 0, source.len() as u64),
                            "jump": true
                        });
                    }
                }
                Instruction::new(*pc, opcode, Some(context))
            })
            .collect();
        ProfileProgram::new(
            address.map(str::to_owned),
            EthdebugInfo {
                compilation: json!({}),
                contract_name: name.to_owned(),
                environment: environment.to_owned(),
                instructions,
                sources: BTreeMap::from([(0, format!("{name}.sol"))]),
                variable_locations: BTreeMap::new(),
            },
            BTreeMap::from([(0, source.to_owned())]),
        )
        .expect("profile program")
    }

    fn trace(to: Option<&str>, steps: Vec<TraceStep>) -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x0".to_owned(),
            to_addr: to.map(str::to_owned),
            value: "0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: steps
                .iter()
                .fold(0_u64, |gas, step| gas.saturating_add(step.gas_cost)),
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some("replay".to_owned()),
            capabilities: TraceCapabilities {
                opcode_steps: true,
                gas_details: true,
                ..TraceCapabilities::default()
            },
            artifacts: TraceArtifacts::default(),
            steps: steps.into(),
        }
    }

    fn gas_step(op: &str, gas: u64, gas_cost: u64, depth: u64) -> TraceStep {
        TraceStep::new(
            0,
            op.into(),
            gas,
            gas_cost,
            depth,
            None,
            StepSnapshot::default(),
        )
    }

    fn opcode_gas(report: &ProfileReport, opcode: &str) -> u64 {
        let row = report.opcodes.iter().find(|row| row.opcode == opcode);
        row.expect("opcode row").gas
    }

    fn step(pc: u64, op: &str, gas_cost: u64, depth: u64) -> TraceStep {
        TraceStep {
            pc,
            op: op.into(),
            gas: 1_000,
            gas_cost,
            depth,
            stack: Vec::new(),
            memory: None,
            storage: None,
            error: None,
            snapshot: StepSnapshot::default(),
        }
    }
}
