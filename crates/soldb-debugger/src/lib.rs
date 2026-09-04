//! Source-level debugging over an execution trace.
//!
//! Given a [`soldb_core::TransactionTrace`] and the ETHDebug metadata for the contract
//! it executed, this crate answers the questions a source-level debugger asks: which
//! source span a step is at, which function contains a program counter, and which
//! variables are live there with what values.
//!
//! It is frontend-agnostic on purpose. [`variables_for_step`] is what backs both the CLI
//! REPL's `vars`/`print` commands and the DAP server's variables view, so the terminal
//! and the editor decode identically.
//!
//! Variable values are only as good as the debug info: a location the backend did not
//! capture decodes to [`DebugValueStatus::Unavailable`], and a value whose declared type
//! is not decodable is reported as [`DebugValueStatus::Raw`] rather than guessed at.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use soldb_core::{StepSnapshot, TraceStep, TransactionTrace, Word as StackWord};
use soldb_ethdebug::{decode_value, parse_word, EthdebugInfo, VariableLocation, Word};

pub mod condition;
pub mod state;
pub mod stepping;

pub use condition::{Condition, ConditionContext, Evaluation};
pub use soldb_ethdebug::StorageLayout;
pub use state::{
    short_hex, state_value, state_variables, CachedChain, ChainRead, ChainStorage, StateSource,
    StateVariable, StorageTape, StorageWords,
};
pub use stepping::{
    address_from_word, call_target, normalize_address, source_path_matches, ContractDebugInfo,
    Frame, FunctionId, JumpMarker, LineKey, ResolvedFunction, ResolvedLine, SourceListing,
    StepLocation, StepMap,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugSession {
    pub trace: TransactionTrace,
    pub ethdebug: Option<EthdebugInfo>,
    #[serde(default)]
    pub source_contents: BTreeMap<u64, String>,
    #[serde(default)]
    pub functions: Vec<SourceFunction>,
}

impl DebugSession {
    #[must_use]
    pub fn new(trace: TransactionTrace) -> Self {
        Self {
            trace,
            ethdebug: None,
            source_contents: BTreeMap::new(),
            functions: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_ethdebug(
        trace: TransactionTrace,
        ethdebug: EthdebugInfo,
        source_contents: BTreeMap<u64, String>,
    ) -> Self {
        let mut session = Self::new(trace);
        session.attach_ethdebug(ethdebug, source_contents);
        session
    }

    /// Attaches debug info to a session that already holds a trace, replacing whatever
    /// was attached before.
    ///
    /// The trace is left in place rather than rebuilt, so a frontend that keeps a large
    /// trace resident, such as the WebAssembly module, can add or swap the contract's
    /// artifacts without copying hundreds of thousands of steps.
    pub fn attach_ethdebug(
        &mut self,
        ethdebug: EthdebugInfo,
        source_contents: BTreeMap<u64, String>,
    ) {
        self.functions = source_contents
            .iter()
            .flat_map(|(source_id, source)| parse_source_functions(*source_id, source))
            .collect();
        self.ethdebug = Some(ethdebug);
        self.source_contents = source_contents;
    }

    #[must_use]
    pub fn step(&self, step_index: usize) -> Option<DebugStep> {
        let step = self.trace.steps.get(step_index)?;
        Some(DebugStep {
            index: step_index,
            pc: step.pc,
            op: step.op.to_string(),
            gas: step.gas,
            gas_cost: step.gas_cost,
            depth: step.depth,
            source: self.source_span(step.pc),
            function: self.function_at_pc(step.pc).cloned(),
            snapshot: step.normalized_snapshot(),
            variables: self.variables_at_step(step),
        })
    }

    #[must_use]
    pub fn steps(&self) -> Vec<DebugStep> {
        (0..self.trace.steps.len())
            .filter_map(|step_index| self.step(step_index))
            .collect()
    }

    #[must_use]
    pub fn source_span(&self, pc: u64) -> Option<SourceSpan> {
        let ethdebug = self.ethdebug.as_ref()?;
        let instruction = ethdebug.instruction_at_pc(pc)?;
        let location = instruction.source_location()?;
        let path = ethdebug.sources.get(&location.source_id)?.clone();
        let position = self
            .source_contents
            .get(&location.source_id)
            .map(|source| line_column_for_offset(source, location.offset as usize));
        Some(SourceSpan {
            source_id: location.source_id,
            path,
            offset: location.offset,
            length: location.length,
            line: position.map_or(0, |position| position.line),
            column: position.map_or(0, |position| position.column),
        })
    }

    #[must_use]
    pub fn function_at_pc(&self, pc: u64) -> Option<&SourceFunction> {
        let location = self
            .ethdebug
            .as_ref()?
            .instruction_at_pc(pc)?
            .source_location()?;
        self.functions
            .iter()
            .filter(|function| {
                function.source_id == location.source_id
                    && function.declaration_start <= location.offset
                    && location.offset <= function.body_end
            })
            .min_by_key(|function| function.body_end.saturating_sub(function.declaration_start))
    }

    #[must_use]
    pub fn variables_at_step(&self, step: &TraceStep) -> Vec<DebugVariable> {
        let Some(ethdebug) = &self.ethdebug else {
            return Vec::new();
        };
        variables_for_step(&self.trace, ethdebug, step)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugStep {
    pub index: usize,
    pub pc: u64,
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: u64,
    pub source: Option<SourceSpan>,
    pub function: Option<SourceFunction>,
    pub snapshot: StepSnapshot,
    pub variables: Vec<DebugVariable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub source_id: u64,
    pub path: String,
    pub offset: u64,
    pub length: u64,
    pub line: u64,
    pub column: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFunction {
    pub source_id: u64,
    /// The declared name; `constructor`, `fallback`, and `receive` for those, and the
    /// modifier's name for a modifier.
    pub name: String,
    pub params: Vec<SourceParam>,
    pub declaration_start: u64,
    /// The one-based line the declaration begins on.
    #[serde(default)]
    pub declaration_line: u64,
    pub body_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceParam {
    pub name: String,
    /// The type without its data location, such as `uint256` or `string`.
    pub ty: String,
    /// The data location as declared: `memory`, `calldata`, or `storage`; `None` for a
    /// value type.
    #[serde(default)]
    pub location: Option<String>,
}

/// One argument of a function frame, as it was on the stack when the frame was entered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameArgument {
    pub name: String,
    pub ty: String,
    pub value: DebugValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugVariable {
    pub name: String,
    pub ty: String,
    pub location: DebugLocation,
    pub value: DebugValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugLocation {
    pub kind: String,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugValue {
    pub display: String,
    pub raw: Option<String>,
    pub status: DebugValueStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugValueStatus {
    Decoded,
    Raw,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourcePosition {
    line: u64,
    column: u64,
}

#[must_use]
pub fn variables_for_step(
    trace: &TransactionTrace,
    ethdebug: &EthdebugInfo,
    step: &TraceStep,
) -> Vec<DebugVariable> {
    ethdebug
        .variables_at_pc(step.pc)
        .into_iter()
        .map(|variable| decode_variable(trace, step, variable))
        .collect()
}

fn decode_variable(
    trace: &TransactionTrace,
    step: &TraceStep,
    variable: &VariableLocation,
) -> DebugVariable {
    let raw = raw_value_for_location(trace, step, variable);
    let value = raw.map_or_else(
        || DebugValue {
            display: "<unavailable>".to_owned(),
            raw: None,
            status: DebugValueStatus::Unavailable,
        },
        |raw| decode_debug_value(&raw, &variable.ty),
    );
    DebugVariable {
        name: variable.name.clone(),
        ty: variable.ty.clone(),
        location: DebugLocation {
            kind: variable.location_type.clone(),
            offset: variable.offset,
        },
        value,
    }
}

fn raw_value_for_location(
    trace: &TransactionTrace,
    step: &TraceStep,
    variable: &VariableLocation,
) -> Option<String> {
    let snapshot = step.snapshot_ref();
    match variable.location_type.as_str() {
        "stack" => snapshot
            .stack
            .get(variable.offset as usize)
            .map(|value| normalize_hex(value)),
        "memory" => word_from_hex_bytes(snapshot.memory?, variable.offset as usize),
        "calldata" => word_from_hex_bytes(&trace.input_data, variable.offset as usize),
        "storage" => storage_value(snapshot.storage, variable.offset),
        _ => None,
    }
}

fn decode_debug_value(raw: &str, ty: &str) -> DebugValue {
    let ty = ty.trim();
    let normalized = normalize_hex(raw);
    let word = normalized.trim_start_matches("0x");
    let decoded = decode_static_word(word, ty);
    match decoded {
        Some(display) => DebugValue {
            display,
            raw: Some(normalized),
            status: DebugValueStatus::Decoded,
        },
        None => DebugValue {
            display: normalized.clone(),
            raw: Some(normalized),
            status: DebugValueStatus::Raw,
        },
    }
}

fn decode_static_word(word: &str, ty: &str) -> Option<String> {
    if !word.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    if ty.starts_with("uint") {
        return Some(format_uint_word(word));
    }
    if ty == "address" {
        let padded = left_pad_word(word);
        return Some(
            format!("0x{}", &padded[padded.len().saturating_sub(40)..]).to_ascii_lowercase(),
        );
    }
    if ty == "bool" {
        let trimmed = word.trim_start_matches('0');
        return match trimmed {
            "" | "0" => Some("false".to_owned()),
            "1" => Some("true".to_owned()),
            _ => None,
        };
    }
    if ty == "bytes32" {
        return Some(normalize_hex(word));
    }
    if let Some(size) = fixed_bytes_size(ty) {
        let padded = right_pad_word(word);
        return Some(format!("0x{}", &padded[..size * 2]).to_ascii_lowercase());
    }
    None
}

/// Where the compiler leaves a function's parameters on the stack when the function is
/// entered. Solidity's two code generators disagree, and nothing in the artifacts says
/// which produced the code, so [`StepMap`] proves it from the trace instead of assuming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentOrder {
    /// The first declared parameter is on top: the via-IR pipeline pushes them
    /// right-to-left.
    FirstOnTop,
    /// The last declared parameter is on top: the legacy pipeline pushes them
    /// left-to-right.
    LastOnTop,
}

/// What this trace proved about how a contract's compiler passes arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentLayout {
    /// The parameters are the top words at the entry point, in this order.
    Ordered(ArgumentOrder),
    /// The parameters are the top words, but which is which was not established: the
    /// evidence came from a one-parameter frame, where both orders look the same.
    TopWords,
}

impl ArgumentOrder {
    /// The stack index of parameter `index` of `count`, counting from the bottom of the
    /// stack, given that the parameters occupy the top `count` words.
    #[must_use]
    fn word_index(self, index: usize, count: usize, stack_len: usize) -> usize {
        match self {
            Self::FirstOnTop => stack_len - 1 - index,
            Self::LastOnTop => stack_len - count + index,
        }
    }
}

/// What a frame's arguments are read from: the stack at its entry point, and the memory
/// a pointer among them refers into.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameState<'a> {
    pub stack: &'a [StackWord],
    /// Memory at the entry step, as one unprefixed hex string, when the backend captured
    /// it.
    pub memory: Option<&'a str>,
}

/// The arguments a function was entered with, read off the stack at its entry point.
///
/// Every parameter read here occupies exactly one word: a value type is the value, and a
/// `memory` or `storage` reference is a pointer, which memory's own layout then resolves.
/// A `calldata` slice of a dynamic type is the exception — it is a pointer *and* a length,
/// two words, and nothing in the trace proves that width the way the calldata proves the
/// order — so a function taking one reports no arguments rather than words that may be
/// misaligned.
#[must_use]
pub fn decode_arguments(
    params: &[SourceParam],
    state: FrameState<'_>,
    layout: ArgumentLayout,
) -> Vec<FrameArgument> {
    let stack = state.stack;
    if params.is_empty() || stack.len() < params.len() {
        return Vec::new();
    }
    if !params.iter().all(readable_parameter) {
        return Vec::new();
    }
    // One parameter is on top under either order; more than one needs the order proven.
    let order = match layout {
        ArgumentLayout::Ordered(order) => order,
        ArgumentLayout::TopWords if params.len() == 1 => ArgumentOrder::FirstOnTop,
        ArgumentLayout::TopWords => return Vec::new(),
    };
    params
        .iter()
        .enumerate()
        .map(|(index, param)| {
            let word = &stack[order.word_index(index, params.len(), stack.len())];
            FrameArgument {
                name: param.name.clone(),
                ty: param.ty.clone(),
                value: argument_value(param, word, state.memory),
            }
        })
        .collect()
}

fn argument_value(param: &SourceParam, word: &str, memory: Option<&str>) -> DebugValue {
    let Ok(parsed) = parse_word(&format!("0x{}", word.trim_start_matches("0x"))) else {
        return DebugValue {
            display: "<unreadable stack word>".to_owned(),
            raw: Some(word.to_owned()),
            status: DebugValueStatus::Unavailable,
        };
    };
    let raw = Some(short_hex(&parsed));
    match param.location.as_deref() {
        Some("memory") => {
            let pointer = word_as_usize(&parsed);
            let display = match (pointer, memory) {
                (Some(pointer), Some(memory)) => read_memory_value(memory, pointer, &param.ty)
                    .unwrap_or_else(|| {
                        format!(
                            "<{} in memory at {}, beyond what this step captured>",
                            param.ty,
                            short_hex(&parsed)
                        )
                    }),
                (_, None) => format!(
                    "<{} in memory at {}; this backend captured no memory>",
                    param.ty,
                    short_hex(&parsed)
                ),
                (None, _) => format!("<{} at {}>", param.ty, short_hex(&parsed)),
            };
            let decoded =
                display.starts_with('"') || display.starts_with('[') || display.starts_with("0x");
            DebugValue {
                display,
                raw,
                status: if decoded {
                    DebugValueStatus::Decoded
                } else {
                    DebugValueStatus::Raw
                },
            }
        }
        Some(location) => DebugValue {
            display: format!("<{} in {location} at {}>", param.ty, short_hex(&parsed)),
            raw,
            status: DebugValueStatus::Raw,
        },
        None => DebugValue {
            display: decode_value(value_bytes(&parsed, &param.ty), &param.ty),
            raw,
            status: DebugValueStatus::Decoded,
        },
    }
}

/// Whether a parameter is one word the debugger can place: a value, or a pointer.
pub(crate) fn readable_parameter(param: &SourceParam) -> bool {
    match param.location.as_deref() {
        // A `calldata` slice of a dynamic type is two words; see `decode_arguments`.
        Some("calldata") => !is_dynamic_type(&param.ty),
        Some(_) => true,
        None => is_value_type(&param.ty),
    }
}

/// Whether a type is stored with a length, rather than a fixed number of words.
fn is_dynamic_type(ty: &str) -> bool {
    ty == "string" || ty == "bytes" || ty.ends_with("[]")
}

/// A value living in memory, read through Solidity's memory layout: a `string` or `bytes`
/// is a length followed by its bytes, a dynamic array is a length followed by one word
/// per element, and a fixed-size array is those words with no length.
///
/// The layout is the language's, not a guess — the same standing as the storage layout —
/// but only value-type elements are decoded; anything else is a pointer this does not
/// follow, and it says so rather than printing an offset as a number.
fn read_memory_value(memory: &str, pointer: usize, ty: &str) -> Option<String> {
    if ty == "string" || ty == "bytes" {
        let length = word_as_usize(&memory_word(memory, pointer)?)?;
        let bytes = memory_bytes(memory, pointer.checked_add(32)?, length)?;
        if ty == "string" {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                return Some(format!("{text:?}"));
            }
        }
        return Some(format!("0x{}", hex_of(&bytes)));
    }
    let (element, count) = array_shape(ty)?;
    if !is_value_type(element) {
        return None;
    }
    let (first, count) = match count {
        // Dynamic: the length is the first word, the elements follow it.
        None => (
            pointer.checked_add(32)?,
            word_as_usize(&memory_word(memory, pointer)?)?,
        ),
        Some(count) => (pointer, count),
    };
    let shown = count.min(8);
    let mut parts = Vec::with_capacity(shown);
    for index in 0..shown {
        let word = memory_word(memory, first.checked_add(index.checked_mul(32)?)?)?;
        parts.push(decode_value(value_bytes(&word, element), element));
    }
    if count > shown {
        parts.push(format!("... {} more", count - shown));
    }
    Some(format!("[{}]", parts.join(", ")))
}

/// An array type as its element type and its length: `None` for a dynamic array, which
/// carries its length in memory.
fn array_shape(ty: &str) -> Option<(&str, Option<usize>)> {
    let inner = ty.strip_suffix(']')?;
    let open = inner.rfind('[')?;
    let element = inner[..open].trim();
    let length = &inner[open + 1..];
    if length.is_empty() {
        return Some((element, None));
    }
    Some((element, Some(length.parse::<usize>().ok()?)))
}

/// The 32 bytes at `offset` of a memory image, when it reaches that far.
fn memory_word(memory: &str, offset: usize) -> Option<Word> {
    let bytes = memory_bytes(memory, offset, 32)?;
    let mut word = [0_u8; 32];
    word.copy_from_slice(&bytes);
    Some(word)
}

/// `length` bytes at `offset` of a memory image, which is two hex digits per byte.
fn memory_bytes(memory: &str, offset: usize, length: usize) -> Option<Vec<u8>> {
    let start = offset.checked_mul(2)?;
    let end = start.checked_add(length.checked_mul(2)?)?;
    let digits = memory.get(start..end)?;
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        digits
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex")
            })
            .collect(),
    )
}

/// A word as an offset or a length, when it fits one.
fn word_as_usize(word: &Word) -> Option<usize> {
    if word[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    usize::try_from(u64::from_be_bytes(word[24..].try_into().expect("8 bytes"))).ok()
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The bytes of a stack word a value of type `ty` occupies: a signed integer is its own
/// width from the low end so the sign bit is the right one, fixed bytes are left-aligned,
/// and everything else reads as a whole word.
fn value_bytes<'a>(word: &'a Word, ty: &str) -> &'a [u8] {
    if let Some(bits) = integer_bits(ty, "int") {
        return &word[32 - bits / 8..];
    }
    if let Some(size) = fixed_bytes_size(ty) {
        return &word[..size];
    }
    word
}

/// Whether a value of this type is one stack word the debugger can decode.
#[must_use]
pub fn is_value_type(ty: &str) -> bool {
    matches!(ty, "bool" | "address" | "address payable")
        || fixed_bytes_size(ty).is_some()
        || integer_bits(ty, "uint").is_some()
        || integer_bits(ty, "int").is_some()
}

/// The width of `uint<N>`/`int<N>` in bits, the bare names counting as 256.
fn integer_bits(ty: &str, prefix: &str) -> Option<usize> {
    let rest = ty.strip_prefix(prefix)?;
    // `int8` must not match the `uint` prefix; `strip_prefix` already ruled that out.
    if rest.is_empty() {
        return Some(256);
    }
    let bits = rest.parse::<usize>().ok()?;
    (bits % 8 == 0 && (8..=256).contains(&bits)).then_some(bits)
}

fn fixed_bytes_size(ty: &str) -> Option<usize> {
    let size = ty.strip_prefix("bytes")?.parse::<usize>().ok()?;
    (1..=32).contains(&size).then_some(size)
}

fn format_uint_word(word: &str) -> String {
    let trimmed = word.trim_start_matches('0');
    if trimmed.is_empty() {
        return "0".to_owned();
    }
    if trimmed.len() <= 32 {
        return u128::from_str_radix(trimmed, 16)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| format!("0x{}", trimmed.to_ascii_lowercase()));
    }
    format!("0x{}", trimmed.to_ascii_lowercase())
}

fn storage_value(storage: &BTreeMap<String, String>, slot: u64) -> Option<String> {
    storage
        .get(&format!("0x{slot:x}"))
        .or_else(|| storage.get(&format!("{slot:x}")))
        .or_else(|| storage.get(&format!("0x{slot:064x}")))
        .or_else(|| storage.get(&format!("{slot:064x}")))
        .map(|value| normalize_hex(value))
}

fn word_from_hex_bytes(input: &str, byte_offset: usize) -> Option<String> {
    let hex = input.trim_start_matches("0x");
    let start = byte_offset.checked_mul(2)?;
    let end = start.checked_add(64)?;
    let word = hex.get(start..end)?;
    word.bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| format!("0x{}", word.to_ascii_lowercase()))
}

fn normalize_hex(value: &str) -> String {
    let value = value.trim();
    let hex = value.strip_prefix("0x").unwrap_or(value);
    format!("0x{}", hex.to_ascii_lowercase())
}

fn left_pad_word(word: &str) -> String {
    let word = word.trim_start_matches("0x").to_ascii_lowercase();
    if word.len() >= 64 {
        return word;
    }
    format!("{:0>64}", word)
}

fn right_pad_word(word: &str) -> String {
    let word = word.trim_start_matches("0x").to_ascii_lowercase();
    if word.len() >= 64 {
        return word;
    }
    format!("{:0<64}", word)
}

fn line_column_for_offset(source: &str, offset: usize) -> SourcePosition {
    let mut line = 1;
    let mut column = 1;
    for byte in source.bytes().take(offset.min(source.len())) {
        if byte == b'\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    SourcePosition { line, column }
}

/// The declarations that open a body of executable code in a Solidity source.
const DECLARATION_KEYWORDS: [&str; 5] =
    ["function", "modifier", "constructor", "fallback", "receive"];

/// Finds every function-like declaration in a source file by scanning its text:
/// functions, modifiers, constructors, `fallback`, and `receive`. This is what the
/// debugger attributes steps to when the compiler emits no function boundaries.
#[must_use]
pub fn parse_source_functions(source_id: u64, source: &str) -> Vec<SourceFunction> {
    let mut functions = Vec::new();
    for keyword in DECLARATION_KEYWORDS {
        collect_declarations(source_id, source, keyword, &mut functions);
    }
    functions.sort_by_key(|function| function.declaration_start);
    functions
}

fn collect_declarations(
    source_id: u64,
    source: &str,
    keyword: &str,
    functions: &mut Vec<SourceFunction>,
) {
    let named = matches!(keyword, "function" | "modifier");
    let mut cursor = 0;
    while let Some(keyword_start) = find_solidity_keyword(source, keyword, cursor) {
        let mut index = skip_ascii_whitespace(source, keyword_start + keyword.len());
        let name = if named {
            let Some((name, name_end)) = parse_identifier(source, index) else {
                cursor = index;
                continue;
            };
            index = skip_ascii_whitespace(source, name_end);
            name
        } else {
            keyword
        };
        if source.as_bytes().get(index) != Some(&b'(') {
            cursor = index;
            continue;
        }
        let Some(params_end) = find_matching_delimiter(source, index, b'(', b')') else {
            cursor = index + 1;
            continue;
        };
        let params = parse_source_params(&source[index + 1..params_end]);
        let Some(body_start) = find_next_byte(source, params_end + 1, b'{') else {
            cursor = params_end + 1;
            continue;
        };
        // A call such as `token.receive(x);` has a `;` before the next `{`; only a
        // declaration runs straight from its parameter list into a body.
        if source[params_end + 1..body_start].contains(';') {
            cursor = params_end + 1;
            continue;
        }
        let Some(body_end) = find_matching_delimiter(source, body_start, b'{', b'}') else {
            cursor = body_start + 1;
            continue;
        };

        functions.push(SourceFunction {
            source_id,
            name: name.to_owned(),
            params,
            declaration_start: keyword_start as u64,
            declaration_line: source[..keyword_start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count() as u64
                + 1,
            body_end: body_end as u64,
        });
        cursor = body_end + 1;
    }
}

fn parse_source_params(params: &str) -> Vec<SourceParam> {
    split_top_level_commas(params)
        .into_iter()
        .enumerate()
        .filter_map(|(index, param)| {
            let param = param.trim();
            if param.is_empty() {
                return None;
            }
            let mut tokens = param.split_whitespace().collect::<Vec<_>>();
            let name = tokens
                .last()
                .copied()
                .filter(|token| is_identifier(token))
                .map_or_else(|| format!("arg{index}"), str::to_owned);
            if tokens.last().copied() == Some(name.as_str()) && tokens.len() > 1 {
                tokens.pop();
            }
            let location = tokens
                .iter()
                .find(|token| matches!(**token, "memory" | "calldata" | "storage"))
                .map(|token| (*token).to_owned());
            let ty = tokens
                .into_iter()
                .filter(|token| !matches!(*token, "memory" | "calldata" | "storage" | "payable"))
                .collect::<Vec<_>>()
                .join(" ");
            (!ty.is_empty()).then_some(SourceParam { name, ty, location })
        })
        .collect()
}

fn split_top_level_commas(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&input[start..]);
    parts
}

fn find_solidity_keyword(source: &str, keyword: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    while let Some(relative) = source[cursor..].find(keyword) {
        let absolute = cursor + relative;
        let before = absolute
            .checked_sub(1)
            .and_then(|index| source.as_bytes().get(index))
            .copied();
        let after = source.as_bytes().get(absolute + keyword.len()).copied();
        if before.is_none_or(|byte| !is_identifier_byte(byte))
            && after.is_none_or(|byte| !is_identifier_byte(byte))
        {
            return Some(absolute);
        }
        cursor = absolute + keyword.len();
    }
    None
}

fn parse_identifier(source: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    let first = *bytes.get(start)?;
    if !is_identifier_start_byte(first) {
        return None;
    }
    let mut end = start + 1;
    while bytes.get(end).is_some_and(|byte| is_identifier_byte(*byte)) {
        end += 1;
    }
    Some((&source[start..end], end))
}

fn is_identifier(input: &str) -> bool {
    let mut bytes = input.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    is_identifier_start_byte(first) && bytes.all(is_identifier_byte)
}

fn is_identifier_start_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_byte(byte: u8) -> bool {
    is_identifier_start_byte(byte) || byte.is_ascii_digit()
}

fn skip_ascii_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn find_next_byte(source: &str, start: usize, needle: u8) -> Option<usize> {
    source
        .as_bytes()
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, byte)| (*byte == needle).then_some(index))
}

fn find_matching_delimiter(source: &str, open_index: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0_i32;
    for (index, byte) in source.bytes().enumerate().skip(open_index) {
        if byte == open {
            depth += 1;
        } else if byte == close {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use soldb_core::{TraceStep, TransactionTrace};
    use soldb_ethdebug::{EthdebugInfo, Instruction, VariableLocation};

    use super::{parse_source_functions, DebugSession, DebugValueStatus};

    #[test]
    fn builds_source_steps_and_decodes_active_variables() {
        let source =
            "contract Counter {\n  function set(uint256 x) public {\n    value = x;\n  }\n}\n";
        let offset = source.find("value = x").expect("source offset") as u64;
        let trace = sample_trace();
        let mut sources = BTreeMap::new();
        sources.insert(0, "Counter.sol".to_owned());
        let mut source_contents = BTreeMap::new();
        source_contents.insert(0, source.to_owned());
        let mut variable_locations = BTreeMap::new();
        variable_locations.insert(
            0,
            vec![
                VariableLocation {
                    name: "x".to_owned(),
                    ty: "uint256".to_owned(),
                    location_type: "stack".to_owned(),
                    offset: 0,
                    pc_range: (0, 1),
                },
                VariableLocation {
                    name: "sender".to_owned(),
                    ty: "address".to_owned(),
                    location_type: "calldata".to_owned(),
                    offset: 4,
                    pc_range: (0, 1),
                },
            ],
        );
        let info = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Counter".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![Instruction {
                offset: 0,
                operation: json!({"mnemonic": "PUSH1"}),
                context: Some(json!({
                    "code": {
                        "source": {"id": 0},
                        "range": {"offset": offset, "length": 9}
                    }
                })),
            }],
            sources,
            variable_locations,
        };

        let session = DebugSession::with_ethdebug(trace, info, source_contents);
        let step = session.step(0).expect("debug step");
        assert_eq!(step.source.as_ref().expect("source").line, 3);
        assert_eq!(step.function.as_ref().expect("function").name, "set");
        assert_eq!(
            step.snapshot
                .stack
                .iter()
                .map(|word| &**word)
                .collect::<Vec<_>>(),
            ["0x2a"]
        );
        assert_eq!(step.variables[0].name, "x");
        assert_eq!(step.variables[0].value.display, "42");
        assert_eq!(step.variables[0].value.status, DebugValueStatus::Decoded);
        assert_eq!(
            step.variables[1].value.display,
            "0x1111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn keeps_raw_values_when_type_is_dynamic_or_location_is_unknown() {
        let trace = sample_trace();
        let mut variable_locations = BTreeMap::new();
        variable_locations.insert(
            0,
            vec![
                VariableLocation {
                    name: "name".to_owned(),
                    ty: "string".to_owned(),
                    location_type: "stack".to_owned(),
                    offset: 0,
                    pc_range: (0, 0),
                },
                VariableLocation {
                    name: "missing".to_owned(),
                    ty: "uint256".to_owned(),
                    location_type: "stack".to_owned(),
                    offset: 99,
                    pc_range: (0, 0),
                },
            ],
        );
        let info = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Counter".to_owned(),
            environment: "runtime".to_owned(),
            instructions: Vec::new(),
            sources: BTreeMap::new(),
            variable_locations,
        };

        let session = DebugSession::with_ethdebug(trace, info, BTreeMap::new());
        let step = session.step(0).expect("debug step");
        assert_eq!(step.variables[0].value.status, DebugValueStatus::Raw);
        assert_eq!(step.variables[0].value.display, "0x2a");
        assert_eq!(
            step.variables[1].value.status,
            DebugValueStatus::Unavailable
        );
    }

    #[test]
    fn attaching_ethdebug_matches_constructing_with_it_and_replaces_prior_info() {
        let source =
            "contract Counter {\n  function set(uint256 x) public {\n    value = x;\n  }\n}\n";
        let offset = source.find("value = x").expect("source offset") as u64;
        let info = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Counter".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![Instruction {
                offset: 0,
                operation: json!({"mnemonic": "PUSH1"}),
                context: Some(json!({
                    "code": {"source": {"id": 0}, "range": {"offset": offset, "length": 9}}
                })),
            }],
            sources: BTreeMap::from([(0, "Counter.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        let source_contents = BTreeMap::from([(0, source.to_owned())]);

        let constructed =
            DebugSession::with_ethdebug(sample_trace(), info.clone(), source_contents.clone());
        let mut attached = DebugSession::new(sample_trace());
        assert!(attached.ethdebug.is_none());
        assert!(attached.functions.is_empty());
        attached.attach_ethdebug(info, source_contents);

        assert_eq!(attached, constructed);
        assert_eq!(attached.functions.len(), 1);
        assert_eq!(attached.functions[0].name, "set");
        assert_eq!(
            attached
                .step(0)
                .and_then(|step| step.source)
                .map(|span| span.line),
            Some(3)
        );

        // Attaching again replaces the debug info wholesale rather than merging.
        let other = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Other".to_owned(),
            environment: "runtime".to_owned(),
            instructions: Vec::new(),
            sources: BTreeMap::new(),
            variable_locations: BTreeMap::new(),
        };
        attached.attach_ethdebug(other, BTreeMap::new());
        assert_eq!(
            attached
                .ethdebug
                .as_ref()
                .map(|info| info.contract_name.as_str()),
            Some("Other")
        );
        assert!(attached.functions.is_empty());
        assert!(attached.source_contents.is_empty());
        assert_eq!(attached.step(0).and_then(|step| step.source), None);
        assert_eq!(attached.trace, sample_trace());
    }

    #[test]
    fn parses_source_functions_with_tuple_and_array_params() {
        let functions = parse_source_functions(
            7,
            "contract C { function submit(Person memory p, uint256[2] memory xs) public {} }",
        );
        assert_eq!(functions[0].source_id, 7);
        assert_eq!(functions[0].name, "submit");
        assert_eq!(functions[0].params[0].name, "p");
        assert_eq!(functions[0].params[0].ty, "Person");
        assert_eq!(functions[0].params[1].name, "xs");
        assert_eq!(functions[0].params[1].ty, "uint256[2]");
    }

    fn sample_trace() -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0".to_owned(),
            input_data: format!(
                "0x12345678{}",
                "0000000000000000000000001111111111111111111111111111111111111111"
            ),
            gas_used: 1,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some("debug-rpc".to_owned()),
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: vec![TraceStep {
                pc: 0,
                op: "PUSH1".into(),
                gas: 1,
                gas_cost: 0,
                depth: 0,
                stack: vec!["0x2a".into()],
                memory: Some(format!("{}{}", "00".repeat(32), "2a".repeat(32))),
                storage: Some(BTreeMap::from([("0x0".to_owned(), "0x2a".to_owned())])),
                error: None,
                snapshot: Default::default(),
            }],
        }
    }
    /// Solidity memory: a `string` is a length then its bytes; an array is a length then
    /// one word per element; a fixed-size array is those words with no length.
    fn memory_image(words: &[&str]) -> String {
        words
            .iter()
            .map(|word| format!("{:0>64}", word.trim_start_matches("0x")))
            .collect()
    }

    #[test]
    fn reads_arguments_that_live_in_memory() {
        // 0x00: "hello" as a string (length 5), 0x40: [7, 8, 9] as a dynamic array.
        let memory = memory_image(&[
            "5",
            "68656c6c6f000000000000000000000000000000000000000000000000000000",
            "3",
            "7",
            "8",
            "9",
        ]);
        let string_at = |offset: usize| super::read_memory_value(&memory, offset, "string");
        assert_eq!(string_at(0).as_deref(), Some("\"hello\""));
        assert_eq!(
            super::read_memory_value(&memory, 0, "bytes").as_deref(),
            Some("0x68656c6c6f")
        );
        assert_eq!(
            super::read_memory_value(&memory, 64, "uint256[]").as_deref(),
            Some("[7, 8, 9]")
        );
        // A fixed-size array has no length word: it starts at the pointer.
        assert_eq!(
            super::read_memory_value(&memory, 96, "uint256[2]").as_deref(),
            Some("[7, 8]")
        );
        // Beyond what the step captured, and a type whose elements are not values: no
        // guess, and the caller says where the pointer pointed instead.
        assert_eq!(super::read_memory_value(&memory, 4096, "string"), None);
        assert_eq!(super::read_memory_value(&memory, 64, "string[]"), None);
    }

    #[test]
    fn a_parameter_is_readable_only_when_its_width_is_known() {
        let param = |ty: &str, location: Option<&str>| super::SourceParam {
            name: "x".to_owned(),
            ty: ty.to_owned(),
            location: location.map(str::to_owned),
        };
        assert!(super::readable_parameter(&param("uint256", None)));
        assert!(super::readable_parameter(&param("string", Some("memory"))));
        assert!(super::readable_parameter(&param("Config", Some("storage"))));
        // One word: a calldata slice of a fixed-size type is a pointer.
        assert!(super::readable_parameter(&param(
            "uint256[2]",
            Some("calldata")
        )));
        // Two words, and nothing proves that width: not read.
        assert!(!super::readable_parameter(&param(
            "bytes",
            Some("calldata")
        )));
        assert!(!super::readable_parameter(&param(
            "uint256[]",
            Some("calldata")
        )));
        // A struct by value is not one word of anything the debugger can decode.
        assert!(!super::readable_parameter(&param("Config", None)));
    }
}
