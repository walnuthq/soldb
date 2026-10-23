//! Shared vocabulary types for the SolDB workspace.
//!
//! Every other crate agrees on the types defined here: a [`TransactionTrace`] and the
//! [`StepTable`] of its steps are what an execution backend produces and what the
//! debugger and the frontends consume. A backend builds steps as [`TraceStep`]s or
//! appends them field by field; readers get a [`StepView`] per step. This crate
//! deliberately has no soldb dependencies so that it can stay the single type boundary in
//! the graph.
//!
//! These types are also a serialization contract. They round-trip through `serde` into
//! trace files and into the web-facing JSON document, so adding a field is additive and
//! needs `#[serde(default)]`, while renaming or removing one is a breaking change.
//!
//! [`TraceCapabilities`] describes what the selected backend was actually able to
//! record. Frontends should branch on those flags rather than on the backend name, so a
//! new backend does not require changes further up the stack.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::de::{self, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub use bytes::Bytes;

mod memory;
pub mod opcode;
mod table;
mod word;

pub use table::{Stack, StepError, StepRecord, StepTable, StepView, Steps, STACK_CHECKPOINT};
pub use word::{EvmWord, WordError};

#[derive(Debug, Error)]
pub enum SoldbError {
    /// A failure described by a human-readable message.
    #[error("{0}")]
    Message(String),
    /// The failure was already rendered for the user, typically as a JSON error document
    /// on a `--json` code path. Callers must exit non-zero without printing anything else.
    ///
    /// This exists so the exit path never has to inspect error *text* to decide whether a
    /// message was already shown.
    #[error("")]
    AlreadyReported,
}

pub type SoldbResult<T> = Result<T, SoldbError>;

impl From<StepError> for SoldbError {
    fn from(error: StepError) -> Self {
        Self::Message(format!("invalid trace step: {error}"))
    }
}

/// One recorded EVM step, as a backend builds it.
///
/// A [`TransactionTrace`] holds its steps in a [`StepTable`], which takes them with
/// [`StepTable::push`] and gives each back as a [`StepView`] or, when ownership is needed,
/// with [`StepView::to_trace_step`].
///
/// The machine state lives in `snapshot`, once. The flat `stack`, `memory`, and
/// `storage` fields are the layout older trace files and web clients read: every
/// constructor in this workspace leaves them empty, serialization fills them from the
/// snapshot so the wire format is unchanged, and deserialization moves whatever they
/// hold into the snapshot. Read a step through [`TraceStep::snapshot_ref`], which
/// handles both shapes; never through the flat fields.
///
/// Consecutive steps share their memory and storage when nothing changed between them
/// (see [`StepSnapshot`]), which is what keeps a trace of hundreds of thousands of steps
/// resident: memory changes on a handful of opcodes and storage on `SSTORE` alone.
#[derive(Debug, Clone, Eq)]
pub struct TraceStep {
    pub pc: u64,
    /// The mnemonic, shared with every other step running the same opcode: there are a
    /// couple of hundred of them and hundreds of thousands of steps.
    pub op: Word,
    pub gas: u64,
    /// The cost as the tracer reports it: for a call, its own cost plus the gas it forwards to
    /// the callee; for a creation, the same under REVM but without the forwarded gas under geth.
    pub gas_cost: u64,
    pub depth: u64,
    /// Legacy layout; empty unless a caller filled it by hand. See the type docs.
    pub stack: Vec<Word>,
    /// Legacy layout; `None` unless a caller filled it by hand. See the type docs.
    pub memory: Option<Bytes>,
    /// Legacy layout; `None` unless a caller filled it by hand. See the type docs.
    pub storage: Option<BTreeMap<String, String>>,
    pub error: Option<String>,
    pub snapshot: StepSnapshot,
}

impl TraceStep {
    /// A step whose state lives in `snapshot`, the way every backend builds one.
    #[must_use]
    pub fn new(
        pc: u64,
        op: Word,
        gas: u64,
        gas_cost: u64,
        depth: u64,
        error: Option<String>,
        snapshot: StepSnapshot,
    ) -> Self {
        Self {
            pc,
            op,
            gas,
            gas_cost,
            depth,
            stack: Vec::new(),
            memory: None,
            storage: None,
            error,
            snapshot,
        }
    }

    /// Borrows the machine state this step captured, without copying it.
    ///
    /// Whichever shape the step is in, its snapshot or the legacy flat fields, this
    /// returns a view of it.
    ///
    /// Prefer this over [`TraceStep::normalized_snapshot`] anywhere that walks a trace.
    /// Traces routinely run to hundreds of thousands of steps and each one's `memory` can
    /// be tens of kilobytes, so copying per step — or, as variable decoding does, per
    /// variable per step — dominates the cost of reading a trace.
    #[must_use]
    pub fn snapshot_ref(&self) -> StepSnapshotRef<'_> {
        static EMPTY_STORAGE: BTreeMap<String, String> = BTreeMap::new();
        static EMPTY_STORAGE_DIFF: BTreeMap<String, StorageChange> = BTreeMap::new();

        if !self.snapshot.is_empty() {
            return StepSnapshotRef {
                stack: &self.snapshot.stack,
                memory: self.snapshot.memory.as_deref(),
                storage: &self.snapshot.storage,
                storage_diff: &self.snapshot.storage_diff,
                transient_storage: &self.snapshot.transient_storage,
                return_data: self.snapshot.return_data.as_deref(),
            };
        }
        StepSnapshotRef {
            stack: &self.stack,
            memory: self.memory.as_deref(),
            storage: self.storage.as_ref().unwrap_or(&EMPTY_STORAGE),
            storage_diff: &EMPTY_STORAGE_DIFF,
            transient_storage: &EMPTY_STORAGE,
            return_data: None,
        }
    }

    /// Copies the machine state this step captured into an owned [`StepSnapshot`].
    ///
    /// Use this only when ownership is genuinely required; [`TraceStep::snapshot_ref`] is
    /// the same view without the copy.
    #[must_use]
    pub fn normalized_snapshot(&self) -> StepSnapshot {
        self.snapshot_ref().to_owned_snapshot()
    }

    /// Moves legacy flat fields into the snapshot, so a step read from an older file is
    /// stored once like every other.
    pub(crate) fn normalized(mut self) -> Self {
        if self.snapshot.is_empty() {
            self.snapshot = StepSnapshot {
                stack: std::mem::take(&mut self.stack),
                memory: self.memory.take(),
                storage: Arc::new(self.storage.take().unwrap_or_default()),
                storage_diff: BTreeMap::new(),
                transient_storage: BTreeMap::new(),
                return_data: None,
            };
        } else {
            self.stack = Vec::new();
            self.memory = None;
            self.storage = None;
        }
        self
    }
}

impl PartialEq for TraceStep {
    /// Two steps are equal when they record the same thing, whichever shape holds it.
    fn eq(&self, other: &Self) -> bool {
        self.pc == other.pc
            && self.op == other.op
            && self.gas == other.gas
            && self.gas_cost == other.gas_cost
            && self.depth == other.depth
            && self.error == other.error
            && self.snapshot_ref() == other.snapshot_ref()
    }
}

impl Serialize for TraceStep {
    /// Writes the step in the wire format every client reads: the flat fields and the
    /// snapshot, both from the one copy of the state.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let snapshot = self.snapshot_ref();
        let mut state = serializer.serialize_struct("TraceStep", 10)?;
        state.serialize_field("pc", &self.pc)?;
        state.serialize_field("op", &self.op)?;
        state.serialize_field("gas", &self.gas)?;
        state.serialize_field("gas_cost", &self.gas_cost)?;
        state.serialize_field("depth", &self.depth)?;
        state.serialize_field("stack", snapshot.stack)?;
        state.serialize_field("memory", &snapshot.memory.map(Hex))?;
        state.serialize_field("storage", snapshot.storage)?;
        state.serialize_field("error", &self.error)?;
        state.serialize_field("snapshot", &snapshot)?;
        state.end()
    }
}

/// The wire shape of a step, read as written by any version and then normalized.
#[derive(Deserialize)]
struct TraceStepRepr {
    pc: u64,
    op: String,
    gas: u64,
    gas_cost: u64,
    depth: u64,
    #[serde(default)]
    stack: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_memory")]
    memory: Option<Bytes>,
    #[serde(default)]
    storage: Option<BTreeMap<String, String>>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    snapshot: StepSnapshot,
}

impl<'de> Deserialize<'de> for TraceStep {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = TraceStepRepr::deserialize(deserializer)?;
        Ok(TraceStep {
            pc: repr.pc,
            op: Arc::from(repr.op),
            gas: repr.gas,
            gas_cost: repr.gas_cost,
            depth: repr.depth,
            stack: repr.stack.into_iter().map(Arc::from).collect(),
            memory: repr.memory,
            storage: repr.storage,
            error: repr.error,
            snapshot: repr.snapshot,
        }
        .normalized())
    }
}

/// One machine word as a backend spelled it, shared between the steps that hold it.
///
/// A trace of hundreds of thousands of steps carries a stack of a dozen words at every
/// one of them, and the same handful of values — a jump target, a length, a small
/// constant — appear over and over: a 600,000-step trace of one loop holds 1.7 million
/// stack words drawn from about 1,200 distinct ones. Holding each as its own `String`
/// costs a heap allocation per occurrence; holding a shared pointer costs one per
/// distinct value. [`WordInterner`] is what produces the sharing.
pub type Word = Arc<str>;

/// Hands out one [`Word`] per distinct value, so repeated stack words are stored once.
///
/// One interner covers one trace being built or parsed; it is dropped with the loop that
/// filled it, and the words it handed out live as long as the steps holding them.
#[derive(Debug, Default)]
pub struct WordInterner {
    words: std::collections::HashMap<Word, Word>,
}

impl WordInterner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The shared word equal to `word`, interning it the first time it is seen.
    #[must_use]
    pub fn intern(&mut self, word: &str) -> Word {
        if let Some(shared) = self.words.get(word) {
            return Arc::clone(shared);
        }
        let shared: Word = Arc::from(word);
        self.words.insert(Arc::clone(&shared), Arc::clone(&shared));
        shared
    }

    /// Interns a whole stack, in place.
    pub fn intern_stack(&mut self, stack: &mut [Word]) {
        for word in stack {
            *word = self.intern(word);
        }
    }

    /// How many distinct words have been interned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
}

/// A borrowed view of one step's captured machine state.
///
/// Serializes identically to [`StepSnapshot`], so it can stand in wherever a snapshot is
/// written out. Produced by [`TraceStep::snapshot_ref`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StepSnapshotRef<'a> {
    pub stack: &'a [Word],
    /// Memory as bytes; written out as one unprefixed lowercase hex string.
    #[serde(serialize_with = "serialize_memory")]
    pub memory: Option<&'a [u8]>,
    pub storage: &'a BTreeMap<String, String>,
    pub storage_diff: &'a BTreeMap<String, StorageChange>,
    #[serde(skip_serializing_if = "is_empty_ref")]
    pub transient_storage: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<&'a str>,
}

fn is_empty_ref(map: &&BTreeMap<String, String>) -> bool {
    map.is_empty()
}

fn serialize_memory<S: Serializer>(
    memory: &Option<&[u8]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    memory.map(Hex).serialize(serializer)
}

impl StepSnapshotRef<'_> {
    /// Copies this view into an owned [`StepSnapshot`].
    #[must_use]
    pub fn to_owned_snapshot(&self) -> StepSnapshot {
        StepSnapshot {
            stack: self.stack.to_vec(),
            memory: self.memory.map(Bytes::copy_from_slice),
            storage: Arc::new(self.storage.clone()),
            storage_diff: self.storage_diff.clone(),
            transient_storage: self.transient_storage.clone(),
            return_data: self.return_data.map(Arc::from),
        }
    }
}

/// The machine state one step captured.
///
/// `memory` and `storage` are shared: a backend building steps hands the previous step's
/// value on unchanged, so a trace holds one copy of memory per change rather than one
/// per step. Reads see plain values through `Deref`; a step that changes them gets its
/// own.
///
/// Memory is held as bytes. Trace files spell it as one unprefixed lowercase hex string,
/// and serialization writes and reads that spelling, so the bytes are only a change in
/// how a step holds memory, not in what a file says.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(from = "StepSnapshotRepr")]
pub struct StepSnapshot {
    pub stack: Vec<Word>,
    /// Memory as bytes. A [`Bytes`] clone shares the buffer, which is how consecutive
    /// steps hold one copy of unchanged memory.
    pub memory: Option<Bytes>,
    pub storage: Arc<BTreeMap<String, String>>,
    pub storage_diff: BTreeMap<String, StorageChange>,
    /// The transient slots this step read or wrote, with their value after it.
    pub transient_storage: BTreeMap<String, String>,
    /// The return data buffer before this step, as unprefixed hex; `None` when empty.
    pub return_data: Option<Arc<str>>,
}

impl StepSnapshot {
    /// A snapshot that owns its values, for a backend or a test building one from parts.
    #[must_use]
    pub fn new(
        stack: Vec<Word>,
        memory: Option<Bytes>,
        storage: BTreeMap<String, String>,
        storage_diff: BTreeMap<String, StorageChange>,
    ) -> Self {
        Self {
            stack,
            memory,
            storage: Arc::new(storage),
            storage_diff,
            transient_storage: BTreeMap::new(),
            return_data: None,
        }
    }

    /// The same snapshot with `transient_storage` set.
    #[must_use]
    pub fn with_transient_storage(mut self, transient_storage: BTreeMap<String, String>) -> Self {
        self.transient_storage = transient_storage;
        self
    }

    /// The same snapshot with `return_data` set; empty data is stored as `None`.
    #[must_use]
    pub fn with_return_data(mut self, return_data: Option<String>) -> Self {
        self.return_data = return_data.filter(|data| !data.is_empty()).map(Arc::from);
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
            && self.memory.is_none()
            && self.storage.is_empty()
            && self.storage_diff.is_empty()
            && self.transient_storage.is_empty()
            && self.return_data.is_none()
    }
}

impl Serialize for StepSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StepSnapshot", 6)?;
        state.serialize_field("stack", &self.stack)?;
        state.serialize_field("memory", &self.memory.as_deref().map(Hex))?;
        state.serialize_field("storage", &*self.storage)?;
        state.serialize_field("storage_diff", &self.storage_diff)?;
        // Only where a step touched it, so files without it are unchanged.
        if self.transient_storage.is_empty() {
            state.skip_field("transient_storage")?;
        } else {
            state.serialize_field("transient_storage", &self.transient_storage)?;
        }
        if self.return_data.is_none() {
            state.skip_field("return_data")?;
        } else {
            state.serialize_field("return_data", &self.return_data.as_deref())?;
        }
        state.end()
    }
}

#[derive(Deserialize, Default)]
struct StepSnapshotRepr {
    #[serde(default)]
    stack: Vec<Word>,
    #[serde(default, deserialize_with = "deserialize_memory")]
    memory: Option<Bytes>,
    #[serde(default)]
    storage: BTreeMap<String, String>,
    #[serde(default)]
    storage_diff: BTreeMap<String, StorageChange>,
    #[serde(default)]
    transient_storage: BTreeMap<String, String>,
    #[serde(default)]
    return_data: Option<String>,
}

impl From<StepSnapshotRepr> for StepSnapshot {
    fn from(repr: StepSnapshotRepr) -> Self {
        Self::new(repr.stack, repr.memory, repr.storage, repr.storage_diff)
            .with_transient_storage(repr.transient_storage)
            .with_return_data(repr.return_data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageChange {
    pub before: Option<String>,
    pub after: Option<String>,
}

/// A complete recording of one execution.
///
/// Its steps are a [`StepTable`], which shares what did not change between consecutive
/// steps however they were added, so a trace read from a file costs what one built by a
/// backend costs, at its peak as well as afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "TransactionTraceRepr")]
pub struct TransactionTrace {
    pub tx_hash: Option<String>,
    pub from_addr: String,
    pub to_addr: Option<String>,
    pub value: String,
    pub input_data: String,
    pub gas_used: u64,
    pub output: String,
    pub success: bool,
    pub error: Option<String>,
    pub debug_trace_available: bool,
    pub contract_address: Option<String>,
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub capabilities: TraceCapabilities,
    #[serde(default)]
    pub artifacts: TraceArtifacts,
    pub steps: StepTable,
}

/// The wire shape of a trace.
#[derive(Deserialize)]
struct TransactionTraceRepr {
    tx_hash: Option<String>,
    from_addr: String,
    to_addr: Option<String>,
    value: String,
    input_data: String,
    gas_used: u64,
    output: String,
    success: bool,
    error: Option<String>,
    debug_trace_available: bool,
    contract_address: Option<String>,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    capabilities: TraceCapabilities,
    #[serde(default)]
    artifacts: TraceArtifacts,
    steps: StepTable,
}

impl From<TransactionTraceRepr> for TransactionTrace {
    fn from(repr: TransactionTraceRepr) -> Self {
        Self {
            tx_hash: repr.tx_hash,
            from_addr: repr.from_addr,
            to_addr: repr.to_addr,
            value: repr.value,
            input_data: repr.input_data,
            gas_used: repr.gas_used,
            output: repr.output,
            success: repr.success,
            error: repr.error,
            debug_trace_available: repr.debug_trace_available,
            contract_address: repr.contract_address,
            backend: repr.backend,
            capabilities: repr.capabilities,
            artifacts: repr.artifacts,
            steps: repr.steps,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TraceCapabilities {
    #[serde(default)]
    pub opcode_steps: bool,
    #[serde(default)]
    pub stack: bool,
    #[serde(default)]
    pub memory: bool,
    #[serde(default)]
    pub storage: bool,
    #[serde(default)]
    pub storage_diff: bool,
    #[serde(default)]
    pub call_trace: bool,
    #[serde(default)]
    pub contract_creation: bool,
    #[serde(default)]
    pub logs: bool,
    #[serde(default)]
    pub revert_data: bool,
    #[serde(default)]
    pub gas_details: bool,
    #[serde(default)]
    pub account_changes: bool,
    /// Every `TLOAD`/`TSTORE` since the transaction began carries `transient_storage`.
    #[serde(default)]
    pub transient_storage: bool,
    /// Every step carries the return data buffer it starts with.
    #[serde(default)]
    pub return_data: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TraceArtifacts {
    #[serde(default)]
    pub calls: Vec<ExecutionCall>,
    #[serde(default)]
    pub creations: Vec<ContractCreation>,
    #[serde(default)]
    pub logs: Vec<ExecutionLog>,
    #[serde(default)]
    pub account_changes: Vec<AccountChange>,
    #[serde(default)]
    pub gas: Option<GasSummary>,
    #[serde(default)]
    pub revert_data: Option<String>,
    /// What each top-level call is, for a trace with several, such as Foundry's
    /// `deployment`, `setup` and `execution`. Display only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_kinds: Vec<RootKind>,
}

/// The kind of the top-level call that starts at `entry_step`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootKind {
    pub entry_step: usize,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCall {
    pub id: usize,
    pub parent_id: Option<usize>,
    pub depth: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_step: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_step: Option<usize>,
    pub call_type: String,
    pub from: String,
    pub to: String,
    pub bytecode_address: String,
    pub value: String,
    pub input: String,
    pub gas_limit: u64,
    pub gas_used: Option<u64>,
    pub output: Option<String>,
    pub success: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCreation {
    pub id: usize,
    pub parent_id: Option<usize>,
    pub depth: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_step: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_step: Option<usize>,
    pub create_type: String,
    pub caller: String,
    pub address: Option<String>,
    pub value: String,
    pub init_code: String,
    pub gas_limit: u64,
    pub gas_used: Option<u64>,
    pub output: Option<String>,
    pub success: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub index: usize,
    pub depth: u64,
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChange {
    pub depth: u64,
    pub kind: String,
    pub address: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub value: Option<String>,
    pub key: Option<String>,
    pub previous_value: Option<String>,
    pub previous_nonce: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSummary {
    pub used: u64,
    pub spent: Option<u64>,
    pub refunded: Option<u64>,
    pub remaining: Option<u64>,
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub selector: String,
    pub entry_step: usize,
    pub exit_step: Option<usize>,
    pub gas_used: u64,
    pub depth: u64,
    pub call_type: String,
    pub contract_address: Option<String>,
}

/// Whether two byte views are the same bytes in the same place, which is how a shared
/// [`Bytes`] is recognized without comparing its contents.
#[must_use]
pub fn same_buffer(a: &[u8], b: &[u8]) -> bool {
    a.as_ptr() == b.as_ptr() && a.len() == b.len()
}

/// Why a string is not hex.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HexError {
    /// Hex spells a byte with two digits, so a byte string has an even number of them.
    #[error("{0} hex digits is not a whole number of bytes")]
    OddLength(usize),
    /// A character that is not a hex digit, at its byte offset after any `0x` prefix.
    #[error("`{character}` at offset {offset} is not a hex digit")]
    InvalidDigit { offset: usize, character: char },
}

/// Bytes as lowercase hex digits without a `0x` prefix, the spelling trace files use for
/// memory.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}

/// Hex digits, with or without a `0x` prefix and in either case, as bytes.
///
/// # Errors
///
/// Returns a [`HexError`] when the digits are not a whole number of bytes or a character
/// is not a hex digit.
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, HexError> {
    let mut bytes = Vec::new();
    decode_hex_into(hex, &mut bytes)?;
    Ok(bytes)
}

/// [`decode_hex`] appending to `bytes`, for a caller joining many pieces into one buffer.
///
/// # Errors
///
/// As [`decode_hex`]. On an error `bytes` may hold some of the digits decoded before it.
pub fn decode_hex_into(hex: &str, bytes: &mut Vec<u8>) -> Result<(), HexError> {
    let digits = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    // Decoded over bytes, never by slicing the string: input from a node or a file is not
    // guaranteed to be ASCII.
    let raw = digits.as_bytes();
    let invalid = |offset: usize| HexError::InvalidDigit {
        offset,
        // Every byte before `offset` is an ASCII digit, so `offset` is a character boundary.
        character: digits
            .get(offset..)
            .and_then(|rest| rest.chars().next())
            .unwrap_or(char::REPLACEMENT_CHARACTER),
    };
    bytes.reserve(raw.len() / 2);
    let (pairs, rest) = raw.as_chunks::<2>();
    for (index, [high, low]) in pairs.iter().enumerate() {
        let high = hex_value(*high).ok_or_else(|| invalid(index * 2))?;
        let low = hex_value(*low).ok_or_else(|| invalid(index * 2 + 1))?;
        bytes.push(high << 4 | low);
    }
    if let [last] = rest {
        return Err(match hex_value(*last) {
            Some(_) => HexError::OddLength(raw.len()),
            None => invalid(raw.len() - 1),
        });
    }
    Ok(())
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Writes bytes as one unprefixed lowercase hex string without building the string
/// first: a serializer that streams, as `serde_json` does, writes the digits straight
/// into the output.
#[derive(Clone, Copy)]
pub(crate) struct Hex<'a>(pub(crate) &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [0_u8; 128];
        for chunk in self.0.chunks(buffer.len() / 2) {
            for (index, byte) in chunk.iter().enumerate() {
                buffer[index * 2] = HEX_DIGITS[usize::from(byte >> 4)];
                buffer[index * 2 + 1] = HEX_DIGITS[usize::from(byte & 0x0f)];
            }
            let digits = std::str::from_utf8(&buffer[..chunk.len() * 2]).map_err(|_| fmt::Error)?;
            formatter.write_str(digits)?;
        }
        Ok(())
    }
}

impl Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Reads memory spelled as hex, the way every trace file writes it, into bytes.
fn deserialize_memory<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Bytes>, D::Error> {
    struct MemoryHex;

    impl<'de> Visitor<'de> for MemoryHex {
        type Value = Option<Bytes>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("memory as a hex string")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_str(self)
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            decode_hex(value)
                .map(|bytes| Some(Bytes::from(bytes)))
                .map_err(|error| E::custom(format!("memory is not hex: {error}")))
        }
    }

    deserializer.deserialize_option(MemoryHex)
}

#[cfg(test)]
mod tests {
    /// Borrows a stack as plain strings, for comparing in assertions.

    #[test]
    fn repeated_stack_words_are_stored_once() {
        let mut words = super::WordInterner::new();
        assert!(words.is_empty());
        let first = words.intern("0x2a");
        let again = words.intern("0x2a");
        let other = words.intern("0x1");
        assert_eq!(words.len(), 2);
        assert_eq!(&*first, "0x2a");
        // The same value is the same allocation, which is the whole point: a trace of a
        // few hundred thousand steps repeats a few thousand distinct words millions of
        // times.
        assert!(Arc::ptr_eq(&first, &again));
        assert!(!Arc::ptr_eq(&first, &other));

        let mut stack = vec![Arc::from("0x2a"), Arc::from("0x2a"), Arc::from("0x1")];
        words.intern_stack(&mut stack);
        assert!(Arc::ptr_eq(&stack[0], &stack[1]));
        assert!(Arc::ptr_eq(&stack[0], &first));
        assert_eq!(words.len(), 2, "nothing new was seen");
    }

    #[test]
    fn a_parsed_trace_reads_its_stack_words() {
        // Two steps holding the same words, the second in another spelling.
        let document = serde_json::json!({
            "tx_hash": "0xabc",
            "from_addr": "0x1",
            "to_addr": "0x2",
            "value": "0x0",
            "input_data": "0x",
            "gas_used": 0,
            "output": "0x",
            "success": true,
            "debug_trace_available": true,
            "steps": [
                {"pc": 0, "op": "PUSH1", "gas": 1, "gas_cost": 1, "depth": 1,
                 "stack": ["0x2a", "0x1"]},
                {"pc": 2, "op": "ADD", "gas": 0, "gas_cost": 1, "depth": 1,
                 "stack": ["0x002A", "0x1"]}
            ]
        })
        .to_string();
        let trace: TransactionTrace = serde_json::from_str(&document).expect("trace");
        let stack = |index: usize| trace.steps.step(index).stack().to_vec();
        assert_eq!(stack(0), [EvmWord::from(0x2a), EvmWord::from(1)]);
        assert_eq!(stack(1), stack(0));
        // Written back in the one spelling stack words have.
        let written = serde_json::to_value(&trace).expect("json");
        assert_eq!(
            written["steps"][1]["stack"],
            serde_json::json!(["0x2a", "0x1"])
        );
    }
    fn words(stack: &[super::Word]) -> Vec<&str> {
        stack.iter().map(|word| &**word).collect()
    }

    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::{
        decode_hex, encode_hex, same_buffer, Bytes, EvmWord, FunctionCall, HexError, StepSnapshot,
        StorageChange, TraceArtifacts, TraceCapabilities, TraceStep, TransactionTrace,
    };

    /// Memory spelled as the hex a test reads easiest.
    fn memory(hex: &str) -> Bytes {
        Bytes::from(decode_hex(hex).expect("test memory is hex"))
    }

    fn step_with(snapshot: StepSnapshot) -> TraceStep {
        TraceStep {
            pc: 3,
            op: Arc::from("SSTORE"),
            gas: 100,
            gas_cost: 5,
            depth: 1,
            stack: vec![Arc::from("0x01"), Arc::from("0x02")],
            memory: Some(memory("aabb")),
            storage: Some(BTreeMap::from([("0x00".to_owned(), "0x2a".to_owned())])),
            error: None,
            snapshot,
        }
    }

    #[test]
    fn borrowed_snapshot_matches_the_owned_one() {
        // `snapshot_ref` is what every trace walk uses, so it has to be indistinguishable
        // from `normalized_snapshot` in both shapes a step can take: snapshot populated,
        // and only the flat fields populated. The serialized forms must match too, because
        // a saved trace (`--save-trace`) writes a snapshot per step.
        let flat = step_with(StepSnapshot::default());
        let populated = step_with(StepSnapshot::new(
            vec![Arc::from("0x09")],
            Some(memory("ccdd")),
            BTreeMap::from([("0x01".to_owned(), "0x63".to_owned())]),
            BTreeMap::from([(
                "0x01".to_owned(),
                StorageChange {
                    before: None,
                    after: Some("0x63".to_owned()),
                },
            )]),
        ));

        for step in [&flat, &populated] {
            assert_eq!(
                step.snapshot_ref().to_owned_snapshot(),
                step.normalized_snapshot()
            );
            assert_eq!(
                serde_json::to_string(&step.snapshot_ref()).expect("borrowed snapshot"),
                serde_json::to_string(&step.normalized_snapshot()).expect("owned snapshot"),
            );
        }

        // The flat shape falls back to the top-level fields and reports no storage diff.
        assert_eq!(words(flat.snapshot_ref().stack), ["0x01", "0x02"]);
        assert_eq!(flat.snapshot_ref().memory, Some(&[0xaa, 0xbb][..]));
        assert!(flat.snapshot_ref().storage_diff.is_empty());

        // A populated snapshot wins over the flat fields.
        assert_eq!(words(populated.snapshot_ref().stack), ["0x09"]);
        assert_eq!(populated.snapshot_ref().memory, Some(&[0xcc, 0xdd][..]));
        assert_eq!(populated.snapshot_ref().storage_diff.len(), 1);
    }

    #[test]
    fn steps_serialize_in_the_wire_format_and_read_back_stored_once() {
        // A step holds its state once, in the snapshot; the document still carries the
        // flat fields older readers expect, filled from that one copy.
        let step = TraceStep::new(
            3,
            Arc::from("SSTORE"),
            100,
            5,
            1,
            None,
            StepSnapshot::new(
                vec![Arc::from("0x01")],
                Some(memory("aabb")),
                BTreeMap::from([("0x00".to_owned(), "0x2a".to_owned())]),
                BTreeMap::new(),
            ),
        );
        let json: serde_json::Value = serde_json::to_value(&step).expect("json");
        assert_eq!(json["stack"], serde_json::json!(["0x01"]));
        assert_eq!(json["memory"], "aabb");
        assert_eq!(json["storage"]["0x00"], "0x2a");
        assert_eq!(json["snapshot"]["memory"], "aabb");
        assert_eq!(json["snapshot"]["storage"]["0x00"], "0x2a");
        assert_eq!(json["gas_cost"], 5);

        // A step written by hand in the flat shape serializes the same way.
        let flat = step_with(StepSnapshot::default());
        let flat_json: serde_json::Value = serde_json::to_value(&flat).expect("json");
        assert_eq!(
            flat_json["snapshot"]["stack"],
            serde_json::json!(["0x01", "0x02"])
        );
        assert_eq!(flat_json["stack"], serde_json::json!(["0x01", "0x02"]));

        // Reading back either shape stores the state in the snapshot only, and the
        // result equals the original because equality compares what was recorded.
        let restored: TraceStep = serde_json::from_value(json).expect("step");
        assert_eq!(restored, step);
        assert!(
            restored.stack.is_empty() && restored.memory.is_none() && restored.storage.is_none()
        );
        let legacy: TraceStep = serde_json::from_str(
            r#"{"pc":1,"op":"ADD","gas":9,"gas_cost":3,"depth":1,"stack":["0x1"],"memory":"cc","storage":{"0x0":"0x1"},"error":null}"#,
        )
        .expect("legacy step");
        assert_eq!(words(legacy.snapshot_ref().stack), ["0x1"]);
        assert_eq!(legacy.snapshot_ref().memory, Some(&[0xcc][..]));
        assert_eq!(legacy.snapshot_ref().storage["0x0"], "0x1");
        assert!(legacy.stack.is_empty());
        assert_eq!(legacy, step_with_legacy_fields());

        // Steps share memory and storage by reference when a backend hands them on.
        let shared = TraceStep::new(
            4,
            Arc::from("POP"),
            95,
            2,
            1,
            None,
            StepSnapshot {
                stack: Vec::new(),
                memory: step.snapshot.memory.clone(),
                storage: Arc::clone(&step.snapshot.storage),
                storage_diff: BTreeMap::new(),
                transient_storage: BTreeMap::new(),
                return_data: None,
            },
        );
        assert!(Arc::ptr_eq(
            &shared.snapshot.storage,
            &step.snapshot.storage
        ));
        assert_eq!(shared.snapshot_ref().memory, Some(&[0xaa, 0xbb][..]));
        assert!(same_buffer(
            shared.snapshot_ref().memory.expect("memory"),
            step.snapshot_ref().memory.expect("memory")
        ));
    }

    #[test]
    fn transient_storage_is_written_only_where_a_step_touched_it() {
        let plain = TraceStep::new(
            0,
            Arc::from("ADD"),
            1,
            1,
            1,
            None,
            StepSnapshot::new(
                vec![Arc::from("0x1")],
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        );
        let json = serde_json::to_value(&plain).expect("json");
        assert!(json["snapshot"].get("transient_storage").is_none());

        let touched = TraceStep::new(
            1,
            Arc::from("TSTORE"),
            1,
            100,
            1,
            None,
            StepSnapshot::new(
                vec![Arc::from("0x1")],
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .with_transient_storage(BTreeMap::from([("0x0".to_owned(), "0x2".to_owned())])),
        );
        let json = serde_json::to_value(&touched).expect("json");
        assert_eq!(json["snapshot"]["transient_storage"]["0x0"], "0x2");
        assert_eq!(
            serde_json::to_value(touched.snapshot_ref()).expect("borrowed"),
            json["snapshot"]
        );
        let restored: TraceStep = serde_json::from_value(json).expect("step");
        assert_eq!(restored, touched);
        assert_eq!(restored.snapshot_ref().transient_storage["0x0"], "0x2");

        // A file written before the field existed reads with none, and so does its
        // capability.
        let capabilities: TraceCapabilities =
            serde_json::from_str(r#"{"stack":true}"#).expect("capabilities");
        assert!(!capabilities.transient_storage);
    }

    #[test]
    fn return_data_is_written_only_where_the_buffer_holds_some() {
        let snapshot = || {
            StepSnapshot::new(
                vec![Arc::from("0x1")],
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            )
        };
        let empty = TraceStep::new(
            0,
            Arc::from("CALL"),
            1,
            1,
            1,
            None,
            snapshot().with_return_data(Some(String::new())),
        );
        assert!(empty.snapshot.return_data.is_none());
        let json = serde_json::to_value(&empty).expect("json");
        assert!(json["snapshot"].get("return_data").is_none());

        let filled = TraceStep::new(
            1,
            Arc::from("RETURNDATASIZE"),
            1,
            2,
            1,
            None,
            snapshot().with_return_data(Some("2a".to_owned())),
        );
        let json = serde_json::to_value(&filled).expect("json");
        assert_eq!(json["snapshot"]["return_data"], "2a");
        assert_eq!(
            serde_json::to_value(filled.snapshot_ref()).expect("borrowed"),
            json["snapshot"]
        );
        let restored: TraceStep = serde_json::from_value(json).expect("step");
        assert_eq!(restored, filled);
        assert_eq!(restored.snapshot_ref().return_data, Some("2a"));

        // Consecutive steps read back from a file share one copy of the buffer.
        let mut trace = TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: None,
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 0,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: TraceCapabilities::default(),
            artifacts: TraceArtifacts::default(),
            steps: vec![filled.clone(), filled].into(),
        };
        trace = serde_json::from_str(&serde_json::to_string(&trace).expect("json")).expect("trace");
        let data = |index: usize| trace.steps.step(index).return_data().expect("data");
        assert!(std::ptr::eq(data(0), data(1)));
        assert!(!trace.capabilities.return_data);
    }

    fn step_with_legacy_fields() -> TraceStep {
        TraceStep {
            pc: 1,
            op: Arc::from("ADD"),
            gas: 9,
            gas_cost: 3,
            depth: 1,
            stack: vec![Arc::from("0x1")],
            memory: Some(memory("cc")),
            storage: Some(BTreeMap::from([("0x0".to_owned(), "0x1".to_owned())])),
            error: None,
            snapshot: StepSnapshot::default(),
        }
    }

    #[test]
    fn reading_a_trace_back_shares_unchanged_state_between_steps() {
        let snapshot = |hex: &str, slot: &str| {
            StepSnapshot::new(
                Vec::new(),
                Some(memory(hex)),
                BTreeMap::from([("0x0".to_owned(), slot.to_owned())]),
                BTreeMap::new(),
            )
        };
        let step = |pc: u64, snapshot: StepSnapshot| {
            TraceStep::new(pc, Arc::from("PUSH1"), 1, 1, 1, None, snapshot)
        };
        let trace = TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: None,
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 0,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: TraceCapabilities::default(),
            artifacts: TraceArtifacts::default(),
            steps: vec![
                step(0, snapshot("aa", "0x1")),
                step(1, snapshot("aa", "0x1")),
                step(2, snapshot("bb", "0x1")),
                step(3, snapshot("bb", "0x2")),
            ]
            .into(),
        };
        let json = serde_json::to_string(&trace).expect("json");
        let restored: TransactionTrace = serde_json::from_str(&json).expect("trace");
        assert_eq!(restored, trace);
        // Steps share what did not change however the trace was put together: read back
        // from a file, or built from steps that each held their own copy.
        for trace in [&restored, &trace] {
            let memory = |index: usize| trace.steps.step(index).memory().expect("memory");
            assert!(same_buffer(&memory(0), &memory(1)));
            assert!(!same_buffer(&memory(1), &memory(2)));
            assert!(same_buffer(&memory(2), &memory(3)));
            let storage = |index: usize| trace.steps.step(index).storage();
            assert!(std::ptr::eq(storage(0), storage(2)));
            assert!(!std::ptr::eq(storage(2), storage(3)));
        }
    }

    #[test]
    fn core_models_are_serializable() {
        let trace = TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 1,
            output: "0x".to_owned(),
            success: true,
            error: None,
            steps: vec![TraceStep {
                pc: 0,
                op: Arc::from("STOP"),
                gas: 1,
                gas_cost: 0,
                depth: 0,
                stack: Vec::new(),
                memory: None,
                storage: None,
                error: None,
                snapshot: StepSnapshot::default(),
            }]
            .into(),
            debug_trace_available: true,
            contract_address: None,
            backend: Some("debug-rpc".to_owned()),
            capabilities: TraceCapabilities::default(),
            artifacts: TraceArtifacts::default(),
        };

        let encoded = serde_json::to_string(&trace).expect("trace serializes");
        assert!(encoded.contains("\"success\":true"));

        let call = FunctionCall {
            name: "runtime_dispatcher".to_owned(),
            selector: String::new(),
            entry_step: 0,
            exit_step: Some(0),
            gas_used: 1,
            depth: 0,
            call_type: "entry".to_owned(),
            contract_address: Some("0x2".to_owned()),
        };
        assert_eq!(call.call_type, "entry");

        let change = StorageChange {
            before: None,
            after: Some("0x2a".to_owned()),
        };
        assert_eq!(change.after.as_deref(), Some("0x2a"));
    }

    #[test]
    fn memory_reads_and_writes_as_the_same_hex_string() {
        // A trace file spells memory as one unprefixed lowercase hex string, in the flat
        // field and in the snapshot. Holding it as bytes must not change a byte of the
        // file: what is read back writes out exactly as it was read.
        let words = format!("{}{}", "00".repeat(31), "2a").repeat(3);
        let document = serde_json::json!({
            "tx_hash": "0xabc",
            "from_addr": "0x1",
            "to_addr": "0x2",
            "value": "0x0",
            "input_data": "0x",
            "gas_used": 0,
            "output": "0x",
            "success": true,
            "error": null,
            "debug_trace_available": true,
            "contract_address": null,
            "backend": "replay",
            "capabilities": TraceCapabilities::default(),
            "artifacts": TraceArtifacts::default(),
            "steps": [
                {"pc": 0, "op": "MSTORE", "gas": 1, "gas_cost": 1, "depth": 1,
                 "stack": [], "memory": "", "storage": {}, "error": null,
                 "snapshot": {"stack": [], "memory": "", "storage": {}, "storage_diff": {}}},
                {"pc": 1, "op": "MLOAD", "gas": 1, "gas_cost": 1, "depth": 1,
                 "stack": [], "memory": words, "storage": {}, "error": null,
                 "snapshot": {"stack": [], "memory": words, "storage": {}, "storage_diff": {}}},
                {"pc": 2, "op": "POP", "gas": 1, "gas_cost": 1, "depth": 1,
                 "stack": [], "memory": words, "storage": {}, "error": null,
                 "snapshot": {"stack": [], "memory": words, "storage": {}, "storage_diff": {}}},
                {"pc": 3, "op": "STOP", "gas": 1, "gas_cost": 0, "depth": 1,
                 "stack": [], "memory": null, "storage": {}, "error": null,
                 "snapshot": {"stack": [], "memory": null, "storage": {}, "storage_diff": {}}}
            ]
        })
        .to_string();
        let trace: TransactionTrace = serde_json::from_str(&document).expect("trace");
        let written = serde_json::to_string(&trace).expect("json");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&written).expect("written json"),
            serde_json::from_str::<serde_json::Value>(&document).expect("document json"),
        );
        // Byte for byte, once the keys are in the order the writer puts them.
        let again: TransactionTrace = serde_json::from_str(&written).expect("trace");
        assert_eq!(serde_json::to_string(&again).expect("json"), written);

        let memory = |index: usize| trace.steps.step(index).memory();
        assert_eq!(memory(0).as_deref(), Some(&[][..]));
        assert_eq!(memory(1).map(|memory| memory.len()), Some(96));
        assert_eq!(
            memory(1).and_then(|memory| memory.get(31).copied()),
            Some(0x2a)
        );
        assert_eq!(memory(3), None);
        // The unchanged memory of the third step is the second step's buffer.
        assert!(same_buffer(
            &memory(1).expect("memory"),
            &memory(2).expect("memory")
        ));
    }

    #[test]
    fn memory_from_a_file_may_be_prefixed_but_must_be_hex() {
        let step = |memory: &str| {
            serde_json::from_str::<TraceStep>(&format!(
                r#"{{"pc":0,"op":"STOP","gas":0,"gas_cost":0,"depth":1,"memory":{memory}}}"#
            ))
        };
        let prefixed = step(r#""0xAABB""#).expect("prefixed memory");
        assert_eq!(prefixed.snapshot_ref().memory, Some(&[0xaa, 0xbb][..]));
        // Written back in the one canonical spelling.
        assert_eq!(
            serde_json::to_value(&prefixed).expect("json")["memory"],
            "aabb"
        );

        let odd = step(r#""abc""#).expect_err("odd length");
        assert!(odd
            .to_string()
            .starts_with("memory is not hex: 3 hex digits"));
        let invalid = step(r#""aazz""#).expect_err("not hex");
        assert!(invalid
            .to_string()
            .starts_with("memory is not hex: `z` at offset 2"));
    }

    #[test]
    fn hex_round_trips_and_names_what_is_wrong() {
        assert_eq!(encode_hex(&[0x00, 0x2a, 0xff]), "002aff");
        assert_eq!(decode_hex("002AfF"), Ok(vec![0x00, 0x2a, 0xff]));
        assert_eq!(decode_hex("0x"), Ok(Vec::new()));
        assert_eq!(decode_hex(""), Ok(Vec::new()));
        assert_eq!(decode_hex("0x2"), Err(HexError::OddLength(1)));
        assert_eq!(
            decode_hex("2x"),
            Err(HexError::InvalidDigit {
                offset: 1,
                character: 'x'
            })
        );
        // A multi-byte character is reported whole rather than split.
        assert_eq!(
            decode_hex("aé"),
            Err(HexError::InvalidDigit {
                offset: 1,
                character: 'é'
            })
        );
    }
}
