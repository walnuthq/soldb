//! The steps of a trace, held in columns.
//!
//! A trace runs to millions of steps, and a step holding its own stack, maps and options
//! made building, walking and dropping one a matter of allocation and copying. A
//! [`StepTable`] keeps each field of every step in a column of plain values instead: the
//! program counter, the opcode byte, the depth, the gas, and a tape of stack words in
//! which a step stores only the words above the ones it kept from the step before, with
//! the whole stack every [`STACK_CHECKPOINT`] steps. What only some steps have, an error,
//! a storage diff, transient storage, is kept for those steps alone, and what changes
//! rarely, storage and return data, once per change. Memory is kept by
//! [`crate::memory`].
//!
//! Readers get a [`StepView`] by index; values are formatted only when shown. A trace
//! file is unchanged: a table writes each step in the shape [`TraceStep`] always had.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use serde::de::{self, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::memory::{MemoryRef, MemoryStore};
use crate::{
    encode_hex, opcode, EvmWord, Hex, MemoryWriteError, StepSnapshot, StorageChange, TraceStep,
    Word, WordError,
};

/// Every this many steps, a step stores its whole stack, so that reading a word never
/// walks back further.
pub const STACK_CHECKPOINT: usize = 32;

const CHUNK_BITS: u32 = 14;
const CHUNK: usize = 1 << CHUNK_BITS;

/// A column of one field, grown a fixed-size chunk at a time so that growing never moves
/// what is already in it. The first chunk grows like any vector, which keeps a short
/// trace small.
#[derive(Debug, Clone)]
struct Column<T> {
    chunks: Vec<Vec<T>>,
    len: usize,
}

impl<T> Default for Column<T> {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }
}

impl<T: Copy> Column<T> {
    fn push(&mut self, value: T) {
        match self.chunks.last_mut() {
            Some(chunk) if chunk.len() < CHUNK => chunk.push(value),
            _ => {
                let mut chunk = if self.chunks.is_empty() {
                    Vec::new()
                } else {
                    Vec::with_capacity(CHUNK)
                };
                chunk.push(value);
                self.chunks.push(chunk);
            }
        }
        self.len += 1;
    }

    fn get(&self, index: usize) -> T {
        self.chunks[index >> CHUNK_BITS][index & (CHUNK - 1)]
    }

    fn set(&mut self, index: usize, value: T) {
        self.chunks[index >> CHUNK_BITS][index & (CHUNK - 1)] = value;
    }

    fn last(&self) -> Option<T> {
        self.len.checked_sub(1).map(|index| self.get(index))
    }

    /// Makes room for `chunks` chunks, the first of `first` values.
    fn reserve(&mut self, chunks: usize, first: usize) {
        self.chunks.reserve(chunks);
        if self.chunks.is_empty() && first > 0 {
            self.chunks.push(Vec::with_capacity(first));
        }
    }

    fn truncate(&mut self, len: usize) {
        if len >= self.len {
            return;
        }
        let chunks = len.div_ceil(CHUNK);
        self.chunks.truncate(chunks);
        if let Some(last) = self.chunks.last_mut() {
            last.truncate(len - (chunks - 1) * CHUNK);
        }
        self.len = len;
    }
}

/// One step as a producer appends it with [`StepTable::append`]: its plain fields, and
/// the state that changed since the step before.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepRecord {
    pub pc: u64,
    pub op: u8,
    pub gas: u64,
    /// The cost as the tracer reports it; see [`TraceStep::gas_cost`].
    pub gas_cost: u64,
    pub depth: u64,
    pub error: Option<String>,
    /// The memory the step starts with, in full. `None` leaves it to the frame being
    /// recorded with [`StepTable::write_memory`], or keeps the previous step's when none
    /// is.
    pub memory: Option<Bytes>,
    /// The storage the backend reports for the step; `None` keeps the previous step's.
    pub storage: Option<Arc<BTreeMap<String, String>>>,
    /// The slots the step changed.
    pub storage_diff: Option<BTreeMap<String, StorageChange>>,
    /// The transient slots the step read or wrote, with their value after it.
    pub transient_storage: Option<BTreeMap<String, String>>,
    /// The return data buffer the step starts with, as unprefixed hex; empty for an empty
    /// buffer, and `None` keeps the previous step's.
    pub return_data: Option<Arc<str>>,
}

/// Why a step cannot be added to a [`StepTable`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StepError {
    #[error("step {step}: stack word {position}: {error}")]
    StackWord {
        step: usize,
        position: usize,
        error: WordError,
    },
}

/// The steps of a trace, in columns. See the module docs.
#[derive(Clone, Default)]
pub struct StepTable {
    /// The program counter, or `u32::MAX` for one in `wide_pcs`.
    pc: Column<u32>,
    op: Column<u8>,
    /// The depth, or `u16::MAX` for one in `wide_depths`.
    depth: Column<u16>,
    gas: Column<u64>,
    gas_cost: Column<u64>,
    stack_len: Column<u32>,
    /// How many bottom words of the step's stack are the previous step's; the rest are on
    /// the tape from `stack_start`.
    stack_kept: Column<u32>,
    stack_start: Column<u64>,
    words: Column<EvmWord>,
    memory: Column<MemoryRef>,
    /// The steps whose backend spelled their mnemonic other than [`opcode::mnemonic`]
    /// does, ascending, with that spelling.
    mnemonics: Vec<(usize, Word)>,
    errors: Vec<(usize, Box<str>)>,
    /// The program counters and depths too wide for their columns, which no EVM trace has
    /// but nothing forbids.
    wide_pcs: Vec<(usize, u64)>,
    wide_depths: Vec<(usize, u64)>,
    /// Storage as of each step that changed it, ascending; empty before the first.
    storage: Vec<(usize, Arc<BTreeMap<String, String>>)>,
    storage_diffs: Vec<(usize, BTreeMap<String, StorageChange>)>,
    transient_storage: Vec<(usize, BTreeMap<String, String>)>,
    /// Return data as of each step that changed it, ascending; none before the first.
    return_data: Vec<(usize, Option<Arc<str>>)>,
    memories: MemoryStore,
    /// The stack of the step appended last, which the next one is stored against.
    last_stack: Vec<EvmWord>,
    /// That stack as the backend spelled it, when the step was pushed as a [`TraceStep`]:
    /// a word the next step shares by pointer, as an interning backend shares them, is the
    /// same word and is not parsed again.
    last_spelled: Vec<Word>,
    /// The opcode byte of each mnemonic pushed recently, by the backend's shared string,
    /// and whether the backend spells it as [`opcode::mnemonic`] does.
    spellings: Vec<(Word, Option<u8>, bool)>,
    /// A buffer for the stack of the step being pushed.
    scratch: Vec<EvmWord>,
}

/// How many mnemonics [`StepTable`] remembers by pointer. Every opcode a trace runs fits;
/// a backend that does not share its mnemonics only pays for the misses.
const SPELLINGS: usize = 64;

static EMPTY_STORAGE: BTreeMap<String, String> = BTreeMap::new();
static EMPTY_STORAGE_DIFF: BTreeMap<String, StorageChange> = BTreeMap::new();

impl StepTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty table that holds `steps` steps without allocating its columns again.
    #[must_use]
    pub fn with_capacity(steps: usize) -> Self {
        let mut table = Self::new();
        let chunks = steps.div_ceil(CHUNK);
        let first = steps.min(CHUNK);
        table.pc.reserve(chunks, first);
        table.op.reserve(chunks, first);
        table.depth.reserve(chunks, first);
        table.gas.reserve(chunks, first);
        table.gas_cost.reserve(chunks, first);
        table.stack_len.reserve(chunks, first);
        table.stack_kept.reserve(chunks, first);
        table.stack_start.reserve(chunks, first);
        table.memory.reserve(chunks, first);
        table
    }

    /// A table of `steps`, in order.
    ///
    /// # Errors
    ///
    /// As [`StepTable::try_push`].
    pub fn try_from_steps(steps: impl IntoIterator<Item = TraceStep>) -> Result<Self, StepError> {
        let mut table = Self::new();
        for step in steps {
            table.try_push(step)?;
        }
        Ok(table)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.op.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<StepView<'_>> {
        (index < self.len()).then_some(StepView { table: self, index })
    }

    /// The step at `index`.
    ///
    /// # Panics
    ///
    /// When `index` is not below [`StepTable::len`], as indexing a slice does.
    #[must_use]
    pub fn step(&self, index: usize) -> StepView<'_> {
        assert!(
            index < self.len(),
            "step {index} of a trace of {} steps",
            self.len()
        );
        StepView { table: self, index }
    }

    #[must_use]
    pub fn first(&self) -> Option<StepView<'_>> {
        self.get(0)
    }

    #[must_use]
    pub fn last(&self) -> Option<StepView<'_>> {
        self.len().checked_sub(1).and_then(|index| self.get(index))
    }

    #[must_use]
    pub fn iter(&self) -> Steps<'_> {
        Steps {
            table: self,
            front: 0,
            back: self.len(),
        }
    }

    /// Appends a step built the way every backend builds one, sharing what did not change
    /// since the step before: its stack words, memory, storage and return data.
    ///
    /// # Panics
    ///
    /// When a stack word is not hex. A producer reading words from untrusted input, a node
    /// or a file, appends with [`StepTable::try_push`] instead.
    pub fn push(&mut self, step: TraceStep) {
        if let Err(error) = self.try_push(step) {
            panic!("a step built in this process holds a stack word that is not hex: {error}");
        }
    }

    /// [`StepTable::push`] for a step whose stack words may not be hex.
    ///
    /// # Errors
    ///
    /// Returns a [`StepError`] when a stack word is not hex. Nothing is appended then.
    pub fn try_push(&mut self, step: TraceStep) -> Result<(), StepError> {
        let index = self.len();
        let step = step.normalized();
        let snapshot = step.snapshot;
        let mut stack = std::mem::take(&mut self.scratch);
        stack.clear();
        let mut kept = 0;
        for (position, word) in snapshot.stack.iter().enumerate() {
            let shared = self
                .last_spelled
                .get(position)
                .is_some_and(|before| Arc::ptr_eq(before, word));
            let parsed = match self.last_stack.get(position) {
                Some(before) if shared => *before,
                _ => match EvmWord::parse(word) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        self.scratch = stack;
                        return Err(StepError::StackWord {
                            step: index,
                            position,
                            error,
                        });
                    }
                },
            };
            if kept == position && self.last_stack.get(position) == Some(&parsed) {
                kept += 1;
            }
            stack.push(parsed);
        }
        let (op, canonical) = self.spelling(&step.op);
        self.append_inner(
            StepRecord {
                pc: step.pc,
                op: op.unwrap_or(opcode::INVALID),
                gas: step.gas,
                gas_cost: step.gas_cost,
                depth: step.depth,
                error: step.error,
                memory: None,
                storage: Some(snapshot.storage),
                storage_diff: Some(snapshot.storage_diff),
                transient_storage: Some(snapshot.transient_storage),
                return_data: None,
            },
            kept,
            stack[kept..].iter().copied(),
        );
        self.scratch = stack;
        self.last_spelled = snapshot.stack;
        self.change_return_data(index, snapshot.return_data);
        if !canonical {
            self.mnemonics.push((index, step.op));
        }
        // A step's memory is the one it carries, in full, or none.
        let memory = match snapshot.memory {
            Some(memory) => self.memories.snapshot(memory),
            None => MemoryRef::NONE,
        };
        self.memory.set(index, memory);
        Ok(())
    }

    /// The opcode byte a backend means by `spelled`, and whether it spells it as
    /// [`opcode::mnemonic`] does.
    fn spelling(&mut self, spelled: &Word) -> (Option<u8>, bool) {
        if let Some((_, op, canonical)) = self
            .spellings
            .iter()
            .find(|(known, _, _)| Arc::ptr_eq(known, spelled))
        {
            return (*op, *canonical);
        }
        let op = opcode::from_spelling(spelled);
        let canonical = op.is_some_and(|op| opcode::mnemonic(op) == &**spelled);
        if self.spellings.len() < SPELLINGS {
            self.spellings.push((Arc::clone(spelled), op, canonical));
        }
        (op, canonical)
    }

    /// Appends a step whose whole stack is `stack`, bottom first. The words the previous
    /// step's stack starts with are kept rather than stored again.
    pub fn append(&mut self, record: StepRecord, stack: impl IntoIterator<Item = EvmWord>) {
        // Compared word by word as they come, so the stack is never collected.
        let mut words = stack.into_iter();
        let mut kept = 0;
        let mut first_new = None;
        for word in words.by_ref() {
            if self.last_stack.get(kept) == Some(&word) {
                kept += 1;
            } else {
                first_new = Some(word);
                break;
            }
        }
        self.last_spelled.clear();
        self.append_inner(record, kept, first_new.into_iter().chain(words));
    }

    /// Appends a step whose stack is the bottom `kept` words of the previous step's with
    /// `words` on top, for a producer that knows how much of the stack an instruction left
    /// alone and so never copies the rest.
    ///
    /// # Panics
    ///
    /// When `kept` is more than the previous step's stack holds.
    pub fn append_kept(
        &mut self,
        record: StepRecord,
        kept: usize,
        words: impl IntoIterator<Item = EvmWord>,
    ) {
        self.last_spelled.clear();
        self.append_inner(record, kept, words);
    }

    fn append_inner(
        &mut self,
        record: StepRecord,
        kept: usize,
        words: impl IntoIterator<Item = EvmWord>,
    ) {
        let index = self.len();
        assert!(
            kept <= self.last_stack.len(),
            "step {index} keeps {kept} stack words, but the step before has {}",
            self.last_stack.len()
        );

        self.last_stack.truncate(kept);
        self.last_stack.extend(words);
        let stored_from = if index.is_multiple_of(STACK_CHECKPOINT) {
            0
        } else {
            kept
        };
        self.stack_start.push(self.words.len as u64);
        for word in &self.last_stack[stored_from..] {
            self.words.push(*word);
        }
        // A stack holds at most 1024 words; a count past `u32::MAX` is not a stack.
        self.stack_kept
            .push(u32::try_from(stored_from).unwrap_or(u32::MAX));
        self.stack_len
            .push(u32::try_from(self.last_stack.len()).unwrap_or(u32::MAX));

        match u32::try_from(record.pc) {
            Ok(pc) if pc != u32::MAX => self.pc.push(pc),
            _ => {
                self.pc.push(u32::MAX);
                self.wide_pcs.push((index, record.pc));
            }
        }
        match u16::try_from(record.depth) {
            Ok(depth) if depth != u16::MAX => self.depth.push(depth),
            _ => {
                self.depth.push(u16::MAX);
                self.wide_depths.push((index, record.depth));
            }
        }
        self.op.push(record.op);
        self.gas.push(record.gas);
        self.gas_cost.push(record.gas_cost);

        let memory = match record.memory {
            Some(memory) => self.memories.snapshot(memory),
            None if self.memories.recording() => self.memories.current(),
            None => self.memory.last().unwrap_or(MemoryRef::NONE),
        };
        self.memory.push(memory);
        if let Some(error) = record.error {
            self.errors.push((index, error.into_boxed_str()));
        }
        if let Some(storage) = record.storage {
            self.change_storage(index, storage);
        }
        if let Some(diff) = record.storage_diff.filter(|diff| !diff.is_empty()) {
            self.storage_diffs.push((index, diff));
        }
        if let Some(slots) = record.transient_storage.filter(|slots| !slots.is_empty()) {
            self.transient_storage.push((index, slots));
        }
        if let Some(return_data) = record.return_data {
            self.change_return_data(index, Some(return_data));
        }
    }

    /// Starts recording the memory of a new frame, empty, as a call or a creation starts
    /// one: the steps appended from now on have it, as written with
    /// [`StepTable::write_memory`].
    pub fn start_memory_frame(&mut self) {
        self.memories.start_frame();
    }

    /// Stops recording the innermost frame's memory, as its call returns; the steps
    /// appended from now on have its caller's again.
    pub fn end_memory_frame(&mut self) {
        self.memories.end_frame();
    }

    /// Records that the step appended last wrote `data` at `offset` of its frame's
    /// memory, which is `size` bytes long afterwards; a write without data records memory
    /// growing. The steps appended after it see the write: a step's memory is the memory
    /// it starts with.
    ///
    /// # Errors
    ///
    /// Returns a [`MemoryWriteError`] when the write ends past `size` or `size` is smaller
    /// than the memory was. Nothing is recorded then.
    pub fn write_memory(
        &mut self,
        offset: u64,
        data: &[u8],
        size: u64,
    ) -> Result<(), MemoryWriteError> {
        self.memories.write(offset, data, size)
    }

    /// Starts a run of `storage` at `index`, the step appended last, unless it is the
    /// storage the step already has.
    fn change_storage(&mut self, index: usize, storage: Arc<BTreeMap<String, String>>) {
        let current = self.storage.last().map(|(_, storage)| storage);
        let unchanged = match current {
            Some(current) => Arc::ptr_eq(current, &storage) || **current == *storage,
            None => storage.is_empty(),
        };
        if !unchanged {
            set_sparse(&mut self.storage, index, storage);
        }
    }

    /// Starts a run of `return_data` at `index`, the step appended last, unless it is the
    /// return data the step already has.
    fn change_return_data(&mut self, index: usize, return_data: Option<Arc<str>>) {
        let return_data = return_data.filter(|data| !data.is_empty());
        let current = self.return_data.last().and_then(|(_, data)| data.as_ref());
        // Producers share one buffer between the steps that did not change it, so the
        // pointers decide most comparisons without reading the text.
        let unchanged = match (current, &return_data) {
            (Some(current), Some(data)) => Arc::ptr_eq(current, data) || current == data,
            (current, data) => current.is_none() && data.is_none(),
        };
        if !unchanged {
            set_sparse(&mut self.return_data, index, return_data);
        }
    }

    /// The steps that changed storage, with the slots they changed, in order.
    pub fn storage_diffs(
        &self,
    ) -> impl DoubleEndedIterator<Item = (usize, &BTreeMap<String, StorageChange>)> {
        self.storage_diffs
            .iter()
            .map(|(index, diff)| (*index, diff))
    }

    /// The steps that read or wrote transient storage, with the slots, in order.
    pub fn transient_storage(
        &self,
    ) -> impl DoubleEndedIterator<Item = (usize, &BTreeMap<String, String>)> {
        self.transient_storage
            .iter()
            .map(|(index, slots)| (*index, slots))
    }

    /// Drops the steps from `len` on. What was recorded of their memory stays, unused.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }
        let last_stack = len
            .checked_sub(1)
            .map(|last| self.step(last).stack().to_vec())
            .unwrap_or_default();
        let words = if len == 0 {
            0
        } else {
            let last = len - 1;
            self.stack_start.get(last) as usize + self.stack_len.get(last) as usize
                - self.stack_kept.get(last) as usize
        };
        self.pc.truncate(len);
        self.op.truncate(len);
        self.depth.truncate(len);
        self.gas.truncate(len);
        self.gas_cost.truncate(len);
        self.stack_len.truncate(len);
        self.stack_kept.truncate(len);
        self.stack_start.truncate(len);
        self.memory.truncate(len);
        self.words.truncate(words);
        self.mnemonics.retain(|(index, _)| *index < len);
        self.errors.retain(|(index, _)| *index < len);
        self.wide_pcs.retain(|(index, _)| *index < len);
        self.wide_depths.retain(|(index, _)| *index < len);
        self.storage.retain(|(index, _)| *index < len);
        self.storage_diffs.retain(|(index, _)| *index < len);
        self.transient_storage.retain(|(index, _)| *index < len);
        self.return_data.retain(|(index, _)| *index < len);
        self.last_stack = last_stack;
        self.last_spelled.clear();
    }

    /// Every step as a [`TraceStep`] of its own.
    #[must_use]
    pub fn to_steps(&self) -> Vec<TraceStep> {
        self.iter().map(|step| step.to_trace_step()).collect()
    }

    /// The word at `position` from the bottom of the stack of step `index`, which must
    /// be below the stack's length.
    fn stack_word(&self, index: usize, position: usize) -> EvmWord {
        let mut step = index;
        loop {
            let kept = self.stack_kept.get(step) as usize;
            if position >= kept {
                return self
                    .words
                    .get(self.stack_start.get(step) as usize + position - kept);
            }
            // A step that kept words is not a checkpoint, so it has a step before it, and
            // that step's stack holds every word it kept.
            step -= 1;
        }
    }
}

/// The value of a run list as of `index`.
fn run_value<T>(runs: &[(usize, T)], index: usize) -> Option<&T> {
    let after = runs.partition_point(|(start, _)| *start <= index);
    after.checked_sub(1).map(|run| &runs[run].1)
}

/// The entry of a sparse list for exactly `index`.
fn sparse_value<T>(entries: &[(usize, T)], index: usize) -> Option<&T> {
    entries
        .binary_search_by_key(&index, |(step, _)| *step)
        .ok()
        .map(|position| &entries[position].1)
}

/// Sets the entry for `index`, the last step, replacing one already there.
fn set_sparse<T>(entries: &mut Vec<(usize, T)>, index: usize, value: T) {
    match entries.last_mut() {
        Some((last, current)) if *last == index => *current = value,
        _ => entries.push((index, value)),
    }
}

impl From<Vec<TraceStep>> for StepTable {
    /// # Panics
    ///
    /// As [`StepTable::push`].
    fn from(steps: Vec<TraceStep>) -> Self {
        steps.into_iter().collect()
    }
}

impl FromIterator<TraceStep> for StepTable {
    /// # Panics
    ///
    /// As [`StepTable::push`].
    fn from_iter<I: IntoIterator<Item = TraceStep>>(steps: I) -> Self {
        let mut table = Self::new();
        table.extend(steps);
        table
    }
}

impl Extend<TraceStep> for StepTable {
    /// # Panics
    ///
    /// As [`StepTable::push`].
    fn extend<I: IntoIterator<Item = TraceStep>>(&mut self, steps: I) {
        for step in steps {
            self.push(step);
        }
    }
}

impl PartialEq for StepTable {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl Eq for StepTable {}

impl fmt::Debug for StepTable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl<'a> IntoIterator for &'a StepTable {
    type Item = StepView<'a>;
    type IntoIter = Steps<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The steps of a [`StepTable`], in order.
#[derive(Debug, Clone)]
pub struct Steps<'a> {
    table: &'a StepTable,
    front: usize,
    back: usize,
}

impl<'a> Iterator for Steps<'a> {
    type Item = StepView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.front < self.back).then(|| {
            self.front += 1;
            StepView {
                table: self.table,
                index: self.front - 1,
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.back - self.front;
        (remaining, Some(remaining))
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.front = self.front.saturating_add(n).min(self.back);
        self.next()
    }
}

impl DoubleEndedIterator for Steps<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        (self.front < self.back).then(|| {
            self.back -= 1;
            StepView {
                table: self.table,
                index: self.back,
            }
        })
    }
}

impl ExactSizeIterator for Steps<'_> {}

/// One step of a [`StepTable`].
#[derive(Clone, Copy)]
pub struct StepView<'a> {
    table: &'a StepTable,
    index: usize,
}

impl<'a> StepView<'a> {
    /// The step's position in the trace.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    #[must_use]
    pub fn pc(&self) -> u64 {
        match self.table.pc.get(self.index) {
            u32::MAX => sparse_value(&self.table.wide_pcs, self.index)
                .copied()
                .unwrap_or(u64::from(u32::MAX)),
            pc => u64::from(pc),
        }
    }

    /// The opcode byte. A step whose backend spelled its mnemonic in a way no opcode is
    /// spelled has [`opcode::INVALID`]; [`StepView::mnemonic`] still has the spelling.
    #[must_use]
    pub fn op(&self) -> u8 {
        self.table.op.get(self.index)
    }

    /// The mnemonic, as the backend spelled it.
    #[must_use]
    pub fn mnemonic(&self) -> &'a str {
        if !self.table.mnemonics.is_empty() {
            if let Some(spelled) = sparse_value(&self.table.mnemonics, self.index) {
                return spelled;
            }
        }
        opcode::mnemonic(self.op())
    }

    #[must_use]
    pub fn gas(&self) -> u64 {
        self.table.gas.get(self.index)
    }

    /// The cost as the tracer reports it; see [`TraceStep::gas_cost`].
    #[must_use]
    pub fn gas_cost(&self) -> u64 {
        self.table.gas_cost.get(self.index)
    }

    #[must_use]
    pub fn depth(&self) -> u64 {
        match self.table.depth.get(self.index) {
            u16::MAX => sparse_value(&self.table.wide_depths, self.index)
                .copied()
                .unwrap_or(u64::from(u16::MAX)),
            depth => u64::from(depth),
        }
    }

    #[must_use]
    pub fn error(&self) -> Option<&'a str> {
        if self.table.errors.is_empty() {
            return None;
        }
        sparse_value(&self.table.errors, self.index).map(|error| &**error)
    }

    #[must_use]
    pub fn stack(&self) -> Stack<'a> {
        Stack {
            table: self.table,
            step: self.index,
            len: self.table.stack_len.get(self.index) as usize,
        }
    }

    /// The memory the step starts with; `None` when the backend did not record memory.
    /// The bytes are shared with the trace when it holds them in full, and rebuilt from
    /// the writes before the step otherwise.
    #[must_use]
    pub fn memory(&self) -> Option<Bytes> {
        self.table.memories.read(self.table.memory.get(self.index))
    }

    /// The storage the backend reported for the step.
    #[must_use]
    pub fn storage(&self) -> &'a BTreeMap<String, String> {
        run_value(&self.table.storage, self.index).map_or(&EMPTY_STORAGE, |storage| storage)
    }

    /// The slots the step changed.
    #[must_use]
    pub fn storage_diff(&self) -> &'a BTreeMap<String, StorageChange> {
        sparse_value(&self.table.storage_diffs, self.index).unwrap_or(&EMPTY_STORAGE_DIFF)
    }

    /// The transient slots the step read or wrote, with their value after it.
    #[must_use]
    pub fn transient_storage(&self) -> &'a BTreeMap<String, String> {
        sparse_value(&self.table.transient_storage, self.index).unwrap_or(&EMPTY_STORAGE)
    }

    /// The return data buffer before the step, as unprefixed hex; `None` when empty.
    #[must_use]
    pub fn return_data(&self) -> Option<&'a str> {
        run_value(&self.table.return_data, self.index).and_then(|data| data.as_deref())
    }

    /// The step as a [`TraceStep`] of its own.
    #[must_use]
    pub fn to_trace_step(&self) -> TraceStep {
        TraceStep::new(
            self.pc(),
            Arc::from(self.mnemonic()),
            self.gas(),
            self.gas_cost(),
            self.depth(),
            self.error().map(str::to_owned),
            StepSnapshot {
                stack: self
                    .stack()
                    .iter()
                    .map(|word| Arc::from(word.to_string()))
                    .collect(),
                memory: self.memory(),
                storage: run_value(&self.table.storage, self.index)
                    .cloned()
                    .unwrap_or_default(),
                storage_diff: self.storage_diff().clone(),
                transient_storage: self.transient_storage().clone(),
                return_data: run_value(&self.table.return_data, self.index)
                    .cloned()
                    .flatten(),
            },
        )
    }
}

impl PartialEq for StepView<'_> {
    /// Two steps are equal when they record the same thing.
    fn eq(&self, other: &Self) -> bool {
        self.pc() == other.pc()
            && self.mnemonic() == other.mnemonic()
            && self.gas() == other.gas()
            && self.gas_cost() == other.gas_cost()
            && self.depth() == other.depth()
            && self.error() == other.error()
            && self.stack() == other.stack()
            && self.memory() == other.memory()
            && self.storage() == other.storage()
            && self.storage_diff() == other.storage_diff()
            && self.transient_storage() == other.transient_storage()
            && self.return_data() == other.return_data()
    }
}

impl Eq for StepView<'_> {}

impl fmt::Debug for StepView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StepView")
            .field("index", &self.index)
            .field("pc", &self.pc())
            .field("op", &self.mnemonic())
            .field("gas", &self.gas())
            .field("gas_cost", &self.gas_cost())
            .field("depth", &self.depth())
            .field("error", &self.error())
            .field("stack", &self.stack().to_vec())
            .field("memory", &self.memory().map(|memory| encode_hex(&memory)))
            .field("storage", self.storage())
            .field("storage_diff", self.storage_diff())
            .field("transient_storage", self.transient_storage())
            .field("return_data", &self.return_data())
            .finish()
    }
}

impl Serialize for StepView<'_> {
    /// Writes the step as a [`TraceStep`] is written: the flat fields and the snapshot.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let stack = self.stack().to_vec();
        let memory = self.memory();
        let memory = memory.as_deref().map(Hex);
        let mut state = serializer.serialize_struct("TraceStep", 10)?;
        state.serialize_field("pc", &self.pc())?;
        state.serialize_field("op", self.mnemonic())?;
        state.serialize_field("gas", &self.gas())?;
        state.serialize_field("gas_cost", &self.gas_cost())?;
        state.serialize_field("depth", &self.depth())?;
        state.serialize_field("stack", &stack)?;
        state.serialize_field("memory", &memory)?;
        state.serialize_field("storage", self.storage())?;
        state.serialize_field("error", &self.error())?;
        state.serialize_field(
            "snapshot",
            &SnapshotOut {
                stack: &stack,
                memory,
                storage: self.storage(),
                storage_diff: self.storage_diff(),
                transient_storage: self.transient_storage(),
                return_data: self.return_data(),
            },
        )?;
        state.end()
    }
}

/// A step's snapshot in the shape [`StepSnapshot`] is written in.
struct SnapshotOut<'a> {
    stack: &'a [EvmWord],
    memory: Option<Hex<'a>>,
    storage: &'a BTreeMap<String, String>,
    storage_diff: &'a BTreeMap<String, StorageChange>,
    transient_storage: &'a BTreeMap<String, String>,
    return_data: Option<&'a str>,
}

impl Serialize for SnapshotOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StepSnapshot", 6)?;
        state.serialize_field("stack", self.stack)?;
        state.serialize_field("memory", &self.memory)?;
        state.serialize_field("storage", self.storage)?;
        state.serialize_field("storage_diff", self.storage_diff)?;
        // Only where a step touched it, so files without it are unchanged.
        if self.transient_storage.is_empty() {
            state.skip_field("transient_storage")?;
        } else {
            state.serialize_field("transient_storage", self.transient_storage)?;
        }
        if self.return_data.is_none() {
            state.skip_field("return_data")?;
        } else {
            state.serialize_field("return_data", &self.return_data)?;
        }
        state.end()
    }
}

impl Serialize for StepTable {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for step in self {
            sequence.serialize_element(&step)?;
        }
        sequence.end()
    }
}

impl<'de> Deserialize<'de> for StepTable {
    /// Reads steps as written by any version, appending each as it is read so that a
    /// file's steps are never all resident as [`TraceStep`]s.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Steps;

        impl<'de> Visitor<'de> for Steps {
            type Value = StepTable;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of trace steps")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut table = StepTable::new();
                while let Some(step) = seq.next_element::<TraceStep>()? {
                    table.try_push(step).map_err(de::Error::custom)?;
                }
                Ok(table)
            }
        }

        deserializer.deserialize_seq(Steps)
    }
}

/// The stack of one step, bottom first.
#[derive(Clone, Copy)]
pub struct Stack<'a> {
    table: &'a StepTable,
    step: usize,
    len: usize,
}

impl<'a> Stack<'a> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The word at `position` from the bottom.
    #[must_use]
    pub fn get(&self, position: usize) -> Option<EvmWord> {
        (position < self.len).then(|| self.table.stack_word(self.step, position))
    }

    /// The word `depth` words below the top; `0` is the top.
    #[must_use]
    pub fn peek(&self, depth: usize) -> Option<EvmWord> {
        self.len
            .checked_sub(depth.checked_add(1)?)
            .and_then(|position| self.get(position))
    }

    /// The top word.
    #[must_use]
    pub fn top(&self) -> Option<EvmWord> {
        self.peek(0)
    }

    /// The words, bottom first.
    #[must_use]
    pub fn to_vec(&self) -> Vec<EvmWord> {
        let mut words = vec![EvmWord::ZERO; self.len];
        // Fill from the top down, one step's stored words at a time: the words a step
        // kept are the previous step's, at the same positions.
        let mut step = self.step;
        let mut end = self.len;
        loop {
            let kept = (self.table.stack_kept.get(step) as usize).min(end);
            let start = self.table.stack_start.get(step) as usize;
            let stored_from = self.table.stack_kept.get(step) as usize;
            for (position, slot) in words.iter_mut().enumerate().take(end).skip(kept) {
                *slot = self.table.words.get(start + position - stored_from);
            }
            if kept == 0 {
                return words;
            }
            end = kept;
            step -= 1;
        }
    }

    /// The words, bottom first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = EvmWord> + ExactSizeIterator {
        self.to_vec().into_iter()
    }
}

impl PartialEq for Stack<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.to_vec() == other.to_vec()
    }
}

impl PartialEq<[EvmWord]> for Stack<'_> {
    fn eq(&self, other: &[EvmWord]) -> bool {
        self.len == other.len() && self.to_vec() == other
    }
}

impl fmt::Debug for Stack<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.to_vec()).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use bytes::Bytes;

    use super::{StepRecord, StepTable, STACK_CHECKPOINT};
    use crate::{opcode, EvmWord, StepSnapshot, StorageChange, TraceStep};

    /// A small generator, so that the randomized tests are the same on every run.
    struct Random(u64);

    impl Random {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    fn word(value: u64) -> Arc<str> {
        Arc::from(EvmWord::from(value).to_string())
    }

    /// Steps of every shape a backend builds: stacks growing and shrinking, memory and
    /// storage changing now and then, errors, transient storage and return data.
    fn random_steps(count: usize, seed: u64) -> Vec<TraceStep> {
        let mut random = Random(seed);
        let mut stack = Vec::<Arc<str>>::new();
        let mut memory = Bytes::from(vec![0_u8; 64]);
        let mut storage = Arc::new(BTreeMap::new());
        let mut return_data: Option<String> = None;
        (0..count)
            .map(|index| {
                match random.below(4) {
                    0 => {
                        stack.pop();
                    }
                    1 if !stack.is_empty() => {
                        let top = stack.len() - 1;
                        stack[top] = word(random.below(1 << 20));
                    }
                    _ => stack.push(word(random.next())),
                }
                if random.below(10) == 0 {
                    let mut changed = memory.to_vec();
                    let at = random.below(changed.len() as u64) as usize;
                    changed[at] = random.next() as u8;
                    if random.below(3) == 0 {
                        changed.extend_from_slice(&[0; 32]);
                    }
                    memory = Bytes::from(changed);
                }
                let mut storage_diff = BTreeMap::new();
                if random.below(20) == 0 {
                    let slot = format!("0x{:x}", random.below(5));
                    let value = format!("0x{:x}", random.next());
                    storage_diff.insert(
                        slot.clone(),
                        StorageChange {
                            before: storage.get(&slot).cloned(),
                            after: Some(value.clone()),
                        },
                    );
                    Arc::make_mut(&mut storage).insert(slot, value);
                }
                if random.below(25) == 0 {
                    return_data =
                        (random.below(2) == 0).then(|| format!("{:02x}", random.next() as u8));
                }
                let transient = if random.below(30) == 0 {
                    BTreeMap::from([("0x1".to_owned(), format!("0x{:x}", random.next()))])
                } else {
                    BTreeMap::new()
                };
                let op = match random.below(6) {
                    0 => "SSTORE".to_owned(),
                    1 => "SHA3".to_owned(),
                    2 => "UNKNOWN(0x0c)".to_owned(),
                    _ => opcode::mnemonic(random.next() as u8).to_owned(),
                };
                TraceStep::new(
                    if random.below(100) == 0 {
                        u64::MAX - index as u64
                    } else {
                        random.below(30_000)
                    },
                    Arc::from(op),
                    random.next(),
                    random.below(100),
                    if random.below(100) == 0 {
                        1 << 40
                    } else {
                        random.below(4) + 1
                    },
                    (random.below(50) == 0).then(|| "revert".to_owned()),
                    StepSnapshot {
                        stack: stack.clone(),
                        memory: (random.below(40) != 0).then(|| memory.clone()),
                        storage: Arc::clone(&storage),
                        storage_diff,
                        transient_storage: transient,
                        return_data: return_data.clone().map(Arc::from),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn writes_exactly_what_the_steps_wrote() {
        for seed in [1, 2, 3] {
            let steps = random_steps(500, seed);
            let table = StepTable::from(steps.clone());
            assert_eq!(table.len(), steps.len());
            assert_eq!(
                serde_json::to_string(&table).expect("table"),
                serde_json::to_string(&steps).expect("steps"),
                "seed {seed}"
            );
            for (index, step) in steps.iter().enumerate() {
                assert_eq!(table.step(index).to_trace_step(), *step, "step {index}");
            }
            let read: StepTable =
                serde_json::from_str(&serde_json::to_string(&steps).expect("steps")).expect("read");
            assert_eq!(read, table);
        }
    }

    #[test]
    fn stacks_read_back_across_checkpoints() {
        let steps = random_steps(5 * STACK_CHECKPOINT + 7, 9);
        let table = StepTable::from(steps.clone());
        let mut stored = 0;
        for (index, step) in steps.iter().enumerate() {
            let expected = step
                .snapshot
                .stack
                .iter()
                .map(|word| EvmWord::parse(word).expect("word"))
                .collect::<Vec<_>>();
            let stack = table.step(index).stack();
            assert_eq!(stack.to_vec(), expected, "step {index}");
            assert_eq!(stack.len(), expected.len());
            for (position, word) in expected.iter().enumerate() {
                assert_eq!(stack.get(position), Some(*word));
            }
            assert_eq!(stack.top(), expected.last().copied());
            assert_eq!(stack.peek(expected.len()), None);
            stored += expected.len();
        }
        // Most of every stack is the previous step's and is not stored again.
        assert!(
            table.words.len < stored / 2,
            "{} of {stored}",
            table.words.len
        );
    }

    #[test]
    fn appending_records_what_pushing_records() {
        let steps = random_steps(300, 4);
        let pushed = StepTable::from(steps.clone());
        let mut appended = StepTable::with_capacity(steps.len());
        let mut previous: Option<&TraceStep> = None;
        for step in &steps {
            let snapshot = &step.snapshot;
            appended.append(
                StepRecord {
                    pc: step.pc,
                    op: opcode::from_spelling(&step.op).expect("known"),
                    gas: step.gas,
                    gas_cost: step.gas_cost,
                    depth: step.depth,
                    error: step.error.clone(),
                    memory: snapshot.memory.clone(),
                    storage: Some(Arc::clone(&snapshot.storage)),
                    storage_diff: Some(snapshot.storage_diff.clone()),
                    transient_storage: Some(snapshot.transient_storage.clone()),
                    return_data: Some(
                        snapshot
                            .return_data
                            .clone()
                            .unwrap_or_else(|| Arc::from("")),
                    ),
                },
                snapshot
                    .stack
                    .iter()
                    .map(|word| EvmWord::parse(word).expect("word")),
            );
            // A step without memory has none, rather than the one before it.
            if snapshot.memory.is_none()
                && previous.is_some_and(|step| step.snapshot.memory.is_some())
            {
                appended
                    .memory
                    .set(appended.len() - 1, super::MemoryRef::NONE);
            }
            previous = Some(step);
        }
        // Only the spellings differ: the table keeps a backend's own.
        for index in 0..steps.len() {
            let (a, b) = (pushed.step(index), appended.step(index));
            assert_eq!(a.op(), b.op());
            assert_eq!(a.stack(), b.stack());
            assert_eq!(a.memory(), b.memory());
            assert_eq!(a.storage(), b.storage());
            assert_eq!(a.storage_diff(), b.storage_diff());
            assert_eq!(a.transient_storage(), b.transient_storage());
            assert_eq!(a.return_data(), b.return_data());
            assert_eq!(
                (a.pc(), a.depth(), a.gas(), a.error()),
                (b.pc(), b.depth(), b.gas(), b.error())
            );
        }
    }

    #[test]
    fn keeps_a_backends_spelling_with_the_byte_it_means() {
        let step =
            |op: &str| TraceStep::new(0, Arc::from(op), 0, 0, 1, None, StepSnapshot::default());
        let table = StepTable::from(vec![
            step("SHA3"),
            step("KECCAK256"),
            step("opcode 0xef not defined"),
            step("NOT AN OPCODE"),
        ]);
        let ops = table
            .iter()
            .map(|step| (step.op(), step.mnemonic()))
            .collect::<Vec<_>>();
        assert_eq!(
            ops,
            [
                (opcode::KECCAK256, "SHA3"),
                (opcode::KECCAK256, "KECCAK256"),
                (0xef, "opcode 0xef not defined"),
                (opcode::INVALID, "NOT AN OPCODE"),
            ]
        );
    }

    #[test]
    fn a_word_that_is_not_hex_is_refused() {
        let mut table = StepTable::new();
        let mut step = TraceStep::new(0, Arc::from("ADD"), 0, 0, 1, None, StepSnapshot::default());
        step.snapshot.stack = vec![Arc::from("0x1"), Arc::from("zz")];
        let error = table.try_push(step).expect_err("not hex");
        assert_eq!(
            error.to_string(),
            "step 0: stack word 1: `z` at offset 0 is not a hex digit"
        );
        assert!(table.is_empty());
    }

    #[test]
    fn truncating_keeps_what_comes_before() {
        let steps = random_steps(3 * STACK_CHECKPOINT, 5);
        let mut table = StepTable::from(steps.clone());
        table.truncate(STACK_CHECKPOINT + 3);
        // Steps appended after a truncation are stored against the step now last.
        table.extend(steps[STACK_CHECKPOINT + 3..].iter().cloned());
        assert_eq!(table, StepTable::from(steps));
        table.truncate(0);
        assert!(table.is_empty() && table.first().is_none());
    }

    #[test]
    fn memory_recorded_write_by_write() {
        let record = |pc| StepRecord {
            pc,
            op: opcode::MSTORE,
            depth: 1,
            ..StepRecord::default()
        };
        let mut table = StepTable::new();
        table.append(record(0), []);
        assert_eq!(table.step(0).memory(), None);
        table.start_memory_frame();
        table.append(record(1), []);
        table.write_memory(0, &[7; 32], 32).expect("write");
        table.append(record(2), []);
        table.start_memory_frame();
        table.append(record(3), []);
        table.end_memory_frame();
        table.write_memory(32, &[], 64).expect("grow");
        table.append(record(4), []);
        let memories = table
            .iter()
            .map(|step| step.memory().map(|memory| memory.to_vec()))
            .collect::<Vec<_>>();
        let mut grown = vec![7; 32];
        grown.resize(64, 0);
        assert_eq!(
            memories,
            [
                None,
                Some(Vec::new()),
                Some(vec![7; 32]),
                Some(Vec::new()),
                Some(grown)
            ]
        );
    }
}
