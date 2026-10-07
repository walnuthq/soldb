//! State variables at a step, read through the compiler's storage layout.
//!
//! `solc --storage-layout` says where every state variable lives; the trace says what
//! the words there held. Putting the two together answers `print counter` or `print
//! balances[0xabc]` without ETHDebug variable information, and does so from
//! compiler-issued fact only: the slot arithmetic is the language's own rule, and the
//! words are what the backend recorded.
//!
//! A backend records a slot at the `SLOAD` or `SSTORE` that touches it, not at every
//! step, so the value at a step is the most recent record for that slot in the same
//! storage context. A trace is a complete recording, so that is a lookup on the tape
//! rather than a guess: [`StorageTape`] indexes every record once, keyed by the account
//! whose storage it belongs to, and a `DELEGATECALL` writes the caller's. A frame that
//! reverted did not keep its writes, so after it a slot holds what it held before the
//! frame — and if that was never read, it is unknown again.
//!
//! A slot with no record yet is unknown here, because the trace does not say what is in
//! it. A frontend that has a node can supply one through [`ChainStorage`], which is read
//! only for slots the trace never recorded, and the value is then marked as coming from
//! the chain rather than from the recording. Without one, unknown is reported as unknown
//! and never as zero: this crate has no chain to ask, and it does not pretend to.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use soldb_core::TransactionTrace;
use soldb_ethdebug::{
    dereference_pointer, parse_word, word_hex, Location, Region, StateValue, StorageLayout,
    StorageMachine, StorageRef, TypeDocument, Word,
};

use crate::stepping::{ContractDebugInfo, StepMap};
use crate::{DebugValue, DebugValueStatus};

/// Where a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateSource {
    /// A word the transaction itself read or wrote.
    Trace,
    /// A word read from the chain, for a slot the transaction never touched.
    Chain,
}

/// A chain a frontend can read storage from, for slots the trace never recorded.
///
/// The debugger never opens a connection; the frontend that has a node implements this
/// and answers, and says in [`ChainStorage::label`] where the answer came from, so the
/// value can be shown as what it is rather than as part of the recording.
pub trait ChainStorage {
    /// The word at `slot` of `address`, or `None` when it could not be read.
    fn word(&self, address: &str, slot: &Word) -> Option<Word>;

    /// Where these words come from, as a user-facing phrase such as
    /// `the chain at block 21000000`.
    fn label(&self) -> &str;

    /// The deployed code of `address`, which holds the values of its immutables, or
    /// `None` when it could not be read. A chain that only answers storage has none.
    fn code(&self, _address: &str) -> Option<Vec<u8>> {
        None
    }
}

/// The reading a frontend supplies: one storage word of one account, or nothing.
pub type ChainRead = Box<dyn Fn(&str, &Word) -> Option<Word>>;

/// The reading a frontend supplies for code: the deployed code of one account, or nothing.
pub type CodeRead = Box<dyn Fn(&str) -> Option<Vec<u8>>>;

/// Deployed code a frontend has without asking a chain, such as what a local deployment
/// returned, by address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownCode(HashMap<String, Vec<u8>>);

impl KnownCode {
    /// Adds the deployed `code` of `address`.
    #[must_use]
    pub fn with(mut self, address: &str, code: Vec<u8>) -> Self {
        self.0.insert(address.to_ascii_lowercase(), code);
        self
    }

    /// The deployed code of `address`, when known.
    #[must_use]
    pub fn get(&self, address: &str) -> Option<&[u8]> {
        self.0.get(&address.to_ascii_lowercase()).map(Vec::as_slice)
    }
}

/// Bytes from the `0x`-prefixed hex a node or a trace gives code as.
#[must_use]
pub fn code_from_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(digits.get(index..index + 2)?, 16).ok())
        .collect()
}

/// A [`ChainStorage`] that reads each slot once, through a function the frontend gives.
///
/// The reading is the frontend's — this crate opens no connections — but the caching and
/// the labelling are the same wherever the words come from, so they live here rather than
/// once per frontend.
pub struct CachedChain<F> {
    read: F,
    label: String,
    words: RefCell<HashMap<(String, Word), Option<Word>>>,
    read_code: Option<CodeRead>,
    codes: RefCell<HashMap<String, Option<Vec<u8>>>>,
}

impl<F> std::fmt::Debug for CachedChain<F> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CachedChain")
            .field("label", &self.label)
            .field("words", &self.words.borrow().len())
            .finish()
    }
}

impl<F> CachedChain<F>
where
    F: Fn(&str, &Word) -> Option<Word>,
{
    /// `label` says where the words come from, as a user-facing phrase such as
    /// `the chain at block 21000000`.
    pub fn new(label: impl Into<String>, read: F) -> Self {
        Self {
            read,
            label: label.into(),
            words: RefCell::new(HashMap::new()),
            read_code: None,
            codes: RefCell::new(HashMap::new()),
        }
    }

    /// Reads the deployed code of an account through `read_code`, once per account.
    #[must_use]
    pub fn with_code(mut self, read_code: CodeRead) -> Self {
        self.read_code = Some(read_code);
        self
    }
}

impl<F> ChainStorage for CachedChain<F>
where
    F: Fn(&str, &Word) -> Option<Word>,
{
    fn word(&self, address: &str, slot: &Word) -> Option<Word> {
        let key = (address.to_ascii_lowercase(), *slot);
        if let Some(cached) = self.words.borrow().get(&key) {
            return *cached;
        }
        let word = (self.read)(&key.0, slot);
        self.words.borrow_mut().insert(key, word);
        word
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn code(&self, address: &str) -> Option<Vec<u8>> {
        let read_code = self.read_code.as_ref()?;
        let key = address.to_ascii_lowercase();
        if let Some(cached) = self.codes.borrow().get(&key) {
            return cached.clone();
        }
        let code = read_code(&key);
        self.codes.borrow_mut().insert(key, code.clone());
        code
    }
}

/// One state variable, or one place inside one, with its value at a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateVariable {
    /// The path as resolved, such as `counter` or `balances[0xabc]`.
    pub name: String,
    /// The Solidity type as the layout labels it.
    pub ty: String,
    /// The slot, as `0x`-prefixed hex without leading zeros. For a value in the code,
    /// the offset of its bytes in the code.
    pub slot: String,
    /// The byte offset within the slot.
    pub offset: u64,
    /// Whether the value is in the deployed code, as an immutable's is, rather than in
    /// storage.
    pub in_code: bool,
    pub value: DebugValue,
    /// Whether the value came from the recording or from the chain.
    pub source: StateSource,
}

/// Every storage word a trace recorded, by storage context and slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageTape {
    records: HashMap<(usize, Word), Vec<Record>>,
    /// Whether the backend recorded per-step storage at all.
    captured: bool,
}

/// A value a slot holds from a step on. `None` when a reverted frame undid a write and
/// the value before it was never recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record {
    from: usize,
    value: Option<Word>,
    /// True for a record a revert makes. At one step a read is the later word: the
    /// reverting frame's last step and the caller's next are the same index.
    rollback: bool,
}

/// What the tape knows about one slot at one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lookup {
    Known(Word),
    /// Nothing has read or written the slot by this step.
    Untouched,
    /// The last write was reverted and the value before it was never read.
    Reverted,
}

impl StorageTape {
    /// Indexes every storage word `trace` recorded, in the storage context `map`
    /// computed for the step that recorded it.
    #[must_use]
    pub fn new(trace: &TransactionTrace, map: &StepMap) -> Self {
        let mut records = HashMap::<(usize, Word), Vec<Record>>::new();
        for (index, step) in trace.steps.iter().enumerate() {
            let snapshot = step.snapshot_ref();
            if snapshot.storage_diff.is_empty() {
                continue;
            }
            let Some(context) = map.storage_context_index(index) else {
                continue;
            };
            // A write takes effect after its step; a read reports what is there at it.
            let from = if &*step.op == "SSTORE" {
                index + 1
            } else {
                index
            };
            for (slot, change) in snapshot.storage_diff {
                let Some(after) = change.after.as_deref() else {
                    continue;
                };
                let (Some(slot), Some(value)) = (parse_slot(slot), parse_slot(after)) else {
                    continue;
                };
                let entries = records.entry((context, slot)).or_default();
                if entries.last().is_some_and(|last| last.value == Some(value)) {
                    continue;
                }
                entries.push(Record {
                    from,
                    value: Some(value),
                    rollback: false,
                });
            }
        }

        // A frame that reverted kept none of the writes made while it ran, its callees'
        // included; every slot it touched goes back to what it held when it was entered.
        for (entry, last) in map.reverted_spans() {
            for entries in records.values_mut() {
                let touched = entries
                    .iter()
                    .any(|record| record.from > *entry && record.from <= last + 1);
                if !touched {
                    continue;
                }
                let before = entries
                    .iter()
                    .filter(|record| record.from <= *entry)
                    .max_by_key(|record| (record.from, !record.rollback))
                    .and_then(|record| record.value);
                entries.push(Record {
                    from: last + 1,
                    value: before,
                    rollback: true,
                });
            }
        }
        for entries in records.values_mut() {
            entries.sort_by_key(|record| (record.from, !record.rollback));
        }
        Self {
            records,
            captured: trace.capabilities.storage,
        }
    }

    /// The words known at `step`, in storage context `context`.
    #[must_use]
    pub fn at(&self, step: usize, context: Option<usize>) -> StorageWords<'_> {
        StorageWords {
            tape: self,
            step,
            context,
            address: None,
            chain: None,
            known_code: None,
        }
    }

    /// The words known at `step`, in the storage context that step runs in, with the
    /// address of that context so a [`ChainStorage`] can be asked about its slots.
    #[must_use]
    pub fn at_step<'a>(&'a self, map: &'a StepMap, step: usize) -> StorageWords<'a> {
        StorageWords {
            tape: self,
            step,
            context: map.storage_context_index(step),
            address: map.storage_address(step),
            chain: None,
            known_code: None,
        }
    }

    fn lookup(&self, context: usize, slot: &Word, step: usize) -> Lookup {
        let Some(entries) = self.records.get(&(context, *slot)) else {
            return Lookup::Untouched;
        };
        let count = entries.partition_point(|record| record.from <= step);
        match count.checked_sub(1).map(|index| entries[index].value) {
            Some(Some(value)) => Lookup::Known(value),
            Some(None) => Lookup::Reverted,
            None => Lookup::Untouched,
        }
    }
}

/// The storage words known at one step, in one storage context.
#[derive(Clone, Copy)]
pub struct StorageWords<'a> {
    tape: &'a StorageTape,
    step: usize,
    context: Option<usize>,
    /// The account whose storage this is, for reading from a chain.
    address: Option<&'a str>,
    chain: Option<&'a dyn ChainStorage>,
    /// Deployed code the frontend has without a chain.
    known_code: Option<&'a KnownCode>,
}

impl<'a> StorageWords<'a> {
    /// Reads slots the trace never recorded from `chain`.
    #[must_use]
    pub fn with_chain(mut self, chain: Option<&'a dyn ChainStorage>) -> Self {
        self.chain = chain;
        self
    }

    /// Takes deployed code from `known_code` before asking the chain.
    #[must_use]
    pub fn with_known_code(mut self, known_code: Option<&'a KnownCode>) -> Self {
        self.known_code = known_code;
        self
    }

    /// The deployed code of `address`, or of the account whose storage this is: from the
    /// code the frontend has, otherwise from the chain.
    #[must_use]
    pub fn code(&self, address: Option<&str>) -> Option<Vec<u8>> {
        let address = address.or(self.address)?;
        if let Some(code) = self.known_code.and_then(|known| known.get(address)) {
            return Some(code.to_vec());
        }
        self.chain?.code(address)
    }

    /// The word at `slot`, when the trace recorded one that still holds.
    #[must_use]
    pub fn get(&self, slot: &Word) -> Option<Word> {
        match self.tape.lookup(self.context?, slot, self.step) {
            Lookup::Known(value) => Some(value),
            Lookup::Untouched | Lookup::Reverted => None,
        }
    }

    /// The word at `slot` from the chain, for a slot the trace did not record.
    #[must_use]
    pub(crate) fn chain_word(&self, slot: &Word) -> Option<Word> {
        self.chain?.word(self.address?, slot)
    }

    /// How a chain-read value should be described, when a chain is attached.
    #[must_use]
    pub fn chain_label(&self) -> Option<&str> {
        Some(self.chain?.label())
    }

    /// Every slot with a known value at the step, in slot order.
    #[must_use]
    pub fn known(&self) -> Vec<(Word, Word)> {
        let Some(context) = self.context else {
            return Vec::new();
        };
        let mut known = self
            .tape
            .records
            .keys()
            .filter(|(candidate, _)| *candidate == context)
            .filter_map(
                |(_, slot)| match self.tape.lookup(context, slot, self.step) {
                    Lookup::Known(value) => Some((*slot, value)),
                    Lookup::Untouched | Lookup::Reverted => None,
                },
            )
            .collect::<Vec<_>>();
        known.sort_unstable();
        known
    }

    /// Whether the backend recorded storage at all.
    #[must_use]
    pub fn captured(&self) -> bool {
        self.tape.captured
    }

    /// Why a word is missing, for the user.
    pub(crate) fn unavailable(&self, slot: &Word) -> String {
        let unread = if self.chain.is_some() {
            format!(
                "<unknown: slot {} was not touched by this transaction and the chain could not be read>",
                short_hex(slot)
            )
        } else {
            format!(
                "<unknown: slot {} has not been read or written yet>",
                short_hex(slot)
            )
        };
        if !self.tape.captured {
            return "<unavailable: this backend recorded no storage>".to_owned();
        }
        let Some(context) = self.context else {
            return "<unavailable: the storage of this frame belongs to no known account>"
                .to_owned();
        };
        match self.tape.lookup(context, slot, self.step) {
            Lookup::Reverted => format!(
                "<unknown: the write to slot {} was reverted and the value before it was never read>",
                short_hex(slot)
            ),
            // `Known` cannot reach here: a decode only fails on a slot with no word.
            Lookup::Known(_) | Lookup::Untouched => unread,
        }
    }
}

/// Every state variable in the layout, with its value at the step.
#[must_use]
pub fn state_variables(layout: &StorageLayout, words: &StorageWords<'_>) -> Vec<StateVariable> {
    layout
        .variables
        .iter()
        .map(|variable| {
            let reference = StorageRef {
                path: variable.label.clone(),
                slot: variable.slot,
                offset: variable.offset,
                type_id: variable.type_id.clone(),
            };
            read(layout, words, &reference)
        })
        .collect()
}

/// Every state variable the program-level context of `contract`'s program lists, read
/// through the pointer the compiler gave it instead of through the storage layout, in the
/// compiler's order. `None` when the program lists none or the contract has no resource
/// tables, for a compiler that does not emit them yet: the frontend then falls back to the
/// storage layout.
///
/// Values are shown the way [`state_variables`] shows them: a struct with its members and
/// a static array with its elements, from the regions the pointer names, a dynamic array
/// by its length, and a mapping, which has no value of its own, as needing a key. A path
/// such as `balances[0xabc]` still goes through the layout. When the contract has a
/// layout, its spelling of a variable's type is used, which qualifies a user-defined type
/// by the contract defining it. An immutable is read from the deployed code, which the
/// frontend supplies through [`StorageWords::with_known_code`] or its chain; without it,
/// the immutable is reported as unavailable.
#[must_use]
pub fn context_state_variables(
    contract: &ContractDebugInfo,
    words: &StorageWords<'_>,
) -> Option<Vec<StateVariable>> {
    let resources = contract.resources.as_ref()?;
    if contract.info.state_variables.is_empty() {
        return None;
    }
    let from_chain = Cell::new(false);
    // The first slot a variable needed and nobody knew, which says why it is unknown the
    // same way the storage layout's view does.
    let missing = Cell::new(None);
    let read_storage = |slot: &Word| {
        if let Some(word) = words.get(slot) {
            return Some(word);
        }
        let Some(word) = words.chain_word(slot) else {
            if missing.get().is_none() {
                missing.set(Some(*slot));
            }
            return None;
        };
        from_chain.set(true);
        Some(word)
    };
    // Immutables live in the deployed code of the contract running, which is only asked
    // for when there are any.
    let in_code = contract.info.state_variables.iter().any(|variable| {
        variable
            .pointer
            .as_ref()
            .and_then(|pointer| pointer.get("location"))
            .and_then(serde_json::Value::as_str)
            == Some("code")
    });
    let code = if in_code {
        words.code(contract.address.as_deref())
    } else {
        None
    };
    let machine = StorageMachine {
        storage: &read_storage,
        transient: None,
        code: code.as_deref(),
    };
    let variables = contract
        .info
        .state_variables
        .iter()
        .map(|variable| {
            from_chain.set(false);
            missing.set(None);
            let name = variable.name();
            let ty = variable.type_reference().ok().flatten();
            let pointer = variable.parsed_pointer().ok().flatten();
            let layout_label = contract.storage_layout.as_ref().and_then(|layout| {
                let variable = layout
                    .variables
                    .iter()
                    .find(|variable| variable.label == name)?;
                Some(layout.type_of(&variable.type_id)?.label.clone())
            });
            let label = layout_label.unwrap_or_else(|| {
                ty.as_ref()
                    .map_or_else(|| "<unknown type>".to_owned(), |ty| resources.label(ty))
            });
            let first_region = pointer.as_ref().and_then(|pointer| {
                dereference_pointer(pointer, &resources.pointers, &machine)
                    .ok()?
                    .into_iter()
                    .next()
            });
            let (slot, offset, in_code) = first_region
                .as_ref()
                .map_or_else(|| ("-".to_owned(), 0, false), place);
            let value = match (ty, pointer) {
                (Some(ty), Some(pointer)) => match resources.read_variable(&ty, &pointer, &machine)
                {
                    Ok(values) => composed(&values, resources.resolve(&ty).ok()),
                    Err(error) => DebugValue {
                        display: missing
                            .get()
                            .map_or_else(|| format!("<{error}>"), |slot| words.unavailable(&slot)),
                        raw: None,
                        status: DebugValueStatus::Unavailable,
                    },
                },
                _ => DebugValue {
                    display: "<the compiler gave no type or pointer for it>".to_owned(),
                    raw: None,
                    status: DebugValueStatus::Unavailable,
                },
            };
            // A value no word could be found for says why, as the storage layout's view does.
            let value = match missing.get() {
                Some(slot) if value.status == DebugValueStatus::Unavailable => DebugValue {
                    display: words.unavailable(&slot),
                    ..value
                },
                _ => value,
            };
            StateVariable {
                name,
                ty: label,
                slot,
                offset,
                in_code,
                value,
                source: if from_chain.get() {
                    StateSource::Chain
                } else {
                    StateSource::Trace
                },
            }
        })
        .collect();
    Some(variables)
}

/// Where a region starts, as the storage layout says it: the slot, and the offset from
/// the least significant byte, while a region counts it from the most significant one. A
/// region of the code is placed by its offset in the code.
fn place(region: &Region) -> (String, u64, bool) {
    match (region.location, region.slot) {
        (Location::Storage | Location::Transient, Some(slot)) => {
            let layout_offset = if region.length < 32 {
                32_u64.saturating_sub(region.offset + region.length)
            } else {
                0
            };
            let slot = short_hex(&slot);
            if region.location == Location::Transient {
                (format!("{slot} (transient)"), layout_offset, false)
            } else {
                (slot, layout_offset, false)
            }
        }
        (Location::Code, _) => (format!("{:#x}", region.offset), 0, true),
        (location, _) => (format!("{location} {:#x}", region.offset), 0, false),
    }
}

/// A part of a value under construction from the regions of its pointer.
enum Part {
    Value(String),
    Members(Vec<(String, Part)>),
    Elements(Vec<Part>),
}

impl Part {
    /// Whether the part already holds a value at `path`, so that the next value for that
    /// path belongs to a new array element.
    fn holds(&self, path: &[&str]) -> bool {
        match (self, path.split_first()) {
            (_, None) => true,
            (Self::Members(members), Some((member, rest))) => members
                .iter()
                .find(|(name, _)| name == member)
                .is_some_and(|(_, part)| part.holds(rest)),
            (Self::Elements(elements), Some((&"item", rest))) => {
                elements.last().is_some_and(|element| element.holds(rest))
            }
            _ => false,
        }
    }

    fn insert(&mut self, path: &[&str], display: String) {
        let Some((first, rest)) = path.split_first() else {
            *self = Self::Value(display);
            return;
        };
        if *first == "item" {
            if !matches!(self, Self::Elements(_)) {
                *self = Self::Elements(Vec::new());
            }
            let Self::Elements(elements) = self else {
                unreachable!()
            };
            if elements.last().is_none_or(|element| element.holds(rest)) {
                elements.push(Self::Members(Vec::new()));
            }
            if let Some(element) = elements.last_mut() {
                element.insert(rest, display);
            }
            return;
        }
        if !matches!(self, Self::Members(_)) {
            *self = Self::Members(Vec::new());
        }
        let Self::Members(members) = self else {
            unreachable!()
        };
        if let Some((_, part)) = members.iter_mut().find(|(name, _)| name == first) {
            part.insert(rest, display);
        } else {
            let mut part = Self::Members(Vec::new());
            part.insert(rest, display);
            members.push(((*first).to_owned(), part));
        }
    }

    fn render(&self) -> String {
        match self {
            Self::Value(display) => display.clone(),
            Self::Members(members) => format!(
                "{{ {} }}",
                members
                    .iter()
                    .map(|(name, part)| format!("{name}: {}", part.render()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Elements(elements) => format!(
                "[{}]",
                elements
                    .iter()
                    .map(Self::render)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// One value from the regions a variable's pointer names, which `read_variable` names
/// relative to the variable: `x` is a struct member, `item` an array element and
/// `from-x` a member of a member. `document` is the variable's type: a dynamic array is
/// shown by its length rather than its elements.
fn composed(values: &[StateValue], document: Option<&TypeDocument>) -> DebugValue {
    let mut root = Part::Members(Vec::new());
    for value in values {
        let path = value
            .name
            .split('-')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        root.insert(&path, value.display.clone());
    }
    let dynamic_array = matches!(document, Some(TypeDocument::Array { count: None, .. }));
    let available = dynamic_array || values.iter().any(|value| value.available);
    let display = match (&root, dynamic_array) {
        (Part::Elements(elements), true) => {
            format!("<{} element(s); index it with [i]>", elements.len())
        }
        (Part::Members(members), true) if members.is_empty() => {
            "<0 element(s); index it with [i]>".to_owned()
        }
        (Part::Members(members), false) if members.is_empty() => "<no regions>".to_owned(),
        _ => root.render(),
    };
    DebugValue {
        display,
        raw: None,
        status: if available {
            DebugValueStatus::Decoded
        } else {
            DebugValueStatus::Unavailable
        },
    }
}

/// The value at a storage path such as `owner`, `balances[0xabc]`, `items[2]`, or
/// `config.limit`. `Err` says why the path does not name a place in storage.
pub fn state_value(
    layout: &StorageLayout,
    words: &StorageWords<'_>,
    path: &str,
) -> Result<StateVariable, String> {
    let reference = layout.resolve(path).map_err(|error| error.to_string())?;
    Ok(read(layout, words, &reference))
}

fn read(layout: &StorageLayout, words: &StorageWords<'_>, reference: &StorageRef) -> StateVariable {
    let ty = layout
        .type_of(&reference.type_id)
        .map_or_else(|| reference.type_id.clone(), |ty| ty.label.clone());
    // The recording first; the chain only for a slot it never mentioned, and the value is
    // marked as coming from there.
    let from_chain = Cell::new(false);
    let decoded = layout.decode(reference, &|slot| {
        if let Some(word) = words.get(slot) {
            return Some(word);
        }
        let word = words.chain_word(slot)?;
        from_chain.set(true);
        Some(word)
    });
    let value = match decoded {
        Ok(decoded) => DebugValue {
            display: decoded.display,
            raw: decoded.raw,
            status: DebugValueStatus::Decoded,
        },
        Err(missing) => DebugValue {
            display: words.unavailable(&missing),
            raw: None,
            status: DebugValueStatus::Unavailable,
        },
    };
    StateVariable {
        name: reference.path.clone(),
        ty,
        slot: short_hex(&reference.slot),
        offset: reference.offset,
        in_code: false,
        value,
        source: if from_chain.get() {
            StateSource::Chain
        } else {
            StateSource::Trace
        },
    }
}

/// A recorded slot or word, however the backend spelled it: with or without `0x`, padded
/// to 64 digits or not.
fn parse_slot(text: &str) -> Option<Word> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if digits.is_empty() {
        return Some([0_u8; 32]);
    }
    parse_word(&format!("0x{digits}")).ok()
}

/// `0x`-prefixed hex without leading zeros; `0x0` for zero.
#[must_use]
pub fn short_hex(word: &Word) -> String {
    let full = word_hex(word);
    let trimmed = full[2..].trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use soldb_core::{StepSnapshot, StorageChange, TraceCapabilities, TraceStep, TransactionTrace};
    use soldb_ethdebug::StorageLayout;

    use soldb_ethdebug::{EthdebugInfo, Resources};

    use super::{
        code_from_hex, context_state_variables, short_hex, state_value, state_variables, KnownCode,
        StorageTape, Word,
    };
    use crate::stepping::{ContractDebugInfo, StepMap};
    use crate::DebugValueStatus;

    const RESOURCES: &str =
        include_str!("../../../test/fixtures/ethdebug-resources/ethdebug_resources.json");
    const PROGRAM: &str =
        include_str!("../../../test/fixtures/ethdebug-resources/Resources_ethdebug-runtime.json");

    /// The fixture's `Resources` contract, with the program-level context solc gives it and
    /// the tables of its resources.
    fn context_contract() -> ContractDebugInfo {
        let resources: serde_json::Value = serde_json::from_str(RESOURCES).expect("resources");
        let program: serde_json::Value = serde_json::from_str(PROGRAM).expect("program");
        let info =
            EthdebugInfo::from_artifacts("Resources", "call", &resources, &program).expect("info");
        ContractDebugInfo::new(None, "Resources", info, BTreeMap::new())
            .with_resources(Some(Resources::parse(&resources).expect("tables")))
    }

    /// The slot of `balances[0xf39f…]`, as the layout resolves it.
    fn mapping_entry_slot() -> Word {
        layout()
            .resolve("balances[0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266]")
            .expect("entry")
            .slot
    }

    fn layout() -> StorageLayout {
        StorageLayout::parse(&json!({
            "storage": [
                {"astId": 1, "contract": "T.sol:T", "label": "counter", "offset": 0, "slot": "0", "type": "t_uint256"},
                {"astId": 2, "contract": "T.sol:T", "label": "balances", "offset": 0, "slot": "1", "type": "t_mapping(t_address,t_uint256)"}
            ],
            "types": {
                "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
                "t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"},
                "t_mapping(t_address,t_uint256)": {"encoding": "mapping", "key": "t_address", "label": "mapping(address => uint256)", "numberOfBytes": "32", "value": "t_uint256"}
            }
        }))
        .expect("layout")
    }

    /// One step, recording the slots it touched the way a backend does: at the `SLOAD` or
    /// `SSTORE` itself, not cumulatively.
    fn step(op: &str, depth: u64, stack: &[&str], touched: &[(&str, &str)]) -> TraceStep {
        let storage = touched
            .iter()
            .map(|(slot, value)| ((*slot).to_owned(), (*value).to_owned()))
            .collect::<BTreeMap<_, _>>();
        let storage_diff = touched
            .iter()
            .map(|(slot, value)| {
                (
                    (*slot).to_owned(),
                    StorageChange {
                        before: None,
                        after: Some((*value).to_owned()),
                    },
                )
            })
            .collect();
        TraceStep {
            pc: 0,
            op: op.into(),
            gas: 0,
            gas_cost: 0,
            depth,
            stack: Vec::new(),
            memory: None,
            storage: None,
            error: None,
            snapshot: StepSnapshot::new(
                stack
                    .iter()
                    .map(|word| soldb_core::Word::from(*word))
                    .collect(),
                None,
                storage,
                storage_diff,
            ),
        }
    }

    fn trace(steps: Vec<TraceStep>, captured: bool) -> TransactionTrace {
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
            capabilities: TraceCapabilities {
                storage: captured,
                ..Default::default()
            },
            artifacts: Default::default(),
            steps,
        }
    }

    fn show(trace: &TransactionTrace, at: usize, path: &str) -> String {
        let map = StepMap::new(trace, Vec::new());
        let tape = StorageTape::new(trace, &map);
        state_value(&layout(), &tape.at_step(&map, at), path)
            .expect(path)
            .value
            .display
    }

    #[test]
    fn state_is_read_through_the_program_context() {
        // Where solc puts the fixture's variables: `total` at slot 1, `small` and `flag`
        // packed into slot 2 from its least significant byte, `origin` at slot 5 and the
        // length of `values` at slot 7.
        let trace = trace(
            vec![
                step("SLOAD", 1, &[], &[("0x1", "0x7")]),
                step("SLOAD", 1, &[], &[("0x2", "0x0109")]),
                step("SLOAD", 1, &[], &[("0x5", "0x0201")]),
                step("SLOAD", 1, &[], &[("0x7", "0x2")]),
                step("STOP", 1, &[], &[]),
            ],
            true,
        );
        let map = StepMap::new(&trace, Vec::new());
        let tape = StorageTape::new(&trace, &map);
        let words = tape.at_step(&map, 4);
        let contract = context_contract();
        let variables = context_state_variables(&contract, &words).expect("context");
        let variable = |name: &str| {
            variables
                .iter()
                .find(|variable| variable.name == name)
                .unwrap_or_else(|| panic!("{name}"))
        };
        assert_eq!(
            (
                variable("total").value.display.as_str(),
                variable("total").ty.as_str()
            ),
            ("7", "uint256")
        );
        let small = variable("small");
        assert_eq!(
            (
                small.value.display.as_str(),
                small.slot.as_str(),
                small.offset
            ),
            ("9", "0x2", 0)
        );
        let flag = variable("flag");
        assert_eq!((flag.value.display.as_str(), flag.offset), ("true", 1));
        // Shown the way the storage layout shows them.
        assert_eq!(variable("origin").value.display, "{ x: 1, y: 2 }");
        assert_eq!(
            variable("values").value.display,
            "<2 element(s); index it with [i]>"
        );
        assert_eq!(
            variable("balances").value.display,
            "<mapping; index it with [key]>"
        );
        // A mapping needs a key, a slot the trace never touched is unknown rather than
        // zero, and an immutable lives in the code, which this view does not have.
        for (name, reason) in [
            ("balances", "key"),
            ("inherited", "slot"),
            ("createdAt", "code"),
        ] {
            let value = &variable(name).value;
            assert_eq!(value.status, DebugValueStatus::Unavailable, "{name}");
            assert!(value.display.contains(reason), "{name}: {}", value.display);
        }

        // Without resource tables, the frontend falls back to the storage layout.
        let without_tables =
            ContractDebugInfo::new(None, "Resources", contract.info.clone(), BTreeMap::new());
        assert!(context_state_variables(&without_tables, &words).is_none());

        // With the deployed code of the account running, the immutable is read from the
        // copy of its value the code holds.
        let pointer = contract
            .info
            .state_variables
            .iter()
            .find(|variable| variable.identifier.as_deref() == Some("createdAt"))
            .and_then(|variable| variable.pointer.clone())
            .expect("createdAt pointer");
        let offset = usize::from_str_radix(
            pointer["offset"]
                .as_str()
                .expect("offset")
                .trim_start_matches("0x"),
            16,
        )
        .expect("offset");
        let mut code = vec![0_u8; offset + 64];
        code[offset + 30] = 0x04;
        code[offset + 31] = 0xd2;
        let known = KnownCode::default().with("0xAAaa000000000000000000000000000000000001", code);
        let words = words.with_known_code(Some(&known));
        let variables = context_state_variables(&contract, &words).expect("context");
        let created_at = variables
            .iter()
            .find(|variable| variable.name == "createdAt")
            .expect("createdAt");
        assert_eq!(created_at.value.display, "1234");
        assert!(created_at.in_code);
        assert_eq!(created_at.slot, format!("{offset:#x}"));
    }

    #[test]
    fn code_is_read_from_hex() {
        assert_eq!(
            code_from_hex("0x60016000"),
            Some(vec![0x60, 0x01, 0x60, 0x00])
        );
        assert_eq!(code_from_hex("0x"), Some(Vec::new()));
        assert_eq!(code_from_hex("0x6"), None);
        assert_eq!(code_from_hex("0xzz"), None);
    }

    #[test]
    fn a_slot_holds_its_last_recorded_word_until_the_next_write() {
        let padded = format!("{:0>64}", "7");
        let trace = trace(
            vec![
                step("PUSH1", 1, &[], &[]),
                step("SLOAD", 1, &[], &[(&padded, &format!("{:0>64}", "3"))]),
                step("SLOAD", 1, &[], &[("0x0", "0x2a")]),
                step("ADD", 1, &[], &[]),
                step("SSTORE", 1, &[], &[("0x0", "0x2b")]),
                step("POP", 1, &[], &[]),
                step("STOP", 1, &[], &[]),
            ],
            true,
        );
        assert!(show(&trace, 0, "counter").contains("has not been read or written yet"));
        assert!(show(&trace, 1, "counter").contains("has not been read or written yet"));
        assert_eq!(show(&trace, 2, "counter"), "42");
        assert_eq!(show(&trace, 3, "counter"), "42");
        // The write takes effect after the SSTORE step, not at it.
        assert_eq!(show(&trace, 4, "counter"), "42");
        assert_eq!(show(&trace, 5, "counter"), "43");
        assert_eq!(show(&trace, 6, "counter"), "43");

        let map = StepMap::new(&trace, Vec::new());
        let tape = StorageTape::new(&trace, &map);
        let words = tape.at_step(&map, 6);
        let variables = state_variables(&layout(), &words);
        assert_eq!(variables.len(), 2);
        assert_eq!(
            (
                variables[0].name.as_str(),
                variables[0].ty.as_str(),
                variables[0].slot.as_str()
            ),
            ("counter", "uint256", "0x0")
        );
        assert_eq!(variables[0].value.status, DebugValueStatus::Decoded);
        assert_eq!(
            variables[0].value.raw.as_deref(),
            Some(&format!("0x{:0>64}", "2b")[..])
        );
        assert_eq!(variables[1].value.display, "<mapping; index it with [key]>");
        assert_eq!(variables[1].ty, "mapping(address => uint256)");
        // Slots the trace recorded, however they were spelled, in slot order.
        let known = words.known();
        assert_eq!(known.len(), 2);
        assert_eq!(short_hex(&known[0].1), "0x2b");
        assert_eq!(short_hex(&known[1].0), "0x7");

        let entry = state_value(
            &layout(),
            &words,
            "balances[0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266]",
        )
        .expect("entry");
        assert_eq!(entry.ty, "uint256");
        assert_eq!(entry.value.status, DebugValueStatus::Unavailable);
        let error = state_value(&layout(), &words, "nothing").expect_err("unknown variable");
        assert!(
            error.contains("no state variable named `nothing`"),
            "{error}"
        );
    }

    #[test]
    fn a_reverted_call_keeps_none_of_its_writes() {
        let callee = "0xbbbb000000000000000000000000000000000002";
        let trace = trace(
            vec![
                step("SLOAD", 1, &[], &[("0x0", "0x5")]),
                step(
                    "CALL",
                    1,
                    &["0x0", "0x0", "0x0", "0x0", "0x0", callee, "0x0"],
                    &[],
                ),
                // The callee writes its own storage, then reverts.
                step("SSTORE", 2, &[], &[("0x0", "0x9")]),
                step("POP", 2, &[], &[]),
                step("REVERT", 2, &[], &[]),
                step("POP", 1, &[], &[]),
                step(
                    "DELEGATECALL",
                    1,
                    &["0x0", "0x0", "0x0", "0x0", callee, "0x0"],
                    &[],
                ),
                // A delegate call writes the caller's storage, and commits.
                step("SSTORE", 2, &[], &[("0x0", "0x6")]),
                step("RETURN", 2, &[], &[]),
                step("STOP", 1, &[], &[]),
            ],
            true,
        );
        let map = StepMap::new(&trace, Vec::new());
        let tape = StorageTape::new(&trace, &map);
        let caller = map.storage_context_index(0).expect("root context");
        let callee_context = map.storage_context_index(2).expect("callee context");
        assert_ne!(caller, callee_context);
        // The frame is entered at its first step, not at the caller's `CALL`.
        assert_eq!(map.reverted_spans(), [(2, 4)]);

        // Inside the callee its write holds; after the revert the slot is unknown again,
        // because nothing read it before the write.
        assert_eq!(show(&trace, 3, "counter"), "9");
        let after = tape.at(5, Some(callee_context));
        assert!(after.get(&[0_u8; 32]).is_none());
        assert!(state_value(&layout(), &after, "counter")
            .expect("counter")
            .value
            .display
            .contains("was reverted"));
        // The caller's own slot was never touched by the reverted frame.
        assert_eq!(show(&trace, 5, "counter"), "5");
        // The delegate call runs against the caller's storage, and its write survives.
        assert_eq!(map.storage_context_index(7), Some(caller));
        assert_eq!(show(&trace, 7, "counter"), "5");
        assert_eq!(show(&trace, 8, "counter"), "6");
        assert_eq!(show(&trace, 9, "counter"), "6");
    }

    /// A chain a frontend would read through a node, answering from a fixed table.
    struct FakeChain {
        words: BTreeMap<(String, Word), Word>,
        label: String,
    }

    impl super::ChainStorage for FakeChain {
        fn word(&self, address: &str, slot: &Word) -> Option<Word> {
            self.words
                .get(&(address.to_ascii_lowercase(), *slot))
                .copied()
        }

        fn label(&self) -> &str {
            &self.label
        }
    }

    #[test]
    fn a_slot_the_trace_never_touched_can_come_from_the_chain() {
        let trace = trace(
            vec![
                step("SLOAD", 1, &[], &[]),
                step("SSTORE", 1, &[], &[("0x0", "0x2a")]),
                step("STOP", 1, &[], &[]),
            ],
            true,
        );
        let map = StepMap::new(&trace, Vec::new());
        let tape = StorageTape::new(&trace, &map);
        let address = map.storage_address(0).expect("address").to_owned();
        let entry_slot = mapping_entry_slot();
        let chain = FakeChain {
            words: BTreeMap::from([
                // `counter` before the transaction, and one mapping entry.
                ((address.clone(), [0_u8; 32]), {
                    let mut word = [0_u8; 32];
                    word[31] = 9;
                    word
                }),
                ((address.clone(), entry_slot), {
                    let mut word = [0_u8; 32];
                    word[31] = 4;
                    word
                }),
            ]),
            label: "the chain at block 7".to_owned(),
        };
        let layout = layout();
        let words = tape.at_step(&map, 0).with_chain(Some(&chain));
        assert_eq!(words.chain_label(), Some("the chain at block 7"));

        // Before the transaction writes it, the slot reads from the chain and says so.
        let counter = state_value(&layout, &words, "counter").expect("counter");
        assert_eq!(counter.value.display, "9");
        assert_eq!(counter.source, super::StateSource::Chain);
        assert_eq!(counter.value.status, DebugValueStatus::Decoded);

        // A mapping entry the transaction never touched, read by key.
        let entry = state_value(
            &layout,
            &words,
            "balances[0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266]",
        )
        .expect("entry");
        assert_eq!(entry.value.display, "4");
        assert_eq!(entry.source, super::StateSource::Chain);

        // After the transaction writes it, the recording wins over the chain.
        let words = tape.at_step(&map, 2).with_chain(Some(&chain));
        let counter = state_value(&layout, &words, "counter").expect("counter");
        assert_eq!(counter.value.display, "42");
        assert_eq!(counter.source, super::StateSource::Trace);

        // A slot the chain cannot answer for stays unknown, and says the chain was asked.
        let empty = FakeChain {
            words: BTreeMap::new(),
            label: "the chain at block 7".to_owned(),
        };
        let words = tape.at_step(&map, 0).with_chain(Some(&empty));
        let counter = state_value(&layout, &words, "counter").expect("counter");
        assert_eq!(counter.source, super::StateSource::Trace);
        assert!(
            counter
                .value
                .display
                .contains("the chain could not be read"),
            "{}",
            counter.value.display
        );
    }

    #[test]
    fn a_cached_chain_reads_each_slot_once() {
        use std::cell::Cell;

        let reads = Cell::new(0_u32);
        let chain =
            super::CachedChain::new("the chain at block 7", |_address: &str, slot: &Word| {
                reads.set(reads.get() + 1);
                (slot[31] == 1).then(|| {
                    let mut word = [0_u8; 32];
                    word[31] = 9;
                    word
                })
            });
        let mut slot = [0_u8; 32];
        slot[31] = 1;
        assert_eq!(super::ChainStorage::label(&chain), "the chain at block 7");
        assert!(super::ChainStorage::word(&chain, "0xAA", &slot).is_some());
        // The same slot, and the same account however it is spelled, is not read again.
        assert!(super::ChainStorage::word(&chain, "0xaa", &slot).is_some());
        assert_eq!(reads.get(), 1);
        // A slot the chain has no answer for is remembered as unanswered, not retried.
        let missing = [0_u8; 32];
        assert!(super::ChainStorage::word(&chain, "0xaa", &missing).is_none());
        assert!(super::ChainStorage::word(&chain, "0xaa", &missing).is_none());
        assert_eq!(reads.get(), 2);
        // Without a code reader the chain has no code.
        assert!(super::ChainStorage::code(&chain, "0xaa").is_none());
    }

    #[test]
    fn a_cached_chain_reads_each_account_code_once() {
        use std::rc::Rc;

        let reads = Rc::new(std::cell::Cell::new(0_u32));
        let counted = Rc::clone(&reads);
        let chain = super::CachedChain::new("the chain at block 7", |_: &str, _: &Word| None)
            .with_code(Box::new(move |address: &str| {
                counted.set(counted.get() + 1);
                (address == "0xaa").then(|| vec![0x60, 0x00])
            }));
        assert_eq!(
            super::ChainStorage::code(&chain, "0xAA"),
            Some(vec![0x60, 0x00])
        );
        assert_eq!(
            super::ChainStorage::code(&chain, "0xaa"),
            Some(vec![0x60, 0x00])
        );
        assert!(super::ChainStorage::code(&chain, "0xbb").is_none());
        assert!(super::ChainStorage::code(&chain, "0xbb").is_none());
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn says_when_the_backend_recorded_no_storage() {
        let trace = trace(vec![step("STOP", 1, &[], &[])], false);
        let map = StepMap::new(&trace, Vec::new());
        let tape = StorageTape::new(&trace, &map);
        let words = tape.at_step(&map, 0);
        assert!(!words.captured());
        assert!(words.known().is_empty());
        let counter = state_value(&layout(), &words, "counter").expect("counter");
        assert_eq!(
            counter.value.display,
            "<unavailable: this backend recorded no storage>"
        );
    }

    #[test]
    fn short_hex_trims_leading_zeros() {
        let mut word = [0_u8; 32];
        assert_eq!(short_hex(&word), "0x0");
        word[31] = 0x1f;
        assert_eq!(short_hex(&word), "0x1f");
        word[0] = 0xab;
        assert!(short_hex(&word).starts_with("0xab00"));
    }
}
