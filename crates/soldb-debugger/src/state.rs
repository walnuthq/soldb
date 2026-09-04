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
//! A slot with no record yet is unknown, and is reported as unknown rather than as zero:
//! the debugger has no chain to ask, and it does not pretend to.

use std::collections::HashMap;

use soldb_core::TransactionTrace;
use soldb_ethdebug::{parse_word, word_hex, StorageLayout, StorageRef, Word};

use crate::stepping::StepMap;
use crate::{DebugValue, DebugValueStatus};

/// One state variable, or one place inside one, with its value at a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateVariable {
    /// The path as resolved, such as `counter` or `balances[0xabc]`.
    pub name: String,
    /// The Solidity type as the layout labels it.
    pub ty: String,
    /// The slot, as `0x`-prefixed hex without leading zeros.
    pub slot: String,
    /// The byte offset within the slot.
    pub offset: u64,
    pub value: DebugValue,
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
            let from = if step.op == "SSTORE" {
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
        }
    }

    /// The words known at `step`, in the storage context that step runs in.
    #[must_use]
    pub fn at_step(&self, map: &StepMap, step: usize) -> StorageWords<'_> {
        self.at(step, map.storage_context_index(step))
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
#[derive(Debug, Clone, Copy)]
pub struct StorageWords<'a> {
    tape: &'a StorageTape,
    step: usize,
    context: Option<usize>,
}

impl StorageWords<'_> {
    /// The word at `slot`, when the trace recorded one that still holds.
    #[must_use]
    pub fn get(&self, slot: &Word) -> Option<Word> {
        match self.tape.lookup(self.context?, slot, self.step) {
            Lookup::Known(value) => Some(value),
            Lookup::Untouched | Lookup::Reverted => None,
        }
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
    fn unavailable(&self, slot: &Word) -> String {
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
            Lookup::Known(_) | Lookup::Untouched => format!(
                "<unknown: slot {} has not been read or written yet>",
                short_hex(slot)
            ),
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
    let value = match layout.decode(reference, &|slot| words.get(slot)) {
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
        value,
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

    use super::{short_hex, state_value, state_variables, StorageTape};
    use crate::stepping::StepMap;
    use crate::DebugValueStatus;

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
            op: op.to_owned(),
            gas: 0,
            gas_cost: 0,
            depth,
            stack: Vec::new(),
            memory: None,
            storage: None,
            error: None,
            snapshot: StepSnapshot::new(
                stack.iter().map(|word| (*word).to_owned()).collect(),
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
