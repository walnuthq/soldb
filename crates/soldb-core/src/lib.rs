//! Shared vocabulary types for the SolDB workspace.
//!
//! Every other crate agrees on the types defined here: [`TransactionTrace`] and its
//! [`TraceStep`]s are what an execution backend produces and what the debugger, the
//! serializer, and the frontends consume. This crate deliberately has no soldb
//! dependencies so that it can stay the single type boundary in the graph.
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

use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

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

/// One recorded EVM step.
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
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: u64,
    /// Legacy layout; empty unless a caller filled it by hand. See the type docs.
    pub stack: Vec<String>,
    /// Legacy layout; `None` unless a caller filled it by hand. See the type docs.
    pub memory: Option<String>,
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
        op: String,
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
            };
        }
        StepSnapshotRef {
            stack: &self.stack,
            memory: self.memory.as_deref(),
            storage: self.storage.as_ref().unwrap_or(&EMPTY_STORAGE),
            storage_diff: &EMPTY_STORAGE_DIFF,
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
    fn normalized(mut self) -> Self {
        if self.snapshot.is_empty() {
            self.snapshot = StepSnapshot {
                stack: std::mem::take(&mut self.stack),
                memory: self.memory.take().map(Arc::from),
                storage: Arc::new(self.storage.take().unwrap_or_default()),
                storage_diff: BTreeMap::new(),
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
        state.serialize_field("memory", &snapshot.memory)?;
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
    #[serde(default)]
    memory: Option<String>,
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
            op: repr.op,
            gas: repr.gas,
            gas_cost: repr.gas_cost,
            depth: repr.depth,
            stack: repr.stack,
            memory: repr.memory,
            storage: repr.storage,
            error: repr.error,
            snapshot: repr.snapshot,
        }
        .normalized())
    }
}

/// A borrowed view of one step's captured machine state.
///
/// Serializes identically to [`StepSnapshot`], so it can stand in wherever a snapshot is
/// written out. Produced by [`TraceStep::snapshot_ref`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StepSnapshotRef<'a> {
    pub stack: &'a [String],
    pub memory: Option<&'a str>,
    pub storage: &'a BTreeMap<String, String>,
    pub storage_diff: &'a BTreeMap<String, StorageChange>,
}

impl StepSnapshotRef<'_> {
    /// Copies this view into an owned [`StepSnapshot`].
    #[must_use]
    pub fn to_owned_snapshot(&self) -> StepSnapshot {
        StepSnapshot {
            stack: self.stack.to_vec(),
            memory: self.memory.map(Arc::from),
            storage: Arc::new(self.storage.clone()),
            storage_diff: self.storage_diff.clone(),
        }
    }
}

/// The machine state one step captured.
///
/// `memory` and `storage` are shared: a backend building steps hands the previous step's
/// value on unchanged, so a trace holds one copy of memory per change rather than one
/// per step. Reads see plain values through `Deref`; a step that changes them gets its
/// own.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(from = "StepSnapshotRepr")]
pub struct StepSnapshot {
    pub stack: Vec<String>,
    /// Memory as one unprefixed hex string.
    pub memory: Option<Arc<str>>,
    pub storage: Arc<BTreeMap<String, String>>,
    pub storage_diff: BTreeMap<String, StorageChange>,
}

impl StepSnapshot {
    /// A snapshot that owns its values, for a backend or a test building one from parts.
    #[must_use]
    pub fn new(
        stack: Vec<String>,
        memory: Option<String>,
        storage: BTreeMap<String, String>,
        storage_diff: BTreeMap<String, StorageChange>,
    ) -> Self {
        Self {
            stack,
            memory: memory.map(Arc::from),
            storage: Arc::new(storage),
            storage_diff,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
            && self.memory.is_none()
            && self.storage.is_empty()
            && self.storage_diff.is_empty()
    }
}

impl Serialize for StepSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StepSnapshot", 4)?;
        state.serialize_field("stack", &self.stack)?;
        state.serialize_field("memory", &self.memory.as_deref())?;
        state.serialize_field("storage", &*self.storage)?;
        state.serialize_field("storage_diff", &self.storage_diff)?;
        state.end()
    }
}

#[derive(Deserialize, Default)]
struct StepSnapshotRepr {
    #[serde(default)]
    stack: Vec<String>,
    #[serde(default)]
    memory: Option<String>,
    #[serde(default)]
    storage: BTreeMap<String, String>,
    #[serde(default)]
    storage_diff: BTreeMap<String, StorageChange>,
}

impl From<StepSnapshotRepr> for StepSnapshot {
    fn from(repr: StepSnapshotRepr) -> Self {
        Self::new(repr.stack, repr.memory, repr.storage, repr.storage_diff)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageChange {
    pub before: Option<String>,
    pub after: Option<String>,
}

/// A complete recording of one execution.
///
/// Reading one back from JSON shares unchanged memory and storage between consecutive
/// steps as they are read, so a trace loaded from a file costs what one built by a
/// backend costs, at its peak as well as afterwards. [`TransactionTrace::share_unchanged_state`]
/// does the same for a trace assembled by hand.
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
    pub steps: Vec<TraceStep>,
}

impl TransactionTrace {
    /// Makes consecutive steps whose memory or storage is equal share one copy.
    ///
    /// Backends build steps that way; a trace deserialized from a file arrives with a
    /// copy per step, and this pass, linear in the size of the trace, folds them back.
    pub fn share_unchanged_state(&mut self) {
        for index in 1..self.steps.len() {
            let (before, after) = self.steps.split_at_mut(index);
            share_snapshot(&before[index - 1], &mut after[0]);
        }
    }
}

/// The wire shape of a trace; `From` restores the sharing between steps.
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
    #[serde(deserialize_with = "deserialize_shared_steps")]
    steps: Vec<TraceStep>,
}

/// Deserializes the steps, pointing each one's memory and storage at the previous step's
/// when they are equal, so the duplicates a file carries are never all resident at once.
fn deserialize_shared_steps<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<TraceStep>, D::Error> {
    struct SharedSteps;

    impl<'de> Visitor<'de> for SharedSteps {
        type Value = Vec<TraceStep>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of trace steps")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut steps = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(mut step) = seq.next_element::<TraceStep>()? {
                if let Some(previous) = steps.last() {
                    share_snapshot(previous, &mut step);
                }
                steps.push(step);
            }
            Ok(steps)
        }
    }

    deserializer.deserialize_seq(SharedSteps)
}

/// Points `step`'s memory and storage at `previous`'s when the values are equal.
fn share_snapshot(previous: &TraceStep, step: &mut TraceStep) {
    let previous = &previous.snapshot;
    let current = &mut step.snapshot;
    if let (Some(previous_memory), Some(current_memory)) = (&previous.memory, &current.memory) {
        if !Arc::ptr_eq(previous_memory, current_memory) && **previous_memory == **current_memory {
            current.memory = Some(Arc::clone(previous_memory));
        }
    }
    if !Arc::ptr_eq(&previous.storage, &current.storage) && *previous.storage == *current.storage {
        current.storage = Arc::clone(&previous.storage);
    }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::{
        FunctionCall, StepSnapshot, StorageChange, TraceArtifacts, TraceCapabilities, TraceStep,
        TransactionTrace,
    };

    fn step_with(snapshot: StepSnapshot) -> TraceStep {
        TraceStep {
            pc: 3,
            op: "SSTORE".to_owned(),
            gas: 100,
            gas_cost: 5,
            depth: 1,
            stack: vec!["0x01".to_owned(), "0x02".to_owned()],
            memory: Some("aabb".to_owned()),
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
        // the web JSON document writes a snapshot per step.
        let flat = step_with(StepSnapshot::default());
        let populated = step_with(StepSnapshot::new(
            vec!["0x09".to_owned()],
            Some("ccdd".to_owned()),
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
        assert_eq!(flat.snapshot_ref().stack, ["0x01", "0x02"]);
        assert_eq!(flat.snapshot_ref().memory, Some("aabb"));
        assert!(flat.snapshot_ref().storage_diff.is_empty());

        // A populated snapshot wins over the flat fields.
        assert_eq!(populated.snapshot_ref().stack, ["0x09"]);
        assert_eq!(populated.snapshot_ref().memory, Some("ccdd"));
        assert_eq!(populated.snapshot_ref().storage_diff.len(), 1);
    }

    #[test]
    fn steps_serialize_in_the_wire_format_and_read_back_stored_once() {
        // A step holds its state once, in the snapshot; the document still carries the
        // flat fields older readers expect, filled from that one copy.
        let step = TraceStep::new(
            3,
            "SSTORE".to_owned(),
            100,
            5,
            1,
            None,
            StepSnapshot::new(
                vec!["0x01".to_owned()],
                Some("aabb".to_owned()),
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
        assert_eq!(legacy.snapshot_ref().stack, ["0x1"]);
        assert_eq!(legacy.snapshot_ref().memory, Some("cc"));
        assert_eq!(legacy.snapshot_ref().storage["0x0"], "0x1");
        assert!(legacy.stack.is_empty());
        assert_eq!(legacy, step_with_legacy_fields());

        // Steps share memory and storage by reference when a backend hands them on.
        let shared = TraceStep::new(
            4,
            "POP".to_owned(),
            95,
            2,
            1,
            None,
            StepSnapshot {
                stack: Vec::new(),
                memory: step.snapshot.memory.clone(),
                storage: Arc::clone(&step.snapshot.storage),
                storage_diff: BTreeMap::new(),
            },
        );
        assert!(Arc::ptr_eq(
            &shared.snapshot.storage,
            &step.snapshot.storage
        ));
        assert_eq!(shared.snapshot_ref().memory, Some("aabb"));
    }

    fn step_with_legacy_fields() -> TraceStep {
        TraceStep {
            pc: 1,
            op: "ADD".to_owned(),
            gas: 9,
            gas_cost: 3,
            depth: 1,
            stack: vec!["0x1".to_owned()],
            memory: Some("cc".to_owned()),
            storage: Some(BTreeMap::from([("0x0".to_owned(), "0x1".to_owned())])),
            error: None,
            snapshot: StepSnapshot::default(),
        }
    }

    #[test]
    fn reading_a_trace_back_shares_unchanged_state_between_steps() {
        let snapshot = |memory: &str, slot: &str| {
            StepSnapshot::new(
                Vec::new(),
                Some(memory.to_owned()),
                BTreeMap::from([("0x0".to_owned(), slot.to_owned())]),
                BTreeMap::new(),
            )
        };
        let step = |pc: u64, snapshot: StepSnapshot| {
            TraceStep::new(pc, "PUSH1".to_owned(), 1, 1, 1, None, snapshot)
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
            ],
        };
        let json = serde_json::to_string(&trace).expect("json");
        let restored: TransactionTrace = serde_json::from_str(&json).expect("trace");
        assert_eq!(restored, trace);
        let memory = |index: usize| {
            restored.steps[index]
                .snapshot
                .memory
                .as_ref()
                .expect("memory")
        };
        assert!(Arc::ptr_eq(memory(0), memory(1)));
        assert!(!Arc::ptr_eq(memory(1), memory(2)));
        assert!(Arc::ptr_eq(memory(2), memory(3)));
        let storage = |index: usize| &restored.steps[index].snapshot.storage;
        assert!(Arc::ptr_eq(storage(0), storage(2)));
        assert!(!Arc::ptr_eq(storage(2), storage(3)));

        // The same pass is available for a trace assembled by hand.
        let mut by_hand = trace.clone();
        assert!(!Arc::ptr_eq(
            &by_hand.steps[0].snapshot.storage,
            &by_hand.steps[1].snapshot.storage
        ));
        by_hand.share_unchanged_state();
        assert!(Arc::ptr_eq(
            &by_hand.steps[0].snapshot.storage,
            &by_hand.steps[1].snapshot.storage
        ));
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
                op: "STOP".to_owned(),
                gas: 1,
                gas_cost: 0,
                depth: 0,
                stack: Vec::new(),
                memory: None,
                storage: None,
                error: None,
                snapshot: StepSnapshot::default(),
            }],
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
}
