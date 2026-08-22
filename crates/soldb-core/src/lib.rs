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

use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    pub pc: u64,
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: u64,
    pub stack: Vec<String>,
    pub memory: Option<String>,
    pub storage: Option<BTreeMap<String, String>>,
    pub error: Option<String>,
    #[serde(default)]
    pub snapshot: StepSnapshot,
}

impl TraceStep {
    /// Borrows the machine state this step captured, without copying it.
    ///
    /// A step records the same data twice: the flat `stack`/`memory`/`storage` fields, and
    /// a [`StepSnapshot`] that additionally carries the storage diff. Whichever is
    /// populated, this returns a view of it.
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
            memory: self.memory.map(str::to_owned),
            storage: self.storage.clone(),
            storage_diff: self.storage_diff.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StepSnapshot {
    #[serde(default)]
    pub stack: Vec<String>,
    #[serde(default)]
    pub memory: Option<String>,
    #[serde(default)]
    pub storage: BTreeMap<String, String>,
    #[serde(default)]
    pub storage_diff: BTreeMap<String, StorageChange>,
}

impl StepSnapshot {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
            && self.memory.is_none()
            && self.storage.is_empty()
            && self.storage_diff.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageChange {
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        let populated = step_with(StepSnapshot {
            stack: vec!["0x09".to_owned()],
            memory: Some("ccdd".to_owned()),
            storage: BTreeMap::from([("0x01".to_owned(), "0x63".to_owned())]),
            storage_diff: BTreeMap::from([(
                "0x01".to_owned(),
                StorageChange {
                    before: None,
                    after: Some("0x63".to_owned()),
                },
            )]),
        });

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
