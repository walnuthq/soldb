use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SoldbError {
    #[error("{0}")]
    Message(String),
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
    #[must_use]
    pub fn normalized_snapshot(&self) -> StepSnapshot {
        if !self.snapshot.is_empty() {
            return self.snapshot.clone();
        }
        StepSnapshot {
            stack: self.stack.clone(),
            memory: self.memory.clone(),
            storage: self.storage.clone().unwrap_or_default(),
            storage_diff: BTreeMap::new(),
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
    use super::{
        FunctionCall, StepSnapshot, StorageChange, TraceArtifacts, TraceCapabilities, TraceStep,
        TransactionTrace,
    };

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
