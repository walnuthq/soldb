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
    pub steps: Vec<TraceStep>,
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
    use super::{FunctionCall, StepSnapshot, StorageChange, TraceStep, TransactionTrace};

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
