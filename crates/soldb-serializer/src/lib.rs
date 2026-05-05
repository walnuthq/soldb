use soldb_core::{SoldbResult, TransactionTrace};

pub fn trace_to_json(trace: &TransactionTrace) -> SoldbResult<String> {
    serde_json::to_string_pretty(trace)
        .map_err(|err| soldb_core::SoldbError::Message(err.to_string()))
}
