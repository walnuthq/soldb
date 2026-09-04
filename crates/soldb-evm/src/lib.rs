//! The execution engine behind every trace: what a node says about a transaction, how
//! that becomes a [`soldb_core::TransactionTrace`], and how to re-execute it in REVM.
//!
//! Nothing here opens a socket. The node data shapes ([`RpcTransaction`], [`RpcReceipt`],
//! [`DebugTraceResult`] and friends) are what JSON-RPC answers deserialize into, and the
//! trace assembly ([`debug_rpc_transaction_trace`], [`debug_rpc_simulation_trace`]) turns
//! them into a trace whether they were fetched by `soldb-rpc`, by a browser, or read from
//! a file. The two backends stay in lockstep because both end in
//! [`build_transaction_trace`], and each reports what it captured through
//! `TraceCapabilities` so no caller has to branch on the backend name.
//!
//! The `replay` module, behind the cargo feature of the same name (on by default), is the
//! REVM engine: it re-executes a transaction or a call over state supplied through a
//! [`ReplayStateProvider`], and runs bytecode on a [`LocalChain`] with no node at all. It
//! is the only part of the crate that links REVM, so a build without it, such as the lean
//! WebAssembly package, keeps only the data shapes and the trace assembly.
//!
//! `soldb-rpc` builds on this crate with the JSON-RPC transport, the networked `debug-rpc`
//! backend, and the state provider that reads a node lazily.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use soldb_core::{
    ExecutionLog, GasSummary, SoldbError, SoldbResult, StepSnapshot, StorageChange, TraceArtifacts,
    TraceCapabilities, TraceStep, TransactionTrace,
};

#[cfg(feature = "replay")]
mod replay;

#[cfg(feature = "replay")]
pub use replay::{
    account_info_from_rpc, parse_address, parse_b256, replay_chain_support,
    replay_debug_trace_with_state, replay_prefix_with_state, replay_simulation_trace,
    replay_target_with_state, replay_transaction_trace, AccountState, LocalChain,
    PrefetchedReplayState, ReplayDbError, ReplayInputs, ReplayPrefix, ReplayStateProvider,
    RpcBlockHeader, RpcBlockTransaction, RpcBlockWithTransactions, StateBatch, StateRequest,
};
#[cfg(feature = "replay")]
pub use revm::primitives::{Address, B256};
#[cfg(feature = "replay")]
pub use revm::state::AccountInfo;
pub use ruint::aliases::U256;

/// Whether the REVM replay engine was compiled into this build.
///
/// The engine sits behind the `replay` cargo feature (on by default) because it is the
/// only part of the crate that links REVM. A build without it, such as the lean
/// WebAssembly package, keeps the node data shapes and the trace assembly.
#[must_use]
pub fn replay_available() -> bool {
    cfg!(feature = "replay")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceBackend {
    Auto,
    DebugRpc,
    Replay,
}

impl TraceBackend {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::DebugRpc => "debug-rpc",
            Self::Replay => "replay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructLog {
    pub pc: u64,
    pub op: String,
    pub gas: u64,
    #[serde(rename = "gasCost", default)]
    pub gas_cost: u64,
    pub depth: u64,
    #[serde(default)]
    pub stack: Vec<String>,
    #[serde(default)]
    pub memory: Vec<String>,
    #[serde(default)]
    pub storage: BTreeMap<String, String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Joins a `structLogs` memory array into one unprefixed hex string.
///
/// Nodes disagree on whether the words carry a `0x` prefix. Joining prefixed words
/// verbatim produces `0x..0x..0x..`, which is neither valid hex nor indexable by byte
/// offset, and it makes this backend disagree with the replay backend, which emits one
/// unprefixed string. A step's memory is documented to be a flat byte sequence, and
/// byte-offset lookups such as memory-located variable decoding assume exactly that.
fn joined_memory(words: &[String]) -> String {
    words
        .iter()
        .map(|word| {
            word.strip_prefix("0x")
                .or_else(|| word.strip_prefix("0X"))
                .unwrap_or(word)
        })
        .collect()
}

impl StructLog {
    #[must_use]
    pub fn into_trace_step(self) -> TraceStep {
        self.into_trace_step_with_previous_storage(&BTreeMap::new())
    }

    /// Builds a [`TraceStep`] from a borrowed log.
    ///
    /// Prefer this when walking a whole trace: the owning version cannot be used without
    /// first cloning the log, which doubles the per-step copying for no benefit.
    ///
    /// A `TraceStep` records its stack, memory, and storage twice — once in the flat
    /// fields and once in the snapshot — so two copies of each are unavoidable here. That
    /// is the floor, and this function stays at it.
    #[must_use]
    pub fn to_trace_step_with_previous_storage(
        &self,
        previous_storage: &BTreeMap<String, String>,
    ) -> TraceStep {
        let memory = joined_memory(&self.memory);
        let snapshot = StepSnapshot {
            stack: self.stack.clone(),
            memory: Some(memory.clone()),
            storage: self.storage.clone(),
            storage_diff: if self.storage.is_empty() {
                BTreeMap::new()
            } else {
                storage_diff(previous_storage, &self.storage)
            },
        };
        TraceStep {
            pc: self.pc,
            op: self.op.clone(),
            gas: self.gas,
            gas_cost: self.gas_cost,
            depth: self.depth,
            stack: self.stack.clone(),
            memory: Some(memory),
            storage: Some(self.storage.clone()),
            error: self.error.clone(),
            snapshot,
        }
    }

    #[must_use]
    pub fn into_trace_step_with_previous_storage(
        self,
        previous_storage: &BTreeMap<String, String>,
    ) -> TraceStep {
        let memory = joined_memory(&self.memory);
        // Clone into the snapshot first, then move the originals into the flat fields.
        let snapshot = StepSnapshot {
            stack: self.stack.clone(),
            memory: Some(memory.clone()),
            storage: self.storage.clone(),
            storage_diff: if self.storage.is_empty() {
                BTreeMap::new()
            } else {
                storage_diff(previous_storage, &self.storage)
            },
        };
        TraceStep {
            pc: self.pc,
            op: self.op,
            gas: self.gas,
            gas_cost: self.gas_cost,
            depth: self.depth,
            stack: self.stack,
            memory: Some(memory),
            storage: Some(self.storage),
            error: self.error,
            snapshot,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugTraceResult {
    #[serde(rename = "structLogs", default)]
    pub struct_logs: Vec<StructLog>,
    #[serde(rename = "returnValue", default)]
    pub return_value: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub failed: bool,
    #[serde(default)]
    pub gas: Option<u64>,
    #[serde(default)]
    pub artifacts: TraceArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcTransaction {
    pub hash: String,
    #[serde(rename = "from")]
    pub from_addr: String,
    pub to: Option<String>,
    #[serde(default)]
    pub value: String,
    #[serde(default, alias = "input")]
    pub input_data: String,
    #[serde(default)]
    pub gas: Option<String>,
    #[serde(default, rename = "gasPrice")]
    pub gas_price: Option<String>,
    #[serde(default, rename = "maxFeePerGas")]
    pub max_fee_per_gas: Option<String>,
    #[serde(default, rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default, rename = "blockNumber")]
    pub block_number: Option<String>,
    #[serde(default, rename = "transactionIndex")]
    pub transaction_index: Option<String>,
    #[serde(default, rename = "type")]
    pub transaction_type: Option<String>,
    #[serde(default, rename = "chainId")]
    pub chain_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReceipt {
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    pub status: Option<String>,
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<String>,
    #[serde(default)]
    pub logs: Vec<RpcLog>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcLog {
    pub address: String,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub data: String,
}

impl DebugTraceResult {
    #[must_use]
    pub fn steps(&self) -> Vec<TraceStep> {
        static EMPTY_STORAGE: BTreeMap<String, String> = BTreeMap::new();

        // Borrow the previous log's storage rather than copying it forward: this runs once
        // per EVM step, and a trace can have hundreds of thousands of them.
        let mut previous_storage = &EMPTY_STORAGE;
        self.struct_logs
            .iter()
            .map(|log| {
                let step = log.to_trace_step_with_previous_storage(previous_storage);
                previous_storage = &log.storage;
                step
            })
            .collect()
    }

    #[must_use]
    pub fn failure_message(&self) -> Option<String> {
        if let Some(error) = &self.error {
            return Some(error.clone());
        }

        if self.failed {
            return decode_revert_reason(&self.return_value)
                .or_else(|| {
                    (!self.return_value.is_empty()).then(|| {
                        let data = self.return_value.trim_start_matches("0x");
                        format!("Reverted with data: 0x{data}")
                    })
                })
                .or_else(|| Some("Execution reverted".to_owned()));
        }

        None
    }
}

fn storage_diff(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> BTreeMap<String, StorageChange> {
    let mut diff = BTreeMap::new();
    for key in before.keys().chain(after.keys()) {
        if diff.contains_key(key) {
            continue;
        }
        let before_value = before.get(key).cloned();
        let after_value = after.get(key).cloned();
        if before_value != after_value {
            diff.insert(
                key.clone(),
                StorageChange {
                    before: before_value,
                    after: after_value,
                },
            );
        }
    }
    diff
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEnvelope {
    pub tx_hash: Option<String>,
    pub from_addr: String,
    pub to_addr: Option<String>,
    pub value: String,
    pub input_data: String,
    pub gas_used: u64,
    pub success: bool,
    pub contract_address: Option<String>,
    pub debug_trace_available: bool,
    pub debug_error: Option<String>,
    pub backend: Option<String>,
    pub capabilities: TraceCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulateCallRequest {
    pub from_addr: String,
    pub to_addr: String,
    pub calldata: String,
    pub value: String,
    pub block: Option<u64>,
    pub tx_index: Option<u64>,
}

pub fn build_transaction_trace(
    envelope: TraceEnvelope,
    debug_result: &DebugTraceResult,
) -> TransactionTrace {
    let failure = debug_result.failure_message();
    let success = envelope.success && failure.is_none();
    let error = failure.or(envelope.debug_error.clone());
    let output = normalize_hex_output(&debug_result.return_value);
    let mut artifacts = debug_result.artifacts.clone();
    if artifacts.gas.is_none() {
        if let Some(used) = debug_result.gas {
            artifacts.gas = Some(GasSummary {
                used,
                spent: None,
                refunded: None,
                remaining: None,
                limit: None,
            });
        }
    }
    if artifacts.revert_data.is_none() && !success && output != "0x" {
        artifacts.revert_data = Some(output.clone());
    }

    TransactionTrace {
        tx_hash: envelope.tx_hash,
        from_addr: envelope.from_addr,
        to_addr: envelope.to_addr,
        value: envelope.value,
        input_data: envelope.input_data,
        gas_used: envelope.gas_used,
        output,
        success,
        error,
        debug_trace_available: envelope.debug_trace_available,
        contract_address: envelope.contract_address,
        backend: envelope.backend,
        capabilities: envelope.capabilities,
        artifacts,
        steps: debug_result.steps(),
    }
}

/// Assembles the `debug-rpc` trace of a mined transaction from the node's responses to
/// `eth_getTransactionByHash`, `eth_getTransactionReceipt`, and `debug_traceTransaction`.
///
/// This is the whole of the `debug-rpc` backend once the three requests have been
/// answered, so a host that fetches them itself, such as a WebAssembly client, produces
/// the identical trace to `soldb-rpc`'s `trace_transaction_with_client`.
pub fn debug_rpc_transaction_trace(
    tx: RpcTransaction,
    receipt: RpcReceipt,
    debug_result: &DebugTraceResult,
) -> SoldbResult<TransactionTrace> {
    let envelope = TraceEnvelope {
        tx_hash: Some(tx.hash),
        from_addr: tx.from_addr,
        to_addr: tx.to,
        value: tx.value,
        input_data: normalize_hex_output(&tx.input_data),
        gas_used: parse_quantity(&receipt.gas_used)?,
        success: receipt.status.as_deref().is_none_or(quantity_is_one),
        contract_address: receipt.contract_address,
        debug_trace_available: true,
        debug_error: None,
        backend: Some(TraceBackend::DebugRpc.as_str().to_owned()),
        capabilities: debug_rpc_capabilities(debug_result),
    };
    let mut trace = build_transaction_trace(envelope, debug_result);
    if !receipt.logs.is_empty() && trace.artifacts.logs.is_empty() {
        trace.artifacts.logs = receipt_logs_to_artifacts(&receipt.logs);
        trace.capabilities.logs = true;
    }
    Ok(trace)
}

/// Assembles the trace of a simulated call from the request that was sent and the node's
/// `debug_traceCall` response.
///
/// The request's `block` and `tx_index` only shape the RPC call, so they do not appear in
/// the trace. See [`debug_rpc_transaction_trace`] for why this is separate from the
/// networked `simulate_call_with_client` in `soldb-rpc`.
pub fn debug_rpc_simulation_trace(
    request: &SimulateCallRequest,
    debug_result: &DebugTraceResult,
) -> SoldbResult<TransactionTrace> {
    simulation_trace(
        TraceBackend::DebugRpc,
        debug_rpc_capabilities(debug_result),
        request,
        debug_result,
    )
}

/// The one place a simulated call becomes a trace, whichever backend executed it.
pub(crate) fn simulation_trace(
    backend: TraceBackend,
    capabilities: TraceCapabilities,
    request: &SimulateCallRequest,
    debug_result: &DebugTraceResult,
) -> SoldbResult<TransactionTrace> {
    let failure = debug_result.failure_message();
    Ok(TransactionTrace {
        tx_hash: None,
        from_addr: request.from_addr.clone(),
        to_addr: Some(request.to_addr.clone()),
        value: parse_value_quantity(&request.value)?,
        input_data: normalize_hex_output(&request.calldata),
        gas_used: debug_result.gas.unwrap_or(0),
        output: normalize_hex_output(&debug_result.return_value),
        success: failure.is_none(),
        error: failure,
        debug_trace_available: true,
        contract_address: None,
        backend: Some(backend.as_str().to_owned()),
        capabilities,
        artifacts: {
            let mut artifacts = debug_result.artifacts.clone();
            if artifacts.gas.is_none() {
                artifacts.gas = Some(GasSummary {
                    used: debug_result.gas.unwrap_or(0),
                    spent: None,
                    refunded: None,
                    remaining: None,
                    limit: None,
                });
            }
            artifacts
        },
        steps: debug_result.steps(),
    })
}

fn debug_rpc_capabilities(result: &DebugTraceResult) -> TraceCapabilities {
    let has_steps = !result.struct_logs.is_empty();
    let has_storage = result
        .struct_logs
        .iter()
        .any(|step| !step.storage.is_empty());
    // Whether any step reports a storage change, read straight off the logs. Calling
    // `steps()` here would build the entire trace a second time — hundreds of thousands of
    // steps, each with a copy of the stack and of all of memory — and then throw it away to
    // answer a boolean. This mirrors what `to_trace_step_with_previous_storage` computes:
    // a step has a diff when its own storage is non-empty and differs from the previous
    // step's.
    let has_storage_diff = {
        static EMPTY_STORAGE: BTreeMap<String, String> = BTreeMap::new();
        let mut previous = &EMPTY_STORAGE;
        result.struct_logs.iter().any(|log| {
            let changed = !log.storage.is_empty() && *previous != log.storage;
            previous = &log.storage;
            changed
        })
    };
    let mut notes = Vec::new();
    if has_steps && !has_storage {
        notes.push("debug-rpc node did not return per-step storage".to_owned());
    }

    TraceCapabilities {
        opcode_steps: has_steps,
        stack: has_steps,
        memory: has_steps,
        storage: has_storage,
        storage_diff: has_storage_diff,
        call_trace: false,
        contract_creation: false,
        logs: false,
        revert_data: result.failed && !result.return_value.is_empty(),
        gas_details: result.gas.is_some(),
        account_changes: false,
        notes,
    }
}

fn receipt_logs_to_artifacts(logs: &[RpcLog]) -> Vec<ExecutionLog> {
    logs.iter()
        .enumerate()
        .map(|(index, log)| ExecutionLog {
            index,
            depth: 0,
            address: log.address.clone(),
            topics: log.topics.clone(),
            data: normalize_hex_output(&log.data),
        })
        .collect()
}

#[must_use]
pub fn decode_revert_reason(return_value: &str) -> Option<String> {
    let data = return_value.trim_start_matches("0x");
    if !data.starts_with("08c379a0") || data.len() < 8 + 64 + 64 {
        return None;
    }

    let payload = &data[8..];
    let length_hex = payload.get(64..128)?;
    let length = usize::from_str_radix(length_hex, 16).ok()?;
    let string_start = 128;
    let string_end = string_start + length.checked_mul(2)?;
    let string_hex = payload.get(string_start..string_end)?;
    let bytes = hex_to_bytes(string_hex)?;
    String::from_utf8(bytes).ok()
}

/// Normalizes hex data from a node or a user to a `0x`-prefixed string, `0x` when empty.
#[must_use]
pub fn normalize_hex_output(value: &str) -> String {
    if value.is_empty() {
        "0x".to_owned()
    } else if value.starts_with("0x") {
        value.to_owned()
    } else {
        format!("0x{value}")
    }
}

/// Parses a JSON-RPC quantity (`0x`-prefixed hex) into a `u64`.
pub fn parse_quantity(value: &str) -> SoldbResult<u64> {
    let hex = value.trim_start_matches("0x");
    u64::from_str_radix(hex, 16)
        .map_err(|error| SoldbError::Message(format!("Invalid RPC quantity '{value}': {error}")))
}

/// Parses a JSON-RPC quantity (`0x`-prefixed hex) into a `U256`.
pub fn parse_u256_quantity(value: &str) -> SoldbResult<U256> {
    let hex = value.trim_start_matches("0x");
    if hex.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(hex, 16)
        .map_err(|error| SoldbError::Message(format!("Invalid RPC quantity '{value}': {error}")))
}

fn quantity_is_one(value: &str) -> bool {
    parse_quantity(value).is_ok_and(|quantity| quantity == 1)
}

/// Parses a wei amount given as a decimal, a hex quantity, or an ether amount such as
/// `1.5 ether`, into the hex quantity a transaction carries.
pub fn parse_value_quantity(value: &str) -> SoldbResult<String> {
    let value = value.trim();
    if value.starts_with("0x") {
        Ok(format_u256_quantity(parse_u256_quantity(value)?))
    } else if let Some(ether_value) = strip_ether_suffix(value) {
        Ok(format_u256_quantity(parse_ether_value(ether_value)?))
    } else {
        let parsed = U256::from_str_radix(value, 10).map_err(|error| {
            SoldbError::Message(format!("Invalid call value '{value}': {error}"))
        })?;
        Ok(format_u256_quantity(parsed))
    }
}

fn strip_ether_suffix(value: &str) -> Option<&str> {
    value
        .get(..value.len().checked_sub("ether".len())?)
        .filter(|_| value.to_ascii_lowercase().ends_with("ether"))
        .map(str::trim)
}

fn parse_ether_value(value: &str) -> SoldbResult<U256> {
    let value = value.trim();
    let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty() && fractional.is_empty() {
        return Err(SoldbError::Message("Invalid call value 'ether'".to_owned()));
    }
    if fractional.len() > 18 {
        return Err(SoldbError::Message(format!(
            "Invalid call value '{value}ether': too many decimal places"
        )));
    }
    if (!whole.is_empty() && !whole.chars().all(|ch| ch.is_ascii_digit()))
        || (!fractional.is_empty() && !fractional.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(SoldbError::Message(format!(
            "Invalid call value '{value}ether': expected decimal ether amount"
        )));
    }

    let ether = U256::from(1_000_000_000_000_000_000u64);
    let whole_wei = if whole.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(whole, 10)
            .map_err(|error| {
                SoldbError::Message(format!("Invalid call value '{value}ether': {error}"))
            })?
            .checked_mul(ether)
            .ok_or_else(|| {
                SoldbError::Message(format!("Invalid call value '{value}ether': overflow"))
            })?
    };

    let fractional_wei = if fractional.is_empty() {
        U256::ZERO
    } else {
        let mut padded = fractional.to_owned();
        padded.extend(std::iter::repeat_n('0', 18 - fractional.len()));
        U256::from_str_radix(&padded, 10).map_err(|error| {
            SoldbError::Message(format!("Invalid call value '{value}ether': {error}"))
        })?
    };

    whole_wei
        .checked_add(fractional_wei)
        .ok_or_else(|| SoldbError::Message(format!("Invalid call value '{value}ether': overflow")))
}

/// Formats a `u64` as the JSON-RPC quantity the node expects.
#[must_use]
pub fn format_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

/// Formats a `U256` as a JSON-RPC quantity.
#[must_use]
pub fn format_u256_quantity(value: U256) -> String {
    if value == U256::ZERO {
        return "0x0".to_owned();
    }
    let bytes = value.to_be_bytes::<32>();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let hex = bytes_to_hex(&bytes[first_non_zero..]);
    format!("0x{}", hex.trim_start_matches('0'))
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    // Hex strings reach us from RPC responses and CLI arguments, so they are not
    // guaranteed to be ASCII. Slicing by byte offset would panic on a multi-byte
    // character whose boundary falls inside a pair; decode over bytes instead.
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }

    pairs
        .iter()
        .map(|[high, low]| {
            let high = char::from(*high).to_digit(16)?;
            let low = char::from(*low).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Fill an ASCII byte buffer and validate it once. `String::push` re-runs UTF-8
    // encoding for every character, which is measurable when the replay inspector encodes
    // the whole of EVM memory.
    let mut encoded = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)]);
        encoded.push(HEX[usize::from(byte & 0x0f)]);
    }
    // `HEX` holds only ASCII, so the buffer is valid UTF-8 by construction.
    String::from_utf8(encoded).expect("hex digits are ASCII")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        build_transaction_trace, debug_rpc_capabilities, debug_rpc_simulation_trace,
        debug_rpc_transaction_trace, decode_revert_reason, parse_value_quantity, DebugTraceResult,
        RpcReceipt, RpcTransaction, SimulateCallRequest, StructLog, TraceArtifacts, TraceBackend,
        TraceCapabilities, TraceEnvelope,
    };

    fn canned_debug_result() -> DebugTraceResult {
        serde_json::from_value(json!({
            "gas": 21000,
            "returnValue": "",
            "structLogs": [
                {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                {"pc": 2, "op": "MSTORE", "gas": 97, "gasCost": 3, "depth": 0, "memory": ["aa", "bb"]},
                {"pc": 3, "op": "STOP", "gas": 94, "gasCost": 0, "depth": 0}
            ]
        }))
        .expect("debug result")
    }

    #[test]
    fn debug_rpc_transaction_trace_assembles_the_node_responses() {
        let tx: RpcTransaction = serde_json::from_value(json!({
            "hash": "0xabc",
            "from": "0x1",
            "to": "0x2",
            "value": "0x0",
            "input": "1234"
        }))
        .expect("transaction");
        let receipt: RpcReceipt = serde_json::from_value(json!({
            "gasUsed": "0x5208",
            "status": "0x1",
            "contractAddress": null,
            "logs": [event_log("0x2", "04"), event_log("0x2", "05")]
        }))
        .expect("receipt");

        let trace =
            debug_rpc_transaction_trace(tx, receipt, &canned_debug_result()).expect("trace");

        assert_eq!(trace.tx_hash.as_deref(), Some("0xabc"));
        assert_eq!(trace.from_addr, "0x1");
        assert_eq!(trace.to_addr.as_deref(), Some("0x2"));
        assert_eq!(trace.input_data, "0x1234");
        assert_eq!(trace.gas_used, 21000);
        assert!(trace.success);
        assert_eq!(trace.error, None);
        assert!(trace.debug_trace_available);
        assert_eq!(
            trace.backend.as_deref(),
            Some(TraceBackend::DebugRpc.as_str())
        );
        assert!(trace.capabilities.opcode_steps);
        // Receipt logs stand in for the logs `debug_traceTransaction` never returns.
        assert!(trace.capabilities.logs);
        assert_eq!(trace.artifacts.logs.len(), 2);
        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.steps[1].memory.as_deref(), Some("aabb"));
    }

    #[test]
    fn debug_rpc_transaction_trace_reports_a_reverted_receipt() {
        let tx: RpcTransaction = serde_json::from_value(json!({
            "hash": "0xabc",
            "from": "0x1",
            "to": "0x2"
        }))
        .expect("transaction");
        let receipt: RpcReceipt = serde_json::from_value(json!({
            "gasUsed": "0x5208",
            "status": "0x0"
        }))
        .expect("receipt");

        let trace =
            debug_rpc_transaction_trace(tx, receipt, &canned_debug_result()).expect("trace");

        assert!(!trace.success);
        assert!(!trace.capabilities.logs);
        assert!(trace.artifacts.logs.is_empty());
    }

    #[test]
    fn debug_rpc_transaction_trace_rejects_a_malformed_gas_quantity() {
        let tx: RpcTransaction = serde_json::from_value(json!({
            "hash": "0xabc",
            "from": "0x1",
            "to": "0x2"
        }))
        .expect("transaction");
        let receipt: RpcReceipt = serde_json::from_value(json!({
            "gasUsed": "not-a-quantity",
            "status": "0x1"
        }))
        .expect("receipt");

        assert!(debug_rpc_transaction_trace(tx, receipt, &canned_debug_result()).is_err());
    }

    #[test]
    fn debug_rpc_simulation_trace_carries_the_request_and_the_result() {
        let request = SimulateCallRequest {
            from_addr: "0x1".to_owned(),
            to_addr: "0x2".to_owned(),
            calldata: "0x1234".to_owned(),
            value: "0x0".to_owned(),
            block: Some(7),
            tx_index: Some(3),
        };
        let debug_result: DebugTraceResult = serde_json::from_value(json!({
            "gas": 42000,
            "returnValue": "2a",
            "failed": false,
            "structLogs": [
                {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                {"pc": 2, "op": "STOP", "gas": 95, "gasCost": 0, "depth": 0}
            ]
        }))
        .expect("debug result");

        let trace = debug_rpc_simulation_trace(&request, &debug_result).expect("trace");

        assert_eq!(trace.tx_hash, None);
        assert_eq!(trace.from_addr, "0x1");
        assert_eq!(trace.to_addr.as_deref(), Some("0x2"));
        assert_eq!(trace.input_data, "0x1234");
        assert_eq!(trace.output, "0x2a");
        assert_eq!(trace.gas_used, 42000);
        assert!(trace.success);
        assert_eq!(
            trace.backend.as_deref(),
            Some(TraceBackend::DebugRpc.as_str())
        );
        assert_eq!(
            trace.artifacts.gas.as_ref().map(|gas| gas.used),
            Some(42000)
        );
        assert_eq!(trace.steps.len(), 2);
    }

    #[test]
    fn debug_rpc_simulation_trace_surfaces_the_failure_message() {
        let request = SimulateCallRequest {
            from_addr: "0x1".to_owned(),
            to_addr: "0x2".to_owned(),
            calldata: "0x".to_owned(),
            value: "0x0".to_owned(),
            block: None,
            tx_index: None,
        };
        let debug_result: DebugTraceResult = serde_json::from_value(json!({
            "failed": true,
            "returnValue": "",
            "structLogs": [
                {"pc": 0, "op": "REVERT", "gas": 100, "gasCost": 0, "depth": 0, "error": "execution reverted"}
            ]
        }))
        .expect("debug result");

        let trace = debug_rpc_simulation_trace(&request, &debug_result).expect("trace");

        assert!(!trace.success);
        assert!(trace.error.is_some(), "failure must be reported");
        assert_eq!(trace.gas_used, 0);
    }

    #[test]
    fn storage_diff_capability_matches_the_materialized_steps() {
        // `debug_rpc_capabilities` reads the storage-diff flag off the raw logs instead of
        // building every step. Pin it against the definition it replaces.
        let log = |storage: &[(&str, &str)]| StructLog {
            pc: 0,
            op: "SSTORE".to_owned(),
            gas: 0,
            gas_cost: 0,
            depth: 0,
            stack: Vec::new(),
            memory: Vec::new(),
            storage: storage
                .iter()
                .map(|(slot, value)| ((*slot).to_owned(), (*value).to_owned()))
                .collect(),
            error: None,
        };

        let cases = [
            Vec::new(),
            vec![log(&[])],
            vec![log(&[("0x00", "0x01")])],
            vec![log(&[("0x00", "0x01")]), log(&[("0x00", "0x01")])],
            vec![log(&[("0x00", "0x01")]), log(&[("0x00", "0x02")])],
            vec![log(&[("0x00", "0x01")]), log(&[])],
            vec![log(&[]), log(&[("0x00", "0x01")])],
        ];

        for struct_logs in cases {
            let result = DebugTraceResult {
                struct_logs,
                return_value: String::new(),
                error: None,
                failed: false,
                gas: None,
                artifacts: TraceArtifacts::default(),
            };
            let materialized = result
                .steps()
                .iter()
                .any(|step| !step.snapshot.storage_diff.is_empty());
            assert_eq!(
                super::debug_rpc_capabilities(&result).storage_diff,
                materialized,
                "logs: {:?}",
                result.struct_logs
            );
        }
    }

    #[test]
    fn hex_decoding_rejects_non_ascii_without_panicking() {
        // Hex strings arrive from RPC responses and CLI arguments. Slicing them by byte
        // offset panicked when a multi-byte character straddled a digit pair.
        assert_eq!(super::hex_to_bytes("\u{20ac}\u{20ac}"), None);
        assert_eq!(super::hex_to_bytes("0\u{20ac}"), None);
        assert_eq!(super::hex_to_bytes("zz"), None);
        assert_eq!(super::hex_to_bytes("abc"), None);
        assert_eq!(super::hex_to_bytes("0a1B"), Some(vec![0x0a, 0x1b]));
        assert_eq!(super::hex_to_bytes(""), Some(Vec::new()));
    }

    #[test]
    fn parses_struct_logs_into_trace_steps() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "2a",
            "structLogs": [
                {
                    "pc": 0,
                    "op": "PUSH1",
                    "gas": 100,
                    "gasCost": 3,
                    "depth": 0,
                    "stack": ["0x01"],
                    "memory": ["0xaa", "bb"],
                    "storage": {"0x00": "0x2a"}
                },
                {"pc": 2, "op": "STOP", "gas": 97, "depth": 0}
            ]
        }))
        .expect("debug trace");

        let steps = result.steps();
        assert_eq!(steps.len(), 2);
        // Memory words are normalized to one unprefixed hex string whether or not the node
        // prefixed them, so byte-offset lookups stay valid and both backends agree.
        assert_eq!(steps[0].memory.as_deref(), Some("aabb"));
        assert_eq!(steps[0].storage.as_ref().expect("storage")["0x00"], "0x2a");
        assert_eq!(steps[0].snapshot.stack, ["0x01"]);
        assert_eq!(steps[0].snapshot.memory.as_deref(), Some("aabb"));
        assert_eq!(steps[0].snapshot.storage["0x00"], "0x2a");
        assert_eq!(
            steps[0].snapshot.storage_diff["0x00"].after.as_deref(),
            Some("0x2a")
        );
        assert_eq!(steps[1].gas_cost, 0);
        assert!(steps[1].snapshot.storage_diff.is_empty());
    }

    #[test]
    fn decodes_standard_error_string_reverts() {
        let reason = "boom";
        let encoded_reason = format!("{:0<64}", bytes_to_hex(reason.as_bytes()));
        let return_value = format!(
            "0x08c379a0{offset:064x}{length:064x}{encoded_reason}",
            offset = 32,
            length = reason.len(),
        );

        assert_eq!(decode_revert_reason(&return_value).as_deref(), Some("boom"));
    }

    #[test]
    fn builds_transaction_trace_from_debug_result() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "",
            "failed": false,
            "gas": 7,
            "structLogs": [{"pc": 0, "op": "STOP", "gas": 1, "depth": 0}]
        }))
        .expect("debug trace");
        let envelope = TraceEnvelope {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 21_000,
            success: true,
            contract_address: None,
            debug_trace_available: true,
            debug_error: None,
            backend: Some(TraceBackend::DebugRpc.as_str().to_owned()),
            capabilities: debug_rpc_capabilities(&result),
        };

        let trace = build_transaction_trace(envelope, &result);
        assert!(trace.success);
        assert_eq!(trace.output, "0x");
        assert_eq!(trace.backend.as_deref(), Some("debug-rpc"));
        assert!(trace.capabilities.opcode_steps);
        assert!(trace.capabilities.stack);
        assert!(trace.capabilities.memory);
        assert!(trace.capabilities.gas_details);
        assert_eq!(trace.artifacts.gas.as_ref().map(|gas| gas.used), Some(7));
        assert_eq!(trace.steps[0].op, "STOP");
    }

    #[test]
    fn debug_rpc_capabilities_reflect_returned_trace_data() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "08c379a0",
            "failed": true,
            "gas": 9,
            "structLogs": [
                {
                    "pc": 0,
                    "op": "SSTORE",
                    "gas": 100,
                    "gasCost": 3,
                    "depth": 0,
                    "stack": ["0x2a", "0x0"],
                    "storage": {"0x0": "0x2a"}
                }
            ]
        }))
        .expect("debug trace");

        let capabilities = debug_rpc_capabilities(&result);

        assert!(capabilities.opcode_steps);
        assert!(capabilities.stack);
        assert!(capabilities.memory);
        assert!(capabilities.storage);
        assert!(capabilities.storage_diff);
        assert!(capabilities.revert_data);
        assert!(capabilities.gas_details);
        assert!(capabilities.notes.is_empty());
    }

    #[test]
    fn fallback_debug_errors_do_not_override_receipt_success() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "",
            "structLogs": []
        }))
        .expect("debug trace");
        let envelope = TraceEnvelope {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 21_000,
            success: true,
            contract_address: None,
            debug_trace_available: false,
            debug_error: Some("debug_traceTransaction not available".to_owned()),
            backend: Some(TraceBackend::Auto.as_str().to_owned()),
            capabilities: TraceCapabilities::default(),
        };

        let trace = build_transaction_trace(envelope, &result);
        assert!(trace.success);
        assert_eq!(
            trace.error.as_deref(),
            Some("debug_traceTransaction not available")
        );
    }

    #[test]
    fn failed_debug_result_prefers_explicit_error() {
        let result = DebugTraceResult {
            struct_logs: Vec::<StructLog>::new(),
            return_value: String::new(),
            error: Some("bad opcode".to_owned()),
            failed: true,
            gas: None,
            artifacts: TraceArtifacts::default(),
        };

        assert_eq!(result.failure_message().as_deref(), Some("bad opcode"));
    }

    #[test]
    fn failed_debug_result_reports_raw_revert_data() {
        let result: DebugTraceResult = serde_json::from_value(json!({
            "returnValue": "deadbeef",
            "failed": true
        }))
        .expect("debug trace");

        assert_eq!(
            result.failure_message().as_deref(),
            Some("Reverted with data: 0xdeadbeef")
        );
    }

    #[test]
    fn trace_backend_names_are_stable() {
        assert_eq!(TraceBackend::Auto.as_str(), "auto");
        assert_eq!(TraceBackend::DebugRpc.as_str(), "debug-rpc");
        assert_eq!(TraceBackend::Replay.as_str(), "replay");
    }

    #[test]
    fn parses_simulation_value_quantities() {
        assert_eq!(parse_value_quantity("0").expect("zero"), "0x0");
        assert_eq!(parse_value_quantity("42").expect("decimal wei"), "0x2a");
        assert_eq!(parse_value_quantity("0x2a").expect("hex wei"), "0x2a");
        assert_eq!(
            parse_value_quantity("1ether").expect("one ether"),
            "0xde0b6b3a7640000"
        );
        assert_eq!(
            parse_value_quantity("0.1ether").expect("decimal ether"),
            "0x16345785d8a0000"
        );
        assert_eq!(
            parse_value_quantity(".5ether").expect("fractional ether"),
            "0x6f05b59d3b20000"
        );
        assert!(parse_value_quantity("0.0000000000000000001ether").is_err());
        assert!(parse_value_quantity("nope").is_err());
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn event_log(address: &str, data_suffix: &str) -> serde_json::Value {
        json!({
            "address": address,
            "topics": ["0x3cf8b50771c17d723f2cb711ca7dadde485b222e13c84ba0730a14093fad6d5c"],
            "data": format!("0x{}{}", "0".repeat(62), data_suffix),
        })
    }
}
