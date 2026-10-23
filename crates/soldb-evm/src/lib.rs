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
//! is the only part of the crate that links REVM, so a build without it keeps only the
//! data shapes and the trace assembly, for a host that does its own execution.
//!
//! `soldb-rpc` builds on this crate with the JSON-RPC transport, the networked `debug-rpc`
//! backend, and the state provider that reads a node lazily.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use soldb_core::{
    decode_hex_into, Bytes, ExecutionLog, GasSummary, HexError, SoldbError, SoldbResult, StepError,
    StepSnapshot, StepTable, StorageChange, TraceArtifacts, TraceCapabilities, TraceStep,
    TransactionTrace, Word, WordInterner,
};

#[cfg(feature = "replay")]
mod replay;

#[cfg(feature = "replay")]
pub use replay::{
    account_info_from_rpc, parse_address, parse_b256, replay_chain_support,
    replay_debug_trace_with_state, replay_prefix_with_state, replay_simulation_trace,
    replay_target_with_state, replay_transaction_trace, AccountState, LocalChain,
    PrefetchedReplayState, ReplayBundle, ReplayBundleTarget, ReplayDbError, ReplayInputs,
    ReplayPrefix, ReplayStateProvider, RpcBlockHeader, RpcBlockTransaction,
    RpcBlockWithTransactions, StateBatch, StateRequest, REPLAY_BUNDLE_VERSION,
};
#[cfg(feature = "replay")]
pub use revm::primitives::{Address, B256};
#[cfg(feature = "replay")]
pub use revm::state::AccountInfo;
pub use ruint::aliases::U256;

/// Whether the REVM replay engine was compiled into this build.
///
/// The engine sits behind the `replay` cargo feature (on by default) because it is the
/// only part of the crate that links REVM. A build without it keeps the node data shapes
/// and the trace assembly.
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
    /// The mnemonic, shared the way the stack words are.
    pub op: Word,
    pub gas: u64,
    #[serde(rename = "gasCost", default)]
    pub gas_cost: u64,
    pub depth: u64,
    /// The stack, shared word by word with every other log holding the same value; see
    /// [`soldb_core::WordInterner`].
    #[serde(default)]
    pub stack: Vec<Word>,
    /// Memory as the node reports it, in 32-byte words. Shared with the previous log when
    /// nothing changed, so a payload of hundreds of thousands of steps holds one copy per
    /// change; see [`DebugTraceResult`].
    #[serde(default)]
    pub memory: Arc<Vec<String>>,
    /// Storage as the node reports it, shared with the previous log the same way.
    #[serde(default)]
    pub storage: Arc<BTreeMap<String, String>>,
    #[serde(default)]
    pub error: Option<String>,
    /// The return data buffer before this step; `None` when the node did not report it.
    #[serde(
        rename = "returnData",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub return_data: Option<Arc<str>>,
}

/// Decodes a `structLogs` memory array into one flat byte sequence.
///
/// Nodes disagree on whether the words carry a `0x` prefix, so each word is decoded on its
/// own with or without one. The result is the same whichever backend recorded the
/// memory, which is what byte-offset lookups such as memory-located variable decoding
/// rest on.
fn joined_memory(words: &[String]) -> Result<Bytes, HexError> {
    let mut memory = Vec::with_capacity(words.iter().map(|word| word.len() / 2).sum());
    for word in words {
        decode_hex_into(word, &mut memory)?;
    }
    Ok(Bytes::from(memory))
}

impl StructLog {
    #[must_use]
    pub fn into_trace_step(self) -> TraceStep {
        self.into_trace_step_with_previous_storage(&BTreeMap::new())
    }

    /// Builds a [`TraceStep`] from a borrowed log.
    ///
    /// Prefer this when walking a whole trace: the owning version cannot be used without
    /// first cloning the log, which doubles the per-step copying for no benefit. When
    /// walking a whole trace, [`StructLog::to_trace_step_sharing`] also lets consecutive
    /// steps share unchanged memory and storage.
    #[must_use]
    pub fn to_trace_step_with_previous_storage(
        &self,
        previous_storage: &BTreeMap<String, String>,
    ) -> TraceStep {
        self.to_trace_step_sharing(previous_storage, None)
    }

    /// Builds a [`TraceStep`] that shares its memory with the previous step when this
    /// log's memory is the previous log's.
    ///
    /// `previous` is the previous log's memory and the step built from that log. Storage
    /// is shared by construction: the step takes the log's own `Arc`, which the parser or
    /// the inspector already shares between logs that did not change it. Memory has to
    /// be joined into one string, so the joined string is what gets shared here.
    #[must_use]
    pub fn to_trace_step_sharing(
        &self,
        previous_storage: &BTreeMap<String, String>,
        previous: Option<(&Arc<Vec<String>>, &TraceStep)>,
    ) -> TraceStep {
        let memory = self.shared_memory(previous);
        let storage_diff = if self.storage.is_empty() {
            BTreeMap::new()
        } else {
            storage_diff(previous_storage, &self.storage)
        };
        TraceStep::new(
            self.pc,
            Arc::clone(&self.op),
            self.gas,
            self.gas_cost,
            self.depth,
            self.error.clone(),
            StepSnapshot {
                stack: self.stack.clone(),
                memory,
                storage: self.shared_storage(previous.map(|(_, step)| step)),
                storage_diff,
                transient_storage: BTreeMap::new(),
                return_data: self.shared_return_data(previous.map(|(_, step)| step)),
            },
        )
    }

    /// The consuming form of [`StructLog::to_trace_step_sharing`]: the stack and the
    /// storage move into the step instead of being copied.
    #[must_use]
    pub fn into_trace_step_sharing(
        self,
        previous_storage: &BTreeMap<String, String>,
        previous: Option<(&Arc<Vec<String>>, &TraceStep)>,
    ) -> TraceStep {
        let memory = self.shared_memory(previous);
        let storage = self.shared_storage(previous.map(|(_, step)| step));
        let return_data = self.shared_return_data(previous.map(|(_, step)| step));
        let storage_diff = if self.storage.is_empty() {
            BTreeMap::new()
        } else {
            storage_diff(previous_storage, &self.storage)
        };
        TraceStep::new(
            self.pc,
            self.op,
            self.gas,
            self.gas_cost,
            self.depth,
            self.error,
            StepSnapshot {
                stack: self.stack,
                memory,
                storage,
                storage_diff,
                transient_storage: BTreeMap::new(),
                return_data,
            },
        )
    }

    /// The previous step's storage when it equals this log's, which is a pointer check
    /// when the logs already share it, and the log's own otherwise.
    fn shared_storage(&self, previous: Option<&TraceStep>) -> Arc<BTreeMap<String, String>> {
        match previous {
            Some(step) if step.snapshot.storage == self.storage => {
                Arc::clone(&step.snapshot.storage)
            }
            _ => Arc::clone(&self.storage),
        }
    }

    /// This log's return data as unprefixed lowercase hex, shared with the previous step's
    /// when equal; `None` when empty.
    fn shared_return_data(&self, previous: Option<&TraceStep>) -> Option<Arc<str>> {
        let reported = self.return_data.as_deref()?;
        let digits = reported
            .strip_prefix("0x")
            .or_else(|| reported.strip_prefix("0X"))
            .unwrap_or(reported);
        if digits.is_empty() {
            return None;
        }
        if let Some(shared) = previous.and_then(|step| step.snapshot.return_data.as_ref()) {
            if shared.eq_ignore_ascii_case(digits) {
                return Some(Arc::clone(shared));
            }
        }
        Some(Arc::from(digits.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn into_trace_step_with_previous_storage(
        self,
        previous_storage: &BTreeMap<String, String>,
    ) -> TraceStep {
        self.into_trace_step_sharing(previous_storage, None)
    }

    fn shared_memory(&self, previous: Option<(&Arc<Vec<String>>, &TraceStep)>) -> Option<Bytes> {
        match previous {
            Some((words, step)) if *words == self.memory && step.snapshot.memory.is_some() => {
                step.snapshot.memory.clone()
            }
            // Parsing `structLogs` rejects memory that is not hex, so only a log built by
            // hand with bad memory reaches the error, and its memory is reported as not
            // captured rather than shown as something it is not.
            _ => joined_memory(&self.memory).ok(),
        }
    }
}

/// What `debug_traceTransaction` or `debug_traceCall` returned, or what the replay engine
/// recorded in the same shape.
///
/// Reading it from JSON shares each log's memory and storage with the previous log when
/// they are equal, as it is parsed, so the payload of a large trace costs one copy per
/// change rather than one per step. [`DebugTraceResult::into_steps`] then builds the
/// steps while freeing each log, so the logs and the steps are never both whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugTraceResult {
    #[serde(
        rename = "structLogs",
        default,
        deserialize_with = "deserialize_shared_struct_logs"
    )]
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

/// Deserializes `structLogs`, sharing each log's memory and storage with the previous log
/// when they are equal. The comparison is on the values the node sent; a shared `Arc`
/// then compares by pointer everywhere downstream.
fn deserialize_shared_struct_logs<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<StructLog>, D::Error> {
    struct SharedLogs;

    impl<'de> Visitor<'de> for SharedLogs {
        type Value = Vec<StructLog>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of struct logs")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut logs = Vec::<StructLog>::with_capacity(seq.size_hint().unwrap_or(0));
            let mut decoded = Vec::new();
            while let Some(mut log) = seq.next_element::<StructLog>()? {
                let shared = match logs.last() {
                    Some(previous) => {
                        share_unchanged(previous, &mut log);
                        Arc::ptr_eq(&previous.memory, &log.memory)
                    }
                    None => false,
                };
                // A step's memory is bytes, so memory that is not hex is refused here, at
                // the edge, rather than when the steps are built. Memory shared with the
                // previous log was checked with it.
                if !shared {
                    for word in log.memory.iter() {
                        decoded.clear();
                        decode_hex_into(word, &mut decoded).map_err(|error| {
                            de::Error::custom(format!(
                                "memory of struct log {} is not hex: {error}",
                                logs.len()
                            ))
                        })?;
                    }
                }
                logs.push(log);
            }
            Ok(logs)
        }
    }

    deserializer.deserialize_seq(SharedLogs)
}

/// Points `log`'s memory and storage at `previous`'s when the values are equal.
fn share_unchanged(previous: &StructLog, log: &mut StructLog) {
    if !Arc::ptr_eq(&previous.memory, &log.memory) && *previous.memory == *log.memory {
        log.memory = Arc::clone(&previous.memory);
    }
    if !Arc::ptr_eq(&previous.storage, &log.storage) && *previous.storage == *log.storage {
        log.storage = Arc::clone(&previous.storage);
    }
    if let (Some(previous_data), Some(data)) = (&previous.return_data, &log.return_data) {
        if !Arc::ptr_eq(previous_data, data) && **previous_data == **data {
            log.return_data = Some(Arc::clone(previous_data));
        }
    }
}

/// Fills `transient_storage` on each `TLOAD` and `TSTORE` from the stack, for every backend.
fn record_transient_storage(steps: &mut [TraceStep]) {
    for index in 0..steps.len() {
        if let Some(touched) = transient_storage_of(&steps[index], steps.get(index + 1)) {
            steps[index].snapshot.transient_storage = touched;
        }
    }
}

/// The transient slot `step` reads or writes and its value after it, when it is a
/// `TLOAD` or a `TSTORE` that completed; `next` is the step after it.
fn transient_storage_of(
    step: &TraceStep,
    next: Option<&TraceStep>,
) -> Option<BTreeMap<String, String>> {
    if step.error.is_some() {
        return None;
    }
    let stack = step.snapshot_ref().stack;
    let slot = stack.last()?;
    // A `TLOAD`'s value is what it leaves on top: the next step's stack in its frame.
    let value = match &*step.op {
        "TSTORE" => stack
            .len()
            .checked_sub(2)
            .and_then(|below| stack.get(below)),
        "TLOAD" => next
            .filter(|next| next.depth == step.depth)
            .and_then(|next| next.snapshot_ref().stack.last()),
        _ => None,
    }?;
    Some(BTreeMap::from([(
        normalize_storage_key(slot),
        normalize_storage_key(value),
    )]))
}

/// Whether an opcode can leave data in its frame's return data buffer.
fn fills_return_data(op: &str) -> bool {
    matches!(
        op,
        "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" | "CREATE" | "CREATE2"
    )
}

/// A slot or word as `0x`-prefixed lowercase hex without leading zeros.
pub(crate) fn normalize_storage_key(value: &str) -> String {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{}", trimmed.to_ascii_lowercase())
    }
}

impl DebugTraceResult {
    /// Builds every step, borrowing the logs. Prefer [`DebugTraceResult::into_steps`]
    /// when the result is not needed afterwards: it frees each log as its step is built.
    #[must_use]
    pub fn steps(&self) -> Vec<TraceStep> {
        static EMPTY_STORAGE: BTreeMap<String, String> = BTreeMap::new();

        let mut previous_storage = &EMPTY_STORAGE;
        let mut previous_memory = None::<&Arc<Vec<String>>>;
        let mut steps = Vec::with_capacity(self.struct_logs.len());
        for log in &self.struct_logs {
            let previous = previous_memory.zip(steps.last());
            let step = log.to_trace_step_sharing(previous_storage, previous);
            steps.push(step);
            previous_storage = &log.storage;
            previous_memory = Some(&log.memory);
        }
        record_transient_storage(&mut steps);
        steps
    }

    /// Builds every step, consuming the logs so that each one is freed as its step is
    /// built: the logs and the steps are never both whole, which halves the peak on a
    /// large trace.
    #[must_use]
    pub fn into_steps(self) -> Vec<TraceStep> {
        let mut steps = Vec::with_capacity(self.struct_logs.len());
        // The previous log's memory and storage, kept by reference count rather than as
        // the log itself, which has moved into its step.
        let mut previous = None::<(Arc<Vec<String>>, Arc<BTreeMap<String, String>>)>;
        // Logs parsed from a node's answer carry their own copy of every stack word;
        // steps built from them share one per distinct value. A log the inspector interned
        // already passes through unchanged, at the cost of a hash lookup.
        let mut words = WordInterner::new();
        for mut log in self.struct_logs {
            words.intern_stack(&mut log.stack);
            let memory = Arc::clone(&log.memory);
            let storage = Arc::clone(&log.storage);
            let step = match &previous {
                Some((previous_memory, previous_storage)) => log.into_trace_step_sharing(
                    previous_storage,
                    steps.last().map(|step| (previous_memory, step)),
                ),
                None => log.into_trace_step_sharing(&BTreeMap::new(), None),
            };
            steps.push(step);
            previous = Some((memory, storage));
        }
        record_transient_storage(&mut steps);
        steps
    }

    /// Builds every step into a [`StepTable`], consuming the logs so that each one is
    /// freed as its step is appended: the logs, the steps and the table are never all
    /// whole at once.
    ///
    /// # Errors
    ///
    /// Returns a [`StepError`] when a stack word the node reported is not hex.
    pub fn into_step_table(self) -> Result<StepTable, StepError> {
        let mut table = StepTable::with_capacity(self.struct_logs.len());
        // The previous log's memory and storage, kept by reference count rather than as
        // the log itself, which has moved into its step.
        let mut previous = None::<(Arc<Vec<String>>, Arc<BTreeMap<String, String>>)>;
        // A step is appended once the next one is built: a `TLOAD`'s value is on the next
        // step's stack.
        let mut pending = None::<TraceStep>;
        for log in self.struct_logs {
            let memory = Arc::clone(&log.memory);
            let storage = Arc::clone(&log.storage);
            let step = match (&previous, &pending) {
                (Some((previous_memory, previous_storage)), Some(before)) => {
                    log.into_trace_step_sharing(previous_storage, Some((previous_memory, before)))
                }
                _ => log.into_trace_step_sharing(&BTreeMap::new(), None),
            };
            if let Some(mut before) = pending.take() {
                if let Some(touched) = transient_storage_of(&before, Some(&step)) {
                    before.snapshot.transient_storage = touched;
                }
                table.try_push(before)?;
            }
            pending = Some(step);
            previous = Some((memory, storage));
        }
        if let Some(mut last) = pending {
            if let Some(touched) = transient_storage_of(&last, None) {
                last.snapshot.transient_storage = touched;
            }
            table.try_push(last)?;
        }
        Ok(table)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateCallRequest {
    pub from_addr: String,
    pub to_addr: String,
    pub calldata: String,
    pub value: String,
    pub block: Option<u64>,
    pub tx_index: Option<u64>,
}

/// The one place every backend's execution becomes a trace. Takes the result by value so
/// the node's logs are freed as the steps are built.
///
/// # Errors
///
/// Returns an error when a stack word the backend reported is not hex.
pub fn build_transaction_trace(
    envelope: TraceEnvelope,
    debug_result: DebugTraceResult,
) -> SoldbResult<TransactionTrace> {
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

    Ok(TransactionTrace {
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
        steps: debug_result.into_step_table()?,
    })
}

/// Assembles the `debug-rpc` trace of a mined transaction from the node's responses to
/// `eth_getTransactionByHash`, `eth_getTransactionReceipt`, and `debug_traceTransaction`.
///
/// This is the whole of the `debug-rpc` backend once the three requests have been
/// answered, so a host that fetches them itself produces the identical trace to
/// `soldb-rpc`'s `trace_transaction_with_client`.
pub fn debug_rpc_transaction_trace(
    tx: RpcTransaction,
    receipt: RpcReceipt,
    debug_result: DebugTraceResult,
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
        capabilities: debug_rpc_capabilities(&debug_result),
    };
    let mut trace = build_transaction_trace(envelope, debug_result)?;
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
    debug_result: DebugTraceResult,
) -> SoldbResult<TransactionTrace> {
    let capabilities = debug_rpc_capabilities(&debug_result);
    simulation_trace(TraceBackend::DebugRpc, capabilities, request, debug_result)
}

/// The one place a simulated call becomes a trace, whichever backend executed it.
pub(crate) fn simulation_trace(
    backend: TraceBackend,
    capabilities: TraceCapabilities,
    request: &SimulateCallRequest,
    debug_result: DebugTraceResult,
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
        steps: debug_result.into_step_table()?,
    })
}

fn debug_rpc_capabilities(result: &DebugTraceResult) -> TraceCapabilities {
    let has_steps = !result.struct_logs.is_empty();
    let has_stack = result.struct_logs.iter().any(|log| !log.stack.is_empty());
    // Without a call or a create the buffer is empty throughout, reported or not.
    let has_return_data = result
        .struct_logs
        .iter()
        .any(|log| log.return_data.is_some())
        || !result
            .struct_logs
            .iter()
            .any(|log| fills_return_data(&log.op));
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
            let changed = !log.storage.is_empty() && *previous != *log.storage;
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
        // Read off the stack, so only as complete as the stacks the node returned.
        transient_storage: has_stack,
        return_data: has_steps && has_return_data,
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
    /// A stack as plain strings, for assertions.
    fn stack_words(stack: &[soldb_core::Word]) -> Vec<&str> {
        stack.iter().map(|word| &**word).collect()
    }

    use std::collections::BTreeMap;
    use std::sync::Arc;

    use serde_json::json;

    use soldb_core::same_buffer;

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

        let trace = debug_rpc_transaction_trace(tx, receipt, canned_debug_result()).expect("trace");

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
        assert_eq!(
            trace.steps.step(1).memory().as_deref(),
            Some(&[0xaa, 0xbb][..])
        );
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

        let trace = debug_rpc_transaction_trace(tx, receipt, canned_debug_result()).expect("trace");

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

        assert!(debug_rpc_transaction_trace(tx, receipt, canned_debug_result()).is_err());
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

        let trace = debug_rpc_simulation_trace(&request, debug_result.clone()).expect("trace");

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

        let trace = debug_rpc_simulation_trace(&request, debug_result.clone()).expect("trace");

        assert!(!trace.success);
        assert!(trace.error.is_some(), "failure must be reported");
        assert_eq!(trace.gas_used, 0);
    }

    #[test]
    fn transient_storage_is_read_off_the_stack_for_both_ways_of_building_steps() {
        // A `TSTORE` holds its slot on top and its value below; a `TLOAD`'s value is the
        // top of the next step in the same frame. Padded and unpadded words record alike,
        // and a failed or frame-ending step records nothing.
        let debug_result: DebugTraceResult = serde_json::from_value(json!({
            "structLogs": [
                {"pc": 0, "op": "TSTORE", "gas": 100, "gasCost": 100, "depth": 1,
                 "stack": ["0x0000000000000000000000000000000000000000000000000000000000000007", "0x1"]},
                {"pc": 1, "op": "TLOAD", "gas": 0, "gasCost": 100, "depth": 1, "stack": ["0x1"]},
                {"pc": 2, "op": "POP", "gas": 0, "gasCost": 2, "depth": 1, "stack": ["0x0A"]},
                {"pc": 3, "op": "TSTORE", "gas": 0, "gasCost": 0, "depth": 1, "stack": ["0x5", "0x2"], "error": "out of gas"},
                {"pc": 4, "op": "TLOAD", "gas": 0, "gasCost": 0, "depth": 1, "stack": ["0x2"]},
                {"pc": 0, "op": "STOP", "gas": 0, "gasCost": 0, "depth": 2, "stack": ["0x3"]}
            ]
        }))
        .expect("debug result");

        for steps in [debug_result.steps(), debug_result.clone().into_steps()] {
            let touched = steps
                .iter()
                .map(|step| step.snapshot.transient_storage.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                touched[0],
                BTreeMap::from([("0x1".to_owned(), "0x7".to_owned())])
            );
            assert_eq!(
                touched[1],
                BTreeMap::from([("0x1".to_owned(), "0xa".to_owned())])
            );
            assert!(touched[2].is_empty());
            assert!(touched[3].is_empty(), "a failed TSTORE wrote nothing");
            assert!(touched[4].is_empty(), "the next step is in another frame");
        }
        assert!(debug_rpc_capabilities(&debug_result).transient_storage);

        // Without stacks nothing could be read, so unrecorded slots are not claimed zero.
        let stackless: DebugTraceResult = serde_json::from_value(json!({
            "structLogs": [{"pc": 0, "op": "TSTORE", "gas": 0, "gasCost": 0, "depth": 1}]
        }))
        .expect("debug result");
        assert!(!debug_rpc_capabilities(&stackless).transient_storage);
        assert_eq!(super::normalize_storage_key("0X001A"), "0x1a");
        assert_eq!(super::normalize_storage_key("0"), "0x0");
    }

    #[test]
    fn return_data_comes_from_the_node_and_is_claimed_only_when_reported() {
        let debug_result: DebugTraceResult = serde_json::from_value(json!({
            "structLogs": [
                {"pc": 0, "op": "STATICCALL", "gas": 0, "gasCost": 0, "depth": 1, "returnData": "0x"},
                {"pc": 0, "op": "STOP", "gas": 0, "gasCost": 0, "depth": 2, "returnData": "0x"},
                {"pc": 1, "op": "RETURNDATASIZE", "gas": 0, "gasCost": 2, "depth": 1, "returnData": "0x002A"},
                {"pc": 2, "op": "POP", "gas": 0, "gasCost": 2, "depth": 1, "returnData": "0x002A"}
            ]
        }))
        .expect("debug result");

        for steps in [debug_result.steps(), debug_result.clone().into_steps()] {
            assert_eq!(
                steps[0].snapshot.return_data, None,
                "an empty buffer is None"
            );
            assert_eq!(steps[2].snapshot_ref().return_data, Some("002a"));
            let shared = |index: usize| steps[index].snapshot.return_data.as_ref().expect("data");
            assert!(Arc::ptr_eq(shared(2), shared(3)));
        }
        assert!(debug_rpc_capabilities(&debug_result).return_data);

        // A call the node said nothing about leaves the buffer unknown; with no call at
        // all it is empty throughout.
        let unreported = |op: &str| -> DebugTraceResult {
            serde_json::from_value(json!({
                "structLogs": [{"pc": 0, "op": op, "gas": 0, "gasCost": 0, "depth": 1}]
            }))
            .expect("debug result")
        };
        assert!(!debug_rpc_capabilities(&unreported("CALL")).return_data);
        assert!(debug_rpc_capabilities(&unreported("ADD")).return_data);
    }

    #[test]
    fn storage_diff_capability_matches_the_materialized_steps() {
        // `debug_rpc_capabilities` reads the storage-diff flag off the raw logs instead of
        // building every step. Pin it against the definition it replaces.
        let log = |storage: &[(&str, &str)]| StructLog {
            pc: 0,
            op: "SSTORE".into(),
            gas: 0,
            gas_cost: 0,
            depth: 0,
            stack: Vec::new(),
            memory: Arc::default(),
            storage: Arc::new(
                storage
                    .iter()
                    .map(|(slot, value)| ((*slot).to_owned(), (*value).to_owned()))
                    .collect(),
            ),
            error: None,
            return_data: None,
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
    fn consecutive_steps_share_unchanged_memory_and_storage() {
        let log = |op: &str, memory: &[&str], slot_value: &str| StructLog {
            pc: 0,
            op: op.into(),
            gas: 0,
            gas_cost: 0,
            depth: 1,
            stack: Vec::new(),
            memory: Arc::new(memory.iter().map(|word| (*word).to_owned()).collect()),
            storage: Arc::new(BTreeMap::from([("0x0".to_owned(), slot_value.to_owned())])),
            error: None,
            return_data: None,
        };
        let result = DebugTraceResult {
            struct_logs: vec![
                log("PUSH1", &["aa"], "0x1"),
                log("PUSH1", &["aa"], "0x1"),
                log("MSTORE", &["aa", "bb"], "0x1"),
                log("SSTORE", &["aa", "bb"], "0x2"),
            ],
            return_value: String::new(),
            error: None,
            failed: false,
            gas: None,
            artifacts: Default::default(),
        };
        let steps = result.steps();
        // Nothing changed between the first two steps: one copy of memory and storage.
        assert!(Arc::ptr_eq(
            &steps[0].snapshot.storage,
            &steps[1].snapshot.storage
        ));
        assert!(same_buffer(
            steps[0].snapshot.memory.as_ref().expect("memory"),
            steps[1].snapshot.memory.as_ref().expect("memory")
        ));
        // Memory changed at step 2, storage at step 3; each got its own copy, and the
        // values are what the log said.
        assert!(!same_buffer(
            steps[1].snapshot.memory.as_ref().expect("memory"),
            steps[2].snapshot.memory.as_ref().expect("memory")
        ));
        assert!(Arc::ptr_eq(
            &steps[1].snapshot.storage,
            &steps[2].snapshot.storage
        ));
        assert!(!Arc::ptr_eq(
            &steps[2].snapshot.storage,
            &steps[3].snapshot.storage
        ));
        assert_eq!(steps[2].snapshot_ref().memory, Some(&[0xaa, 0xbb][..]));
        assert_eq!(steps[3].snapshot_ref().storage["0x0"], "0x2");
        assert_eq!(
            steps[3].snapshot_ref().storage_diff["0x0"].after.as_deref(),
            Some("0x2")
        );
        // The flat fields stay empty: the state is stored once.
        assert!(steps
            .iter()
            .all(|step| step.stack.is_empty() && step.memory.is_none() && step.storage.is_none()));
        // Consuming the logs builds the same steps with the same sharing.
        let consumed = result.clone().into_steps();
        assert_eq!(consumed, steps);
        assert!(Arc::ptr_eq(
            &consumed[0].snapshot.storage,
            &consumed[1].snapshot.storage
        ));
        assert!(same_buffer(
            consumed[0].snapshot.memory.as_ref().expect("memory"),
            consumed[1].snapshot.memory.as_ref().expect("memory")
        ));
        // Parsing the node's payload shares as it reads, so the logs themselves hold one
        // copy of unchanged memory and storage.
        let json = serde_json::to_string(&result).expect("json");
        let parsed: DebugTraceResult = serde_json::from_str(&json).expect("result");
        assert_eq!(parsed, result);
        assert!(Arc::ptr_eq(
            &parsed.struct_logs[0].memory,
            &parsed.struct_logs[1].memory
        ));
        assert!(Arc::ptr_eq(
            &parsed.struct_logs[0].storage,
            &parsed.struct_logs[2].storage
        ));
        assert!(!Arc::ptr_eq(
            &parsed.struct_logs[1].memory,
            &parsed.struct_logs[2].memory
        ));
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
        // Memory words are decoded into one byte sequence whether or not the node prefixed
        // them, so byte-offset lookups stay valid and both backends agree.
        assert_eq!(steps[0].snapshot_ref().memory, Some(&[0xaa, 0xbb][..]));
        assert_eq!(steps[0].snapshot_ref().storage["0x00"], "0x2a");
        assert_eq!(stack_words(&steps[0].snapshot.stack), ["0x01"]);
        assert_eq!(steps[0].snapshot.memory.as_deref(), Some(&[0xaa, 0xbb][..]));
        // A trace file still spells it as one unprefixed hex string.
        assert_eq!(
            serde_json::to_value(&steps[0]).expect("json")["snapshot"]["memory"],
            "aabb"
        );
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

        let trace = build_transaction_trace(envelope, result.clone()).expect("trace");
        assert!(trace.success);
        assert_eq!(trace.output, "0x");
        assert_eq!(trace.backend.as_deref(), Some("debug-rpc"));
        assert!(trace.capabilities.opcode_steps);
        assert!(trace.capabilities.stack);
        assert!(trace.capabilities.memory);
        assert!(trace.capabilities.gas_details);
        assert_eq!(trace.artifacts.gas.as_ref().map(|gas| gas.used), Some(7));
        assert_eq!(trace.steps.step(0).mnemonic(), "STOP");
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

        let trace = build_transaction_trace(envelope, result.clone()).expect("trace");
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

    #[test]
    fn struct_log_memory_that_is_not_hex_is_refused() {
        let parsed = serde_json::from_value::<DebugTraceResult>(json!({
            "structLogs": [
                {"pc": 0, "op": "PUSH1", "gas": 1, "depth": 1, "memory": ["aa"]},
                {"pc": 2, "op": "MSTORE", "gas": 1, "depth": 1, "memory": ["aa", "0xzz"]}
            ]
        }));
        let error = parsed.expect_err("memory is not hex").to_string();
        assert_eq!(
            error,
            "memory of struct log 1 is not hex: `z` at offset 0 is not a hex digit"
        );
    }
}
