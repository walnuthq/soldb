//! The `replay` engine: re-executing a transaction in REVM over supplied state.
//!
//! The node stays the execution oracle. The caller reads the accounts, storage, and block
//! hashes the transaction touches at the parent block, and we re-execute any
//! earlier transactions in the same block so the target sees the state it saw on chain,
//! and then run the target through REVM with inspectors that record every step, call,
//! creation, log, and account change. The result is the same
//! [`soldb_core::TransactionTrace`] the `debug-rpc` backend produces, built through the
//! same [`build_transaction_trace`] so the two stay in lockstep.
//!
//! Execution is split from I/O. [`ReplayInputs`] holds what the node has to say about
//! the transaction and its block, and [`replay_debug_trace_with_state`] runs REVM over
//! any [`ReplayStateProvider`]. The native backend in `soldb-rpc` fetches the inputs and
//! reads state lazily over RPC; a WebAssembly host, which cannot block on the network,
//! supplies state up front through [`PrefetchedReplayState`] and repeats the run until
//! nothing is missing; `soldb run` describes a [`LocalChain`] and needs no node at all.
//!
//! Execution itself has two phases. [`replay_prefix_with_state`] runs the transactions
//! before the target and returns the state they leave behind as a [`ReplayPrefix`];
//! [`replay_target_with_state`] runs the target over it. A host that repeats runs keeps
//! the prefix once it ran with nothing missing, so later rounds cost only the target.
//!
//! This module is the only part of the crate that links REVM, which is why it sits
//! behind the `replay` cargo feature.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;

use revm::bytecode::opcode::OpCode;
use revm::context::{BlockEnv, CfgEnv, ContextTr, Journal, JournalEntry, JournalTr, TxEnv};
use revm::database::{Cache, CacheDB, WrapDatabaseRef};
use revm::database_interface::DBErrorMarker;
use revm::inspector::inspectors::GasInspector;
use revm::inspector::JournalExt;
use revm::interpreter::interpreter_types::{Jumps, LoopControl, MemoryTr};
use revm::interpreter::{
    CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, Interpreter,
};
use revm::primitives::{hardfork::SpecId, Address, Bytes, TxKind, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::{
    Context, DatabaseRef, ExecuteCommitEvm, InspectEvm, Inspector, MainBuilder, MainContext,
};
use serde::{Deserialize, Serialize};

use soldb_core::{
    AccountChange, ContractCreation, ExecutionCall, ExecutionLog, GasSummary, SoldbError,
    SoldbResult, TraceArtifacts, TraceCapabilities, TransactionTrace, WordInterner,
};

use crate::{
    build_transaction_trace, bytes_to_hex, decode_revert_reason, format_quantity,
    format_u256_quantity, hex_to_bytes, normalize_hex_output, parse_quantity, parse_u256_quantity,
    parse_value_quantity, quantity_is_one, DebugTraceResult, RpcReceipt, RpcTransaction,
    SimulateCallRequest, StructLog, TraceBackend, TraceEnvelope,
};

/// The header fields of an `eth_getBlockByNumber` response that replay reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcBlockHeader {
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    pub timestamp: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: String,
    #[serde(default, rename = "baseFeePerGas")]
    pub base_fee_per_gas: Option<String>,
    #[serde(default)]
    pub difficulty: Option<String>,
    #[serde(default, rename = "mixHash")]
    pub mix_hash: Option<String>,
    #[serde(default, rename = "prevRandao")]
    pub prevrandao: Option<String>,
    #[serde(default)]
    pub miner: Option<String>,
    #[serde(default)]
    pub beneficiary: Option<String>,
}

/// An `eth_getBlockByNumber(number, true)` response: the header plus every transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcBlockWithTransactions {
    #[serde(flatten)]
    pub header: RpcBlockHeader,
    #[serde(default)]
    pub transactions: Vec<RpcBlockTransaction>,
}

/// A block's transaction as the node returned it: in full, or as a bare hash when the
/// block was requested without transaction objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcBlockTransaction {
    Full(Box<RpcTransaction>),
    Hash(String),
}

fn replay_capabilities(chain_id: u64) -> TraceCapabilities {
    TraceCapabilities {
        opcode_steps: true,
        stack: true,
        memory: true,
        storage: true,
        storage_diff: true,
        call_trace: true,
        contract_creation: true,
        logs: true,
        revert_data: true,
        gas_details: true,
        account_changes: true,
        notes: replay_chain_support(chain_id).unwrap_or_default(),
    }
}

/// How the engine relates to a chain.
///
/// `Ok(notes)` means the chain executes under the rules the engine implements, with
/// `notes` naming anything a user should know: a chain it knows only as EVM-equivalent
/// runs under Ethereum rules at the latest fork, so fee and gas accounting and
/// chain-specific precompiles are not modelled. `Err` names a chain whose execution
/// itself differs from the EVM the engine implements, which a replay would get wrong
/// silently; the node's own tracer is the honest tool there.
pub fn replay_chain_support(chain_id: u64) -> Result<Vec<String>, String> {
    if let Some((name, reason)) = unmodelled_chain(chain_id) {
        return Err(format!(
            "the replay backend does not model {name} (chain id {chain_id}): {reason}; use `--backend debug-rpc` against a node that can trace"
        ));
    }
    if MODELLED_CHAINS.contains(&chain_id) {
        return Ok(Vec::new());
    }
    Ok(vec![match evm_equivalent_chain(chain_id) {
        Some(name) => format!(
            "{name} (chain id {chain_id}) is replayed with Ethereum mainnet rules at the latest fork; its fee and gas accounting and chain-specific precompiles are not modelled, so gas figures may differ from the node"
        ),
        None => format!(
            "chain id {chain_id} is not known to the replay engine; it is replayed with Ethereum mainnet rules at the latest fork"
        ),
    }])
}

/// Chains whose fork schedule the engine selects exactly: Ethereum, its testnets, and
/// the development chains.
const MODELLED_CHAINS: [u64; 6] = [1, 11_155_111, 17_000, 560_048, 1_337, 31_337];

/// Chains that execute EVM bytecode under Ethereum rules but account for gas and fees
/// differently or add precompiles.
fn evm_equivalent_chain(chain_id: u64) -> Option<&'static str> {
    Some(match chain_id {
        10 => "OP Mainnet",
        11_155_420 => "OP Sepolia",
        8_453 => "Base",
        84_532 => "Base Sepolia",
        7_777_777 => "Zora",
        34_443 => "Mode",
        81_457 => "Blast",
        5_000 => "Mantle",
        56 => "BNB Smart Chain",
        97 => "BNB Smart Chain Testnet",
        137 => "Polygon PoS",
        80_002 => "Polygon Amoy",
        43_114 => "Avalanche C-Chain",
        43_113 => "Avalanche Fuji",
        100 => "Gnosis",
        10_200 => "Gnosis Chiado",
        59_144 => "Linea",
        59_141 => "Linea Sepolia",
        534_352 => "Scroll",
        534_351 => "Scroll Sepolia",
        42_220 => "Celo",
        _ => return None,
    })
}

/// Chains whose execution the engine cannot reproduce: different bytecode, opcodes, or
/// precompile behaviour that a replay would get wrong without noticing.
fn unmodelled_chain(chain_id: u64) -> Option<(&'static str, &'static str)> {
    const ARBITRUM: &str = "ArbOS adds precompiles and changes gas and some opcode semantics";
    const ZKSYNC: &str = "it does not execute EVM bytecode";
    const ZKEVM: &str = "its zkEVM diverges from the EVM in opcodes and precompiles";
    Some(match chain_id {
        42_161 => ("Arbitrum One", ARBITRUM),
        42_170 => ("Arbitrum Nova", ARBITRUM),
        421_614 => ("Arbitrum Sepolia", ARBITRUM),
        324 => ("zkSync Era", ZKSYNC),
        300 => ("zkSync Era Sepolia", ZKSYNC),
        1_101 => ("Polygon zkEVM", ZKEVM),
        2_442 => ("Polygon zkEVM Cardona", ZKEVM),
        _ => return None,
    })
}

/// Assembles the `replay` trace of a mined transaction from its RPC transaction, its
/// receipt, and the replayed execution.
///
/// This is the replay counterpart of [`crate::debug_rpc_transaction_trace`]: the same
/// inputs produce the same trace whether the state was read over RPC or supplied by a
/// host through [`PrefetchedReplayState`].
pub fn replay_transaction_trace(
    tx: RpcTransaction,
    receipt: RpcReceipt,
    debug_result: DebugTraceResult,
    chain_id: u64,
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
        backend: Some(TraceBackend::Replay.as_str().to_owned()),
        capabilities: replay_capabilities(chain_id),
    };
    Ok(build_transaction_trace(envelope, debug_result))
}

/// Assembles the trace of a simulated call replayed locally; the replay counterpart of
/// [`crate::debug_rpc_simulation_trace`].
pub fn replay_simulation_trace(
    request: &SimulateCallRequest,
    debug_result: DebugTraceResult,
    chain_id: u64,
) -> SoldbResult<TransactionTrace> {
    crate::simulation_trace(
        TraceBackend::Replay,
        replay_capabilities(chain_id),
        request,
        debug_result,
    )
}

/// What a replay needs from the node besides state: the transaction, the block it was
/// mined in with every transaction in full, and the chain id.
///
/// Gathering these first is what lets [`replay_debug_trace_with_state`] run without a
/// client. The native backend fills them over RPC; a WebAssembly host fetches the same
/// three responses itself and builds them with [`ReplayInputs::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayInputs {
    transaction: RpcTransaction,
    header: RpcBlockHeader,
    transactions: Vec<RpcTransaction>,
    target_index: usize,
    block_number: u64,
    /// The block whose state the replay starts from: the parent for a mined transaction
    /// or a call placed inside a block, the block itself for a call on top of it.
    state_block: u64,
    chain_id: u64,
    /// True for a simulated call rather than a mined transaction, which relaxes the
    /// nonce check the way `eth_call` does.
    simulation: bool,
}

impl ReplayInputs {
    /// Validates that the transaction is mined past the genesis block and sits in the
    /// block it names, which must carry full transaction objects.
    pub fn new(
        transaction: RpcTransaction,
        block: RpcBlockWithTransactions,
        chain_id: u64,
    ) -> SoldbResult<Self> {
        let block_number = Self::mined_block_number(&transaction)?;
        let expected_index = transaction
            .transaction_index
            .as_deref()
            .map(parse_quantity)
            .transpose()?
            .unwrap_or(0) as usize;
        let transactions = replay_full_block_transactions(block_number, &block.transactions)?;
        let target_index = replay_target_index(&transactions, expected_index, &transaction.hash)?;
        Ok(Self {
            transaction,
            header: block.header,
            transactions,
            target_index,
            block_number,
            state_block: block_number - 1,
            chain_id,
            simulation: false,
        })
    }

    /// Inputs for simulating a call against the chain as it stood at `block_number`,
    /// the way `eth_call` and `debug_traceCall` would see it.
    ///
    /// With `request.tx_index` set, the call runs inside the block at that position:
    /// state comes from the parent and the transactions before the index run first, so
    /// the block must carry full transaction objects. Without it the call runs on top
    /// of the block's final state and nothing runs first. The call is a synthetic legacy
    /// transaction with a zero gas price and the block's gas limit; its nonce is not
    /// checked.
    pub fn for_call(
        request: &SimulateCallRequest,
        block: RpcBlockWithTransactions,
        block_number: u64,
        chain_id: u64,
    ) -> SoldbResult<Self> {
        let (transactions, target_index, state_block) = match request.tx_index {
            Some(index) => {
                if block_number == 0 {
                    return Err(SoldbError::Message(
                        "Replay backend cannot use parent state for block 0".to_owned(),
                    ));
                }
                let index = index as usize;
                let transactions =
                    replay_full_block_transactions(block_number, &block.transactions)?;
                if index > transactions.len() {
                    return Err(SoldbError::Message(format!(
                        "block {block_number} has {} transactions; cannot simulate at index {index}",
                        transactions.len()
                    )));
                }
                let prefix = transactions.into_iter().take(index).collect::<Vec<_>>();
                (prefix, index, block_number - 1)
            }
            None => (Vec::new(), 0, block_number),
        };
        let gas_limit = parse_quantity(&block.header.gas_limit).unwrap_or(30_000_000);
        let transaction = RpcTransaction {
            hash: String::new(),
            from_addr: request.from_addr.clone(),
            to: Some(request.to_addr.clone()),
            value: parse_value_quantity(&request.value)?,
            input_data: normalize_hex_output(&request.calldata),
            gas: Some(format_quantity(gas_limit)),
            gas_price: Some("0x0".to_owned()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
            block_number: Some(format_quantity(block_number)),
            transaction_index: Some(format_quantity(target_index as u64)),
            transaction_type: Some("0x0".to_owned()),
            chain_id: Some(format_quantity(chain_id)),
        };
        Ok(Self {
            transaction,
            header: block.header,
            transactions,
            target_index,
            block_number,
            state_block,
            chain_id,
            simulation: true,
        })
    }

    /// The block a mined transaction sits in. A pending transaction has none, and block
    /// 0 has no parent state to start from, so both are rejected.
    pub fn mined_block_number(transaction: &RpcTransaction) -> SoldbResult<u64> {
        let block_number = transaction
            .block_number
            .as_deref()
            .ok_or_else(|| {
                SoldbError::Message("Replay backend requires a mined transaction".to_owned())
            })
            .and_then(parse_quantity)?;
        if block_number == 0 {
            return Err(SoldbError::Message(
                "Replay backend cannot use parent state for block 0".to_owned(),
            ));
        }
        Ok(block_number)
    }

    /// The block as a replay needs it: the header, and in full the transactions the
    /// replay runs. For a mined transaction that is everything up to and including the
    /// target; for a call, only what runs before it.
    #[must_use]
    pub fn block(&self) -> RpcBlockWithTransactions {
        RpcBlockWithTransactions {
            header: self.header.clone(),
            transactions: self
                .transactions
                .iter()
                .map(|transaction| RpcBlockTransaction::Full(Box::new(transaction.clone())))
                .collect(),
        }
    }

    /// The block whose state the replay starts from, as an RPC block tag.
    #[must_use]
    pub fn parent_block_tag(&self) -> String {
        format_quantity(self.state_block)
    }

    #[must_use]
    pub fn transaction(&self) -> &RpcTransaction {
        &self.transaction
    }

    #[must_use]
    pub fn header(&self) -> &RpcBlockHeader {
        &self.header
    }

    /// The block's transactions up to and including the target for a mined
    /// transaction; only the ones that run first for a simulated call.
    #[must_use]
    pub fn transactions(&self) -> &[RpcTransaction] {
        &self.transactions
    }

    #[must_use]
    pub fn target_index(&self) -> usize {
        self.target_index
    }

    #[must_use]
    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Whether the target is a simulated call rather than a mined transaction.
    #[must_use]
    pub fn is_simulation(&self) -> bool {
        self.simulation
    }

    /// The accounts every replay reads before executing a single opcode: senders and
    /// recipients of the target transaction and of every transaction that runs before it
    /// in the block, and the block's fee recipient. A host that fetches them up front
    /// saves one round per transaction.
    pub fn participants(&self) -> SoldbResult<Vec<Address>> {
        let mut participants = Vec::new();
        let prefix = self.transactions.iter().take(self.target_index);
        for transaction in prefix.chain(std::iter::once(&self.transaction)) {
            participants.push(parse_address(&transaction.from_addr)?);
            if let Some(to) = transaction.to.as_deref() {
                participants.push(parse_address(to)?);
            }
        }
        participants.push(self.beneficiary());
        Ok(participants)
    }

    /// The block's fee recipient as REVM sees it, defaulting to the zero address like
    /// the block environment does when the header names none.
    fn beneficiary(&self) -> Address {
        self.header
            .beneficiary
            .as_deref()
            .or(self.header.miner.as_deref())
            .and_then(|address| parse_address(address).ok())
            .unwrap_or(Address::ZERO)
    }
}

/// A chain that exists only for one run.
///
/// `soldb run` debugs bytecode with no node: the contract, the caller, and the block are
/// described here, [`PrefetchedReplayState`] answers from them, and the replay engine
/// executes. Everything a node would supply is synthetic, so the trace is exactly as real
/// as the state given, and accounts not described are empty, as on a fresh chain.
#[derive(Debug, Clone)]
pub struct LocalChain {
    chain_id: u64,
    block_number: u64,
    timestamp: u64,
    gas_limit: u64,
    state: StateBatch,
}

impl Default for LocalChain {
    fn default() -> Self {
        Self {
            chain_id: 31_337,
            block_number: 1,
            timestamp: 0,
            gas_limit: 30_000_000,
            state: StateBatch::default(),
        }
    }
}

impl LocalChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The chain id, which selects the hardfork rules together with the block.
    #[must_use]
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// The block the run happens in; it must be past genesis so a deployment has a
    /// parent state to start from.
    #[must_use]
    pub fn with_block_number(mut self, block_number: u64) -> Self {
        self.block_number = block_number.max(1);
        self
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    #[must_use]
    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Puts an account on the chain. `balance` takes the forms `soldb simulate --value`
    /// does, `code` is hex and may be empty.
    pub fn with_account(
        mut self,
        address: &str,
        balance: &str,
        nonce: u64,
        code: &str,
    ) -> SoldbResult<Self> {
        let address = address_hex(parse_address(address)?);
        self.state.accounts.insert(
            address,
            AccountState {
                balance: parse_value_quantity(balance)?,
                nonce: format_quantity(nonce),
                code: normalize_hex_output(code),
            },
        );
        Ok(self)
    }

    /// Sets a storage slot on an account before the run.
    pub fn with_storage(mut self, address: &str, slot: &str, value: &str) -> SoldbResult<Self> {
        let address = address_hex(parse_address(address)?);
        let slot = format_u256_quantity(parse_u256_quantity(slot)?);
        let value = format_u256_quantity(parse_u256_quantity(value)?);
        self.state
            .storage
            .entry(address)
            .or_default()
            .insert(slot, value);
        Ok(self)
    }

    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// The address a deployment from `from` at `nonce` creates, as `CREATE` computes it.
    pub fn created_address(from: &str, nonce: u64) -> SoldbResult<String> {
        Ok(address_hex(parse_address(from)?.create(nonce)))
    }

    /// A transaction that deploys `init_code` from `from`, the way `eth_sendTransaction`
    /// without `to` would: zero gas price, the block's gas limit.
    pub fn deployment(
        &self,
        from: &str,
        init_code: &str,
        value: &str,
        nonce: u64,
    ) -> SoldbResult<RpcTransaction> {
        parse_address(from)?;
        Ok(RpcTransaction {
            hash: format!("0xlocal-deployment-{nonce}"),
            from_addr: from.to_owned(),
            to: None,
            value: parse_value_quantity(value)?,
            input_data: normalize_hex_output(init_code),
            gas: Some(format_quantity(self.gas_limit)),
            gas_price: Some("0x0".to_owned()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: Some(format_quantity(nonce)),
            block_number: Some(format_quantity(self.block_number)),
            transaction_index: Some("0x0".to_owned()),
            transaction_type: Some("0x0".to_owned()),
            chain_id: Some(format_quantity(self.chain_id)),
        })
    }

    /// Traces a deployment: the constructor's execution. The trace's `contract_address`
    /// is the created address and its `output` the runtime code the constructor returned.
    pub fn deploy(&self, deployment: &RpcTransaction) -> SoldbResult<TransactionTrace> {
        let block = self.block(std::slice::from_ref(deployment));
        let inputs = ReplayInputs::new(deployment.clone(), block, self.chain_id)?;
        let state = self.state()?;
        let result = replay_debug_trace_with_state(&inputs, &state)?;
        let nonce = deployment
            .nonce
            .as_deref()
            .map(parse_quantity)
            .transpose()?
            .unwrap_or(0);
        let receipt = RpcReceipt {
            gas_used: format_quantity(result.gas.unwrap_or(0)),
            status: Some(if result.failed { "0x0" } else { "0x1" }.to_owned()),
            contract_address: Some(Self::created_address(&deployment.from_addr, nonce)?),
            logs: Vec::new(),
        };
        let mut trace =
            replay_transaction_trace(deployment.clone(), receipt, result, self.chain_id)?;
        // Nothing was mined, so there is no hash to report.
        trace.tx_hash = None;
        Ok(trace)
    }

    /// Simulates `request` after `prefix` ran in the same block. A caller that deployed
    /// first passes the deployment as the prefix, so the constructor's state is what the
    /// call sees.
    pub fn call(
        &self,
        prefix: &[RpcTransaction],
        request: &SimulateCallRequest,
    ) -> SoldbResult<TransactionTrace> {
        let mut request = request.clone();
        request.block = Some(self.block_number);
        request.tx_index = (!prefix.is_empty()).then_some(prefix.len() as u64);
        let inputs = ReplayInputs::for_call(
            &request,
            self.block(prefix),
            self.block_number,
            self.chain_id,
        )?;
        let state = self.state()?;
        let result = replay_debug_trace_with_state(&inputs, &state)?;
        replay_simulation_trace(&request, result, self.chain_id)
    }

    /// The synthetic block the run happens in, carrying `transactions` in full.
    #[must_use]
    pub fn block(&self, transactions: &[RpcTransaction]) -> RpcBlockWithTransactions {
        RpcBlockWithTransactions {
            header: RpcBlockHeader {
                hash: Some(format!("0x{}", "11".repeat(32))),
                number: Some(format_quantity(self.block_number)),
                timestamp: format_quantity(self.timestamp),
                gas_limit: format_quantity(self.gas_limit),
                base_fee_per_gas: Some("0x0".to_owned()),
                difficulty: None,
                mix_hash: Some(format!("0x{}", "00".repeat(32))),
                prevrandao: None,
                miner: None,
                beneficiary: None,
            },
            transactions: transactions
                .iter()
                .cloned()
                .map(|transaction| RpcBlockTransaction::Full(Box::new(transaction)))
                .collect(),
        }
    }

    /// The state provider for the described accounts; anything else reads as empty.
    pub fn state(&self) -> SoldbResult<PrefetchedReplayState> {
        let mut state = PrefetchedReplayState::default();
        state.provide(&self.state)?;
        Ok(state)
    }
}

/// Re-executes the block prefix and the target transaction in REVM over `provider` and
/// records the target's execution as a `debug_traceTransaction`-shaped result.
///
/// Nothing here talks to a node: state comes from the provider, everything else from
/// `inputs`. With an [`RpcReplayStateProvider`] this is the native backend; with a
/// [`PrefetchedReplayState`] a host runs it repeatedly until the provider records no
/// missing state, at which point every value the run used was real. It is
/// [`replay_prefix_with_state`] followed by [`replay_target_with_state`].
pub fn replay_debug_trace_with_state<P: ReplayStateProvider>(
    inputs: &ReplayInputs,
    provider: &P,
) -> SoldbResult<DebugTraceResult> {
    let prefix = replay_prefix_with_state(inputs, provider)?;
    replay_target_with_state(inputs, &prefix, provider)
}

/// The state the transactions before the target leave behind, ready to run the target
/// over.
///
/// It holds only what the prefix loaded and wrote, so it is small, and it is plain data:
/// a host keeps it between rounds and rehydrates it over whatever the provider holds
/// now. That is sound once the prefix ran with nothing missing, because everything the
/// prefix read was real and real values do not change; a prefix that read defaults must
/// be discarded and run again.
#[derive(Debug, Clone)]
pub struct ReplayPrefix {
    cache: Cache,
}

type ReplayCacheDb<'a, P> = CacheDB<WrapDatabaseRef<ReplayStateDb<'a, P>>>;

type ReplayContext<'a, P> =
    Context<BlockEnv, TxEnv, CfgEnv, ReplayCacheDb<'a, P>, Journal<ReplayCacheDb<'a, P>>>;

/// Runs every transaction before the target, committing each, and returns the state
/// they leave behind. A target at index zero has an empty prefix and runs nothing.
pub fn replay_prefix_with_state<P: ReplayStateProvider>(
    inputs: &ReplayInputs,
    provider: &P,
) -> SoldbResult<ReplayPrefix> {
    replay_chain_support(inputs.chain_id).map_err(SoldbError::Message)?;
    let cache_db = CacheDB::new(WrapDatabaseRef(ReplayStateDb::new(provider)));
    if inputs.target_index == 0 {
        return Ok(ReplayPrefix {
            cache: cache_db.cache,
        });
    }

    let context = replay_context(inputs, cache_db);
    let mut evm = context.build_mainnet();
    for (index, prior_tx) in inputs
        .transactions
        .iter()
        .take(inputs.target_index)
        .enumerate()
    {
        let tx_env = tx_env_from_rpc_transaction(prior_tx, inputs.chain_id)?;
        evm.transact_commit(tx_env).map_err(|error| {
            SoldbError::Message(format!(
                "Replay backend failed while replaying prior block transaction {index} ({}): {error:?}",
                prior_tx.hash
            ))
        })?;
    }
    Ok(ReplayPrefix {
        cache: evm.ctx.journaled_state.database.cache,
    })
}

/// Runs the target transaction over `prefix` with the step inspector attached and
/// records its execution as a `debug_traceTransaction`-shaped result.
pub fn replay_target_with_state<P: ReplayStateProvider>(
    inputs: &ReplayInputs,
    prefix: &ReplayPrefix,
    provider: &P,
) -> SoldbResult<DebugTraceResult> {
    let cache_db = CacheDB {
        cache: prefix.cache.clone(),
        db: WrapDatabaseRef(ReplayStateDb::new(provider)),
    };
    let context = replay_context(inputs, cache_db);

    let tx_env = tx_env_from_rpc_transaction(&inputs.transaction, inputs.chain_id)?;
    let mut inspector = ReplayStepInspector::default();
    let mut evm = context.build_mainnet_with_inspector(&mut inspector);
    let result = evm.inspect_one_tx(tx_env).map_err(|error| {
        SoldbError::Message(format!("Replay backend execution failed: {error:?}"))
    })?;

    let return_value = result
        .output()
        .map_or_else(String::new, |output| bytes_to_hex(output.as_ref()));
    let error = match &result {
        revm::context::result::ExecutionResult::Success { .. } => None,
        revm::context::result::ExecutionResult::Revert { output, .. } => {
            let encoded = bytes_to_hex(output.as_ref());
            decode_revert_reason(&encoded)
                .or_else(|| Some(format!("Reverted with data: 0x{encoded}")))
        }
        revm::context::result::ExecutionResult::Halt { reason, .. } => Some(format!("{reason:?}")),
    };
    let (struct_logs, mut artifacts) = inspector.into_parts();
    if artifacts.logs.is_empty() {
        artifacts.logs = result
            .logs()
            .iter()
            .enumerate()
            .map(|(index, log)| log_artifact(index, 0, log))
            .collect();
    }
    artifacts.gas = Some(gas_summary_from_result(&result));
    if !result.is_success() && !return_value.is_empty() {
        artifacts.revert_data = Some(bytes_to_prefixed_hex(
            result
                .output()
                .map_or([].as_slice(), |output| output.as_ref()),
        ));
    }

    Ok(DebugTraceResult {
        struct_logs,
        return_value,
        error,
        failed: !result.is_success(),
        gas: Some(result.gas_used()),
        artifacts,
    })
}

/// The block and chain configuration both phases execute under.
fn replay_context<'a, P: ReplayStateProvider>(
    inputs: &ReplayInputs,
    cache_db: ReplayCacheDb<'a, P>,
) -> ReplayContext<'a, P> {
    let block = &inputs.header;
    let block_number = inputs.block_number;
    let chain_id = inputs.chain_id;
    let block_timestamp = parse_quantity(&block.timestamp).unwrap_or(0);
    let spec = replay_spec_for_chain(chain_id, block_number, block_timestamp);

    Context::mainnet()
        .with_db(cache_db)
        .modify_block_chained(|block_env| {
            block_env.number = U256::from(block_number);
            block_env.timestamp = U256::from(block_timestamp);
            block_env.gas_limit = parse_quantity(&block.gas_limit).unwrap_or(u64::MAX);
            block_env.basefee = block
                .base_fee_per_gas
                .as_deref()
                .map(parse_quantity)
                .transpose()
                .unwrap_or(None)
                .unwrap_or_default();
            block_env.difficulty = block
                .difficulty
                .as_deref()
                .map(parse_u256_quantity)
                .transpose()
                .unwrap_or(None)
                .unwrap_or_default();
            block_env.prevrandao = block
                .prevrandao
                .as_deref()
                .or(block.mix_hash.as_deref())
                .map(parse_b256)
                .transpose()
                .unwrap_or(None);
            block_env.beneficiary = block
                .beneficiary
                .as_deref()
                .or(block.miner.as_deref())
                .map(parse_address)
                .transpose()
                .unwrap_or(None)
                .unwrap_or(Address::ZERO);
        })
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.set_spec_and_mainnet_gas_params(spec);
            cfg.disable_eip3607 = true;
            cfg.disable_block_gas_limit = true;
            cfg.disable_base_fee = true;
            // A simulated call carries no meaningful nonce, as with `eth_call`.
            cfg.disable_nonce_check = inputs.simulation;
        })
}

fn replay_spec_for_chain(chain_id: u64, block_number: u64, block_timestamp: u64) -> SpecId {
    match chain_id {
        1 => ethereum_mainnet_spec(block_number, block_timestamp),
        11_155_111 => timestamp_scheduled_spec(
            block_number,
            block_timestamp,
            TimestampForks {
                base: SpecId::LONDON,
                merge_block: Some(1_735_371),
                shanghai_time: Some(1_677_557_088),
                cancun_time: Some(1_706_655_072),
                prague_time: Some(1_741_159_776),
                osaka_time: Some(1_760_427_360),
            },
        ),
        17_000 => timestamp_scheduled_spec(
            block_number,
            block_timestamp,
            TimestampForks {
                base: SpecId::MERGE,
                merge_block: Some(0),
                shanghai_time: Some(1_696_000_704),
                cancun_time: Some(1_707_305_664),
                prague_time: Some(1_740_434_112),
                osaka_time: Some(1_759_308_480),
            },
        ),
        560_048 => timestamp_scheduled_spec(
            block_number,
            block_timestamp,
            TimestampForks {
                base: SpecId::MERGE,
                merge_block: Some(0),
                shanghai_time: Some(0),
                cancun_time: Some(0),
                prague_time: Some(1_742_999_832),
                osaka_time: Some(1_761_677_592),
            },
        ),
        1_337 | 31_337 => SpecId::PRAGUE,
        _ => SpecId::PRAGUE,
    }
}

fn ethereum_mainnet_spec(block_number: u64, block_timestamp: u64) -> SpecId {
    let pre_merge = [
        (15_537_394, SpecId::MERGE),
        (15_050_000, SpecId::GRAY_GLACIER),
        (13_773_000, SpecId::ARROW_GLACIER),
        (12_965_000, SpecId::LONDON),
        (12_244_000, SpecId::BERLIN),
        (9_200_000, SpecId::MUIR_GLACIER),
        (9_069_000, SpecId::ISTANBUL),
        (7_280_000, SpecId::PETERSBURG),
        (4_370_000, SpecId::BYZANTIUM),
        (2_675_000, SpecId::SPURIOUS_DRAGON),
        (2_463_000, SpecId::TANGERINE),
        (1_920_000, SpecId::DAO_FORK),
        (1_150_000, SpecId::HOMESTEAD),
        (200_000, SpecId::FRONTIER_THAWING),
    ];

    if block_number < 15_537_394 {
        return pre_merge
            .iter()
            .find_map(|(fork_block, spec)| (block_number >= *fork_block).then_some(*spec))
            .unwrap_or(SpecId::FRONTIER);
    }

    timestamp_scheduled_spec(
        block_number,
        block_timestamp,
        TimestampForks {
            base: SpecId::MERGE,
            merge_block: Some(15_537_394),
            shanghai_time: Some(1_681_338_455),
            cancun_time: Some(1_710_338_135),
            prague_time: Some(1_746_612_311),
            osaka_time: Some(1_764_798_551),
        },
    )
}

#[derive(Debug, Clone, Copy)]
struct TimestampForks {
    base: SpecId,
    merge_block: Option<u64>,
    shanghai_time: Option<u64>,
    cancun_time: Option<u64>,
    prague_time: Option<u64>,
    osaka_time: Option<u64>,
}

fn timestamp_scheduled_spec(
    block_number: u64,
    block_timestamp: u64,
    forks: TimestampForks,
) -> SpecId {
    if forks
        .osaka_time
        .is_some_and(|fork_time| block_timestamp >= fork_time)
    {
        return SpecId::OSAKA;
    }
    if forks
        .prague_time
        .is_some_and(|fork_time| block_timestamp >= fork_time)
    {
        return SpecId::PRAGUE;
    }
    if forks
        .cancun_time
        .is_some_and(|fork_time| block_timestamp >= fork_time)
    {
        return SpecId::CANCUN;
    }
    if forks
        .shanghai_time
        .is_some_and(|fork_time| block_timestamp >= fork_time)
    {
        return SpecId::SHANGHAI;
    }
    if forks
        .merge_block
        .is_some_and(|fork_block| block_number >= fork_block)
    {
        return SpecId::MERGE;
    }
    forks.base
}

fn replay_full_block_transactions(
    block_number: u64,
    transactions: &[RpcBlockTransaction],
) -> SoldbResult<Vec<RpcTransaction>> {
    if transactions.is_empty() {
        return Err(SoldbError::Message(format!(
            "Replay backend preflight failed: block {block_number} has no transactions in eth_getBlockByNumber response",
        )));
    }

    transactions
        .iter()
        .map(|transaction| match transaction {
            RpcBlockTransaction::Full(transaction) => Ok(transaction.as_ref().clone()),
            RpcBlockTransaction::Hash(hash) => Err(SoldbError::Message(format!(
                "Replay backend preflight failed: block {block_number} returned transaction hash {hash} instead of full transaction objects; replay requires eth_getBlockByNumber(block, true)",
            ))),
        })
        .collect()
}

fn replay_target_index(
    transactions: &[RpcTransaction],
    expected_index: usize,
    tx_hash: &str,
) -> SoldbResult<usize> {
    if transactions.is_empty() {
        return Err(SoldbError::Message(
            "Replay backend requires eth_getBlockByNumber with full transaction objects".to_owned(),
        ));
    }

    if transactions
        .get(expected_index)
        .is_some_and(|tx| tx.hash.eq_ignore_ascii_case(tx_hash))
    {
        return Ok(expected_index);
    }

    transactions
        .iter()
        .position(|tx| tx.hash.eq_ignore_ascii_case(tx_hash))
        .ok_or_else(|| {
            SoldbError::Message(format!(
                "Replay backend could not find transaction {tx_hash} in its block"
            ))
        })
}

/// REVM's view of a [`ReplayStateProvider`]. Reads go straight through; the code hash
/// lookup is never needed because every account arrives with its bytecode attached.
#[derive(Debug, Clone)]
struct ReplayStateDb<'a, P> {
    provider: &'a P,
}

/// A state read the replay could not satisfy, with the guidance a user needs to fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayDbError(pub String);

impl fmt::Display for ReplayDbError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ReplayDbError {}

impl DBErrorMarker for ReplayDbError {}

impl From<SoldbError> for ReplayDbError {
    fn from(error: SoldbError) -> Self {
        Self(error.to_string())
    }
}

impl<'a, P> ReplayStateDb<'a, P> {
    fn new(provider: &'a P) -> Self {
        Self { provider }
    }
}

/// Where a replay reads parent-block state from.
///
/// Every account comes back whole, bytecode included, so REVM never has to look code up
/// by hash. Reads take `&self` because REVM holds the database by shared reference.
pub trait ReplayStateProvider {
    fn account(&self, address: Address) -> Result<AccountInfo, ReplayDbError>;
    fn storage(&self, address: Address, index: U256) -> Result<U256, ReplayDbError>;
    fn block_hash(&self, number: u64) -> Result<B256, ReplayDbError>;
}

/// One piece of parent-block state a replay needed and did not have.
///
/// Serialized with a `kind` tag so a host can dispatch on it: an `account` needs
/// `eth_getBalance`, `eth_getTransactionCount`, and `eth_getCode`; `storage` needs
/// `eth_getStorageAt`; `blockHash` needs `eth_getBlockByNumber`. All are read at the
/// parent block, which [`ReplayInputs::parent_block_tag`] names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StateRequest {
    Account { address: String },
    Storage { address: String, slot: String },
    BlockHash { number: u64 },
}

/// One account as the node reports it at the parent block: the results of
/// `eth_getBalance`, `eth_getTransactionCount`, and `eth_getCode`, verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: String,
    pub nonce: String,
    pub code: String,
}

/// State a host hands to a [`PrefetchedReplayState`], keyed the way it was requested.
///
/// `accounts` and `storage` are keyed by address in any casing, `storage` values by
/// slot, and `block_hashes` by block number. Every field is optional so a host can
/// answer only the requests it has results for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateBatch {
    #[serde(default)]
    pub accounts: BTreeMap<String, AccountState>,
    #[serde(default)]
    pub storage: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub block_hashes: BTreeMap<u64, String>,
}

impl StateBatch {
    /// Records an account as the node reported it.
    pub fn insert_account(&mut self, address: Address, info: &AccountInfo) {
        self.accounts.insert(
            address_hex(address),
            AccountState {
                balance: format_u256_quantity(info.balance),
                nonce: format_quantity(info.nonce),
                code: bytes_to_prefixed_hex(
                    info.code
                        .as_ref()
                        .map(|code| code.original_bytes())
                        .unwrap_or_default()
                        .as_ref(),
                ),
            },
        );
    }

    /// Records one storage slot.
    pub fn insert_storage(&mut self, address: Address, slot: U256, value: U256) {
        self.storage
            .entry(address_hex(address))
            .or_default()
            .insert(format_u256_quantity(slot), format_u256_quantity(value));
    }

    /// Records one block hash.
    pub fn insert_block_hash(&mut self, number: u64, hash: B256) {
        self.block_hashes.insert(number, b256_hex(hash));
    }

    /// How many items the batch holds, for reporting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len()
            + self.storage.values().map(BTreeMap::len).sum::<usize>()
            + self.block_hashes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The current version of the replay file format. Bump it on a breaking change.
pub const REPLAY_BUNDLE_VERSION: u32 = 1;

/// Everything a replay read from the node, so the same transaction or call replays with
/// no node at all: the inputs, and the parent-block state the run read.
///
/// A replay that ran to completion over [`RpcReplayStateProvider`] or a host's
/// [`PrefetchedReplayState`] read exactly this state, so replaying the bundle produces
/// the same trace. It is what turns a bug into a file that can be sent along.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayBundle {
    pub version: u32,
    pub chain_id: u64,
    /// The block the target ran in, carrying in full the transactions that ran before
    /// the target, and the target itself for a mined transaction.
    pub block: RpcBlockWithTransactions,
    #[serde(flatten)]
    pub target: ReplayBundleTarget,
    pub state: StateBatch,
}

/// What a [`ReplayBundle`] replays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ReplayBundleTarget {
    /// A mined transaction and its receipt.
    Transaction {
        transaction: Box<RpcTransaction>,
        receipt: Box<RpcReceipt>,
    },
    /// A call placed on top of, or inside, the block.
    Call {
        request: SimulateCallRequest,
        block_number: u64,
    },
}

impl ReplayBundle {
    /// Bundles a mined transaction with the state its replay read.
    #[must_use]
    pub fn for_transaction(inputs: &ReplayInputs, receipt: RpcReceipt, state: StateBatch) -> Self {
        Self {
            version: REPLAY_BUNDLE_VERSION,
            chain_id: inputs.chain_id(),
            block: inputs.block(),
            target: ReplayBundleTarget::Transaction {
                transaction: Box::new(inputs.transaction().clone()),
                receipt: Box::new(receipt),
            },
            state,
        }
    }

    /// Bundles a simulated call with the state its replay read.
    #[must_use]
    pub fn for_call(
        inputs: &ReplayInputs,
        request: &SimulateCallRequest,
        state: StateBatch,
    ) -> Self {
        Self {
            version: REPLAY_BUNDLE_VERSION,
            chain_id: inputs.chain_id(),
            block: inputs.block(),
            target: ReplayBundleTarget::Call {
                request: request.clone(),
                block_number: inputs.block_number(),
            },
            state,
        }
    }

    /// The replay inputs the bundle describes, validated the same way a node's answers
    /// are.
    pub fn inputs(&self) -> SoldbResult<ReplayInputs> {
        if self.version != REPLAY_BUNDLE_VERSION {
            return Err(SoldbError::Message(format!(
                "unsupported replay file version {}; this build reads version {REPLAY_BUNDLE_VERSION}",
                self.version
            )));
        }
        match &self.target {
            ReplayBundleTarget::Transaction { transaction, .. } => ReplayInputs::new(
                transaction.as_ref().clone(),
                self.block.clone(),
                self.chain_id,
            ),
            ReplayBundleTarget::Call {
                request,
                block_number,
            } => ReplayInputs::for_call(request, self.block.clone(), *block_number, self.chain_id),
        }
    }

    /// Replays the bundle over the state it holds and assembles the trace, exactly as the
    /// recording run did.
    pub fn replay(&self) -> SoldbResult<TransactionTrace> {
        let inputs = self.inputs()?;
        let mut state = PrefetchedReplayState::default();
        state.provide(&self.state)?;
        let result = replay_debug_trace_with_state(&inputs, &state);
        // Missing state explains a failure better than the failure does: a sender the
        // file does not hold reads as an empty account, and REVM then reports that it
        // cannot pay for gas.
        let missing = state.missing();
        if let Some(first) = missing.first() {
            return Err(SoldbError::Message(format!(
                "the replay file does not hold all the state this replay reads: {} item(s) missing, the first being {}",
                missing.len(),
                describe_request(first)
            )));
        }
        let result = result?;
        match &self.target {
            ReplayBundleTarget::Transaction {
                transaction,
                receipt,
            } => replay_transaction_trace(
                transaction.as_ref().clone(),
                receipt.as_ref().clone(),
                result,
                self.chain_id,
            ),
            ReplayBundleTarget::Call { request, .. } => {
                replay_simulation_trace(request, result, self.chain_id)
            }
        }
    }

    /// One line saying what the bundle holds.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.target {
            ReplayBundleTarget::Transaction { transaction, .. } => format!(
                "transaction {} on chain {} with {} state item(s)",
                transaction.hash,
                self.chain_id,
                self.state.len()
            ),
            ReplayBundleTarget::Call {
                request,
                block_number,
            } => format!(
                "call to {} at block {block_number} on chain {} with {} state item(s)",
                request.to_addr,
                self.chain_id,
                self.state.len()
            ),
        }
    }
}

fn describe_request(request: &StateRequest) -> String {
    match request {
        StateRequest::Account { address } => format!("account {address}"),
        StateRequest::Storage { address, slot } => format!("storage slot {slot} of {address}"),
        StateRequest::BlockHash { number } => format!("the hash of block {number}"),
    }
}

/// Parent-block state supplied up front, recording every read it cannot answer.
///
/// REVM reads state synchronously and a WebAssembly host cannot block on the network, so
/// replay there runs in rounds. A run reads what is known; anything missing is answered
/// with an empty account, a zero slot, or a zero hash and recorded. The host fetches the
/// recorded keys at the parent block, supplies them, and runs again. A default can send an
/// early round down a path the real values would not take, but every value a round that
/// records nothing used was real, so that round's result is the one
/// [`RpcReplayStateProvider`] produces. Seeding with [`ReplayInputs::participants`]
/// answers the accounts every run reads first and saves a round per transaction.
#[derive(Debug, Clone, Default)]
pub struct PrefetchedReplayState {
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    block_hashes: HashMap<u64, B256>,
    missing: RefCell<BTreeSet<StateRequest>>,
    reads: RefCell<BTreeSet<StateRequest>>,
}

impl PrefetchedReplayState {
    /// An empty state whose first run will request the accounts every replay reads.
    pub fn for_inputs(inputs: &ReplayInputs) -> SoldbResult<Self> {
        let state = Self::default();
        for address in inputs.participants()? {
            state.record(StateRequest::Account {
                address: address_hex(address),
            });
        }
        Ok(state)
    }

    /// The reads recorded since the last [`PrefetchedReplayState::clear_missing`], in a
    /// stable order and without duplicates.
    #[must_use]
    pub fn missing(&self) -> Vec<StateRequest> {
        self.missing.borrow().iter().cloned().collect()
    }

    /// Forgets the recorded misses. Call it before a run so the run reports only what it
    /// still lacks.
    pub fn clear_missing(&self) {
        self.missing.borrow_mut().clear();
    }

    /// Every read since the last [`PrefetchedReplayState::clear_reads`], answered or not,
    /// in a stable order and without duplicates. After a run that recorded nothing
    /// missing, this is exactly the state that run depended on.
    #[must_use]
    pub fn reads(&self) -> Vec<StateRequest> {
        self.reads.borrow().iter().cloned().collect()
    }

    pub fn clear_reads(&self) {
        self.reads.borrow_mut().clear();
    }

    /// The held state behind `requests`, in the form [`PrefetchedReplayState::provide`]
    /// accepts, so a host can keep it, share it, or replay from it without a node.
    /// Requests for state not held are left out.
    #[must_use]
    pub fn export(&self, requests: &[StateRequest]) -> StateBatch {
        let mut batch = StateBatch::default();
        for request in requests {
            match request {
                StateRequest::Account { address } => {
                    let Some(account) = parse_address(address)
                        .ok()
                        .and_then(|address| self.accounts.get(&address))
                    else {
                        continue;
                    };
                    batch.accounts.insert(
                        address.clone(),
                        AccountState {
                            balance: format_u256_quantity(account.balance),
                            nonce: format_quantity(account.nonce),
                            code: bytes_to_prefixed_hex(
                                account
                                    .code
                                    .as_ref()
                                    .map(|code| code.original_bytes())
                                    .unwrap_or_default()
                                    .as_ref(),
                            ),
                        },
                    );
                }
                StateRequest::Storage { address, slot } => {
                    let Some(value) = parse_address(address)
                        .ok()
                        .zip(parse_u256_quantity(slot).ok())
                        .and_then(|key| self.storage.get(&key))
                    else {
                        continue;
                    };
                    batch
                        .storage
                        .entry(address.clone())
                        .or_default()
                        .insert(slot.clone(), format_u256_quantity(*value));
                }
                StateRequest::BlockHash { number } => {
                    if let Some(hash) = self.block_hashes.get(number) {
                        batch.block_hashes.insert(*number, b256_hex(*hash));
                    }
                }
            }
        }
        batch
    }

    fn note_read(&self, request: StateRequest) {
        self.reads.borrow_mut().insert(request);
    }

    /// Adds the state in `batch`, replacing anything already held for the same key.
    /// Values are validated the way the RPC provider validates node responses.
    pub fn provide(&mut self, batch: &StateBatch) -> SoldbResult<()> {
        for (address_text, account) in &batch.accounts {
            let address = parse_address(address_text)?;
            let info =
                account_info_from_rpc(address, &account.balance, &account.nonce, &account.code)
                    .map_err(|error| SoldbError::Message(error.to_string()))?;
            self.accounts.insert(address, info);
        }
        for (address_text, slots) in &batch.storage {
            let address = parse_address(address_text)?;
            for (slot, value) in slots {
                self.storage.insert(
                    (address, parse_u256_quantity(slot)?),
                    parse_u256_quantity(value)?,
                );
            }
        }
        for (number, hash) in &batch.block_hashes {
            self.block_hashes.insert(*number, parse_b256(hash)?);
        }
        Ok(())
    }

    fn record(&self, request: StateRequest) {
        self.missing.borrow_mut().insert(request);
    }
}

impl ReplayStateProvider for PrefetchedReplayState {
    fn account(&self, address: Address) -> Result<AccountInfo, ReplayDbError> {
        let request = StateRequest::Account {
            address: address_hex(address),
        };
        self.note_read(request.clone());
        if let Some(account) = self.accounts.get(&address) {
            return Ok(account.clone());
        }
        self.record(request);
        Ok(empty_account())
    }

    fn storage(&self, address: Address, index: U256) -> Result<U256, ReplayDbError> {
        let request = StateRequest::Storage {
            address: address_hex(address),
            slot: format_u256_quantity(index),
        };
        self.note_read(request.clone());
        if let Some(value) = self.storage.get(&(address, index)) {
            return Ok(*value);
        }
        self.record(request);
        Ok(U256::ZERO)
    }

    fn block_hash(&self, number: u64) -> Result<B256, ReplayDbError> {
        let request = StateRequest::BlockHash { number };
        self.note_read(request.clone());
        if let Some(hash) = self.block_hashes.get(&number) {
            return Ok(*hash);
        }
        self.record(request);
        Ok(B256::ZERO)
    }
}

/// The account a node reports for an address that does not exist.
fn empty_account() -> AccountInfo {
    let bytecode = Bytecode::new_raw(Bytes::new());
    let code_hash = bytecode.hash_slow();
    AccountInfo::new(U256::ZERO, 0, code_hash, bytecode)
}

/// Builds an account from the node's `eth_getBalance`, `eth_getTransactionCount`, and
/// `eth_getCode` results, validating each the same way whether it arrived over RPC or
/// from a host.
pub fn account_info_from_rpc(
    address: Address,
    balance: &str,
    nonce: &str,
    code: &str,
) -> Result<AccountInfo, ReplayDbError> {
    let code_bytes = hex_to_bytes(code.trim_start_matches("0x")).ok_or_else(|| {
        ReplayDbError(format!(
            "Invalid bytecode returned for account {address}: {code}"
        ))
    })?;
    let bytecode = Bytecode::new_raw(Bytes::from(code_bytes));
    let code_hash = bytecode.hash_slow();
    Ok(AccountInfo::new(
        parse_u256_quantity(balance).map_err(ReplayDbError::from)?,
        parse_quantity(nonce).map_err(ReplayDbError::from)?,
        code_hash,
        bytecode,
    ))
}

impl<P: ReplayStateProvider> DatabaseRef for ReplayStateDb<'_, P> {
    type Error = ReplayDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.provider.account(address).map(Some)
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.provider.storage(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.provider.block_hash(number)
    }
}

#[derive(Debug, Default)]
struct ReplayStepInspector {
    gas: GasInspector,
    pending: Option<StructLog>,
    struct_logs: Vec<StructLog>,
    artifacts: TraceArtifacts,
    call_stack: Vec<usize>,
    create_stack: Vec<usize>,
    journal_entries_seen: usize,
    /// EVM memory as of the last step that changed it, with its hex encoding as the log
    /// carries it.
    ///
    /// Most instructions leave memory untouched, but the inspector records memory on every
    /// step. Comparing bytes is what keeps the encoder from running a full pass per step,
    /// and handing the same `Arc` to every log until memory changes is what keeps the
    /// logs from holding a copy per step.
    last_memory: Vec<u8>,
    last_memory_words: Arc<Vec<String>>,
    /// One shared copy of each distinct stack word. A run of a few hundred thousand steps
    /// pushes millions of words drawn from a few thousand values, so the sharing is the
    /// difference between holding an allocation per occurrence and one per value.
    words: WordInterner,
    /// The storage every log starts from; a log that touches a slot gets its own map.
    empty_storage: Arc<BTreeMap<String, String>>,
}

impl ReplayStepInspector {
    fn into_parts(self) -> (Vec<StructLog>, TraceArtifacts) {
        (self.struct_logs, self.artifacts)
    }
}

impl<CTX> Inspector<CTX> for ReplayStepInspector
where
    CTX: ContextTr,
    CTX::Journal: JournalExt,
{
    fn initialize_interp(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        self.gas.initialize_interp(&interp.gas);
    }

    fn step(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        self.gas.step(&interp.gas);
        let opcode = interp.bytecode.opcode();
        let op = OpCode::new(opcode).map_or_else(
            || format!("UNKNOWN(0x{opcode:02x})"),
            |op| op.as_str().to_owned(),
        );
        let stack = interp
            .stack
            .data()
            .iter()
            .map(|value| self.words.intern(&format_u256_quantity(*value)))
            .collect();
        {
            let memory_slice = interp.memory.slice(0..interp.memory.size());
            let memory_bytes: &[u8] = memory_slice.as_ref();
            if self.last_memory != memory_bytes {
                self.last_memory.clear();
                self.last_memory.extend_from_slice(memory_bytes);
                let hex = bytes_to_hex(memory_bytes);
                self.last_memory_words = Arc::new(if hex.is_empty() {
                    Vec::new()
                } else {
                    vec![hex]
                });
            }
        }
        self.pending = Some(StructLog {
            pc: interp.bytecode.pc() as u64,
            op,
            gas: interp.gas.remaining(),
            gas_cost: 0,
            depth: context.journal_mut().depth() as u64,
            stack,
            memory: Arc::clone(&self.last_memory_words),
            storage: Arc::clone(&self.empty_storage),
            error: None,
        });
    }

    fn step_end(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        self.gas.step_end(&interp.gas);
        if let Some(mut log) = self.pending.take() {
            log.gas_cost = self.gas.last_gas_cost();
            log.error = interp
                .bytecode
                .action()
                .as_ref()
                .and_then(|action| action.instruction_result())
                .map(|result| format!("{result:?}"));
            record_replay_storage_touch(&mut log, interp);
            self.struct_logs.push(log);
        }
    }

    fn log_full(
        &mut self,
        _interp: &mut Interpreter,
        context: &mut CTX,
        log: revm::primitives::Log,
    ) {
        let index = self.artifacts.logs.len();
        self.artifacts
            .logs
            .push(log_artifact(index, context.journal().depth() as u64, &log));
        self.record_journal_changes(context);
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let id = self.artifacts.calls.len();
        let parent_id = self.call_stack.last().copied();
        let depth = context.journal().depth() as u64 + 1;
        let input = bytes_to_prefixed_hex(inputs.input.bytes(context).as_ref());
        self.artifacts.calls.push(ExecutionCall {
            id,
            parent_id,
            depth,
            entry_step: Some(self.struct_logs.len()),
            exit_step: None,
            call_type: call_scheme_name(inputs.scheme).to_owned(),
            from: address_hex(inputs.caller),
            to: address_hex(inputs.target_address),
            bytecode_address: address_hex(inputs.bytecode_address),
            value: format_u256_quantity(inputs.call_value()),
            input,
            gas_limit: inputs.gas_limit,
            gas_used: None,
            output: None,
            success: None,
            error: None,
        });
        self.call_stack.push(id);
        self.record_journal_changes(context);
        None
    }

    fn call_end(&mut self, context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        if let Some(id) = self.call_stack.pop() {
            if let Some(call) = self.artifacts.calls.get_mut(id) {
                let result = *outcome.instruction_result();
                call.exit_step = Some(self.struct_logs.len());
                call.gas_used = Some(outcome.gas().used());
                call.output = Some(bytes_to_prefixed_hex(outcome.output().as_ref()));
                call.success = Some(result.is_ok());
                call.error = (!result.is_ok()).then(|| format!("{result:?}"));
            }
        }
        self.record_journal_changes(context);
    }

    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        let id = self.artifacts.creations.len();
        let parent_id = self.call_stack.last().copied();
        self.artifacts.creations.push(ContractCreation {
            id,
            parent_id,
            depth: context.journal().depth() as u64 + 1,
            entry_step: Some(self.struct_logs.len()),
            exit_step: None,
            create_type: create_scheme_name(inputs.scheme()).to_owned(),
            caller: address_hex(inputs.caller()),
            address: None,
            value: format_u256_quantity(inputs.value()),
            init_code: bytes_to_prefixed_hex(inputs.init_code().as_ref()),
            gas_limit: inputs.gas_limit(),
            gas_used: None,
            output: None,
            success: None,
            error: None,
        });
        self.create_stack.push(id);
        self.record_journal_changes(context);
        None
    }

    fn create_end(
        &mut self,
        context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if let Some(id) = self.create_stack.pop() {
            if let Some(create) = self.artifacts.creations.get_mut(id) {
                let result = *outcome.instruction_result();
                create.exit_step = Some(self.struct_logs.len());
                create.address = outcome.address.map(address_hex);
                create.gas_used = Some(outcome.gas().used());
                create.output = Some(bytes_to_prefixed_hex(outcome.output().as_ref()));
                create.success = Some(result.is_ok());
                create.error = (!result.is_ok()).then(|| format!("{result:?}"));
            }
        }
        self.record_journal_changes(context);
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        self.artifacts.account_changes.push(AccountChange {
            depth: 0,
            kind: "selfdestruct".to_owned(),
            address: Some(address_hex(contract)),
            from: Some(address_hex(contract)),
            to: Some(address_hex(target)),
            value: Some(format_u256_quantity(value)),
            key: None,
            previous_value: None,
            previous_nonce: None,
        });
    }
}

impl ReplayStepInspector {
    fn record_journal_changes<CTX>(&mut self, context: &mut CTX)
    where
        CTX: ContextTr,
        CTX::Journal: JournalExt,
    {
        let journal = context.journal().journal();
        for entry in journal.iter().skip(self.journal_entries_seen) {
            if let Some(change) =
                account_change_from_journal_entry(context.journal().depth() as u64, entry)
            {
                self.artifacts.account_changes.push(change);
            }
        }
        self.journal_entries_seen = journal.len();
    }
}

fn log_artifact(index: usize, depth: u64, log: &revm::primitives::Log) -> ExecutionLog {
    ExecutionLog {
        index,
        depth,
        address: address_hex(log.address),
        topics: log
            .data
            .topics()
            .iter()
            .map(|topic| b256_hex(*topic))
            .collect(),
        data: bytes_to_prefixed_hex(log.data.data.as_ref()),
    }
}

fn account_change_from_journal_entry(depth: u64, entry: &JournalEntry) -> Option<AccountChange> {
    let base = |kind: &str| AccountChange {
        depth,
        kind: kind.to_owned(),
        address: None,
        from: None,
        to: None,
        value: None,
        key: None,
        previous_value: None,
        previous_nonce: None,
    };

    match entry {
        JournalEntry::AccountDestroyed {
            had_balance,
            address,
            target,
            ..
        } => {
            let mut change = base("account_destroyed");
            change.address = Some(address_hex(*address));
            change.from = Some(address_hex(*address));
            change.to = Some(address_hex(*target));
            change.value = Some(format_u256_quantity(*had_balance));
            Some(change)
        }
        JournalEntry::AccountTouched { address } => {
            let mut change = base("account_touched");
            change.address = Some(address_hex(*address));
            Some(change)
        }
        JournalEntry::BalanceChange {
            old_balance,
            address,
        } => {
            let mut change = base("balance_change");
            change.address = Some(address_hex(*address));
            change.previous_value = Some(format_u256_quantity(*old_balance));
            Some(change)
        }
        JournalEntry::BalanceTransfer { balance, from, to } => {
            let mut change = base("balance_transfer");
            change.from = Some(address_hex(*from));
            change.to = Some(address_hex(*to));
            change.value = Some(format_u256_quantity(*balance));
            Some(change)
        }
        JournalEntry::NonceChange {
            address,
            previous_nonce,
        } => {
            let mut change = base("nonce_change");
            change.address = Some(address_hex(*address));
            change.previous_nonce = Some(*previous_nonce);
            Some(change)
        }
        JournalEntry::NonceBump { address } => {
            let mut change = base("nonce_bump");
            change.address = Some(address_hex(*address));
            Some(change)
        }
        JournalEntry::AccountCreated { address, .. } => {
            let mut change = base("account_created");
            change.address = Some(address_hex(*address));
            Some(change)
        }
        JournalEntry::StorageChanged {
            address,
            key,
            had_value,
        } => {
            let mut change = base("storage_change");
            change.address = Some(address_hex(*address));
            change.key = Some(format_u256_quantity(*key));
            change.previous_value = Some(format_u256_quantity(*had_value));
            Some(change)
        }
        JournalEntry::TransientStorageChange {
            address,
            key,
            had_value,
        } => {
            let mut change = base("transient_storage_change");
            change.address = Some(address_hex(*address));
            change.key = Some(format_u256_quantity(*key));
            change.previous_value = Some(format_u256_quantity(*had_value));
            Some(change)
        }
        JournalEntry::CodeChange { address } => {
            let mut change = base("code_change");
            change.address = Some(address_hex(*address));
            Some(change)
        }
        JournalEntry::AccountWarmed { .. } | JournalEntry::StorageWarmed { .. } => None,
    }
}

fn call_scheme_name(scheme: CallScheme) -> &'static str {
    match scheme {
        CallScheme::Call => "CALL",
        CallScheme::CallCode => "CALLCODE",
        CallScheme::DelegateCall => "DELEGATECALL",
        CallScheme::StaticCall => "STATICCALL",
    }
}

fn create_scheme_name(scheme: revm::context_interface::CreateScheme) -> &'static str {
    match scheme {
        revm::context_interface::CreateScheme::Create => "CREATE",
        revm::context_interface::CreateScheme::Create2 { .. } => "CREATE2",
        revm::context_interface::CreateScheme::Custom { .. } => "CUSTOM_CREATE",
    }
}

fn record_replay_storage_touch(log: &mut StructLog, interp: &Interpreter) {
    match log.op.as_str() {
        "SLOAD" => {
            let Some(slot) = log.stack.last().map(|word| word.to_string()) else {
                return;
            };
            let value = interp
                .stack
                .data()
                .last()
                .copied()
                .map(format_u256_quantity)
                .unwrap_or_else(|| "0x0".to_owned());
            Arc::make_mut(&mut log.storage).insert(normalize_storage_key(&slot), value);
        }
        "SSTORE" => {
            let Some(slot) = log.stack.last().map(|word| word.to_string()) else {
                return;
            };
            let Some(value) = log
                .stack
                .get(log.stack.len().saturating_sub(2))
                .map(|word| word.to_string())
            else {
                return;
            };
            Arc::make_mut(&mut log.storage)
                .insert(normalize_storage_key(&slot), normalize_hex_output(&value));
        }
        _ => {}
    }
}

fn normalize_storage_key(value: &str) -> String {
    let value = normalize_hex_output(value);
    let trimmed = value.trim_start_matches("0x").trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{}", trimmed.to_ascii_lowercase())
    }
}

fn tx_env_from_rpc_transaction(tx: &RpcTransaction, chain_id: u64) -> SoldbResult<TxEnv> {
    let gas_limit = tx
        .gas
        .as_deref()
        .map(parse_quantity)
        .transpose()?
        .unwrap_or(30_000_000);
    let gas_price = tx
        .max_fee_per_gas
        .as_deref()
        .or(tx.gas_price.as_deref())
        .map(parse_u128_quantity)
        .transpose()?
        .unwrap_or_default();
    let gas_priority_fee = tx
        .max_priority_fee_per_gas
        .as_deref()
        .map(parse_u128_quantity)
        .transpose()?;
    let nonce = tx
        .nonce
        .as_deref()
        .map(parse_quantity)
        .transpose()?
        .unwrap_or_default();
    let mut builder = TxEnv::builder()
        .caller(parse_address(&tx.from_addr)?)
        .gas_limit(gas_limit)
        .gas_price(gas_price)
        .value(parse_u256_quantity(&tx.value)?)
        .data(Bytes::from(
            hex_to_bytes(tx.input_data.trim_start_matches("0x")).ok_or_else(|| {
                SoldbError::Message(format!("Invalid transaction input: {}", tx.input_data))
            })?,
        ))
        .nonce(nonce)
        .chain_id(Some(chain_id));

    if let Some(priority_fee) = gas_priority_fee {
        builder = builder.gas_priority_fee(Some(priority_fee));
    }

    builder = match tx.to.as_deref() {
        Some(to) => builder.kind(TxKind::Call(parse_address(to)?)),
        None => builder.create(),
    };

    if let Some(tx_type) = tx.transaction_type.as_deref() {
        builder = builder.tx_type(Some(parse_quantity(tx_type)? as u8));
    }

    builder.build().map_err(|error| {
        SoldbError::Message(format!("Failed to build replay transaction: {error}"))
    })
}

/// Parses a `0x`-prefixed 20-byte address from node output or user input.
pub fn parse_address(value: &str) -> SoldbResult<Address> {
    let bytes = hex_to_bytes(value.trim_start_matches("0x"))
        .ok_or_else(|| SoldbError::Message(format!("Invalid address '{value}'")))?;
    if bytes.len() != 20 {
        return Err(SoldbError::Message(format!(
            "Invalid address '{value}': expected 20 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(Address::from_slice(&bytes))
}

/// Parses a `0x`-prefixed 32-byte word from node output.
pub fn parse_b256(value: &str) -> SoldbResult<B256> {
    let bytes = hex_to_bytes(value.trim_start_matches("0x"))
        .ok_or_else(|| SoldbError::Message(format!("Invalid bytes32 value '{value}'")))?;
    if bytes.len() != 32 {
        return Err(SoldbError::Message(format!(
            "Invalid bytes32 value '{value}': expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

fn address_hex(address: Address) -> String {
    bytes_to_prefixed_hex(address.as_slice())
}

fn b256_hex(value: B256) -> String {
    bytes_to_prefixed_hex(value.as_slice())
}

fn gas_summary_from_result(result: &revm::context::result::ExecutionResult) -> GasSummary {
    let gas = result.gas();
    GasSummary {
        used: gas.used(),
        spent: Some(gas.spent()),
        refunded: Some(gas.final_refunded()),
        remaining: Some(gas.remaining()),
        limit: Some(gas.limit()),
    }
}

fn parse_u128_quantity(value: &str) -> SoldbResult<u128> {
    let hex = value.trim_start_matches("0x");
    u128::from_str_radix(hex, 16)
        .map_err(|error| SoldbError::Message(format!("Invalid RPC quantity '{value}': {error}")))
}

fn bytes_to_prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", bytes_to_hex(bytes))
}

#[cfg(test)]
mod tests {
    /// A stack as plain strings, for assertions.
    fn stack_words(stack: &[soldb_core::Word]) -> Vec<&str> {
        stack.iter().map(|word| &**word).collect()
    }

    use std::collections::BTreeMap;

    use revm::primitives::{Address, B256, U256};
    use serde_json::{json, Value};

    use super::{
        account_info_from_rpc, empty_account, parse_address, replay_capabilities,
        replay_chain_support, replay_debug_trace_with_state, replay_full_block_transactions,
        replay_prefix_with_state, replay_simulation_trace, replay_spec_for_chain,
        replay_target_index, replay_target_with_state, replay_transaction_trace, AccountState,
        LocalChain, PrefetchedReplayState, ReplayBundle, ReplayInputs, ReplayStateProvider,
        RpcBlockTransaction, RpcBlockWithTransactions, SpecId, StateBatch, StateRequest,
        REPLAY_BUNDLE_VERSION,
    };
    use crate::{hex_to_bytes, RpcReceipt, RpcTransaction, SimulateCallRequest};

    const SENDER: &str = "0x1111111111111111111111111111111111111111";

    const COUNTER: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";

    // PUSH1 0 BLOCKHASH POP  PUSH1 0 SLOAD PUSH1 1 ADD PUSH1 0 SSTORE  STOP: reads a block
    // hash and increments slot 0, so a replay touches every kind of state a host can supply.
    const COUNTER_CODE: &str = "0x6000405060005460010160005500";

    fn counter_transaction(hash: &str, nonce: &str, index: &str) -> RpcTransaction {
        serde_json::from_value(json!({
            "hash": hash,
            "from": SENDER,
            "to": COUNTER,
            "value": "0x0",
            "input": "0x",
            "gas": "0x186a0",
            "gasPrice": "0x1",
            "nonce": nonce,
            "blockNumber": "0x1",
            "transactionIndex": index,
            "type": "0x0",
            "chainId": "0x7a69"
        }))
        .expect("transaction")
    }

    fn counter_block(transactions: Vec<Value>) -> RpcBlockWithTransactions {
        serde_json::from_value(json!({
            "hash": format!("0x{}", "11".repeat(32)),
            "timestamp": "0x64",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x0",
            "mixHash": format!("0x{}", "33".repeat(32)),
            "transactions": transactions
        }))
        .expect("block")
    }

    fn counter_inputs() -> ReplayInputs {
        let tx = counter_transaction("0xaaa", "0x0", "0x0");
        let block = counter_block(vec![serde_json::to_value(&tx).expect("tx value")]);
        ReplayInputs::new(tx, block, 31_337).expect("inputs")
    }

    /// Everything the counter replay can ask for, as a host would have fetched it,
    /// including the fee recipient the block leaves at the zero address.
    fn counter_world() -> StateBatch {
        let mut world = StateBatch::default();
        world.accounts.insert(
            format!("0x{}", "00".repeat(20)),
            AccountState {
                balance: "0x0".to_owned(),
                nonce: "0x0".to_owned(),
                code: "0x".to_owned(),
            },
        );
        world.accounts.insert(
            SENDER.to_owned(),
            AccountState {
                balance: "0xde0b6b3a7640000".to_owned(),
                nonce: "0x0".to_owned(),
                code: "0x".to_owned(),
            },
        );
        world.accounts.insert(
            COUNTER.to_uppercase().replace("0X", "0x"),
            AccountState {
                balance: "0x0".to_owned(),
                nonce: "0x1".to_owned(),
                code: COUNTER_CODE.to_owned(),
            },
        );
        world.storage.insert(
            COUNTER.to_owned(),
            BTreeMap::from([("0x0".to_owned(), "0x29".to_owned())]),
        );
        world
            .block_hashes
            .insert(0, format!("0x{}", "22".repeat(32)));
        world
    }

    /// Answers only the requests in `missing` out of `world`, as a careful host would.
    fn answer(world: &StateBatch, missing: &[StateRequest]) -> StateBatch {
        let mut batch = StateBatch::default();
        for request in missing {
            match request {
                StateRequest::Account { address } => {
                    let account = world
                        .accounts
                        .iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case(address))
                        .map(|(_, account)| account.clone())
                        .unwrap_or_else(|| AccountState {
                            balance: "0x0".to_owned(),
                            nonce: "0x0".to_owned(),
                            code: "0x".to_owned(),
                        });
                    batch.accounts.insert(address.clone(), account);
                }
                StateRequest::Storage { address, slot } => {
                    let value = world
                        .storage
                        .iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case(address))
                        .and_then(|(_, slots)| slots.get(slot))
                        .cloned()
                        .unwrap_or_else(|| "0x0".to_owned());
                    batch
                        .storage
                        .entry(address.clone())
                        .or_default()
                        .insert(slot.clone(), value);
                }
                StateRequest::BlockHash { number } => {
                    batch.block_hashes.insert(
                        *number,
                        world
                            .block_hashes
                            .get(number)
                            .cloned()
                            .unwrap_or_else(|| format!("0x{}", "00".repeat(32))),
                    );
                }
            }
        }
        batch
    }

    fn fully_supplied_state() -> PrefetchedReplayState {
        let mut state = PrefetchedReplayState::default();
        state.provide(&counter_world()).expect("world");
        state
    }

    #[test]
    fn replay_inputs_validate_the_transaction_and_its_block() {
        let mut unmined = counter_transaction("0xaaa", "0x0", "0x0");
        unmined.block_number = None;
        let block = counter_block(vec![serde_json::to_value(&unmined).expect("tx")]);
        let error = ReplayInputs::new(unmined, block, 31_337).expect_err("unmined");
        assert!(error.to_string().contains("mined transaction"), "{error}");

        let mut genesis = counter_transaction("0xaaa", "0x0", "0x0");
        genesis.block_number = Some("0x0".to_owned());
        let block = counter_block(vec![serde_json::to_value(&genesis).expect("tx")]);
        let error = ReplayInputs::new(genesis, block, 31_337).expect_err("block 0");
        assert!(error.to_string().contains("block 0"), "{error}");

        let tx = counter_transaction("0xaaa", "0x0", "0x0");
        let hash_only = counter_block(vec![json!("0xaaa")]);
        let error = ReplayInputs::new(tx.clone(), hash_only, 31_337).expect_err("hash-only");
        assert!(
            error.to_string().contains("full transaction objects"),
            "{error}"
        );

        let missing = counter_block(vec![serde_json::to_value(counter_transaction(
            "0xbbb", "0x0", "0x0",
        ))
        .expect("tx")]);
        let error = ReplayInputs::new(tx.clone(), missing, 31_337).expect_err("not in block");
        assert!(
            error.to_string().contains("could not find transaction"),
            "{error}"
        );

        // The index the node reports is trusted only when the hash agrees; otherwise the
        // transaction is located by hash.
        let earlier = counter_transaction("0xbbb", "0x0", "0x0");
        let mut misindexed = counter_transaction("0xaaa", "0x1", "0x5");
        misindexed.to = None;
        let block = counter_block(vec![
            serde_json::to_value(&earlier).expect("tx"),
            serde_json::to_value(&misindexed).expect("tx"),
        ]);
        let inputs = ReplayInputs::new(misindexed.clone(), block, 31_337).expect("inputs");
        assert_eq!(inputs.target_index, 1);
        assert_eq!(inputs.parent_block_tag(), "0x0");
        assert_eq!(inputs.transaction(), &misindexed);
        // Participants: the earlier transaction's sender and recipient, the target's
        // sender (it creates a contract and so has no recipient), and the fee recipient,
        // which this header leaves at the zero address.
        assert_eq!(
            inputs.participants().expect("participants"),
            [
                parse_address(SENDER).expect("sender"),
                parse_address(COUNTER).expect("counter"),
                parse_address(SENDER).expect("sender"),
                Address::ZERO,
            ]
        );
    }

    #[test]
    fn prefetched_state_answers_from_supplied_state_and_records_the_rest() {
        let state = PrefetchedReplayState::default();
        let sender = parse_address(SENDER).expect("sender");
        let counter = parse_address(COUNTER).expect("counter");

        assert_eq!(state.account(sender).expect("account"), empty_account());
        assert_eq!(
            state.storage(counter, U256::from(1)).expect("storage"),
            U256::ZERO
        );
        assert_eq!(
            state.storage(counter, U256::from(1)).expect("storage"),
            U256::ZERO
        );
        assert_eq!(state.block_hash(7).expect("hash"), B256::ZERO);
        assert_eq!(
            state.missing(),
            [
                StateRequest::Account {
                    address: SENDER.to_owned()
                },
                StateRequest::Storage {
                    address: COUNTER.to_owned(),
                    slot: "0x1".to_owned()
                },
                StateRequest::BlockHash { number: 7 },
            ]
        );

        let mut state = state;
        state.provide(&counter_world()).expect("world");
        state.clear_missing();
        let account = state.account(counter).expect("account");
        assert_eq!(account.nonce, 1);
        assert_eq!(
            account
                .code
                .as_ref()
                .map(|code| code.original_bytes().to_vec()),
            hex_to_bytes(COUNTER_CODE.trim_start_matches("0x"))
        );
        assert_eq!(
            state.account(sender).expect("account").balance,
            U256::from(1_000_000_000_000_000_000u64)
        );
        assert_eq!(
            state.storage(counter, U256::ZERO).expect("slot"),
            U256::from(0x29)
        );
        assert_ne!(state.block_hash(0).expect("hash"), B256::ZERO);
        assert!(state.missing().is_empty(), "supplied state is not recorded");

        // Still-unknown reads keep being recorded, once each.
        state.storage(counter, U256::from(9)).expect("slot");
        state.storage(counter, U256::from(9)).expect("slot");
        assert_eq!(state.missing().len(), 1);
    }

    #[test]
    fn prefetched_state_rejects_malformed_batches_by_name() {
        let mut state = PrefetchedReplayState::default();

        let mut batch = StateBatch::default();
        batch.accounts.insert(
            "0x12".to_owned(),
            AccountState {
                balance: "0x0".to_owned(),
                nonce: "0x0".to_owned(),
                code: "0x".to_owned(),
            },
        );
        let error = state.provide(&batch).expect_err("short address");
        assert!(error.to_string().contains("0x12"), "{error}");

        let mut batch = StateBatch::default();
        batch.accounts.insert(
            SENDER.to_owned(),
            AccountState {
                balance: "0x0".to_owned(),
                nonce: "0x0".to_owned(),
                code: "0xzz".to_owned(),
            },
        );
        let error = state.provide(&batch).expect_err("bad code");
        assert!(error.to_string().contains("bytecode"), "{error}");

        let mut batch = StateBatch::default();
        batch.storage.insert(
            COUNTER.to_owned(),
            BTreeMap::from([("0x0".to_owned(), "nope".to_owned())]),
        );
        let error = state.provide(&batch).expect_err("bad slot value");
        assert!(error.to_string().contains("nope"), "{error}");

        let mut batch = StateBatch::default();
        batch.block_hashes.insert(1, "0x1234".to_owned());
        let error = state.provide(&batch).expect_err("short hash");
        assert!(error.to_string().contains("bytes32"), "{error}");

        let sender = parse_address(SENDER).expect("sender");
        let error = account_info_from_rpc(sender, "0x1", "0xnonce", "0x").expect_err("nonce");
        assert!(error.to_string().contains("0xnonce"), "{error}");
    }

    #[test]
    fn state_requests_and_batches_have_a_stable_json_shape() {
        let requests = vec![
            StateRequest::Account {
                address: SENDER.to_owned(),
            },
            StateRequest::Storage {
                address: COUNTER.to_owned(),
                slot: "0x0".to_owned(),
            },
            StateRequest::BlockHash { number: 7 },
        ];
        let json = serde_json::to_value(&requests).expect("json");
        assert_eq!(
            json,
            json!([
                {"kind": "account", "address": SENDER},
                {"kind": "storage", "address": COUNTER, "slot": "0x0"},
                {"kind": "blockHash", "number": 7}
            ])
        );
        let parsed: Vec<StateRequest> = serde_json::from_value(json).expect("round trip");
        assert_eq!(parsed, requests);

        let batch: StateBatch = serde_json::from_value(json!({
            "accounts": {SENDER: {"balance": "0x1", "nonce": "0x2", "code": "0x"}},
            "storage": {COUNTER: {"0x0": "0x29"}},
            "blockHashes": {"0": format!("0x{}", "22".repeat(32))}
        }))
        .expect("batch");
        assert_eq!(batch.accounts[SENDER].nonce, "0x2");
        assert_eq!(batch.storage[COUNTER]["0x0"], "0x29");
        assert_eq!(batch.block_hashes[&0], format!("0x{}", "22".repeat(32)));
        // Every section is optional so a host answers only what it has.
        let partial: StateBatch = serde_json::from_value(json!({})).expect("empty batch");
        assert_eq!(partial, StateBatch::default());
    }

    #[test]
    fn replay_converges_over_rounds_and_matches_a_fully_supplied_state() {
        let inputs = counter_inputs();
        let world = counter_world();
        let mut state = PrefetchedReplayState::for_inputs(&inputs).expect("seeded");
        // Seeding requests the participants before anything runs: both parties and the
        // fee recipient.
        assert_eq!(
            state.missing(),
            [
                StateRequest::Account {
                    address: format!("0x{}", "00".repeat(20))
                },
                StateRequest::Account {
                    address: SENDER.to_owned()
                },
                StateRequest::Account {
                    address: COUNTER.to_owned()
                },
            ]
        );

        let mut rounds = Vec::new();
        let result = loop {
            state
                .provide(&answer(&world, &state.missing()))
                .expect("provide");
            state.clear_missing();
            let result = replay_debug_trace_with_state(&inputs, &state);
            let missing = state.missing();
            rounds.push(missing.clone());
            if missing.is_empty() {
                break result.expect("complete run");
            }
            assert!(rounds.len() < 10, "replay did not converge: {rounds:?}");
        };

        // Round one ran with real accounts and discovered the block hash and the slot the
        // code reads; round two had everything.
        assert_eq!(rounds.len(), 2);
        assert_eq!(
            rounds[0],
            [
                StateRequest::Storage {
                    address: COUNTER.to_owned(),
                    slot: "0x0".to_owned()
                },
                StateRequest::BlockHash { number: 0 },
            ]
        );

        assert!(!result.failed, "{:?}", result.error);
        let ops: Vec<&str> = result
            .struct_logs
            .iter()
            .map(|log| log.op.as_str())
            .collect();
        assert_eq!(
            ops,
            [
                "PUSH1",
                "BLOCKHASH",
                "POP",
                "PUSH1",
                "SLOAD",
                "PUSH1",
                "ADD",
                "PUSH1",
                "SSTORE",
                "STOP"
            ]
        );
        // Storage is recorded on the steps that touch it: the SLOAD sees the supplied
        // value and the SSTORE writes the increment.
        let steps = result.steps();
        assert_eq!(steps[4].snapshot.storage["0x0"], "0x29");
        assert_eq!(stack_words(&steps[8].snapshot.stack), ["0x2a", "0x0"]);
        assert_eq!(steps[8].snapshot.storage["0x0"], "0x2a");
        assert_eq!(
            steps[8].snapshot.storage_diff["0x0"].after.as_deref(),
            Some("0x2a")
        );

        // The converged run is exactly the run a provider with everything known produces.
        let reference =
            replay_debug_trace_with_state(&inputs, &fully_supplied_state()).expect("reference");
        assert_eq!(result, reference);

        let receipt: RpcReceipt = serde_json::from_value(json!({
            "gasUsed": format!("0x{:x}", result.gas.expect("gas")),
            "status": "0x1"
        }))
        .expect("receipt");
        let trace = replay_transaction_trace(
            inputs.transaction().clone(),
            receipt,
            result.clone(),
            31_337,
        )
        .expect("trace");
        assert_eq!(trace.backend.as_deref(), Some("replay"));
        assert!(trace.success);
        assert!(trace.capabilities.storage_diff);
        assert!(trace.capabilities.account_changes);
        assert_eq!(trace.steps.len(), 10);
        assert_eq!(trace.artifacts.gas.as_ref().map(|gas| gas.used), result.gas);
    }

    #[test]
    fn replay_reports_real_failures_only_once_nothing_is_missing() {
        let inputs = counter_inputs();
        // The sender cannot pay for gas: with all state known, that is a real error.
        let mut world = counter_world();
        world.accounts.get_mut(SENDER).expect("sender").balance = "0x0".to_owned();
        let mut state = PrefetchedReplayState::default();
        state.provide(&world).expect("world");

        let error = replay_debug_trace_with_state(&inputs, &state).expect_err("cannot pay");
        assert!(state.missing().is_empty(), "nothing was missing");
        assert!(error.to_string().contains("execution failed"), "{error}");

        // With nothing known the same failure is not final: the misses explain it.
        let unknown = PrefetchedReplayState::default();
        let _ = replay_debug_trace_with_state(&inputs, &unknown);
        assert!(!unknown.missing().is_empty());
    }

    #[test]
    fn the_two_phases_match_the_single_run_and_an_empty_prefix_runs_nothing() {
        let first = counter_transaction("0xaaa", "0x0", "0x0");
        let target = counter_transaction("0xbbb", "0x1", "0x1");
        let block = counter_block(vec![
            serde_json::to_value(&first).expect("tx"),
            serde_json::to_value(&target).expect("tx"),
        ]);
        let inputs = ReplayInputs::new(target, block, 31_337).expect("inputs");
        let state = fully_supplied_state();

        let prefix = replay_prefix_with_state(&inputs, &state).expect("prefix");
        let phased = replay_target_with_state(&inputs, &prefix, &state).expect("target");
        let single = replay_debug_trace_with_state(&inputs, &state).expect("single run");
        assert_eq!(phased, single);
        assert_eq!(phased.steps()[8].snapshot.storage["0x0"], "0x2b");

        // A target at index zero has nothing to run first, and reads nothing doing it.
        let inputs = counter_inputs();
        let state = fully_supplied_state();
        let _ = replay_prefix_with_state(&inputs, &state).expect("empty prefix");
        assert!(state.reads().is_empty());
    }

    #[test]
    fn a_kept_prefix_carries_its_state_into_later_target_runs() {
        let first = counter_transaction("0xaaa", "0x0", "0x0");
        let target = counter_transaction("0xbbb", "0x1", "0x1");
        let block = counter_block(vec![
            serde_json::to_value(&first).expect("tx"),
            serde_json::to_value(&target).expect("tx"),
        ]);
        let inputs = ReplayInputs::new(target, block, 31_337).expect("inputs");
        let prefix = replay_prefix_with_state(&inputs, &fully_supplied_state()).expect("prefix");

        // Everything the target reads was loaded or written by the prefix, so it runs to
        // completion over a provider that holds nothing and asks it for nothing.
        let empty = PrefetchedReplayState::default();
        let result = replay_target_with_state(&inputs, &prefix, &empty).expect("target");
        assert!(empty.missing().is_empty(), "{:?}", empty.missing());
        assert!(!result.failed, "{:?}", result.error);
        assert_eq!(result.steps()[4].snapshot.storage["0x0"], "0x2a");
        assert_eq!(result.steps()[8].snapshot.storage["0x0"], "0x2b");

        // The prefix's writes take precedence over the parent-block value the provider
        // holds, exactly as a continued run would see them.
        let reference =
            replay_debug_trace_with_state(&inputs, &fully_supplied_state()).expect("reference");
        assert_eq!(
            replay_target_with_state(&inputs, &prefix, &fully_supplied_state()).expect("target"),
            reference
        );
        assert_eq!(result, reference);
    }

    #[test]
    fn reads_are_recorded_and_export_replays_without_a_node() {
        let inputs = counter_inputs();
        let state = fully_supplied_state();
        let result = replay_debug_trace_with_state(&inputs, &state).expect("run");
        assert!(state.missing().is_empty());

        let reads = state.reads();
        assert_eq!(
            reads,
            [
                StateRequest::Account {
                    address: format!("0x{}", "00".repeat(20))
                },
                StateRequest::Account {
                    address: SENDER.to_owned()
                },
                StateRequest::Account {
                    address: COUNTER.to_owned()
                },
                StateRequest::Storage {
                    address: COUNTER.to_owned(),
                    slot: "0x0".to_owned()
                },
                StateRequest::BlockHash { number: 0 },
            ]
        );

        let exported = state.export(&reads);
        assert_eq!(exported.accounts[SENDER].balance, "0xde0b6b3a7640000");
        assert_eq!(exported.accounts[SENDER].nonce, "0x0");
        assert_eq!(exported.accounts[SENDER].code, "0x");
        assert_eq!(exported.accounts[COUNTER].code, COUNTER_CODE);
        assert_eq!(exported.accounts[COUNTER].nonce, "0x1");
        assert_eq!(exported.storage[COUNTER]["0x0"], "0x29");
        assert_eq!(exported.block_hashes[&0], format!("0x{}", "22".repeat(32)));

        // The export is a complete witness: a fresh state loaded from it runs with
        // nothing missing and produces the same result.
        let mut offline = PrefetchedReplayState::default();
        offline.provide(&exported).expect("provide export");
        let again = replay_debug_trace_with_state(&inputs, &offline).expect("offline run");
        assert!(offline.missing().is_empty());
        assert_eq!(again, result);

        // Exporting what is not held yields nothing for it, and clearing reads forgets them.
        let unknown = state.export(&[StateRequest::Storage {
            address: COUNTER.to_owned(),
            slot: "0x7".to_owned(),
        }]);
        assert_eq!(unknown, StateBatch::default());
        state.clear_reads();
        assert!(state.reads().is_empty());
    }

    fn counter_call(tx_index: Option<u64>) -> SimulateCallRequest {
        SimulateCallRequest {
            from_addr: SENDER.to_owned(),
            to_addr: COUNTER.to_owned(),
            calldata: "0x".to_owned(),
            value: "0".to_owned(),
            block: Some(1),
            tx_index,
        }
    }

    #[test]
    fn a_call_on_top_of_a_block_runs_over_its_final_state() {
        // The block is fetched without transaction objects when nothing has to run first.
        let block = counter_block(vec![json!("0xaaa")]);
        let inputs = ReplayInputs::for_call(&counter_call(None), block, 1, 31_337).expect("inputs");
        assert!(inputs.is_simulation());
        assert_eq!(
            inputs.parent_block_tag(),
            "0x1",
            "state is read at the block itself"
        );
        assert!(inputs.transactions().is_empty());
        assert_eq!(inputs.target_index(), 0);
        assert_eq!(inputs.transaction().hash, "");
        assert_eq!(inputs.transaction().gas_price.as_deref(), Some("0x0"));
        assert_eq!(inputs.transaction().gas.as_deref(), Some("0x1c9c380"));
        assert_eq!(
            inputs.participants().expect("participants"),
            [
                parse_address(SENDER).expect("sender"),
                parse_address(COUNTER).expect("counter"),
                Address::ZERO,
            ]
        );

        // The sender's real nonce is 5; the synthetic call carries none and still runs.
        let mut world = counter_world();
        world.accounts.get_mut(SENDER).expect("sender").nonce = "0x5".to_owned();
        let mut state = PrefetchedReplayState::default();
        state.provide(&world).expect("world");
        let result = replay_debug_trace_with_state(&inputs, &state).expect("call");
        assert!(!result.failed, "{:?}", result.error);
        assert!(state.missing().is_empty());
        let steps = result.steps();
        assert_eq!(steps[4].snapshot.storage["0x0"], "0x29");
        assert_eq!(steps[8].snapshot.storage["0x0"], "0x2a");

        let trace =
            replay_simulation_trace(&counter_call(None), result.clone(), 31_337).expect("trace");
        assert_eq!(trace.tx_hash, None);
        assert_eq!(trace.from_addr, SENDER);
        assert_eq!(trace.to_addr.as_deref(), Some(COUNTER));
        assert_eq!(trace.value, "0x0");
        assert_eq!(trace.backend.as_deref(), Some("replay"));
        assert!(trace.success);
        assert!(trace.capabilities.storage_diff);
        assert_eq!(trace.steps.len(), 10);
    }

    #[test]
    fn a_call_inside_a_block_sees_the_transactions_before_it() {
        let first = counter_transaction("0xaaa", "0x0", "0x0");
        let block = counter_block(vec![serde_json::to_value(&first).expect("tx")]);
        let inputs =
            ReplayInputs::for_call(&counter_call(Some(1)), block, 1, 31_337).expect("inputs");
        assert_eq!(
            inputs.parent_block_tag(),
            "0x0",
            "state is read at the parent"
        );
        assert_eq!(inputs.transactions().len(), 1);
        assert_eq!(inputs.target_index(), 1);

        let result = replay_debug_trace_with_state(&inputs, &fully_supplied_state()).expect("call");
        assert!(!result.failed, "{:?}", result.error);
        let steps = result.steps();
        // The mined increment ran first, so the call reads 0x2a and writes 0x2b.
        assert_eq!(steps[4].snapshot.storage["0x0"], "0x2a");
        assert_eq!(steps[8].snapshot.storage["0x0"], "0x2b");
    }

    #[test]
    fn call_inputs_reject_what_cannot_be_placed() {
        let hash_only = counter_block(vec![json!("0xaaa")]);
        let error = ReplayInputs::for_call(&counter_call(Some(1)), hash_only, 1, 31_337)
            .expect_err("needs full transactions");
        assert!(
            error.to_string().contains("full transaction objects"),
            "{error}"
        );

        let block = counter_block(vec![serde_json::to_value(counter_transaction(
            "0xaaa", "0x0", "0x0",
        ))
        .expect("tx")]);
        let error = ReplayInputs::for_call(&counter_call(Some(3)), block.clone(), 1, 31_337)
            .expect_err("index past the block");
        assert!(error.to_string().contains("has 1 transactions"), "{error}");

        let error = ReplayInputs::for_call(&counter_call(Some(0)), block, 0, 31_337)
            .expect_err("genesis has no parent");
        assert!(error.to_string().contains("block 0"), "{error}");

        let mut bad_value = counter_call(None);
        bad_value.value = "lots".to_owned();
        assert!(ReplayInputs::for_call(&bad_value, counter_block(vec![]), 1, 31_337).is_err());
    }

    // PUSH1 0x29 PUSH1 0 SSTORE, then copy the counter runtime out and return it: a
    // constructor that seeds slot 0 before handing over the counter.
    const COUNTER_INIT_CODE: &str =
        "0x6029600055600e6011600039600e6000f36000405060005460010160005500";

    const ANVIL_SENDER: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    fn local_call(to: &str) -> SimulateCallRequest {
        SimulateCallRequest {
            from_addr: SENDER.to_owned(),
            to_addr: to.to_owned(),
            calldata: "0x".to_owned(),
            value: "0".to_owned(),
            block: None,
            tx_index: None,
        }
    }

    #[test]
    fn a_local_chain_runs_runtime_code_without_a_node() {
        let chain = LocalChain::new()
            .with_account(SENDER, "1ether", 0, "0x")
            .expect("sender")
            .with_account(
                &COUNTER.to_uppercase().replace("0X", "0x"),
                "0",
                1,
                COUNTER_CODE,
            )
            .expect("counter")
            .with_storage(COUNTER, "0x0", "0x29")
            .expect("slot");
        assert_eq!(chain.chain_id(), 31_337);
        assert_eq!(chain.block_number(), 1);

        let trace = chain.call(&[], &local_call(COUNTER)).expect("call");
        assert_eq!(trace.tx_hash, None);
        assert_eq!(trace.backend.as_deref(), Some("replay"));
        assert!(trace.success, "{:?}", trace.error);
        assert_eq!(trace.steps.len(), 10);
        assert_eq!(trace.steps[4].snapshot.storage["0x0"], "0x29");
        assert_eq!(trace.steps[8].snapshot.storage["0x0"], "0x2a");
        // Accounts never described, the fee recipient here, are simply empty.
        assert!(chain.state().expect("state").missing().is_empty());
    }

    #[test]
    fn a_local_chain_deploys_then_calls_with_the_constructor_state() {
        let chain = LocalChain::new()
            .with_account(SENDER, "1ether", 0, "0x")
            .expect("sender");
        let deployment = chain
            .deployment(SENDER, COUNTER_INIT_CODE, "0", 0)
            .expect("deployment");
        let created = LocalChain::created_address(SENDER, 0).expect("address");

        let constructor = chain.deploy(&deployment).expect("deploy");
        assert!(constructor.success, "{:?}", constructor.error);
        assert_eq!(constructor.tx_hash, None);
        assert_eq!(
            constructor.contract_address.as_deref(),
            Some(created.as_str())
        );
        assert_eq!(constructor.output, COUNTER_CODE);
        let ops: Vec<&str> = constructor
            .steps
            .iter()
            .map(|step| step.op.as_str())
            .collect();
        assert_eq!(&ops[..3], ["PUSH1", "PUSH1", "SSTORE"]);
        assert_eq!(*ops.last().expect("last"), "RETURN");

        // The call runs after the deployment in the same block and sees slot 0 == 0x29.
        let trace = chain
            .call(&[deployment], &local_call(&created))
            .expect("call");
        assert!(trace.success, "{:?}", trace.error);
        assert_eq!(trace.to_addr.as_deref(), Some(created.as_str()));
        assert_eq!(trace.steps[4].snapshot.storage["0x0"], "0x29");
        assert_eq!(trace.steps[8].snapshot.storage["0x0"], "0x2a");
    }

    #[test]
    fn created_addresses_follow_create_and_deployments_can_fail() {
        assert_eq!(
            LocalChain::created_address(ANVIL_SENDER, 0).expect("address"),
            "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        );
        assert!(LocalChain::created_address("0x12", 0).is_err());

        let chain = LocalChain::new()
            .with_account(SENDER, "1ether", 0, "0x")
            .expect("sender")
            .with_block_number(0)
            .with_timestamp(1_700_000_000)
            .with_gas_limit(1_000_000)
            .with_chain_id(1);
        assert_eq!(
            chain.block_number(),
            1,
            "genesis has no parent; the run moves to block 1"
        );
        assert_eq!(chain.gas_limit(), 1_000_000);
        // INVALID as the whole constructor: the deployment fails and says so.
        let deployment = chain
            .deployment(SENDER, "0xfe", "0", 0)
            .expect("deployment");
        let trace = chain.deploy(&deployment).expect("trace");
        assert!(!trace.success);
        assert!(trace.error.is_some());
        assert!(chain.deployment("0x12", "0x", "0", 0).is_err());
        assert!(LocalChain::new()
            .with_account(SENDER, "lots", 0, "0x")
            .is_err());
        assert!(LocalChain::new()
            .with_storage(COUNTER, "0x0", "nope")
            .is_err());
    }

    #[test]
    fn a_replay_bundle_replays_offline_and_round_trips_through_json() {
        let tx = counter_transaction("0xaaa", "0x0", "0x0");
        let block = counter_block(vec![serde_json::to_value(&tx).expect("tx")]);
        let inputs = ReplayInputs::new(tx, block, 31_337).expect("inputs");
        let state = fully_supplied_state();
        let result = replay_debug_trace_with_state(&inputs, &state).expect("replay");
        let receipt: RpcReceipt =
            serde_json::from_value(json!({"gasUsed": "0x5208", "status": "0x1", "logs": []}))
                .expect("receipt");
        let online = replay_transaction_trace(
            inputs.transaction().clone(),
            receipt.clone(),
            result.clone(),
            31_337,
        )
        .expect("trace");

        let bundle = ReplayBundle::for_transaction(&inputs, receipt, state.export(&state.reads()));
        assert_eq!(bundle.version, REPLAY_BUNDLE_VERSION);
        assert!(!bundle.state.is_empty());
        assert!(bundle
            .describe()
            .starts_with("transaction 0xaaa on chain 31337"));
        let json = serde_json::to_string(&bundle).expect("json");
        assert!(json.contains("\"kind\":\"transaction\""), "{json}");
        let restored: ReplayBundle = serde_json::from_str(&json).expect("bundle");
        assert_eq!(restored, bundle);
        assert_eq!(restored.replay().expect("offline replay"), online);

        // A bundle missing state names the first item it lacks; a newer format is refused.
        let mut incomplete = bundle.clone();
        incomplete.state = StateBatch::default();
        let error = incomplete.replay().expect_err("missing state");
        assert!(
            error.to_string().contains("does not hold all the state"),
            "{error}"
        );
        let mut future = bundle;
        future.version = 99;
        let error = future.replay().expect_err("future version");
        assert!(error.to_string().contains("version 99"), "{error}");
    }

    #[test]
    fn a_call_bundle_replays_the_call_where_it_was_placed() {
        let request = counter_call(None);
        let inputs =
            ReplayInputs::for_call(&request, counter_block(Vec::new()), 1, 31_337).expect("inputs");
        let state = fully_supplied_state();
        let result = replay_debug_trace_with_state(&inputs, &state).expect("replay");
        let online = replay_simulation_trace(&request, result.clone(), 31_337).expect("trace");
        let bundle = ReplayBundle::for_call(&inputs, &request, state.export(&state.reads()));
        assert!(
            bundle.describe().contains("call to"),
            "{}",
            bundle.describe()
        );
        let json = serde_json::to_string(&bundle).expect("json");
        assert!(json.contains("\"kind\":\"call\""), "{json}");
        let restored: ReplayBundle = serde_json::from_str(&json).expect("bundle");
        assert_eq!(restored.replay().expect("offline replay"), online);
    }

    #[test]
    fn chain_support_names_what_the_engine_models() {
        assert_eq!(replay_chain_support(1), Ok(Vec::new()));
        assert_eq!(replay_chain_support(11_155_111), Ok(Vec::new()));
        assert_eq!(replay_chain_support(31_337), Ok(Vec::new()));

        let notes = replay_chain_support(10).expect("EVM-equivalent chains run");
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].contains("OP Mainnet (chain id 10)"),
            "{}",
            notes[0]
        );
        assert!(notes[0].contains("gas figures may differ"), "{}", notes[0]);
        let notes = replay_chain_support(424_242).expect("unknown chains run");
        assert!(
            notes[0].contains("chain id 424242 is not known to the replay engine"),
            "{}",
            notes[0]
        );

        let error = replay_chain_support(42_161).expect_err("Arbitrum is refused");
        assert!(error.contains("Arbitrum One (chain id 42161)"), "{error}");
        assert!(error.contains("`--backend debug-rpc`"), "{error}");
        assert!(replay_chain_support(324).is_err());
        assert!(replay_chain_support(1_101).is_err());

        // The notes travel with the trace so a client can show them.
        assert!(replay_capabilities(1).notes.is_empty());
        assert_eq!(replay_capabilities(8_453).notes.len(), 1);
    }

    #[test]
    fn unmodelled_chains_are_refused_before_execution() {
        let tx = counter_transaction("0xaaa", "0x0", "0x0");
        let block = counter_block(vec![serde_json::to_value(&tx).expect("tx")]);
        let inputs = ReplayInputs::new(tx, block, 42_161).expect("inputs");
        let error = replay_debug_trace_with_state(&inputs, &fully_supplied_state())
            .expect_err("Arbitrum execution is not modelled");
        assert!(error.to_string().contains("Arbitrum One"), "{error}");
        assert!(
            replay_prefix_with_state(&inputs, &fully_supplied_state()).is_err(),
            "the check guards the first phase a host runs"
        );
    }

    #[test]
    fn replay_runs_the_block_prefix_before_the_target() {
        // Two increments in one block: the target must see the first one's write.
        let first = counter_transaction("0xaaa", "0x0", "0x0");
        let target = counter_transaction("0xbbb", "0x1", "0x1");
        let block = counter_block(vec![
            serde_json::to_value(&first).expect("tx"),
            serde_json::to_value(&target).expect("tx"),
        ]);
        let inputs = ReplayInputs::new(target, block, 31_337).expect("inputs");
        let result =
            replay_debug_trace_with_state(&inputs, &fully_supplied_state()).expect("replay");

        assert!(!result.failed, "{:?}", result.error);
        let steps = result.steps();
        assert_eq!(steps[4].snapshot.storage["0x0"], "0x2a");
        assert_eq!(steps[8].snapshot.storage["0x0"], "0x2b");
    }

    fn mock_rpc_transaction(hash: &str) -> RpcTransaction {
        RpcTransaction {
            hash: hash.to_owned(),
            from_addr: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_owned(),
            to: Some("0x5fbdb2315678afecb367f032d93f642f64180aa3".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas: Some("0x5208".to_owned()),
            gas_price: Some("0x1".to_owned()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: Some("0x0".to_owned()),
            block_number: Some("0x1".to_owned()),
            transaction_index: Some("0x0".to_owned()),
            transaction_type: Some("0x0".to_owned()),
            chain_id: Some("0x1".to_owned()),
        }
    }

    #[test]
    fn replay_target_index_uses_rpc_index_or_hash_fallback() {
        let transactions = vec![mock_rpc_transaction("0xaaa"), mock_rpc_transaction("0xbbb")];

        assert_eq!(
            replay_target_index(&transactions, 1, "0xbbb").expect("target by index"),
            1
        );
        assert_eq!(
            replay_target_index(&transactions, 9, "0xaaa").expect("target by hash"),
            0
        );
        assert!(replay_target_index(&transactions, 0, "0xccc")
            .expect_err("missing tx")
            .to_string()
            .contains("could not find transaction"));
    }

    #[test]
    fn replay_full_block_transactions_rejects_hash_only_blocks() {
        let error =
            replay_full_block_transactions(12, &[RpcBlockTransaction::Hash("0xabc".to_owned())])
                .expect_err("hash-only block should fail preflight");
        let message = error.to_string();
        assert!(message.contains("full transaction objects"), "{message}");
        assert!(message.contains("block 12"), "{message}");

        let transactions = replay_full_block_transactions(
            12,
            &[RpcBlockTransaction::Full(Box::new(mock_rpc_transaction(
                "0xabc",
            )))],
        )
        .expect("full transaction");
        assert_eq!(transactions[0].hash, "0xabc");
    }

    #[test]
    fn selects_mainnet_specs_by_block_and_timestamp() {
        assert_eq!(replay_spec_for_chain(1, 0, 0), SpecId::FRONTIER);
        assert_eq!(
            replay_spec_for_chain(1, 200_000, 0),
            SpecId::FRONTIER_THAWING
        );
        assert_eq!(replay_spec_for_chain(1, 1_150_000, 0), SpecId::HOMESTEAD);
        assert_eq!(replay_spec_for_chain(1, 12_965_000, 0), SpecId::LONDON);
        assert_eq!(replay_spec_for_chain(1, 15_537_394, 0), SpecId::MERGE);
        assert_eq!(
            replay_spec_for_chain(1, 17_034_870, 1_681_338_455),
            SpecId::SHANGHAI
        );
        assert_eq!(
            replay_spec_for_chain(1, 19_426_587, 1_710_338_135),
            SpecId::CANCUN
        );
        assert_eq!(
            replay_spec_for_chain(1, 22_431_084, 1_746_612_311),
            SpecId::PRAGUE
        );
        assert_eq!(
            replay_spec_for_chain(1, 24_800_000, 1_764_798_551),
            SpecId::OSAKA
        );
    }

    #[test]
    fn selects_common_testnet_and_dev_specs() {
        assert_eq!(
            replay_spec_for_chain(11_155_111, 5_000_000, 1_706_655_072),
            SpecId::CANCUN
        );
        assert_eq!(
            replay_spec_for_chain(11_155_111, 5_000_000, 1_741_159_776),
            SpecId::PRAGUE
        );
        assert_eq!(
            replay_spec_for_chain(17_000, 1, 1_759_308_480),
            SpecId::OSAKA
        );
        assert_eq!(
            replay_spec_for_chain(560_048, 1, 1_742_999_831),
            SpecId::CANCUN
        );
        assert_eq!(
            replay_spec_for_chain(560_048, 1, 1_742_999_832),
            SpecId::PRAGUE
        );
        assert_eq!(
            replay_spec_for_chain(31_337, 1, 1_818_000_000),
            SpecId::PRAGUE
        );
    }
}
