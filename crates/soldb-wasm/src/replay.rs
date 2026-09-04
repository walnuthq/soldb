//! Host-driven replay: REVM runs in the module and the host supplies state in rounds.
//!
//! REVM reads state synchronously and a WebAssembly module cannot block on the network,
//! so a replay here is a loop the host drives. [`Replay::prepare`] takes the transaction,
//! its receipt, its block with full transactions, and the chain id. [`Replay::status`]
//! lists the parent-block state the next run needs; the host fetches it with ordinary
//! `eth_*` calls and hands it to [`Replay::provide_state`]; [`Replay::run`] executes and
//! either completes or lists what it still lacks. Missing values default to empty and are
//! recorded, so every round discovers everything the current path touches, and the loop
//! converges in a few rounds. [`Replay::finish`] then yields the [`Trace`], identical to
//! the one the native `replay` backend produces from the same chain.
//!
//! The first status already names the accounts every replay reads, so a host that
//! answers it before the first run saves a round. The transactions before the target in
//! its block run only until they run with nothing missing; from then on their state is
//! kept and each round re-executes the target alone. Once complete,
//! [`Replay::export_state`] returns exactly the state the replay depended on, which a
//! host can keep, share, or feed back through [`Replay::provide_state`] to replay the
//! same transaction in one round with no node at all.
//!
//! [`Replay::prepare_call`] drives the same loop for a call that was never mined: the
//! chain as it stood at a block becomes the fork the call runs on, on top of the block
//! or inside it at a transaction index, which is what stepping through an `eth_call`
//! on a fork needs.

use std::collections::BTreeSet;

use serde::Serialize;
use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_evm::{
    replay_prefix_with_state, replay_simulation_trace, replay_target_with_state,
    replay_transaction_trace, PrefetchedReplayState, ReplayInputs, ReplayPrefix,
    RpcBlockWithTransactions, RpcReceipt, RpcTransaction, SimulateCallRequest, StateBatch,
    StateRequest,
};

use crate::pipeline::{parse_json, to_json, Trace};

/// Where a replay stands, as reported to the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum ReplayStatus {
    /// A run completed with nothing missing; [`Replay::finish`] yields the trace.
    Complete,
    /// State the next run needs. Fetch every request at `block` and pass the results to
    /// [`Replay::provide_state`], then run again.
    NeedsState {
        block: String,
        requests: Vec<StateRequest>,
    },
}

/// What a replay produces a trace of.
#[derive(Debug)]
enum ReplayTarget {
    Transaction { receipt: RpcReceipt },
    Call { request: SimulateCallRequest },
}

/// A replay in progress: the inputs, the state supplied so far, the block prefix once
/// it ran clean, and the result once a run completes.
#[derive(Debug)]
pub struct Replay {
    inputs: ReplayInputs,
    /// The mined transaction's receipt, or the call being simulated.
    target: ReplayTarget,
    state: PrefetchedReplayState,
    /// The prefix's state, kept from the first round in which the prefix read nothing
    /// missing. Later rounds run the target over it instead of re-executing the prefix.
    prefix: Option<ReplayPrefix>,
    /// What the kept prefix read, so an export covers it even though later rounds never
    /// read it through the provider again.
    prefix_reads: BTreeSet<StateRequest>,
    /// Everything the completed replay depended on.
    used: BTreeSet<StateRequest>,
    trace: Option<TransactionTrace>,
}

impl Replay {
    /// Prepares a replay from the node's responses. `chain_id` is the `eth_chainId`
    /// result, hex or decimal.
    pub fn prepare(
        transaction_json: &str,
        receipt_json: &str,
        block_json: &str,
        chain_id: &str,
    ) -> SoldbResult<Self> {
        let transaction =
            parse_json::<RpcTransaction>("`eth_getTransactionByHash` result", transaction_json)?;
        let receipt = parse_json::<RpcReceipt>("`eth_getTransactionReceipt` result", receipt_json)?;
        let block =
            parse_json::<RpcBlockWithTransactions>("`eth_getBlockByNumber` result", block_json)?;
        let chain_id = parse_chain_id(chain_id)?;
        let inputs = ReplayInputs::new(transaction, block, chain_id)?;
        Self::over(inputs, ReplayTarget::Transaction { receipt })
    }

    /// Prepares a call against the chain as it stood at the block in `block_json`, the
    /// `result` of `eth_getBlockByNumber`, whose `number` names the fork point. With
    /// `tx_index` the call runs inside that block after the transactions before the
    /// index, which then must be full objects; without it, on top of the block. `value`
    /// accepts the same forms as `soldb simulate --value`.
    pub fn prepare_call(
        from: &str,
        to: &str,
        calldata: &str,
        value: &str,
        block_json: &str,
        chain_id: &str,
        tx_index: Option<u64>,
    ) -> SoldbResult<Self> {
        let block =
            parse_json::<RpcBlockWithTransactions>("`eth_getBlockByNumber` result", block_json)?;
        let block_number = block
            .header
            .number
            .as_deref()
            .ok_or_else(|| {
                SoldbError::Message(
                    "the block has no `number`; pass the `eth_getBlockByNumber` result whole"
                        .to_owned(),
                )
            })
            .and_then(parse_chain_id)?;
        let chain_id = parse_chain_id(chain_id)?;
        let request = SimulateCallRequest {
            from_addr: from.to_owned(),
            to_addr: to.to_owned(),
            calldata: calldata.to_owned(),
            value: value.to_owned(),
            block: Some(block_number),
            tx_index,
        };
        let inputs = ReplayInputs::for_call(&request, block, block_number, chain_id)?;
        Self::over(inputs, ReplayTarget::Call { request })
    }

    fn over(inputs: ReplayInputs, target: ReplayTarget) -> SoldbResult<Self> {
        let state = PrefetchedReplayState::for_inputs(&inputs)?;
        Ok(Self {
            inputs,
            target,
            state,
            prefix: None,
            prefix_reads: BTreeSet::new(),
            used: BTreeSet::new(),
            trace: None,
        })
    }

    #[must_use]
    pub fn status(&self) -> ReplayStatus {
        if self.trace.is_some() {
            return ReplayStatus::Complete;
        }
        ReplayStatus::NeedsState {
            block: self.inputs.parent_block_tag(),
            requests: self.state.missing(),
        }
    }

    pub fn status_json(&self) -> SoldbResult<String> {
        to_json(&self.status())
    }

    /// Adds parent-block state, replacing anything held for the same keys.
    pub fn provide_state(&mut self, batch_json: &str) -> SoldbResult<()> {
        let batch = parse_json::<StateBatch>("state batch", batch_json)?;
        self.state.provide(&batch)
    }

    /// Runs the replay over the state supplied so far.
    ///
    /// A run that recorded missing state reports it and discards its result, whatever
    /// that result was: with defaults in play a failure proves nothing. An error is
    /// returned only when a run failed with nothing missing. The block prefix is kept
    /// from the first run in which it read nothing missing, so later runs execute only
    /// the target; a prefix that read defaults is still used for the round, since the
    /// target's reads are worth discovering, but is not kept.
    pub fn run(&mut self) -> SoldbResult<ReplayStatus> {
        self.state.clear_missing();
        self.state.clear_reads();

        let prefix = match &self.prefix {
            Some(prefix) => prefix.clone(),
            None => match replay_prefix_with_state(&self.inputs, &self.state) {
                Ok(prefix) if self.state.missing().is_empty() => {
                    self.prefix_reads = self.state.reads().into_iter().collect();
                    self.prefix = Some(prefix.clone());
                    prefix
                }
                Ok(prefix) => prefix,
                Err(error) => {
                    let missing = self.state.missing();
                    if missing.is_empty() {
                        return Err(error);
                    }
                    self.trace = None;
                    return Ok(self.needs_state(missing));
                }
            },
        };

        let result = replay_target_with_state(&self.inputs, &prefix, &self.state);
        let missing = self.state.missing();
        if !missing.is_empty() {
            self.trace = None;
            return Ok(self.needs_state(missing));
        }
        let debug_result = result?;
        self.used = self
            .prefix_reads
            .iter()
            .cloned()
            .chain(self.state.reads())
            .collect();
        self.trace = Some(match &self.target {
            ReplayTarget::Transaction { receipt } => replay_transaction_trace(
                self.inputs.transaction().clone(),
                receipt.clone(),
                &debug_result,
                self.inputs.chain_id(),
            )?,
            ReplayTarget::Call { request } => {
                replay_simulation_trace(request, &debug_result, self.inputs.chain_id())?
            }
        });
        Ok(ReplayStatus::Complete)
    }

    fn needs_state(&self, requests: Vec<StateRequest>) -> ReplayStatus {
        ReplayStatus::NeedsState {
            block: self.inputs.parent_block_tag(),
            requests,
        }
    }

    /// Whether the block prefix has run with nothing missing and is being reused.
    #[must_use]
    pub fn prefix_cached(&self) -> bool {
        self.prefix.is_some()
    }

    /// Exactly the parent-block state the completed replay depended on, in the form
    /// [`Replay::provide_state`] accepts. Feeding it to a new replay of the same
    /// transaction completes in one run without a node.
    pub fn export_state(&self) -> SoldbResult<StateBatch> {
        if self.trace.is_none() {
            return Err(SoldbError::Message(
                "the replay has not completed; there is no state to export yet".to_owned(),
            ));
        }
        let used = self.used.iter().cloned().collect::<Vec<_>>();
        Ok(self.state.export(&used))
    }

    pub fn export_state_json(&self) -> SoldbResult<String> {
        to_json(&self.export_state()?)
    }

    pub fn run_json(&mut self) -> SoldbResult<String> {
        let status = self.run()?;
        to_json(&status)
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.trace.is_some()
    }

    /// The completed replay as a [`Trace`].
    pub fn finish(self) -> SoldbResult<Trace> {
        let trace = self.trace.ok_or_else(|| {
            SoldbError::Message(
                "the replay has not completed; run it until `status` reports `complete`".to_owned(),
            )
        })?;
        Ok(Trace::from_trace(trace))
    }
}

fn parse_chain_id(text: &str) -> SoldbResult<u64> {
    let text = text.trim();
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|error| {
        SoldbError::Message(format!(
            "invalid chain id `{text}`: {error}; pass the `eth_chainId` result"
        ))
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use soldb_evm::StateRequest;

    use super::{parse_chain_id, Replay, ReplayStatus};

    const SENDER: &str = "0x1111111111111111111111111111111111111111";
    const COUNTER: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    const ZERO: &str = "0x0000000000000000000000000000000000000000";
    // PUSH1 0 BLOCKHASH POP  PUSH1 0 SLOAD PUSH1 1 ADD PUSH1 0 SSTORE  STOP.
    const COUNTER_CODE: &str = "0x6000405060005460010160005500";

    fn transaction() -> Value {
        json!({
            "hash": "0xaaa",
            "from": SENDER,
            "to": COUNTER,
            "value": "0x0",
            "input": "0x",
            "gas": "0x186a0",
            "gasPrice": "0x1",
            "nonce": "0x0",
            "blockNumber": "0x1",
            "transactionIndex": "0x0",
            "type": "0x0",
            "chainId": "0x7a69"
        })
    }

    fn receipt() -> String {
        json!({"gasUsed": "0x5208", "status": "0x1"}).to_string()
    }

    fn block() -> String {
        json!({
            "hash": format!("0x{}", "11".repeat(32)),
            "timestamp": "0x64",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x0",
            "mixHash": format!("0x{}", "33".repeat(32)),
            "transactions": [transaction()]
        })
        .to_string()
    }

    /// Everything the counter replay can ask for, as the host's node would answer.
    fn world() -> Value {
        json!({
            "accounts": {
                SENDER: {"balance": "0xde0b6b3a7640000", "nonce": "0x0", "code": "0x"},
                COUNTER: {"balance": "0x0", "nonce": "0x1", "code": COUNTER_CODE}
            },
            "storage": {COUNTER: {"0x0": "0x29"}},
            "blockHashes": {"0": format!("0x{}", "22".repeat(32))}
        })
    }

    /// The host side of the loop: answers the requests in `status` out of `world`.
    fn answer(world: &Value, status: &ReplayStatus) -> String {
        let ReplayStatus::NeedsState { requests, .. } = status else {
            panic!("nothing to answer");
        };
        let empty_account = json!({"balance": "0x0", "nonce": "0x0", "code": "0x"});
        let mut batch = json!({"accounts": {}, "storage": {}, "blockHashes": {}});
        for request in requests {
            match request {
                StateRequest::Account { address } => {
                    let account = world["accounts"]
                        .get(address)
                        .cloned()
                        .unwrap_or(empty_account.clone());
                    batch["accounts"][address] = account;
                }
                StateRequest::Storage { address, slot } => {
                    let value = world["storage"][address]
                        .get(slot)
                        .cloned()
                        .unwrap_or(json!("0x0"));
                    if batch["storage"].get(address).is_none() {
                        batch["storage"][address] = json!({});
                    }
                    batch["storage"][address][slot] = value;
                }
                StateRequest::BlockHash { number } => {
                    let hash = world["blockHashes"][number.to_string()].clone();
                    batch["blockHashes"][number.to_string()] = hash;
                }
            }
        }
        batch.to_string()
    }

    fn prepared() -> Replay {
        Replay::prepare(&transaction().to_string(), &receipt(), &block(), "0x7a69")
            .expect("prepared")
    }

    fn drive(world: &Value, replay: &mut Replay) -> usize {
        let mut runs = 0;
        let mut status = replay.status();
        while status != ReplayStatus::Complete {
            replay
                .provide_state(&answer(world, &status))
                .expect("provide");
            status = replay.run().expect("run");
            runs += 1;
            assert!(runs < 10, "did not converge: {status:?}");
        }
        runs
    }

    #[test]
    fn prepare_asks_for_the_participants_first() {
        let replay = prepared();
        assert!(!replay.is_complete());
        assert_eq!(
            replay.status(),
            ReplayStatus::NeedsState {
                block: "0x0".to_owned(),
                requests: vec![
                    StateRequest::Account {
                        address: ZERO.to_owned()
                    },
                    StateRequest::Account {
                        address: SENDER.to_owned()
                    },
                    StateRequest::Account {
                        address: COUNTER.to_owned()
                    },
                ],
            }
        );
        let status: Value =
            serde_json::from_str(&replay.status_json().expect("json")).expect("value");
        assert_eq!(status["status"], "needsState");
        assert_eq!(status["block"], "0x0");
        assert_eq!(
            status["requests"][1],
            json!({"kind": "account", "address": SENDER})
        );
    }

    #[test]
    fn converges_in_two_runs_and_yields_a_replay_trace() {
        let mut replay = prepared();
        let world = world();

        assert_eq!(drive(&world, &mut replay), 2);
        assert!(replay.is_complete());
        assert_eq!(replay.status(), ReplayStatus::Complete);
        assert_eq!(
            replay.status_json().expect("json"),
            r#"{"status":"complete"}"#
        );

        let trace = replay.finish().expect("trace");
        let summary = trace.summary();
        assert_eq!(summary.backend.as_deref(), Some("replay"));
        assert!(summary.success);
        assert_eq!(summary.tx_hash.as_deref(), Some("0xaaa"));
        assert_eq!(summary.step_count, 10);
        assert!(summary.capabilities.storage_diff);
        assert!(summary.capabilities.account_changes);

        let sload: Value =
            serde_json::from_str(&trace.step_json(4).expect("step").expect("in range"))
                .expect("step");
        assert_eq!(sload["op"], "SLOAD");
        assert_eq!(sload["snapshot"]["storage"]["0x0"], "0x29");
        let sstore: Value =
            serde_json::from_str(&trace.step_json(8).expect("step").expect("in range"))
                .expect("step");
        assert_eq!(sstore["op"], "SSTORE");
        assert_eq!(sstore["snapshot"]["storage"]["0x0"], "0x2a");

        let document: Value =
            serde_json::from_str(&trace.to_web_json(None).expect("web JSON")).expect("document");
        assert_eq!(document["backend"], "replay");
        assert_eq!(document["steps"].as_array().map(Vec::len), Some(10));
    }

    #[test]
    fn the_second_round_asks_only_for_what_execution_touched() {
        let mut replay = prepared();
        let world = world();
        let first = replay.status();
        replay
            .provide_state(&answer(&world, &first))
            .expect("accounts");

        let status = replay.run().expect("run");
        assert_eq!(
            status,
            ReplayStatus::NeedsState {
                block: "0x0".to_owned(),
                requests: vec![
                    StateRequest::Storage {
                        address: COUNTER.to_owned(),
                        slot: "0x0".to_owned()
                    },
                    StateRequest::BlockHash { number: 0 },
                ],
            }
        );
        assert_eq!(
            replay.status(),
            status,
            "status repeats what the run reported"
        );
        assert!(!replay.is_complete());
        let json: Value = serde_json::from_str(&replay.run_json().expect("json")).expect("value");
        assert_eq!(json["status"], "needsState");
        assert_eq!(json["requests"][0]["kind"], "storage");
        assert_eq!(
            json["requests"][1],
            json!({"kind": "blockHash", "number": 0})
        );
    }

    #[test]
    fn running_before_supplying_anything_still_reports_what_is_needed() {
        let mut replay = prepared();
        let status = replay.run().expect("run");
        let ReplayStatus::NeedsState { requests, .. } = status else {
            panic!("a run with no state cannot complete");
        };
        assert!(requests.contains(&StateRequest::Account {
            address: SENDER.to_owned()
        }));
        assert!(!replay.is_complete());
    }

    #[test]
    fn a_failure_with_nothing_missing_is_reported_as_the_error_it_is() {
        let mut replay = prepared();
        let mut world = world();
        world["accounts"][SENDER]["balance"] = json!("0x0");
        replay.provide_state(&world.to_string()).expect("world");

        let error = replay.run().expect_err("the sender cannot pay for gas");
        assert!(error.to_string().contains("execution failed"), "{error}");
        assert!(!replay.is_complete());
        assert_eq!(
            replay.status(),
            ReplayStatus::NeedsState {
                block: "0x0".to_owned(),
                requests: Vec::new()
            }
        );
    }

    #[test]
    fn keeps_the_prefix_once_it_ran_clean_and_reuses_it() {
        // Two increments in one block: the first is the prefix, the second the target.
        let first = transaction();
        let mut target = transaction();
        target["hash"] = json!("0xbbb");
        target["nonce"] = json!("0x1");
        target["transactionIndex"] = json!("0x1");
        let block = json!({
            "hash": format!("0x{}", "11".repeat(32)),
            "timestamp": "0x64",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x0",
            "mixHash": format!("0x{}", "33".repeat(32)),
            "transactions": [first, target]
        })
        .to_string();
        let mut replay =
            Replay::prepare(&target.to_string(), &receipt(), &block, "0x7a69").expect("prepared");
        let world = world();

        // Round one: the accounts are known but the prefix reads the slot and the block
        // hash it has not been given, so its state is not kept.
        replay
            .provide_state(&answer(&world, &replay.status()))
            .expect("accounts");
        let status = replay.run().expect("run");
        assert!(matches!(status, ReplayStatus::NeedsState { .. }));
        assert!(!replay.prefix_cached());

        // Round two: the prefix runs clean and is kept; the target, which reads only what
        // the prefix loaded and wrote, completes in the same run.
        replay
            .provide_state(&answer(&world, &status))
            .expect("rest");
        assert_eq!(replay.run().expect("run"), ReplayStatus::Complete);
        assert!(replay.prefix_cached());

        // The export covers the prefix's reads even though the final round served them
        // from the kept prefix, so a fresh replay from it completes in one run.
        let exported = replay.export_state_json().expect("export");
        let trace = replay.finish().expect("trace");
        let mut offline =
            Replay::prepare(&target.to_string(), &receipt(), &block, "0x7a69").expect("prepared");
        offline.provide_state(&exported).expect("provide export");
        assert_eq!(offline.run().expect("run"), ReplayStatus::Complete);
        assert!(offline.prefix_cached());
        assert_eq!(
            offline.finish().expect("trace").to_json().expect("json"),
            trace.to_json().expect("json")
        );
        let sstore: Value =
            serde_json::from_str(&trace.step_json(8).expect("step").expect("in range"))
                .expect("step");
        assert_eq!(sstore["snapshot"]["storage"]["0x0"], "0x2b");
    }

    #[test]
    fn exports_exactly_the_state_a_completed_replay_used() {
        let mut replay = prepared();
        let world = world();
        drive(&world, &mut replay);

        let exported = replay.export_state().expect("export");
        let json: Value =
            serde_json::from_str(&replay.export_state_json().expect("json")).expect("value");
        assert_eq!(json["accounts"][SENDER]["balance"], "0xde0b6b3a7640000");
        assert_eq!(json["accounts"][COUNTER]["code"], COUNTER_CODE);
        assert_eq!(json["accounts"][ZERO]["nonce"], "0x0");
        assert_eq!(json["storage"][COUNTER]["0x0"], "0x29");
        assert_eq!(json["blockHashes"]["0"], format!("0x{}", "22".repeat(32)));
        assert_eq!(exported.accounts.len(), 3);
        assert_eq!(exported.storage[COUNTER].len(), 1);

        // Replaying from the export needs no further state and gives the same trace.
        let trace = replay.finish().expect("trace");
        let mut offline = prepared();
        offline
            .provide_state(&serde_json::to_string(&exported).expect("json"))
            .expect("provide");
        assert_eq!(offline.run().expect("run"), ReplayStatus::Complete);
        assert_eq!(offline.export_state().expect("export again"), exported);
        assert_eq!(
            offline.finish().expect("trace").to_json().expect("json"),
            trace.to_json().expect("json")
        );
    }

    #[test]
    fn export_requires_a_completed_run() {
        let replay = prepared();
        let error = replay.export_state().expect_err("not complete");
        assert!(error.to_string().contains("not completed"), "{error}");
        assert!(!replay.prefix_cached());
    }

    fn block_with_number(transactions: Vec<Value>) -> String {
        json!({
            "number": "0x1",
            "hash": format!("0x{}", "11".repeat(32)),
            "timestamp": "0x64",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x0",
            "mixHash": format!("0x{}", "33".repeat(32)),
            "transactions": transactions
        })
        .to_string()
    }

    #[test]
    fn simulates_a_call_on_top_of_a_block_as_a_fork() {
        // No transaction objects are needed when nothing runs before the call.
        let mut replay = Replay::prepare_call(
            SENDER,
            COUNTER,
            "0x",
            "0",
            &block_with_number(vec![json!("0xaaa")]),
            "31337",
            None,
        )
        .expect("prepared");
        let ReplayStatus::NeedsState { block, requests } = replay.status() else {
            panic!("needs state first");
        };
        assert_eq!(
            block, "0x1",
            "a call on top of the block reads its final state"
        );
        assert!(requests.contains(&StateRequest::Account {
            address: SENDER.to_owned()
        }));

        // The sender's nonce is whatever it is: a call carries none.
        let mut world = world();
        world["accounts"][SENDER]["nonce"] = json!("0x9");
        assert_eq!(drive(&world, &mut replay), 2);
        let trace = replay.finish().expect("trace");
        let summary = trace.summary();
        assert_eq!(summary.backend.as_deref(), Some("replay"));
        assert_eq!(summary.tx_hash, None);
        assert_eq!(summary.from, SENDER);
        assert_eq!(summary.to.as_deref(), Some(COUNTER));
        assert!(summary.success);
        assert_eq!(summary.step_count, 10);
        let sstore: Value =
            serde_json::from_str(&trace.step_json(8).expect("step").expect("in range"))
                .expect("step");
        assert_eq!(sstore["snapshot"]["storage"]["0x0"], "0x2a");
        let document: Value = serde_json::from_str(
            &trace
                .to_simulation_web_json("increment", None)
                .expect("doc"),
        )
        .expect("document");
        assert_eq!(document["backend"], "replay");
        assert_eq!(document["function_name"], "increment");
    }

    #[test]
    fn simulates_a_call_inside_a_block_after_its_earlier_transactions() {
        let mut replay = Replay::prepare_call(
            SENDER,
            COUNTER,
            "0x",
            "0",
            &block_with_number(vec![transaction()]),
            "0x7a69",
            Some(1),
        )
        .expect("prepared");
        let ReplayStatus::NeedsState { block, .. } = replay.status() else {
            panic!("needs state first");
        };
        assert_eq!(
            block, "0x0",
            "inside the block, state comes from the parent"
        );

        drive(&world(), &mut replay);
        assert!(replay.prefix_cached());
        let trace = replay.finish().expect("trace");
        let sstore: Value =
            serde_json::from_str(&trace.step_json(8).expect("step").expect("in range"))
                .expect("step");
        // The mined increment ran first, so the call writes 0x2b.
        assert_eq!(sstore["snapshot"]["storage"]["0x0"], "0x2b");
    }

    #[test]
    fn prepare_call_names_what_it_cannot_use() {
        let block_without_number =
            json!({"timestamp": "0x64", "gasLimit": "0x1", "transactions": []}).to_string();
        let error = Replay::prepare_call(
            SENDER,
            COUNTER,
            "0x",
            "0",
            &block_without_number,
            "0x1",
            None,
        )
        .expect_err("no number");
        assert!(error.to_string().contains("`number`"), "{error}");

        let error = Replay::prepare_call(
            SENDER,
            COUNTER,
            "0x",
            "0",
            &block_with_number(vec![json!("0xaaa")]),
            "0x7a69",
            Some(1),
        )
        .expect_err("hash-only block cannot host a call inside it");
        assert!(
            error.to_string().contains("full transaction objects"),
            "{error}"
        );

        let error = Replay::prepare_call(SENDER, COUNTER, "0x", "0", "nope", "0x1", None)
            .expect_err("block JSON");
        assert!(
            error.to_string().contains("`eth_getBlockByNumber` result"),
            "{error}"
        );

        let error = Replay::prepare_call(
            SENDER,
            COUNTER,
            "0x",
            "lots",
            &block_with_number(vec![]),
            "0x1",
            None,
        )
        .expect_err("value");
        assert!(error.to_string().contains("lots"), "{error}");
    }

    #[test]
    fn finish_requires_a_completed_run() {
        let replay = prepared();
        let error = replay.finish().expect_err("not complete");
        assert!(error.to_string().contains("not completed"), "{error}");
    }

    #[test]
    fn supplied_state_replaces_earlier_values() {
        let mut replay = prepared();
        let mut world = world();
        world["storage"][COUNTER]["0x0"] = json!("0x5");
        drive(&world, &mut replay);
        let trace = replay.finish().expect("trace");
        let sstore: Value =
            serde_json::from_str(&trace.step_json(8).expect("step").expect("in range"))
                .expect("step");
        assert_eq!(sstore["snapshot"]["storage"]["0x0"], "0x6");
    }

    #[test]
    fn prepare_names_the_malformed_argument() {
        let error = Replay::prepare("{", &receipt(), &block(), "0x7a69").expect_err("tx");
        assert!(
            error
                .to_string()
                .contains("`eth_getTransactionByHash` result"),
            "{error}"
        );

        let error = Replay::prepare(&transaction().to_string(), "[]", &block(), "0x7a69")
            .expect_err("receipt");
        assert!(
            error
                .to_string()
                .contains("`eth_getTransactionReceipt` result"),
            "{error}"
        );

        let error = Replay::prepare(&transaction().to_string(), &receipt(), "null", "0x7a69")
            .expect_err("block");
        assert!(
            error.to_string().contains("`eth_getBlockByNumber` result"),
            "{error}"
        );

        let error = Replay::prepare(&transaction().to_string(), &receipt(), &block(), "mainnet")
            .expect_err("chain id");
        assert!(error.to_string().contains("chain id"), "{error}");

        let mut unmined = transaction();
        unmined["blockNumber"] = Value::Null;
        let error = Replay::prepare(&unmined.to_string(), &receipt(), &block(), "0x7a69")
            .expect_err("unmined");
        assert!(error.to_string().contains("mined transaction"), "{error}");

        let hash_only = json!({
            "timestamp": "0x64", "gasLimit": "0x1c9c380", "transactions": ["0xaaa"]
        })
        .to_string();
        let error = Replay::prepare(&transaction().to_string(), &receipt(), &hash_only, "0x7a69")
            .expect_err("hash-only block");
        assert!(
            error.to_string().contains("full transaction objects"),
            "{error}"
        );
    }

    #[test]
    fn provide_state_rejects_malformed_batches() {
        let mut replay = prepared();
        let error = replay.provide_state("nope").expect_err("not json");
        assert!(
            error.to_string().contains("invalid state batch JSON"),
            "{error}"
        );

        let bad_address =
            json!({"accounts": {"0x12": {"balance": "0x0", "nonce": "0x0", "code": "0x"}}});
        let error = replay
            .provide_state(&bad_address.to_string())
            .expect_err("short address");
        assert!(error.to_string().contains("0x12"), "{error}");

        // A partial batch is fine: every section is optional.
        replay.provide_state("{}").expect("empty batch");
    }

    #[test]
    fn parses_chain_ids_in_both_forms() {
        assert_eq!(parse_chain_id("0x7a69").expect("hex"), 31_337);
        assert_eq!(parse_chain_id("31337").expect("decimal"), 31_337);
        assert_eq!(parse_chain_id(" 0x1 ").expect("padded"), 1);
        assert!(parse_chain_id("").is_err());
        assert!(parse_chain_id("0x").is_err());
        assert!(parse_chain_id("sepolia").is_err());
    }
}
