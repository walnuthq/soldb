//! Times building a synthetic million-step trace and mapping it through a contract, once
//! from `TraceStep`s the way a backend builds them and once recorded straight into the
//! table with `StepTable::append`.
//!
//! The benchmarks are ignored by default; run them in release mode:
//! `cargo test --release -p soldb-debugger --test step_table_bench -- --ignored --nocapture`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use soldb_core::{
    opcode, Bytes, EvmWord, StepRecord, StepSnapshot, StepTable, StorageChange, TraceStep,
    TransactionTrace, Word, WordInterner,
};
use soldb_debugger::{ContractDebugInfo, StepMap};
use soldb_ethdebug::{EthdebugInfo, Instruction};

const STEPS: usize = 1_000_000;

const ROUNDS: usize = 5;

const SOURCE: &str = "\
contract C {
    function outer(uint256 a) public {
        uint256 b = a + 1;
        inner(b);
        b = 0;
    }
    function inner(uint256 x) internal {
        x += 1;
    }
}
";

fn offset_of(needle: &str) -> u64 {
    SOURCE.find(needle).expect(needle) as u64
}

fn instruction(pc: u64, offset: u64, length: u64) -> Instruction {
    serde_json::from_value(json!({
        "offset": pc,
        "operation": {"mnemonic": "JUMPDEST"},
        "context": {"code": {"source": {"id": 0}, "range": {"offset": offset, "length": length}}}
    }))
    .expect("instruction")
}

fn contract() -> ContractDebugInfo {
    let whole = SOURCE.len() as u64;
    let info = EthdebugInfo {
        compilation: serde_json::Value::Null,
        contract_name: "C".to_owned(),
        environment: "runtime".to_owned(),
        instructions: vec![
            instruction(0, 0, whole),
            instruction(1, 0, whole),
            instruction(10, offset_of("function outer"), 90),
            instruction(11, offset_of("uint256 b = a + 1;"), 18),
            instruction(12, offset_of("inner(b);"), 9),
            instruction(13, offset_of("inner(b);"), 9),
            instruction(14, offset_of("b = 0;"), 6),
            instruction(20, offset_of("function inner"), 50),
            instruction(21, offset_of("x += 1;"), 7),
            instruction(30, 0, whole),
        ],
        sources: BTreeMap::from([(0, "C.sol".to_owned())]),
        variable_locations: BTreeMap::new(),
    };
    ContractDebugInfo::new(None, "C", info, BTreeMap::from([(0, SOURCE.to_owned())]))
}

/// One synthetic step, handed to whatever records it.
struct Step<'a> {
    pc: u64,
    op: &'static str,
    /// The stack, bottom first.
    stack: &'a [u64],
    memory: &'a Bytes,
    /// The slot and value an `SSTORE` writes.
    store: Option<(u64, u64)>,
}

/// One loop of `outer` calling `inner`, repeated: eleven steps per iteration, a stack of
/// about a dozen words, memory that changes once per iteration, and an `SSTORE` every
/// tenth iteration.
fn synthetic_steps(steps: usize, mut record: impl FnMut(Step<'_>)) {
    let base = [0xe0, 0x4, 0x40, 0x80, 0x2a, 0xffff_ffff, 0x1234_5678, 0x0];
    let mut memory = Bytes::from(vec![0_u8; 256]);
    let mut stack = Vec::with_capacity(16);
    let mut count = 0;
    let mut iteration = 0_u64;
    while count < steps {
        let (a, b, ret, target) = (iteration, iteration + 1, 13, 20);
        let store = iteration
            .is_multiple_of(10)
            .then_some((iteration % 7, iteration));
        let mut changed = memory.to_vec();
        changed[(iteration % 224) as usize] = iteration as u8;
        let changed = Bytes::from(changed);
        let script: [(u64, &'static str, &[u64], bool); 11] = [
            (0, "PUSH1", &[], false),
            (1, "JUMPI", &[a], false),
            (10, "JUMPDEST", &[a], false),
            (11, "ADD", &[a, b], true),
            (12, "JUMP", &[a, ret, b, target], true),
            (20, "JUMPDEST", &[a, ret, b], true),
            (21, "ADD", &[a, ret, b], true),
            (21, "JUMP", &[a, ret], true),
            (13, "JUMPDEST", &[a], true),
            (
                14,
                if store.is_some() { "SSTORE" } else { "POP" },
                &[a],
                true,
            ),
            (30, "JUMP", &[], true),
        ];
        for (position, (pc, op, extra, after_change)) in script.into_iter().enumerate() {
            if count == steps {
                break;
            }
            stack.clear();
            stack.extend_from_slice(&base);
            stack.extend_from_slice(extra);
            record(Step {
                pc,
                op,
                stack: &stack,
                memory: if after_change { &changed } else { &memory },
                store: store.filter(|_| position == 9),
            });
            count += 1;
        }
        memory = changed;
        iteration += 1;
    }
}

/// The slot changes an `SSTORE` makes, and the storage after it.
fn store(
    storage: &mut Arc<BTreeMap<String, String>>,
    (slot, value): (u64, u64),
) -> BTreeMap<String, StorageChange> {
    let slot = format!("0x{slot:x}");
    let value = format!("0x{value:x}");
    let before = storage.get(&slot).cloned();
    Arc::make_mut(storage).insert(slot.clone(), value.clone());
    BTreeMap::from([(
        slot,
        StorageChange {
            before,
            after: Some(value),
        },
    )])
}

/// The synthetic steps as a backend builds them: every stack word and mnemonic a shared
/// string, interned.
fn trace_steps(count: usize) -> Vec<TraceStep> {
    let mut words = WordInterner::new();
    let mut storage = Arc::new(BTreeMap::<String, String>::new());
    let mut steps = Vec::with_capacity(count);
    let mut gas = u64::MAX / 2;
    synthetic_steps(count, |step| {
        let storage_diff = step
            .store
            .map(|write| store(&mut storage, write))
            .unwrap_or_default();
        gas -= 3;
        let stack = step
            .stack
            .iter()
            .map(|value| words.intern(&format!("0x{value:x}")))
            .collect::<Vec<Word>>();
        steps.push(TraceStep::new(
            step.pc,
            words.intern(step.op),
            gas,
            3,
            1,
            None,
            StepSnapshot {
                stack,
                memory: Some(step.memory.clone()),
                storage: Arc::clone(&storage),
                storage_diff,
                transient_storage: BTreeMap::new(),
                return_data: None,
            },
        ));
    });
    steps
}

fn trace(steps: Vec<TraceStep>) -> TransactionTrace {
    TransactionTrace {
        tx_hash: None,
        from_addr: "0x1".to_owned(),
        to_addr: Some("0x2".to_owned()),
        value: "0x0".to_owned(),
        input_data: "0x".to_owned(),
        gas_used: 0,
        output: "0x".to_owned(),
        success: true,
        error: None,
        debug_trace_available: true,
        contract_address: None,
        backend: None,
        capabilities: Default::default(),
        artifacts: Default::default(),
        steps: steps.into_iter().collect(),
    }
}

#[test]
#[ignore = "a benchmark; run in release with --ignored --nocapture"]
fn synthetic_million_step_trace() {
    // The machine may be busy; the fastest of several rounds is the one least disturbed.
    let mut best = [Duration::MAX; 4];
    for _ in 0..ROUNDS {
        let started = Instant::now();
        let steps = trace_steps(STEPS);
        let built = started.elapsed();

        let started = Instant::now();
        let trace = trace(steps);
        let pushed = started.elapsed();

        let started = Instant::now();
        let map = StepMap::new(&trace, vec![contract()]);
        let mapped = started.elapsed();
        assert_eq!(map.step_count(), STEPS);
        assert!(map.frame_depth(5).is_some());
        drop(map);

        let started = Instant::now();
        drop(trace);
        let dropped = started.elapsed();

        for (best, now) in best.iter_mut().zip([built, pushed, mapped, dropped]) {
            *best = (*best).min(now);
        }
    }
    let [built, pushed, mapped, dropped] = best;
    eprintln!(
        "{STEPS} steps, best of {ROUNDS}: build TraceSteps {built:?}, into trace {pushed:?}, \
         StepMap::build {mapped:?}, drop trace {dropped:?}, total {:?}",
        built + pushed + mapped + dropped
    );
}

/// The synthetic steps recorded straight into a table, the way an embedder that holds
/// the stack as words records them, without building a `TraceStep`.
fn appended_steps(count: usize) -> StepTable {
    let mut table = StepTable::with_capacity(count);
    let mut storage = Arc::new(BTreeMap::<String, String>::new());
    let mut gas = u64::MAX / 2;
    synthetic_steps(count, |step| {
        let storage_diff = step.store.map(|write| store(&mut storage, write));
        gas -= 3;
        table.append(
            StepRecord {
                pc: step.pc,
                op: opcode::from_mnemonic(step.op).expect("a known opcode"),
                gas,
                gas_cost: 3,
                depth: 1,
                memory: Some(step.memory.clone()),
                storage: storage_diff.is_some().then(|| Arc::clone(&storage)),
                storage_diff,
                ..StepRecord::default()
            },
            step.stack.iter().map(|value| EvmWord::from(*value)),
        );
    });
    table
}

#[test]
#[ignore = "a benchmark; run in release with --ignored --nocapture"]
fn synthetic_million_step_trace_appended() {
    let mut best = [Duration::MAX; 3];
    for _ in 0..ROUNDS {
        let started = Instant::now();
        let mut trace = trace(Vec::new());
        trace.steps = appended_steps(STEPS);
        let appended = started.elapsed();

        let started = Instant::now();
        let map = StepMap::new(&trace, vec![contract()]);
        let mapped = started.elapsed();
        assert_eq!(map.step_count(), STEPS);
        drop(map);

        let started = Instant::now();
        drop(trace);
        let dropped = started.elapsed();

        for (best, now) in best.iter_mut().zip([appended, mapped, dropped]) {
            *best = (*best).min(now);
        }
    }
    let [appended, mapped, dropped] = best;
    eprintln!(
        "{STEPS} steps, best of {ROUNDS}: append {appended:?}, StepMap::build {mapped:?}, \
         drop trace {dropped:?}, total {:?}",
        appended + mapped + dropped
    );
}

#[test]
fn appending_records_what_pushing_trace_steps_records() {
    // A few thousand of the synthetic steps, both ways.
    let pushed = StepTable::from(trace_steps(5_000));
    let appended = appended_steps(5_000);
    assert_eq!(pushed, appended);
}
