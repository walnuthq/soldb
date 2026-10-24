//! Times recording a trace whose memory grows word by word, once with every step's
//! memory in full and once as the writes the steps make, and reading memory back at
//! steps spread over the trace, as `memory` in the REPL does.
//!
//! The benchmarks are ignored by default; run them in release mode:
//! `cargo test --release -p soldb-core --test memory_bench -- --ignored --nocapture`.

use std::time::{Duration, Instant};

use soldb_core::{opcode, Bytes, EvmWord, StepRecord, StepTable};

/// The elements of the memory array the loop fills, one 32-byte word each.
const ELEMENTS: usize = 3000;

/// Where the array starts, past the scratch space and the free memory pointer.
const ARRAY: usize = 0x80;

/// The steps of one iteration; the last one stores the element.
const SCRIPT: [u8; 8] = [
    opcode::JUMPDEST,
    0x80, // DUP1
    0x60, // PUSH1
    0x01, // ADD
    0x60, // PUSH1
    0x02, // MUL
    0x60, // PUSH1
    opcode::MSTORE,
];

const ROUNDS: usize = 5;

/// How the steps' memory is recorded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Memory {
    /// Every step carries its memory in full, copied whenever it changes.
    Snapshots,
    /// The table records the bytes each `MSTORE` writes.
    Writes,
}

fn record(elements: usize, memory: Memory) -> StepTable {
    let mut table = StepTable::with_capacity(elements * SCRIPT.len());
    let mut current = vec![0_u8; ARRAY];
    let mut shared = Bytes::from(current.clone());
    if memory == Memory::Writes {
        table.start_memory_frame();
        table
            .write_memory(0, &[], ARRAY as u64)
            .expect("the scratch space");
    }
    let mut gas = 1_000_000_000_u64;
    for element in 0..elements {
        let offset = ARRAY + element * 32;
        let value = EvmWord::from(element as u64 + 1);
        for op in SCRIPT {
            gas -= 3;
            table.append(
                StepRecord {
                    pc: u64::from(op),
                    op,
                    gas,
                    gas_cost: 3,
                    depth: 1,
                    memory: (memory == Memory::Snapshots).then(|| shared.clone()),
                    ..StepRecord::default()
                },
                [EvmWord::from(offset as u64), value],
            );
        }
        // The `MSTORE` writes the element; the step after it sees the memory grown.
        current.extend_from_slice(value.as_bytes());
        match memory {
            Memory::Snapshots => shared = Bytes::from(current.clone()),
            Memory::Writes => table
                .write_memory(offset as u64, value.as_bytes(), current.len() as u64)
                .expect("the element"),
        }
    }
    table
}

/// Reads the memory of 200 steps spread over the trace, as the REPL's `memory` command
/// does at each stop, and returns how many bytes it read.
fn read_spread(table: &StepTable) -> usize {
    let stride = (table.len() / 200).max(1);
    (0..table.len())
        .step_by(stride)
        .filter_map(|index| table.step(index).memory())
        .map(|memory| memory.len())
        .sum()
}

fn bench(memory: Memory, name: &str) {
    let mut best = [Duration::MAX; 2];
    for _ in 0..ROUNDS {
        let started = Instant::now();
        let table = record(ELEMENTS, memory);
        let recorded = started.elapsed();
        let started = Instant::now();
        let read = read_spread(&table);
        let reading = started.elapsed();
        assert!(read > 0);
        for (best, now) in best.iter_mut().zip([recorded, reading]) {
            *best = (*best).min(now);
        }
    }
    let [recorded, reading] = best;
    eprintln!(
        "{name}: {} steps, best of {ROUNDS}: record {recorded:?}, read 200 steps {reading:?}",
        ELEMENTS * SCRIPT.len()
    );
}

#[test]
#[ignore = "a benchmark; run in release with --ignored --nocapture"]
fn memory_array_as_snapshots() {
    bench(Memory::Snapshots, "snapshots");
}

#[test]
#[ignore = "a benchmark; run in release with --ignored --nocapture"]
fn memory_array_as_writes() {
    bench(Memory::Writes, "writes");
}

#[test]
fn writes_rebuild_the_memory_snapshots_hold() {
    let snapshots = record(300, Memory::Snapshots);
    let writes = record(300, Memory::Writes);
    assert_eq!(snapshots.len(), writes.len());
    for index in 0..snapshots.len() {
        assert_eq!(
            snapshots.step(index).memory(),
            writes.step(index).memory(),
            "step {index}"
        );
    }
    // Backwards as well, which rebuilds from the images instead of the cache.
    for index in (0..writes.len()).rev().step_by(7) {
        assert_eq!(
            snapshots.step(index).memory(),
            writes.step(index).memory(),
            "step {index}"
        );
    }
    assert_eq!(snapshots, writes);
}
