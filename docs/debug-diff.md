# Debug Information Differentials

`soldb debug-diff` tests the debugging experience produced by two compiler
outputs. It follows the central idea of LLVM's
[Dexter](https://github.com/llvm/llvm-project/tree/main/cross-project-tests/debuginfo-tests/dexter):
compare what a debugger presents while executing a program, not the raw debug
records.

Two Solidity compilers can generate different EVM programs for the same source.
Their program counters and source-map strings therefore cannot be compared
directly. The command instead builds the same `StepMap` used by the interactive
debugger and DAP server, records each source-level step, and compares those
records.

## Compare Transactions

Deploy the reference and candidate bytecode, send the same calldata and value to
both contracts, then pass their transaction hashes and artifacts:

```console
soldb debug-diff \
  --reference-tx 0xREFERENCE \
  --candidate-tx 0xCANDIDATE \
  --reference-ethdebug-dir 0xREF_ADDRESS:Counter:out-solc \
  --candidate-ethdebug-dir 0xCANDIDATE_ADDRESS:Counter:out-candidate \
  --rpc http://localhost:8545
```

The command separately compares calldata, call value, success status, and return
data. A program-behavior difference is therefore reported as an execution
difference rather than blamed on debug metadata.

For contract-creation traces, returned runtime bytecode is intentionally not
compared because different compilers are expected to deploy different programs.
Constructor calldata, value, and success status are still checked.

Each side also accepts a contract mapping through `--reference-contracts` or
`--candidate-contracts`, and repeatable `--reference-source-path` and
`--candidate-source-path` arguments for artifacts whose source paths are
relative to their original build directories.

## Comparison Modes

`--mode steps` is the default. It compares the ordered source lines, containing
functions, inferred call depth, and function entries that source stepping shows.
Program counters and instruction indexes are retained only for diagnostics and
do not participate in equality.

`--mode spans` additionally compares byte offsets, lengths, columns,
compiler-generated attribution, and legacy modifier depth. Use it when both
compilers are expected to attribute expressions at the same granularity.

`--mode coverage` compares unique source line and function pairs. It ignores
order, repetition, and frame depth, which makes it useful when optimization
legitimately inlines, merges, or reorders machine code while source coverage
should remain intact.

## Offline and CI Use

For a hermetic test, pass serialized `TransactionTrace` values instead of
transaction hashes:

```console
soldb debug-diff \
  --reference-trace-file traces/reference.json \
  --candidate-trace-file traces/candidate.json \
  --reference-ethdebug-dir 0xREF_ADDRESS:Counter:out-solc \
  --candidate-ethdebug-dir 0xCANDIDATE_ADDRESS:Counter:out-candidate \
  --mode steps --json
```

Equivalent traces exit with status 0. Execution or debug-info differences exit
with status 2, so the command can be used directly from lit, shell scripts, or
CI. `--json` emits a stable report containing mapping summaries, the total
difference count, and samples capped by `--max-differences`.

A comparison with no source steps on either side is inconclusive and fails. It
cannot turn missing or unusable debug metadata into a vacuous passing test; the
JSON report sets `comparable` to `false` and explains which side lacked source
steps.

The library entry points are `soldb_debugger::capture_debug_trace` and
`soldb_debugger::compare_debug_traces`. They take already loaded
`TransactionTrace` and `ContractDebugInfo` values and perform no file or network
I/O.
