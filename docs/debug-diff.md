# Debug Information Differentials

`soldb debug-diff` tests the debugging experience produced by two compiler
outputs. It follows the central idea of LLVM's
[Dexter](https://github.com/llvm/llvm-project/tree/main/cross-project-tests/debuginfo-tests/dexter):
compare what a debugger presents while executing a program, not the raw debug
records.

Two Solidity compilers can generate different EVM programs for the same source.
Their program counters and source-map strings therefore cannot be compared
directly. The command uses the debugger's `StepMap` with line smoothing disabled:
even a single-instruction source stop participates, so an optimized `SLOAD`
cannot disappear just because the interactive stepper smooths that excursion.
It records those source steps and compares them.

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
Pass `--reference-constructor-args` and `--candidate-constructor-args` with the
known ABI-encoded payload (`0x` for no arguments). Initcode cannot be compared as
calldata because it includes compiler-specific code and data. The payload must
match the end of each creation input; value, success, and failed-constructor
revert data are still checked. Missing argument boundaries fail visibly.

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

Use `--checkpoints-file checks.json` for Dexter-style test expectations:

```json
[{"source": "Counter.sol", "line": 12}, {"source": "Counter.sol", "line": 18}]
```

Both executions must reach every listed source line. Comparison then considers
those stops in the selected mode. This permits tests to assert executable
statements independently of compiler-specific declaration or prologue stops.
An unreached checkpoint fails even when it is missing from both executions.
Without this option, every debugger-visible stop participates in comparison.

Source identity includes the exact content hash and normalized path. Two
different paths do not match just because their basenames agree. Absolute paths
may match a complete relative suffix; use common Standard JSON source names
when comparing builds made in different checkouts.

Every traced instruction in a supplied program must match its artifact opcode.
Missing instructions, unidentified frames, duplicate PCs, unavailable source
text, and out-of-bounds source ranges make the report inconclusive and fail.
This validates the recorded opcodes, not a cryptographic identity of the full
executed bytecode: PUSH immediates are not part of a trace step.

## Offline and CI Use

For a hermetic test, pass serialized `TransactionTrace` values instead of
transaction hashes. `soldb run ... --save-trace trace.json` creates this format
through local REVM execution. The normal `run --json` output remains the
web-facing document:

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

## Shared Compiler Tests

CI builds `paradigmxyz/solar` at `main` and exercises its CLI debug artifacts
through local REVM, debug comparisons, and both profiling formats. The solc CI
jobs run the same test files against their selected compiler. One Solidity
fixture and one `.test` file cover each behavior, with common FileCheck checks
and compiler-specific prefixes only for genuine differences.
The job runs on pull requests, pushes to `main`, the daily schedule, and manual
dispatch. It is non-blocking, like the solc development job: upstream compiler
changes can expose gaps independently of a debugger change. Failing steps stay
visible, and the job summary lists failed checks.

Run the same lit/FileCheck suite locally with a Solar binary supporting
`--emit=ethdebug,ethdebug-runtime,srcmap,srcmap-runtime`, solc 0.8.36,
`lit`, `jq`, and LLVM's `FileCheck` on `PATH`:

```console
cargo build --bin soldb
export SOLAR=/path/to/solar
export SOLC_PATH=/path/to/solc
for optimization in none gas size; do
  lit -v -j2 test/compiler --param compiler=both --param optimization="$optimization" || break
done
```

For independent runs, use `--param compiler=solar` or `--param compiler=solc`.
Only the selected compiler is required. Each mode checks runtime results,
explicit source checkpoints, gas attribution, and flamegraphs; `both` also
compares the compiler outputs. The default is `compiler=both`.

On macOS, Homebrew's FileCheck may need
`export PATH="$(brew --prefix llvm)/bin:$PATH"`. Set `SOLDB_BIN` to override
`target/debug/soldb`. No node, deployment script, or generated lit site
configuration is needed.

The `baseline/` tests cover creation, arithmetic, branching, and storage
reads. The `capabilities/` tests cover modifiers, loops, internal calls,
`require`, and dynamic calldata. Each `.test` file runs the CLI directly and
uses jq/FileCheck to assert runtime results, cross-format debug equivalence,
solc checkpoint coverage, source-attributed gas, and flamegraph output.
Both compilers run directly in the lit `RUN` lines: Solar uses `--emit`,
and solc uses `--combined-json`, `--bin`, and `--abi`. Their legacy
`combined.json` files are consumed as emitted, without format conversion.
`jq` extracts Solar's ETHDebug programs/resources into separate files and
selects named source checkpoints. There is no Python preparation adapter.
Compilation diagnostics remain beside the artifacts, and a failed compiler
or missing requested JSON field stops the test.

There is no expected-failure allowlist. Positive checkpoint tests require the
specified stops in both compilers: two debug formats dropping the same
statement cannot make the comparison pass. The gas-mode `bytes-length` case
instead verifies an intentional unknown location after return-tail sharing
and fallthrough elimination. It requires failed comparisons with the exact
missing-source diagnostics, correct execution, and sourceless legacy profiling.
ETHDebug may retain alternatives the profiler can resolve with compiler-authored
function identity; any attributed source gas must belong to the executed
checkpoint. Both profiles must account for all program gas. The `none` and
`size` versions still require the checkpoint. This does not change codegen or
relax `debug-diff`'s handling of empty traces. These are source-coverage checks,
not a claim of exact function-frame, variable-location, or full span parity.

The `solar-main-compatibility` artifact contains the exact Solar revision,
compiler versions, CLI artifacts and diagnostics, REVM traces, comparison
reports, profiles, SVGs, and lit results with the failing commands. Local output
defaults to `target/compiler-lit/<compiler>/<optimization>`; change its parent with
`--param output=/path/to/results`. CI still tracks main, so compiler fixes
and the debug-output CLI must land there before its run becomes green.
This suite is separate from the solc-specific live-node tests and does not imply that
`soldb compile --solc /path/to/solar` accepts Solar's CLI.
