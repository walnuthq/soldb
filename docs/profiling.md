# Gas profiling

`soldb profile` combines an execution trace with compiler-generated ETHDebug
programs. The trace supplies executed program counters and dynamic opcode costs;
ETHDebug supplies the contract, function, source range, and line associated with
each instruction.

Solar can emit the required resources plus creation and runtime programs directly:

```console
solar -g --out-dir out Contract.sol
```

The loader accepts Solar's source-qualified artifact names, such as
`Contract_sol_Contract_ethdebug-runtime.json`, as well as solc's
`Contract_ethdebug-runtime.json` spelling.

## Profile a local transaction

Start Anvil, compile with ETHDebug, deploy the contract, and submit the workload
as an ordinary transaction. Then run:

```console
soldb profile <tx-hash> \
  --backend replay \
  --rpc http://localhost:8545 \
  --ethdebug-dir <address>:<contract>:out
```

The replay backend reads the transaction's parent-block state over normal RPC and
executes it through REVM. Anvil is convenient for local development, but the
backend can use another RPC endpoint with the required historical state. The
`debug-rpc` backend can also supply opcode costs; source attribution for nested
contracts remains unavailable when the node omits call identities.

The report separates:

- transaction gas used, as reported by the transaction receipt;
- traced instruction gas, the sum of per-step `gas_cost` values;
- gas attributed to a known creation or runtime program;
- gas attributed to an ETHDebug source range; and
- gas deliberately left unmapped because the executing program was unknown.

Transaction gas and traced instruction gas are separate quantities. Intrinsic
transaction gas, refunds, and backend accounting can make them differ.

## Captured traces

The profiler library consumes `soldb_core::TransactionTrace`, so integrations can
profile without an RPC request. The CLI accepts the same serialized structure:

```console
soldb profile --trace-file trace.json \
  --ethdebug-dir <address>:<contract>:out
```

This is the intended integration point for Foundry: a future `forge profile` can
construct a transaction trace directly from its local executor and call
`soldb_profiler::profile_transaction`, without starting Anvil or parsing CLI
output.

## Flame graphs

Write standard folded stacks or a self-contained interactive SVG:

```console
soldb profile <tx-hash> \
  --ethdebug-dir <address>:<contract>:out \
  --folded profile.folded \
  --flamegraph profile.svg
```

Each sample is weighted by dynamic gas, not wall-clock time. Frames include the
external call path when the backend provides it, followed by the current contract,
function, and source line. ETHDebug does not yet describe every optimized internal
call transition, so the graph does not invent an internal Solidity call stack.

## Multi-contract transactions

Pass one `--ethdebug-dir` per deployed contract or use the existing contract
mapping file accepted by `--contracts`. Runtime programs are selected by code
address, and creation programs are selected separately. This distinction matters
for `DELEGATECALL`, where the storage address and bytecode address differ.

Use `--backend replay` for accurate cross-contract attribution. If only raw
`structLogs` are available, their depth does not identify the executing address;
nested gas is reported as unmapped rather than assigned to a program with a
coincidentally matching PC.

## JSON

`--json` emits the complete versioned profile document, including totals,
contract/function/line/opcode tables, instruction hotspots, and folded-stack
samples. Human-readable `--top N` only limits displayed rows; JSON remains
complete.
