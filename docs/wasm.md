# WebAssembly

SolDB's library crates build for `wasm32-unknown-unknown`, and the `soldb-wasm` crate
wraps them in a small `wasm-bindgen` API so a browser or Node.js host can build traces,
step through them at source level, render the same versioned JSON document as
`soldb trace --json` including its `contracts` section, and, in the replay-capable
package, re-execute a transaction in REVM when the node offers no
`debug_traceTransaction`. CI builds and tests both packages on every pull request and
fails if either grows past its size budget.

## What runs in WebAssembly

The WebAssembly surface is the frontend-agnostic model. The binaries stay native: they
spawn `solc`, listen on sockets, and read the filesystem, none of which a
`wasm32-unknown-unknown` module can do.

| crate | in WebAssembly | note |
| --- | --- | --- |
| `soldb-core` | yes | trace, snapshot, capability, and error types |
| `soldb-ethdebug` | yes | ETHDebug artifacts, ABI and event decoding |
| `soldb-debugger` | yes | source spans, functions, variables per step |
| `soldb-profiler` | yes | gas attribution and folded stacks |
| `soldb-repl` | yes | breakpoint and stepping state machine |
| `soldb-serializer` | yes | the web JSON document and its per-contract metadata |
| `soldb-rpc` | yes | transport types and trace assembly in both packages; the REVM backend, behind the `replay` feature, only in the replay-capable one |
| `soldb-wasm` | yes | the bindings described below |
| `soldb-cli`, `soldb-dap` | no | terminal and editor frontends |
| `soldb-compiler` | no | invokes `solc` |
| `soldb-bridge` | no | TCP bridge server |

The host is the I/O layer. It calls JSON-RPC with `fetch` or any client library, reads
ETHDebug artifacts however it stores them, and passes everything to the module as
strings. This follows the same premise as the native tool: the node is the execution
oracle, and debug info comes from the compiler's artifacts rather than from guessing.

## Two packages

`crates/soldb-wasm` builds two packages from one crate, selected by its `replay` cargo
feature:

| package | output | REVM | size | budget |
| --- | --- | --- | --- | --- |
| lean | `crates/soldb-wasm/pkg/` | no | about 360 KB, 150 KB gzipped | 400,000 bytes |
| replay-capable | `crates/soldb-wasm/pkg-replay/` | yes | about 960 KB, 400 KB gzipped | 1,100,000 bytes |

Both export `Trace` and `version()`; only the replay-capable one exports `Replay`.
`replayAvailable()` tells a host which it loaded. Pick the lean package when every node
you talk to answers `debug_traceTransaction`; pick the replay-capable one when some do
not, such as public RPC endpoints.

## Building

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

make wasm-check   # clippy on the target in both configurations, plus native tests without `replay`
make wasm         # both packages, each checked against its size budget
make wasm-lean    # only crates/soldb-wasm/pkg
make wasm-replay  # only crates/soldb-wasm/pkg-replay
make wasm-test    # wasm-pack test --node, with and without `replay`
make wasm-live-test  # replay a transaction on a live node through the package (RPC_URL)
```

Each package directory (gitignored) holds the module, its JavaScript loader, TypeScript
declarations, and a `package.json`, ready to be published to npm or copied into an
application. Builds use `WASM_PROFILE` from the `Makefile`, a size-oriented cargo profile
applied to that invocation only (`opt-level = "z"`, fat LTO, one codegen unit,
`panic = "abort"`), and `wasm-opt -Oz` from the crate's `wasm-pack` metadata. Pass a
different `--target` to `wasm-pack build` for a bundler or Node.js consumer:

```bash
wasm-pack build crates/soldb-wasm --target bundler --no-default-features   # lean
wasm-pack build crates/soldb-wasm --target nodejs --out-dir pkg-replay      # replay-capable
```

The crate list behind `make wasm-check` is the `WASM_CRATES` variable in the `Makefile`.
CI runs the same targets in the `wasm` job of `.github/workflows/ci.yml`.

## API

Inputs and outputs cross the boundary as JSON strings, so the documents are the ones
this repository already specifies, but the trace itself stays in WebAssembly memory
between calls: it is parsed once, and stepping, summaries, and the web document all read
it in place. Serialization happens exactly once per output the host asks for. Failures
throw a JavaScript `Error` whose message is the debugger's own error text.

| member | purpose |
| --- | --- |
| `Trace.fromTransaction(debugTrace, transaction, receipt)` | the `result` fields of `debug_traceTransaction`, `eth_getTransactionByHash`, and `eth_getTransactionReceipt` |
| `Trace.fromSimulation(from, to, calldata, value, debugTrace)` | the call that was sent plus the `result` of `debug_traceCall` |
| `Trace.fromJson(trace)` | trace JSON from `toJson()` or a trace file saved by the native CLI |
| `trace.attachEthdebug(artifacts)` | attach one contract's artifacts; replaces what was attached before |
| `trace.hasEthdebug()` | whether steps carry source spans and variables |
| `trace.stepCount()` | number of opcode steps |
| `trace.step(index)` | one step as JSON, or `undefined` past the end |
| `trace.summary()` | header as JSON: hash, parties, gas, status, backend, capabilities, step count, attached debug info |
| `trace.toJson()` | the trace as JSON, the input `fromJson` accepts |
| `trace.toWebJson(contracts?)` | the versioned document from [json.md](json.md) for a transaction |
| `trace.toSimulationWebJson(functionName, contracts?)` | the versioned document for a simulation |
| `trace.free()` | release the trace; it lives outside the JavaScript heap |
| `Replay.prepare(transaction, receipt, block, chainId)` | replay-capable package only; see below |
| `Replay.prepareCall(from, to, calldata, value, block, chainId, txIndex?)` | a call on a fork of the chain at `block`; see below |
| `replay.exportState()` | the state a completed replay depended on, ready for `provideState` |
| `replayAvailable()` | whether `Replay` is exported by this build |
| `version()` | the version the module was built from |

A step carries the program counter, opcode, gas, depth, and machine state, and, once
debug info is attached, the source span, the enclosing function, and the variables the
artifact declares at that program counter, with the same `Unavailable` and `Raw`
statuses the CLI and DAP server report when the debug info does not cover a value.
`summary().debugInfo.pcsWithVariables` tells the host up front whether the compiler
emitted variable locations at all; when it is zero, every step's `variables` list is
empty by design. That dependence on the compiler is the same in the native tool.

### Contract artifacts

Debug info reaches the module as one JSON object per contract, the same shape whether it
attaches to a trace or fills the web document:

```json
{
  "name": "Counter",
  "metadata": { "...": "the parsed ethdebug.json or ethdebug_resources.json" },
  "program": { "...": "the parsed Counter_ethdebug-runtime.json" },
  "sources": { "0": "pragma solidity ^0.8.0; ..." },
  "abi": [ { "type": "function", "name": "increment", "...": "..." } ]
}
```

`name`, `metadata`, and `program` are required. `sources` maps ETHDebug source ids to
file contents; any id it leaves out falls back to the source the compilation metadata
embeds, when the compiler inlined it. `abi` is copied into the web document when
present.

`toWebJson` and `toSimulationWebJson` take a map from contract address to one of these
as their optional `contracts` argument and fill the document's `contracts` section
exactly as `--ethdebug-dir` does for the CLI: `pcToSourceMappings`, `sourcePaths`,
`sources`, `debugAvailable`, and `abi` per contract, keyed by the lowercased address. A
source without contents falls back to its path, and a contract with nothing to report is
left out, both as on the command line. Omit the argument to leave the section empty. The
projection itself is `WebContractMetadata::from_ethdebug` in `soldb-serializer`, the
single implementation the CLI and the module share.

### Example

```js
import init, { Trace } from "./pkg/soldb_wasm.js";

await init();

const rpc = async (method, params) => {
  const response = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const { result, error } = await response.json();
  if (error) throw new Error(error.message);
  return result;
};
const text = async (method, params) => JSON.stringify(await rpc(method, params));
const file = async (path) => (await fetch(path)).text();

const txHash = "0x…";
const trace = Trace.fromTransaction(
  await text("debug_traceTransaction", [txHash, { enableMemory: true, disableStorage: false }]),
  await text("eth_getTransactionByHash", [txHash]),
  await text("eth_getTransactionReceipt", [txHash]),
);

const counter = {
  name: "Counter",
  metadata: JSON.parse(await file("out/ethdebug_resources.json")),
  program: JSON.parse(await file("out/Counter_ethdebug-runtime.json")),
  sources: { 0: await file("Counter.sol") },
  abi: JSON.parse(await file("out/Counter.abi")),
};
trace.attachEthdebug(JSON.stringify(counter));

const summary = JSON.parse(trace.summary());
console.log(summary.status, summary.stepCount, summary.debugInfo.pcsWithVariables);

for (let index = 0; index < trace.stepCount(); index += 1) {
  const step = JSON.parse(trace.step(index));
  if (step.source) {
    console.log(`${step.pc} ${step.op} ${step.source.path}:${step.source.line}`);
  }
}

const document = JSON.parse(
  trace.toWebJson(JSON.stringify({ [COUNTER_ADDRESS]: counter })),
);
trace.free();
```

## Replay in the browser

The native `replay` backend re-executes a transaction in REVM from state read over
ordinary RPC, for nodes that do not answer `debug_traceTransaction`. REVM reads state
synchronously, and a WebAssembly module cannot block on the network, so the replay-capable
package turns that into a loop the host drives:

1. `Replay.prepare(transaction, receipt, block, chainId)` takes the `result` fields of
   `eth_getTransactionByHash`, `eth_getTransactionReceipt`, and
   `eth_getBlockByNumber(blockNumber, true)` for the transaction's block, which must
   carry full transaction objects, plus the `eth_chainId` result.
2. `replay.status()` returns `{"status": "needsState", "block": "0x…", "requests": [...]}`.
   Every request is read at `block`, the parent of the transaction's block, and carries a
   `kind`:

   | kind | fields | fetch with |
   | --- | --- | --- |
   | `account` | `address` | `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode` |
   | `storage` | `address`, `slot` | `eth_getStorageAt` |
   | `blockHash` | `number` | `eth_getBlockByNumber(number, false)`, its `hash` |

3. `replay.provideState(batch)` takes the answers as one JSON object:

   ```json
   {
     "accounts": { "0xaddress": { "balance": "0x…", "nonce": "0x…", "code": "0x…" } },
     "storage": { "0xaddress": { "0xslot": "0xvalue" } },
     "blockHashes": { "7": "0x…" }
   }
   ```

   Every section is optional, so a host answers only what was asked. Values are the
   node's results verbatim.
4. `replay.run()` executes and returns the new status: `{"status": "complete"}`, or
   `needsState` with what the run still lacked. Repeat from step 3 until it completes.
5. `replay.exportState()` returns exactly the state the completed replay depended on,
   in the shape `provideState` accepts, and `replay.finish()` yields a `Trace` with
   `backend` set to `replay`, the same one the native backend produces from the same
   chain. `finish` consumes the `Replay` object, so export first.

Missing values are answered with an empty account, a zero slot, or a zero hash and
recorded, so a run never stops at the first gap: each round discovers everything the
current path touches. A default can send an early round down a path the real values
would not take, but every value used by a round that recorded nothing was real, so its
result is exact. The first status already names the accounts every replay reads, the
parties to each transaction up to the target and the block's fee recipient, so a host
that answers it before the first run saves a round; a typical transaction converges in
two to four rounds.

The transactions before the target in its block are not re-executed every round. The
first time they run with nothing missing, everything they read was real, so the state
they leave behind is kept and later rounds run the target alone over it. A prefix that
read defaults is still used for that round, because the target's reads are worth
discovering, but it is run again next round. For a transaction deep in a busy block this
removes most of the work: the prefix is paid once, usually in the first round after the
participants are supplied.

A failure is reported only from a run that recorded nothing missing, because with
defaults in play a failure proves nothing. A failure with nothing missing is real: the
sender could not pay for gas, the transaction is unmined, the block did not include full
transaction objects, or the node's state at the parent block is wrong.

```js
import init, { Replay, replayAvailable } from "./pkg-replay/soldb_wasm.js";

await init();
if (!replayAvailable()) throw new Error("load the replay-capable package");

const tx = await rpc("eth_getTransactionByHash", [txHash]);
const replay = Replay.prepare(
  JSON.stringify(tx),
  await text("eth_getTransactionReceipt", [txHash]),
  await text("eth_getBlockByNumber", [tx.blockNumber, true]),
  await rpc("eth_chainId", []),
);

// One JSON-RPC batch per round: every request in a round is independent.
const rpcBatch = async (calls) => {
  const response = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(calls.map(([method, params], id) => ({ jsonrpc: "2.0", id, method, params }))),
  });
  const results = new Map((await response.json()).map((entry) => [entry.id, entry]));
  return calls.map((_, id) => {
    const { result, error } = results.get(id);
    if (error) throw new Error(error.message);
    return result;
  });
};

let status = JSON.parse(replay.status());
while (status.status !== "complete") {
  const calls = [];
  const fill = [];
  const batch = { accounts: {}, storage: {}, blockHashes: {} };
  for (const request of status.requests) {
    if (request.kind === "account") {
      const at = calls.length;
      calls.push(
        ["eth_getBalance", [request.address, status.block]],
        ["eth_getTransactionCount", [request.address, status.block]],
        ["eth_getCode", [request.address, status.block]],
      );
      fill.push((results) => {
        batch.accounts[request.address] = { balance: results[at], nonce: results[at + 1], code: results[at + 2] };
      });
    } else if (request.kind === "storage") {
      const at = calls.length;
      calls.push(["eth_getStorageAt", [request.address, request.slot, status.block]]);
      fill.push((results) => {
        (batch.storage[request.address] ??= {})[request.slot] = results[at];
      });
    } else if (request.kind === "blockHash") {
      const at = calls.length;
      calls.push(["eth_getBlockByNumber", [`0x${request.number.toString(16)}`, false]]);
      fill.push((results) => {
        batch.blockHashes[request.number] = results[at].hash;
      });
    }
  }
  const results = await rpcBatch(calls);
  for (const apply of fill) apply(results);
  replay.provideState(JSON.stringify(batch));
  status = JSON.parse(replay.run());
}

localStorage.setItem(`soldb-replay:${txHash}`, replay.exportState()); // next time: one run, no node
const trace = replay.finish();
```

### Calls on a fork

`Replay.prepareCall(from, to, calldata, value, block, chainId, txIndex?)` drives the same
loop for a call that was never mined. `block` is the `result` of `eth_getBlockByNumber`
for the fork point, and its `number` says where the chain is forked. Without `txIndex` the
call runs on top of that block's final state, so the block can be fetched without
transaction objects; with it, the call runs inside the block after the transactions before
that index, which must then be full objects. The call carries no nonce and pays no gas
price, as with `eth_call`. `finish()` yields a simulation trace, the one
`toSimulationWebJson` renders, and `exportState()` works the same way. This is how a
browser steps through an `eth_call` against a fork with nothing but a node that serves
state at that block. `test/wasm/replay-live.cjs` checks the result against the node's
`debug_traceCall` step for step.

The node must serve state at the parent block, which for anything but recent blocks
means an archive-capable endpoint, exactly as for the native backend. That is a property
of replay itself: the state a transaction ran against has to come from somewhere, and a
node that keeps neither history nor a tracer cannot supply it. What the export changes
is how often you pay for it.

### Exported state

Once a replay completes, `exportState()` returns the accounts, storage slots, and block
hashes the run actually read, and nothing else:

```json
{
  "accounts": { "0xaddress": { "balance": "0x…", "nonce": "0x…", "code": "0x…" } },
  "storage": { "0xaddress": { "0x0": "0x29" } },
  "blockHashes": { "7": "0x…" }
}
```

It covers the block prefix's reads too, even when the final round served them from the
kept prefix. Feeding it to `Replay.prepare` for the same transaction through
`provideState` completes the replay in one run with no node at all, and produces the
identical trace. A host can cache it per transaction in the browser, attach it to a bug
report, check it into a regression test, or hand it to a colleague who has no archive
access. The live check in `test/wasm/replay-live.cjs` does exactly that round trip: for a
small contract call the export is under a kilobyte.

Requests within a round are independent, so a host should send them as one JSON-RPC
batch rather than one call each, as the example below does.

`test/wasm/replay-live.cjs` is this loop as a runnable check: it deploys a small contract
on the node at `RPC_URL`, calls it, replays that transaction through the Node.js build of
the replay-capable package with real RPC calls, and compares every step's program
counter, opcode, and stack with the node's own `debug_traceTransaction`. CI runs it
against a local `anvil`; `make wasm-live-test` runs it for you.

## Size

`make wasm` fails when a module grows past its budget in the `Makefile`:
`WASM_LEAN_SIZE_BUDGET_BYTES` and `WASM_REPLAY_SIZE_BUDGET_BYTES`. The budgets are
tripwires for a dependency creeping in, not targets; raise one deliberately, in the same
change that explains the growth.

Where the bytes go, from a build with symbol names kept:

- In the lean package, about a third is `serde_json` deserializing the trace, RPC, and
  ETHDebug types the API has to accept. This is the cost of a JSON boundary and grows
  with every type parsed. Most of the rest is `core` and `alloc`: formatting, string and
  slice routines, the `BTreeMap`s the trace types use, and the allocator. The debugger's
  own crates are a small fraction.
- The replay-capable package adds REVM: the interpreter, the precompiles with their
  elliptic-curve and hashing code, and the state journal. That is what the second budget
  pays for.
- Gating REVM behind the `replay` feature did not shrink the lean package by itself,
  because the linker had already been discarding unreachable replay code; it saved
  compile time and dependencies. The size-oriented build profile is what brought the
  lean package down from about 480 KB. The Node.js test
  `the_lean_package_links_without_the_replay_backend` pins that the feature stays off
  there.

To see the breakdown yourself, build with names kept and run `twiggy`:

```bash
CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=fat \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=abort \
CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=1 \
  cargo build --release --target wasm32-unknown-unknown -p soldb-wasm --no-default-features
twiggy top -n 40 target/wasm32-unknown-unknown/release/soldb_wasm.wasm
```

## Keeping it building

- Adding a dependency to a crate in the WebAssembly set means checking it against the
  target. Run `make wasm-check` before proposing the change; CI runs it too.
- `std::net`, `std::process`, and `std::fs` compile for `wasm32-unknown-unknown` but every
  operation fails at runtime. That is why `soldb-rpc`'s HTTP transport builds there and
  why the bindings never call it. New code paths reachable from the exports must not
  touch them.
- `soldb-rpc` keeps REVM behind its `replay` feature, on by default. Code that needs REVM
  belongs in its `replay` module, and execution stays separate from I/O there:
  `replay_prefix_with_state` and `replay_target_with_state` run over any
  `ReplayStateProvider` and never touch a client, which is what lets the host-driven loop
  exist. A `ReplayPrefix` may only be reused after a run in which the provider recorded
  nothing missing; keeping one from a run that read defaults would bake those defaults
  in. `soldb-rpc` and `soldb-wasm` must keep building and passing their tests with
  `--no-default-features`, which `make wasm-check` verifies natively and on the target.
- The web document's `steps` are streamed from the trace by `WebSteps` in
  `soldb-serializer`, one step at a time, rather than copied into a `serde_json::Value`
  tree first. A test pins the output byte-for-byte against the former shape, so a change
  there is a contract change and needs `docs/json.md` updated with it.
- The logic behind every export lives in `soldb_wasm::pipeline` and
  `soldb_wasm::replay` and is tested natively, so it counts toward the workspace coverage
  gate. `crates/soldb-wasm/tests/web.rs` proves the bindings link, hold the trace across
  calls, drive a replay to completion, and round-trip through the JavaScript ABI.
  `test/wasm/replay-live.cjs` is the only check that needs a chain, and it is the one
  that proves the replay package against a real node.
- A new WebAssembly-capable crate goes into `WASM_CRATES` in the `Makefile`; CI picks it
  up from there.
