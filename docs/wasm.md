# WebAssembly

SolDB's library crates build for `wasm32-unknown-unknown`, and the `soldb-wasm` crate
wraps them in a small `wasm-bindgen` API so a browser or Node.js host can build traces,
step through them at source level, and render the same versioned JSON document as
`soldb trace --json`, including its `contracts` section. CI builds and tests the package
on every pull request.

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
| `soldb-rpc` | builds | trace assembly and REVM replay compile; the HTTP transport exists but cannot open a socket |
| `soldb-wasm` | yes | the bindings described below |
| `soldb-cli`, `soldb-dap` | no | terminal and editor frontends |
| `soldb-compiler` | no | invokes `solc` |
| `soldb-bridge` | no | TCP bridge server |

The host is the I/O layer. It calls JSON-RPC with `fetch` or any client library, reads
ETHDebug artifacts however it stores them, and passes everything to the module as
strings. This follows the same premise as the native tool: the node is the execution
oracle, and debug info comes from the compiler's artifacts rather than from guessing.

## Building

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

make wasm-check   # clippy on the target for every WebAssembly-capable crate
make wasm         # wasm-pack build crates/soldb-wasm --target web
make wasm-test    # wasm-pack test --node crates/soldb-wasm
```

`make wasm` writes `crates/soldb-wasm/pkg/` (gitignored) with the module, its JavaScript
loader, TypeScript declarations, and a `package.json`, ready to be published to npm or
copied into an application. Pass a different `--target` to `wasm-pack build` for a
bundler or Node.js consumer:

```bash
wasm-pack build crates/soldb-wasm --target bundler
wasm-pack build crates/soldb-wasm --target nodejs
```

The crate list behind `make wasm-check` is the `WASM_CRATES` variable in the `Makefile`.
CI runs the same three targets in the `wasm` job of `.github/workflows/ci.yml`.

## API

Every argument and result crosses the boundary as a JSON string, so the documents are the
ones this repository already specifies. Failures throw a JavaScript `Error` whose message
is the debugger's own error text.

| export | purpose |
| --- | --- |
| `version()` | the version the module was built from |
| `buildTransactionTrace(debugTrace, transaction, receipt)` | the `result` fields of `debug_traceTransaction`, `eth_getTransactionByHash`, and `eth_getTransactionReceipt` in, trace JSON out |
| `buildSimulationTrace(from, to, calldata, value, debugTrace)` | the call that was sent plus the `result` of `debug_traceCall` in, trace JSON out |
| `traceToWebJson(trace, contracts?)` | the versioned document from [json.md](json.md) for a transaction |
| `simulateToWebJson(trace, functionName, contracts?)` | the versioned document for a simulation |
| `new DebugSession(trace)` | opcode-level session with no debug info |
| `DebugSession.withEthdebug(trace, artifacts)` | source-level session |
| `session.stepCount()` | number of opcode steps |
| `session.step(index)` | one step as JSON, or `undefined` past the end |

"Trace JSON" is the serialized `TransactionTrace` that `buildTransactionTrace` and
`buildSimulationTrace` return. It is the input every other export accepts, so a host can
also cache it or produce it from a trace saved by the native CLI.

### Contract artifacts

Debug info reaches the module as one JSON object per contract, the same shape whether it
opens a session or fills the web document:

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

`DebugSession.withEthdebug` takes one of these. Each `step` then carries the source
span, the enclosing function, and the variables the artifact declares at that program
counter, with the same `Unavailable` and `Raw` statuses the CLI and DAP server report
when the debug info does not cover a value.

`traceToWebJson` and `simulateToWebJson` take a map from contract address to one of
these as their optional `contracts` argument and fill the document's `contracts` section
exactly as `--ethdebug-dir` does for the CLI: `pcToSourceMappings`, `sourcePaths`,
`sources`, `debugAvailable`, and `abi` per contract, keyed by the lowercased address. A
source without contents falls back to its path, and a contract with nothing to report is
left out, both as on the command line. Omit the argument to leave the section empty. The
projection itself is `WebContractMetadata::from_ethdebug` in `soldb-serializer`, which
is the single implementation the CLI and the module share.

### Example

```js
import init, { buildTransactionTrace, DebugSession, traceToWebJson } from "./pkg/soldb_wasm.js";

await init();

const rpc = async (method, params) => {
  const response = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const { result, error } = await response.json();
  if (error) throw new Error(error.message);
  return JSON.stringify(result);
};
const file = async (path) => (await fetch(path)).text();

const txHash = "0x…";
const trace = buildTransactionTrace(
  await rpc("debug_traceTransaction", [txHash, { enableMemory: true, disableStorage: false }]),
  await rpc("eth_getTransactionByHash", [txHash]),
  await rpc("eth_getTransactionReceipt", [txHash]),
);

const counter = {
  name: "Counter",
  metadata: JSON.parse(await file("out/ethdebug_resources.json")),
  program: JSON.parse(await file("out/Counter_ethdebug-runtime.json")),
  sources: { 0: await file("Counter.sol") },
  abi: JSON.parse(await file("out/Counter.abi")),
};

const session = DebugSession.withEthdebug(trace, JSON.stringify(counter));
for (let index = 0; index < session.stepCount(); index += 1) {
  const step = JSON.parse(session.step(index));
  if (step.source) {
    console.log(`${step.pc} ${step.op} ${step.source.path}:${step.source.line}`);
  }
}

const document = JSON.parse(
  traceToWebJson(trace, JSON.stringify({ [COUNTER_ADDRESS]: counter })),
);
```

## Keeping it building

- Adding a dependency to a crate in the WebAssembly set means checking it against the
  target. Run `make wasm-check` before proposing the change; CI runs it too.
- `std::net`, `std::process`, and `std::fs` compile for `wasm32-unknown-unknown` but every
  operation fails at runtime. That is why `soldb-rpc` builds despite its HTTP transport
  and why the bindings never call it. New code paths reachable from the exports must not
  touch them.
- `soldb-rpc` reaches `getrandom` through REVM's `k256` dependency. Its manifest selects
  the `js` backend for `wasm32-unknown-unknown` only; nothing in the debugger draws
  randomness, and without that feature the target does not link.
- The logic behind every export lives in `soldb_wasm::pipeline` and is tested natively,
  so it counts toward the workspace coverage gate. `crates/soldb-wasm/tests/web.rs`
  only proves the bindings link and round-trip through the JavaScript ABI.
- A new WebAssembly-capable crate goes into `WASM_CRATES` in the `Makefile`; CI picks it
  up from there.
