# soldb-wasm

WebAssembly bindings for [SolDB](https://github.com/walnuthq/soldb), the ETHDebug-first
Solidity debugger. The module builds transaction traces from a node's JSON-RPC responses,
holds them in memory, steps through them at source level with the contract's ETHDebug
artifacts, and renders the same versioned web JSON document as `soldb trace --json`,
including its per-contract source metadata. The replay-capable build also re-executes a
transaction in REVM from state the host fetches, for nodes without
`debug_traceTransaction`.

The host does the I/O: fetch the JSON-RPC responses yourself, read the ETHDebug
artifacts, and pass everything in as strings. The trace is parsed once and never re-parsed
between calls.

```js
import init, { Trace } from "soldb-wasm";

await init();
const trace = Trace.fromTransaction(debugTraceResult, transaction, receipt);
const counter = { name: "Counter", metadata: resources, program: runtimeProgram, sources, abi };
trace.attachEthdebug(JSON.stringify(counter));
const step = JSON.parse(trace.step(0));
const document = JSON.parse(trace.toWebJson(JSON.stringify({ [address]: counter })));
trace.free();
```

Two packages are built from this crate: a lean one without REVM (`make wasm-lean`) and a
replay-capable one that adds `Replay` (`make wasm-replay`); `replayAvailable()` tells you
which you loaded. See
[docs/wasm.md](https://github.com/walnuthq/soldb/blob/main/docs/wasm.md) for the full
API, the replay protocol, what runs in WebAssembly and what does not, and how the build
is checked in CI.
