# soldb-wasm

WebAssembly bindings for [SolDB](https://github.com/walnuthq/soldb), the ETHDebug-first
Solidity debugger. The module builds transaction traces from a node's JSON-RPC responses,
runs a source-level debug session over them with the contract's ETHDebug artifacts, and
renders the same versioned web JSON document as `soldb trace --json`, including its
per-contract source metadata.

The host does the I/O: fetch `debug_traceTransaction`, `eth_getTransactionByHash`, and
`eth_getTransactionReceipt` yourself, read the ETHDebug artifacts, and pass everything in
as strings.

```js
import init, { buildTransactionTrace, DebugSession, traceToWebJson } from "soldb-wasm";

await init();
const trace = buildTransactionTrace(debugTraceResult, transaction, receipt);
const counter = { name: "Counter", metadata: resources, program: runtimeProgram, sources, abi };
const session = DebugSession.withEthdebug(trace, JSON.stringify(counter));
const step = JSON.parse(session.step(0));
const document = JSON.parse(traceToWebJson(trace, JSON.stringify({ [address]: counter })));
```

Build it with `wasm-pack build crates/soldb-wasm --target web` from the repository root.
See [docs/wasm.md](https://github.com/walnuthq/soldb/blob/main/docs/wasm.md) for the
full API, what runs in WebAssembly and what does not, and how the build is checked in CI.
