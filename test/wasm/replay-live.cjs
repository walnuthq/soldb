// Replays a transaction through the replay-capable WebAssembly package against a live
// node, driving the host loop with real JSON-RPC calls, and checks the result against
// the node's own `debug_traceTransaction`. This is the WebAssembly counterpart of the
// backend-parity lit tests: the two backends must agree on the opcode stream.
//
// Usage: node test/wasm/replay-live.cjs [package-dir]
//   RPC_URL   the node (default http://127.0.0.1:8545); anvil's unlocked account signs.
//   package-dir defaults to crates/soldb-wasm/pkg-replay-node (a `--target nodejs` build).

"use strict";

const path = require("node:path");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
const PACKAGE_DIR = path.resolve(
  process.argv[2] || path.join(__dirname, "..", "..", "crates", "soldb-wasm", "pkg-replay-node"),
);
// anvil's first default account.
const SENDER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
// PUSH1 0 BLOCKHASH POP  PUSH1 0 SLOAD PUSH1 1 ADD PUSH1 0 SSTORE  STOP: every kind of
// state a replay can ask for.
const RUNTIME = "6000405060005460010160005500";
// Copies the runtime into memory and returns it: PUSH1 len PUSH1 offset PUSH1 0 CODECOPY
// PUSH1 len PUSH1 0 RETURN, twelve bytes, so the runtime starts at offset 0x0c.
const INIT_CODE = `0x600e600c600039600e6000f3${RUNTIME}`;
const EXPECTED_OPS = ["PUSH1", "BLOCKHASH", "POP", "PUSH1", "SLOAD", "PUSH1", "ADD", "PUSH1", "SSTORE", "STOP"];

let nextId = 1;
async function rpc(method, params) {
  const response = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  });
  const { result, error } = await response.json();
  if (error) throw new Error(`${method}: ${error.message}`);
  return result;
}

async function receiptOf(hash) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const receipt = await rpc("eth_getTransactionReceipt", [hash]);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`transaction ${hash} was not mined`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function main() {
  const { Replay, Trace, replayAvailable, version } = require(path.join(PACKAGE_DIR, "soldb_wasm.js"));
  assert(replayAvailable(), `${PACKAGE_DIR} is not the replay-capable package`);
  console.log(`soldb-wasm ${version()} against ${RPC_URL}`);

  // Deploy the counter and call it once.
  const deployHash = await rpc("eth_sendTransaction", [{ from: SENDER, data: INIT_CODE, gas: "0x30d40" }]);
  const contract = (await receiptOf(deployHash)).contractAddress;
  assert(contract, "deployment produced no contract address");
  const code = await rpc("eth_getCode", [contract, "latest"]);
  assert(code === `0x${RUNTIME}`, `unexpected runtime code ${code}`);
  const callHash = await rpc("eth_sendTransaction", [{ from: SENDER, to: contract, gas: "0x186a0" }]);
  const receipt = await receiptOf(callHash);
  assert(receipt.status === "0x1", "the call reverted");

  // The host side of the replay loop, over real RPC.
  const transaction = await rpc("eth_getTransactionByHash", [callHash]);
  const block = await rpc("eth_getBlockByNumber", [transaction.blockNumber, true]);
  const chainId = await rpc("eth_chainId", []);
  const replay = Replay.prepare(
    JSON.stringify(transaction),
    JSON.stringify(receipt),
    JSON.stringify(block),
    chainId,
  );

  let status = JSON.parse(replay.status());
  let rounds = 0;
  let requests = 0;
  while (status.status !== "complete") {
    assert(status.status === "needsState", `unexpected status ${JSON.stringify(status)}`);
    const batch = { accounts: {}, storage: {}, blockHashes: {} };
    for (const request of status.requests) {
      requests += 1;
      if (request.kind === "account") {
        const [balance, nonce, accountCode] = await Promise.all([
          rpc("eth_getBalance", [request.address, status.block]),
          rpc("eth_getTransactionCount", [request.address, status.block]),
          rpc("eth_getCode", [request.address, status.block]),
        ]);
        batch.accounts[request.address] = { balance, nonce, code: accountCode };
      } else if (request.kind === "storage") {
        (batch.storage[request.address] ??= {})[request.slot] = await rpc("eth_getStorageAt", [
          request.address,
          request.slot,
          status.block,
        ]);
      } else if (request.kind === "blockHash") {
        const header = await rpc("eth_getBlockByNumber", [`0x${request.number.toString(16)}`, false]);
        batch.blockHashes[request.number] = header.hash;
      } else {
        throw new Error(`unknown request kind ${request.kind}`);
      }
    }
    replay.provideState(JSON.stringify(batch));
    status = JSON.parse(replay.run());
    rounds += 1;
    assert(rounds < 10, "the replay did not converge");
  }
  assert(replay.isComplete(), "status says complete but the replay does not");
  const bundle = replay.exportState();
  const replayed = replay.finish();

  // The exported state replays the same transaction in one run without touching the node.
  const offline = Replay.prepare(
    JSON.stringify(transaction),
    JSON.stringify(receipt),
    JSON.stringify(block),
    chainId,
  );
  offline.provideState(bundle);
  assert(JSON.parse(offline.run()).status === "complete", "the exported state did not complete the replay in one run");
  const offlineTrace = offline.finish();
  assert(offlineTrace.toJson() === replayed.toJson(), "the offline replay differs from the online one");
  offlineTrace.free();

  // What the module produced.
  const summary = JSON.parse(replayed.summary());
  assert(summary.backend === "replay", `backend ${summary.backend}`);
  assert(summary.success === true, `replay reports failure: ${summary.error}`);
  assert(summary.txHash.toLowerCase() === callHash.toLowerCase(), "wrong transaction");
  const replayedSteps = [];
  for (let index = 0; index < replayed.stepCount(); index += 1) {
    replayedSteps.push(JSON.parse(replayed.step(index)));
  }
  const replayedOps = replayedSteps.map((step) => step.op);
  assert(
    JSON.stringify(replayedOps) === JSON.stringify(EXPECTED_OPS),
    `unexpected opcode stream ${replayedOps.join(" ")}`,
  );
  const sstore = replayedSteps[8];
  assert(sstore.snapshot.storage["0x0"] === "0x1", `slot 0 after the call: ${JSON.stringify(sstore.snapshot.storage)}`);
  assert(sstore.snapshot.storage_diff["0x0"].after === "0x1", "storage diff missing");
  const document = JSON.parse(replayed.toWebJson());
  assert(document.backend === "replay" && document.steps.length === EXPECTED_OPS.length, "web document mismatch");

  // Backend parity: the node's debug_traceTransaction, through the same module, must
  // agree on program counters and opcodes.
  const debugTrace = await rpc("debug_traceTransaction", [callHash, { enableMemory: true, disableStorage: false }]);
  const traced = Trace.fromTransaction(JSON.stringify(debugTrace), JSON.stringify(transaction), JSON.stringify(receipt));
  assert(traced.stepCount() === replayed.stepCount(), `step count ${traced.stepCount()} vs ${replayed.stepCount()}`);
  for (let index = 0; index < traced.stepCount(); index += 1) {
    const expected = JSON.parse(traced.step(index));
    const actual = replayedSteps[index];
    assert(expected.pc === actual.pc && expected.op === actual.op, `step ${index}: ${expected.op}@${expected.pc} vs ${actual.op}@${actual.pc}`);
    assert(
      JSON.stringify(expected.snapshot.stack) === JSON.stringify(actual.snapshot.stack),
      `step ${index}: stack differs`,
    );
  }
  traced.free();
  replayed.free();

  const bundleSize = Buffer.byteLength(bundle);
  console.log(`replayed ${callHash} in ${rounds} run(s) answering ${requests} state request(s); ${replayedOps.length} steps match debug_traceTransaction; ${bundleSize}-byte state export replays offline`);
}

main().catch((error) => {
  console.error(`replay-live: ${error.message}`);
  process.exit(1);
});
