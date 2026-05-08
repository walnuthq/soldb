# SolDB JSON Output

`soldb trace --json` and `soldb simulate --json` emit a web-facing JSON document with a stable top-level schema.

Current schema:

```json
{
  "schemaVersion": 1,
  "status": "success",
  "error": null,
  "backend": "debug-rpc",
  "capabilities": {
    "opcode_steps": true,
    "stack": true,
    "memory": true,
    "storage": false,
    "storage_diff": false,
    "call_trace": false,
    "contract_creation": false,
    "logs": false,
    "revert_data": false,
    "gas_details": true,
    "account_changes": false,
    "notes": []
  },
  "artifacts": {
    "calls": [],
    "creations": [],
    "logs": [],
    "account_changes": [],
    "gas": {
      "used": 21000,
      "spent": null,
      "refunded": null,
      "remaining": null,
      "limit": null
    },
    "revert_data": null
  },
  "traceCall": {
    "type": "CALL",
    "callId": 0,
    "childrenCallIds": [1],
    "functionName": "runtime_dispatcher",
    "from": "0x...",
    "to": "0x...",
    "value": "0x0",
    "gas": 100000,
    "gasUsed": 21000,
    "input": "0x...",
    "output": "0x",
    "isRevertedFrame": false,
    "calls": [
      {
        "type": "CALL",
        "callId": 1,
        "parentCallId": 0,
        "childrenCallIds": [],
        "from": "0x...",
        "to": "0x...",
        "value": "0x0",
        "gas": 50000,
        "gasUsed": 20000,
        "input": "0x...",
        "output": "0x",
        "isRevertedFrame": false,
        "calls": []
      }
    ]
  },
  "steps": [
    {
      "step": 0,
      "pc": 0,
      "traceCallIndex": 0,
      "op": "PUSH1",
      "gas": 100000,
      "gasCost": 3,
      "depth": 0,
      "stack": [],
      "snapshot": {
        "stack": [],
        "memory": null,
        "storage": {},
        "storage_diff": {}
      }
    }
  ],
  "contracts": {
    "0x...": {
      "pcToSourceMappings": {
        "10": "120:24:0"
      },
      "sourcePaths": {
        "0": "contracts/Counter.sol"
      },
      "sources": {
        "0": "contract Counter { ... }"
      },
      "debugAvailable": true,
      "abi": []
    }
  }
}
```

`simulate --json` uses the same shape, with `traceCall.type` set to `ENTRY`, `traceCall.functionName` set to the simulated function label, and top-level `function_name` and `isVerified` fields retained for existing clients.

## Compatibility Rules

- `schemaVersion` is incremented only for breaking JSON contract changes.
- `status` is lowercase: `success` or `reverted`.
- `error` is `null` on success and contains the execution or RPC error message on failure.
- `traceCall.callId` is `0` for the root call. Nested calls are emitted recursively in `traceCall.calls`, and `childrenCallIds` mirrors those child IDs for clients that prefer indexing.
- `steps[].traceCallIndex` points at the active call frame when the selected backend records call ranges. It falls back to `0` when only flat opcode steps are available.
- `backend` identifies the execution backend: `debug-rpc`, `replay`, or another future backend name.
- `capabilities` describes which data is actually available from the selected backend.
- `artifacts` carries backend-level data that is not tied to one opcode step, including replay calls, contract creations, logs, account changes, gas details, and revert data.
- `contracts` is populated from `--ethdebug-dir`/`--contracts` when available. `pcToSourceMappings` uses the `offset:length:sourceId` format generated from ETHDebug instruction locations, `sourcePaths` and `sources` are keyed by source ID, `debugAvailable` is true when ETHDebug source locations were loaded, and `abi` is copied from the compiled artifact.

Clients should treat unknown fields as additive and should prefer capability flags over backend names when deciding whether a view can be shown.
