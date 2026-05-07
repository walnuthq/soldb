# ETHDebug Debugger Contract

SolDB consumes compiler-produced ETHDebug data through `soldb-debugger`.
The goal is to keep debugger features independent from compiler implementation details.

## Instruction Source Mapping

Each runtime instruction can provide a source range:

```json
{
  "offset": 42,
  "operation": {"mnemonic": "SLOAD"},
  "context": {
    "code": {
      "source": {"id": 0},
      "range": {"offset": 59, "length": 9}
    }
  }
}
```

`source.id` must match an entry in `ethdebug.json` compilation sources:

```json
{
  "compilation": {
    "sources": [
      {"id": 0, "path": "contracts/Counter.sol"}
    ]
  }
}
```

Offsets and lengths are byte offsets in the Solidity source file.

## Variable Locations

SolDB accepts variables attached to instruction context:

```json
{
  "offset": 42,
  "context": {
    "variables": [
      {
        "name": "amount",
        "type": "uint256",
        "location": {"type": "stack", "offset": 0},
        "scope": {"start": 40, "end": 55}
      }
    ]
  }
}
```

It also accepts a top-level compatibility form:

```json
{
  "variables": [
    {
      "name": "stored",
      "type": "uint256",
      "location_type": "storage",
      "offset": 0,
      "pc_start": 40,
      "pc_end": 55
    }
  ]
}
```

## Location Semantics

- `stack`: `offset` is the stack index exposed by the trace step.
- `memory`: `offset` is a byte offset into EVM memory.
- `calldata`: `offset` is a byte offset into transaction calldata, including the 4-byte selector.
- `storage`: `offset` is the storage slot number.

SolDB decodes static ABI-like values where possible, including `uint*`, `address`, `bool`, `bytesN`, and `bytes32`.
For dynamic or unsupported types, SolDB keeps the raw word and marks the value as raw instead of guessing.
For unavailable locations, SolDB reports an unavailable value.
