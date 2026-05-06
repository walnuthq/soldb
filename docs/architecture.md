# SolDB Architecture: Blockchain Transaction Debugging

## Overview

SolDB implements blockchain transaction debugging by leveraging the Ethereum node's built-in replay capabilities combined with source code mapping. Unlike traditional debuggers that need to copy the entire blockchain state, SolDB uses the node's `debug_traceTransaction` RPC method to replay transactions in their original context.

## Core Architecture Components

### 1. Transaction Replay via RPC

The key insight is that Ethereum nodes (like offchainlabs/nitro-node) already have the capability to replay transactions with full execution traces. SolDB leverages this instead of reimplementing blockchain state management.

```
User provides transaction hash
    ↓
SolDB connects to Ethereum node (RPC)
    ↓
Calls debug_traceTransaction(txHash)
    ↓
Node replays transaction in original block context
    ↓
Returns step-by-step execution trace
```

**Key Files:**
- `crates/soldb-rpc/src/lib.rs` - Handles JSON-RPC communication and trace retrieval
- `crates/soldb-cli/src/main.rs` - Wires trace data into user-facing commands

### 2. Execution Trace Structure

The node returns a detailed trace for every EVM instruction executed:

```json
{
    "pc": 123,
    "op": "PUSH1",
    "gas": 100000,
    "gasCost": 3,
    "depth": 1,
    "stack": ["0x4"],
    "memory": "0x...",
    "storage": {}
}
```

### 3. Source Code Mapping (ETHDebug)

ETHDebug provides the critical mapping between EVM bytecode positions (PC) and source code locations:

```
PC 123 → TestContract.sol:39:15 (line 39, column 15)
```

**ETHDebug Files:**
- `Contract_ethdebug.json` - Constructor debug info
- `Contract_ethdebug-runtime.json` - Runtime debug info with instruction mappings

Each instruction entry contains:
```json
{
  "opcode": "PUSH1",
  "value": "0x4",
  "context": {
    "source": {
      "id": 0,
      "offset": 523,
      "length": 1
    }
  }
}
```

### 4. Function Call Analysis

The system analyzes the execution trace to reconstruct function calls:

1. **Function Detection:**
   - Identifies JUMPDEST opcodes that correspond to function entries
   - Matches against source code function declarations
   - Decodes function selectors from calldata

2. **Call Stack Reconstruction:**
   ```
   Step 99:  JUMPDEST (PC: 296) → Function: x()
   Step 296: JUMP (PC: 493)     → Internal call to y()
   Step 493: JUMPDEST           → Function: y()
   Step 966: RETURN             → Exit y()
   ```

3. **Parameter Extraction:**
   - External calls: Decode from transaction calldata
   - Internal calls: Extract from stack at function entry
   - Unknown function signatures: Lookup via 4byte.directory API at `https://www.4byte.directory/api/v1/signatures/?hex_signature=0x{selector}`

### 5. Architecture Flow

```
┌─────────────────┐
│   Blockchain    │
│   Transaction   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  Ethereum Node  │     │  ETHDebug Files  │
│  (debug_trace)  │     │  (PC mappings)   │
└────────┬────────┘     └────────┬─────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────┐
│          TransactionTracer              │
│  - Fetches transaction trace            │
│  - Loads ETHDebug mappings              │
│  - Correlates PC → Source               │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│         Function Call Analyzer          │
│  - Detects function boundaries          │
│  - Builds call stack                    │
│  - Extracts parameters                  │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│          Output Formatter               │
│  - Function trace view                  │
│  - Raw instruction view                 │
│  - Interactive debugger                 │
└─────────────────────────────────────────┘
```

## Key Implementation Details

### Transaction Loading (`soldb-rpc`)

```rust
pub fn trace_transaction(rpc_url: &str, tx_hash: &str) -> SoldbResult<TransactionTrace> {
    let transaction = rpc_request(rpc_url, "eth_getTransactionByHash", json!([tx_hash]))?;
    let receipt = rpc_request(rpc_url, "eth_getTransactionReceipt", json!([tx_hash]))?;
    let debug = rpc_request(
        rpc_url,
        "debug_traceTransaction",
        json!([tx_hash, {"enableMemory": true, "disableStack": false}]),
    )?;

    build_transaction_trace(tx_hash, transaction, receipt, debug)
}
```

### PC to Source Mapping

```rust
pub fn source_info_for_pc(&self, pc: u64) -> Option<SourceInfo> {
    let instruction = self.instruction_for_pc(pc)?;
    let source = instruction.source.as_ref()?;
    let source_file = self.sources.get(&source.id)?;
    let (line, column) = byte_offset_to_position(&source_file.content, source.offset);

    Some(SourceInfo {
        path: source_file.path.clone(),
        line,
        column,
    })
}
```

### Function Call Detection

```rust
pub fn summarize_calls(trace: &TransactionTrace, metadata: &ContractMetadata) -> Vec<FunctionCall> {
    trace
        .steps
        .iter()
        .filter_map(|step| metadata.function_at_pc(step.pc))
        .map(|function| FunctionCall {
            name: function.name,
            source: function.source,
            gas_used: trace.gas_used,
        })
        .collect()
}
```

## Why This Architecture Works

1. **No State Copying Required**: The Ethereum node already has the full blockchain state and can replay any transaction in its original context.

2. **Accurate Execution**: Using the node's replay ensures the exact same execution path, including all state dependencies.

3. **Source-Level Debugging**: ETHDebug mappings provide precise correlation between EVM execution and Solidity source code.

4. **Minimal Dependencies**: Relies on standard Ethereum RPC methods and debug information from the Solidity compiler.

## Usage Example

When you run:
```bash
soldb trace 0x35ffb6c4... --ethdebug-dir 0x3aa5ebb10dc797cac828524e59a333d0a371443c:TestContract:./debug --rpc http://localhost:8547
```

The flow is:
1. Connect to Ethereum node at localhost:8547
2. Request debug trace for transaction 0x35ffb6c4...
3. Load ETHDebug files from ./debug directory
4. Map each PC in the trace to source locations
5. Analyze trace to identify function calls
6. Display formatted call stack with gas usage

This architecture provides efficient, accurate debugging without requiring a full blockchain copy or complex state management.
