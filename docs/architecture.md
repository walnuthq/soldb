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
- `src/soldb/transaction_tracer.py` - Handles RPC communication and trace retrieval

### 2. Execution Trace Structure

The node returns a detailed trace for every EVM instruction executed:

```python
{
    "pc": 123,           # Program Counter
    "op": "PUSH1",       # Opcode
    "gas": 100000,       # Remaining gas
    "gasCost": 3,        # Cost of this operation
    "depth": 1,          # Call stack depth
    "stack": ["0x4"],    # Stack state
    "memory": "0x...",   # Memory state
    "storage": {...}     # Storage state
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

### Transaction Loading (`transaction_tracer.py`)

```python
def trace_transaction(tx_hash, rpc_url, ethdebug_dir):
    # 1. Connect to node
    w3 = Web3(HTTPProvider(rpc_url))
    
    # 2. Fetch transaction
    tx = w3.eth.get_transaction(tx_hash)
    receipt = w3.eth.get_transaction_receipt(tx_hash)
    
    # 3. Get execution trace
    trace = w3.manager.request_blocking("debug_traceTransaction", 
        [tx_hash, {"tracer": "callTracer", "tracerConfig": {...}}])
    
    # 4. Load ETHDebug mappings
    ethdebug = load_ethdebug_files(ethdebug_dir, receipt.contractAddress)
    
    # 5. Correlate and analyze
    return analyze_trace(trace, ethdebug)
```

### PC to Source Mapping

```python
def map_pc_to_source(pc, ethdebug_data):
    # Find instruction at PC
    instruction = ethdebug_data.instructions.get(pc)
    if instruction and instruction.context:
        source_id = instruction.context.source.id
        offset = instruction.context.source.offset
        length = instruction.context.source.length
        
        # Convert byte offset to line:column
        source_file = ethdebug_data.sources[source_id]
        line, column = byte_offset_to_position(source_file.content, offset)
        
        return SourceLocation(file=source_file.path, line=line, column=column)
```

### Function Call Detection

```python
def analyze_function_calls(trace, ethdebug):
    call_stack = []
    current_calls = []
    
    for step in trace:
        if step.op == "JUMPDEST":
            # Check if this is a function entry
            source = map_pc_to_source(step.pc, ethdebug)
            if is_function_declaration(source):
                function = extract_function_info(source, step)
                current_calls.append(function)
                
        elif step.op in ["RETURN", "STOP", "REVERT"]:
            # Function exit
            if current_calls:
                completed_call = current_calls.pop()
                completed_call.gas_used = calculate_gas_used(completed_call, step)
                call_stack.append(completed_call)
    
    return build_call_tree(call_stack)
```

## Why This Architecture Works

1. **No State Copying Required**: The Ethereum node already has the full blockchain state and can replay any transaction in its original context.

2. **Accurate Execution**: Using the node's replay ensures the exact same execution path, including all state dependencies.

3. **Source-Level Debugging**: ETHDebug mappings provide precise correlation between EVM execution and Solidity source code.

4. **Minimal Dependencies**: Relies on standard Ethereum RPC methods and debug information from the Solidity compiler.

## Usage Example

When you run:
```bash
soldb trace 0x35ffb6c4... --ethdebug-dir ./debug --rpc http://localhost:8547
```

The flow is:
1. Connect to Ethereum node at localhost:8547
2. Request debug trace for transaction 0x35ffb6c4...
3. Load ETHDebug files from ./debug directory
4. Map each PC in the trace to source locations
5. Analyze trace to identify function calls
6. Display formatted call stack with gas usage

This architecture provides efficient, accurate debugging without requiring a full blockchain copy or complex state management.
