# Stylus Interoperability

SolDB supports cross-environment debugging for Solidity<>Stylus interactions. This allows tracing transactions where Solidity contracts call Stylus contracts and vice versa.

## Prerequisites

1. **Arbitrum Nitro dev node with debug support**
   ```bash
   docker run -it --rm --name nitro-dev -p 8547:8547 \
     offchainlabs/nitro-node:v3.5.3-rc.3-653b078 \
     --dev \
     --http.addr 0.0.0.0 \
     --http.api=net,web3,eth,arb,arbdebug,debug
   ```

2. **cargo-stylus-beta** (Walnut fork with debug support)

   Follow the installation guide: [StylusDebugger.md](https://github.com/OffchainLabs/stylus-sdk-rs/blob/main/cargo-stylus/docs/StylusDebugger.md)

   ```bash
   git clone https://github.com/OffchainLabs/stylus-sdk-rs.git
   cargo install --path cargo-stylus
   ```

3. **Cross-environment bridge**

   The bridge enables communication between soldb and the Stylus debugger:
   ```bash
   # From stylus-sdk-rs directory
   soldb bridge
   # Bridge runs at http://127.0.0.1:8765
   ```

## Usage

```bash
soldb trace <tx_hash> \
  --ethdebug-dir <solidity_address>:<contract_name>:./out \
  --cross-env-bridge http://127.0.0.1:8765 \
  --stylus-contracts ./stylus-contracts.json \
  --rpc http://localhost:8547
```

The `stylus-contracts.json` file registers Stylus contracts for debugging:
```json
{
  "contracts": [
    {
      "address": "0x...",
      "environment": "stylus",
      "name": "Counter",
      "lib_path": "./target/aarch64-apple-darwin/debug/libcounter.dylib",
      "project_path": "./counter"
    }
  ]
}
```

## Example Output

```
[STYLUS] Connected to cross-env bridge at http://127.0.0.1:8765
[STYLUS] Registered 2 contracts from stylus-contracts.json

Call Stack:
#0 StylusCounterCaller::runtime_dispatcher [entry] @ StylusCounterCaller.sol:1
  #1 complexStylusOperation(uint256,uint256,uint256) [external] @ StylusCounterCaller.sol:42
    #2 CALL → [Stylus] Counter::setNumber(uint256) [STYLUS_CALL]
      #3 [Stylus] counter::Counter::set_number [stylus:internal] @ line 48
    #4 CALL → [Stylus] Counter::increment() [STYLUS_CALL]
      #5 [Stylus] counter::Counter::increment [stylus:internal] @ line 57
    #6 STATICCALL → [Stylus] Counter::number() [STYLUS_STATICCALL]
```
