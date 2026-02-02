# Stylus Interop Test

This directory contains contracts for testing Solidity <> Stylus cross-environment tracing.

## Structure

```
stylus/
├── counter/                    # Stylus (Rust) counter contract
│   ├── Cargo.toml
│   ├── Stylus.toml
│   ├── rust-toolchain.toml
│   └── src/lib.rs
├── solidity-caller/            # Solidity contract that calls Stylus
│   └── StylusCounterCaller.sol
├── deploy.sh                   # Deployment script
├── deployment.env              # Generated deployment info
└── stylus-contracts.json       # Generated contracts registry
```

## Prerequisites

1. **Nitro testnode with Stylus support**
   ```bash
   # Clone and run nitro-testnode
   git clone https://github.com/OffchainLabs/nitro-testnode.git
   cd nitro-testnode
   ./test-node.bash --init --dev
   ```

2. **cargo-stylus-beta** (with debug/usertrace support)

   Follow the installation instructions at:
   https://github.com/walnuthq/stylus-sdk-rs/blob/main/cargo-stylus/docs/StylusDebugger.md

   ```bash
   # Clone the walnut fork of stylus-sdk-rs
   git clone https://github.com/walnuthq/stylus-sdk-rs.git
   cd stylus-sdk-rs/cargo-stylus

   # Install cargo-stylus-beta
   cargo install --path . --force
   ```

3. **Solidity compiler** (>= 0.8.23 with ETHDebug)
   ```bash
   solc-select install 0.8.31
   solc-select use 0.8.31
   ```

4. **Stylus bridge** (cross-env-bridge)

   The cross-env-bridge must be running at `http://127.0.0.1:8765`.
   See the stylus-sdk-rs documentation for setup instructions.

## Deployment

```bash
cd test/stylus
./deploy.sh
```

This will:
1. Deploy the Stylus Counter contract
2. Compile the Solidity StylusCounterCaller with ETHDebug
3. Deploy the Solidity contract
4. Create a test transaction
5. Generate `deployment.env` and `stylus-contracts.json`

## Running the Test

After deployment:

```bash
# Source the deployment info
source deployment.env

# Run soldb trace
soldb trace $TEST_TX \
  --ethdebug-dir $SOLIDITY_CALLER_ADDRESS:StylusCounterCaller:./solidity-caller/out \
  --cross-env-bridge http://127.0.0.1:8765 \
  --stylus-contracts ./stylus-contracts.json \
  --rpc $RPC_URL
```

## Running with lit

To run the test with the test suite, you need to configure Stylus in `lit.site.cfg.py`:

```python
config.stylus_config = {
    'rpc_url': 'http://localhost:8547',
    'bridge_url': 'http://127.0.0.1:8765',
    'test_tx': '0x...',  # From deployment.env
    'caller_address': '0x...',  # SOLIDITY_CALLER_ADDRESS
    'counter_address': '0x...',  # STYLUS_COUNTER_ADDRESS
    'debug_dir': '/path/to/test/stylus/solidity-caller/out',
    'contracts_json': '/path/to/test/stylus/stylus-contracts.json'
}
```

Then run:
```bash
lit trace/stylus-interop.test -v
```
