# SolDB Test Suite

This directory contains the test infrastructure for SolDB.

## Quick Start

### Run All Tests
```bash
# From project root
./run-tests.sh

# Or with specific SOLC_PATH
SOLC_PATH=/path/to/solc ./run-tests.sh

# Or using make
make test
```

### Setup Test Environment
```bash
# Verify test environment
./test-setup.sh

# Deploy test contracts
./test-setup.sh --deploy-test

# Or using make
make test-setup
make test-deploy
```

## Test Structure

### Test Files
- `basic-trace.test` - Tests basic transaction tracing functionality
- `raw-trace.test` - Tests raw instruction trace output
- `increment-trace.test` - Tests complex function call tracing

### Test Infrastructure
- `run-tests.sh` - Main test runner that ensures TestContract is deployed
<<<<<<< HEAD
- `deploy-test-contract.sh` - Deploys TestContract.sol to `test_debug` directory
=======
- `deploy-test-contract.sh` - Deploys TestContract.sol to `out` directory
>>>>>>> upstream/main
- `lit.cfg.py` - Test framework configuration
- `lit.site.cfg.py` - Generated site-specific configuration (gitignored)

## Test Contract

The tests use `examples/TestContract.sol` which includes:
- Multiple functions with internal calls
- Events and state changes
- Function overloading

<<<<<<< HEAD
Test deployments are kept in `examples/test_debug/` separate from regular deployments.
=======
Test deployments are kept in `examples/out/` separate from regular deployments.
>>>>>>> upstream/main

## Requirements

1. **Anvil running with tracing enabled:**
   ```bash
   anvil --steps-tracing
   ```

2. **Solidity compiler 0.8.29+** (for ETHDebug support)

3. **Python packages:**
   - lit (test runner)
   - FileCheck (test verification)

## Adding New Tests

1. Create a new `.test` file in this directory
2. Use the `REQUIRES: soldb` directive
3. Use FileCheck syntax for verification:
   ```
   # RUN: %soldb trace %{test_tx} ... | FileCheck %s
   # CHECK: Expected output
   ```

4. Available substitutions:
   - `%soldb` - Path to soldb executable
   - `%{test_tx}` - Test transaction hash
   - `%{ethdebug_dir}` - ETHDebug directory path
   - `%{rpc_url}` - RPC endpoint URL

## Troubleshooting

### Tests Failing
1. Ensure Anvil is running: `anvil --steps-tracing`
<<<<<<< HEAD
2. Check test deployment: `cat examples/test_debug/deployment.json`
=======
2. Check test deployment: `cat examples/out/deployment.json`
>>>>>>> upstream/main
3. Verify soldb is installed: `make dev`

### Wrong Contract Deployed
The test suite automatically deploys TestContract.sol. If you see a different contract:
```bash
# Clean and redeploy
<<<<<<< HEAD
rm -rf examples/test_debug
=======
rm -rf examples/out
>>>>>>> upstream/main
./test/deploy-test-contract.sh
```
