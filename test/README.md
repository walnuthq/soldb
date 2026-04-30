# SolDB Test Suite

This directory contains the test infrastructure for SolDB.

## Directory Structure

```
test/
├── unit/            # Pytest unit coverage for deterministic Python modules
├── trace/           # Trace command tests
├── simulate/        # Simulate command tests
├── events/          # Events command tests
├── cli/             # CLI command and validation tests
├── stylus/          # Stylus interop test contracts and scripts
├── run-tests.sh     # Main test runner script
├── lit.cfg.py       # Test framework configuration
├── lit.site.cfg.py  # Generated site-specific configuration (gitignored)
└── README.md
```

## Test Categories

### Trace Tests (`test/trace/`)
Tests for the `soldb trace` command:
- **basic-trace.test**: Basic transaction tracing
- **increment-trace.test**: Function call tracing with nested calls
- **raw-trace.test**: Raw instruction trace with `--raw` flag

### Simulate Tests (`test/simulate/`)
Tests for the `soldb simulate` command:
- **basic-simulate.test**: Basic function simulation
- **json-simulate.test**: JSON output format testing
- **raw-data-simulate.test**: Raw calldata simulation
- **raw-simulate.test**: Raw instruction trace for simulation
- **no-debug-info.test**: Simulation without ETHDebug or ABI metadata
- **invalid-value-json.test**: JSON error output for invalid values
- **missing-function-signature.test**: Required signature validation
- **raw-data-argument-error.test**: Raw calldata argument validation
- **wrong-argument-count.test**: ABI-backed argument count validation

### Events Tests (`test/events/`)
Tests for the `soldb list-events` command:
- **multiple-events.test**: Event listing for a transaction with logs
- **multiple-events-json.test**: JSON event output
- **no-events.test**: Empty event output
- **balance-updated-decoded.test**: ABI-decoded indexed and non-indexed event fields
- **balance-updated-decoded-json.test**: JSON ABI-decoded event fields
- **invalid-transaction-json.test**: JSON error output for missing receipts

### CLI Tests (`test/cli/`)
Tests for command-line parsing and shared command behavior:
- **help.test**: Top-level and subcommand help output
- **missing-command.test**: Required command validation
- **list-contracts-basic.test**: Contract listing for a local transaction
- **bridge-invalid-host.test**: Bridge command startup error handling

### Unit Tests (`test/unit/`)
Pytest tests for deterministic Python modules that do not need a live chain:
- Protocol and contract registry round-trips
- Bridge client request and error handling
- ABI parsing, shared CLI helpers, logging, and exception formatting
- ETHDebug/source-map parsers, trace serialization, and tracer helper behavior

### Stylus Interop Tests (`test/stylus/`)
Tests for Solidity <> Stylus cross-environment tracing:
- **stylus-interop.test**: Cross-environment trace with Stylus bridge

These tests require additional setup. See `test/stylus/README.md` for details.

## Running Tests

### Run All Tests
```bash
cd test
./run-tests.sh
```

### Run Specific Test Categories
```bash
# Run only trace tests
./run-tests.sh --trace-only

# Run only simulate tests
./run-tests.sh --simulate-only

# Run only events tests
./run-tests.sh --events-only

# Run only CLI tests
./run-tests.sh --cli-only
```

### Run with Verbose Output
```bash
./run-tests.sh -v
```

### Run with Coverage
```bash
coverage erase
coverage run --parallel-mode -m pytest test/unit
./run-tests.sh --coverage
coverage combine
coverage report
coverage html
coverage xml
```

This records pytest unit coverage, wraps each `soldb` CLI invocation in `coverage run --parallel-mode`, then combines all subprocess data after lit finishes.
CI enforces a 70% total coverage gate for the expanded Python module scope configured in `pyproject.toml`, plus at least 80% coverage on Python lines changed in each pull request.

### Run Remote Tests with Sepolia API Key
```bash
# Via command line option
./run-tests.sh --sepolia-key=YOUR_API_KEY

# Via environment variable
export SEPOLIA_KEY_ENV=YOUR_API_KEY
./run-tests.sh
```

### Run Individual Tests
```bash
# Run a specific test file
lit trace/basic-trace.test
lit simulate/basic-simulate.test

# Run all tests in a category
lit trace/
lit simulate/
```

### Run Stylus Interop Tests
Stylus tests require additional setup (nitro-testnode, cargo-stylus-beta, cross-env-bridge).
See `test/stylus/README.md` for full instructions.

```bash
# Deploy contracts first
cd test/stylus
./deploy.sh

# Then run the test (requires stylus-bridge feature)
lit trace/stylus-interop.test -v
```

## Prerequisites

1. **Anvil or local Ethereum node** running on `http://localhost:8545`
2. **Solidity compiler (solc)** (version 0.8.29+ for ETHDebug)
3. **Test dependencies** installed:
   - `lit` test runner
   - `FileCheck` test verification
4. **SolDB** installed and available

### Additional Prerequisites for Stylus Tests

5. **Nitro debug testnode with Stylus support** running on `http://localhost:8547`
6. **cargo-stylus-beta** from walnut fork:
   - Installation: https://github.com/walnuthq/stylus-sdk-rs/blob/main/cargo-stylus/docs/StylusDebugger.md
7. **cross-env-bridge** running on `http://127.0.0.1:8765`

## Test Environment

The tests use the following environment:
- **RPC URL**: `http://localhost:8545` (configurable via `RPC_URL` environment variable)
- **Sepolia RPC**: Optimism Sepolia testnet (requires API key via `--sepolia-key` or `SEPOLIA_KEY_ENV`)
- **Private Key**: Default Anvil private key for deployment
- **Contract**: TestContract from `examples/TestContract.sol`
- **Debug Format**: ETHDebug for source mapping

## Test Configuration

The test suite uses the following configuration files:
- **lit.cfg.py**: Main lit configuration with substitutions and features
- **lit.site.cfg.py**: Site-specific configuration (auto-generated by run-tests.sh)
- **run-tests.sh**: Main test runner with deployment and execution logic

## Adding New Tests

1. Create a new `.test` file in `test/*` directory
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
   - `%{sepolia_rpc_url}` - Optimism Sepolia RPC URL (when API key is provided)
   - `%{contract_address}` - Contract address
   - `%{project_root}` - Project root directory path

### Test Format Example
```bash
# Test description
# REQUIRES: soldb
# RUN: %soldb command [args] | FileCheck %s

# CHECK: Expected output line 1
# CHECK: Expected output line 2
```

## Troubleshooting

### Common Issues

1. **RPC Connection Failed**
   - Ensure Anvil is running: `anvil`
   - Check RPC URL: `echo $RPC_URL`

2. **Contract Deployment Failed**
   - Verify Solidity compiler: `solc --version` (needs 0.8.29+ for ETHDebug)
   - Check compilation: `cd examples && solc --via-ir --debug-info ethdebug TestContract.sol`

3. **FileCheck Not Found**
   - Install LLVM: `brew install llvm`
   - Update PATH: `export PATH="/opt/homebrew/opt/llvm/bin:$PATH"`

4. **Lit Not Found**
   - Install lit: `pip install lit`
