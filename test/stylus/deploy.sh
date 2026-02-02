#!/bin/bash
# Deploy Stylus Counter and Solidity Caller for interop testing
#
# Prerequisites:
# - cargo stylus-beta (from walnuthq/stylus-sdk-rs)
# - solc >= 0.8.23 with ETHDebug support
# - cast (from foundry)
# - Running nitro-testnode with Stylus support

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Configuration
RPC_URL="${RPC_URL:-http://localhost:8547}"
PRIVATE_KEY="${PRIVATE_KEY:-0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659}"

echo "=== Deploying Stylus Interop Test Contracts ==="
echo "RPC URL: ${RPC_URL}"
echo ""

# Step 1: Deploy Stylus Counter
if [ -z "$STYLUS_COUNTER_ADDRESS" ]; then
    echo ""
    echo "Step 1: Deploying Stylus Counter contract..."
    cd "${SCRIPT_DIR}/counter"

    # Ensure we use rustup cargo, not homebrew
    if [ -d "$HOME/.rustup" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
        # Remove homebrew paths temporarily to avoid conflicts
        export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "/opt/homebrew/opt" | tr '\n' ':' | sed 's/:$//')
    fi

    # Verify cargo is from rustup
    CARGO_PATH=$(which cargo)
    echo "Using cargo: ${CARGO_PATH}"

    if [[ "${CARGO_PATH}" == *"homebrew"* ]]; then
        echo "Error: Using homebrew cargo. Please ensure rustup cargo is in PATH first."
        echo "Run: export PATH=\"\$HOME/.cargo/bin:\$PATH\""
        exit 1
    fi

    # Set rustup override for the counter directory
    rustup override set 1.88

    echo "Rust toolchain: $(rustup show active-toolchain)"
    echo "Cargo version: $(cargo --version)"

    # Build and deploy
    echo "Running: cargo stylus-beta deploy... at ${SCRIPT_DIR}/counter"
    BUILD_OUTPUT=$(cargo stylus-beta build) || {
        echo "Failed to build Stylus Counter"
        echo "${BUILD_OUTPUT}"
        exit 1
    }
    DEPLOY_OUTPUT=$(cargo stylus-beta deploy \
        --private-key="${PRIVATE_KEY}" \
        --endpoint="${RPC_URL}" \
        --no-verify 2>&1) || {
        echo "Failed to deploy Stylus Counter"
        echo "${DEPLOY_OUTPUT}"
        exit 1
    }

    echo "${DEPLOY_OUTPUT}"

    # Extract address - try multiple patterns
    STYLUS_COUNTER_ADDRESS=$(echo "${DEPLOY_OUTPUT}" | grep -iE "deployed code at address:|contract address:|deployed to:" | sed 's/.*[: ]//' | sed 's/\x1b\[[0-9;]*m//g' | tr -d '[:space:]' | head -1)

    if [ -z "$STYLUS_COUNTER_ADDRESS" ]; then
        # Try to find any 0x address in output
        STYLUS_COUNTER_ADDRESS=$(echo "${DEPLOY_OUTPUT}" | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
    fi

    if [ -z "$STYLUS_COUNTER_ADDRESS" ]; then
        echo "Failed to extract Stylus Counter address from output"
        exit 1
    fi

    # Ensure address has 0x prefix
    if [[ ! "${STYLUS_COUNTER_ADDRESS}" =~ ^0x ]]; then
        STYLUS_COUNTER_ADDRESS="0x${STYLUS_COUNTER_ADDRESS}"
    fi

    export STYLUS_COUNTER_ADDRESS
    echo "Stylus Counter deployed to: ${STYLUS_COUNTER_ADDRESS}"

    # Build debug dylib for usertrace
    echo ""
    echo "Building debug dylib for usertrace..."

    # Detect architecture
    ARCH=$(uname -m)
    if [ "$ARCH" = "arm64" ]; then
        TARGET="aarch64-apple-darwin"
    elif [ "$ARCH" = "x86_64" ]; then
        if [ "$(uname -s)" = "Darwin" ]; then
            TARGET="x86_64-apple-darwin"
        else
            TARGET="x86_64-unknown-linux-gnu"
        fi
    else
        TARGET="x86_64-unknown-linux-gnu"
    fi

    echo "Building for target: ${TARGET}"
    cargo build --lib --target "${TARGET}" --features debug || {
        echo "Warning: Debug build failed (non-critical for basic tests)"
    }

    cd "${SCRIPT_DIR}"
else
    echo "Step 1: Using existing Stylus Counter: ${STYLUS_COUNTER_ADDRESS}"
fi

# Step 2: Compile Solidity contract
echo ""
echo "Step 2: Compiling Solidity StylusCounterCaller contract..."

if ! command -v solc &> /dev/null; then
    echo "Error: solc not found. Install Solidity compiler >= 0.8.23"
    exit 1
fi

SOLC_VERSION=$(solc --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "Using solc version: ${SOLC_VERSION}"

mkdir -p "${SCRIPT_DIR}/solidity-caller/out"
solc --via-ir \
    --debug-info ethdebug \
    --ethdebug \
    --ethdebug-runtime \
    --bin \
    --abi \
    --overwrite \
    -o "${SCRIPT_DIR}/solidity-caller/out" \
    "${SCRIPT_DIR}/solidity-caller/StylusCounterCaller.sol"

echo "Solidity contract compiled with ETHDebug info"

# Step 3: Deploy Solidity contract
echo ""
echo "Step 3: Deploying Solidity StylusCounterCaller contract..."

CALLER_BYTECODE=$(cat "${SCRIPT_DIR}/solidity-caller/out/StylusCounterCaller.bin")
if [[ ! "${CALLER_BYTECODE}" =~ ^0x ]]; then
    CALLER_BYTECODE="0x${CALLER_BYTECODE}"
fi

# Encode constructor arguments
CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address)" "${STYLUS_COUNTER_ADDRESS}")
CONSTRUCTOR_ARGS="${CONSTRUCTOR_ARGS#0x}"
FULL_BYTECODE="${CALLER_BYTECODE}${CONSTRUCTOR_ARGS}"

echo "Deploying with Stylus Counter address: ${STYLUS_COUNTER_ADDRESS}"
DEPLOY_OUTPUT=$(cast send \
    --rpc-url="${RPC_URL}" \
    --private-key="${PRIVATE_KEY}" \
    --create \
    "${FULL_BYTECODE}" 2>&1)

CALLER_ADDRESS=$(echo "${DEPLOY_OUTPUT}" | grep "contractAddress" | awk '{print $2}')

if [ -z "$CALLER_ADDRESS" ]; then
    echo "Failed to deploy Solidity contract"
    echo "${DEPLOY_OUTPUT}"
    exit 1
fi

echo "Solidity StylusCounterCaller deployed to: ${CALLER_ADDRESS}"

# Step 4: Create test transaction
echo ""
echo "Step 4: Creating test transaction..."
sleep 2

TX_OUTPUT=$(cast send \
    --rpc-url="${RPC_URL}" \
    --private-key="${PRIVATE_KEY}" \
    "${CALLER_ADDRESS}" \
    "complexStylusOperation(uint256,uint256,uint256)" 10 5 15 --json 2>&1)

echo "${TX_OUTPUT}"
TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')

if [ -z "$TX_HASH" ]; then
    echo "Warning: Could not extract transaction hash"
    echo "${TX_OUTPUT}"
fi

echo "Test transaction: ${TX_HASH}"

# Step 5: Generate configuration files
echo ""
echo "Step 5: Generating configuration files..."

# Determine dylib path based on architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    DYLIB_PATH="${SCRIPT_DIR}/counter/target/aarch64-apple-darwin/debug/libcounter.dylib"
elif [ "$ARCH" = "x86_64" ] && [ "$(uname -s)" = "Darwin" ]; then
    DYLIB_PATH="${SCRIPT_DIR}/counter/target/x86_64-apple-darwin/debug/libcounter.dylib"
else
    DYLIB_PATH="${SCRIPT_DIR}/counter/target/x86_64-unknown-linux-gnu/debug/libcounter.so"
fi

# Save deployment info
cat > "${SCRIPT_DIR}/deployment.env" << EOF
RPC_URL=${RPC_URL}
STYLUS_COUNTER_ADDRESS=${STYLUS_COUNTER_ADDRESS}
SOLIDITY_CALLER_ADDRESS=${CALLER_ADDRESS}
TEST_TX=${TX_HASH}
EOF

echo "Created deployment.env"

# Generate stylus-contracts.json
cat > "${SCRIPT_DIR}/stylus-contracts.json" << EOF
{
  "contracts": [
    {
      "address": "${STYLUS_COUNTER_ADDRESS}",
      "environment": "stylus",
      "name": "Counter",
      "lib_path": "${DYLIB_PATH}",
      "project_path": "${SCRIPT_DIR}/counter"
    },
    {
      "address": "${CALLER_ADDRESS}",
      "environment": "evm",
      "name": "StylusCounterCaller",
      "project_path": "${SCRIPT_DIR}/solidity-caller",
      "debug_dir": "out"
    }
  ]
}
EOF

echo "Created stylus-contracts.json"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Stylus Counter:     ${STYLUS_COUNTER_ADDRESS}"
echo "Solidity Caller:    ${CALLER_ADDRESS}"
echo "Test Transaction:   ${TX_HASH}"
echo ""
echo "Configuration files:"
echo "  - ${SCRIPT_DIR}/deployment.env"
echo "  - ${SCRIPT_DIR}/stylus-contracts.json"
echo ""
echo "Test with soldb:"
echo "  soldb trace ${TX_HASH} \\"
echo "    --ethdebug-dir ${CALLER_ADDRESS}:StylusCounterCaller:${SCRIPT_DIR}/solidity-caller/out \\"
echo "    --cross-env-bridge http://127.0.0.1:8765 \\"
echo "    --stylus-contracts ${SCRIPT_DIR}/stylus-contracts.json \\"
echo "    --rpc ${RPC_URL}"
