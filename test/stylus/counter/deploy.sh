#!/bin/bash
# Deploy Counter Stylus Contract

set -e
set -x

RPC_URL="${RPC_URL:-http://localhost:8547}"
PRIVATE_KEY="${PRIVATE_KEY:-0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659}"

echo "=== Deploying Counter Contract ==="
echo "RPC URL: ${RPC_URL}"
echo ""

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "${SCRIPT_DIR}"

# Step 2: Deploy Stylus Counter contract
echo ""
echo "Step 2: Deploying Stylus Counter contract..."

DEPLOY_OUTPUT=$(cargo stylus-beta deploy \
    --private-key="${PRIVATE_KEY}" \
    --endpoint="${RPC_URL}" \
    --no-verify 2>&1)

COUNTER_ADDRESS=$(echo "${DEPLOY_OUTPUT}" | grep "deployed code at address:" | sed 's/.*deployed code at address: //' | sed 's/\x1b\[[0-9;]*m//g')

if [ -z "$COUNTER_ADDRESS" ]; then
    echo "Failed to deploy Counter contract"
    echo "${DEPLOY_OUTPUT}"
    exit 1
fi

echo "✓ Counter deployed to: ${COUNTER_ADDRESS}"

# Step 1: Build debug dylib (aarch64-apple-darwin)
echo "Step 1: Building debug dylib"
cargo build --lib --target aarch64-apple-darwin --features debug

# Step 3: Send a test transaction
echo ""
echo "Step 3: Sending test transaction (increment)..."
TX_OUTPUT=$(cast send \
    --rpc-url="${RPC_URL}" \
    --private-key="${PRIVATE_KEY}" \
    "${COUNTER_ADDRESS}" \
    "increment()" 2>&1)

TX_HASH=$(echo "${TX_OUTPUT}" | grep -oE '(transactionHash|blockHash)[[:space:]]*:[[:space:]]*"0x[0-9a-fA-F]+"' | grep -oE '0x[0-9a-fA-F]+' | head -1)

if [ -z "$TX_HASH" ]; then
    TX_HASH=$(echo "${TX_OUTPUT}" | grep -oE '0x[0-9a-fA-F]{64}' | head -1)
fi

if [ -z "$TX_HASH" ]; then
    echo "Warning: Could not extract transaction hash"
    echo "${TX_OUTPUT}"
else
    echo "✓ Transaction hash: ${TX_HASH}"
fi

# Save deployment info
cat > deployment.env << EOF
RPC_URL=${RPC_URL}
PRIVATE_KEY=${PRIVATE_KEY}
COUNTER_ADDRESS=${COUNTER_ADDRESS}
COUNTER_TX=${TX_HASH}
EOF

echo ""
echo "=== Deployment Complete ==="
echo "Counter Address: ${COUNTER_ADDRESS}"
if [ ! -z "$TX_HASH" ]; then
    echo "Test Transaction: ${TX_HASH}"
fi
echo ""
echo "Test the contract:"
echo "  cast call ${COUNTER_ADDRESS} \"number()\" --rpc-url ${RPC_URL}"
echo "  cast send ${COUNTER_ADDRESS} \"increment()\" --rpc-url ${RPC_URL} --private-key ${PRIVATE_KEY}"
echo ""
echo "Usertrace:"
echo "  cargo stylus-beta usertrace --tx ${TX_HASH} --endpoint ${RPC_URL}"
