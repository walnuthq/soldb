#!/bin/bash
# Test SolDB EVM Debugger setup

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${BLUE}Testing SolDB EVM Debugger Setup${NC}"
echo "=================================="
echo

# Configuration - uses environment variables or defaults
RPC_URL="${RPC_URL:-http://localhost:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
DEBUG_DIR="${DEBUG_DIR:-out}"
SOLC_PATH="${SOLC_PATH:-solc}"

echo -e "${BLUE}Configuration:${NC}"
echo "  RPC_URL: $RPC_URL"
echo "  DEBUG_DIR: $DEBUG_DIR"
echo "  SOLC_PATH: $SOLC_PATH"
echo

# Test Solidity compiler
echo -n "Testing solc... "
if command -v "$SOLC_PATH" &> /dev/null; then
    if "$SOLC_PATH" --version > /dev/null 2>&1; then
        VERSION=$("$SOLC_PATH" --version | grep -oE 'Version: [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)
        echo -e "${GREEN}✓ OK${NC} (version $VERSION)"
    else
        echo -e "${RED}✗ Failed to run${NC}"
    fi
elif command -v solc &> /dev/null; then
    VERSION=$(solc --version | grep -oE 'Version: [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)
    echo -e "${GREEN}✓ OK${NC} (version $VERSION from PATH)"
else
    echo -e "${YELLOW}⚠ Not configured${NC}"
    echo "  You can specify a custom solc with --solc flag when deploying"
fi

# Test RPC connection
echo -n "Testing RPC connection to $RPC_URL... "
if curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    "$RPC_URL" > /dev/null 2>&1; then
    BLOCK=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        "$RPC_URL" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    echo -e "${GREEN}✓ OK${NC} (block: $BLOCK)"
else
    echo -e "${YELLOW}⚠ Failed${NC}"
    echo "  Make sure Anvil is running: anvil --fork-url <RPC> --steps-tracing"
fi

# Test Python dependencies
echo -n "Testing Python dependencies... "
if python3 -c "import web3, eth_utils" 2>/dev/null; then
    echo -e "${GREEN}✓ OK${NC}"
else
    echo -e "${YELLOW}⚠ Missing${NC}"
    echo "  Install with: pip install -r requirements.txt"
fi

# Test cast (Foundry)
echo -n "Testing cast (Foundry)... "
if command -v cast &> /dev/null; then
    CAST_VERSION=$(cast --version 2>&1 | head -1)
    echo -e "${GREEN}✓ OK${NC} ($CAST_VERSION)"
else
    echo -e "${RED}✗ Not found${NC}"
    echo "  Install Foundry: https://getfoundry.sh"
fi

echo
echo -e "${BLUE}Configuration Summary:${NC}"
echo "  SOLC_PATH=${SOLC_PATH:-"(will use system solc)"}"
echo "  RPC_URL=$RPC_URL"
echo "  DEBUG_DIR=$DEBUG_DIR"

# Deploy test contract if requested
if [ "$1" = "--deploy-test" ] || [ "$1" = "-d" ]; then
    echo
    echo -e "${BLUE}Deploying TestContract for tests...${NC}"
    if [ -x "$SCRIPT_DIR/test/deploy-test-contract.sh" ]; then
        # Ensure SOLC_PATH is properly set
        if [ -z "$SOLC_PATH" ] && command -v solc &> /dev/null; then
            SOLC_PATH=$(which solc)
        fi
        SOLC_PATH="$SOLC_PATH" RPC_URL="$RPC_URL" PRIVATE_KEY="$PRIVATE_KEY" \
            "$SCRIPT_DIR/test/deploy-test-contract.sh"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Test contract deployed successfully${NC}"
        else
            echo -e "${RED}✗ Test contract deployment failed${NC}"
        fi
    else
        echo -e "${YELLOW}Test deployment script not found or not executable${NC}"
    fi
fi

echo
echo -e "${BLUE}Next steps:${NC}"
echo "1. Start Anvil with tracing:"
echo "   anvil --fork-url <YOUR_RPC> --steps-tracing"
echo
echo "2. Deploy test contract:"
echo "   ./test-setup.sh --deploy-test"
echo "   OR"
echo "   ./test/deploy-test-contract.sh"
echo
echo "3. Run tests:"
echo "   ./test/run-tests.sh"
echo
echo "4. Debug a transaction:"
echo "   soldb trace <tx_hash>"