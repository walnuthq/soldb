#!/bin/bash
# Convenient test runner that ensures test infrastructure is ready
# This is a top-level script that users can run easily

set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== SolDB Test Runner ===${NC}"
echo

# Check if SOLC_PATH is provided
if [ -z "$SOLC_PATH" ]; then
    echo -e "${YELLOW}SOLC_PATH not set. Trying to find solc...${NC}"
    if command -v solc &> /dev/null; then
        SOLC_PATH=$(which solc)
        echo -e "${GREEN}Found solc at: $SOLC_PATH${NC}"
    else
        echo -e "${RED}Error: solc not found. Please set SOLC_PATH or install solc${NC}"
        echo "Example: SOLC_PATH=/path/to/solc $0"
        exit 1
    fi
fi

# Export for child scripts
export SOLC_PATH

# Activate virtual environment if it exists and soldb is not in PATH
if [ -f "${SCRIPT_DIR}/MyEnv/bin/activate" ] && ! command -v soldb &> /dev/null; then
    echo -e "${YELLOW}Activating virtual environment...${NC}"
    source "${SCRIPT_DIR}/MyEnv/bin/activate"
fi

# Check RPC connection
RPC_URL="${RPC_URL:-http://localhost:8545}"
echo -n "Checking RPC connection to $RPC_URL... "
if curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    "$RPC_URL" > /dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}Failed${NC}"
    echo -e "${YELLOW}Make sure Anvil is running with: anvil --steps-tracing${NC}"
    exit 1
fi

# Run the actual test suite
echo
echo -e "${BLUE}Running test suite...${NC}"
"${SCRIPT_DIR}/test/run-tests.sh" "$@"