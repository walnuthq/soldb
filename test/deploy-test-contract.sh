#!/bin/bash
# Deploy TestContract.sol specifically for tests
# This script ensures we have the right contract deployed for our test suite

set -e

# Get script directories
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration from environment or defaults
RPC_URL="${RPC_URL:-http://localhost:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
SOLC_PATH="${SOLC_PATH:-solc}"
CONTRACT_NAME="${CONTRACT_NAME:-TestContract}"
CONTRACT_FILE="${CONTRACT_FILE:-TestContract.sol}"
DEBUG_DIR="${DEBUG_DIR:-out}"

echo -e "${BLUE}Deploying ${CONTRACT_NAME} for tests...${NC}"

# Change to examples directory
cd "${PROJECT_DIR}/examples"

# Clean up old test deployment if exists
rm -rf "${DEBUG_DIR}"

# Deploy the contract
echo -e "${YELLOW}Running deployment script...${NC}"
"${PROJECT_DIR}/test/deploy-contract.sh" \
    --solc="${SOLC_PATH}" \
    --rpc="${RPC_URL}" \
    --private-key="${PRIVATE_KEY}" \
    "${CONTRACT_NAME}" \
    "${CONTRACT_FILE}" \
    --debug-dir="${DEBUG_DIR}"

# Check if deployment was successful
if [ -f "${DEBUG_DIR}/deployment.json" ]; then
    echo -e "${GREEN}✓ Contract deployed successfully${NC}"
    
    # Extract deployment info
    CONTRACT_ADDRESS=$(jq -r '.address' "${DEBUG_DIR}/deployment.json")
    DEPLOY_TX=$(jq -r '.transaction' "${DEBUG_DIR}/deployment.json")
    
    echo -e "${BLUE}Contract Address: ${CONTRACT_ADDRESS}${NC}"
    echo -e "${BLUE}Deploy TX: ${DEPLOY_TX}${NC}"
    
    # Export for use by tests
    export TEST_CONTRACT_ADDRESS="${CONTRACT_ADDRESS}"
    export TEST_DEPLOY_TX="${DEPLOY_TX}"
    export TEST_DEBUG_DIR="${PROJECT_DIR}/examples/${DEBUG_DIR}"
    
    # Return success
    exit 0
else
    echo -e "${RED}✗ Deployment failed - no deployment.json found${NC}"
    exit 1
fi