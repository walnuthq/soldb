#!/bin/bash
# Run soldb tests

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse command line arguments
for arg in "$@"; do
    case $arg in
        SOLC_PATH=*)
            SOLC_PATH="${arg#*=}"
            shift
            ;;
        *)
            # Unknown option
            ;;
    esac
done

# Configuration
RPC_URL="${RPC_URL:-http://localhost:8545}"
CHAIN_ID="${CHAIN_ID:-1}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
SOLC_PATH="${SOLC_PATH:-solc}"

# Export SOLC_PATH so it's available to the Python config
export SOLC_PATH

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== SolDB Test Suite ===${NC}"

# Test-specific debug directory (relative to examples)
TEST_DEBUG_REL="test_debug"
TEST_DEBUG_DIR="${PROJECT_DIR}/examples/${TEST_DEBUG_REL}"

# Check if test deployment exists and is for TestContract
DEPLOYMENT_JSON="${TEST_DEBUG_DIR}/deployment.json"
NEED_DEPLOY=false

if [ -f "${DEPLOYMENT_JSON}" ]; then
    # Check if it's the right contract
    DEPLOYED_CONTRACT=$(jq -r '.contract // empty' "${DEPLOYMENT_JSON}")
    if [ "${DEPLOYED_CONTRACT}" != "TestContract" ]; then
        echo -e "${YELLOW}Found deployment for ${DEPLOYED_CONTRACT}, but need TestContract${NC}"
        NEED_DEPLOY=true
    else
        echo -e "${GREEN}Found existing TestContract deployment${NC}"
    fi
else
    echo -e "${YELLOW}No test deployment found${NC}"
    NEED_DEPLOY=true
fi

if [ "${NEED_DEPLOY}" = true ]; then
    echo -e "${YELLOW}Deploying TestContract for tests...${NC}"
    
    # Use the dedicated test deployment script if it exists
    if [ -x "${SCRIPT_DIR}/deploy-test-contract.sh" ]; then
        # Use dedicated test deployment script
        SOLC_PATH="${SOLC_PATH}" RPC_URL="${RPC_URL}" PRIVATE_KEY="${PRIVATE_KEY}" \
            DEBUG_DIR="test_debug" CONTRACT_NAME="TestContract" CONTRACT_FILE="TestContract.sol" \
            "${SCRIPT_DIR}/deploy-test-contract.sh"
    else
        # Fallback to direct deployment
        cd "${PROJECT_DIR}/examples"
        rm -rf test_debug
        "${SCRIPT_DIR}/deploy-contract.sh" --solc="${SOLC_PATH}" --rpc="${RPC_URL}" --private-key="${PRIVATE_KEY}" TestContract TestContract.sol --debug-dir=test_debug
    fi
    
    # Check deployment succeeded
    if [ ! -f "${DEPLOYMENT_JSON}" ]; then
        echo -e "${RED}Deployment failed!${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ TestContract deployed successfully${NC}"
fi

# Load deployment info
DEPLOYMENT_INFO=$(cat "$DEPLOYMENT_JSON")
# Try new format first (from ETHDebug deploy script)
CONTRACT_ADDRESS=$(echo "$DEPLOYMENT_INFO" | jq -r '.address // empty')
DEPLOY_TX=$(echo "$DEPLOYMENT_INFO" | jq -r '.transaction // empty')

# Fallback to old format if needed
if [ -z "$CONTRACT_ADDRESS" ]; then
    CONTRACT_ADDRESS=$(echo "$DEPLOYMENT_INFO" | grep -o '"contract_address": "[^"]*' | sed 's/"contract_address": "//')
fi
if [ -z "$DEPLOY_TX" ]; then
    DEPLOY_TX=$(echo "$DEPLOYMENT_INFO" | grep -o '"transaction_hash": "[^"]*' | sed 's/"transaction_hash": "//')
fi

# Use the test transaction provided by the user or create a new one
# If we have a deployment and no TEST_TX is provided, create a fresh increment transaction
if [ -z "$TEST_TX" ] && [ -n "$CONTRACT_ADDRESS" ]; then
    echo -e "${YELLOW}Creating fresh test transaction...${NC}"
    # Send an increment transaction and capture the TX hash
    TX_OUTPUT=$(cd "${PROJECT_DIR}/examples" && DEBUG_DIR="${TEST_DEBUG_REL}" RPC_URL="${RPC_URL}" PRIVATE_KEY="${PRIVATE_KEY}" "${SCRIPT_DIR}/interact-contract.sh" send "increment(uint256)" 4 2>&1)
    TEST_TX=$(echo "$TX_OUTPUT" | grep -o '0x[a-fA-F0-9]\{64\}' | head -1)
    if [ -z "$TEST_TX" ]; then
        echo -e "${RED}Failed to create test transaction${NC}"
        echo "$TX_OUTPUT"
        exit 1
    fi
    echo -e "${GREEN}Created test transaction: ${TEST_TX}${NC}"
else
    # Fallback to the old hardcoded transaction if nothing else works
    TEST_TX="${TEST_TX:-0x8a387193d19ae8ff6d15b32b7abec4144601d98da8c2af1eebd9cf4061c033a7}"
fi

echo "Using contract: ${CONTRACT_ADDRESS}"
echo "Using transaction: ${TEST_TX}"
echo ""

# Find soldb - prefer system-wide installation
SOLDB_CMD=""
SOLDB_TYPE=""
if command -v soldb &> /dev/null; then
    # Use system soldb if available
    SOLDB_CMD="soldb"
    SOLDB_TYPE="system"
    echo -e "${GREEN}Using system soldb${NC}"
elif [ -f "${PROJECT_DIR}/MyEnv/bin/soldb" ]; then
    # Fall back to virtual environment
    SOLDB_CMD="MyEnv/bin/soldb"
    SOLDB_TYPE="venv"
    echo -e "${GREEN}Using venv soldb${NC}"
else
    echo -e "${RED}Error: soldb not found${NC}"
    echo "Install with: pip install -e ${PROJECT_DIR}"
    exit 1
fi

# Create lit config with relative paths
cat > "${SCRIPT_DIR}/lit.site.cfg.py" << EOF
import sys
import os
import shutil

# Get the test directory and project directory dynamically
script_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(script_dir)

config.soldb_dir = project_dir

# Find soldb dynamically
if shutil.which('soldb'):
    config.soldb = shutil.which('soldb')
elif os.path.exists(os.path.join(project_dir, 'MyEnv', 'bin', 'soldb')):
    config.soldb = os.path.join(project_dir, 'MyEnv', 'bin', 'soldb')
else:
    config.soldb = "${SOLDB_CMD}"
config.rpc_url = "${RPC_URL}"
config.chain_id = "${CHAIN_ID}"
config.private_key = "${PRIVATE_KEY}"
config.test_contracts = {
    "contract_address": "${CONTRACT_ADDRESS}",
    "deploy_tx": "${DEPLOY_TX}",
    "test_tx": "${TEST_TX}",
    "ethdebug_dir": os.path.join(project_dir, "examples", "${TEST_DEBUG_REL}")
}
# Determine solc path dynamically
solc_path = os.environ.get('SOLC_PATH')
if not solc_path:
    # Try to find solc in PATH
    solc_path = shutil.which('solc')
if not solc_path:
    # Fallback to a default
    solc_path = 'solc'
config.solc_path = solc_path

# Load the main config
lit_config.load_config(config, os.path.join(script_dir, "lit.cfg.py"))
EOF

# Check for lit
if ! command -v lit &> /dev/null; then
    # Try llvm-lit
    LLVM_LIT=""
    for path in "/usr/local/opt/llvm/bin/llvm-lit" "/opt/homebrew/opt/llvm/bin/llvm-lit" "/usr/bin/llvm-lit"; do
        if [ -f "$path" ]; then
            LLVM_LIT="$path"
            break
        fi
    done
    
    if [ -z "$LLVM_LIT" ]; then
        echo -e "${RED}Error: Neither 'lit' nor 'llvm-lit' found${NC}"
        echo "Install with: pip install lit"
        echo "Or install LLVM: brew install llvm"
        exit 1
    fi
    
    LIT_CMD="$LLVM_LIT"
else
    LIT_CMD="lit"
fi

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
"$LIT_CMD" -v "${SCRIPT_DIR}"

echo -e "${GREEN}Test suite completed!${NC}"
