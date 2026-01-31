#!/bin/bash
# Run soldb tests

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse command line arguments
RUN_TRACE_TESTS=true
RUN_SIMULATE_TESTS=true
RUN_EVENTS_TESTS=true
VERBOSE=false
SEPOLIA_KEY=""

for arg in "$@"; do
    case $arg in
        SOLC_PATH=*)
            SOLC_PATH="${arg#*=}"
            shift
            ;;
        --sepolia-key=*)
            SEPOLIA_KEY="${arg#*=}"
            shift
            ;;
        --trace-only)
            RUN_SIMULATE_TESTS=false
            RUN_EVENTS_TESTS=false
            shift
            ;;
        --simulate-only)
            RUN_TRACE_TESTS=false
            RUN_EVENTS_TESTS=false
            shift
            ;;
        --events-only)
            RUN_TRACE_TESTS=false
            RUN_SIMULATE_TESTS=false
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --trace-only       Run only trace tests (from test/trace/)"
            echo "  --simulate-only    Run only simulate tests (from test/simulate/)"
            echo "  --events-only      Run only events tests (from test/events/)"
            echo "  --sepolia-key=KEY  Set Optimism Sepolia API key for remote tests"
            echo "  -v, --verbose      Run tests with verbose output"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Test Structure:"
            echo "  test/trace/        Contains trace command tests"
            echo "  test/simulate/     Contains simulate command tests"
            echo "  test/events/       Contains list-events command tests"
            echo ""
            echo "Environment variables:"
            echo "  RPC_URL            RPC endpoint (default: http://localhost:8545)"
            echo "  SOLC_PATH          Path to solc binary (default: solc)"
            echo "  TEST_TX            Specific transaction hash to test"
            echo "  SEPOLIA_KEY        Optimism Sepolia API key (can also use --sepolia-key)"
            echo ""
            echo "Examples:"
            echo "  $0                           # Run all tests"
            echo "  $0 --trace-only              # Run only trace tests"
            echo "  $0 --simulate-only           # Run only simulate tests"
            echo "  $0 --events-only             # Run only events tests"
            echo "  $0 -v                        # Run all tests with verbose output"
            exit 0
            ;;
        *)
            # Unknown option
            ;;
    esac
done

# Configuration
# Set fixed RPC URL for tests
RPC_URL="http://localhost:8545"
echo -e "${BLUE}Using RPC: ${RPC_URL}${NC}"
CHAIN_ID="${CHAIN_ID:-1}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
SOLC_PATH="${SOLC_PATH:-solc}"

# Function to check and ensure solc version is 0.8.31+ for ETHDebug tests
ensure_ethdebug_solc() {
    local solc_bin="$1"
    
    # Check if solc-select is available
    if command -v solc-select &> /dev/null; then
        # Try to use solc 0.8.31 if available
        # Note: solc-select versions (not list) shows installed versions
        if solc-select versions 2>/dev/null | grep -q "0.8.31"; then
            # Try to switch to 0.8.31 (may fail due to permissions, but that's OK)
            solc-select use 0.8.31 >/dev/null 2>&1 || true
            # Verify the switch worked
            if command -v solc >/dev/null 2>&1; then
                local version=$(solc --version 2>/dev/null | grep -oE 'Version: [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2 || echo "")
                if [ "$version" = "0.8.31" ]; then
                    SOLC_PATH="solc"
                    echo -e "${GREEN}Using solc 0.8.31 (ETHDebug) via solc-select${NC}"
                    return 0
                fi
            fi
            # If switch failed due to permissions, try direct path
            local direct_solc="${HOME}/.solc-select/artifacts/solc-0.8.31"
            if [ -f "$direct_solc" ] && [ -x "$direct_solc" ]; then
                SOLC_PATH="$direct_solc"
                echo -e "${GREEN}Using solc 0.8.31 (ETHDebug) from direct path${NC}"
                return 0
            fi
        fi
    fi
    
    # Check current solc version
    if command -v "$solc_bin" &> /dev/null; then
        local version=$("$solc_bin" --version 2>/dev/null | grep -oE 'Version: [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2 || echo "")
        if [ -n "$version" ]; then
            IFS='.' read -r MAJOR MINOR PATCH <<< "$version"
            if [ "$MAJOR" -eq 0 ] && [ "$MINOR" -eq 8 ] && [ "$PATCH" -ge 29 ]; then
                echo -e "${GREEN}Using solc $version (ETHDebug compatible)${NC}"
                return 0
            elif [ "$MAJOR" -eq 0 ] && [ "$MINOR" -eq 8 ] && [ "$PATCH" -lt 29 ]; then
                echo -e "${YELLOW}Warning: solc $version does not support ETHDebug (needs 0.8.29+). Some tests may fail.${NC}"
                echo -e "${YELLOW}Consider installing solc 0.8.31: solc-select install 0.8.31 && solc-select use 0.8.31${NC}"
                return 1
            fi
        fi
    fi
    
    return 0
}

# Use environment variable if no command line option provided
SEPOLIA_KEY="${SEPOLIA_KEY:-${SEPOLIA_KEY_ENV:-}}"

# Construct Sepolia RPC URL if key is provided
if [ -n "$SEPOLIA_KEY" ]; then
    SEPOLIA_RPC_URL="https://opt-sepolia.g.alchemy.com/v2/${SEPOLIA_KEY}"
    echo -e "${GREEN}Sepolia RPC configured${NC}"
else
    SEPOLIA_RPC_URL=""
    echo -e "${YELLOW}No Sepolia API key provided (use --sepolia-key=KEY to enable remote tests)${NC}"
fi

# Export SOLC_PATH so it's available to the Python config
# Note: Individual tests will set their own solc version via solc-select
export SOLC_PATH

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== SolDB Test Suite ===${NC}"
echo -e "${GREEN}Organized test structure:${NC}"
echo -e "${GREEN}  - test/trace/     : Trace command tests${NC}"
echo -e "${GREEN}  - test/simulate/  : Simulate command tests${NC}"
echo -e "${GREEN}  - test/events/    : List-events command tests${NC}"

# Test-specific debug directory (relative to examples)
TEST_DEBUG_REL="out"
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
    
    # Default deployment uses solc 0.8.31 (ETHDebug) for simulate/trace tests
    # Legacy tests will override this with their own solc-select use 0.8.16
    ensure_ethdebug_solc "$SOLC_PATH"
    export SOLC_PATH
    
    # Use the dedicated test deployment script if it exists
    if [ -x "${SCRIPT_DIR}/deploy-test-contract.sh" ]; then
        # Use dedicated test deployment script
        SOLC_PATH="${SOLC_PATH}" RPC_URL="${RPC_URL}" PRIVATE_KEY="${PRIVATE_KEY}" \
            DEBUG_DIR="out" CONTRACT_NAME="TestContract" CONTRACT_FILE="TestContract.sol" \
            "${SCRIPT_DIR}/deploy-test-contract.sh"
    else
        # Fallback to direct deployment
        cd "${PROJECT_DIR}/examples"
        rm -rf out
        "${SCRIPT_DIR}/deploy-contract.sh" --solc="${SOLC_PATH}" --rpc="${RPC_URL}" --private-key="${PRIVATE_KEY}" TestContract TestContract.sol --debug-dir=out
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

# Create additional test transactions for events testing
if [ -n "$CONTRACT_ADDRESS" ]; then
    # Create a transaction that doesn't emit events (complexCalculation is pure function)
    if [ -z "$TEST_TX_NO_EVENTS" ]; then
        echo -e "${YELLOW}Creating no-events test transaction (complexCalculation)...${NC}"
        NO_EVENTS_TX_OUTPUT=$(cd "${PROJECT_DIR}/examples" && DEBUG_DIR="${TEST_DEBUG_REL}" RPC_URL="${RPC_URL}" PRIVATE_KEY="${PRIVATE_KEY}" "${SCRIPT_DIR}/interact-contract.sh" send "complexCalculation(uint256,uint256)" 10 20 2>&1)
        TEST_TX_NO_EVENTS=$(echo "$NO_EVENTS_TX_OUTPUT" | grep -o '0x[a-fA-F0-9]\{64\}' | head -1)
        if [ -n "$TEST_TX_NO_EVENTS" ]; then
            echo -e "${GREEN}Created no-events test transaction: ${TEST_TX_NO_EVENTS}${NC}"
        else
            echo -e "${YELLOW}Failed to create no-events test transaction, using fallback${NC}"
            TEST_TX_NO_EVENTS="${TEST_TX}"
        fi
    fi
fi

echo "Using contract: ${CONTRACT_ADDRESS}"
echo "Using transaction: ${TEST_TX}"
if [ -n "$TEST_TX_NO_EVENTS" ]; then
    echo "Using no-events transaction: ${TEST_TX_NO_EVENTS}"
fi
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
config.sepolia_rpc_url = "${SEPOLIA_RPC_URL}"
config.chain_id = "${CHAIN_ID}"
config.private_key = "${PRIVATE_KEY}"
config.test_contracts = {
    "contract_address": "${CONTRACT_ADDRESS}",
    "deploy_tx": "${DEPLOY_TX}",
    "test_tx": "${TEST_TX}",
    "test_tx_no_events": "${TEST_TX_NO_EVENTS}",
    "ethdebug_dir": os.path.join(project_dir, "examples", "${TEST_DEBUG_REL}")
}
# Determine solc path dynamically
# Note: Most tests expect ETHDebug format (solc 0.8.31+) which shows nested internal function calls
# Tests that explicitly use solc-select will override this (e.g., legacy tests use 0.8.16)
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

# Set up lit command options
# Use -j1 to run tests sequentially (avoids race conditions when tests share resources)
LIT_OPTS="-j1"
if [ "$VERBOSE" = true ]; then
    LIT_OPTS="$LIT_OPTS -v"
fi

# Run trace tests
if [ "$RUN_TRACE_TESTS" = true ]; then
    echo -e "${YELLOW}Running trace tests...${NC}"
    if [ -d "${SCRIPT_DIR}/trace" ]; then
        # First run legacy tests separately (they need solc 0.8.16)
        # This ensures they run before other tests that might change solc version
        echo -e "${BLUE}Running legacy tests first (solc 0.8.16)...${NC}"
        if [ -f "${SCRIPT_DIR}/trace/increment-trace-legacy.test" ]; then
            "$LIT_CMD" $LIT_OPTS "${SCRIPT_DIR}/trace/increment-trace-legacy.test"
        fi
        
        # Then run all other trace tests (they use solc 0.8.31)
        # Ensure solc is set to 0.8.31 after legacy test may have changed it
        echo -e "${BLUE}Running ETHDebug tests (solc 0.8.31)...${NC}"
        ensure_ethdebug_solc "$SOLC_PATH"
        export SOLC_PATH
        # Use lit's filter-out to exclude legacy test
        "$LIT_CMD" $LIT_OPTS "${SCRIPT_DIR}/trace" --filter-out="increment-trace-legacy"
    else
        echo -e "${YELLOW}Warning: trace directory not found${NC}"
    fi
fi

# Run simulate tests
if [ "$RUN_SIMULATE_TESTS" = true ]; then
    echo -e "${YELLOW}Running simulate tests...${NC}"
    if [ -d "${SCRIPT_DIR}/simulate" ]; then
        "$LIT_CMD" $LIT_OPTS "${SCRIPT_DIR}/simulate"
    else
        echo -e "${YELLOW}Warning: simulate directory not found${NC}"
    fi
fi

# Run events tests
if [ "$RUN_EVENTS_TESTS" = true ]; then
    echo -e "${YELLOW}Running events tests...${NC}"
    if [ -d "${SCRIPT_DIR}/events" ]; then
        "$LIT_CMD" $LIT_OPTS "${SCRIPT_DIR}/events"
    else
        echo -e "${YELLOW}Warning: events directory not found${NC}"
    fi
fi

echo -e "${GREEN}Test suite completed!${NC}"
