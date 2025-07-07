#!/bin/bash
# Interact with deployed contract and debug transactions

set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOLDB_DIR="$(dirname "$SCRIPT_DIR")"

# Save environment variables before loading config
SAVED_DEBUG_DIR="${DEBUG_DIR}"
SAVED_RPC_URL="${RPC_URL}"
SAVED_PRIVATE_KEY="${PRIVATE_KEY}"

# Load configuration if exists
if [ -f "$SOLDB_DIR/soldb.config.local" ]; then
    source "$SOLDB_DIR/soldb.config.local"
elif [ -f "$SOLDB_DIR/soldb.config" ]; then
    source "$SOLDB_DIR/soldb.config"
fi

# Configuration (prefer environment variables over config file)
RPC_URL="${SAVED_RPC_URL:-${RPC_URL:-http://localhost:8545}}"
PRIVATE_KEY="${SAVED_PRIVATE_KEY:-${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}}"
DEBUG_DIR="${SAVED_DEBUG_DIR:-${DEBUG_DIR:-debug}}"

# Function to get the debug command for soldb
get_debug_command() {
    local tx_hash="$1"
    
    # Get absolute path to debug directory
    local abs_debug_dir
    if [[ "$DEBUG_DIR" = /* ]]; then
        abs_debug_dir="$DEBUG_DIR"
    else
        abs_debug_dir="$(pwd)/$DEBUG_DIR"
    fi
    
    # Check if ethdebug format is available
    if [ -f "$abs_debug_dir/ethdebug.json" ]; then
        echo "soldb trace $tx_hash --ethdebug-dir $abs_debug_dir --rpc $RPC_URL"
    else
        # Default to simple trace without debug info
        echo "soldb trace $tx_hash --rpc $RPC_URL"
    fi
}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Load deployment info
if [ -f "$DEBUG_DIR/deployment.json" ]; then
    DEPLOYMENT_JSON="$DEBUG_DIR/deployment.json"
elif [ -f "$DEBUG_DIR/deployment.json" ]; then
    DEPLOYMENT_JSON="$DEBUG_DIR/deployment.json"
else
    echo -e "${RED}No deployment found. Run deploy-contract.sh first.${NC}"
    exit 1
fi

CONTRACT_ADDR=$(jq -r '.address' "$DEPLOYMENT_JSON")
CONTRACT_NAME=$(jq -r '.contract' "$DEPLOYMENT_JSON")

echo -e "${BLUE}${CONTRACT_NAME} contract at: ${CONTRACT_ADDR}${NC}"

# Parse command
COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    help)
        echo "Usage: $0 <command> [args...]"
        echo "Commands:"
        echo "  get              - Get current value"
        echo "  set <value>      - Set value"
        echo "  inc <amount>     - Increment by amount"
        echo "  call <sig> [args] - Call arbitrary function (auto-detects view/pure)"
        echo "  send <sig> [args] - Force transaction for function (useful for debugging)"
        echo "  trace <tx>       - Debug a transaction"
        ;;
    
    get|number|counter)
        echo -e "\n${BLUE}Getting current value...${NC}"
        RESULT=$(cast call "$CONTRACT_ADDR" "counter()(uint256)" --rpc-url "$RPC_URL")
        echo -e "Current value: ${GREEN}$RESULT${NC}"
        ;;
    
    set|setNumber)
        VALUE="${1:-42}"
        echo -e "\n${BLUE}Setting value to $VALUE...${NC}"
        
        TX_OUTPUT=$(cast send \
            "$CONTRACT_ADDR" \
            "setNumber(uint256)" "$VALUE" \
            --rpc-url "$RPC_URL" \
            --private-key "$PRIVATE_KEY" \
            --json)
        
        # Check if transaction succeeded
        if echo "$TX_OUTPUT" | jq -e '.transactionHash' > /dev/null 2>&1; then
            TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
            echo -e "${GREEN}Transaction: $TX_HASH${NC}"
            DEBUG_CMD=$(get_debug_command "$TX_HASH")
            echo -e "To debug: ${BLUE}$DEBUG_CMD${NC}"
        else
            echo -e "${RED}Transaction failed:${NC}"
            echo "$TX_OUTPUT"
            exit 1
        fi
        ;;
    
    inc|increment)
        AMOUNT="${1:-1}"
        echo -e "\n${BLUE}Incrementing by $AMOUNT...${NC}"
        
        TX_OUTPUT=$(cast send \
            "$CONTRACT_ADDR" \
            "increment(uint256)" "$AMOUNT" \
            --rpc-url "$RPC_URL" \
            --private-key "$PRIVATE_KEY" \
            --json)
        
        # Check if transaction succeeded
        if echo "$TX_OUTPUT" | jq -e '.transactionHash' > /dev/null 2>&1; then
            TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
            echo -e "${GREEN}Transaction: $TX_HASH${NC}"
            DEBUG_CMD=$(get_debug_command "$TX_HASH")
            echo -e "To debug: ${BLUE}$DEBUG_CMD${NC}"
        else
            echo -e "${RED}Transaction failed:${NC}"
            echo "$TX_OUTPUT"
            exit 1
        fi
        ;;
    
    call)
        SIG="$1"
        shift || true
        echo -e "\n${BLUE}Calling $SIG with args: $@${NC}"
        
        # Check if this is a view/pure function by trying cast call first
        CALL_RESULT=$(cast call \
            "$CONTRACT_ADDR" \
            "$SIG" "$@" \
            --rpc-url "$RPC_URL")
        
        if [ $? -eq 0 ] && [ -n "$CALL_RESULT" ]; then
            # This is a view/pure function - show the result
            echo -e "${GREEN}Result: $CALL_RESULT${NC}"
            echo -e "${YELLOW}Note: This is a view/pure function - no transaction created${NC}"
            echo -e "${BLUE}To debug execution, use: $0 send $SIG $@${NC}"
        else
            # This is a state-changing function - send transaction
            TX_OUTPUT=$(cast send \
                "$CONTRACT_ADDR" \
                "$SIG" "$@" \
                --rpc-url "$RPC_URL" \
                --private-key "$PRIVATE_KEY" \
                --json)
            
            TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
            echo -e "${GREEN}Transaction: $TX_HASH${NC}"
            DEBUG_CMD=$(get_debug_command "$TX_HASH")
            echo -e "To debug: ${BLUE}$DEBUG_CMD${NC}"
        fi
        ;;
    
    send)
        SIG="$1"
        shift || true
        echo -e "\n${BLUE}Sending transaction for $SIG with args: $@${NC}"
        
        TX_OUTPUT=$(cast send \
            "$CONTRACT_ADDR" \
            "$SIG" "$@" \
            --rpc-url "$RPC_URL" \
            --private-key "$PRIVATE_KEY" \
            --gas-limit 1000000 \
            --json 2>&1)
        
        # Check if transaction succeeded
        if echo "$TX_OUTPUT" | jq -e '.transactionHash' > /dev/null 2>&1; then
            TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
            echo -e "${GREEN}Transaction: $TX_HASH${NC}"
            DEBUG_CMD=$(get_debug_command "$TX_HASH")
            echo -e "To debug: ${BLUE}$DEBUG_CMD${NC}"
        else
            echo -e "${RED}Transaction failed:${NC}"
            echo "$TX_OUTPUT"
            exit 1
        fi
        ;;
    
    trace|debug)
        TX_HASH="$1"
        if [ -z "$TX_HASH" ]; then
            echo -e "${RED}Usage: $0 trace <tx_hash>${NC}"
            exit 1
        fi
        
        echo -e "\n${BLUE}Debugging transaction $TX_HASH...${NC}"
        DEBUG_CMD=$(get_debug_command "$TX_HASH")
        echo -e "${BLUE}Running: $DEBUG_CMD${NC}"
        eval "$DEBUG_CMD"
        ;;
    
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        echo "Run '$0 help' for usage"
        exit 1
        ;;
esac