#!/bin/bash
# Deploy a Solidity contract with ETHDebug support
# This is an enhanced version that ensures proper ETHDebug compilation

set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOLDB_DIR="$(dirname "$SCRIPT_DIR")"

# Default configuration - uses environment variables or defaults
RPC_URL="${RPC_URL:-http://localhost:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
DEBUG_DIR="${DEBUG_DIR:-debug}"
SOLC_PATH="${SOLC_PATH:-solc}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Parse arguments
CONTRACT_NAME=""
CONTRACT_FILE=""
CONSTRUCTOR_ARGS=()
DUAL_COMPILE=false

usage() {
    echo "Usage: $0 [OPTIONS] <contract_name> <contract_file>"
    echo ""
    echo "Arguments:"
    echo "  contract_name     Name of the contract to deploy (e.g., 'Counter')"
    echo "  contract_file     Path to the Solidity file (e.g., 'src/Counter.sol')"
    echo ""
    echo "Options:"
    echo "  --solc=PATH       Path to solc binary (default: solc)"
    echo "  --rpc=URL         RPC URL (default: http://localhost:8545)"
    echo "  --private-key=KEY Private key for deployment"
    echo "  --debug-dir=DIR   ETHDebug output directory (default: debug)"
    echo "  --dual-compile    Create both optimized and unoptimized builds"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Basic usage with ETHDebug:"
    echo "  $0 Counter src/Counter.sol"
    echo ""
    echo "  # Dual compilation (optimized + debug):"
    echo "  $0 --dual-compile Counter src/Counter.sol"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --solc=*)
            SOLC_PATH="${1#*=}"
            shift
            ;;
        --rpc=*)
            RPC_URL="${1#*=}"
            shift
            ;;
        --private-key=*)
            PRIVATE_KEY="${1#*=}"
            shift
            ;;
        --debug-dir=*)
            DEBUG_DIR="${1#*=}"
            shift
            ;;
        --dual-compile)
            DUAL_COMPILE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        --*)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
        *)
            if [ -z "$CONTRACT_NAME" ]; then
                CONTRACT_NAME="$1"
            elif [ -z "$CONTRACT_FILE" ]; then
                CONTRACT_FILE="$1"
            else
                CONSTRUCTOR_ARGS+=("$1")
            fi
            shift
            ;;
    esac
done

# Validate arguments
if [ -z "$CONTRACT_NAME" ] || [ -z "$CONTRACT_FILE" ]; then
    echo -e "${RED}Error: Contract name and file are required${NC}"
    usage
fi

# Check if contract file exists
if [ ! -f "$CONTRACT_FILE" ]; then
    echo -e "${RED}Error: Contract file '$CONTRACT_FILE' does not exist${NC}"
    exit 1
fi

# Check solc version
echo -e "${BLUE}Checking Solidity compiler version...${NC}"
SOLC_VERSION=$("$SOLC_PATH" --version | grep -oE 'Version: [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)
echo -e "Found solc version: $SOLC_VERSION"

# Parse version
IFS='.' read -r MAJOR MINOR PATCH <<< "$SOLC_VERSION"

# Check if version supports ETHDebug (0.8.29+)
USE_ETHDEBUG=true
if [ "$MAJOR" -eq 0 ] && [ "$MINOR" -eq 8 ] && [ "$PATCH" -lt 29 ]; then
    USE_ETHDEBUG=false
    echo -e "${YELLOW}Solidity $SOLC_VERSION does not support ETHDebug format, using legacy srcmap format${NC}"
else
    echo -e "${GREEN}✓ Solidity $SOLC_VERSION supports ETHDebug${NC}"
fi

# Create output directories
mkdir -p "$DEBUG_DIR"
if [ "$DUAL_COMPILE" = true ]; then
    mkdir -p "build/contracts"
fi

# Compile with ETHDebug or legacy format
if [ "$USE_ETHDEBUG" = true ]; then
    echo -e "\n${BLUE}Compiling with ETHDebug format...${NC}"
    
    # ETHDebug compilation flags
    # Note: ETHDebug doesn't support optimization flags yet
    COMPILE_FLAGS=(
        --via-ir
        --debug-info ethdebug
        --ethdebug
        --ethdebug-runtime
        --bin
        --abi
        --overwrite
        -o "$DEBUG_DIR"
    )
else
    echo -e "\n${BLUE}Compiling with legacy srcmap format...${NC}"
    
    # Legacy compilation flags (srcmap format)
    # Use --combined-json to generate combined.json with srcmap-runtime
    COMPILE_FLAGS=(
        --combined-json
        bin,bin-runtime,abi,srcmap,srcmap-runtime,metadata
        --overwrite
        -o "$DEBUG_DIR"
    )
fi

echo -e "${BLUE}Running: $SOLC_PATH ${COMPILE_FLAGS[*]} $CONTRACT_FILE${NC}"

# Compile
"$SOLC_PATH" "${COMPILE_FLAGS[@]}" "$CONTRACT_FILE" 2>&1 | tee "$DEBUG_DIR/compile.log"

# Check for errors
COMPILE_EXIT_CODE=${PIPESTATUS[0]}
if [ $COMPILE_EXIT_CODE -ne 0 ]; then
    if [ "$USE_ETHDEBUG" = true ]; then
        echo -e "${RED}ETHDebug compilation failed with exit code $COMPILE_EXIT_CODE${NC}"
    else
        echo -e "${RED}Compilation failed with exit code $COMPILE_EXIT_CODE${NC}"
    fi
    cat "$DEBUG_DIR/compile.log"
    exit 1
fi

# Verify output files were created
if [ "$USE_ETHDEBUG" = true ]; then
    echo -e "\n${BLUE}Verifying ETHDebug output...${NC}"
    
    if [ ! -f "$DEBUG_DIR/ethdebug.json" ]; then
        echo -e "${YELLOW}Warning: Main ethdebug.json file not found${NC}"
    else
        echo -e "${GREEN}✓ Found ethdebug.json${NC}"
    fi
else
    echo -e "\n${BLUE}Verifying legacy output...${NC}"
    
    if [ ! -f "$DEBUG_DIR/combined.json" ]; then
        echo -e "${RED}Error: combined.json file not found${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ Found combined.json${NC}"
    fi
fi

# Find the contract files
BIN_FILE=""
FOUND_CONTRACTS=()

if [ "$USE_ETHDEBUG" = true ]; then
    # ETHDebug format: individual .bin and .abi files
    for file in "$DEBUG_DIR"/*.bin; do
        if [ -f "$file" ]; then
            contract_name=$(basename "$file" .bin)
            FOUND_CONTRACTS+=("$contract_name")
            
            if [[ "$contract_name" == "$CONTRACT_NAME" ]]; then
                BIN_FILE="$file"
                break
            fi
        fi
    done
    
    # If exact match not found, look for partial matches
    if [ -z "$BIN_FILE" ] && [ ${#FOUND_CONTRACTS[@]} -gt 0 ]; then
        for contract in "${FOUND_CONTRACTS[@]}"; do
            if [[ "$contract" == *"$CONTRACT_NAME"* ]] || [[ "$CONTRACT_NAME" == *"$contract"* ]]; then
                BIN_FILE="$DEBUG_DIR/${contract}.bin"
                CONTRACT_NAME="$contract"
                echo -e "${YELLOW}Using matching contract: ${CONTRACT_NAME}${NC}"
                break
            fi
        done
        
        # If still no match, use the first non-library contract
        if [ -z "$BIN_FILE" ]; then
            for contract in "${FOUND_CONTRACTS[@]}"; do
                if [[ "$contract" != *"Library"* ]] && [[ "$contract" != *"Interface"* ]]; then
                    BIN_FILE="$DEBUG_DIR/${contract}.bin"
                    CONTRACT_NAME="$contract"
                    echo -e "${YELLOW}Using contract: ${CONTRACT_NAME}${NC}"
                    break
                fi
            done
        fi
    fi
    
    if [ -z "$BIN_FILE" ] || [ ! -f "$BIN_FILE" ]; then
        echo -e "${RED}Error: No binary file found${NC}"
        exit 1
    fi
    
    # Load bytecode and ABI from individual files
    BYTECODE=$(cat "$BIN_FILE")
    ABI_FILE="$DEBUG_DIR/${CONTRACT_NAME}.abi"
    ABI=$(cat "$ABI_FILE" 2>/dev/null || echo "[]")
else
    # Legacy format: extract from combined.json
    COMBINED_JSON="$DEBUG_DIR/combined.json"
    
    # Find contract in combined.json
    CONTRACT_KEY=$(jq -r ".contracts | keys[] | select(test(\"${CONTRACT_NAME}\"))" "$COMBINED_JSON" | head -1)
    
    if [ -z "$CONTRACT_KEY" ]; then
        # Try to find any contract
        CONTRACT_KEY=$(jq -r ".contracts | keys[0]" "$COMBINED_JSON")
        if [ -z "$CONTRACT_KEY" ] || [ "$CONTRACT_KEY" = "null" ]; then
            echo -e "${RED}Error: No contracts found in combined.json${NC}"
            exit 1
        fi
        # Extract contract name from key (format: "path/to/file.sol:ContractName")
        CONTRACT_NAME=$(echo "$CONTRACT_KEY" | cut -d':' -f2)
        echo -e "${YELLOW}Using contract: ${CONTRACT_NAME}${NC}"
    fi
    
    # Extract bytecode and ABI from combined.json
    BYTECODE=$(jq -r ".contracts[\"$CONTRACT_KEY\"].bin" "$COMBINED_JSON")
    ABI=$(jq -r ".contracts[\"$CONTRACT_KEY\"].abi" "$COMBINED_JSON")
    
    if [ -z "$BYTECODE" ] || [ "$BYTECODE" = "null" ]; then
        echo -e "${RED}Error: No bytecode found for contract $CONTRACT_KEY in combined.json${NC}"
        exit 1
    fi
fi

# Check for ETHDebug files (only if using ETHDebug)
if [ "$USE_ETHDEBUG" = true ]; then
    ETHDEBUG_CONTRACT_FILE="$DEBUG_DIR/${CONTRACT_NAME}_ethdebug.json"
    ETHDEBUG_RUNTIME_FILE="$DEBUG_DIR/${CONTRACT_NAME}_ethdebug-runtime.json"
    
    if [ -f "$ETHDEBUG_CONTRACT_FILE" ]; then
        echo -e "${GREEN}✓ Found ${CONTRACT_NAME}_ethdebug.json${NC}"
    else
        echo -e "${YELLOW}Warning: ${CONTRACT_NAME}_ethdebug.json not found${NC}"
    fi
    
    if [ -f "$ETHDEBUG_RUNTIME_FILE" ]; then
        echo -e "${GREEN}✓ Found ${CONTRACT_NAME}_ethdebug-runtime.json${NC}"
    else
        echo -e "${YELLOW}Warning: ${CONTRACT_NAME}_ethdebug-runtime.json not found${NC}"
    fi
fi

# Validate bytecode
if [ -z "$BYTECODE" ] || [ "$BYTECODE" = "0x" ]; then
    echo -e "${RED}Error: Contract bytecode is empty${NC}"
    exit 1
fi

# Dual compilation if requested
if [ "$DUAL_COMPILE" = true ]; then
    echo -e "\n${BLUE}Creating optimized production build...${NC}"
    
    PROD_FLAGS=(
        --via-ir
        --optimize
        --optimize-runs 200
        --bin
        --abi
        -o "build/contracts"
    )
    
    "$SOLC_PATH" "${PROD_FLAGS[@]}" "$CONTRACT_FILE" 2>&1 | tee "build/contracts/compile-prod.log"
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo -e "${GREEN}✓ Production build created in build/contracts/${NC}"
    else
        echo -e "${YELLOW}Warning: Production build failed${NC}"
    fi
fi

# Ensure bytecode has 0x prefix for cast
if [[ "$BYTECODE" != 0x* ]]; then
    BYTECODE="0x$BYTECODE"
fi

DEPLOY_DATA="$BYTECODE"
    if [ ${#CONSTRUCTOR_ARGS[@]} -gt 0 ]; then
    # Load ABI
    if [ "$USE_ETHDEBUG" = true ]; then
        if [ ! -f "$ABI_FILE" ]; then
            echo -e "${RED}Error: ABI file not found ($ABI_FILE)${NC}"
            exit 1
        fi
        ABI_CONTENT=$(cat "$ABI_FILE")
    else
        # ABI is already loaded from combined.json
        ABI_CONTENT="$ABI"
    fi

    # Search for constructor signature in ABI
    CONSTRUCTOR_SIG=$(echo "$ABI_CONTENT" | jq -r '.[] | select(.type=="constructor") | .inputs | map("\(.type)") | join(",")')
    if [ -z "$CONSTRUCTOR_SIG" ]; then
        CONSTRUCTOR_SIG=""
    fi

    # Prepare cast abi-encode string
    if [ -n "$CONSTRUCTOR_SIG" ]; then
        ABI_ENCODE_STR="constructor($CONSTRUCTOR_SIG)"
    else
        ABI_ENCODE_STR="constructor()"
    fi

    # Encode arguments
    ENCODED_ARGS=$(cast abi-encode "$ABI_ENCODE_STR" "${CONSTRUCTOR_ARGS[@]}")
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to abi-encode constructor arguments${NC}"
        exit 1
    fi

    # Combine bytecode and arguments (remove 0x from ENCODED_ARGS)
    DEPLOY_DATA="${BYTECODE}${ENCODED_ARGS:2}"
fi

# Deploy with cast
echo -e "\n${BLUE}Deploying to chain...${NC}"
echo -e "${BLUE}Bytecode length: ${#BYTECODE} characters${NC}"

DEPLOY_OUTPUT=$(cast send \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --create "$DEPLOY_DATA" \
    --json)

# Extract transaction hash and contract address
TX_HASH=$(echo "$DEPLOY_OUTPUT" | jq -r '.transactionHash')
CONTRACT_ADDR=$(echo "$DEPLOY_OUTPUT" | jq -r '.contractAddress')

echo -e "${GREEN}Transaction: $TX_HASH${NC}"
echo -e "${GREEN}Contract deployed at: $CONTRACT_ADDR${NC}"

# Save deployment info
if [ "$USE_ETHDEBUG" = true ]; then
    cat > "$DEBUG_DIR/deployment.json" <<EOF
{
  "contract": "$CONTRACT_NAME",
  "address": "$CONTRACT_ADDR",
  "transaction": "$TX_HASH",
  "network": "$RPC_URL",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "ethdebug": {
    "enabled": true,
    "main_file": "ethdebug.json",
    "contract_file": "${CONTRACT_NAME}_ethdebug.json",
    "runtime_file": "${CONTRACT_NAME}_ethdebug-runtime.json"
  }
}
EOF
    echo -e "\n${GREEN}Deployment complete!${NC}"
    echo -e "\n${BLUE}ETHDebug files location:${NC} $DEBUG_DIR"
    echo -e "\n${BLUE}To trace with ETHDebug:${NC}"
    echo -e "  soldb trace $TX_HASH --ethdebug-dir $CONTRACT_ADDR:$CONTRACT_NAME:$DEBUG_DIR --rpc $RPC_URL"
else
    cat > "$DEBUG_DIR/deployment.json" <<EOF
{
  "contract": "$CONTRACT_NAME",
  "address": "$CONTRACT_ADDR",
  "transaction": "$TX_HASH",
  "network": "$RPC_URL",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "format": "legacy"
}
EOF
    echo -e "\n${GREEN}Deployment complete!${NC}"
    echo -e "\n${BLUE}Debug files location:${NC} $DEBUG_DIR"
    echo -e "\n${BLUE}To trace with legacy format:${NC}"
    echo -e "  soldb trace $TX_HASH --ethdebug-dir $CONTRACT_ADDR:$CONTRACT_NAME:$DEBUG_DIR --rpc $RPC_URL"
fi