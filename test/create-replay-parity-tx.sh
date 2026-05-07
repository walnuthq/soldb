#!/bin/bash
# Create local Anvil transactions used by replay parity tests.

set -euo pipefail

CASE="${1:?transaction case is required}"
CONTRACT_ADDR="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
SOLC_PATH="${SOLC_PATH:-solc}"

extract_tx_hash() {
    grep -o '0x[a-fA-F0-9]\{64\}' | head -1
}

send_contract_tx() {
    local signature="$1"
    shift

    if [ -z "$CONTRACT_ADDR" ]; then
        echo "contract address is required for $CASE" >&2
        exit 1
    fi

    local output tx
    output=$(cast send \
        "$CONTRACT_ADDR" \
        "$signature" \
        "$@" \
        --rpc-url "$RPC_URL" \
        --private-key "$PRIVATE_KEY" \
        --gas-limit 1000000 \
        --async 2>&1 || true)
    tx=$(printf '%s\n' "$output" | extract_tx_hash)

    if [ -z "$tx" ]; then
        echo "Failed to submit $CASE transaction" >&2
        echo "$output" >&2
        exit 1
    fi

    cast receipt --rpc-url "$RPC_URL" "$tx" >/dev/null 2>&1 || true
    printf '%s\n' "$tx"
}

case "$CASE" in
    update-balance)
        sender=$(cast wallet address "$PRIVATE_KEY")
        send_contract_tx "updateBalance(address,uint256)" "$sender" 123
        ;;
    revert-increment)
        send_contract_tx "increment(uint256)" 0
        ;;
    create-contract)
        debug_rel="${DEBUG_DIR:-out_replay_create}"
        cd "${PROJECT_DIR}/examples"
        rm -rf "$debug_rel"

        if ! output=$(SOLC_PATH="$SOLC_PATH" \
            "${PROJECT_DIR}/test/deploy-contract.sh" \
            --solc="$SOLC_PATH" \
            --rpc="$RPC_URL" \
            --private-key="$PRIVATE_KEY" \
            TestContract \
            TestContract.sol \
            --debug-dir="$debug_rel" 2>&1); then
            echo "Failed to deploy create-contract fixture" >&2
            echo "$output" >&2
            exit 1
        fi

        deployment="${PROJECT_DIR}/examples/${debug_rel}/deployment.json"
        if [ ! -f "$deployment" ]; then
            echo "Failed to deploy create-contract fixture" >&2
            echo "$output" >&2
            exit 1
        fi

        address=$(jq -r '.address' "$deployment")
        tx=$(jq -r '.transaction' "$deployment")
        if [ -z "$address" ] || [ -z "$tx" ] || [ "$address" = "null" ] || [ "$tx" = "null" ]; then
            echo "Deployment fixture did not produce address and transaction" >&2
            echo "$output" >&2
            exit 1
        fi

        printf '%s %s %s\n' "$tx" "$address" "${PROJECT_DIR}/examples/${debug_rel}"
        ;;
    *)
        echo "unknown replay parity transaction case: $CASE" >&2
        exit 1
        ;;
esac
