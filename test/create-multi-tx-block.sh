#!/bin/bash
# Create a local Anvil block containing two TestContract transactions and print the second hash.

set -euo pipefail

CONTRACT_ADDR="${1:?contract address is required}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

extract_tx_hash() {
    grep -o '0x[a-fA-F0-9]\{64\}' | head -1
}

cast rpc --rpc-url "$RPC_URL" evm_setAutomine false >/dev/null
trap 'cast rpc --rpc-url "$RPC_URL" evm_setAutomine true >/dev/null 2>&1 || true' EXIT

SENDER=$(cast wallet address "$PRIVATE_KEY")
NONCE=$(cast nonce --rpc-url "$RPC_URL" --block pending "$SENDER")

TX1_OUTPUT=$(cast send \
    "$CONTRACT_ADDR" \
    "increment(uint256)" 2 \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --nonce "$NONCE" \
    --gas-limit 1000000 \
    --async 2>&1)
TX1=$(printf '%s\n' "$TX1_OUTPUT" | extract_tx_hash)

TX2_OUTPUT=$(cast send \
    "$CONTRACT_ADDR" \
    "increment(uint256)" 5 \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --nonce "$((NONCE + 1))" \
    --gas-limit 1000000 \
    --async 2>&1)
TX2=$(printf '%s\n' "$TX2_OUTPUT" | extract_tx_hash)

if [ -z "$TX1" ] || [ -z "$TX2" ]; then
    echo "Failed to submit multi-transaction block inputs" >&2
    echo "$TX1_OUTPUT" >&2
    echo "$TX2_OUTPUT" >&2
    exit 1
fi

cast rpc --rpc-url "$RPC_URL" evm_mine >/dev/null
cast receipt --rpc-url "$RPC_URL" "$TX1" >/dev/null
cast receipt --rpc-url "$RPC_URL" "$TX2" >/dev/null

printf '%s\n' "$TX2"
