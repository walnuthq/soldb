#!/bin/bash
# Deploy a small caller/callee fixture and submit a transaction with an external nested call.

set -euo pipefail

DEBUG_DIR="${1:?debug directory is required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
SOLC_PATH="${SOLC_PATH:-solc}"
SOURCE="${PROJECT_DIR}/test/fixtures/NestedCalls.sol"

extract_tx_hash() {
    grep -o '0x[a-fA-F0-9]\{64\}' | head -1
}

deploy_contract() {
    local contract_name="$1"
    shift
    local log_file="${DEBUG_DIR}/deploy-${contract_name}.log"

    if ! "${SCRIPT_DIR}/deploy-contract.sh" \
        --solc="${SOLC_PATH}" \
        --rpc="${RPC_URL}" \
        --private-key="${PRIVATE_KEY}" \
        --debug-dir="${DEBUG_DIR}" \
        "${contract_name}" \
        "${SOURCE}" \
        "$@" >"${log_file}" 2>&1; then
        cat "${log_file}" >&2
        exit 1
    fi

    jq -r '.address' "${DEBUG_DIR}/deployment.json"
}

rm -rf "${DEBUG_DIR}"
mkdir -p "${DEBUG_DIR}"

CALLEE_ADDRESS="$(deploy_contract Callee)"
CALLER_ADDRESS="$(deploy_contract Caller "${CALLEE_ADDRESS}")"

send_output="$(cast send \
    "${CALLER_ADDRESS}" \
    "callPing(uint256)" \
    7 \
    --rpc-url "${RPC_URL}" \
    --private-key "${PRIVATE_KEY}" \
    --gas-limit 1000000 \
    --async 2>&1 || true)"
TX_HASH="$(printf '%s\n' "${send_output}" | extract_tx_hash)"

if [ -z "${TX_HASH}" ]; then
    echo "Failed to submit nested-call transaction" >&2
    echo "${send_output}" >&2
    exit 1
fi

cast receipt --rpc-url "${RPC_URL}" "${TX_HASH}" >/dev/null 2>&1 || true

printf '%s %s %s %s\n' "${TX_HASH}" "${CALLER_ADDRESS}" "${CALLEE_ADDRESS}" "${DEBUG_DIR}"
