#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
task_dir=$(mktemp -d)
"${SOLC_PATH:?Set SOLC_PATH to the solc build with layout templates}" Layouts.sol \
    --via-ir --debug-info ethdebug,ast-id --experimental --ethdebug-program-runtime \
    --ethdebug-resources --bin --abi --storage-layout --evm-version cancun -o "$task_dir"
cp "$task_dir/ethdebug_resources.json" ethdebug_resources.json

snapshot() {
    local name=$1 calldata=$2
    "${SOLDB_BIN:-../../../target/debug/soldb}" run "$task_dir/Layouts.bin" \
        --raw-data "$calldata" --save-trace "$task_dir/$name.json" --max-steps 0
    jq -e '.success' "$task_dir/$name.json" > /dev/null
    jq '{calldata:.input_data, output, memory:.steps[-1].memory,
        storage:(reduce .steps[].snapshot.storage_diff as $diff ({}; . + ($diff | map_values(.after)))),
        transient:(reduce (.steps[].snapshot.transient_storage // {}) as $words ({}; . + $words))}' \
        "$task_dir/$name.json" > "$name.json"
}

snapshot snapshot "$(cast calldata \
    'snapshot(((uint8,int16),uint16[],string,bytes4,uint64,uint8,function))' \
    '((7,-3),[11,513],hello,0x12345678,42,1,0x1111111111111111111111111111111111111111abcdef01)')"
snapshot arrays "$(cast calldata 'arrays(uint16[2][3],bytes[][2])' \
    '[[1,2],[3,4],[5,6]]' '[[0x1122,0x],[]]')"

printf 'Full traces retained in %s\n' "$task_dir"
