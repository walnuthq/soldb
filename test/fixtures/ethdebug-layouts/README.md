# Layout templates

The resources are solc's output for `Layouts.sol`, with distinct pointer IDs for
storage, transient storage, memory and calldata. `snapshot.json` and `arrays.json`
are snapshots from executing that same bytecode locally. They retain the input,
return data, memory at `RETURN`, and the recorded storage and transient writes.
The functions return their memory addresses so the tests bind templates without
guessing where the compiler allocated their results.

The Rust integration tests decode the same record from storage, memory and calldata,
including packed signed values, left-aligned bytes, a UDVT, an enum and an external
function. They also cover nested static and dynamic arrays, empty arrays and empty
byte values. The older `ethdebug-resources` fixture stays pinned to its original
compiler output to test compatibility with pointer IDs that equal type IDs.

Regenerate with a compiler containing the layout-template changes:

```sh
SOLC_PATH=/absolute/path/to/solc bash test/fixtures/ethdebug-layouts/regenerate.sh
cargo test -p soldb-ethdebug --test layouts
```

The script also needs `cast`, `jq` and a built `target/debug/soldb`. It retains the
full traces in the temporary directory it prints. No node is needed.
