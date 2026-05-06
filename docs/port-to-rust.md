# Port To Rust Plan

This branch ports SolDB incrementally. Rust now owns the CLI, compiler,
auto-deploy, RPC transport, ABI/event decoding, DAP entrypoint, bridge protocol,
parser/serializer/debugger internals, and command execution. Python is no
longer part of the SolDB runtime or packaging; it remains only as lit test
runner infrastructure.

## Invariants

- Keep existing behavior covered by parity tests before removing Python modules.
- Keep Rust coverage above the configured gate; do not use Python test harness
  coverage as implementation coverage.
- Run lit tests through the Rust `soldb` binary by default; `SOLDB_BIN` remains
  configurable for local experiments.

## Target Workspace

- `soldb-cli`: command-line parsing and command dispatch.
- `soldb-core`: shared trace, function-call, and error model.
- `soldb-ethdebug`: ETHDebug and legacy source-map parsing.
- `soldb-rpc`: Ethereum JSON-RPC tracing and simulation.
- `soldb-serializer`: JSON/web trace serialization.
- `soldb-repl`: debugger state machine and interactive command loop.
- `soldb-bridge`: Stylus bridge protocol, client, and server.
- `soldb-dap`: Debug Adapter Protocol server.

## Migration Order

1. Add workspace, Rust CI, and `SOLDB_BIN` test selection.
2. Port deterministic helpers: ABI parsing, ETHDebug specs, source maps, errors,
   and serializers.
3. Port `trace` raw/debug output and `debug_traceTransaction` parsing.
4. Port `simulate`, ABI calldata encoding, `debug_traceCall`, and auto-deploy.
5. Port events and multi-contract listing.
6. Port the REPL as a state machine before polishing terminal behavior.
7. Port Stylus bridge and DAP after trace/simulate behavior is stable.
8. Switch lit defaults to Rust command by command, then remove Python modules only
   after parity and coverage are in place.
9. Remove Python packaging shims and make CI Rust-first.

## Removed Python Surfaces

- `src/soldb/cli/*`
- `src/soldb/compiler/*`
- `src/soldb/core/auto_deploy.py`
- `src/soldb/core/evm_repl.py`
- `src/soldb/core/serializer.py`
- `src/soldb/core/transaction_tracer.py`
- `src/soldb/cross_env/*`
- `src/soldb/parsers/*`
- `src/soldb/utils/*`
- `src/soldb/rust_cli.py`
- `src/tools/rust_dap_cli.py`
- `pyproject.toml` / pip packaging
- `src/tools/dap_server.py`
- `src/tools/dap_utils.py`
