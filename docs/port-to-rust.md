# Port To Rust Plan

This branch ports SolDB incrementally. Rust now owns the CLI, compiler,
auto-deploy, RPC transport, ABI/event decoding, DAP entrypoint, bridge protocol,
parser/serializer/debugger internals, and lit command execution. Python remains
only as a thin packaging shim for console-script entrypoints.

## Invariants

- Keep existing behavior covered by parity tests before removing Python modules.
- Keep Python coverage at the configured gate while Python shims remain in use.
- Add Rust coverage as soon as Rust behavior exists; do not use Python coverage to
  hide untested Rust code.
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
- `src/tools/dap_server.py`
- `src/tools/dap_utils.py`
