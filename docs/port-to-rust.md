# Port To Rust Plan

This branch ports SolDB incrementally. Python remains the behavior reference until
the Rust binary passes the same lit and integration tests for a migrated surface.

## Invariants

- Keep the existing Python `soldb` CLI working until an equivalent Rust command is
  covered by parity tests.
- Keep Python coverage at the configured gate while Python code remains in use.
- Add Rust coverage as soon as Rust behavior exists; do not use Python coverage to
  hide untested Rust code.
- Run lit tests through a configurable `SOLDB_BIN` so the same tests can exercise
  Python or Rust.

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
