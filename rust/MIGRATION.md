# Python → Rust migration plan

## End state

A pure Rust repository. `src/soldb/`, `pyproject.toml`, `requirements.txt`,
and `MANIFEST.in` are deleted. `rust/` is renamed to the repo root.
`pip install soldb` ships a wheel that contains only the compiled Rust
binary, built with [maturin](https://www.maturin.rs/).

## Approach: subcommand-at-a-time (strangler fig)

We do **not** rewrite in parallel and swap at the end. Each PR ports one
CLI subcommand into `rust/`. The Python `soldb` entry-point dispatches
to the Rust binary when a subcommand has been ported, and otherwise
falls through to the existing Python implementation. Every PR is
shippable; users keep getting a working `soldb` throughout.

### Migration order

Simpler, read-only subcommands first; the interactive REPL last:

1. `soldb events` — read-only, decodes receipt logs.
2. `soldb contracts` — read-only, lists contracts touched by a tx.
3. `soldb simulate` — adds RPC `eth_call` + ABI encoding/decoding.
4. `soldb trace` — adds source-map / ETHDebug / DWARF parsing and the
   interactive REPL. The largest single port.
5. `soldb bridge` — cross-environment Stylus bridge, last because it
   has the smallest user base and depends on stable trace internals.

`soldb-dap-server` (the DAP entry-point) follows after `trace` lands,
since it reuses the same machinery.

### Dispatch during the transition

The Python `soldb.cli.main:main` wrapper checks whether the requested
subcommand is implemented in the Rust binary. If yes, it `execvp`s
`soldb-rs <subcommand> <args...>` and the Python process is replaced.
If no, it dispatches to the current Python handler. This keeps the
public CLI surface stable and lets us remove Python modules one at a
time as their Rust replacements ship.

### Shared concerns

Some plumbing — RPC client, ABI codec, hex utilities — gets a Rust
implementation in the first port that needs it (likely `events` for
ABI/RPC). Subsequent ports reuse those modules instead of duplicating.
We accept some duplication between the Python and Rust sides during
the migration; the alternative (FFI/PyO3 to share code) is more
plumbing than it's worth for a CLI.

### Per-PR rules

- A subcommand port PR must reach **behavioral parity** with the
  Python version on the existing lit tests under `test/`. The Python
  test suite is the migration's acceptance gate.
- A port PR may not break any non-ported subcommand.
- A port PR deletes the corresponding Python module(s) only when the
  Python entry-point no longer references them.

## Final swap

Once every subcommand and `soldb-dap-server` dispatch to Rust:

1. Replace the Python package build with a maturin-built wheel that
   ships only the Rust binary.
2. Delete `src/soldb/`, `src/tools/`, `pyproject.toml` (replaced by
   `rust/Cargo.toml` + maturin config), `requirements.txt`,
   `MANIFEST.in`.
3. Move `rust/`'s contents to the repo root and delete the `rust/`
   directory.
4. Merge `.github/workflows/rust.yml` into a single CI workflow and
   delete the Python `ci.yml`.
