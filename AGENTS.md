# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

SolDB is an ETHDebug-first, LLDB-style debugger for Solidity and the EVM, written in
Rust. It maps EVM execution back to Solidity source using compiler-generated debug
information, and exposes that as a CLI (`trace`, `simulate`, `run`, `replay`,
`list-events`, `list-contracts`, `bridge`), an interactive REPL, a versioned JSON document for web
clients, a DAP server for editors, and a WebAssembly module for browser and Node.js
hosts.

Two premises drive most design decisions:

- **Debug info comes from the compiler, not from guessing.** We consume
  `solc --debug-info ethdebug` artifacts. When metadata is missing or incomplete, the
  right behavior is to degrade visibly (say what is unavailable), never to invent a
  source mapping from heuristics. Legacy `srcmap` support exists only as a fallback for
  pre-ETHDebug compilers.
- **The node is the execution oracle.** We do not maintain chain state. Either the node
  replays the transaction for us (`debug_traceTransaction`), or we pull the state a
  transaction touched over normal RPC and replay it in REVM. Both paths must produce the
  same `TransactionTrace` shape. The one exception is deliberate: `soldb run` executes
  bytecode on a `LocalChain` that exists only for that run, with every account the user
  described and nothing else, so what it shows is exactly as real as the state given.

Do not describe SolDB in the third person in code comments, docs, or commit messages.
This repository is the project: say "we", "this codebase", or "the debugger" instead of
"SolDB does" / "SolDB supports". User-facing docs (`README.md`, `docs/*.md`) are the
exception and may name the product.

## Commands

```bash
cargo build --workspace --all-targets                   # Build everything
cargo test --workspace --all-targets                    # Rust unit + integration tests
cargo fmt --all                                         # Format
cargo clippy --workspace --all-targets -- -D warnings   # Lint (CI gate)
cargo llvm-cov --workspace --all-targets --fail-under-lines 80   # Coverage gate
./test/run-tests.sh                                     # lit/FileCheck end-to-end suite
make test                                               # cargo test + lit
make wasm-check                                         # clippy on wasm32-unknown-unknown (CI gate)
make wasm && make wasm-test                             # both wasm-pack packages + Node.js tests (CI gate)
make wasm-live-test                                     # replay through the package against a live node (CI gate)
cargo run --bin soldb -- trace <tx> --rpc http://127.0.0.1:8545  # Run the CLI
```

`cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check`
are hard CI gates. Run both before proposing a change; neither needs a node.

The lit suite is **not hermetic**. It needs a live node, compiles contracts with `solc`,
deploys them, and sends transactions:

```bash
anvil --steps-tracing --host 127.0.0.1 --port 8545 &   # required
cargo build --bin soldb                                # run-tests.sh picks up target/debug/soldb
./test/run-tests.sh                                    # or SOLC_PATH=/path/to/solc ./test/run-tests.sh
```

`run-tests.sh` generates `test/lit.site.cfg.py` (gitignored) with the freshly deployed
contract address and transaction hashes. **Run it at least once before invoking `lit`
directly**, otherwise every substitution such as `%{test_tx}` is empty and tests fail for
the wrong reason. After that, iterate on a single test with:

```bash
lit test/trace/basic-trace.test -v
lit test/simulate/ -v
```

Scope a full run with `--trace-only`, `--simulate-only`, `--run-only`, `--events-only`, or
`--cli-only`.
Tests run with `-j1` on purpose: they share one node, one contract deployment, and the
`examples/out` artifact directory.

Some tests are opt-in and silently skip without their prerequisites, so a green run does
not mean full coverage:

- `test/events/sepolia-*.test`, `test/trace/multi-contract-*sepolia.test` need
  `--sepolia-key=KEY` or `SEPOLIA_KEY_ENV`; they gate on the `sepolia-rpc` lit feature.
- `test/trace/stylus-interop.test` needs a nitro testnode, `cargo-stylus-beta`, and the
  bridge on `127.0.0.1:8765`; it gates on the `stylus-bridge` feature. See
  `test/stylus/README.md`.
- `test/trace/increment-trace-legacy.test` pins `solc` 0.8.16 and is run separately by
  `run-tests.sh` before the ETHDebug tests, because it switches the active compiler.

Do not "fix" a skipped test by removing its `REQUIRES:` line.

## Architecture

Crate dependencies, as actually declared in `crates/*/Cargo.toml`:

| crate | depends on |
| --- | --- |
| `soldb-core` | *(nothing)* |
| `soldb-ethdebug` | core, `revm-bytecode` |
| `soldb-evm` | core, `ruint`, `revm` (behind the default-on `replay` feature) |
| `soldb-rpc` | core, evm |
| `soldb-repl` | core, debugger |
| `soldb-serializer` | core, ethdebug |
| `soldb-debugger` | core, ethdebug |
| `soldb-profiler` | core, ethdebug |
| `soldb-bridge` | core, rpc |
| `soldb-compiler` | core, ethdebug, rpc |
| `soldb-dap` | core, ethdebug, rpc, repl, debugger |
| `soldb-cli` | core, ethdebug, rpc, repl, debugger, profiler, serializer, compiler, bridge, `inferno` |
| `soldb-wasm` | core, ethdebug, evm (without `replay`), debugger, serializer, `wasm-bindgen` |

The crate in `crates/soldb-cli` is named `soldb` on crates.io, so the install is
`cargo install soldb`; the directory keeps the `soldb-cli` name to match its siblings.

`soldb-debugger` is the shared frontend model: both `soldb-cli` and `soldb-dap` go
through it for variable decoding, and both drive `soldb-repl`, whose stepping and
breakpoints rest on `soldb-debugger`'s `StepMap`, so the terminal and an editor stop at
the same steps and report the same values. Debug artifacts are found and read through
`soldb_ethdebug::load_debug_program` in both frontends. The CLI still builds the `trace`
command's call-frame summary itself in `main.rs`; new frontend logic that both would want
belongs in `soldb-debugger`, not in a second copy.

- **soldb-core**: the shared vocabulary — `TraceStep`, `StepSnapshot`,
  `TransactionTrace`, `TraceCapabilities`, `TraceArtifacts`, `SoldbError`. It has no
  soldb dependencies and must stay that way; it is the type boundary every other crate
  agrees on.
- **soldb-ethdebug**: ETHDebug artifact loading (`metadata.rs`), legacy `srcmap` parsing
  (`source_map.rs`), ABI encode/decode and signature parsing (`abi.rs`), event decoding
  (`events.rs`). Pure functions over files and bytes; no network.
- **soldb-evm**: the execution engine, with no I/O. The node data shapes
  (`RpcTransaction`, `RpcReceipt`, `DebugTraceResult`, the block types) are what JSON-RPC
  answers deserialize into, wherever they were fetched; `debug_rpc_transaction_trace` and
  `debug_rpc_simulation_trace` assemble a trace from them, and every backend ends in
  `build_transaction_trace`. The REVM engine lives in `replay.rs` behind the `replay`
  cargo feature (on by default) because it is the only code that links REVM; the crate
  must keep building and passing its tests with `--no-default-features`, and code that
  needs REVM goes in that module. `ReplayInputs` holds what the node says about the
  transaction and its block, `replay_prefix_with_state` and `replay_target_with_state`
  run REVM over any `ReplayStateProvider`, `PrefetchedReplayState` is the provider a host
  fills in rounds (it records every read so a completed run can export exactly the state
  it used), `LocalChain` is the synthetic chain `soldb run` executes on, and
  `ReplayBundle` is a completed replay's inputs and state as one serializable value, which
  `--save-replay` writes and `soldb replay` runs with no node. A `ReplayPrefix` is
  reusable only after a run that recorded nothing missing.
  `replay_chain_support` decides per chain id whether the engine models the chain,
  runs it under Ethereum rules with a capability note, or refuses it; extend the tables
  there rather than letting an unknown chain replay silently wrong. Nothing in this crate
  may open a socket, spawn a process, or read a file.
- **soldb-rpc**: the JSON-RPC transport and everything that needs a node: the `debug-rpc`
  backend, `debug_traceCall` simulation, log retrieval, and the node side of the `replay`
  backend in its own `replay.rs` (fetching a transaction's inputs, the lazy
  `RpcReplayStateProvider`, the archive preflight, batch requests), all behind the same
  `replay` feature, which also turns on the engine's. It re-exports `soldb-evm`'s public
  surface so frontends see one crate. This is the only crate that talks to a node.
- **soldb-debugger**: source-step, function, and variable decoding over a
  `TransactionTrace` plus `EthdebugInfo`. Frontend-agnostic; shared by CLI, REPL, and DAP.
  `ContractDebugInfo` is one contract's metadata prepared for stepping (line index, PC
  index, parsed functions), from ETHDebug or a legacy source map alike, and `StepMap`
  maps every step of a trace through the loaded
  contracts once: the line it belongs to, its frame depth (EVM depth plus internal
  Solidity functions, from the artifact's jump markers where it has them, from a jump
  onto a parsed function's entry point with the return address read off the stack at
  the call, and from the spans as a fallback), and the
  searches behind `next`, `step`, `finish`, their reverse forms,
  line and function breakpoints, and `backtrace`. Compiler-generated helpers carry the
  whole-contract span; the map attributes them to the executing statement and marks them
  `generated`. All of it is a search over the recording; nothing re-executes.
- **soldb-profiler**: gas attribution over borrowed trace steps and indexed ETHDebug
  programs. Frontend-agnostic; returns tables and folded stacks without printing or I/O.
- **soldb-repl**: the interactive debugger *state machine* — breakpoints, stepping,
  display mode, and the inspection queries (`frames`, `source_listing`, `calldata`). It
  owns no I/O; the CLI drives it and prints. Keep it that way, because it is what makes
  REPL behavior unit-testable without a terminal. Breakpoints are predicates on a step
  (`BreakpointKind`: PC, line entry, function entry, `SSTORE` to a slot, revert, call,
  opcode), checked on every step a movement passes through, forward or backward.
- **soldb-serializer**: the versioned web/JSON projection of traces and simulations,
  including the per-contract `contracts` entry built from `EthdebugInfo`.
- **soldb-compiler**: `solc` invocation, ETHDebug artifact discovery, deploy helpers.
- **soldb-bridge**: cross-VM bridge protocol and server (Stylus today).
- **soldb-dap**: Debug Adapter Protocol server for editors.
- **soldb-cli**: argument parsing, command dispatch, and *all* human-readable formatting.
- **soldb-wasm**: `wasm-bindgen` exports over the library crates for browser and Node.js
  hosts. One handle, `Trace`, holds the parsed trace in WebAssembly memory; inputs and
  outputs cross the boundary as JSON strings, but the trace is never re-parsed between
  calls. With its `replay` feature (on by default) it also exports `Replay`, a host-driven
  REVM replay that reports the state it needs, runs in rounds, keeps the block prefix
  once it ran clean, and exports the state it used. The behavior lives in
  its `pipeline` and `replay` modules and is tested natively. Two packages are built from
  it: lean (`--no-default-features`, no REVM) and replay-capable. `publish = false`: it
  ships through `wasm-pack`, not crates.io.

Pipeline: `tx hash -> backend (debug-rpc | replay) -> TransactionTrace -> ETHDebug
enrichment -> call frames + source steps + decoded values -> CLI text | JSON | REPL | DAP
| WASM`.

### Layering Rules

- Terminal formatting, ANSI color, and `println!` belong in `soldb-cli`. A library crate
  that prints is a library crate that cannot be reused by the DAP server or the JSON
  path. If a library needs to report something, return it.
- Backend-specific quirks stay inside `soldb-rpc` behind `TraceBackend`. Everything above
  it reads `TraceCapabilities` to decide what it can show — never `backend == "replay"`.
  Adding a backend must not require touching the CLI.
- Stepping is bidirectional. A trace is a complete recording, so `soldb-repl` moves
  backward (`reverse-*` commands, DAP `stepBack`/`reverseContinue`) by index, never by
  re-executing. Do not add reverse commands that replay the transaction.
- ETHDebug parsing stays in `soldb-ethdebug`. If the CLI is indexing into raw ETHDebug
  JSON, the accessor is missing from the metadata layer.
- `soldb-core` types are a serialization contract with on-disk artifacts and web clients.
  Adding a field is additive and needs `#[serde(default)]`; renaming or removing one is a
  breaking change (see JSON Output Contract).
- The crates listed in `WASM_CRATES` in the `Makefile` must keep building for
  `wasm32-unknown-unknown`; the `wasm` CI job lints them on that target, checks
  `soldb-evm` and `soldb-rpc` without their `replay` feature, and runs the `soldb-wasm`
  package build and
  tests. `std::net`, `std::process`, and `std::fs` compile there but fail at runtime, so
  a WebAssembly host does the I/O and hands results over as strings: nothing reachable
  from a `soldb-wasm` export may open a socket, spawn a process, or read a file. That is
  why the bindings depend on `soldb-evm` and not on `soldb-rpc`; do not add the transport
  back. Check a new dependency in one of those crates with `make wasm-check` before
  proposing it.
  `make wasm` builds both packages and fails when either exceeds its budget
  (`WASM_LEAN_SIZE_BUDGET_BYTES`, `WASM_REPLAY_SIZE_BUDGET_BYTES`); raise a budget
  deliberately, in the change that explains the growth, never to make CI pass.
  `soldb-evm` selects `getrandom`'s `js` backend for that target only because REVM's
  `k256` needs it to link. See `docs/wasm.md`.

### Big Files

`crates/soldb-cli/src/main.rs` (~4400 lines) and `crates/soldb-evm/src/replay.rs` (~2700
lines) are the two outliers. Prefer adding to a focused module over growing them further;
when you touch a coherent region of either, splitting that region into its own module is
a welcome change as long as it is a pure move with no behavior delta. The transport and
the engine were separated that way: `soldb-rpc` once held both, and the split into
`soldb-evm` moved code without changing it.

## ETHDebug Notes

### Instruction Shape

An ETHDebug runtime artifact is a list of instructions, each with its program counter
(`offset`) and a `context` describing where it came from:

```json
{
  "offset": 5,
  "operation": {"mnemonic": "PUSH1", "arguments": ["0x04"]},
  "context": {"code": {"source": {"id": 0}, "range": {"offset": 144, "length": 2771}}}
}
```

**Source spans nest, and a span that contains a line is not a span generated for it.**
The compiler attaches a whole-contract range to dispatcher and preamble instructions, so
that range intersects every line in the file. Any code that resolves a source line to a
program counter has to rank candidates — prefer spans that *begin* on the line, and fall
back to the narrowest intersecting span — or it will resolve every line to the first
instruction of the contract. `ContractDebugInfo::effective_line` in
`crates/soldb-debugger/src/stepping.rs` is the reference implementation, and the same
whole-contract span marks compiler-generated helper code mid-function, which `StepMap`
attributes to the executing statement rather than to the contract's first line.

### Variables

`EthdebugInfo::variables_at_pc` reads `context.variables` on each instruction (and the
artifact's top-level `variables` array). Not every compiler release emits either yet —
solc 0.8.36 does not — so variable inspection legitimately reports nothing in scope on
those compilers. That is a debug-info gap, and the correct behavior is to say so rather
than to guess values from the stack. Do not "fix" it by inferring locations.

### Artifacts

Artifacts produced per contract in the output directory:

- `<Contract>_ethdebug.json` — creation-code debug info.
- `<Contract>_ethdebug-runtime.json` — runtime debug info; this is what PC-to-source
  mapping uses for an ordinary call.
- `ethdebug.json` (legacy) / `ethdebug_resources.json` (modern) — the global resource
  file listing sources.
- `<Contract>.abi`, `<Contract>.bin` — ABI and bytecode.

### Compiler Channels

CI runs the lit suite against three compilers, for three different reasons:

| channel | why |
| --- | --- |
| solc 0.8.31 (pinned) | the legacy `--ethdebug`/`--ethdebug-runtime` flag generation |
| solc 0.8.36 (pinned) | the modern `--experimental --ethdebug-program …` generation |
| solc `develop`, built from source | where ETHDebug output changes first |

The `develop` job builds `argotorg/solidity@develop`, caches the binary by commit, and is
**non-blocking** (`continue-on-error: true`): that branch moves without us, so a break
there is an early warning, not a reason to hold up a pull request. It also runs on a daily
schedule so a change lands in front of us without needing a soldb pull request, and it
prints whether the build emits ETHDebug variable locations yet — the thing `vars` and
`print` read. As of `f985208` it does not; instruction `context` carries only `code`.

Development builds report a prerelease version such as `0.8.37-develop.2026.8.22`. The
version gate reads only the leading `major.minor.patch`; do not reintroduce a parser that
chokes on the suffix, or the one compiler that matters most for new ETHDebug output gets
rejected as unsupported.

**solc flag drift is a real, tested compatibility surface.** Older compilers accept
`--ethdebug --ethdebug-runtime`; solc dropped those around 0.8.32 in favor of
`--experimental --ethdebug-program --ethdebug-program-runtime --ethdebug-resources`.
`CompilerConfig::compile_with_ethdebug` tries the legacy flags and falls back on the
modern ones *only* when solc reports an unrecognised option, deliberately avoiding a
hardcoded version cutoff. CI runs the whole lit suite twice, once per flag generation
(solc 0.8.31 and 0.8.36 in `.github/workflows/ci.yml`).

When you change compiler invocation or artifact discovery, verify against both
generations. Do not add a version-number branch where a capability probe works.

A contract is addressed on the command line as `--ethdebug-dir <address>:<name>:<dir>`;
`--multi-contract` takes a JSON manifest. Address matching is case-insensitive and
checksum-agnostic — normalize before comparing.

## Testing

Two layers, with different jobs:

- **Rust tests** (`#[test]` in-crate, plus `crates/soldb-cli/tests/trace_cli.rs`) cover
  pure logic: ABI encoding, signature parsing, source-map math, REPL state transitions,
  trace construction from a canned `debug_traceTransaction` payload, backend selection.
  These must not need a node. If a new behavior can be tested here, test it here —
  it runs in every CI job and counts toward the 80% line-coverage gate.
- **lit + FileCheck tests** (`test/**/*.test`) cover end-to-end CLI behavior against a
  real node and real solc output: exact rendered output, exit codes, JSON documents,
  error messages. Prefer these for anything user-visible.
- **`test/wasm/replay-live.cjs`** replays a transaction through the replay-capable
  WebAssembly package against a live node and compares it with the node's
  `debug_traceTransaction`, then simulates a call on the fork and compares it with
  `debug_traceCall`. It needs only `anvil` and Node.js, and the `wasm` CI job runs it;
  `make wasm-live-test` runs it locally.

**Backend parity is itself a test target.** `test/trace/replay-*.test` run the same
transaction through `--backend debug-rpc` and `--backend replay` and diff the opcode
streams and the JSON step snapshots. Any change to how a `TraceStep` is built has to keep
the two backends producing identical output, including incidental formatting: memory is
normalized to one unprefixed hex string precisely because nodes disagree about whether
`structLogs` memory words carry a `0x` prefix.

Line coverage is enforced at 80% for the Rust workspace. Lit tests do not contribute to
it, so a feature implemented only behind a lit test can push coverage down — add unit
tests for the logic underneath.

### Writing lit Tests

```bash
# Short description of what this covers
# REQUIRES: soldb
# RUN: %soldb trace %{test_tx} --ethdebug-dir %{contract_address}:TestContract:%{ethdebug_dir} --rpc %{rpc_url} 2>&1 | FileCheck %s

# CHECK: Contract: TestContract
# CHECK: Call Stack:
# CHECK: #0 TestContract::runtime_dispatcher
```

Substitutions available (defined in `test/lit.cfg.py`, filled by `run-tests.sh`):
`%soldb`, `%{rpc_url}`, `%{sepolia_rpc_url}`, `%{contract_address}`, `%{test_tx}`,
`%{test_tx_no_events}`, `%{deploy_tx}`, `%{ethdebug_dir}`, `%{solc_path}`,
`%{private_key}`, `%{chain_id}`, `%{project_root}`, and the `%{stylus_*}` set.

Conventions:

- Every test starts with `# REQUIRES: soldb`. Add `# REQUIRES: sepolia-rpc` or
  `# REQUIRES: stylus-bridge` for tests that need those environments.
- Put the test in the directory that matches the command under test: `test/trace/`,
  `test/simulate/`, `test/run/`, `test/events/`, `test/cli/`, `test/stylus/`. Tests in
  `test/run/` need no node, only the compiled artifacts in `%{ethdebug_dir}`.
- Expect failures explicitly with `not %soldb ...` rather than letting a nonzero exit
  fail the RUN line.
- Pipe `2>&1` when the assertion covers diagnostics; SolDB writes progress and errors to
  stderr and results to stdout.
- For JSON output, pipe through `jq` before FileCheck when you care about one field, so
  the test does not break on unrelated additive schema changes.

### FileCheck Guidance

Follow the [FileCheck reference](https://llvm.org/docs/CommandGuide/FileCheck.html).

- Put checks immediately above or beside the behavior they cover, and keep patterns short
  — match the distinguishing part of a line, not the whole line.
- `CHECK` is ordered. Use `CHECK-DAG` for output whose order is not part of the contract
  (help text flags, event fields), `CHECK-NEXT` when adjacency *is* the contract (call
  stack nesting), and `CHECK-NOT` to pin an absence.
- Capture varying values with `[[NAME:regex]]` and reuse them as `[[NAME]]`. Gas numbers,
  addresses, and transaction hashes change between runs — never hardcode them.
- Use `--check-prefix` only when one file drives several distinct invocations (as
  `test/cli/help.test` does). With a single invocation, use the default `CHECK`.
- lit substitutions are regular expressions applied to the whole RUN line, and this suite
  substitutes the bare word `not` (to LLVM's `not` binary). It is anchored with `\bnot\b`,
  so identifiers like `cannot_find` are safe, but a `not` surrounded by non-word
  characters will still be rewritten. If a RUN line mangles itself, check the
  substitution list in `test/lit.cfg.py` before suspecting the code.
- Keep each check specific enough to fail for the bug it covers. `# CHECK: Gas used:` is
  a shape assertion; if the test exists to pin a value, capture and assert the value.

## CLI Output and Error Style

The CLI is a developer tool: output is read under time pressure, often after something
already went wrong.

- Errors do not end with a full stop, and start lowercase unless the first word is a
  proper noun or a literal.
- Refer to code, flags, files, and identifiers in backticks: `` `--ethdebug-dir` ``, not
  `"--ethdebug-dir"`.
- The main message is one line and says what failed. Detail goes on follow-up lines.
- Say what to do next when there is a next step. "no ETHDebug metadata for `0xabc…`; pass
  `--ethdebug-dir <address>:<contract>:<dir>`" beats "metadata not found".
- Never claim a capability that is not there. If the backend gave us no storage, the
  storage view says so; it does not render an empty map as if it were the truth.
- Respect `NO_COLOR`, `CLICOLOR_FORCE`, and non-TTY stdout — go through the existing
  `paint`/`bold`/`info` helpers in `crates/soldb-cli/src/main.rs` rather than emitting raw
  escapes, or lit tests will match against ANSI noise.
- Human-readable output goes to stdout (including progress lines such as
  `Loading transaction`); the final error message from `main` goes to stderr. `--json`
  and `--json-events` paths print *only* the JSON document, so `soldb trace … --json | jq`
  stays usable — keep it that way. Never add a progress `println!` that is not gated on
  the JSON flag.
- On failure the process exits with code `2`, not `1`. Lit tests that expect failure use
  `not %soldb …`.

Errors flow as `SoldbResult<T>` from `soldb-core`. When you add a failure path, produce a
message that would let a user fix it without reading our source. Do not branch on error
*text* — if a caller needs to distinguish a failure, give it a distinguishable error.
A command that has already rendered its failure (the `--json` paths print a JSON error
document) returns `SoldbError::AlreadyReported` so `main` exits non-zero without printing
a second time.

**A failed ETHDebug load is never silent.** The user asked for debug info by naming a
directory; degrading to a raw opcode view without saying why produces a symptom identical
to a contract compiled without debug info, which is the worst outcome for this tool.
Load metadata through `load_source_index` and resolve specs through
`resolve_contract_specs_reporting`: both report once to stderr via `report_once` and then
degrade. Resolving *zero* contracts from a spec the user typed is a failure too, not an
empty result. Never reintroduce a bare `TraceSourceIndex::load(spec).ok()` or
`resolve_contract_specs(..).unwrap_or_default()`.

## JSON Output Contract

`soldb trace --json` and `soldb simulate --json` are consumed by web clients and
explorers. `docs/json.md` is the specification; update it in the same change as the code.

- `schemaVersion` increments only on a breaking change. Adding a field is not breaking.
- New fields must round-trip through `serde` with `#[serde(default)]` so older artifacts
  still deserialize.
- Capability flags exist so clients can degrade gracefully. When a backend gains or loses
  data, update `TraceCapabilities` — do not let clients infer it from `backend`.
- Any change to the emitted document needs a lit test that pins it (see
  `test/trace/json-trace.test`, `test/simulate/json-simulate.test`).

## Commit Messages

Follow the GitHub **50/72 rule**:

- The subject line is at most **50 characters**, imperative, sentence-case, with no
  trailing period: `Support solc versions that dropped --ethdebug`.
- Separate the subject from the body with a blank line.
- Wrap every body line at **72 characters**.

Beyond the rule:

- An optional lowercase scope prefix is common and welcome for narrow changes:
  `cli: improve trace output`, `ci: fix clippy`, `soldb-repl: add resource info command`.
  The prefix counts toward the 50-character subject budget.
- Include a body for bug fixes, behavior changes, and anything non-obvious: what was
  wrong, why the fix is right. Skip it for mechanical changes.
- Check recent `git log` and match the surrounding style before committing.

## PR Titles and Descriptions

- Title follows the commit-subject rules above.
- Describe what changed and why in prose. Link the issue or PR it relates to.
- Include real measurements only; no invented numbers.
- No templates, no testing boilerplate ("Validated with…", command dumps) unless asked.
- Never pass escaped `\n` in a PR body — use a heredoc or a file so newlines are real.

## Code Style

- Comments are full sentences ending with a period (except URLs and code fragments).
- Files end with a trailing newline.
- Follow the patterns already in the file you are editing.
- Never commit secrets, private keys, or API keys. The Anvil dev key in `test/` is the
  well-known public one and is fine; nothing else is.

### Rust

- `unsafe_code = "forbid"` is set workspace-wide. Do not introduce `unsafe`, and do not
  add a crate-level override.
- Doc comments come before attributes: `/// ...` then `#[derive(...)]`.
- Module docs are inner comments (`//! ...`) at the top of the module file, not `///` on
  the `mod` item in the parent.
- All `use` statements go at the top of the file, grouped: `std`, then external crates,
  then `soldb_*`, then `crate`/`self`. Never import inside a function unless `#[cfg(...)]`
  gating requires it. Test-only imports go inside `#[cfg(test)] mod tests`.
- The workspace is **edition 2021**, so let-chains
  (`if let Some(a) = a && let Some(b) = b`) do not compile here — they are edition 2024
  only. Do not reach for them; the compiler error is `let chains are only allowed in Rust
  2024 or later`.
- Prefer `let Some(x) = x else { return ... };` over `match x { Some(x) => x, _ => ... }`,
  and use it as the default for gating on several optional values in sequence, since it
  keeps the happy path unindented and is the closest edition-2021 equivalent of a
  let-chain. Match on a tuple (`match (a, b) { (Some(a), Some(b)) => ..., _ => ... }`)
  when the values must be tested together.
- Never reach for `ref` / `ref mut` in patterns; borrow the scrutinee with `&` / `&mut`.
- Skip type annotations the compiler can infer. When a hint is genuinely needed, prefer
  turbofish (`Vec::<String>::new()`) over an annotated binding.
- Return `SoldbResult<T>`. In library crates, `unwrap`/`expect`/`panic!` are only
  acceptable on an invariant that cannot depend on input — and then say why in the
  message. Anything derived from RPC responses, ETHDebug JSON, ABI input, or user
  arguments is untrusted: propagate an error instead.
- Do not silently swallow failures. `let _ = ...`, `.ok()`, and `unwrap_or_default()` on
  a fallible call hide exactly the bugs this tool exists to find; if a failure is
  genuinely tolerable, leave a comment saying why.
- `#[must_use]` on constructors and pure accessors that return data.

## Notes

- **Trace steps are the hot loop.** A mainnet transaction is easily hundreds of thousands
  of `TraceStep`s, each carrying a stack `Vec<String>` and all of memory as a hex string.
  Avoid per-step `clone()`, `format!`, and `String`-keyed map lookups in anything that
  walks the full trace; borrow, and hoist allocation out of the loop.
- **Read a step's state with `TraceStep::snapshot_ref`, never `normalized_snapshot`.**
  The borrowed view costs nothing; the owned one copies the stack, all of memory, and the
  storage map. Reach for `normalized_snapshot` only where ownership is genuinely required.
  The same rule applies to the flat `step.stack`/`step.memory`/`step.storage` fields: go
  through `snapshot_ref`, which also reads correctly for a step that carries only a
  snapshot.
- **Do not materialize a trace to answer a question about it.** `DebugTraceResult::steps`
  builds every `TraceStep`; calling it to compute a flag or a count costs a full second
  copy of the trace. Read the raw `struct_logs` instead, and pin the result against the
  definition it replaces with a test. The same applies to writing one out: the web
  document's `steps` are streamed by `WebSteps` in `soldb-serializer`, one borrowed step
  at a time, with a test pinning the bytes against the former `json!` shape. Do not
  reintroduce a `Vec<serde_json::Value>` of steps.
- **A `TraceStep` stores its state once and serializes it twice.** The flat `stack`,
  `memory`, and `storage` fields are the wire format older files and clients read; every
  constructor leaves them empty, `Serialize` fills them from `snapshot`, and
  `Deserialize` moves whatever they held into `snapshot`. Build steps with
  `TraceStep::new` and `StepSnapshot::new`, never by filling the flat fields. Memory and
  storage in a snapshot are `Arc`s, and `DebugTraceResult::steps` hands the previous
  step's on when a log did not change them, so a trace holds one copy per change rather
  than one per step; keep that sharing when you touch step construction. The node's
  payload is held the same way: `StructLog` memory and storage are `Arc`s shared with the
  previous log as `structLogs` is parsed and as the replay inspector records, and
  `build_transaction_trace` takes the result by value so `into_steps` frees each log as
  its step is built. A trace read from a file shares as its steps are parsed. Loading a
  20,000-step, 89 MB file through the DAP server peaks at 114 MB; it peaked at 236 MB
  when every step held two copies.
- **PC-to-source lookups should be indexed, not scanned.** Build the PC map once per
  contract (`build_pc_to_instruction_map`) and reuse it; a linear scan per step turns a
  trace walk quadratic.
- **Addresses and hashes are user input.** Normalize case and `0x` prefixes at the edge,
  once, and keep one canonical form internally.
- **Hex from a node is not guaranteed to be ASCII.** Never slice a hex string by byte
  offset (`&value[2..6]`, `&hex[i..i + 2]`); a multi-byte character straddling the
  boundary panics. Decode over `as_bytes()` or take `chars()`.
- **ABI offsets and lengths are attacker-controlled.** Event data and calldata carry
  32-byte words that become `usize` offsets and lengths. Add them with `checked_add`,
  multiply with `checked_mul`, index with `get(..)`, and bound any `with_capacity` against
  the data actually present. Unchecked, they panic in debug and wrap in release into a
  reversed slice range or a multi-terabyte reservation.
- **Structures deserialized from JSON are not guaranteed acyclic.** Trace artifacts reach
  us from backends and from trace files; recursive walks over their parent links need a
  visited set, because a stack overflow aborts the process and no caller can catch it.
- **`examples/out*` and `test/Output` are generated.** They are gitignored build output
  from the test runner; never hand-edit them or commit them.
- **Stale Python leftovers.** `src/`, `test/unit/`, and `test/integration/` still contain
  `__pycache__`/egg-info from the pre-Rust implementation and are untracked. The runtime
  is Rust-only (`docs/port-to-rust.md`); do not add code there or resurrect the Python
  paths.
- **Keep the docs honest.** `docs/commands.md` documents every REPL command, what a stop
  shows, and how line breakpoints and internal frames are inferred. If you change that
  behavior, change the doc in the same commit; the interactive lit tests pin the
  wording.
