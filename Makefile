.PHONY: help install dev test coverage rust-test lit-test wasm-check wasm wasm-lean wasm-replay wasm-test wasm-live-test test-setup test-deploy clean

# Crates that must keep building for the WebAssembly target. The binaries, `soldb-compiler`
# (spawns `solc`), and `soldb-bridge` (a TCP server) are host-only by design. CI runs the
# same targets, so this list is the single place to extend. See docs/wasm.md.
WASM_TARGET = wasm32-unknown-unknown
WASM_CRATES = soldb-core soldb-ethdebug soldb-debugger soldb-profiler soldb-repl soldb-serializer soldb-evm soldb-wasm

# Size-oriented cargo settings for the published module. They apply to this invocation
# only, so native release builds keep their profile. `panic = "abort"` is free on
# wasm32-unknown-unknown, which cannot unwind anyway; it just drops the landing pads.
WASM_PROFILE = CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=fat \
	CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=abort
# `make wasm` fails when an optimized module grows past its budget. The numbers are
# tripwires for a dependency creeping in, not targets: raise one deliberately, in the same
# change that explains the growth. The lean package carries no REVM; the replay-capable
# one does, and is several times larger for it. See docs/wasm.md.
WASM_LEAN_SIZE_BUDGET_BYTES = 400000
WASM_REPLAY_SIZE_BUDGET_BYTES = 1100000
WASM_LEAN_MODULE = crates/soldb-wasm/pkg/soldb_wasm_bg.wasm
WASM_REPLAY_MODULE = crates/soldb-wasm/pkg-replay/soldb_wasm_bg.wasm

# $(call check_wasm_size,<module>,<budget>)
define check_wasm_size
	@size=$$(wc -c < $(1) | tr -d ' '); \
	echo "$(1): $$size bytes (budget $(2))"; \
	if [ "$$size" -gt "$(2)" ]; then \
		echo "error: $(1) is over its size budget; see docs/wasm.md" >&2; \
		exit 1; \
	fi
endef

help:
	@echo "SolDB - Build and Distribution"
	@echo ""
	@echo "Available commands:"
	@echo "  make install         Install Rust binaries locally"
	@echo "  make dev            Build Rust workspace"
	@echo "  make test           Run Rust and LIT tests"
	@echo "  make coverage       Run Rust coverage and LIT tests"
	@echo "  make rust-test      Run Rust workspace tests"
	@echo "  make lit-test       Run LIT tests"
	@echo "  make wasm-check     Lint the WebAssembly-capable crates for wasm32-unknown-unknown"
	@echo "  make wasm           Build both soldb-wasm packages (lean and replay) and check their size budgets"
	@echo "  make wasm-lean      Build the lean soldb-wasm package (no REVM) into crates/soldb-wasm/pkg"
	@echo "  make wasm-replay    Build the replay-capable soldb-wasm package into crates/soldb-wasm/pkg-replay"
	@echo "  make wasm-test      Run the soldb-wasm tests under Node.js, with and without replay"
	@echo "  make wasm-live-test Replay a transaction through the package against a live node (RPC_URL)"
	@echo "  make test-setup     Setup and verify test environment"
	@echo "  make test-deploy    Deploy test contracts"
	@echo "  make clean          Clean build artifacts"

install:
	cargo install --path crates/soldb-cli
	cargo install --path crates/soldb-dap

dev:
	cargo build --workspace --all-targets

test:
	cargo test --workspace --all-targets
	./test/run-tests.sh

coverage:
	cargo llvm-cov --workspace --all-targets --fail-under-lines 80
	./test/run-tests.sh

rust-test:
	cargo test --workspace --all-targets

lit-test:
	./test/run-tests.sh

wasm-check:
	cargo clippy --target $(WASM_TARGET) $(addprefix -p ,$(WASM_CRATES)) -- -D warnings
	cargo clippy --target $(WASM_TARGET) -p soldb-evm -p soldb-wasm --no-default-features -- -D warnings
	cargo clippy -p soldb-evm -p soldb-rpc -p soldb-wasm --no-default-features --all-targets -- -D warnings
	cargo test -p soldb-evm -p soldb-rpc -p soldb-wasm --no-default-features

wasm: wasm-lean wasm-replay

wasm-lean:
	$(WASM_PROFILE) wasm-pack build crates/soldb-wasm --target web --no-default-features
	$(call check_wasm_size,$(WASM_LEAN_MODULE),$(WASM_LEAN_SIZE_BUDGET_BYTES))

wasm-replay:
	$(WASM_PROFILE) wasm-pack build crates/soldb-wasm --target web --out-dir pkg-replay
	$(call check_wasm_size,$(WASM_REPLAY_MODULE),$(WASM_REPLAY_SIZE_BUDGET_BYTES))

wasm-test:
	wasm-pack test --node crates/soldb-wasm --no-default-features
	wasm-pack test --node crates/soldb-wasm

# Needs a node at RPC_URL (default http://127.0.0.1:8545) with an unlocked first account,
# such as `anvil --steps-tracing`. Builds the replay-capable package for Node.js without
# the size profile: this checks behavior against a real chain, not bytes.
wasm-live-test:
	wasm-pack build crates/soldb-wasm --target nodejs --out-dir pkg-replay-node --dev
	node test/wasm/replay-live.cjs

test-setup:
	./test/test-setup.sh

test-deploy:
	./test/test-setup.sh --deploy-test

clean:
	cargo clean
	rm -rf build dist out test/Output
	find . -name ".DS_Store" -delete
