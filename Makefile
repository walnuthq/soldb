.PHONY: help install dev test coverage rust-test lit-test wasm-check wasm wasm-test test-setup test-deploy clean

# Crates that must keep building for the WebAssembly target. The binaries, `soldb-compiler`
# (spawns `solc`), and `soldb-bridge` (a TCP server) are host-only by design. CI runs the
# same targets, so this list is the single place to extend. See docs/wasm.md.
WASM_TARGET = wasm32-unknown-unknown
WASM_CRATES = soldb-core soldb-ethdebug soldb-debugger soldb-profiler soldb-repl soldb-serializer soldb-rpc soldb-wasm

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
	@echo "  make wasm           Build the soldb-wasm package with wasm-pack"
	@echo "  make wasm-test      Run the soldb-wasm tests under Node.js"
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

wasm:
	wasm-pack build crates/soldb-wasm --target web

wasm-test:
	wasm-pack test --node crates/soldb-wasm

test-setup:
	./test/test-setup.sh

test-deploy:
	./test/test-setup.sh --deploy-test

clean:
	cargo clean
	rm -rf build dist out test/Output
	find . -name ".DS_Store" -delete
