.PHONY: help install dev test coverage rust-test lit-test test-setup test-deploy clean

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

test-setup:
	./test/test-setup.sh

test-deploy:
	./test/test-setup.sh --deploy-test

clean:
	cargo clean
	rm -rf build dist out test/Output
	find . -name ".DS_Store" -delete
