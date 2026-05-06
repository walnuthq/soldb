.PHONY: help install dev test coverage rust-test test-setup test-deploy publish clean

help:
	@echo "SolDB - Build and Distribution"
	@echo ""
	@echo "Available commands:"
	@echo "  make install         Install package locally"
	@echo "  make dev            Install in development mode"
	@echo "  make test           Run tests"
	@echo "  make coverage       Run Python shim coverage, Rust coverage, and LIT tests"
	@echo "  make rust-test      Run Rust workspace tests"
	@echo "  make test-setup     Setup and verify test environment"
	@echo "  make test-deploy    Deploy test contracts"
	@echo "  make publish        Publish to PyPI"
	@echo "  make clean          Clean build artifacts"

install:
	pip install .

dev:
	pip install -e .

test:
	pytest test/unit
	./test/run-tests.sh

coverage:
	cargo llvm-cov --workspace --all-targets --fail-under-lines 80
	coverage erase
	coverage run --parallel-mode -m pytest test/unit
	./test/run-tests.sh --coverage
	coverage combine
	coverage report
	coverage html
	coverage xml

rust-test:
	cargo test --workspace --all-targets

test-setup:
	./test/test-setup.sh

test-deploy:
	./test/test-setup.sh --deploy-test

publish:
	./scripts/publish-pypi.sh

clean:
	rm -rf build dist *.egg-info
	rm -rf __pycache__ */__pycache__ */*/__pycache__
	find . -name "*.pyc" -delete
	find . -name ".DS_Store" -delete
