.PHONY: help install dev test coverage test-setup test-deploy publish clean

help:
	@echo "SolDB - Build and Distribution"
	@echo ""
	@echo "Available commands:"
	@echo "  make install         Install package locally"
	@echo "  make dev            Install in development mode"
	@echo "  make test           Run tests"
	@echo "  make coverage       Run tests with Python coverage"
	@echo "  make test-setup     Setup and verify test environment"
	@echo "  make test-deploy    Deploy test contracts"
	@echo "  make publish        Publish to PyPI"
	@echo "  make clean          Clean build artifacts"

install:
	pip install .

dev:
	pip install -e .
	pip install -r requirements.txt

test:
	./test/run-tests.sh

coverage:
	coverage erase
	./test/run-tests.sh --coverage
	coverage combine
	coverage report
	coverage html
	coverage xml

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
