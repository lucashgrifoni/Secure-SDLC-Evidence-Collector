.PHONY: install install-dev lint format typecheck test test-cov run-example clean

PY ?= python

install:
	$(PY) -m pip install -e .

install-dev:
	$(PY) -m pip install -e ".[dev]"

lint:
	ruff check src tests

format:
	ruff format src tests
	ruff check --fix src tests

typecheck:
	mypy src tests

test:
	pytest

test-cov:
	pytest --cov=evidence_collector --cov-report=term-missing --cov-report=html

run-example:
	$(PY) -m evidence_collector.cli.main run \
		--application payments-api \
		--repository acme/payments-api \
		--release-id 2026.04.10 \
		--commit-sha abc123def456 \
		--branch main \
		--artifacts-dir examples/sample_release/artifacts \
		--attestations-dir examples/sample_release/attestations \
		--output-dir output/sample_release

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
