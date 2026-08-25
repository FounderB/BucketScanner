.PHONY: install hooks test lint audit build check-package scan-demo live-proof aws-demo diff-demo clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

build:
	.venv/bin/pip install -q build twine
	.venv/bin/python -m build
	.venv/bin/twine check dist/*

check-package: build
	.venv/bin/pip install --force-reinstall dist/bucket_scanner-*.whl
	.venv/bin/bucket-scanner --version

hooks:
	chmod +x scripts/setup-git-hooks.sh .githooks/pre-commit
	./scripts/setup-git-hooks.sh

test:
	.venv/bin/pytest -q --cov=bucket_scanner --cov-report=term-missing

lint:
	.venv/bin/ruff check .

audit: lint
	.venv/bin/bandit -r src -q
	.venv/bin/pip install --upgrade pip "setuptools>=83"
	.venv/bin/pip-audit

aws-demo:
	.venv/bin/bucket-scanner scan --cloud aws --fixture examples/demo-vulnerable/fixture-aws.toml

azure-demo:
	.venv/bin/bucket-scanner scan --cloud azure --fixture examples/demo-vulnerable/fixture-azure.toml

gcs-demo:
	.venv/bin/bucket-scanner scan --cloud gcs --fixture examples/demo-vulnerable/fixture-gcs.toml

scan-demo:
	.venv/bin/bucket-scanner scan --fixture examples/demo-vulnerable/fixture.toml

live-proof:
	chmod +x scripts/live_proof.sh
	./scripts/live_proof.sh

diff-demo:
	.venv/bin/bucket-scanner diff examples/demo-vulnerable/terraform \
		--fixture examples/demo-vulnerable/fixture.toml

stack-demo:
	.venv/bin/bucket-scanner scan --fixture examples/demo-vulnerable/fixture.toml \
		--repo examples/demo-vulnerable/repo \
		--tracefuse-report examples/demo-vulnerable/tracefuse-report.json \
		--terraform examples/demo-vulnerable/terraform

clean:
	rm -rf .venv .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
