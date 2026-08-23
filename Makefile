.PHONY: install hooks test lint audit scan-demo aws-demo diff-demo clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

hooks:
	chmod +x scripts/setup-git-hooks.sh .githooks/pre-commit
	./scripts/setup-git-hooks.sh

test:
	.venv/bin/pytest -q --cov=bucket_scanner --cov-report=term-missing

lint:
	.venv/bin/ruff check .

audit: lint
	.venv/bin/bandit -r src -q
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip-audit

aws-demo:
	.venv/bin/bucket-scanner scan --cloud aws --fixture examples/demo-vulnerable/fixture-aws.toml

azure-demo:
	.venv/bin/bucket-scanner scan --cloud azure --fixture examples/demo-vulnerable/fixture-azure.toml

scan-demo:
	.venv/bin/bucket-scanner scan --fixture examples/demo-vulnerable/fixture.toml

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
