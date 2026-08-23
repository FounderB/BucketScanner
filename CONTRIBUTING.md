# Contributing

Thanks for helping improve Bucket Scanner.

## Development setup

```bash
git clone https://github.com/FounderB/BucketScanner.git
cd BucketScanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Pull requests

1. Fork and create a feature branch
2. Keep changes focused — one concern per PR
3. Add or update tests when behavior changes
4. Run `ruff check .` and `pytest` before opening
5. Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes

## Code style

- Python 3.11+
- `ruff` for lint/format
- Type hints on public APIs
- Match existing report / finding schema conventions

## Demo fixtures

Any credentials or bucket names in `examples/` must be labeled **FAKE / EXAMPLE** and must not work against real infrastructure.
