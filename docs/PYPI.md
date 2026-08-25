# PyPI publishing

Bucket Scanner is published as [`bucket-scanner`](https://pypi.org/project/bucket-scanner/) on PyPI.

## Install

```bash
pip install bucket-scanner
pip install "bucket-scanner[gcs]"
pip install "bucket-scanner==1.8.1"
```

## Maintainer release

1. Bump `version` in `pyproject.toml` and `src/bucket_scanner/__init__.py`
2. Update `CHANGELOG.md`
3. Commit via `git commit-tree` (FounderB author)
4. Tag and push:

```bash
git tag v1.5.0
git push origin main
git push origin v1.5.0
```

5. GitHub Actions workflow [`.github/workflows/publish.yml`](../.github/workflows/publish.yml) builds and uploads on tag push

### One-time setup

1. Create account on [pypi.org](https://pypi.org/account/register/)
2. Create API token (scope: entire account or project `bucket-scanner`)
3. Add repository secret **`PYPI_API_TOKEN`** in GitHub → Settings → Secrets
4. Optional: create GitHub Environment **`pypi`** with required reviewers

### Local dry run

```bash
pip install build twine
python -m build
twine check dist/*
# TestPyPI (optional):
# twine upload --repository testpypi dist/*
pip install dist/bucket_scanner-*.whl
bucket-scanner --help
```

## GitHub Action consumers

After publish, external workflows can use:

```yaml
- uses: FounderB/BucketScanner/action@v1.8.1
  with:
    version: "1.8.1"
    profile: yc-prod
```

The composite action installs from PyPI when `version` is set, or from the checked-out repo when run as `./action` in this repository.
