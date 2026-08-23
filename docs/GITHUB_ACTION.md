# GitHub Action

Composite action: `FounderB/BucketScanner/action@v1.0.0` (or `./action` from a checkout).

Install from **PyPI** by pinning `version`, or from the checked-out repo when `version` is omitted and `pyproject.toml` is present. See [PYPI.md](PYPI.md).

## Quick start — named profile (recommended)

Commit `.bucket-scanner.toml` with `[[profiles]]` and reference a profile from CI:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: FounderB/BucketScanner/action@v1.0.0
        with:
          profile: yc-prod
          config-path: .bucket-scanner.toml
          fail-on: high
          sarif-path: bucket-scanner.sarif
        env:
          YC_TOKEN: ${{ secrets.YC_TOKEN }}
```

Store **`YC_TOKEN`** (and optionally **`YC_FOLDER_ID`**) as repository secrets. Folder IDs can also live in the profile inside `.bucket-scanner.toml`.

## Offline profile demo (no secrets)

This repository ships fixture profiles under `examples/ci/`:

```yaml
- uses: FounderB/BucketScanner/action@v1.0.0
  with:
    profile: yc-fixture
    config-path: examples/ci/.bucket-scanner.toml
    fail-on: high
```

Profiles: `yc-fixture`, `aws-fixture`, `stack-fixture`.

Copy-ready templates:

| File | Purpose |
|------|---------|
| `examples/ci/workflow-scheduled.yml` | Weekly cron + `workflow_dispatch` |
| `examples/ci/workflow-live.yml` | PR + daily live scan with secrets |
| `examples/ci/.bucket-scanner.toml` | Fixture profiles for CI demos |

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `version` | — | Install `bucket-scanner==<version>` from PyPI (e.g. `1.0.0`) |
| `profile` | — | Named `[[profiles]]` entry from config |
| `config-path` | `.bucket-scanner.toml` | TOML path (skipped if missing) |
| `cloud` | `yandex` | Used when `profile` is empty |
| `folder-id` | — | Overrides profile / config folder |
| `aws-region` | `us-east-1` | When `cloud: aws` without profile |
| `terraform-path` | — | IaC drift directory |
| `probe` | `false` | Anonymous reachability checks |
| `fail-on` | `high` | Severity gate |
| `sarif-path` | `bucket-scanner.sarif` | SARIF for Code Scanning |
| `json-path` | — | Optional JSON artifact path |
| `prometheus-path` | — | Optional Prometheus textfile |

When **`profile`** is set, the action does **not** pass `--cloud` — the profile drives cloud, fixture, terraform, and folder scope. Explicit inputs (`folder-id`, `terraform-path`, `probe`) still override via CLI semantics.

## Scheduled drift detection

```yaml
on:
  schedule:
    - cron: "0 7 * * *"
  workflow_dispatch:
    inputs:
      profile:
        default: yc-prod
        type: string

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: FounderB/BucketScanner/action@v1.0.0
        with:
          profile: ${{ github.event.inputs.profile || 'yc-prod' }}
          fail-on: high
        env:
          YC_TOKEN: ${{ secrets.YC_TOKEN }}
```

See `.github/workflows/scheduled-scan.yml` in this repo for a fixture-based scheduled job (runs every Monday, uploads SARIF + JSON artifacts).

## Matrix over profiles

```yaml
strategy:
  matrix:
    profile: [yc-prod, aws-prod, yc-backup]
steps:
  - uses: FounderB/BucketScanner/action@v1.0.0
    with:
      profile: ${{ matrix.profile }}
      json-path: report-${{ matrix.profile }}.json
    env:
      YC_TOKEN: ${{ secrets.YC_TOKEN }}
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

## Example `.bucket-scanner.toml` for CI

```toml
[[profiles]]
name = "yc-prod"
folder_ids = ["b1gfolder-prod", "b1gfolder-backup"]
probe = true
fail_on = "high"

[[profiles]]
name = "aws-prod"
cloud = "aws"
aws_region = "eu-west-1"
probe = false

[serve]
interval_seconds = 300
profile = "yc-prod"
```

## AWS credentials

Set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (or use OIDC → keys in the runner). Profile `cloud = "aws"` selects the S3 backend; `aws_region` in TOML sets the API region.

## SARIF / Code Scanning

The action uploads SARIF via `github/codeql-action/upload-sarif`. Enable **GitHub Advanced Security** or Code Scanning on the repository to view findings in the Security tab.

Findings in demo fixtures exit `1` by design (`--fail-on high`) — treat as a successful gate in CI with `|| test $? -eq 1` when you only want to prove the pipeline, not pass a clean bill of health.
