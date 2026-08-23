# Quickstart (5 minutes)

Goal: **fixture scan → SARIF → CI baseline gate** with zero cloud secrets.

## 1. Install

```bash
pip install bucket-scanner==1.3.1
bucket-scanner --version
```

## 2. Offline scan (no credentials)

```bash
git clone https://github.com/FounderB/BucketScanner.git
cd BucketScanner

bucket-scanner scan \
  --fixture examples/demo-vulnerable/fixture.toml \
  --fail-on high -q || test $? -eq 1
```

Exit `1` means findings above threshold — expected on the demo fixture.

## 3. JSON + SARIF + compliance

```bash
bucket-scanner scan \
  --fixture examples/demo-vulnerable/fixture.toml \
  --json --sarif /tmp/report.sarif \
  --compliance-report /tmp/compliance.json \
  --fail-on high -q || test $? -eq 1
```

Upload `/tmp/report.sarif` to GitHub Code Scanning.

## 4. Production config in one command

```bash
bucket-scanner init --preset yc-prod
# edit folder_ids in .bucket-scanner.toml

export YC_TOKEN=$(yc iam create-token)
bucket-scanner doctor --json
bucket-scanner scan --profile yc-prod --fail-on high
```

Presets: `yc-prod`, `aws-prod`, `azure-prod`, `gcs-prod`, `audit-only`, `ci-offline`.  
See [POLICY_PRESETS.md](POLICY_PRESETS.md).

## 5. GitHub Action (fixture profile)

```yaml
  - uses: FounderB/BucketScanner/action@v1.3.1
    with:
      version: "1.3.1"
    profile: yc-fixture
    config-path: examples/ci/.bucket-scanner.toml
    fail-on: high
    json-path: bucket-scanner.json
    compliance-report-path: compliance.json
```

## 6. Baseline delta (fail only on NEW findings)

```bash
# First run — save baseline
bucket-scanner scan --profile yc-prod-baseline \
  --config examples/ci/.bucket-scanner.toml \
  --write-baseline baselines/yc-prod.json -q || test $? -eq 1

# Later — gate on delta
bucket-scanner scan --profile yc-prod-baseline \
  --config examples/ci/.bucket-scanner.toml \
  --fail-on new -q
```

This repo runs the same gate in [.github/workflows/baseline-gate.yml](../.github/workflows/baseline-gate.yml).

## 7. Live cloud credentials

| Cloud | Install extra | Env / flag |
|-------|---------------|------------|
| Yandex | (core) | `YC_TOKEN`, `--folder-id` or profile `folder_ids` |
| AWS | (core) | `AWS_*` or OIDC — [OIDC.md](OIDC.md) |
| Azure | `pip install 'bucket-scanner[azure]'` | `AZURE_*` or OIDC |
| GCS | `pip install 'bucket-scanner[gcs]'` | `GCP_PROJECT`, ADC or WIF |

Live workflow template: [examples/ci/workflow-live.yml](../examples/ci/workflow-live.yml)  
Copy [.github/workflows/live-scan.yml](../.github/workflows/live-scan.yml) and set repository secrets.

## Next steps

- [MIGRATION.md](MIGRATION.md) — from manual checklists  
- [GRAFANA.md](GRAFANA.md) — continuous metrics on a VM  
- [GOLDEN_DEMO.md](GOLDEN_DEMO.md) — full stack demo  
- [GITHUB_ACTION.md](GITHUB_ACTION.md) — all Action inputs
