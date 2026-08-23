# Policy presets

Ready-made scan policies for teams that don't want to tune every flag on day one.

## CLI init presets

```bash
bucket-scanner init --preset yc-prod      # Yandex production
bucket-scanner init --preset aws-prod     # AWS S3 production
bucket-scanner init --preset azure-prod   # Azure Blob production
bucket-scanner init --preset gcs-prod     # GCS production
bucket-scanner init --preset audit-only   # report all; fail on critical only
bucket-scanner init --preset ci-offline   # fixture profiles for CI demos
```

Presets ship inside the PyPI package (`bucket_scanner/presets/*.toml`). Edit `folder_ids` / placeholders before live scans.

## CI profiles (repo examples)

File: [examples/ci/.bucket-scanner.toml](../examples/ci/.bucket-scanner.toml)

| Profile | Mode | fail_on | Use case |
|---------|------|---------|----------|
| `yc-fixture` | offline fixture | high | PR checks without secrets |
| `aws-fixture` | offline + terraform | high | AWS IaC drift demo |
| `stack-fixture` | fixture + repo + tracefuse + tf | high | Full stack demo |
| `azure-fixture` / `gcs-fixture` | offline + terraform | high | Multi-cloud CI matrix |
| `strict-prod` | fixture + probe | critical | Strict gate demo |
| `audit-only` | fixture | critical | Report-only posture |
| `yc-prod-baseline` | fixture + baseline | new | Delta gate demo |
| `*-prod-baseline` | per-cloud baseline | new | Same for AWS/Azure/GCS |

## Recommended production mapping

| Team maturity | Profile | Gate |
|---------------|---------|------|
| First week | `yc-prod` / `aws-prod` | `--fail-on high` |
| Legacy prod with noise | `*-prod` + baseline file | `--fail-on new` |
| Audit / compliance export | any + `--compliance-report` | `--fail-on critical` or audit-only |
| CDN / known buckets | + `[scan.suppressions]` | see [examples/suppressions/](../examples/suppressions/) |

## Severity overrides

Lower noise without hiding critical issues:

```toml
[[scan.severity_overrides]]
rule = "versioning/disabled"
severity = "medium"
```

## Serve / Grafana

```toml
[serve]
addr = "127.0.0.1:9090"
interval_seconds = 300
profile = "yc-prod"
```

See [GRAFANA.md](GRAFANA.md) and [examples/docker-compose/](../examples/docker-compose/).
