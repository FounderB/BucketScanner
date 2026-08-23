# Bucket Scanner architecture

Multi-cloud Object Storage security scanner: metadata APIs, optional anonymous probe, Terraform drift, CI gates.

## Pipeline

1. **CLI / Action** loads flags, profiles, and `.bucket-scanner.toml`
2. **Cloud backend** collects bucket snapshots (YC, AWS, Azure, GCS)
3. **Checks** emit normalized `Finding` records
4. **Gate** applies suppressions and baseline delta
5. **Chains** compose compound risks
6. **Report** renders human (Rich), JSON (`report_schema: 1.0`), SARIF, Prometheus

## Modules

| Module | Role |
|--------|------|
| `bucket_scanner.yc` | Yandex Cloud management + S3 API |
| `bucket_scanner.aws` | AWS S3 + IAM helpers |
| `bucket_scanner.checks` | Detectors (ACL, policy, encryption, cloud-specific BPA) |
| `bucket_scanner.gate` | Suppressions, baseline fingerprints, delta |
| `bucket_scanner.chains` | Misconfig graph composer |
| `bucket_scanner.probe` | Anonymous HTTP reachability (no redirect follow) |
| `bucket_scanner.secrets` | Repo credential pattern scan |
| `bucket_scanner.terraform` | IaC intent parsing + drift |
| `bucket_scanner.report` | Human / JSON / SARIF / Prometheus |
| `bucket_scanner.serve` | `/metrics` + `/health` exporter |

## Cloud backends

| Cloud | Live scan | Fixture | Terraform drift |
|-------|-----------|---------|-----------------|
| Yandex Cloud | Yes | Yes | `yandex_storage_bucket` |
| AWS S3 | Yes | Yes | `aws_s3_*` + BPA |
| Azure Blob | Planned | Yes | Planned |
| GCS | Planned | Planned | Planned |

## Credential model

- **YC**: `YC_TOKEN` or SA key file; static keys via `YC_ACCESS_KEY_ID` only (not AWS env aliases)
- **AWS**: env keys, session token, or `AWS_PROFILE` / OIDC on GitHub Actions
- **Azure**: fixture-only until live backend ships
