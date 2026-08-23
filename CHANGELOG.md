# Changelog

All notable changes to Bucket Scanner are documented here.

## [0.6.0] - 2026-08-23

### Added

- **Multi-region AWS scans** — resolve each bucket's region via `GetBucketLocation`
- **`iac/bpa-drift`** — Terraform `aws_s3_bucket_public_access_block` vs live BPA
- `aws_resolve_regions` config (default `true`; disable for single-region fast path)
- Region column in `bucket-scanner list` output
- Serve/metrics unit tests

### Fixed

- AWS bucket metadata fetched with regional S3 client (fixes wrong-region API errors)

## [0.5.0] - 2026-08-23

### Added

- **AWS Terraform diff** — `aws_s3_bucket` + `aws_s3_bucket_acl` ref resolution
- Demo: `examples/demo-vulnerable/terraform-aws/` + `fixture-aws.toml` stack
- **AWS secret chains** — `AKIA…` / `AWS_*` patterns in `chain/leaked-credentials-exposure`
- Tracefuse import recognizes AWS markers (`akia`, `aws_`, `amazon`)
- `--cloud` on `inspect`, `list`, `chain`, `diff`; `serve` accepts `--terraform`, `--repo`
- Cloud-aware human report, SARIF (`arn:aws:s3`), Prometheus (`cloud` label), notifications
- GitHub Action inputs: `cloud`, `aws-region`, `terraform-path`, `probe`
- AWS IAM over-privilege detection via attached policies (`AdministratorAccess`, `AmazonS3FullAccess`)
- Config: `scan.terraform_path` loaded from TOML

### Fixed

- `diff` command shows IaC findings only (no unrelated bucket noise)
- Repo secret scan respects active `--cloud` backend

## [0.4.0] - 2026-08-23

### Added

- **AWS S3 backend** — optional second cloud via `--cloud aws`
- Shared S3 snapshot logic (`s3_common`) for Yandex Cloud and AWS parity checks
- AWS-specific findings: `aws/block-public-access-incomplete`, `aws/account-public-access-incomplete`
- AWS credential patterns in `--repo` scan (`AKIA…`, `AWS_*` env vars)
- Offline AWS demo fixture: `examples/demo-vulnerable/fixture-aws.toml`
- Docs: `docs/AWS.md`

## [0.3.0] - 2026-08-23

### Added

- **Tracefuse hook** — `--repo` YC secret scan + `--tracefuse-report` JSON import
- **`chain/leaked-credentials-exposure`** when repo secrets meet public buckets
- **Prometheus exporter** — `--prometheus` file output and `serve` command (`/metrics`, `/health`)
- **Notifications** — webhook + Telegram via CLI flags or `[notify]` config
- Grafana dashboard JSON under `examples/grafana/`
- Docs: `PROMETHEUS.md`, `NOTIFY.md`

## [0.2.0] - 2026-08-23

### Added

- `bucket-scanner diff` and `scan --terraform` — Terraform intent vs live/fixture
- IaC findings: `iac/acl-drift`, `iac/shadow-bucket`, `iac/ghost-bucket`
- `tags/missing-env` check for production-like bucket names
- `metadata/limited` when scanning without S3 static keys
- Configurable `key_age_days` in `.bucket-scanner.toml`
- Makefile, expanded test suite, CI demo job with pip-audit and coverage gate

### Fixed

- IAM access bindings fetched once per scan (not per service account)
- Encryption/logging/versioning skipped when metadata unavailable (no false positives)

## [0.1.1] - 2026-08-23

### Added

- Real scan engine: ACL, policy, encryption, logging, versioning, lifecycle, IAM checks
- Misconfig **chains** (`chain/silent-exfil`, `chain/public-no-audit`)
- `--fixture` offline demo mode for CI and wow demos
- Human (Rich), JSON, and SARIF 2.1.0 reports
- `doctor`, `init`, `explain`, `inspect`, `list`, `chain` commands
- YC IAM token auth from `YC_TOKEN` or service account key file
- S3 metadata via static keys (`YC_ACCESS_KEY_ID` / `YC_SECRET_ACCESS_KEY`)
- Optional anonymous `--probe` reachability checks
- GitHub composite action under `action/`

## [0.1.0] - 2026-08-23

### Added

- Initial public release
- README, project scaffold, and FounderB security stack branding
- CLI surface: `scan`, `inspect`, `chain`, `doctor`, `explain`, `list`, `init`
- SARIF 2.1.0 and JSON report targets
- Anonymous `--probe` mode design (opt-in reachability checks)
- Misconfig **chains** model (public + no logging + no versioning)
- Demo fixtures under `examples/demo-vulnerable/` (FAKE / EXAMPLE values)
- GitHub Actions CI workflow
