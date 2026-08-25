# Changelog

All notable changes to Bucket Scanner are documented here.

## [1.8.1] - 2026-08-25

### Fixed

- `scan_duration_ms` no longer truncates sub-millisecond fixture/live scans to `0` (floor at 1 ms)

## [1.8.0] - 2026-08-25

### Fixed (calibration)

- `PUBLIC_RULES` no longer treats missing/incomplete BPA or Azure account allow-public as "public exposure" (false `chain/silent-exfil`)
- AWS account BPA: AccessDenied → `aws/account-public-access-unknown` (not missing); emit once per account
- Bucket BPA `partial_metadata` no longer skips account BPA checks
- Azure/GCS: drop synthetic `acl/public-read` (native rules only); Azure logging unknown → partial, not "disabled"
- GCS: record `google-managed` / `CMEK` encryption algorithm
- `PROD_LIKE` no longer matches substrings like `product`
- Fixture loader: `encryption_algorithm`, `object_lock_enabled`, `encryption_kms_key_id`
- `scan_duration_ms` set on Azure/GCS/YC live paths; gate suppression expiry warnings on `report.warnings`

## [1.7.1] - 2026-08-25

### Fixed

- SARIF artifact URIs use repo-relative `buckets/<cloud>/<name>` paths so GitHub Code Scanning accepts Azure/GCS/YC uploads (no custom `azure://` schemes)

## [1.7.0] - 2026-08-25

### Added (ops product)

- `suppressed_findings` audit trail in JSON (reason, expires, matched bucket)
- Suppression `fnmatch` globs for bucket/rule; expiry warnings in human output
- Hard baseline gate workflow (fails on `summary.new`; no soft continue-on-error)
- Prometheus `bucket_scanner_findings_by_rule` + `bucket_scanner_scan_duration_ms`
- Notify `new_only` / `--notify-new-only` with Slack-compatible webhook `blocks`
- Grafana dashboard panels for per-rule findings and scan duration

## [1.6.0] - 2026-08-25

### Added (security depth)

- AWS **missing** Block Public Access (bucket + account) → HIGH
  (`aws/block-public-access-missing`, `aws/account-public-access-missing`)
- Cross-cloud `PUBLIC_RULES` (Azure/GCS/AWS missing BPA) for silent-exfil chains
- `chain/privileged-public-blast` — over-privileged SA + public exposure
- `encryption/sse-s3-only`, `object-lock/disabled` for prod-like buckets
- Probe evidence (HTTP status, cloud-aware list parsers, YC website endpoint)

## [1.5.0] - 2026-08-25

### Added

- **Bucket.Get enrichment** — ACL, policy, anonymous flags, website, CORS, lifecycle, tags via
  Storage `GET .../buckets/{name}?view=VIEW_FULL` when S3 keys are missing (or to supplement S3)
- **Ephemeral S3 credentials** — `CreateEphemeralAccessKey` from IAM token so CI needs only
  `YC_TOKEN` / `YC_FOLDER_ID` (no stored `YC_ACCESS_KEY_*`)
- Medium findings: `yc/website-enabled`, `yc/cors-enabled`; `yc/anonymous-config-read-enabled`
  severity lowered to **medium**
- VCR fixtures under `tests/fixtures/yc/` with realistic YC JSON + `tests/test_yc_fixtures.py`
- Snapshot `auth_mode`: `static-keys` | `ephemeral` | `management-only`

### Changed

- Doctor: IAM-token-only is OK (ephemeral / Bucket.Get path) instead of warning about missing static keys
- Docs: [OIDC.md](docs/OIDC.md), [ARCHITECTURE.md](docs/ARCHITECTURE.md), [CHECKS.md](docs/CHECKS.md)

## [1.4.0] - 2026-08-25

### Fixed (critical — live Yandex Cloud)

- **Folder access bindings** now call Resource Manager
  (`resource-manager/.../folders/{id}:listAccessBindings`) instead of the broken IAM path that aborted live scans
- **Static S3 access keys** listed via `/iam/aws-compatibility/v1/accessKeys` (`accessKeys`), not RSA `/iam/v1/keys`
- **IAM-token-only scans** consume Storage List `anonymousAccessFlags` → new rules
  `yc/anonymous-read-enabled`, `yc/anonymous-list-enabled`, `yc/anonymous-config-read-enabled`
- **`safe_s3_call`** distinguishes AccessDenied vs “not configured” — no more false `encryption/disabled`
- **Policy Principal** detects `{"AWS": ["*"]}` and nested wildcards
- **Probe** no longer crashes the scan on network errors; anonymous read works when ACL is unknown
- **Doctor IAM ping** passes `folderId` (List serviceAccounts requires it)
- **Terraform ACL drift** dead branch fixed; added `anonymous_access_flags` drift (`iac/yc-anonymous-drift`)
- Management API errors become `ScanError` instead of raw httpx tracebacks
- List APIs paginate with `nextPageToken`

### Added

- Contract tests for YC management URLs/response keys (`tests/test_yc_contracts.py`)
- `metadata/partial` findings when S3 APIs are denied
- Inventory enrichment of versioning from Storage List when present

## [1.2.0] - 2026-08-23

### Added

- **Tier 4 field deployment** — prod profiles (`yc-prod`, `aws-prod`, `azure-prod`, `gcs-prod`) + baseline variants
- **`baselines/`** sample JSON for `--fail-on new` gates
- **Multi-scope Azure/GCS** — `folder_ids` loops subscriptions/projects like Yandex folders
- **Profile `baseline_path`** — per-profile baseline in TOML
- CI templates: `workflow-azure-oidc.yml`, `workflow-gcs-oidc.yml`, `workflow-baseline-prod.yml`
- **`examples/ci/.bucket-scanner.prod.toml.example`** — copy-paste live prod config
- [GRAFANA.md](docs/GRAFANA.md) — VM/systemd/Prometheus deployment guide
- `examples/systemd/bucket-scanner-serve.service`, `examples/prometheus/scrape-bucket-scanner.yml`

### Changed

- AWS/Azure/GCS OIDC workflow templates pin `@v1.1.0`+; baseline gate in CI matrix
- README: fix stale Azure line

## [1.3.0] - 2026-08-23

### Added

- **Medium-audience onboarding** — [QUICKSTART.md](docs/QUICKSTART.md), [MIGRATION.md](docs/MIGRATION.md), [OIDC.md](docs/OIDC.md), [POLICY_PRESETS.md](docs/POLICY_PRESETS.md)
- **`bucket-scanner init --preset`** — shipped TOML presets in `bucket_scanner/presets/`
- **`doctor --profile`** for CI health checks
- **`.github/workflows/baseline-gate.yml`** and **`live-scan.yml`** (live proof templates)
- GitHub Action: `run-doctor`, `doctor-only`, scan summary annotations from JSON
- **Docker Compose** Prometheus/Grafana stack + alert rules
- **Suppressions example** — `examples/suppressions/common.toml.example`
- README comparison table and “who is this for” section

### Changed

- Action pins `@v1.3.0`; scheduled/baseline workflows upload compliance JSON

## [1.3.1] - 2026-08-23

### Fixed

- **`init --preset`** creates the target directory when missing (e.g. `init --preset yc-prod --force /tmp/project`)
- **CI race on release** — `pypi-smoke` retries PyPI install; repo workflows use `./action` from checkout instead of waiting for PyPI during tag push

## [1.2.1] - 2026-08-23

### Changed

- GitHub docs English-only: remove social/article drafts from the repo
- GitHub repository description set to English

### Removed

- `docs/HABR.md` (keep local drafts under `local/`, gitignored)

## [1.1.0] - 2026-08-23

### Added

- **Terraform drift for Azure + GCS** — `azurerm_storage_container`, `google_storage_bucket`, IAM members
- Example Terraform: `terraform-azure/`, `terraform-gcs/`; CI profiles wire `terraform_path`
- **`doctor --json`** and CLI **`--cloud`** override for all backends
- **`--compliance-report`** — JSON aggregation by CIS / NIST / SOC2 control tags
- Expanded compliance tags for `iac/*` and `tracefuse/*` rules
- **Tracefuse** Azure/GCS cloud markers; [docs/TRACEFUSE.md](docs/TRACEFUSE.md)
- Policy profiles: `strict-prod`, `audit-only` + example workflows
- GitHub Action: Azure/GCS env, `tracefuse-report`, `repo-path`, `compliance-report-path`

### Changed

- Action and docs pin `@v1.1.0` / `bucket-scanner==1.1.0`
- Grafana/Prometheus docs cover all four clouds

## [1.0.0] - 2026-08-23

### Added

- **v1.0 stable release** — four-cloud live scan (YC, AWS, Azure, GCS)
- SARIF **compliance tags** — CIS / NIST / SOC2 mappings in rule properties
- Docs: [COMPLIANCE.md](docs/COMPLIANCE.md), [GOLDEN_DEMO.md](docs/GOLDEN_DEMO.md)

### Changed

- All docs and examples pin `@v1.0.0` / `bucket-scanner==1.0.0`
- PyPI classifier: Production/Stable

## [0.15.0] - 2026-08-23

### Added

- **GCS live scan** — project bucket inventory via `google-cloud-storage` + ADC
- Optional extra: `pip install 'bucket-scanner[gcs]'`
- Golden demo: [GOLDEN_DEMO.md](docs/GOLDEN_DEMO.md), [examples/golden-demo/](examples/golden-demo/)

### Changed

- All four clouds support live scan (YC, AWS, Azure, GCS)
- `doctor --cloud gcs` validates SDK + project configuration

## [0.14.0] - 2026-08-23

### Added

- **GCS backend (fixture-first)** — `--cloud gcs`, offline `fixture-gcs.toml`
- GCS checks: `gcs/iam-public-principal`, `gcs/public-access-prevention-not-enforced`, `gcs/uniform-access-disabled`
- `gcs-fixture` CI profile, `docs/GCS.md`, `make gcs-demo`

### Fixed

- CLI scope guard: Azure live scans work with `--folder-id` / config subscription (was blocked)
- CI `pypi-smoke`: install `bucket-scanner>=0.13.0`

## [0.13.0] - 2026-08-23

### Added

- **Azure Blob live scan** — subscription inventory via `azure-identity` + `azure-mgmt-storage`
- Optional extra: `pip install 'bucket-scanner[azure]'`
- Container-level public access + storage account `allowBlobPublicAccess` checks from live API

### Changed

- PyPI badge in README; CI `pypi-smoke` job installs published wheel
- GitHub Action profile demo pins `version: "0.13.0"` from PyPI
- Publish workflow uses `twine upload --skip-existing`
- Fixture loader preserves Azure `tags.storage_account` for probes

## [0.12.0] - 2026-08-23

### Added

- **PyPI distribution** — `pip install bucket-scanner`
- GitHub Actions [publish.yml](.github/workflows/publish.yml) — upload on `v*.*.*` tags
- CI `package` job — build wheel, install, smoke scan
- GitHub Action `version` input — install pinned release from PyPI
- Docs: [PYPI.md](docs/PYPI.md), `make build` / `make check-package`

## [0.11.0] - 2026-08-23

### Added

- **AWS OIDC workflow template** — `examples/ci/workflow-aws-oidc.yml`
- **Azure repo secret patterns** — `secrets/azure-env-var`
- Docs: [ARCHITECTURE.md](docs/ARCHITECTURE.md), [AUDIT.md](docs/AUDIT.md) refresh

### Security

- YC credential resolver no longer falls back to `AWS_*` environment variables
- Webhook notifications reject non-HTTP(S) URLs
- Anonymous probe disables HTTP redirect following
- Baseline JSON limited to 10 MB on load
- IAM key listing catches `ClientError`/`BotoCoreError` instead of bare `Exception`

### Fixed

- Notify/report scope labels for Azure (`subscription`)
- SARIF artifact URI for Azure containers
- CLI `ClickException` display uses `str(exc)` (Click 8+ compatible)

## [0.10.0] - 2026-08-23

### Added

- **Baseline / delta** — `--baseline`, `--write-baseline`, `--fail-on new`
- **Suppressions** — `[[scan.suppressions]]` with optional `expires`
- JSON `report_schema = "1.0"`, `new_findings`, `new_chains`, `summary.suppressed/new`
- Prometheus: `bucket_scanner_suppressed_total`, `bucket_scanner_new_total`
- GitHub Action inputs: `baseline-path`, `write-baseline-path`
- Docs: [BASELINE.md](docs/BASELINE.md)

## [0.9.0] - 2026-08-23

### Added

- **Azure Blob backend (fixture-first)** — `--cloud azure`, offline `fixture-azure.toml`
- Azure checks: `azure/container-public-access`, `azure/account-public-access-enabled`
- Probe URL builder for Azure blob endpoints
- `docs/AZURE.md`, `azure-fixture` CI profile

## [0.8.0] - 2026-08-23

### Added

- **CI/CD profiles** — `profile` + `config-path` inputs on GitHub Action
- `examples/ci/.bucket-scanner.toml` with fixture profiles (`yc-fixture`, `aws-fixture`, `stack-fixture`)
- Copy-ready workflow templates: `examples/ci/workflow-scheduled.yml`, `workflow-live.yml`
- `.github/workflows/scheduled-scan.yml` — weekly fixture scan + artifact upload
- CI jobs: `profile-demo` matrix and `action-profile` composite action smoke test
- Expanded `docs/GITHUB_ACTION.md` (profiles, matrix, scheduled scans)

## [0.7.0] - 2026-08-23

### Added

- **Scan profiles** — `[[profiles]]` in `.bucket-scanner.toml`, `--profile`, `profiles list`
- **`[serve] profile`** — scheduled metrics server picks a named profile
- **YC multi-folder scan** — `folder_ids` in config or repeated `--folder-id`
- `scope_ids` in JSON report; human output shows multiple folders
- Grafana dashboard variables for `cloud` and `scope_id` labels

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
