# Bucket Scanner architecture

Bucket Scanner audits Yandex Cloud Object Storage using metadata APIs and optional anonymous probes.

## Pipeline

1. **CLI** parses flags and loads `.bucket-scanner.toml`
2. **YC client** lists buckets and fetches ACL, policy, encryption, logging, versioning, lifecycle
3. **Checks** emit normalized `Finding` records
4. **Chains** compose compound risks from individual findings
5. **Report** renders human (Rich), JSON, or SARIF 2.1.0

## Modules (planned)

| Module | Role |
|--------|------|
| `bucket_scanner.yc` | Yandex Cloud / S3-compatible API client |
| `bucket_scanner.checks` | Individual detectors |
| `bucket_scanner.chains` | Misconfig graph composer |
| `bucket_scanner.probe` | Anonymous HTTP reachability |
| `bucket_scanner.report` | Human / JSON / SARIF emitters |
| `bucket_scanner.config` | TOML loader and overrides |
