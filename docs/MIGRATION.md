# Migration from manual checks

Moving from spreadsheets, console spot-checks, or ad-hoc `aws s3api` scripts.

## Before (typical manual process)

1. Open cloud console per bucket  
2. Note ACL / public access / encryption / logging  
3. Compare with Terraform (if remembered)  
4. File ticket for gaps  
5. Re-check after fix — no delta tracking  

## After (Bucket Scanner)

| Manual step | Bucket Scanner |
|-------------|----------------|
| Inventory | `bucket-scanner list --folder-id ID` or scan report |
| ACL / public access | `acl/*`, `probe/*`, cloud BPA rules |
| Encryption / logging / versioning | `encryption/*`, `logging/*`, `versioning/*` |
| Terraform intent | `--terraform ./infra` or `bucket-scanner diff` |
| CI gate | GitHub Action + `--fail-on high` |
| Legacy noise in prod | `--baseline baselines/prod.json --fail-on new` |
| CDN / known exceptions | `[scan.suppressions]` — see [examples/suppressions/](../examples/suppressions/) |

## Week 1 rollout

**Day 1 — offline proof**

```bash
pip install bucket-scanner
bucket-scanner scan --fixture examples/demo-vulnerable/fixture.toml --fail-on high
```

**Day 2 — live read-only scan**

```bash
bucket-scanner init --preset yc-prod   # or aws-prod / azure-prod / gcs-prod
bucket-scanner doctor --json
bucket-scanner scan --profile yc-prod --sarif report.sarif
```

**Day 3 — baseline**

```bash
bucket-scanner scan --profile yc-prod \
  --write-baseline baselines/prod.json --fail-on high
git add baselines/prod.json
```

**Day 4 — CI**

Enable [.github/workflows/baseline-gate.yml](../.github/workflows/baseline-gate.yml) pattern or copy [workflow-live.yml](../examples/ci/workflow-live.yml).

**Day 5 — drift monitoring (optional)**

```bash
bucket-scanner serve --profile yc-prod --addr 127.0.0.1:9090 --interval 300
```

See [GRAFANA.md](GRAFANA.md).

## Suppressions (don't silence real issues)

Use time-boxed suppressions for known exceptions:

```toml
[[scan.suppressions]]
rule = "logging/disabled"
bucket = "public-assets-cdn"
reason = "CDN origin — ticket SEC-123"
expires = "2026-12-31"
```

## What we don't replace

- Full-account CSPM (Compute, Network, IAM hub)  
- Data classification / DLP inside objects  
- Automated remediation (open PRs) — future integration point  

Bucket Scanner answers: **"What does Object Storage actually expose, vs what we declared?"**
