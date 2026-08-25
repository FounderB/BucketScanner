# Baseline and suppressions

Production CI gates often fail on **legacy noise**. Bucket Scanner supports baselines (delta) and time-boxed suppressions.

## Baseline workflow

```bash
# 1. First run — save accepted state
bucket-scanner scan --folder-id "$YC_FOLDER_ID" \
  --write-baseline baselines/prod.json \
  --fail-on high -q || test $? -eq 1

# 2. Later runs — fail only on NEW findings
bucket-scanner scan --folder-id "$YC_FOLDER_ID" \
  --baseline baselines/prod.json \
  --fail-on new -q
```

Or set in `.bucket-scanner.toml`:

```toml
[scan]
baseline_path = "baselines/prod.json"
fail_on = "high"
```

CLI: `--fail-on new` requires `--baseline` or `scan.baseline_path`. Severity threshold for new findings comes from `[scan] fail_on` (default `high`).

## JSON report schema

Reports include `report_schema = "1.0"` plus:

| Field | Description |
|-------|-------------|
| `findings` | Active findings after suppressions |
| `suppressed_findings` | Audit trail: finding + reason + expires |
| `new_findings` | Delta vs baseline (empty without baseline) |
| `new_chains` | New misconfig chains vs baseline |
| `summary.suppressed` | Findings removed by policy |
| `summary.new` | Count of new findings + chains |
| `baseline_path` | Baseline file used, if any |

Fingerprints: `rule_id|bucket|resource` for findings; `chain_id|sorted_buckets` for chains.

## Suppressions

```toml
[[scan.suppressions]]
rule = "logging/disabled"
bucket = "public-assets-cdn"
reason = "CDN origin — ticket SEC-42"
expires = "2026-12-31"

[[scan.suppressions]]
rule = "versioning/disabled"
bucket = "temp-*"
reason = "Ephemeral staging fleet"
expires = "2026-06-30"
```

Optional fields: `resource`, `expires` (ISO date). `bucket` and `rule` accept `fnmatch` globs (`temp-*`, `aws/*`). Expired suppressions are ignored automatically. JSON reports keep an audit list in `suppressed_findings` (reason + expires). Human output warns when a suppression expires within 14 days.

Suppressions apply before baseline comparison and recompose chains on remaining findings.

### Refreshing baselines (trusted main only)

1. Review current findings on `main` after an intentional accept.
2. Run with `--write-baseline baselines/<cloud>-prod.json` in a **manual** workflow (not on every PR).
3. Commit the baseline JSON; subsequent PRs use `--fail-on new` via [baseline-gate.yml](../.github/workflows/baseline-gate.yml) (hard fail — no `continue-on-error`).

## GitHub Action

```yaml
- uses: FounderB/BucketScanner/action@v1.7.1
  with:
    profile: yc-prod
    fail-on: new
    baseline-path: baselines/prod.json
```

Use `write-baseline-path` on a manual workflow to refresh the baseline artifact.

## Prometheus

When `serve` runs with baseline/suppressions configured:

- `bucket_scanner_suppressed_total`
- `bucket_scanner_new_total`
- `bucket_scanner_findings_by_rule{rule_id=...}`
- `bucket_scanner_scan_duration_ms`
