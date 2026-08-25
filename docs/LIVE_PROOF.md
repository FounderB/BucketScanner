# Live proof (field calibration)

Goal: **declared-vs-real evidence** from your folder, not marketing demos.

## Offline rehearsal (no secrets)

```bash
./scripts/live_proof.sh
bucket-scanner proof-log summary --log proofs/fp-log.jsonl
```

## Live Yandex Cloud

```bash
export YC_TOKEN=$(yc iam create-token)
export YC_FOLDER_ID=b1g…   # or --folder-id

./scripts/live_proof.sh --live --folder-id "$YC_FOLDER_ID" --probe
```

Or profile:

```bash
cp examples/ci/.bucket-scanner.prod.toml.example .bucket-scanner.toml
# edit folder_ids
./scripts/live_proof.sh --live --config .bucket-scanner.toml --profile yc-prod
```

## Triage FP / accepted risk

```bash
# fingerprints are rule|bucket|resource (see proof-log JSONL)
bucket-scanner proof-log set \
  --log proofs/fp-log.jsonl \
  --fingerprint 'logging/disabled|cdn-assets|' \
  --status accepted_risk \
  --notes 'CDN origin — edge logs only'
```

Statuses: `unreviewed` · `confirmed` · `false_positive` · `accepted_risk` · `fixed`

## GitHub Actions

[.github/workflows/live-scan.yml](../.github/workflows/live-scan.yml):

1. Always runs a **fixture smoke** (no secrets) → proof-log artifact
2. Runs **live YC** when `YC_TOKEN` (+ optional `YC_FOLDER_ID`) secrets exist
3. Uploads JSON / SARIF / proof-log

Set repository secrets: `YC_TOKEN`, `YC_FOLDER_ID`. Then **Actions → Live scan → Run workflow**.

## What “good” looks like after 2 weeks

| Signal | Target |
|--------|--------|
| Unreviewed backlog | trending down |
| Confirmed / fixed | growing |
| False positive rate | known and documented in notes |
| Baseline gate | `summary.new == 0` on main |
