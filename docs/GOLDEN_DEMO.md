# Golden demo (v1.0 walkthrough)

Five-minute end-to-end story: **fixture scan → baseline → delta gate → SARIF → GitHub Action**.

No cloud credentials required — uses offline fixtures from this repository.

## 1. Install

```bash
pip install bucket-scanner==1.0.0
# or from source:
pip install -e ".[dev]"
```

## 2. First scan (expect findings)

```bash
bucket-scanner scan \
  --profile yc-fixture \
  --config examples/ci/.bucket-scanner.toml \
  --sarif /tmp/bucket-scanner.sarif \
  --fail-on high
echo "exit=$?"   # expect 1 — findings by design
```

## 3. Write baseline (accept current state)

```bash
bucket-scanner scan \
  --profile yc-fixture \
  --config examples/ci/.bucket-scanner.toml \
  --write-baseline /tmp/baseline.json -q
```

## 4. Delta gate (pass until something new appears)

```bash
bucket-scanner scan \
  --profile yc-fixture \
  --config examples/ci/.bucket-scanner.toml \
  --baseline /tmp/baseline.json \
  --fail-on new -q
echo "exit=$?"   # expect 0
```

## 5. Multi-cloud fixture matrix

```bash
for profile in yc-fixture aws-fixture azure-fixture gcs-fixture; do
  bucket-scanner scan --profile "$profile" \
    --config examples/ci/.bucket-scanner.toml \
    --fail-on high -q || test $? -eq 1
done
```

## 6. GitHub Action (copy-paste)

See [examples/golden-demo/workflow.yml](../examples/golden-demo/workflow.yml):

- Installs `bucket-scanner==1.0.0` from PyPI
- Runs `yc-fixture` profile
- Uploads SARIF + JSON artifacts

## 7. Live cloud (optional)

| Cloud | Command |
|-------|---------|
| Yandex | `YC_TOKEN=... bucket-scanner scan --folder-id b1g...` |
| AWS | `bucket-scanner scan --cloud aws` |
| Azure | `pip install 'bucket-scanner[azure]'` + `AZURE_SUBSCRIPTION_ID=...` |
| GCS | `pip install 'bucket-scanner[gcs]'` + `GCP_PROJECT=...` |

## What to show on video

1. Terminal banner + findings table (fixture)
2. `--write-baseline` / `--fail-on new` flip
3. SARIF file snippet (`ruleId`, `level`)
4. GitHub Actions green job with artifact
5. One sentence: **declared vs real**

## Files

| Path | Purpose |
|------|---------|
| `examples/ci/.bucket-scanner.toml` | Named profiles |
| `examples/demo-vulnerable/fixture*.toml` | Offline vulnerable buckets |
| `examples/golden-demo/workflow.yml` | Copy-ready CI |
| `docs/GITHUB_ACTION.md` | Action inputs |
| `docs/PYPI.md` | Install + publish |
