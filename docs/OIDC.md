# OIDC / keyless CI setup

Run Bucket Scanner in GitHub Actions **without long-lived cloud access keys** in secrets.

Workflow templates:

| Cloud | Template |
|-------|----------|
| AWS | [examples/ci/workflow-aws-oidc.yml](../examples/ci/workflow-aws-oidc.yml) |
| Azure | [examples/ci/workflow-azure-oidc.yml](../examples/ci/workflow-azure-oidc.yml) |
| GCS | [examples/ci/workflow-gcs-oidc.yml](../examples/ci/workflow-gcs-oidc.yml) |

Repository live scan (static secrets): [.github/workflows/live-scan.yml](../.github/workflows/live-scan.yml)

## AWS (GitHub OIDC → IAM role)

1. Create IAM OIDC provider for `token.actions.githubusercontent.com`  
2. IAM role trust policy — restrict to your repo/branch  
3. Attach read-only S3 policy (`ListAllMyBuckets`, `GetBucket*`, `GetPublicAccessBlock`, …)  
4. Workflow:

```yaml
permissions:
  id-token: write
  contents: read
  security-events: write

steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::ACCOUNT:role/bucket-scanner-oidc
      aws-region: eu-west-1
  - uses: FounderB/BucketScanner/action@v1.3.0
    with:
      version: "1.3.0"
      profile: aws-prod
      fail-on: new
      baseline-path: baselines/aws-prod.json
```

## Azure (federated credential)

1. App registration + federated credential for GitHub Actions  
2. Role: **Reader** on subscription + **Storage Blob Data Reader** (or custom read-only storage role)  
3. Secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`  
4. Workflow uses `azure/login@v2` — see [workflow-azure-oidc.yml](../examples/ci/workflow-azure-oidc.yml)

## GCS (Workload Identity Federation)

1. GCP service account with `storage.buckets.list`, `storage.objects.get` (metadata)  
2. Workload Identity Pool + Provider for GitHub OIDC  
3. `google-github-actions/auth@v2` — see [workflow-gcs-oidc.yml](../examples/ci/workflow-gcs-oidc.yml)

## Yandex Cloud (IAM token)

YC has no GitHub OIDC first-party flow in Bucket Scanner today. Recommended:

- Short-lived `YC_TOKEN` from CI secret (rotate via your secret manager)  
- Or scan from a trusted runner inside YC with metadata credentials  

```yaml
env:
  YC_TOKEN: ${{ secrets.YC_TOKEN }}
  YC_FOLDER_ID: ${{ secrets.YC_FOLDER_ID }}
```

Run `bucket-scanner doctor --cloud yandex --json` as first CI step when `run-doctor: true` on the Action.

## Baseline + OIDC

Combine OIDC auth with delta gating:

```yaml
with:
  fail-on: new
  baseline-path: baselines/aws-prod.json
  write-baseline-path: baselines/aws-prod.json  # manual refresh workflow only
```

See [BASELINE.md](BASELINE.md).
