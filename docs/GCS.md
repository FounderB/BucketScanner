# Google Cloud Storage backend

GCS is supported in **fixture** mode (offline demos) and **live** mode (project inventory).

## Offline fixture

```bash
bucket-scanner scan --cloud gcs --fixture examples/demo-vulnerable/fixture-gcs.toml
bucket-scanner explain gcs/iam-public-principal
```

## Live scan

Install GCS SDK dependencies:

```bash
pip install "bucket-scanner[gcs]"
```

Authenticate with [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials):

- `gcloud auth application-default login`
- Service account key: `GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json`
- Workload identity on GKE / GitHub Actions OIDC

Set project scope:

```bash
export GCP_PROJECT=my-gcp-project
bucket-scanner scan --cloud gcs --folder-id "$GCP_PROJECT"
bucket-scanner doctor --cloud gcs
```

Required IAM (minimum): **Storage Object Viewer** or `roles/storage.admin` on project to list buckets and read IAM policy.

## What live scan collects

For each bucket in the project:

| Field | Source |
|-------|--------|
| Public IAM binding | `bucket.get_iam_policy()` — `allUsers` / `allAuthenticatedUsers` |
| Public access prevention | `bucket.iam_configuration.public_access_prevention` |
| Uniform bucket-level access | `uniform_bucket_level_access_enabled` |
| Versioning / logging | Bucket metadata |
| Encryption | GCS default encryption at rest (always on) |

## Fixture fields

| Field | Meaning |
|-------|---------|
| `folder_id` | GCP project ID label in reports |
| `block_public_access.public_access_prevention` | `inherited`, `enforced`, or `unspecified` |
| `block_public_access.uniform_bucket_level_access` | Uniform bucket-level access toggle |
| `block_public_access.iam_public` | Bucket grants `allUsers` / `allAuthenticatedUsers` |
| `account_public_access_block.public_access_prevention` | Project-level PAP default |

## Findings

| Rule | Severity |
|------|----------|
| `gcs/iam-public-principal` | HIGH — public IAM binding on bucket |
| `gcs/public-access-prevention-not-enforced` | HIGH — PAP not enforced |
| `gcs/uniform-access-disabled` | MEDIUM — legacy ACL path still open |
| Generic checks | `acl/public-read`, `logging/disabled`, `versioning/disabled`, … |

## Roadmap

- Terraform drift for `google_storage_bucket_iam_*`
- Org-policy checks for `constraints/storage.publicAccessPrevention`

See [AWS.md](AWS.md) and [AZURE.md](AZURE.md) for reference patterns.
