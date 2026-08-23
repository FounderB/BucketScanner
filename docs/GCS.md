# Google Cloud Storage backend (fixture-first)

GCS live inventory is **not implemented yet**. Use the offline fixture to explore checks and CI integration:

```bash
bucket-scanner scan --cloud gcs --fixture examples/demo-vulnerable/fixture-gcs.toml
bucket-scanner explain gcs/iam-public-principal
```

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
| Generic checks | `acl/public-read`, `encryption/disabled`, `iam/stale-static-key`, … |

## Roadmap

- Live scan via `google-cloud-storage` + Application Default Credentials
- Terraform drift for `google_storage_bucket_iam_*`
- Org-policy checks for `constraints/storage.publicAccessPrevention`

See [AWS.md](AWS.md) and [AZURE.md](AZURE.md) for reference patterns.
