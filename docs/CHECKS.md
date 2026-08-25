# Checks reference

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `acl/public-read` | critical | Bucket ACL allows anonymous read |
| `acl/public-read-write` | critical | Bucket ACL allows anonymous write |
| `policy/overly-permissive` | high | Bucket policy wider than expected |
| `encryption/disabled` | high | Default encryption not enabled |
| `logging/disabled` | medium | Access logging off |
| `versioning/disabled` | medium | Object versioning off |
| `lifecycle/aggressive-expiration` | medium | Short retention on prod-like bucket |
| `iam/stale-static-key` | high | SA static key older than policy |
| `iam/over-privileged-sa` | high | SA has storage.admin on many buckets |
| `probe/anonymous-list` | critical | Anonymous ListObjects confirmed |
| `probe/anonymous-read-confirmed` | critical | Anonymous read despite private ACL |
| `yc/anonymous-read-enabled` | critical | Storage anonymousAccessFlags.read |
| `yc/anonymous-list-enabled` | critical | Storage anonymousAccessFlags.list |
| `yc/anonymous-config-read-enabled` | medium | Storage anonymousAccessFlags.configRead |
| `yc/website-enabled` | medium | Static website hosting configured |
| `yc/cors-enabled` | medium | CORS rules present on the bucket |
| `iac/acl-drift` | critical | Terraform private, live public |
| `iac/shadow-bucket` | high | Live bucket not in Terraform |
| `iac/ghost-bucket` | medium | Terraform bucket missing live |
| `iac/bpa-drift` | high | Terraform BPA enabled, live incomplete |
| `tags/missing-env` | low | Prod-like name without env tag |
| `metadata/limited` | info | Inventory-only when Bucket.Get/ephemeral unavailable |
| `secrets/yc-env-var` | critical | YC credential assignment in repo |
| `secrets/yc-static-key` | critical | YC static key pattern in repo |
| `secrets/aws-env-var` | critical | AWS credential assignment in repo |
| `secrets/aws-access-key-id` | critical | AWS access key ID pattern in repo |
| `aws/block-public-access-incomplete` | high | S3 bucket Block Public Access incomplete |
| `aws/account-public-access-incomplete` | high | Account Block Public Access incomplete |
| `azure/container-public-access` | high | Azure container blob/container public access |
| `azure/account-public-access-enabled` | high | Storage account allowBlobPublicAccess enabled |
| `gcs/iam-public-principal` | high | GCS bucket IAM binding for allUsers/allAuthenticatedUsers |
| `gcs/public-access-prevention-not-enforced` | high | publicAccessPrevention inherited or unspecified |
| `gcs/uniform-access-disabled` | medium | Uniform bucket-level access disabled |
| `secrets/azure-env-var` | critical | Azure credential assignment in repo |
| `iac/no-buckets-declared` | info | No storage resources in Terraform path |
| `tracefuse/*` | varies | Imported Tracefuse cloud-related finding |
| `chain/leaked-credentials-exposure` | critical | repo secrets + public bucket |
| `chain/silent-exfil` | critical | public-read + no-logging + no-versioning |

Use `bucket-scanner explain <rule-id>` for remediation steps.
