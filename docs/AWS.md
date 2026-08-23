# AWS S3 backend

Bucket Scanner can scan **Amazon S3** as an optional second backend alongside Yandex Cloud Object Storage.

## Quick start

```bash
export AWS_REGION=us-east-1
# optional: export AWS_PROFILE=your-profile
# or: export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...

bucket-scanner scan --cloud aws
bucket-scanner scan --cloud aws --aws-region eu-west-1 --probe
bucket-scanner doctor --cloud aws
```

Scope in reports uses the **AWS account ID** from STS (`GetCallerIdentity`).

## Offline demo

No credentials required:

```bash
bucket-scanner scan --cloud aws --fixture examples/demo-vulnerable/fixture-aws.toml
```

## Configuration

In `.bucket-scanner.toml`:

```toml
[scan]
cloud = "aws"
aws_region = "us-east-1"
aws_profile = "default"
aws_scan_iam = true
```

## Checks

AWS buckets get the same core checks as Yandex (ACL, policy, encryption, logging, versioning, lifecycle, tags) plus:

| Rule | Meaning |
|------|---------|
| `aws/block-public-access-incomplete` | Bucket-level Block Public Access not fully enabled |
| `aws/account-public-access-incomplete` | Account-level Block Public Access not fully enabled |

## Permissions

Minimum IAM for live scans:

- `s3:ListAllMyBuckets`
- `s3:GetBucket*`, `s3:GetEncryptionConfiguration`, `s3:GetLifecycleConfiguration`, `s3:GetBucketTagging`
- `s3:GetPublicAccessBlock` (bucket)
- `s3:GetAccountPublicAccessBlock` via **S3 Control** (`s3control:GetPublicAccessBlock`)

Optional IAM user key age checks (`aws_scan_iam = true`):

- `iam:ListUsers`, `iam:ListAccessKeys`

## Probe URLs

Anonymous probe mode uses regional endpoints:

- `us-east-1`: `https://{bucket}.s3.amazonaws.com/`
- Other regions: `https://{bucket}.s3.{region}.amazonaws.com/`

Same safety model as Yandex: HEAD + list metadata only, no object body download.

## Yandex vs AWS

| | Yandex (default) | AWS |
|--|------------------|-----|
| CLI flag | `--cloud yandex` | `--cloud aws` |
| Scope | `--folder-id` | STS account ID |
| Auth | `YC_TOKEN`, SA key, static keys | AWS profile / env keys |
| Extra checks | YC IAM SA bindings | Block Public Access, optional IAM keys |

Both backends share chains, SARIF/JSON/Prometheus output, Terraform diff, and repo secret scanning.

```bash
bucket-scanner diff examples/demo-vulnerable/terraform-aws \
  --cloud aws --fixture examples/demo-vulnerable/fixture-aws.toml
```
