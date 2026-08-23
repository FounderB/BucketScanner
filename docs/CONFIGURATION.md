# Configuration

`bucket-scanner init` creates `.bucket-scanner.toml` in the project root.

```toml
[scan]
folder_id = "b1gxxxxxxxxxx"
# folder_ids = ["b1gfolder-a", "b1gfolder-b"]
fail_on = "high"
probe = false

[scan.ignore_buckets]
names = ["public-assets-cdn"]

[[scan.severity_overrides]]
rule = "versioning/disabled"
severity = "medium"
```

CLI flags override file values when both are set.

## Multi-folder Yandex Cloud

Scan several folders in one run (merged inventory and findings):

```toml
[scan]
folder_ids = ["b1gfolder-prod", "b1gfolder-backup"]
```

Or on the CLI:

```bash
bucket-scanner scan --folder-id b1gfolder-a --folder-id b1gfolder-b
```

## Scan profiles

Named presets for CI, demos, or continuous monitoring:

```toml
[[profiles]]
name = "aws-demo"
cloud = "aws"
fixture = "examples/demo-vulnerable/fixture-aws.toml"
terraform_path = "examples/demo-vulnerable/terraform-aws"

[[profiles]]
name = "yc-prod"
folder_ids = ["b1gfolder-prod", "b1gfolder-backup"]
probe = true

[serve]
addr = "127.0.0.1:9090"
interval_seconds = 300
profile = "yc-prod"
```

```bash
bucket-scanner scan --profile aws-demo
bucket-scanner serve --profile yc-prod --interval 300
bucket-scanner profiles list
```

Profile fields map to scan options (`cloud`, `folder_id`, `folder_ids`, `aws_region`, `fixture`, `terraform_path`, etc.). CLI flags still override profile values.
