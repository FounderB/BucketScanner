# Configuration

`bucket-scanner init` creates `.bucket-scanner.toml` in the project root.

```toml
[scan]
folder_id = "b1gxxxxxxxxxx"
fail_on = "high"
probe = false

[scan.ignore_buckets]
names = ["public-assets-cdn"]

[[scan.severity_overrides]]
rule = "versioning/disabled"
severity = "medium"
```

CLI flags override file values when both are set.
