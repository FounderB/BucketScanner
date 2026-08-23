# Azure Blob Storage backend (fixture-first)

Azure live inventory is **not implemented yet**. Use the offline fixture to explore checks and CI integration:

```bash
bucket-scanner scan --cloud azure --fixture examples/demo-vulnerable/fixture-azure.toml
bucket-scanner explain azure/container-public-access
```

## Fixture fields

| Field | Meaning |
|-------|---------|
| `folder_id` | Subscription ID label in reports |
| `block_public_access.public_access` | `off`, `blob`, or `container` |
| `account_public_access_block.allow_blob_public_access` | Account-level public blob toggle |
| `tags.storage_account` | Used for probe URL construction |

## Findings

| Rule | Severity |
|------|----------|
| `azure/container-public-access` | HIGH — anonymous blob/container access |
| `azure/account-public-access-enabled` | HIGH — `allowBlobPublicAccess` on account |
| Generic checks | `acl/public-read`, `encryption/disabled`, `iam/stale-static-key`, … |

## Roadmap

- Live scan via Azure SDK (`azure-storage-blob` / `DefaultAzureCredential`)
- Terraform drift for `azurerm_storage_container`
- GCS backend (separate cloud provider)

See [AWS.md](AWS.md) for the reference pattern used here.
