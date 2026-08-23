# Azure Blob Storage backend

Azure is supported in **fixture** mode (offline demos) and **live** mode (subscription inventory).

## Offline fixture

```bash
bucket-scanner scan --cloud azure --fixture examples/demo-vulnerable/fixture-azure.toml
bucket-scanner explain azure/container-public-access
```

## Live scan

Install Azure SDK dependencies:

```bash
pip install "bucket-scanner[azure]"
```

Authenticate with any method supported by [DefaultAzureCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential):

- `az login` (Azure CLI)
- Service principal: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
- Managed identity on Azure VM / GitHub Actions OIDC

Set subscription scope:

```bash
export AZURE_SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
bucket-scanner scan --cloud azure --folder-id "$AZURE_SUBSCRIPTION_ID"
bucket-scanner doctor --cloud azure
```

Required RBAC (minimum): **Reader** on subscription plus **Storage Blob Data Reader** (or Storage Account Contributor) to list containers.

## What live scan collects

For each storage account in the subscription:

| Field | Source |
|-------|--------|
| Container public access | `BlobServiceClient.list_containers()` |
| Account `allowBlobPublicAccess` | `StorageManagementClient.storage_accounts.get_properties()` |
| Encryption | Account encryption settings |
| Versioning | Account blob versioning flag |
| Probe URL tag | `tags.storage_account` = account name |

Containers map to Bucket Scanner **buckets** (same model as S3 bucket names).

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

- Terraform drift for `azurerm_storage_container`
- GCS backend (separate cloud provider)

See [AWS.md](AWS.md) for the reference pattern used here.
