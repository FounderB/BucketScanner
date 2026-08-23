"""Azure Blob Storage live inventory."""

from __future__ import annotations

from typing import Any

from bucket_scanner.auth import Credentials
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import BucketSnapshot


class AzureDependencyError(ImportError):
    pass


def _import_azure():
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.storage import StorageManagementClient
        from azure.storage.blob import BlobServiceClient
    except ImportError as exc:
        raise AzureDependencyError(
            "Azure live scan requires optional dependencies: pip install 'bucket-scanner[azure]'"
        ) from exc
    return DefaultAzureCredential, StorageManagementClient, BlobServiceClient


def _public_access_label(value: Any) -> str:
    if value is None:
        return "off"
    text = str(value).lower()
    if text in {"blob", "container"}:
        return text
    if "blob" in text:
        return "blob"
    if "container" in text:
        return "container"
    return "off"


def _acl_from_public_access(public_access: str) -> str:
    return "public-read" if public_access in {"blob", "container"} else "private"


def _resource_group_from_id(resource_id: str) -> str:
    parts = resource_id.split("/")
    if len(parts) > 4 and parts[3] == "resourceGroups":
        return parts[4]
    raise ValueError(f"Cannot parse resource group from Azure resource id: {resource_id}")


def snapshot_azure_container(
    *,
    container_name: str,
    subscription_id: str,
    storage_account: str,
    region: str | None,
    public_access: str,
    account_allow_blob_public_access: bool | None,
    encryption_enabled: bool,
    versioning_enabled: bool,
) -> BucketSnapshot:
    account_bpa = {"allow_blob_public_access": account_allow_blob_public_access}
    return BucketSnapshot(
        name=container_name,
        cloud=CloudProvider.AZURE.value,
        folder_id=subscription_id,
        region=region,
        acl=_acl_from_public_access(public_access),
        encryption_enabled=encryption_enabled,
        logging_enabled=False,
        versioning_enabled=versioning_enabled,
        block_public_access={
            "public_access": public_access,
            "allow_blob_public_access": account_allow_blob_public_access,
        },
        account_public_access_block=account_bpa,
        tags={"storage_account": storage_account},
    )


def collect_azure_containers(
    credentials: Credentials,
    *,
    subscription_id: str,
    ignore: set[str],
) -> list[BucketSnapshot]:
    DefaultAzureCredential, StorageManagementClient, BlobServiceClient = _import_azure()
    credential = DefaultAzureCredential(
        exclude_interactive_browser_credential=True,
    )
    mgmt = StorageManagementClient(credential, subscription_id)

    buckets: list[BucketSnapshot] = []
    for account in mgmt.storage_accounts.list():
        account_name = account.name
        if not account_name or not account.id:
            continue
        resource_group = _resource_group_from_id(account.id)
        props = mgmt.storage_accounts.get_properties(resource_group, account_name)
        allow_public = props.allow_blob_public_access
        encryption_enabled = bool(
            props.encryption
            and props.encryption.services
            and props.encryption.services.blob
            and props.encryption.services.blob.enabled
        )
        versioning_enabled = bool(getattr(props, "is_versioning_enabled", False))
        region = account.location

        account_url = f"https://{account_name}.blob.core.windows.net"
        blob_service = BlobServiceClient(account_url=account_url, credential=credential)
        try:
            containers = blob_service.list_containers(include_metadata=False)
        except OSError:
            continue

        for container in containers:
            container_name = container.name
            if container_name in ignore:
                continue
            public_access = _public_access_label(getattr(container, "public_access", None))
            buckets.append(
                snapshot_azure_container(
                    container_name=container_name,
                    subscription_id=subscription_id,
                    storage_account=account_name,
                    region=region,
                    public_access=public_access,
                    account_allow_blob_public_access=allow_public,
                    encryption_enabled=encryption_enabled,
                    versioning_enabled=versioning_enabled,
                )
            )
    return buckets
