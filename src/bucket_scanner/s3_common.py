"""Shared S3 bucket snapshot logic for Yandex Cloud and AWS."""

from __future__ import annotations

import json
from typing import Any

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import BucketSnapshot


def safe_s3_call(client: BaseClient, method: str, **kwargs: Any) -> dict[str, Any] | None:
    try:
        return getattr(client, method)(**kwargs)
    except ClientError:
        return None


def snapshot_bucket(
    client: BaseClient,
    name: str,
    *,
    cloud: CloudProvider = CloudProvider.YANDEX,
    scope_id: str | None = None,
    region: str | None = None,
) -> BucketSnapshot:
    acl_resp = safe_s3_call(client, "get_bucket_acl", Bucket=name)
    acl = None
    if acl_resp:
        acl = classify_acl(acl_resp.get("Grants", []))

    policy_resp = safe_s3_call(client, "get_bucket_policy", Bucket=name)
    policy = None
    if policy_resp and policy_resp.get("Policy"):
        policy = json.loads(policy_resp["Policy"])

    encryption_resp = safe_s3_call(client, "get_bucket_encryption", Bucket=name)
    encryption_enabled = bool(
        encryption_resp
        and encryption_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules")
    )

    logging_resp = safe_s3_call(client, "get_bucket_logging", Bucket=name)
    logging_enabled = bool(
        logging_resp and logging_resp.get("LoggingEnabled", {}).get("TargetBucket")
    )

    versioning_resp = safe_s3_call(client, "get_bucket_versioning", Bucket=name)
    versioning_enabled = versioning_resp is not None and versioning_resp.get("Status") == "Enabled"

    lifecycle_resp = safe_s3_call(client, "get_bucket_lifecycle_configuration", Bucket=name)
    lifecycle_rules: list[dict[str, Any]] = []
    if lifecycle_resp:
        lifecycle_rules = lifecycle_resp.get("Rules", [])

    tags_resp = safe_s3_call(client, "get_bucket_tagging", Bucket=name)
    tags: dict[str, str] = {}
    if tags_resp:
        tags = {item["Key"]: item["Value"] for item in tags_resp.get("TagSet", [])}

    block_public_access = None
    if cloud == CloudProvider.AWS:
        bpa_resp = safe_s3_call(client, "get_public_access_block", Bucket=name)
        if bpa_resp:
            block_public_access = bpa_resp.get("PublicAccessBlockConfiguration", {})

    return BucketSnapshot(
        name=name,
        cloud=cloud.value,
        folder_id=scope_id,
        region=region,
        acl=acl,
        policy=policy,
        encryption_enabled=encryption_enabled,
        logging_enabled=logging_enabled,
        versioning_enabled=versioning_enabled,
        lifecycle_rules=lifecycle_rules,
        tags=tags,
        block_public_access=block_public_access,
    )


def classify_acl(grants: list[dict[str, Any]]) -> str:
    for grant in grants:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        permission = grant.get("Permission", "")
        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
            if permission in {"READ", "FULL_CONTROL"}:
                return "public-read"
            if permission == "WRITE":
                return "public-read-write"
    return "private"
