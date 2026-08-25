"""Shared S3 bucket snapshot logic for Yandex Cloud and AWS."""

from __future__ import annotations

import json
from typing import Any

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import BucketSnapshot

# Errors that mean "feature not configured" rather than AccessDenied.
_MISSING_CODES = {
    "NoSuchBucketPolicy",
    "NoSuchTagSet",
    "NoSuchLifecycleConfiguration",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchBucket",
    "ObjectLockConfigurationNotFoundError",
    "NoSuchPublicAccessBlockConfiguration",
}


def safe_s3_call(
    client: BaseClient,
    method: str,
    **kwargs: Any,
) -> tuple[dict[str, Any] | None, str | None]:
    """Call an S3 API method.

    Returns ``(response, error_code)``.
    ``error_code`` is set on ClientError (AccessDenied, NoSuch*, …).
    """
    try:
        return getattr(client, method)(**kwargs), None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return None, code


def snapshot_bucket(
    client: BaseClient,
    name: str,
    *,
    cloud: CloudProvider = CloudProvider.YANDEX,
    scope_id: str | None = None,
    region: str | None = None,
) -> BucketSnapshot:
    partial: list[str] = []

    acl_resp, acl_err = safe_s3_call(client, "get_bucket_acl", Bucket=name)
    acl = None
    if acl_resp:
        acl = classify_acl(acl_resp.get("Grants", []))
    elif acl_err and acl_err not in _MISSING_CODES:
        partial.append("acl")

    policy_resp, policy_err = safe_s3_call(client, "get_bucket_policy", Bucket=name)
    policy = None
    if policy_resp and policy_resp.get("Policy"):
        policy = json.loads(policy_resp["Policy"])
    elif policy_err and policy_err not in _MISSING_CODES:
        partial.append("policy")

    encryption_resp, enc_err = safe_s3_call(client, "get_bucket_encryption", Bucket=name)
    encryption_enabled = False
    encryption_algorithm: str | None = None
    encryption_kms_key_id: str | None = None
    if encryption_resp:
        rules = encryption_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        encryption_enabled = bool(rules)
        if rules:
            default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
            encryption_algorithm = default.get("SSEAlgorithm")
            encryption_kms_key_id = default.get("KMSMasterKeyID")
    elif enc_err and enc_err not in _MISSING_CODES:
        partial.append("encryption")

    logging_resp, log_err = safe_s3_call(client, "get_bucket_logging", Bucket=name)
    logging_enabled = bool(
        logging_resp and logging_resp.get("LoggingEnabled", {}).get("TargetBucket")
    )
    if log_err and log_err not in _MISSING_CODES:
        partial.append("logging")

    versioning_resp, ver_err = safe_s3_call(client, "get_bucket_versioning", Bucket=name)
    versioning_enabled = versioning_resp is not None and versioning_resp.get("Status") == "Enabled"
    if ver_err and ver_err not in _MISSING_CODES:
        partial.append("versioning")

    lifecycle_resp, life_err = safe_s3_call(
        client, "get_bucket_lifecycle_configuration", Bucket=name
    )
    lifecycle_rules: list[dict[str, Any]] = []
    if lifecycle_resp:
        lifecycle_rules = lifecycle_resp.get("Rules", [])
    elif life_err and life_err not in _MISSING_CODES:
        partial.append("lifecycle")

    tags_resp, tags_err = safe_s3_call(client, "get_bucket_tagging", Bucket=name)
    tags: dict[str, str] = {}
    if tags_resp:
        tags = {item["Key"]: item["Value"] for item in tags_resp.get("TagSet", [])}
    elif tags_err and tags_err not in _MISSING_CODES:
        partial.append("tags")

    object_lock_enabled: bool | None = None
    lock_resp, lock_err = safe_s3_call(client, "get_object_lock_configuration", Bucket=name)
    if lock_resp:
        cfg = lock_resp.get("ObjectLockConfiguration") or {}
        object_lock_enabled = str(cfg.get("ObjectLockEnabled", "")).upper() == "ENABLED"
    elif lock_err == "ObjectLockConfigurationNotFoundError":
        object_lock_enabled = False
    elif lock_err and lock_err not in _MISSING_CODES:
        partial.append("object_lock")

    block_public_access = None
    if cloud == CloudProvider.AWS:
        bpa_resp, bpa_err = safe_s3_call(client, "get_public_access_block", Bucket=name)
        if bpa_resp:
            block_public_access = bpa_resp.get("PublicAccessBlockConfiguration", {})
        elif bpa_err == "NoSuchPublicAccessBlockConfiguration":
            block_public_access = None
        elif bpa_err and bpa_err not in _MISSING_CODES:
            partial.append("block_public_access")

    return BucketSnapshot(
        name=name,
        cloud=cloud.value,
        folder_id=scope_id,
        region=region,
        acl=acl,
        policy=policy,
        encryption_enabled=encryption_enabled,
        encryption_algorithm=encryption_algorithm,
        encryption_kms_key_id=encryption_kms_key_id,
        object_lock_enabled=object_lock_enabled,
        logging_enabled=logging_enabled,
        versioning_enabled=versioning_enabled,
        lifecycle_rules=lifecycle_rules,
        tags=tags,
        block_public_access=block_public_access,
        partial_metadata=partial,
    )


def classify_acl(grants: list[dict[str, Any]]) -> str:
    has_public_read = False
    has_public_write = False
    for grant in grants:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        permission = grant.get("Permission", "")
        if "AllUsers" not in uri and "AuthenticatedUsers" not in uri:
            continue
        if permission in {"WRITE", "WRITE_ACP", "FULL_CONTROL"}:
            has_public_write = True
        if permission in {"READ", "READ_ACP", "FULL_CONTROL"}:
            has_public_read = True
    if has_public_write:
        return "public-read-write"
    if has_public_read:
        return "public-read"
    return "private"
