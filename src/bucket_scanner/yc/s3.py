"""S3-compatible client for Yandex Object Storage."""

from __future__ import annotations

import boto3
from botocore.client import BaseClient

from bucket_scanner.auth import Credentials
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import BucketSnapshot
from bucket_scanner.s3_common import classify_acl, snapshot_bucket

YC_S3_ENDPOINT = "https://storage.yandexcloud.net"
YC_REGION = "ru-central1"


def build_s3_client(credentials: Credentials) -> BaseClient:
    if not credentials.access_key_id or not credentials.secret_access_key:
        raise ValueError("Static access keys are required for S3 metadata calls.")
    return boto3.client(
        "s3",
        endpoint_url=YC_S3_ENDPOINT,
        region_name=YC_REGION,
        aws_access_key_id=credentials.access_key_id,
        aws_secret_access_key=credentials.secret_access_key,
    )


def snapshot_yandex_bucket(
    client: BaseClient,
    name: str,
    *,
    folder_id: str | None = None,
) -> BucketSnapshot:
    return snapshot_bucket(
        client,
        name,
        cloud=CloudProvider.YANDEX,
        scope_id=folder_id,
        region=YC_REGION,
    )


# Backward-compatible aliases used in tests and imports.
_classify_acl = classify_acl
