"""AWS S3 backend."""

from __future__ import annotations

from typing import Any

import boto3
from botocore.client import BaseClient

from bucket_scanner.auth import AwsCredentials
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import BucketSnapshot
from bucket_scanner.s3_common import safe_s3_call, snapshot_bucket


def build_aws_s3_client(credentials: AwsCredentials, *, region: str | None = None) -> BaseClient:
    session_kwargs: dict[str, Any] = {}
    if credentials.profile:
        session_kwargs["profile_name"] = credentials.profile
    session = boto3.Session(**session_kwargs)
    client_kwargs: dict[str, Any] = {
        "region_name": region or credentials.region or "us-east-1",
    }
    if credentials.access_key_id and credentials.secret_access_key:
        client_kwargs["aws_access_key_id"] = credentials.access_key_id
        client_kwargs["aws_secret_access_key"] = credentials.secret_access_key
        if credentials.session_token:
            client_kwargs["aws_session_token"] = credentials.session_token
    return session.client("s3", **client_kwargs)


def build_aws_sts_client(credentials: AwsCredentials) -> BaseClient:
    session_kwargs: dict[str, Any] = {}
    if credentials.profile:
        session_kwargs["profile_name"] = credentials.profile
    session = boto3.Session(**session_kwargs)
    client_kwargs: dict[str, Any] = {"region_name": credentials.region or "us-east-1"}
    if credentials.access_key_id and credentials.secret_access_key:
        client_kwargs["aws_access_key_id"] = credentials.access_key_id
        client_kwargs["aws_secret_access_key"] = credentials.secret_access_key
        if credentials.session_token:
            client_kwargs["aws_session_token"] = credentials.session_token
    return session.client("sts", **client_kwargs)


def resolve_account_id(credentials: AwsCredentials) -> str:
    sts = build_aws_sts_client(credentials)
    return sts.get_caller_identity()["Account"]


def list_bucket_names(client: BaseClient) -> list[str]:
    response = client.list_buckets()
    return [item["Name"] for item in response.get("Buckets", [])]


def resolve_bucket_region(client: BaseClient, bucket_name: str, *, default: str) -> str:
    response, _err = safe_s3_call(client, "get_bucket_location", Bucket=bucket_name)
    if not response:
        return default
    location = response.get("LocationConstraint")
    if not location:
        return "us-east-1"
    if location == "EU":
        return "eu-west-1"
    return str(location)


def get_account_public_access_block(
    credentials: AwsCredentials,
    account_id: str,
) -> dict[str, Any] | None:
    session_kwargs: dict[str, Any] = {}
    if credentials.profile:
        session_kwargs["profile_name"] = credentials.profile
    session = boto3.Session(**session_kwargs)
    client_kwargs: dict[str, Any] = {"region_name": credentials.region or "us-east-1"}
    if credentials.access_key_id and credentials.secret_access_key:
        client_kwargs["aws_access_key_id"] = credentials.access_key_id
        client_kwargs["aws_secret_access_key"] = credentials.secret_access_key
        if credentials.session_token:
            client_kwargs["aws_session_token"] = credentials.session_token
    control = session.client("s3control", **client_kwargs)
    response, _err = safe_s3_call(control, "get_public_access_block", AccountId=account_id)
    if not response:
        return None
    return response.get("PublicAccessBlockConfiguration")


def snapshot_aws_bucket(
    client: BaseClient,
    name: str,
    *,
    account_id: str,
    region: str,
    account_public_access_block: dict[str, Any] | None = None,
) -> BucketSnapshot:
    snapshot = snapshot_bucket(
        client,
        name,
        cloud=CloudProvider.AWS,
        scope_id=account_id,
        region=region,
    )
    return snapshot.model_copy(update={"account_public_access_block": account_public_access_block})
