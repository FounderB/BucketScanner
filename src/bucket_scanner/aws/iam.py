"""AWS IAM helpers."""

from __future__ import annotations

from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

from bucket_scanner.auth import AwsCredentials
from bucket_scanner.models import ServiceAccountKeySnapshot

RISKY_POLICY_NAMES = {
    "AdministratorAccess",
    "AmazonS3FullAccess",
    "PowerUserAccess",
    "IAMFullAccess",
}


def _key_age_days(created_at: datetime | None) -> int | None:
    if created_at is None:
        return None
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return (datetime.now(tz=UTC) - created_at).days


def _list_user_roles(iam, username: str) -> list[str]:
    roles: list[str] = []
    try:
        attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
        roles.extend(item["PolicyName"] for item in attached)
        inline = iam.list_user_policies(UserName=username).get("PolicyNames", [])
        roles.extend(f"inline:{name}" for name in inline)
    except ClientError:
        return ["iam-user"]
    if not roles:
        roles.append("iam-user")
    return roles


def list_iam_access_keys(credentials: AwsCredentials) -> list[ServiceAccountKeySnapshot]:
    session_kwargs: dict = {}
    if credentials.profile:
        session_kwargs["profile_name"] = credentials.profile
    session = boto3.Session(**session_kwargs)
    client_kwargs = {"region_name": credentials.region}
    if credentials.access_key_id and credentials.secret_access_key:
        client_kwargs["aws_access_key_id"] = credentials.access_key_id
        client_kwargs["aws_secret_access_key"] = credentials.secret_access_key
        if credentials.session_token:
            client_kwargs["aws_session_token"] = credentials.session_token
    iam = session.client("iam", **client_kwargs)
    keys: list[ServiceAccountKeySnapshot] = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            roles = _list_user_roles(iam, username)
            key_page = iam.list_access_keys(UserName=username)
            for item in key_page.get("AccessKeyMetadata", []):
                keys.append(
                    ServiceAccountKeySnapshot(
                        sa_id=username,
                        key_id=item.get("AccessKeyId"),
                        age_days=_key_age_days(item.get("CreateDate")),
                        roles=roles,
                    )
                )
    return keys
