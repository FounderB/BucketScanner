"""Credential resolution for Yandex Cloud and AWS."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import boto3
import httpx
import jwt

from bucket_scanner.cloud import CloudProvider

IAM_TOKEN_URL = "https://iam.api.cloud.yandex.net/iam/v1/tokens"  # nosec B105


@dataclass
class Credentials:
    cloud: CloudProvider = CloudProvider.YANDEX
    iam_token: str | None = None
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None
    folder_id: str | None = None
    cloud_id: str | None = None
    region: str | None = None
    profile: str | None = None
    account_id: str | None = None
    subscription_id: str | None = None
    tenant_id: str | None = None
    source: str = "env"


AwsCredentials = Credentials


class CredentialError(RuntimeError):
    pass


def _env(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _iam_token_from_sa_key(key_path: Path) -> str:
    payload = json.loads(key_path.read_text(encoding="utf-8"))
    service_account_id = payload["service_account_id"]
    key_id = payload["id"]
    private_key = payload["private_key"]
    now = int(time.time())
    encoded = jwt.encode(
        {
            "aud": IAM_TOKEN_URL,
            "iss": service_account_id,
            "iat": now,
            "exp": now + 3600,
        },
        private_key,
        algorithm="PS256",
        headers={"kid": key_id},
    )
    response = httpx.post(IAM_TOKEN_URL, json={"jwt": encoded}, timeout=30.0)
    response.raise_for_status()
    return response.json()["iamToken"]


def resolve_credentials(
    *,
    cloud: CloudProvider = CloudProvider.YANDEX,
    region: str | None = None,
    profile: str | None = None,
) -> Credentials:
    if cloud == CloudProvider.AWS:
        return resolve_aws_credentials(region=region, profile=profile)
    if cloud == CloudProvider.AZURE:
        return resolve_azure_credentials()
    if cloud == CloudProvider.GCS:
        return resolve_gcs_credentials()
    return _resolve_yandex_credentials()


def _resolve_yandex_credentials() -> Credentials:
    folder_id = _env("YC_FOLDER_ID")
    cloud_id = _env("YC_CLOUD_ID")
    access_key_id = _env("YC_ACCESS_KEY_ID")
    secret_access_key = _env("YC_SECRET_ACCESS_KEY")
    iam_token = _env("YC_TOKEN", "YC_IAM_TOKEN")

    key_file = _env("YC_SERVICE_ACCOUNT_KEY_FILE")
    if key_file and not iam_token:
        iam_token = _iam_token_from_sa_key(Path(key_file))

    if not iam_token and not (access_key_id and secret_access_key):
        raise CredentialError(
            "Missing credentials. Set YC_TOKEN, YC_SERVICE_ACCOUNT_KEY_FILE, "
            "or YC_ACCESS_KEY_ID + YC_SECRET_ACCESS_KEY."
        )

    source = "iam-token" if iam_token else "static-keys"
    return Credentials(
        cloud=CloudProvider.YANDEX,
        iam_token=iam_token,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        folder_id=folder_id,
        cloud_id=cloud_id,
        source=source,
    )


def resolve_azure_credentials() -> Credentials:
    subscription_id = _env("AZURE_SUBSCRIPTION_ID", "ARM_SUBSCRIPTION_ID")
    tenant_id = _env("AZURE_TENANT_ID", "ARM_TENANT_ID")
    return Credentials(
        cloud=CloudProvider.AZURE,
        subscription_id=subscription_id,
        tenant_id=tenant_id,
        folder_id=subscription_id,
        source="default-credential-chain",
    )


def resolve_gcs_credentials() -> Credentials:
    project_id = _env("GCP_PROJECT", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT")
    return Credentials(
        cloud=CloudProvider.GCS,
        folder_id=project_id,
        source="application-default-credentials",
    )


def resolve_aws_credentials(
    *,
    region: str | None = None,
    profile: str | None = None,
) -> Credentials:
    resolved_region = region or _env("AWS_REGION", "AWS_DEFAULT_REGION") or "us-east-1"
    resolved_profile = profile or _env("AWS_PROFILE")
    access_key_id = _env("AWS_ACCESS_KEY_ID")
    secret_access_key = _env("AWS_SECRET_ACCESS_KEY")
    session_token = _env("AWS_SESSION_TOKEN")

    if access_key_id and secret_access_key:
        return Credentials(
            cloud=CloudProvider.AWS,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            region=resolved_region,
            profile=resolved_profile,
            source="env-keys",
        )

    session_kwargs: dict = {}
    if resolved_profile:
        session_kwargs["profile_name"] = resolved_profile
    session = boto3.Session(**session_kwargs)
    frozen = session.get_credentials()
    if frozen is None:
        raise CredentialError(
            "Missing AWS credentials. Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY "
            "or configure AWS_PROFILE with valid credentials."
        )
    return Credentials(
        cloud=CloudProvider.AWS,
        access_key_id=frozen.access_key,
        secret_access_key=frozen.secret_key,
        session_token=frozen.token,
        region=resolved_region,
        profile=resolved_profile,
        source="profile" if resolved_profile else "default-chain",
    )
