"""Contract tests for Yandex Cloud management API shapes and URLs."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from bucket_scanner.checks import _principal_is_wildcard, check_bucket
from bucket_scanner.models import BucketSnapshot
from bucket_scanner.s3_common import classify_acl, safe_s3_call
from bucket_scanner.yc.management import (
    AWS_COMPAT_API,
    RESOURCE_MANAGER_API,
    ManagementError,
    YcManagementClient,
)


def test_access_bindings_use_resource_manager():
    client = YcManagementClient("token")
    with patch("bucket_scanner.yc.management.httpx.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"accessBindings": [{"roleId": "storage.viewer"}]},
            raise_for_status=lambda: None,
        )
        bindings = client.list_folder_access_bindings("b1gFOLDER")
    assert bindings[0]["roleId"] == "storage.viewer"
    url = mock_get.call_args.args[0]
    assert url.startswith(RESOURCE_MANAGER_API)
    assert "folders/b1gFOLDER:listAccessBindings" in url
    assert "iam.api.cloud.yandex.net/iam/v1/folders" not in url


def test_access_keys_use_aws_compatibility_api():
    client = YcManagementClient("token")
    with patch("bucket_scanner.yc.management.httpx.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"accessKeys": [{"id": "aje123", "createdAt": "2020-01-01T00:00:00Z"}]},
            raise_for_status=lambda: None,
        )
        keys = client.list_access_keys("ajeservice")
    assert keys[0]["id"] == "aje123"
    url = mock_get.call_args.args[0]
    assert url.startswith(AWS_COMPAT_API)
    assert url.endswith("/accessKeys")
    assert mock_get.call_args.kwargs["params"]["serviceAccountId"] == "ajeservice"


def test_management_http_error_becomes_management_error():
    client = YcManagementClient("token")
    response = MagicMock(status_code=404, text="not found")
    response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "boom",
        request=MagicMock(),
        response=response,
    )
    with patch("bucket_scanner.yc.management.httpx.get", return_value=response):
        with pytest.raises(ManagementError, match="404"):
            client.list_buckets("b1gFOLDER")


def test_ping_requires_folder_when_possible():
    client = YcManagementClient("token")
    with patch("bucket_scanner.yc.management.httpx.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)
        assert client.ping(folder_id="b1gFOLDER") is True
    assert mock_get.call_args.kwargs["params"]["folderId"] == "b1gFOLDER"


def test_paginate_follows_next_page_token():
    client = YcManagementClient("token")
    pages = [
        MagicMock(
            status_code=200,
            json=lambda: {"buckets": [{"name": "a"}], "nextPageToken": "t2"},
            raise_for_status=lambda: None,
        ),
        MagicMock(
            status_code=200,
            json=lambda: {"buckets": [{"name": "b"}]},
            raise_for_status=lambda: None,
        ),
    ]
    with patch("bucket_scanner.yc.management.httpx.get", side_effect=pages):
        buckets = client.list_buckets("b1gFOLDER")
    assert [item["name"] for item in buckets] == ["a", "b"]


def test_yc_anonymous_flags_finding_without_s3_keys():
    bucket = BucketSnapshot(
        name="public-demo",
        cloud="yandex",
        metadata_known=False,
        anonymous_access_flags={"read": True, "list": True},
        partial_metadata=["versioning"],
    )
    rules = {item.rule_id for item in check_bucket(bucket)}
    assert "yc/anonymous-read-enabled" in rules
    assert "yc/anonymous-list-enabled" in rules
    assert "metadata/limited" in rules
    assert "encryption/disabled" not in rules


def test_policy_principal_list_star():
    assert _principal_is_wildcard({"AWS": ["*"]})
    assert _principal_is_wildcard("*")
    assert _principal_is_wildcard({"AWS": "*"})
    assert not _principal_is_wildcard({"AWS": "arn:aws:iam::123:root"})

    bucket = BucketSnapshot(
        name="policy-demo",
        policy={"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "s3:*"}]},
    )
    rules = {item.rule_id for item in check_bucket(bucket)}
    assert "policy/overly-permissive" in rules


def test_classify_acl_full_control_is_read_write():
    grants = [
        {
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
            "Permission": "FULL_CONTROL",
        }
    ]
    assert classify_acl(grants) == "public-read-write"


def test_safe_s3_call_returns_error_code():
    client = MagicMock()
    from botocore.exceptions import ClientError

    client.get_bucket_acl.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"}},
        "GetBucketAcl",
    )
    data, code = safe_s3_call(client, "get_bucket_acl", Bucket="x")
    assert data is None
    assert code == "AccessDenied"


def test_access_denied_encryption_not_false_positive():
    bucket = BucketSnapshot(
        name="denied",
        encryption_enabled=False,
        partial_metadata=["encryption"],
        logging_enabled=True,
        versioning_enabled=True,
    )
    rules = {item.rule_id for item in check_bucket(bucket)}
    assert "encryption/disabled" not in rules
    assert "metadata/partial" in rules
