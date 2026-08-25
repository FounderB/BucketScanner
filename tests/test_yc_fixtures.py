"""VCR-style fixtures: realistic YC JSON responses + enrichment / findings."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from bucket_scanner.auth import Credentials
from bucket_scanner.checks import check_bucket
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import BucketSnapshot, Severity
from bucket_scanner.scan import _collect_yandex_data, _maybe_ephemeral_credentials
from bucket_scanner.yc.enrich import enrich_from_bucket_get, snapshot_from_bucket_get
from bucket_scanner.yc.management import (
    AWS_COMPAT_API,
    RESOURCE_MANAGER_API,
    STORAGE_API,
    YcManagementClient,
)

FIXTURES = Path(__file__).parent / "fixtures" / "yc"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_fixture_get_bucket_view_full_shape():
    detail = _load("get_bucket_view_full.json")
    assert detail["name"] == "bucket-public-assets"
    assert "anonymousAccessFlags" in detail
    assert detail["anonymousAccessFlags"]["configRead"] is True
    assert detail["acl"]["grants"]
    assert detail["policy"]["Statement"]
    assert detail["cors"]
    assert detail["websiteSettings"]["index"]
    assert "encryption" in detail


def test_snapshot_from_bucket_get_enriches_acl_policy_website_cors():
    detail = _load("get_bucket_view_full.json")
    snap = snapshot_from_bucket_get(detail, folder_id="b1gFOLDEREXAMPLE")
    assert snap.metadata_known is True
    assert snap.auth_mode == "management-only"
    assert snap.acl == "public-read"
    assert snap.policy is not None
    assert snap.anonymous_access_flags == {
        "read": True,
        "list": False,
        "config_read": True,
    }
    assert snap.website_enabled is True
    assert len(snap.cors_rules) == 1
    assert snap.encryption_enabled is False
    assert "logging" in snap.partial_metadata
    assert "encryption" not in snap.partial_metadata
    assert snap.tags["env"] == "prod"
    assert snap.lifecycle_rules


def test_enrich_preserves_existing_s3_snapshot_fields():
    base = BucketSnapshot(
        name="bucket-public-assets",
        cloud="yandex",
        metadata_known=True,
        auth_mode="ephemeral",
        encryption_enabled=True,
        logging_enabled=True,
        acl="private",
    )
    detail = _load("get_bucket_view_full.json")
    enriched = enrich_from_bucket_get(base, detail)
    assert enriched.auth_mode == "ephemeral"
    assert enriched.encryption_enabled is True  # do not downgrade S3-known encryption
    assert enriched.logging_enabled is True
    assert enriched.acl == "public-read"
    assert enriched.website_enabled is True


def test_medium_findings_for_website_cors_config_read():
    snap = snapshot_from_bucket_get(_load("get_bucket_view_full.json"))
    findings = check_bucket(snap)
    by_id = {f.rule_id: f for f in findings}
    assert by_id["yc/anonymous-config-read-enabled"].severity == Severity.MEDIUM
    assert by_id["yc/website-enabled"].severity == Severity.MEDIUM
    assert by_id["yc/cors-enabled"].severity == Severity.MEDIUM
    assert by_id["yc/anonymous-read-enabled"].severity == Severity.CRITICAL
    assert by_id["acl/public-read"].severity == Severity.CRITICAL


def test_get_bucket_contract_url_and_view_param():
    client = YcManagementClient("token")
    detail = _load("get_bucket_view_full.json")
    with patch("bucket_scanner.yc.management.httpx.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: detail,
            raise_for_status=lambda: None,
        )
        got = client.get_bucket("bucket-public-assets", view="VIEW_FULL")
    assert got["name"] == "bucket-public-assets"
    url = mock_get.call_args.args[0]
    assert url == f"{STORAGE_API}/buckets/bucket-public-assets"
    assert mock_get.call_args.kwargs["params"]["view"] == "VIEW_FULL"


def test_create_ephemeral_access_key_contract():
    client = YcManagementClient("token")
    body = _load("create_ephemeral_access_key.json")
    with patch("bucket_scanner.yc.management.httpx.post") as mock_post:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: body,
            raise_for_status=lambda: None,
        )
        created = client.create_ephemeral_access_key(
            session_name="bucket-scanner-scan",
            duration_seconds=3600,
        )
    assert created["accessKeyId"].startswith("YCAJ")
    assert created["sessionToken"]
    assert created["secret"]
    url = mock_post.call_args.args[0]
    assert url == f"{AWS_COMPAT_API}/ephemeralAccessKeys"
    payload = mock_post.call_args.kwargs["json"]
    assert payload["sessionName"] == "bucket-scanner-scan"
    assert payload["duration"] == "3600s"


def test_maybe_ephemeral_credentials_from_fixture():
    management = YcManagementClient("iam-token")
    creds = Credentials(cloud=CloudProvider.YANDEX, iam_token="iam-token")
    with patch.object(
        management,
        "create_ephemeral_access_key",
        return_value=_load("create_ephemeral_access_key.json"),
    ):
        ephemeral = _maybe_ephemeral_credentials(management, creds)
    assert ephemeral is not None
    assert ephemeral.source == "ephemeral"
    assert ephemeral.session_token
    assert ephemeral.access_key_id == "YCAJephemeralExample01"


def test_maybe_ephemeral_skipped_when_static_keys_present():
    management = YcManagementClient("iam-token")
    creds = Credentials(
        cloud=CloudProvider.YANDEX,
        iam_token="iam-token",
        access_key_id="YCAJstatic",
        secret_access_key="secret",
    )
    assert _maybe_ephemeral_credentials(management, creds) is None


def test_list_fixtures_match_api_keys():
    buckets = _load("list_buckets.json")
    assert "buckets" in buckets
    bindings = _load("list_access_bindings.json")
    assert "accessBindings" in bindings
    keys = _load("list_access_keys.json")
    assert "accessKeys" in keys
    sas = _load("list_service_accounts.json")
    assert "serviceAccounts" in sas


def test_collect_yandex_management_only_uses_bucket_get(monkeypatch):
    """IAM token, ephemeral fails → inventory + Bucket.Get enrichment."""
    folder_id = "b1gFOLDEREXAMPLE"
    list_buckets = _load("list_buckets.json")["buckets"]
    get_detail = _load("get_bucket_view_full.json")
    bindings = _load("list_access_bindings.json")["accessBindings"]
    sas = _load("list_service_accounts.json")["serviceAccounts"]
    access_keys = _load("list_access_keys.json")["accessKeys"]

    client = MagicMock(spec=YcManagementClient)
    client.list_buckets.return_value = list_buckets
    client.list_folder_access_bindings.return_value = bindings
    client.list_service_accounts.return_value = sas
    client.list_access_keys.return_value = access_keys
    client.get_bucket.return_value = get_detail

    monkeypatch.setattr(
        "bucket_scanner.scan._maybe_ephemeral_credentials",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "bucket_scanner.scan.YcManagementClient",
        lambda *_a, **_k: client,
    )

    creds = Credentials(cloud=CloudProvider.YANDEX, iam_token="t", folder_id=folder_id)
    buckets, sa_keys = _collect_yandex_data(folder_id, creds, probe=False, ignore=set())
    assert len(buckets) == 2
    public = next(b for b in buckets if b.name == "bucket-public-assets")
    assert public.metadata_known is True
    assert public.auth_mode == "management-only"
    assert public.acl == "public-read"
    assert public.website_enabled is True
    assert public.cors_rules
    client.get_bucket.assert_called()
    assert any(k.sa_id == "ajeserviceaccount01" for k in sa_keys)


def test_collect_yandex_ephemeral_path_sets_auth_mode(monkeypatch):
    folder_id = "b1gFOLDEREXAMPLE"
    list_buckets = [_load("list_buckets.json")["buckets"][1]]
    get_detail = {
        "name": "bucket-private-logs",
        "folderId": folder_id,
        "anonymousAccessFlags": {"read": False, "list": False, "configRead": False},
        "versioning": "VERSIONING_ENABLED",
        "acl": {"grants": []},
        "encryption": {"rules": [{"sseAlgorithm": "aws:kms", "kmsMasterKeyId": "abjkms"}]},
    }

    client = MagicMock(spec=YcManagementClient)
    client.list_buckets.return_value = list_buckets
    client.list_folder_access_bindings.return_value = []
    client.list_service_accounts.return_value = []
    client.get_bucket.return_value = get_detail

    ephemeral_creds = Credentials(
        cloud=CloudProvider.YANDEX,
        iam_token="t",
        access_key_id="YCAJephemeral",
        secret_access_key="sec",
        session_token="tok",
        source="ephemeral",
    )
    monkeypatch.setattr(
        "bucket_scanner.scan._maybe_ephemeral_credentials",
        lambda *_a, **_k: ephemeral_creds,
    )
    monkeypatch.setattr(
        "bucket_scanner.scan.YcManagementClient",
        lambda *_a, **_k: client,
    )

    fake_snapshot = BucketSnapshot(
        name="bucket-private-logs",
        cloud="yandex",
        folder_id=folder_id,
        metadata_known=True,
        encryption_enabled=True,
        acl="private",
    )
    monkeypatch.setattr(
        "bucket_scanner.scan.build_s3_client",
        lambda _c: MagicMock(),
    )
    monkeypatch.setattr(
        "bucket_scanner.scan.snapshot_yandex_bucket",
        lambda *_a, **_k: fake_snapshot,
    )

    creds = Credentials(cloud=CloudProvider.YANDEX, iam_token="t", folder_id=folder_id)
    buckets, _ = _collect_yandex_data(folder_id, creds, probe=False, ignore=set())
    assert len(buckets) == 1
    assert buckets[0].auth_mode == "ephemeral"
    assert buckets[0].encryption_enabled is True


def test_resource_manager_and_storage_urls_documented_in_fixtures_workflow():
    client = YcManagementClient("token")
    with patch("bucket_scanner.yc.management.httpx.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: _load("list_access_bindings.json"),
            raise_for_status=lambda: None,
        )
        client.list_folder_access_bindings("b1gFOLDEREXAMPLE")
    assert mock_get.call_args.args[0].startswith(RESOURCE_MANAGER_API)
