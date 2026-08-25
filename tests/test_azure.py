"""Azure Blob Storage backend tests."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from bucket_scanner.auth import resolve_credentials
from bucket_scanner.azure.storage import (
    AzureDependencyError,
    collect_azure_containers,
    snapshot_azure_container,
)
from bucket_scanner.checks import check_bucket
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig
from bucket_scanner.doctor import run_doctor
from bucket_scanner.fixture import load_fixture
from bucket_scanner.models import BucketSnapshot
from bucket_scanner.probe import _probe_urls
from bucket_scanner.scan import ScanError, run_scan

AZURE_FIXTURE = Path("examples/demo-vulnerable/fixture-azure.toml")


def test_cloud_provider_parse_azure():
    assert CloudProvider.parse("azure") == CloudProvider.AZURE
    assert CloudProvider.parse("blob") == CloudProvider.AZURE


def test_load_azure_fixture():
    folder_id, buckets, keys = load_fixture(AZURE_FIXTURE)
    assert folder_id.startswith("sub-")
    assert buckets[0].cloud == "azure"
    assert buckets[0].block_public_access["public_access"] == "container"
    assert buckets[0].tags["storage_account"] == "fakeprodstorage"
    assert len(keys) == 1


def test_azure_fixture_finds_public_access_rules():
    _, buckets, _ = load_fixture(AZURE_FIXTURE)
    findings = check_bucket(buckets[0])
    rules = {item.rule_id for item in findings}
    assert "azure/container-public-access" in rules
    assert "azure/account-public-access-enabled" in rules
    assert "acl/public-read" not in rules


def test_run_scan_azure_fixture():
    config = ScanConfig(cloud=CloudProvider.AZURE)
    report = run_scan(folder_id=None, fixture=AZURE_FIXTURE, config=config)
    assert report.cloud == "azure"
    assert report.folder_id == "sub-FAKE-AZURE-00000001"
    assert report.summary.buckets_scanned == 2


def test_run_scan_azure_live_missing_subscription():
    config = ScanConfig(cloud=CloudProvider.AZURE)
    with pytest.raises(ScanError, match="subscription"):
        run_scan(folder_id=None, fixture=None, config=config)


def test_run_scan_azure_live_missing_dependencies(monkeypatch):
    config = ScanConfig(cloud=CloudProvider.AZURE)

    def _boom(*args, **kwargs):
        raise AzureDependencyError("pip install bucket-scanner[azure]")

    monkeypatch.setattr("bucket_scanner.scan.collect_azure_containers", _boom)
    with pytest.raises(ScanError, match="azure"):
        run_scan(
            folder_id="sub-00000000-0000-0000-0000-000000000001",
            fixture=None,
            config=config,
        )


def test_resolve_credentials_azure_from_env(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-test")
    creds = resolve_credentials(cloud=CloudProvider.AZURE)
    assert creds.subscription_id == "sub-test"
    assert creds.cloud == CloudProvider.AZURE


def test_doctor_azure_live_mode(monkeypatch):
    mock_cfg = MagicMock()
    mock_cfg.scan = ScanConfig(cloud=CloudProvider.AZURE, folder_id="sub-test")
    monkeypatch.setattr("bucket_scanner.doctor.load_config", lambda: mock_cfg)
    with patch(
        "bucket_scanner.azure.storage._import_azure",
        return_value=(MagicMock, MagicMock, MagicMock),
    ):
        assert run_doctor(Console(file=StringIO())) == 0


def test_probe_urls_azure():
    bucket = BucketSnapshot(
        name="logs",
        cloud="azure",
        tags={"storage_account": "myaccount"},
    )
    bucket_url, list_url = _probe_urls(bucket)
    assert bucket_url == "https://myaccount.blob.core.windows.net/logs"
    assert "restype=container" in list_url


def test_snapshot_azure_container():
    bucket = snapshot_azure_container(
        container_name="logs",
        subscription_id="sub-1",
        storage_account="acct",
        region="eastus",
        public_access="container",
        account_allow_blob_public_access=True,
        encryption_enabled=True,
        versioning_enabled=False,
    )
    assert bucket.cloud == "azure"
    assert bucket.acl == "public-read"
    assert bucket.tags["storage_account"] == "acct"


def test_collect_azure_containers_mocked():
    account = SimpleNamespace(
        name="acct",
        id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct",
        location="eastus",
    )
    props = SimpleNamespace(
        allow_blob_public_access=True,
        encryption=SimpleNamespace(
            services=SimpleNamespace(blob=SimpleNamespace(enabled=True)),
        ),
        is_versioning_enabled=False,
    )
    container = SimpleNamespace(name="open-data", public_access="container")

    mock_mgmt = MagicMock()
    mock_mgmt.storage_accounts.list.return_value = [account]
    mock_mgmt.storage_accounts.get_properties.return_value = props

    mock_blob_service = MagicMock()
    mock_blob_service.list_containers.return_value = [container]

    mock_blob_cls = MagicMock(return_value=mock_blob_service)
    mock_mgmt_cls = MagicMock(return_value=mock_mgmt)

    with patch(
        "bucket_scanner.azure.storage._import_azure",
        return_value=(MagicMock, mock_mgmt_cls, mock_blob_cls),
    ):
        creds = resolve_credentials(cloud=CloudProvider.AZURE)
        buckets = collect_azure_containers(
            creds,
            subscription_id="sub-1",
            ignore=set(),
        )

    assert len(buckets) == 1
    assert buckets[0].name == "open-data"
    assert buckets[0].block_public_access["public_access"] == "container"


def test_run_scan_azure_live_mocked(monkeypatch):
    bucket = snapshot_azure_container(
        container_name="open-data",
        subscription_id="sub-1",
        storage_account="acct",
        region="eastus",
        public_access="container",
        account_allow_blob_public_access=True,
        encryption_enabled=False,
        versioning_enabled=False,
    )

    def _collect(*args, **kwargs):
        return [bucket]

    monkeypatch.setattr("bucket_scanner.scan.collect_azure_containers", _collect)
    config = ScanConfig(cloud=CloudProvider.AZURE)
    report = run_scan(
        folder_id="sub-1",
        fixture=None,
        config=config,
    )
    assert report.method == "live"
    assert report.summary.buckets_scanned == 1
    assert any(item.rule_id == "azure/container-public-access" for item in report.findings)
