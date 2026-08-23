"""Azure Blob Storage backend tests (fixture-first)."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from bucket_scanner.auth import CredentialError, resolve_credentials
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
    assert len(keys) == 1


def test_azure_fixture_finds_public_access_rules():
    _, buckets, _ = load_fixture(AZURE_FIXTURE)
    findings = check_bucket(buckets[0])
    rules = {item.rule_id for item in findings}
    assert "azure/container-public-access" in rules
    assert "azure/account-public-access-enabled" in rules
    assert "acl/public-read" in rules


def test_run_scan_azure_fixture():
    config = ScanConfig(cloud=CloudProvider.AZURE)
    report = run_scan(folder_id=None, fixture=AZURE_FIXTURE, config=config)
    assert report.cloud == "azure"
    assert report.folder_id == "sub-FAKE-AZURE-00000001"
    assert report.summary.buckets_scanned == 2


def test_run_scan_azure_live_not_implemented():
    config = ScanConfig(cloud=CloudProvider.AZURE)
    with pytest.raises(ScanError, match="not implemented"):
        run_scan(folder_id=None, fixture=None, config=config)


def test_resolve_credentials_azure_raises():
    with pytest.raises(CredentialError, match="not supported"):
        resolve_credentials(cloud=CloudProvider.AZURE)


def test_doctor_azure_fixture_mode(monkeypatch):
    mock_cfg = MagicMock()
    mock_cfg.scan = ScanConfig(cloud=CloudProvider.AZURE)
    monkeypatch.setattr("bucket_scanner.doctor.load_config", lambda: mock_cfg)
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
