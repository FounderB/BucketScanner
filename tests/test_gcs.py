"""Google Cloud Storage backend tests."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from bucket_scanner.auth import resolve_credentials
from bucket_scanner.checks import check_bucket
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig
from bucket_scanner.doctor import run_doctor
from bucket_scanner.fixture import load_fixture
from bucket_scanner.gcs.storage import GcsDependencyError, collect_gcs_buckets, snapshot_gcs_bucket
from bucket_scanner.models import BucketSnapshot
from bucket_scanner.probe import _probe_urls
from bucket_scanner.scan import ScanError, run_scan

GCS_FIXTURE = Path("examples/demo-vulnerable/fixture-gcs.toml")


def test_cloud_provider_parse_gcs():
    assert CloudProvider.parse("gcs") == CloudProvider.GCS
    assert CloudProvider.parse("gcp") == CloudProvider.GCS


def test_load_gcs_fixture():
    folder_id, buckets, keys = load_fixture(GCS_FIXTURE)
    assert folder_id.startswith("project-")
    assert buckets[0].cloud == "gcs"
    assert buckets[0].block_public_access["iam_public"] is True
    assert buckets[0].tags["project_id"] == "fake-prod-project"
    assert len(keys) == 1


def test_gcs_fixture_finds_public_access_rules():
    _, buckets, _ = load_fixture(GCS_FIXTURE)
    findings = check_bucket(buckets[0])
    rules = {item.rule_id for item in findings}
    assert "gcs/iam-public-principal" in rules
    assert "gcs/public-access-prevention-not-enforced" in rules
    assert "gcs/uniform-access-disabled" in rules
    assert "acl/public-read" not in rules


def test_run_scan_gcs_fixture():
    config = ScanConfig(cloud=CloudProvider.GCS)
    report = run_scan(folder_id=None, fixture=GCS_FIXTURE, config=config)
    assert report.cloud == "gcs"
    assert report.folder_id == "project-FAKE-GCS-00000001"
    assert report.summary.buckets_scanned == 2


def test_run_scan_gcs_live_missing_project():
    config = ScanConfig(cloud=CloudProvider.GCS)
    with pytest.raises(ScanError, match="project"):
        run_scan(folder_id=None, fixture=None, config=config)


def test_run_scan_gcs_live_missing_dependencies(monkeypatch):
    config = ScanConfig(cloud=CloudProvider.GCS)

    def _boom(*args, **kwargs):
        raise GcsDependencyError("pip install bucket-scanner[gcs]")

    monkeypatch.setattr("bucket_scanner.scan.collect_gcs_buckets", _boom)
    with pytest.raises(ScanError, match="gcs"):
        run_scan(folder_id="fake-prod-project", fixture=None, config=config)


def test_resolve_credentials_gcs_from_env(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "my-project")
    creds = resolve_credentials(cloud=CloudProvider.GCS)
    assert creds.folder_id == "my-project"
    assert creds.cloud == CloudProvider.GCS


def test_doctor_gcs_live_mode(monkeypatch):
    mock_cfg = MagicMock()
    mock_cfg.scan = ScanConfig(cloud=CloudProvider.GCS, folder_id="my-project")
    monkeypatch.setattr("bucket_scanner.doctor.load_config", lambda: mock_cfg)
    with patch(
        "bucket_scanner.gcs.storage._import_gcs",
        return_value=MagicMock(),
    ):
        assert run_doctor(Console(file=StringIO())) == 0


def test_probe_urls_gcs():
    bucket = BucketSnapshot(name="logs", cloud="gcs")
    bucket_url, list_url = _probe_urls(bucket)
    assert bucket_url == "https://storage.googleapis.com/logs/"
    assert "maxResults=1" in list_url


def test_snapshot_gcs_bucket():
    bucket = snapshot_gcs_bucket(
        name="open-data",
        project_id="my-project",
        region="US",
        public_access_prevention="inherited",
        uniform_bucket_level_access=False,
        iam_public=True,
        encryption_enabled=True,
        logging_enabled=False,
        versioning_enabled=False,
    )
    assert bucket.acl == "public-read"
    assert bucket.tags["project_id"] == "my-project"


def test_collect_gcs_buckets_mocked():
    iam_config = SimpleNamespace(
        public_access_prevention="inherited",
        uniform_bucket_level_access_enabled=False,
    )
    live_bucket = SimpleNamespace(
        name="open-data",
        location="US",
        iam_configuration=iam_config,
        logging=None,
        versioning_enabled=False,
        reload=MagicMock(),
        get_iam_policy=MagicMock(
            return_value=SimpleNamespace(
                bindings=[{"members": ["allUsers"], "role": "roles/storage.objectViewer"}],
            ),
        ),
    )
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = [live_bucket]
    mock_storage = MagicMock()
    mock_storage.Client.return_value = mock_client

    with patch("bucket_scanner.gcs.storage._import_gcs", return_value=mock_storage):
        creds = resolve_credentials(cloud=CloudProvider.GCS)
        buckets = collect_gcs_buckets(creds, project_id="my-project", ignore=set())

    assert len(buckets) == 1
    assert buckets[0].name == "open-data"
    assert buckets[0].block_public_access["iam_public"] is True


def test_run_scan_gcs_live_mocked(monkeypatch):
    bucket = snapshot_gcs_bucket(
        name="open-data",
        project_id="my-project",
        region="US",
        public_access_prevention="inherited",
        uniform_bucket_level_access=False,
        iam_public=True,
        encryption_enabled=True,
        logging_enabled=False,
        versioning_enabled=False,
    )

    def _collect(*args, **kwargs):
        return [bucket]

    monkeypatch.setattr("bucket_scanner.scan.collect_gcs_buckets", _collect)
    config = ScanConfig(cloud=CloudProvider.GCS)
    report = run_scan(folder_id="my-project", fixture=None, config=config)
    assert report.method == "live"
    assert report.summary.buckets_scanned == 1
    assert any(item.rule_id == "gcs/iam-public-principal" for item in report.findings)
