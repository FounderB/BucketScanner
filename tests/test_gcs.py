"""Google Cloud Storage backend tests (fixture-first)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bucket_scanner.checks import check_bucket
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig
from bucket_scanner.fixture import load_fixture
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
    assert "acl/public-read" in rules


def test_run_scan_gcs_fixture():
    config = ScanConfig(cloud=CloudProvider.GCS)
    report = run_scan(folder_id=None, fixture=GCS_FIXTURE, config=config)
    assert report.cloud == "gcs"
    assert report.folder_id == "project-FAKE-GCS-00000001"
    assert report.summary.buckets_scanned == 2


def test_run_scan_gcs_live_not_implemented():
    config = ScanConfig(cloud=CloudProvider.GCS)
    with pytest.raises(ScanError, match="not implemented"):
        run_scan(
            folder_id="project-FAKE-GCS-00000001",
            fixture=None,
            config=config,
        )


def test_probe_urls_gcs():
    bucket = BucketSnapshot(name="logs", cloud="gcs")
    bucket_url, list_url = _probe_urls(bucket)
    assert bucket_url == "https://storage.googleapis.com/logs/"
    assert "maxResults=1" in list_url
