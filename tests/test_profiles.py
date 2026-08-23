"""Scan profiles and multi-folder YC scan tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from bucket_scanner.cli import main
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig, ScanProfile, load_config
from bucket_scanner.models import BucketSnapshot
from bucket_scanner.scan import resolve_folder_ids, run_scan

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")
AWS_FIXTURE = Path("examples/demo-vulnerable/fixture-aws.toml")


def test_resolve_folder_ids_prefers_cli_folder_id():
    config = ScanConfig(folder_id="single", folder_ids=["a", "b"])
    assert resolve_folder_ids(config, "cli") == ["cli"]


def test_resolve_folder_ids_uses_folder_ids():
    config = ScanConfig(folder_id="single", folder_ids=["a", "b"])
    assert resolve_folder_ids(config) == ["a", "b"]


def test_resolve_folder_ids_falls_back_to_folder_id():
    config = ScanConfig(folder_id="single")
    assert resolve_folder_ids(config) == ["single"]


def test_scan_profile_apply_to():
    config = ScanConfig(folder_id="old", cloud="yandex")
    profile = ScanProfile(
        name="demo",
        cloud="aws",
        folder_ids=["b1g-a", "b1g-b"],
        aws_region="eu-west-1",
        probe=True,
        fixture=AWS_FIXTURE,
    )
    profile.apply_to(config)
    assert config.cloud == CloudProvider.AWS
    assert config.folder_ids == ["b1g-a", "b1g-b"]
    assert config.folder_id is None or config.folder_id == "old"
    assert config.aws_region == "eu-west-1"
    assert config.probe is True


def test_load_profiles_from_toml(tmp_path: Path):
    config_path = tmp_path / ".bucket-scanner.toml"
    config_path.write_text(
        """
[[profiles]]
name = "aws-demo"
cloud = "aws"
fixture = "examples/demo-vulnerable/fixture-aws.toml"

[[profiles]]
name = "yc-prod"
folder_ids = ["b1gfolder-prod", "b1gfolder-backup"]
probe = true
""",
        encoding="utf-8",
    )
    app = load_config(config_path)
    assert set(app.profiles) == {"aws-demo", "yc-prod"}
    assert app.profiles["yc-prod"].folder_ids == ["b1gfolder-prod", "b1gfolder-backup"]
    assert app.profiles["aws-demo"].fixture == AWS_FIXTURE


def test_cli_profiles_list(tmp_path: Path):
    config_path = tmp_path / ".bucket-scanner.toml"
    config_path.write_text(
        """
[[profiles]]
name = "demo"
cloud = "yandex"
folder_id = "b1gTEST"
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(main, ["profiles", "list", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "demo" in result.output
    assert "cloud=yandex" in result.output


def test_cli_scan_with_profile(tmp_path: Path):
    config_path = tmp_path / ".bucket-scanner.toml"
    config_path.write_text(
        f"""
[[profiles]]
name = "offline"
cloud = "yandex"
fixture = "{FIXTURE.as_posix()}"
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "--profile", "offline", "--config", str(config_path), "--json", "-q"],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["method"] == "fixture"
    assert payload["scope_ids"]


@patch("bucket_scanner.scan.resolve_credentials")
@patch("bucket_scanner.scan.YcManagementClient")
@patch("bucket_scanner.scan.build_s3_client")
@patch("bucket_scanner.scan.snapshot_yandex_bucket")
def test_multi_folder_yandex_scan(mock_snapshot, mock_s3, mock_mgmt, mock_creds):
    mock_creds.return_value = MagicMock(
        iam_token="token",
        access_key_id="id",
        secret_access_key="secret",
    )

    def buckets_for_folder(folder_id: str):
        if folder_id == "b1gA":
            return [{"name": "bucket-a"}]
        if folder_id == "b1gB":
            return [{"name": "bucket-b"}]
        return []

    mock_mgmt.return_value.list_buckets.side_effect = buckets_for_folder
    mock_mgmt.return_value.list_folder_access_bindings.return_value = []
    mock_mgmt.return_value.list_service_accounts.return_value = []
    mock_snapshot.side_effect = lambda _s3, name, folder_id=None: BucketSnapshot(
        name=name,
        folder_id=folder_id,
        acl="private",
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        metadata_known=True,
    )

    config = ScanConfig(folder_ids=["b1gA", "b1gB"])
    report = run_scan(folder_id=None, fixture=None, config=config)
    assert report.method == "live"
    assert report.scope_ids == ["b1gA", "b1gB"]
    assert report.folder_id == "b1gA,b1gB"
    assert report.summary.buckets_scanned == 2
    assert {bucket.name for bucket in report.buckets} == {"bucket-a", "bucket-b"}


@patch("bucket_scanner.scan.collect_gcs_buckets")
@patch("bucket_scanner.scan.resolve_credentials")
def test_multi_project_gcs_scan(mock_creds, mock_collect):
    mock_creds.return_value = MagicMock(folder_id=None)
    mock_collect.side_effect = lambda _c, project_id, ignore: [
        BucketSnapshot(
            name=f"bucket-{project_id}",
            cloud="gcs",
            folder_id=project_id,
            acl="private",
        )
    ]

    config = ScanConfig(cloud=CloudProvider.GCS, folder_ids=["proj-a", "proj-b"])
    report = run_scan(folder_id=None, fixture=None, config=config)
    assert report.method == "live"
    assert report.scope_ids == ["proj-a", "proj-b"]
    assert report.summary.buckets_scanned == 2


@patch("bucket_scanner.scan.collect_azure_containers")
@patch("bucket_scanner.scan.resolve_credentials")
def test_multi_subscription_azure_scan(mock_creds, mock_collect):
    mock_creds.return_value = MagicMock(subscription_id=None)
    mock_collect.side_effect = lambda _c, subscription_id, ignore: [
        BucketSnapshot(
            name=f"container-{subscription_id[:4]}",
            cloud="azure",
            folder_id=subscription_id,
            acl="private",
        )
    ]

    config = ScanConfig(
        cloud=CloudProvider.AZURE,
        folder_ids=["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"],
    )
    report = run_scan(folder_id=None, fixture=None, config=config)
    assert report.method == "live"
    assert len(report.scope_ids) == 2
    assert report.summary.buckets_scanned == 2


def test_scan_profile_baseline_path():
    config = ScanConfig()
    profile = ScanProfile(
        name="demo",
        baseline_path=Path("baselines/yc-prod.json"),
    )
    profile.apply_to(config)
    assert config.baseline_path == Path("baselines/yc-prod.json")


def test_cli_unknown_profile(tmp_path: Path):
    config_path = tmp_path / ".bucket-scanner.toml"
    config_path.write_text("[scan]\nfolder_id = \"b1gTEST\"\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--profile", "missing", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "Unknown profile" in result.output
