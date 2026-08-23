"""Auth, doctor, report, and S3 helper tests."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from bucket_scanner.auth import CredentialError, resolve_credentials
from bucket_scanner.cli import main
from bucket_scanner.config import load_config
from bucket_scanner.doctor import run_doctor
from bucket_scanner.report.human import render_human
from bucket_scanner.scan import run_scan
from bucket_scanner.yc.s3 import _classify_acl

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")


def test_resolve_credentials_missing(monkeypatch):
    monkeypatch.delenv("YC_TOKEN", raising=False)
    monkeypatch.delenv("YC_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    with pytest.raises(CredentialError):
        resolve_credentials()


def test_resolve_credentials_static_keys(monkeypatch):
    monkeypatch.setenv("YC_ACCESS_KEY_ID", "FAKEKEY")
    monkeypatch.setenv("YC_SECRET_ACCESS_KEY", "FAKESECRET")
    creds = resolve_credentials()
    assert creds.access_key_id == "FAKEKEY"
    assert creds.source == "static-keys"


def test_doctor_missing_credentials(monkeypatch):
    monkeypatch.delenv("YC_TOKEN", raising=False)
    monkeypatch.delenv("YC_ACCESS_KEY_ID", raising=False)
    assert run_doctor(Console(file=StringIO())) == 2


@patch("bucket_scanner.doctor.load_config")
@patch("bucket_scanner.doctor.resolve_credentials")
@patch("bucket_scanner.yc.management.YcManagementClient")
def test_doctor_ok(mock_client, mock_creds, mock_load_config):
    from bucket_scanner.cloud import CloudProvider

    mock_cfg = MagicMock()
    mock_cfg.scan.folder_id = "b1gTEST"
    mock_cfg.scan.cloud = CloudProvider.YANDEX
    mock_cfg.scan.aws_region = None
    mock_cfg.scan.aws_profile = None
    mock_load_config.return_value = mock_cfg
    mock_creds.return_value = MagicMock(
        source="iam-token",
        iam_token="token",
        access_key_id="id",
        secret_access_key="secret",
    )
    mock_client.return_value.ping.return_value = True
    assert run_doctor(Console(file=StringIO())) == 0


def test_human_report_renders():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    console = Console(record=True)
    render_human(report, console)
    text = console.export_text()
    assert "BUCKET SCANNER" in text
    assert "prod-backups-open" in text


def test_classify_acl_public_read():
    grants = [
        {
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
            "Permission": "READ",
        }
    ]
    assert _classify_acl(grants) == "public-read"


def test_classify_acl_private():
    grants = [{"Grantee": {"ID": "owner"}, "Permission": "FULL_CONTROL"}]
    assert _classify_acl(grants) == "private"


def test_cli_diff_command():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            "examples/demo-vulnerable/terraform",
            "--fixture",
            str(FIXTURE),
            "--json",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert any(item["rule_id"].startswith("iac/") for item in payload["findings"])


@patch("bucket_scanner.scan.resolve_credentials")
@patch("bucket_scanner.scan.YcManagementClient")
@patch("bucket_scanner.scan.build_s3_client")
@patch("bucket_scanner.scan.snapshot_yandex_bucket")
def test_live_scan_with_mocks(mock_snapshot, mock_s3, mock_mgmt, mock_creds):
    mock_creds.return_value = MagicMock(
        iam_token="token",
        access_key_id="id",
        secret_access_key="secret",
    )
    mock_mgmt.return_value.list_buckets.return_value = [{"name": "b1"}]
    mock_mgmt.return_value.list_folder_access_bindings.return_value = []
    mock_mgmt.return_value.list_service_accounts.return_value = []
    from bucket_scanner.models import BucketSnapshot

    mock_snapshot.return_value = BucketSnapshot(
        name="b1",
        acl="private",
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        metadata_known=True,
    )
    report = run_scan(folder_id="b1gTEST", fixture=None, config=load_config().scan)
    assert report.method == "live"
    assert report.summary.buckets_scanned == 1
