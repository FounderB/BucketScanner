"""AWS backend tests."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from bucket_scanner.auth import resolve_aws_credentials, resolve_credentials
from bucket_scanner.aws.s3 import (
    build_aws_s3_client,
    get_account_public_access_block,
    list_bucket_names,
    resolve_account_id,
    resolve_bucket_region,
    snapshot_aws_bucket,
)
from bucket_scanner.checks import check_bucket
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig, load_config
from bucket_scanner.doctor import run_doctor
from bucket_scanner.fixture import load_fixture
from bucket_scanner.models import BucketSnapshot
from bucket_scanner.probe import _probe_urls
from bucket_scanner.s3_common import classify_acl, snapshot_bucket
from bucket_scanner.scan import run_scan

AWS_FIXTURE = Path("examples/demo-vulnerable/fixture-aws.toml")


def test_cloud_provider_parse():
    assert CloudProvider.parse(None) == CloudProvider.YANDEX
    assert CloudProvider.parse("aws") == CloudProvider.AWS
    assert CloudProvider.parse("s3") == CloudProvider.AWS
    assert CloudProvider.parse("yandex") == CloudProvider.YANDEX
    assert CloudProvider.parse("gcp") == CloudProvider.GCS
    with pytest.raises(ValueError):
        CloudProvider.parse("unknown-cloud")


def test_resolve_aws_credentials_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    creds = resolve_aws_credentials()
    assert creds.cloud == CloudProvider.AWS
    assert creds.region == "eu-west-1"
    assert creds.source == "env-keys"


def test_resolve_credentials_routes_aws():
    with patch("bucket_scanner.auth.resolve_aws_credentials") as mock_aws:
        mock_aws.return_value = MagicMock(cloud=CloudProvider.AWS)
        resolve_credentials(cloud=CloudProvider.AWS, region="us-east-1")
        mock_aws.assert_called_once_with(region="us-east-1", profile=None)


def test_classify_acl_public_read():
    grants = [
        {
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
            "Permission": "READ",
        }
    ]
    assert classify_acl(grants) == "public-read"


def test_probe_urls_aws_us_east_1():
    bucket = BucketSnapshot(name="my-bucket", cloud="aws", region="us-east-1")
    bucket_url, list_url = _probe_urls(bucket)
    assert bucket_url == "https://my-bucket.s3.amazonaws.com/"
    assert list_url.endswith("?max-keys=1")


def test_probe_urls_aws_other_region():
    bucket = BucketSnapshot(name="my-bucket", cloud="aws", region="eu-west-1")
    bucket_url, _ = _probe_urls(bucket)
    assert bucket_url == "https://my-bucket.s3.eu-west-1.amazonaws.com/"


def test_load_aws_fixture():
    folder_id, buckets, keys = load_fixture(AWS_FIXTURE)
    assert folder_id == "123456789012"
    assert buckets[0].cloud == "aws"
    assert buckets[0].block_public_access["BlockPublicAcls"] is False
    assert len(keys) == 1


def test_aws_fixture_finds_bpa_and_public_acl():
    _, buckets, _ = load_fixture(AWS_FIXTURE)
    findings = check_bucket(buckets[0])
    rules = {item.rule_id for item in findings}
    assert "acl/public-read" in rules
    assert "aws/block-public-access-incomplete" in rules
    assert "aws/account-public-access-incomplete" in rules


def test_run_scan_aws_fixture():
    config = ScanConfig(cloud=CloudProvider.AWS)
    report = run_scan(folder_id=None, fixture=AWS_FIXTURE, config=config)
    assert report.cloud == "aws"
    assert report.folder_id == "123456789012"
    assert report.summary.buckets_scanned == 2


def test_list_bucket_names():
    client = MagicMock()
    client.list_buckets.return_value = {"Buckets": [{"Name": "a"}, {"Name": "b"}]}
    assert list_bucket_names(client) == ["a", "b"]


@patch("bucket_scanner.aws.s3.safe_s3_call")
def test_get_account_public_access_block(mock_safe):
    mock_safe.return_value = {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
    }
    credentials = MagicMock(profile=None, region="us-east-1")
    credentials.access_key_id = None
    credentials.secret_access_key = None
    result = get_account_public_access_block(credentials, "123456789012")
    assert result == {"BlockPublicAcls": True}


@patch("bucket_scanner.aws.s3.snapshot_bucket")
def test_snapshot_aws_bucket_merges_account_bpa(mock_snapshot):
    mock_snapshot.return_value = BucketSnapshot(name="x", cloud="aws")
    client = MagicMock()
    account_bpa = {"BlockPublicAcls": False}
    snapshot = snapshot_aws_bucket(
        client,
        "x",
        account_id="123",
        region="us-east-1",
        account_public_access_block=account_bpa,
    )
    assert snapshot.account_public_access_block == account_bpa


@patch("bucket_scanner.s3_common.safe_s3_call")
def test_snapshot_bucket_aws_sets_bpa(mock_safe):
    mock_safe.side_effect = [
        {"Grants": []},
        None,
        None,
        None,
        None,
        None,
        None,
        {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}},
    ]
    client = MagicMock()
    snapshot = snapshot_bucket(
        client,
        "demo",
        cloud=CloudProvider.AWS,
        scope_id="123",
        region="us-east-1",
    )
    assert snapshot.cloud == "aws"
    assert snapshot.block_public_access == {"BlockPublicAcls": True}


@patch("bucket_scanner.scan.list_iam_access_keys")
@patch("bucket_scanner.scan.get_account_public_access_block")
@patch("bucket_scanner.scan.resolve_bucket_region")
@patch("bucket_scanner.scan.resolve_account_id")
@patch("bucket_scanner.scan.snapshot_aws_bucket")
@patch("bucket_scanner.scan.list_bucket_names")
@patch("bucket_scanner.scan.build_aws_s3_client")
@patch("bucket_scanner.scan.resolve_credentials")
def test_live_aws_scan_with_mocks(
    mock_creds,
    mock_s3,
    mock_names,
    mock_snapshot,
    mock_account,
    mock_region,
    mock_bpa,
    mock_iam,
):
    mock_creds.return_value = MagicMock(
        cloud=CloudProvider.AWS,
        region="us-east-1",
        access_key_id="id",
        secret_access_key="secret",
    )
    mock_names.return_value = ["demo"]
    mock_account.return_value = "123456789012"
    mock_region.return_value = "eu-west-1"
    mock_bpa.return_value = {"BlockPublicAcls": False}
    mock_snapshot.return_value = BucketSnapshot(
        name="demo",
        cloud="aws",
        acl="private",
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        metadata_known=True,
    )
    mock_iam.return_value = []
    config = ScanConfig(cloud=CloudProvider.AWS)
    report = run_scan(folder_id=None, fixture=None, config=config)
    assert report.cloud == "aws"
    assert report.folder_id == "123456789012"
    assert report.method == "live"
    mock_region.assert_called_once()


def test_resolve_bucket_region_us_east_1():
    client = MagicMock()
    client.get_bucket_location.return_value = {"LocationConstraint": None}
    assert resolve_bucket_region(client, "demo", default="us-west-2") == "us-east-1"


def test_resolve_bucket_region_eu_legacy():
    client = MagicMock()
    client.get_bucket_location.return_value = {"LocationConstraint": "EU"}
    assert resolve_bucket_region(client, "demo", default="us-east-1") == "eu-west-1"


@patch("bucket_scanner.doctor.build_aws_s3_client")
@patch("bucket_scanner.doctor.build_aws_sts_client")
@patch("bucket_scanner.doctor.resolve_account_id")
@patch("bucket_scanner.doctor.resolve_credentials")
@patch("bucket_scanner.doctor.load_config")
def test_doctor_aws_ok(mock_load, mock_creds, mock_account, mock_sts, mock_s3):
    mock_cfg = MagicMock()
    mock_cfg.scan.cloud = CloudProvider.AWS
    mock_cfg.scan.aws_region = "us-east-1"
    mock_cfg.scan.aws_profile = None
    mock_load.return_value = mock_cfg
    mock_creds.return_value = MagicMock(source="profile", region="us-east-1")
    mock_account.return_value = "123456789012"
    mock_sts.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_s3.return_value.list_buckets.return_value = {"Buckets": []}
    assert run_doctor(Console(file=StringIO())) == 0


@patch("bucket_scanner.aws.s3.boto3.Session")
def test_build_aws_s3_client_with_profile(mock_session):
    mock_session.return_value.client.return_value = MagicMock()
    credentials = MagicMock(
        profile="dev",
        region="us-east-1",
        access_key_id=None,
        secret_access_key=None,
        session_token=None,
    )
    build_aws_s3_client(credentials)
    mock_session.assert_called_once_with(profile_name="dev")


@patch("bucket_scanner.aws.s3.build_aws_sts_client")
def test_resolve_account_id(mock_sts):
    mock_sts.return_value.get_caller_identity.return_value = {"Account": "999"}
    credentials = MagicMock()
    assert resolve_account_id(credentials) == "999"


def test_config_loads_cloud_aws(tmp_path: Path):
    config_path = tmp_path / ".bucket-scanner.toml"
    config_path.write_text(
        '[scan]\ncloud = "aws"\naws_region = "eu-central-1"\n'
        'terraform_path = "terraform-aws"\n',
        encoding="utf-8",
    )
    cfg = load_config(config_path)
    assert cfg.scan.cloud == CloudProvider.AWS
    assert cfg.scan.aws_region == "eu-central-1"
    assert cfg.scan.terraform_path == Path("terraform-aws")


@patch("bucket_scanner.aws.iam.boto3.Session")
def test_iam_over_privileged_policy(mock_session):
    from bucket_scanner.aws.iam import list_iam_access_keys
    from bucket_scanner.checks import check_service_accounts

    iam = MagicMock()
    mock_session.return_value.client.return_value = iam
    iam.get_paginator.return_value.paginate.return_value = [
        {"Users": [{"UserName": "deploy-bot"}]}
    ]
    iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "AmazonS3FullAccess"}]
    }
    iam.list_user_policies.return_value = {"PolicyNames": []}
    iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [{"AccessKeyId": "AKIA123", "CreateDate": None}]
    }
    credentials = MagicMock(profile=None, region="us-east-1")
    credentials.access_key_id = "x"
    credentials.secret_access_key = "y"
    keys = list_iam_access_keys(credentials)
    rules = {item.rule_id for item in check_service_accounts(keys)}
    assert "iam/over-privileged-sa" in rules
