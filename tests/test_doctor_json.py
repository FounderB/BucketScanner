"""Doctor JSON and cloud override tests."""

from __future__ import annotations

import json
from unittest.mock import patch

from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig
from bucket_scanner.doctor import build_doctor_report


@patch("bucket_scanner.doctor.resolve_credentials")
def test_doctor_json_cloud_override(mock_creds):
    mock_creds.return_value.source = "env"
    config = ScanConfig(cloud=CloudProvider.YANDEX, folder_id="b1test", aws_region="eu-west-1")
    report = build_doctor_report(cloud=CloudProvider.AWS, config=config)
    assert report["cloud"] == "aws"
    assert report["command"] == "doctor"
    assert json.loads(json.dumps(report))["exit_code"] == report["exit_code"]
    assert any(item["name"] == "aws_region" for item in report["checks"])
