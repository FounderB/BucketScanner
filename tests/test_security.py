"""Security and notification hardening tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from bucket_scanner.auth import CredentialError, resolve_credentials
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.gate import MAX_BASELINE_BYTES, load_baseline_report
from bucket_scanner.models import ScanReport, ScanSummary
from bucket_scanner.notify import _validate_webhook_url, send_webhook
from bucket_scanner.scope import scope_label_for_cloud


def test_scope_label_for_cloud():
    assert scope_label_for_cloud("aws") == "account"
    assert scope_label_for_cloud("azure") == "subscription"
    assert scope_label_for_cloud("yandex") == "folder"


def test_yc_credentials_do_not_use_aws_env_fallback(monkeypatch):
    monkeypatch.delenv("YC_TOKEN", raising=False)
    monkeypatch.delenv("YC_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("YC_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATESTKEY000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret-value")
    with pytest.raises(CredentialError):
        resolve_credentials(cloud=CloudProvider.YANDEX)


def test_validate_webhook_url_rejects_file_scheme():
    with pytest.raises(ValueError, match="http or https"):
        _validate_webhook_url("file:///etc/passwd")


def test_validate_webhook_url_accepts_https():
    _validate_webhook_url("https://hooks.example.com/bucket-scanner")


def test_baseline_file_size_limit(tmp_path: Path):
    huge = tmp_path / "huge.json"
    huge.write_text("x" * (MAX_BASELINE_BYTES + 1), encoding="utf-8")
    with pytest.raises(ValueError, match="too large"):
        load_baseline_report(huge)


def test_send_webhook_rejects_invalid_scheme():
    report = ScanReport(
        version="0.11.0",
        cloud="yandex",
        folder_id="b1g",
        summary=ScanSummary(),
    )
    with pytest.raises(ValueError):
        send_webhook("ftp://example.com/hook", report)
