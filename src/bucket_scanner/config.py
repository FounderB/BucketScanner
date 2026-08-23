"""Configuration loading for Bucket Scanner."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import Severity


@dataclass
class ScanConfig:
    folder_id: str | None = None
    cloud: CloudProvider = CloudProvider.YANDEX
    aws_region: str | None = None
    aws_profile: str | None = None
    aws_scan_iam: bool = True
    fail_on: Severity = Severity.HIGH
    probe: bool = False
    ignore_buckets: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    key_age_days: int = 90
    terraform_path: Path | None = None
    repo_path: Path | None = None
    tracefuse_report: Path | None = None


@dataclass
class NotifyConfig:
    webhook_url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    min_severity: Severity = Severity.HIGH


@dataclass
class ServeConfig:
    addr: str = "127.0.0.1:9090"
    interval_seconds: int = 0


@dataclass
class AppConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    serve: ServeConfig = field(default_factory=ServeConfig)


DEFAULT_CONFIG = """# Bucket Scanner configuration
# Docs: https://github.com/FounderB/BucketScanner/blob/main/docs/CONFIGURATION.md

[scan]
folder_id = "b1gxxxxxxxxxx"
# cloud = "yandex"  # or "aws"
# aws_region = "us-east-1"
# aws_profile = "default"
fail_on = "high"
probe = false
key_age_days = 90

[scan.ignore_buckets]
names = ["public-assets-cdn"]

# repo scanning (Tracefuse-style YC secret detection)
# [repo]
# path = "."
# tracefuse_report = "tracefuse-report.json"

# [notify]
# webhook_url = "https://hooks.example.com/bucket-scanner"
# telegram_bot_token = "123:abc"
# telegram_chat_id = "123456"
# min_severity = "high"

# [serve]
# addr = "127.0.0.1:9090"
# interval_seconds = 300

# [[scan.severity_overrides]]
# rule = "versioning/disabled"
# severity = "medium"
"""


def _parse_severity(value: str) -> Severity:
    return Severity(value.lower())


def load_config(path: Path | None = None) -> AppConfig:
    config_path = path or Path(".bucket-scanner.toml")
    if not config_path.exists():
        return AppConfig()

    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    scan_data = data.get("scan", {})
    repo_data = data.get("repo", {})
    notify_data = data.get("notify", {})
    serve_data = data.get("serve", {})
    ignore = scan_data.get("ignore_buckets", {}).get("names", [])
    overrides: dict[str, Severity] = {}
    for item in scan_data.get("severity_overrides", []):
        overrides[item["rule"]] = _parse_severity(item["severity"])

    repo_path = repo_data.get("path")
    tracefuse_report = repo_data.get("tracefuse_report")

    return AppConfig(
        scan=ScanConfig(
            folder_id=scan_data.get("folder_id"),
            cloud=CloudProvider.parse(scan_data.get("cloud")),
            aws_region=scan_data.get("aws_region"),
            aws_profile=scan_data.get("aws_profile"),
            aws_scan_iam=bool(scan_data.get("aws_scan_iam", True)),
            fail_on=_parse_severity(scan_data.get("fail_on", "high")),
            probe=bool(scan_data.get("probe", False)),
            ignore_buckets=set(ignore),
            severity_overrides=overrides,
            key_age_days=int(scan_data.get("key_age_days", 90)),
            repo_path=Path(repo_path) if repo_path else None,
            tracefuse_report=Path(tracefuse_report) if tracefuse_report else None,
        ),
        notify=NotifyConfig(
            webhook_url=notify_data.get("webhook_url"),
            telegram_bot_token=notify_data.get("telegram_bot_token"),
            telegram_chat_id=str(notify_data.get("telegram_chat_id"))
            if notify_data.get("telegram_chat_id") is not None
            else None,
            min_severity=_parse_severity(notify_data.get("min_severity", "high")),
        ),
        serve=ServeConfig(
            addr=serve_data.get("addr", "127.0.0.1:9090"),
            interval_seconds=int(serve_data.get("interval_seconds", 0)),
        ),
    )


def write_default_config(path: Path, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"Config already exists: {path}")
    path.write_text(DEFAULT_CONFIG, encoding="utf-8")
