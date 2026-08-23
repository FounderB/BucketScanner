"""Configuration loading for Bucket Scanner."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from bucket_scanner.cloud import CloudProvider
from bucket_scanner.gate import Suppression
from bucket_scanner.models import Severity


@dataclass
class ScanConfig:
    folder_id: str | None = None
    folder_ids: list[str] = field(default_factory=list)
    cloud: CloudProvider = CloudProvider.YANDEX
    aws_region: str | None = None
    aws_profile: str | None = None
    aws_scan_iam: bool = True
    aws_resolve_regions: bool = True
    fail_on: Severity = Severity.HIGH
    fail_on_new: bool = False
    probe: bool = False
    ignore_buckets: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    key_age_days: int = 90
    terraform_path: Path | None = None
    repo_path: Path | None = None
    tracefuse_report: Path | None = None
    baseline_path: Path | None = None
    suppressions: list[Suppression] = field(default_factory=list)


@dataclass
class ScanProfile:
    name: str
    cloud: CloudProvider = CloudProvider.YANDEX
    folder_id: str | None = None
    folder_ids: list[str] = field(default_factory=list)
    aws_region: str | None = None
    aws_profile: str | None = None
    aws_scan_iam: bool = True
    aws_resolve_regions: bool = True
    probe: bool = False
    fail_on: Severity | None = None
    fail_on_new: bool = False
    key_age_days: int | None = None
    ignore_buckets: set[str] = field(default_factory=set)
    terraform_path: Path | None = None
    repo_path: Path | None = None
    tracefuse_report: Path | None = None
    fixture: Path | None = None
    baseline_path: Path | None = None

    def apply_to(self, config: ScanConfig) -> None:
        config.cloud = self.cloud
        if self.folder_id:
            config.folder_id = self.folder_id
        if self.folder_ids:
            config.folder_ids = list(self.folder_ids)
        if self.aws_region:
            config.aws_region = self.aws_region
        if self.aws_profile:
            config.aws_profile = self.aws_profile
        config.aws_scan_iam = self.aws_scan_iam
        config.aws_resolve_regions = self.aws_resolve_regions
        if self.probe:
            config.probe = True
        if self.fail_on_new:
            config.fail_on_new = True
        if self.fail_on is not None:
            config.fail_on = self.fail_on
        if self.key_age_days is not None:
            config.key_age_days = self.key_age_days
        if self.ignore_buckets:
            config.ignore_buckets = set(self.ignore_buckets)
        if self.terraform_path:
            config.terraform_path = self.terraform_path
        if self.repo_path:
            config.repo_path = self.repo_path
        if self.tracefuse_report:
            config.tracefuse_report = self.tracefuse_report
        if self.baseline_path:
            config.baseline_path = self.baseline_path


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
    profile: str | None = None


@dataclass
class AppConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    serve: ServeConfig = field(default_factory=ServeConfig)
    profiles: dict[str, ScanProfile] = field(default_factory=dict)


DEFAULT_CONFIG = """# Bucket Scanner configuration
# Docs: https://github.com/FounderB/BucketScanner/blob/main/docs/CONFIGURATION.md

[scan]
folder_id = "b1gxxxxxxxxxx"
# folder_ids = ["b1gfolder-a", "b1gfolder-b"]
# cloud = "yandex"  # or "aws"
# aws_region = "us-east-1"
# aws_profile = "default"
# aws_resolve_regions = true
fail_on = "high"
probe = false
key_age_days = 90

[scan.ignore_buckets]
names = ["public-assets-cdn"]

# terraform_path = "terraform/"
# [repo]
# path = "."
# tracefuse_report = "tracefuse-report.json"

# [[profiles]]
# name = "aws-demo"
# cloud = "aws"
# fixture = "examples/demo-vulnerable/fixture-aws.toml"
# terraform_path = "examples/demo-vulnerable/terraform-aws"
# probe = false

# [[profiles]]
# name = "yc-prod"
# folder_ids = ["b1gfolder-prod", "b1gfolder-backup"]
# probe = true

# [notify]
# webhook_url = "https://hooks.example.com/bucket-scanner"
# telegram_bot_token = "123:abc"
# telegram_chat_id = "123456"
# min_severity = "high"

# [serve]
# addr = "127.0.0.1:9090"
# interval_seconds = 300
# profile = "aws-demo"

# [[scan.severity_overrides]]
# rule = "versioning/disabled"
# severity = "medium"

# baseline_path = "baselines/prod.json"

# [[scan.suppressions]]
# rule = "logging/disabled"
# bucket = "public-assets-cdn"
# reason = "CDN origin bucket"
# expires = "2026-12-31"
"""


def _parse_severity(value: str) -> Severity:
    return Severity(value.lower())


def _parse_date(value: str) -> date:
    return date.fromisoformat(value)


def _parse_suppressions(scan_data: dict) -> list[Suppression]:
    items = scan_data.get("suppressions", [])
    suppressions: list[Suppression] = []
    for item in items:
        expires_raw = item.get("expires")
        suppressions.append(
            Suppression(
                rule=item["rule"],
                bucket=item.get("bucket"),
                resource=item.get("resource"),
                reason=item.get("reason", ""),
                expires=_parse_date(expires_raw) if expires_raw else None,
            )
        )
    return suppressions


def _parse_profile(item: dict) -> ScanProfile:
    ignore = item.get("ignore_buckets", {}).get("names", item.get("ignore_buckets", []))
    if isinstance(ignore, dict):
        ignore = ignore.get("names", [])
    fail_on_raw = item.get("fail_on")
    fail_on_new = fail_on_raw == "new"
    fail_on = None if fail_on_new else (_parse_severity(fail_on_raw) if fail_on_raw else None)
    return ScanProfile(
        name=item["name"],
        cloud=CloudProvider.parse(item.get("cloud")),
        folder_id=item.get("folder_id"),
        folder_ids=list(item.get("folder_ids", [])),
        aws_region=item.get("aws_region"),
        aws_profile=item.get("aws_profile"),
        aws_scan_iam=bool(item.get("aws_scan_iam", True)),
        aws_resolve_regions=bool(item.get("aws_resolve_regions", True)),
        probe=bool(item.get("probe", False)),
        fail_on=fail_on,
        fail_on_new=fail_on_new,
        key_age_days=int(item["key_age_days"]) if item.get("key_age_days") is not None else None,
        ignore_buckets=set(ignore),
        terraform_path=Path(item["terraform_path"]) if item.get("terraform_path") else None,
        repo_path=Path(item["repo_path"]) if item.get("repo_path") else None,
        tracefuse_report=Path(item["tracefuse_report"]) if item.get("tracefuse_report") else None,
        fixture=Path(item["fixture"]) if item.get("fixture") else None,
        baseline_path=Path(item["baseline_path"]) if item.get("baseline_path") else None,
    )


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
    terraform_path = scan_data.get("terraform_path")
    folder_ids = list(scan_data.get("folder_ids", []))
    baseline_path = scan_data.get("baseline_path")
    suppressions = _parse_suppressions(scan_data)

    profiles: dict[str, ScanProfile] = {}
    for item in data.get("profiles", []):
        profile = _parse_profile(item)
        profiles[profile.name] = profile

    return AppConfig(
        scan=ScanConfig(
            folder_id=scan_data.get("folder_id"),
            folder_ids=folder_ids,
            cloud=CloudProvider.parse(scan_data.get("cloud")),
            aws_region=scan_data.get("aws_region"),
            aws_profile=scan_data.get("aws_profile"),
            aws_scan_iam=bool(scan_data.get("aws_scan_iam", True)),
            aws_resolve_regions=bool(scan_data.get("aws_resolve_regions", True)),
            fail_on=_parse_severity(scan_data.get("fail_on", "high")),
            probe=bool(scan_data.get("probe", False)),
            ignore_buckets=set(ignore),
            severity_overrides=overrides,
            key_age_days=int(scan_data.get("key_age_days", 90)),
            terraform_path=Path(terraform_path) if terraform_path else None,
            repo_path=Path(repo_path) if repo_path else None,
            tracefuse_report=Path(tracefuse_report) if tracefuse_report else None,
            baseline_path=Path(baseline_path) if baseline_path else None,
            suppressions=suppressions,
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
            profile=serve_data.get("profile"),
        ),
        profiles=profiles,
    )


def write_default_config(path: Path, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"Config already exists: {path}")
    path.write_text(DEFAULT_CONFIG, encoding="utf-8")
