"""Core data models for Bucket Scanner."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 10,
    Severity.CRITICAL: 25,
}


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    message: str
    bucket: str | None = None
    resource: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None


class ChainFinding(BaseModel):
    chain_id: str
    title: str
    severity: Severity
    message: str
    rule_ids: list[str]
    buckets: list[str] = Field(default_factory=list)


class BucketSnapshot(BaseModel):
    name: str
    cloud: str = "yandex"
    folder_id: str | None = None
    region: str | None = None
    acl: str | None = None
    policy: dict[str, Any] | None = None
    encryption_enabled: bool = False
    logging_enabled: bool = False
    versioning_enabled: bool = False
    lifecycle_rules: list[dict[str, Any]] = Field(default_factory=list)
    anonymous_listable: bool | None = None
    anonymous_readable: bool | None = None
    metadata_known: bool = True
    block_public_access: dict[str, Any] | None = None
    account_public_access_block: dict[str, Any] | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class ServiceAccountKeySnapshot(BaseModel):
    sa_id: str
    key_id: str | None = None
    age_days: int | None = None
    roles: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    chains: int = 0
    score: int = 0
    buckets_scanned: int = 0
    suppressed: int = 0
    new: int = 0


class ScanReport(BaseModel):
    tool: str = "bucket-scanner"
    report_schema: str = "1.0"
    version: str
    cloud: str = "yandex"
    folder_id: str
    scope_ids: list[str] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    probe_enabled: bool = False
    buckets: list[BucketSnapshot] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    chains: list[ChainFinding] = Field(default_factory=list)
    new_findings: list[Finding] = Field(default_factory=list)
    new_chains: list[ChainFinding] = Field(default_factory=list)
    baseline_path: str | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    method: str = "metadata"


def severity_at_least(severity: Severity, threshold: Severity) -> bool:
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]
