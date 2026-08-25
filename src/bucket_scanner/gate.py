"""Baseline comparison and finding suppressions for CI gates."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from bucket_scanner.chains import compose_chains
from bucket_scanner.models import (
    SEVERITY_WEIGHT,
    ChainFinding,
    Finding,
    ScanReport,
    ScanSummary,
    SuppressedFinding,
)


@dataclass(frozen=True)
class Suppression:
    rule: str
    bucket: str | None = None
    resource: str | None = None
    reason: str = ""
    expires: date | None = None

    def matches(self, finding: Finding, *, today: date | None = None) -> bool:
        if self.expires is not None:
            current = today or datetime.now(tz=UTC).date()
            if self.expires < current:
                return False
        if finding.rule_id != self.rule and not fnmatch.fnmatch(finding.rule_id, self.rule):
            return False
        if self.bucket is not None:
            name = finding.bucket or ""
            if any(ch in self.bucket for ch in "*?["):
                if not fnmatch.fnmatch(name, self.bucket):
                    return False
            elif name != self.bucket:
                return False
        if self.resource is not None and finding.resource != self.resource:
            return False
        return True


def finding_fingerprint(finding: Finding) -> str:
    return f"{finding.rule_id}|{finding.bucket or ''}|{finding.resource or ''}"


def chain_fingerprint(chain: ChainFinding) -> str:
    buckets = ",".join(sorted(chain.buckets))
    return f"{chain.chain_id}|{buckets}"


MAX_BASELINE_BYTES = 10 * 1024 * 1024


def load_baseline_report(path: Path) -> ScanReport:
    size = path.stat().st_size
    if size > MAX_BASELINE_BYTES:
        raise ValueError(f"Baseline file too large ({size} bytes); limit is {MAX_BASELINE_BYTES}")
    return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))


def apply_suppressions(
    findings: list[Finding],
    suppressions: list[Suppression],
    *,
    today: date | None = None,
) -> tuple[list[Finding], list[SuppressedFinding], list[str]]:
    """Return kept findings, audit trail, and expiry warning messages."""
    if not suppressions:
        return findings, [], []
    kept: list[Finding] = []
    suppressed_rows: list[SuppressedFinding] = []
    warnings: list[str] = []
    current = today or datetime.now(tz=UTC).date()

    for rule in suppressions:
        if rule.expires is not None:
            days_left = (rule.expires - current).days
            if 0 <= days_left <= 14:
                warnings.append(
                    f"Suppression {rule.rule} "
                    f"({rule.bucket or '*'}) expires in {days_left} day(s) "
                    f"({rule.expires.isoformat()})"
                )

    for finding in findings:
        matched = next(
            (item for item in suppressions if item.matches(finding, today=current)),
            None,
        )
        if matched is None:
            kept.append(finding)
            continue
        suppressed_rows.append(
            SuppressedFinding(
                finding=finding,
                reason=matched.reason,
                expires=matched.expires.isoformat() if matched.expires else None,
                matched_bucket=matched.bucket,
            )
        )
    return kept, suppressed_rows, warnings


def compute_delta(
    report: ScanReport,
    baseline: ScanReport,
) -> tuple[list[Finding], list[ChainFinding]]:
    baseline_findings = {finding_fingerprint(item) for item in baseline.findings}
    baseline_chains = {chain_fingerprint(item) for item in baseline.chains}
    new_findings = [
        item for item in report.findings if finding_fingerprint(item) not in baseline_findings
    ]
    new_chains = [item for item in report.chains if chain_fingerprint(item) not in baseline_chains]
    return new_findings, new_chains


def apply_gate(
    report: ScanReport,
    *,
    suppressions: list[Suppression],
    baseline_path: Path | None = None,
) -> ScanReport:
    findings, suppressed_rows, warnings = apply_suppressions(report.findings, suppressions)
    chains = compose_chains(report.buckets, findings)

    new_findings: list[Finding] = []
    new_chains: list[ChainFinding] = []
    baseline_label: str | None = None

    if baseline_path is not None:
        baseline = load_baseline_report(baseline_path)
        interim = report.model_copy(update={"findings": findings, "chains": chains})
        new_findings, new_chains = compute_delta(interim, baseline)
        baseline_label = str(baseline_path)

    summary = _build_summary(findings, chains, buckets_scanned=report.summary.buckets_scanned)
    summary.suppressed = len(suppressed_rows)
    summary.new = len(new_findings) + len(new_chains)
    if report.summary.scan_duration_ms is not None:
        summary.scan_duration_ms = report.summary.scan_duration_ms

    merged_warnings = list(report.warnings) + warnings
    return report.model_copy(
        update={
            "findings": findings,
            "chains": chains,
            "new_findings": new_findings,
            "new_chains": new_chains,
            "suppressed_findings": suppressed_rows,
            "warnings": merged_warnings,
            "baseline_path": baseline_label,
            "summary": summary,
        }
    )


def write_baseline_report(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def _build_summary(findings, chains, *, buckets_scanned: int) -> ScanSummary:
    summary = ScanSummary(buckets_scanned=buckets_scanned, chains=len(chains))
    score = 0
    for finding in findings:
        summary.total += 1
        score += SEVERITY_WEIGHT[finding.severity]
        setattr(summary, finding.severity.value, getattr(summary, finding.severity.value) + 1)
    summary.score = min(score, 100)
    return summary
