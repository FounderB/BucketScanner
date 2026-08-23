"""Baseline comparison and finding suppressions for CI gates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from bucket_scanner.chains import compose_chains
from bucket_scanner.models import SEVERITY_WEIGHT, ChainFinding, Finding, ScanReport, ScanSummary


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
        if finding.rule_id != self.rule:
            return False
        if self.bucket is not None and finding.bucket != self.bucket:
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
) -> tuple[list[Finding], int]:
    if not suppressions:
        return findings, 0
    kept: list[Finding] = []
    suppressed = 0
    for finding in findings:
        if any(item.matches(finding) for item in suppressions):
            suppressed += 1
            continue
        kept.append(finding)
    return kept, suppressed


def compute_delta(
    report: ScanReport,
    baseline: ScanReport,
) -> tuple[list[Finding], list[ChainFinding]]:
    baseline_findings = {finding_fingerprint(item) for item in baseline.findings}
    baseline_chains = {chain_fingerprint(item) for item in baseline.chains}
    new_findings = [
        item for item in report.findings if finding_fingerprint(item) not in baseline_findings
    ]
    new_chains = [
        item for item in report.chains if chain_fingerprint(item) not in baseline_chains
    ]
    return new_findings, new_chains


def apply_gate(
    report: ScanReport,
    *,
    suppressions: list[Suppression],
    baseline_path: Path | None = None,
) -> ScanReport:
    findings, suppressed = apply_suppressions(report.findings, suppressions)
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
    summary.suppressed = suppressed
    summary.new = len(new_findings) + len(new_chains)

    return report.model_copy(
        update={
            "findings": findings,
            "chains": chains,
            "new_findings": new_findings,
            "new_chains": new_chains,
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
