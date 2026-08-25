"""FP/FN proof log — triage findings from scan JSON into a durable review file."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from bucket_scanner.gate import finding_fingerprint
from bucket_scanner.models import Finding, ScanReport

ReviewStatus = Literal["unreviewed", "confirmed", "false_positive", "accepted_risk", "fixed"]

VALID_STATUSES = frozenset(
    {"unreviewed", "confirmed", "false_positive", "accepted_risk", "fixed"}
)


def _now() -> str:
    return datetime.now(tz=UTC).replace(microsecond=0).isoformat()


def load_report(path: Path) -> ScanReport:
    return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))


def load_log(path: Path) -> dict[str, dict[str, Any]]:
    """Load JSONL proof log keyed by fingerprint."""
    if not path.is_file():
        return {}
    entries: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        fp = row.get("fingerprint")
        if not fp:
            continue
        entries[str(fp)] = row
    return entries


def write_log(path: Path, entries: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(entries[key], ensure_ascii=False, sort_keys=True)
        for key in sorted(entries)
    ]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def upsert_from_report(
    report: ScanReport,
    entries: dict[str, dict[str, Any]],
    *,
    seen_at: str | None = None,
) -> tuple[dict[str, dict[str, Any]], int, int]:
    """Merge findings into the log. Returns (entries, new_count, refreshed_count)."""
    stamp = seen_at or _now()
    new_count = 0
    refreshed = 0
    for finding in report.findings:
        fp = finding_fingerprint(finding)
        existing = entries.get(fp)
        if existing is None:
            entries[fp] = _row_from_finding(finding, fp, stamp, report)
            new_count += 1
            continue
        existing["last_seen"] = stamp
        existing["severity"] = finding.severity.value
        existing["title"] = finding.title
        existing["cloud"] = report.cloud
        existing["version"] = report.version
        refreshed += 1
    return entries, new_count, refreshed


def _row_from_finding(
    finding: Finding,
    fingerprint: str,
    stamp: str,
    report: ScanReport,
) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "rule_id": finding.rule_id,
        "bucket": finding.bucket,
        "resource": finding.resource,
        "severity": finding.severity.value,
        "title": finding.title,
        "status": "unreviewed",
        "notes": "",
        "first_seen": stamp,
        "last_seen": stamp,
        "cloud": report.cloud,
        "folder_id": report.folder_id,
        "version": report.version,
    }


def summarize(entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_status = Counter(str(row.get("status", "unreviewed")) for row in entries.values())
    by_rule = Counter(str(row.get("rule_id", "?")) for row in entries.values())
    return {
        "total": len(entries),
        "by_status": dict(sorted(by_status.items())),
        "top_rules": by_rule.most_common(10),
        "unreviewed": by_status.get("unreviewed", 0),
        "false_positive": by_status.get("false_positive", 0),
        "confirmed": by_status.get("confirmed", 0),
    }


def set_status(
    entries: dict[str, dict[str, Any]],
    fingerprint: str,
    status: str,
    *,
    notes: str | None = None,
) -> dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status {status!r}; expected one of {sorted(VALID_STATUSES)}")
    if fingerprint not in entries:
        raise KeyError(f"Unknown fingerprint: {fingerprint}")
    entries[fingerprint]["status"] = status
    if notes is not None:
        entries[fingerprint]["notes"] = notes
    return entries[fingerprint]


def render_summary_text(summary: dict[str, Any]) -> str:
    lines = [
        f"proof-log entries: {summary['total']}",
        f"  unreviewed={summary['unreviewed']}  confirmed={summary['confirmed']}  "
        f"false_positive={summary['false_positive']}",
    ]
    status = summary.get("by_status") or {}
    if status:
        lines.append("  by_status: " + ", ".join(f"{k}={v}" for k, v in status.items()))
    top = summary.get("top_rules") or []
    if top:
        lines.append("  top_rules:")
        for rule, count in top[:5]:
            lines.append(f"    {count:3d}  {rule}")
    return "\n".join(lines)
