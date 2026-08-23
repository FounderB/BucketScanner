"""Prometheus metrics exporter."""

from __future__ import annotations

from bucket_scanner.models import ScanReport


def render_prometheus(report: ScanReport) -> str:
    folder = report.folder_id
    lines = [
        "# HELP bucket_scanner_info Bucket Scanner build info",
        "# TYPE bucket_scanner_info gauge",
        f'bucket_scanner_info{{version="{report.version}",method="{report.method}"}} 1',
        "# HELP bucket_scanner_score Aggregated risk score (0-100)",
        "# TYPE bucket_scanner_score gauge",
        f'bucket_scanner_score{{folder_id="{folder}"}} {report.summary.score}',
        "# HELP bucket_scanner_buckets_scanned Buckets scanned in last run",
        "# TYPE bucket_scanner_buckets_scanned gauge",
        (
            f'bucket_scanner_buckets_scanned{{folder_id="{folder}"}} '
            f"{report.summary.buckets_scanned}"
        ),
        "# HELP bucket_scanner_chains_total Misconfiguration chains detected",
        "# TYPE bucket_scanner_chains_total gauge",
        f'bucket_scanner_chains_total{{folder_id="{folder}"}} {report.summary.chains}',
        "# HELP bucket_scanner_findings_total Findings by severity",
        "# TYPE bucket_scanner_findings_total gauge",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        count = getattr(report.summary, severity)
        lines.append(
            
                f'bucket_scanner_findings_total{{folder_id="{folder}",'
                f'severity="{severity}"}} {count}'
            
        )
    for chain in report.chains:
        lines.extend(
            [
                "# HELP bucket_scanner_chain_present Chain detected (1=present)",
                "# TYPE bucket_scanner_chain_present gauge",
                (
                    f'bucket_scanner_chain_present{{folder_id="{folder}",'
                    f'chain_id="{chain.chain_id}"}} 1'
                ),
            ]
        )
    return "\n".join(lines) + "\n"
