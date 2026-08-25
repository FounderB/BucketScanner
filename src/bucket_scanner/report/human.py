"""Human-readable Rich report."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bucket_scanner.models import ScanReport, Severity
from bucket_scanner.scope import scope_label_for_cloud


def render_human(report: ScanReport, console: Console | None = None) -> None:
    out = console or Console()
    banner = (
        "╔══════════════════════════════════════════════════════════╗\n"
        "║                      BUCKET SCANNER                      ║\n"
        "║        declared vs real · object storage truth           ║\n"
        "╚══════════════════════════════════════════════════════════╝"
    )
    out.print(banner, style="bold cyan")
    out.print()

    scope_label = scope_label_for_cloud(report.cloud)
    if len(report.scope_ids) > 1:
        scope_text = f"folders {', '.join(report.scope_ids)}"
    else:
        scope_text = f"{scope_label} {report.folder_id}"
    out.print(f"  cloud {report.cloud}  {scope_text}", style="dim")
    out.print()

    score_bar = _score_bar(report.summary.score)
    out.print(f"  score {report.summary.score:>3}  {score_bar}")
    out.print(
        "  "
        f"CRIT {report.summary.critical}  "
        f"HIGH {report.summary.high}  "
        f"MED {report.summary.medium}  "
        f"LOW {report.summary.low}  "
        f"INFO {report.summary.info}"
    )
    if report.summary.chains:
        out.print(f"  CHAINS {report.summary.chains}", style="bold red")
    if report.summary.suppressed:
        out.print(f"  SUPPRESSED {report.summary.suppressed}", style="dim")
        for row in report.suppressed_findings[:10]:
            expiry = f" expires {row.expires}" if row.expires else ""
            out.print(
                f"    · {row.finding.rule_id} @ {row.finding.bucket or '*'} "
                f"— {row.reason or 'no reason'}{expiry}",
                style="dim",
            )
        soon = [row for row in report.suppressed_findings if row.expires]
        # Surface nearing expiry in human output
        from datetime import UTC, date, datetime

        today = datetime.now(tz=UTC).date()
        for row in soon:
            try:
                exp = date.fromisoformat(row.expires)
            except ValueError:
                continue
            days = (exp - today).days
            if 0 <= days <= 14:
                out.print(
                    f"  ! Suppression expires in {days}d: {row.finding.rule_id}",
                    style="yellow",
                )
    for warning in report.warnings:
        out.print(f"  ! {warning}", style="yellow")
    if report.baseline_path:
        out.print(
            f"  NEW vs baseline {report.summary.new}  ({report.baseline_path})",
            style="bold yellow" if report.summary.new else "dim",
        )
    out.print()

    if report.chains:
        out.print("[bold]Misconfig chains[/bold]")
        for chain in report.chains:
            out.print(
                Panel(
                    chain.message,
                    title=f"[{chain.severity.value.upper()}] {chain.title}",
                    border_style=_severity_style(chain.severity),
                )
            )
        out.print()

    table = Table(title=f"Findings · {scope_label} {report.folder_id}")
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("Bucket")
    table.add_column("Message")
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for finding in sorted(
        report.findings,
        key=lambda item: (-rank[item.severity.value], item.rule_id),
    ):
        table.add_row(
            finding.severity.value.upper(),
            finding.rule_id,
            finding.bucket or "-",
            finding.message,
        )
    out.print(table)


def _score_bar(score: int) -> str:
    filled = score // 5
    return "█" * filled + "░" * (20 - filled)


def _severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "red",
        Severity.HIGH: "bright_red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "cyan",
    }[severity]
