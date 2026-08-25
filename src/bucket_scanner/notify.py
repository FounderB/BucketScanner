"""Webhook and Telegram notifications."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from bucket_scanner.models import ScanReport, Severity, severity_at_least
from bucket_scanner.scope import scope_label_for_cloud


@dataclass
class NotifyConfig:
    webhook_url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    min_severity: Severity = Severity.HIGH
    new_only: bool = False


def _findings_for_notify(report: ScanReport, config: NotifyConfig):
    if config.new_only and report.baseline_path is not None:
        return report.new_findings, report.new_chains
    return report.findings, report.chains


def should_notify(report: ScanReport, config: NotifyConfig) -> bool:
    findings, chains = _findings_for_notify(report, config)
    for finding in findings:
        if severity_at_least(finding.severity, config.min_severity):
            return True
    for chain in chains:
        if severity_at_least(chain.severity, config.min_severity):
            return True
    return False


def build_summary_text(report: ScanReport, *, new_only: bool = False) -> str:
    scope_label = scope_label_for_cloud(report.cloud)
    delta = ""
    if report.baseline_path:
        delta = f" · new {report.summary.new}"
    if report.summary.suppressed:
        delta += f" · suppressed {report.summary.suppressed}"
    mode = " (new vs baseline)" if new_only and report.baseline_path else ""
    return (
        f"Bucket Scanner {report.version} ({report.cloud}){mode}\n"
        f"{scope_label}: {report.folder_id}\n"
        f"score: {report.summary.score}/100\n"
        f"CRIT {report.summary.critical} · HIGH {report.summary.high} · "
        f"MED {report.summary.medium} · chains {report.summary.chains}{delta}\n"
        f"top: {_top_findings(report, limit=3, new_only=new_only)}"
    )


def _validate_webhook_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Webhook URL must use http or https")
    if not parsed.netloc:
        raise ValueError("Webhook URL must include a host")


def send_webhook(
    url: str,
    report: ScanReport,
    *,
    timeout: float = 15.0,
    new_only: bool = False,
) -> None:
    _validate_webhook_url(url)
    findings, chains = _findings_for_notify(
        report, NotifyConfig(new_only=new_only, min_severity=Severity.INFO)
    )
    # When new_only, use delta lists even if min_severity is INFO for payload.
    if new_only and report.baseline_path is not None:
        findings, chains = report.new_findings, report.new_chains
    text = build_summary_text(report, new_only=new_only)
    payload = {
        "tool": report.tool,
        "version": report.version,
        "cloud": report.cloud,
        "folder_id": report.folder_id,
        "summary": report.summary.model_dump(),
        "text": text,
        "new_only": new_only,
        "findings": [item.model_dump(mode="json") for item in findings[:20]],
        "chains": [item.model_dump(mode="json") for item in chains],
        # Slack-compatible attachment-style fields
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"```{text}```"},
            }
        ],
    }
    response = httpx.post(url, json=payload, timeout=timeout)
    response.raise_for_status()


def send_telegram(
    token: str,
    chat_id: str,
    report: ScanReport,
    *,
    timeout: float = 15.0,
    new_only: bool = False,
) -> None:
    text = build_summary_text(report, new_only=new_only)
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    response = httpx.post(
        url,
        json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
        timeout=timeout,
    )
    response.raise_for_status()


def notify_all(report: ScanReport, config: NotifyConfig) -> list[str]:
    sent: list[str] = []
    if not should_notify(report, config):
        return sent
    if config.webhook_url:
        send_webhook(config.webhook_url, report, new_only=config.new_only)
        sent.append("webhook")
    if config.telegram_bot_token and config.telegram_chat_id:
        send_telegram(
            config.telegram_bot_token,
            config.telegram_chat_id,
            report,
            new_only=config.new_only,
        )
        sent.append("telegram")
    return sent


def _top_findings(report: ScanReport, *, limit: int, new_only: bool = False) -> str:
    pool = report.new_findings if new_only and report.baseline_path else report.findings
    ranked = sorted(
        pool,
        key=lambda item: (
            -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[item.severity.value],
            item.rule_id,
        ),
    )
    if not ranked:
        return "none"
    return "; ".join(f"{item.rule_id} ({item.severity.value})" for item in ranked[:limit])
