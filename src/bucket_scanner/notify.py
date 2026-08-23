"""Webhook and Telegram notifications."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from bucket_scanner.models import ScanReport, Severity, severity_at_least


@dataclass
class NotifyConfig:
    webhook_url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    min_severity: Severity = Severity.HIGH


def should_notify(report: ScanReport, config: NotifyConfig) -> bool:
    for finding in report.findings:
        if severity_at_least(finding.severity, config.min_severity):
            return True
    for chain in report.chains:
        if severity_at_least(chain.severity, config.min_severity):
            return True
    return False


def build_summary_text(report: ScanReport) -> str:
    return (
        f"Bucket Scanner {report.version}\n"
        f"folder: {report.folder_id}\n"
        f"score: {report.summary.score}/100\n"
        f"CRIT {report.summary.critical} · HIGH {report.summary.high} · "
        f"MED {report.summary.medium} · chains {report.summary.chains}\n"
        f"top: {_top_findings(report, limit=3)}"
    )


def send_webhook(url: str, report: ScanReport, *, timeout: float = 15.0) -> None:
    payload = {
        "tool": report.tool,
        "version": report.version,
        "folder_id": report.folder_id,
        "summary": report.summary.model_dump(),
        "text": build_summary_text(report),
        "findings": [item.model_dump(mode="json") for item in report.findings[:20]],
        "chains": [item.model_dump(mode="json") for item in report.chains],
    }
    response = httpx.post(url, json=payload, timeout=timeout)
    response.raise_for_status()


def send_telegram(token: str, chat_id: str, report: ScanReport, *, timeout: float = 15.0) -> None:
    text = build_summary_text(report)
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
        send_webhook(config.webhook_url, report)
        sent.append("webhook")
    if config.telegram_bot_token and config.telegram_chat_id:
        send_telegram(config.telegram_bot_token, config.telegram_chat_id, report)
        sent.append("telegram")
    return sent


def _top_findings(report: ScanReport, *, limit: int) -> str:
    ranked = sorted(
        report.findings,
        key=lambda item: (
            -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[item.severity.value],
            item.rule_id,
        ),
    )
    if not ranked:
        return "none"
    return "; ".join(f"{item.rule_id} ({item.severity.value})" for item in ranked[:limit])
