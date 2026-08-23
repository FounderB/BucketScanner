"""Scan local repositories for cloud credential leaks."""

from __future__ import annotations

import re
from pathlib import Path

from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import Finding, Severity

MAX_FILE_BYTES = 1_048_576
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
}
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".tar", ".gz", ".pdf", ".pyc"}

PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "secrets/yc-env-var",
        re.compile(
            r"(?i)YC_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|TOKEN|IAM_TOKEN)\s*=\s*"
            r"['\"]?([^'\"\s#]{8,})"
        ),
        Severity.CRITICAL,
        "Yandex Cloud credential in environment assignment",
    ),
    (
        "secrets/yc-static-key",
        re.compile(r"\b(YCAJ[A-Za-z0-9]{20,})\b"),
        Severity.CRITICAL,
        "Yandex Cloud static access key pattern",
    ),
    (
        "secrets/yc-sa-key-json",
        re.compile(r'"service_account_id"\s*:\s*"([^"]+)"'),
        Severity.CRITICAL,
        "Yandex Cloud service account authorized key JSON",
    ),
    (
        "secrets/aws-env-var",
        re.compile(
            r"(?i)AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)\s*=\s*"
            r"['\"]?([^'\"\s#]{8,})"
        ),
        Severity.CRITICAL,
        "AWS credential in environment assignment",
    ),
    (
        "secrets/aws-access-key-id",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        Severity.CRITICAL,
        "AWS access key ID pattern",
    ),
    (
        "secrets/azure-env-var",
        re.compile(
            r"(?i)AZURE_(?:CLIENT_SECRET|STORAGE_ACCOUNT_KEY|TENANT_ID|CLIENT_ID)\s*=\s*"
            r"['\"]?([^'\"\s#]{8,})"
        ),
        Severity.CRITICAL,
        "Azure credential in environment assignment",
    ),
    (
        "secrets/aws-compat-key-in-yc-context",
        re.compile(r"(?i)(?:yandex|storage\.yandexcloud).*AWS_SECRET_ACCESS_KEY\s*=\s*(\S+)"),
        Severity.HIGH,
        "AWS-compat secret near Yandex Cloud context",
    ),
]

YC_PATTERNS = {
    "secrets/yc-env-var",
    "secrets/yc-static-key",
    "secrets/yc-sa-key-json",
    "secrets/aws-compat-key-in-yc-context",
}
AWS_PATTERNS = {
    "secrets/aws-env-var",
    "secrets/aws-access-key-id",
}
AZURE_PATTERNS = {
    "secrets/azure-env-var",
    "secrets/aws-env-var",
    "secrets/aws-access-key-id",
}


def scan_repo(
    repo_path: Path,
    *,
    cloud: CloudProvider = CloudProvider.YANDEX,
) -> list[Finding]:
    if not repo_path.exists():
        return []
    allowed = _patterns_for_cloud(cloud)
    findings: list[Finding] = []
    for file_path in _iter_files(repo_path):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if len(text.encode("utf-8")) > MAX_FILE_BYTES:
            continue
        rel = str(file_path.relative_to(repo_path))
        for rule_id, pattern, severity, title in PATTERNS:
            if rule_id not in allowed:
                continue
            match = pattern.search(text)
            if not match:
                continue
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    message=f"Possible credential material in '{rel}'.",
                    resource=rel,
                    evidence={
                        "file": rel,
                        "match": _redact_match(match.group(0)),
                    },
                    remediation=(
                        "Rotate exposed credentials and move secrets to a vault or CI secrets."
                    ),
                )
            )
            break
    return findings


def _patterns_for_cloud(cloud: CloudProvider) -> set[str]:
    if cloud == CloudProvider.AWS:
        return AWS_PATTERNS
    if cloud == CloudProvider.AZURE:
        return AZURE_PATTERNS
    return YC_PATTERNS


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        yield path


def _redact_match(value: str) -> str:
    if len(value) <= 12:
        return value[:3] + "…"
    return value[:6] + "…" + value[-4:]
