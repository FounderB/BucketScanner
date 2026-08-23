"""Environment and credential health checks."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from bucket_scanner.auth import CredentialError, resolve_credentials
from bucket_scanner.aws.s3 import build_aws_s3_client, build_aws_sts_client, resolve_account_id
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig, load_config


def _check(name: str, status: str, message: str) -> dict[str, str]:
    return {"name": name, "status": status, "message": message}


def build_doctor_report(
    *,
    cloud: CloudProvider | None = None,
    config: ScanConfig | None = None,
) -> dict[str, Any]:
    scan_config = config or load_config().scan
    active_cloud = cloud or scan_config.cloud
    checks: list[dict[str, str]] = []
    issues = 0
    exit_code = 0

    checks.append(_check("cloud", "ok", active_cloud.value))

    if active_cloud == CloudProvider.AWS:
        if scan_config.aws_region:
            checks.append(_check("aws_region", "ok", scan_config.aws_region))
        if scan_config.aws_profile:
            checks.append(_check("aws_profile", "ok", scan_config.aws_profile))
    elif active_cloud == CloudProvider.AZURE:
        if scan_config.folder_id:
            checks.append(_check("subscription", "ok", scan_config.folder_id))
        else:
            checks.append(
                _check(
                    "subscription",
                    "warn",
                    "No subscription in .bucket-scanner.toml "
                    "(use --folder-id or AZURE_SUBSCRIPTION_ID)",
                )
            )
            issues += 1
    elif active_cloud == CloudProvider.GCS:
        if scan_config.folder_id:
            checks.append(_check("project", "ok", scan_config.folder_id))
        else:
            checks.append(
                _check(
                    "project",
                    "warn",
                    "No project in .bucket-scanner.toml (use --folder-id or GCP_PROJECT)",
                )
            )
            issues += 1
    elif scan_config.folder_id or scan_config.folder_ids:
        if scan_config.folder_ids:
            checks.append(
                _check("folder_ids", "ok", ", ".join(scan_config.folder_ids))
            )
        else:
            checks.append(_check("folder_id", "ok", scan_config.folder_id or ""))
    else:
        checks.append(
            _check(
                "folder_id",
                "warn",
                "No folder_id in .bucket-scanner.toml (use --folder-id or init)",
            )
        )
        issues += 1

    try:
        credentials = resolve_credentials(
            cloud=active_cloud,
            region=scan_config.aws_region,
            profile=scan_config.aws_profile,
        )
        checks.append(_check("credentials", "ok", f"resolved via {credentials.source}"))
    except CredentialError as exc:
        checks.append(_check("credentials", "error", str(exc)))
        return {
            "tool": "bucket-scanner",
            "command": "doctor",
            "cloud": active_cloud.value,
            "exit_code": 2,
            "checks": checks,
        }

    if active_cloud == CloudProvider.AWS:
        try:
            sts = build_aws_sts_client(credentials)
            sts.get_caller_identity()
            account_id = resolve_account_id(credentials)
            checks.append(_check("aws_sts", "ok", f"reachable (account {account_id})"))
        except Exception as exc:
            checks.append(_check("aws_sts", "error", f"unreachable: {exc}"))
            issues += 1
        try:
            s3 = build_aws_s3_client(credentials)
            s3.list_buckets(MaxBuckets=1)
            checks.append(_check("aws_s3", "ok", "API reachable"))
        except Exception as exc:
            checks.append(_check("aws_s3", "error", f"unreachable: {exc}"))
            issues += 1
        exit_code = 1 if issues else 0
        return {
            "tool": "bucket-scanner",
            "command": "doctor",
            "cloud": active_cloud.value,
            "exit_code": exit_code,
            "checks": checks,
        }

    if active_cloud == CloudProvider.AZURE:
        try:
            from bucket_scanner.azure.storage import AzureDependencyError, _import_azure

            _import_azure()
            checks.append(_check("azure_sdk", "ok", "dependencies available"))
        except AzureDependencyError as exc:
            checks.append(_check("azure_sdk", "error", str(exc)))
            return {
                "tool": "bucket-scanner",
                "command": "doctor",
                "cloud": active_cloud.value,
                "exit_code": 2,
                "checks": checks,
            }
        if credentials.subscription_id:
            checks.append(
                _check("azure_subscription", "ok", credentials.subscription_id)
            )
        elif scan_config.folder_id:
            checks.append(
                _check("azure_subscription", "ok", f"config: {scan_config.folder_id}")
            )
        else:
            checks.append(
                _check(
                    "azure_subscription",
                    "warn",
                    "AZURE_SUBSCRIPTION_ID not set (pass --folder-id for live scan)",
                )
            )
            issues += 1
        checks.append(
            _check(
                "azure_credentials",
                "ok",
                "DefaultAzureCredential / AZURE_* env / managed identity",
            )
        )
        exit_code = 1 if issues else 0
        return {
            "tool": "bucket-scanner",
            "command": "doctor",
            "cloud": active_cloud.value,
            "exit_code": exit_code,
            "checks": checks,
        }

    if active_cloud == CloudProvider.GCS:
        try:
            from bucket_scanner.gcs.storage import GcsDependencyError, _import_gcs

            _import_gcs()
            checks.append(_check("gcs_sdk", "ok", "dependencies available"))
        except GcsDependencyError as exc:
            checks.append(_check("gcs_sdk", "error", str(exc)))
            return {
                "tool": "bucket-scanner",
                "command": "doctor",
                "cloud": active_cloud.value,
                "exit_code": 2,
                "checks": checks,
            }
        project = credentials.folder_id or scan_config.folder_id
        if project:
            checks.append(_check("gcp_project", "ok", project))
        else:
            checks.append(
                _check(
                    "gcp_project",
                    "warn",
                    "GCP_PROJECT not set (pass --folder-id for live scan)",
                )
            )
            issues += 1
        checks.append(
            _check(
                "gcp_credentials",
                "ok",
                "Application Default Credentials / GOOGLE_APPLICATION_CREDENTIALS",
            )
        )
        exit_code = 1 if issues else 0
        return {
            "tool": "bucket-scanner",
            "command": "doctor",
            "cloud": active_cloud.value,
            "exit_code": exit_code,
            "checks": checks,
        }

    if credentials.iam_token:
        from bucket_scanner.yc.management import YcManagementClient

        client = YcManagementClient(credentials.iam_token)
        if client.ping():
            checks.append(_check("iam_api", "ok", "reachable"))
        else:
            checks.append(_check("iam_api", "error", "unreachable"))
            issues += 1
    else:
        checks.append(
            _check(
                "iam_token",
                "warn",
                "No IAM token — folder inventory and SA checks limited",
            )
        )

    if credentials.access_key_id and credentials.secret_access_key:
        checks.append(_check("s3_keys", "ok", "static S3 keys present"))
    else:
        checks.append(
            _check(
                "s3_keys",
                "warn",
                "No static S3 keys — ACL/encryption checks will be limited",
            )
        )

    exit_code = 1 if issues else 0
    return {
        "tool": "bucket-scanner",
        "command": "doctor",
        "cloud": active_cloud.value,
        "exit_code": exit_code,
        "checks": checks,
    }


def run_doctor(
    console: Console | None = None,
    *,
    cloud: CloudProvider | None = None,
    config: ScanConfig | None = None,
) -> int:
    out = console or Console()
    report = build_doctor_report(cloud=cloud, config=config)
    for item in report["checks"]:
        status = item["status"]
        prefix = {"ok": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "error": "[red]✗[/red]"}
        label = item["name"].replace("_", " ")
        out.print(f"{prefix.get(status, status)} {label}: {item['message']}")
    return int(report["exit_code"])


def render_doctor_json(
    *,
    cloud: CloudProvider | None = None,
    config: ScanConfig | None = None,
) -> str:
    return json.dumps(build_doctor_report(cloud=cloud, config=config), indent=2)
