"""Environment and credential health checks."""

from __future__ import annotations

from rich.console import Console

from bucket_scanner.auth import CredentialError, resolve_credentials
from bucket_scanner.aws.s3 import build_aws_s3_client, build_aws_sts_client, resolve_account_id
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import load_config
from bucket_scanner.yc.management import YcManagementClient


def run_doctor(console: Console | None = None) -> int:
    out = console or Console()
    issues = 0

    config = load_config()
    cloud = config.scan.cloud
    out.print(f"[green]✓[/green] Cloud backend: {cloud.value}")

    if cloud == CloudProvider.AWS:
        if config.scan.aws_region:
            out.print(f"[green]✓[/green] AWS region: {config.scan.aws_region}")
        if config.scan.aws_profile:
            out.print(f"[green]✓[/green] AWS profile: {config.scan.aws_profile}")
    elif cloud == CloudProvider.AZURE:
        out.print(
            "[yellow]![/yellow] Azure live scan is fixture-only today "
            "(use --fixture or --profile with fixture)"
        )
        return 0
    elif config.scan.folder_id or config.scan.folder_ids:
        if config.scan.folder_ids:
            out.print(
                f"[green]✓[/green] Config folder_ids: {', '.join(config.scan.folder_ids)}"
            )
        else:
            out.print(f"[green]✓[/green] Config folder_id: {config.scan.folder_id}")
    else:
        out.print(
            "[yellow]![/yellow] No folder_id in .bucket-scanner.toml "
            "(use --folder-id or init)"
        )
        issues += 1

    try:
        credentials = resolve_credentials(
            cloud=cloud,
            region=config.scan.aws_region,
            profile=config.scan.aws_profile,
        )
        out.print(f"[green]✓[/green] Credentials resolved via {credentials.source}")
    except CredentialError as exc:
        out.print(f"[red]✗[/red] {exc}")
        return 2

    if cloud == CloudProvider.AWS:
        try:
            sts = build_aws_sts_client(credentials)
            sts.get_caller_identity()
            account_id = resolve_account_id(credentials)
            out.print(f"[green]✓[/green] AWS STS reachable (account {account_id})")
        except Exception as exc:
            out.print(f"[red]✗[/red] AWS STS unreachable: {exc}")
            issues += 1
        try:
            s3 = build_aws_s3_client(credentials)
            s3.list_buckets(MaxBuckets=1)
            out.print("[green]✓[/green] AWS S3 API reachable")
        except Exception as exc:
            out.print(f"[red]✗[/red] AWS S3 unreachable: {exc}")
            issues += 1
        return 1 if issues else 0

    if credentials.iam_token:
        client = YcManagementClient(credentials.iam_token)
        if client.ping():
            out.print("[green]✓[/green] IAM API reachable")
        else:
            out.print("[red]✗[/red] IAM API unreachable")
            issues += 1
    else:
        out.print(
            "[yellow]![/yellow] No IAM token — folder inventory and SA checks limited"
        )

    if credentials.access_key_id and credentials.secret_access_key:
        out.print("[green]✓[/green] Static S3 keys present")
    else:
        out.print("[yellow]![/yellow] No static S3 keys — ACL/encryption checks will be limited")

    return 1 if issues else 0
