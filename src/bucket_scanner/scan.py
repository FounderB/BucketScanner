"""Scan orchestration."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from bucket_scanner import __version__
from bucket_scanner.auth import Credentials, resolve_credentials
from bucket_scanner.aws.iam import list_iam_access_keys
from bucket_scanner.aws.s3 import (
    build_aws_s3_client,
    get_account_public_access_block,
    list_bucket_names,
    resolve_account_id,
    resolve_bucket_region,
    snapshot_aws_bucket,
)
from bucket_scanner.azure.storage import AzureDependencyError, collect_azure_containers
from bucket_scanner.chains import compose_chains
from bucket_scanner.checks import (
    apply_overrides,
    check_bucket,
    check_service_accounts,
    dedupe_account_scoped_findings,
    redact_finding,
)
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig
from bucket_scanner.diff import diff_terraform
from bucket_scanner.fixture import load_fixture
from bucket_scanner.gcs.storage import GcsDependencyError, collect_gcs_buckets
from bucket_scanner.models import (
    SEVERITY_WEIGHT,
    BucketSnapshot,
    ScanReport,
    ScanSummary,
    ServiceAccountKeySnapshot,
    Severity,
    severity_at_least,
)
from bucket_scanner.probe import probe_bucket
from bucket_scanner.secrets import scan_repo
from bucket_scanner.tracefuse import load_tracefuse_report
from bucket_scanner.yc.enrich import enrich_from_bucket_get
from bucket_scanner.yc.management import ManagementError, YcManagementClient
from bucket_scanner.yc.s3 import build_s3_client, snapshot_yandex_bucket


class ScanError(RuntimeError):
    pass


def _key_age_days(created_at: str | None) -> int | None:
    if not created_at:
        return None
    created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    return (datetime.now(tz=UTC) - created).days


def _roles_for_subject(bindings: list[dict], subject_id: str) -> list[str]:
    return [
        binding["roleId"]
        for binding in bindings
        if binding.get("subject", {}).get("id") == subject_id
    ]


def _anonymous_flags_from_row(row: dict) -> dict[str, bool] | None:
    raw = row.get("anonymousAccessFlags") or row.get("anonymous_access_flags")
    if not isinstance(raw, dict):
        return None
    flags: dict[str, bool] = {}
    for key in ("read", "list", "configRead", "config_read"):
        if key in raw:
            normalized = "config_read" if key in {"configRead", "config_read"} else key
            flags[normalized] = bool(raw[key])
    return flags or None


def _versioning_from_row(row: dict) -> bool | None:
    value = row.get("versioning") or row.get("versioningStatus")
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).upper()
    return text in {"ENABLED", "VERSIONING_ENABLED", "TRUE"}


def _maybe_ephemeral_credentials(
    management: YcManagementClient,
    credentials: Credentials,
) -> Credentials | None:
    """Mint short-lived S3 keys from IAM token so CI needs no YC_ACCESS_KEY_*."""
    if credentials.access_key_id and credentials.secret_access_key:
        return None
    if not credentials.iam_token:
        return None
    try:
        ephemeral = management.create_ephemeral_access_key(
            session_name="bucket-scanner-scan",
            duration_seconds=3600,
        )
    except ManagementError:
        return None
    access_key_id = ephemeral.get("accessKeyId") or ephemeral.get("access_key_id")
    secret = ephemeral.get("secret") or ephemeral.get("secretAccessKey")
    session_token = ephemeral.get("sessionToken") or ephemeral.get("session_token")
    if not access_key_id or not secret or not session_token:
        return None
    return Credentials(
        cloud=CloudProvider.YANDEX,
        iam_token=credentials.iam_token,
        access_key_id=str(access_key_id),
        secret_access_key=str(secret),
        session_token=str(session_token),
        folder_id=credentials.folder_id,
        cloud_id=credentials.cloud_id,
        source="ephemeral",
    )


def _enrich_with_bucket_get(
    management: YcManagementClient,
    snapshot: BucketSnapshot,
) -> BucketSnapshot:
    try:
        detail = management.get_bucket(snapshot.name, view="VIEW_FULL")
    except ManagementError:
        return snapshot
    return enrich_from_bucket_get(snapshot, detail)


def _snapshot_from_inventory_row(
    row: dict,
    *,
    folder_id: str,
) -> BucketSnapshot:
    flags = _anonymous_flags_from_row(row)
    versioning = _versioning_from_row(row)
    partial: list[str] = []
    if versioning is None:
        partial.append("versioning")
    return BucketSnapshot(
        name=row["name"],
        cloud=CloudProvider.YANDEX.value,
        folder_id=folder_id,
        metadata_known=False,
        anonymous_access_flags=flags,
        versioning_enabled=bool(versioning) if versioning is not None else False,
        partial_metadata=partial,
        auth_mode="management-only",
    )


def _merge_inventory_into_snapshot(snapshot: BucketSnapshot, row: dict) -> BucketSnapshot:
    """Enrich an S3 metadata snapshot with Storage List fields."""
    updates: dict = {}
    flags = _anonymous_flags_from_row(row)
    if flags is not None:
        updates["anonymous_access_flags"] = flags
    versioning = _versioning_from_row(row)
    if versioning is not None and not snapshot.versioning_enabled:
        updates["versioning_enabled"] = versioning
    if not updates:
        return snapshot
    return snapshot.model_copy(update=updates)


def _collect_yandex_data(
    folder_id: str,
    credentials: Credentials,
    *,
    probe: bool,
    ignore: set[str],
) -> tuple[list[BucketSnapshot], list[ServiceAccountKeySnapshot]]:
    if not credentials.iam_token:
        raise ScanError("IAM token is required to list buckets in a folder.")

    management = YcManagementClient(credentials.iam_token)
    try:
        bucket_rows = management.list_buckets(folder_id)
        bindings = management.list_folder_access_bindings(folder_id)
        service_accounts = management.list_service_accounts(folder_id)
    except ManagementError as exc:
        raise ScanError(str(exc)) from exc

    s3_credentials = credentials
    auth_mode = "static-keys"
    if credentials.access_key_id and credentials.secret_access_key:
        auth_mode = "static-keys"
    else:
        ephemeral = _maybe_ephemeral_credentials(management, credentials)
        if ephemeral is not None:
            s3_credentials = ephemeral
            auth_mode = "ephemeral"

    has_s3_keys = bool(s3_credentials.access_key_id and s3_credentials.secret_access_key)
    s3 = build_s3_client(s3_credentials) if has_s3_keys else None

    buckets: list[BucketSnapshot] = []
    for row in bucket_rows:
        name = row["name"]
        if name in ignore:
            continue
        if s3 is not None:
            snapshot = snapshot_yandex_bucket(s3, name, folder_id=folder_id)
            snapshot = _merge_inventory_into_snapshot(snapshot, row)
            snapshot = snapshot.model_copy(update={"auth_mode": auth_mode})
        else:
            snapshot = _snapshot_from_inventory_row(row, folder_id=folder_id)
        snapshot = _enrich_with_bucket_get(management, snapshot)
        if probe:
            snapshot = probe_bucket(snapshot)
        buckets.append(snapshot)

    sa_keys: list[ServiceAccountKeySnapshot] = []
    try:
        for sa in service_accounts:
            roles = _roles_for_subject(bindings, sa["id"])
            for key in management.list_access_keys(sa["id"]):
                sa_keys.append(
                    ServiceAccountKeySnapshot(
                        sa_id=sa["id"],
                        key_id=key.get("id"),
                        age_days=_key_age_days(key.get("createdAt")),
                        roles=roles,
                    )
                )
    except ManagementError as exc:
        raise ScanError(str(exc)) from exc
    return buckets, sa_keys


def _collect_aws_data(
    credentials: Credentials,
    *,
    probe: bool,
    ignore: set[str],
    scan_iam: bool,
    resolve_regions: bool,
) -> tuple[list[BucketSnapshot], list[ServiceAccountKeySnapshot], str]:
    default_region = credentials.region or "us-east-1"
    listing_client = build_aws_s3_client(credentials, region=default_region)
    account_id = resolve_account_id(credentials)
    account_cfg, account_status = get_account_public_access_block(credentials, account_id)
    if account_status == "ok":
        account_bpa: dict | None = account_cfg or {}
        account_partial = False
    elif account_status == "missing":
        account_bpa = {}
        account_partial = False
    else:
        account_bpa = None
        account_partial = True
    client_cache: dict[str, object] = {default_region: listing_client}

    def client_for_region(region: str):
        if region not in client_cache:
            client_cache[region] = build_aws_s3_client(credentials, region=region)
        return client_cache[region]

    buckets: list[BucketSnapshot] = []
    for name in list_bucket_names(listing_client):
        if name in ignore:
            continue
        bucket_region = default_region
        if resolve_regions:
            bucket_region = resolve_bucket_region(
                listing_client,
                name,
                default=default_region,
            )
        snapshot = snapshot_aws_bucket(
            client_for_region(bucket_region),
            name,
            account_id=account_id,
            region=bucket_region,
            account_public_access_block=account_bpa,
        )
        if account_partial:
            partial = list(snapshot.partial_metadata)
            if "account_public_access" not in partial:
                partial.append("account_public_access")
            snapshot = snapshot.model_copy(update={"partial_metadata": partial})
        if probe:
            snapshot = probe_bucket(snapshot)
        buckets.append(snapshot)

    sa_keys: list[ServiceAccountKeySnapshot] = []
    if scan_iam:
        try:
            sa_keys = list_iam_access_keys(credentials)
        except (ClientError, BotoCoreError, OSError):
            sa_keys = []
    return buckets, sa_keys, account_id


def _collect_azure_data(
    credentials: Credentials,
    *,
    subscription_id: str,
    probe: bool,
    ignore: set[str],
) -> tuple[list[BucketSnapshot], list[ServiceAccountKeySnapshot], str]:
    try:
        buckets = collect_azure_containers(
            credentials,
            subscription_id=subscription_id,
            ignore=ignore,
        )
    except AzureDependencyError as exc:
        raise ScanError(str(exc)) from exc
    if probe:
        buckets = [probe_bucket(bucket) for bucket in buckets]
    return buckets, [], subscription_id


def _collect_gcs_data(
    credentials: Credentials,
    *,
    project_id: str,
    probe: bool,
    ignore: set[str],
) -> tuple[list[BucketSnapshot], list[ServiceAccountKeySnapshot], str]:
    try:
        buckets = collect_gcs_buckets(
            credentials,
            project_id=project_id,
            ignore=ignore,
        )
    except GcsDependencyError as exc:
        raise ScanError(str(exc)) from exc
    if probe:
        buckets = [probe_bucket(bucket) for bucket in buckets]
    return buckets, [], project_id


def resolve_folder_ids(config: ScanConfig, folder_id: str | None = None) -> list[str]:
    if folder_id:
        return [folder_id]
    if config.folder_ids:
        return list(config.folder_ids)
    if config.folder_id:
        return [config.folder_id]
    return []


def _finalize_report(
    *,
    buckets: list[BucketSnapshot],
    sa_keys: list[ServiceAccountKeySnapshot],
    folder: str,
    scope_ids: list[str],
    report_cloud: str,
    method: str,
    probe: bool,
    config: ScanConfig,
    terraform_path: Path | None,
    repo_path: Path | None,
    tracefuse_report: Path | None,
    started: float,
) -> ScanReport:
    findings = []
    for bucket in buckets:
        findings.extend(check_bucket(bucket))
    findings.extend(check_service_accounts(sa_keys, key_age_days=config.key_age_days))
    if terraform_path:
        findings.extend(diff_terraform(terraform_path, buckets))
    if repo_path:
        findings.extend(scan_repo(repo_path, cloud=config.cloud))
    if tracefuse_report:
        findings.extend(load_tracefuse_report(tracefuse_report))
    findings = apply_overrides(findings, config.severity_overrides)
    findings = [redact_finding(item) for item in findings]
    findings = dedupe_account_scoped_findings(findings)
    chains = compose_chains(buckets, findings)
    summary = _build_summary(findings, chains, buckets_scanned=len(buckets))
    summary.scan_duration_ms = _elapsed_ms(started)
    return ScanReport(
        version=__version__,
        cloud=report_cloud,
        folder_id=folder,
        scope_ids=scope_ids,
        probe_enabled=probe,
        buckets=buckets,
        findings=findings,
        chains=chains,
        summary=summary,
        method=method,
    )


def run_scan(
    *,
    folder_id: str | None,
    fixture: Path | None,
    config: ScanConfig,
    terraform_path: Path | None = None,
    repo_path: Path | None = None,
    tracefuse_report: Path | None = None,
) -> ScanReport:
    started = time.perf_counter()
    probe = config.probe
    ignore = config.ignore_buckets
    tf_path = terraform_path or config.terraform_path
    repo = repo_path or config.repo_path
    tracefuse = tracefuse_report or config.tracefuse_report
    cloud = config.cloud

    if fixture:
        resolved_folder, buckets, sa_keys = load_fixture(fixture)
        folder = folder_id or resolved_folder
        if probe:
            buckets = [probe_bucket(bucket) for bucket in buckets]
        method = "fixture"
        report_cloud = buckets[0].cloud if buckets else cloud.value
    elif cloud == CloudProvider.AWS:
        credentials = resolve_credentials(
            cloud=CloudProvider.AWS,
            region=config.aws_region,
            profile=config.aws_profile,
        )
        buckets, sa_keys, account_id = _collect_aws_data(
            credentials,
            probe=probe,
            ignore=ignore,
            scan_iam=config.aws_scan_iam,
            resolve_regions=config.aws_resolve_regions,
        )
        folder = folder_id or account_id
        method = "live"
        report_cloud = CloudProvider.AWS.value
    elif cloud == CloudProvider.AZURE:
        credentials = resolve_credentials(cloud=CloudProvider.AZURE)
        scope_ids = resolve_folder_ids(config, folder_id)
        if not scope_ids and credentials.subscription_id:
            scope_ids = [credentials.subscription_id]
        if not scope_ids:
            raise ScanError(
                "Provide --folder-id with Azure subscription GUID, folder_ids in config, "
                "or set AZURE_SUBSCRIPTION_ID."
            )
        all_buckets: list[BucketSnapshot] = []
        for subscription_id in scope_ids:
            buckets_part, _, _ = _collect_azure_data(
                credentials,
                subscription_id=subscription_id,
                probe=probe,
                ignore=ignore,
            )
            all_buckets.extend(buckets_part)
        folder = ",".join(scope_ids)
        method = "live"
        report_cloud = CloudProvider.AZURE.value
        return _finalize_report(
            buckets=all_buckets,
            sa_keys=[],
            folder=folder,
            scope_ids=scope_ids,
            report_cloud=report_cloud,
            method=method,
            probe=probe,
            config=config,
            terraform_path=tf_path,
            repo_path=repo,
            tracefuse_report=tracefuse,
            started=started,
        )
    elif cloud == CloudProvider.GCS:
        credentials = resolve_credentials(cloud=CloudProvider.GCS)
        scope_ids = resolve_folder_ids(config, folder_id)
        if not scope_ids and credentials.folder_id:
            scope_ids = [credentials.folder_id]
        if not scope_ids:
            raise ScanError(
                "Provide --folder-id with GCP project ID, folder_ids in config, "
                "or set GCP_PROJECT / GOOGLE_CLOUD_PROJECT."
            )
        all_buckets = []
        for project_id in scope_ids:
            buckets_part, _, _ = _collect_gcs_data(
                credentials,
                project_id=project_id,
                probe=probe,
                ignore=ignore,
            )
            all_buckets.extend(buckets_part)
        folder = ",".join(scope_ids)
        method = "live"
        report_cloud = CloudProvider.GCS.value
        return _finalize_report(
            buckets=all_buckets,
            sa_keys=[],
            folder=folder,
            scope_ids=scope_ids,
            report_cloud=report_cloud,
            method=method,
            probe=probe,
            config=config,
            terraform_path=tf_path,
            repo_path=repo,
            tracefuse_report=tracefuse,
            started=started,
        )
    else:
        folder_ids = resolve_folder_ids(config, folder_id)
        if not folder_ids:
            raise ScanError("Provide --folder-id, folder_ids in config, or --fixture.")
        credentials = resolve_credentials(cloud=CloudProvider.YANDEX)
        all_buckets: list[BucketSnapshot] = []
        all_sa_keys: list[ServiceAccountKeySnapshot] = []
        for fid in folder_ids:
            buckets_part, keys_part = _collect_yandex_data(
                fid,
                credentials,
                probe=probe,
                ignore=ignore,
            )
            all_buckets.extend(buckets_part)
            all_sa_keys.extend(keys_part)
        folder = ",".join(folder_ids)
        method = "live"
        report_cloud = CloudProvider.YANDEX.value
        return _finalize_report(
            buckets=all_buckets,
            sa_keys=all_sa_keys,
            folder=folder,
            scope_ids=folder_ids,
            report_cloud=report_cloud,
            method=method,
            probe=probe,
            config=config,
            terraform_path=tf_path,
            repo_path=repo,
            tracefuse_report=tracefuse,
            started=started,
        )

    findings = []
    for bucket in buckets:
        findings.extend(check_bucket(bucket))
    findings.extend(check_service_accounts(sa_keys, key_age_days=config.key_age_days))
    if tf_path:
        findings.extend(diff_terraform(tf_path, buckets))
    if repo:
        findings.extend(scan_repo(repo, cloud=cloud))
    if tracefuse:
        findings.extend(load_tracefuse_report(tracefuse))
    findings = apply_overrides(findings, config.severity_overrides)
    findings = [redact_finding(item) for item in findings]
    findings = dedupe_account_scoped_findings(findings)
    chains = compose_chains(buckets, findings)

    scope_ids = [folder] if folder else []
    summary = _build_summary(findings, chains, buckets_scanned=len(buckets))
    summary.scan_duration_ms = _elapsed_ms(started)
    return ScanReport(
        version=__version__,
        cloud=report_cloud,
        folder_id=folder,
        scope_ids=scope_ids,
        probe_enabled=probe,
        buckets=buckets,
        findings=findings,
        chains=chains,
        summary=summary,
        method=method,
    )


def _elapsed_ms(started: float) -> int:
    """Wall time in ms; floor at 1 when the scan actually ran (sub-ms fixtures)."""
    elapsed = (time.perf_counter() - started) * 1000
    if elapsed <= 0:
        return 0
    return max(1, int(elapsed))


def _build_summary(findings, chains, *, buckets_scanned: int) -> ScanSummary:
    summary = ScanSummary(buckets_scanned=buckets_scanned, chains=len(chains))
    score = 0
    for finding in findings:
        summary.total += 1
        score += SEVERITY_WEIGHT[finding.severity]
        setattr(summary, finding.severity.value, getattr(summary, finding.severity.value) + 1)
    summary.score = min(score, 100)
    return summary


def should_fail(report: ScanReport, threshold: Severity, *, new_only: bool = False) -> bool:
    findings = report.new_findings if new_only else report.findings
    chains = report.new_chains if new_only else report.chains
    for finding in findings:
        if severity_at_least(finding.severity, threshold):
            return True
    for chain in chains:
        if severity_at_least(chain.severity, threshold):
            return True
    return False
