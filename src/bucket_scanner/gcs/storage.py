"""Google Cloud Storage live inventory."""

from __future__ import annotations

from typing import Any

from bucket_scanner.auth import Credentials
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.models import BucketSnapshot

PUBLIC_IAM_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


class GcsDependencyError(ImportError):
    pass


def _import_gcs():
    try:
        from google.cloud import storage
    except ImportError as exc:
        raise GcsDependencyError(
            "GCS live scan requires optional dependencies: pip install 'bucket-scanner[gcs]'"
        ) from exc
    return storage


def _pap_label(value: Any) -> str:
    if value is None:
        return "unspecified"
    text = str(value).lower()
    if text in {"inherited", "enforced", "unspecified"}:
        return text
    return "unspecified"


def _iam_grants_public(policy: Any) -> bool:
    for binding in getattr(policy, "bindings", []) or []:
        members = binding.get("members", [])
        if PUBLIC_IAM_MEMBERS.intersection(members):
            return True
    return False


def snapshot_gcs_bucket(
    *,
    name: str,
    project_id: str,
    region: str | None,
    public_access_prevention: str,
    uniform_bucket_level_access: bool,
    iam_public: bool,
    encryption_enabled: bool,
    logging_enabled: bool,
    versioning_enabled: bool,
) -> BucketSnapshot:
    return BucketSnapshot(
        name=name,
        cloud=CloudProvider.GCS.value,
        folder_id=project_id,
        region=region,
        acl="public-read" if iam_public else "private",
        encryption_enabled=encryption_enabled,
        logging_enabled=logging_enabled,
        versioning_enabled=versioning_enabled,
        block_public_access={
            "public_access_prevention": public_access_prevention,
            "uniform_bucket_level_access": uniform_bucket_level_access,
            "iam_public": iam_public,
        },
        tags={"project_id": project_id},
    )


def collect_gcs_buckets(
    credentials: Credentials,
    *,
    project_id: str,
    ignore: set[str],
) -> list[BucketSnapshot]:
    storage = _import_gcs()
    client = storage.Client(project=project_id)

    buckets: list[BucketSnapshot] = []
    for bucket in client.list_buckets(project=project_id):
        name = bucket.name
        if not name or name in ignore:
            continue
        try:
            bucket.reload()
        except OSError:
            continue

        iam_config = bucket.iam_configuration
        pap = _pap_label(getattr(iam_config, "public_access_prevention", None))
        ubla = bool(getattr(iam_config, "uniform_bucket_level_access_enabled", False))

        iam_public = False
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            iam_public = _iam_grants_public(policy)
        except OSError:
            iam_public = False

        buckets.append(
            snapshot_gcs_bucket(
                name=name,
                project_id=project_id,
                region=bucket.location,
                public_access_prevention=pap,
                uniform_bucket_level_access=ubla,
                iam_public=iam_public,
                encryption_enabled=True,
                logging_enabled=bucket.logging is not None,
                versioning_enabled=bool(bucket.versioning_enabled),
            )
        )
    return buckets
