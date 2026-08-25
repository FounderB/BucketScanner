"""Enrich BucketSnapshot from Yandex Storage Bucket.Get (management API)."""

from __future__ import annotations

from typing import Any

from bucket_scanner.models import BucketSnapshot


def classify_yc_acl(grants: list[dict[str, Any]] | None) -> str:
    """Map Yandex Storage ACL grants to public-read / public-read-write / private."""
    if not grants:
        return "private"
    has_public_read = False
    has_public_write = False
    for grant in grants:
        grant_type = str(grant.get("grantType", "")).upper()
        permission = str(grant.get("permission", "")).upper()
        public = "ALL_USERS" in grant_type or "ALL_AUTHENTICATED" in grant_type
        if not public:
            # Some payloads use grantee URI style.
            uri = str(grant.get("uri") or grant.get("granteeId") or "")
            public = "AllUsers" in uri or "AuthenticatedUsers" in uri
        if not public:
            continue
        if "WRITE" in permission or "FULL_CONTROL" in permission:
            has_public_write = True
        if "READ" in permission or "FULL_CONTROL" in permission:
            has_public_read = True
    if has_public_write:
        return "public-read-write"
    if has_public_read:
        return "public-read"
    return "private"


def _anonymous_flags(detail: dict[str, Any]) -> dict[str, bool] | None:
    raw = detail.get("anonymousAccessFlags") or detail.get("anonymous_access_flags")
    if not isinstance(raw, dict):
        return None
    flags: dict[str, bool] = {}
    for key in ("read", "list", "configRead", "config_read"):
        if key in raw:
            normalized = "config_read" if key in {"configRead", "config_read"} else key
            flags[normalized] = bool(raw[key])
    return flags or None


def _versioning_enabled(detail: dict[str, Any]) -> bool | None:
    value = detail.get("versioning") or detail.get("versioningStatus")
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).upper()
    return text in {"ENABLED", "VERSIONING_ENABLED", "TRUE"}


def _website_enabled(detail: dict[str, Any]) -> bool:
    settings = detail.get("websiteSettings") or detail.get("website_settings") or {}
    if not isinstance(settings, dict):
        return False
    return bool(
        settings.get("index")
        or settings.get("error")
        or settings.get("redirectAllRequests")
        or settings.get("routingRules")
    )


def _cors_rules(detail: dict[str, Any]) -> list[dict[str, Any]]:
    rules = detail.get("cors") or detail.get("corsRules") or []
    return rules if isinstance(rules, list) else []


def _lifecycle_rules(detail: dict[str, Any]) -> list[dict[str, Any]]:
    rules = detail.get("lifecycleRules") or detail.get("lifecycle_rules") or []
    if not isinstance(rules, list):
        return []
    # Normalize YC shape toward S3-like Expiration.Days when possible.
    normalized: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        item = dict(rule)
        expiration = item.get("expiration") or {}
        if isinstance(expiration, dict) and "days" in expiration and "Expiration" not in item:
            item["Expiration"] = {"Days": int(expiration["days"])}
        normalized.append(item)
    return normalized


def _tags(detail: dict[str, Any]) -> dict[str, str]:
    raw = detail.get("tags") or {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for item in raw:
            if isinstance(item, dict) and "key" in item:
                out[str(item["key"])] = str(item.get("value", ""))
        return out
    return {}


def enrich_from_bucket_get(snapshot: BucketSnapshot, detail: dict[str, Any]) -> BucketSnapshot:
    """Merge Bucket.Get VIEW_FULL fields into an existing snapshot."""
    updates: dict[str, Any] = {}

    flags = _anonymous_flags(detail)
    if flags is not None:
        updates["anonymous_access_flags"] = flags

    acl_payload = detail.get("acl") or {}
    grants = acl_payload.get("grants") if isinstance(acl_payload, dict) else None
    if grants is not None:
        updates["acl"] = classify_yc_acl(grants)

    policy = detail.get("policy")
    if isinstance(policy, dict) and policy:
        updates["policy"] = policy

    versioning = _versioning_enabled(detail)
    if versioning is not None:
        updates["versioning_enabled"] = versioning
        partial = [p for p in snapshot.partial_metadata if p != "versioning"]
        updates["partial_metadata"] = partial

    if _website_enabled(detail):
        updates["website_enabled"] = True

    cors = _cors_rules(detail)
    if cors:
        updates["cors_rules"] = cors

    lifecycle = _lifecycle_rules(detail)
    if lifecycle and not snapshot.lifecycle_rules:
        updates["lifecycle_rules"] = lifecycle

    tags = _tags(detail)
    if tags and not snapshot.tags:
        updates["tags"] = tags

    if "encryption" in detail:
        enc = detail.get("encryption") or {}
        rules = enc.get("rules") if isinstance(enc, dict) else None
        enabled = bool(isinstance(rules, list) and rules)
        # Prefer Bucket.Get when encryption was unknown; never downgrade a known S3 True.
        if "encryption" in snapshot.partial_metadata or not snapshot.metadata_known:
            updates["encryption_enabled"] = enabled
        elif enabled and not snapshot.encryption_enabled:
            updates["encryption_enabled"] = True

    # Management enrichment is enough to run ACL/policy/anonymous checks.
    if snapshot.metadata_known is False and (
        "acl" in updates or "policy" in updates or "anonymous_access_flags" in updates
    ):
        updates["metadata_known"] = True
        updates["auth_mode"] = snapshot.auth_mode or "management-only"
        partial = list(updates.get("partial_metadata", snapshot.partial_metadata))
        if "versioning_enabled" in updates:
            partial = [p for p in partial if p != "versioning"]
        if "encryption" in detail:
            partial = [p for p in partial if p != "encryption"]
        elif "encryption" not in partial:
            partial.append("encryption")
        if "logging" not in partial:
            partial.append("logging")
        updates["partial_metadata"] = partial

    if not updates:
        return snapshot
    return snapshot.model_copy(update=updates)


def snapshot_from_bucket_get(
    detail: dict[str, Any],
    *,
    folder_id: str | None = None,
) -> BucketSnapshot:
    """Build a snapshot purely from Bucket.Get (no S3 static keys)."""
    name = detail.get("name") or detail.get("id") or "unknown"
    base = BucketSnapshot(
        name=str(name),
        cloud="yandex",
        folder_id=folder_id or detail.get("folderId"),
        metadata_known=False,
        auth_mode="management-only",
        partial_metadata=["encryption", "logging"],
    )
    return enrich_from_bucket_get(base, detail)
