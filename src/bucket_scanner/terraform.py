"""Parse Terraform intent for Object Storage buckets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUCKET_RESOURCE = re.compile(
    r'resource\s+"(yandex_storage_bucket|aws_s3_bucket)"\s+"([^"]+)"\s*\{'
)
ACL_RESOURCE = re.compile(r'resource\s+"aws_s3_bucket_acl"\s+"([^"]+)"\s*\{')
BPA_RESOURCE = re.compile(r'resource\s+"aws_s3_bucket_public_access_block"\s+"([^"]+)"\s*\{')
STRING_FIELD = re.compile(r'^\s*(bucket|acl|bucket_prefix)\s*=\s*"([^"]*)"')
REF_FIELD = re.compile(r"^\s*(bucket)\s*=\s*([\w.]+)")
BOOL_FIELD = re.compile(
    r"^\s*(block_public_acls|ignore_public_acls|block_public_policy|restrict_public_buckets)"
    r"\s*=\s*(true|false)",
    re.IGNORECASE,
)

SKIP_EXTENSIONS = {".tfstate", ".terraform"}
BPA_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


@dataclass(frozen=True)
class TerraformBucketIntent:
    resource_name: str
    bucket: str | None = None
    acl: str | None = None
    block_public_access: dict[str, bool] = field(default_factory=dict)
    source_file: str | None = None
    resource_type: str | None = None


def parse_terraform_dir(path: Path) -> list[TerraformBucketIntent]:
    bucket_blocks: list[tuple[str, str, list[str], str]] = []
    acl_blocks: list[tuple[str, list[str], str]] = []
    bpa_blocks: list[tuple[str, list[str], str]] = []

    for file_path in sorted(path.rglob("*.tf")):
        if any(part in SKIP_EXTENSIONS for part in file_path.parts):
            continue
        text = file_path.read_text(encoding="utf-8")
        lines = text.splitlines()
        index = 0
        while index < len(lines):
            bucket_match = BUCKET_RESOURCE.match(lines[index])
            if bucket_match:
                resource_type, resource_name = bucket_match.groups()
                block_lines, index = _read_block(lines, index)
                bucket_blocks.append((resource_type, resource_name, block_lines, str(file_path)))
                continue
            acl_match = ACL_RESOURCE.match(lines[index])
            if acl_match:
                resource_name = acl_match.group(1)
                block_lines, index = _read_block(lines, index)
                acl_blocks.append((resource_name, block_lines, str(file_path)))
                continue
            bpa_match = BPA_RESOURCE.match(lines[index])
            if bpa_match:
                resource_name = bpa_match.group(1)
                block_lines, index = _read_block(lines, index)
                bpa_blocks.append((resource_name, block_lines, str(file_path)))
                continue
            index += 1

    registry = _build_bucket_registry(bucket_blocks)
    intents: list[TerraformBucketIntent] = []

    for resource_type, resource_name, block_lines, source_file in bucket_blocks:
        bucket, acl = _parse_bucket_block(block_lines)
        if bucket:
            intents.append(
                TerraformBucketIntent(
                    resource_name=resource_name,
                    bucket=bucket,
                    acl=acl or "private",
                    source_file=source_file,
                    resource_type=resource_type,
                )
            )

    for resource_name, block_lines, source_file in acl_blocks:
        bucket_ref, acl = _parse_acl_block(block_lines)
        bucket = _resolve_bucket_ref(bucket_ref, registry) if bucket_ref else None
        if bucket:
            intents.append(
                TerraformBucketIntent(
                    resource_name=resource_name,
                    bucket=bucket,
                    acl=acl or "private",
                    source_file=source_file,
                    resource_type="aws_s3_bucket_acl",
                )
            )

    for resource_name, block_lines, source_file in bpa_blocks:
        bucket_ref, bpa = _parse_bpa_block(block_lines)
        bucket = _resolve_bucket_ref(bucket_ref, registry) if bucket_ref else None
        if bucket:
            intents.append(
                TerraformBucketIntent(
                    resource_name=resource_name,
                    bucket=bucket,
                    block_public_access=bpa,
                    source_file=source_file,
                    resource_type="aws_s3_bucket_public_access_block",
                )
            )

    return _dedupe_intents(intents)


def parse_terraform_file(path: Path) -> list[TerraformBucketIntent]:
    root = path if path.is_dir() else path.parent
    return parse_terraform_dir(root)


def _build_bucket_registry(
    bucket_blocks: list[tuple[str, str, list[str], str]],
) -> dict[str, str]:
    registry: dict[str, str] = {}
    for resource_type, resource_name, block_lines, _ in bucket_blocks:
        bucket, _ = _parse_bucket_block(block_lines)
        if bucket:
            registry[f"{resource_type}.{resource_name}"] = bucket
    return registry


def _parse_bucket_block(block_lines: list[str]) -> tuple[str | None, str | None]:
    bucket: str | None = None
    acl: str | None = None
    for line in block_lines:
        string_match = STRING_FIELD.match(line)
        if string_match:
            key, value = string_match.groups()
            if key == "bucket":
                bucket = value
            elif key == "acl":
                acl = value
    return bucket, acl


def _parse_acl_block(block_lines: list[str]) -> tuple[str | None, str | None]:
    bucket_ref: str | None = None
    acl: str | None = None
    for line in block_lines:
        string_match = STRING_FIELD.match(line)
        if string_match:
            key, value = string_match.groups()
            if key == "acl":
                acl = value
            continue
        ref_match = REF_FIELD.match(line)
        if ref_match:
            bucket_ref = ref_match.group(2)
    return bucket_ref, acl


def _parse_bpa_block(block_lines: list[str]) -> tuple[str | None, dict[str, bool]]:
    bucket_ref: str | None = None
    config: dict[str, bool] = {}
    for line in block_lines:
        bool_match = BOOL_FIELD.match(line)
        if bool_match:
            key, value = bool_match.groups()
            config[_normalize_bpa_key(key)] = value.lower() == "true"
            continue
        ref_match = REF_FIELD.match(line)
        if ref_match:
            bucket_ref = ref_match.group(2)
    return bucket_ref, config


def _normalize_bpa_key(key: str) -> str:
    mapping = {
        "block_public_acls": "BlockPublicAcls",
        "ignore_public_acls": "IgnorePublicAcls",
        "block_public_policy": "BlockPublicPolicy",
        "restrict_public_buckets": "RestrictPublicBuckets",
    }
    return mapping[key.lower()]


def _resolve_bucket_ref(value: str, registry: dict[str, str]) -> str | None:
    if value in registry.values():
        return value
    parts = value.split(".")
    if len(parts) >= 2:
        resource_type = parts[0]
        resource_name = parts[1]
        return registry.get(f"{resource_type}.{resource_name}")
    return None


def _dedupe_intents(intents: list[TerraformBucketIntent]) -> list[TerraformBucketIntent]:
    merged: dict[str, TerraformBucketIntent] = {}
    for intent in intents:
        if not intent.bucket:
            continue
        current = merged.get(intent.bucket)
        if current is None:
            merged[intent.bucket] = intent
            continue
        merged[intent.bucket] = TerraformBucketIntent(
            resource_name=intent.resource_name,
            bucket=intent.bucket,
            acl=intent.acl or current.acl,
            block_public_access={**current.block_public_access, **intent.block_public_access},
            source_file=intent.source_file or current.source_file,
            resource_type=intent.resource_type or current.resource_type,
        )
    return list(merged.values())


def _read_block(lines: list[str], start: int) -> tuple[list[str], int]:
    depth = 0
    collected: list[str] = []
    index = start
    while index < len(lines):
        line = lines[index]
        collected.append(line)
        depth += line.count("{") - line.count("}")
        index += 1
        if depth == 0 and index > start:
            break
    return collected, index
