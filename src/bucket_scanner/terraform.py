"""Parse Terraform intent for Object Storage buckets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

RESOURCE_START = re.compile(
    r'resource\s+"(?:yandex_storage_bucket|aws_s3_bucket|aws_s3_bucket_acl)"\s+"([^"]+)"\s*\{'
)
STRING_FIELD = re.compile(r'^\s*(bucket|acl|bucket_prefix)\s*=\s*"([^"]*)"')
BLOCK_NAME = re.compile(r'^\s*(bucket|acl)\s*=\s*(\w+)\.(\w+)')

SKIP_EXTENSIONS = {".tfstate", ".terraform"}


@dataclass(frozen=True)
class TerraformBucketIntent:
    resource_name: str
    bucket: str | None = None
    acl: str | None = None
    source_file: str | None = None


def parse_terraform_dir(path: Path) -> list[TerraformBucketIntent]:
    intents: list[TerraformBucketIntent] = []
    for file_path in sorted(path.rglob("*.tf")):
        if any(part in SKIP_EXTENSIONS for part in file_path.parts):
            continue
        intents.extend(parse_terraform_file(file_path))
    return intents


def parse_terraform_file(path: Path) -> list[TerraformBucketIntent]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    intents: list[TerraformBucketIntent] = []
    index = 0
    while index < len(lines):
        match = RESOURCE_START.match(lines[index])
        if not match:
            index += 1
            continue
        resource_name = match.group(1)
        block_lines, index = _read_block(lines, index)
        bucket, acl = _parse_block_fields(block_lines)
        if bucket:
            intents.append(
                TerraformBucketIntent(
                    resource_name=resource_name,
                    bucket=bucket,
                    acl=acl,
                    source_file=str(path),
                )
            )
    return intents


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


def _parse_block_fields(block_lines: list[str]) -> tuple[str | None, str | None]:
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
            continue
        ref_match = BLOCK_NAME.match(line)
        if ref_match:
            key, _, _ = ref_match.groups()
            if key == "bucket" and bucket is None:
                bucket = f"${ref_match.group(2)}.{ref_match.group(3)}"
            if key == "acl" and acl is None:
                acl = "private"
    return bucket, acl
