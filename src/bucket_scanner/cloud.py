"""Cloud provider definitions."""

from __future__ import annotations

from enum import StrEnum


class CloudProvider(StrEnum):
    YANDEX = "yandex"
    AWS = "aws"

    @classmethod
    def parse(cls, value: str | None) -> CloudProvider:
        if not value:
            return cls.YANDEX
        normalized = value.lower().strip()
        if normalized in {"aws", "s3", "amazon"}:
            return cls.AWS
        if normalized in {"yandex", "yc", "yandex-cloud"}:
            return cls.YANDEX
        raise ValueError(f"Unsupported cloud provider: {value}")
