"""PyPI package smoke tests."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from bucket_scanner import __version__


def test_version_matches_package():
    assert __version__ == "0.12.0"
    try:
        installed = version("bucket-scanner")
    except PackageNotFoundError:
        installed = __version__
    assert installed.split(".")[:2] == __version__.split(".")[:2]
