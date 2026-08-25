"""PyPI package smoke tests."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from bucket_scanner import __version__


def test_version_matches_package():
    assert __version__ == "1.9.0"
    try:
        installed = version("bucket-scanner")
    except PackageNotFoundError:
        return
    assert installed == __version__, (
        f"Installed bucket-scanner {installed} != source {__version__}. Run: pip install -e ."
    )
