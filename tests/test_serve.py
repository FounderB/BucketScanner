"""Metrics server tests."""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from pathlib import Path

from bucket_scanner.config import ScanConfig
from bucket_scanner.serve import ScanCache, _build_handler, _parse_addr, run_metrics_server

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")


def test_parse_addr():
    assert _parse_addr("127.0.0.1:9090") == ("127.0.0.1", 9090)
    assert _parse_addr(":9090")[0] == "0.0.0.0"
    assert _parse_addr("9090") == ("127.0.0.1", 9090)


def test_scan_cache_snapshot():
    cache = ScanCache()
    cache.set_error("boom")
    report, error = cache.snapshot()
    assert report is None
    assert error == "boom"


def test_metrics_handler_serves_health_and_metrics():
    from bucket_scanner.scan import run_scan

    report = run_scan(folder_id=None, fixture=FIXTURE, config=ScanConfig())
    cache = ScanCache()
    cache.update(report)
    handler = _build_handler(cache)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    from http.server import ThreadingHTTPServer

    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    try:
        health = urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
        assert health.read() == b"ok\n"
        metrics = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2)
        body = metrics.read().decode("utf-8")
        assert "bucket_scanner_score" in body
        assert 'cloud="yandex"' in body
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_run_metrics_server_starts_and_serves(monkeypatch):
    from bucket_scanner import serve as serve_module

    captured: dict = {}

    class FakeServer:
        def __init__(self, addr, handler):
            captured["addr"] = addr

        def serve_forever(self):
            captured["started"] = True

    monkeypatch.setattr(serve_module, "ThreadingHTTPServer", FakeServer)
    config = ScanConfig()
    run_metrics_server(
        addr="127.0.0.1:9091",
        config=config,
        fixture=FIXTURE,
        interval_seconds=0,
    )
    assert captured["started"] is True
    assert captured["addr"] == ("127.0.0.1", 9091)
