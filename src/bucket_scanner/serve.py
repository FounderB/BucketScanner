"""HTTP server exposing Prometheus metrics and health checks."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bucket_scanner.config import ScanConfig
from bucket_scanner.gate import apply_gate
from bucket_scanner.report.prometheus import render_prometheus
from bucket_scanner.scan import ScanError, run_scan


class ScanCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._report = None
        self._error: str | None = None

    def update(self, report) -> None:
        with self._lock:
            self._report = report
            self._error = None

    def set_error(self, message: str) -> None:
        with self._lock:
            self._error = message

    def snapshot(self):
        with self._lock:
            return self._report, self._error


def run_metrics_server(
    *,
    addr: str,
    config: ScanConfig,
    fixture: Path | None,
    interval_seconds: int,
) -> None:
    cache = ScanCache()

    def refresh() -> None:
        try:
            report = run_scan(
                folder_id=None,
                fixture=fixture,
                config=config,
                repo_path=config.repo_path,
                tracefuse_report=config.tracefuse_report,
                terraform_path=config.terraform_path,
            )
            report = apply_gate(
                report,
                suppressions=config.suppressions,
                baseline_path=config.baseline_path,
            )
            cache.update(report)
        except ScanError as exc:
            cache.set_error(str(exc))

    refresh()

    def _loop() -> None:
        while interval_seconds > 0:
            time.sleep(interval_seconds)
            refresh()

    if interval_seconds > 0:
        thread = threading.Thread(target=_loop, daemon=True)
        thread.start()

    handler = _build_handler(cache)
    host, port = _parse_addr(addr)
    server = ThreadingHTTPServer((host, port), handler)
    server.serve_forever()


def _build_handler(cache: ScanCache) -> type[BaseHTTPRequestHandler]:
    class MetricsHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            if self.path in {"/", "/health", "/healthz"}:
                report, error = cache.snapshot()
                if error and report is None:
                    self._write(503, "text/plain", f"unhealthy: {error}\n")
                    return
                self._write(200, "text/plain", "ok\n")
                return
            if self.path == "/metrics":
                report, error = cache.snapshot()
                if report is None:
                    self._write(503, "text/plain", f"# error {error}\n")
                    return
                body = render_prometheus(report)
                self._write(200, "text/plain; version=0.0.4; charset=utf-8", body)
                return
            self._write(404, "text/plain", "not found\n")

        def _write(self, status: int, content_type: str, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return MetricsHandler


def _parse_addr(addr: str) -> tuple[str, int]:
    if addr.startswith(":"):
        return "0.0.0.0", int(addr[1:])  # nosec B104 - explicit user bind like :9090
    if ":" in addr:
        host, port = addr.rsplit(":", 1)
        return host, int(port)
    return "127.0.0.1", int(addr)
