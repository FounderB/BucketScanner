# Grafana on VM (Block O / lab deployment)

Continuous drift monitoring: `bucket-scanner serve` exposes Prometheus metrics; Grafana visualizes risk score and findings.

## Architecture

```
bucket-scanner serve ──► :9090/metrics ◄── Prometheus scrape ──► Grafana dashboard
     ▲
     └── rescan every interval_seconds (profile from .bucket-scanner.toml)
```

## 1. Install on Ubuntu Server (lab VM)

```bash
pip install 'bucket-scanner==1.1.0'
cp examples/ci/.bucket-scanner.prod.toml.example .bucket-scanner.toml
# edit folder_ids / secrets
```

## 2. Systemd unit

Copy and enable:

```bash
sudo cp examples/systemd/bucket-scanner-serve.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bucket-scanner-serve
curl -s http://127.0.0.1:9090/health
curl -s http://127.0.0.1:9090/metrics | head
```

Unit runs as dedicated user, reads `/etc/bucket-scanner/.bucket-scanner.toml`, listens on `127.0.0.1:9090` (expose via reverse proxy or bind to LAN if needed).

Environment file for secrets (`/etc/bucket-scanner/env`):

```bash
YC_TOKEN=...
YC_FOLDER_ID=b1g...
# or AWS_*, AZURE_*, GOOGLE_APPLICATION_CREDENTIALS
```

## 3. Prometheus scrape

Add to `prometheus.yml` (see `examples/prometheus/scrape-bucket-scanner.yml`):

```yaml
scrape_configs:
  - job_name: bucket-scanner
    static_configs:
      - targets: ["127.0.0.1:9090"]
    metrics_path: /metrics
    scrape_interval: 60s
```

Labels on metrics: `cloud`, `scope_id` — filter in Grafana template variables.

## 4. Grafana dashboard

1. Import `examples/grafana/bucket-scanner-dashboard.json`
2. Select Prometheus datasource
3. Pick `cloud` + `scope_id` variables

Panels: risk score, findings by severity, misconfig chains.

## 5. Profile + baseline on VM

For prod folder with legacy noise:

```toml
[scan]
baseline_path = "baselines/prod.json"
fail_on = "high"

[serve]
interval_seconds = 300
profile = "yc-prod"
```

Metrics `bucket_scanner_new_total` and `bucket_scanner_suppressed_total` appear when baseline/suppressions are configured.

## 6. nftables / network (Block O)

If the scanner container/VM uses `192.168.10.100` or host forwarding:

- Bind `serve` to LAN IP only: `--addr 192.168.10.5:9090` or `[serve] addr` in TOML
- Allow Prometheus host (`10.0.0.0/24`) in `FORWARD`/`INPUT` — same pattern as health-check `:8080` in Block O nftables

## Quick offline test (no cloud)

```bash
bucket-scanner serve \
  --profile yc-fixture \
  --config examples/ci/.bucket-scanner.toml \
  --addr 127.0.0.1:9090 \
  --interval 60
```

See also [PROMETHEUS.md](PROMETHEUS.md).
