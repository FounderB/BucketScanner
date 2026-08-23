# Prometheus + Grafana

## Metrics endpoint

```bash
bucket-scanner serve --fixture examples/demo-vulnerable/fixture.toml --addr 127.0.0.1:9090
curl -s http://127.0.0.1:9090/metrics
```

Or write metrics from a one-shot scan:

```bash
bucket-scanner scan --fixture examples/demo-vulnerable/fixture.toml \
  --prometheus /tmp/bucket-scanner.prom
```

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `bucket_scanner_score` | gauge | Risk score 0–100 |
| `bucket_scanner_buckets_scanned` | gauge | Buckets in last scan |
| `bucket_scanner_findings_total{severity}` | gauge | Findings by severity |
| `bucket_scanner_chains_total` | gauge | Misconfig chains |
| `bucket_scanner_chain_present{chain_id}` | gauge | Specific chain detected |

## Grafana

Import `examples/grafana/bucket-scanner-dashboard.json` and point Prometheus at the `/metrics` target.

Continuous drift monitoring:

```bash
bucket-scanner serve --folder-id "$YC_FOLDER_ID" --addr :9090 --interval 300
```
