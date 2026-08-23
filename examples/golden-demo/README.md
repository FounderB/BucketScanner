# Golden demo

Copy [workflow.yml](workflow.yml) into `.github/workflows/` or run locally:

```bash
make test
bucket-scanner scan --profile yc-fixture \
  --config examples/ci/.bucket-scanner.toml --fail-on high -q || test $? -eq 1
```

Full walkthrough: [docs/GOLDEN_DEMO.md](../../docs/GOLDEN_DEMO.md)
