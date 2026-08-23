# Habr draft — Bucket Scanner v1.x

> Черновик для публикации. Не копировать дословно без проверки скринов и версий.

## Заголовок (варианты)

1. **Declared vs real: сканер объектных хранилищ для YC, AWS, Azure и GCS**
2. **Как я автоматизировал проверку «заявлено в Terraform / реально в облаке»**

## Лид

Object Storage — главная точка утечек в облаке. Bucket Scanner сравнивает **заявленное** (Terraform, политики) с **реальным** (ACL, public access, IAM) и отдаёт SARIF для GitHub Code Scanning, compliance JSON и Prometheus-метрики.

Четыре облака: Yandex Cloud, AWS S3, Azure Blob, GCS.

## Проблема

- Terraform говорит `private`, в live — `public-read`
- Секрет в репо + публичный bucket = chain `leaked-credentials-exposure`
- CI падает на legacy findings — нужен baseline (`--fail-on new`)

## Решение за 60 секунд

```bash
pip install bucket-scanner==1.1.0
bucket-scanner scan --fixture examples/demo-vulnerable/fixture.toml \
  --terraform examples/demo-vulnerable/terraform \
  --compliance-report compliance.json \
  --sarif report.sarif --fail-on high
```

## Чем отличается

| | Bucket Scanner | Классический CSPM |
|---|----------------|-------------------|
| Фокус | Object Storage | Весь аккаунт |
| IaC drift | Terraform intent vs live | Редко |
| Cross-stack | Tracefuse + repo secrets | Отдельные tools |
| CI | GitHub Action + baseline | Тяжёлые агенты |

## GitHub Actions

```yaml
- uses: FounderB/BucketScanner/action@v1.1.0
  with:
    profile: yc-prod
    fail-on: new
    baseline-path: baselines/yc-prod.json
  env:
    YC_TOKEN: ${{ secrets.YC_TOKEN }}
```

OIDC для AWS / Azure / GCS — шаблоны в `examples/ci/workflow-*-oidc.yml`.

## Grafana на VM

`bucket-scanner serve --interval 300` + dashboard из репозитория — см. [GRAFANA.md](GRAFANA.md).

## Compliance

SARIF tags: CIS-1.5, NIST-AC-3, SOC2-CC6.1 — фильтр в Code Scanning.

## CTA

- GitHub: https://github.com/FounderB/BucketScanner
- PyPI: https://pypi.org/project/bucket-scanner/
- Discussions: вопросы и профили CI

## Теги для Habr

`devsecops`, `yandex cloud`, `aws`, `terraform`, `sarif`, `object storage`, `security`

## Скрины для статьи (TODO)

1. Terminal: fixture scan + chain output
2. GitHub Code Scanning SARIF
3. Grafana dashboard (risk score panel)
4. `bucket-scanner diff` IaC drift
