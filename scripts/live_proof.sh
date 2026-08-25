#!/usr/bin/env bash
# Live / fixture proof run: scan → JSON → proof-log → short summary.
# Usage:
#   ./scripts/live_proof.sh                          # offline fixture (default)
#   ./scripts/live_proof.sh --live --folder-id b1g…  # needs YC_TOKEN
#   ./scripts/live_proof.sh --profile yc-prod --config .bucket-scanner.toml

set -euo pipefail

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$root"

BS="${BS:-}"
if [ -z "$BS" ]; then
  if [ -x .venv/bin/bucket-scanner ]; then
    BS=.venv/bin/bucket-scanner
  else
    BS=bucket-scanner
  fi
fi

OUT_DIR="${OUT_DIR:-proofs/runs}"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT_DIR"

mode=fixture
folder_id=""
profile=""
config=""
cloud=""
extra=()

while [ $# -gt 0 ]; do
  case "$1" in
    --live) mode=live; shift ;;
    --folder-id) folder_id=$2; shift 2 ;;
    --profile) profile=$2; shift 2 ;;
    --config) config=$2; shift 2 ;;
    --cloud) cloud=$2; shift 2 ;;
    --probe) extra+=(--probe); shift ;;
    -h|--help)
      sed -n '2,8p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

report="$OUT_DIR/report-$stamp.json"
sarif="$OUT_DIR/report-$stamp.sarif"
prom="$OUT_DIR/report-$stamp.prom"
log="${PROOF_LOG:-proofs/fp-log.jsonl}"

args=(scan --fail-on high --json --sarif "$sarif" --prometheus "$prom" -q)
if [ -n "$config" ]; then args+=(--config "$config"); fi
if [ -n "$profile" ]; then
  args+=(--profile "$profile")
elif [ "$mode" = fixture ]; then
  args+=(--fixture examples/demo-vulnerable/fixture.toml)
else
  if [ -z "$folder_id" ] && [ -z "${YC_FOLDER_ID:-}" ]; then
    echo "error: live mode needs --folder-id or YC_FOLDER_ID" >&2
    exit 2
  fi
  if [ -z "${YC_TOKEN:-}" ]; then
    echo "error: live mode needs YC_TOKEN" >&2
    exit 2
  fi
  args+=(--cloud "${cloud:-yandex}")
  if [ -n "$folder_id" ]; then args+=(--folder-id "$folder_id"); fi
fi
args+=("${extra[@]}")

echo "== doctor =="
doctor_args=(doctor)
if [ -n "$config" ]; then doctor_args+=(--config "$config"); fi
if [ -n "$profile" ]; then doctor_args+=(--profile "$profile"); fi
if [ -n "$cloud" ]; then doctor_args+=(--cloud "$cloud"); fi
"$BS" "${doctor_args[@]}" || true

echo "== scan → $report =="
set +e
"$BS" "${args[@]}" >"$report"
rc=$?
set -e
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  echo "scan failed rc=$rc" >&2
  exit "$rc"
fi

echo "== proof-log → $log =="
"$BS" proof-log update --report "$report" --log "$log"
"$BS" proof-log summary --log "$log"

echo
echo "artifacts:"
echo "  $report"
echo "  $sarif"
echo "  $prom"
echo "  $log"
echo "triage example:"
echo "  $BS proof-log set --log $log --fingerprint 'rule|bucket|' --status false_positive --notes 'why'"
