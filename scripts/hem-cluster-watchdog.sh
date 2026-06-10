#!/usr/bin/env bash
set -euo pipefail

INTERVAL="${HEM_CLUSTER_WATCHDOG_INTERVAL:-60}"
ONCE=0
WITH_BACKUP=0
ALERT_CMD="${HEM_CLUSTER_ALERT_CMD:-}"
RECEIPT_REF="${HEM_CLUSTER_WATCHDOG_RECEIPT_REF:-}"
RECEIPT_KEY="${HEM_CLUSTER_WATCHDOG_RECEIPT_KEY:-}"
SMOKE_SCRIPT="${HEM_CLUSTER_SMOKE_SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hem-cluster-smoke.sh}"
ARTIFACT_ROOT="${HEM_CLUSTER_WATCHDOG_ARTIFACT_ROOT:-artifacts/hem-cluster-watchdog}"

usage() {
  cat <<'USAGE'
Usage: scripts/hem-cluster-watchdog.sh [options] [-- smoke-options...]

Options:
  --once                  Run one monitoring pass and exit.
  --interval SECONDS      Poll interval. Default: 60.
  --with-backup           Take a full backup on each pass. By default watchdog skips backups.
  --receipt-ref REF       Safely read REF and verify read.fulfilled receipts.
  --receipt-key KEY       Optional key for receipt-ref.
  --alert-cmd CMD         Shell command invoked on failure. Receives HEM_ALERT_MESSAGE.

The watchdog delegates checks to hem-cluster-smoke.sh watchdog-once. It alerts on
non-zero health, divergent or lagging peers, offline peers, permission failures,
sync errors, and missing read.fulfilled receipts when --receipt-ref is provided.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --once)
      ONCE=1
      shift
      ;;
    --interval)
      INTERVAL="$2"
      shift 2
      ;;
    --with-backup)
      WITH_BACKUP=1
      shift
      ;;
    --receipt-ref)
      RECEIPT_REF="$2"
      shift 2
      ;;
    --receipt-key)
      RECEIPT_KEY="$2"
      shift 2
      ;;
    --alert-cmd)
      ALERT_CMD="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

alert() {
  local message="$1"
  printf '[%s] ALERT %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$message" >&2
  if [[ -n "$ALERT_CMD" ]]; then
    HEM_ALERT_MESSAGE="$message" sh -c "$ALERT_CMD" || true
  fi
}

run_once() {
  local run_id artifact_dir args=()
  run_id="watchdog-$(date -u +%Y%m%d%H%M%S)"
  artifact_dir="${ARTIFACT_ROOT}/${run_id}"
  args+=(watchdog-once --run-id "$run_id" --artifact-dir "$artifact_dir")
  if [[ "$WITH_BACKUP" != "1" ]]; then
    args+=(--skip-backup)
  fi
  if [[ -n "$RECEIPT_REF" ]]; then
    args+=(--receipt-probe-ref "$RECEIPT_REF")
  fi
  if [[ -n "$RECEIPT_KEY" ]]; then
    args+=(--receipt-probe-key "$RECEIPT_KEY")
  fi
  args+=("$@")

  if "$SMOKE_SCRIPT" "${args[@]}"; then
    printf '[%s] hem cluster watchdog ok artifacts=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$artifact_dir"
    return 0
  fi
  alert "hem cluster watchdog failed; artifacts=${artifact_dir}"
  return 1
}

while true; do
  run_once "$@" || true
  if [[ "$ONCE" == "1" ]]; then
    exit 0
  fi
  sleep "$INTERVAL"
done
