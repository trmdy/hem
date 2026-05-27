#!/usr/bin/env bash
set -euo pipefail

MODE="acceptance"
RUN_STAMP="$(date -u +%Y%m%d%H%M%S)"
RUN_ID="hem-cluster-${RUN_STAMP}"
ARTIFACT_DIR="${HEM_CLUSTER_SMOKE_ARTIFACT_DIR:-artifacts/hem-cluster-smoke/${RUN_ID}}"
WAIT_SECONDS="${HEM_CLUSTER_SMOKE_WAIT_SECONDS:-120}"
WAIT_INTERVAL="${HEM_CLUSTER_SMOKE_WAIT_INTERVAL:-5}"
BACKUP_FIRST=1
RUN_FAILURE=1
RUN_TWO_NODE_FAILURE="auto"
RUN_REAL_SECRET=1
SYNC_REFRESH=1
REAL_SECRET_REF="${HEM_CLUSTER_REAL_SECRET_REF:-global/smoke-test-secret}"
REAL_SECRET_KEY="${HEM_CLUSTER_REAL_SECRET_KEY:-}"
SMOKE_SOURCE="${HEM_CLUSTER_SMOKE_SOURCE:-mac}"
FAILURE_NODE="${HEM_CLUSTER_FAILURE_NODE:-elm}"
SECOND_FAILURE_NODE="${HEM_CLUSTER_SECOND_FAILURE_NODE:-dogwood}"
EXPECTED_PEERS=""
RECEIPT_PROBE_REF=""
RECEIPT_PROBE_KEY=""
FAILURES=0

DEFAULT_DATA_DIR='~/.valhall/system-daemons/data/hem'
DEFAULT_ENDPOINT='http://127.0.0.1:50091'

NODES=(
  "mac|local|${DEFAULT_DATA_DIR}|${DEFAULT_ENDPOINT}"
  "alder|alder.local|${DEFAULT_DATA_DIR}|${DEFAULT_ENDPOINT}"
  "birch|birch|${DEFAULT_DATA_DIR}|${DEFAULT_ENDPOINT}"
  "cedar|cedar|${DEFAULT_DATA_DIR}|${DEFAULT_ENDPOINT}"
  "dogwood|192.0.2.85|${DEFAULT_DATA_DIR}|${DEFAULT_ENDPOINT}"
  "elm|elm|${DEFAULT_DATA_DIR}|${DEFAULT_ENDPOINT}"
)

usage() {
  cat <<'USAGE'
Usage: scripts/hem-cluster-smoke.sh [mode] [options]

Modes:
  acceptance          Backup, hardening, health, smoke replication, recovery, real-secret check.
  health              Backup, hardening, and health/convergence checks only.
  smoke               Backup, health, replication smoke, real-secret check.
  failure             Backup and failure/recovery checks only.
  real-secret         Backup and safe real-secret/read-rewrap verification only.
  watchdog-once       Health check plus optional receipt probe for monitoring.

Options:
  --node SPEC         Add a node: name|host|data_dir|endpoint. host=local runs locally.
  --clear-nodes       Clear built-in node list before --node entries.
  --artifact-dir DIR  Local directory for logs and manifests.
  --run-id ID         Stable run id used in smoke secret names and backup paths.
  --wait-seconds N    Max convergence wait.
  --wait-interval N   Convergence polling interval.
  --skip-backup       Do not take full node data backups first. Not allowed for acceptance/failure.
  --skip-failure      Skip stop/start recovery scenario.
  --include-two-node-failure
  --skip-two-node-failure
  --skip-real-secret
  --no-sync-refresh
  --real-secret-ref REF       Default: global/smoke-test-secret.
  --real-secret-key KEY       Optional key; omitted means hash full hem get output.
  --receipt-probe-ref REF     For watchdog-once: safely read REF and verify read.fulfilled.
  --receipt-probe-key KEY
  --smoke-source NAME         Node name that writes smoke secrets. Default: mac.
  --failure-node NAME         Node stopped for single-node recovery. Default: elm.
  --second-failure-node NAME  Second node for two-node recovery. Default: dogwood.

Safety:
  The script never calls hem rotate, hem cluster migrate, hem cluster fork, or replay-fork.
  It records master.key and node-identity.json hashes before and after live checks and fails
  if either changes. Acceptance and failure modes require full backups by default.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

case "${1:-}" in
  acceptance|health|smoke|failure|real-secret|watchdog-once)
    MODE="$1"
    shift
    ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node)
      NODES+=("$2")
      shift 2
      ;;
    --clear-nodes)
      NODES=()
      shift
      ;;
    --artifact-dir)
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      RUN_STAMP="$(printf '%s' "$RUN_ID" | tr '[:upper:]_' '[:lower:]-' | tr -cd 'a-z0-9-')"
      shift 2
      ;;
    --wait-seconds)
      WAIT_SECONDS="$2"
      shift 2
      ;;
    --wait-interval)
      WAIT_INTERVAL="$2"
      shift 2
      ;;
    --skip-backup)
      BACKUP_FIRST=0
      shift
      ;;
    --skip-failure)
      RUN_FAILURE=0
      shift
      ;;
    --include-two-node-failure)
      RUN_TWO_NODE_FAILURE=1
      shift
      ;;
    --skip-two-node-failure)
      RUN_TWO_NODE_FAILURE=0
      shift
      ;;
    --skip-real-secret)
      RUN_REAL_SECRET=0
      shift
      ;;
    --no-sync-refresh)
      SYNC_REFRESH=0
      shift
      ;;
    --real-secret-ref)
      REAL_SECRET_REF="$2"
      shift 2
      ;;
    --real-secret-key)
      REAL_SECRET_KEY="$2"
      shift 2
      ;;
    --receipt-probe-ref)
      RECEIPT_PROBE_REF="$2"
      shift 2
      ;;
    --receipt-probe-key)
      RECEIPT_PROBE_KEY="$2"
      shift 2
      ;;
    --smoke-source)
      SMOKE_SOURCE="$2"
      shift 2
      ;;
    --failure-node)
      FAILURE_NODE="$2"
      shift 2
      ;;
    --second-failure-node)
      SECOND_FAILURE_NODE="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${#NODES[@]}" -eq 0 ]]; then
  echo "no nodes configured" >&2
  exit 2
fi

case "$MODE" in
  acceptance|failure)
    if [[ "$BACKUP_FIRST" != "1" ]]; then
      echo "${MODE} mode requires backups; remove --skip-backup" >&2
      exit 2
    fi
    ;;
esac

EXPECTED_PEERS="${EXPECTED_PEERS:-$((${#NODES[@]} - 1))}"
mkdir -p "$ARTIFACT_DIR/nodes"

log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2
}

mark_failure() {
  FAILURES=$((FAILURES + 1))
  printf 'FAIL: %s\n' "$*" >&2
}

sq() {
  printf "'"
  printf '%s' "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

path_assignment() {
  local var="$1"
  local value="$2"
  case "$value" in
    "~/"*) printf '%s="$HOME/%s"\n' "$var" "${value#\~/}" ;;
    '$HOME/'*) printf '%s="$HOME/%s"\n' "$var" "${value#\$HOME/}" ;;
    *) printf '%s=%s\n' "$var" "$(sq "$value")" ;;
  esac
}

split_node() {
  local spec="$1"
  IFS='|' read -r NODE_NAME NODE_HOST NODE_DATA_DIR NODE_ENDPOINT <<EOF
$spec
EOF
  if [[ -z "${NODE_NAME:-}" || -z "${NODE_HOST:-}" || -z "${NODE_DATA_DIR:-}" || -z "${NODE_ENDPOINT:-}" ]]; then
    echo "invalid node spec: $spec" >&2
    exit 2
  fi
}

node_spec_by_name() {
  local wanted="$1"
  local spec
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    if [[ "$NODE_NAME" == "$wanted" ]]; then
      printf '%s\n' "$spec"
      return 0
    fi
  done
  return 1
}

node_dir() {
  local name="$1"
  mkdir -p "$ARTIFACT_DIR/nodes/$name"
  printf '%s\n' "$ARTIFACT_DIR/nodes/$name"
}

run_node() {
  local spec="$1"
  local command="$2"
  split_node "$spec"
  command="PATH=\"\$HOME/.valhall/system-daemons/bin:\$HOME/.local/bin:\$PATH:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\"; export PATH
$command"
  if [[ "$NODE_HOST" == "local" ]]; then
    zsh -lc "$command"
  else
    local quoted
    quoted="$(printf '%q' "$command")"
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$NODE_HOST" "zsh -lc $quoted"
  fi
}

capture_node() {
  local spec="$1"
  local label="$2"
  local command="$3"
  split_node "$spec"
  local dir out rc_file rc
  dir="$(node_dir "$NODE_NAME")"
  out="$dir/${label}.out"
  rc_file="$dir/${label}.rc"
  set +e
  run_node "$spec" "$command" >"$out" 2>&1
  rc=$?
  set -e
  printf '%s\n' "$rc" >"$rc_file"
  printf '%s\n' "$out"
  return 0
}

require_capture_success() {
  local spec="$1"
  local label="$2"
  local command="$3"
  local out rc
  out="$(capture_node "$spec" "$label" "$command")"
  rc="$(cat "${out%.out}.rc")"
  if [[ "$rc" != "0" ]]; then
    split_node "$spec"
    mark_failure "$NODE_NAME $label failed with rc=$rc; see $out"
    sed -n '1,80p' "$out" >&2
    return 1
  fi
  return 0
}

kv_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1); exit}' "$file"
}

require_kv() {
  local file="$1"
  local key="$2"
  local expected="$3"
  local actual
  actual="$(kv_value "$file" "$key")"
  if [[ "$actual" != "$expected" ]]; then
    mark_failure "$(basename "$(dirname "$file")") $(basename "$file" .out): expected ${key}=${expected}, got ${actual:-<missing>}"
    return 1
  fi
}

hem_health_cmd() {
  local data_dir="$1"
  local endpoint="$2"
  cat <<EOF
set -euo pipefail
$(path_assignment data_dir "$data_dir")
endpoint=$(sq "$endpoint")
hem --endpoint "\$endpoint" health
EOF
}

cluster_cmd() {
  local data_dir="$1"
  local args="$2"
  cat <<EOF
set -euo pipefail
$(path_assignment data_dir "$data_dir")
HEM_DATA_DIR="\$data_dir" hem cluster $args
EOF
}

fingerprint_cmd() {
  local data_dir="$1"
  cat <<EOF
set -euo pipefail
$(path_assignment data_dir "$data_dir")
for path in "\$data_dir/master.key" "\$data_dir/node-identity.json"; do
  if [[ -f "\$path" ]]; then
    /usr/bin/shasum -a 256 "\$path"
  else
    printf 'missing  %s\n' "\$path"
  fi
done
EOF
}

backup_cmd() {
  local name="$1"
  local data_dir="$2"
  cat <<EOF
set -euo pipefail
$(path_assignment data_dir "$data_dir")
node=$(sq "$name")
run_id=$(sq "$RUN_ID")
backup_root="\${HEM_CLUSTER_BACKUP_ROOT:-\$HOME/.valhall/backups/hem-cluster-smoke}"
backup_dir="\$backup_root/\$run_id/\$node"
if [[ ! -d "\$data_dir" ]]; then
  echo "backup_error=data_dir_missing"
  echo "data_dir=\$data_dir"
  exit 12
fi
if [[ -e "\$backup_dir" ]]; then
  echo "backup_error=backup_dir_exists"
  echo "backup_dir=\$backup_dir"
  exit 13
fi
umask 077
mkdir -p "\$backup_dir"
if command -v rsync >/dev/null 2>&1; then
  rsync -aE \
    --exclude '/distributed/ledger.sqlite3' \
    --exclude '/distributed/ledger.sqlite3-wal' \
    --exclude '/distributed/ledger.sqlite3-shm' \
    "\$data_dir/" "\$backup_dir/data/"
elif command -v ditto >/dev/null 2>&1; then
  ditto "\$data_dir" "\$backup_dir/data"
else
  mkdir -p "\$backup_dir/data"
  cp -pR "\$data_dir/." "\$backup_dir/data/"
fi
ledger="\$data_dir/distributed/ledger.sqlite3"
if [[ -f "\$ledger" ]] && command -v sqlite3 >/dev/null 2>&1; then
  mkdir -p "\$backup_dir/data/distributed"
  backup_ok=0
  for attempt in 1 2 3 4 5; do
    if sqlite3 "\$ledger" ".timeout 5000" ".backup '\$backup_dir/data/distributed/ledger.sqlite3'"; then
      backup_ok=1
      break
    fi
    sleep "\$attempt"
  done
  if [[ "\$backup_ok" != "1" ]]; then
    echo "backup_error=ledger_sqlite_backup_failed"
    exit 14
  fi
  cp -p "\$backup_dir/data/distributed/ledger.sqlite3" "\$backup_dir/ledger.sqlite3.backup"
fi
{
  echo "created_at=\$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "hostname=\$(/bin/hostname)"
  echo "node=\$node"
  echo "data_dir=\$data_dir"
  echo "backup_dir=\$backup_dir"
  for path in "\$data_dir/master.key" "\$data_dir/node-identity.json" "\$data_dir/cluster.toml" "\$data_dir/distributed/ledger.sqlite3"; do
    if [[ -e "\$path" ]]; then
      /usr/bin/stat -f 'mode=%OLp path=%N' "\$path" 2>/dev/null || /usr/bin/stat -c 'mode=%a path=%n' "\$path"
      if [[ -f "\$path" ]]; then /usr/bin/shasum -a 256 "\$path"; fi
    else
      echo "missing path=\$path"
    fi
  done
} > "\$backup_dir/manifest.txt"
/bin/chmod -R go-rwx "\$backup_dir" 2>/dev/null || true
echo "backup_dir=\$backup_dir"
EOF
}

hardening_cmd() {
  local data_dir="$1"
  cat <<EOF
set -euo pipefail
$(path_assignment data_dir "$data_dir")
hem_path="\$(command -v hem || true)"
hemd_path="\$(command -v hemd || true)"
echo "hem_path=\$hem_path"
echo "hemd_path=\$hemd_path"
if [[ -n "\$hem_path" ]]; then echo "hem_sha256=\$(/usr/bin/shasum -a 256 "\$hem_path" | /usr/bin/awk '{print \$1}')"; fi
if [[ -n "\$hemd_path" ]]; then echo "hemd_sha256=\$(/usr/bin/shasum -a 256 "\$hemd_path" | /usr/bin/awk '{print \$1}')"; fi
if launchctl print "gui/\$(id -u)/io.valhall.hemd" >/dev/null 2>&1; then
  echo "launchd_hemd=loaded"
else
  echo "launchd_hemd=missing"
fi
for path in "\$data_dir" "\$data_dir/master.key" "\$data_dir/node-identity.json" "\$data_dir/cluster.toml" "\$data_dir/distributed/ledger.sqlite3"; do
  if [[ -e "\$path" ]]; then
    /usr/bin/stat -f 'mode=%OLp path=%N' "\$path" 2>/dev/null || /usr/bin/stat -c 'mode=%a path=%n' "\$path"
  else
    echo "missing path=\$path"
  fi
done
EOF
}

safe_secret_hash_cmd() {
  local endpoint="$1"
  local ref="$2"
  local key="$3"
  local receipt_check_name="$4"
  local data_dir="$5"
  local key_arg=""
  if [[ -n "$key" ]]; then
    key_arg=" $(sq "$key")"
  fi
  cat <<EOF
set -euo pipefail
$(path_assignment data_dir "$data_dir")
endpoint=$(sq "$endpoint")
ref=$(sq "$ref")
secret_name=$(sq "$receipt_check_name")
value="\$(hem --endpoint "\$endpoint" get "\$ref"$key_arg)"
bytes="\$(printf '%s' "\$value" | /usr/bin/wc -c | /usr/bin/tr -d ' ')"
sha="\$(printf '%s' "\$value" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print \$1}')"
echo "secret_ref=\$ref"
echo "secret_bytes=\$bytes"
echo "secret_sha256=\$sha"
ledger="\$data_dir/distributed/ledger.sqlite3"
if [[ -f "\$ledger" ]] && command -v sqlite3 >/dev/null 2>&1; then
  query="select count(*) from ledger_operations where op_type='read.fulfilled' and payload_json like '%\"secret_name\":\"\${secret_name}\"%';"
  count=""
  for attempt in 1 2 3 4 5; do
    if count="\$(sqlite3 "\$ledger" ".timeout 5000" "\$query")"; then
      break
    fi
    sleep "\$attempt"
  done
  if [[ -z "\$count" ]]; then
    echo "read_fulfilled_count=unavailable"
    exit 5
  fi
  echo "read_fulfilled_count=\$count"
else
  echo "read_fulfilled_count=unavailable"
fi
EOF
}

smoke_set_cmd() {
  local endpoint="$1"
  local secret_ref="$2"
  local value="$3"
  cat <<EOF
set -euo pipefail
endpoint=$(sq "$endpoint")
secret_ref=$(sq "$secret_ref")
value=$(sq "$value")
hem --endpoint "\$endpoint" set "\$secret_ref" "value=\$value" --description "hem cluster smoke ${RUN_ID}" --actor hem-cluster-smoke
EOF
}

smoke_read_cmd() {
  local endpoint="$1"
  local secret_ref="$2"
  local expected="$3"
  local data_dir="$4"
  local secret_name="$5"
  cat <<EOF
set -euo pipefail
$(path_assignment data_dir "$data_dir")
endpoint=$(sq "$endpoint")
secret_ref=$(sq "$secret_ref")
expected=$(sq "$expected")
secret_name=$(sq "$secret_name")
actual="\$(hem --endpoint "\$endpoint" get "\$secret_ref" value)"
if [[ "\$actual" != "\$expected" ]]; then
  echo "smoke_read=wrong_value"
  exit 20
fi
echo "smoke_read=ok"
echo "smoke_value_sha256=\$(printf '%s' "\$actual" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print \$1}')"
ledger="\$data_dir/distributed/ledger.sqlite3"
if [[ -f "\$ledger" ]] && command -v sqlite3 >/dev/null 2>&1; then
  query="select count(*) from ledger_operations where op_type='read.fulfilled' and payload_json like '%\"secret_name\":\"\${secret_name}\"%';"
  count=""
  for attempt in 1 2 3 4 5; do
    if count="\$(sqlite3 "\$ledger" ".timeout 5000" "\$query")"; then
      break
    fi
    sleep "\$attempt"
  done
  if [[ -z "\$count" ]]; then
    echo "read_fulfilled_count=unavailable"
    exit 22
  fi
  echo "read_fulfilled_count=\$count"
  if [[ "\$count" == "0" ]]; then
    echo "read_receipt=missing"
    exit 21
  fi
else
  echo "read_receipt=unavailable"
  exit 22
fi
EOF
}

launchd_stop_cmd() {
  cat <<'EOF'
set -euo pipefail
label="io.valhall.hemd"
plist="$HOME/Library/LaunchAgents/${label}.plist"
launchctl bootout "gui/$(id -u)" "$plist" >/dev/null 2>&1 || launchctl remove "$label" >/dev/null 2>&1 || true
sleep 2
if hem --endpoint http://127.0.0.1:50091 health >/dev/null 2>&1; then
  echo "hemd_stop=failed_still_healthy"
  exit 30
fi
echo "hemd_stop=ok"
EOF
}

launchd_start_cmd() {
  cat <<'EOF'
set -euo pipefail
label="io.valhall.hemd"
plist="$HOME/Library/LaunchAgents/${label}.plist"
if [[ ! -f "$plist" ]]; then
  echo "hemd_start=missing_plist"
  exit 31
fi
launchctl bootstrap "gui/$(id -u)" "$plist" >/dev/null 2>&1 || true
launchctl kickstart -k "gui/$(id -u)/${label}" >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  if hem --endpoint http://127.0.0.1:50091 health >/dev/null 2>&1; then
    echo "hemd_start=ok"
    exit 0
  fi
  sleep 1
done
echo "hemd_start=timeout"
exit 32
EOF
}

run_backups() {
  if [[ "$BACKUP_FIRST" != "1" ]]; then
    log "backup skipped by explicit request"
    return 0
  fi
  log "taking full Hem data backups on ${#NODES[@]} nodes"
  local spec
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    require_capture_success "$spec" "backup" "$(backup_cmd "$NODE_NAME" "$NODE_DATA_DIR")" || true
  done
}

capture_fingerprints() {
  local label="$1"
  local spec
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    require_capture_success "$spec" "$label" "$(fingerprint_cmd "$NODE_DATA_DIR")" || true
  done
}

assert_fingerprints_unchanged() {
  local spec name dir before after
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    name="$NODE_NAME"
    dir="$(node_dir "$name")"
    before="$dir/fingerprint-before.out"
    after="$dir/fingerprint-after.out"
    if [[ -f "$before" && -f "$after" ]]; then
      if ! diff -u "$before" "$after" >"$dir/fingerprint.diff"; then
        mark_failure "$name master key or node identity hash changed; see $dir/fingerprint.diff"
      fi
    else
      mark_failure "$name missing fingerprint evidence"
    fi
  done
}

run_hardening_checks() {
  log "running operational hardening checks"
  local spec out hem_hash="" hemd_hash="" cur_hem cur_hemd
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    require_capture_success "$spec" "hardening" "$(hardening_cmd "$NODE_DATA_DIR")" || true
    out="$(node_dir "$NODE_NAME")/hardening.out"
    require_kv "$out" "launchd_hemd" "loaded" || true
    cur_hem="$(kv_value "$out" hem_sha256)"
    cur_hemd="$(kv_value "$out" hemd_sha256)"
    if [[ -z "$cur_hem" || -z "$cur_hemd" ]]; then
      mark_failure "$NODE_NAME missing hem/hemd binary hash"
    fi
    if [[ -z "$hem_hash" ]]; then hem_hash="$cur_hem"; elif [[ "$cur_hem" != "$hem_hash" ]]; then mark_failure "$NODE_NAME hem binary hash differs"; fi
    if [[ -z "$hemd_hash" ]]; then hemd_hash="$cur_hemd"; elif [[ "$cur_hemd" != "$hemd_hash" ]]; then mark_failure "$NODE_NAME hemd binary hash differs"; fi
  done
}

run_health_checks() {
  log "running node health, cluster health, and ledger verify"
  local spec out health_out verify_out first_pos="" first_hash="" pos hash
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    require_capture_success "$spec" "hem-health" "$(hem_health_cmd "$NODE_DATA_DIR" "$NODE_ENDPOINT")" || true
    require_capture_success "$spec" "cluster-health" "$(cluster_cmd "$NODE_DATA_DIR" "health")" || true
    require_capture_success "$spec" "cluster-verify" "$(cluster_cmd "$NODE_DATA_DIR" "verify")" || true
    health_out="$(node_dir "$NODE_NAME")/cluster-health.out"
    verify_out="$(node_dir "$NODE_NAME")/cluster-verify.out"
    require_kv "$health_out" cluster_health_status healthy || true
    require_kv "$health_out" healthy_peers "$EXPECTED_PEERS" || true
    require_kv "$health_out" divergent_peers 0 || true
    require_kv "$health_out" sync_errors 0 || true
    require_kv "$health_out" collisions 0 || true
    require_kv "$verify_out" ledger_ok true || true
    require_kv "$verify_out" issues 0 || true
    require_kv "$verify_out" data_dir_security_ok true || true
    pos="$(kv_value "$health_out" latest_position)"
    hash="$(kv_value "$health_out" latest_body_hash)"
    if [[ -z "$first_pos" ]]; then
      first_pos="$pos"
      first_hash="$hash"
    elif [[ "$pos" != "$first_pos" || "$hash" != "$first_hash" ]]; then
      mark_failure "$NODE_NAME diverged: pos=$pos hash=$hash expected pos=$first_pos hash=$first_hash"
    fi
  done
}

refresh_cluster_sync() {
  [[ "$SYNC_REFRESH" == "1" ]] || return 0
  wait_for_convergence "health-refresh" || true
}

sync_once_all() {
  local tag="$1"
  local spec
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    capture_node "$spec" "sync-${tag}" "$(cluster_cmd "$NODE_DATA_DIR" "sync --once")" >/dev/null
  done
}

summarize_sync_failures() {
  local tag="$1"
  local spec dir rc out
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    dir="$(node_dir "$NODE_NAME")"
    rc="$dir/sync-${tag}.rc"
    out="$dir/sync-${tag}.out"
    if [[ -f "$rc" && "$(cat "$rc")" != "0" ]]; then
      mark_failure "$NODE_NAME sync ${tag} failed with rc=$(cat "$rc"); see $out"
      sed -n '1,40p' "$out" >&2
    fi
  done
}

check_converged_once() {
  local tag="$1"
  local expected_status="${2:-healthy}"
  local first_pos="" first_hash="" spec out rc status pos hash sync_errors divergent
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    out="$(capture_node "$spec" "wait-health-${tag}-${RUN_STAMP}" "$(cluster_cmd "$NODE_DATA_DIR" "health")")"
    rc="$(cat "${out%.out}.rc")"
    [[ "$rc" == "0" ]] || return 1
    status="$(kv_value "$out" cluster_health_status)"
    [[ "$status" == "$expected_status" ]] || return 1
    sync_errors="$(kv_value "$out" sync_errors)"
    divergent="$(kv_value "$out" divergent_peers)"
    [[ "$sync_errors" == "0" && "$divergent" == "0" ]] || return 1
    pos="$(kv_value "$out" latest_position)"
    hash="$(kv_value "$out" latest_body_hash)"
    if [[ -z "$first_pos" ]]; then
      first_pos="$pos"
      first_hash="$hash"
    elif [[ "$pos" != "$first_pos" || "$hash" != "$first_hash" ]]; then
      return 1
    fi
  done
  return 0
}

wait_for_convergence() {
  local label="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local attempt=0 tag=""
  while [[ "$SECONDS" -le "$deadline" ]]; do
    attempt=$((attempt + 1))
    tag="${label}-${attempt}"
    sync_once_all "$tag"
    if check_converged_once "$tag" healthy; then
      log "cluster converged for $label"
      return 0
    fi
    sleep "$WAIT_INTERVAL"
  done
  if [[ -n "$tag" ]]; then
    summarize_sync_failures "$tag"
  fi
  mark_failure "cluster did not converge for $label within ${WAIT_SECONDS}s"
  return 1
}

LAST_SMOKE_SECRET_REF=""
LAST_SMOKE_SECRET_VALUE=""
LAST_SMOKE_SECRET_NAME=""

write_smoke_secret() {
  local label="$1"
  local source_spec secret_name secret_ref value
  source_spec="$(node_spec_by_name "$SMOKE_SOURCE")" || {
    mark_failure "smoke source node not found: $SMOKE_SOURCE"
    return 1
  }
  secret_name="hem-distribution-smoke-${RUN_STAMP}-${label}"
  secret_name="$(printf '%s' "$secret_name" | tr '[:upper:]_' '[:lower:]-' | tr -cd 'a-z0-9-')"
  secret_ref="global/${secret_name}"
  value="smoke-${RUN_STAMP}-${label}-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  split_node "$source_spec"
  log "writing harmless smoke secret $secret_ref on $NODE_NAME"
  require_capture_success "$source_spec" "smoke-set-${label}" "$(smoke_set_cmd "$NODE_ENDPOINT" "$secret_ref" "$value")" || true
  LAST_SMOKE_SECRET_REF="$secret_ref"
  LAST_SMOKE_SECRET_VALUE="$value"
  LAST_SMOKE_SECRET_NAME="$secret_name"
}

read_smoke_secret_everywhere() {
  local label="$1"
  local spec
  if [[ -z "$LAST_SMOKE_SECRET_REF" || -z "$LAST_SMOKE_SECRET_VALUE" || -z "$LAST_SMOKE_SECRET_NAME" ]]; then
    mark_failure "no smoke secret has been written for $label"
    return 1
  fi
  log "reading $LAST_SMOKE_SECRET_REF on every node and verifying read receipts"
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    require_capture_success "$spec" "smoke-read-${label}" "$(smoke_read_cmd "$NODE_ENDPOINT" "$LAST_SMOKE_SECRET_REF" "$LAST_SMOKE_SECRET_VALUE" "$NODE_DATA_DIR" "$LAST_SMOKE_SECRET_NAME")" || true
  done
}

run_smoke_write_and_reads() {
  local label="$1"
  local before="$FAILURES"
  write_smoke_secret "$label"
  wait_for_convergence "smoke-set-${label}" || true
  read_smoke_secret_everywhere "$label"
  wait_for_convergence "smoke-read-${label}" || true
  [[ "$FAILURES" -eq "$before" ]]
}

secret_name_from_ref() {
  local ref="$1"
  printf '%s\n' "${ref##*/}"
}

run_real_secret_check() {
  [[ "$RUN_REAL_SECRET" == "1" ]] || return 0
  local secret_name spec out first_sha="" sha count
  secret_name="$(secret_name_from_ref "$REAL_SECRET_REF")"
  log "safely verifying $REAL_SECRET_REF on every node without printing plaintext"
  for spec in "${NODES[@]}"; do
    split_node "$spec"
    require_capture_success "$spec" "real-secret" "$(safe_secret_hash_cmd "$NODE_ENDPOINT" "$REAL_SECRET_REF" "$REAL_SECRET_KEY" "$secret_name" "$NODE_DATA_DIR")" || true
    out="$(node_dir "$NODE_NAME")/real-secret.out"
    sha="$(kv_value "$out" secret_sha256)"
    count="$(kv_value "$out" read_fulfilled_count)"
    if [[ -z "$sha" ]]; then
      mark_failure "$NODE_NAME missing safe secret hash"
    elif [[ -z "$first_sha" ]]; then
      first_sha="$sha"
    elif [[ "$sha" != "$first_sha" ]]; then
      mark_failure "$NODE_NAME safe secret hash differs for $REAL_SECRET_REF"
    fi
    if [[ "$count" == "0" || "$count" == "unavailable" || -z "$count" ]]; then
      mark_failure "$NODE_NAME read.fulfilled receipt missing for $REAL_SECRET_REF"
    fi
    require_capture_success "$spec" "rewrap-dry-run" "$(cluster_cmd "$NODE_DATA_DIR" "rewrap-values --dry-run")" || true
    out="$(node_dir "$NODE_NAME")/rewrap-dry-run.out"
    require_kv "$out" values_rewrapped 0 || true
    require_kv "$out" operations_planned 0 || true
    require_kv "$out" unsupported_records 0 || true
  done
  wait_for_convergence "real-secret-read" || true
}

stop_node() {
  local name="$1"
  local spec
  spec="$(node_spec_by_name "$name")" || {
    mark_failure "failure node not found: $name"
    return 1
  }
  log "stopping hemd on $name"
  require_capture_success "$spec" "hemd-stop" "$(launchd_stop_cmd)" || true
}

start_node() {
  local name="$1"
  local spec
  spec="$(node_spec_by_name "$name")" || {
    mark_failure "failure node not found: $name"
    return 1
  }
  log "starting hemd on $name"
  require_capture_success "$spec" "hemd-start" "$(launchd_start_cmd)" || true
}

cluster_quorum_allows_two_down() {
  local source_spec out quorum total available
  source_spec="$(node_spec_by_name "$SMOKE_SOURCE")" || return 1
  split_node "$source_spec"
  out="$(capture_node "$source_spec" "two-node-quorum-check" "$(cluster_cmd "$NODE_DATA_DIR" "health")")"
  quorum="$(kv_value "$out" quorum)"
  total="${#NODES[@]}"
  available=$((total - 2))
  [[ -n "$quorum" && "$quorum" -le "$available" ]]
}

run_failure_recovery() {
  [[ "$RUN_FAILURE" == "1" ]] || return 0
  wait_for_convergence "before-failure" || true
  stop_node "$FAILURE_NODE"
  write_smoke_secret "one-offline"
  start_node "$FAILURE_NODE"
  wait_for_convergence "one-node-recovery" || true
  read_smoke_secret_everywhere "one-offline"
  wait_for_convergence "one-node-recovery-read" || true
  local recovered_spec
  recovered_spec="$(node_spec_by_name "$FAILURE_NODE")" || return 0
  split_node "$recovered_spec"
  require_capture_success "$recovered_spec" "post-recovery-verify" "$(cluster_cmd "$NODE_DATA_DIR" "verify")" || true

  if [[ "$RUN_TWO_NODE_FAILURE" == "1" || ( "$RUN_TWO_NODE_FAILURE" == "auto" && "$(cluster_quorum_allows_two_down && echo yes || echo no)" == "yes" ) ]]; then
    log "running two-node recovery scenario"
    stop_node "$FAILURE_NODE"
    stop_node "$SECOND_FAILURE_NODE"
    write_smoke_secret "two-offline"
    start_node "$SECOND_FAILURE_NODE"
    start_node "$FAILURE_NODE"
    wait_for_convergence "two-node-recovery" || true
    read_smoke_secret_everywhere "two-offline"
    wait_for_convergence "two-node-recovery-read" || true
  else
    log "two-node recovery skipped; quorum policy does not allow it or it was disabled"
  fi
}

run_watchdog_once() {
  run_health_checks
  if [[ -n "$RECEIPT_PROBE_REF" ]]; then
    local old_real_ref="$REAL_SECRET_REF"
    local old_real_key="$REAL_SECRET_KEY"
    REAL_SECRET_REF="$RECEIPT_PROBE_REF"
    REAL_SECRET_KEY="$RECEIPT_PROBE_KEY"
    RUN_REAL_SECRET=1
    run_real_secret_check
    REAL_SECRET_REF="$old_real_ref"
    REAL_SECRET_KEY="$old_real_key"
  fi
}

main() {
  log "artifacts: $ARTIFACT_DIR"
  run_backups
  capture_fingerprints "fingerprint-before"
  if [[ "$FAILURES" -gt 0 ]]; then
    log "preflight failed before live checks; artifacts in $ARTIFACT_DIR"
    exit 1
  fi

  case "$MODE" in
    acceptance)
      run_hardening_checks
      refresh_cluster_sync
      run_health_checks
      if run_smoke_write_and_reads "baseline"; then
        run_failure_recovery
        run_real_secret_check
      else
        log "smoke phase failed; skipping failure recovery and real-secret checks to avoid adding more ledger writes"
      fi
      refresh_cluster_sync
      run_health_checks
      ;;
    health)
      run_hardening_checks
      refresh_cluster_sync
      run_health_checks
      ;;
    smoke)
      refresh_cluster_sync
      run_health_checks
      if run_smoke_write_and_reads "baseline"; then
        run_real_secret_check
      else
        log "smoke phase failed; skipping real-secret check to avoid adding more ledger writes"
      fi
      refresh_cluster_sync
      run_health_checks
      ;;
    failure)
      run_failure_recovery
      run_health_checks
      ;;
    real-secret)
      run_real_secret_check
      refresh_cluster_sync
      run_health_checks
      ;;
    watchdog-once)
      run_watchdog_once
      ;;
    *)
      echo "unknown mode: $MODE" >&2
      exit 2
      ;;
  esac

  capture_fingerprints "fingerprint-after"
  assert_fingerprints_unchanged

  if [[ "$FAILURES" -gt 0 ]]; then
    log "completed with $FAILURES failure(s); artifacts in $ARTIFACT_DIR"
    exit 1
  fi
  log "completed successfully; artifacts in $ARTIFACT_DIR"
}

main "$@"
