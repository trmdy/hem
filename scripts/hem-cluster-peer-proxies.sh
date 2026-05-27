#!/usr/bin/env bash
set -euo pipefail

ACTION="install"
BASE_PORT="${HEM_CLUSTER_PROXY_BASE_PORT:-55091}"
DATA_DIR='~/.valhall/system-daemons/data/hem'
RESTART_HEMD=1

NODES=(
  "birch|birch"
  "cedar|cedar"
  "elm|elm"
)

usage() {
  cat <<'USAGE'
Usage: scripts/hem-cluster-peer-proxies.sh [install|status|restore] [options]

Installs loopback peer proxies for hemd on macOS nodes where Local Network
Privacy blocks daemon-owned LAN sockets. The proxy process uses /usr/bin/nc;
hemd connects only to 127.0.0.1 ports.

Options:
  --node NAME|HOST      Add a node. Defaults: birch, cedar, elm.
  --clear-nodes        Clear built-in node list before --node entries.
  --base-port N        First local proxy port. Default: 55091.
  --data-dir DIR       Hem daemon data dir. Default: ~/.valhall/system-daemons/data/hem.
  --no-restart-hemd    Do not restart hemd after install/restore.

Actions:
  install              Backup cluster.toml, install proxies, rewrite peer endpoints to 127.0.0.1.
  status               Show proxy launchd/service status and local port checks.
  restore              Restore latest pre-proxy cluster.toml backup and unload proxies.

Safety:
  This script never reads, writes, rotates, or replaces master.key or
  node-identity.json. It only backs up and rewrites cluster.toml and installs
  user LaunchAgents under ~/Library/LaunchAgents.
USAGE
}

case "${1:-}" in
  install|status|restore)
    ACTION="$1"
    shift
    ;;
  -h|--help)
    usage
    exit 0
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
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --data-dir)
      DATA_DIR="$2"
      shift 2
      ;;
    --no-restart-hemd)
      RESTART_HEMD=0
      shift
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

run_node() {
  local spec="$1"
  local command="$2"
  local name host
  IFS='|' read -r name host <<<"$spec"
  command="PATH=\"\$HOME/.valhall/system-daemons/bin:\$HOME/.local/bin:\$PATH:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\"; export PATH
$command"
  printf '\n== %s (%s): %s ==\n' "$name" "$host" "$ACTION"
  if [[ "$host" == "local" ]]; then
    zsh -lc "$command"
  else
    local quoted
    quoted="$(printf '%q' "$command")"
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" "zsh -lc $quoted"
  fi
}

remote_program() {
  cat <<'REMOTE'
set -euo pipefail
action="$1"
base_port="$2"
restart_hemd="$3"
REMOTE
  path_assignment "data_dir" "$DATA_DIR"
  cat <<'REMOTE'
cluster="$data_dir/cluster.toml"
bin_dir="$HOME/.valhall/system-daemons/bin"
plist_dir="$HOME/Library/LaunchAgents"
log_dir="$HOME/.valhall/system-daemons/logs/hem-peer-proxies"
legacy_log_dir="$data_dir/proxy-logs"
manifest="$log_dir/proxy-manifest.tsv"
mkdir -p "$bin_dir" "$plist_dir" "$log_dir"

proxy_bin="$bin_dir/hem-peer-proxy"
cat >"$proxy_bin" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
listen_host="$1"
listen_port="$2"
target_host="$3"
target_port="$4"
while true; do
  pipe="$(mktemp -u "/tmp/hem-peer-proxy.${listen_port}.XXXXXX")"
  mkfifo "$pipe"
  /usr/bin/nc -l "$listen_host" "$listen_port" <"$pipe" | /usr/bin/nc "$target_host" "$target_port" >"$pipe" || true
  rm -f "$pipe"
  sleep 0.1
done
SCRIPT
chmod 755 "$proxy_bin"

require_python() {
  command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required to parse cluster.toml" >&2
    exit 1
  }
}

list_proxy_specs() {
  require_python
  if [[ -s "$manifest" ]]; then
    cat "$manifest"
    return 0
  fi
  python3 - "$cluster" "$base_port" <<'PY'
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

cluster = Path(sys.argv[1])
base = int(sys.argv[2])
peers = []
current = None
for line in cluster.read_text().splitlines():
    if line.strip() == "[[peers]]":
        current = {}
        peers.append(current)
        continue
    if current is None:
        continue
    match = re.match(r'\s*(node_id|endpoint)\s*=\s*"([^"]+)"', line)
    if match:
        current[match.group(1)] = match.group(2)

for index, peer in enumerate(peers):
    endpoint = peer.get("endpoint", "")
    parsed = urlparse(endpoint)
    if parsed.hostname in {"127.0.0.1", "localhost"}:
        continue
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    print(f"{peer.get('node_id', f'peer_{index}')}|{base + index}|{parsed.hostname}|{port}")
PY
}

rewrite_cluster_to_proxies() {
  require_python
  python3 - "$cluster" "$base_port" <<'PY'
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

cluster = Path(sys.argv[1])
base = int(sys.argv[2])
lines = cluster.read_text().splitlines()
in_peer = False
peer_index = -1
rewritten = []
for line in lines:
    stripped = line.strip()
    if stripped == "[[peers]]":
        in_peer = True
        peer_index += 1
        rewritten.append(line)
        continue
    if in_peer and stripped.startswith("[") and stripped != "[[peers]]":
        in_peer = False
    if in_peer:
        match = re.match(r'(\s*endpoint\s*=\s*)"([^"]+)(".*)', line)
        if match:
            endpoint = match.group(2)
            parsed = urlparse(endpoint)
            if parsed.hostname not in {"127.0.0.1", "localhost"}:
                local = f"{parsed.scheme}://127.0.0.1:{base + peer_index}"
                line = f'{match.group(1)}"{local}{match.group(3)}'
    rewritten.append(line)
cluster.write_text("\n".join(rewritten) + "\n")
PY
}

restart_hemd_if_requested() {
  [[ "$restart_hemd" == "1" ]] || return 0
  local hemd_plist="$HOME/Library/LaunchAgents/io.valhall.hemd.plist"
  launchctl bootout "gui/$(id -u)" "$hemd_plist" >/dev/null 2>&1 || true
  sleep 1
  launchctl bootstrap "gui/$(id -u)" "$hemd_plist" >/dev/null 2>&1 \
    || launchctl kickstart -k "gui/$(id -u)/io.valhall.hemd" >/dev/null 2>&1 \
    || true
  for _ in $(seq 1 30); do
    if hem --endpoint http://127.0.0.1:50091 health >/dev/null 2>&1; then
      echo "hemd=healthy"
      return 0
    fi
    sleep 1
  done
  echo "hemd did not become healthy" >&2
  return 1
}

install_proxy() {
  local peer_node_id="$1"
  local local_port="$2"
  local target_host="$3"
  local target_port="$4"
  local label="io.valhall.hem-peer-proxy.${peer_node_id}"
  local plist="$plist_dir/${label}.plist"
  cat >"$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array><string>${proxy_bin}</string><string>127.0.0.1</string><string>${local_port}</string><string>${target_host}</string><string>${target_port}</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>${log_dir}/${peer_node_id}.out.log</string>
<key>StandardErrorPath</key><string>${log_dir}/${peer_node_id}.err.log</string>
</dict></plist>
PLIST
  launchctl bootout "gui/$(id -u)" "$plist" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$(id -u)" "$plist" >/dev/null
  echo "proxy=${peer_node_id} local=127.0.0.1:${local_port} target=${target_host}:${target_port}"
}

case "$action" in
  install)
    [[ -f "$cluster" ]] || { echo "missing cluster.toml at $cluster" >&2; exit 1; }
    backup="$cluster.backup-peer-proxy-$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$cluster" "$backup"
    echo "cluster_backup=$backup"
    for plist in "$plist_dir"/io.valhall.hem-peer-proxy.*.plist; do
      [[ -e "$plist" ]] || continue
      launchctl bootout "gui/$(id -u)" "$plist" >/dev/null 2>&1 || true
      rm -f "$plist"
    done
    rm -rf "$legacy_log_dir"
    rm -f "$manifest"
    list_proxy_specs >"$manifest"
    while IFS='|' read -r peer_node_id local_port target_host target_port; do
      [[ -n "$peer_node_id" ]] || continue
      install_proxy "$peer_node_id" "$local_port" "$target_host" "$target_port"
    done <"$manifest"
    sleep 1
    while IFS='|' read -r peer_node_id local_port target_host target_port; do
      [[ -n "$peer_node_id" ]] || continue
      /usr/bin/nc -z -w 2 127.0.0.1 "$local_port" >/dev/null
      echo "proxy_port_ok=${peer_node_id}:${local_port}"
    done <"$manifest"
    rewrite_cluster_to_proxies
    restart_hemd_if_requested
    ;;
  status)
    while IFS='|' read -r peer_node_id local_port target_host target_port; do
      [[ -n "$peer_node_id" ]] || continue
      label="io.valhall.hem-peer-proxy.${peer_node_id}"
      if launchctl print "gui/$(id -u)/${label}" >/dev/null 2>&1; then
        state="loaded"
      else
        state="missing"
      fi
      if /usr/bin/nc -z -w 2 127.0.0.1 "$local_port" >/dev/null 2>&1; then
        port_state="open"
      else
        port_state="closed"
      fi
      echo "${peer_node_id} ${state} local=127.0.0.1:${local_port} ${port_state} target=${target_host}:${target_port}"
    done < <(list_proxy_specs)
    ;;
  restore)
    latest_backup="$(ls -t "$cluster".backup-peer-proxy-* "$cluster".backup-proxy-canary-* 2>/dev/null | head -1 || true)"
    [[ -n "$latest_backup" ]] || { echo "no cluster.toml proxy backup found" >&2; exit 1; }
    cp -p "$latest_backup" "$cluster"
    echo "restored_cluster=$latest_backup"
    for plist in "$plist_dir"/io.valhall.hem-peer-proxy.*.plist; do
      [[ -e "$plist" ]] || continue
      launchctl bootout "gui/$(id -u)" "$plist" >/dev/null 2>&1 || true
      rm -f "$plist"
      echo "removed_proxy_plist=$plist"
    done
    rm -rf "$legacy_log_dir"
    rm -f "$manifest"
    restart_hemd_if_requested
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
REMOTE
}

REMOTE_BODY="$(remote_program)"
for spec in "${NODES[@]}"; do
  run_node "$spec" "bash -s -- $(sq "$ACTION") $(sq "$BASE_PORT") $(sq "$RESTART_HEMD") <<'REMOTE_SCRIPT'
$REMOTE_BODY
REMOTE_SCRIPT"
done
