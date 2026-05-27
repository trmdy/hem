# Hem Multi-Machine Deployment Runbook

This runbook prepares a second Hem machine from a built release artifact without source spelunking.

## Artifact Layout

The artifact directory must contain executable `hem` and `hemd` files:

```sh
artifact/
  hem
  hemd
```

Install or rebuild from that artifact:

```sh
hem cluster install \
  --artifact-dir /path/to/artifact \
  --prefix /usr/local/valhall \
  --data-dir /var/lib/valhall/hem \
  --bind 127.0.0.1:50091 \
  --supervisor launchd \
  --force
```

For an upgrade, back up the previous install before overwrite:

```sh
hem cluster rebuild \
  --artifact-dir /path/to/new-artifact \
  --prefix /usr/local/valhall \
  --data-dir /var/lib/valhall/hem \
  --bind 127.0.0.1:50091 \
  --supervisor launchd \
  --backup-dir /var/backups/valhall/hem-install-$(date +%Y%m%d%H%M%S)
```

The command writes:

- `bin/hem`
- `bin/hemd`
- `etc/hem/hemd.env`
- `etc/hem/install-manifest.json`
- `supervisor/io.valhall.hemd.plist` for launchd or `supervisor/hemd.service` for systemd

## Supervisor Activation

The generated supervisor file preserves the configured data dir by invoking:

```sh
hemd --bind <bind> --data-dir <data-dir>
```

For launchd, copy or symlink `io.valhall.hemd.plist` into the chosen LaunchAgents or LaunchDaemons directory, then run:

```sh
launchctl bootstrap gui/$(id -u) /path/to/io.valhall.hemd.plist
launchctl kickstart -k gui/$(id -u)/io.valhall.hemd
```

For systemd, copy or symlink `hemd.service` into the chosen systemd unit directory, then run:

```sh
systemctl daemon-reload
systemctl enable --now hemd.service
```

## Firewall And NAT

Prefer private network links and do not expose `hemd` directly to the public internet.

- Best: bind to `127.0.0.1` and connect through SSH or WireGuard tunnels.
- Acceptable on a private LAN: bind to a private interface and allow only known peer IPs.
- Avoid NAT port forwarding unless the link is wrapped by a private tunnel.
- Peer RPCs are signed and replay-protected, but plaintext gRPC is not transport encryption.
- Open the configured bind port only between cluster peers.
- Keep each peer endpoint in `cluster.toml` aligned with the address other peers can reach.

## Second-Machine Checklist

1. Install binaries with `hem cluster install`.
2. Initialize local cluster state with `hem cluster join <invite> --node-id <node> --listen <peer-reachable-endpoint>`.
3. Add the new peer to the existing machine with `hem cluster peer add`.
4. Start `hemd` under the generated supervisor file.
5. Run the verification commands printed by install:
   - `hem --version`
   - `hem --endpoint <endpoint> health`
   - `HEM_DATA_DIR=<data-dir> hem cluster status`
   - `HEM_DATA_DIR=<data-dir> hem cluster verify`
6. Bootstrap history if needed:

```sh
HEM_DATA_DIR=<data-dir> hem cluster bootstrap-ledger --peer <existing-node>
```

7. Run one sync pass from both machines:

```sh
HEM_DATA_DIR=<data-dir> hem cluster sync --once
```

## Backup Before Migration

Before `hem cluster migrate` on real data:

1. Stop `hemd`.
2. Copy the entire Hem data dir to a timestamped backup.
3. Record the current installed artifact manifest.
4. Run `hem cluster verify` and keep the output with the backup.
5. Run `hem cluster migrate --dry-run`.
6. Run `hem cluster migrate` only after the dry run matches expectations.

## Rollback

If install or rebuild fails before data migration, stop the supervisor and restore `bin/hem`, `bin/hemd`, supervisor files, and `install-manifest.json` from the backup directory.

If migration already appended ledger operations, do not edit SQLite by hand. Either restore the entire Hem data dir backup or declare an intentional hard fork and replay:

```sh
hem cluster fork --reason "rollback to checkpoint"
hem cluster replay-fork <fork-id> --confirm-rewind <fork-id> --backup-confirmed <backup-reference>
```

After rollback, verify:

```sh
hem --version
hem --endpoint <endpoint> health
HEM_DATA_DIR=<data-dir> hem cluster status
HEM_DATA_DIR=<data-dir> hem cluster verify
```

## Six-Node Acceptance Loop

After every distributed Hem rebuild or cluster membership change, run the
operator acceptance script from the Valhall repo root:

```sh
make hem-cluster-smoke
```

The script targets the current six-node cluster by default:

- Mac
- Alder (`alder.local`)
- Birch (`birch`)
- Cedar (`cedar`)
- Dogwood (`192.0.2.85`)
- Elm (`elm`)

The acceptance loop intentionally takes full Hem data backups before it performs
any verification that can write audit/read-receipt records. Backups are written
under each node's `~/.valhall/backups/hem-cluster-smoke/<run-id>/<node>/` and
include:

- a full copy of the Hem data directory;
- a consistent SQLite `.backup` of `distributed/ledger.sqlite3` when `sqlite3`
  is available;
- a manifest with mode bits and hashes for `master.key`, `node-identity.json`,
  `cluster.toml`, and the ledger.

The script never calls `hem rotate`, `hem cluster migrate`, `hem cluster fork`,
or `hem cluster replay-fork`. It records `master.key` and `node-identity.json`
hashes before and after the run and fails if either changed.

The loop verifies:

- `hem health`, `hem cluster health`, and `hem cluster verify` on every node;
- identical `latest_position` and `latest_body_hash` across all nodes;
- `healthy_peers=5`, `issues=0`, `sync_errors=0`, and no divergent peers;
- identical `hem` and `hemd` binary hashes;
- launchd has `io.valhall.hemd` loaded;
- strict data-dir security via `hem cluster verify`;
- a harmless smoke secret can be written, replicated, read from every node, and
  produces `read.fulfilled` ledger receipts;
- one-node stop/write/restart recovery converges without manual repair;
- two-node stop/write/restart recovery when the configured quorum permits it;
- `global/smoke-test-secret` can be read on every node without printing
  plaintext, by comparing only bytes and SHA-256 hashes;
- `hem cluster rewrap-values --dry-run` reports no remaining recipient rewrap
  work (`values_rewrapped=0`, `operations_planned=0`,
  `unsupported_records=0`).

Useful narrower entry points:

```sh
make hem-cluster-health
scripts/hem-cluster-smoke.sh smoke
scripts/hem-cluster-smoke.sh real-secret
```

### macOS Local Network Privacy proxies

On macOS 15.5+ and 26.x, Local Network Privacy can block daemon-owned LAN
sockets even when SSH-launched tools can reach the same peer. The observed
failure is a `peer connect failed ... No route to host` error from `hemd`, while
`hem --endpoint http://<peer>:50091 health` and `/usr/bin/nc` succeed from the
same host.

`hemd` embeds `NSLocalNetworkUsageDescription`, but headless machines may still
need either explicit Local Network approval or an operational bypass. For
headless cluster nodes, install loopback peer proxies:

```sh
make hem-cluster-peer-proxies
scripts/hem-cluster-peer-proxies.sh status
```

The proxy script defaults to Birch, Cedar, and Elm. It:

- backs up each node's `cluster.toml`;
- installs `/usr/bin/nc`-based LaunchAgents under
  `~/Library/LaunchAgents/io.valhall.hem-peer-proxy.<peer>.plist`;
- rewrites peer endpoints in `cluster.toml` to `http://127.0.0.1:<port>`;
- writes proxy logs outside the Hem data directory under
  `~/.valhall/system-daemons/logs/hem-peer-proxies/`;
- restarts `io.valhall.hemd` and verifies local health;
- never reads, writes, rotates, or replaces `master.key` or
  `node-identity.json`.

To remove the bypass and restore the previous peer endpoints:

```sh
scripts/hem-cluster-peer-proxies.sh restore
```

For custom machines, pass explicit node specs:

```sh
scripts/hem-cluster-smoke.sh acceptance \
  --clear-nodes \
  --node 'mac|local|~/.valhall/system-daemons/data/hem|http://127.0.0.1:50091' \
  --node 'peer-a|peer-a.local|~/.valhall/system-daemons/data/hem|http://127.0.0.1:50091'
```

Each node spec is `name|host|data_dir|endpoint`; `host=local` runs commands on
the current machine and any other host is reached through SSH.

## Watchdog

For recurring monitoring, run:

```sh
scripts/hem-cluster-watchdog.sh --interval 60
```

The watchdog delegates to `scripts/hem-cluster-smoke.sh watchdog-once` and
alerts on non-zero cluster health, divergent peers, lagging peers, offline
peers, permission failures, sync errors, and failed receipt probes.

To verify read receipts continuously, point the watchdog at a low-risk smoke
secret:

```sh
scripts/hem-cluster-watchdog.sh \
  --interval 60 \
  --receipt-ref global/hem-distribution-smoke-watchdog \
  --receipt-key value
```

Set `HEM_CLUSTER_ALERT_CMD` to integrate with a local notification or paging
command. The command receives `HEM_ALERT_MESSAGE`.

## Troubleshooting: Previous Hash Mismatch

If `hem cluster sync --once` fails with:

```text
ledger previous hash mismatch
```

stop running smoke, failure, and real-secret acceptance passes until the ledger
convergence issue is resolved. This means more than one node appended to its
local linear hash chain before the cluster had a shared next operation.

For the current implementation, this is most likely to happen after reads from
multiple nodes because every successful read appends a signed `read.fulfilled`
operation. The acceptance script intentionally treats this as a hard failure
because distributed Hem requires all retrieval receipts to converge.

Immediate operator rules:

- keep the fresh backups from the failed run;
- do not run `hem cluster fork`, `hem cluster replay-fork`, migration, or key
  rotation as an automatic repair;
- keep `hemd` running if secrets must remain available, but avoid multi-node
  write/read-receipt tests until the ledger model supports multi-writer
  convergence or a single sequencer is configured;
- fix the ledger convergence model first, then rerun `make hem-cluster-health`
  and `make hem-cluster-smoke`.
