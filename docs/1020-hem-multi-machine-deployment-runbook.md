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
