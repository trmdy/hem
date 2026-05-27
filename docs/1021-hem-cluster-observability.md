# Hem Cluster Observability

`hem cluster health` is the stable local surface for operations and CI checks.

## Exit Codes

- `0`: healthy
- `1`: warning; action is needed, but local ledger integrity is not critically broken
- `2`: critical; divergence, corrupt signed data, or peer cursor mismatch needs immediate attention

## Summary Fields

The command prints key/value fields:

- `cluster_health_status`: `healthy`, `warning`, or `critical`
- `latest_position`
- `latest_body_hash`
- `ledger_ok`
- `integrity_issues`
- `divergence_issues`
- `collisions`
- `healthy_peers`
- `lagging_peers`
- `offline_peers`
- `divergent_peers`
- `quorum_risk`
- `checkpoint_status`
- `sync_errors`

Each peer also gets a stable `peer_health` line:

```text
peer_health node_id=<id> status=<caught_up|lagging|offline|unknown|divergent> endpoint=<url> cursor_position=<n> cursor_hash=<hash> lag=<n> last_seen=<rfc3339|-> error=<reason|->
```

## Alert Guidance

Alert on:

- exit code `2`
- `divergent_peers > 0`
- `divergence_issues > 0`
- `offline_peers > 0` for longer than an expected maintenance window
- `lagging_peers > 0` when lag keeps increasing
- `collisions > 0`
- `quorum_risk=true`
- `checkpoint_status=pending_quorum` for longer than the sync interval plus backoff

## Daemon Logs

`hemd` emits structured tracing events for:

- sync peer start/success/failure
- checkpoint creation/cosigning
- peer quorum approval success/failure
- peer collision approval signing
- master approval routing and receipt consumption

These events include cluster id, local node id, peer node id where applicable, position/lag fields, and error text on failures.
