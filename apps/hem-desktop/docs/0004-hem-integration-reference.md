# 0004 — Hem Integration Reference (facts sheet)

Distilled from the 2026-07-04 deep dive of the valhall repo
(`crates/hem-core`, `crates/hemd`, `crates/hem`, `crates/hem-client`,
`sdks/typescript/packages/hem`, docs 0034–0044, 1014–1021) and the live
system. This is the sheet to keep open while implementing Hem Desk or the
Raycast extension.

## Daemon

- gRPC (tonic) service `valhall.hem.v1.HemRuntime`, plaintext HTTP/2,
  default `127.0.0.1:50091`. No TLS, no REST, no unix socket.
- Proto source of truth: `valhall/proto/valhall/hem/v1/hem.proto`.
- Data dir: `--data-dir` → `HEM_DATA_DIR` → `~/.valhall/hem`.
  Live install (launchd `io.valhall.hemd`):
  `~/.valhall/system-daemons/data/hem`, binaries in
  `~/.valhall/system-daemons/bin/`.
- Restart: `launchctl kickstart -k gui/$UID/io.valhall.hemd`.
- Events published to NATS `nats://127.0.0.1:4222`: `hem.secret.read`,
  `.written`, `.deleted`, `hem.token.issued/revoked`,
  `hem.approval.requested/resolved`. Optional — treat as enhancement.

## Auth

- Bearer token in `authorization` metadata. Everything requires it except
  `Health` and `InitHem`.
- Token types: operator (admin, 365 d), service (global reads + grants,
  30 d), agent-run (scoped, ≤24 h).
- Resolution order (be CLI-compatible): explicit → `VALHALL_HEM_TOKEN` →
  `$HEM_DATA_DIR/operator.token` →
  `$VALHALL_SYSTEM_DAEMONS_DIR/data/hem/operator.token` →
  `~/.valhall/hem/operator.token` →
  `~/.valhall/system-daemons/data/hem/operator.token`.
- Endpoint env: libraries honor `VALHALL_HEM_ADDR` then
  `VALHALL_HEMD_ENDPOINT`; the CLI honors only the latter.

## RPC surface (auth level)

Vault: SetSecret (token; operator/receipt if requires_approval) ·
GetSecret, GetSecretInfo, GetSecrets, ListSecrets (any valid token +
scope/grant) · DeleteSecret (token + server-side approval) ·
ScanForSecrets (token).

Operator-only: SetGroup/AddToGroup/RemoveFromGroup/ListGroups/
ListGroupSecrets · IssueAgentToken/IssueServiceToken/RevokeToken/
ListActiveTokens · GrantAccess/RevokeAccess/ListGrants ·
ListPendingApprovals/ApproveAccess/DenyAccess/GetApprovalStatus ·
GetAuditLog · RotateMasterKey · ExportSecrets/ImportSecrets.

Unauthenticated: Health (status string + version), InitHem.

Peer-only (ed25519 transport auth — not for apps): PeerHello,
PeerApproveRead, PeerApproveCollision, PeerRouteMasterApproval,
PeerGetMasterApprovalStatus, PeerConsumeMasterApprovalReceipt,
PeerListOperations, PeerPushOperations, PeerAckOperations,
PeerCosignCheckpoint.

## Semantics that bite

- **Secret = map.** `values: {key → value}`; `SetSecret` replaces the
  whole value set (≥1 pair required).
- **Refs**: `global/<name>`, `project/<p>/<name>`, `identity/<id>/<name>`.
  Bare `<name>` = global on write but identity→project→global resolution
  on read — always be explicit. Slugs: `[a-z0-9-]+` lowercase.
- **Approval flow**: delete (always) and non-operator reads of
  `requires_approval` secrets yield `approval_required` / a pending
  `request_id`. Operator resolves via ApproveAccess → single-use,
  **action-bound** receipt (get ≠ set ≠ delete) → retry original call
  with receipt (field or `x-hem-approval-receipt` metadata).
- **Cluster read policies** (when `cluster.toml` enabled=true):
  `local_logged` (default) / `offline_lease` / `peer_quorum` /
  `master_biometric`. Quorum/master tiers fail `FAILED_PRECONDITION` when
  peers unreachable — explain, don't retry-loop.
- Error map: token → `UNAUTHENTICATED`, authz → `PERMISSION_DENIED`,
  missing key → `FAILED_PRECONDITION`, NotFound read → `NOT_FOUND`
  (Rust client maps to None).

## Cluster observability (no RPC — local CLI only)

- `hem cluster health`: `key=value` lines + one `peer_health node_id=…
  status=… endpoint=… cursor_position=… lag=… last_seen=… error=…` line
  per peer. Exit 0 ok / 1 warning / 2 critical. Key fields:
  `cluster_health_status`, `latest_position`, `latest_body_hash`,
  `ledger_ok`, `integrity_issues`, `divergence_issues`, `collisions`,
  `healthy_peers`, `lagging_peers`, `offline_peers`, `divergent_peers`,
  `quorum_risk`, `checkpoint_status`, `latest_checkpoint_cosignatures`,
  `sync_errors`.
- `hem cluster status` / `peers` / `collisions` — same kv style. All run
  against local files; daemon not required.
- Peer statuses: `caught_up`, `lagging`, `offline`, `divergent`, `unknown`.
- Live cluster (2026-07-04): id `hmc_democluster000000000000000`, quorum 1,
  nodes `hmn_main` (local), `alder01`, `birch02`, `cedar03`,
  `dogwood04` caught up @7856; `elm05` lagging 6541 ops (last seen
  2026-06-03). Steady state is `warning` — render calmly.
- Known upstream issue: multi-writer `read.fulfilled` convergence bug
  (valhall doc 1020) — collisions/divergence may appear; the runbook says
  never auto-repair (no fork/replay/migrate from an app).
- macOS Local Network Privacy can block LAN peers; deployments use
  loopback `nc` proxy LaunchAgents — endpoints in `cluster.toml` may
  legitimately be `127.0.0.1:<odd port>`.

## Storage facts (for read-only history access)

- Secrets/tokens/grants/approvals/audit: JSON files under the data dir
  (values encrypted XChaCha20-Poly1305; never read these directly).
- Distributed ledger: `distributed/ledger.sqlite3` (user_version 10).
  Tables of interest for history UI: `ledger_secret_metadata`,
  `ledger_secret_value_versions` (version_seq, node, timestamps — no
  plaintext anywhere in the DB). Open `mode=ro&immutable=1` only.
- Master key is plaintext-on-disk (`master.key`, 0600) — vault security is
  Unix perms; an app "lock screen" would be theater, don't build one.

## CLI notes (when shelling out)

- Only `scan --json` and `examples --format json` emit JSON. Cluster/
  policy/lease commands emit parseable `key=value`; other daemon commands
  emit `{:<24} {}` columns — avoid parsing those, use gRPC.
- `hem get <ref> <key>` prints the raw value alone (the one clean scripting
  read path).
- Never call `approve`/`deny`/`set --interactive` from a GUI (TTY-gated).
- Set `NO_COLOR=1` on all shell-outs.
- `archive` writes plaintext JSON to `~/.valhall/hem/archive` — do not
  expose it in UI.
