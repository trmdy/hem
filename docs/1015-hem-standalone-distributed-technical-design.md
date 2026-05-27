# 1015 - Technical Design: Standalone Distributed Hem

Date: 2026-05-25  
Status: Draft  
Linear: LAB-5  
PRD: `docs/1014-hem-standalone-distributed-prd.md`

## Purpose

This document turns the standalone distributed Hem PRD into concrete implementation boundaries. It defines the first module names, storage contracts, operation envelope, cluster lifecycle, and compatibility rules needed before production code work starts.

The key constraint is that Hem must become standalone. Distributed Hem must not depend on Verk, valhall-net, NATS, Kode, Bod, Smi, Vis, or Ting for core operation. Valhall services may remain Hem clients, but Hem owns its own cluster and durability model.

## Current State

Hem V1 is a local daemon stack:

- `hem-core` owns local encrypted file storage, tokens, approvals, grants, audit, and key rotation.
- `hemd` exposes the local gRPC API and currently emits optional events through `valhall-net`.
- `hem` is the operator CLI.
- `hem-client` is the Rust client used by services.

Distributed mode must be additive. Existing local mode and existing live Hem data remain valid and must not be migrated implicitly.

## Top-Level Architecture

Distributed Hem introduces a second storage/runtime path beside the current local store:

- `hem_core::cluster`: cluster config, node identity, peer records, and policy defaults.
- `hem_core::ledger`: signed operation envelope, hash chain, operation validation, Merkle checkpoints.
- `hem_core::distributed_store`: SQLite-backed ledger, blobs, cursors, checkpoints, and materialized state.
- `hemd::peer`: daemon-to-daemon API and peer authentication.
- `hemd::replication`: cursor exchange, operation fetch/push, blob fetch, catch-up loop.
- `hem` cluster commands: operator lifecycle and inspection commands.

The existing `HemStore` file-backed implementation remains the local-mode backend. Distributed mode gets a new backend instead of retrofitting the file layout in place.

## Explicit Decisions

### First Key Model

Use a trusted-cluster shared keyset for the first distributed implementation.

Reasoning:

- It lets the project prove cluster membership, ledger integrity, replication, collision handling, and offline policy behavior before adding key wrapping complexity.
- It matches a personal-machine mesh where all initial nodes are trusted.
- It is not the final high-security shape.

Design constraint:

- The storage model must leave room for per-secret data encryption keys wrapped to authorized nodes. The ledger payloads must include `key_model` and `key_version` fields so envelope encryption can be introduced without changing operation identity rules.

### First Transport

Use direct gRPC over rustls mTLS for peer-to-peer communication.

Reasoning:

- Hem already uses tonic/prost for daemon APIs.
- mTLS gives authenticated peers without Valhall infrastructure.
- Static peer config is sufficient for the MVP.

Deferred:

- LAN discovery.
- NAT traversal.
- Noise transport.
- QUIC.

### First Consensus Model

Use signed operation replication with quorum-cosigned checkpoints, not full Byzantine consensus.

Reasoning:

- The first goal is tamper evidence, durable catch-up, explicit conflict records, and personal-machine resilience.
- Full BFT consensus would materially slow the first useful slice.

Guarantee:

- Local operations may exist before quorum stability.
- A checkpoint is stable only after the configured `K-of-N` signatures.
- Conflicting secret writes remain explicit and unresolved until an operator-approved resolution operation is appended.

### First Offline Model

Offline behavior is policy-specific:

- `local_logged`: allowed offline after local signed read receipt.
- `offline_lease`: allowed offline only with a valid bounded lease.
- `peer_quorum`: fail closed while quorum is unreachable.
- `master_biometric`: fail closed while the master approval path is unreachable unless the current node is the master and can satisfy the policy locally.

No offline path may weaken a configured policy.

## Cluster Data Model

### ClusterConfig

Stored under the Hem data dir, independent from Valhall config:

```toml
[cluster]
enabled = true
cluster_id = "hmc_..."
node_id = "hmn_..."
listen = "127.0.0.1:50191"
quorum = 2
master_node_id = "hmn_master"

[[cluster.peers]]
node_id = "hmn_peer"
endpoint = "https://peer.example:50191"
public_key = "..."
```

### NodeIdentity

Each node has:

- `node_id`
- signing public/private key
- transport public/private key or certificate
- created timestamp
- optional human label

Private material must use the same strict permission discipline as `master.key`.

## Ledger Model

### OperationEnvelope

Every distributed mutation uses the same envelope:

```rust
pub struct OperationEnvelope {
    pub op_id: String,
    pub schema_version: u32,
    pub cluster_id: String,
    pub fork_id: String,
    pub epoch: u64,
    pub node_id: String,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub object_ref: String,
    pub base_revision: Option<String>,
    pub prev_local_op_hash: Option<String>,
    pub payload_kind: OperationKind,
    pub payload_hash: String,
    pub payload: Vec<u8>,
    pub signature: String,
}
```

The canonical bytes for signing exclude `signature` and use deterministic JSON or protobuf encoding. This choice must be locked in before network replication lands.

### Operation Kinds

Initial operation kinds:

- `ClusterInitialized`
- `NodeJoined`
- `NodeRemoved`
- `SecretCreated`
- `SecretValueAdded`
- `SecretValueSuperseded`
- `SecretTombstoned`
- `GrantChanged`
- `ReadRequested`
- `ReadApproved`
- `ReadFulfilled`
- `ApprovalRequested`
- `ApprovalResolved`
- `CollisionDetected`
- `CollisionResolved`
- `CheckpointCosigned`
- `ForkDeclared`

### Read Receipts

Cluster-enabled `hemd` must append signed read receipt operations before returning plaintext secret values to a client:

- `read.requested` records the requester, token id, secret scope/name, requested keys, materialized version marker, policy decision, and approval reference when present.
- `read.fulfilled` records the same non-secret metadata plus the corresponding `read.requested` operation id and released key count.

Read receipt payloads must never include plaintext secret values. They are integrity and accountability records, not access control by themselves. A node that holds the Hem master key or equivalent decrypt material can still decrypt local ciphertext outside the honest daemon path; read receipts make honest daemon retrieval auditable, but they cannot cryptographically prove that no out-of-band local decryption occurred on a fully trusted node. Policies that require stronger assurance must move decrypt authority into hardware-backed or threshold approval paths in later phases.

### Policy Tiers and Offline Leases

The first policy store is file-backed under the Hem data directory and is intentionally additive to existing local storage. Effective policy resolves in this order:

1. secret-specific policy
2. scope policy
3. default policy, initially `local_logged`

When a clustered daemon is explicitly offline, `local_logged` may release after signed local read receipts, `offline_lease` requires a valid unexpired lease for the secret/requester/node and consumes one use, and `peer_quorum` plus `master_biometric` fail closed until the required authority is reachable. The current offline detector is an explicit runtime switch for deterministic testing and operator-controlled offline mode; production reachability scoring belongs in the replication/approval phases.

For `master_biometric`, a non-master node does not release plaintext without a receipt. It persists a pending `get_secret` approval bound to requester, secret, content version marker, action, and expiry, and annotates the request with the configured master node target. The master-routing transport is still a follow-up; this slice establishes the durable request and receipt semantics that transport will replicate.

### Local Approval Adapters

`hem-core` exposes a standalone local approval adapter boundary for master-node acceptance. The first adapter is a master-password fallback that stores only a PBKDF2-HMAC-SHA256 verifier and evaluates approval challenges without issuing receipts itself. A successful adapter decision can be handed to the existing approval store to resolve a request; denied or aborted decisions are not receipt-bearing values and must leave the request pending or denied according to the calling flow.

The platform biometric adapter is capability-detected and isolated behind the same trait. Until a platform binding is wired, it reports biometrics unavailable and aborts approval attempts. This keeps Touch ID/WebAuthn support additive and testable without requiring real biometric hardware in CI.

### Local Store Migration

The V1 local JSON store migrates into the distributed ledger through an explicit operator command:

1. Back up the Hem data directory before migration.
2. Run `hem cluster migrate --dry-run` and inspect scanned secrets, values, groups, grants, planned operations, and unsupported records.
3. Run `hem cluster migrate` only when the distributed ledger is empty.
4. Verify `hem cluster status`, ledger materialization, and local `hem get` behavior.

The migration path reads the old local store and appends signed ledger operations; it does not delete, rewrite, or move existing local secret files. If migration needs to be rolled back before distributed mode is trusted, disable cluster use and continue with the old local store. If signed operations were appended incorrectly, restore from backup or intentionally hard-fork/rewind the distributed ledger; do not try to edit old local secret files as part of rollback.

Migrated records are represented as `group.set`, `secret.metadata.set`, `secret.value.set`, and `grant.access` operations. Current materializers make migrated metadata and value versions queryable immediately. Grant operations are preserved in the ledger history for the grant materializer that follows.

### Repair, Divergence, and Hard Forks

Operators verify ledger health with `hem cluster verify`. Verification walks the local hash chain, operation signatures, value blob envelopes, checkpoints, checkpoint cosignatures, peer cursors, and declared forks. Peer cursors or checkpoints that point beyond the local head are reported as divergence warnings; signature, hash-chain, checkpoint, or malformed blob failures are reported as integrity errors.

`hem cluster verify --repair` is intentionally conservative: it refreshes materialized views from the signed ledger, but it does not edit signed history. A destructive correction requires an explicit hard fork declaration. `hem cluster fork --parent-checkpoint <checkpoint-id> --reason <reason>` appends a signed `ledger.hard_fork` operation and records a fork row with a new fork id, epoch, parent checkpoint id, parent checkpoint hash, parent position, operator, reason, and operation id. Clients and operators can see declared forks through verification output and must not treat forked histories as silently equivalent.

### Distributed Integration Gate

The standalone distributed quality gate is `cargo test -p hemd --test distributed_integration`. The suite uses isolated temporary Hem data directories and ephemeral localhost ports, and covers two-node replication, offline catch-up, idempotent duplicate delivery, invalid signature rejection, three-node conflict detection, migration dry-run behavior, hard-fork declaration, and divergence reporting. CI should run this suite alongside `cargo test -p hem-core --test ledger_store` and `cargo test -p hemd --test peer_api` before distributed Hem changes are merged.

### Checkpoints

`Checkpoint` records include:

- checkpoint id
- cluster id
- fork id
- epoch
- operation range
- Merkle root
- signer node id
- signature
- created timestamp

The Merkle root is computed over operation hashes in a deterministic sorted order.

## SQLite Store

Distributed mode uses SQLite in `distributed/hem.db` under the selected Hem data dir.

Initial tables:

- `schema_migrations`
- `cluster_config`
- `node_identity`
- `peers`
- `operations`
- `operation_payloads`
- `blobs`
- `peer_cursors`
- `checkpoints`
- `checkpoint_signatures`
- `materialized_secrets`
- `secret_versions`
- `conflicts`
- `read_receipts`
- `approval_requests`
- `offline_leases`

No table stores plaintext secret values.

## Materialized State Rules

The materializer derives queryable state from the ledger:

- Latest non-tombstoned secret version is current.
- Tombstoned secrets are hidden from normal list/get paths.
- History metadata remains visible.
- Conflicted secrets remain readable only according to a conflict policy. The default is to return the last stable value and surface the unresolved conflict.
- Materialized state can be deleted and rebuilt from ledger operations plus encrypted blobs.

## Peer API

The peer API is separate from the existing local Hem runtime API.

First RPCs:

- `PeerHello`
- `GetHeadSummary`
- `PullOperations`
- `PushOperations`
- `GetCheckpointSummary`
- `PushCheckpointSignature`
- `FetchBlob`
- `RouteApprovalRequest`
- `ReportReadReceipt`

All peer RPCs require authenticated peer identity. Unknown peers fail before request handling.

## CLI Surface

First cluster commands:

- `hem cluster init`
- `hem cluster join`
- `hem cluster peers`
- `hem cluster status`
- `hem cluster remove`

Later commands:

- `hem history`
- `hem conflicts`
- `hem resolve-conflict`
- `hem lease issue`
- `hem ledger verify`
- `hem fork declare`
- `hem migrate-to-ledger`

## Compatibility Contract

- Local mode remains the default unless cluster mode is enabled.
- Existing `HEM_DATA_DIR` behavior remains unchanged.
- Tests must use explicit temp data dirs.
- No code path may automatically migrate or rewrite live Hem data.
- `hem-client` keeps `VALHALL_HEM_ADDR` and `VALHALL_HEM_TOKEN` defaults.
- `hemd` may still emit optional Valhall events in local mode, but distributed Hem core behavior cannot require those events.

## Implementation Sequence

1. Add cluster config and node identity scaffolding.
2. Add CLI cluster command shell.
3. Add SQLite ledger store.
4. Add signed operation envelope and hash-chain validation.
5. Add checkpoint calculation.
6. Add materializer.
7. Add peer API.
8. Add replication cursors and catch-up.
9. Move distributed-mode secrets to immutable versions.
10. Add conflicts, read receipts, policies, leases, master approvals, migration, and hardening.

Each item maps to one Linear task and one git commit.

## Safety Rules

- Never run tests against the operator's live Hem data dir.
- Never print secret values in test output, logs, debug formatting, or errors.
- Back up live Hem data before any migration or compatibility test.
- Prefer additive code paths until distributed mode has independent coverage.
- Any migration command must support dry-run before write mode.

## Open Items for Later Tasks

- Exact canonical encoding choice for signed operation bytes.
- Whether operation payloads should be stored as JSON or prost bytes.
- Whether peer transport certificates are generated by Hem or derived from node signing keys.
- Which platform binding should back the first hardware biometric adapter.
- Exact conflict read behavior for application clients.
