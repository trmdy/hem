# 1014 - PRD: Standalone Distributed Hem

Date: 2026-05-25  
Status: Draft  
Owner: Hem stream  
Linear project: (internal tracker)  
Implementation status: Initial distributed Hem slices have landed; remaining hardening is tracked in Linear.  
Related: `docs/0034-hem-proposal-prompt.md`, `docs/0044-hem-v1-readiness-closure.md`, `docs/0089-hem-scan-secret-leak-detection.md`

## Summary

Hem should evolve from a local Valhall secret daemon into a standalone distributed secret system. The new system must let multiple trusted machines share secrets without depending on Verk, Kode, valhall-net, NATS, or other Valhall primitives. Valhall tools should remain clients of Hem, but Hem itself must own its cluster membership, peer transport, replication, approval policy, audit history, and cryptographic integrity model.

Distributed Hem is not a simple file sync layer. It needs a ledger-style operation model with immutable history, signed read receipts, durable peer catch-up, explicit collision handling, and policy-controlled offline behavior. The strongest retrieval guarantees require that high-security secrets cannot be decrypted by ordinary nodes unless an approval or lease has already been recorded.

## Goals

- Run Hem as a standalone service on many machines.
- Keep local reads fast and offline-capable for secrets whose policy permits it.
- Preserve full value history through immutable ledger events unless an explicit hard fork creates a new epoch.
- Track secret reads with signed read receipts and replicated audit history.
- Detect and surface write collisions instead of silently choosing a winner.
- Provide multiple approval levels, including master-node approval backed by Touch ID/WebAuthn or a master password.
- Allow gradual adoption from the existing local Hem V1 store.
- Keep Smi, Vis, Kode, and other Valhall components able to use Hem via the existing daemon/client contract.

## Non-Goals

- No dependency on Verk node inventory.
- No dependency on valhall-net, Ting, NATS, Kode, Bod, Smi, or Vis for core operation.
- No public blockchain or cryptocurrency model.
- No attempt to make all secrets offline-readable. High-security policies must be allowed to fail closed.
- No silent automatic merge of concurrent secret value writes.
- No hidden history rewrite. Rewind requires an explicit fork/epoch transition.

## Product Principles

1. **Standalone first.** Hem owns its mesh.
2. **Tamper evident by default.** History is append-only and hash-linked.
3. **Local when safe, gated when necessary.** Offline behavior is policy-specific.
4. **No silent winners.** Secret value collisions become first-class records.
5. **Reads are events.** A retrieval is not complete until the read path has produced a signed receipt.
6. **Security tiers are explicit.** A low-risk development key and a root cloud credential should not share the same read policy.
7. **Migration is incremental.** Existing local Hem remains useful while distributed mode is introduced.

## Users and Use Cases

### Human Operator

The operator wants to manage secrets once and have them safely available on multiple personal or work machines. They need clear status, collision warnings, approval prompts, and recovery tools.

### Local Agent Runtime

An agent running on a node needs local access to allowed secrets, preferably through the local `hemd`, with clear failure when a policy requires online approval.

### Automation Service

A service needs service-scoped access tokens, durable revocation, and predictable behavior when nodes are offline.

### Master Approval Node

The master node can approve high-security secret retrievals through Touch ID/WebAuthn or a master password. Other nodes can route approval requests there and wait for one-time approval receipts.

## Security Tiers

Hem should support at least these read policies:

| Tier | Policy | Offline Behavior |
| --- | --- | --- |
| Low | `local_logged` | Node may read after appending a signed local read receipt. |
| Medium | `offline_lease` | Node may read only if it already holds a valid bounded lease. |
| High | `peer_quorum` | Node must obtain quorum approval before decrypting. |
| Highest | `master_biometric` | Node must obtain a master-node approval backed by Touch ID/WebAuthn or master password. |

If a node unexpectedly goes offline, Hem must never downgrade a secret policy. For high and highest tiers, the request remains pending until the needed authority is reachable.

## Core Concepts

### Hem Cluster

A Hem cluster is a standalone group of `hemd` peers. A cluster has:

- `cluster_id`
- cryptographic cluster epoch
- peer list
- peer public keys
- checkpoint history
- policy defaults

### Hem Node

Each machine running `hemd` has:

- `node_id`
- local node signing key
- optional transport certificate/key
- local encrypted store
- local operation ledger
- peer cursors
- replication state

### Operation Ledger

Every meaningful action is represented as an immutable operation:

- `cluster.initialized`
- `node.joined`
- `node.removed`
- `secret.created`
- `secret.value.added`
- `secret.value.superseded`
- `secret.tombstoned`
- `grant.changed`
- `read.requested`
- `read.approved`
- `read.fulfilled`
- `approval.requested`
- `approval.resolved`
- `collision.detected`
- `collision.resolved`
- `checkpoint.cosigned`
- `fork.declared`

Each operation includes:

- operation id
- cluster id
- fork id / epoch
- node id
- local sequence
- timestamp
- actor
- object reference
- base revision when applicable
- previous local op hash
- payload hash
- node signature

### Checkpoints

Nodes periodically compute Merkle roots over operation ranges. Peers cosign checkpoints so the cluster can identify stable history and detect tampering or forks.

### Secret Values

Secret values are immutable encrypted versions. Updating a value appends a new version and supersedes the old one; it does not overwrite history.

### Hard Fork / Rewind

A rewind creates a new fork id or epoch with an explicit parent checkpoint. Clients must not silently mix epochs. Operators must acknowledge the fork.

## Functional Requirements

### Cluster Management

- `hem cluster init` creates a standalone Hem cluster.
- `hem cluster join` joins a node through an invite bundle or invite token.
- `hem cluster peers` shows current peers and their replication status.
- `hem cluster remove <node_id>` removes a node from future key wrapping and marks the removal in the ledger.
- `hem cluster status` shows local head, stable checkpoint, peer cursors, conflicts, and pending approvals.

### Transport

- `hemd` exposes a peer-to-peer API separate from the local client API.
- Initial peer discovery can be static config.
- Transport must authenticate peers cryptographically.
- The transport must support operation pull, operation push, checkpoint exchange, blob fetch, and approval request routing.

### Storage

- Distributed mode should use a transactional store for the operation ledger and materialized state.
- SQLite is acceptable and preferred for the first distributed implementation.
- Encrypted secret blobs may remain content-addressed files or move into SQLite blobs if simpler.
- The system must be able to rebuild materialized state from the ledger.

### Replication

- Peers exchange signed heads and cursors.
- Missing operations are fetched by range.
- Applying operations must be idempotent.
- Offline operations remain local until replicated.
- A local operation is not considered stable until quorum checkpoint rules are satisfied.

### Collision Handling

- Secret writes include a base revision.
- Concurrent writes from the same base create a `collision.detected` record.
- Collisions block automatic promotion of the affected secret.
- Resolution appends a `collision.resolved` operation and requires an approval policy appropriate to the secret.

### History

- All secret values remain available as encrypted historical versions unless an explicit hard fork creates a new epoch.
- Tombstones mark deletions.
- Operators can inspect value history metadata without revealing plaintext.
- Reading historical plaintext follows the same approval policy as reading current plaintext unless overridden.

### Retrieval Tracking

- Honest `hemd` reads must append a signed `read.requested` record before releasing plaintext.
- A successful read appends `read.fulfilled`.
- The receipt includes secret ref, version, key name, requester, approving authority if any, timestamp, and policy result.
- Read receipts replicate to peers.
- High-security secrets must not keep sufficient decrypt material on ordinary nodes unless covered by a valid lease.

### Approval

- Approval policies are attached to secrets and may inherit defaults by scope.
- Approval receipts are one-time, action-bound, requester-bound, secret-bound, version-bound, and expiry-bound.
- Highest-tier approval routes to a configured master node.
- The master node supports Touch ID/WebAuthn where available and master-password fallback.
- Approval requests survive restarts and reconnect after offline periods.

### Offline Mode

- Offline reads obey the secret's policy.
- Offline writes are tentative local branch operations.
- On reconnect, Hem reconciles local operations with remote history.
- Unexpected offline must never weaken a policy.
- Operators can pre-issue offline leases for selected secrets.

### Key Management

- The MVP may use a shared trusted-cluster keyset if every node is equally trusted.
- The architecture must leave room for per-secret data encryption keys wrapped to authorized nodes.
- Node removal must prevent that node from receiving new wrapped keys.
- Rewrapping and rotation should be explicit cluster operations.

### Compatibility

- Existing local Hem commands continue to work outside cluster mode.
- Valhall services can keep using `VALHALL_HEM_ADDR` and `VALHALL_HEM_TOKEN`.
- Existing Hem secrets can migrate into the ledger with a one-time import operation.

## Rollout Plan

### Phase 1 - Standalone Cluster Skeleton

Create cluster and node identity primitives, static peer configuration, and basic `hemd` peer API without changing existing local secret behavior.

### Phase 2 - Ledger Storage

Introduce the signed operation ledger, SQLite schema, operation hashing, and materialized state rebuild.

### Phase 3 - Replication

Implement operation exchange, peer cursors, blob fetch, and offline catch-up.

### Phase 4 - Secret History and Conflict Semantics

Move secret writes into versioned ledger events, add tombstones, base revisions, and collision records.

### Phase 5 - Retrieval Receipts and Approval Policies

Make reads ledger-backed, add policy evaluation, offline leases, and receipt replication.

### Phase 6 - Master Approval

Add master-node routing and local biometric/password approval for highest-tier secrets.

### Phase 7 - Hardening and Migration

Add migration, repair, rotation, rewrap, multi-node tests, and operator runbooks.

## Acceptance Criteria

- Two nodes can join a standalone Hem cluster without Verk or valhall-net.
- A secret written on node A becomes readable on node B after replication.
- A node offline during a write catches up after reconnect.
- Concurrent conflicting secret writes produce an explicit collision record.
- Historical value metadata is visible and immutable.
- Read receipts are written and replicated for successful reads.
- Highest-tier secrets fail closed when the master node is unreachable.
- Master-node approval can release a one-time read receipt.
- Existing local Hem remains usable when cluster mode is disabled.
- Multi-node tests cover replication, offline catch-up, collisions, approvals, and hard-fork detection.

## Risks

- Full Byzantine consensus is expensive and likely unnecessary for the first standalone personal mesh.
- Shared cluster keyset is simpler but increases compromise blast radius.
- Biometric support differs by platform and may need separate adapters.
- Offline readability and cryptographic certainty are in tension; policies must make that tradeoff explicit.
- Retrofitting the current file store may be harder than introducing SQLite for distributed mode.

## Open Decisions

- First key model: trusted shared cluster keyset or envelope encryption from day one.
- First transport: gRPC over rustls mTLS or Noise-based transport.
- Quorum default: simple majority or configurable `K-of-N`.
- Master approval UX: CLI prompt first, native app later, or both.
- Whether historical plaintext reads always require current policy or can use version-specific policy.
