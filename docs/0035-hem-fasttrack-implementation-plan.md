# 0035 - Fast-Track Implementation Plan: `hem`

Date: 2026-02-21  
Status: In progress
Owner: Hem stream

## Decision

`docs/0034-hem-proposal-prompt.md` is source-of-truth for Hem scope and requirements.  
`docs/0000-system-architecture.md` is architectural authority.  
`docs/0005-sprint-1-claude-proposed-structure.md` remains source-of-truth for already-shipped Sprint-1 behavior that Hem must integrate with.

## Goal

Fast-track a production-usable local Hem stack:

- `hemd` daemon with encrypted-at-rest secret store, token authn/authz, approvals, grants, audit.
- `hem` CLI for full operator workflows.
- `hem-core` Rust library for service embedding (`smi`, `vis`, later others).
- first cross-service integrations:
  - Smi provider keys + agent run token injection
  - Vis embedding key resolution
  - Skip host alias support for containerized agent -> host `hemd` reachability
- backward-compatible fallback to current env-var behavior.

## Baseline (today)

- `crates/hem` is placeholder only (`README.md`), no Cargo crate.
- no `hem-core`, no `hemd`, no Hem protobuf contract.
- no Hem event topics in `valhall-events`.
- Smi/Vis still resolve keys from env/config directly.
- Skip does not yet expose host alias convention (`host.skip.internal`) for container-to-host service calls.

## Scope boundaries (fast-track)

In:

- single-node local Hem only.
- token-based auth (operator/service/agent-run), HMAC signed.
- encrypted secret values using XChaCha20-Poly1305.
- secret scopes: global, project, identity + explicit grants.
- approval flow: blocking + async pending/poll/event.
- audit logs + Hem event emission.
- key rotation with crash-safe semantics.

Out (explicitly deferred):

- mesh-distributed secret replication.
- mTLS / full cryptographic identity binding to Vis.
- hardware-backed key storage.
- desk/UI.
- advanced policy engine beyond scope/grants/approval flag.

## Architecture target

### Crates

- `crates/hem-core` (new):
  - domain model, storage, crypto, tokens, authz, approval orchestration, audit.
- `crates/hemd` (new):
  - gRPC server, mesh events, daemon lifecycle, runtime config.
- `crates/hem` (convert placeholder -> real CLI crate):
  - operator workflows over `hemd` RPC.

### Proto

- `proto/valhall/hem/v1/hem.proto` (new): HemRuntime contract.
- `build.rs` in `hem`/`hemd` same pattern as `smi`/`smid`.

### TypeScript SDK

- `sdks/typescript/packages/hem` (new): `@valhall/hem-sdk`.

### Runtime paths

Default `HEM_DATA_DIR=~/.valhall/hem`:

- `master.key` (0600)
- `operator.token` (0600)
- `service-tokens/<service>.token` (0600)
- `secrets/global/*.json`
- `secrets/project/<project>/*.json`
- `secrets/identity/<identity_id>/*.json`
- `grants/*.json`
- `approvals/pending/*.json`, `approvals/resolved/*.json`
- `tokens/revoked.json`
- `audit/YYYY-MM-DD.jsonl`
- `rotation/` (temporary manifests for safe key rotation)

## Key technical decisions

### 1) Secret file schema (v1)

Metadata plaintext; values encrypted blobs only.

Per value record:

- `alg = "xchacha20poly1305"`
- `nonce_b64`
- `ciphertext_b64`
- `key_id` (for rotation compatibility)

Secret metadata fields:

- name, scope, description, requires_approval, group
- created_at, updated_at, created_by
- last_accessed_at, last_accessed_by

### 2) Token format

Use compact HMAC token (not JWT):

- payload: JSON claims base64url
- signature: HMAC-SHA256(base64url(payload), signing_key)
- token string: `<payload_b64>.<sig_b64>`

Claims:

- `token_id` (ULID)
- `token_type` (`operator|service|agent_run`)
- `issued_at`, `expires_at`
- `issued_by`
- `identity_id?`, `project?`
- `scopes[]`
- `service_name?`

Signing key:

- derived from master key via HKDF label `hem-token-v1`.

Revocation:

- token-id denylist in `tokens/revoked.json` with expiry pruning.

### 3) Scope resolution

Unscoped secret get by name uses strict order:

- identity -> project -> global, first match wins.

Scoped gets bypass fallback chain and enforce exact scope.

### 4) Approval flow runtime

For `requires_approval=true` reads:

- create `ApprovalRequest` + persist + emit `hem.approval.requested`.
- sync path: block wait up to timeout (default 5m).
- async path: return `pending` response with `request_id`.
- approval/deny resolves waiting callers + emit `hem.approval.resolved`.

### 5) Key rotation safety

Two-key compatible rotation:

1. create new key `K2` with new `key_id`.
2. re-encrypt all values from current keyset into temp files.
3. atomic replace secret files.
4. atomically write keyset (`primary=K2`, keep previous key `K1`).
5. mark rotation complete, prune old key in later maintenance window.

Crash mid-rotation must preserve decryptability via keyset.

### 6) `valhall-common` dependency note

`0034` mentions `valhall-common`, but repo has no such crate.  
Fast-track decision: implement using existing workspace crates (`valhall-net`, `valhall-auth`, `valhall-config`) and std modules.  
Optional later: extract shared helpers into `valhall-common` after Hem MVP lands.

## API contract plan (proto)

Service: `HemRuntime`.

Core RPCs:

- Secret mgmt: `SetSecret`, `GetSecret`, `GetSecretInfo`, `DeleteSecret`, `ListSecrets`, `GetSecrets`.
- Groups: `SetGroup`, `AddToGroup`, `RemoveFromGroup`, `ListGroups`, `ListGroupSecrets`.
- Tokens: `IssueAgentToken`, `IssueServiceToken`, `RevokeToken`, `ListActiveTokens`.
- Grants: `GrantAccess`, `RevokeAccess`, `ListGrants`.
- Approval: `ListPendingApprovals`, `ApproveAccess`, `DenyAccess`, `GetApprovalStatus`.
- Audit: `GetAuditLog`.
- Admin: `RotateMasterKey`, `ExportSecrets`, `ImportSecrets`, `InitHem`, `Health`.

Proto design rules:

- explicit enums for scope/grantee/result status.
- `oneof` for secret lookup key (`name` or fully qualified ref).
- optional `wait_timeout_ms` + `async` on read requests.
- response includes `pending` state for approval-delayed reads.

## Authorization matrix (v1)

- Operator token: full access.
- Service token:
  - read global by default.
  - read/write scoped secrets only with explicit grants.
  - can issue agent tokens only for its own service identity.
- Agent-run token:
  - read scopes in token claims.
  - no admin, no token issuance, no key rotation.

Write/delete actions always audited.

## Fast-track phases and task list

### Phase 0 - bootstrap contracts and crates

- [x] `HEM-001` Add workspace members: `crates/hem-core`, `crates/hem`, `crates/hemd`.
- [x] `HEM-002` Add `proto/valhall/hem/v1/hem.proto`.
- [x] `HEM-003` Add `build.rs` + proto compile for CLI/daemon crates.
- [x] `HEM-004` Add workspace deps: `chacha20poly1305`, `hmac`, `sha2`, `rand`/`getrandom`, `base64`, `subtle`.
- [x] `HEM-005` Add Hem topics to `valhall-events`.

Exit:

- crates compile with empty stubs and generated proto.

### Phase 1 - `hem-core` models + encrypted storage

- [x] `HEM-010` Define core models: `Secret`, `SecretScope`, `SecretValueCipher`, `TokenClaims`, `Grant`, `ApprovalRequest`, `AuditEntry`.
- [ ] `HEM-011` Implement path-safe store layout and file locking strategy.
- [x] `HEM-012` Implement XChaCha20-Poly1305 encrypt/decrypt API with AAD.
- [x] `HEM-013` Implement master key creation/load + strict 0600 permission checks.
- [x] `HEM-014` Implement secret CRUD (encrypted values only on disk).
- [x] `HEM-015` Implement group metadata operations.

Exit:

- encryption roundtrip + secret persistence tests green.

### Phase 2 - tokens, authn/authz, grants

- [x] `HEM-020` Implement token signer/verifier (HMAC, constant-time verify).
- [x] `HEM-021` Implement operator/service/agent-run token issuance.
- [x] `HEM-022` Implement token TTL enforcement + max agent TTL (24h).
- [x] `HEM-023` Implement revoke list + prune expired revocations.
- [x] `HEM-024` Implement scope resolution chain (identity -> project -> global).
- [ ] `HEM-025` Implement explicit grant checks for cross-scope access.

Exit:

- token validation benchmark + expiry/revoke/authz tests green.

### Phase 3 - approvals + audit engine

- [ ] `HEM-030` Implement approval request persistence + in-memory wait registry.
- [ ] `HEM-031` Implement sync wait flow (timeout + denial propagation).
- [ ] `HEM-032` Implement async pending flow (`request_id`, polling status).
- [ ] `HEM-033` Implement audit append/query + 90-day retention pruning.
- [ ] `HEM-034` Implement structured action/result taxonomy for all reads/writes/token ops.

Exit:

- approval sync/async integration tests + audit correctness tests green.

### Phase 4 - `hemd` daemon

- [ ] `HEM-040` Implement tonic `HemRuntime` service over `hem-core`.
- [ ] `HEM-041` Add auth interceptors (bearer token extraction + validation context).
- [ ] `HEM-042` Add mesh connection `Mesh::connect("hemd", ...)`.
- [ ] `HEM-043` Emit Hem events:
  - `hem.secret.read`
  - `hem.secret.written`
  - `hem.secret.deleted`
  - `hem.token.issued`
  - `hem.token.revoked`
  - `hem.approval.requested`
  - `hem.approval.resolved`
- [ ] `HEM-044` Add graceful startup checks (`master.key` perms, data-dir readiness).

Exit:

- daemon RPC smoke and event emission tests green.

### Phase 5 - `hem` CLI

- [ ] `HEM-050` Implement command surface from `0034` (`set/get/info/delete/list`, groups, grants, approvals, token, admin, service register).
- [x] `HEM-051` Add `hem init` (master key + operator token bootstrap).
- [ ] `HEM-052` Add secure output modes (redaction option, `--json`).
- [ ] `HEM-053` Add robust scope parser shorthand (`global/foo`, `project/p/name`, `identity/id/name`).
- [ ] `HEM-054` Add CLI error mapping for approval pending/timeout/denied.

Exit:

- CLI end-to-end operator workflows functional.

### Phase 6 - Smi integration

- [ ] `HEM-060` Extend `smi-core::HarnessProfile` with secret refs (`api_key_secret`, optional map for provider/env overrides).
- [ ] `HEM-061` Add Hem client in `smi-core` to resolve provider key at run time.
- [ ] `HEM-062` Add fallback semantics: Hem first, env fallback if unavailable/missing.
- [ ] `HEM-063` In `smid`, issue agent token per run and inject:
  - `VALHALL_HEM_TOKEN`
  - `VALHALL_HEM_ADDR`
- [ ] `HEM-064` Ensure stop/finalize path handles token expiry/revocation cleanup (if needed).

Exit:

- API harness can run with Hem-managed provider keys without env key.

### Phase 7 - Skip integration (`host.skip.internal`)

- [ ] `HEM-070` Add host alias plumbing in `skip-core` runtime setup for containerized skips.
- [ ] `HEM-071` Validate containerized process can reach host `hemd` via alias.
- [ ] `HEM-072` Wire `smid` containerized flow to set `VALHALL_HEM_ADDR=http://host.skip.internal:<port>`.

Exit:

- containerized Smi agent can successfully read Hem secret through alias.

### Phase 8 - Vis integration

- [ ] `HEM-080` Extend `vis-core` config with `openai_api_key_secret` (or provider-neutral secret ref).
- [ ] `HEM-081` Resolve key via Hem first, fallback env/config second.
- [ ] `HEM-082` Add tests for missing Hem, missing secret, and successful secret resolution.

Exit:

- Vis embeddings can run from Hem-managed key with fallback preserved.

### Phase 9 - TypeScript SDK

- [ ] `HEM-090` Create `sdks/typescript/packages/hem` package scaffold.
- [ ] `HEM-091` Implement `HemClient` methods: `get`, `getAll`, `set`, `delete`, `waitForApproval`, token/env config.
- [ ] `HEM-092` Support `VALHALL_HEM_TOKEN` and `VALHALL_HEM_ADDR` defaults.
- [ ] `HEM-093` Add package typecheck/build integration.

Exit:

- Node/Bun agents can consume Hem directly.

### Phase 10 - backup/import/rotation hardening

- [ ] `HEM-100` Implement encrypted export/import bundle format.
- [ ] `HEM-101` Implement key rotation transaction journal + restart recovery logic.
- [ ] `HEM-102` Add interruption tests for rotation safety.
- [ ] `HEM-103` Add operator runbook docs for backup/restore/rotation.

Exit:

- key rotation and restore validated under failure scenarios.

## Integration with repo ops

- Add `hemd` into:
  - `Makefile` targets (`install`, `install-daemons`, `hem-*` commands).
  - `scripts/valhall-daemons.sh` and `scripts/valhall-system-daemons.sh`.
- Define default bind (proposed): `127.0.0.1:50091`.
- Add `scripts/hem-smoke-test.sh` and include in docs.

## Test matrix (must-have)

- encryption roundtrip + tamper detection.
- plaintext-never-on-disk checks.
- token issue/validate/expire/revoke tests.
- scope resolution precedence tests.
- grants allow/deny tests.
- approval sync timeout/deny/approve tests.
- approval async pending/poll tests.
- batch get performance and correctness.
- audit completeness tests.
- concurrent read/write lock safety tests.
- key rotation crash-recovery tests.
- containerized host reachability via `host.skip.internal` tests.
- smi integration tests (Hem secret -> provider call path).
- vis integration tests (Hem secret -> embedding call path).

## Performance targets

- token validation p95 < 0.1ms (in-process benchmark).
- single secret decrypt p95 < 2ms on local SSD.
- `GetSecrets` batch(10) p95 < 15ms local.
- approval wake-up latency p95 < 50ms after approve action.

## Rollout and migration

1. Land Hem standalone (`hem-core`, `hemd`, `hem`) behind no cross-service behavior changes.
2. Enable Smi Hem resolution as opt-in via profile fields.
3. Enable Vis Hem resolution as opt-in via config key-secret field.
4. Keep env fallback enabled by default during migration window.
5. After usage confidence, mark env direct secrets as deprecated in docs.

## Risks and mitigations

- Risk: accidental plaintext leakage through logs/errors.
  - Mitigation: central redaction helper, lint checks, audit payload schema with explicit excludes.
- Risk: rotation bugs causing unrecoverable decrypt failures.
  - Mitigation: keyset model + journaled rotation + interruption tests.
- Risk: approval blocking stalls agent loops.
  - Mitigation: default timeout + async mode + clear pending errors.
- Risk: Skip host alias behavior drifts per OS.
  - Mitigation: dedicated linux/macos reachability tests + explicit fallback docs.

## Acceptance criteria (fast-track done)

- Hem daemon/CLI/library fully functional in local single-node mode.
- all secret values encrypted at rest; permission checks enforced.
- token authn/authz and approvals operational (sync + async).
- audit/events emitted for all critical actions.
- Smi and Vis integrations working with env fallback preserved.
- containerized agents can reach Hem via stable host alias convention.
- quality gates green:
  - `cargo fmt --all -- --check`
  - `cargo check --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - focused `cargo test` sets + Hem smoke scripts

## Immediate next slice (start now)

- [x] `HEM-N1` Phase 0 tasks `HEM-001..005`.
- [ ] `HEM-N2` Phase 1 tasks `HEM-010..015` with encryption and storage tests first.
  Remaining: `HEM-011` (file-locking strategy).
- [ ] `HEM-N3` Phase 2 tasks `HEM-020..025` to unblock daemon auth.
  Remaining: `HEM-025` (persisted grants + enforcement path).
- [x] `HEM-N4` minimal daemon+CLI loop: `hem init`, `hem set`, `hem get` against `hemd`.
