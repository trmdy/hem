# 0044 - Hem V1 Readiness Closure

Date: 2026-02-22
Status: V1-ready (local single-node scope)
Owner: Hem stream

## Scope

Source plan and requirements:
- `docs/0034-hem-proposal-prompt.md`
- `docs/0035-hem-fasttrack-implementation-plan.md`
- `docs/0038-hem-auth-grants-audit-hardening-summary.md`
- `docs/0041-hem-admin-and-service-secret-wiring.md`

This closure confirms Hem fast-track completion for the local node architecture (distribution/UI deferred by design).

## Final Checklist

- [x] Encrypted secret store with strict master-key permissions and crash-safe rotation journal.
- [x] Token authn/authz model (operator/service/agent-run), TTL enforcement, revoke list.
- [x] Grant-aware authorization enforcement for scoped access.
- [x] Approval flow complete: async pending + sync wait + receipt consumption.
- [x] Audit engine complete with retention pruning and query filters.
- [x] `hemd` runtime complete: RPC surface, mesh hookup, Hem event emission.
- [x] `hemd` startup preflight checks for data-dir + key readiness semantics.
- [x] `hem` CLI operator/admin flows complete (set/get/info/search/list aliases/archive/delete approvals/export/import/rotate/audit/grants/tokens/service).
- [x] Rust shared client crate (`hem-client`) implemented and integrated.
- [x] Smi integration complete: Hem key resolution + per-run token/address injection.
- [x] Skip integration complete: `host.skip.internal` alias for container-to-host Hem access.
- [x] Vis integration complete: Hem-backed OpenAI key resolution with fallback preserved.
- [x] TypeScript SDK complete: `@valhall/hem-sdk` with `get`, `getAll`, `set`, `delete`, `waitForApproval`.

## Validation Evidence

Rust/CI gates:
- `make ci` (pass)
  - `cargo fmt --all -- --check`
  - `cargo check --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `cargo test -p valhall-net --features integration-nats`
  - `./scripts/bod-perf-targets.sh`

Additional focused gates:
- `cargo clippy -p hem-core -p hem-client -p hemd -p smi-core -p vis-core -p skip-core --all-targets -- -D warnings` (pass)
- `cargo run -p hemd -- --once --data-dir <tmpdir>` (pass)

TypeScript SDK gates:
- `cd sdks/typescript && npm run typecheck` (pass)
- `cd sdks/typescript && npm run build` (pass)

## Deferred by Design (Not V1 Blockers)

- Mesh-distributed secret replication.
- Desk/UI approval surfaces.
- mTLS / hardware-backed key storage.
- Advanced policy engine beyond token scopes + grants + approval flag.

## Verdict

Hem is ready to operate as the project’s V1 secret system for meaningful local production work now.

Recommended immediate follow-up:
- cut/tag a `hem-v1` release marker and update operator runbook links to this closure doc.
