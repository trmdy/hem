# 0038 - Hem Auth/Grants/Audit Hardening Summary

Date: 2026-02-21  
Status: Completed (this pass)

## Scope completed

This pass closes the pending Hem fast-track items for:
- grant-aware authorization enforcement in `hemd`
- action-bound approval policy wiring in `hemd`
- audit-log RPC implementation + audit writes
- operator CLI coverage for grants and audit
- integration test matrix for auth/grants/approvals/audit
- secure bootstrap runbook

## What changed

### `hemd`

- Fixed incomplete grant-aware authorization path:
  - scoped lookup
  - name-resolution chain (`identity -> project -> global`)
  - batch lookups
  - list filtering (`list_secrets`, `list_group_secrets`)
- Completed grants RPCs wiring:
  - `GrantAccess`
  - `RevokeAccess`
  - `ListGrants`
- Completed audit RPC wiring:
  - `GetAuditLog` with optional scope/since/until/limit filters
- Added audit append calls for:
  - secret set/get/delete (including pending approval states)
  - grant/revoke
  - approve/deny
  - token issue/revoke
- Added approval action-policy gate for approval resolution:
  - allows `get_secret | set_secret | delete_secret`
  - rejects unknown action strings

### `hem-core`

- Added `AuditStore` (`audit/entries.jsonl`) with append/list filtering.
- Added grants persistence and API on `HemStore`:
  - `grant_access`, `revoke_access`, `list_grants`, `has_grant`

### `hem` CLI

Added commands:
- `hem grant-access <secret> --grantee-scope <scope> --grantee-id <id>`
- `hem revoke-access <secret> --grantee-scope <scope> --grantee-id <id>`
- `hem list-grants <secret>`
- `hem audit [--scope global|project/<p>|identity/<id>] [--since RFC3339] [--until RFC3339] [--limit N]`

Also updated examples payload/shell output to include grant/audit flows.

### Tests

New integration test:
- `crates/hemd/tests/auth_approval_matrix.rs`

Covers end-to-end:
- unauthenticated runtime call rejection
- service token global read allowed
- project read denied before grant
- project read allowed after grant
- approval pending -> approve -> receipt -> successful read
- single-use receipt enforcement
- action-bound receipt enforcement (`get_secret` receipt rejected for `set_secret`)
- audit entries present for key actions

### Documentation

- Updated `crates/hem/README.md` with grants/audit examples.
- Updated `docs/0036-hem-cli-agent-usage-clarification.md` with grants/audit usage.
- Added `docs/0037-hem-bootstrap-secure-usage-runbook.md`.

## Validation run

- `cargo check -p hemd -p hem-core` (pass)
- `cargo test -p hemd --test auth_approval_matrix` (pass)
- `cargo test -p hem-core -p hemd -p hem` (pass)
- `cargo run -p hem -- grant-access --help` (pass)
- `cargo run -p hem -- list-grants --help` (pass)
- `cargo run -p hem -- audit --help` (pass)
- `cargo install --path crates/hemd --locked --force` (pass)
- `cargo install --path crates/hem --locked --force` (pass)
- `make daemons-system-restart` (pass, `hemd` listening on `127.0.0.1:50091`)
- `hem health` (pass)

## Current known deferred items

- `hemd` export/import/rotate RPCs remain unimplemented.
