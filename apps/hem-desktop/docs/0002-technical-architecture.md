# 0002 — Hem Desk Technical Architecture

Status: draft v1 · 2026-07-04
Companion to [0001-product-spec.md](0001-product-spec.md). All daemon facts
verified against the valhall repo (2026-07-04 deep dive).

## 1. Stack decision

**Tauri v2** (Rust shell) + **React 19 / TypeScript / Vite** frontend.

Why Tauri over Electron:
- Hem is a Rust system; a Rust core lets us speak tonic gRPC natively with
  types generated from the same proto the daemon compiles
  (`valhall/proto/valhall/hem/v1/hem.proto`) — no grpc-js, no proto-loader
  drift, no Node sidecar holding secrets.
- Secret values then live only in Rust process memory + the moment of
  render; the webview never holds more than the currently displayed view
  model.
- Small binary, native macOS feel, first-class keyboard/menu APIs.

Frontend libs: TanStack Router (view routing), TanStack Query (server
state, polling), Tailwind v4 (design tokens from doc 0003), cmdk-style
palette component (custom, keyboard-first). No global state library —
server state is Query, UI state is component-local.

## 2. Process architecture

```
┌─ Tauri app ──────────────────────────────────────────────┐
│                                                          │
│  WebView (React)                                         │
│    · views, palette, forms                               │
│    · TanStack Query ⇄ tauri::invoke (typed commands)     │
│    · listens: tauri events "hem://approval", "hem://…"   │
│                                                          │
│  Rust core (crate: hem-desk-core)                        │
│    ├ grpc.rs      tonic client → 127.0.0.1:50091         │
│    │              full HemRuntime surface                │
│    ├ auth.rs      operator-token discovery chain         │
│    ├ cluster.rs   `hem cluster health|peers|collisions`  │
│    │              shell-out + kv/peer_health parsers     │
│    ├ events.rs    async-nats → nats://127.0.0.1:4222     │
│    │              subscribe hem.secret.*, hem.token.*,   │
│    │              hem.approval.* → Tauri events          │
│    ├ clipboard.rs concealed copy + timed clear           │
│    └ redact.rs    view-model shaping: masks by default,  │
│                   reveal returns value once, no caching  │
└──────────────────────────────────────────────────────────┘
```

### 2.1 Data-source rules (mirror the daemon's real shape)

| Data | Source | Why |
|---|---|---|
| Secrets, groups, tokens, grants, approvals, audit, scan, health | gRPC `HemRuntime` | the only real API; operator token required for management RPCs |
| Cluster health / peers / collisions | shell-out to `hem cluster …` | cluster state is local-file + peer-probe; **no daemon RPC exists**. Output is documented machine-readable `key=value` (valhall doc 1021). `NO_COLOR=1`, absolute binary path (configurable, default `~/.valhall/system-daemons/bin/hem`) |
| Live change notifications | NATS `hem.*` topics | hemd publishes secret read/write/delete, token issue/revoke, approval request/resolve; failure to connect is non-fatal (poll fallback) |
| Value history (cluster mode) | gRPC first; if not exposed, read-only SQLite on `distributed/ledger.sqlite3` (`ledger_secret_value_versions`, metadata columns only) | plaintext never lives in the ledger; metadata-only query is safe. Open read-only, immutable=1, and tolerate schema drift (user_version pinned) |

### 2.2 Auth

Token discovery (identical order to `hem` CLI so behavior never surprises):
`VALHALL_HEM_TOKEN` → `$HEM_DATA_DIR/operator.token` →
`$VALHALL_SYSTEM_DAEMONS_DIR/data/hem/operator.token` →
`~/.valhall/hem/operator.token` → `~/.valhall/system-daemons/data/hem/operator.token`.
Settings can pin an explicit token (stored in macOS Keychain, not config
file). Endpoint: `VALHALL_HEM_ADDR` → `VALHALL_HEMD_ENDPOINT` → default.

The app uses the **operator token** deliberately (single-user tool; the
management RPCs it needs — ListActiveTokens, ListGrants, GetAuditLog,
Approve/DenyAccess, ListPendingApprovals — are operator-only anyway).

### 2.3 IPC command surface (tauri::invoke)

Thin, view-model-shaped, all typed with serde + a generated TS mirror
(specta or hand-kept `ipc.ts`):

```
vault_list()                → [SecretRow]            (masked, no values)
vault_get(ref)              → SecretDetail           (values masked; per-key mask tail)
vault_reveal(ref, key)      → String                 (one-shot; not retained in Rust)
vault_copy(ref, key)        → ()                     (Rust copies concealed + schedules clear;
                                                      value never crosses IPC)
vault_set(input)            → SecretMeta
vault_delete(ref)           → DeleteOutcome{done | approval_required{request_id}}
approvals_list/approve/deny, tokens_list/issue/revoke,
grants_list/grant/revoke, audit_query(filter, cursor),
mesh_health(), mesh_sync_once(), mesh_collisions(),
daemon_health(), scan_text(text)
```

Note `vault_copy`: the common path (copy a value) never sends the value to
the webview at all — Rust fetches, Rust copies, Rust clears.

### 2.4 Approval-flow correctness (the subtle daemon semantics)

- `DeleteSecret` without receipt ⇒ `approval_required` + `request_id`;
  the app surfaces it and navigates to Approvals. After approve, the app
  retries the delete with the receipt automatically (receipts are
  single-use and action-bound to delete).
- `GetSecret` on `requires_approval` secrets: operator token bypasses —
  but the app still badges these secrets and confirms before reveal, so
  the UI doesn't silently erase the secret's own protection intent.
- Cluster read policies: `peer_quorum` / `master_biometric` reads can fail
  `FAILED_PRECONDITION` when peers/master are unreachable. Map these to a
  policy-explaining state, never a retry loop.

## 3. Live updates & polling

- NATS subscription drives: approvals badge + notification, vault list
  invalidation (`hem.secret.written/deleted`), token list invalidation.
- Poll cadence (TanStack Query): daemon `Health` 30 s (cheap,
  unauthenticated); `mesh_health()` 60 s when Mesh/Overview visible
  (it probes peers — don't hammer); everything else on-focus/on-event.
- All polling pauses when the window is hidden; menu-bar-less by design
  (the Raycast extension owns ambient status).

## 4. Security engineering

- Values: never in webview localStorage/sessionStorage, never in Query
  cache (reveal responses bypass Query), never logged (tracing layer with
  redaction test), never in window title. Reveal auto-remask 30 s.
- Clipboard: `org.nspasteboard.ConcealedType` flavor + clear after 90 s
  (only if clipboard still holds our value — compare hash, not value).
- CSP: default-src 'self'; no remote content in the webview at all.
- Tauri allowlist: only the declared commands; no shell plugin exposure to
  the frontend (shell-outs happen in Rust with fixed argv, values never in
  argv).
- macOS hardening: app-sandbox off (needs `~/.valhall` + spawning `hem`),
  but hardened runtime + notarization for a clean local install.
- The app never writes to the hem data dir. Read-only ledger access uses
  sqlite `mode=ro&immutable=1`.

## 5. Repo layout

```
hem-desktop/
  src-tauri/
    Cargo.toml            workspace: app + hem-desk-core
    src/main.rs           tauri setup, command registration
    crates/hem-desk-core/ grpc, auth, cluster, events, clipboard, redact
    proto/hem.proto       vendored + PROTO_REV (sync script from valhall repo)
  src/                    React app
    routes/               overview, vault, mesh, approvals, tokens, audit
    components/palette/   ⌘K
    ipc.ts                typed invoke wrappers
  docs/                   these specs
```

Proto sync: `scripts/sync-proto.sh` copies from
`../valhall/proto/valhall/hem/v1/hem.proto` and stamps the source git rev;
CI-less for now, drift is caught by tonic build failures.

## 6. Testing strategy

- `hem-desk-core` unit tests: kv/peer_health parsers against captured real
  outputs (fixtures from the live 6-node cluster, including the lagging-
  node and warning states); token discovery chain; redaction property
  ("no value string ever appears in any Debug/log output").
- Integration: spin `hemd --data-dir <tmp>` (binary already built in the
  valhall repo) + `hem init`, run the full IPC surface against it —
  including the delete→approval→receipt→retry loop.
- Frontend: palette + keyboard-model tests (vitest + testing-library);
  no e2e until the UI settles.

## 7. Milestones

1. **M1 — skeleton + read path**: tauri app boots, token discovery, Vault
   list/detail (masked), Overview daemon card, ⌘K object jump.
2. **M2 — mesh**: cluster parsers + Mesh view with node grid, health
   states, sync-now.
3. **M3 — write path**: new/edit secret forms, delete→approval loop,
   Approvals view, NATS live badge.
4. **M4 — admin**: tokens & grants, audit, palette actions, reveal/copy
   hardening (concealed + clear), notarized build.
5. **M5 — history**: ledger version timeline in secret detail.
