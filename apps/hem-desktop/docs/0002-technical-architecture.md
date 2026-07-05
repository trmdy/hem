# 0002 — Hem Desk Technical Architecture

Status: v2 · 2026-07-05 (v1 specced Tauri; superseded by owner decision:
**Electron + React + StyleX + Base UI**)
Companion to [0001-product-spec.md](0001-product-spec.md). Daemon facts:
[0004-hem-integration-reference.md](0004-hem-integration-reference.md).
Visual source of truth: `design/hem-desk-v3.dc.html` (exported from Claude
design; grayscale token direction per [0003](0003-claude-design-prompt.md) v2).

## 1. Stack

- **Electron** (main = Node) + **electron-vite** for dev/build.
- **React 19 + TypeScript** renderer.
- **StyleX** for styling — design tokens extracted from the design file's
  CSS into `src/renderer/theme/tokens.stylex.ts` (single source for the
  gray ramp, spacing, radii, type scale).
- **Base UI** (`@base-ui-components/react`) for unstyled primitives
  (menus, dialogs, popovers, tooltips, fields) — styled exclusively with
  StyleX to match the design.
- **TanStack Query** for server state (polling, invalidation).
  View routing is plain state (⌘1–⌘6 switch) — no router dependency
  unless deep-linking appears.
- gRPC in the **main process** via `@grpc/grpc-js` + `@grpc/proto-loader`
  over the vendored proto — the exact pattern proven in
  `../hem-raycast/src/hem/client.ts`; port that code rather than rewriting.

## 2. Process architecture

```
┌─ Electron ────────────────────────────────────────────────┐
│                                                           │
│  Main (Node, trusted)              src/main/              │
│    ├ hem/client.ts   grpc-js → 127.0.0.1:50091            │
│    ├ hem/token.ts    operator-token discovery chain       │
│    ├ hem/cluster.ts  `hem cluster …` shell-out + parsers  │
│    ├ hem/events.ts   nats.js → 127.0.0.1:4222 (hem.*)     │
│    ├ clipboard.ts    concealed copy + timed clear         │
│    ├ redact.ts       view models: masked by default       │
│    └ ipc.ts          typed handlers (surface below)       │
│                                                           │
│  Preload (contextBridge)           src/preload/           │
│    └ exposes window.hem = typed invoke/subscribe only     │
│                                                           │
│  Renderer (sandboxed, no Node)     src/renderer/          │
│    · React + StyleX + Base UI, views + ⌘K palette         │
│    · TanStack Query ⇄ window.hem.invoke                   │
│    · window.hem.on("approval", …) live badges             │
└───────────────────────────────────────────────────────────┘
```

### 2.1 Data-source rules (unchanged from v1 — mirror the daemon's shape)

| Data | Source |
|---|---|
| Secrets, groups, tokens, grants, approvals, audit, scan, health | gRPC `HemRuntime` from main |
| Cluster snapshot (instant) | `hem cluster status` + `peers` shell-out (~10 ms, local files) |
| Cluster health (slow) | `hem cluster health` shell-out — **~30 s** (ledger verify + peer probes); never block a view on it; cache with a 5-min staleness guard (lesson learned in hem-raycast, see its docs/0002 §Post-import fixes) |
| Live updates | NATS `hem.*` via nats.js in main → forwarded as IPC events; non-fatal if NATS is down (poll fallback) |
| Value history (cluster mode) | read-only SQLite on `distributed/ledger.sqlite3` (`mode=ro&immutable=1`, metadata columns only) — `better-sqlite3` in main |

### 2.2 Auth (unchanged)

Token discovery identical to the CLI:
`VALHALL_HEM_TOKEN` → `$HEM_DATA_DIR/operator.token` →
`$VALHALL_SYSTEM_DAEMONS_DIR/data/hem/operator.token` →
`~/.valhall/hem/operator.token` → `~/.valhall/system-daemons/data/hem/operator.token`.
Endpoint: `VALHALL_HEM_ADDR` → `VALHALL_HEMD_ENDPOINT` → default. Explicit
overrides live in app settings (electron-store; a pinned token goes to the
macOS Keychain via `keytar`/`safeStorage`, never a JSON file).

### 2.3 IPC surface (ipcMain.handle, all typed end to end)

```
vault:list()                → SecretRow[]           (masked, no values)
vault:get(ref)              → SecretDetail          (values masked)
vault:reveal(ref, key)      → string                (one-shot; renderer must not retain)
vault:copy(ref, key)        → void                  (main fetches + copies concealed +
                                                     schedules clear; value NEVER crosses IPC)
vault:set(input)            → SecretMeta
vault:delete(ref)           → {done} | {approvalRequired: requestId}
approvals:list/approve/deny · tokens:list/issue/revoke
grants:list/grant/revoke    · audit:query(filter, cursor)
mesh:snapshot()             → instant status+peers
mesh:health(maxAgeMs)       → cached-or-fresh slow probe
mesh:syncOnce() · mesh:collisions()
daemon:health() · scan:text(text)
events: "hem:approval", "hem:secret-changed", "hem:token-changed"
```

`vault:copy` is the hot path and the security-critical one: the common
"copy a value" action never sends the value to the renderer at all.

### 2.4 Approval-flow semantics (verified against hemd; see 0004)

- `GetSecret` on gated secrets: always pass `async_read: true` — without
  it the RPC blocks server-side (hem-raycast finding).
- Delete is approval-gated even for the operator token: first call returns
  `approval_required` + request id; after approve, auto-retry with the
  single-use, action-bound receipt.
- Cluster policy reads can fail `FAILED_PRECONDITION` (peer quorum /
  master unreachable) — render the policy explanation, never retry-loop.

## 3. Security engineering

- BrowserWindow: `contextIsolation: true`, `nodeIntegration: false`,
  `sandbox: true`, `webSecurity: true`; CSP `default-src 'self'`; no
  remote content, ever; `will-navigate`/`setWindowOpenHandler` deny.
- Values: never in renderer storage of any kind, never in TanStack Query
  cache (reveal bypasses Query), never logged (redaction test asserts no
  value string reaches any log sink), never in the window title.
  Reveal auto-remasks after 30 s.
- Clipboard: `org.nspasteboard.ConcealedType` flavor + clear after 90 s,
  comparing SHA-256 (hash via stdin, value never in argv/env — port the
  hem-raycast helper).
- Shell-outs: fixed argv arrays, `NO_COLOR=1`, absolute binary path from
  settings (default `~/.valhall/system-daemons/bin/hem`).
- The app never writes to the hem data dir; ledger access is read-only.
- Packaging: hardened runtime + notarization; no auto-update in v1.

## 4. Repo layout

```
hem-desktop/
  design/hem-desk-v3.dc.html   exported design (visual source of truth)
  proto/hem.proto + PROTO_REV  vendored from ../valhall (sync script)
  src/main/                    hem/, ipc.ts, clipboard.ts, redact.ts, index.ts
  src/preload/index.ts
  src/renderer/
    theme/tokens.stylex.ts     extracted from the design file
    components/                Base UI + StyleX primitives (Button, Table, …)
    palette/                   ⌘K
    views/                     overview, vault, mesh, approvals, tokens, audit
  tests/                       vitest unit + integration (isolated hemd)
  docs/
```

## 5. Testing

- Unit (vitest, main-process modules): token chain, cluster parsers
  (reuse hem-raycast fixtures), redaction property, `.env` paste parser.
- Integration: boot isolated `hemd --data-dir <tmp>` on a dedicated port
  (59092 — 59091 is hem-raycast's), drive the full IPC handler surface
  including the delete→approval→receipt loop; tear down.
- Renderer: palette + keyboard-model tests with testing-library; no e2e
  (Playwright-Electron) until the UI settles.

## 6. Milestones

1. **M1 — skeleton + read path**: electron-vite boots, tokens.stylex.ts
   from the design, main-process hem client + token discovery, Vault
   list/detail (masked), Overview daemon card, ⌘K object jump.
2. **M2 — mesh**: snapshot/health staged loading, Mesh view per design,
   sync-now, collisions.
3. **M3 — write path**: new/edit secret forms, delete→approval loop,
   Approvals view, NATS live badges.
4. **M4 — admin + polish**: tokens & grants, audit, palette actions,
   reveal/copy hardening, keyboard hint line, packaged + notarized build.
5. **M5 — history**: ledger version timeline in secret detail.
