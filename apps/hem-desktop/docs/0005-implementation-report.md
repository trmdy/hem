# 0005 — Implementation Report

Status: v1 complete · 2026-07-05
Implements [0001](0001-product-spec.md) + [0002](0002-technical-architecture.md)
per the implementation brief; visuals from `design/hem-desk-v3.dc.html`.

## Quickstart

```sh
cd ~/src/hem-desktop
npm install                # electron binary: node node_modules/electron/install.js if needed
npm run dev                # boots against hemd on 127.0.0.1:50091, token auto-discovered
npm test                   # 34 unit tests
npm run test:integration   # 19 e2e tests against an isolated hemd on :59092 (throwaway tmpdir)
npm run typecheck && npm run lint && npm run build   # all clean
```

Config is env-based: `VALHALL_HEM_ADDR` (endpoint), `VALHALL_HEM_TOKEN` /
operator.token discovery chain (0004 §Auth), `HEM_DESK_BINARY` (hem CLI path),
`HEM_DESK_CLIPBOARD_CLEAR_SECONDS` (90), `HEM_DESK_REVEAL_REMASK_SECONDS` (30).

Keyboard: ⌘1–6 views · ⌘K palette · `/` filter · ↑↓/jk nav · ⌘C copy ·
⌘R reveal · ⌘⇧C copy ref · ⌘N new · E edit · ⌘⌫ delete · A/D approve/deny ·
S sync · H versions · I issue token · R revoke · g then o/v/m/a/t/l chords.

## Per-milestone status

**M1 — skeleton + read path: done.** electron-vite 5 + React 19 + StyleX 0.19
(postcss-plugin + babel via @vitejs/plugin-react) + Base UI. Tokens in
`src/renderer/theme/tokens.stylex.ts` are extracted verbatim from the design
file (gray ramp, borders, shadows, Geist/Geist Mono via @fontsource). Main
process ports hem-raycast's proven `client.ts` (grpc-js over vendored proto @
valhall `14d77f8`, in `proto/` + `PROTO_REV`), token discovery chain, refs,
errors. Vault master-detail with sectioned list, fuzzy `/` filter, masked
keys; Overview with daemon/mesh/approvals cards + activity; ⌘K palette with
object jump and ⌘⏎ copy-primary (two keystrokes).

**M2 — mesh: done.** `mesh:snapshot` (cluster status+peers, ~10 ms) paints
instantly; the ~30 s `cluster health` probe streams in behind it, cached in
main with a 5-minute staleness guard and single-flight dedup (the
hem-raycast launch-bug lesson, encoded in `createHandlers`). Node grid local
first, lag/last-seen lines, per-node copy-diagnosis, collisions panel that
copies a ready-made `resolve-collision` command (runbook stance: never
auto-repair), Sync now (S).

**M3 — write path: done.** New/Edit modal per design 1b (scope segmented
control, project combobox with "Create …", live ref availability, dynamic
key/value rows, `.env` paste split with quote/export/comment handling).
Delete rides the server-side approval flow: `vault:delete` →
`approval_required` + request id → jump to Approvals → approve → the
action-bound receipt is consumed automatically by a delete retry. Approvals
view per 1e with inline confirms and one-shot receipt cards. NATS bridge in
main (`hem.>` → IPC events → query invalidation), poll fallback if NATS is
down; payloads deliberately ignored (subjects only).

**M4 — admin + polish: done except packaging.** Tokens view (list, issue
service/agent with TTL presets — agent capped 24 h, revoke with inline
confirm, token shown once + concealed copy). Audit view (until-cursor
paging, fuzzy filter, expandable rows, copy-JSON). Palette actions. Reveal
auto-remasks (30 s countdown rendered per key); copy path never sends the
value to the renderer; clipboard is concealed + cleared after 90 s. Status
bar renders per-view shortcut hints per the design. **Not done: packaged/
notarized build** — no electron-builder config; `npm run build` (electron-vite)
is what's verified.

**M5 — history: done.** Version timeline in secret detail from
`distributed/ledger.sqlite3`, read via `/usr/bin/sqlite3 -json` with
`mode=ro&immutable=1`, metadata columns only, grouped per operation
(one SetSecret = one row), "All versions" behind H. Degrades to nothing
when there is no ledger (verified in integration).

## Verification actually performed

- **Unit (34)**: token chain order/fallthrough/trim, cluster kv + health
  parsers against captured live fixtures, exit-code fallback, ref
  parse/format/proto round-trips, `.env` parser, redaction property —
  values registered as sensitive never reach a log sink in any shape, and
  masks never contain more than a 4-char suffix.
- **Integration (19)** against an isolated `hemd --bind 127.0.0.1:59092
  --data-dir <tmpdir>`: init → set across 3 scopes → single-call list →
  masked get (asserts no plaintext in anything crossing the IPC boundary) →
  reveal → concealed copy + scheduled clear (fake adapter) → replace
  semantics → groups → scan → service-token issue → gated read (async_read)
  → pending → approve → receipt retry → **receipt single-use asserted** →
  deny → delete → approval → receipt retry deletes → grants round-trip →
  revoke → audit (no plaintext) → error mapping → history degrade. Daemon
  SIGTERMed, tmpdir removed.
- **GUI**: `npm run dev` booted against a seeded isolated hemd on 59092
  (remote-debugging CDP harness, `scripts/drive-gui.mjs`); screenshots of
  all six views, palette, and New Secret modal captured with **zero
  renderer console errors**; approve loop exercised in the GUI — receipt
  card rendered, badge decremented. Mesh + History pulled genuinely live
  data during this run (cluster CLI reads local files; ledger read-only) —
  elm05 shown lagging 6,917 ops, amber, exactly per the design's calm
  idiom.
- **Production daemon** (allowlist only, `scripts/live-smoke.ts`): Health
  ok (v0.2.0 on 127.0.0.1:50091 loopback), ListSecrets (97 across 13
  sections), GetSecretInfo, ListGroups. No writes, no value reads, no
  approvals, no sync were ever issued against production; cluster CLI use
  was limited to `status`/`peers`/`health` (read-only).

## Design-fidelity notes (deviations, with why)

1. **`@base-ui/react` 1.6.0** instead of `@base-ui-components/react` — the
   package was renamed upstream; same library.
2. **Detail header buttons are "Edit E · Delete ⌘⌫"**, not the design's
   "Rotate R". Rotate isn't a daemon primitive for value secrets — editing
   replaces the value set (hem's SetSecret semantics), which is what
   rotation means here. Spec behavior (§3.2 Edit ⌘E) won over the label.
3. **New Secret modal has a fourth quiet group "Details"** (description +
   requires-approval) beyond 1b's three groups — spec §3.2 requires both
   fields for a well-formed secret; kept to one compact row.
4. **Approve also confirms inline** (design 1e shows a confirm only for
   deny); spec §3.4 demands an explicit confirm naming action and ref for
   both. Same inline pattern, never a modal.
5. **A desaturated red `#b0453f`** exists for critical/offline/unreachable
   dots; the design file contains no red at all. Used sparingly (status
   dots only).
6. **Concealed clipboard** is a JXA `osascript` helper writing
   `org.nspasteboard.ConcealedType` + plain text, value passed via stdin —
   Electron's clipboard API has no concealed flavor. Falls back to plain
   `clipboard.writeText` if osascript fails. Timed clear is the ported
   detached `/bin/sh` + SHA-256-via-stdin helper.
7. **Ledger history uses `/usr/bin/sqlite3 -json`** (shell-out, immutable
   read-only URI) instead of better-sqlite3 — avoids native-module ABI
   rebuilds for Electron entirely; macOS ships sqlite3.
8. **Grants browser** lives in the secret detail ("Access" section, live
   grant data; grant/revoke handlers exist on the IPC surface) rather than
   a second pane in Tokens; the Tokens view says so. Spec §3.5's
   "by grantee" pivot is not built.
9. **Resolved-approvals tail** is session-local receipt cards + the Audit
   view, not a persistent last-20 list (hemd has no list-resolved RPC;
   deriving it from audit actions felt like guessing).
10. **Settings are env vars**, no electron-store/keychain pinned-token UI
    yet — token discovery covers the single-operator case; noted for later.
11. Sidebar label is **"Tokens"** (design) though the spec calls the view
    "Tokens & Grants".
12. Mesh status bar shows the clock rather than "last sync 14:31" — the
    CLI doesn't expose a last-sync timestamp cheaply.

## Untested / not implemented

- **Packaging + notarization** (M4 item): not implemented.
- **`mesh:syncOnce`**: implemented, never executed — the brief forbids
  cluster mutations against the live mesh and the isolated daemon has no
  cluster. Treat as untested until a human clicks it once.
- **NATS live badges**: bridge implemented and non-fatal by design, but no
  event was provoked end-to-end during verification.
- **macOS notification** on approval request (spec §3.4 "optional"): not
  implemented.
- Collisions panel with non-zero collisions; `FAILED_PRECONDITION`
  policy-read rendering (needs peer_quorum + peers down) — both rendered
  from code paths that unit/integration cover structurally, not visually.
- Real-pasteboard concealed flavor + 90 s clear (helper logic tested with a
  fake adapter; the JXA/pbcopy path itself wasn't asserted).
- The app pointed at the **production** daemon end-to-end: the agent's
  safety allowlist forbade Approvals/Tokens/Audit RPCs against production,
  so full-surface live rendering was verified against the isolated daemon
  instead. Launching `npm run dev` as the human operator is the remaining
  step; nothing in the app mutates without an explicit confirmed action.

## Open issues

- Renderer bundle is ~900 kB (grpc types are main-side; this is React +
  Base UI + Query); fine for a desktop app, untuned.
- `notion-sync`-style per-key focused row uses Tab to cycle keys; design
  implies ↑↓ inside the keys card — ↑↓ currently moves the secret list.
- Audit `result` badness heuristic assumes `ok|success` vocabulary.
