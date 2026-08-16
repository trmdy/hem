# 0002 — Implementation Report

Status: v1 complete · 2026-07-04
Implements: [0001-extension-spec.md](0001-extension-spec.md), executed per `AGENT_BRIEF.md`.

## Quickstart (10 lines)

```sh
cd ~/src/hem-raycast
npm install
npm run dev          # ray develop → imports the extension into Raycast (Development section)
# In Raycast: "Search Secrets" ⏎ copies the primary value, ⌘I inspects,
# ⌘N adds, ⌃X deletes (approval-gated). "Cluster Status" shows the mesh.
# Menu bar dot: ● ok / ◐ warning / ✕ critical or daemon down, badge = pending approvals.
npm test                  # 37 unit tests (parsers, token chain, refs, .env)
npm run test:integration  # 16 e2e tests against an isolated hemd on :59091
npm run build && npm run lint   # both pass clean
# Token/endpoint/binary/clipboard-clear are Raycast preferences (⌘, on any command).
```

## Built, per milestone

**M1 — read path.** `src/hem/client.ts` (grpc-js + proto-loader over vendored
`assets/hem.proto` @ valhall rev in `assets/hem.proto.rev`; typed wrappers for
the full app-facing HemRuntime surface — vault, groups, tokens, grants,
approvals, audit, admin, health; Peer* RPCs deliberately excluded).
`src/hem/token.ts` implements the six-step discovery chain (spec §2) with
injectable env/home for tests. Search Secrets: sectioned by scope, cached
metadata paint via `useCachedPromise`, Copy Primary Value / Pick Key / Paste /
Inspect (masked values, per-key reveal, grants) / Copy Ref / Copy as CLI.
Menu bar with health dot.

**M2 — write path.** Shared `SecretForm` for Add + Edit (scope dropdown,
live slugify, group dropdown fed by `ListGroups` + "New Group…" free text,
requires-approval checkbox, dynamic key/value rows with password fields).
Delete fires `DeleteSecret`, surfaces `approval_request_id` with a jump to
Pending Approvals — never auto-approves. Approvals command with
confirmation-alert Approve/Deny, receipt copy (concealed), single-use +
action-bound messaging.

**M3 — mesh.** `src/hem/cluster.ts`: execa shell-out (`NO_COLOR=1`,
configurable binary), generic `key=value` + record-line parser, peer_health
mapping, exit-code → status fallback. Cluster Status view (header facts,
local node first, per-peer lag/cursor/last-seen, amber lagging state),
Sync Now (`cluster sync --once`), Copy Health Report, collisions sub-list
with ready-made `resolve-collision` command copy (resolution stays in the
terminal). Menu-bar approval badge + per-node one-liners.

**M4 — polish.** Scan Clipboard (no-view, HUD, refs only), Audit Log
(limit 200, newest-first sort, scope filter dropdown, copy-JSON), concealed
copy + detached timed clipboard clear, `.env` paste import (quotes, `export `,
comments; keys normalized to `[a-z0-9_]`, original kept as row hint).

Tests: 37 unit (token chain, cluster parsers vs captured live fixtures in
`tests/fixtures/`, ref parse/format, `.env` parser) + 16 integration
(`tests/integration/hemd.itest.ts`): boots isolated hemd on 127.0.0.1:59091
with throwaway data dir, then init → set (3 scopes) → list (verifies
unspecified scope = all scopes) → get (map + single key + replace semantics)
→ groups → scan → gated read as service token → approve → receipt retry →
deny → delete → approval_required → approve → receipt retry → not-found
mapping → audit entries. Teardown kills the daemon and removes the tmpdir.

## Facts learned the hard way (now encoded in code/tests)

- **`async_read: true` is required** for approval-gated reads to return
  `Pending{request_id}`; otherwise the RPC blocks server-side until the
  approval resolves or the deadline expires. The UI always sets it.
- Approval `action` strings are `get_secret` / `delete_secret` style (not
  bare `get`/`delete`).
- `ListSecrets` with an unspecified scope selector returns all scopes
  (integration-verified) — Search Secrets needs exactly one RPC.
- The `Health` status string is `"ok cluster_enabled=… node_id=… …"` —
  parseable with the same k=v tokenizer.
- Delete is approval-gated even for the operator token (integration-verified:
  `deleted=false` + pending request on first call).

## Deviations & judgment calls

1. **Command entry files.** Raycast requires entry points at
   `src/<command-name>.tsx`; the spec's layout (§7) wants `src/commands/*.tsx`.
   Both: implementations live in `src/commands/`, one-line re-export shims sit
   at `src/*.tsx`.
2. **`npm run lint`.** `ray lint` validates `author` against raycast.com and
   404s for every candidate handle (no registered account found on this
   machine, and even `--relaxed` still checks it). `npm run lint` therefore
   runs the identical local checks (`eslint src && prettier --check src &&
   tsc --noEmit`); `npm run lint:ray` keeps full validation for when a real
   Raycast username is put in `package.json#author`. This is the only reason
   `ray lint` proper doesn't pass; ESLint/Prettier/TS are clean.
3. **`.env` paste import** explodes via an explicit "Import .env From Paste
   Area" action (⌘⇧I) rather than on every keystroke — onChange-triggered
   explosion mangles half-typed lines.
4. **Per-key reveal (⌘R)** in Inspect is an ActionPanel submenu listing keys;
   Raycast's Detail view has no per-row selection to hang a single toggle on.
5. **Copy as CLI** fetches values once to pick the primary key for
   `hem get <ref> <key>` (metadata alone doesn't know the keys); the value is
   discarded.
6. **Timed clipboard clear** is a detached `/bin/sh` helper (survives the
   command process). It clears only if the clipboard still matches, comparing
   a SHA-256 passed via **stdin** — the value itself never reaches argv, env,
   or disk; only its hash leaves the process.
7. **Dynamic form rows**: Raycast forms can't add rows inline, so Add/Remove
   Row are ActionPanel actions (⌘⇧A / ⌘⇧⌫).
8. **Menu-bar command disabled.** The original spec's five-minute background
   command is no longer registered. A non-ok peer made the full-ledger
   `hem cluster health` probe eligible on every tick, which contributed to a
   recurring filesystem-event and CPU storm. Cluster health is now strictly
   user-initiated through Cluster Status.
9. **KeyPicker paste variant**: when Paste-into-frontmost falls through to the
   key picker, the picker's primary action is Paste instead of Copy.

## Untested (needs the real Raycast UI)

- Everything visual: list rendering, Detail markdown/metadata, form UX,
  toasts/HUDs, confirmation alerts, `launchCommand` jumps between commands.
- `npm run dev` import flow and preferences panel (documented as written;
  `ray build` compiles the same entry points, but I could not drive the
  Raycast app itself).
- Menu-bar background interval behavior and `Clipboard.copy(…, {concealed})`
  semantics.
- **Sync Now** (`hem cluster sync --once`) — implemented but never executed:
  the brief forbids cluster mutations against the live mesh, and the isolated
  daemon has no cluster. Treat as untested until clicked once by a human.
- Collision list rendering with non-zero collisions (live cluster has 0; the
  parser handles record lines generically, fixture-tested only for the empty
  case).
- `FAILED_PRECONDITION` cluster-policy read rendering (needs a peer_quorum
  policy secret with peers down).

## Post-import fixes

- **2026-07-04 · Cluster Status perceived hang.** `hem cluster health` takes
  ~31 s on this cluster (full ledger verification + probing the dead
  elm05 peer), and both Cluster Status and the menu bar awaited it before
  rendering. Fixed with staged rendering: `cluster status` + `cluster peers`
  (local config reads, ~10 ms, `getClusterSnapshot`) paint the view
  instantly with a "probing peers… ~30 s" health row and per-node
  "probing…" accessories; the health probe streams in when done. The menu
  bar now renders from cache immediately, fetches daemon health + approvals
  in a fast gRPC pass, and reruns the 31 s probe only when the cached result
  is older than 5 minutes (staleness guard — previously it reran on every
  popover open while the cluster was non-ok, which is this cluster's steady
  state).
- **2026-08-16 · Background health storm.** System diagnostics correlated the
  five-minute Raycast menu-bar probe with repeated high-CPU/full-ledger Hem
  scans and runaway `fseventsd` pressure. The menu-bar command was removed
  from the manifest. Add Secret and every user-invoked command remain
  available; no Hem CLI process is now launched in the background.

## Known issues / notes

- `ray lint` (full) fails only on the unregistered `author` (see deviation 2).
- Audit-log `result` coloring assumes `ok`/`success` = green; other strings
  render red. Adjust if hemd emits different vocabulary.
- Real-vault exposure during development was read-only and within the allowed
  set (Health, ListSecrets, ListGroups smoke checks + `hem cluster
  health/status/peers/collisions` fixture capture). No writes, no deletes, no
  approvals, no sync against production. No secret value was logged or
  committed.
