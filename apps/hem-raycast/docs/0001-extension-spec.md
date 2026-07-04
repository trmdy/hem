# 0001 — Hem Raycast Extension Spec

Status: draft v1 · 2026-07-04
Audience: personal extension for Tormod, not for the Raycast store.

## 1. Why

Hem's only interface is the `hem` CLI. Day-to-day use ("what was that Fiken
key called again?", "copy the anthropic api_key", "is elm05 still
lagging?") costs a terminal round-trip every time. Raycast is already the
launcher; secrets and mesh status should be two keystrokes away.

## 2. Ground truth about Hem (from the 2026-07-04 deep dive)

Everything below is verified against the valhall repo and the live system.

- `hemd` is a **tonic gRPC** daemon (`valhall.hem.v1.HemRuntime`), plaintext
  HTTP/2 on `127.0.0.1:50091`. No REST, no unix socket. Proto source of
  truth: `valhall/proto/valhall/hem/v1/hem.proto`.
- **Auth**: `authorization: Bearer <token>` metadata on every RPC except
  `Health` and `InitHem`. Operator token resolution order (CLI-compatible):
  1. explicit preference/`--token`
  2. `VALHALL_HEM_TOKEN`
  3. `$HEM_DATA_DIR/operator.token`
  4. `$VALHALL_SYSTEM_DAEMONS_DIR/data/hem/operator.token`
  5. `~/.valhall/hem/operator.token`
  6. `~/.valhall/system-daemons/data/hem/operator.token`  ← launchd install (current live setup)
- **Operator token = full admin.** Management RPCs (ListActiveTokens,
  ListGrants, GetAuditLog, ListPendingApprovals, Approve/DenyAccess,
  IssueServiceToken…) are operator-only. Since this is a single-user
  extension, we use the operator token.
- **Secrets are maps**: one secret ref holds many `key=value` pairs.
  Refs: `global/<name>`, `project/<project>/<name>`, `identity/<id>/<name>`.
  Names/projects are strict slugs: `[a-z0-9-]+`.
- **Approval-gated secrets** (`requires_approval`) return
  `Pending{request_id}` for non-operator callers; operator tokens bypass.
  Delete is always approval-gated server-side.
- **Cluster state is local-file + peer-probe**, not a daemon RPC. The
  machine-readable source is `hem cluster health` (stable `key=value` lines +
  `peer_health …` lines, exit 0/1/2). `Health` RPC returns a one-line status
  string with `cluster_enabled/node_id/peers/…` tokens.
- **`@valhall/hem-sdk`** (grpc-js + proto-loader, pure JS — Raycast-safe)
  covers get/getAll/set/delete/approval-status only. No list/search, grants,
  audit, tokens, approvals-list. → We use grpc-js against the vendored proto
  directly and get the full RPC surface.
- Known live quirk: one mesh node (`hmn_elm05`) has been lagging
  since June; `cluster_health_status=warning` is a normal steady state to
  render, not an error to hide.

## 3. Architecture

```
Raycast command (React, @raycast/api)
        │
        ├── src/hem/client.ts      grpc-js + @grpc/proto-loader
        │      · vendored hem.proto (assets/hem.proto)
        │      · full HemRuntime surface, typed wrappers
        │      · token discovery (order above) + endpoint pref
        │
        └── src/hem/cluster.ts     execa → `hem cluster health` / `status` / `peers`
               · parses key=value + peer_health lines
               · NO_COLOR=1, explicit binary path pref
                 (default /home/user/.valhall/system-daemons/bin/hem)
```

Rules:

- **gRPC for everything the daemon serves** (secrets, tokens, grants, audit,
  approvals, scan, health). No stdout parsing for vault data.
- **CLI shell-out only for `cluster *`** (those commands read local
  `cluster.toml`/ledger and probe peers — the daemon has no equivalent RPC).
  Their `key=value` output is documented as machine-readable (valhall docs
  1021) and safe to parse.
- Never invoke interactive CLI commands (`approve`, `deny`,
  `set --interactive`) — approvals go through `ApproveAccess`/`DenyAccess`
  RPCs, which have no TTY requirement.
- Proto sync: `assets/hem.proto` is copied from the valhall repo; a
  `npm run sync-proto` script re-copies and records the source commit in
  `assets/hem.proto.rev`.

### Preferences (Raycast extension preferences)

| Pref | Default | Notes |
|---|---|---|
| `endpoint` | `http://127.0.0.1:50091` | maps to gRPC target |
| `token` | empty | password field; empty ⇒ file discovery |
| `hemBinary` | `~/.valhall/system-daemons/bin/hem` | for cluster commands |
| `clipboardClearSeconds` | `90` | 0 = never clear |
| `primaryKeyGuess` | `api_key,token,key,password,secret` | ordered candidates for the "just copy it" action |

## 4. Commands

### 4.1 `Search Secrets` (view) — the workhorse

- `List` with fuzzy filtering over `ListSecrets` (all scopes), sections by
  scope (`global`, `project/<p>`, `identity/<id>`), subtitle = description,
  accessories = group tag + relative `updated_at`.
- Cache: last successful listing cached (Raycast `Cache`) for instant paint;
  refresh in background on open. Metadata only — **never cache values**.
- Actions (⏎-first ordering):
  - **Copy Primary Value** (⏎) — `GetSecret`, pick first key matching
    `primaryKeyGuess`, else sole key, else fall through to key picker.
    Copies with `concealed: true` (kept out of clipboard managers),
    schedules clear after `clipboardClearSeconds`.
  - **Pick Key…** (⌘⏎) — sub-list of keys → copy that value (concealed).
  - **Paste into Frontmost App** (⌥⏎).
  - **Inspect** (⌘I) — Detail view: metadata, keys with masked values
    (`••••` + last 4), per-key reveal toggle (⌘R), grants, ref.
  - **Copy Ref** (⌘⇧C) — e.g. `project/globex/linear`.
  - **Copy as CLI** (⌘⇧X) — `hem get project/globex/linear api_key`.
  - **Edit…** (⌘E) — push Add/Edit form pre-filled (values fetched, editable).
  - **New Secret** (⌘N) — push Add form.
  - **Delete…** (⌃X) — fires `DeleteSecret`; on `approval_required`, shows
    the `request_id` with a "Open Pending Approvals" action (receipt flow —
    see 4.4). Never auto-approves.

### 4.2 `Add Secret` (view, form)

- Fields: scope dropdown (`global` default / `project` / `identity`),
  project or identity id (conditional), name (live-slugified, validation
  `[a-z0-9-]+`), description, group (dropdown from `ListGroups` + free
  text), requires-approval checkbox, and a dynamic key/value list
  (start with `api_key`).
- **Paste import**: a text area that accepts `.env`-style `KEY=VALUE` lines
  and explodes them into the key/value list (keys lowercased to valid form,
  originals preserved as displayed hint).
- Values passed as literals via `SetSecret` (never through a shell, never
  through argv).
- On success: toast + optional "Copy Ref".

### 4.3 `Cluster Status` (view)

- Runs `hem cluster health` (+ `hem cluster peers` for wrap-key info).
- Header section: `cluster_health_status` (ok/warning/critical), cluster id,
  local node id, `latest_position`, checkpoint status + cosignature count,
  `quorum_risk`, `collisions`, `sync_errors`.
- One list item per node (local node first): status icon
  (caught_up ✓ / lagging ◐ / offline ✕ / divergent ⚠), endpoint, lag (ops),
  cursor position, last_seen (relative). Live example: `hmn_elm05`
  lagging 6541 ops → ◐ + amber.
- Actions: **Sync Now** (`hem cluster sync --once`, streamed toast),
  **Copy Health Report**, **Refresh** (⌘R), **Show Collisions** (sub-list
  from `hem cluster collisions`; resolution stays in the terminal — copy
  the ready-made `hem cluster resolve-collision …` command instead).

### 4.4 `Pending Approvals` (view)

- `ListPendingApprovals` → list: request id, secret ref, action
  (get/set/delete), requester token, reason, age.
- Actions: **Approve** (⏎, with Raycast confirmation alert — this is the
  human-confirmation step replacing the CLI's typed `APPROVE <id>`),
  **Deny** (⌃X, confirmation alert), **Copy Receipt** after approving
  (receipts are single-use and action-bound — surface that in the toast),
  **Copy request id**.
- Empty state doubles as a health check ("No pending approvals · daemon ok").

### 4.5 `Audit Log` (view)

- `GetAuditLog` (limit 200, newest first): action, actor, secret ref,
  result, timestamp. Filter dropdown by scope. Action: copy entry JSON.

### 4.6 `Scan Clipboard for Secrets` (no-view)

- Reads clipboard, calls `ScanForSecrets` RPC. HUD: "Clean" or
  "⚠ Contains <ref>:<key>" (ref only — values never shown). Exit path for
  the "am I about to paste a key into Slack?" reflex.

### 4.7 `Hem Menu Bar` (menu-bar, background refresh 5 min)

- Icon: ● black (ok) / ◐ (warning) / ✕ (critical or daemon unreachable),
  badge with pending-approval count when > 0.
- Menu: health one-liner per node, pending approvals (click → open
  Approvals command), "Sync Now", "Open Search Secrets".
- Data: `Health` RPC (cheap, unauthenticated) every refresh;
  `hem cluster health` + `ListPendingApprovals` only when the popover opens
  or on the 5-min tick if last state was non-ok.

## 5. Security posture

- Values are fetched on demand, held only in command memory, rendered
  masked by default, and copied `concealed` with timed clipboard clear.
- No secret value ever goes through: argv, env of child processes, Raycast
  Cache/LocalStorage, logs, or toasts.
- Token preference stored in Raycast's encrypted preferences; file-discovery
  path never copies the token anywhere.
- `archive`/`export` are deliberately **not** exposed (plaintext-on-disk
  footgun / rare enough for the terminal).
- Extension is personal: no store publishing, repo may reference private
  hostnames.

## 6. Failure handling

| Condition | Behavior |
|---|---|
| `Health` unreachable | Every view renders a single actionable empty state: "hemd not reachable at <endpoint>" + copy `launchctl kickstart -k gui/$UID/io.valhall.hemd` |
| `UNAUTHENTICATED` | Empty state naming the token paths searched + open-preferences action |
| `FAILED_PRECONDITION` on read (cluster policy: peer_quorum/master unreachable) | Explain tier ("read blocked by peer-quorum policy; N peers reachable") — do not retry-loop |
| `Pending{request_id}` on read | Show request id + jump to Approvals |
| CLI exit 2 / parse failure | Show raw output in Detail, never crash the list |

## 7. Build & repo layout

```
package.json          raycast extension manifest (commands above)
assets/hem.proto      vendored proto + .rev marker
src/hem/client.ts     grpc wrapper (typed, full surface)
src/hem/cluster.ts    CLI shell-out + parsers (kv, peer_health)
src/hem/token.ts      discovery chain
src/commands/*.tsx    one file per command
```

- TypeScript strict; `@raycast/api`, `@grpc/grpc-js`, `@grpc/proto-loader`,
  `execa`. No native modules (Raycast constraint — grpc-js is pure JS).
- `npm run dev` (raycast develop), `npm run sync-proto`.

## 8. Milestones

1. **M1 — read path**: client.ts + token discovery, Search Secrets with
   copy/inspect, menu bar with Health dot.
2. **M2 — write path**: Add/Edit forms, delete + approval jump, Approvals
   command.
3. **M3 — mesh**: Cluster Status, sync-now, collisions sub-list, menu-bar
   approval badge.
4. **M4 — polish**: Scan Clipboard, Audit Log, clipboard-clear timer,
   `.env` paste import.
