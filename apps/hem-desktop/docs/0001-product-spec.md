# 0001 — Hem Desk Product Spec

Status: draft v1 · 2026-07-04
Audience: single operator (Tormod). One machine class (macOS), one daemon
per machine, one live 6-node mesh.

## 1. Problem

Hem stores ~100 secrets across three scopes and replicates them over a
6-node ledger mesh — and the only window into all of it is a CLI with
mostly non-JSON output. Routine questions are expensive:

- "What's in `project/acme/*` again?" → terminal, search, squint.
- "Is the mesh healthy?" → `hem cluster health`, read 40 key=value lines.
- "Approve this delete" → a TTY ritual (`APPROVE <request-id>` typed back).
- "Add the new Fiken creds properly (right scope, group, description)" →
  flag archaeology.

The V1 design intentionally deferred all UI to a future "desk" surface.
Hem Desk is that surface.

## 2. Product principles

1. **Keyboard is the interface.** Every navigation and every action has a
   shortcut; ⌘K reaches anything. The mouse is optional, never required.
2. **Read fast, write deliberately.** Browsing/metadata is instant and
   ambient; revealing values, writing, approving, deleting are explicit,
   confirmed, and audited.
3. **The daemon is the truth.** No local secret cache, no shadow state. The
   app renders what `hemd` + the local cluster files say right now.
4. **Calm status.** The mesh view is a steady-state dashboard, not an
   alarm panel — a lagging node (hello, elm05) is information, not a
   modal.
5. **One user, full trust, least ceremony.** Operator token, no login
   screens, no multi-tenant abstractions.

## 3. Information architecture

Six primary views, one palette:

```
⌘1 Overview   ⌘2 Vault   ⌘3 Mesh   ⌘4 Approvals   ⌘5 Tokens & Grants   ⌘6 Audit
                              ⌘K  Command palette
```

### 3.1 Overview (home)

A single screen that answers "is everything fine and what happened lately":

- Daemon card: reachable?, version, endpoint, data dir.
- Mesh card: health status (ok/warning/critical), healthy/lagging/offline
  node counts, ledger position, checkpoint status, quorum risk, collisions.
- Approvals card: pending count (deep-links to ⌘4); zero-state is a quiet ✓.
- Recent activity: last ~15 audit entries.
- Vault stats: secret counts per scope, most recently updated secrets.

### 3.2 Vault

Master-detail. Left: every secret, sectioned by scope, with instant fuzzy
filter (`/` focuses it). Right: the selected secret.

List row: `name` · description (dim) · group tag · relative updated-at.
Sections: `global` (96 live today), `project/<p>` grouped per project,
`identity/<id>`.

Detail pane:
- Header: full ref (mono, click/⌘⇧C to copy), scope badge,
  requires-approval badge, group, description, created/updated/last-access.
- **Keys table**: key name + masked value (`••••7f2a`). Per-row: copy
  (⌘C, concealed + timed clipboard clear), reveal (⌘R, auto-remask after
  30 s), copy `hem get <ref> <key>` command.
- Grants section: grantee list with revoke; "grant access…" action.
- History section (cluster mode): value versions from the ledger
  (`version_seq`, author node, timestamp) — metadata only.
- Per-secret audit tail (last 10 events touching this ref).

Actions: **New secret** (⌘N — form with scope picker, live slug
validation, dynamic key/value rows, `.env` paste-import), **Edit** (⌘E),
**Delete** (⌃⌫ — runs the server-side approval flow: shows the created
`request_id`, jumps to Approvals; the approve step is always a separate,
deliberate act).

### 3.3 Mesh

The view that doesn't exist anywhere today, not even in the CLI as one
picture.

- **Cluster header**: cluster id, epoch/fork, quorum config vs. reality
  (`quorum_risk`), latest position + body hash (mono, truncated,
  copyable), checkpoint status + cosignature count, sync errors.
- **Node grid**: one card per node (local first): node id, endpoint,
  status (caught_up / lagging / offline / divergent / unknown), cursor
  position, **lag in ops**, last-seen relative time. A lagging node shows
  its drift trend since the app opened.
- **Collisions panel**: unresolved write collisions with both branches'
  metadata; resolution intentionally copies a ready-made
  `hem cluster resolve-collision …` command rather than one-click resolve
  (matches the runbook's "don't auto-repair" stance).
- Actions: Sync now (`--once`), Refresh, Copy full health report,
  per-node "Copy endpoint" / "Copy diagnosis" (node id, lag, last error).

Non-goals here: install/rebuild/fork/replay-fork/migrate — those are
break-glass runbook operations and stay in the terminal on purpose.

### 3.4 Approvals

The canonical human-confirmation surface (replaces the CLI's typed
`APPROVE <id>` ritual).

- Pending list: request id, action (get/set/delete — receipts are
  action-bound), secret ref, requester token identity, reason, age.
- **Live**: new requests arrive via the `hem.approval.requested` NATS
  event → app badge + optional macOS notification with "Review…" button.
- Approve (⏎) / Deny (⌫), each with an explicit confirm step that names
  the action and ref. After approving: receipt shown once, copyable,
  labeled "single-use, action-bound".
- Resolved tail (last 20) for context.

### 3.5 Tokens & Grants

- Active tokens table: type (operator/service/agent-run), id,
  service/identity, scopes, issued/expires, with **Revoke**.
- Issue service token / agent token forms (TTL presets; agent capped 24 h).
- Grants browser: by secret or by grantee; grant/revoke inline.

### 3.6 Audit

- Filterable table (scope, action, actor, time range, free text), newest
  first, infinite scroll over `GetAuditLog` pagination.
- Row → detail drawer with full entry; copy as JSON.

### 3.7 Command palette (⌘K)

Two result classes, one input:
- **Objects**: secrets (by name/description/group), nodes, tokens, pending
  approvals → ⏎ jumps to them; secrets support "copy primary value"
  directly from the palette (⌘⏎) for true two-keystroke retrieval.
- **Actions**: every app action ("New secret", "Sync mesh now", "Reveal
  values", "Copy health report", "Issue service token…"), fuzzy-matched
  with shortcut hints displayed.

## 4. Keyboard model

- ⌘1–⌘6 views · ⌘K palette · `/` filter · ↑↓/jk list nav · ⏎ open/primary
- ⌘C copy value (in context) · ⌘⇧C copy ref · ⌘R reveal · Esc back/dismiss
- ⌘N new secret (global) · g then v/m/a/t/l go-to chords (vim-style)
- Every button in the UI renders its shortcut; anything clickable is
  palette-findable.

## 5. Trust & safety behaviors

- Values: fetched on demand, masked by default, reveal auto-expires,
  clipboard copies are concealed (`org.nspasteboard.ConcealedType`) and
  cleared after 90 s (configurable).
- No secret value in: logs, window title, crash reports, renderer
  persistence, or any file this app writes.
- Destructive paths (delete, revoke, deny, rotate) always confirm and name
  the target; delete additionally rides Hem's server-side approval flow.
- The app never edits cluster files, never runs fork/replay/migrate, and
  respects read-policy failures (`peer_quorum` unreachable ⇒ explain, not
  retry-storm).
- App itself is offline-tolerant: daemon-unreachable renders one honest
  empty state per view with the launchctl restart command copyable.

## 6. Out of scope (v1)

- Multi-user, roles, remote daemons over the network (localhost only).
- Editing read-policy tiers / leases (CLI).
- 1Password import (CLI `--from-op-item` exists; revisit later).
- Windows/Linux builds (architecture keeps the door open; macOS first).
- Master-biometric approval adapter UX (daemon-side wiring isn't complete;
  design leaves a slot for it).

## 7. Success criteria

- Find-and-copy any secret in < 3 s / ≤ 4 keystrokes from app focus.
- Add a well-formed secret (scope, group, description) in < 30 s.
- Mesh state comprehensible in one glance; lagging node identifiable in
  < 2 s.
- Approve a pending request in ≤ 3 deliberate interactions.
- Zero secret values at rest anywhere outside hemd.
