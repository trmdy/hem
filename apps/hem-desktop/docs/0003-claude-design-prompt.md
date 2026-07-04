# 0003 — Initial prompt for Claude design

Status: v1 · 2026-07-04
Paste the block below into Claude design as the opening prompt for the
Hem Desk visual design. It is self-contained on purpose — the design
session has no access to our repos.

---

Design **Hem Desk**, a macOS desktop app (single window, ~1280×800 default)
for one power user managing his personal secret vault and its replication
mesh. It is the GUI for "hem", a local secrets daemon: ~100 secrets
organized in scopes (`global/…`, `project/<project>/…`, `identity/<id>/…`),
each secret holding several key→value pairs, replicated across a 6-node
cluster of his own machines via a signed append-only ledger.

**Aesthetic: strict black & white, light mode.** White background, black
ink, a disciplined gray ramp for hierarchy — and *no other color anywhere*,
with one single exception: node/cluster health may use small semantic dots
(green/amber/red); everything else conveys state through weight, fill vs.
outline, and typography. Modern, sharp, editorial: think Linear's density
and calm, Vercel's monochrome confidence, a Braun-instrument sense of
order. Hairline 1px borders, generous whitespace between dense clusters of
information, almost no shadows, no gradients, no glassmorphism. Type: a
crisp grotesque (e.g. Inter/Geist) for UI, and a monospace face doing real
work — secret refs like `project/globex/linear`, hashes, node ids, and
positions are always mono. Corners barely rounded (≤6px). It should feel
like a precision tool, not a dashboard product.

**The defining trait is keyboard-first UX.** Design as if the mouse
doesn't exist, then let it work anyway:

- A **⌘K command palette** is the app's centerpiece — it finds *objects*
  (secrets, nodes, pending approvals, tokens) and *actions* ("New secret",
  "Sync mesh now", "Copy health report") in one input. Design its empty,
  typed, and mixed-result states. From the palette, a secret's value can
  be copied directly (⌘⏎) — the two-keystroke happy path.
- Visible shortcut hints everywhere: every button shows its key, list rows
  show ⏎ / ⌘C / ⌘R affordances on focus, a persistent but quiet shortcut
  hint line lives at the bottom edge.
- Strong, unmistakable **focus states** (2px black ring or inverted row) —
  focus is the cursor of this app, design it as a first-class element.
- Sidebar nav with ⌘1–⌘6: Overview, Vault, Mesh, Approvals, Tokens &
  Grants, Audit.

**Screens to design (in priority order):**

1. **Vault** — master-detail. Left: filterable list (`/` to filter) of
   secrets sectioned by scope, rows show name, dim description, group tag,
   relative updated time. Right: secret detail — big mono ref header, meta
   line (scope badge, group, "requires approval" badge, created/updated),
   then a **keys table**: key name + masked value (`••••••7f2a`) with
   per-row copy and reveal; revealed values auto-remask. Below: grants
   list and a compact version-history timeline (version, author node,
   time). Include the **New Secret** form as an overlay or inline panel:
   scope picker, live-validated slug name, dynamic key/value rows, paste-a-
   .env import affordance.
2. **Mesh** — the cluster in one glance. Header strip: cluster id (mono),
   health word (OK / WARNING / CRITICAL), ledger position, checkpoint
   state ("quorum met, 1 cosignature"), collisions count. Then a **grid of
   6 node cards**: node id (mono, e.g. `hmn_main`, `hmn_alder01`,
   `hmn_elm05`), endpoint, status (caught_up / lagging / offline),
   cursor position, lag in operations, last-seen. Show the realistic state:
   4 nodes caught up at position 7856, the local node, and one node
   lagging 6541 ops behind, last seen a month ago — the design must make
   that scannable in under two seconds without screaming.
3. **Overview** — calm home: daemon card (running, version, endpoint),
   mesh summary card, approvals card (pending count or quiet ✓), recent
   activity list, vault stats per scope.
4. **Approvals** — pending requests list (request id, action get/delete,
   secret ref, requester, reason, age) with Approve/Deny as deliberate
   confirm interactions; an approved state that presents a one-time
   receipt (mono, copy-once feel). Design the empty state to feel like
   good news.
5. **Command palette** over any screen (design it over Vault).

**Interaction character:** instant, dense but never cramped, zero
decorative animation — only functional motion (focus movement, palette
open ≤120ms, reveal/remask). Empty and error states are written in plain
first-person-tool language ("hemd isn't reachable at 127.0.0.1:50091 —
copy restart command") and always include the next action. Destructive
actions (delete, revoke, deny) confirm inline with the target named, never
with a vague "Are you sure?".

Use realistic data everywhere: secret names like `anthropic-api-key`,
`fiken-oauth`, `project/acme/openai-prod`, `identity/vis-7f31/github`;
keys like `api_key`, `client_secret`; timestamps this week; the node
names above. No lorem ipsum, no placeholder gray boxes.

Deliver: the five screens at 1280×800, plus the focus-state, masked/
revealed, and confirm-step component details as callouts.

---

## Notes for iterating after the first pass

- If the monochrome + green/amber/red exception feels off, try pure B/W:
  status as ●/◐/○ glyph fills — decide by comparing the Mesh screen both
  ways.
- Watch the Vault list at 96+ secrets in `global` — it needs sub-grouping
  or a tighter row (24–28px) before it needs pagination.
- The palette's mixed object+action results need a clear type affordance
  (small caps label vs. icon) — first pass tends to blur them.
- Ask for the keyboard-hint bottom edge in both "quiet" and "learning"
  densities.
