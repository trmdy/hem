# 0003 — Claude design prompts for Hem Desk

Status: v2 · 2026-07-04
v1 ("strict black & white") produced a design that was too high-contrast.
v2 shifts the direction to **soft grayscale, Linear-light-mode / Medusa
style, SaaS dashboard idiom**. Two prompts below:

- **A. Course-correction prompt** — paste into the *existing* design
  session to restyle without redoing layout work.
- **B. Full initial prompt (v2)** — use if starting a fresh session.

---

## A. Course-correction prompt (existing session)

Keep the layouts, screens, information architecture, keyboard-first
behavior, and all the realistic data exactly as they are. Restyle the
visual language only — the current version is too high-contrast and too
black-and-white. Move it to a soft grayscale, modern SaaS dashboard look:
Linear's light mode and medusajs.com are the references — calm, layered,
quietly premium.

Concretely:

- **Kill pure black and pure white pairings.** App canvas `#FAFAFA`,
  content surfaces/cards white `#FFFFFF`, sidebar a slightly deeper layer
  `#F4F5F6`. Primary text is soft charcoal `#26282C`, secondary `#6B7075`,
  muted/tertiary `#9CA1A8`. Nothing is `#000000`.
- **Borders do the separating, softly**: hairline `#E6E8EB` everywhere,
  `#DADDE0` only where structure needs a firmer line. No heavy rules, no
  2px black anything.
- **Depth is allowed but whisper-quiet**: cards are border-only or carry a
  barely-there shadow; popovers and the ⌘K palette get one soft ambient
  shadow (`0 8px 24px rgba(0,0,0,0.07)`), never hard outlines.
- **Focus states soften**: replace black rings/inverted rows with a
  selected-row fill `#EEEFF2` + charcoal text, and a subtle 1.5px
  `#C7CBD1` focus ring with offset on controls. Focus must still be
  instantly findable — do it with fill and weight, not contrast slam.
- **One dark element per screen at most**: the primary action button is
  charcoal `#26282C` with white text; every other button is white with a
  hairline border, or a ghost. This is the SaaS accent — grayscale apps
  live or die on this restraint.
- **Radius up slightly**: 8px cards/panels, 6px controls and inputs.
- **Status dots stay the only color**, but muted: `#3E9B63` / `#D9A514` /
  `#D4614D` at small dot size; their labels stay gray text.
- **Lean into dashboard idiom**: page header bar (title left, primary
  action right), stat tiles on Overview (big number, small gray label),
  proper table styling (uppercase 11px gray column headers, 40px rows,
  hover fill `#F4F5F6`), filter chips, and the node cards on Mesh as clean
  white cards on the gray canvas.
- Keep monospace for secret refs, hashes, node ids, positions — but at
  charcoal, not black, and let the mono sit slightly smaller than body.

The feel to hit: if Linear made a secrets manager. Calm layers of gray,
one charcoal button, color only in five tiny status dots.

---

## B. Full initial prompt (v2) — fresh session

Design **Hem Desk**, a macOS desktop app (single window, ~1280×800
default) for one power user managing his personal secret vault and its
replication mesh. It is the GUI for "hem", a local secrets daemon: ~100
secrets organized in scopes (`global/…`, `project/<project>/…`,
`identity/<id>/…`), each secret holding several key→value pairs,
replicated across a 6-node cluster of his own machines via a signed
append-only ledger.

**Aesthetic: soft grayscale light mode, modern SaaS dashboard.** The
references are Linear's light mode and medusajs.com — layered neutrals,
quietly premium, zero visual noise. Not high-contrast black-on-white:
nothing in the UI is pure black. Token spec:

- Canvas `#FAFAFA` · surfaces/cards `#FFFFFF` · sidebar layer `#F4F5F6`
- Text: primary charcoal `#26282C`, secondary `#6B7075`, muted `#9CA1A8`
- Borders: hairline `#E6E8EB`, firm `#DADDE0` — borders separate, never
  heavy rules
- Hover fill `#F4F5F6`, selected fill `#EEEFF2`, focus ring 1.5px
  `#C7CBD1` with offset
- Exactly one dark element per screen: the primary button, charcoal
  `#26282C` with white text; all other buttons are white + hairline
  border, or ghosts
- Shadows whisper: cards border-only or barely-there; popovers/palette
  `0 8px 24px rgba(0,0,0,0.07)`
- Radius 8px panels/cards, 6px controls · type: crisp grotesque
  (Inter/Geist) for UI, monospace for secret refs, hashes, node ids,
  ledger positions (charcoal, slightly smaller than body)
- **The only color in the app**: small muted status dots — `#3E9B63` ok /
  `#D9A514` warning / `#D4614D` critical; labels stay gray text

Dashboard idiom throughout: left sidebar nav (⌘1–⌘6: Overview, Vault,
Mesh, Approvals, Tokens & Grants, Audit), page header bar with title left
and the single primary action right, stat tiles with big numbers and
small gray labels, tables with uppercase 11px gray column headers and
40px hover-fill rows, filter chips.

**The defining trait is keyboard-first UX.** Design as if the mouse
doesn't exist, then let it work anyway:

- A **⌘K command palette** is the app's centerpiece — it finds *objects*
  (secrets, nodes, pending approvals, tokens) and *actions* ("New
  secret", "Sync mesh now", "Copy health report") in one input. Design
  its empty, typed, and mixed-result states. From the palette, a secret's
  value can be copied directly (⌘⏎) — the two-keystroke happy path.
- Visible shortcut hints everywhere: buttons show their key, focused list
  rows show ⏎ / ⌘C / ⌘R affordances, a quiet shortcut hint line lives at
  the bottom edge.
- Focus is the cursor of this app: selected-fill rows and the soft focus
  ring must make it findable at a glance, using fill and weight rather
  than contrast.

**Screens to design (in priority order):**

1. **Vault** — master-detail. Left: filterable list (`/` to filter) of
   secrets sectioned by scope, rows show name, dim description, group
   tag, relative updated time. Right: secret detail — mono ref header,
   meta line (scope badge, group, "requires approval" badge,
   created/updated), then a **keys table**: key name + masked value
   (`••••••7f2a`) with per-row copy and reveal; revealed values
   auto-remask. Below: grants list and a compact version-history timeline
   (version, author node, time). Include the **New Secret** form as an
   overlay: scope picker, live-validated slug name, dynamic key/value
   rows, paste-a-.env import affordance.
2. **Mesh** — the cluster in one glance. Header strip: cluster id (mono),
   health word (OK / WARNING / CRITICAL) with its status dot, ledger
   position, checkpoint state ("quorum met, 1 cosignature"), collisions
   count. Then a **grid of 6 white node cards** on the gray canvas: node
   id (mono, e.g. `hmn_main`, `hmn_alder01`, `hmn_elm05`),
   endpoint, status (caught_up / lagging / offline), cursor position, lag
   in operations, last-seen. Show the realistic state: 4 nodes caught up
   at position 7856, the local node, and one node lagging 6541 ops
   behind, last seen a month ago — scannable in under two seconds without
   screaming.
3. **Overview** — calm home: stat tiles (secrets per scope, pending
   approvals, mesh health), daemon card (running, version, endpoint),
   mesh summary card, recent activity table.
4. **Approvals** — pending requests table (request id, action get/delete,
   secret ref, requester, reason, age) with Approve/Deny as deliberate
   confirm interactions; an approved state presenting a one-time receipt
   (mono, copy-once feel). The empty state should feel like good news.
5. **Command palette** over any screen (design it over Vault).

**Interaction character:** instant, dense but never cramped, zero
decorative animation — only functional motion (focus movement, palette
open ≤120ms, reveal/remask). Empty and error states are written in plain
first-person-tool language ("hemd isn't reachable at 127.0.0.1:50091 —
copy restart command") and always include the next action. Destructive
actions (delete, revoke, deny) confirm inline with the target named,
never a vague "Are you sure?".

Use realistic data everywhere: secret names like `anthropic-api-key`,
`fiken-oauth`, `project/acme/openai-prod`, `identity/vis-7f31/github`;
keys like `api_key`, `client_secret`; timestamps this week; the node
names above. No lorem ipsum, no placeholder gray boxes.

Deliver: the five screens at 1280×800, plus focus-state, masked/revealed,
and confirm-step component details as callouts.

---

## Notes for iterating

- If the grayscale reads flat, the fix is *more layer separation*
  (canvas vs. card vs. sidebar), not more contrast in text or borders.
- Watch the Vault list at 96+ secrets in `global` — it needs sub-grouping
  or a tighter row (32–36px in this idiom) before it needs pagination.
- The palette's mixed object+action results need a clear type affordance
  (small-caps gray label vs. icon) — first pass tends to blur them.
- Verify the "one dark element per screen" rule survived: if two charcoal
  buttons appear on one screen, demote one to secondary.
- Status dots: check them against the gray ramp for color-blind
  legibility — pair each with its status word, never dot-only.
