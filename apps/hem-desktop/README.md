# hem-desktop — "Hem Desk"

A keyboard-first macOS desktop app for [Hem](../valhall/crates/hem), the
Valhall secret vault and mesh. Black-on-white, fast, and built for one
operator.

Hem's V1 docs explicitly deferred every UI ("Do NOT build a UI"; approval
surfaces were left to a future *desk*). This is that desk:

- **Vault** — browse/search every secret across `global` / `project/*` /
  `identity/*`, inspect keys, copy values, add and edit without the CLI
- **Mesh** — the live cluster at a glance: per-node health, lag, ledger
  position, checkpoints, quorum risk, collisions
- **Approvals** — the human-confirmation surface for approval-gated reads
  and deletes, with live prompts pushed over the NATS event bus
- **Tokens & Grants** — issue, list, revoke; see who can read what
- **Audit** — filterable activity log
- **⌘K everything** — every object and every action reachable from the
  command palette

## Docs

- [0001 — Product spec](docs/0001-product-spec.md)
- [0002 — Technical architecture](docs/0002-technical-architecture.md)
- [0003 — Claude design prompt](docs/0003-claude-design-prompt.md)

## Status

Spec + design phase. No code yet. Next step: visual design in Claude design
using [docs/0003](docs/0003-claude-design-prompt.md).

## Stack (planned)

Tauri v2 · Rust core (tonic client against `valhall.hem.v1.HemRuntime`) ·
React + TypeScript + TanStack Router/Query · Tailwind. See doc 0002.
