# hem-raycast

Personal Raycast extension for [Hem](../valhall/crates/hem) — the Valhall secret vault daemon.

Hem is powerful but CLI-only. This extension makes the everyday 95% instant:
find a secret, copy a value, add a new one, check the mesh — without leaving
the keyboard or opening a terminal.

- **Search Secrets** — fuzzy-find across all scopes, copy values in two keystrokes
- **Add Secret** — form-based create with slug validation and `.env` paste import
- **Cluster Status** — per-node health, lag, checkpoints, quorum risk
- **Pending Approvals** — approve/deny from Raycast (no TTY dance)
- **Audit Log** — recent vault activity
- **Scan Clipboard** — leak-check clipboard contents before pasting somewhere public
- **Menu bar** — cluster health dot + pending approval count, always visible

See [docs/0001-extension-spec.md](docs/0001-extension-spec.md) for the full spec.

## Status

Spec phase. No code yet.

## Requirements

- Raycast ≥ 1.75, Node 20+ (Raycast-managed runtime)
- A running `hemd` reachable at `http://127.0.0.1:50091` (default)
- Operator token on disk (auto-discovered) or set in extension preferences
