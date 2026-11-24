# hem-raycast

Personal Raycast extension for [Hem](../../crates/hem) — the Valhall secret vault daemon.

Hem is powerful but CLI-only. This extension makes the everyday 95% instant:
find a secret, copy a value, add a new one, check the mesh — without leaving
the keyboard or opening a terminal.

- **Search Secrets** — fuzzy-find across all scopes, copy values in two keystrokes
- **Add Secret** — form-based create with slug validation and `.env` paste import
- **Cluster Status** — per-node health, lag, checkpoints, quorum risk
- **Pending Approvals** — approve/deny from Raycast (no TTY dance)
- **Audit Log** — recent vault activity
- **Scan Clipboard** — leak-check clipboard contents before pasting somewhere public

The extension has no background command. Expensive cluster-health verification
runs only when **Cluster Status** is opened explicitly.

See [docs/0001-extension-spec.md](docs/0001-extension-spec.md) for the spec and
[docs/0002-implementation-report.md](docs/0002-implementation-report.md) for
implementation status, judgment calls, and known issues.

## Requirements

- Raycast ≥ 1.75, Node 20+ (`ray` CLI ships with `@raycast/api`)
- A running `hemd` reachable at `http://127.0.0.1:50091` (default)
- Operator token on disk (auto-discovered) or set in extension preferences
- `hem` CLI at `~/.valhall/system-daemons/bin/hem` (configurable) for the
  cluster commands

## Install (manual import — this extension is not in the store)

1. `cd` into this repo and run `npm install`.
2. Run `npm run dev`. This starts `ray develop`, which builds the extension
   and imports it into your local Raycast under **Development** — Raycast
   opens automatically and the six commands become searchable immediately.
3. Once you see the commands, you can stop the dev server (Ctrl-C); the
   extension stays imported. Re-run `npm run dev` after code changes.
4. Alternatively: open Raycast → search "Import Extension" → select this
   repo's directory.

### Preferences

| Preference | Default | Purpose |
|---|---|---|
| Daemon Endpoint | `http://127.0.0.1:50091` | hemd gRPC target |
| Operator Token | _(empty)_ | empty ⇒ auto-discover from the standard token files |
| Hem Binary | `~/.valhall/system-daemons/bin/hem` | cluster commands only |
| Clipboard Clear (Seconds) | `90` | timed clear for copied values, `0` disables |
| Primary Key Guess | `api_key,token,key,password,secret` | ordered candidates for Copy Primary Value |

## Development

```sh
npm run build            # ray build (type-checks + bundles)
npm run lint             # eslint + prettier + tsc (see report §lint note)
npm test                 # vitest unit tests (parsers, token discovery, refs, .env)
npm run test:integration # boots an ISOLATED hemd on 127.0.0.1:59091, exercises
                         # the client end to end (init → set → get → delete →
                         # approval → receipt retry), tears down
npm run sync-proto       # re-copy hem.proto from the repo root proto/ + record git rev
```

The integration suite never touches the production daemon on port 50091; it
spawns its own `hemd` with a throwaway data dir and kills it afterwards.

## Security posture

- Secret values are fetched on demand, kept in command memory only, rendered
  masked, and copied with `concealed: true` plus a timed clipboard clear.
- Values never pass through argv, child-process env, Raycast Cache/LocalStorage,
  logs, or toasts. Only listing metadata is cached.
- `archive`/`export` are deliberately not exposed.
