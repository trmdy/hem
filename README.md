# Hem

Hem is an agent-first secret vault. A local daemon (`hemd`) keeps secrets encrypted on disk and serves them over gRPC. The `hem` CLI, a TypeScript SDK, a desktop app (Hem Desk) and a Raycast extension talk to it. Reads can require human approval, every access is audited, and several machines can run `hemd` as a replicated cluster.

Hem was extracted from the [vlhl/valhall](https://github.com/vlhl/valhall) monorepo (commit `063bf7b`) with its git history. Hem Desk and the Raycast extension were merged in from their own repositories, also with history.

## Layout

| Path | What |
|---|---|
| `crates/hem` | `hem` CLI |
| `crates/hemd` | `hemd` daemon (gRPC server) |
| `crates/hem-core` | Vault library: store, crypto, tokens, approvals, audit, ledger, cluster |
| `crates/hem-client` | Rust gRPC client for `hemd` |
| `crates/hem-config` | IDs and shared config helpers (was `valhall-config`) |
| `crates/hem-events` | Event envelope types (was `valhall-events`) |
| `crates/hem-net` | NATS and gRPC mesh networking (was `valhall-net`) |
| `proto/valhall/hem/v1/hem.proto` | gRPC API (package `valhall.hem.v1`) |
| `sdk/ts` | TypeScript SDK (`@valhall/hem-sdk`) |
| `apps/hem-desktop` | Hem Desk, Electron desktop app |
| `apps/hem-raycast` | Raycast extension |
| `scripts/` | Cluster smoke, watchdog and peer-proxy scripts |
| `docs/` | Design notes and runbooks |

Only the Rust crate names changed in the extraction. Runtime names are unchanged so existing installs keep working: the `~/.valhall/...` paths, `VALHALL_*` and `HEM_*` environment variables, the `valhall.hem.v1` proto package, the `io.valhall.hemd` launchd label and the token formats.

## Build and install

Requires a stable Rust toolchain. `protoc` is vendored.

```bash
cargo build --workspace
cargo test --workspace
cargo install --path crates/hem
cargo install --path crates/hemd
```

TypeScript parts:

```bash
(cd sdk/ts && npm ci && npm run build)
(cd apps/hem-desktop && npm ci && npm run build)
(cd apps/hem-raycast && npm ci && npm run build)
```

## Running hemd

```bash
hemd --bind 127.0.0.1:50091 --data-dir ~/.valhall/hem
hem init
hem health
hem examples
```

- Data dir: `--data-dir`, else `HEM_DATA_DIR`, else `~/.valhall/hem`. The launchd install on Tormod's machines uses `~/.valhall/system-daemons/data/hem`.
- CLI endpoint: `--endpoint` or `VALHALL_HEMD_ENDPOINT` (default `http://127.0.0.1:50091`).
- CLI auth: `--token` or `VALHALL_HEM_TOKEN`, falling back to `operator.token` in the data dir.
- On macOS `hemd` usually runs under launchd as `io.valhall.hemd`; restart it with `launchctl kickstart -k gui/$UID/io.valhall.hemd`.

Hem Desk and the Raycast extension call the `hem` CLI at `~/.valhall/system-daemons/bin/hem` by default (Hem Desk: `HEM_DESK_BINARY`; Raycast: the "Hem Binary" preference).

Multi-machine setup is covered in `docs/1020-hem-multi-machine-deployment-runbook.md`.
