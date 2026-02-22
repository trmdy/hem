# 0041 - Hem Admin Ops + Service Secret Wiring

Date: 2026-02-22
Status: Active

## What landed

### 1) `hemd` admin RPCs now implemented

- `RotateMasterKey`
- `ExportSecrets`
- `ImportSecrets`

Implemented in:

- `crates/hemd/src/main.rs`
- `crates/hem-core/src/store.rs`

### 2) `hem` CLI admin commands now available

- `hem export [--scope ...] [-o <path>]`
- `hem import -i <path> [--merge]`
- `hem rotate [--actor ...]`

Implemented in:

- `crates/hem/src/main.rs`
- `crates/hem/README.md`

### 3) Service-side Hem key resolution added

- `smi-core` API harness:
  - optional Hem lookup from profile env key `SMI_HEM_API_KEY_SECRET`
  - fallback keeps existing env behavior
- `vis-core` config:
  - new config/env `openai_api_key_secret` / `VALHALL_VIS_OPENAI_API_KEY_SECRET`
  - resolves via `hem get <secret> api_key` when explicit key missing

Implemented in:

- `crates/smi-core/src/harness/mod.rs`
- `crates/smi-core/src/harness/providers.rs`
- `crates/vis-core/src/model.rs`

## Notes

- export/import bundle now accepts any `master_key_id` present in local keyset (not only current primary).
- `--merge` import mode skips existing target secrets.
- rotate is crash-safe:
  - `master.key` stores a keyset (`primary_key_id` + retained prior keys),
  - rotation writes a journal (`rotation/master-key-rotation.json`),
  - startup auto-recovers incomplete rotations and finalizes safely.
- `hemd` refreshes local `operator.token` after rotate to keep CLI fallback usable.

## Quick usage

```bash
# backup
hem export -o /tmp/hem-export.bin

# restore (skip existing)
hem import -i /tmp/hem-export.bin --merge

# rotate key
hem rotate
```

`smi` profile example:

```toml
[[profile]]
name = "api1"
harness = "api"
provider = "openai"
model = "gpt-4.1"

[profile.env]
SMI_HEM_API_KEY_SECRET = "global/openai-prod"
```

`vis` config/env example:

```toml
openai_api_key_secret = "global/openai-prod"
```
