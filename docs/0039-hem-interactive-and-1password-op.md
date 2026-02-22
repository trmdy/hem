# 0039 - Hem Interactive Set + 1Password OP Value Resolution

Date: 2026-02-22  
Status: Active

## What landed

`hem set` now supports:

- `--interactive`: prompt secret values in terminal instead of passing values on command line.
- `op://` value resolution: any `KEY=op://...` value is resolved via `op read` before sending to `hemd`.
- `--from-op-item`: import all non-empty fields from one 1Password item into the target Hem secret.

## Why

- avoids shell-history leakage of raw secret values.
- enables quick import from 1Password CLI without manual copy/paste.

## Usage

```bash
# interactive (hidden value input)
hem set openai-prod --interactive

# interactive with fixed keys (prompts values for each key)
hem set openai-prod api_key org --interactive

# 1Password direct value resolution
hem set openai-prod api_key=op://Personal/openai-prod/api_key
hem set cloudflare-prod \
  token=op://Personal/cloudflare-prod/token \
  zone_id=op://Personal/cloudflare-prod/zone_id

# 1Password whole-item import
hem set openai-prod --from-op-item op://Personal/openai-prod
# optional explicit overrides/additions
hem set openai-prod --from-op-item op://Personal/openai-prod env=prod
```

## Notes

- interactive mode requires a TTY.
- `op://` resolution depends on `op` CLI being installed and authenticated.
- only value is resolved; keys remain explicit on the command.
- whole-item import calls `op item get --format json --reveal`.
