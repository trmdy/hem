# Hem CLI Agent Usage Clarification

Date: 2026-02-21  
Status: Active

## Why this doc

Agents hit avoidable friction using `hem`:
- unclear secret reference scope formats
- wildcard search usage unclear (`*`, `?`, shell quoting)
- delete workflow unclear after approval hardening

This doc captures the canonical command patterns.

## Canonical secret reference formats

- `<name>` -> global scope (`global/<name>`)
- `global/<name>`
- `project/<project>/<name>`
- `identity/<identity_id>/<name>`

If you pass an unknown scope prefix (example: `tmp/foo`), `hem` now returns actionable guidance with accepted formats.

## Common workflows

```bash
# examples payload for agents (machine-readable default)
hem examples
hem examples --format json | jq .
hem examples --format shell

# set
hem set openai-prod api_key=... model=gpt-4.1
hem set project/acme/cloudflare token=...
# hidden input mode (no secret values in shell history)
hem set openai-prod --interactive
# resolve value from 1Password CLI reference
hem set openai-prod api_key=op://Personal/openai-prod/api_key
# if write requires approval:
hem set openai-prod api_key=... --approval-receipt <receipt>

# get
hem get openai-prod
hem get project/acme/cloudflare token
# if read requires approval:
hem get openai-prod --approval-receipt <receipt>

# search (quote wildcards)
hem search openai
hem search 'project/*/openai-*'
hem search 'identity/*/github'
hem list 'project/*/openai-*'
hem ls 'project/*/openai-*'

# token lifecycle
hem token issue-service smi
hem token issue-agent --identity-id agent-123 --project acme --scopes global,project,identity
hem token list --token-type service
hem token revoke <token-id>

# grants
hem grant-access project/acme/cloudflare --grantee-scope global --grantee-id smi
hem list-grants project/acme/cloudflare
hem revoke-access project/acme/cloudflare --grantee-scope global --grantee-id smi

# audit
hem audit --limit 100
hem audit --scope project/acme --since 2026-02-21T00:00:00Z

# archive
hem archive global/openai-prod

# delete (server-enforced approval)
hem delete global/openai-prod
hem approvals
hem approve <request-id>
hem delete global/openai-prod --approval-receipt <receipt>
```

`hem approve` and `hem deny` require interactive human confirmation.  
Legacy aliases remain: `hem approve-delete`, `hem deny-delete`.

## Token resolution order

`hem` resolves bearer token in this order:

1. `--token <token>`
2. `VALHALL_HEM_TOKEN`
3. `$HEM_DATA_DIR/operator.token`
4. `~/.valhall/hem/operator.token`
5. `~/.valhall/system-daemons/data/hem/operator.token`

## Related files

- `crates/hem/src/main.rs`
- `crates/hem/README.md`
