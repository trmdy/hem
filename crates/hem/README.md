# hem

CLI for the Hem secret-management daemon (`hemd`).

## Secret reference formats

- `<name>` -> global scope (`global/<name>`)
- `global/<name>`
- `project/<project>/<name>`
- `identity/<identity_id>/<name>`

Secret names are lowercase slug format: `a-z`, `0-9`, `-`.

## Auth token resolution

`hem` sends `authorization: Bearer <token>` to `hemd` using this order:

1. `--token <token>`
2. `VALHALL_HEM_TOKEN`
3. `$HEM_DATA_DIR/operator.token`
4. `~/.valhall/hem/operator.token`
5. `~/.valhall/system-daemons/data/hem/operator.token`

## Quick usage

```bash
# health / endpoint
hem health
hem --endpoint http://127.0.0.1:50091 health

# create/update
hem set openai-prod api_key=... model=gpt-4.1
hem set project/acme/cloudflare token=...
# hidden input (no secret values in shell history)
hem set openai-prod --interactive
# resolve directly from 1Password reference via op CLI
hem set openai-prod api_key=op://Personal/openai-prod/api_key
# import all non-empty fields from a 1Password item
hem set openai-prod --from-op-item op://Personal/openai-prod
# when write requires approval
hem set openai-prod api_key=... --approval-receipt <receipt>

# read
hem get openai-prod
hem get project/acme/cloudflare token   # prints raw value only
# when read requires approval
hem get openai-prod --approval-receipt <receipt>

# scan stdin for leaked secret values
echo "text to check" | hem scan
echo "text to check" | hem scan --quiet
echo "text to check" | hem scan --scope project/acme --json

# search (quote wildcards)
hem search openai
hem search 'project/*/openai-*'
# aliases
hem list 'project/*/openai-*'
hem ls 'project/*/openai-*'
# ls with default wildcard query
hem ls

# machine-readable command examples for agents
hem examples
hem examples --format json | jq .
hem examples --format shell

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

# admin bundle + rotation
hem export -o /tmp/hem-export.bin
hem import -i /tmp/hem-export.bin --merge
hem rotate

# archive
hem archive global/openai-prod
hem archive project/acme/cloudflare -o /tmp/cloudflare.json
```

## Delete approval flow

```bash
hem delete global/openai-prod
hem approvals
hem approve <request-id>                       # interactive human confirmation
hem delete global/openai-prod --approval-receipt <receipt>
```

`hem approve` and `hem deny` require an interactive terminal and typed confirmation.
Legacy aliases remain: `hem approve-delete`, `hem deny-delete`.

`hem search/list/ls` uses colorized output on interactive terminals. Set `NO_COLOR=1` to disable.
