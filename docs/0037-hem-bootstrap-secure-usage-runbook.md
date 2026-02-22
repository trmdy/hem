# 0037 - Hem Secure Bootstrap Usage Runbook

Date: 2026-02-21  
Status: Active

## Purpose

Operator runbook for secure first-use of Hem with `hemd` + `hem`.

Covers:
- bootstrap
- token issuance
- scoped grants
- approval workflow
- audit checks

## 1) Start and initialize

```bash
# start local daemon (default endpoint http://127.0.0.1:50091)
hemd --bind 127.0.0.1:50091 --data-dir ~/.valhall/hem

# initialize master key + operator token (one-time)
hem init
```

Expected:
- `~/.valhall/hem/master.key` mode `0600`
- `~/.valhall/hem/operator.token` mode `0600`

## 2) Store baseline secrets

```bash
# global secret
hem set openai-prod api_key=... organization=...
# interactive mode to avoid shell history leaks
hem set openai-prod --interactive
# 1Password reference via op CLI
hem set openai-prod api_key=op://Personal/openai-prod/api_key

# project secret
hem set project/acme/cloudflare-prod token=...

# identity secret
hem set identity/agent-123/github token=...
```

## 3) Issue runtime tokens

```bash
# service token (for smi/smid)
hem token issue-service smi

# agent token (scoped)
hem token issue-agent \
  --identity-id agent-123 \
  --project acme \
  --scopes global,project,identity
```

## 4) Add explicit grant (cross-scope)

Example: allow service `smi` to read one project secret.

```bash
hem grant-access \
  project/acme/cloudflare-prod \
  --grantee-scope global \
  --grantee-id smi
```

Check:

```bash
hem list-grants project/acme/cloudflare-prod
```

## 5) Approval-controlled reads/writes

Mark a secret approval-required:

```bash
hem set openai-prod api_key=... --requires-approval
```

Read flow:

```bash
# requester gets pending request id
hem get openai-prod

# operator resolves (interactive human confirm)
hem approvals
hem approve <request-id>

# requester retries with receipt
hem get openai-prod --approval-receipt <receipt>
```

Notes:
- approval receipts are single-use
- receipts are action-bound (`get_secret` != `set_secret` != `delete_secret`)

## 6) Audit checks

```bash
hem audit --limit 200
hem audit --scope project/acme --since 2026-02-21T00:00:00Z
```

Verify expected records exist for:
- `set_secret`, `get_secret`, `delete_secret`
- `grant_access`, `revoke_access`
- pending/approved/denied approval actions

## 7) Rotation and hygiene

- keep operator token local-only; do not commit or paste in logs.
- use service/agent tokens for automation; revoke when unused:

```bash
hem token list
hem token revoke <token-id>
```

- rotate master key during maintenance window when rotation RPC lands.

## 8) Minimal production defaults (local single-node)

- daemon bind: `127.0.0.1` only.
- data dir permissions restricted to owner.
- all automation uses least-privilege service/agent tokens.
- destructive approvals require interactive `hem approve` / `hem deny` confirmation.
