# 1022 — Hem audit attribution

Status: accepted design, phased rollout
Scope: hemd, hem CLI, hem-client, @valhall/hem-sdk, SMI/Hive, external clients (Hem Desktop, Hermes MCP)

## Problem

Audit rows (`audit/entries.jsonl`) record `get_secret` with `actor = token:<token_id>`.
Because most consumers share one broad operator token, a row cannot answer *who*
actually read a secret: Hem Desktop, Hermes MCP, Hive/Honeybee, Claude Code, Codex,
a shell script, or a remote peer. The `global/ahrefs` read loop (Hem Desktop
invalidation bug) took log archaeology to attribute; it should have been one grep.

## Current state (verified in code)

- `AuditEntry { audit_id, ts, action, actor, token_id, secret_scope, secret_name, result, details }`
  (`crates/hem-core/src/model.rs`). Written by `HemRuntimeService::audit()`
  (`crates/hemd/src/main.rs`), which receives only a `CallerPrincipal`.
- `actor` is literally `format!("token:{token_id}")` — redundant with `token_id`.
- `TokenClaims` already carries verified `token_type` (Operator/Service/AgentRun),
  `service_name`, `identity_id`, `project`, `issued_by` — none of it is written to audit.
- Transport is plain tonic gRPC on loopback TCP `127.0.0.1:50091`. No TLS, no UDS,
  no interceptor. Nothing reads `remote_addr()` or the `user-agent` header.
- No client sends any identity metadata; the only header is `authorization`.
  Clients: hem CLI, hem-client (verk, dued, vis-core, smi-core), hjuld bridge,
  TS SDK; Hem Desktop and Hermes MCP live outside this repo.
- Cluster peer RPCs are Ed25519-signed (`x-hem-peer-*`) and read receipts carry
  `requester`/`token_id`, but not the original client identity.
- Audit does not record which `key` was read even though `req.key` is in scope.

## Trust tiers

Every attribution field belongs to a tier; the schema keeps tiers structurally
separate so a self-reported string is never mistaken for proof.

1. **Cryptographic** — verified token claims, peer Ed25519 signatures.
2. **Kernel-verified** — UDS peer credentials (`getpeereid`, `LOCAL_PEERPID` → `proc_pidpath`).
3. **Self-reported** — `x-hem-client-*` headers, CLI-collected fingerprint, `HEM_CALLER`.
4. **Forensic** — `lsof`/timestamp correlation. Never in the product path.

Threat model: *well-behaved but anonymous automation*, not a hostile same-user
process (which can read the operator token file anyway). This is attribution
hygiene plus least-privilege, not adversarial security.

## Audit schema v2

New fields are optional / `serde(default)` so existing v1 JSONL keeps parsing.

```json
{
  "schema_version": 2,
  "audit_id": "aud_...", "ts": "...", "action": "get_secret",
  "actor": "token:tok_...", "token_id": "tok_...",
  "token": {
    "type": "service", "service_name": "hem-desktop",
    "identity_id": null, "project": null,
    "issued_by": "operator:tok_root", "issued_at": "...", "expires_at": "..."
  },
  "client": {
    "reported": true, "name": "hem-cli", "version": "0.3.0", "pid": 4821,
    "classification": "agent:claude-code",
    "markers": ["ancestor:claude", "env:CLAUDECODE"],
    "agent_session": "01JZ...", "tty": false,
    "context": "HEM_CALLER value or MCP tool-call id", "request_id": "req_01JZ..."
  },
  "transport": { "kind": "tcp|uds", "remote_addr": "127.0.0.1:52233",
                 "user_agent": "tonic/...", "peer_pid": null, "peer_uid": null, "peer_exe": null },
  "origin": { "node_id": "node-mbp", "forwarded": false },
  "secret_scope": { "type": "global" }, "secret_name": "ahrefs", "key": "API_KEY",
  "result": "ok", "reason": null, "warnings": [], "details": ""
}
```

Tier legibility: `token.*` and `origin.node_id` are verified; `transport.peer_*`
is kernel-verified (UDS only); everything under `client.*` is reported.

## Metadata contract (headers)

Optional gRPC metadata, parsed centrally, sanitized (printable ASCII, length caps —
they are untrusted input into a security log):

- `x-hem-client-name`, `x-hem-client-version`, `x-hem-client-pid`
- `x-hem-client-context` — free-text breadcrumb (Desktop view, Hermes tool-call id), ≤256 chars
- `x-hem-request-id` — client ULID, echoed in audit + errors (the approval
  `request_id` in details is renamed `approval_reference` to avoid collision)
- `x-hem-caller-fingerprint` — CLI-computed agent classification + markers

## Agent detection (hem CLI)

The CLI computes a caller fingerprint per invocation from three signals:

1. **Ancestry walk** (primary): `proc_pidinfo(PROC_PIDTBSDINFO)` ppid loop +
   `proc_pidpath`, up to ~8 ancestor basenames, matched against a signature table.
   Survives `env -i` and nested shells. Verified live: a hem call from Claude Code
   has ancestry `zsh → claude → node → tmux`.
2. **Env markers** (secondary): presence of known variable *names* (never values).
3. **TTY** (`isatty`): human-confirmation signal only, never agent evidence.

Signature table (built-in defaults + user-extensible `<hem data>/agent-signatures.toml`):

| Agent | Ancestor | Env markers | Session id |
|---|---|---|---|
| Claude Code | `claude` | `CLAUDECODE`, `CLAUDE_CODE_*` (verified inherited) | `CLAUDE_CODE_SESSION_ID` |
| Codex CLI | `codex` | `CODEX_*` (calibrate) | — |
| Cursor CLI | `cursor-agent` | `CURSOR_*` (calibrate) | — |
| Grok CLI | `grok` | `GROK_AGENT`, `GROK_*` (calibrate) | — |
| Gemini CLI | `gemini` | `GEMINI_CLI_*` (calibrate) | — |
| Amp | `amp` | `AGENT=amp`, `AMP_*` | `AMP_CURRENT_THREAD_ID` |
| Hive/SMI | — | `SMI_HEM_IDENTITY`, `SMI_*` (we control) | run id |
| Generic | — | `AI_AGENT`, `AGENT`, `HEM_CALLER` | `HEM_AGENT_SESSION` |

`hem doctor agent` prints the fingerprint the current context produces; running it
once inside each CLI calibrates the env columns empirically.

## Classification and enforcement

Classification: `human` | `agent:<name>` | `unknown`. Policy lives in hemd:
`agent_attribution: off | warn | approve | deny` (rollout starts at `warn`).

Invariants (the "operator's own usage never falters" guarantee):

- **Positive evidence only.** `agent:*` requires an explicit marker. No-TTY alone
  never classifies as agent — cron/launchd/scripts stay `unknown`; `unknown` is
  always allowed.
- **Human fast-path.** stderr-isatty + zero markers → `human`, unconditionally
  allowed in every mode.
- **Generic markers warn only.** `AGENT`/`AI_AGENT` are never deny-evidence;
  only specific signatures are.
- **Override.** `HEM_ALLOW_UNATTRIBUTED=1` / `--allow-unattributed` bypasses and
  writes `warnings: ["attribution_override"]`.
- Edge case, accepted: `! hem get` typed inside an agent session classifies as
  agent (output enters the LLM context — arguably correct); override covers it.

Enforcement (`deny`): identified agent + operator token + no attribution → gRPC
error whose message *is* the remediation doc ("Agent context detected
(claude-code). Run `hem agent begin` …"). `approve` mode routes through the
existing pending-approval flow instead. `warn` mode only writes
`warnings: ["unattributed_agent_read"]` / `["operator_token_read"]`.

## Agent self-identification

Env contract (CLI + hem-client + TS SDK): `HEM_CALLER=<name>`,
`HEM_AGENT_SESSION=<id>`. The CLI auto-forwards `CLAUDE_CODE_SESSION_ID` /
`AMP_CURRENT_THREAD_ID` when present. SMI injects `HEM_CALLER=hive:<harness>` and
`HEM_AGENT_SESSION=<run-id>` into spawned agents (it already injects
`VALHALL_HEM_ADDR`). These vars must never be set in shell profiles;
`hem doctor agent` warns if seen in an interactive-human context.

## Short-lived agent tokens

Plumbing exists (`TokenType::AgentRun`, `IssueAgentToken`, 24h TTL cap,
`SMI_HEM_ISSUE_AGENT_TOKENS`). Missing UX:

```
eval "$(hem agent begin [--name claude-code] [--ttl 900] [--project X])"
# mints AgentRun token (default 15–60 min, project-scoped, name auto-filled
# from fingerprint) and prints VALHALL_HEM_TOKEN / HEM_CALLER / HEM_AGENT_SESSION exports
```

Claims then flow into audit tier-1. Optionally record the minting fingerprint on
the issuance record so hemd can flag cross-client token reuse.

## Teaching agents

- `skills/hem-secrets/SKILL.md` + `hem agent snippet` (paste-able AGENTS.md block):
  session-start mint, `--reason` on reads, wait on `pending_approval` (don't
  retry-loop), never cat token files or print secret values.
- The deny-mode error text is the enforcement-side copy of the same lesson.

## Valhall MCP codemode server

`valhall-mcp` (TS, wraps `@valhall/hem-sdk`): agents connect via MCP instead of
shelling out. Attribution becomes structural — MCP `initialize` carries
`clientInfo{name,version}`. Server mints one AgentRun token per MCP session and
stamps `x-hem-client-name=mcp:<clientInfo.name>` + tool-call id context.
Codemode: a single `run_code` tool executing sandboxed TS against a bound `hem`
API. Enables **use-without-read**: `hem.getRef()` returns an opaque handle usable
in server-side actions without plaintext entering the model context; audit
records `result: "ref_issued"` vs `"ok"`.

## Other accepted items (summary)

- **UDS listener** with kernel peer creds (`getpeereid` + `LOCAL_PEERPID` →
  `proc_pidpath`) — the only non-spoofable local "which binary called me".
  Local clients prefer UDS, TCP stays for cluster peers. Paths stay in the local
  log only; anything replicated carries `client.name` + `origin.node_id` at most.
- **Interceptor refactor**: one tower layer building a `RequestContext
  { caller, client, transport, request_id }` extension instead of 28 hand-placed
  `require_caller` calls.
- **Named service tokens** per consumer (`hem-desktop`, `hermes-mcp`, …) with
  `require_named_tokens_for_read: warn|deny` migration knob.
- **Cluster origin**: `requester_client` (name/version only) on peer-forwarded
  requests and read receipts; `origin.{node_id,forwarded}` on audit rows.
- **Read-burst detection**: reads per `(client.name, secret)` per minute →
  `read_burst_detected` audit entry (would have caught the ahrefs loop live).
- **Rejected/deferred**: EndpointSecurity (entitlement-gated), OpenBSM
  (deprecated), DTrace (SIP), mTLS for local clients (UDS + named tokens suffice),
  loopback port→pid matching in hemd (racy; forensic scripts only).

## Privacy rules

Never log: token values, secret/key values, raw env values, full command lines
(args carry secrets — parent process is basename only). Sanitize all
client-supplied metadata. `entries.jsonl` stays owner-only; pids/paths never
leave the node.

## Rollout

1. Audit schema v2 in hem-core + hemd enrichment from claims/metadata (pure
   observation; makes existing logs interpretable immediately).
2. CLI fingerprinting + client headers + `hem doctor agent`; calibrate env
   columns against installed agent CLIs.
3. `hem agent begin` + skill/snippet + SMI env injection.
4. hemd policy `warn`; soak for false positives (positive-evidence rule should
   yield none on human flows).
5. Flip to `approve`/`deny` for identified-agent + operator-token reads.
   UDS listener, interceptor refactor, cluster origin, burst detection, and the
   MCP codemode server land independently after.
