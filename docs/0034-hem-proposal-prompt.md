# Valhall: Hem Agent Prompt

> Fast-tracked from Sprint 2. Build immediately after Sprint 1 closure.

---

## Hem (Secret Management)

### Prompt

You are building **Hem**, the secret management service for the **Valhall** agent productivity suite.

**Your task:** Implement Hem — an agent-first vault for storing, encrypting, and distributing secrets to agents and services across the Valhall ecosystem.

**Context:**
Valhall is a system of interconnected services where AI agents execute work. These agents and services need secrets: LLM API keys, OAuth tokens, deployment credentials, database passwords, third-party service keys, and more. Today these are scattered across environment variables, config files, and harness home directories. Hem centralizes all of this behind a single, encrypted, access-controlled interface.

Hem is being fast-tracked because every new integration adds another ad-hoc secret path. Smi needs API keys for LLM providers. Vis needs embedding API keys. Harness profiles need OAuth credentials. Agents doing real work need credentials for external services. Hem solves this once.

Hem is **not** a general-purpose secret manager like HashiCorp Vault. It is purpose-built for Valhall's agent workflows — simple, fast, and deeply integrated with Smi, Vis, and the rest of the ecosystem.

In this phase, Hem runs **locally on a single node**. Distribution across the mesh comes later.

**Architecture:**

Hem has three components:
1. **`hemd`** — The daemon managing secrets. Exposes a gRPC API via `valhall-net`. All secret data is encrypted at rest.
2. **`hem` CLI** — Command-line tool for managing secrets (primarily used by humans and ops scripts).
3. **`hem` library** — Rust library for programmatic access (used by Smi, Vis, and other services).

---

### Core Concepts

#### Secrets

A **secret** is a named bundle of one or more key-value pairs. Secrets are the atomic unit of Hem.

```
Secret: "anthropic-prod"
├── api_key = "sk-ant-..."
└── org_id = "org-..."

Secret: "project-x-db"
├── host = "db.example.com"
├── port = "5432"
├── username = "app"
├── password = "..."
└── database = "project_x"
```

Secret properties:
- **Name** — Unique within its scope. Lowercase alphanumeric + hyphens.
- **Scope** — Where this secret lives (see Scopes below).
- **Values** — One or more key-value pairs. Values are always strings (callers parse as needed).
- **Requires approval** — Boolean flag. When true, any read by an agent triggers a user approval prompt before the secret is released. Defaults to false.
- **Description** — Optional human-readable description of what this secret is for.
- **Created/updated timestamps.**
- **Created by** — Who created this secret (user, agent identity, system).
- **Last accessed** — Timestamp + accessor identity of last read.

#### Scopes

Secrets are organized into scopes that determine visibility and access:

1. **Global** — Available to any authenticated caller. Typically infrastructure-level secrets: LLM API keys, shared service credentials, mesh-wide tokens.
2. **Project** — Scoped to a project name. Available to any agent working within that project. Maps to Kode project names when available.
3. **Identity** — Scoped to a Vis agent identity. Only the owning agent (or a caller with explicit grant) can access these. Created by Vis when an identity is provisioned, or by agents during their work.

Scope resolution follows a hierarchy: when an agent requests a secret by name, Hem searches identity scope first, then project scope (if the agent has a project context), then global scope. The first match wins. This allows project-level overrides of global defaults, and agent-level overrides of project defaults.

#### Secret Groups

Secrets may be organized into **groups** for human convenience. A group is just a label — it doesn't affect access control. Examples: "Production deployment", "Development keys", "Client X credentials". A secret can belong to zero or one group.

---

### Authentication and Authorization

Hem operates on a zero-trust model. Every request must be authenticated, even on the local machine.

**For this phase, implement a token-based scheme:**

1. **Operator token:** A long-lived token generated during `hemd` setup and stored in a root-only-readable file (e.g., `~/.valhall/hem/operator.token`). The CLI uses this token. It has full access to all scopes.

2. **Service tokens:** Each Valhall daemon (smid, vishd, bodd, etc.) gets a service token provisioned during setup. Service tokens grant access to global secrets and any secrets explicitly granted to that service.

3. **Agent run tokens:** When Smi spawns an agent, it requests a short-lived, scoped token from Hem on behalf of that agent. The token encodes:
   - The agent's Vis identity ID (if any).
   - The project context (if any).
   - An expiration time (default: lifetime of the agent run, max: 24 hours).
   - Allowed scopes (derived from the agent's identity and project).

   Smi passes this token to the agent via an environment variable (`VALHALL_HEM_TOKEN`). The agent uses it to request secrets from Hem during its run.

```rust
pub struct AgentRunToken {
    pub token_id: String,           // ULID
    pub identity_id: Option<String>,// Vis identity, if any
    pub project: Option<String>,    // Project context, if any
    pub scopes: Vec<Scope>,         // Allowed scopes
    pub expires_at: DateTime<Utc>,
    pub issued_by: String,          // Service that requested the token (e.g., "smi")
}
```

Tokens are signed using a symmetric key derived from the Hem master key. Hem can validate tokens without a database lookup (self-contained JWT-like structure, but use `paseto` or a simple HMAC scheme — not JWT).

**Future (not this phase):** Full proof-of-identity tied to Vis cryptographic identity, mutual TLS between services, hardware-backed keys.

---

### Encryption

All secret values are encrypted at rest. Hem never stores plaintext secret values on disk.

**Encryption scheme:**
- A **master key** is generated during `hemd` first-run and stored in a protected file (`~/.valhall/hem/master.key`, permissions `0600`).
- Each secret value is encrypted using `XChaCha20-Poly1305` (via the `chacha20poly1305` crate) with a unique nonce per value.
- The master key encrypts/decrypts individual secret values. Key derivation per-scope is a future enhancement.
- The master key file is the critical asset. If lost, all secrets are unrecoverable. Document this clearly.

**On-disk storage structure:**

```
~/.valhall/hem/
├── master.key                    # Master encryption key (0600)
├── operator.token                # Operator auth token (0600)
├── service-tokens/               # Per-service tokens
│   ├── smi.token
│   ├── vis.token
│   └── ...
├── secrets/
│   ├── global/
│   │   ├── anthropic-prod.json   # Encrypted secret bundle
│   │   ├── openai-prod.json
│   │   └── ...
│   ├── project/
│   │   ├── project-x/
│   │   │   ├── db-prod.json
│   │   │   └── ...
│   │   └── ...
│   └── identity/
│       ├── {identity-ulid}/
│       │   ├── personal-api.json
│       │   └── ...
│       └── ...
└── audit/
    └── ...                       # Audit log files
```

Each `.json` file contains the secret metadata in plaintext (name, scope, description, timestamps, flags) and the values as encrypted blobs. This allows listing and inspecting secrets without decrypting their values.

---

### Implement the following:

#### hemd (daemon)

gRPC API:

```
// Secret management
SetSecret(scope, name, values, options) -> SecretInfo
GetSecret(scope, name) -> SecretWithValues          // Decrypts and returns values
GetSecretInfo(scope, name) -> SecretInfo             // Metadata only, no decryption
DeleteSecret(scope, name)
ListSecrets(scope, filters) -> Vec<SecretInfo>

// Bulk operations
GetSecrets(requests: Vec<SecretRequest>) -> Vec<SecretWithValues>  // Batch get

// Secret groups
SetGroup(group_name, description)
AddToGroup(scope, secret_name, group_name)
RemoveFromGroup(scope, secret_name)
ListGroups() -> Vec<GroupInfo>
ListGroupSecrets(group_name) -> Vec<SecretInfo>

// Token management
IssueAgentToken(identity_id, project, ttl) -> Token  // Called by Smi
IssueServiceToken(service_name) -> Token              // Called during setup
RevokeToken(token_id)
ListActiveTokens() -> Vec<TokenInfo>

// Access grants (cross-scope access)
GrantAccess(secret_scope, secret_name, grantee_scope, grantee_id)
RevokeAccess(secret_scope, secret_name, grantee_scope, grantee_id)
ListGrants(secret_scope, secret_name) -> Vec<GrantInfo>

// User approval (for secrets flagged requires_approval)
ListPendingApprovals() -> Vec<ApprovalRequest>
ApproveAccess(request_id)
DenyAccess(request_id)

// Audit
GetAuditLog(scope, since, until, limit) -> Vec<AuditEntry>

// Admin
RotateMasterKey()                                    // Re-encrypts all secrets
ExportSecrets(scope) -> EncryptedBundle              // For backup
ImportSecrets(bundle: EncryptedBundle)               // For restore
```

#### hem CLI

```
# Secret operations
hem set <scope>/<name> <key>=<value> [<key>=<value>...] [--description "..."] [--requires-approval] [--group <g>]
hem get <scope>/<name> [<key>]           # Print decrypted value(s)
hem info <scope>/<name>                  # Metadata only
hem delete <scope>/<name>
hem list [<scope>] [--group <g>]         # List secrets, optionally filtered

# Scope shorthand: "global/foo", "project/myproj/foo", "identity/{id}/foo"
# Or omit scope for global: "hem set foo key=value" implies global/foo

# Secret groups
hem group create <group_name> [--description "..."]
hem group list
hem group secrets <group_name>
hem group add <scope>/<name> <group_name>
hem group remove <scope>/<name>

# Access grants
hem grant <scope>/<name> --to <grantee_scope>/<grantee_id>
hem revoke-grant <scope>/<name> --from <grantee_scope>/<grantee_id>
hem grants <scope>/<name>

# Approvals (interactive)
hem approvals                            # List pending approval requests
hem approve <request_id>
hem deny <request_id>

# Token management
hem token list                           # List active tokens
hem token revoke <token_id>

# Admin
hem init                                 # First-time setup: generate master key + operator token
hem rotate-key                           # Rotate master key (re-encrypts everything)
hem export [<scope>] -o <file>           # Encrypted backup
hem import <file>                        # Restore from backup
hem audit [<scope>] [--since <time>] [--limit <n>]

# Service setup (run once per service)
hem service register <service_name>      # Generates service token
hem service list
```

#### User Approval Flow

When an agent requests a secret that has `requires_approval = true`:

1. Hem does not return the secret immediately.
2. Instead, Hem creates an `ApprovalRequest` with: requester identity, secret name, timestamp, and a reason (if provided by the caller).
3. Hem emits an event: `hem.approval.requested`.
4. The request appears in `hem approvals` and in the Valhall desk (future).
5. The agent's `GetSecret` call blocks (with a configurable timeout, default 5 minutes) waiting for approval.
6. When the operator runs `hem approve <id>`, the secret is released to the waiting caller.
7. If denied or timed out, the caller receives an error.

For agents running non-interactively, the blocking behavior may not be practical. An alternative async pattern should be supported: the agent can request with `async = true`, receive a `pending` response with the request ID, and poll or subscribe to `hem.approval.resolved` events.

---

### Integration Points

#### Smi integration

Smi is the primary consumer of Hem. Integration points:

1. **Profile API keys:** Harness profiles can reference Hem secrets instead of env vars or local files:
   ```toml
   [[profile]]
   name = "claude-api"
   harness = "api"
   provider = "anthropic"
   model = "claude-sonnet-4-20250514"
   api_key_secret = "global/anthropic-prod/api_key"   # Hem reference
   max_concurrency = 10
   ```
   When loading a profile, Smi resolves `api_key_secret` from Hem using its service token.

2. **Agent run token injection:** When Smi spawns an agent run that has a `vis_id` or project context, Smi calls `IssueAgentToken` and injects the resulting token as `VALHALL_HEM_TOKEN` into the agent's environment. The agent can then call Hem directly for any secrets it needs during execution.

3. **Skip integration:** When running containerized agents, Smi must ensure the agent can reach `hemd` from inside the container. This requires two things injected into the Skip container environment:
   - `VALHALL_HEM_TOKEN` — the agent's scoped access token.
   - `VALHALL_HEM_ADDR` — the address of `hemd` reachable from inside the container (e.g., `http://host.skip.internal:9400` or the host's tailnet IP + port).

   Skip must provide a stable, well-known mechanism for containers to reach host services. Implement this as a DNS alias or injected `/etc/hosts` entry (e.g., `host.skip.internal` → host IP) that is automatically configured when a skip is created. This is a Skip-level concern, not a Hem-level concern — but Hem and Smi must agree on the convention and use it consistently. If this host-resolution mechanism does not yet exist in Skip, implement it as part of this work.

#### Vis integration

1. **Embedding API keys:** Vis reads its embedding provider API key from Hem instead of config files:
   ```toml
   # ~/.valhall/vis/config.toml
   [embeddings]
   provider = "openai"
   api_key_secret = "global/openai-prod/api_key"   # Hem reference
   ```

2. **Identity secrets:** When Vis creates an agent identity, it can optionally provision a Hem identity scope for that agent. Agent-specific secrets (personal API keys, service credentials the agent has acquired) live here.

#### TS SDK

A TypeScript SDK (`@valhall/hem-sdk`) for agents running in Node/Bun environments:

```typescript
import { HemClient } from '@valhall/hem-sdk';

// Client auto-reads VALHALL_HEM_TOKEN from env
const hem = new HemClient();

// Get a secret
const apiKey = await hem.get('global/anthropic-prod', 'api_key');

// Get all values of a secret
const dbCreds = await hem.getAll('project/myproj/db-prod');
// { host: "db.example.com", port: "5432", username: "app", password: "..." }

// Set a secret (if token has write permission)
await hem.set('identity/my-agent/scraped-token', { token: '...' });

// Request with approval
const result = await hem.get('global/deploy-key', 'key', { async: true });
if (result.pending) {
  // Poll or wait for approval
  const approved = await hem.waitForApproval(result.requestId, { timeout: 300_000 });
}
```

---

### Audit Log

Hem maintains a comprehensive audit log tracking:
- Every secret read (who, what, when, from where).
- Every secret write/delete.
- Every token issued/revoked.
- Every approval request/resolution.
- Every access grant/revocation.
- Failed access attempts (wrong scope, expired token, denied).

Audit entries include: timestamp, action, actor (token ID + resolved identity), secret scope/name (but never the secret values), result (success/denied/error), source IP or service name.

Retention: 3 months, matching Vis audit retention.

The audit log is the primary forensic tool for answering "who accessed what and when." In an agent-heavy system where secrets flow to many autonomous actors, this is critical.

`hemd` emits audit events via `valhall-net`: `hem.secret.read`, `hem.secret.written`, `hem.secret.deleted`, `hem.token.issued`, `hem.token.revoked`, `hem.approval.requested`, `hem.approval.resolved`.

---

### Requirements

1. **All secret values encrypted at rest** using XChaCha20-Poly1305. Plaintext secret values must never touch disk. Encrypted values are decrypted in-memory only when requested by an authenticated caller.
2. **Master key protection.** The master key file must be `0600` permissions. `hemd` should refuse to start if the master key has wrong permissions. Document backup/recovery procedures clearly.
3. **Token validation must be fast.** Tokens are self-contained and validated via HMAC — no database lookup required. Target: < 0.1ms per token validation.
4. **Scope resolution must be correct.** Identity → project → global, first match wins. This must be well-tested with edge cases (agent with no project context, overlapping secret names across scopes).
5. **The approval flow must handle both sync and async patterns.** Blocking with timeout for interactive agents, polling/event-based for non-interactive agents.
6. **Batch get (`GetSecrets`) must be efficient.** Agents starting up often need 5-10 secrets at once. This should be a single RPC, not N sequential calls.
7. **`hemd` registers with `valhall-net`** and emits events for all auditable actions.
8. **Key rotation must be safe.** `RotateMasterKey` must re-encrypt all secrets atomically. If interrupted, the old key must still work (keep the old key until rotation is confirmed complete).
9. **Backward compatibility with env vars.** Services should try Hem first, fall back to env vars if Hem is unavailable or the secret isn't found. This allows gradual migration — you don't have to move everything to Hem on day one.
10. Write tests for: encryption roundtrip, token issuance and validation, token expiry rejection, scope resolution order, approval flow (sync + async), key rotation, batch get, audit log correctness, concurrent access, and container-to-host `hemd` reachability (via the `host.skip.internal` convention).

**Dependencies:**
- `valhall-net` (workspace crate)
- `valhall-common` (workspace crate)
- `tokio`
- `tonic`, `prost`
- `clap`
- `tracing`
- `chacha20poly1305` (AEAD encryption)
- `rand` (nonce generation)
- `hmac`, `sha2` (token signing)
- `serde`, `serde_json`
- `chrono`
- `ulid`

**Do NOT:**
- Implement distribution across the mesh. Single-node only for now.
- Implement full cryptographic proof-of-identity tied to Vis. The token scheme is sufficient for this phase.
- Implement mutual TLS between services. Bearer tokens over the local network are acceptable for this phase.
- Implement hardware-backed key storage (HSM/TPM). File-based master key is fine.
- Over-engineer the permission model. Three scopes (global, project, identity) with optional explicit grants covers the current needs.
- Build a UI. The CLI is the management interface for now. The Valhall desk will integrate approval flows later.
