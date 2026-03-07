# 0089: hem scan — Secret Leak Detection

**Status:** Implemented (2026-03-03)
**Author:** Tormod Haugland
**Date:** 2026-03-03
**Component:** hem CLI + hemd

## Problem

Valhall agents (e.g. Nanotobber) process untrusted input from email, web content, and messaging. A prompt injection or bug could cause an agent to include secret values in outgoing text (email replies, Telegram messages, API calls). There is currently no way to detect this before the text leaves the system.

Each consumer maintaining its own regex-based secret scanner is fragile — it requires knowing all secret patterns in advance and updating scanners whenever new secrets are added. Hem already holds all secret values centrally, making it the natural place for this check.

## Proposal

Add a `hem scan` command that checks arbitrary text against all secret values in the hem store. If any secret value appears in the input, the command reports which secrets matched and exits with a non-zero status code.

### Usage

```bash
# Pipe text to scan via stdin
echo "Here is some text with a leaked key sk-ant-api03-fIkCp..." | hem scan

# Exit code: 0 = clean, 1 = secrets detected
echo $?  # 1

# Typical agent usage: gate outgoing messages
MESSAGE="Hei Tormod, her er en oppdatering..."
if echo "$MESSAGE" | hem scan --quiet; then
  send_message "$MESSAGE"
else
  echo "BLOCKED: outgoing message contains secret material"
fi

# Scope the scan to specific secrets
echo "some text" | hem scan --scope global
echo "some text" | hem scan --scope project/acme

# Show which secrets matched (default)
echo "some text with leaked-key-value" | hem scan
# match   global/anthropic-api-key (key: api_key)
# match   global/tobber-telegram (key: bot_token)
# result  2 secrets detected

# Quiet mode — exit code only, no output
echo "some text" | hem scan --quiet
```

### CLI Interface

```
hem scan [OPTIONS]

Scan stdin for leaked secret values.

Reads text from stdin and checks whether any secret values stored in Hem
appear as substrings. Returns exit code 0 if clean, 1 if secrets detected.

Options:
    --scope <SCOPE>       Limit scan to secrets in a specific scope
                          (global, project/<name>, identity/<id>)
    --min-length <N>      Minimum secret value length to match against (default: 8).
                          Prevents false positives on short values like "true" or "443".
    --quiet, -q           Suppress output. Only set exit code.
    --json                Output results as JSON.
    --endpoint <URL>      Hem daemon endpoint (global flag)
    --token <TOKEN>       Bearer token for hemd auth (global flag)

Aliases: sc

Exit codes:
    0   No secrets found in input (clean)
    1   One or more secret values detected
    2   Error (daemon unreachable, auth failure, etc.)
```

### JSON Output

```json
{
  "clean": false,
  "matches": [
    {
      "secret": "global/anthropic-api-key",
      "key": "api_key",
      "offset": 142
    },
    {
      "secret": "global/tobber-telegram",
      "key": "bot_token",
      "offset": 305
    }
  ],
  "scanned_length": 1024,
  "secrets_checked": 47
}
```

Note: The output includes the secret *name* and *key*, never the secret *value*. The offset indicates where in the input the match was found, useful for debugging.

## Architecture

### Option A: Daemon-side scan (recommended)

Add a new `ScanForSecrets` RPC to the `HemRuntime` service. The client sends the text to scan, the daemon checks against its store, and returns match metadata.

**Advantages:**
- Secret values never leave the daemon — the client only sends text in and gets match metadata back
- Single implementation, no client-side secret enumeration
- Daemon can use efficient matching (e.g. Aho-Corasick automaton built once and cached)
- Works correctly with approval-gated secrets (daemon has access, client may not)

**Proto addition:**

```protobuf
message ScanForSecretsRequest {
  string text = 1;
  string scope = 2;           // optional scope filter
  uint32 min_value_length = 3; // minimum secret value length to check (default 8)
}

message ScanMatch {
  string secret_ref = 1;      // e.g. "global/anthropic-api-key"
  string key = 2;             // e.g. "api_key"
  uint32 offset = 3;          // position in input text
}

message ScanForSecretsResponse {
  bool clean = 1;
  repeated ScanMatch matches = 2;
  uint32 scanned_length = 3;
  uint32 secrets_checked = 4;
}
```

**Daemon implementation sketch:**
1. Load all secret key-value pairs (optionally filtered by scope)
2. Filter out values shorter than `min_value_length`
3. Build an Aho-Corasick automaton from the values (cache and invalidate on secret changes)
4. Run the automaton over the input text
5. Map matches back to secret refs and return metadata

### Option B: Client-side scan

Use `GetSecrets` (batch get) to fetch all values, then do substring matching client-side.

**Disadvantages:**
- All secret values are transmitted to the client over gRPC
- Client must be authorized to read every secret in scope
- No caching benefit across invocations
- More code in the CLI for matching logic

**Not recommended** unless daemon changes are impractical.

## Security Considerations

- The scan text is transmitted to the daemon. This is acceptable — the text is the *potentially leaked* content, not a secret itself. The daemon should not log or persist it.
- The daemon must ensure the requesting token has appropriate permissions. A reasonable default: any valid token can scan against secrets it has read access to.
- The `min_value_length` filter (default 8) is important. Without it, short secret values like port numbers ("993"), booleans ("true"), or common strings would cause false positives on nearly all input.
- The response must never include the matched secret *value* — only the secret reference, key name, and match offset.

## Use Cases

### 1. Agent output gating

Before any agent sends an outgoing message (email, Telegram, Ting, webhook), pipe it through `hem scan`:

```typescript
async function safeSend(text: string): Promise<void> {
  const result = await exec(`echo ${shellQuote(text)} | hem scan --quiet`);
  if (result.exitCode === 1) {
    throw new Error("Blocked: outgoing message contains secret material");
  }
  // proceed with send
}
```

### 2. CI/CD leak detection

Scan build logs, generated configs, or deployment manifests for accidentally embedded secrets:

```bash
cat deployment.yaml | hem scan --scope project/myproject
```

### 3. Code review integration

Check diffs for leaked secrets before committing:

```bash
git diff --staged | hem scan
```

### 4. Log sanitization audit

Retroactively check log files for secret exposure:

```bash
cat /var/log/myapp.log | hem scan --json > leak-report.json
```

## Implementation Scope

### Minimum Viable

1. New `ScanForSecrets` RPC in hemd
2. `hem scan` CLI subcommand reading from stdin
3. Default and `--quiet` output modes
4. `--min-length` filter (default 8)
5. Exit codes: 0 clean, 1 detected, 2 error

### Nice to Have

- `--json` output mode
- `--scope` filtering
- Aho-Corasick caching in daemon (invalidate on secret set/delete)
- `--redact` mode: output the input text with matched values replaced by `[REDACTED:secret-name]`
- Programmatic SDK support (hem-client crate exposes `scan()`)

## Effort Estimate

- Proto changes: small
- Daemon handler + matching logic: small-medium
- CLI subcommand: small (follows existing pattern exactly)
- Tests: medium
- Total: roughly half a day for MVP
