# Hem Retrieval Certainty Boundaries

Hem can make cryptographic statements about retrievals only when the read flows
through the daemon and the distributed ledger is enabled.

## Cryptographically known reads

Daemon-mediated `GetSecret` and `GetSecrets` calls emit signed ledger receipts
when cluster runtime is enabled. Each read emits:

- `read.requested`, before plaintext values leave the daemon.
- `read.fulfilled`, after policy checks pass and values are released.

The receipt payload records the requester, token id, secret scope/name, requested
keys, secret version, policy decision, approval reference, and confirms that the
ledger receipt does not include plaintext. These operations are signed by the
serving node and are verified by `hem cluster verify` as part of the ledger chain.

## What Hem cannot certify

Hem does not claim retrieval certainty for reads that bypass the daemon. This
includes direct file reads, copied backups, memory scraping, debugger access,
already-unlocked compromised machines, and plaintext that a caller stores after a
legitimate retrieval. Those events may be detectable by host telemetry, but they
are outside Hem's cryptographic receipt boundary.

## Permission boundary checks

`hem cluster verify` now checks the Hem data directory for weak local filesystem
boundaries. On Unix systems it reports:

- files or directories with group/other permission bits set;
- symlinks inside the data directory, which Hem does not follow for certainty;
- non-regular files inside the data directory.

The command prints `data_dir_security_ok=false` and exits non-zero when these
issues are present. It also appends an audit entry with action
`cluster.verify.security` and result `unsafe_permissions`.

Operators should remediate reported paths with owner-only permissions, normally
`chmod 700` for directories and `chmod 600` for files, then rerun
`hem cluster verify`.
