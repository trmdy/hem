# Hem: distributed ledger growth is dominated by read-audit operations (issue)

Status: open backlog item
Filed: 2026-07-09 (during MacBook Pro node onboarding, see runbook 1020)
Linear: Tormod workspace, Labs team ("Hem: stop replicating read-audit ops to the distributed ledger")

## Problem

Every `hem get` appends two signed operations (`read.requested`, `read.fulfilled`)
to the distributed ledger, which replicates to all peers and is replayed by every
new node forever.

Measured on `hmn_main` 2026-07-08 (ledger position 165850, file size 176 MB):

| op_type               | count  | payload   |
|-----------------------|--------|-----------|
| `read.requested`      | 82,756 | 28.0 MB   |
| `read.fulfilled`      | 82,745 | 34.6 MB   |
| `secret.value.set`    | 238    | 0.8 MB    |
| `secret.metadata.set` | 111    | ~0        |

99.8% of operations are read audit; actual secret state is 349 ops (~1 MB).
Growth is ~4k ops/day (agents fetching keys), unbounded. Consequences observed
while onboarding `hmn_fir06`:

- `bootstrap-ledger` transfers and replays 176 MB instead of ~1 MB.
- Materializer catch-up requires ~166 forward-only batches of 1000 ops
  (`repair_materializers`, `crates/hem-core/src/ledger.rs:567-571`), each
  triggered by a read or `verify --repair` call.
- Every future node and every full re-materialization pays the same cost again.

## Proposed fix (primary)

Stop writing read-audit events to the *distributed* ledger. Reads are already
recorded in the local audit trail (`audit/entries.jsonl`); replicating them as
signed cluster operations adds little and costs unbounded ledger growth.

- Add a config flag (e.g. `ledger_read_audit = false` in `cluster.toml` or
  hemd config), defaulting to local-audit-only.
- Route `read.requested` / `read.fulfilled` to the local audit log only.

## Complementary (longer term)

Checkpoint-based compaction: a supported command that starts a new epoch from a
checkpoint and discards `read.*` (or all non-state) operations before it, so
existing over-grown ledgers can be shrunk. The current hard-fork/replay
machinery (docs 1017) is a rewind tool, not compaction, and is not suitable for
this on a healthy cluster.

## Notes

- Materializer cursor is forward-only (`ledger_materializer_state`,
  `crates/hem-core/src/ledger.rs:1780-1803`); if views are reset the replay
  proceeds in 1000-op batches per read — a `hem cluster rematerialize` command
  (wrapping `reset_materializers()` + a full replay loop, `ledger.rs:1697-1708`)
  would also have made node onboarding recovery one command instead of a loop.
