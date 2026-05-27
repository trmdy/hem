# Hem Hard-Fork Replay Runbook

Hard-fork replay is the operator workflow for rewinding Hem's materialized
distributed state without deleting the signed ledger history.

## Flow

1. Create or choose a trusted checkpoint.
2. Declare the fork:

   ```sh
   hem cluster fork --parent-checkpoint <checkpoint-id> --reason "<why>"
   ```

3. Confirm a backup exists outside the active Hem data directory.
4. Execute replay:

   ```sh
   hem cluster replay-fork <fork-id> \
     --confirm-rewind <fork-id> \
     --backup-confirmed <backup-reference>
   ```

The replay command clears local materializer tables, rebuilds them through the
fork parent checkpoint, and then applies operations after the fork declaration.
The original signed operations remain in the ledger. Hem also appends a signed
`ledger.replay` operation and stores a replay record with the backup reference.

## Safety Gates

`replay-fork` is intentionally fail-closed. It refuses to run unless:

- `--confirm-rewind` exactly matches the fork id;
- `--backup-confirmed` is non-empty;
- the fork, parent checkpoint, and fork operation all exist locally.

After replay, run:

```sh
hem cluster verify
```

The verification output includes `fork_replays_declared=<n>` so operators can
see that the replay record is part of the local integrity state.
