# Hem Peer Ledger Bootstrap

`hem cluster bootstrap-ledger` imports signed distributed ledger history from a
configured peer into a fresh node.

## Usage

After `hem cluster join` has written `cluster.toml` and `node-identity.json`,
pull history from a trusted peer:

```sh
hem cluster bootstrap-ledger --peer <peer-node-id>
```

The command verifies the peer hello, operation signatures, hash chain continuity,
and cluster id before accepting operations. It materializes metadata and encrypted
value versions after each accepted batch. It does not import plaintext secret
values; node-level key authorization remains a separate step.

Bootstrap is resumable. If interrupted, rerun the command. Existing operations
with the same hash are counted as duplicates; conflicting hashes fail closed.

## Failure Boundaries

Bootstrap refuses to import:

- operations signed with invalid or tampered signatures;
- operations from a different cluster id;
- operations that do not connect to the local hash-chain head;
- operation ids that already exist locally with a different body hash.

Run `hem cluster verify` after bootstrap to confirm the local ledger and
materialized state.
