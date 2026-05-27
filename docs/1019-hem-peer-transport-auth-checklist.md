# Hem Peer Transport Authentication Checklist

Hem peer RPCs are authenticated at the application transport layer with pinned node identities. This is the standalone equivalent of mTLS for the current gRPC plaintext endpoints: every protected peer request carries signed metadata from a configured cluster peer, and the receiver verifies the signature against `cluster.toml`.

## Signed Request Binding

Every protected request signs a canonical `hem-peer-transport-v1` statement containing:

- `cluster_id`
- `node_id`
- RPC method name
- nonce
- Unix timestamp

The signed values are mirrored into gRPC metadata:

- `x-hem-peer-cluster-id`
- `x-hem-peer-node-id`
- `x-hem-peer-method`
- `x-hem-peer-nonce`
- `x-hem-peer-timestamp`
- `x-hem-peer-signature`

## Server Checks

Reviewers should verify that protected peer handlers do all of the following before accepting the request body:

- Load the local cluster config and require auth when configured peers exist.
- Reject missing, malformed, stale, future-dated, or replayed auth metadata.
- Reject unknown peer node ids.
- Verify signatures with the configured peer signing public key.
- Check the signed method matches the RPC being handled.
- Check body requester fields match the authenticated peer where the protobuf carries requester identity.
- Keep localhost/dev mode explicit: unauthenticated peer RPCs are allowed only when the local cluster has no configured peers.

## Protected Calls

The daemon verifies peer transport auth for hello, list, ack, push, read approval, collision approval, master approval routing/status/receipt consumption, and checkpoint cosignature RPCs.

The `hem` CLI and `hemd` daemon sign outgoing peer requests for cluster sync, ledger bootstrap, collision approval, master approval routing, and checkpoint cosigning.

## Current Boundary

This layer authenticates the peer node and rejects replay at the RPC layer. It does not encrypt the gRPC transport by itself; deploy over localhost, private network links, SSH tunnels, WireGuard, or future TLS/mTLS wrapping when confidentiality of peer traffic is required.
