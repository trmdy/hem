# Contributing to Hem

Thanks for your interest. Bug reports, fixes and small improvements are welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Report security problems privately through GitHub's "Report a vulnerability" on this repository, not in a public issue.

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
```

`hemd` connects to NATS on `127.0.0.1:4222`, so its integration tests need a local server, for example `docker run -p 4222:4222 nats:2` or `nats-server`.

For the TypeScript parts, run `npm ci`, then the `build`, `typecheck` and `test` scripts in `sdk/ts`, `apps/hem-desktop` or `apps/hem-raycast`.

## Pull requests

- Keep each pull request focused on one change.
- Make sure CI passes: formatting, build and tests for Rust, and build, typecheck and tests for the TypeScript packages.
- Don't change on-disk or wire formats (data directory layout, environment variable names, the `valhall.hem.v1` proto package, token formats) without discussing it first. Existing vaults depend on them.
- Never include real secrets, tokens, hostnames or personal data in code, tests or fixtures.

By contributing you agree that your contributions are licensed under the MIT License.
