# Kv-Rust-Mig

Rust rewrite of [kv-secrets](https://github.com/Kv-Secrets-2/kv-secrets) as a single `kv` binary (CLI, daemon, MCP server, Claude Code hook), drop-in compatible with 0.4.0 vaults.

See [PLAN.md](PLAN.md) for the staged migration plan.

## Building

```sh
cargo build --release
cargo test --workspace
```

Local tests without `KV_PY_REF` explicitly skip the live Python comparisons.
CI also runs a mandatory Linux parity gate against pinned Python 0.4.0 source:
Python 3.10 defines exact transcripts; 3.11–3.13 check semantic compatibility.
See [the parity guide](docs/migration/PARITY.md) for reference setup, execution,
and the comparison inventory.

The migration is incomplete. See [the baseline audit](docs/migration/BASELINE-2026-11-06.md)
for implemented coverage, remaining features, and known findings, and the
[IPC/shutdown update](docs/migration/IPC-SHUTDOWN.md) for the subsequent timeout
and daemon-lifecycle work.
