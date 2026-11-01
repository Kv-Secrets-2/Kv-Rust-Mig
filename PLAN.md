# Kv-Rust-Mig — kv-secrets Rust migration plan

Status: draft for owner approval. No code is ported until this plan is approved.
Reference implementation: `Kv-Secrets-2/kv-secrets` branch `release/0.4.0-candidate` (Python, version 0.4.0).
0.4.0 ships in Python from that repo; this repo is the Rust track (target: 0.5).

## Goals (owner)

1. One static binary `kv`: CLI, daemon (`kv unlock`), MCP server, and Claude Code hook. No Python needed.
2. Better memory behaviour: secrets held in locked, zeroed-on-drop buffers; no copies left by a GC.
3. Better speed: startup in milliseconds (this matters most for the hook and the MCP server, which run on every call).
4. Better security: memory-safe parsers, fuzzed protocol and file parsers, smaller dependency surface, signed releases.

## Hard requirement: drop-in compatibility

The Rust `kv` reads and writes the **same `.secrets/` files** as Python 0.4.0, byte for byte:
key files (KVW v1–v4, scrypt settings, owner identity), drawer index/records (`.kvi`/`.kvs`),
older env-bundle `.enc` files, `config.json`, TOTP blobs, backups, `run_grants.json`, approval
signatures (Ed25519) and request records. Users can switch binaries either way on the same vault.
The daemon control protocol and MCP tool surface (10 tools, 4 profiles) stay wire-compatible,
so editors configured by `kv setup` keep working.

## What the Python code is (measured)

- 71k lines in 79 modules (`kv/`, `kv_mcp/`). Biggest: `cli.py` 13.4k (≈130 subcommands),
  `agent.py` 8.6k (≈30 daemon commands), `hook.py` 4.7k, `sandbox.py` 3.2k, `approval_verify.py` 2.4k,
  `saved_passes.py` 2.3k, `providers.py` 2.1k, `kv_mcp/tools.py` 2.1k, `store.py` 1.9k, `audit.py` 1.9k.
- Crypto: ChaCha20-Poly1305, AES-GCM, BLAKE2b, scrypt (PBKDF2 read for old keys), Ed25519, SHA-256, HMAC, TOTP.
- Tests: 169k lines in 499 files. 392 import Python internals (not reusable as-is); ~107 drive the
  CLI from outside and can be pointed at the Rust binary.
- Out of tree: Cloudflare workers (`workers/`, JavaScript) are not part of the port.

## Rust architecture

Cargo workspace, one release binary:

| Crate | Replaces | Notes |
|---|---|---|
| `kv-crypto` | crypto.py, key_config, owner_key, old_key | RustCrypto (`chacha20poly1305`, `aes-gcm`, `blake2`, `scrypt`, `pbkdf2`, `sha2`, `hmac`), `ed25519-dalek`; `zeroize`/`secrecy` everywhere |
| `kv-store` | store.py, vaultfs, fssec, file_lock, structure, migration, backup, drawer_integrity, env_recovery | atomic writes, storage lock, drawer + env-bundle backends |
| `kv-config` | config.py, config_authority, setup_toml, trust, vault_origin, vault_registry | `serde_json`, `toml_edit` |
| `kv-approvals` | approval_*.py, approvals, grants, owner_approval, saved_passes, policy_requests, request_records, runtime_anchor | signed artifacts, verifier |
| `kv-proto` | control_proto, client, cap_client wire, approval_wire | framed canonical JSON + MAC handshake; fuzzed |
| `kv-broker` | providers, broker_policy, capabilities, limits | HTTP via `rustls` (no OpenSSL), SSRF guard, redirect block |
| `kv-sandbox` | sandbox.py, preflight | bwrap launch, sealed args fd, redaction, file scan; `PR_SET_DUMPABLE`, `mlock` |
| `kv-agent` | agent.py, owner_terminal, approval_channel | daemon; Unix socket / authenticated TCP on Windows |
| `kv-mcp` | kv_mcp/ | JSON-RPC over stdio |
| `kv-hook` | hook.py, hook_launcher | Bash-command analysis for the PreToolUse hook (highest-risk port) |
| `kv-cli` | cli.py, audit, dashboard, approval_page, setup_*.py, env.py | `clap`; tty passphrase prompts |

Threading: plain OS threads like the Python daemon (no async runtime) unless profiling shows a need.
Memory: secrets live in `secrecy::SecretBox` over `mlock`ed pages, zeroized on drop; core dumps off.

`kv.cap_client.api_call` is a Python library user scripts import. It stays available as a tiny
pure-Python shim package (`kv-cap-client` on PyPI) speaking the same socket protocol; the main product needs no Python.

## How parity is proven

1. **Golden vectors**: a script run against Python 0.4.0 writes fixtures (key files at every
   version, drawer vaults, env bundles, signed grants/permits, TOTP blobs, control-protocol transcripts).
   Rust must read every fixture and produce byte-identical output for deterministic inputs.
2. **Round-trip both ways**: vault made by Python → used by Rust → read by Python again, and the reverse.
3. **Black-box suite**: the ~107 CLI-level Python tests run with `KV_BIN` pointed at the Rust binary.
4. **Differential runs**: the same command sequence on Python and Rust, outputs compared (masking only run-made fields).
5. **Ported unit tests**: security-relevant cases from the 392 internal test files are re-written as Rust tests per crate.
6. **Fuzzing**: `cargo-fuzz` targets for control frames, approval wire, key headers, drawer records, hook shell parser.
7. **Supply chain**: `cargo-deny`, `cargo-audit`, pinned toolchain, reproducible release builds.

## Stages (each ends with its gate green before the next starts)

| # | Stage | Gate |
|---|---|---|
| 0 | Workspace, CI (fmt, clippy -D warnings, test, deny, audit), fixture generator against Python 0.4.0 | CI green; fixtures committed |
| 1 | `kv-crypto` + key file formats v1–v4, TOTP | all key/TOTP fixtures decrypt; Rust-written keys open in Python |
| 2 | `kv-store`: drawer + env-bundle read/write, locks, migration, backup | round-trip both ways; integrity checker matches Python |
| 3 | `kv-config` + `kv-approvals`: config, signing, verification, grants, permits | every signed fixture verifies; tampered fixtures refused identically |
| 4 | `kv-proto` + `kv-agent` core: unlock/lock/status/list/envs, owner terminal | Python client ↔ Rust daemon and Rust client ↔ Python daemon both work |
| 5 | `kv-broker`: kv_api, providers, HTTP policy, permits, cap_api, POST wallets | broker black-box tests pass on Rust |
| 6 | `kv-sandbox`: kv_run with bwrap, redaction, file scan, grants | sandbox black-box tests pass (Linux + bwrap) |
| 7 | `kv-mcp`: 10 tools, 4 profiles | MCP tests pass against Rust binary |
| 8 | `kv-hook`: Claude Code hook | hook decision tables identical to Python on the full corpus + fuzz |
| 9 | Remaining CLI: history, env management, backup, 2FA, recovery key, passphrase reset, doctor, audit, dashboard, approval page, `kv setup` editors | full black-box suite green |
| 10 | macOS + Windows platform code, release pipeline (signed binaries), install docs | CI on Linux/macOS/Windows; release dry run |

Rough size: 6–12 engineer-months, i.e. on the order of 25–50 Devin sessions; stages 4–8 are the bulk.
Stages 1–3 can start immediately after approval; 4+ depend on them.

## Proposed scope cuts (owner to confirm)

- **Remote/cloud commands** (`signup`, `login`, `push`, `pull`, `team`, `token`, drawer sync remote):
  the server is not deployed; leave them out of 0.5 and add later.
- **Parked tools** `kv_query` / `kv_ssh`: parked on v3/v4 vaults already; not ported in 0.5.
- **Old vaults** (plaintext key, v1/v2 wrapped keys): Rust reads them only to upgrade them (`kv upgrade-security`), never writes them.

## Conventions

- Branches `devin/<timestamp>-<slug>`, one PR per stage (or sub-stage), no direct pushes to `main` after the first commit.
- The Python repo is not modified by this work.
