# Stage 9a: kv-secrets' own CLI tests against the Rust binary

kv-secrets 0.4.0 ships 281 CLI tests in `tests/test_cli.py`. They were run against the
Rust `kv` (release build) on 2026-11-07 with the shim in
`crates/kv-cli/tests/support/python_shim.sh`, which makes `sys.executable -m kv` and the
tests' pseudo-terminal launcher start the Rust binary while pytest itself keeps running
on the reference interpreter. Raw result: 147 passed, 151 failed. The raw numbers mean
little on their own, because most of the suite does not exercise what this build
supports. Verdict per test class:

| Class | Tests | Fixture / subject | Verdict |
|---|---|---|---|
| TestCLIAuthRetries | 3 | passphrase vault; wrong-passphrase retries | **3 passed** |
| TestCLIInit | 29 | in-process `cli.main()` with mocked `input` | omitted: tests the Python module in-process, never a binary |
| TestCLISecretCRUD | 10 | `init_legacy_plaintext_project` (plaintext key, `.enc` bundles) | omitted: legacy vaults are not supported ("no old vaults") |
| TestCLIExportImport | 7 | legacy plaintext project | omitted: legacy vaults |
| TestCLIEnvironments | 3 | legacy plaintext project | omitted: legacy vaults |
| TestCLIVaultMigration | 67 | legacy plaintext project; `migrate-drawers` and friends | omitted: migration commands are not ported |
| TestCLIExportImportKey | 3 | legacy plaintext project; `export-key`/`import-key` | omitted: legacy vaults; Stage 9b commands |
| TestCorruptedConfigAdvice | 1 | legacy plaintext project | omitted: legacy vaults |
| TestCLISecurityPolicy | 15 | legacy plaintext project; `policy`, `allow`/`deny` | omitted: Stage 9b commands |
| TestCLIGrant | 19 | legacy plaintext project; `grant` | omitted: Stage 9b commands |
| TestCLIApprovals | 17 | legacy plaintext project; `approvals` | omitted: Stage 9b commands |
| TestCLIProviders | 24 | legacy plaintext project; `provider` | omitted: Stage 9b commands |
| TestCLIDiagnostics | 21 | legacy plaintext project; `doctor`, `audit` | omitted: Stage 9b commands |
| TestMCPProfileDisplay | 4 | `setup` output | omitted: Stage 9b commands |
| TestCLIAgentCodeScan | 4 | `preflight`/`run` | omitted: Stage 6 |
| TestCLIPreflight | 12 | passphrase vault; `preflight` | omitted: Stage 6 |
| TestCLIRun | 18 | `run` | omitted: Stage 6 |
| TestCLI2FA | 14 | passphrase vault; `2fa`, `setup-2fa` | omitted: Stage 9b (this build refuses TOTP vaults at unlock) |
| TestCLIRecovery | 6 | passphrase vault; `recover`, `passphrase reset` | omitted: Stage 9b commands |
| TestCLIRecoveryKey | 1 | passphrase vault; `recovery-key` | omitted: Stage 9b commands |
| module-level ctty tests | 6 | the Python launcher's own controlling-terminal probe | omitted: tests the Python test harness |

So of the 281 tests, 3 apply to this build and pass; 278 are omitted, each for one of the
reasons above. Tests in omitted classes that happen to pass against the Rust binary
(for example a refusal that both implementations word alike) are not counted as
evidence. None of the 151 failures is a failure of an in-scope command.

What covers the Stage 9a commands instead:

- `crates/kv-cli/tests/cli_blackbox.rs`: exit codes and argparse-identical help/usage
  errors without a terminal; the whole owner flow on a pseudo-terminal (init, set/get/ls/
  rm/export, every `history` action, every `env` action, `backup create/show/restore`,
  `vault approve-config`, `unlock`/`unlock` again/`status`/`lock`/`lock` again) with the
  passphrase never echoed; and, with `KV_PY_REF` set, the same script through kv-secrets
  0.4.0 with byte-identical output after normalising timestamps, paths, PIDs, digests,
  key ids and recovery keys. The daemon steps run in release builds only: in a debug
  build the Argon2 derivation does not fit the 10 s background-start bound.
- Cross-implementation checks done by hand during the stage and kept as the parity
  contract: vaults, backups and `approve-config` records made by one implementation
  open in the other; Python's `kv status`/`kv lock` operate the Rust daemon and Rust's
  operate the Python daemon.

Deliberate differences from Python 0.4.0 in this stage:

- `kv history ...` on an environment that is not registered is refused
  (`environment 'X' does not exist`); Python operates on the drawer files anyway.
- `kv env repair-names`, `kv vault` actions other than `approve-config`, `kv unlock
  --install` and two-factor unlock are refused with a message naming the reason: they
  exist for pre-drawer or passphrase-less vaults, or belong to a later stage.
- `kv unlock` starts the daemon as a detached child process of the same binary
  (`kv __agent-child`, passphrase handed over on stdin) instead of `fork()`, because the
  workspace forbids unsafe code; the 10 s start bound and the refusal channel are kept.
- `kv status` has no sandbox-detection branch ("agent connection blocked by sandbox"),
  always reports drawer sync as not initialised (remote sync is out of scope) and counts
  the approval inbox from `.secrets/approval_requests.json` directly.
