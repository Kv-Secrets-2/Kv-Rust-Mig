# Parity slice validation — 6 November 2026

Implemented on `codex/migration-baseline-audit`, based on Rust commit
`3a9c3c7d1cc9ee34ab801ff02ffb64114561dc16`. These results validate the local
working-tree changes, not the unchanged baseline commit. The owner approved the
slice, selected Python 3.10 as the canonical transcript runtime, and selected
Unicode 13 for digit classification.

## Changes

- Four required Linux parity lanes attest the Python 0.4.0 source pin and require
  all 29 recorded comparison tests to be discovered and pass with a validated
  reference marker. Missing, invalid or skipped references fail the gate.
- Source hashes come from pinned Git blobs. Negative controls demonstrate that
  `assume-unchanged` and `skip-worktree` edits cannot change the reference silently.
- Rust's passphrase digit predicate now matches Python 3.10 `str.isdigit()`;
  Roman numerals and fractions no longer cause the incorrect all-digit refusal.
- Unix socket fixture names fit independently of PID width. MCP subprocess
  checks validate exit status and have bounded collection. Semantic lanes
  normalize only the reviewed integer-conversion error wording difference.
- No external Rust dependency versions changed. `kv-test-support` is a new local
  test-only crate. Product changes are limited to the digit predicate.

## Results

Linux, Rust/Cargo 1.97.1, locked release builds, production KDF settings,
`TMPDIR=/var/tmp`, serial tests within each executable, `tini -s` process reaping.
Every lane attests all 79 Python source files from the installed reference and uses
cryptography 50.0.2.

| Reference runtime | Mode | Rust test cases | Required comparisons | Reverse crypto |
|---|---|---:|---:|---|
| CPython 3.10.22 | Canonical | 140 passed | 29 passed | Passed |
| CPython 3.11.17 | Semantic | 140 passed | 29 passed | Passed |
| CPython 3.12.14 | Semantic | 140 passed | 29 passed | Passed |
| CPython 3.13.16 | Semantic | 140 passed | 29 passed | Passed |

No discovered tests were ignored and no comparisons were skipped. Test counts
include helper entry points and repeated shared-harness controls; they are not
independent feature counts. The digit comparison exercised 947 passphrases in
each lane. The canonical generator exhaustively checked all code points and
confirmed 778 digits in 80 ranges.

Additional validation:

- Gate negative controls: 14 passed.
- Formatting, Clippy for all workspace targets with warnings denied, and
  `git diff --check`: passed.
- Workspace doctest command: passed; no executable doctest cases exist.
- `cargo-deny` 0.20.2: advisories, bans, licenses and sources passed; existing
  duplicate-version warnings remain.
- `cargo-audit` 0.22.2: zero known vulnerabilities; existing unmaintained
  `rustls-pemfile` notice `RUSTSEC-2025-0134` remains.
- Workflow YAML parsed; the four parity lanes have no optional success path.

## Retained evidence and limits

Reports and per-target logs are under
`/workspace/migration-parity-validation/{canonical-final,semantic-311,semantic-312,semantic-313}/`.
Other validation logs are under `/workspace/migration-audit/logs/`, prefixed
`parity-` or `new-`. The canonical gate was rerun after the source-attestation
review fix. See [PARITY.md](PARITY.md) for portable reproduction instructions.

Validation ran locally on Linux. Remote GitHub Actions, branch protection,
native macOS/Windows execution, static release binaries, fuzzing and signing
were not validated or configured by this slice. The workflow changes must be
published before GitHub can execute them. Repository rulesets must require its
checks to prevent merging a failing workflow.

After local validation, the owner configured `KV_REFERENCE_READ_TOKEN` as a
repository Actions secret. The workflow now uses it only for the pinned Python
reference checkout, with credential persistence disabled. This supports a private
reference repository. The credential wiring was checked locally; its actual
GitHub permissions and organization approval remain unverified until CI runs.

The remaining migration scope and IPC, audit-file, memory-lifetime and storage
race findings remain in the [baseline audit](BASELINE-2026-11-06.md). Passing
frontend parity does not complete missing backend authorization or execution.
