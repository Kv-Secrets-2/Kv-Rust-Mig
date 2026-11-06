# Audit writer validation — 6 November 2026

Product commit: `c8870458a599302879bdca11753ac5b39be8cfa4`, on
`codex/audit-log-safety`, based on PR #16 at `0669744`. The pinned Python source
remains `9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`.
See [AUDIT-SAFETY.md](AUDIT-SAFETY.md) for the contract and limits.

## Reproduced baseline defect

An isolated worktree at unchanged IPC commit `0669744` ran only
`daemon_audit_refusal_warns_only_opted_in_replies_like_python`, copied from the
new slice. It used its own Cargo target directory, production KDF parameters,
the required Python 3.10 reference, and the same local HTTPS fixture.

The Python leg completed. The baseline Rust leg failed the assertion that an
unrelated symlink target retained its contents: an `api_call` JSON record had
been appended after the sentinel. This was an executed regression failure,
not a setup failure. The replacement passes the same test and preserves both
target contents and mode while the provider action succeeds. F3 is therefore
reproduced at the IPC baseline; the original audit snapshot remains historical.

F4's old implementation remains a source-confirmed process-local-lock finding.
The replacement is tested with a 163-record alternating/concurrent Python/Rust
chain, real shared lock contention, and exact loss counts. That establishes the
new implementation's interoperation without claiming an executed old-code race.

## Full local gates

Each gate attested all 79 pinned Python source files, cryptography 50.0.2,
the product commit above, and a clean Rust worktree. Linux validation used
Rust/Cargo 1.97.1, locked release builds, serial tests within each executable,
short private fixture paths under `/var/tmp`, and `tini -s` process reaping.

| Python | Mode | Rust tests | Required comparisons | Reverse crypto |
|---|---|---:|---:|---|
| 3.10.22 | Canonical | 235 passed | 48 passed | Passed |
| 3.11.17 | Semantic | 235 passed | 48 passed | Passed |
| 3.12.14 | Semantic | 235 passed | 48 passed | Passed |
| 3.13.16 | Semantic | 235 passed | 48 passed | Passed |

No discovered tests were ignored and no required comparison was skipped.
Counts include helper entry points, not independent features. The canonical
Unicode table check passed. The new inventory comprises 12 audit-library
comparisons and one daemon comparison in addition to the 35 IPC-era comparisons.

Formatting, workspace/all-targets/all-features Clippy with warnings denied,
14 parity-gate controls, workspace doctests (zero executable cases), and
`git diff --check` passed. `cargo-deny` passed advisories, bans, licenses and
sources. `cargo-audit` reported zero known vulnerabilities and the existing
unmaintained `rustls-pemfile` advisory. No external dependency versions changed;
the audit crate enables serde_json's `float_roundtrip` feature, covered by the
full workspace gates.

Focused tests cover unsafe names and held-directory replacement, shared locks,
health corruption and recovery, close failures, warning leases, signed/control
reply exclusions, response limits, and retirement replacements. The deliberately
conservative missing-`lost` health exception retains a live reproduction of
Python's `KeyError`; it is documented as a divergence, not exact parity.

## Upstream transport-test integration

Merge `fb9dc26` brings PR #16's later CI diagnostics and synchronized transport
fixtures into this branch. Relative to the fully tested product commit, the
only crate change is inside `kv-proto`'s test module; production transport bytes
and all audit implementation files are unchanged. All 12 protocol tests passed
again with the audit JSON feature configuration and required Python reference.
A separate deliberate deadline-renewal mutation failed the synchronized test,
then the restored source passed. Logs are `transport-integration.log` here and
`transport-reset-deadline-mutation.log` under the IPC validation directory.

## Evidence and limits

Reports and logs are retained under `/workspace/migration-audit-safety-validation/`.
The four `*-final/report.json` files identify the attested revision and completed
inventory. `baseline-daemon-audit.log` contains the old-code failure;
`daemon-warning.log` contains the focused passing comparison. Local activation is
`activate.sh` in that directory; portable gate instructions are in
[PARITY.md](PARITY.md).

Initial documentation/dependency commands encountered the command sandbox's
read-only temporary directory and network restrictions. Their supported-mode
reruns passed; setup failures are not counted as product failures or successes.

The parent IPC PR #16 at `2be1f69` subsequently passed all eleven GitHub checks,
including native Linux/macOS/Windows and all four Python parity lanes:
[CI run 42280696008](https://github.com/Kv-Secrets-2/Kv-Rust-Mig/actions/runs/42280696008).
That parent result does not validate this new audit crate. Native macOS ACL
execution and GitHub Actions for this audit branch remain pending its pull request. Linux evidence does not certify those platforms,
branch protection, release artifacts, or the remainder of the migration.
