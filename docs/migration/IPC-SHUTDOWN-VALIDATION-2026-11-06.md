# IPC/shutdown validation — 6 November 2026

Product commit: `d4ad2d5f60514fd60199995a8b05c3185609b4fd`, on
`codex/daemon-deadlines-shutdown`. Its base is PR #15 head
`14e5cf5e192897a16ddd750465f5bf0ceb52d94e`. PR #15's
[GitHub run](https://github.com/Kv-Secrets-2/Kv-Rust-Mig/actions/runs/42267410063)
passed all eleven checks; that evidence does not validate this new slice.

The Python source pin remains `9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`.
Each final gate attested all 79 Python source files, cryptography 50.0.2,
the committed Rust source, and a clean worktree. This subsequent documentation
update does not change product or test code.

## Reproduced baseline failures

An isolated worktree at the unchanged PR #15 head ran the new tests copied from
this slice. Its Cargo target directory was separate from the fixed checkout.

- A complete valid status reply whose peer kept the socket open was incorrectly
  reported as not running after the two-second wait. The public MCP probe
  regression failed before the fix and passes afterward.
- All five new shutdown comparisons failed on the baseline after the Python
  legs completed. Non-string stop choices incorrectly stopped the daemon;
  in-flight provider scenarios returned a fixed zero-cutoff stop answer instead
  of awaiting the owner's choice; SIGTERM with idle clients did not exit within
  the test's five-second idle-cleanup bound.

The fixed target passes the same comparisons, including real HTTPS provider
requests, the production ten-second cutoff in both languages, wait completion,
retirement refusals, and a delayed URL-safety check with no outbound send after
retirement. Tests use separate child-process homes and temporary test-only CAs.

An independent transport review additionally reproduced two malformed-UTF-8
diagnostic differences: MCP's exception class and the byte range reported for an
invalid continuation. Both are fixed and covered by focused regressions. The
review checked 119,607 numeric-prefix inputs against Python without finding an
additional framing difference.

## Final local gates

Linux, Rust/Cargo 1.97.1, locked release builds, production KDF parameters,
`TMPDIR=/var/tmp`, serial tests within each executable, and `tini -s` reaping.

| Python runtime | Mode | Rust test cases | Required comparisons | Reverse crypto |
|---|---|---:|---:|---|
| 3.10.22 | Canonical | 177 passed | 35 passed | Passed |
| 3.11.17 | Semantic | 177 passed | 35 passed | Passed |
| 3.12.14 | Semantic | 177 passed | 35 passed | Passed |
| 3.13.16 | Semantic | 177 passed | 35 passed | Passed |

No discovered tests were ignored and no required comparison was skipped. Test
counts include harness/helper entry points, not independent feature counts.
The canonical Unicode table check also passed. The lifecycle module covers
deadline shortening/expiry, admission races, stable cutoff accounting,
connection closure, worker reclamation, pin ownership, and reaper-spawn failure.

Additional checks passed: formatting; workspace/all-targets/all-features Clippy
with warnings denied; 14 gate negative controls; workspace doctest command
(zero executable doctest cases); `git diff --check`; `cargo-deny` advisories,
bans, licenses and sources; and `cargo-audit` with zero known vulnerabilities.
The pre-existing unmaintained `rustls-pemfile` advisory remains. No external
dependency versions changed.

## Evidence and limits

Retained reports are under `/workspace/migration-shutdown-validation/`:
`{canonical-final,semantic-311-final,semantic-312-final,semantic-313-final}/`
contain complete reports and per-target logs. Baseline evidence is
`baseline-status.log` and `baseline-shutdown-isolated.log`; focused fixed runs
are `fixed-status-clean.log` and `fixed-stage6.log`.

Earlier fixture-setup failures, overlapping build-cache attempts, and the
environment-restart interruption are retained separately and are not counted
as product validation. Reproduction activation is
`/workspace/migration-shutdown-validation/activate.sh`; portable gate commands
are in [PARITY.md](PARITY.md).

Native macOS/Windows execution and GitHub Actions for this new commit remain
pending publication of its pull request. macOS socket APIs were source-reviewed,
not locally executed. Branch protection and release artifacts are not certified
by these local results. See [IPC-SHUTDOWN.md](IPC-SHUTDOWN.md) for the intentional
per-read timeout behavior and retained-worker limits; this slice does not claim
the rest of the migration is complete.
