# Linux API permit validation — 6 November 2026

Branch: `codex/api-one-call-permits`, stacked on audit PR #17 at
`ccaf3f80b96ef5f155fd82ae9e87867a1e6977b0`. Product implementation:
`30e214a`. Test-only Python 3.13 follow-up: `ede775c`.
The Python reference remains unchanged at
`9a497d91a0f6e95b0949deaf8f5c431f9a4333c0` (0.4.0).
See [API-PERMITS.md](API-PERMITS.md) for behavior, scope and deliberate differences.

## Full Linux gates

| Python | Mode | Tests passed | Required comparisons | Tested revision |
|---|---|---:|---:|---|
| 3.10.22 | canonical | 288 | 66 | `30e214a` |
| 3.11.17 | semantic | 288 | 66 | `30e214a` |
| 3.12.14 | semantic | 288 | 66 | `30e214a` |
| 3.13.16 | semantic | 288 | 66 | `ede775c` |

Every lane attested the pinned reference commit, clean checkout, installed source
hashes, package/runtime versions and a clean Rust worktree. Every discovered test
passed without ignored tests or missing comparison markers. Counts include shared
harness checks and subprocess helper entry points; 66 is the number of required
comparison test functions, each potentially exercising many cases. Reverse Rust
crypto interoperability passed in every lane; the canonical lane also checked the
complete Unicode 13 digit table. Rust was 1.97.1 and cryptography was 50.0.2.

The first Python 3.13 run failed only the facts helper's uppercase IPvFuture URL
case. Python 3.13 accepts `https://[VF.example]/`, while canonical 3.10 refuses it.
Commit `ede775c` changes tests and documentation only: it asserts both exact
outcomes and adds broker checks proving both IPvFuture spellings are refused
before preview, callbacks or connection. All 20 approval-crate tests, including
five live comparisons, passed again with the updated workspace-built executable
on all four interpreters. The affected broker check passed separately. The full
3.13 gate then passed at `ede775c`; the other three complete reports remain at
`30e214a`, whose production code is identical.

## Focused coverage and checks

The daemon's 33 unit tests passed, including atomic charge/stop ordering, held
trust pins, and signed owner answers prepared before a hard-lock latch. The new
daemon target passed 13 tests: nine mandatory live Python comparisons, three
shared harness tests and one subprocess helper. Python's owner client verifies
the signed review/acknowledgment and approves real HTTPS requests against each
backend. Coverage includes exact one-send success, concurrent retries, altered
calls and signed bindings, replay, preflight versus transport failure, stop
before/after commit, query authentication masking, complete-preview refusal,
audit attribution/chain integrity, no persisted permit/body data, restart,
unprotected sessions and protected approval mode.

Registry tests cover capacity/pruning, first monotonic deadlines, clock rollback,
idempotent registration, no refund, independent exported facts and atomic spending.
Broker tests compare preparation with Python and exercise real TLS callback order
and guard lifetime. Serialization checks cover DEL, Unicode, decimal rounding,
large integers and overflowing floats. Requester field comparisons preserve the
canonical Unicode classification and check withholding/truncation behavior.

Formatting, strict workspace/all-targets/all-features Clippy, 14 parity-gate
controls, workspace doctests (zero executable cases), and whitespace checks passed.
Cargo-deny passed advisories, bans, licenses and sources. Cargo-audit found no known
vulnerabilities and reported the existing unmaintained `rustls-pemfile` advisory.
No external dependency versions changed.

The first daemon run exposed two fixture mistakes against Python: treating its
runtime metadata log as persisted permit state, and expecting an ordinary success
reply after shutdown admission had closed. Corrected tests separately check the
runtime log for permit/body/credential leakage and require exact hard-lock replies,
while retaining outbound count and drain assertions. A first doctest command hit
the environment's read-only `/var/tmp`; its supported `/tmp` rerun passed. These
initial failures are retained and are not counted as passing runs.

## Evidence and limits

Reports are under `/workspace/migration-permit-validation/`, in the four
`*-final/report.json` files with build/discovery/test logs. The first 3.13 failure
is retained in `semantic-313-first/`. Focused logs include
`daemon-permits-first.log`, `daemon-permits-final.log`,
`approvals-followup-310.log` through `approvals-followup-313.log`,
`broker-ipvfuture-boundary.log`, `clippy-followup.log`, `gate-controls.log`,
`doctests-final.log`, `deny.log`, and `audit.log`. Portable gate commands are in
[PARITY.md](PARITY.md); local activation is `activate.sh` in the validation folder.

Linux is the current focus. The HTTPS tests use a test CA and a controlled safety
seam; they do not prove complete production DNS/rebinding behavior. The fixed
1,000-container JSON review bound and interpreter-specific malformed URL case
are documented differences, not claims of exact equality. Rust owner CLI,
capability calls, POST wallets, sandbox/run and pause controls remain deferred.
These results do not establish native macOS/Windows acceptance, release readiness,
or completion of the whole migration. No PRs were merged during this slice.
