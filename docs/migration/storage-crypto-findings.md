# Storage and crypto baseline findings

Reviewed Rust commit `3a9c3c7d1cc9ee34ab801ff02ffb64114561dc16` against Python reference `9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`. Paths and line numbers below refer to those commits. This was a bounded source review; the root agent separately reproduced the passphrase discrepancy. No repository files were changed by this review.

## Confirmed compatibility defect: Unicode passphrase classification

`crates/kv-crypto/src/lib.rs:801` uses `char::is_numeric`; Python `kv/crypto.py:957` uses `str.isdigit()`. These predicates differ for Unicode numbers such as Roman numerals and fractions. The external probe in `logs/passphrase-probe.log` confirms:

| Input | Python | Rust |
| --- | --- | --- |
| `12345678901Ⅻ` | accepted | rejected as all-digit |
| `12345678901½` | accepted | rejected as all-digit |
| `123456789012` | rejected as all-digit | rejected as all-digit |

Rust is stricter in these examples; this is a compatibility defect, not evidence of weakened password validation.

Acceptance: differential cases for ASCII digits, Unicode decimal digits, superscript digits, Roman numerals, fractions, mixed alphabetic input, repeated characters, and the 12/16-character boundaries must match Python's result and message. Keep fixture expectations sourced from the pinned reference.

## Confirmed implementation gap: secret copies escape zeroizing storage

`crates/kv-store/src/lib.rs:1093` converts a `Zeroizing<String>` secret into an ordinary `String`. `copy_env_checked_locked` holds source and destination secrets in ordinary `BTreeMap<String, String>` values at lines 865–866, and `plan_copy` clones plaintext values again at lines 144 and 161. These allocations have no zeroizing drop behavior on successful completion or early errors. The source-level lifetime gap is confirmed; no allocator-memory recovery experiment was performed.

Related copies occur in `crates/kv-crypto/src/lib.rs`: recovery generation produces ordinary `encoded`/`grouped` strings at lines 574–580; parsing builds ordinary `normalized`/`padded` strings at lines 590–596; passphrase-strength checking allocates an ordinary normalized passphrase at line 784. This is separate from the already identified absence of locked secret memory.

Acceptance: define a secret-owner type whose drop wipes the allocation; carry it through copy planning and recovery parsing without ordinary plaintext clones. Verify cleanup through an owned instrumented buffer on success, rejection, and injected error paths, without reading freed memory. Review all plaintext conversions and recovery output ownership. Keep vault and recovery formats unchanged. Explicitly track locked-memory work separately.

## Static race risk: lock name and opened descriptor can diverge

`crates/kv-store/src/fsx.rs:492–548` checks the storage-lock name, opens it, then verifies only that the opened file is regular before locking it. The config-lock path repeats this at lines 572–626. Python `kv/file_lock.py:113–121` additionally compares the opened descriptor's device/inode with the current named file and refuses a changed name.

The missing identity check is confirmed by inspection. A replacement between opening and locking could leave one writer locking an obsolete inode and another locking the replacement. This has not been reproduced, and arbitrary noncooperating filesystem writers require a defined threat model; do not describe it as a demonstrated exploit.

Acceptance: a deterministic barrier test replaces each lock name between open and validation; the operation must refuse before mutation. Test a parent-directory replacement separately, and verify ordinary concurrent writers still serialize. Specify whether replacement while waiting for a lock is in scope and test that contract explicitly.

## Static race risk: pathname-based permission repair and publication

`crates/kv-store/src/fsx.rs:53–86` checks directory metadata, then uses pathname-based `set_permissions`, which follows a link introduced after the check. Atomic writes allocate temporary files through a pathname at lines 439–440 and publish through pathname-based hard-link/rename calls at lines 464–469. `ensure_env_tree` checks components individually at `crates/kv-store/src/lib.rs:1533–1542`; those checks do not retain directory identities for later operations.

A concurrent directory replacement could redirect permission changes or publication. These are source-level race risks, not reproduced failures. Record deletion and tree clearing already use descriptor-relative traversal, so this finding does not apply equally to every filesystem operation.

Acceptance: deterministic component-swap tests must show that an outside sentinel directory/file is never chmodded, created in, overwritten, or removed. Verify refusal or completion against a retained intended-directory descriptor, private temporary-file modes, cleanup after failure, and both exclusive/nonexclusive publication. Use no-follow descriptor-relative operations for the chosen contract.

## Review limits and observed protections

Regular-file reads are bounded and use `O_NOFOLLOW | O_NONBLOCK` plus descriptor/name identity comparison on Unix. Destructive record operations traverse with directory descriptors. Key location authentication and local provenance/config-authority checks exist. These observations do not establish complete security or platform parity.

Windows/macOS permission behavior, full backup transactional semantics, dependency internals, and every error path were outside this short review. Recommended plan changes are explicit secret-lifetime and deterministic filesystem-race acceptance gates before storage/memory milestones are declared complete.
