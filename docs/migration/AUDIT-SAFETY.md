# Audit filesystem and serialization migration

This slice replaces the Unix daemon's existing `api_call` audit writer with
[`kv-audit`](../../crates/kv-audit/README.md) and delivers pending audit warnings
at its ordinary reply boundary. The reference is Python 0.4.0 at
`9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`, principally `kv/audit.py`,
`kv/fssec.py`, and the daemon's `_send` wrapper in `kv/agent.py`.

Historical [F3/F4](implemented-path-findings.md) remain **source-confirmed** findings
at baseline `3a9c3c7`: audit opens followed paths, and a local mutex did not serialize
other processes. The new regression tests exercise the replacement implementation;
they do not establish an executed reproduction against the old baseline. This
record covers a focused migration slice, not a complete security audit.

## Compatibility and failure policy

The reference policy is to **drop, count, and warn**, while allowing the action
itself to proceed. Audit failure after a provider request does not rewrite its
successful result. No append occurs without the shared log lock. Closed failure
reasons are `folder_refused`, `file_refused`, `write_failed`, `lock_unavailable`,
and `lock_unsupported`; warnings contain fixed text rather than paths or exceptions.

Records retain Python's field order, compact Unicode JSON, numeric spelling,
and truncated SHA-256 chain format. Timestamps are sampled after lock acquisition
and predecessor lookup. Tail reads are bounded and an invalid last nonblank line
returns `genesis`, without selecting an older valid record. Attribution fields
receive Python trimming, length limits, allowlisting, and credential-shaped text
withholding. Producers must still exclude secrets and bodies; withholding is
best effort. Arbitrary-size integer counts and nonfinite JSON literals are retained.
Nonfinite handling is local to audit reads and does not extend wire parsing.

Only `repr()` of strings inside a malformed non-string historical hash uses frozen
Unicode 13.0.0 printability. Its exhaustive inventory matches canonical Python 3.10;
newer runtimes compare stable classifications. Ordinary event strings and valid
string hashes retain Unicode without that table.

## Filesystem, locking, and health

Each emit holds one owned, checked directory descriptor. Child operations remain
relative to it if its name is replaced. Directory ownership is checked before
hardening to `0700`. Children use no-follow, nonblocking, close-on-exec opens;
logs and locks must be regular single-link files, hardened to `0600` before writes.
macOS additionally removes extended ACLs through descriptors, even when modes
already look private. Links and FIFOs cannot redirect writes or block file opens.

Lock order is local mutex → `audit.lock` → `audit-health.lock`. Python and Rust
share these names and flock protocol. Each flock acquisition has one two-second
retry budget. The log lock covers tail/hash/append and the following health update.
Acquisition rechecks the lock's named device/inode; replacement retries within the
original budget. Post-append replacement leaves durable order uncertainty. These
budgets do not make general filesystem I/O or local mutex waits cancellable.

| Sidecar | Contract |
|---|---|
| `audit-health.json` | Validated, at most 4096 bytes; exclusive temp, file sync, rename, directory sync |
| `audit-health.unkept` | Count uncertainty; only successful locked publication can clear it |
| `audit.uncertain` | Observed log-lock replacement; anything at the name counts, never automatically cleared |

Counts remain lower bounds; unknown coverage stays `lost: null`. Health-lock
failure attempts an unknown-count publication and leaves the unkept marker.
Read-only health snapshots create or modify nothing. Marker persistence failure
queues a separate warning. Log appends retain Python's lack of per-record fsync;
write and delayed close errors produce `write_failed`. Health close errors prevent
publication and mark uncertainty. Explicit close consumes the descriptor once.

## Warning delivery and malformed-health exception

One warning is owed per failure transition; recovery does not discard it. Ordinary
object replies may consume one only for JSON `audit_warning: true`, after final
bounding or retirement replacement. Size overflow, serialization, partial-write,
and flush failures retain the warning through a lease. Signed owner replies and
enforcement/stop controls leave it pending. Cloned writers share state; the library
also offers once-per-invocation stderr delivery for future command callers.

Python accepts health records missing `lost`, then raises `KeyError('lost')` while
reading them. Rust deliberately treats that malformed shape as untrusted and
reports an unknown count; later publication preserves `lost: null`. The live test
`missing_lost_health_is_untrusted_despite_python_reference_exception` retains the
Python reproduction and separately verifies this approved exception.

## Focused evidence and limits

Linux focused runs passed **46 crate tests and 12 live Python comparisons** under
both Python 3.10 and 3.13, including shared harness checks. Coverage includes exact
record bytes/hashes, approximately 4100 numeric cases, a 163-record mixed-writer
chain, real lock contention, unsafe targets, health corruption/recovery, overflow
floats, lock replacement, close failures, and marker failures. **11 daemon unit
tests and one live daemon comparison** passed, covering the actual reply boundary,
opt-in, response limits, signed/control exclusions, retirement, and an unchanged
symlink sentinel while provider requests still succeed. Crate formatting and strict
Clippy passed. The full workspace gate for this slice is pending; these focused
results do not substitute for it. Native macOS ACL tests are included but were not
executed locally. See [PARITY.md](PARITY.md) for reference setup and inventory.

This adds no new event coverage, Windows writer, audit/doctor CLI, permits, or
capabilities. The chain remains unkeyed and cannot prevent same-account rewriting
or suffix deletion. Advisory identity checks cannot detect every swap-and-restore
between checks. Marker persistence is best effort when writes or syncs are refused.
