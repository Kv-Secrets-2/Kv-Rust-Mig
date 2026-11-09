# kv-audit

Unix audit writer for the existing Python 0.4.0 record contract, pinned at
`Kv-Secrets-2/kv-secrets@9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`.
The daemon integration is separate from this crate. This does not add event
coverage, a Windows writer, or new audit CLI commands.

Create one `Audit` for the process's `~/.kv` directory and clone it for producers.
`emit(event, ordered_fields)` returns `Ok(())` or a closed `LossReason`. An audit
failure leaves the completed action in effect. Metadata must exclude secrets and
request/response bodies; the writer applies Python's attribution sanitization.

`take_warning()` leases a fixed warning. Attach it only to an opted-in unsigned
reply after selecting its final bounded form. Call `delivered()` after successful
delivery. Dropping the lease returns it when serialization, bounding, retirement,
or transport prevents delivery. `WarningChannel::Stderr` additionally prints each
warning kind once per invocation. `health()` is read-only.

Cooperating Python and Rust writers use the same descriptor-relative files:

- `audit.lock`: serializes tail/hash/append and the following health update.
- `audit-health.lock`: serializes loss-count publication.
- `audit-health.json`: bounded atomic state record; counts can be unknown.
- `audit-health.unkept`: a loss count could not be kept reliably.
- `audit.uncertain`: a held log lock was replaced; never automatically cleared.

The unkeyed chain detects some corruption, not deletion or rewriting by a process
with the same filesystem authority. Lock identity checks detect observed
replacement, not a swap and restoration between checks. Ordinary log appends are
flushed without a durability guarantee, matching Python; health publication and
uncertainty markers sync their contents and directory. Marker persistence is
best effort when the filesystem refuses it.

Serialization preserves field order and literal Unicode. Live differential tests
use `KV_PY_REF`; `KV_PARITY_REQUIRED=1` makes a missing reference fail. Cross-process
tests share the actual lock files with Python rather than approximating flock
with a Rust-only mutex.

Only `repr()` of a string nested inside a malformed non-string historical hash
uses a frozen Unicode 13.0.0 printability table, matching canonical CPython 3.10.
Its exhaustive inventory check is canonical-only; it does not assert newer
Unicode classifications are identical. Ordinary event strings and valid string
hashes retain literal Unicode and do not use that table. Python's nonfinite JSON
literals are supported locally when reading audit files; wire parsing is unchanged.

One malformed-input exception is deliberate: Python's `_health_record_valid`
accepts an object missing `lost`, but its public `audit_health()` then raises
`KeyError('lost')`. Rust rejects that incomplete record as untrusted and reports
an unknown count. It does not report zero or panic. Valid health records retain
the reference contract.
