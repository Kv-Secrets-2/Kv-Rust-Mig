# kv-audit

Unix audit storage for two explicit chain modes:

- `Audit::new` is the legacy Python 0.4.0-compatible writer pinned at
  `Kv-Secrets-2/kv-secrets@9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`.
  It remains for migration interoperability and uses the reference's truncated,
  unkeyed hash spelling.
- `Audit::with_authenticated_chain` writes the versioned v1 authenticated chain
  described below, and `AdmissionJournal` adds its fail-closed privileged
  admission/outcome lifecycle. The broker integration that selects either mode
  is outside this crate and is not yet wired.

## Authenticated v1 chain

Each record is one canonical compact JSON object followed by `\n`. Object keys
are sorted recursively by UTF-8 bytes, JSON has no insignificant whitespace,
numbers use the crate's deterministic Python-compatible spelling, every line is
at most 1 MiB, and container nesting is at most 127 deep. The verifier requires
exact canonical bytes; reordered keys, extra whitespace, duplicate-key ambiguity,
or another noncanonical spelling is
corruption even when the semantic JSON value is unchanged.

Top-level `ts` and `event` are broker-owned strings. Caller metadata must not
use `ts`, `event`, or the reserved top-level `chain` key. The chain object is
exactly:

```json
{"hash":"<64 lowercase hex>","prev":"<64 lowercase hex>","seq":1,"v":1,"vault":"<64 lowercase hex>"}
```

`seq` is one-based and contiguous. `prev` is the previous record head; the
genesis head is 32 zero bytes encoded as 64 zero hex characters. `vault` is the
full-width SHA-256 digest of the broker-supplied opaque vault identity bytes.
Only that digest appears in the log. The identity must be stable and unique to
the vault, but it is not a secret and must not reuse key material.

`hash` is a full-width HMAC-SHA256 tag, not a truncated digest. With `u64be(x)`
meaning the eight-byte big-endian unsigned encoding of `x`, its preimage is:

```text
"kv-audit-chain-v1\0"
|| u64be(len(identity)) || identity
|| u64be(sequence)
|| u64be(len(previous_head)) || previous_head
|| u64be(len(content_json)) || content_json
```

`sequence` has no length frame because it is already fixed-width; every variable
field does. `content_json` is the canonical JSON of the complete record content
excluding `chain`. Changing record content, metadata, order, vault identity,
sequence, or predecessor changes the tag. The chain key must be 32 bytes and is
zeroized by `ChainKey` on drop.

## Required trust state

Verification and authenticated append require a complete `ChainTrust` tuple:

1. the secret chain key;
2. the broker-supplied vault identity bytes; and
3. an independently trusted expected head/count (`ChainPosition`).

Passing no trust tuple returns `missing_trust_state`; it never means valid
history. A missing or empty log is valid only for trusted genesis (`count: 0`
and the zero head). With a nonzero trusted count, that same missing log is a
continuity loss.

The writer authenticates the durable tail and compares its head/count with the
trusted position before encoding a new record. A rollback, partial tail,
corrupt tail, or externally valid append not reflected in the trusted position
fails closed for audit purposes and does not append. Successful appends advance
the writer's in-memory position. Publishing that position to independent,
durable broker-owned trust state is deliberately an integration responsibility
outside `crates/kv-audit/`.

Tail comparison is a continuity gate, not a full-history scan: an in-place edit
to an older record does not change the untouched tail. `AdmissionJournal`
therefore performs the complete scan below before every lifecycle write. The
lower-level authenticated writer remains available for non-lifecycle use and
still relies on the verifier API or command when complete corruption detection
is required.

## Privileged admission/outcome lifecycle

`AdmissionJournal::new(directory, key, identity, checkpoint)` is the concrete
broker-facing lifecycle API. `checkpoint` is a broker-owned implementation of:

```rust
pub trait TrustedCheckpoint {
    fn load_durable(&mut self) -> Result<ChainPosition, CheckpointFailure>;
    fn publish_durable(&mut self, position: ChainPosition) -> Result<(), CheckpointFailure>;
}
```

The checkpoint is not optional and is not derived from the journal. Its backing
store must live outside the audit directory, `load_durable` must return the
latest committed position rather than a cached or stale value, and
`publish_durable` must atomically replace and synchronize that position before
returning success. Once a journal uses a checkpoint, no other writer may publish
that checkpoint outside this lifecycle.

`admit(action, metadata)` performs these operations in order:

1. validate the action and caller metadata;
2. serialize on the audit-directory log lock (with the same bounded two-second
   wait used by writers);
3. load the independent trusted checkpoint;
4. verify every journal record from the start against that checkpoint,
   including canonical bytes, sequence, links, vault identity, and HMACs;
5. append exactly one authenticated admission record, synchronize the file,
   close it, and synchronize the directory;
6. re-check lock identity and durably publish the advanced checkpoint; and
7. only then return an `Admission` token.

Any failure returns a closed `LifecycleError` and no usable token exists. The
token is intentionally not `Clone`: `Admission::run(effect)` consumes it and is
the only effect-callback path. `run` returns `Execution`; calling
`Execution::finish(outcome, metadata)` appends a separate terminal outcome
through the same full-verification, durable-append, checkpoint-publication
critical section. If the outcome cannot be committed, `OutcomeError` retains
the effect output so the caller cannot mistake the already-run effect for an
unexecuted one.

A dropped `Admission`, a panic or process exit before `finish`, or a failed
outcome commit leaves no outcome record. `admission_states()` and the read-only
`scan_admissions(directory, trust)` report that admission as
`AdmissionOutcomeState::Unknown`; unknown means the effect may or may not have
happened and is never authorization to repeat it automatically. Multiple
outcomes for one admission are reported as `Conflicted`; outcomes without an
admission and malformed lifecycle-shaped records are counted separately in
`AdmissionReport` instead of being silently paired.

Lifecycle actions are non-empty ASCII strings of at most 128 bytes using
alphanumerics or `._-:/+`. `privileged_admission` and `privileged_outcome` are
lifecycle-owned event names. Caller metadata must not use the lifecycle-owned
`action`, `admission_seq`, or `outcome` fields, in addition to the chain-owned
fields described above. Metadata remains subject to the canonical JSON, 1 MiB
record, and nesting limits and must exclude secrets and request/response
bodies.

Crash behavior is deliberately conservative. If append or synchronization
fails, bytes may or may not have reached the journal; because the checkpoint is
not advanced in that case, a partially or completely landed record makes the
next verification fail closed (`beyond_checkpoint`, truncation, or corruption)
instead of being hidden or replayed. If checkpoint publication fails, the same
rule applies: no token is returned and later lifecycle writes fail closed until
broker-owned recovery reconciles the independent checkpoint. This crate does
not repair, rewrite, or compact journals.

The lifecycle module contains no hard-lock latch and no hard-lock callback.
Hard-lock state and key purging belong outside the audit journal and must not
wait on journal verification, append, synchronization, checkpoint publication,
or even the existence of the audit directory.

The correctness-first lifecycle scan is linear in the complete journal for
every admission and outcome, so a sequence of lifecycle writes is quadratic in
total history length. That is the concrete v1 scalability limit; snapshotting,
compaction, or a verified index is outside this crate's current integration.
The report itself is linear in the number of admission records.

## Verifier outcomes

`verify_reader`, `verify_bytes`, and `verify_directory` are read-only. Their
distinctions are:

| Status | Meaning |
|---|---|
| `valid` | Every record is canonical/authenticated and the final head/count exactly equals the trusted position. |
| `missing_trust_state` | No complete key/identity/head/count tuple was supplied. This is inconclusive, not validity. |
| `truncated` | The final record is incomplete, including a missing final newline. |
| `corrupted` | A present record is malformed, noncanonical, wrongly shaped, for the wrong vault, out of sequence, detached from its predecessor, or fails HMAC authentication. |
| `continuity_loss` | Present complete records authenticate in order, but their final position differs from trusted state: complete suffix deletion, rollback, replacement, extra records, or a missing log can all produce this. |
| `unreadable` | The directory/file could not be safely read, including unsafe links or non-single-name log files. |

Every continuity-loss report carries machine-readable `position_mismatch`:
`absent_or_empty_history` when no complete records are observed against a
nonzero expected count, `short_nonempty_history` when a nonempty verified
history ends below that count, `conflicting_checkpoint` when observed and
trusted counts match but heads differ, or `beyond_checkpoint` when the observed
count is higher. These labels describe only the two positions; they do not
claim deletion, rollback, replacement, cause, or ancestry.

A fabricated chain whose every record was made with the correct key is
internally valid but still reports `continuity_loss` unless it reaches the
independently trusted head/count. An attacker who can update that trusted
position is outside this mechanism's protection.

## Crate-local verifier command

The crate builds a diagnostic command (not yet integrated into the main `kv`
CLI):

```sh
cargo run -p kv-audit --bin kv-audit-verify -- \
  --directory /path/to/audit-dir --trust-file /path/to/trust.json
```

Trust JSON is one object with exactly these fields:

```json
{"v":1,"key":"<64 lowercase hex>","identity":"<lowercase hex>","head":"<64 lowercase hex>","count":0}
```

The identity is hex-encoded raw bytes, not its displayed digest. `head` is the
independently trusted head; use 64 zeroes with `count` 0 for a new vault. The
trust file must be regular, owned by the invoking account, at most 16 KiB, and
inaccessible to group/other users. `--trust-file -` reads the JSON from stdin.
Omitting `--trust-file` emits `missing_trust_state`. Because the file contains
the chain key, it must come from broker-owned trusted state, never from the
audit directory, and production integration should prefer an in-process broker
API over writing this file.

The command prints one JSON report. Exit codes are `0` valid, `10` truncated,
`11` corrupted, `12` continuity loss, `13` missing trust state, `14`
unreadable, and `64` usage/trust-input errors.

## Shared filesystem and warning behavior

Cooperating Python and Rust legacy writers use the same descriptor-relative
files:

- `audit.lock`: serializes tail/hash/append and the following health update.
- `audit-health.lock`: serializes loss-count publication.
- `audit-health.json`: bounded atomic state record; counts can be unknown.
- `audit-health.unkept`: a loss count could not be kept reliably.
- `audit.uncertain`: a held log lock was replaced; never automatically cleared.

Create one `Audit` for the process's audit directory and clone it for producers.
`emit(event, ordered_fields)` returns `Ok(())` or a closed `LossReason`. Under
the legacy policy an audit failure leaves the completed action in effect.
Metadata must exclude secrets and request/response bodies; the writer applies
Python's attribution sanitization. `take_warning()` leases a fixed warning;
dropping the lease returns it when delivery cannot complete.
`WarningChannel::Stderr` additionally prints each warning kind once per
invocation. `health()` is read-only.

Lock identity checks detect observed replacement, not a swap and restoration
between checks. Ordinary log appends are flushed without a durability guarantee,
matching Python; health publication and uncertainty markers sync their contents
and directory. Marker persistence is best effort when the filesystem refuses it.

Serialization in the legacy mode preserves field order and literal Unicode. Live
differential tests use `KV_PY_REF`; `KV_PARITY_REQUIRED=1` makes a missing
reference fail. Cross-process tests share the actual lock files with Python
rather than approximating flock with a Rust-only mutex.

Only `repr()` of a string nested inside a malformed non-string historical hash
uses a frozen Unicode 13.0.0 printability table, matching canonical CPython 3.10.
Ordinary event strings and valid string hashes retain literal Unicode. Python's
nonfinite JSON literals are supported locally when reading audit files; wire
parsing is unchanged.

One malformed-input exception is deliberate: Python's `_health_record_valid`
accepts an object missing `lost`, but its public `audit_health()` then raises
`KeyError('lost')`. Rust rejects that incomplete record as untrusted and reports
an unknown count.

## Current limits and required integration

The authenticated chain does not create the missing trust state or its durable
checkpoint backing store, choose the broker's canonical vault identity, derive
or purge the broker chain key, wire `AdmissionJournal` into the brokered
provider path, or expose a `kv audit` subcommand. Those require changes outside
`crates/kv-audit/` and are intentionally not made here. Until that integration
selects `Audit::with_authenticated_chain` or `AdmissionJournal`, existing
daemon writes remain in the legacy compatibility format.

The verifier is linear in the log and bounded per record, not total runtime. It
cannot distinguish all physical causes of a final-position mismatch; they are
reported together as continuity loss. It does not reconstruct lost records,
prove that trusted state itself is fresh, protect against compromise of the
chain key plus trusted-state publication, or make legacy Python-format logs
valid v1 chains. Windows remains outside this crate's Unix writer.
