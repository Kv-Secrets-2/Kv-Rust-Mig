# kv-requests

Library-only request stores for the Python 0.4.0 current vault format.
Approval requests are review records, not authorization grants.

`approvals::create_approval_request` accepts a JSON object of Python keyword
arguments (including `run_identity`). Omitted `ttl_seconds` defaults to 900.
All public lifecycle functions accept integer epoch seconds; `None` uses the
clock. `RequestHooks` delegates risk-card construction/normalization and
multi-service call normalization to the calling application, in Python's order.
No grant creation is implemented here.

| Python `kv.approvals` | Rust `kv_requests::approvals` |
| --- | --- |
| `approval_store_path` | `approval_store_path` |
| `create_approval_request`, `_find_equivalent_pending` | `create_approval_request` |
| `list_approval_requests`, `get_approval_request` | same names (polling primitives) |
| `mark_approval_request_approved`, `deny_approval_request` | same names |
| `mark_request_in_held_lock`, `_mark_request_held` | `mark_request_in_held_lock` |
| `prune_approval_requests`, `is_missed_request` | same names |
| `_request_status` | `effective_status` |
| `_normalize_reason`, `_normalize_actor` | `normalize_reason`, `normalize_actor` |
| request integrity helpers | `verify_approval_request_integrity`; internal sealing uses `kv-approvals` |
| `kv.approval_wire.request_content_digest` | re-exported `request_content_digest` |

The caller of `mark_request_in_held_lock` must hold this vault's
`kv_store::fsx::lock_storage` guard on the same thread. It supports arbitrary
status strings and `from_status`, including approval withdrawal and expiry.

## Conservative differences

- Windows writes and existing private-file reads refuse until private ACL
  validation is available. They do not publish new signing keys on Windows.
- Missing, linked or non-private `.secrets` directories refuse rather than
  being created or permission-repaired. macOS extended ACLs also refuse.
- JSON NaN/Infinity and unpaired Unicode surrogates refuse at decoding;
  Python's JSON extensions can accept them.
- Decimal integer strings use the canonical Python 3.10 Unicode 13 digit
  repertoire. Digits introduced in newer Unicode releases refuse; this follows
  the migration's pinned canonical-runtime convention.

The live differential test isolates unrelated provenance/permission repair and
delegates risk/call-budget dependencies to identical deterministic hooks in both
languages. It compares results, errors, serialized store bytes and ignore files
after each operation; separately it exercises independent signing-key creation
(whose random keys/seals necessarily differ) and bidirectional cross-reads.

## Command-policy requests

These records ask the owner to review command shapes; they never grant access
to secrets or capabilities. The same conservative storage differences above
apply to this store.

| Python `kv.policy_requests` | Rust `kv_requests::policy_requests` |
| --- | --- |
| `policy_request_store_path`, `policy_pattern_for_argv` | same names |
| `create_policy_request`, `_find_equivalent_pending` | `create_policy_request` |
| `list_policy_requests`, `get_policy_request` | same names (polling primitives) |
| `mark_policy_request_allowed`, `block_policy_request` | same names |
| `_mark_request_held` | `mark_request_in_held_lock` (requires storage guard) |
| `prune_policy_requests`, `request_fingerprint` | same names |
| `_request_status` | `effective_status` |
| `allow_policy_request` | `allow_policy_request` with `AllowPolicyRequest` options |

`kv-store` has a snapshot guard and config transactions, but no equivalent of
Python's `add_allowed_command`. Accordingly `allow_policy_request` receives a
caller-supplied pattern-writing closure. The library verifies same-vault identity,
the reviewed fingerprint, pending status, pattern narrowness and the original
config snapshot, marks the request allowed, then invokes the closure while both
locks remain held. Closure failure leaves the request decided and cannot be
completed by retrying it. Production config mutation is deliberately left to
the caller; the differential test supplies a transaction matching Python's
existing pattern writer and compares config bytes as well as queue/ignore bytes.

Same-vault checks resolve existing vault directories with the OS; unavailable
directories fail closed rather than accepting a non-strict lexical fallback.

## Session request records

| Python `kv.request_records` | Rust `kv_requests::request_records` |
| --- | --- |
| `RequestRecord`, `RequestRecordsFull` | same names |
| `_record_of` | `record_of` |
| `RequestRecords(bound=None)` | `RequestRecords::new(None)` / `default()` |
| `record`, `get`, `__len__` | `record`, `get`, `len` |

The mutex-backed session store preserves the first record for an id, prunes on
`record` and `get` using the supplied epoch (or current time), and never evicts a
live record to admit another. Like Python, `len` does not prune. Expiry preserves
arbitrary-sized JSON integers; booleans and floating-point numbers are not
integers for record validation. A poisoned Rust mutex refuses further access.
The typed Rust bound is a nonnegative `usize`; ids passed to `get` are strings.
