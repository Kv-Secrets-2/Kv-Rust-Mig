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
