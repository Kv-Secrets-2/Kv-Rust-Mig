# Ordinary API one-call permits

This slice implements Linux daemon permits for ordinary HTTP API calls requiring
per-call approval. It follows Python 0.4.0 at
`9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`, principally `approval_verify.py`,
`approval_render.py`, `agent.py`, and `providers.py`. The pinned Python owner
client supplies the approval UI and signing operation during interoperability
tests. A Rust owner CLI remains future work.

## Request and approval

An eligible call returns `permit_required` with generated request and permit IDs.
`permit_requests` lists pending requests and returns an empty `pauses` list.
The authenticated `owner_permit_request` endpoint returns signed facts, complete
body text, caller headers and sanitized requester attribution. The owner signs
those facts; `owner_permit_register` verifies the signature and returns a signed
acknowledgment. Retrying the exact call with its permit ID can send once.

Facts bind the vault identity and location, owner key, daemon session, environment,
immutable provider definition, method, shown URL, header names, caller-header
digest, exact body bytes, and expiry. Ordinary permits require null grant/run IDs.
Authentication header values remain outside the preview. Query authentication
uses the reference's literal `<added-by-kv-not-shown>` placeholder; only the
transport receives the credential-bearing URL.

Both request and use require a passphrase-protected session. Invalid, missing,
expired or spent retries are refused before credential lookup. Approved
`protected-approval` configuration allows review but refuses new local permit
registration; a verified retry of an existing registration remains acknowledged.

## One send and bounded session state

The ledger is memory-only and shared by daemon workers. It retains at most 1,000
request records, with a 600-second default expiry. Either the wall-clock deadline
or the original monotonic deadline expires authority. New requests prune expired
records. Registered and spent requests still occupy capacity until pruning.
Duplicate registration never renews expiry or refunds a spent permit. Restarting
the daemon changes the session and discards the ledger.

Broker preparation checks policy, URL safety and request facts without sending.
The final prepared request is matched again. Immediately before transport, the
daemon checks retirement and the connection, observes the trust pin, spends the
permit, and publishes committed work under one admission lock. Lock order is
lifecycle, trust pin, then permit registry. The checked pin remains held until
publication; all these locks are released before HTTP work.

A preparation failure consumes nothing. Entering transport spends authority even
if the connection fails. Concurrent retries can therefore produce at most one
transport attempt. A stop that wins admission refuses the request without debit;
a committed call is counted by the existing shutdown choices.

## Complete previews and attribution

Admission validates the complete escaped approval card, including individual
field limits and the 32,768-character total limit. The body limit is 512 KiB, but
the escaped card can refuse a smaller body. Bodies must be UTF-8. Linux location
bytes use Python's surrogate-escape display rather than lossy replacement.
Body serialization and canonical signing bytes preserve Python's ASCII escaping,
number spelling and caller-header ordering requirements.

The local JSON summary parser is iterative and limits nesting to 1,000 containers.
Above that limit Rust refuses the preview without recording a request. Python
raises an uncaught `RecursionError` at a runtime- and call-stack-dependent depth.
The retained preparation-helper probe first raised at 991 containers on Python
3.10/3.11, 9,998 on 3.12 and 9,999 on 3.13. Rust can render through 1,000 without
recursion, and conservatively refuses deeper bodies that newer Python accepts.
The live regression records this deliberate difference separately from exact
card comparisons. This parser does not broaden daemon wire parsing.

Ordinary API audit events gain request/permit IDs and sanitized current-caller
attribution. The original requester remains in the owner's review copy. Unknown
permit IDs use a fixed audit label. Bodies, caller-header values and provider
credentials are never added to audit records by this slice. Expired pending waits
retain bounded tombstones for the reference's one-time `owner_wait_gave_up` event.

## Scope and validation

The mandatory Linux comparison inventory includes successful Python owner
approval against Rust, exact outbound requests, concurrent retries, altered
facts and signatures, replay, failed preflight and transport, stop ordering,
query masking, card refusal, audit attribution, restart, and the passphrase and
protected-approval boundaries. Focused registry tests cover capacity, pruning,
expiry and wall-clock rollback. See the slice's validation record for executed
results; an inventory alone does not establish a passing run. The HTTPS recorder
uses a test CA and a safety seam that pins a public-shaped hostname to loopback;
it does not establish complete production DNS or rebinding coverage.

Capabilities, POST wallets, sandbox/run, pause/refuse-permit controls and the Rust
owner CLI remain deferred. This slice does not establish completion of all Stage
5 or migration acceptance gates. Linux is the current implementation and
validation focus; no new native macOS or Windows acceptance claim is made here.
