# Stage 6d-1: `cap_api`, the script-facing broker call

Python reference: `kv/agent.py` `_handle_capability_api_call` and the `cap_api` branch of
the dispatch; client side `kv/cap_client.py` (`api_call`).

## What is ported

`crates/kv-agent/src/capapi.rs`. A program admitted with an `api:PROVIDER` capability
calls the broker over the daemon socket with its `KV_CAP_TOKEN`; the daemon token is not
required (Python: "secret-bearing capsules hide ~/.kv"). The request is validated like
`api` with `capability_token` (≤ 256 bytes) in place of `token` and a `run_identity`
object; `env` must be a registered environment (`_daemon_env_error` words, without the
caller's text). Then, in Python's order:

1. provider lookup and type, `api_body_security_error`, the HTTP policy decision
   (`http_policy_denied` and the other refusals are answered before the token is read);
2. the token is checked, not charged (`consume_capability_token` with `charge=False`,
   `require_parent=True`, the provider definition's digest) before any secret is read;
3. `permit_id` on a safe call → `permit_invalid`; the permit precheck for an unsafe call;
4. the provider secret is read from the cache (a missing secret answers with
   `capability_name`, `capability_token_id`, `capability_consumed: false`);
5. `require_verified(kind="transport")`: the pass's verified grant must cover this
   environment, capability and provider definition;
6. the call goes out through `kv_broker::ApiCaller`; the charge (`Ledger::spend_pass`,
   this call's service only) happens inside the committed work window, after the hard-lock
   check, immediately before the send; a refused charge sends nothing and answers
   `capability denied: ...`;
7. the reply carries `capability_name`, `capability_token_id`, `capability_consumed`,
   `capability_remaining_calls` and the policy warning.

Every call writes a `capability_api` audit event (provider or `"unknown"`, the capability
fields, `error_code`, `policy_rule`, `approval_required`, `policy_warning`, `error`, the
actor fields and the permit fields).

## One-call permits for capability runs (stage 6d-1b)

An unsafe call (POST, PUT, PATCH, DELETE under a `per-call` rule) goes through the same
`permits::prepare` as the daemon-token `api` command (`_prepare_api_permit`), with the
pass's binding added: the permit facts carry the pass's `grant_id` and
`created_from_run_id`, and the permit waits as long as the grant's `owner_wait_seconds`
instead of the default TTL. Without a `permit_id` the daemon files the permit request and
answers `permit_required` (the script's `kv.cap_client` polls it); with one, the call is
matched against the signed facts, then charged inside the committed send window in
Python's `spend_permit(..., token_hash)` order: the pass is checked (`check_pass_for_permit`:
not revoked, expired or exhausted; not a wallet pass; the same grant, run and service as the
permit, else "this permit belongs to another run or provider"), the permit is spent
(`SessionPermits::spend_for_run`, which also refuses a permit signed for another run), and
the pass is debited for this call's service (`spend_pass`). Refusals carry
`capability_consumed: false` and `capability_remaining_calls`. The permit's facts, request
and `owner_wait_gave_up` audit are those of the ordinary `api` path.

Not yet: a permit the owner refused on the approval page (`permit_wait_over == "refused"`
→ `permit_refused`); this service does not track refused permit requests, so such a call
waits out the owner's chosen time and answers `owner_wait_gave_up` like Python does for an
unanswered one. Permit approval is the pinned Python owner client (`kv approvals approve`);
the Rust CLI's approvals commands are stage 9b.

## Not ported yet (fixed refusals, nothing charged or sent)

- POST wallets (`_wallet_*`): a wallet pass's call is refused.
- Pauses and saved passes (`_spent_pass_answer`, `_owner_held_answer`,
  `_ended_wait_answer`, `_refused_job_answer`, `_save_part2`, `_extension_snapshot`): a
  spent pass is denied outright instead of pausing; `pause_id` is validated and ignored.
- Python coalesces repeated refusals of one kind in the audit log (`RefusalCoalescer`);
  this service writes each refusal.

## Comparison against Python 0.4.0

`crates/kv-agent/tests/stage6_capapi.rs::capability_run_api_calls_match_python`: on one
vault with a provider bound to a local HTTPS server, each daemon in turn gets an
owner-signed `api:` grant (the Python signer now takes the daemon's own provider
definitions, as `kv grant approve` does) and runs the same script under bubblewrap. The
script makes an allowed GET, a call outside the policy, a call to an unknown provider and a
second allowed call (the pass has one call). Compared: the run reply, the script's output
(the provider's answer reaches it redacted; the secret reaches only the provider), the
calls the provider saw and the `capability_api` audit events (chain fields masked). Skipped
without `KV_PY_REF` or bubblewrap.

`capability_run_permit_matches_python`: the same vault with a `per-call` POST rule and a
two-call grant. The script POSTs and waits; the test polls the daemon's `permit_requests`
and approves the one pending permit with the pinned Python owner client
(`PermitSigningContext`, as `kv approvals approve` does), then the script makes an allowed
GET. Compared: the run reply (the permit request id in the script's stderr masked), the
provider's view (POST then GET, each with the secret), and the `capability_api` events
(permit and request ids masked; consecutive duplicates collapsed, since Python coalesces a
run's repeated refusals and the script polls once a second). The provider is reached by a
public-shaped hostname both daemons resolve to loopback, as the stage 5 permit tests do: a
permit refuses a URL whose host is a non-global address.
