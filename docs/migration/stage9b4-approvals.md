# Stage 9b-4a: `kv approvals approve` for one-call permits

The Rust `kv` can now make the owner decision that a script's or an agent's unsafe API call
waits for: `kv approvals approve permit_request_<id>` (Python `_approve_call_permit`).
`kv approvals list [--all]` and `kv approvals watch [--all] [--follow] [--interval N]` show
the inbox as Python does: the approval mode, the service's
pending one-call permits and paused jobs (`permit_requests`), then the approval requests on
disk (`kv_requests::approvals::list_approval_requests`, rendered as `_print_approval_request`).
Everything else under `kv approvals` (request, page, pause, deny, prune, and approving
a run grant or a paused job) keeps Python's argparse usage and help (`--help` shows Python's
text) but refuses as not available in this build; `kv grant` is not ported yet.

## What happens

1. NOPASS: a vault without a passphrase is refused before anything is read.
2. `block_local_approval_if_protected` (protected-approval mode refuses local approval),
   the owner-terminal check, and the refusal of run-grant flags on a permit.
3. `crates/kv-cli/src/owner_signing.rs`, Python's `PermitSigningContext`: the passphrase is
   read (`_owner_getpass`, one attempt, no "verified" line) and unwraps the key file; the
   owner channel is opened (`kv_proto::open_channel`); an UNPROTECTED session refuses.
   `owner_permit_request` fetches the service's record of the request, MAC-checked against
   the challenge (`check_answer`, `permit-request-v1`), and every binding is re-derived:
   the fact keys, the session nonce, both request ids, location, local approval id, owner
   key id, signer, body digest and length, header digest; a mismatch is "the call differs
   from the service's authenticated facts".
4. The review text is `kv_approvals::permit_review::render_review` (Python
   `render_permit_request`), then "Sign this one-call permit? [y/N]".
5. The mode is re-checked, the facts are signed (`attach_permit_approval`) and registered
   with `owner_permit_register` (two attempts; only an ack naming this permit id, request
   id and payload digest counts, else "no permit confirmed").
6. Audit: `call_permit_approved` / `call_permit_denied` / `call_permit_abandoned` with the
   request's requester fields, permit id, provider, method, body length and digest, URL
   without query.

## Deliberate differences

- 2FA: Python asks for a TOTP or backup code before signing when `security.totp` is set.
  This build has no second factor and refuses instead ("two-factor approval is not
  available in this build; nothing was signed").
- Python signs under the vault's authorization lock; Rust re-checks the approval mode
  right before signing but takes no file lock (the service re-checks the mode when it
  registers, as in Python).
- `watch --follow` ends on Ctrl-C with the process (Python catches the interrupt and prints a
  newline first).
- A wrong passphrase ends the command (Python's `prompt_unwrapped` does the same).
- A lost registration answer reports Python's `_permit_outcome_unknown_text` and audits
  `call_permit_outcome_unknown`; the expiry time is shown in UTC (Python: local zone).
- In `kv approvals list`, a decided request's grant line is Python's wording for an unread
  grant list ("grant <id>: state unreadable"): the live grant state (`_approval_grant_line`)
  is read once `kv grant` is ported.

## Comparison against Python 0.4.0

`crates/kv-cli/tests/approvals_permit_parity.rs::approving_a_one_call_permit_matches_python`:
the stage 5 permit fixture (a vault bound to a local HTTPS server reached by a public-shaped
hostname) is served by the Python daemon and then by the Rust daemon. On each, an agent's
POST asks for a permit; the Rust `kv` and Python's `kv` each approve one on a pty (passphrase,
then `y`); the retried call is sent exactly once and a replay answers `permit_invalid`. The
four terminal transcripts are identical once ids, times and the session nonce are masked;
`kv approvals list` from both CLIs is compared with a pending permit and with an empty inbox.
Skipped without `KV_PY_REF`.
