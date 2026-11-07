# Stage 9b-3 owner configuration CLI

## Deliberate differences from Python 0.4.0

- Rust does not implement two-factor authentication. A policy loosening that
  requires a 2FA code (in either the authorization snapshot or the current
  settings, including unreadable settings) refuses without writing anything.
  The check is repeated after passphrase verification. Python instead prompts
  for a TOTP or backup code. Rust never skips the second factor.

## Approval mode

`kv approval-mode [status|set MODE]` shares owner-policy authorization with
subsequent owner configuration commands. Changes take the Python-compatible
`storage.lock` authorization lock before the config guard, preserving the
original snapshot across the owner's confirmation and passphrase prompt.

Live comparisons in `kv-cli/tests/approval_mode.rs` cover status, confirmation,
wrong passphrases, protected-mode refusals, parser output, byte-identical config
writes, storage getter/setter semantics, and mutual Python/Rust lock exclusion.
The test runs both CLI implementations on copies of one initialized vault at the
same absolute path so the wrapped key's location binding remains intact.
