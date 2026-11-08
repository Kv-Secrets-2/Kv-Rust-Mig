# Stage 9b-3 owner configuration CLI

## Deliberate differences from Python 0.4.0

- Rust does not implement two-factor authentication. A policy loosening that
  requires a 2FA code (in either the authorization snapshot or the current
  settings, including unreadable settings) refuses without writing anything.
  The check is repeated after passphrase verification. Python instead prompts
  for a TOTP or backup code. Rust never skips the second factor.
- Rust refuses malformed command/network list settings that are not lists of
  strings, and non-string run-policy settings, rather than interpreting or
  displaying them permissively. It leaves the configuration unchanged. Python
  can, for example, display a numeric entry; the live tests cover this refusal.

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

## Command and network allowlists

`kv allow`, `kv deny`, `kv network-allow`, and `kv network-deny` use the same
owner-policy helpers. Broad command patterns are classified by `kv-sandbox`.
Removing a broad entry is a loosening repair, not an ordinary revocation.
Narrow revocations remain available in protected-approval mode; grants and broad
repairs do not. Missing deny entries retain Python's exit-zero error behavior.
Network revocation uses the original load/save snapshot without an outer config
guard, just like Python; the store's conditional save still rejects stale data.

`kv-cli/tests/allow_commands.rs` compares owner transcripts and config bytes,
including unset-mode warnings, confirmation cancellation, duplicate/missing
entries, broad-entry repair, protected mode, list/help output, and non-terminal
refusals. Its storage comparison covers empty patterns and absent settings.
