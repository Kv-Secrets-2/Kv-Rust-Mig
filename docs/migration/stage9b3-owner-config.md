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
- Provider ports must be ASCII decimal integers representable as signed 64-bit
  values (with Python-style surrounding whitespace, sign and digit separators).
  Rust refuses non-ASCII decimal spellings and larger integers at argument
  parsing, without writing configuration. Python accepts these spellings and
  arbitrary-precision integers. Live tests cover both refusals.
- Malformed provider containers/entries are refused without mutation. Where
  Python raises an attribute error during listing or removal, Rust reports a
  concise object-type error instead of a traceback. Tests compare refusal and
  unchanged config bytes for these cases rather than traceback text.

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

## Providers

`kv provider` / `list`, `add`, and `rm` share broker provider validation and
owner authorization. HTTP registration validates the origin, resolves all
addresses through the broker SSRF guard, and appends origin-bound deny-all
policy entries. Removal deletes the corresponding HTTP policy entry as well.
Unloaded-provider removal is a loosening repair. Protected approval blocks
both addition and removal. Non-HTTP providers retain the MCP parked-tool notice.

Provider command comparisons cover auth modes/defaults, insertion-ordered config
bytes, URL refusals, DB/SSH required fields and defaults, duplicates, removal,
repair, cancellation, protected approval, malformed provider/policy containers,
and parser help/errors. Broker comparisons cover validators, provider-table
loading, default policy, and public/restricted IPv6 literals. The shared URL
guard now also rejects reserved and special-purpose IPv6 ranges that Python
rejects; it retains Python's public exceptions.
