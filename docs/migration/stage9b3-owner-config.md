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

### IPv6 URL admission baseline

The broker guard is pinned to CPython **3.10.22**, not whichever interpreter
happens to run the tests. Step 4 added rejection of reserved IPv6 space outside
`2000::/3`, and `2001::/23` and `2002::/16` special-purpose ranges. Public
exceptions within `2001::/23` are retained: `2001:1::1/128`, `2001:1::2/128`,
`2001:3::/32`, `2001:4:112::/48`, `2001:20::/28`, and `2001:30::/28`.

The canonical tables also reject **`3fff::/20`** (RFC 9637); Step 5 adds that
missing range, with both boundary and neighboring-address parity cases.
The installed 3.10.12 runtime's tables did not contain this range. This is a
maintenance-version difference, not simply a Python 3.10-versus-3.13 distinction.
All IPv4-mapped IPv6 addresses and `fec0::/10` remain refused, including addresses
that CPython 3.10.22 admits. These are deliberate fail-closed differences: parity
does not justify loosening an existing URL guard. The live comparison asserts
both Python admission and Rust refusal for `::ffff:1.1.1.1` and `fec0::1`, rather
than skipping either case. Live comparisons use a separately installed 3.10.22.

## HTTP policy CLI

`kv policy http` / `list [provider]`, `add`, and `remove` / `rm` reuse broker rule
validation and binding checks. Additions authorize loosening and save the loaded
snapshot; invalid-entry removal is a protected-mode-blocked loosening repair,
while ordinary removal remains available in protected mode. Command-policy
actions deliberately refuse as unavailable until step 6.

There is no unsafe-method flag: Python automatically stores `approval: per-call`
for POST, PUT, PATCH, and DELETE rules. Mixing safe and unsafe methods is refused.
An accepted unsafe rule does not authorize calls; a signed one-call permit is
still required at runtime. Python accepts `Authorization` in an allowed-header
list, although request-time broker checks still reject caller authentication
headers; this command preserves that distinction.

Differential tests compare transcripts, exits, and config bytes for read-only
and unsafe rules, repeated methods/query keys/headers, default-policy insertion,
binding errors, duplicate IDs, route validation, repair, cancellation, protected
mode, listing, aliases, and argparse help/errors. Pure broker helper comparisons
also cover empty/default input, unsupported methods, labels, and binding checks.
