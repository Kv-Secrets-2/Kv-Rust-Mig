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
- Rust refuses every IPv4-mapped IPv6 address, including public mapped IPv4
  addresses such as `::ffff:1.1.1.1` that Python 3.10.22 admits. This preserves
  the existing fail-closed URL guard; the comparison asserts both outcomes.
- Rust refuses `fec0::/10`, including `fec0::1` that Python 3.10.22 admits.
  This also preserves the existing URL guard, with explicit asymmetric tests.
- A non-private policy-request store is refused without changing its mode.
  Python repairs its permissions and proceeds; the live comparison asserts
  Rust refusal, Python admission, and the respective permission outcomes.
- Existing policy-request stores are refused on Windows because private-ACL
  verification is not implemented. Rust does not trust unchecked ACLs; this
  follows the existing Rust approval-store restriction.
- Non-array request argv and non-string request cwd fields receive explicit
  field-type refusals rather than Python's coercion or type-error behavior.
  The live numeric-field error cases preserve queue and config in both.
- Numeric options on unavailable command-policy watch/request commands require
  ASCII decimal spellings; signs, whitespace, underscores and arbitrary-sized
  ASCII integers are accepted. Python also accepts non-ASCII decimal spellings,
  which Rust refuses.
- Command-policy `watch` and `request` retain parser help/usage but refuse
  execution as unavailable in this build. Python implements them; they were
  explicitly excluded from this stage. Test requests are created by Python.

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
watch/request actions remain parsed but unavailable; command-policy decisions are
implemented below.

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

## Command-policy inbox and owner decisions

Bare `kv policy` and `kv policy list [--all]` show the command-policy inbox.
`allow`, `block` / `deny`, and `prune` interoperate with Python-created requests.
`watch` and `request` retain argparse help/usage but refuse as unavailable; tests
create their requests using Python, not a Rust request command.

The private request store preserves Python's sorted, ASCII-escaped, indented
JSON format, including its trailing newline and floating-point record fields.
Decision writes hold Python's stable `storage.lock`; allowing records the
decision before adding the pattern under that same lock and a checked config
snapshot. Request fingerprints bind exactly the fields Python reviews and are
rechecked under the lock, along with status, expiry, and broad-pattern refusal.
Decided requests never implicitly re-apply missing allowlist shapes.

Owner prompts escape stored values and refuse overlong approval values. Audit
decisions use the shared audit emitter and requester attribution, explicitly
marked unverified. Protected mode blocks allow but leaves block and prune open.

Differential tests cover empty/pending/all listings, decisions, aliases,
already-decided and missing/expired IDs, broad patterns, protected mode,
passphrase absence, cancellation, prune counts, audit fields, parser/help, and
cross-implementation reads. Config and request-store bytes are compared; only
the two decision-generated update timestamps are masked in interactive runs.
Fixed-clock store comparisons additionally compare request-store bytes without
masking, fingerprints, stale snapshots, changed review fields, malformed stores,
and ignore-file maintenance.

The applicable refusal differences, including unsupported 2FA, are catalogued
in the consolidated list above.

## Daemon interop and help regression coverage

`kv-cli/tests/owner_config_interop.rs` is Unix-only and release-only, matching
the existing daemon-start timing convention. Both implementations write the
same owner configuration sequence on copies of one fresh vault at the same
absolute project path, sharing HOME and using a short private TMPDIR. The
sequence sets local-convenience approval, command/network allowlists, HTTP and
Postgres providers, and GET plus POST per-call HTTP rules. Transcripts and
config.json bytes match across writers.

Python approves and unlocks Rust-written configuration, and Rust approves and
unlocks Python-written configuration. Each daemon reports an unlocked/running
status and is locked again, with cleanup on failure. The Python and Rust broker
snapshot loaders agree on provider bindings, rules, per-call approval, and policy
description metadata on the same configuration; no external API call is made.

All seven owner-command help pages match byte-for-byte. Global `-h` / `--help`
text differs only in the existing build-version footer, which is explicitly
checked and normalized in the comparison, not changed in the binary. Top-level
argument-error usage preserves the implemented-command subset, in Python's
relative order; the test compares it with Python's list filtered to the Rust
parser's implemented commands. The separate Rust `mcp-server` entry point is
unchanged and is not advertised as an argparse choice, since Python's top-level
parser has no such choice. Existing version/subset conventions are not new
stage-specific hardening differences.
