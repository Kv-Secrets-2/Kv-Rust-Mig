# Stage 9b2: static preflight and run risk cards

`crates/kv-preflight` ports Python 0.4.0's `kv/agent_code_scan.py` and
`kv/preflight.py`: directory/file scans, provider/SSH/write estimates,
recommendation guards, run identities, and sorted, indented ASCII JSON with
arbitrary-precision integers. It reuses sandbox classification and identity
helpers; standalone scans have no watched vaults. Analysis is report-only and
does not execute the proposed command.

`kv-approvals::risk_card::build_run_risk_card` accepts a resolved cwd and an
injected preflight callback to avoid a dependency cycle. The convenience builder
in `kv-preflight` resolves cwd and supplies the scanner. `kv preflight` wires the
Python options, REMAINDER argv, JSON/text output, colours, escaping, not-copyable
guidance, and too-long markers into `kv-cli`. Both help listings already existed.
Like Python, this command does not prepare vault access before dispatch.

## Compatibility and deliberate differences

- **Depth hardening.** Maximum AST depth is 100, counting the Module root and
  nested nodes conservatively. Deeper input returns `PreflightError::TooDeep`
  (`Python script is nested too deeply for static preflight`). CPython 3.10's
  visitor first failed around depth 333 for call chains and 496/497 for other
  deep expression families; very deep parsing can raise MemoryError. Rust can
  therefore refuse inputs Python accepts. Traversal and AST teardown are
  iterative; increasing the thread stack alone was insufficient.
- **Unparsed input.** Parse errors, unsupported syntax newer than Python 3.10,
  brackets deeper than 200, indentation reaching 100, and a leading BOM produce
  `Python script could not be parsed; estimates are incomplete.` BOM elsewhere
  in code is rejected; BOM inside strings/comments remains valid. These guards
  close known Ruff/CPython disagreements rather than accepting newer syntax.
  Both Ruff parse errors and unsupported-target diagnostics must be empty.
- **NUL and arithmetic errors.** A decoded source NUL raises ValueError with
  `source code string cannot contain null bytes`, matching CPython 3.10/3.11.
  Newer references can classify it as SyntaxError; Rust retains the older
  contract. Integer-to-float overflow and infinity-to-integer overflow preserve
  Python's exact messages. Unix identity resolution errors preserve exception
  kinds and Python exception spelling, with the runtime filename fork below.
- **No traceback paths.** The CLI prints one error line and exits 1 for
  ValueError, OverflowError, TooDeep and other preflight failures. Python's
  `cmd_preflight` catches ValueError and its `main()` catches remaining Exceptions,
  so ordinary non-ValueError failures already have no traceback through the
  Python CLI. TooDeep still deliberately has a different message. Risk cards
  turn preflight failures into limited cards; cwd resolution errors remain
  outside that conversion, as in Python.
- **Requests fail closed.** Run-approval/policy-request creation is not ported.
  `--request` first checks project membership, then refuses with
  `kv preflight --request is not supported by this kv build yet; run kv preflight without --request`.
  No root-taking CLI NOPASS guard exists to reuse; no request or project state is
  written, and no approval/passphrase flow is attempted.
- **Rendering.** Preserve Python's literal `{RESET}` suffix in one rewrite
  guidance line. The existing top-level help footer reports this build's Cargo
  version rather than Python's 0.4.0. Tests compare the full help prefix/listing
  and separately assert each package-version footer, without masking it.
- **Reference-runtime differences.** Keep the CPython 3.10.12 argparse contract:
  unknown preflight options exit 2 with usage, and `-hfoo` is an invalid attached
  help value. Newer argparse can instead return branded help (exit 1) or help
  (exit 0). These complete alternative transcripts are asserted separately.
  The existing Rust resolver follows Python's `_resolve_walk` fallback and
  identifies the non-directory component in ENOTDIR. CPython before 3.13 with
  `os.path.ALLOW_MISSING` can instead name the following child component;
  this filename difference is explicitly asserted, not masked. ELOOP and the
  remaining tested exception messages match byte-for-byte. Newer NUL risk cards
  assert the documented older limited-card contract instead of silently
  accepting the newer reference's complete-but-unparsed card.
- **Parser and license.** Pin `ruff_python_parser = "=0.0.21"` with `stacker`
  and `ruff_python_ast = "=0.0.21"`, targeting PY310. `Unicode-DFS-2016` is allowed
  for the parser's transitive Unicode data (the predecessor of Unicode-3.0).
- **Platform limits.** Live filesystem/PTY comparisons are Unix-gated; no claim
  is made of Python-exact Windows path-resolution errors. Existing stage-8
  Windows path-resolution limitations still apply. Native dependencies need an
  MSVC/Windows SDK toolchain when cross-checking the Windows target.

## Verification

Four comparisons are registered in `scripts/parity_inventory.json`:

| Package/target | Exact comparison name | Coverage |
| --- | --- | --- |
| `kv-preflight/agent_code_parity` | `agent_code_matches_python` | 98 cases, 53 source samples, Unicode/newline/encoding handling, skipped directories and symlinks |
| `kv-preflight/preflight_parity` | `preflight_matches_python` | 258 cases, 97 sources, byte-exact manifest JSON except random run ID and explicit depth refusals |
| `kv-preflight/risk_card_parity` | `run_risk_cards_match_python` | 59 cases, 38 scripts, identical Python-generated identities, explicit depth/newer-NUL differences |
| `kv-cli/preflight_parity` | `preflight_cli_matches_python` | 17 normal scripts plus error fixtures; exact stdout/stderr/status on pipe and PTY, each plain and ANSI; explicit request refusals and depth/version exceptions |

CLI error fixtures exercise both overflow messages, AttributeError, TypeError,
FileNotFoundError, and identity resolution failures (ENOTDIR, ELOOP, escaped
filenames), not merely the caught ValueError path. Only random manifest run IDs
are masked in ordinary CLI comparisons. See [PARITY.md](PARITY.md) for the
reference pin, runtime lanes, inventory enforcement and mandatory gate commands.
