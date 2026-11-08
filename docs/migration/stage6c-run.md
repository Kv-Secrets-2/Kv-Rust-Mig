# Stage 6c: the daemon's `run` command and `kv run`

Stage 6c wires the Stage 6a sandbox (`kv-sandbox`) and the Stage 6b grants and
capability tokens (`kv-grants`) into the daemon (`kv-agent`) and adds the `kv run`
client to the Rust `kv` binary. It ports the `run` branch of Python
`kv/agent.py`'s request loop plus the `kv run` command of `kv/cli.py`.

## What the daemon does for `run`

In Python's order, with Python's wording for every refusal:

1. **Validate the request** (`argv`, `env_names`, `capability_names`, `cwd`,
   `private_cwd`): counts, lengths, types, "cannot mix raw secrets and
   capabilities", a relative or missing `cwd`.
2. **Resolve the working folder** and refuse a script or `cwd` inside `.secrets`.
3. **Classify the command** (`kv_sandbox::classify`) against the project's
   allowlist and network rules; refusals carry `mode`, `approval_hint` and the
   command fingerprint as Python's do.
4. **Admit the run** (`kv_grants::admit_run_grant`) before any secret is
   selected or decrypted. A run without secrets or capabilities needs no grant.
   A secret- or capability-bearing run needs an owner-signed grant for the
   exact command fingerprint, script hash, secret scope, actor and environment,
   verified against this daemon session (`require_verified`); it is spent in
   the same transaction, and a failed launch does not refund it.
5. **Launch under bubblewrap** (`kv_sandbox::bwrap`): secrets and the
   capability token travel in the sealed memfd, never in the daemon's argv or
   environment; the child gets a process group, a null stdin, piped
   stdout/stderr, and the private script/cwd capsules when Python would use them.
   Secret- and capability-bearing runs are refused where bubblewrap is missing.
6. **Capture and redact**: bounded stdout/stderr (truncation flags as Python's),
   redaction of every secret variant (`kv_sandbox::redact`), and of the
   capability token.
7. **Scan for leaks** in the temp folders and the cwd, delete or report leaked
   files, and **track new files** for the Claude Code hook.
8. **Answer** with Python's reply shape (`exit_code`, `stdout`, `stderr`,
   `run_id`, `command_fingerprint`, `script_kind`, `script_sha256`,
   `secrets_injected`, warnings) and append Python's audit record.

`tracked_files` and `check_file` now answer from the real tracked-file state
(stage 8 answered "no tracked files" until here). `stop` counts running
programs as work: `stop` with a `wait` choice waits for them within Python's
budget, `now` ends their process groups (`SIGTERM`, then `SIGKILL` after the
grace), and a run's reply is written exactly once.

## `kv run`

`crates/kv-cli/src/runcmd.rs` mirrors Python's `cmd_run`: `-e/--env`, `--cwd`,
`--private-cwd`/`--no-private-cwd`, `-q/--quiet`, repeated `--secret`,
`--no-secrets`, repeated `--capability`, a leading `--` before the command, the
environment default from the project (then `dev`), the absolute-cwd rule, the
`api:` capability-name check, the `running via agent (ENV)` header, the relayed
stdout/stderr/warnings, the daemon's exit code, and the "start it first: kv
unlock / kv unlock --foreground" guidance when the daemon is down.

## Comparisons against Python 0.4.0

`crates/kv-agent/tests/stage6_run.rs`, registered in
`scripts/parity_inventory.json` (floor 80 → 83). Each test starts the Python
0.4.0 daemon and the Rust daemon in turn on the same passphrase vault (Python
made it) and compares the replies field by field; only `run_id`,
`audit_warning` and `approval_request` (below) are left out.

| Test | What it compares |
|---|---|
| `run_replies_match_python_on_the_same_vault` | 14 run cases: a plain run, a non-zero exit, a shell asking for secrets, a relative cwd, a missing cwd, a script inside `.secrets`, secrets and a capability without a grant, unnamed secrets, a bad capability name, mixed secrets and capabilities, an over-long argv, a non-boolean `private_cwd`; then `tracked_files` and `check_file` |
| `secret_bearing_run_with_an_owner_grant_matches_python` | the owner signs a one-run grant for a Python script that reads `API_KEY` (through Python's own signer bound to each daemon's session); both daemons launch it under bubblewrap, redact the key in stdout, write the same reply, and refuse the second run as spent in the same words |
| `stop_waits_for_a_running_program_and_ends_it_on_now` | with `/bin/sleep 30` running, the first `stop` asks for a choice, `now` ends the program within Python's budget, and the run's reply arrives once |

## Deliberate differences

- **No pending approval request yet.** When a secret- or capability-bearing run
  has no matching grant, Python also files a pending approval request and names
  it in `approval_request`. Rust returns the same refusal and `approval_hint`
  without filing one until the request stores (`kv-requests`, PR #22) are
  integrated; the parity test leaves `approval_request` out for that reason.
  No policy request is filed for an allowlist refusal either, for the same reason.
- **Not in this stage** (6d): `cap_api` for scripts, paused jobs and pass
  extensions, POST wallets. A capability-bearing run is admitted and gets its
  token; the broker side that spends it is 6d.
- **Platforms.** `run` is Linux-only here; macOS and Windows answer the Stage 10
  refusal. The Windows cross-check of `kv-agent` cannot run on this VM (`ring`'s
  build script needs MSVC `lib.exe`); CI's Windows job covers it.
- **No old vaults, no migration**, as in every stage.
