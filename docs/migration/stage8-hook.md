# Stage 8: Claude Code hook (`kv hook pre`)

The Rust `kv` binary answers Claude Code `PreToolUse` requests exactly as
Python 0.4.0's `kv/hook.py` does: one JSON object on stdin, one reply on
stdout (`{}` to allow, `hookSpecificOutput.permissionDecision = "deny"` with
the reason to refuse), exit code 0 either way. Unreadable input, an internal
error and an exhausted 30 s scan budget all refuse with Python's texts.

Crate: `crates/kv-hook`. Entry: `kv hook [MODE]` (`crates/kv-cli/src/hook.rs`);
only `pre` decides, every other mode allows, as Python's `main` does.

| Python (`kv/hook.py`) | Rust |
| --- | --- |
| `_lex_shell`, `_lex_partial`, option walkers | `shell.rs` (character-indexed, same spans) |
| `_is_kv_reveal_command` and its helpers, `shlex.split` | `kvcmd.rs` |
| `_extract_*`, git file flags, `fnmatch`, `_has_glob_path_to_secrets`, `_has_variable_path_read`, `_extract_shell_subcommands` | `fileaccess.rs` |
| `kv.structure.resolve` (`realpath(strict=ALLOW_MISSING)`), protected paths, vault spellings, MCP/hook config files | `paths.rs` |
| `_glob_reach`, `_glob_selects_tracked` | `glob.rs` |
| `_tracked_listing`, `_exact_tracked`, `_agent_status_check`, `_agent_service_state`, `_service_unanswered` | `dynamic.rs` |
| `_pre_hook`, `_decide`, `_decide_within_budget`, `main` | `lib.rs` |

## Differences from Python

- **Glob oracle.** Python runs a real ripgrep (`rg --files --hidden --no-ignore
  --glob=PATTERN`) that it locates and validates at run time, and refuses every
  Glob when none is usable. Rust evaluates the same walk in-process with
  ripgrep's own `ignore` and `globset` crates, so no oracle binary is looked
  up, spawned or trusted. The walk keeps Python's 10 s budget and 4 MiB output
  cap; exceeding either refuses, as `_OracleUnavailable` does.
- **Scan budget.** Python arms `SIGALRM` (or a worker process). Rust decides on
  a thread and refuses when the 30 s deadline passes; the process then exits,
  which ends the thread.
- **Internal errors.** Python reports the exception class in the refusal.
  Rust reports `TypeError`/`AttributeError` where Python's string operations
  would raise on a truthy non-string field, and `RuntimeError` for a panic.
- **Windows.** Python's `_resolve_nt` and extended-length path handling are not
  ported; on non-Unix targets the dynamic layer reports the service as
  `unchecked` (a refusal). Stage 10 covers Windows.
- **Daemon replies.** The Rust daemon answers `tracked_files` with an empty
  list and `check_file` with `tracked: false` until Stage 6 adds `kv run`
  tracking, which is the truth for a daemon that has run nothing.

## Verification

- `crates/kv-hook/tests/bash_parity.rs`: every RR3 Bash command plus hand
  cases (849 texts) through Python's lexer, protected-command recognition,
  path extraction, git handling and glob rules versus the Rust port; every
  dumped field must match.
- `crates/kv-hook/tests/hook_parity.rs`: Python `_decide` versus Rust
  `decide` over the tool cases (Read/Write/Edit/Glob/Grep/Bash, symlinks,
  loops, editor configuration files, unusual field types) and, with
  `KV_RR3_CASES` pointing at the reference's `rr3_cases.json`, all 647 RR3
  inputs, in one fixture project and HOME. 841 of 841 replies matched.
- Both tests are registered in `scripts/parity_inventory.json`.
