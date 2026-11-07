# Stage 6a: `kv-sandbox` foundations

The `kv-sandbox` crate ports the parts of Python `kv/sandbox.py` that decide
what a `kv run` may do and how its child is confined, without yet running
anything. Stage 6b (grants and capability tokens), 6c (the daemon's `run`
command and `kv run`) and 6d (`cap_api`, paused jobs, POST wallets) build on it.

## Modules

| Module | Python source | What it covers |
|---|---|---|
| `classify` | `classify_command`, `_ALLOWLIST`, exfiltration patterns | work / brokered_act / guarded_env / unsafe_env / reveal modes, allowlist and refusal text |
| `redact` | `build_secret_variants`, `redact` | secret variants (URL, base64, hex, JSON, shell escapes) and output redaction |
| `runenv` | `build_run_env`, `_check_run_env_pairs`, `decode_args_bytes` | sensitive inherited names, reserved names, the run environment, `--setenv` byte framing |
| `sealed` | `SealedArgsFd`, `_sealed_args_fd`, `read_args_fd` | the memfd that carries secrets to bubblewrap, sealed against growth, shrinking, writes and more seals |
| `bwrap` | `wrap_argv`, `_emit_bwrap_option`, `launch_facts`, `_effective_launch_argv`, isolation probe | trusted bubblewrap discovery, fail-closed option table, the wrapper argv, private tmp rules, launch facts |
| `identity` | `_hash_file`, `_script_file_path`, `module_script_path`, `build_run_identity` | script hashing, `python -m` resolution, the command fingerprint |
| `capsule` | `_harden_capsule_dir`, `prepare_run_artifact_capsule`, `prepare_run_cwd_capsule`, `checked_run_cwd` | the private script copy bound over the original, the private working-folder copy |
| `scan` | `scan_leaked_files`, `snapshot_files`, `collect_changed_files`, `track_new_files`, `leak_report` | leaked-file scanning and file tracking after a run |
| `paths` | `structure.inside_secrets`, `_path_is_or_under`, `_paths_overlap` | `.secrets` fencing and path containment |

## Comparisons against Python 0.4.0

Each probe under `crates/kv-sandbox/tests/py/` runs the reference code over a
corpus the Rust test generates, and the test compares field by field. All are
registered in `scripts/parity_inventory.json`.

| Test | Cases | Compared |
|---|---|---|
| `classify_decisions_match_python` | 5,404 generated argv/allowlist/mode combinations | mode, allowed, refusal text |
| `redaction_matches_python` | generated secret values and encodings | variant sets and redacted text |
| `run_env_rules_match_python` | inherited environments, reserved and sensitive names, NUL and `=` cases | kept names, refusals, `--setenv` bytes |
| `wrapper_matches_python` | 1,922 host/run combinations (bwrap, unshare, none; six environments; five overlay sets; sixteen option sets) | wrapped argv, refusal text, launch facts |
| `scanners_match_python` | one layout: fresh and old files, nested folders, `.secrets`, folder and file links, invalid UTF-8, encoded secrets, exclusions | snapshots, changed and new files, leaked files, specific-file scan, leak report |

The wrapper comparison found one real difference during development: Rust
sorted the runtime files it hides under `~/.kv`; Python keeps directory order.
Rust now keeps directory order too.

## Deliberate differences

- **Sealed arguments are Linux-only.** Python falls back to an error on other
  systems too (`SealedArgsUnavailableError`); Rust reports the same refusal.
- **Text decoding when scanning files.** Python opens files with
  `errors="ignore"`; Rust drops invalid UTF-8 sequences the same way but
  counts the 1 MiB scan window in decoded characters per read, so chunk
  boundaries can differ. The 1 KiB overlap keeps a secret split across a
  boundary detectable on both sides.
- **System temp folder.** Rust's `temp_scan_dirs` uses `TMPDIR` then `/tmp`;
  Python's `tempfile.gettempdir()` also tries `TEMP`, `TMP`, `/var/tmp` and
  `/usr/tmp` and checks that the folder is writable.
- **Capsule refusal wording.** Where Python re-raises an arbitrary exception
  from the artifact copy, Rust reports `blocked for security: private run
  artifact failed`. The documented refusals (`script changed after approval`,
  `the run's private folder ...`, `private cwd contains symlink outside
  project`, `private cwd capsule failed`) match Python's text.
- **No old vaults.** Nothing here reads env-bundle `.enc` files or
  pre-drawer layouts.

## Not in this stage

Grants and capability tokens, the daemon's `run` command, process launch and
output streaming, tracked-file replies to the hook, stop draining, `cap_api`,
paused jobs and POST wallets. `kv preflight` is deferred to stage 9b because it
parses Python source with Python's own `ast` module.
