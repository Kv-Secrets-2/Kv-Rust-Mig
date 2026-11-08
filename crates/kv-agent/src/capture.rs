//! Launching a run's program and capturing its output within bounds (Python
//! `agent.py` `_run_bounded_capture`, `_stream_pipe_limited`, `_reap`).
//!
//! The program is the leader of a new session so a stop can end its whole
//! group without touching the service's own; stdin is `/dev/null`; stdout
//! and stderr are drained fully while only the first `MAX_RUN_OUTPUT_BYTES`
//! of each are kept. The leader is reaped under its run slot's lock, which
//! is what lets a stop's TERM/KILL say "only while the leader is
//! uncollected" (the same guarantee as Python's reap lock).
//!
//! A sealed args descriptor is inherited by the child alone: `CLOEXEC` is
//! cleared on it only inside the process-wide spawn lock, so no other
//! program the service starts at the same time can inherit another run's
//! secrets, and it is set again as soon as the spawn returns.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::fd::BorrowedFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use rustix::io::{FdFlags, fcntl_setfd};

use crate::runs::Slot;

/// Python `MAX_RUN_OUTPUT_BYTES`.
pub(crate) const MAX_RUN_OUTPUT_BYTES: usize = 1024 * 1024;
const READ_CHUNK: usize = 65536;
const REAP_POLL: Duration = Duration::from_millis(20);

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// Python `BoundedRunResult`.
pub(crate) struct BoundedRunResult {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
}

/// What a launch needs: the checked argv, the wrapper's own environment,
/// the working directory and the descriptor the child inherits.
pub(crate) struct Launch<'a> {
    pub(crate) argv: &'a [String],
    pub(crate) env: &'a BTreeMap<String, String>,
    pub(crate) cwd: Option<&'a Path>,
    pub(crate) pass_fd: Option<BorrowedFd<'a>>,
}

/// Start the program with its output piped. The caller registers the child
/// in its run slot and then calls [`capture`].
pub(crate) fn spawn(launch: &Launch<'_>) -> io::Result<Child> {
    let Some((program, args)) = launch.argv.split_first() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "argv is empty"));
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(launch.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(cwd) = launch.cwd {
        command.current_dir(cwd);
    }
    let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(fd) = launch.pass_fd {
        fcntl_setfd(fd, FdFlags::empty())?;
    }
    let spawned = command.spawn();
    if let Some(fd) = launch.pass_fd {
        let _ = fcntl_setfd(fd, FdFlags::CLOEXEC);
    }
    spawned
}

/// Python `_stream_pipe_limited`: drain fully, keep the first `max_bytes`.
fn drain_limited<R: Read>(mut pipe: R, max_bytes: usize) -> (String, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        let read = match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let remaining = max_bytes.saturating_sub(kept.len());
        let take = read.min(remaining);
        kept.extend_from_slice(&chunk[..take]);
        if read > take {
            truncated = true;
        }
    }
    (String::from_utf8_lossy(&kept).into_owned(), truncated)
}

fn reader<R: Read + Send + 'static>(
    name: &str,
    pipe: R,
) -> io::Result<thread::JoinHandle<(String, bool)>> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || drain_limited(pipe, MAX_RUN_OUTPUT_BYTES))
}

/// Python `_reap`: wait for the leader under the slot's lock.
fn reap(slot: &Slot) -> io::Result<ExitStatus> {
    loop {
        {
            let mut state = slot.lock().unwrap_or_else(|e| e.into_inner());
            let Some(child) = state.proc.as_mut() else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "the run's process is gone",
                ));
            };
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
        }
        thread::sleep(REAP_POLL);
    }
}

/// Drain the registered run's pipes and reap it.
pub(crate) fn capture(
    slot: &Slot,
    stdout: ChildStdout,
    stderr: ChildStderr,
) -> io::Result<BoundedRunResult> {
    let out = reader("kv-run-stdout", stdout)?;
    let err = reader("kv-run-stderr", stderr)?;
    let status = reap(slot)?;
    let (stdout, stdout_truncated) = out
        .join()
        .map_err(|_| io::Error::other("the stdout reader panicked"))?;
    let (stderr, stderr_truncated) = err
        .join()
        .map_err(|_| io::Error::other("the stderr reader panicked"))?;
    Ok(BoundedRunResult {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::Lifecycle;
    use crate::runs::{Runs, new_slot};

    fn run(argv: &[&str]) -> BoundedRunResult {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let env = BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]);
        let launch = Launch {
            argv: &argv,
            env: &env,
            cwd: None,
            pass_fd: None,
        };
        let mut child = spawn(&launch).expect("spawns");
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let lifecycle = Lifecycle::new();
        let runs = Runs::new();
        let slot = new_slot(None, &argv[0], false, Some(false), false);
        runs.register(&lifecycle, &slot, child);
        let result = capture(&slot, stdout, stderr).expect("captures");
        runs.collected(&slot);
        runs.unregister(&lifecycle, &slot);
        result
    }

    #[test]
    fn captures_both_streams_and_the_exit_code() {
        let result = run(&["sh", "-c", "printf out; printf err >&2; exit 3"]);
        assert_eq!(result.status.code(), Some(3));
        assert_eq!(result.stdout, "out");
        assert_eq!(result.stderr, "err");
        assert!(!result.stdout_truncated);
        assert!(!result.stderr_truncated);
    }

    #[test]
    fn output_is_bounded_and_marked_truncated() {
        let result = run(&["sh", "-c", "head -c 1500000 /dev/zero | tr '\\0' a"]);
        assert_eq!(result.status.code(), Some(0));
        assert_eq!(result.stdout.len(), MAX_RUN_OUTPUT_BYTES);
        assert!(result.stdout_truncated);
        assert!(!result.stderr_truncated);
    }

    #[test]
    fn stdin_is_null_and_env_is_only_what_was_given() {
        // `cat` returns at once on a null stdin; the shell adds only its own
        // variables (PWD, SHLVL, ...), never this process's.
        assert!(std::env::var_os("HOME").is_some());
        let result = run(&["sh", "-c", "cat; env"]);
        assert_eq!(result.status.code(), Some(0));
        let names: Vec<&str> = result
            .stdout
            .lines()
            .filter_map(|line| line.split_once('=').map(|(name, _)| name))
            .collect();
        assert!(names.contains(&"PATH"), "{names:?}");
        assert!(!names.contains(&"HOME"), "{names:?}");
    }
}
