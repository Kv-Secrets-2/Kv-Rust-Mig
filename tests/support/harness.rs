//! Test-only temporary paths and bounded subprocess collection.
//!
//! File-backed streams avoid blocked pipe readers/writers, including when a
//! child exits before consuming its input. No production timeouts are changed.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn temporary_directory(prefix: &str) -> PathBuf {
    let mut random = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .expect("read operating-system randomness for test directory");
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    // No PID or timestamp: 128 random bits provide uniqueness without making
    // socket paths longer when the process ID has more digits.
    let path = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize test temporary directory")
        .join(format!("kv{prefix}-{suffix}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("create private test directory");
    path
}

fn socket_path_fits(home: &Path) -> bool {
    let path = home.join(".kv/agent-000000000000.sock");
    // macOS permits 103 pathname bytes plus NUL, Linux 107 plus NUL. Keep
    // these Unix tests portable; bytes, not Unicode characters, count here.
    path.as_os_str().as_bytes().len() <= 103
}

pub fn socket_temp_dir(prefix: &str, relative_home: &str) -> PathBuf {
    let path = temporary_directory(prefix);
    if !socket_path_fits(&path.join(relative_home)) {
        let _ = fs::remove_dir(&path);
        panic!(
            "TMPDIR makes the test daemon socket path too long: {}. Set TMPDIR to a short directory such as /var/tmp or /tmp",
            path.join(relative_home).display()
        );
    }
    path
}

struct ProcessFiles(PathBuf);

impl Drop for ProcessFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[derive(Debug)]
pub enum ProcessError {
    Io(io::Error),
    TimedOut(Output),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "test subprocess I/O: {error}"),
            Self::TimedOut(output) => write!(
                formatter,
                "test subprocess exceeded its deadline; killed and reaped ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }
}

impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn output(
    mut command: Command,
    input: &[u8],
    timeout: Duration,
) -> Result<Output, ProcessError> {
    let files = ProcessFiles(temporary_directory("p"));
    let stdin = files.0.join("stdin");
    let stdout = files.0.join("stdout");
    let stderr = files.0.join("stderr");
    fs::write(&stdin, input)?;
    command
        .stdin(Stdio::from(File::open(&stdin)?))
        .stdout(Stdio::from(File::create(&stdout)?))
        .stderr(Stdio::from(File::create(&stderr)?));
    let deadline = Instant::now() + timeout;
    let mut child = ChildGuard(command.spawn()?);
    let (status, timed_out) = loop {
        if let Some(status) = child.0.try_wait()? {
            break (status, false);
        }
        if Instant::now() >= deadline {
            child.0.kill()?;
            break (child.0.wait()?, true);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = Output {
        status,
        stdout: fs::read(&stdout)?,
        stderr: fs::read(&stderr)?,
    };
    if timed_out {
        Err(ProcessError::TimedOut(output))
    } else {
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn subprocess_collection_preserves_nonzero_exit_and_large_streams() {
        let input = vec![b'x'; 256 * 1024];
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "cat; printf 'test stderr' >&2; exit 23"]);
        let result = output(command, &input, Duration::from_secs(5)).unwrap();
        assert_eq!(result.status.code(), Some(23));
        assert_eq!(result.stdout, input);
        assert_eq!(result.stderr, b"test stderr");
    }

    #[test]
    fn subprocess_timeout_kills_and_reaps_a_child_that_does_not_read_input() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]);
        let started = Instant::now();
        let result = output(command, &vec![b'x'; 256 * 1024], Duration::from_millis(100));
        let Err(ProcessError::TimedOut(output)) = result else {
            panic!("expected timeout, got {result:?}");
        };
        assert_eq!(output.status.signal(), Some(9));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn socket_budget_accepts_short_roots_and_rejects_long_or_multibyte_roots() {
        let suffix = "0".repeat(32);
        // PID length cannot affect these names: it is intentionally omitted.
        assert!(socket_path_fits(Path::new(&format!(
            "/var/tmp/kva5-{suffix}/python-home"
        ))));
        assert!(!socket_path_fits(Path::new(&"x".repeat(104))));
        assert!(!socket_path_fits(Path::new(&"é".repeat(52))));
    }
}
