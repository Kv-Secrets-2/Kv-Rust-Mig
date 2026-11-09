//! Descriptor-relative POSIX operations for Python-compatible audit storage.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::IntoRawFd;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt};
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{self as unix, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde_json::Value;

#[cfg(target_os = "macos")]
#[path = "darwin.rs"]
mod darwin;

const LOG: &str = "audit.jsonl";
const HEALTH: &str = "audit-health.json";
const UNKEPT: &str = "audit-health.unkept";
const UNCERTAIN: &str = "audit.uncertain";
const POLL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub(crate) struct Directory {
    file: File,
}

#[derive(Debug)]
pub(crate) struct Lock {
    file: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LockFailure {
    pub(crate) unsupported: bool,
    pub(crate) timed_out: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AppendFailure {
    FileRefused,
    WriteFailed,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[allow(unsafe_code)]
fn close_file(file: File) -> io::Result<()> {
    let descriptor = file.into_raw_fd();
    // SAFETY: into_raw_fd transfers the exclusively owned, valid descriptor
    // out of File, so no destructor can close it again. try_close consumes it
    // even on error; never retry an error on a possibly reused descriptor.
    unsafe { rustix::io::try_close(descriptor) }.map_err(Into::into)
}

fn harden(file: &File, mode: rustix::fs::RawMode) -> io::Result<()> {
    unix::fchmod(file, Mode::from_bits_truncate(mode))?;
    #[cfg(target_os = "macos")]
    darwin::clear_acl(file)?;
    Ok(())
}

fn single_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(invalid("not a regular single-name audit file"));
    }
    Ok(())
}

fn create_directory(path: &Path) -> io::Result<()> {
    // Match makedirs: missing ancestors use ordinary directory permissions;
    // only the audit directory itself is created private from its first inode.
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

impl Directory {
    /// With `create == false`, opening is a read-only probe: no mkdir/chmod/ACL repair.
    pub(crate) fn open(path: &Path, create: bool) -> io::Result<Self> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = match unix::open(path, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) if create => {
                create_directory(path)?;
                unix::open(path, flags, Mode::empty())?
            }
            Err(error) => return Err(error.into()),
        };
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(invalid("audit directory is not owned by this account"));
        }
        if create {
            // Always harden, including an existing 0700 directory with a Darwin ACL.
            harden(&file, 0o700)?;
        }
        Ok(Self { file })
    }

    fn open_child(&self, name: &str, flags: OFlags) -> io::Result<File> {
        let flags = flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        Ok(File::from(unix::openat(
            &self.file,
            name,
            flags,
            Mode::from_bits_truncate(0o600),
        )?))
    }

    pub(crate) fn lock(&self, name: &str, wait: Duration) -> Result<Lock, LockFailure> {
        self.lock_with_hook(name, wait, || {})
    }

    fn lock_with_hook(
        &self,
        name: &str,
        wait: Duration,
        mut opened: impl FnMut(),
    ) -> Result<Lock, LockFailure> {
        let deadline = Instant::now() + wait;
        let failed = LockFailure {
            unsupported: false,
            timed_out: false,
        };
        loop {
            let file = loop {
                match self.open_child(name, OFlags::RDWR | OFlags::CREATE) {
                    Ok(file) => break file,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        // APFS can report ENOENT while another writer creates the name.
                        if !pause(deadline) {
                            return Err(failed);
                        }
                    }
                    Err(_) => return Err(failed),
                }
            };
            single_file(&file).map_err(|_| failed)?;
            harden(&file, 0o600).map_err(|_| failed)?;
            opened();
            loop {
                match unix::flock(&file, unix::FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => break,
                    Err(error) if error == Errno::ACCESS || error == Errno::AGAIN => {
                        if !pause(deadline) {
                            return Err(LockFailure {
                                timed_out: true,
                                ..failed
                            });
                        }
                    }
                    Err(error) => {
                        return Err(LockFailure {
                            unsupported: [
                                Errno::NOLCK,
                                Errno::NOTSUP,
                                Errno::OPNOTSUPP,
                                Errno::NOSYS,
                            ]
                            .contains(&error),
                            ..failed
                        });
                    }
                }
            }
            let lock = Lock { file };
            if self.lock_matches(&lock, name).map_err(|_| failed)? {
                return Ok(lock);
            }
            // Closing the stale inode releases its flock before retrying the name.
            drop(lock);
            if !pause(deadline) {
                return Err(LockFailure {
                    timed_out: true,
                    ..failed
                });
            }
        }
    }

    // Darwin's stat device is signed and narrower than MetadataExt::dev.
    #[allow(clippy::unnecessary_cast)]
    pub(crate) fn lock_matches(&self, lock: &Lock, name: &str) -> io::Result<bool> {
        let held = lock.file.metadata()?;
        match unix::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(named) => Ok(held.dev() == named.st_dev as u64 && held.ino() == named.st_ino as u64),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn tail_hash(&self) -> Value {
        self.read_tail_hash()
            .unwrap_or_else(|_| Value::String("genesis".into()))
    }

    fn read_tail_hash(&self) -> io::Result<Value> {
        const CHUNK: usize = 64 * 1024;
        const MAX: usize = 8 * 1024 * 1024;
        let file = self.open_child(LOG, OFlags::RDONLY)?;
        single_file(&file)?;
        let mut pos = file.metadata()?.len();
        let mut buffer = Vec::new();
        // The inclusive condition intentionally matches Python: the final read
        // can extend one chunk beyond MAX before recognizing a complete line.
        while pos > 0 && buffer.len() <= MAX {
            let step = (CHUNK as u64).min(pos) as usize;
            pos -= step as u64;
            let mut next = vec![0; step];
            let got = file.read_at(&mut next, pos)?;
            next.truncate(got);
            next.extend_from_slice(&buffer);
            buffer = next;
            let content = trim_python_bytes_end(&buffer);
            if content.is_empty() {
                continue;
            }
            let newline = content.iter().rposition(|byte| *byte == b'\n');
            if newline.is_none() && pos > 0 {
                continue;
            }
            let line = trim_ascii(&content[newline.map_or(0, |index| index + 1)..]);
            let entry: Value =
                crate::python_json::from_slice(line).map_err(|_| invalid("invalid audit tail"))?;
            return entry
                .as_object()
                .map(|entry| {
                    entry
                        .get("hash")
                        .cloned()
                        .unwrap_or_else(|| Value::String("genesis".into()))
                })
                .ok_or_else(|| invalid("audit tail is not an object"));
        }
        Ok(Value::String("genesis".into()))
    }

    pub(crate) fn append(&self, bytes: &[u8]) -> Result<(), AppendFailure> {
        self.append_with_close(bytes, close_file)
    }

    fn append_with_close(
        &self,
        bytes: &[u8],
        close: impl FnOnce(File) -> io::Result<()>,
    ) -> Result<(), AppendFailure> {
        let mut file = self
            .open_child(LOG, OFlags::WRONLY | OFlags::CREATE | OFlags::APPEND)
            .map_err(|_| AppendFailure::FileRefused)?;
        single_file(&file).map_err(|_| AppendFailure::FileRefused)?;
        harden(&file, 0o600).map_err(|_| AppendFailure::FileRefused)?;
        // Unbuffered writes report errors before returning. Python does not fsync
        // the log; durability barriers belong to the health and marker files.
        let written = file.write_all(bytes);
        let closed = close(file);
        written.and(closed).map_err(|_| AppendFailure::WriteFailed)
    }

    pub(crate) fn read_bounded(&self, name: &str, limit: usize) -> io::Result<Vec<u8>> {
        let file = self.open_child(name, OFlags::RDONLY)?;
        single_file(&file)?;
        if file.metadata()?.len() > limit as u64 {
            return Err(invalid("audit file exceeds its bound"));
        }
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(invalid("audit file exceeds its bound"));
        }
        Ok(bytes)
    }

    pub(crate) fn exists(&self, name: &str) -> bool {
        !matches!(
            unix::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW),
            Err(Errno::NOENT)
        )
    }

    pub(crate) fn write_health(&self, bytes: &[u8]) -> io::Result<()> {
        self.write_health_with_close(bytes, close_file)
    }

    fn write_health_with_close(
        &self,
        bytes: &[u8],
        close: impl FnMut(File) -> io::Result<()>,
    ) -> io::Result<()> {
        let result = self.publish_health(bytes, close);
        if result.is_err() {
            self.mark_unkept();
        }
        result
    }

    fn publish_health(
        &self,
        bytes: &[u8],
        mut close: impl FnMut(File) -> io::Result<()>,
    ) -> io::Result<()> {
        for attempt in 0..8 {
            let name = format!("{HEALTH}.{}.{attempt}.new", std::process::id());
            let mut file =
                match self.open_child(&name, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL) {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                };
            let written = (|| {
                single_file(&file)?;
                harden(&file, 0o600)?;
                file.write_all(bytes)?;
                file.sync_all()
            })();
            let closed = close(file);
            if let Err(error) = written.and(closed) {
                self.mark_unkept_from(Some(&name));
                return Err(error);
            }
            if let Err(error) = unix::renameat(&self.file, &name, &self.file, HEALTH) {
                let _ = unix::unlinkat(&self.file, &name, AtFlags::empty());
                return Err(error.into());
            }
            self.file.sync_all()?;
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "audit health temporary names occupied",
        ))
    }

    pub(crate) fn mark_unkept(&self) {
        self.mark_unkept_from(None);
    }

    fn mark_unkept_from(&self, temporary: Option<&str>) {
        if let Some(name) = temporary {
            if unix::renameat(&self.file, name, &self.file, UNKEPT).is_ok() {
                let _ = self.file.sync_all();
                return;
            }
            let _ = unix::unlinkat(&self.file, name, AtFlags::empty());
        }
        let Ok(file) = self.open_child(UNKEPT, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)
        else {
            // An existing name is already a marker. Never chmod/open its target.
            return;
        };
        let _ = (|| -> io::Result<()> {
            harden(&file, 0o600)?;
            file.sync_all()?;
            self.file.sync_all()
        })();
    }

    pub(crate) fn mark_uncertain(&self) -> io::Result<()> {
        match self.open_child(UNCERTAIN, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL) {
            Ok(file) => {
                harden(&file, 0o600)?;
                file.sync_all()?;
                self.file.sync_all()
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => self.file.sync_all(),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn clear_unkept(&self) {
        let _ = unix::unlinkat(&self.file, UNKEPT, AtFlags::empty());
    }

    pub(crate) fn folder_state(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        match darwin::has_acl(&self.file) {
            Ok(true) => return "acl",
            Err(_) => return "unreadable",
            Ok(false) => {}
        }
        match self.file.metadata() {
            Ok(metadata) if metadata.mode() & 0o7777 == 0o700 => "ok",
            Ok(_) => "mode",
            Err(_) => "unreadable",
        }
    }

    pub(crate) fn probe_log(&self) -> &'static str {
        match self.open_child(LOG, OFlags::RDONLY) {
            Ok(file) if single_file(&file).is_ok() => {}
            Ok(_) => return "refused",
            Err(error) if error.kind() == io::ErrorKind::NotFound => return "absent",
            Err(_) => return "refused",
        }
        // Match os.access: unsupported descriptor-relative access probes do not
        // turn an otherwise valid file into a refusal.
        match unix::accessat(
            &self.file,
            LOG,
            unix::Access::WRITE_OK,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(error)
                if ![Errno::NOSYS, Errno::NOTSUP, Errno::OPNOTSUPP, Errno::INVAL]
                    .contains(&error) =>
            {
                "refused"
            }
            _ => "ok",
        }
    }
}

fn pause(deadline: Instant) -> bool {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        false
    } else {
        std::thread::sleep(POLL.min(remaining));
        true
    }
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    // Python bytes.strip uses ASCII whitespace (including VT/FF, not 0x1c).
    let bytes = trim_python_bytes_end(bytes);
    let start = bytes
        .iter()
        .position(|byte| !b" \t\n\r\x0b\x0c".contains(byte))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn trim_python_bytes_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| !b" \t\n\r\x0b\x0c".contains(byte))
        .map_or(0, |index| index + 1);
    &bytes[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kv-audit-fs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn unsafe_log_names_are_refused_without_touching_targets_or_blocking() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        let target = temp.0.join("unrelated");
        fs::write(&target, b"unchanged").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        for kind in ["symlink", "hardlink", "fifo", "directory"] {
            let log = temp.0.join(LOG);
            match kind {
                "symlink" => symlink(&target, &log).unwrap(),
                "hardlink" => fs::hard_link(&target, &log).unwrap(),
                "fifo" => {
                    // mkfifoat is unavailable on Darwin; this fixture command
                    // takes one explicit path and never executes a shell.
                    assert!(
                        std::process::Command::new("mkfifo")
                            .arg(&log)
                            .status()
                            .unwrap()
                            .success()
                    );
                }
                _ => fs::create_dir(&log).unwrap(),
            }
            let started = Instant::now();
            assert_eq!(directory.tail_hash(), Value::String("genesis".into()));
            assert_eq!(
                directory.append(b"must not land\n"),
                Err(AppendFailure::FileRefused)
            );
            assert_eq!(directory.probe_log(), "refused");
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{kind} open blocked"
            );
            assert_eq!(fs::read(&target).unwrap(), b"unchanged");
            assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o644);
            if kind == "directory" {
                fs::remove_dir(log).unwrap();
            } else {
                fs::remove_file(log).unwrap();
            }
        }
    }

    #[test]
    fn directory_probe_does_not_harden_and_directory_links_are_refused() {
        let temp = Temp::new();
        let path = temp.0.join("audit");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let probe = Directory::open(&path, false).unwrap();
        assert_eq!(probe.folder_state(), "mode");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o755);
        let linked = temp.0.join("linked");
        symlink(&path, &linked).unwrap();
        assert!(Directory::open(&linked, true).is_err());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o755);
        Directory::open(&path, true).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn held_directory_remains_authority_after_its_name_is_replaced() {
        let temp = Temp::new();
        let path = temp.0.join("audit");
        let held = Directory::open(&path, true).unwrap();
        held.append(b"{\"hash\":\"before\"}\n").unwrap();
        let renamed = temp.0.join("held");
        fs::rename(&path, &renamed).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join(LOG), b"replacement sentinel").unwrap();
        assert_eq!(held.tail_hash(), Value::String("before".into()));
        held.append(b"{\"hash\":\"after\"}\n").unwrap();
        assert_eq!(fs::read(path.join(LOG)).unwrap(), b"replacement sentinel");
        assert_eq!(held.tail_hash(), Value::String("after".into()));
    }

    #[test]
    fn append_reports_close_only_failure_after_written_bytes() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        let result = directory.append_with_close(b"written\n", |file| {
            drop(file);
            Err(io::Error::other("injected close failure"))
        });
        assert_eq!(result, Err(AppendFailure::WriteFailed));
        assert_eq!(fs::read(temp.0.join(LOG)).unwrap(), b"written\n");
    }

    #[test]
    fn health_close_failure_retains_old_record_and_marks_unkept() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        fs::write(temp.0.join(HEALTH), b"previous health").unwrap();
        let result = directory.write_health_with_close(b"new health", |file| {
            drop(file);
            Err(io::Error::other("injected close failure"))
        });
        assert!(result.is_err());
        assert_eq!(fs::read(temp.0.join(HEALTH)).unwrap(), b"previous health");
        assert!(temp.0.join(UNKEPT).exists());
        assert_eq!(fs::read(temp.0.join(UNKEPT)).unwrap(), b"new health");
    }

    #[test]
    fn tail_reads_last_nonblank_line_without_falling_back_over_corruption() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        for (bytes, expected) in [
            (
                b"{\"hash\":\"old\"}\nnot-json\n".as_slice(),
                serde_json::json!("genesis"),
            ),
            (b"{\"hash\":null}\n \t\r\n\x0b\x0c".as_slice(), Value::Null),
            (
                b"{\"hash\":[1,true]}\n".as_slice(),
                serde_json::json!([1, true]),
            ),
            (b"{}\n".as_slice(), serde_json::json!("genesis")),
        ] {
            fs::write(temp.0.join(LOG), bytes).unwrap();
            assert_eq!(directory.tail_hash(), expected);
        }
        let mut content = vec![b'x'; 2 * 64 * 1024];
        content.extend_from_slice(b"\n{\"hash\":\"tail\"}\n");
        fs::write(temp.0.join(LOG), content).unwrap();
        assert_eq!(directory.tail_hash(), serde_json::json!("tail"));
    }

    #[test]
    fn replacing_a_lock_before_flock_retries_the_current_inode() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        let mut first = true;
        let lock = directory
            .lock_with_hook("audit.lock", Duration::from_secs(1), || {
                if first {
                    first = false;
                    fs::rename(temp.0.join("audit.lock"), temp.0.join("old.lock")).unwrap();
                    fs::write(temp.0.join("audit.lock"), b"").unwrap();
                }
            })
            .unwrap();
        assert!(directory.lock_matches(&lock, "audit.lock").unwrap());
        assert!(!directory.lock_matches(&lock, "old.lock").unwrap());
    }

    #[test]
    fn waiting_writer_does_not_enter_on_a_replaced_lock_inode() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        let original = directory
            .lock("audit.lock", Duration::from_secs(1))
            .unwrap();
        let (opened_tx, opened_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let path = temp.0.clone();
        let worker = std::thread::spawn(move || {
            let directory = Directory::open(&path, true).unwrap();
            let lock = directory
                .lock_with_hook("audit.lock", Duration::from_secs(3), || {
                    let _ = opened_tx.send(());
                })
                .unwrap();
            assert!(directory.lock_matches(&lock, "audit.lock").unwrap());
            done_tx.send(()).unwrap();
        });
        opened_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        fs::rename(temp.0.join("audit.lock"), temp.0.join("old.lock")).unwrap();
        let replacement = directory
            .lock("audit.lock", Duration::from_secs(1))
            .unwrap();
        drop(original);
        // Wait until the worker rejected the old inode and opened the new name.
        opened_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(replacement);
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn existing_markers_are_not_opened_or_hardened_and_publication_is_private() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        let target = temp.0.join("unrelated");
        fs::write(&target, b"kept").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&target, temp.0.join(UNCERTAIN)).unwrap();
        symlink(&target, temp.0.join(UNKEPT)).unwrap();
        directory.mark_uncertain().unwrap();
        directory.mark_unkept();
        assert_eq!(fs::read(&target).unwrap(), b"kept");
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o644);
        directory
            .write_health(b"{\"lost\":null,\"state\":\"ok\",\"v\":1}\n")
            .unwrap();
        assert_eq!(
            fs::metadata(temp.0.join(HEALTH)).unwrap().mode() & 0o777,
            0o600
        );
        assert!(directory.exists(UNKEPT));
        directory.clear_unkept();
        assert!(!directory.exists(UNKEPT));
        assert_eq!(fs::read(&target).unwrap(), b"kept");
    }

    #[test]
    fn failed_health_publication_marks_unknown_without_replacing_old_record() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        fs::write(temp.0.join(HEALTH), b"old").unwrap();
        for attempt in 0..8 {
            fs::write(
                temp.0
                    .join(format!("{HEALTH}.{}.{attempt}.new", std::process::id())),
                b"occupied",
            )
            .unwrap();
        }
        assert!(directory.write_health(b"new").is_err());
        assert_eq!(fs::read(temp.0.join(HEALTH)).unwrap(), b"old");
        assert!(directory.exists(UNKEPT));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_descriptor_hardening_removes_directory_and_log_acls() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0, true).unwrap();
        assert!(
            std::process::Command::new("chmod")
                .args(["+a", "everyone allow list,add_file,delete_child"])
                .arg(&temp.0)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(directory.file.metadata().unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            Directory::open(&temp.0, false).unwrap().folder_state(),
            "acl"
        );
        let directory = Directory::open(&temp.0, true).unwrap();
        assert_eq!(directory.folder_state(), "ok");
        directory.append(b"first\n").unwrap();
        assert!(
            std::process::Command::new("chmod")
                .args(["+a", "everyone allow read"])
                .arg(temp.0.join(LOG))
                .status()
                .unwrap()
                .success()
        );
        let log = directory.open_child(LOG, OFlags::RDONLY).unwrap();
        assert!(darwin::has_acl(&log).unwrap());
        directory.append(b"second\n").unwrap();
        assert!(!darwin::has_acl(&log).unwrap());
    }
}
