use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{StoreError, fsx, pyjson};

pub const MARKER: &str = "vault-marker";
const RECORD_LIMIT: usize = 16 * 1024;
const START_REFUSAL: &str = "This vault was not created or approved on this machine; run kv vault approve-local at your terminal.";
const LOCAL_CHANGED: &str = "Local vault approval changed; run kv vault approve-local again.";

#[derive(Debug, Error)]
#[error("{0}")]
pub struct VaultOriginError(pub String);

impl From<StoreError> for VaultOriginError {
    fn from(error: StoreError) -> Self {
        Self(error.to_string())
    }
}

impl From<std::io::Error> for VaultOriginError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

#[cfg(windows)]
fn unsupported<T>() -> Result<T, VaultOriginError> {
    Err(VaultOriginError(
        "local vault provenance is not yet supported on Windows".into(),
    ))
}

pub fn state_dir() -> Result<PathBuf, VaultOriginError> {
    #[cfg(windows)]
    {
        return unsupported();
    }
    #[cfg(unix)]
    {
        let home =
            std::env::var_os("HOME").ok_or_else(|| VaultOriginError("HOME is not set".into()))?;
        Ok(PathBuf::from(home).join(".kv"))
    }
}

fn random_hex(bytes: usize) -> Result<String, VaultOriginError> {
    let mut value = vec![0u8; bytes];
    getrandom::getrandom(&mut value)
        .map_err(|_| VaultOriginError("operating-system randomness unavailable".into()))?;
    Ok(hex(&value))
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn record_name(path: &str) -> String {
    format!(
        "vault-origin-{}.json",
        hex(&Sha256::digest(path.as_bytes()))
    )
}

#[cfg(unix)]
struct StateFolder {
    dir: File,
}

#[cfg(unix)]
impl StateFolder {
    fn open(create: bool) -> Result<Option<Self>, VaultOriginError> {
        use rustix::fs::{Mode, OFlags, fchmod, open};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path = state_dir()?;
        if create {
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = match open(&path, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(_error) => {
                return Err(VaultOriginError(format!(
                    "{} is not a real directory",
                    path.display()
                )));
            }
        };
        let dir = File::from(fd);
        let metadata = dir.metadata()?;
        let named = fs::symlink_metadata(&path)?;
        if !metadata.is_dir()
            || named.file_type().is_symlink()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || (metadata.dev(), metadata.ino()) != (named.dev(), named.ino())
        {
            return Err(VaultOriginError(format!(
                "{} is not a folder owned by this account",
                path.display()
            )));
        }
        if metadata.mode() & 0o777 != 0o700 {
            fchmod(&dir, Mode::from_bits_truncate(0o700))
                .map_err(|error| VaultOriginError(error.to_string()))?;
        }
        Ok(Some(Self { dir }))
    }

    fn read(&self, name: &str) -> Result<Option<Value>, VaultOriginError> {
        use rustix::fs::{Mode, OFlags, openat};
        use std::os::unix::fs::MetadataExt;

        let fd = match openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => return Err(VaultOriginError(error.to_string())),
        };
        let mut file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(VaultOriginError(
                "The local vault record is not a regular file.".into(),
            ));
        }
        if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o777 != 0o600
        {
            return Err(VaultOriginError(
                "The local vault record is not private; restore it from a trusted local backup."
                    .into(),
            ));
        }
        if metadata.len() > RECORD_LIMIT as u64 {
            return Err(VaultOriginError(
                "The local vault record is invalid; restore it from a trusted local backup.".into(),
            ));
        }
        let mut raw = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut raw)?;
        let record: Value = serde_json::from_slice(&raw).map_err(|_| {
            VaultOriginError(
                "The local vault record is invalid; restore it from a trusted local backup.".into(),
            )
        })?;
        if !valid_record(&record) {
            return Err(VaultOriginError(
                "The local vault record is invalid; restore it from a trusted local backup.".into(),
            ));
        }
        Ok(Some(record))
    }

    fn write(&self, name: &str, record: &Value) -> Result<(), VaultOriginError> {
        use rustix::fs::{AtFlags, Mode, OFlags, fchmod, fsync, openat, renameat, unlinkat};
        use std::os::fd::AsFd;

        let temporary = format!(".kv-write-{}.tmp", random_hex(16)?);
        let mut file = File::from(
            openat(
                &self.dir,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|error| VaultOriginError(error.to_string()))?,
        );
        let result = (|| {
            fchmod(&file, Mode::RUSR | Mode::WUSR)
                .map_err(|error| VaultOriginError(error.to_string()))?;
            let bytes = pyjson::to_vec_python(record, true)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            renameat(&self.dir, &temporary, &self.dir, name)
                .map_err(|error| VaultOriginError(error.to_string()))?;
            fsync(self.dir.as_fd()).map_err(|error| VaultOriginError(error.to_string()))?;
            Ok(())
        })();
        let _ = unlinkat(&self.dir, &temporary, AtFlags::empty());
        result
    }

    fn lock(&self) -> Result<FileLock, VaultOriginError> {
        use rustix::fs::{Mode, OFlags, flock, openat};
        use std::os::unix::fs::MetadataExt;

        let file = File::from(
            openat(
                &self.dir,
                "vaults.lock",
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|error| VaultOriginError(error.to_string()))?,
        );
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(VaultOriginError(
                "the list's lock is not a private file".into(),
            ));
        }
        flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|error| VaultOriginError(error.to_string()))?;
        Ok(FileLock(file))
    }
}

#[cfg(unix)]
struct FileLock(File);

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}

fn valid_record(record: &Value) -> bool {
    let Some(object) = record.as_object() else {
        return false;
    };
    object.get("version").and_then(Value::as_u64) == Some(1)
        && object.get("vault").is_some_and(Value::is_object)
        && object
            .get("source")
            .and_then(Value::as_str)
            .is_some_and(|source| {
                matches!(source, "created" | "owner-approved" | "observed-unsafe")
            })
        && object.get("exposed").is_some_and(Value::is_boolean)
}

pub fn identity(root: impl AsRef<Path>) -> Result<Value, VaultOriginError> {
    #[cfg(windows)]
    {
        let _ = root;
        return unsupported();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let path = fs::canonicalize(root.as_ref())?;
        let shown = path
            .to_str()
            .ok_or_else(|| VaultOriginError("vault path cannot be encoded".into()))?;
        let secrets = path.join(".secrets");
        let metadata = fs::symlink_metadata(&secrets)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(VaultOriginError(
                ".secrets must be a real private directory".into(),
            ));
        }
        if metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(VaultOriginError(
                "This vault belongs to another account; create a new vault with kv init.".into(),
            ));
        }
        let marker = match fsx::read_regular_limit(&secrets.join(MARKER), "vault marker", 128) {
            Ok(bytes) => String::from_utf8(bytes).ok(),
            Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(VaultOriginError(error.to_string())),
        };
        Ok(json!({
            "path": shown,
            "device": metadata.dev(),
            "inode": metadata.ino(),
            "marker": marker
        }))
    }
}

fn record_path_name(here: &Value) -> Result<String, VaultOriginError> {
    let path = here
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| VaultOriginError("vault identity is invalid".into()))?;
    Ok(record_name(path))
}

fn read_record(
    folder: Option<&StateFolder>,
    here: &Value,
) -> Result<Option<Value>, VaultOriginError> {
    let Some(folder) = folder else {
        return Ok(None);
    };
    folder.read(&record_path_name(here)?)
}

fn write_record(
    folder: &StateFolder,
    here: &Value,
    record: &Value,
) -> Result<(), VaultOriginError> {
    folder.write(&record_path_name(here)?, record)
}

pub fn check_key(root: impl AsRef<Path>) -> Result<Option<String>, VaultOriginError> {
    #[cfg(windows)]
    {
        let _ = root;
        return unsupported();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let root = fs::canonicalize(root.as_ref())?;
        if tracked_key(&root)? {
            return Ok(Some("The key is tracked by git; rotate any affected credentials and create a new vault with kv init.".into()));
        }
        let path = root.join(".secrets/key");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(VaultOriginError(
                "the key must be a regular private file".into(),
            ));
        }
        if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o777 != 0o600
        {
            return Ok(Some("The key was readable outside its owner or is not private; rotate any affected credentials and create a new vault with kv init.".into()));
        }
        Ok(None)
    }
}

#[cfg(unix)]
fn tracked_key(root: &Path) -> Result<bool, VaultOriginError> {
    let mut parent = root;
    loop {
        if fs::symlink_metadata(parent.join(".git")).is_ok() {
            break;
        }
        let Some(next) = parent.parent() else {
            return Ok(false);
        };
        if next == parent {
            return Ok(false);
        }
        parent = next;
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("ls-files")
        .arg("--cached")
        .arg("-z")
        .arg("--")
        .arg(".secrets/key")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (name, value) in std::env::vars_os() {
        if !name.to_string_lossy().starts_with("GIT_") {
            command.env(name, value);
        }
    }
    command.env("GIT_OPTIONAL_LOCKS", "0");
    let mut child = command.spawn().map_err(|_| {
        VaultOriginError(
            "Cannot check whether git tracks the key; repair access to the repository and retry."
                .into(),
        )
    })?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().map_err(|_| {
                    VaultOriginError("Cannot check whether git tracks the key; repair access to the repository and retry.".into())
                })?;
                if !status.success() {
                    return Err(VaultOriginError("Cannot check whether git tracks the key; repair access to the repository and retry.".into()));
                }
                return Ok(!output.stdout.is_empty());
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(VaultOriginError("Cannot check whether git tracks the key; repair access to the repository and retry.".into()));
            }
        }
    }
}

pub fn require_local(root: impl AsRef<Path>) -> Result<Value, VaultOriginError> {
    #[cfg(windows)]
    {
        let _ = root;
        return unsupported();
    }
    #[cfg(unix)]
    {
        let root = root.as_ref();
        let here = identity(root)?;
        let folder = StateFolder::open(false)?;
        let record = read_record(folder.as_ref(), &here)?;
        if record
            .as_ref()
            .and_then(|value| value.get("exposed"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(VaultOriginError("The key was previously exposed; rotate any affected credentials and create a new vault with kv init.".into()));
        }
        if let Some(problem) = check_key(root)? {
            let folder = StateFolder::open(true)?.ok_or_else(|| {
                VaultOriginError("could not create the local vault state directory".into())
            })?;
            let _lock = folder.lock()?;
            let source = record
                .as_ref()
                .and_then(|value| value.get("source"))
                .cloned()
                .unwrap_or_else(|| Value::String("observed-unsafe".into()));
            write_record(
                &folder,
                &here,
                &json!({
                    "version":1,
                    "vault":here,
                    "exposed":true,
                    "source":source
                }),
            )?;
            return Err(VaultOriginError(problem));
        }
        let Some(record) = record.filter(|record| {
            record.get("vault") == Some(&here)
                && here
                    .get("marker")
                    .and_then(Value::as_str)
                    .is_some_and(|marker| !marker.is_empty())
                && record.get("local_id").and_then(Value::as_str).is_some()
        }) else {
            return Err(VaultOriginError(START_REFUSAL.into()));
        };
        Ok(record)
    }
}

pub fn record_created(root: impl AsRef<Path>) -> Result<Value, VaultOriginError> {
    #[cfg(windows)]
    {
        let _ = root;
        return unsupported();
    }
    #[cfg(unix)]
    {
        let root = root.as_ref();
        let marker = random_hex(32)?;
        fsx::write_atomic(
            &root.join(".secrets").join(MARKER),
            marker.as_bytes(),
            false,
        )?;
        let here = identity(root)?;
        let folder = StateFolder::open(true)?.ok_or_else(|| {
            VaultOriginError("could not create the local vault state directory".into())
        })?;
        let _lock = folder.lock()?;
        let record = json!({
            "version":1,
            "vault":here,
            "source":"created",
            "exposed":false,
            "local_id":random_hex(32)?
        });
        write_record(&folder, &here, &record)?;
        Ok(record)
    }
}

pub fn record_config_approval(
    root: impl AsRef<Path>,
    local_record: &Value,
    digest: &str,
) -> Result<Value, VaultOriginError> {
    #[cfg(windows)]
    {
        let _ = (root, local_record, digest);
        return unsupported();
    }
    #[cfg(unix)]
    {
        let here = identity(root)?;
        let folder =
            StateFolder::open(false)?.ok_or_else(|| VaultOriginError(LOCAL_CHANGED.into()))?;
        let _lock = folder.lock()?;
        let current = read_record(Some(&folder), &here)?;
        if current.as_ref() != Some(local_record) || local_record.get("vault") != Some(&here) {
            return Err(VaultOriginError(LOCAL_CHANGED.into()));
        }
        let mut updated = local_record.clone();
        updated
            .as_object_mut()
            .expect("local record is an object")
            .insert("config_sha256".into(), Value::String(digest.into()));
        write_record(&folder, &here, &updated)?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_writer_matches_python_json_dumps_defaults() {
        let record = json!({
            "vault":{"path":"/tmp/vault","marker":"café","inode":7,"device":3},
            "source":"created","version":1,"exposed":false,"local_id":"00"
        });
        assert_eq!(
            pyjson::to_vec_python(&record, true).unwrap(),
            br#"{"exposed": false, "local_id": "00", "source": "created", "vault": {"device": 3, "inode": 7, "marker": "caf\u00e9", "path": "/tmp/vault"}, "version": 1}"#
        );
    }
}
