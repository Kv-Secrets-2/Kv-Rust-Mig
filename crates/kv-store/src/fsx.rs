use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::StoreError;

pub const VAULT_FILE_LIMIT: usize = 64 * 1024 * 1024;

pub(crate) struct StorageLock {
    identity: PathBuf,
    _file: File,
}

pub(crate) struct ConfigLock {
    identity: PathBuf,
    _file: Option<File>,
}

struct HeldLock {
    rank: u8,
    identity: PathBuf,
}

thread_local! {
    static LOCK_STACK: RefCell<Vec<HeldLock>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn strictly_present(path: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(StoreError::Io(error)),
    }
}

pub(crate) fn check_directory(path: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if is_indirect(&metadata) || !metadata.is_dir() {
                return Err(StoreError::Structure(format!(
                    "{} must be a real directory",
                    path.display()
                )));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(StoreError::Io(error)),
    }
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if is_indirect(&metadata) || !metadata.is_dir() {
                return Err(StoreError::Structure(format!(
                    "{} must be a real directory",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(StoreError::Io(error)),
            }
            let metadata = fs::symlink_metadata(path)?;
            if is_indirect(&metadata) || !metadata.is_dir() {
                return Err(StoreError::Structure(format!(
                    "{} must be a real directory",
                    path.display()
                )));
            }
        }
        Err(error) => return Err(StoreError::Io(error)),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = fs::symlink_metadata(path)?;
        if metadata.mode() & 0o777 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

pub(crate) fn read_regular(path: &Path, what: &str) -> Result<Vec<u8>, StoreError> {
    read_regular_limit(path, what, VAULT_FILE_LIMIT)
}

pub(crate) fn read_regular_limit(
    path: &Path,
    what: &str,
    limit: usize,
) -> Result<Vec<u8>, StoreError> {
    read_regular_limit_with_metadata(path, what, limit).map(|(contents, _)| contents)
}

pub(crate) fn read_regular_limit_with_metadata(
    path: &Path,
    what: &str,
    limit: usize,
) -> Result<(Vec<u8>, fs::Metadata), StoreError> {
    let named_before = fs::symlink_metadata(path)?;
    if is_indirect(&named_before) {
        return Err(StoreError::Structure(format!(
            "{} must be a regular file, not a link or reparse point",
            path.display()
        )));
    }

    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{Mode, OFlags, open};

        let fd = open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_io_error)?;
        File::from(fd)
    };
    #[cfg(not(unix))]
    let mut file = File::open(path)?;

    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(StoreError::Structure(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if opened.len() > limit as u64 {
        return Err(StoreError::TooLarge {
            what: what.to_owned(),
            len: usize::try_from(opened.len()).unwrap_or(usize::MAX),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let named_after = fs::symlink_metadata(path)?;
        if is_indirect(&named_after)
            || opened.dev() != named_after.dev()
            || opened.ino() != named_after.ino()
        {
            return Err(StoreError::Structure(format!(
                "{} changed while it was being opened",
                path.display()
            )));
        }
    }

    #[cfg(windows)]
    {
        let named_after = fs::symlink_metadata(path)?;
        if is_indirect(&named_after) || !named_after.is_file() {
            return Err(StoreError::Structure(format!(
                "{} changed while it was being opened",
                path.display()
            )));
        }
    }

    let mut contents = Vec::new();
    let mut buffer = [0u8; 8192];
    while contents.len() <= limit {
        let remaining = limit + 1 - contents.len();
        let read_len = remaining.min(buffer.len());
        let count = file.read(&mut buffer[..read_len])?;
        if count == 0 {
            break;
        }
        contents.extend_from_slice(&buffer[..count]);
    }
    if contents.len() > limit {
        return Err(StoreError::TooLarge {
            what: what.to_owned(),
            len: contents.len(),
        });
    }
    Ok((contents, opened))
}

pub(crate) fn clear_env_tree(secrets_dir: &Path, env_id: &str) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use rustix::fs::{AtFlags, Dir, Mode, OFlags, fsync, open, openat, unlinkat};
        use std::ffi::CString;
        use std::os::fd::AsFd;

        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let root = match open(secrets_dir, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
            Err(error) if error == rustix::io::Errno::LOOP => {
                return Err(StoreError::Structure(format!(
                    "{} must be a real directory",
                    secrets_dir.display()
                )));
            }
            Err(error) => return Err(rustix_io_error(error).into()),
        };
        let mut parent = root;
        for component in ["drawers", "envs"] {
            parent = match openat(&parent, component, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
                Err(error)
                    if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR =>
                {
                    return Err(StoreError::Structure(format!(
                        "symlink or non-directory in drawer path component {component}"
                    )));
                }
                Err(error) => return Err(rustix_io_error(error).into()),
            };
        }
        let env_dir = match openat(&parent, env_id, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
            Err(error)
                if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR =>
            {
                return Err(StoreError::Structure(
                    "environment drawer must be a real directory".into(),
                ));
            }
            Err(error) => return Err(rustix_io_error(error).into()),
        };

        match openat(&env_dir, "records", flags, Mode::empty()) {
            Ok(records_dir) => {
                let mut directory = Dir::read_from(&records_dir).map_err(rustix_io_error)?;
                let mut names = Vec::new();
                while let Some(entry) = directory.read() {
                    let entry = entry.map_err(rustix_io_error)?;
                    let name = entry.file_name().to_bytes();
                    if name != b"." && name != b".." {
                        names.push(CString::new(name).expect("filesystem name has no NUL"));
                    }
                }
                names.sort_by(|left: &CString, right: &CString| {
                    left.as_bytes().cmp(right.as_bytes())
                });
                for name in names {
                    match unlinkat(&records_dir, &name, AtFlags::empty()) {
                        Ok(()) => {}
                        Err(error) if error == rustix::io::Errno::NOENT => {}
                        Err(error) => return Err(rustix_io_error(error).into()),
                    }
                }
                fsync(records_dir.as_fd()).map_err(rustix_io_error)?;
                match unlinkat(&env_dir, "records", AtFlags::REMOVEDIR) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::NOENT => {}
                    Err(error) => return Err(rustix_io_error(error).into()),
                }
            }
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error)
                if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR =>
            {
                return Err(StoreError::Structure(
                    "drawer records must be a real directory".into(),
                ));
            }
            Err(error) => return Err(rustix_io_error(error).into()),
        }

        let mut directory = Dir::read_from(&env_dir).map_err(rustix_io_error)?;
        let mut names = Vec::new();
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(rustix_io_error)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(CString::new(name).expect("filesystem name has no NUL"));
            }
        }
        names.sort_by(|left: &CString, right: &CString| left.as_bytes().cmp(right.as_bytes()));
        for name in names {
            match unlinkat(&env_dir, &name, AtFlags::empty()) {
                Ok(()) => {}
                Err(error) if error == rustix::io::Errno::NOENT => {}
                Err(error) => return Err(rustix_io_error(error).into()),
            }
        }
        fsync(env_dir.as_fd()).map_err(rustix_io_error)?;
        match unlinkat(&parent, env_id, AtFlags::REMOVEDIR) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => return Err(rustix_io_error(error).into()),
        }
        fsync(parent.as_fd()).map_err(rustix_io_error)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fn require_dir(path: &Path) -> Result<bool, StoreError> {
            check_directory(path)
        }

        fn unlink_plain_children(path: &Path) -> Result<(), StoreError> {
            for item in fs::read_dir(path)? {
                let item = item?;
                let child = item.path();
                let metadata = match fs::symlink_metadata(&child) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                };
                if is_indirect(&metadata) || metadata.is_dir() {
                    return Err(StoreError::Structure(format!(
                        "{} must contain only plain files",
                        path.display()
                    )));
                }
                match fs::remove_file(child) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        }

        let drawers = secrets_dir.join("drawers");
        let envs = drawers.join("envs");
        let env_dir = envs.join(env_id);
        for path in [&drawers, &envs] {
            if !require_dir(path)? {
                return Ok(());
            }
        }
        if !require_dir(&env_dir)? {
            return Ok(());
        }
        let records = env_dir.join("records");
        if require_dir(&records)? {
            unlink_plain_children(&records)?;
            match fs::remove_dir(&records) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        unlink_plain_children(&env_dir)?;
        match fs::remove_dir(&env_dir) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub(crate) fn sync_envs_dir(secrets_dir: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, fsync, open, openat};
        use std::os::fd::AsFd;

        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut current = match open(secrets_dir, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
            Err(error) if error == rustix::io::Errno::LOOP => {
                return Err(StoreError::Structure(format!(
                    "{} must be a real directory",
                    secrets_dir.display()
                )));
            }
            Err(error) => return Err(rustix_io_error(error).into()),
        };
        for component in ["drawers", "envs"] {
            current = match openat(&current, component, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
                Err(error)
                    if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR =>
                {
                    return Err(StoreError::Structure(format!(
                        "symlink or non-directory in drawer path component {component}"
                    )));
                }
                Err(error) => return Err(rustix_io_error(error).into()),
            };
        }
        fsync(current.as_fd()).map_err(rustix_io_error)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = secrets_dir;
        Ok(())
    }
}

pub(crate) fn write_atomic(
    path: &Path,
    contents: &[u8],
    exclusive: bool,
) -> Result<(), StoreError> {
    write_atomic_limit(path, contents, exclusive, VAULT_FILE_LIMIT, "drawer file")
}

pub(crate) fn write_atomic_limit(
    path: &Path,
    contents: &[u8],
    exclusive: bool,
    limit: usize,
    what: &str,
) -> Result<(), StoreError> {
    if contents.len() > limit {
        return Err(StoreError::TooLarge {
            what: what.to_owned(),
            len: contents.len(),
        });
    }
    let parent = path.parent().ok_or_else(|| {
        StoreError::Structure(format!("{} has no parent directory", path.display()))
    })?;

    let mut temporary_path = PathBuf::new();
    let mut temporary_file = None;
    for _ in 0..32 {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| {
            StoreError::Io(io::Error::other("operating-system randomness unavailable"))
        })?;
        let candidate = parent.join(format!(".kv-write-{}.tmp", hex(&random)));
        match create_private_file(&candidate) {
            Ok(file) => {
                temporary_path = candidate;
                temporary_file = Some(file);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    let mut file = temporary_file.ok_or_else(|| {
        StoreError::Io(io::Error::other(
            "could not allocate a private drawer write temporary file",
        ))
    })?;

    let write_result = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(StoreError::Io(error));
    }

    let publish_result = if exclusive {
        match fs::hard_link(&temporary_path, path) {
            Ok(()) => fs::remove_file(&temporary_path),
            Err(error) => Err(error),
        }
    } else {
        fs::rename(&temporary_path, path)
    };
    if let Err(error) = publish_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(StoreError::Io(error));
    }

    #[cfg(unix)]
    sync_directory(parent)?;
    Ok(())
}

pub(crate) fn lock_storage(secrets_dir: &Path) -> Result<StorageLock, StoreError> {
    if !check_directory(secrets_dir)? {
        return Err(StoreError::Structure(format!(
            "{} must be a real directory",
            secrets_dir.display()
        )));
    }
    let identity = lock_identity(secrets_dir, "storage.lock")?;
    let reentrant = check_lock_order(1, &identity)?;
    debug_assert!(!reentrant);
    let path = identity.clone();
    let named = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if is_indirect(&metadata) || !metadata.is_file() {
                return Err(StoreError::Structure(format!(
                    "{} must be a regular lock file",
                    path.display()
                )));
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(StoreError::Io(error)),
    };

    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};

        let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        if !named {
            flags |= OFlags::CREATE;
        }
        let fd = open(
            &path,
            flags,
            if named {
                Mode::empty()
            } else {
                Mode::RUSR | Mode::WUSR
            },
        )
        .map_err(rustix_io_error)?;
        File::from(fd)
    };
    #[cfg(not(unix))]
    let file = {
        use std::fs::OpenOptions;

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(!named);
        options.open(&path)?
    };

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(StoreError::Structure(format!(
            "{} must be a regular lock file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    file.lock()?;
    push_lock(1, &identity);
    Ok(StorageLock {
        identity,
        _file: file,
    })
}

pub(crate) fn lock_config(secrets_dir: &Path) -> Result<ConfigLock, StoreError> {
    if !check_directory(secrets_dir)? {
        return Err(StoreError::Structure(format!(
            "{} must be a real directory",
            secrets_dir.display()
        )));
    }
    let identity = lock_identity(secrets_dir, "config.lock")?;
    if check_lock_order(2, &identity)? {
        push_lock(2, &identity);
        return Ok(ConfigLock {
            identity,
            _file: None,
        });
    }
    let path = identity.clone();
    let named = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if is_indirect(&metadata) || !metadata.is_file() {
                return Err(StoreError::Structure(format!(
                    "{} must be a regular lock file",
                    path.display()
                )));
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(StoreError::Io(error)),
    };

    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};

        let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        if !named {
            flags |= OFlags::CREATE;
        }
        let fd = open(
            &path,
            flags,
            if named {
                Mode::empty()
            } else {
                Mode::RUSR | Mode::WUSR
            },
        )
        .map_err(rustix_io_error)?;
        File::from(fd)
    };
    #[cfg(not(unix))]
    let file = {
        use std::fs::OpenOptions;

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(!named);
        options.open(&path)?
    };

    if !file.metadata()?.is_file() {
        return Err(StoreError::Structure(format!(
            "{} must be a regular lock file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.lock()?;
    push_lock(2, &identity);
    Ok(ConfigLock {
        identity,
        _file: Some(file),
    })
}

impl Drop for StorageLock {
    fn drop(&mut self) {
        pop_lock(1, &self.identity);
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        pop_lock(2, &self.identity);
    }
}

fn lock_identity(secrets_dir: &Path, name: &str) -> Result<PathBuf, StoreError> {
    let directory = fs::canonicalize(secrets_dir)?;
    let path = directory.join(name);
    #[cfg(windows)]
    {
        Ok(PathBuf::from(path.to_string_lossy().to_ascii_lowercase()))
    }
    #[cfg(not(windows))]
    {
        Ok(path)
    }
}

fn check_lock_order(rank: u8, identity: &Path) -> Result<bool, StoreError> {
    LOCK_STACK.with(|stack| {
        let stack = stack.borrow();
        let Some(top) = stack.last() else {
            return Ok(false);
        };
        if rank == 1 {
            return Err(StoreError::LockOrder(
                "lock order violation: storage locks cannot be nested or acquired under config"
                    .into(),
            ));
        }
        if top.rank == 2 {
            if top.identity == identity {
                return Ok(true);
            }
            return Err(StoreError::LockOrder(
                "lock order violation: config locks are reentrant only for the same vault".into(),
            ));
        }
        Ok(false)
    })
}

fn push_lock(rank: u8, identity: &Path) {
    LOCK_STACK.with(|stack| {
        stack.borrow_mut().push(HeldLock {
            rank,
            identity: identity.to_path_buf(),
        });
    });
}

fn pop_lock(rank: u8, identity: &Path) {
    LOCK_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if stack
            .last()
            .is_some_and(|held| held.rank == rank && held.identity == identity)
        {
            stack.pop();
        }
    });
}

pub(crate) fn unlink_record(
    secrets_dir: &Path,
    env_id: &str,
    record_id: &str,
) -> Result<(), StoreError> {
    validate_record_id(record_id)?;
    #[cfg(unix)]
    {
        use rustix::fs::{AtFlags, Mode, OFlags, fsync, open, openat, unlinkat};
        use std::os::fd::{AsFd, OwnedFd};

        let directory_flags =
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut current = match open(secrets_dir, directory_flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
            Err(error) => return Err(rustix_io_error(error).into()),
        };
        for component in ["drawers", "envs", env_id, "records"] {
            let next: OwnedFd = match openat(&current, component, directory_flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
                Err(error) if error == rustix::io::Errno::LOOP => {
                    return Err(StoreError::Structure(format!(
                        "symlink in drawer path component {component}"
                    )));
                }
                Err(error) => return Err(rustix_io_error(error).into()),
            };
            current = next;
        }

        let name = format!("{record_id}.kvs");
        match unlinkat(&current, name.as_str(), AtFlags::empty()) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
            Err(error) => return Err(rustix_io_error(error).into()),
        }
        fsync(current.as_fd()).map_err(rustix_io_error)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let path = secrets_dir
            .join("drawers")
            .join("envs")
            .join(env_id)
            .join("records")
            .join(format!("{record_id}.kvs"));
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Io(error)),
        }
    }
}

pub(crate) fn validate_record_id(record_id: &str) -> Result<(), StoreError> {
    let Some(hex) = record_id.strip_prefix("r_") else {
        return Err(StoreError::Corrupt("invalid drawer record id".into()));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::Corrupt("invalid drawer record id".into()));
    }
    Ok(())
}

fn create_private_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};

        let fd = open(
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(rustix_io_error)?;
        Ok(File::from(fd))
    }
    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;
        OpenOptions::new().write(true).create_new(true).open(path)
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StoreError> {
    use rustix::fs::{Mode, OFlags, fsync, open};

    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io_error)?;
    fsync(&fd).map_err(rustix_io_error)?;
    Ok(())
}

fn is_indirect(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return metadata.file_attributes() & 0x400 != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(unix)]
fn rustix_io_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::lock_storage;
    use crate::StoreError;

    #[test]
    fn nested_storage_lock_is_rejected_before_relocking() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let secrets =
            std::env::temp_dir().join(format!("kv-store-lock-{}-{suffix}", std::process::id()));
        std::fs::create_dir_all(&secrets).expect("create secrets directory");

        let first = lock_storage(&secrets).expect("first storage lock");
        assert!(matches!(
            lock_storage(&secrets),
            Err(StoreError::LockOrder(_))
        ));
        drop(first);
        std::fs::remove_dir_all(secrets).expect("remove temporary secrets directory");
    }
}
