//! The sealed descriptor that carries a run's `--setenv` arguments to
//! bubblewrap without any secret appearing on a command line (Python
//! `kv/sandbox.py`: `SealedArgsFd`, `_sealed_args_fd`, `read_args_fd`).
//! Linux only: `memfd_create` plus `F_ADD_SEALS`. Anywhere else, or when
//! the kernel refuses, the run fails closed with `SealedArgsUnavailable`.

use crate::runenv::RunEnvError;
#[cfg(target_os = "linux")]
use crate::runenv::encode_args_bytes;

/// An owned memfd whose contents can no longer change. Closing checks the
/// descriptor still names the file kv made, so a number reused by someone
/// else is never closed from under them (Python `SealedArgsFd.close`).
#[derive(Debug)]
pub struct SealedArgsFd {
    #[cfg(target_os = "linux")]
    fd: Option<std::os::fd::OwnedFd>,
    #[cfg(target_os = "linux")]
    identity: (u64, u64),
}

#[cfg(target_os = "linux")]
impl SealedArgsFd {
    /// Python `_sealed_args_fd`: write `args` NUL-terminated into a fresh
    /// memfd, seal it against growth, shrinking, writes and more seals,
    /// rewind, and hand it over.
    pub fn new(args: &[String]) -> Result<Self, RunEnvError> {
        use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fstat, memfd_create, seek};
        use std::io::Write;

        let fd = memfd_create(
            "kv_run_args",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        )
        .map_err(|_| RunEnvError::SealedArgsUnavailable)?;
        let st = fstat(&fd).map_err(|e| RunEnvError::ArgsDescriptorWrite(e.to_string()))?;
        let identity = (st.st_dev, st.st_ino);
        let data = encode_args_bytes(args);
        let mut file = std::fs::File::from(fd);
        file.write_all(&data)
            .map_err(|e| RunEnvError::ArgsDescriptorWrite(e.to_string()))?;
        fcntl_add_seals(
            &file,
            SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE | SealFlags::SEAL,
        )
        .map_err(|_| RunEnvError::SealedArgsUnavailable)?;
        seek(&file, rustix::fs::SeekFrom::Start(0))
            .map_err(|e| RunEnvError::ArgsDescriptorWrite(e.to_string()))?;
        Ok(Self {
            fd: Some(std::os::fd::OwnedFd::from(file)),
            identity,
        })
    }

    /// The raw number for `--args N` (Python `fileno`); `None` once taken.
    /// The descriptor to pass to the child, while kv still holds it.
    pub fn as_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.fd.as_ref().map(std::os::fd::AsFd::as_fd)
    }

    pub fn raw(&self) -> Option<i32> {
        use std::os::fd::AsRawFd;
        self.fd.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Give the descriptor up to a caller that now owns closing it.
    pub fn take(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.fd.take()
    }

    /// Does the descriptor still name the file kv made?
    pub fn still_ours(&self) -> bool {
        self.fd
            .as_ref()
            .and_then(|fd| rustix::fs::fstat(fd).ok())
            .is_some_and(|st| (st.st_dev, st.st_ino) == self.identity)
    }

    pub fn close(&mut self) {
        if let Some(fd) = self.fd.take() {
            if rustix::fs::fstat(&fd).is_ok_and(|st| (st.st_dev, st.st_ino) == self.identity) {
                drop(fd);
            } else {
                std::mem::forget(fd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for SealedArgsFd {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(not(target_os = "linux"))]
impl SealedArgsFd {
    pub fn new(_args: &[String]) -> Result<Self, RunEnvError> {
        Err(RunEnvError::SealedArgsUnavailable)
    }

    pub fn as_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        None
    }

    pub fn raw(&self) -> Option<i32> {
        None
    }

    #[cfg(unix)]
    pub fn take(&mut self) -> Option<std::os::fd::OwnedFd> {
        None
    }

    pub fn still_ours(&self) -> bool {
        false
    }

    pub fn close(&mut self) {}
}

/// Python `read_args_fd`: exactly `st_size` bytes by `pread`, or an error.
#[cfg(unix)]
pub fn read_args_fd(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::from(fd.try_clone_to_owned()?);
    let size = usize::try_from(file.metadata()?.len()).unwrap_or(0);
    let mut out = vec![0u8; size];
    let mut got = 0usize;
    while got < size {
        let read = file.read_at(&mut out[got..], got as u64)?;
        if read == 0 {
            return Err(std::io::Error::other(format!(
                "short read on the args descriptor: {got} of {size} bytes"
            )));
        }
        got += read;
    }
    Ok(out)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::runenv::decode_args_bytes;
    use std::os::fd::AsFd;

    #[test]
    fn sealed_roundtrip_and_immutability() {
        let args = vec![
            "--setenv".to_owned(),
            "API_KEY".to_owned(),
            "héllo=wörld".to_owned(),
        ];
        let sealed = SealedArgsFd::new(&args).unwrap();
        assert!(sealed.still_ours());
        let fd = sealed.fd.as_ref().unwrap();
        let bytes = read_args_fd(fd.as_fd()).unwrap();
        assert_eq!(decode_args_bytes(&bytes).unwrap(), args);
        let mut file = std::fs::File::from(fd.try_clone().unwrap());
        use std::io::Write;
        assert!(
            file.write_all(b"x").is_err(),
            "sealed memfd accepted a write"
        );
        assert!(file.set_len(1).is_err(), "sealed memfd accepted a shrink");
        let seals = rustix::fs::fcntl_get_seals(fd).unwrap();
        assert!(seals.contains(rustix::fs::SealFlags::SEAL));
    }

    #[test]
    fn take_hands_over_ownership() {
        let mut sealed = SealedArgsFd::new(&["a".to_owned()]).unwrap();
        let raw = sealed.raw().unwrap();
        let owned = sealed.take().unwrap();
        assert!(sealed.raw().is_none());
        assert_eq!(std::os::fd::AsRawFd::as_raw_fd(&owned), raw);
        drop(sealed);
        assert!(rustix::fs::fstat(&owned).is_ok());
    }
}
