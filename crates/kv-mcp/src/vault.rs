//! `kv.mcp_vault`: which tools a vault can offer, from its key file's header.
//! Takes no lock and writes nothing.

use std::io::{self, Read};
use std::path::Path;

use crate::pyerr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Protected,
    Unprotected,
    Unreadable,
}

pub const PARKED_ON_PROTECTED: [&str; 2] = ["kv_query", "kv_ssh"];
pub const DIRECT_ONLY: [&str; 3] = ["kv_set", "kv_rm", "kv_get"];

pub fn hidden_on_protected(name: &str) -> bool {
    PARKED_ON_PROTECTED.contains(&name) || DIRECT_ONLY.contains(&name)
}

const STRUCTURE: &str = "VaultStructureError";

fn os_reason(error: &io::Error) -> String {
    pyerr::type_name(error).to_owned()
}

#[cfg(unix)]
fn is_structural(error: &io::Error) -> bool {
    use rustix::io::Errno;
    error.raw_os_error().is_some_and(|code| {
        let errno = Errno::from_raw_os_error(code);
        errno == Errno::LOOP || errno == Errno::NOTDIR
    })
}

#[cfg(not(unix))]
fn is_structural(_error: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn open_key(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags =
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)
}

#[cfg(not(unix))]
fn open_key(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(unix)]
fn same_file(opened: &std::fs::Metadata, named: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (opened.dev(), opened.ino()) == (named.dev(), named.ino())
}

#[cfg(not(unix))]
fn same_file(_opened: &std::fs::Metadata, _named: &std::fs::Metadata) -> bool {
    true
}

/// `crypto.key_header_kind`.
fn key_header_kind(path: &Path) -> (Kind, String) {
    if cfg!(not(unix))
        && let Ok(named) = std::fs::symlink_metadata(path)
        && named.file_type().is_symlink()
    {
        return (Kind::Unreadable, STRUCTURE.into());
    }
    let mut file = match open_key(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return (Kind::Unprotected, "no key file".into());
        }
        Err(error) if is_structural(&error) => return (Kind::Unreadable, STRUCTURE.into()),
        Err(error) => return (Kind::Unreadable, os_reason(&error)),
    };
    let opened = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return (Kind::Unreadable, os_reason(&error)),
    };
    if !opened.is_file() {
        return (Kind::Unreadable, STRUCTURE.into());
    }
    match std::fs::symlink_metadata(path) {
        Ok(named) if named.file_type().is_symlink() || !same_file(&opened, &named) => {
            return (Kind::Unreadable, STRUCTURE.into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return (Kind::Unreadable, STRUCTURE.into());
        }
        Err(error) => return (Kind::Unreadable, os_reason(&error)),
    }
    let mut magic = Vec::with_capacity(4);
    if let Err(error) = Read::by_ref(&mut file).take(4).read_to_end(&mut magic) {
        return (Kind::Unreadable, os_reason(&error));
    }
    if magic.len() < 4 {
        return (Kind::Unreadable, "the key file is too short".into());
    }
    if &magic[..3] != b"KVW" || magic[3] >= 0x20 {
        return (Kind::Unprotected, "plaintext key".into());
    }
    match magic[3] {
        version @ (3 | 4) => (Kind::Protected, format!("v{version}")),
        version @ (1 | 2) => (Kind::Unprotected, format!("v{version}")),
        version => (Kind::Unreadable, format!("unknown key version {version}")),
    }
}

/// `mcp_vault.vault_key_kind`.
pub fn vault_key_kind(root: &Path) -> (Kind, String) {
    let sdir = root.join(".secrets");
    let metadata = match std::fs::symlink_metadata(&sdir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return (Kind::Unreadable, "the .secrets folder is missing".into());
        }
        Err(error) => return (Kind::Unreadable, os_reason(&error)),
    };
    if metadata.file_type().is_symlink() {
        return (
            Kind::Unreadable,
            "the .secrets folder is a link or reparse point".into(),
        );
    }
    if !metadata.is_dir() {
        return (
            Kind::Unreadable,
            "the .secrets folder is not a folder".into(),
        );
    }
    match std::fs::symlink_metadata(sdir.join("key-config.pending")) {
        Ok(_) => return (Kind::Unreadable, "a key change is pending".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return (Kind::Unreadable, os_reason(&error)),
    }
    let (kind, reason) = key_header_kind(&sdir.join("key"));
    if kind == Kind::Unreadable && reason == "PermissionError" {
        return (
            kind,
            "its permissions block reading it; 'kv status' repairs them".into(),
        );
    }
    (kind, reason)
}

/// `mcp_vault.why_not_offered` for a kind that hides tools.
pub fn why_not_offered(kind: Kind, reason: &str) -> String {
    match kind {
        Kind::Protected => "on this passphrase-protected (v3/v4) vault".into(),
        _ => format!(
            "because the vault's key file could not be read as a known key ({reason}); \
             'kv status' or 'kv doctor' in a terminal says more"
        ),
    }
}
