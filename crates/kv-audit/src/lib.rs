//! Audit records compatible with the pinned Python 0.4.0 writer.
//!
//! The Unix writer serializes cooperating Python and Rust processes through
//! `audit.lock`. Audit failure drops the record and queues a fixed warning;
//! it never authorizes cancelling an action that already happened. The chain
//! is unkeyed and cannot prove completeness against a same-account writer.
//!
//! Construct one [`Audit`] per process and clone it for every producer. The
//! directory is normally `~/.kv`; callers may supply an isolated directory.
//! The Windows writer is not implemented by this crate yet.

#[cfg(unix)]
mod codec;
#[cfg(unix)]
mod fs;
#[cfg(unix)]
mod python_json;
#[cfg(unix)]
mod runtime;

#[cfg(unix)]
pub use runtime::{Audit, WarningLease};

use serde::{Deserialize, Serialize};

pub const AUDIT_WARNING: &str = "kv could not write an audit record - the action still went ahead; 'kv audit' and 'kv doctor' show the audit state";
pub const AUDIT_MARK_WARNING: &str = "kv could not save the audit order mark - records written while its lock file was replaced are not proven in order; 'kv audit' and 'kv doctor' show the audit state";

/// Closed reasons safe to return to a caller: no paths or exception messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossReason {
    FolderRefused,
    FileRefused,
    WriteFailed,
    LockUnavailable,
    LockUnsupported,
}

impl std::fmt::Display for LossReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FolderRefused => "folder_refused",
            Self::FileRefused => "file_refused",
            Self::WriteFailed => "write_failed",
            Self::LockUnavailable => "lock_unavailable",
            Self::LockUnsupported => "lock_unsupported",
        })
    }
}

impl std::error::Error for LossReason {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Warning {
    RecordLost,
    OrderMarkNotKept,
}

impl Warning {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordLost => AUDIT_WARNING,
            Self::OrderMarkNotKept => AUDIT_MARK_WARNING,
        }
    }
}

/// Daemons deliver warnings through an opted-in reply. Commands also print
/// each warning kind at most once in their invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WarningChannel {
    Reply,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Ok,
    Refused,
    Empty,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Floor,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    Serialized,
    Uncertain,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderState {
    Ok,
    Mode,
    Acl,
    Unreadable,
    Unknown,
}

/// Read-only snapshot. A number is only a lower bound, never a claim that no
/// records were lost. JSON numbers retain Python's arbitrary integer counts.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AuditHealth {
    pub state: HealthState,
    pub reason: Option<LossReason>,
    pub lost: Option<serde_json::Number>,
    pub coverage: Coverage,
    pub order: Order,
    pub folder: FolderState,
}
