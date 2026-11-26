//! Unix audit storage with legacy Python-compatible and authenticated v1 chains.
//!
//! [`Audit::new`] retains the pinned Python 0.4.0 writer, including its
//! truncated unkeyed chain for migration interoperability.
//! [`Audit::with_authenticated_chain`] writes canonical records with full-width
//! HMAC-SHA256 chain tags bound to a broker-supplied vault identity. Extending
//! or verifying that format requires a [`ChainTrust`] containing the secret
//! chain key, raw vault identity, and independently trusted head/count. Without
//! that tuple verification is [`ChainVerification::MissingTrustState`], never
//! valid history.
//!
//! Audit failure drops the record and queues a fixed warning; under the legacy
//! policy it never authorizes cancelling an action that already happened. The
//! Windows writer is not implemented by this crate yet.

#[cfg(unix)]
mod chain;
#[cfg(unix)]
mod codec;
#[cfg(unix)]
mod fs;
#[cfg(unix)]
mod python_json;
#[cfg(unix)]
mod runtime;

#[cfg(unix)]
pub use chain::{
    CHAIN_FORMAT_VERSION, ChainCorruption, ChainHead, ChainKey, ChainPosition,
    ChainPositionMismatch, ChainReadFailure, ChainStatus, ChainTrust, ChainVerification, HexError,
    IdentityError, MAX_CHAIN_ENTRY_BYTES, MAX_VAULT_IDENTITY_BYTES, VaultIdentity, verify_bytes,
    verify_directory, verify_reader,
};
#[cfg(unix)]
pub use codec::{label_text, requester_fields};
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
    ChainUnauthenticated,
}

impl std::fmt::Display for LossReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FolderRefused => "folder_refused",
            Self::FileRefused => "file_refused",
            Self::WriteFailed => "write_failed",
            Self::LockUnavailable => "lock_unavailable",
            Self::LockUnsupported => "lock_unsupported",
            Self::ChainUnauthenticated => "chain_unauthenticated",
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
