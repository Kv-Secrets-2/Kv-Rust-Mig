//! Run grants (`kv/grants.py`): creating, matching, admitting, revoking and
//! pruning the owner-signed records in `run_grants.json`.

use std::fmt;

use kv_approvals::verify::AdmissionRefused;

use crate::normalize::InvalidValue;
use crate::store::StoreFault;

/// Why a grant operation failed, keeping Python's error classes apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// Python `ValueError`.
    Invalid(InvalidValue),
    /// A store could not be read or written.
    Store(StoreFault),
    /// Python `AdmissionRefused`.
    Refused(AdmissionRefused),
    /// Python `GrantSpentError`: token minting failed after admission.
    Spent {
        message: String,
        grant_id: String,
        spent: bool,
        error_type: &'static str,
    },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantError::Invalid(e) => f.write_str(e.message()),
            GrantError::Store(e) => f.write_str(e.message()),
            GrantError::Refused(e) => f.write_str(e.message()),
            GrantError::Spent { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for GrantError {}

impl From<InvalidValue> for GrantError {
    fn from(error: InvalidValue) -> Self {
        GrantError::Invalid(error)
    }
}

impl From<StoreFault> for GrantError {
    fn from(error: StoreFault) -> Self {
        GrantError::Store(error)
    }
}

impl From<AdmissionRefused> for GrantError {
    fn from(error: AdmissionRefused) -> Self {
        GrantError::Refused(error)
    }
}
