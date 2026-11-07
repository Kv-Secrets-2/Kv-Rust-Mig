#![forbid(unsafe_code)]

pub mod approvals;

use kv_store::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Approval(#[from] kv_approvals::ApprovalError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RequestError>;

fn invalid(message: impl Into<String>) -> RequestError {
    RequestError::Invalid(message.into())
}
