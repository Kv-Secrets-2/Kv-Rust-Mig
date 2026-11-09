#![forbid(unsafe_code)]

pub mod approvals;
pub mod policy_requests;
pub mod request_records;

use kv_store::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error(transparent)]
    RecordsFull(#[from] request_records::RequestRecordsFull),
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
