#![forbid(unsafe_code)]

pub mod artifacts;
pub mod canonical;
pub mod owner;
pub mod pause;
pub mod permit;
pub mod wire;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("{0}")]
    Message(String),
}

impl From<String> for ApprovalError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}

impl From<&str> for ApprovalError {
    fn from(value: &str) -> Self {
        Self::Message(value.to_owned())
    }
}
