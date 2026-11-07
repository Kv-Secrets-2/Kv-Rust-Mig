//! kv-sandbox: the `kv run` sandbox (Stage 6a), ported from Python
//! `kv/sandbox.py`: command classification, run environment, bubblewrap
//! wrapping, output redaction and leaked-file scanning.

pub mod classify;
pub mod redact;
pub mod runenv;

pub use classify::{
    CommandDecision, MODE_BROKERED_ACT, MODE_GUARDED_ENV, MODE_REVEAL, MODE_UNSAFE_ENV, MODE_WORK,
    check_command, classify_command, effective_run_mode, session_denial_reason,
};
pub use redact::{build_secret_variants, redact, redaction_needles};
