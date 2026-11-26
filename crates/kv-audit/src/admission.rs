//! Durable privileged-admission and terminal-outcome lifecycle.
//!
//! The ordering is deliberately strict: while the audit log lock is held, the
//! broker-owned checkpoint is read, the complete journal is authenticated to
//! that checkpoint, a first-use journal directory hierarchy is committed through
//! its parent chain, the admission record is appended with file and directory
//! synchronization, and the advanced checkpoint is published durably. Only then
//! does [`AdmissionJournal::admit`] return a usable [`Admission`]. Dropping an
//! admission never repeats or completes its effect; in a journal that verifies
//! against its checkpoint, an admission without a later terminal outcome is
//! reported as unknown.
//!
//! This module deliberately has no hard-lock latch and no hard-lock callback.
//! Vault hard-lock state belongs outside the audit journal and must never wait
//! for journal verification, append, synchronization, or checkpoint publication.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Map, Number, Value};

use crate::chain::{
    ChainKey, ChainPosition, ChainPositionMismatch, ChainReadFailure, ChainTrust,
    ChainVerification, VaultIdentity, encode_authenticated_entry, verify_open_directory,
    verify_open_directory_observed, verify_reader_observed,
};
use crate::fs::{Directory, DurableAppendFailure, LOG_LOCK};
use crate::runtime::utc_timestamp;

const LOCK_WAIT: Duration = Duration::from_secs(2);
const ACTION_FIELD: &str = "action";
const ADMISSION_SEQUENCE_FIELD: &str = "admission_seq";
const OUTCOME_FIELD: &str = "outcome";
const LIFECYCLE_FIELDS: [&str; 3] = [ACTION_FIELD, ADMISSION_SEQUENCE_FIELD, OUTCOME_FIELD];

pub const ADMISSION_EVENT: &str = "privileged_admission";
pub const OUTCOME_EVENT: &str = "privileged_outcome";
pub const MAX_ADMISSION_ACTION_BYTES: usize = 128;

/// Broker-owned checkpoint storage independent of the audit journal.
///
/// Implementations must make both operations durable before returning success.
/// `publish_durable` must atomically replace the checkpoint and synchronize its
/// backing store; a write that may have landed but is not known durable is a
/// failure. The checkpoint must live outside the audit directory and must be
/// updated only through this lifecycle while the audit lock is held.
pub trait TrustedCheckpoint {
    /// Return the latest durably committed position. Implementations must not
    /// return a cached position that a successful publication did not commit.
    fn load_durable(&mut self) -> Result<ChainPosition, CheckpointFailure>;
    /// Atomically replace and durably commit `position` before returning
    /// success. Any uncertain or partial publication must return an error.
    fn publish_durable(&mut self, position: ChainPosition) -> Result<(), CheckpointFailure>;
}

/// Closed checkpoint failure classes. Backing-store details must not be copied
/// into audit records or caller-facing errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointFailure {
    ReadFailed,
    Invalid,
    WriteFailed,
    SyncFailed,
}

impl CheckpointFailure {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadFailed => "checkpoint_read_failed",
            Self::Invalid => "checkpoint_invalid",
            Self::WriteFailed => "checkpoint_write_failed",
            Self::SyncFailed => "checkpoint_sync_failed",
        }
    }
}

impl fmt::Display for CheckpointFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for CheckpointFailure {}

/// Closed lifecycle failure classes. Continuity loss preserves the verifier's
/// machine-readable checkpoint-mismatch reason instead of flattening it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    FolderRefused,
    FileRefused,
    LockUnavailable,
    LockUnsupported,
    CheckpointReadFailed,
    CheckpointInvalid,
    CheckpointWriteFailed,
    CheckpointSyncFailed,
    JournalWriteFailed,
    JournalSyncFailed,
    ChainTruncated,
    ChainCorrupted,
    ChainContinuityLoss(ChainPositionMismatch),
    ChainUnreadable,
    ChainUnauthenticated,
    InvalidAction,
    InvalidMetadata,
    SequenceExhausted,
}

impl LifecycleError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FolderRefused => "folder_refused",
            Self::FileRefused => "file_refused",
            Self::LockUnavailable => "lock_unavailable",
            Self::LockUnsupported => "lock_unsupported",
            Self::CheckpointReadFailed => "checkpoint_read_failed",
            Self::CheckpointInvalid => "checkpoint_invalid",
            Self::CheckpointWriteFailed => "checkpoint_write_failed",
            Self::CheckpointSyncFailed => "checkpoint_sync_failed",
            Self::JournalWriteFailed => "journal_write_failed",
            Self::JournalSyncFailed => "journal_sync_failed",
            Self::ChainTruncated => "truncated",
            Self::ChainCorrupted => "corrupted",
            Self::ChainContinuityLoss(mismatch) => mismatch.as_str(),
            Self::ChainUnreadable => "unreadable",
            Self::ChainUnauthenticated => "chain_unauthenticated",
            Self::InvalidAction => "invalid_action",
            Self::InvalidMetadata => "invalid_metadata",
            Self::SequenceExhausted => "sequence_exhausted",
        }
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for LifecycleError {}

/// Terminal outcome for a privileged effect. `Completed` means the effect
/// reached a definite terminal state, even when that state is a domain error
/// response carried in metadata. `Failed` means the effect definitely failed.
/// If completion is uncertain or the process is interrupted, write no outcome;
/// the admission remains unknown rather than being guessed or repeated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Completed,
    Failed,
}

impl TerminalOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

type AppendDurable = dyn Fn(&Directory, &[u8]) -> Result<(), DurableAppendFailure> + Send + Sync;
type ParentChainSync = dyn Fn(&Directory) -> io::Result<()> + Send + Sync;

struct Inner {
    directory: PathBuf,
    key: ChainKey,
    identity: VaultIdentity,
    checkpoint: Mutex<Box<dyn TrustedCheckpoint + Send>>,
    append_durable: Box<AppendDurable>,
    sync_parent_chain: Box<ParentChainSync>,
}

/// Authenticated privileged-admission journal. Clones share the checkpoint
/// object and audit-lock critical section.
#[derive(Clone)]
pub struct AdmissionJournal(Arc<Inner>);

enum LifecycleRecord {
    Admission {
        action: String,
        metadata: Map<String, Value>,
    },
    Outcome {
        admission_sequence: u64,
        outcome: TerminalOutcome,
        metadata: Map<String, Value>,
    },
}

impl LifecycleRecord {
    fn into_fields(self, sequence: u64) -> Map<String, Value> {
        match self {
            Self::Admission {
                action,
                mut metadata,
            } => {
                metadata.insert(ACTION_FIELD.into(), Value::String(action));
                metadata.insert(
                    ADMISSION_SEQUENCE_FIELD.into(),
                    Value::Number(Number::from(sequence)),
                );
                metadata
            }
            Self::Outcome {
                admission_sequence,
                outcome,
                mut metadata,
            } => {
                metadata.insert(
                    ADMISSION_SEQUENCE_FIELD.into(),
                    Value::Number(Number::from(admission_sequence)),
                );
                metadata.insert(OUTCOME_FIELD.into(), Value::String(outcome.as_str().into()));
                metadata
            }
        }
    }

    fn event(&self) -> &'static str {
        match self {
            Self::Admission { .. } => ADMISSION_EVENT,
            Self::Outcome { .. } => OUTCOME_EVENT,
        }
    }
}

impl AdmissionJournal {
    /// Create the lifecycle writer. No filesystem or checkpoint I/O happens
    /// until the first admission, outcome, or status request.
    pub fn new(
        directory: impl Into<PathBuf>,
        key: ChainKey,
        identity: VaultIdentity,
        checkpoint: impl TrustedCheckpoint + Send + 'static,
    ) -> Self {
        Self::with_checkpoint_box(directory, key, identity, Box::new(checkpoint))
    }

    fn with_checkpoint_box(
        directory: impl Into<PathBuf>,
        key: ChainKey,
        identity: VaultIdentity,
        checkpoint: Box<dyn TrustedCheckpoint + Send>,
    ) -> Self {
        Self::with_parts(
            directory,
            key,
            identity,
            checkpoint,
            Box::new(|directory, bytes| directory.append_durable(bytes)),
            Box::new(|directory| directory.sync_parent_chain()),
        )
    }

    #[cfg(test)]
    fn with_append_failure_injection(
        directory: impl Into<PathBuf>,
        key: ChainKey,
        identity: VaultIdentity,
        checkpoint: Box<dyn TrustedCheckpoint + Send>,
        append_durable: Box<AppendDurable>,
        sync_parent_chain: Box<ParentChainSync>,
    ) -> Self {
        Self::with_parts(
            directory,
            key,
            identity,
            checkpoint,
            append_durable,
            sync_parent_chain,
        )
    }

    fn with_parts(
        directory: impl Into<PathBuf>,
        key: ChainKey,
        identity: VaultIdentity,
        checkpoint: Box<dyn TrustedCheckpoint + Send>,
        append_durable: Box<AppendDurable>,
        sync_parent_chain: Box<ParentChainSync>,
    ) -> Self {
        Self(Arc::new(Inner {
            directory: directory.into(),
            key,
            identity,
            checkpoint: Mutex::new(checkpoint),
            append_durable,
            sync_parent_chain,
        }))
    }

    pub fn directory(&self) -> &Path {
        &self.0.directory
    }

    /// Commit a privileged admission and return its one-time use token. The
    /// callback capable token does not exist until the complete journal was
    /// authenticated, the admission record was synchronized, and the broker's
    /// independent checkpoint was durably advanced.
    pub fn admit(
        &self,
        action: &str,
        metadata: Map<String, Value>,
    ) -> Result<Admission, LifecycleError> {
        if !valid_action(action) {
            return Err(LifecycleError::InvalidAction);
        }
        if uses_lifecycle_fields(&metadata) {
            return Err(LifecycleError::InvalidMetadata);
        }
        let position = self.append_record(LifecycleRecord::Admission {
            action: action.to_owned(),
            metadata,
        })?;
        Ok(Admission {
            journal: self.clone(),
            position,
        })
    }

    /// Report admissions paired with terminal outcomes. This method takes the
    /// same audit lock as writers, so a cooperating concurrent admission cannot
    /// make a healthy journal look discontinuous halfway through the scan.
    pub fn admission_states(&self) -> Result<AdmissionReport, LifecycleError> {
        let directory =
            Directory::open(&self.0.directory, true).map_err(|_| LifecycleError::FolderRefused)?;
        let log_lock = directory.lock(LOG_LOCK, LOCK_WAIT).map_err(lock_error)?;
        let trusted_position = self
            .checkpoint()?
            .load_durable()
            .map_err(checkpoint_error)?;
        let trust = ChainTrust::new(
            self.0.key.clone(),
            self.0.identity.clone(),
            trusted_position,
        );
        let report = scan_open_directory(&directory, &trust).map_err(verification_error)?;
        if !directory.lock_matches(&log_lock, LOG_LOCK).unwrap_or(false) {
            return Err(LifecycleError::LockUnavailable);
        }
        Ok(report)
    }

    fn append_record(&self, record: LifecycleRecord) -> Result<ChainPosition, LifecycleError> {
        let directory =
            Directory::open(&self.0.directory, true).map_err(|_| LifecycleError::FolderRefused)?;
        let log_lock = directory.lock(LOG_LOCK, LOCK_WAIT).map_err(lock_error)?;
        let mut checkpoint = self.checkpoint()?;
        let trusted_position = checkpoint.load_durable().map_err(checkpoint_error)?;
        let trust = ChainTrust::new(
            self.0.key.clone(),
            self.0.identity.clone(),
            trusted_position,
        );
        let verification = verify_open_directory(&directory, &trust);
        let position = match verification {
            ChainVerification::Valid { position } => position,
            other => return Err(verification_error(other)),
        };
        if position.count == 0 {
            (self.0.sync_parent_chain)(&directory)
                .map_err(|_| LifecycleError::JournalSyncFailed)?;
        }
        if !directory.lock_matches(&log_lock, LOG_LOCK).unwrap_or(false) {
            return Err(LifecycleError::LockUnavailable);
        }
        let sequence = position
            .count
            .checked_add(1)
            .ok_or(LifecycleError::SequenceExhausted)?;
        let event = record.event();
        let fields = record.into_fields(sequence);
        let encoded = encode_authenticated_entry(
            &utc_timestamp(),
            event,
            fields,
            &self.0.key,
            &self.0.identity,
            position,
        )
        .map_err(|_| LifecycleError::InvalidMetadata)?;
        (self.0.append_durable)(&directory, &encoded.bytes).map_err(|failure| match failure {
            DurableAppendFailure::FileRefused => LifecycleError::FileRefused,
            DurableAppendFailure::WriteFailed => LifecycleError::JournalWriteFailed,
            DurableAppendFailure::SyncFailed => LifecycleError::JournalSyncFailed,
        })?;
        if !directory.lock_matches(&log_lock, LOG_LOCK).unwrap_or(false) {
            return Err(LifecycleError::LockUnavailable);
        }
        checkpoint
            .publish_durable(encoded.position)
            .map_err(checkpoint_error)?;
        if !directory.lock_matches(&log_lock, LOG_LOCK).unwrap_or(false) {
            return Err(LifecycleError::LockUnavailable);
        }
        Ok(encoded.position)
    }

    fn checkpoint(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Box<dyn TrustedCheckpoint + Send>>, LifecycleError> {
        self.0
            .checkpoint
            .lock()
            .map_err(|_| LifecycleError::LockUnavailable)
    }
}

/// One committed privileged admission. It is intentionally not `Clone`; moving
/// it into [`Admission::run`] is the only effect callback path, so the type
/// cannot invoke the same effect twice.
#[must_use = "a dropped admission is durable and remains unknown until a terminal outcome"]
pub struct Admission {
    journal: AdmissionJournal,
    position: ChainPosition,
}

impl Admission {
    /// Sequence number of the admission record in the authenticated journal.
    pub fn sequence(&self) -> u64 {
        self.position.count
    }

    /// Authenticated journal position after the admission record.
    pub fn position(&self) -> ChainPosition {
        self.position
    }

    /// Invoke the privileged effect once. If this callback panics or the
    /// process stops before `finish` commits a terminal outcome, no outcome is
    /// invented: the durable admission is later reported as unknown.
    pub fn run<T>(self, effect: impl FnOnce(ChainPosition) -> T) -> Execution<T> {
        let position = self.position;
        let output = effect(position);
        Execution {
            admission: self,
            output,
        }
    }
}

/// Result of an effect whose admission was committed. Call [`Execution::finish`]
/// with the terminal outcome after the effect is known to be finished.
#[must_use = "dropping execution before finish leaves the admission unknown"]
pub struct Execution<T> {
    admission: Admission,
    output: T,
}

impl<T> Execution<T> {
    pub fn output(&self) -> &T {
        &self.output
    }

    /// Commit the separate terminal outcome record. On success the effect
    /// output is returned. On failure the output is retained in
    /// [`OutcomeError`] so callers do not mistake a completed effect for an
    /// unexecuted one. If outcome bytes may have landed without checkpoint
    /// publication, later scans fail closed instead of reporting a paired state.
    pub fn finish(
        self,
        outcome: TerminalOutcome,
        metadata: Map<String, Value>,
    ) -> Result<T, OutcomeError<T>> {
        let this = self;
        let output = this.output;
        let admission = this.admission;
        let result = if uses_lifecycle_fields(&metadata) {
            Err(LifecycleError::InvalidMetadata)
        } else {
            admission.journal.append_record(LifecycleRecord::Outcome {
                admission_sequence: admission.sequence(),
                outcome,
                metadata,
            })
        };
        match result {
            Ok(_) => Ok(output),
            Err(error) => Err(OutcomeError { error, output }),
        }
    }
}

/// Effect output paired with the lifecycle error that prevented its terminal
/// outcome from being committed.
pub struct OutcomeError<T> {
    pub error: LifecycleError,
    pub output: T,
}

impl<T> OutcomeError<T> {
    pub fn into_output(self) -> T {
        self.output
    }
}

impl<T: fmt::Debug> fmt::Debug for OutcomeError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutcomeError")
            .field("error", &self.error)
            .field("output", &self.output)
            .finish()
    }
}

impl<T> fmt::Display for OutcomeError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "terminal outcome was not durably committed: {}",
            self.error
        )
    }
}

impl<T: fmt::Debug> std::error::Error for OutcomeError<T> {}

/// Observed state of one authenticated admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionState {
    pub admission_seq: u64,
    pub action: String,
    pub outcome: AdmissionOutcomeState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AdmissionOutcomeState {
    /// No terminal outcome exists. This includes interrupted operations and is
    /// never evidence that repeating the privileged effect is safe.
    Unknown,
    Terminal {
        outcome: TerminalOutcome,
        outcome_seq: u64,
    },
    Conflicted {
        outcome_seqs: Vec<u64>,
    },
}

/// Read-only lifecycle pairing report for a completely valid journal.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AdmissionReport {
    pub position: ChainPosition,
    pub admissions: Vec<AdmissionState>,
    pub orphan_outcomes: u64,
    pub malformed_lifecycle_records: u64,
}

struct Observation {
    sequence: u64,
    event: Option<String>,
    action: Option<String>,
    admission_sequence: Option<u64>,
    outcome: Option<String>,
}

impl Observation {
    fn parse(line: &[u8], position: ChainPosition) -> Self {
        let value = crate::python_json::from_slice(line).unwrap_or(Value::Null);
        let object = value.as_object();
        Self {
            sequence: position.count,
            event: object
                .and_then(|object| object.get("event"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            action: object
                .and_then(|object| object.get(ACTION_FIELD))
                .and_then(Value::as_str)
                .map(str::to_owned),
            admission_sequence: object
                .and_then(|object| object.get(ADMISSION_SEQUENCE_FIELD))
                .and_then(Value::as_u64),
            outcome: object
                .and_then(|object| object.get(OUTCOME_FIELD))
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }
}

struct OpenAdmission {
    action: String,
    outcomes: Vec<(u64, TerminalOutcome)>,
}

#[derive(Default)]
struct ReportBuilder {
    admissions: BTreeMap<u64, OpenAdmission>,
    orphan_outcomes: u64,
    malformed_lifecycle_records: u64,
}

impl ReportBuilder {
    fn observe_line(&mut self, line: &[u8], position: ChainPosition) {
        self.observe(Observation::parse(line, position));
    }

    fn observe(&mut self, observation: Observation) {
        match observation.event.as_deref() {
            Some(ADMISSION_EVENT) => {
                let valid = observation.admission_sequence == Some(observation.sequence)
                    && observation.action.as_deref().is_some_and(valid_action);
                if valid {
                    self.admissions.insert(
                        observation.sequence,
                        OpenAdmission {
                            action: observation.action.expect("validated action"),
                            outcomes: Vec::new(),
                        },
                    );
                } else {
                    self.malformed_lifecycle_records =
                        self.malformed_lifecycle_records.saturating_add(1);
                }
            }
            Some(OUTCOME_EVENT) => {
                let outcome = observation
                    .outcome
                    .as_deref()
                    .and_then(TerminalOutcome::parse);
                let Some(outcome) = outcome else {
                    self.malformed_lifecycle_records =
                        self.malformed_lifecycle_records.saturating_add(1);
                    return;
                };
                let Some(admission_sequence) = observation.admission_sequence else {
                    self.malformed_lifecycle_records =
                        self.malformed_lifecycle_records.saturating_add(1);
                    return;
                };
                if admission_sequence >= observation.sequence {
                    self.malformed_lifecycle_records =
                        self.malformed_lifecycle_records.saturating_add(1);
                } else if let Some(admission) = self.admissions.get_mut(&admission_sequence) {
                    admission.outcomes.push((observation.sequence, outcome));
                } else {
                    self.orphan_outcomes = self.orphan_outcomes.saturating_add(1);
                }
            }
            _ => {}
        }
    }

    fn finish(self, position: ChainPosition) -> AdmissionReport {
        let admissions = self
            .admissions
            .into_iter()
            .map(|(admission_seq, admission)| {
                let outcome = match admission.outcomes.as_slice() {
                    [] => AdmissionOutcomeState::Unknown,
                    [(outcome_seq, outcome)] => AdmissionOutcomeState::Terminal {
                        outcome: *outcome,
                        outcome_seq: *outcome_seq,
                    },
                    many => AdmissionOutcomeState::Conflicted {
                        outcome_seqs: many.iter().map(|(sequence, _)| *sequence).collect(),
                    },
                };
                AdmissionState {
                    admission_seq,
                    action: admission.action,
                    outcome,
                }
            })
            .collect();
        AdmissionReport {
            position,
            admissions,
            orphan_outcomes: self.orphan_outcomes,
            malformed_lifecycle_records: self.malformed_lifecycle_records,
        }
    }
}

fn finish_scan(
    verification: ChainVerification,
    builder: ReportBuilder,
) -> Result<AdmissionReport, ChainVerification> {
    match verification {
        ChainVerification::Valid { position } => Ok(builder.finish(position)),
        other => Err(other),
    }
}

fn scan_open_directory(
    directory: &Directory,
    trust: &ChainTrust,
) -> Result<AdmissionReport, ChainVerification> {
    let mut builder = ReportBuilder::default();
    let verification = verify_open_directory_observed(directory, Some(trust), |line, position| {
        builder.observe_line(line, position)
    });
    finish_scan(verification, builder)
}

/// Pair admissions and outcomes in a fully authenticated journal without
/// creating or repairing any file. `trust` must contain the broker's complete
/// key, raw vault identity, and independently trusted position. Any verifier
/// failure is returned instead of a lifecycle report.
pub fn scan_admissions(
    directory: impl AsRef<Path>,
    trust: Option<&ChainTrust>,
) -> Result<AdmissionReport, ChainVerification> {
    let Some(trust) = trust else {
        return Err(ChainVerification::MissingTrustState);
    };
    let directory = match Directory::open(directory.as_ref(), false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let empty: &[u8] = b"";
            let builder = ReportBuilder::default();
            let verification = verify_reader_observed(empty, Some(trust), |_, _| {});
            return finish_scan(verification, builder);
        }
        Err(_) => {
            return Err(ChainVerification::Unreadable {
                reason: ChainReadFailure::FolderRefused,
            });
        }
    };
    scan_open_directory(&directory, trust)
}

fn valid_action(action: &str) -> bool {
    !action.is_empty()
        && action.len() <= MAX_ADMISSION_ACTION_BYTES
        && action
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:/+".contains(&byte))
}

fn uses_lifecycle_fields(metadata: &Map<String, Value>) -> bool {
    metadata
        .keys()
        .any(|key| LIFECYCLE_FIELDS.contains(&key.as_str()))
}

fn lock_error(failure: crate::fs::LockFailure) -> LifecycleError {
    if failure.unsupported {
        LifecycleError::LockUnsupported
    } else {
        LifecycleError::LockUnavailable
    }
}

fn checkpoint_error(failure: CheckpointFailure) -> LifecycleError {
    match failure {
        CheckpointFailure::ReadFailed => LifecycleError::CheckpointReadFailed,
        CheckpointFailure::Invalid => LifecycleError::CheckpointInvalid,
        CheckpointFailure::WriteFailed => LifecycleError::CheckpointWriteFailed,
        CheckpointFailure::SyncFailed => LifecycleError::CheckpointSyncFailed,
    }
}

fn verification_error(verification: ChainVerification) -> LifecycleError {
    match verification {
        ChainVerification::MissingTrustState | ChainVerification::Valid { .. } => {
            LifecycleError::ChainUnauthenticated
        }
        ChainVerification::Truncated { .. } => LifecycleError::ChainTruncated,
        ChainVerification::Corrupted { .. } => LifecycleError::ChainCorrupted,
        ChainVerification::ContinuityLoss { mismatch, .. } => {
            LifecycleError::ChainContinuityLoss(mismatch)
        }
        ChainVerification::Unreadable { reason } => match reason {
            ChainReadFailure::FolderRefused => LifecycleError::FolderRefused,
            ChainReadFailure::FileRefused => LifecycleError::FileRefused,
            ChainReadFailure::ReadFailed => LifecycleError::ChainUnreadable,
        },
    }
}

#[cfg(test)]
mod tests;
