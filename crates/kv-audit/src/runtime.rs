use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{Map, Number, Value};

use crate::fs::{AppendFailure, Directory};
use crate::{
    AuditHealth, Coverage, FolderState, HealthState, LossReason, Order, Warning, WarningChannel,
};

const LOG_LOCK: &str = "audit.lock";
const HEALTH_LOCK: &str = "audit-health.lock";
const HEALTH_FILE: &str = "audit-health.json";
const UNKEPT: &str = "audit-health.unkept";
const UNCERTAIN: &str = "audit.uncertain";
const LOCK_WAIT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct State {
    refused: Option<LossReason>,
    lost_any: bool,
    pending: usize,
    printed: bool,
    unkept: bool,
    uncertain: bool,
    uncertain_told: bool,
    pending_mark: usize,
    printed_mark: bool,
    vault_label: Option<String>,
}

struct Inner {
    directory: PathBuf,
    channel: WarningChannel,
    state: Mutex<State>,
}

/// Shared audit writer and pending-warning state. Clones share the same mutex.
#[derive(Clone)]
pub struct Audit(Arc<Inner>);

impl Audit {
    /// Create a writer whose warnings are delivered by opted-in daemon replies.
    /// No filesystem access occurs until an emit or a health snapshot.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self::with_channel(directory, WarningChannel::Reply)
    }

    pub fn with_channel(directory: impl Into<PathBuf>, channel: WarningChannel) -> Self {
        Self(Arc::new(Inner {
            directory: directory.into(),
            channel,
            state: Mutex::new(State::default()),
        }))
    }

    pub fn directory(&self) -> &Path {
        &self.0.directory
    }

    /// Optional registry short name; this must never be a vault filesystem path.
    pub fn set_vault_label(&self, label: Option<&str>) {
        self.state().vault_label = label.filter(|label| !label.is_empty()).map(str::to_owned);
    }

    /// Append one event. Keep field insertion order: it is part of the hash.
    /// Values must already be safe event metadata, never request/response bodies
    /// or secret values. The reference's attribution withholding is applied here.
    pub fn emit(&self, event: &str, fields: Map<String, Value>) -> Result<(), LossReason> {
        self.emit_with(event, fields, utc_timestamp, || {})
    }

    #[cfg(test)]
    fn emit_at(
        &self,
        event: &str,
        fields: Map<String, Value>,
        timestamp: &str,
    ) -> Result<(), LossReason> {
        self.emit_with(event, fields, || timestamp.to_owned(), || {})
    }

    // Private clock and post-append seams make contention and replacement
    // tests deterministic. Production callers cannot bypass the lock checks.
    fn emit_with(
        &self,
        event: &str,
        fields: Map<String, Value>,
        timestamp: impl FnOnce() -> String,
        after_append: impl FnOnce(),
    ) -> Result<(), LossReason> {
        let mut state = self.state();
        let directory = match Directory::open(&self.0.directory, true) {
            Ok(directory) => directory,
            Err(_) => {
                self.record_loss(&mut state, LossReason::FolderRefused);
                state.unkept = true;
                self.warn_once(&mut state);
                return Err(LossReason::FolderRefused);
            }
        };
        let log_lock = match directory.lock(LOG_LOCK, LOCK_WAIT) {
            Ok(lock) => lock,
            Err(failure) => {
                let reason = if failure.unsupported {
                    LossReason::LockUnsupported
                } else {
                    LossReason::LockUnavailable
                };
                self.record_loss(&mut state, reason);
                self.write_health(&directory, &mut state, Some(reason));
                self.warn_once(&mut state);
                return Err(reason);
            }
        };
        let previous = directory.tail_hash();
        let outcome = crate::codec::encode_entry(
            &timestamp(),
            event,
            fields,
            state.vault_label.as_deref(),
            previous,
        )
        .map_err(|_| LossReason::WriteFailed)
        .and_then(|bytes| {
            directory.append(&bytes).map_err(|failure| match failure {
                AppendFailure::FileRefused => LossReason::FileRefused,
                AppendFailure::WriteFailed => LossReason::WriteFailed,
            })
        });
        after_append();
        if !directory.lock_matches(&log_lock, LOG_LOCK).unwrap_or(false) {
            state.uncertain = true;
            if directory.mark_uncertain().is_err() {
                self.mark_not_kept(&directory, &mut state);
            }
        }
        match outcome {
            Err(reason) => {
                self.record_loss(&mut state, reason);
                self.write_health(&directory, &mut state, Some(reason));
                self.warn_once(&mut state);
                Err(reason)
            }
            Ok(()) => {
                let recovered = state.refused.take().is_some();
                if recovered {
                    self.write_health(&directory, &mut state, None);
                }
                Ok(())
            }
        }
        // The owned flock is released after the entire health update.
    }

    /// Reserve one pending warning. Drop returns it to its queue; call
    /// `delivered` only after the complete reply was successfully sent.
    pub fn take_warning(&self) -> Option<WarningLease> {
        let mut state = self.state();
        let warning = if state.pending > 0 {
            state.pending -= 1;
            Warning::RecordLost
        } else if state.pending_mark > 0 {
            state.pending_mark -= 1;
            Warning::OrderMarkNotKept
        } else {
            return None;
        };
        Some(WarningLease {
            audit: self.clone(),
            warning,
            delivered: false,
        })
    }

    /// Probe without creating files, changing modes, or clearing markers.
    pub fn health(&self) -> AuditHealth {
        let mut order = if self.state().uncertain {
            Order::Uncertain
        } else {
            Order::Serialized
        };
        let directory = match Directory::open(&self.0.directory, false) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let state = self.state();
                let unknown = state.unkept || state.refused.is_some() || state.lost_any;
                return AuditHealth {
                    state: if state.refused.is_some() {
                        HealthState::Refused
                    } else {
                        HealthState::Empty
                    },
                    reason: state.refused,
                    lost: (!unknown).then(|| Number::from(0)),
                    coverage: if unknown {
                        Coverage::Unknown
                    } else {
                        Coverage::Floor
                    },
                    order,
                    folder: FolderState::Ok,
                };
            }
            Err(_) => {
                return AuditHealth {
                    state: HealthState::Refused,
                    reason: Some(LossReason::FolderRefused),
                    lost: None,
                    coverage: Coverage::Unknown,
                    order: if order == Order::Uncertain {
                        order
                    } else {
                        Order::Unknown
                    },
                    folder: FolderState::Unknown,
                };
            }
        };
        if directory.exists(UNCERTAIN) {
            order = Order::Uncertain;
        }
        let folder = match directory.folder_state() {
            "ok" => FolderState::Ok,
            "mode" => FolderState::Mode,
            "acl" => FolderState::Acl,
            "unreadable" => FolderState::Unreadable,
            _ => FolderState::Unknown,
        };
        let file_state = directory.probe_log();
        let health_exists = directory.exists(HEALTH_FILE);
        let marked = directory.exists(UNKEPT);
        let record = read_health(&directory);
        let state = self.state();
        let (health_state, reason) = if file_state == "refused" {
            (HealthState::Refused, Some(LossReason::FileRefused))
        } else if let Some(reason) = state.refused {
            (HealthState::Refused, Some(reason))
        } else if let Some(reason) = record.as_ref().and_then(|record| record.reason) {
            (HealthState::Refused, Some(reason))
        } else if file_state == "absent" {
            (HealthState::Empty, None)
        } else {
            (HealthState::Ok, None)
        };
        let lost = if let Some(record) = record {
            if state.unkept || marked {
                None
            } else {
                record.lost
            }
        } else if health_exists || marked || health_state == HealthState::Refused || state.lost_any
        {
            None
        } else {
            Some(Number::from(0))
        };
        AuditHealth {
            state: health_state,
            reason,
            coverage: if lost.is_some() {
                Coverage::Floor
            } else {
                Coverage::Unknown
            },
            lost,
            order,
            folder,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn record_loss(&self, state: &mut State, reason: LossReason) {
        if state.refused.is_none() {
            state.pending = state.pending.saturating_add(1);
        }
        state.refused = Some(reason);
        state.lost_any = true;
    }

    fn warn_once(&self, state: &mut State) {
        if self.0.channel == WarningChannel::Stderr && !state.printed {
            state.printed = true;
            let _ = writeln!(std::io::stderr(), "! {}", Warning::RecordLost.as_str());
        }
    }

    fn mark_not_kept(&self, directory: &Directory, state: &mut State) {
        directory.mark_unkept();
        if !state.uncertain_told {
            state.uncertain_told = true;
            state.pending_mark = state.pending_mark.saturating_add(1);
        }
        if self.0.channel == WarningChannel::Stderr && !state.printed_mark {
            state.printed_mark = true;
            let _ = writeln!(
                std::io::stderr(),
                "! {}",
                Warning::OrderMarkNotKept.as_str()
            );
        }
    }

    fn write_health(&self, directory: &Directory, state: &mut State, reason: Option<LossReason>) {
        let health_lock = directory.lock(HEALTH_LOCK, LOCK_WAIT);
        if health_lock.is_err() {
            directory.mark_unkept();
        }
        let exists = directory.exists(HEALTH_FILE);
        let existing = read_health(directory);
        let marked = directory.exists(UNKEPT);
        let untrusted = state.unkept || marked || health_lock.is_err();
        let mut lost = if !untrusted && existing.is_some() {
            existing.and_then(|record| record.lost)
        } else if exists || untrusted {
            None
        } else {
            Some(Number::from(0))
        };
        if reason.is_some() && !untrusted {
            lost = lost.map(increment_count);
        }
        // This order matches json.dumps(sort_keys=True, separators=(",", ":")).
        let mut record = Map::new();
        record.insert("lost".into(), lost.map_or(Value::Null, Value::Number));
        if let Some(reason) = reason {
            record.insert("reason".into(), Value::String(reason.to_string()));
        }
        record.insert(
            "state".into(),
            Value::String(if reason.is_some() { "refused" } else { "ok" }.into()),
        );
        record.insert("v".into(), Value::from(1));
        let mut bytes = serde_json::to_vec(&record).expect("fixed health record is JSON");
        bytes.push(b'\n');
        if directory.write_health(&bytes).is_err() {
            state.unkept = true;
            directory.mark_unkept();
        } else {
            state.unkept = false;
            if marked && health_lock.is_ok() {
                directory.clear_unkept();
            }
        }
    }
}

fn utc_timestamp() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// An owed warning stays owed until delivery succeeds. Dropping the lease on
/// serialization, size-bound, retirement, or transport failure returns it.
pub struct WarningLease {
    audit: Audit,
    warning: Warning,
    delivered: bool,
}

impl WarningLease {
    pub fn warning(&self) -> Warning {
        self.warning
    }
    pub fn as_str(&self) -> &'static str {
        self.warning.as_str()
    }
    pub fn delivered(mut self) {
        self.delivered = true;
    }
}

impl Drop for WarningLease {
    fn drop(&mut self) {
        if !self.delivered {
            let mut state = self.audit.state();
            let pending = match self.warning {
                Warning::RecordLost => &mut state.pending,
                Warning::OrderMarkNotKept => &mut state.pending_mark,
            };
            *pending = pending.saturating_add(1);
        }
    }
}

struct HealthRecord {
    reason: Option<LossReason>,
    lost: Option<Number>,
}

fn read_health(directory: &Directory) -> Option<HealthRecord> {
    let bytes = directory.read_bounded(HEALTH_FILE, 4096).ok()?;
    parse_health(crate::python_json::from_slice(&bytes).ok()?)
}

fn parse_health(value: Value) -> Option<HealthRecord> {
    let object = value.as_object()?;
    // Python's `data.get("v") != 1` also accepts True and 1.0.
    if !object
        .get("v")
        .is_some_and(|value| value == &Value::Bool(true) || value.as_f64() == Some(1.0))
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "v" | "state" | "reason" | "lost"))
    {
        return None;
    }
    // The pinned Python validator accidentally accepts a missing `lost`, then
    // audit_health raises KeyError. Treat that corrupted record as untrusted
    // instead of propagating the reference's crash into the daemon.
    let lost = match object.get("lost")? {
        Value::Null => None,
        Value::Number(number) => Some(nonnegative_integer(number)?),
        _ => return None,
    };
    let reason = match object.get("state")?.as_str()? {
        "ok" if object.get("reason").is_none_or(Value::is_null) => None,
        "refused" => {
            let reason = object.get("reason")?.as_str()?;
            Some(serde_json::from_value(Value::String(reason.to_owned())).ok()?)
        }
        _ => return None,
    };
    Some(HealthRecord { reason, lost })
}

fn nonnegative_integer(number: &Number) -> Option<Number> {
    let text = number.to_string();
    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(number.clone())
    } else if text == "-0" {
        // Python json.loads("-0") produces the integer zero.
        Some(Number::from(0))
    } else {
        None
    }
}

fn increment_count(number: Number) -> Number {
    let mut digits = number.to_string().into_bytes();
    let mut carry = true;
    for digit in digits.iter_mut().rev() {
        if *digit == b'9' {
            *digit = b'0';
        } else {
            *digit += 1;
            carry = false;
            break;
        }
    }
    if carry {
        digits.insert(0, b'1');
    }
    String::from_utf8(digits)
        .expect("decimal digits")
        .parse()
        .expect("nonnegative integer")
}

#[cfg(test)]
mod tests;
