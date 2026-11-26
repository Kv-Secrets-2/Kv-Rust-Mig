use super::*;
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kv-audit-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("isolated admission test directory");
        Self(path)
    }

    fn audit_dir(&self) -> PathBuf {
        self.0.join("audit")
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct CheckpointState {
    position: ChainPosition,
    events: Vec<&'static str>,
    read_failures: VecDeque<CheckpointFailure>,
    publish_failures: VecDeque<CheckpointFailure>,
}

#[derive(Clone)]
struct MemoryCheckpoint {
    state: Arc<Mutex<CheckpointState>>,
}

impl MemoryCheckpoint {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CheckpointState {
                position: ChainPosition::genesis(),
                events: Vec::new(),
                read_failures: VecDeque::new(),
                publish_failures: VecDeque::new(),
            })),
        }
    }
}

impl TrustedCheckpoint for MemoryCheckpoint {
    fn load_durable(&mut self) -> Result<ChainPosition, CheckpointFailure> {
        let mut state = self.state.lock().unwrap();
        state.events.push("checkpoint_read");
        if let Some(failure) = state.read_failures.pop_front() {
            return Err(failure);
        }
        Ok(state.position)
    }

    fn publish_durable(&mut self, position: ChainPosition) -> Result<(), CheckpointFailure> {
        let mut state = self.state.lock().unwrap();
        state.events.push("checkpoint_publish");
        if let Some(failure) = state.publish_failures.pop_front() {
            return Err(failure);
        }
        state.position = position;
        Ok(())
    }
}

struct Fixture {
    temp: Temp,
    journal: AdmissionJournal,
    checkpoint: MemoryCheckpoint,
    append_failures: Arc<Mutex<VecDeque<DurableAppendFailure>>>,
}

fn key() -> ChainKey {
    ChainKey::new([0x42; 32])
}

fn identity() -> VaultIdentity {
    VaultIdentity::new(b"fixture-vault-identity").unwrap()
}

fn fixture() -> Fixture {
    let temp = Temp::new();
    let directory = temp.audit_dir();
    fixture_in(temp, directory)
}

fn fixture_in(temp: Temp, directory: PathBuf) -> Fixture {
    let checkpoint = MemoryCheckpoint::new();
    let append_events = checkpoint.state.clone();
    let append_failures = Arc::new(Mutex::new(VecDeque::new()));
    let injected = append_failures.clone();
    let append = Box::new(move |directory: &Directory, bytes: &[u8]| {
        append_events.lock().unwrap().events.push("journal_append");
        if let Some(failure) = injected.lock().unwrap().pop_front() {
            if failure == DurableAppendFailure::SyncFailed {
                let _ = directory.append_durable(bytes);
            }
            return Err(failure);
        }
        directory.append_durable(bytes)
    });
    let journal = AdmissionJournal::with_append_failure_injection(
        directory,
        key(),
        identity(),
        Box::new(checkpoint.clone()),
        append,
    );
    Fixture {
        temp,
        journal,
        checkpoint,
        append_failures,
    }
}

fn metadata(entries: &[(&str, &str)]) -> Map<String, Value> {
    let mut output = Map::new();
    for (key, value) in entries {
        output.insert((*key).into(), Value::String((*value).into()));
    }
    output
}

fn checkpoint_state(fixture: &Fixture) -> (ChainPosition, Vec<&'static str>) {
    let state = fixture.checkpoint.state.lock().unwrap();
    (state.position, state.events.clone())
}

fn counter() -> Arc<AtomicUsize> {
    Arc::new(AtomicUsize::new(0))
}

fn run_if_admitted(
    admission: Result<Admission, LifecycleError>,
    counter: Arc<AtomicUsize>,
) -> Option<Execution<usize>> {
    admission
        .ok()
        .map(|admission| admission.run(|_| counter.fetch_add(1, Ordering::SeqCst) + 1))
}

#[test]
fn admission_and_terminal_outcome_commit_in_order_and_effect_runs_once() {
    let fixture = fixture();
    let effect = counter();
    let admission = fixture
        .journal
        .admit("broker.http.get", metadata(&[("provider", "fixture")]))
        .unwrap();
    assert_eq!(admission.sequence(), 1);
    assert_eq!(
        checkpoint_state(&fixture).1,
        ["checkpoint_read", "journal_append", "checkpoint_publish",]
    );

    let callback_effect = effect.clone();
    let execution = admission.run(|position| {
        assert_eq!(position.count, 1);
        callback_effect.fetch_add(1, Ordering::SeqCst)
    });
    assert_eq!(effect.load(Ordering::SeqCst), 1);
    let output = execution
        .finish(TerminalOutcome::Completed, Map::new())
        .unwrap();
    assert_eq!(output, 0);

    let (position, _) = checkpoint_state(&fixture);
    assert_eq!(position.count, 2);
    let report = fixture.journal.admission_states().unwrap();
    assert_eq!(report.position.count, 2);
    assert_eq!(report.admissions.len(), 1);
    assert_eq!(report.admissions[0].action, "broker.http.get");
    assert_eq!(
        report.admissions[0].outcome,
        AdmissionOutcomeState::Terminal {
            outcome: TerminalOutcome::Completed,
            outcome_seq: 2
        }
    );
    assert_eq!(effect.load(Ordering::SeqCst), 1);
}

#[test]
fn checkpoint_load_failures_block_before_write_or_effect() {
    for (failure, expected) in [
        (
            CheckpointFailure::ReadFailed,
            LifecycleError::CheckpointReadFailed,
        ),
        (
            CheckpointFailure::Invalid,
            LifecycleError::CheckpointInvalid,
        ),
    ] {
        let fixture = fixture();
        fixture
            .checkpoint
            .state
            .lock()
            .unwrap()
            .read_failures
            .push_back(failure);
        let effect = counter();
        let result = fixture.journal.admit("broker.http.get", Map::new());
        assert_eq!(result.as_ref().err(), Some(&expected));
        assert!(run_if_admitted(result, effect.clone()).is_none());
        assert_eq!(effect.load(Ordering::SeqCst), 0);
        assert!(!fixture.temp.audit_dir().join("audit.jsonl").exists());
        assert_eq!(checkpoint_state(&fixture).1, ["checkpoint_read"]);
    }
}

#[test]
fn checkpoint_write_and_sync_failures_block_usable_admission_and_effect() {
    for (failure, expected) in [
        (
            CheckpointFailure::WriteFailed,
            LifecycleError::CheckpointWriteFailed,
        ),
        (
            CheckpointFailure::SyncFailed,
            LifecycleError::CheckpointSyncFailed,
        ),
    ] {
        let fixture = fixture();
        fixture
            .checkpoint
            .state
            .lock()
            .unwrap()
            .publish_failures
            .push_back(failure);
        let effect = counter();
        let result = fixture.journal.admit("broker.http.post", Map::new());
        assert_eq!(result.as_ref().err(), Some(&expected));
        assert!(run_if_admitted(result, effect.clone()).is_none());
        assert_eq!(effect.load(Ordering::SeqCst), 0);
        let (position, events) = checkpoint_state(&fixture);
        assert_eq!(position, ChainPosition::genesis());
        assert_eq!(
            events,
            ["checkpoint_read", "journal_append", "checkpoint_publish",]
        );
        let trust = ChainTrust::new(key(), identity(), ChainPosition::genesis());
        assert!(matches!(
            scan_admissions(fixture.temp.audit_dir(), Some(&trust)),
            Err(ChainVerification::ContinuityLoss {
                mismatch: ChainPositionMismatch::BeyondCheckpoint,
                ..
            })
        ));
    }
}

#[test]
fn journal_write_and_sync_failures_block_checkpoint_and_effect() {
    for (failure, expected) in [
        (
            DurableAppendFailure::FileRefused,
            LifecycleError::FileRefused,
        ),
        (
            DurableAppendFailure::WriteFailed,
            LifecycleError::JournalWriteFailed,
        ),
        (
            DurableAppendFailure::SyncFailed,
            LifecycleError::JournalSyncFailed,
        ),
    ] {
        let fixture = fixture();
        fixture.append_failures.lock().unwrap().push_back(failure);
        let effect = counter();
        let result = fixture.journal.admit("broker.http.get", Map::new());
        assert_eq!(result.as_ref().err(), Some(&expected));
        assert!(run_if_admitted(result, effect.clone()).is_none());
        assert_eq!(effect.load(Ordering::SeqCst), 0);
        let (position, events) = checkpoint_state(&fixture);
        assert_eq!(position, ChainPosition::genesis());
        assert_eq!(events, ["checkpoint_read", "journal_append"]);
        if failure == DurableAppendFailure::SyncFailed {
            let retry_effect = counter();
            let retry = fixture.journal.admit("broker.http.retry", Map::new());
            assert_eq!(
                retry.as_ref().err(),
                Some(&LifecycleError::ChainContinuityLoss(
                    ChainPositionMismatch::BeyondCheckpoint
                ))
            );
            assert!(run_if_admitted(retry, retry_effect.clone()).is_none());
            assert_eq!(retry_effect.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn first_admission_fails_closed_when_new_journal_directory_cannot_be_made_durable() {
    use std::os::unix::fs::PermissionsExt;

    let temp = Temp::new();
    let parent = temp.0.join("parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).unwrap();
    let fixture = fixture_in(temp, parent.join("audit"));
    let effect = counter();
    let result = fixture.journal.admit("broker.http.get", Map::new());
    assert_eq!(result.as_ref().err(), Some(&LifecycleError::FolderRefused));
    assert!(run_if_admitted(result, effect.clone()).is_none());
    assert_eq!(effect.load(Ordering::SeqCst), 0);
    assert!(!parent.join("audit").join("audit.jsonl").exists());
    assert!(!parent.join("audit").exists());
    let (position, events) = checkpoint_state(&fixture);
    assert_eq!(position, ChainPosition::genesis());
    assert_eq!(events, Vec::<&'static str>::new());
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn first_admission_creates_multilevel_journal_directories() {
    let temp = Temp::new();
    let audit = temp.0.join("outer").join("inner").join("audit");
    let fixture = fixture_in(temp, audit.clone());
    let effect = counter();
    let admission = fixture
        .journal
        .admit("broker.http.get", Map::new())
        .unwrap();
    let execution = admission.run(|_| effect.fetch_add(1, Ordering::SeqCst));
    drop(execution);
    assert_eq!(effect.load(Ordering::SeqCst), 1);
    assert!(audit.join("audit.jsonl").is_file());
    assert_eq!(checkpoint_state(&fixture).0.count, 1);
}

#[test]
fn search_only_existing_ancestors_do_not_block_first_admission() {
    use std::os::unix::fs::PermissionsExt;

    let temp = Temp::new();
    let gateway = temp.0.join("gateway");
    let parent = gateway.join("parent");
    fs::create_dir(&gateway).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&gateway, fs::Permissions::from_mode(0o300)).unwrap();
    let fixture = fixture_in(temp, parent.join("audit"));
    let effect = counter();
    let admission = fixture
        .journal
        .admit("broker.http.get", Map::new())
        .unwrap();
    let execution = admission.run(|_| effect.fetch_add(1, Ordering::SeqCst));
    drop(execution);
    assert_eq!(effect.load(Ordering::SeqCst), 1);
    assert_eq!(checkpoint_state(&fixture).0.count, 1);
    fs::set_permissions(&gateway, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn in_place_history_corruption_blocks_even_when_tail_remains_authentic() {
    let fixture = fixture();
    drop(fixture.journal.admit("alpha", Map::new()).unwrap());
    drop(fixture.journal.admit("beta", Map::new()).unwrap());
    let log = fixture.temp.audit_dir().join("audit.jsonl");
    let original = fs::read(&log).unwrap();
    let at = original
        .windows(b"alpha".len())
        .position(|window| window == b"alpha")
        .unwrap();
    let mut corrupted = original.clone();
    corrupted[at] = b'A';
    fs::write(&log, corrupted).unwrap();

    let effect = counter();
    let result = fixture.journal.admit("gamma", Map::new());
    assert_eq!(result.as_ref().err(), Some(&LifecycleError::ChainCorrupted));
    assert!(run_if_admitted(result, effect.clone()).is_none());
    assert_eq!(effect.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(&log)
            .unwrap()
            .iter()
            .filter(|byte| **byte == b'\n')
            .count(),
        2
    );
}

#[test]
fn unmatched_interrupted_admissions_are_unknown_and_never_repeated() {
    let fixture = fixture();
    let effect = counter();

    drop(fixture.journal.admit("dropped", Map::new()).unwrap());

    let interrupted_effect = effect.clone();
    let execution = fixture
        .journal
        .admit("interrupted", Map::new())
        .unwrap()
        .run(|_| interrupted_effect.fetch_add(1, Ordering::SeqCst));
    drop(execution);

    let finished_effect = effect.clone();
    let output = fixture
        .journal
        .admit("finished", Map::new())
        .unwrap()
        .run(|_| finished_effect.fetch_add(1, Ordering::SeqCst))
        .finish(
            TerminalOutcome::Failed,
            metadata(&[("error_code", "fixture_failed")]),
        )
        .unwrap();
    assert_eq!(output, 1);

    let report = fixture.journal.admission_states().unwrap();
    assert_eq!(report.admissions.len(), 3);
    assert_eq!(report.admissions[0].outcome, AdmissionOutcomeState::Unknown);
    assert_eq!(report.admissions[1].outcome, AdmissionOutcomeState::Unknown);
    assert_eq!(
        report.admissions[2].outcome,
        AdmissionOutcomeState::Terminal {
            outcome: TerminalOutcome::Failed,
            outcome_seq: 4
        }
    );
    assert_eq!(effect.load(Ordering::SeqCst), 2);
}

#[test]
fn outcome_write_failure_preserves_effect_output_and_leaves_admission_unknown() {
    let fixture = fixture();
    let admission = fixture
        .journal
        .admit("broker.http.get", Map::new())
        .unwrap();
    let effect = counter();
    let callback_effect = effect.clone();
    let execution = admission.run(|_| {
        callback_effect.fetch_add(1, Ordering::SeqCst);
        7_usize
    });
    fixture
        .append_failures
        .lock()
        .unwrap()
        .push_back(DurableAppendFailure::WriteFailed);
    let error = execution
        .finish(TerminalOutcome::Completed, Map::new())
        .unwrap_err();
    assert_eq!(error.error, LifecycleError::JournalWriteFailed);
    assert_eq!(error.into_output(), 7);
    assert_eq!(effect.load(Ordering::SeqCst), 1);

    let report = fixture.journal.admission_states().unwrap();
    assert_eq!(report.admissions.len(), 1);
    assert_eq!(report.admissions[0].outcome, AdmissionOutcomeState::Unknown);
    assert_eq!(effect.load(Ordering::SeqCst), 1);
}

#[test]
fn outcome_error_formatting_redacts_output_but_explicit_retrieval_preserves_it() {
    let fixture = fixture();
    let marker = "synthetic-provider-result-marker";
    let execution = fixture
        .journal
        .admit("broker.http.get", Map::new())
        .unwrap()
        .run(|_| marker);
    fixture
        .append_failures
        .lock()
        .unwrap()
        .push_back(DurableAppendFailure::WriteFailed);
    let error = execution
        .finish(TerminalOutcome::Completed, Map::new())
        .unwrap_err();

    let debug = format!("{error:?}");
    let display = error.to_string();
    assert!(!debug.contains(marker));
    assert!(!display.contains(marker));
    assert!(debug.contains("<redacted>"));
    assert_eq!(error.into_output(), marker);
}

#[test]
fn outcome_checkpoint_publish_failure_preserves_output_and_fails_scans_closed() {
    let fixture = fixture();
    let execution = fixture
        .journal
        .admit("broker.http.get", Map::new())
        .unwrap()
        .run(|_| 13_usize);
    fixture
        .checkpoint
        .state
        .lock()
        .unwrap()
        .publish_failures
        .push_back(CheckpointFailure::SyncFailed);
    let error = execution
        .finish(TerminalOutcome::Completed, Map::new())
        .unwrap_err();
    assert_eq!(error.error, LifecycleError::CheckpointSyncFailed);
    assert_eq!(error.into_output(), 13);
    assert!(matches!(
        fixture.journal.admission_states(),
        Err(LifecycleError::ChainContinuityLoss(
            ChainPositionMismatch::BeyondCheckpoint
        ))
    ));
}

#[test]
fn invalid_actions_and_lifecycle_metadata_are_rejected_before_io() {
    let fixture = fixture();
    for action in ["", "bad action", "bad\naction", &"x".repeat(129)] {
        assert_eq!(
            fixture.journal.admit(action, Map::new()).err(),
            Some(LifecycleError::InvalidAction)
        );
    }
    for reserved in LIFECYCLE_FIELDS {
        assert_eq!(
            fixture
                .journal
                .admit("broker.http.get", metadata(&[(reserved, "caller")]))
                .err(),
            Some(LifecycleError::InvalidMetadata)
        );
    }
    assert!(!fixture.temp.audit_dir().exists());
}

#[test]
fn lifecycle_fields_in_outcome_metadata_preserve_output_without_appending() {
    let fixture = fixture();
    let execution = fixture
        .journal
        .admit("broker.http.get", Map::new())
        .unwrap()
        .run(|_| 11_usize);
    let error = execution
        .finish(
            TerminalOutcome::Completed,
            metadata(&[(ACTION_FIELD, "caller")]),
        )
        .unwrap_err();
    assert_eq!(error.error, LifecycleError::InvalidMetadata);
    assert_eq!(error.into_output(), 11);
    let (position, events) = checkpoint_state(&fixture);
    assert_eq!(position.count, 1);
    assert_eq!(
        events,
        ["checkpoint_read", "journal_append", "checkpoint_publish",]
    );
    let report = fixture.journal.admission_states().unwrap();
    assert_eq!(report.admissions[0].outcome, AdmissionOutcomeState::Unknown);
}

#[test]
fn concurrent_admissions_are_serialized_without_sequence_loss() {
    let fixture = fixture();
    let mut workers = Vec::new();
    for index in 0..4 {
        let journal = fixture.journal.clone();
        workers.push(std::thread::spawn(move || {
            let action = format!("worker{index}");
            journal.admit(&action, Map::new()).unwrap().sequence()
        }));
    }
    let mut sequences: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    sequences.sort_unstable();
    assert_eq!(sequences, [1, 2, 3, 4]);
    let report = fixture.journal.admission_states().unwrap();
    assert_eq!(report.position.count, 4);
    assert_eq!(report.admissions.len(), 4);
}

fn observation(
    sequence: u64,
    event: &str,
    action: Option<&str>,
    admission_sequence: Option<u64>,
    outcome: Option<&str>,
) -> Observation {
    Observation {
        sequence,
        event: Some(event.into()),
        action: action.map(str::to_owned),
        admission_sequence,
        outcome: outcome.map(str::to_owned),
    }
}

#[test]
fn report_marks_conflicted_orphan_and_malformed_lifecycle_records() {
    let observations = vec![
        observation(1, ADMISSION_EVENT, Some("alpha"), Some(1), None),
        observation(2, OUTCOME_EVENT, None, Some(1), Some("completed")),
        observation(3, OUTCOME_EVENT, None, Some(1), Some("failed")),
        observation(4, OUTCOME_EVENT, None, Some(2), Some("completed")),
        observation(5, ADMISSION_EVENT, Some("broken"), Some(8), None),
        observation(6, OUTCOME_EVENT, None, Some(1), Some("unknown")),
    ];
    let mut builder = ReportBuilder::default();
    for observation in observations {
        builder.observe(observation);
    }
    let report = builder.finish(ChainPosition {
        count: 6,
        head: crate::chain::ChainHead::GENESIS,
    });
    assert_eq!(report.orphan_outcomes, 1);
    assert_eq!(report.malformed_lifecycle_records, 2);
    assert_eq!(report.admissions.len(), 1);
    assert_eq!(
        report.admissions[0].outcome,
        AdmissionOutcomeState::Conflicted {
            outcome_seqs: vec![2, 3]
        }
    );
}
