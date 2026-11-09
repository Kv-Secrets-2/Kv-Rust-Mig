use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kv-audit-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("isolated test directory");
        Self(path)
    }
    fn audit(&self) -> Audit {
        Audit::new(self.0.join("audit"))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fields() -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("provider".into(), Value::String("example".into()));
    fields
}

fn hardlink_log(audit: &Audit) -> PathBuf {
    let alias = audit.directory().join("alias");
    fs::hard_link(audit.directory().join("audit.jsonl"), &alias).unwrap();
    alias
}

#[test]
fn health_probe_is_read_only_and_normal_writes_need_no_health_record() {
    let temp = Temp::new();
    let audit = temp.audit();
    assert_eq!(audit.health().state, HealthState::Empty);
    assert!(!audit.directory().exists());
    audit
        .emit_at("api_call", fields(), "2026-01-02T03:04:05Z")
        .unwrap();
    assert!(!audit.directory().join(HEALTH_FILE).exists());
    assert!(audit.take_warning().is_none());
    fs::set_permissions(audit.directory(), fs::Permissions::from_mode(0o755)).unwrap();
    let health = audit.health();
    assert_eq!(health.state, HealthState::Ok);
    assert_eq!(health.folder, FolderState::Mode);
    assert_eq!(
        fs::metadata(audit.directory())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    audit.emit("second", Map::new()).unwrap();
    assert_eq!(audit.health().folder, FolderState::Ok);
}

#[test]
fn folder_refusal_does_not_touch_target_and_recovery_keeps_unknown_loss() {
    let temp = Temp::new();
    let target = temp.0.join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    let audit = temp.audit();
    symlink(&target, audit.directory()).unwrap();
    assert_eq!(
        audit.emit("api_call", fields()),
        Err(LossReason::FolderRefused)
    );
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o755
    );
    fs::remove_file(audit.directory()).unwrap();
    audit.emit("recovered", Map::new()).unwrap();
    assert_eq!(audit.health().state, HealthState::Ok);
    assert_eq!(audit.health().lost, None);
    assert_eq!(audit.health().coverage, Coverage::Unknown);
    let lease = audit
        .take_warning()
        .expect("recovery must not spend warning");
    assert_eq!(lease.as_str(), crate::AUDIT_WARNING);
    drop(lease);
    audit
        .take_warning()
        .expect("failed delivery returns warning")
        .delivered();
    assert!(audit.take_warning().is_none());
}

#[test]
fn counted_refusals_recovery_and_warning_transitions_are_independent() {
    let temp = Temp::new();
    let audit = temp.audit();
    audit.emit("first", Map::new()).unwrap();
    let alias = hardlink_log(&audit);
    let original = fs::read(&alias).unwrap();
    for _ in 0..2 {
        assert_eq!(
            audit.emit("dropped", Map::new()),
            Err(LossReason::FileRefused)
        );
    }
    assert_eq!(fs::read(&alias).unwrap(), original);
    assert_eq!(audit.health().lost, Some(Number::from(2)));
    fs::remove_file(alias).unwrap();
    audit.emit("recovered", Map::new()).unwrap();
    assert_eq!(audit.health().state, HealthState::Ok);
    assert_eq!(audit.health().lost, Some(Number::from(2)));
    let alias = hardlink_log(&audit);
    assert_eq!(
        audit.emit("third_loss", Map::new()),
        Err(LossReason::FileRefused)
    );
    assert_eq!(audit.health().lost, Some(Number::from(3)));
    audit.take_warning().unwrap().delivered();
    audit.take_warning().unwrap().delivered();
    assert!(audit.take_warning().is_none());
    fs::remove_file(alias).unwrap();
}

#[test]
fn unreadable_health_is_replaced_with_unknown_count() {
    let temp = Temp::new();
    let audit = temp.audit();
    audit.emit("first", Map::new()).unwrap();
    fs::write(
        audit.directory().join(HEALTH_FILE),
        br#"{"v":1,"state":"ok","lost":2,"extra":true}"#,
    )
    .unwrap();
    let _alias = hardlink_log(&audit);
    assert_eq!(audit.emit("drop", Map::new()), Err(LossReason::FileRefused));
    let body: Value =
        serde_json::from_slice(&fs::read(audit.directory().join(HEALTH_FILE)).unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"v":1,"state":"refused","reason":"file_refused","lost":null})
    );
    assert_eq!(audit.health().coverage, Coverage::Unknown);
}

#[test]
fn object_shaped_reason_is_untrusted_and_cannot_seed_a_known_count() {
    let temp = Temp::new();
    let audit = temp.audit();
    audit.emit("first", Map::new()).unwrap();
    fs::write(
        audit.directory().join(HEALTH_FILE),
        br#"{"v":1,"state":"refused","reason":{"write_failed":null},"lost":7}"#,
    )
    .unwrap();
    assert_eq!(audit.health().state, HealthState::Ok);
    assert_eq!(audit.health().lost, None);
    assert_eq!(audit.health().coverage, Coverage::Unknown);
    let _alias = hardlink_log(&audit);
    assert_eq!(audit.emit("drop", Map::new()), Err(LossReason::FileRefused));
    assert_eq!(audit.health().lost, None);
    let record: Value =
        serde_json::from_slice(&fs::read(audit.directory().join(HEALTH_FILE)).unwrap()).unwrap();
    assert_eq!(record["lost"], Value::Null);
    assert_eq!(record["reason"], "file_refused");
}

#[test]
fn failed_health_publication_leaves_unkept_mark_and_unknown_after_recovery() {
    let temp = Temp::new();
    let audit = temp.audit();
    audit.emit("first", Map::new()).unwrap();
    fs::create_dir(audit.directory().join(HEALTH_FILE)).unwrap();
    let alias = hardlink_log(&audit);
    assert_eq!(audit.emit("drop", Map::new()), Err(LossReason::FileRefused));
    assert!(audit.directory().join(UNKEPT).exists());
    assert_eq!(audit.health().lost, None);
    fs::remove_dir(audit.directory().join(HEALTH_FILE)).unwrap();
    fs::remove_file(alias).unwrap();
    audit.emit("recovered", Map::new()).unwrap();
    assert!(!audit.directory().join(UNKEPT).exists());
    assert_eq!(audit.health().state, HealthState::Ok);
    assert_eq!(audit.health().lost, None);
}

#[test]
fn loss_count_preserves_arbitrary_precision_python_integers() {
    let temp = Temp::new();
    let audit = temp.audit();
    audit.emit("first", Map::new()).unwrap();
    fs::write(
        audit.directory().join(HEALTH_FILE),
        br#"{"v":1,"state":"ok","lost":999999999999999999999999999999999999999}"#,
    )
    .unwrap();
    let _alias = hardlink_log(&audit);
    assert_eq!(audit.emit("drop", Map::new()), Err(LossReason::FileRefused));
    assert_eq!(
        audit.health().lost.unwrap().to_string(),
        "1000000000000000000000000000000000000000"
    );
}

#[test]
fn health_shape_matches_python_integer_and_version_rules() {
    for text in [
        r#"{"v":true,"state":"ok","lost":null}"#,
        r#"{"v":1.0,"state":"ok","lost":null}"#,
        r#"{"v":1,"state":"ok","lost":-0}"#,
        r#"{"v":1,"state":"refused","lost":12,"reason":"lock_unsupported"}"#,
    ] {
        assert!(
            parse_health(serde_json::from_str(text).unwrap()).is_some(),
            "{text}"
        );
    }
    for text in [
        r#"{"v":1,"state":"ok"}"#,
        r#"{"v":1,"state":"ok","lost":true}"#,
        r#"{"v":1,"state":"ok","lost":1.0}"#,
        r#"{"v":1,"state":"ok","lost":-1}"#,
        r#"{"v":1,"state":"ok","reason":"file_refused"}"#,
        r#"{"v":1,"state":"refused","reason":"secret exception text"}"#,
        r#"{"v":1,"state":"refused","reason":{"write_failed":null}}"#,
        r#"{"v":1,"state":"ok","extra":0}"#,
    ] {
        assert!(
            parse_health(serde_json::from_str(text).unwrap()).is_none(),
            "{text}"
        );
    }
}

#[test]
fn uncertainty_marker_survives_recovery_and_warning_lease_returns_its_kind() {
    let temp = Temp::new();
    let audit = temp.audit();
    audit.emit("first", Map::new()).unwrap();
    let directory = Directory::open(audit.directory(), true).unwrap();
    directory.mark_uncertain().unwrap();
    {
        let mut state = audit.state();
        state.uncertain = true;
        audit.mark_not_kept(&directory, &mut state);
        audit.mark_not_kept(&directory, &mut state);
        audit.record_loss(&mut state, LossReason::WriteFailed);
    }
    let record = audit.take_warning().unwrap();
    assert_eq!(record.warning(), Warning::RecordLost);
    record.delivered();
    let mark = audit.take_warning().unwrap();
    assert_eq!(mark.warning(), Warning::OrderMarkNotKept);
    drop(mark);
    audit.take_warning().unwrap().delivered();
    assert!(audit.take_warning().is_none());
    audit.emit("recovered", Map::new()).unwrap();
    assert!(audit.directory().join(UNCERTAIN).exists());
    assert_eq!(
        Audit::new(audit.directory()).health().order,
        Order::Uncertain
    );
}

#[test]
fn vault_label_is_appended_only_when_event_has_no_label() {
    let temp = Temp::new();
    let audit = temp.audit();
    audit.set_vault_label(Some("work"));
    audit
        .emit_at("first", Map::new(), "2026-01-02T03:04:05Z")
        .unwrap();
    let mut explicit = Map::new();
    explicit.insert("vault".into(), Value::String("explicit".into()));
    audit
        .emit_at("second", explicit, "2026-01-02T03:04:05Z")
        .unwrap();
    let lines = fs::read_to_string(audit.directory().join("audit.jsonl")).unwrap();
    let values: Vec<Value> = lines
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(values[0]["vault"], "work");
    assert_eq!(values[1]["vault"], "explicit");
}

#[test]
fn timestamp_is_sampled_only_after_the_shared_log_lock_is_acquired() {
    use std::sync::atomic::AtomicBool;
    let temp = Temp::new();
    let audit = temp.audit();
    let directory = Directory::open(audit.directory(), true).unwrap();
    let held = directory.lock(LOG_LOCK, LOCK_WAIT).unwrap();
    let released = Arc::new(AtomicBool::new(false));
    let clock_gate = released.clone();
    let (started, ready) = std::sync::mpsc::channel();
    let writer = audit.clone();
    let worker = std::thread::spawn(move || {
        started.send(()).unwrap();
        writer.emit_with(
            "after_wait",
            Map::new(),
            || {
                assert!(
                    clock_gate.load(Ordering::SeqCst),
                    "timestamp sampled before lock release"
                );
                "2026-01-02T03:04:05Z".into()
            },
            || {},
        )
    });
    ready.recv_timeout(Duration::from_secs(1)).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    released.store(true, Ordering::SeqCst);
    drop(held);
    worker.join().unwrap().unwrap();
}

#[test]
fn rust_append_detects_replaced_lock_and_persists_uncertainty() {
    let temp = Temp::new();
    let audit = temp.audit();
    audit.emit("before", Map::new()).unwrap();
    audit
        .emit_with("replaced", Map::new(), utc_timestamp, || {
            fs::rename(
                audit.directory().join(LOG_LOCK),
                audit.directory().join("old-lock"),
            )
            .unwrap();
            fs::write(audit.directory().join(LOG_LOCK), b"").unwrap();
        })
        .unwrap();
    assert!(audit.directory().join(UNCERTAIN).exists());
    assert_eq!(audit.health().order, Order::Uncertain);
    assert_eq!(
        Audit::new(audit.directory()).health().order,
        Order::Uncertain
    );
    assert!(
        audit.take_warning().is_none(),
        "durable mark needs no warning"
    );
}

#[test]
fn failed_uncertainty_mark_warns_once_without_reclassifying_written_record() {
    let temp = Temp::new();
    let audit = temp.audit();
    for _ in 0..2 {
        audit
            .emit_with("removed_folder", Map::new(), utc_timestamp, || {
                // A held descriptor remains valid, but no new marker can be
                // created in this unlinked directory, even by a root test user.
                fs::remove_dir_all(audit.directory()).unwrap();
            })
            .unwrap();
    }
    assert_eq!(audit.health().order, Order::Uncertain);
    assert_eq!(audit.health().reason, None);
    let warning = audit.take_warning().expect("failed durable mark must warn");
    assert_eq!(warning.warning(), Warning::OrderMarkNotKept);
    warning.delivered();
    assert!(audit.take_warning().is_none());
}
