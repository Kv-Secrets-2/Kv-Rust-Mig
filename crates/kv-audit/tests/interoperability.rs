#![cfg(unix)]

#[path = "../../../tests/support/harness.rs"]
mod harness;

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use kv_audit::{AUDIT_WARNING, Audit, LossReason};
use serde_json::{Map, Value, json};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        Self(harness::socket_temp_dir("audit", ""))
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_dir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn python_command(python: &OsStr, directory: &Path, mode: &str) -> Command {
    let mut command = Command::new(python);
    command
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/audit_reference.py"))
        .arg(directory)
        .arg(mode);
    command
}

fn python_json(command: Command) -> Value {
    let output = harness::output(command, b"", Duration::from_secs(30)).unwrap();
    assert!(
        output.status.success(),
        "Python audit fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

struct PythonProcess {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
    deadline: Instant,
}

struct RustWriter(Option<thread::JoinHandle<()>>);

impl RustWriter {
    fn join(mut self) {
        self.0.take().unwrap().join().unwrap();
    }
}

impl Drop for RustWriter {
    fn drop(&mut self) {
        // Do not let an assertion leave a producer writing after Temp removes
        // its directory. Production lock acquisition remains bounded at 2s.
        if let Some(worker) = self.0.take() {
            let _ = worker.join();
        }
    }
}

impl PythonProcess {
    fn start(mut command: Command, directory: &Path, name: &str) -> Self {
        let stdout = directory.join(format!("{name}.stdout"));
        let stderr = directory.join(format!("{name}.stderr"));
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(File::create(&stdout).unwrap()))
            .stderr(Stdio::from(File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        Self {
            child,
            stdout,
            stderr,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    fn wait_for(&mut self, gate: &Path) {
        while !gate.exists() {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "Python fixture exited before its gate: {}",
                fs::read_to_string(&self.stderr).unwrap()
            );
            assert!(
                Instant::now() < self.deadline,
                "Python fixture did not reach its gate"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn finish(mut self) -> Value {
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < self.deadline,
                "Python fixture exceeded its deadline"
            );
            thread::sleep(Duration::from_millis(5));
        };
        assert!(
            status.success(),
            "Python audit fixture: {}",
            fs::read_to_string(&self.stderr).unwrap()
        );
        serde_json::from_slice(&fs::read(&self.stdout).unwrap()).unwrap()
    }
}

impl Drop for PythonProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn fields(writer: &str, seq: usize) -> Map<String, Value> {
    json!({"writer":writer,"seq":seq})
        .as_object()
        .unwrap()
        .clone()
}

fn health(audit: &Audit) -> Value {
    serde_json::to_value(audit.health()).unwrap()
}

fn snapshot(python: &OsStr, directory: &Path) -> Value {
    python_json(python_command(python, directory, "snapshot"))
}

fn take_delivered(audit: &Audit) -> Value {
    audit.take_warning().map_or(Value::Null, |warning| {
        let text = Value::String(warning.as_str().to_owned());
        warning.delivered();
        text
    })
}

fn outcome(result: Result<(), LossReason>) -> Value {
    result
        .err()
        .map_or(Value::Null, |reason| serde_json::to_value(reason).unwrap())
}

#[test]
fn alternating_and_concurrent_writers_match_python_chain_and_exact_counts() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let temp = Temp::new();
    let directory = temp.0.join("audit");
    let audit = Audit::new(&directory);
    audit.emit("interop", fields("rust", 0)).unwrap();
    let mut command = python_command(&python, &directory, "emit");
    command.arg(json!(["interop", fields("python", 0)]).to_string());
    assert_eq!(python_json(command)["outcome"], Value::Null);
    audit.emit("interop", fields("rust", 1)).unwrap();

    const COUNT: usize = 80;
    let ready = temp.0.join("ready");
    let release = temp.0.join("release");
    let mut command = python_command(&python, &directory, "writer");
    command.arg(&ready).arg(&release).arg(COUNT.to_string());
    let mut process = PythonProcess::start(command, &temp.0, "writer");
    process.wait_for(&ready);
    let (started_tx, started_rx) = mpsc::channel();
    let (first_tx, first_rx) = mpsc::channel();
    let writer = audit.clone();
    let worker = RustWriter(Some(thread::spawn(move || {
        started_tx.send(()).unwrap();
        let first = writer.emit("interop", fields("rust", 2));
        first_tx.send(first).unwrap();
        for seq in 3..COUNT + 2 {
            writer.emit("interop", fields("rust", seq)).unwrap();
        }
    })));
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // Python is paused inside its real append while it holds audit.lock. A
    // writer that does not share that lock would finish before this release.
    let premature = first_rx.recv_timeout(Duration::from_millis(100));
    fs::write(&release, b"go").unwrap();
    let first = match premature {
        Err(mpsc::RecvTimeoutError::Timeout) => {
            first_rx.recv_timeout(Duration::from_secs(10)).unwrap()
        }
        other => {
            worker.join();
            let _ = process.finish();
            panic!("Rust append bypassed Python's held audit lock: {other:?}");
        }
    };
    first.unwrap();
    worker.join();
    let python_writer = process.finish();
    assert_eq!(python_writer["outcomes"], json!(vec![Value::Null; COUNT]));

    let records: Vec<Value> = fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2 * COUNT + 3);
    let actual: BTreeSet<_> = records
        .iter()
        .map(|record| {
            assert_eq!(record["event"], "interop");
            (
                record["writer"].as_str().unwrap().to_owned(),
                record["seq"].as_u64().unwrap() as usize,
            )
        })
        .collect();
    let expected: BTreeSet<_> = (0..COUNT + 2)
        .map(|seq| ("rust".to_owned(), seq))
        .chain((0..COUNT + 1).map(|seq| ("python".to_owned(), seq)))
        .collect();
    assert_eq!(actual, expected);
    let reference = snapshot(&python, &directory);
    assert_eq!(
        reference["chain"],
        json!([true, format!("{} entries", 2 * COUNT + 3)])
    );
    assert_eq!(health(&audit), reference["health"]);
    assert_eq!(health(&audit)["lost"], 0);
    assert!(!directory.join("audit.uncertain").exists());
}

#[test]
fn overflow_float_records_remain_chain_compatible_with_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let temp = Temp::new();
    let directory = temp.0.join("audit");
    let audit = Audit::new(&directory);
    let mut metadata = Map::new();
    metadata.insert("overflow".into(), serde_json::from_str("1e999").unwrap());
    audit.emit("rust_overflow", metadata).unwrap();
    let first = fs::read_to_string(directory.join("audit.jsonl")).unwrap();
    assert!(
        first.contains("\"overflow\":Infinity"),
        "overflow was not serialized with Python's float semantics: {first}"
    );

    // The tail reader must recover the previous hash even though strict JSON
    // parsing rejects Infinity. Otherwise this second append resets the chain.
    audit.emit("rust_after_overflow", Map::new()).unwrap();
    let mut command = python_command(&python, &directory, "emit");
    command.arg(json!(["python_after_rust", {}]).to_string());
    let reference = python_json(command);
    assert_eq!(reference["outcome"], Value::Null);
    assert_eq!(reference["chain"], json!([true, "3 entries"]));
    assert_eq!(health(&audit), reference["health"]);
    assert_eq!(
        fs::read_to_string(directory.join("audit.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
}

#[test]
fn python_log_lock_causes_bounded_drop_warning_and_recovery() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let temp = Temp::new();
    let directory = temp.0.join("audit");
    let audit = Audit::new(&directory);
    audit.emit("before", Map::new()).unwrap();
    let original = fs::read(directory.join("audit.jsonl")).unwrap();
    let ready = temp.0.join("ready");
    let release = temp.0.join("release");
    let mut command = python_command(&python, &directory, "hold");
    command.arg("audit.lock").arg(&ready).arg(&release);
    let mut holder = PythonProcess::start(command, &temp.0, "holder");
    holder.wait_for(&ready);
    let start = Instant::now();
    assert_eq!(
        audit.emit("dropped", Map::new()),
        Err(LossReason::LockUnavailable)
    );
    assert!(start.elapsed() >= Duration::from_millis(1900));
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_eq!(fs::read(directory.join("audit.jsonl")).unwrap(), original);
    assert_eq!(health(&audit), snapshot(&python, &directory)["health"]);
    assert_eq!(health(&audit)["lost"], 1);
    assert_eq!(take_delivered(&audit), AUDIT_WARNING);
    assert_eq!(take_delivered(&audit), Value::Null);
    fs::write(&release, b"go").unwrap();
    assert_eq!(holder.finish(), json!({"released":true}));
    audit.emit("recovered", Map::new()).unwrap();
    let reference = snapshot(&python, &directory);
    assert_eq!(reference["chain"], json!([true, "2 entries"]));
    assert_eq!(health(&audit), reference["health"]);
    assert_eq!(health(&audit)["state"], "ok");
    assert_eq!(health(&audit)["lost"], 1);
}

#[test]
fn python_health_lock_preserves_unknown_loss_through_recovery() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let temp = Temp::new();
    let directory = temp.0.join("audit");
    private_dir(&directory);
    let victim = temp.0.join("victim");
    fs::write(&victim, b"untouched").unwrap();
    symlink(&victim, directory.join("audit.jsonl")).unwrap();
    let audit = Audit::new(&directory);
    let ready = temp.0.join("ready");
    let release = temp.0.join("release");
    let mut command = python_command(&python, &directory, "hold");
    command.arg("audit-health.lock").arg(&ready).arg(&release);
    let mut holder = PythonProcess::start(command, &temp.0, "holder");
    holder.wait_for(&ready);
    let start = Instant::now();
    assert_eq!(
        audit.emit("dropped", Map::new()),
        Err(LossReason::FileRefused)
    );
    assert!(start.elapsed() >= Duration::from_millis(1900));
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    assert!(directory.join("audit-health.unkept").exists());
    assert_eq!(health(&audit), snapshot(&python, &directory)["health"]);
    assert_eq!(health(&audit)["lost"], Value::Null);
    assert_eq!(health(&audit)["coverage"], "unknown");
    fs::write(&release, b"go").unwrap();
    holder.finish();
    fs::remove_file(directory.join("audit.jsonl")).unwrap();
    audit.emit("recovered", Map::new()).unwrap();
    let reference = snapshot(&python, &directory);
    assert_eq!(health(&audit), reference["health"]);
    assert_eq!(health(&audit)["state"], "ok");
    assert_eq!(health(&audit)["lost"], Value::Null);
    assert_eq!(health(&audit)["coverage"], "unknown");
    assert!(!directory.join("audit-health.unkept").exists());
    assert_eq!(reference["chain"], json!([true, "1 entries"]));
}

#[test]
fn refusal_recovery_health_and_warning_leases_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let rust_temp = Temp::new();
    let python_temp = Temp::new();
    let directory = rust_temp.0.join("audit");
    let audit = Audit::new(&directory);
    let mut states = vec![health(&audit)];
    private_dir(&directory);
    let victim = rust_temp.0.join("victim");
    fs::write(&victim, b"untouched").unwrap();
    let log = directory.join("audit.jsonl");
    symlink(&victim, &log).unwrap();
    let mut outcomes = Vec::new();
    for _ in 0..2 {
        outcomes.push(outcome(audit.emit("refused", Map::new())));
        states.push(health(&audit));
    }
    let warning = audit.take_warning().unwrap();
    let mut warnings = vec![Value::String(warning.as_str().to_owned())];
    drop(warning); // An unsent warning must return to the pending queue.
    warnings.push(take_delivered(&audit));
    warnings.push(take_delivered(&audit));
    fs::remove_file(&log).unwrap();
    outcomes.push(outcome(audit.emit("recovered", Map::new())));
    states.push(health(&audit));
    warnings.push(take_delivered(&audit));
    fs::remove_file(&log).unwrap();
    symlink(&victim, &log).unwrap();
    outcomes.push(outcome(audit.emit("refused_again", Map::new())));
    states.push(health(&audit));
    fs::remove_file(&log).unwrap();
    outcomes.push(outcome(audit.emit("recovered_before_warning", Map::new())));
    states.push(health(&audit));
    warnings.push(take_delivered(&audit));
    warnings.push(take_delivered(&audit));
    let actual = json!({"health":states,"outcomes":outcomes,"warnings":warnings,"victim":fs::read_to_string(victim).unwrap()});
    let expected = python_json(python_command(
        &python,
        &python_temp.0.join("audit"),
        "fault_recovery",
    ));
    assert_eq!(actual, expected);
    assert_eq!(actual["health"][4]["lost"], 3);
    assert_eq!(
        actual["outcomes"],
        json!(["file_refused", "file_refused", null, "file_refused", null])
    );
    assert_eq!(
        actual["warnings"],
        json!([
            AUDIT_WARNING,
            AUDIT_WARNING,
            null,
            null,
            AUDIT_WARNING,
            null
        ])
    );
}

#[test]
fn persisted_health_validation_and_loss_updates_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let huge = "9".repeat(200);
    let huge_next = serde_json::from_str::<Value>(&format!("1{}", "0".repeat(200))).unwrap();
    // A missing `lost` field is deliberately outside this differential table:
    // reference 9a497d91 accepts it in _health_record_valid, then audit_health
    // raises KeyError at kv/audit.py:1506. The regression below pins that bug
    // separately and checks the approved Rust behavior for untrusted health.
    let cases = [
        (
            "object_reason",
            r#"{"v":1,"state":"refused","reason":{"write_failed":null},"lost":7}"#.to_owned(),
            "file",
            Value::Null,
        ),
        (
            "boolean_loss",
            r#"{"v":1,"state":"ok","lost":true}"#.to_owned(),
            "file",
            Value::Null,
        ),
        (
            "floating_loss",
            r#"{"v":1,"state":"ok","lost":1.0}"#.to_owned(),
            "file",
            Value::Null,
        ),
        (
            "negative_loss",
            r#"{"v":1,"state":"ok","lost":-1}"#.to_owned(),
            "file",
            Value::Null,
        ),
        (
            "huge_loss",
            format!(r#"{{"v":1,"state":"ok","lost":{huge}}}"#),
            "file",
            huge_next,
        ),
        (
            "boolean_version",
            r#"{"v":true,"state":"ok","lost":7}"#.to_owned(),
            "file",
            json!(8),
        ),
        (
            "floating_version",
            r#"{"v":1.0,"state":"ok","lost":7}"#.to_owned(),
            "file",
            json!(8),
        ),
        (
            "oversized_body",
            format!(r#"{{"v":1,"state":"ok","lost":7}}{}"#, " ".repeat(4096)),
            "file",
            Value::Null,
        ),
        (
            "hardlink",
            r#"{"v":1,"state":"ok","lost":7}"#.to_owned(),
            "hardlink",
            Value::Null,
        ),
        (
            "symlink",
            r#"{"v":1,"state":"ok","lost":7}"#.to_owned(),
            "symlink",
            Value::Null,
        ),
    ];
    for (name, body, kind, next_loss) in cases {
        let rust_temp = Temp::new();
        let python_temp = Temp::new();
        for base in [&rust_temp.0, &python_temp.0] {
            let directory = base.join("audit");
            private_dir(&directory);
            let health_path = directory.join("audit-health.json");
            let source = if kind == "file" {
                health_path.clone()
            } else {
                base.join("health-source")
            };
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&source)
                .unwrap();
            std::io::Write::write_all(&mut file, body.as_bytes()).unwrap();
            match kind {
                "hardlink" => fs::hard_link(&source, &health_path).unwrap(),
                "symlink" => symlink(&source, &health_path).unwrap(),
                "file" => {}
                _ => unreachable!(),
            }
        }
        let directory = rust_temp.0.join("audit");
        let health_path = directory.join("audit-health.json");
        let audit = Audit::new(&directory);
        let original = fs::symlink_metadata(&health_path).unwrap();
        let before = health(&audit);
        let probed = fs::symlink_metadata(&health_path).unwrap();
        assert_eq!(
            fs::read_to_string(&health_path).unwrap(),
            body,
            "probe changed {name} bytes"
        );
        assert_eq!(
            (original.ino(), original.mode(), original.nlink()),
            (probed.ino(), probed.mode(), probed.nlink()),
            "probe changed {name} metadata"
        );
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            1,
            "probe created files for {name}"
        );
        let victim = rust_temp.0.join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, directory.join("audit.jsonl")).unwrap();
        let refused = outcome(audit.emit("refused", Map::new()));
        let record: Value = serde_json::from_slice(&fs::read(&health_path).unwrap()).unwrap();
        let source = rust_temp.0.join("health-source");
        let actual = json!({
            "before":before,"outcome":refused,"after":health(&audit),"record":record,
            "victim":fs::read_to_string(&victim).unwrap(),
            "source":if source.exists() { Some(fs::read_to_string(&source).unwrap()) } else { None },
        });
        let expected = python_json(python_command(
            &python,
            &python_temp.0.join("audit"),
            "health_validation",
        ));
        assert_eq!(actual, expected, "health record case {name}");
        assert_eq!(actual["outcome"], "file_refused", "{name}");
        assert_eq!(actual["record"]["lost"], next_loss, "{name}");
        assert_eq!(actual["victim"], "untouched", "{name}");
        if kind != "file" {
            assert_eq!(
                actual["source"], body,
                "health publication modified linked source in {name}"
            );
        }
    }
}

#[test]
fn missing_lost_health_is_untrusted_despite_python_reference_exception() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let temp = Temp::new();
    let directory = temp.0.join("audit");
    Audit::new(&directory).emit("before", Map::new()).unwrap();
    let health_path = directory.join("audit-health.json");
    let original = b"{\"v\":1,\"state\":\"ok\"}\n";
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&health_path)
        .unwrap();
    std::io::Write::write_all(&mut file, original).unwrap();
    drop(file);
    let metadata = fs::symlink_metadata(&health_path).unwrap();
    let log_before = fs::read(directory.join("audit.jsonl")).unwrap();
    let reference = python_json(python_command(&python, &directory, "missing_loss_bug"));
    assert_eq!(
        reference,
        json!({"validator_accepted":true,"exception":{"type":"KeyError","args":["lost"]}})
    );

    // Explicitly approved deviation: corrupt health cannot crash its reader
    // or become a trustworthy count merely because Python validates its shape.
    let audit = Audit::new(&directory);
    assert_eq!(
        health(&audit),
        json!({
            "state":"ok","reason":null,"lost":null,"coverage":"unknown",
            "order":"serialized","folder":"ok",
        })
    );
    let probed = fs::symlink_metadata(&health_path).unwrap();
    assert_eq!(fs::read(&health_path).unwrap(), original);
    assert_eq!(
        (metadata.ino(), metadata.mode(), metadata.nlink()),
        (probed.ino(), probed.mode(), probed.nlink())
    );
    assert_eq!(fs::read(directory.join("audit.jsonl")).unwrap(), log_before);

    let victim = temp.0.join("victim");
    fs::write(&victim, b"untouched").unwrap();
    fs::remove_file(directory.join("audit.jsonl")).unwrap();
    symlink(&victim, directory.join("audit.jsonl")).unwrap();
    assert_eq!(
        audit.emit("refused", Map::new()),
        Err(LossReason::FileRefused)
    );
    let record: Value = serde_json::from_slice(&fs::read(&health_path).unwrap()).unwrap();
    assert_eq!(
        record,
        json!({"v":1,"state":"refused","reason":"file_refused","lost":null})
    );
    assert_eq!(health(&audit)["coverage"], "unknown");
    assert_eq!(health(&audit)["lost"], Value::Null);
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
}

#[test]
fn python_lock_replacement_marks_order_uncertain_for_fresh_rust_readers() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let temp = Temp::new();
    let directory = temp.0.join("audit");
    let audit = Audit::new(&directory);
    audit.emit("before", Map::new()).unwrap();
    let ready = temp.0.join("ready");
    let release = temp.0.join("release");
    let mut command = python_command(&python, &directory, "paused_append");
    command.arg(&ready).arg(&release);
    let mut process = PythonProcess::start(command, &temp.0, "paused");
    process.wait_for(&ready);
    fs::rename(
        directory.join("audit.lock"),
        directory.join("audit.lock.old"),
    )
    .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("audit.lock"))
        .unwrap();
    audit.emit("replacement_holder", Map::new()).unwrap();
    fs::write(&release, b"go").unwrap();
    let writer = process.finish();
    assert_eq!(writer["outcomes"], json!([null]));
    assert!(directory.join("audit.uncertain").exists());
    // Both writers legitimately held different lock inodes. Python computed
    // its predecessor before Rust's intervening append: that order is broken,
    // and both old and fresh Rust readers must expose the durable uncertainty.
    let reference = snapshot(&python, &directory);
    assert_eq!(reference["chain"][0], false);
    assert_eq!(reference["health"]["order"], "uncertain");
    assert_eq!(health(&audit), reference["health"]);
    assert_eq!(health(&Audit::new(&directory)), reference["health"]);
    assert_eq!(
        fs::read_to_string(directory.join("audit.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
}
