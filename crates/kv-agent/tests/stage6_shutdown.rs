//! Observable shutdown behavior against the pinned Python daemon.
//! Each daemon runs in its own process and HOME; blocking fixtures have bounds.
#![cfg(unix)]

#[path = "../../../tests/support/harness.rs"]
mod harness;

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, LazyLock};
use std::thread;
use std::time::{Duration, Instant};

use kv_agent::{TrustContext, run_agent_with_api_caller};
use kv_broker::{ApiCaller, UrlSafety};
use kv_crypto::{Key32, keyfile};
use kv_store::DrawerStore;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{Value, json};
use url::Url;

const REQUEST_BOUND: Duration = Duration::from_secs(20);
const CLEANUP_BOUND: Duration = Duration::from_secs(5);
const API_SECRET: &str = "shutdown-fixture-secret";

static FIXTURE_KEY: LazyLock<([u8; 32], String)> = LazyLock::new(|| {
    let fixture = fixture_root();
    let expected: Value =
        serde_json::from_slice(&fs::read(fixture.join("vaults/basic.expected.json")).unwrap())
            .unwrap();
    let passphrase = expected["passphrase"].as_str().unwrap().to_owned();
    let blob = fs::read(fixture.join("vaults/basic/.secrets/key")).unwrap();
    let identity = keyfile::unwrap_v4(&blob, passphrase.as_bytes()).unwrap();
    (*identity.master_key.as_bytes(), passphrase)
});

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v0.4.0")
}

fn fixture_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lifecycle.py")
}

struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn wait_until(description: &str, bound: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + bound;
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::metadata(source).unwrap().permissions()).unwrap();
    for item in fs::read_dir(source).unwrap() {
        let item = item.unwrap();
        let target = destination.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_dir(&item.path(), &target);
        } else {
            assert!(item.file_type().unwrap().is_file());
            fs::copy(item.path(), target).unwrap();
        }
    }
}

struct Scenario {
    // Children are dropped before the temporary directory is removed.
    _server: ChildGuard,
    temp: TestDir,
    root: PathBuf,
    home: PathBuf,
    control: PathBuf,
    socket: PathBuf,
    token: PathBuf,
    pid: PathBuf,
}

impl Scenario {
    fn new(python: &OsStr) -> Self {
        let temp = TestDir(harness::socket_temp_dir("s6", "home"));
        let root = temp.0.join("vault");
        let home = temp.0.join("home");
        let control = temp.0.join("control");
        for directory in [&root, &home, &control] {
            fs::create_dir(directory).unwrap();
        }
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "Shutdown fixture CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        server_params.use_authority_key_identifier_extension = true;
        let certificate = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();
        fs::write(temp.0.join("ca.pem"), ca.pem()).unwrap();
        fs::write(temp.0.join("ca.der"), ca.der()).unwrap();
        fs::write(temp.0.join("server.pem"), certificate.pem()).unwrap();
        fs::write(temp.0.join("server.key"), server_key.serialize_pem()).unwrap();
        let log = fs::File::create(temp.0.join("server.log")).unwrap();
        let mut server = ChildGuard(
            Command::new(python)
                .arg("-I")
                .arg(fixture_script())
                .arg("server")
                .arg(temp.0.join("server.pem"))
                .arg(temp.0.join("server.key"))
                .arg(control.join("observed.jsonl"))
                .arg(&control)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        wait_until("HTTPS fixture startup", Duration::from_secs(10), || {
            assert!(
                server.0.try_wait().unwrap().is_none(),
                "HTTPS fixture exited: {}",
                fs::read_to_string(temp.0.join("server.log")).unwrap_or_default()
            );
            control.join("server.port").exists()
        });
        let port: u16 = fs::read_to_string(control.join("server.port"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let base_url = format!("https://127.0.0.1:{port}");

        copy_dir(
            &fixture_root().join("vaults/basic/.secrets"),
            &root.join(".secrets"),
        );
        fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut setup = Command::new(python);
        setup.args(["-I", "-c", "import sys; from kv.vault_origin import record_created; from kv.owner_key import relocate_key_file; record_created(sys.argv[1]); relocate_key_file(sys.argv[1],sys.argv[2])"])
            .arg(&root).arg(&FIXTURE_KEY.1).env("HOME", &home);
        let output = harness::output(setup, &[], Duration::from_secs(180)).unwrap();
        assert!(
            output.status.success(),
            "fixture setup: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config_path = root.join(".secrets/config.json");
        let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config["providers"]["shutdown-local"] = json!({
            "base_url":base_url, "secret_name":"API_TOKEN", "auth_type":"bearer"
        });
        config["broker_policy"]["http"]["shutdown-local"] = json!({
            "origin":base_url, "secret_name":"API_TOKEN",
            "rules":[{"id":"local-read", "methods":["GET"], "path_prefix":"/api", "approval":"none"}]
        });
        fs::write(config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        // Provenance is tied to HOME, so approval belongs in a child with the
        // same private HOME as the daemon rather than changing the test process.
        let mut approve = Command::new(std::env::current_exe().unwrap());
        approve
            .args([
                "--exact",
                "shutdown_daemon_subprocess_helper",
                "--nocapture",
            ])
            .env("KV_SHUTDOWN_SETUP", "1")
            .env("KV_SHUTDOWN_ROOT", &root)
            .env("HOME", &home);
        let output = harness::output(approve, &[], Duration::from_secs(180)).unwrap();
        assert!(
            output.status.success(),
            "fixture approval: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let hash = kv_proto::project_hash(Some(&root)).unwrap();
        let runtime = home.join(".kv");
        let socket = runtime.join(format!("agent-{hash}.sock"));
        let token = runtime.join(format!("agent-{hash}.token"));
        let pid = runtime.join(format!("agent-{hash}.pid"));
        Self {
            _server: server,
            temp,
            root,
            home,
            control,
            socket,
            token,
            pid,
        }
    }

    fn start(&self, python: &OsStr, rust: bool) -> Daemon {
        let mut command = if rust {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "shutdown_daemon_subprocess_helper",
                    "--nocapture",
                ])
                .env("KV_SHUTDOWN_ROOT", &self.root)
                .env("KV_SHUTDOWN_CONTROL", &self.control)
                .env("KV_SHUTDOWN_CA", self.temp.0.join("ca.der"));
            command
        } else {
            let mut command = Command::new(python);
            command
                .arg("-I")
                .arg(fixture_script())
                .arg("daemon")
                .arg(&self.root)
                .arg(&FIXTURE_KEY.1)
                .arg(&self.control);
            command
        };
        let log = self.temp.0.join("daemon.log");
        let mut daemon = Daemon {
            child: ChildGuard(
                command
                    .env("HOME", &self.home)
                    .env("SSL_CERT_FILE", self.temp.0.join("ca.pem"))
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(fs::File::create(&log).unwrap())
                    .spawn()
                    .unwrap(),
            ),
            log,
        };
        wait_until("daemon socket", Duration::from_secs(30), || {
            assert!(
                daemon.child.0.try_wait().unwrap().is_none(),
                "daemon exited during startup: {}",
                daemon.log()
            );
            self.socket.exists()
        });
        assert!(self.request("status", json!({})).get("error").is_none());
        daemon
    }

    fn send(&self, command: &str, fields: Value) -> UnixStream {
        let mut fields = fields.as_object().unwrap().clone();
        fields.insert("cmd".into(), json!(command));
        fields.insert(
            "token".into(),
            json!(fs::read_to_string(&self.token).unwrap().trim()),
        );
        fields.entry("audit_warning").or_insert(json!(false));
        let mut socket = UnixStream::connect(&self.socket).unwrap();
        socket.set_write_timeout(Some(REQUEST_BOUND)).unwrap();
        socket.set_read_timeout(Some(REQUEST_BOUND)).unwrap();
        socket
            .write_all(&serde_json::to_vec(&fields).unwrap())
            .unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        socket
    }

    fn request(&self, command: &str, fields: Value) -> Value {
        read_reply(&mut self.send(command, fields))
    }

    fn api(&self, path: &str) -> UnixStream {
        self.send(
            "api",
            json!({"provider":"shutdown-local", "path":path, "method":"GET"}),
        )
    }

    fn observed(&self) -> Vec<Value> {
        fs::read_to_string(self.control.join("observed.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn wait_observed(&self, count: usize, request: &mut UnixStream) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.observed().len() < count {
            if Instant::now() >= deadline {
                request
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                let mut reply = Vec::new();
                let read = request.read_to_end(&mut reply);
                panic!(
                    "provider request did not arrive: {read:?}, reply={}, daemon={}, server={}",
                    String::from_utf8_lossy(&reply),
                    fs::read_to_string(self.temp.0.join("daemon.log")).unwrap_or_default(),
                    fs::read_to_string(self.temp.0.join("server.log")).unwrap_or_default()
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(self.observed().len(), count);
    }

    fn release(&self, name: &str) {
        fs::write(self.control.join(name), b"release").unwrap();
    }

    fn assert_cleaned(&self) {
        for path in [&self.socket, &self.token, &self.pid] {
            assert!(!path.exists(), "runtime file remains: {}", path.display());
        }
    }
}

struct Daemon {
    child: ChildGuard,
    log: PathBuf,
}

impl Daemon {
    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn wait_success(&mut self, bound: Duration) {
        let deadline = Instant::now() + bound;
        loop {
            if let Some(status) = self.child.0.try_wait().unwrap() {
                assert!(status.success(), "daemon exited {status}: {}", self.log());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not exit within {bound:?}: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn read_reply(socket: &mut UnixStream) -> Value {
    let mut reply = Vec::new();
    socket
        .read_to_end(&mut reply)
        .expect("bounded daemon reply read");
    serde_json::from_slice(&reply).unwrap_or_else(|error| {
        panic!(
            "invalid daemon reply {error}: {}",
            String::from_utf8_lossy(&reply)
        )
    })
}

fn assert_reply_pending(socket: &mut UnixStream) {
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let result = socket.read(&mut [0]);
    assert!(
        matches!(result, Err(ref error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)),
        "stop replied before committed work drained: {result:?}"
    );
    socket.set_read_timeout(Some(REQUEST_BOUND)).unwrap();
}

struct GatedSafety(PathBuf);

impl UrlSafety for GatedSafety {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        if url.host_str() != Some("127.0.0.1") {
            return Err("shutdown fixture only permits localhost".into());
        }
        if url.path().contains("/api/pending") {
            fs::write(self.0.join("safety.entered"), b"entered").unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !self.0.join("safety.release").exists() {
                if Instant::now() >= deadline {
                    return Err("shutdown fixture safety check timed out".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            fs::write(self.0.join("safety.returned"), b"returned").unwrap();
        }
        Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}

#[test]
fn shutdown_daemon_subprocess_helper() {
    let Some(root) = std::env::var_os("KV_SHUTDOWN_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    if std::env::var_os("KV_SHUTDOWN_SETUP").as_deref() == Some(OsStr::new("1")) {
        kv_store::config_authority::approve_config_unattended(&root, &Key32::new(FIXTURE_KEY.0))
            .unwrap();
        DrawerStore::open(root.join(".secrets"), Key32::new(FIXTURE_KEY.0))
            .set_secret("dev", "API_TOKEN", API_SECRET, 1)
            .unwrap();
        return;
    }
    let control = PathBuf::from(std::env::var_os("KV_SHUTDOWN_CONTROL").unwrap());
    let ca = fs::read(std::env::var_os("KV_SHUTDOWN_CA").unwrap()).unwrap();
    let master = Key32::new(FIXTURE_KEY.0);
    let store = Arc::new(DrawerStore::open(
        root.join(".secrets"),
        Key32::new(FIXTURE_KEY.0),
    ));
    let trust = TrustContext::at_unlock(&root, Some(FIXTURE_KEY.1.as_bytes()), &master).unwrap();
    let caller = ApiCaller::with_test_ca_for_test(Arc::new(GatedSafety(control)), &ca).unwrap();
    run_agent_with_api_caller(root, store, master, trust, Arc::new(caller)).unwrap();
}

#[test]
fn invalid_stop_choices_and_idle_client_cleanup_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let idle = UnixStream::connect(&scenario.socket).unwrap();
        let mut partial = UnixStream::connect(&scenario.socket).unwrap();
        partial.write_all(b"{\"cmd\":").unwrap();
        let mut invalid = Vec::new();
        for choice in [json!(7), json!(false), json!([]), json!({}), json!("later")] {
            let reply = scenario.request("stop", json!({"choice":choice}));
            assert!(
                reply.get("error").is_some(),
                "invalid choice stopped daemon: {reply}"
            );
            assert!(scenario.request("status", json!({})).get("error").is_none());
            invalid.push(reply);
        }
        let started = Instant::now();
        let stop = scenario.request("stop", json!({}));
        daemon.wait_success(CLEANUP_BOUND);
        assert!(
            started.elapsed() < CLEANUP_BOUND,
            "idle sockets delayed shutdown"
        );
        scenario.assert_cleaned();
        drop((idle, partial));
        results.push(json!({"invalid":invalid,"stop":stop}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn stop_wait_drains_provider_and_refuses_new_dispatch_like_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let mut held = scenario.api("/api/hold");
        scenario.wait_observed(1, &mut held);
        let first = scenario.request("stop", json!({}));
        assert_eq!(
            first,
            json!({"in_flight":1,"awaiting_choice":true,"runs":[]})
        );
        let status = scenario.request("status", json!({}));
        let refused = read_reply(&mut scenario.api("/api/new"));
        assert_eq!(status["error_code"], "agent_stopping");
        assert_eq!(refused["error_code"], "agent_stopping");
        let repeated = scenario.request("stop", json!({}));
        assert_eq!(repeated, first);
        let mut stop = scenario.send("stop", json!({"choice":"wait"}));
        assert_reply_pending(&mut stop);
        scenario.release("provider.release");
        let stopped = read_reply(&mut stop);
        assert_eq!(
            stopped,
            json!({"stopping":true,"wait_seconds":135,"cut_off":0,"ended_runs":[]})
        );
        let api_reply = read_reply(&mut held);
        daemon.wait_success(CLEANUP_BOUND);
        scenario.assert_cleaned();
        assert_eq!(
            scenario.observed().len(),
            1,
            "new dispatch reached provider while stopping"
        );
        results.push(json!({"first":first,"repeated":repeated,"status":status,"refused":refused,"stopped":stopped,"api":api_reply}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn stop_now_cuts_off_provider_with_one_short_budget_like_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let mut held = scenario.api("/api/hold");
        scenario.wait_observed(1, &mut held);
        let first = scenario.request("stop", json!({}));
        assert_eq!(first["awaiting_choice"], true);
        let started = Instant::now();
        let stopped = scenario.request("stop", json!({"choice":"now"}));
        assert_eq!(
            stopped,
            json!({"stopping":true,"wait_seconds":10,"cut_off":1,"ended_runs":[]})
        );
        daemon.wait_success(CLEANUP_BOUND);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(9),
            "committed work was cut off before its budget: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "short stop budget was exceeded: {elapsed:?}"
        );
        scenario.assert_cleaned();
        assert_eq!(scenario.observed().len(), 1);
        drop(held);
        results.push(json!({"first":first,"stopped":stopped}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn pending_provider_safety_check_cannot_send_after_stop_like_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let mut held = scenario.api("/api/hold");
        scenario.wait_observed(1, &mut held);
        let mut pending = scenario.api("/api/pending");
        wait_until("pending URL safety check", Duration::from_secs(10), || {
            scenario.control.join("safety.entered").exists()
        });
        let first = scenario.request("stop", json!({}));
        assert_eq!(
            first,
            json!({"in_flight":1,"awaiting_choice":true,"runs":[]})
        );
        scenario.release("safety.release");
        wait_until("released URL safety check", Duration::from_secs(10), || {
            scenario.control.join("safety.returned").exists()
        });
        assert_eq!(
            scenario.observed().len(),
            1,
            "pending safety check sent after stop"
        );
        let mut stop = scenario.send("stop", json!({"choice":"wait"}));
        scenario.release("provider.release");
        let stopped = read_reply(&mut stop);
        let refused = read_reply(&mut pending);
        assert!(
            refused.get("error").is_some(),
            "pending operation succeeded after stop: {refused}"
        );
        let api_reply = read_reply(&mut held);
        daemon.wait_success(CLEANUP_BOUND);
        scenario.assert_cleaned();
        assert_eq!(scenario.observed().len(), 1);
        results.push(json!({"first":first,"refused":refused,"stopped":stopped,"api":api_reply}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn sigterm_with_idle_clients_cleans_runtime_within_bound_like_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let idle = UnixStream::connect(&scenario.socket).unwrap();
        let mut partial = UnixStream::connect(&scenario.socket).unwrap();
        partial.write_all(b"{\"cmd\":").unwrap();
        assert!(scenario.request("status", json!({})).get("error").is_none());
        let started = Instant::now();
        rustix::process::kill_process(
            rustix::process::Pid::from_child(&daemon.child.0),
            rustix::process::Signal::TERM,
        )
        .unwrap();
        daemon.wait_success(CLEANUP_BOUND);
        assert!(started.elapsed() < CLEANUP_BOUND);
        scenario.assert_cleaned();
        drop((idle, partial));
    }
}

#[test]
fn daemon_audit_refusal_warns_only_opted_in_replies_like_python() {
    use std::os::unix::fs::symlink;

    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let log = scenario.home.join(".kv/audit.jsonl");
        if log.exists() {
            fs::remove_file(&log).unwrap();
        }
        let sentinel = scenario.temp.0.join("unrelated-file");
        fs::write(&sentinel, "unchanged").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&sentinel, &log).unwrap();
        let call = |warning| {
            scenario.request(
                "api",
                json!({
                    "provider":"shutdown-local", "path":"/api/probe", "method":"GET",
                    "audit_warning":warning
                }),
            )
        };

        let first = call(false);
        assert_eq!(
            first["status"], 200,
            "audit failure changed provider result: {first}"
        );
        assert!(first.get("audit_warning").is_none());
        assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
        assert_eq!(
            fs::metadata(&sentinel).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let mut warnings = Vec::new();
        for flag in [
            json!(false),
            json!("true"),
            json!(1),
            json!(true),
            json!(true),
        ] {
            let answer = scenario.request("status", json!({"audit_warning":flag}));
            warnings.push(answer.get("audit_warning").cloned().unwrap_or(Value::Null));
        }
        assert_eq!(&warnings[..3], &[Value::Null, Value::Null, Value::Null]);
        assert!(warnings[3].as_str().is_some());
        assert!(warnings[4].is_null());

        fs::remove_file(&log).unwrap();
        let recovered = call(true);
        assert_eq!(recovered["status"], 200);
        assert!(recovered.get("audit_warning").is_none());
        fs::remove_file(&log).unwrap();
        fs::create_dir(&log).unwrap();
        let failed_again = call(true);
        assert_eq!(failed_again["status"], 200);
        assert_eq!(failed_again["audit_warning"], warnings[3]);
        let health: Value =
            serde_json::from_slice(&fs::read(scenario.home.join(".kv/audit-health.json")).unwrap())
                .unwrap();
        assert_eq!(health["state"], "refused");
        assert_eq!(health["lost"], 2);
        assert_eq!(health["reason"], "file_refused");
        assert_eq!(scenario.observed().len(), 3);
        scenario.request("stop", json!({}));
        daemon.wait_success(CLEANUP_BOUND);
        scenario.assert_cleaned();
        results.push(json!({"warnings":warnings,"health":health,"warning_again":failed_again["audit_warning"]}));
    }
    assert_eq!(results[0], results[1]);
}
