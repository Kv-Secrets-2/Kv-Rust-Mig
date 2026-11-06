//! Full-daemon one-call permits, approved by the pinned Python owner client.
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
use sha2::{Digest, Sha256};
use url::Url;

const REQUEST_BOUND: Duration = Duration::from_secs(20);
const CLEANUP_BOUND: Duration = Duration::from_secs(5);
const API_SECRET: &str = "permit-fixture-secret";
const HOST: &str = "permit-fixture.example";
const BODY: &str = "{\"message\": \"permit-body-unique-π\", \"count\": 1}";

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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/permits.py")
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
    unprotected: bool,
}

impl Scenario {
    fn new(python: &OsStr) -> Self {
        Self::with_options(python, "local-convenience", false)
    }

    fn with_options(python: &OsStr, approval_mode: &str, unprotected: bool) -> Self {
        let temp = TestDir(harness::socket_temp_dir("p5", "home"));
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
            .push(DnType::OrganizationName, "Permit fixture CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec![HOST.into()]).unwrap();
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
        let base_url = format!("https://{HOST}:{port}");

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
        for (name, auth) in [
            ("permit-local", "bearer"),
            ("permit-other", "bearer"),
            ("permit-query", "query"),
            ("permit-missing", "bearer"),
        ] {
            let secret_name = if name == "permit-missing" {
                "ABSENT_PERMIT_SECRET"
            } else {
                "API_TOKEN"
            };
            config["providers"][name] = json!({
                "base_url":base_url, "secret_name":secret_name, "auth_type":auth
            });
            config["broker_policy"]["http"][name] = json!({
                "origin":base_url, "secret_name":secret_name,
                "rules":[{"id":"local-write", "methods":["POST","PUT","PATCH","DELETE"], "path_prefix":"/api", "approval":"per-call",
                    "allowed_headers":["X-Request-Label"], "allow_query":true, "query_keys":["batch","extra"]}]
            });
        }
        config["security"]["approval_mode"] = json!(approval_mode);
        fs::write(config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        // Provenance is tied to HOME, so approval belongs in a child with the
        // same private HOME as the daemon rather than changing the test process.
        let mut approve = Command::new(std::env::current_exe().unwrap());
        approve
            .args(["--exact", "permit_daemon_subprocess_helper", "--nocapture"])
            .env("KV_PERMIT_SETUP", "1")
            .env("KV_PERMIT_ROOT", &root)
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
            unprotected,
        }
    }

    fn start(&self, python: &OsStr, rust: bool) -> Daemon {
        let mut command = if rust {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "permit_daemon_subprocess_helper", "--nocapture"])
                .env("KV_PERMIT_ROOT", &self.root)
                .env(
                    "KV_PERMIT_UNPROTECTED",
                    if self.unprotected { "1" } else { "0" },
                )
                .env("KV_PERMIT_CONTROL", &self.control)
                .env("KV_PERMIT_CA", self.temp.0.join("ca.der"));
            command
        } else {
            let mut command = Command::new(python);
            command
                .arg("-I")
                .arg(fixture_script())
                .arg("daemon")
                .arg(&self.root)
                .arg(&FIXTURE_KEY.1)
                .arg(&self.control)
                .arg(if self.unprotected {
                    "unprotected"
                } else {
                    "protected"
                });
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

struct GatedSafety {
    control: PathBuf,
    entered: std::sync::atomic::AtomicUsize,
}

impl UrlSafety for GatedSafety {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        if url.host_str() != Some(HOST) {
            return Err("permit fixture only permits its public-shaped hostname".into());
        }
        if self.control.join("safety.fail").exists() {
            return Err("fixture rejected preflight".into());
        }
        if self.control.join("safety.arm").exists() {
            let n = self
                .entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            fs::write(self.control.join(format!("safety.entered.{n}")), b"entered").unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !self.control.join("safety.release").exists() {
                if Instant::now() >= deadline {
                    return Err("permit fixture safety check timed out".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            fs::write(self.control.join("safety.returned"), b"returned").unwrap();
        }
        Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}

#[test]
fn permit_daemon_subprocess_helper() {
    let Some(root) = std::env::var_os("KV_PERMIT_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    if std::env::var_os("KV_PERMIT_SETUP").as_deref() == Some(OsStr::new("1")) {
        kv_store::config_authority::approve_config_unattended(&root, &Key32::new(FIXTURE_KEY.0))
            .unwrap();
        DrawerStore::open(root.join(".secrets"), Key32::new(FIXTURE_KEY.0))
            .set_secret("dev", "API_TOKEN", API_SECRET, 1)
            .unwrap();
        DrawerStore::open(root.join(".secrets"), Key32::new(FIXTURE_KEY.0))
            .set_secret("prod", "API_TOKEN", API_SECRET, 1)
            .unwrap();
        return;
    }
    let control = PathBuf::from(std::env::var_os("KV_PERMIT_CONTROL").unwrap());
    let ca = fs::read(std::env::var_os("KV_PERMIT_CA").unwrap()).unwrap();
    let master = Key32::new(FIXTURE_KEY.0);
    let store = Arc::new(DrawerStore::open(
        root.join(".secrets"),
        Key32::new(FIXTURE_KEY.0),
    ));
    let passphrase =
        if std::env::var_os("KV_PERMIT_UNPROTECTED").as_deref() == Some(OsStr::new("1")) {
            None
        } else {
            Some(FIXTURE_KEY.1.as_bytes())
        };
    let trust = TrustContext::at_unlock(&root, passphrase, &master).unwrap();
    let caller = ApiCaller::with_test_ca_for_test(
        Arc::new(GatedSafety {
            control,
            entered: std::sync::atomic::AtomicUsize::new(0),
        }),
        &ca,
    )
    .unwrap();
    run_agent_with_api_caller(root, store, master, trust, Arc::new(caller)).unwrap();
}

impl Scenario {
    fn owner(&self, python: &OsStr, input: Value) -> Value {
        let mut command = Command::new(python);
        command
            .arg("-I")
            .arg(fixture_script())
            .arg("owner")
            .arg(&self.root)
            .arg(&FIXTURE_KEY.1)
            .env("HOME", &self.home);
        let output = harness::output(
            command,
            &serde_json::to_vec(&input).unwrap(),
            Duration::from_secs(90),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "owner failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn approve(&self, python: &OsStr, call: &Value) -> Value {
        let required = self.request("api", call.clone());
        assert_eq!(required["error_code"], "permit_required", "{required}");
        assert_eq!(required["approval_required"], true);
        let approved = self.owner(python, json!({"request_id":required["request_id"]}));
        assert_eq!(approved["status"], "registered");
        assert_eq!(
            approved["record"]["facts"]["permit_id"],
            required["permit_id"]
        );
        assert_eq!(
            approved["record"]["facts"]["request_id"],
            required["request_id"]
        );
        approved
    }

    fn stop(&self, daemon: &mut Daemon) {
        assert_eq!(self.request("stop", json!({}))["stopping"], true);
        daemon.wait_success(CLEANUP_BOUND);
        self.assert_cleaned();
    }

    fn assert_audit_chain(&self, python: &OsStr) {
        let mut command = Command::new(python);
        command
            .arg("-I")
            .arg(fixture_script())
            .arg("audit")
            .env("HOME", &self.home);
        let output = harness::output(command, &[], Duration::from_secs(15)).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert!(
            fs::metadata(self.home.join(".kv/audit.jsonl"))
                .unwrap()
                .len()
                > 0
        );
    }
}

fn call(path: &str) -> Value {
    json!({"provider":"permit-local", "path":path, "method":"POST", "body":BODY,
        "headers":{"X-Request-Label":"permit-fixture"}})
}

fn retry(call: &Value, approval: &Value) -> Value {
    let mut request = call.clone();
    request["permit_id"] = approval["record"]["facts"]["permit_id"].clone();
    request
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_spent(result: &Value) {
    assert_eq!(
        result,
        &json!({"error":"permit already spent", "error_code":"permit_invalid"})
    );
}

fn assert_sent(observed: &Value, body: &str) {
    assert_eq!(observed["method"], "POST");
    assert_eq!(observed["body_hex"], hex(body.as_bytes()));
    assert_eq!(observed["headers"]["content-type"], "application/json");
    assert_eq!(observed["headers"]["x-request-label"], "permit-fixture");
    assert!(
        observed["headers"]["host"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{HOST}:"))
    );
}

#[test]
fn owner_approval_sends_exact_request_once() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let call = call("/api/write?batch=1");
        let required = scenario.request("api", call.clone());
        assert_eq!(required["error_code"], "permit_required", "{required}");
        let pending = scenario.request("permit_requests", json!({}));
        assert_eq!(pending["pauses"], json!([]));
        assert_eq!(pending["requests"].as_array().unwrap().len(), 1);
        assert_eq!(pending["requests"][0]["request_id"], required["request_id"]);
        let mut early = call.clone();
        early["permit_id"] = required["permit_id"].clone();
        assert_eq!(scenario.request("api", early), required);
        assert!(scenario.observed().is_empty());
        let approval = scenario.owner(&python, json!({"request_id":required["request_id"]}));
        assert_eq!(approval["status"], "registered");
        let facts = &approval["record"]["facts"];
        assert_eq!(facts["permit_id"], required["permit_id"]);
        assert_eq!(facts["body_length"], BODY.len());
        assert_eq!(facts["body_sha256"], hex(&Sha256::digest(BODY.as_bytes())));
        assert_eq!(facts["body_present"], true);
        assert!(facts["grant_id"].is_null() && facts["run_id"].is_null());
        assert_eq!(approval["record"]["body_text"], BODY);
        assert!(
            approval["rendered"]
                .as_str()
                .unwrap()
                .contains("Approve exactly one HTTP call.")
        );
        assert_eq!(
            scenario.request("permit_requests", json!({}))["requests"],
            json!([])
        );
        assert!(scenario.observed().is_empty());
        let retry = retry(&call, &approval);
        let sent = scenario.request("api", retry.clone());
        assert_eq!(sent["status"], 200, "{sent}");
        assert_eq!(sent["body"], json!({"ok":true}));
        let replay = scenario.request("api", retry.clone());
        assert_spent(&replay);
        let registered = scenario.owner(
            &python,
            json!({"action":"register", "permit":approval["permit"]}),
        );
        assert_eq!(registered["status"], "already-registered");
        assert_spent(&scenario.request("api", retry));
        let observed = scenario.observed();
        assert_eq!(observed.len(), 1);
        assert_sent(&observed[0], BODY);
        assert_eq!(observed[0]["path"], "/api/write?batch=1");
        assert_eq!(
            observed[0]["headers"]["authorization"],
            format!("Bearer {API_SECRET}")
        );
        scenario.stop(&mut daemon);
        results.push(json!({"sent":sent,"replay":replay,"registered":registered}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn concurrent_retries_spend_one_permit_once() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let call = call("/api/hold");
        let approval = scenario.approve(&python, &call);
        let retry = retry(&call, &approval);
        scenario.release("safety.arm");
        let mut first = scenario.send("api", retry.clone());
        let mut second = scenario.send("api", retry.clone());
        wait_until("both retries in preflight", Duration::from_secs(10), || {
            scenario.control.join("safety.entered.2").exists()
        });
        scenario.release("safety.release");
        scenario.wait_observed(1, &mut first);
        scenario.release("provider.release");
        let replies = [read_reply(&mut first), read_reply(&mut second)];
        let successes: Vec<_> = replies
            .iter()
            .filter(|reply| reply["status"] == 200)
            .collect();
        let refusals: Vec<_> = replies
            .iter()
            .filter(|reply| reply["error_code"] == "permit_invalid")
            .collect();
        assert_eq!(successes.len(), 1, "{replies:?}");
        assert_eq!(refusals.len(), 1, "{replies:?}");
        assert_spent(refusals[0]);
        assert_eq!(scenario.observed().len(), 1);
        assert_spent(&scenario.request("api", retry));
        scenario.stop(&mut daemon);
        results.push(json!({"success":successes[0], "refusal":refusals[0]}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn altered_calls_and_signed_facts_are_refused_without_spending() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let call = call("/api/write");
        let required = scenario.request("api", call.clone());
        assert_eq!(required["error_code"], "permit_required", "{required}");
        let mutated = scenario.owner(&python, json!({"action":"mutations", "request_id":required["request_id"], "mutations":[
            ["session_nonce","00".repeat(32)], ["location","00"], ["local_approval_id","00".repeat(16)],
            ["provider_digest","00".repeat(32)], ["provider","missing-provider"],
            ["method","DELETE"], ["body_sha256","00".repeat(32)], ["grant_id","unexpected-grant"], ["run_id","unexpected-run"]
        ]}));
        let expected = [
            "not_signed",
            "not_signed",
            "not_signed",
            "provider_changed",
            "provider_changed",
            "unknown_request",
            "unknown_request",
            "unknown_request",
            "unknown_request",
            "not_signed",
        ];
        for (response, code) in mutated["results"].as_array().unwrap().iter().zip(expected) {
            assert_eq!(response["code"], code, "{response}");
        }
        assert_eq!(mutated["results"].as_array().unwrap().len(), expected.len());
        assert!(scenario.observed().is_empty());
        assert_eq!(
            scenario.owner(
                &python,
                json!({"action":"register", "permit":mutated["permit"]})
            )["status"],
            "registered"
        );
        let retry = retry(&call, &mutated);
        let mut refusals = Vec::new();
        for (field, value) in [
            ("body", json!(format!("{BODY} "))),
            ("body", Value::Null),
            ("body", json!("")),
            ("method", json!("PATCH")),
            ("path", json!("/api/other")),
            ("path", json!("/api/write?extra=1")),
            ("headers", json!({"X-Request-Label":"changed"})),
            ("provider", json!("permit-other")),
            ("env", json!("prod")),
        ] {
            let mut changed = retry.clone();
            changed[field] = value;
            let refusal = scenario.request("api", changed);
            assert_eq!(
                refusal,
                json!({"error":"this call differs from the approved permit", "error_code":"permit_invalid"})
            );
            refusals.push(refusal);
        }
        let mut outside_policy = retry.clone();
        outside_policy["path"] = json!("/outside-policy");
        let denied = scenario.request("api", outside_policy);
        assert_eq!(
            denied,
            json!({"error":"HTTP policy denied POST /outside-policy", "error_code":"http_policy_denied"})
        );
        refusals.push(denied);
        assert!(scenario.observed().is_empty());
        assert_eq!(scenario.request("api", retry)["status"], 200);
        assert_eq!(scenario.observed().len(), 1);
        scenario.stop(&mut daemon);
        results.push(json!({"mutations":mutated["results"], "refusals":refusals}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn preflight_failure_preserves_and_transport_failure_spends_permit() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let call = call("/api/write");
        let approved = scenario.approve(&python, &call);
        scenario.release("safety.fail");
        let preflight = scenario.request("api", retry(&call, &approved));
        assert_eq!(
            preflight["error"],
            "SSRF blocked: fixture rejected preflight"
        );
        assert!(scenario.observed().is_empty());
        fs::remove_file(scenario.control.join("safety.fail")).unwrap();
        assert_eq!(
            scenario.request("api", retry(&call, &approved))["status"],
            200
        );
        let dropped = self::call("/api/drop");
        let approved = scenario.approve(&python, &dropped);
        let failed = scenario.request("api", retry(&dropped, &approved));
        assert!(failed["error"].is_string(), "{failed}");
        assert!(
            failed.get("status").is_none(),
            "transport unexpectedly returned HTTP: {failed}"
        );
        let replay = scenario.request("api", retry(&dropped, &approved));
        assert_spent(&replay);
        assert_eq!(scenario.observed().len(), 2);
        assert_eq!(scenario.observed()[1]["path"], "/api/drop");
        scenario.stop(&mut daemon);
        // urllib and ureq supply their own transport-error prose. The permit
        // contract is proved by the accepted wire request plus spent replay.
        results.push(json!({"preflight":preflight, "replay":replay, "sends":2}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn stop_before_and_after_commit_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let held_call = call("/api/hold");
        let pending_call = call("/api/pending");
        let held_approval = scenario.approve(&python, &held_call);
        let pending_approval = scenario.approve(&python, &pending_call);
        let mut held = scenario.send("api", retry(&held_call, &held_approval));
        scenario.wait_observed(1, &mut held);
        scenario.release("safety.arm");
        let mut pending = scenario.send("api", retry(&pending_call, &pending_approval));
        wait_until("pending approved retry", Duration::from_secs(10), || {
            scenario.control.join("safety.entered.1").exists()
        });
        let first = scenario.request("stop", json!({}));
        assert_eq!(
            first,
            json!({"in_flight":1,"awaiting_choice":true,"runs":[]})
        );
        scenario.release("safety.release");
        wait_until(
            "preflight released after stop",
            Duration::from_secs(10),
            || scenario.control.join("safety.returned").exists(),
        );
        assert_eq!(scenario.observed().len(), 1);
        let mut stop = scenario.send("stop", json!({"choice":"wait"}));
        assert_reply_pending(&mut stop);
        scenario.release("provider.release");
        let stopped = read_reply(&mut stop);
        let refused = read_reply(&mut pending);
        let sent = read_reply(&mut held);
        // Python _reply opens a separate work window for an ordinary API
        // response. Stop retires that authority even when the HTTP operation
        // was already committed; its result is replaced after work drains.
        let retired = json!({"error":"vault changed under the running daemon", "error_code":"vault_hard_locked"});
        let backend = if rust { "Rust" } else { "Python" };
        assert_eq!(
            refused, retired,
            "{backend} pending reply after stop: {refused}; committed reply: {sent}"
        );
        assert_eq!(
            sent, retired,
            "{backend} committed reply after stop: {sent}; pending reply: {refused}"
        );
        assert_eq!(
            stopped,
            json!({"stopping":true,"wait_seconds":135,"cut_off":0,"ended_runs":[]})
        );
        daemon.wait_success(CLEANUP_BOUND);
        scenario.assert_cleaned();
        assert_eq!(scenario.observed().len(), 1);
        results.push(json!({"first":first,"stopped":stopped,"refused":refused,"sent":sent}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn query_auth_and_unshowable_previews_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let mut call = call("/api/write?batch=1");
        call["provider"] = json!("permit-query");
        let approval = scenario.approve(&python, &call);
        let shown = approval["record"]["facts"]["url"].as_str().unwrap();
        assert!(
            shown.ends_with("/api/write?batch=1&key=<added-by-kv-not-shown>"),
            "{shown}"
        );
        assert!(
            !serde_json::to_string(&approval["record"])
                .unwrap()
                .contains(API_SECRET)
        );
        assert!(!approval["rendered"].as_str().unwrap().contains(API_SECRET));
        assert_eq!(
            scenario.request("api", retry(&call, &approval))["status"],
            200
        );
        let observed = scenario.observed();
        assert_eq!(observed.len(), 1);
        assert_sent(&observed[0], BODY);
        assert_eq!(
            observed[0]["path"],
            format!("/api/write?batch=1&key={API_SECRET}")
        );
        assert!(observed[0]["headers"].get("authorization").is_none());
        let mut refused = Vec::new();
        for (index, body) in [
            "x".repeat(512 * 1024 + 1),
            "\0".repeat(9000),
            "π".repeat(9000),
        ]
        .into_iter()
        .enumerate()
        {
            let mut oversized = call.clone();
            oversized["body"] = json!(body);
            let result = scenario.request("api", oversized);
            if index == 0 {
                assert_eq!(result, json!({"error":"body exceeds 524288 bytes"}));
            } else {
                assert_eq!(result["error_code"], "permit_request_refused", "{result}");
            }
            assert!(result.get("permit_id").is_none());
            refused.push(result);
        }
        assert_eq!(
            scenario.request("permit_requests", json!({}))["requests"],
            json!([])
        );
        assert_eq!(scenario.observed().len(), 1);
        scenario.stop(&mut daemon);
        results.push(json!({"refused":refused}));
    }
    assert_eq!(results[0], results[1]);
}

fn file_snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), out);
            } else if entry.file_type().unwrap().is_file() {
                out.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    visit(root, root, &mut out);
    out
}

fn durable_home_snapshot(scenario: &Scenario) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = file_snapshot(&scenario.home);
    for runtime in [&scenario.token, &scenario.pid] {
        files.remove(runtime.strip_prefix(&scenario.home).unwrap());
    }
    // Python records command/environment and success/error metadata here.
    // Its contents are checked separately at every permit lifecycle stage.
    files.remove(Path::new(".kv/agent.log"));
    for audit in [
        "audit.jsonl",
        "audit.lock",
        "audit-health.json",
        "audit-health.lock",
        "audit-health.unkept",
        "audit.uncertain",
    ] {
        files.remove(&Path::new(".kv").join(audit));
    }
    files
}

fn assert_runtime_log_has_no_permit_material(scenario: &Scenario, facts: &Value) {
    let log = match fs::read_to_string(scenario.home.join(".kv/agent.log")) {
        Ok(log) => log,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => panic!("cannot inspect runtime metadata log: {error}"),
    };
    for value in [
        API_SECRET,
        BODY,
        "permit-body-unique",
        facts["permit_id"].as_str().unwrap(),
        facts["request_id"].as_str().unwrap(),
    ] {
        assert!(
            !log.contains(value),
            "runtime metadata log contains permit material: {value:?}"
        );
    }
}

#[test]
fn permit_audit_attribution_and_session_state_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::new(&python);
        let mut daemon = scenario.start(&python, rust);
        let before = file_snapshot(&scenario.root);
        let before_home = durable_home_snapshot(&scenario);
        let mut call = call("/api/write");
        call["audit_ctx"] = json!({"client_name":"asking\nclient", "source":"permit-test"});
        call["reason"] = json!("create the approved record");
        let required = scenario.request("api", call.clone());
        assert_eq!(required["error_code"], "permit_required", "{required}");
        assert_eq!(
            before,
            file_snapshot(&scenario.root),
            "pending permit persisted in vault"
        );
        assert_eq!(
            before_home,
            durable_home_snapshot(&scenario),
            "pending permit persisted in HOME"
        );
        assert_runtime_log_has_no_permit_material(&scenario, &required);
        let approval = scenario.owner(&python, json!({"request_id":required["request_id"]}));
        assert_eq!(approval["status"], "registered");
        assert_eq!(
            before,
            file_snapshot(&scenario.root),
            "registered permit persisted in vault"
        );
        assert_eq!(
            before_home,
            durable_home_snapshot(&scenario),
            "registered permit persisted in HOME"
        );
        assert_runtime_log_has_no_permit_material(&scenario, &approval["record"]["facts"]);
        assert_eq!(
            approval["record"]["requester"],
            json!({"agent":"client=asking_client source=permit-test", "agent_reason":"create the approved record"})
        );
        let mut retry = retry(&call, &approval);
        retry["audit_ctx"] = json!({"client_name":"retry-client"});
        retry["reason"] = json!("send once");
        assert_eq!(scenario.request("api", retry.clone())["status"], 200);
        retry["reason"] = json!("check replay");
        assert_spent(&scenario.request("api", retry.clone()));
        let mut unknown = retry.clone();
        unknown["permit_id"] = json!("permit_deadbeef");
        assert_eq!(
            scenario.request("api", unknown)["error_code"],
            "permit_invalid"
        );
        scenario.stop(&mut daemon);
        assert_eq!(
            before,
            file_snapshot(&scenario.root),
            "permit flow changed vault files"
        );
        assert_eq!(
            before_home,
            durable_home_snapshot(&scenario),
            "permit flow changed durable HOME files"
        );
        assert_runtime_log_has_no_permit_material(&scenario, &approval["record"]["facts"]);
        scenario.assert_audit_chain(&python);
        let audit = fs::read_to_string(scenario.home.join(".kv/audit.jsonl")).unwrap();
        assert!(!audit.contains(API_SECRET));
        assert!(!audit.contains("permit-body-unique"));
        let events: Vec<Value> = audit
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|entry| entry["event"] == "api_call")
            .collect();
        assert_eq!(events.len(), 4, "{events:?}");
        assert_eq!(
            events[0]["request_id"],
            approval["record"]["facts"]["request_id"]
        );
        for event in &events[..3] {
            assert_eq!(event["permit_id"], approval["record"]["facts"]["permit_id"]);
        }
        assert_eq!(
            events[0]["agent"],
            "client=asking_client source=permit-test"
        );
        assert_eq!(events[0]["agent_reason"], "create the approved record");
        assert_eq!(events[1]["agent"], "client=retry-client");
        assert_eq!(events[1]["agent_reason"], "send once");
        // Ordinary api_call uses refused=False even on permit_invalid.
        assert_eq!(events[2]["agent_reason"], "check replay");
        assert_eq!(
            events[3]["permit_id"],
            "[permit id not known to this service]"
        );
        for (path, contents) in file_snapshot(&scenario.home) {
            if path == Path::new(".kv/audit.jsonl") {
                continue;
            }
            let text = String::from_utf8_lossy(&contents);
            assert!(!text.contains(BODY), "body persisted in {}", path.display());
            assert!(
                !text.contains(approval["record"]["facts"]["permit_id"].as_str().unwrap()),
                "permit persisted in {}",
                path.display()
            );
        }
        let mut restarted = scenario.start(&python, rust);
        let old = scenario.request("api", retry);
        assert_eq!(
            old,
            json!({"error":"permit request is missing or expired", "error_code":"permit_invalid"})
        );
        assert_eq!(
            scenario.request("permit_requests", json!({}))["requests"],
            json!([])
        );
        let old_registration = scenario.owner(
            &python,
            json!({"action":"register_result", "permit":approval["permit"]}),
        );
        assert_eq!(old_registration, json!({"code":"not_signed"}));
        scenario.stop(&mut restarted);
        let other = Scenario::new(&python);
        let mut other_daemon = other.start(&python, rust);
        let other_registration = other.owner(
            &python,
            json!({"action":"register_result", "permit":approval["permit"]}),
        );
        assert_eq!(other_registration, json!({"code":"not_signed"}));
        assert!(other.observed().is_empty());
        other.stop(&mut other_daemon);
        results.push(json!({"old":old,"session":old_registration,"vault":other_registration,"attribution":events.iter().map(|event| json!({"agent":event["agent"],"reason":event["agent_reason"],"error_code":event["error_code"]})).collect::<Vec<_>>()}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn unprotected_session_refuses_before_lookup_or_preview_like_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        // Open the synthetic store normally, then build the session through
        // at_unlock(None). This checks the daemon's session-authority boundary
        // without weakening or replacing its pinned key file.
        let scenario = Scenario::with_options(&python, "local-convenience", true);
        let mut daemon = scenario.start(&python, rust);
        assert_eq!(
            scenario.request("status", json!({}))["session"],
            "unprotected"
        );
        scenario.release("safety.arm");
        let mut call = call("/api/write");
        call["provider"] = json!("permit-missing");
        let refused = scenario.request("api", call.clone());
        assert_eq!(
            refused,
            json!({"error_code":"no_passphrase", "error":concat!(
            "refused: kv gives approvals, passes and permits only on a passphrase-protected vault ",
            "unlocked with its passphrase, and never uses one made without it. Run 'kv ",
            "upgrade-security' if this vault has no passphrase, unlock with the passphrase, then ",
            "approve again.")})
        );
        call["provider"] = json!("permit-local");
        assert_eq!(scenario.request("api", call), refused);
        assert!(
            !scenario.control.join("safety.entered.1").exists(),
            "unprotected request reached preview"
        );
        let owner = scenario.owner(&python, json!({"action":"unprotected"}));
        assert_eq!(owner, json!({"code":"no_passphrase", "owner_refused":true}));
        assert!(scenario.observed().is_empty());
        scenario.stop(&mut daemon);
        results.push(json!({"refused":refused,"owner":owner}));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn protected_approval_allows_review_but_refuses_registration_like_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut results = Vec::new();
    for rust in [false, true] {
        let scenario = Scenario::with_options(&python, "protected-approval", false);
        let mut daemon = scenario.start(&python, rust);
        let call = call("/api/write");
        let required = scenario.request("api", call.clone());
        assert_eq!(required["error_code"], "permit_required", "{required}");
        let reviewed = scenario.owner(
            &python,
            json!({"action":"record", "request_id":required["request_id"]}),
        );
        assert_eq!(reviewed["record"]["body_text"], BODY);
        assert!(
            reviewed["rendered"]
                .as_str()
                .unwrap()
                .contains("Approve exactly one HTTP call.")
        );
        let refused = scenario.owner(
            &python,
            json!({"action":"register_result", "permit":reviewed["permit"]}),
        );
        assert_eq!(refused, json!({"code":"protected_mode"}));
        assert_eq!(scenario.request("api", retry(&call, &reviewed)), required);
        let pending = scenario.request("permit_requests", json!({}));
        assert_eq!(pending["requests"].as_array().unwrap().len(), 1);
        assert_eq!(pending["requests"][0]["request_id"], required["request_id"]);
        assert_eq!(pending["pauses"], json!([]));
        assert!(scenario.observed().is_empty());
        scenario.stop(&mut daemon);
        results.push(refused);
    }
    assert_eq!(results[0], results[1]);
}
