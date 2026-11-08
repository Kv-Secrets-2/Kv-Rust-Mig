#![cfg(unix)]
//! Stage 6d-1: a capability run's `cap_api` calls against Python 0.4.0 on the same
//! vault. A script admitted with an owner-signed `api:` grant calls the broker through
//! `kv.cap_client.api_call` (token-authenticated, no daemon token) and both daemons
//! must answer it, charge the pass and audit the calls alike.

#[path = "../../../tests/support/harness.rs"]
mod harness;

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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
use serde_json::{Map, Value, json};
use url::Url;

const API_SECRET: &str = "stage6d-cap-secret-value-1234567890";
const PROVIDER: &str = "stage6-local";
/// A public-shaped hostname for the loopback provider: a one-call permit refuses a
/// URL whose host is a non-global address, so both daemons' URL safety hooks resolve
/// this name to 127.0.0.1 (as the stage 5 permit fixture does).
const HOST: &str = "stage6-fixture.example";

static HOME_LOCK: Mutex<()> = Mutex::new(());

struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct HomeGuard(Option<std::ffi::OsString>);

impl HomeGuard {
    fn set(home: &Path) -> Self {
        let previous = std::env::var_os("HOME");
        update_home(Some(home.as_os_str()));
        Self(previous)
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        update_home(self.0.take().as_deref());
    }
}

#[allow(unsafe_code)]
fn update_home(home: Option<&std::ffi::OsStr>) {
    // SAFETY: tests that touch HOME serialize on HOME_LOCK.
    unsafe {
        match home {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
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

struct LocalSafety;

impl UrlSafety for LocalSafety {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        if matches!(url.host_str(), Some("127.0.0.1") | Some(HOST)) {
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
        } else {
            Err("test caller only permits the loopback provider".into())
        }
    }
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v0.4.0")
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn fixture_master_key() -> (Key32, String) {
    let expected: Value = serde_json::from_slice(
        &fs::read(fixture_root().join("vaults/basic.expected.json")).unwrap(),
    )
    .unwrap();
    let passphrase = expected["passphrase"].as_str().unwrap().to_owned();
    let blob = fs::read(fixture_root().join("vaults/basic/.secrets/key")).unwrap();
    let identity = keyfile::unwrap_v4(&blob, passphrase.as_bytes()).unwrap();
    (Key32::new(*identity.master_key.as_bytes()), passphrase)
}

fn run_python(
    python: &std::ffi::OsStr,
    code: &str,
    root: &Path,
    home: &Path,
    args: &[&str],
) -> Value {
    let mut command = Command::new(python);
    command
        .arg("-c")
        .arg(code)
        .arg(root)
        .env("HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for arg in args {
        command.arg(arg);
    }
    let output = command.output().expect("run Python reference");
    assert!(
        output.status.success(),
        "Python reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Python JSON")
}

fn python_agent_request(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    cmd: &str,
    fields: &Value,
) -> Value {
    run_python(
        python,
        "import json,sys\nfrom kv import agent\nfields=json.loads(sys.argv[3])\nprint(json.dumps(agent.agent_request(sys.argv[2],project_root=sys.argv[1],timeout=None,**fields)))",
        root,
        home,
        &[cmd, &fields.to_string()],
    )
}

fn rust_request(root: &Path, cmd: &str, fields: &Value) -> Value {
    let fields: Map<String, Value> = fields.as_object().cloned().unwrap_or_default();
    kv_proto::agent_request_with_timeout(root, cmd, &fields, None).unwrap()
}

fn wait_for_socket(root: &Path) -> PathBuf {
    let socket = kv_proto::agent_socket_path(Some(root)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "daemon socket did not appear");
    socket
}

fn stop_daemon(root: &Path) {
    let _ = rust_request(root, "stop", &json!({"choice": "now"}));
    let socket = kv_proto::agent_socket_path(Some(root)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
}

fn bwrap_installed() -> bool {
    kv_sandbox::bwrap::bwrap_path().is_some()
}

struct HttpsServer {
    _child: ChildGuard,
    port: u16,
    certificate_der: Vec<u8>,
    ca_pem_path: PathBuf,
    observed_path: PathBuf,
}

impl HttpsServer {
    fn start(python: &std::ffi::OsStr, directory: &Path) -> Self {
        let ca_key_pair = KeyPair::generate().expect("generate test CA key");
        let mut ca_params =
            CertificateParams::new(Vec::new()).expect("test CA certificate parameters");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "Stage6d test CA");
        let ca = ca_params
            .self_signed(&ca_key_pair)
            .expect("self-sign test CA");
        let server_key_pair = KeyPair::generate().expect("generate test server key");
        let mut server_params = CertificateParams::new(vec!["127.0.0.1".into(), HOST.into()])
            .expect("test server parameters");
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        server_params.use_authority_key_identifier_extension = true;
        let server_certificate = server_params
            .signed_by(&server_key_pair, &ca, &ca_key_pair)
            .expect("sign test server certificate");
        let ca_pem_path = directory.join("test-ca.pem");
        let server_certificate_path = directory.join("test-server.pem");
        let key_path = directory.join("test-server-key.pem");
        let observed_path = directory.join("requests.jsonl");
        fs::write(&ca_pem_path, ca.pem()).unwrap();
        fs::write(&server_certificate_path, server_certificate.pem()).unwrap();
        fs::write(&key_path, server_key_pair.serialize_pem()).unwrap();

        const SERVER: &str = r#"
import http.server, json, ssl, sys
cert, key, observed = sys.argv[1:4]
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.do_GET()
    def do_GET(self):
        with open(observed, "a", encoding="utf-8") as output:
            output.write(json.dumps({"method":self.command,"path":self.path,"authorization":self.headers.get("Authorization")})+"\n")
        body = json.dumps({"echo":self.headers.get("Authorization"),"path":self.path,"ok":True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
"#;
        let stderr = fs::File::create(directory.join("https-server.log")).unwrap();
        let mut child = Command::new(python)
            .arg("-c")
            .arg(SERVER)
            .arg(&server_certificate_path)
            .arg(&key_path)
            .arg(&observed_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("start local HTTPS server");
        let stdout = child.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        let port = line.trim().parse().expect("HTTPS server port number");
        Self {
            _child: ChildGuard(child),
            port,
            certificate_der: ca.der().as_ref().to_vec(),
            ca_pem_path,
            observed_path,
        }
    }

    fn observed(&self) -> Vec<Value> {
        fs::read_to_string(&self.observed_path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

/// A vault both daemons can serve, with one HTTP provider bound to the local server
/// and a safe GET rule, and its secret stored in `dev`.
struct Vault {
    _temp: TestDir,
    _home_guard: HomeGuard,
    root: PathBuf,
    home: PathBuf,
    master: Key32,
    passphrase: String,
}

fn prepare_vault(python: &std::ffi::OsStr, tag: &str, server: &HttpsServer) -> Vault {
    let temp = TestDir(harness::socket_temp_dir(tag, "home"));
    let home = temp.0.join("home");
    fs::create_dir(&home).unwrap();
    let home_guard = HomeGuard::set(&home);
    let root = temp.0.join("vault");
    fs::create_dir(&root).unwrap();
    let secrets_path = root.join(".secrets");
    copy_dir(&fixture_root().join("vaults/basic/.secrets"), &secrets_path);
    fs::set_permissions(secrets_path.join("key"), fs::Permissions::from_mode(0o600)).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let home = fs::canonicalize(home).unwrap();
    let (master, passphrase) = fixture_master_key();
    run_python(
        python,
        "import json,sys\nfrom kv import vault_origin\nprint(json.dumps(vault_origin.record_created(sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    run_python(
        python,
        "import json,sys\nfrom kv.owner_key import relocate_key_file\nprint(json.dumps(relocate_key_file(sys.argv[1],sys.argv[2])))",
        &root,
        &home,
        &[&passphrase],
    );
    let base_url = format!("https://{HOST}:{}", server.port);
    let config_path = secrets_path.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    if !config["providers"].is_object() {
        config["providers"] = json!({});
    }
    config["providers"][PROVIDER] = json!({
        "base_url": base_url,
        "secret_name": "API_TOKEN",
        "auth_type": "bearer",
        "default_headers": {"Content-Type": "application/json"}
    });
    config["broker_policy"]["http"][PROVIDER] = json!({
        "origin": base_url,
        "secret_name": "API_TOKEN",
        "rules": [
            {"id": "safe-read", "methods": ["GET"], "path_prefix": "/api", "approval": "none"},
            {"id": "write", "methods": ["POST"], "path_prefix": "/api/write", "approval": "per-call"}
        ]
    });
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    kv_store::config_authority::approve_config_unattended(&root, &master).unwrap();
    let store = DrawerStore::open(secrets_path, Key32::new(*master.as_bytes()));
    store
        .set_secret("dev", "API_TOKEN", API_SECRET, 1)
        .expect("store the provider secret");
    Vault {
        _temp: temp,
        _home_guard: home_guard,
        root,
        home,
        master,
        passphrase,
    }
}

fn start_rust_daemon(
    vault: &Vault,
    server: &HttpsServer,
) -> thread::JoinHandle<Result<Value, kv_agent::AgentError>> {
    let store = Arc::new(DrawerStore::open(
        vault.root.join(".secrets"),
        Key32::new(*vault.master.as_bytes()),
    ));
    let master = Key32::new(*vault.master.as_bytes());
    let trust =
        TrustContext::at_unlock(&vault.root, Some(vault.passphrase.as_bytes()), &master).unwrap();
    let caller = ApiCaller::with_test_ca_for_test(Arc::new(LocalSafety), &server.certificate_der)
        .expect("construct test-only TLS caller");
    let root = vault.root.clone();
    let join = thread::spawn(move || {
        run_agent_with_api_caller(root, store, master, trust, Arc::new(caller))
    });
    wait_for_socket(&vault.root);
    join
}

fn start_python_daemon(
    python: &std::ffi::OsStr,
    vault: &Vault,
    server: &HttpsServer,
) -> ChildGuard {
    // The URL safety check is bypassed for the loopback test server, as in stage5_api;
    // the test CA comes in through SSL_CERT_FILE.
    const PYTHON_DAEMON: &str = r#"
import sys
from kv import providers
from kv.agent import run_agent
from kv.config import get_default_env
from kv.store import SecretStore
from kv.trust import TrustContext
providers._check_url_safety = lambda url: (True, "", "127.0.0.1")
root,passphrase=sys.argv[1:3]
store=SecretStore(root,passphrase=passphrase)
master=store.master_key
store.pin()
store.trust=TrustContext.at_unlock(root,passphrase,master)
run_agent(store,get_default_env(root))
"#;
    let log = fs::File::create(vault.root.join("python-daemon.log")).unwrap();
    let child = Command::new(python)
        .arg("-c")
        .arg(PYTHON_DAEMON)
        .arg(&vault.root)
        .arg(&vault.passphrase)
        .env("HOME", &vault.home)
        .env("SSL_CERT_FILE", &server.ca_pem_path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    wait_for_socket(&vault.root);
    ChildGuard(child)
}

fn sign_grant_for_running_daemon(python: &std::ffi::OsStr, vault: &Vault, case: &Value) -> Value {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/grant_for_daemon.py");
    let mut child = Command::new(python)
        .arg(&script)
        .env("HOME", &vault.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run Python grant signer");
    let mut case = case.clone();
    case["root"] = json!(vault.root);
    case["passphrase"] = json!(vault.passphrase);
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(case.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "grant signer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("grant JSON")
}

/// Fields that legitimately differ between the two daemons on one request.
fn comparable(mut value: Value) -> Value {
    if let Some(map) = value.as_object_mut() {
        for key in [
            "run_id",
            "audit_warning",
            "capability_token_id",
            "grant_id",
            "expires_at",
        ] {
            map.remove(key);
        }
        // `kv.cap_client` names the pending permit request on stderr; its id is random.
        if let Some(stderr) = map.get("stderr").and_then(Value::as_str) {
            let masked = stderr
                .split_whitespace()
                .map(|word| {
                    if word.starts_with("permit_request_") {
                        "permit_request_<id>"
                    } else {
                        word
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            map.insert("stderr".into(), Value::String(masked));
        }
    }
    value
}

fn capability_events(home: &Path) -> Vec<Value> {
    fs::read_to_string(home.join(".kv/audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "capability_api")
        .map(|mut event| {
            let object = event.as_object_mut().unwrap();
            for field in [
                "ts",
                "duration_ms",
                "prev",
                "hash",
                "capability_token_id",
                "run_id",
                "grant_id",
                "permit_id",
                "request_id",
            ] {
                object.remove(field);
            }
            event
        })
        .collect()
}

/// Python coalesces a run's repeated identical refusals (`RefusalCoalescer`) and the
/// script polls a pending permit once a second, so only the sequence of distinct
/// consecutive events is comparable between the two daemons.
fn distinct_consecutive(events: Vec<Value>) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for event in events {
        if out.last() != Some(&event) {
            out.push(event);
        }
    }
    out
}

/// The owner approves the one pending one-call permit of a running capability script
/// with the pinned Python owner client (`PermitSigningContext`), as `kv approvals
/// approve` does, once the daemon lists it.
fn approve_pending_permit(
    python: &std::ffi::OsStr,
    vault: &Vault,
    list: impl Fn() -> Value,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    let request_id = loop {
        let listed = list();
        if let Some(first) = listed["requests"].as_array().and_then(|r| r.first()) {
            break first["request_id"].as_str().unwrap().to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "no permit request appeared: {listed}; events so far: {:?}",
            capability_events(&vault.home)
        );
        thread::sleep(Duration::from_millis(200));
    };
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/permits.py");
    let mut child = Command::new(python)
        .arg("-I")
        .arg(&script)
        .arg("owner")
        .arg(&vault.root)
        .arg(&vault.passphrase)
        .env("HOME", &vault.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run the Python owner client");
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(json!({"request_id": request_id}).to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "owner approval failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let approved: Value = serde_json::from_slice(&output.stdout).expect("owner JSON");
    assert_eq!(approved["status"], "registered", "{approved}");
    approved
}

const SCRIPT: &str = r#"
import json
from kv.cap_client import api_call

def show(label, call):
    try:
        reply = call()
        extra = {k: reply.raw.get(k) for k in ("capability_name", "capability_consumed", "capability_remaining_calls")}
        print(label, reply.status, json.dumps(reply.body, sort_keys=True), json.dumps(extra, sort_keys=True))
    except Exception as exc:
        print(label, "error", type(exc).__name__, str(exc))

show("first", lambda: api_call("stage6-local", "/api/one"))
show("outside", lambda: api_call("stage6-local", "/other"))
show("unknown", lambda: api_call("nobody", "/api/one"))
show("second", lambda: api_call("stage6-local", "/api/two"))
"#;

/// A capability run's script calls the broker through `kv.cap_client`: an allowed GET goes
/// out with the provider secret and comes back redacted, a call outside the policy and an
/// unknown provider are refused without charge, and both daemons agree, run reply, script
/// output and `capability_api` audit events alike.
const SCRIPT_POST: &str = r#"
import json
from kv.cap_client import api_call

def show(label, call):
    try:
        reply = call()
        extra = {k: reply.raw.get(k) for
                 k in ("capability_name", "capability_consumed",
                       "capability_remaining_calls")}
        print(label, reply.status, json.dumps(reply.body, sort_keys=True),
              json.dumps(extra, sort_keys=True))
    except Exception as exc:
        print(label, "error", type(exc).__name__, str(exc))

show("post", lambda: api_call("stage6-local", "/api/write", method="POST", body={"n": 1}))
show("after", lambda: api_call("stage6-local", "/api/after"))
"#;

/// Stage 6d-1b: a capability script's POST waits for the owner's one-call permit
/// (`_prepare_api_permit` with the pass's grant and run), which is spent together with
/// the pass at send time; the two daemons agree on the reply, the provider's view, the
/// pass accounting and the audit record.
#[test]
fn capability_run_permit_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Stage 6d-1b permit parity: set KV_PY_REF");
        return;
    };
    if !bwrap_installed() {
        eprintln!("SKIP Stage 6d-1b permit parity: bubblewrap is not installed");
        return;
    }
    let _home_lock = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let server_dir = TestDir(harness::socket_temp_dir("c6p", "x"));
    let server = HttpsServer::start(&python, &server_dir.0);
    let vault = prepare_vault(&python, "c6p", &server);
    let project = vault.root.join("project");
    fs::create_dir(&project).unwrap();
    let script = project.join("post.py");
    fs::write(&script, SCRIPT_POST).unwrap();
    let python_path = Path::new(&python).to_path_buf();
    let actor = json!({"source": "mcp", "client_name": "codex", "session_id": "s-6d1b"});
    let grant_case = json!({
        "argv": [python_path, script], "cwd": project,
        "capability_names": [format!("api:{PROVIDER}")], "actor": actor, "env": "dev",
        "max_calls": 2,
    });
    let run_fields = json!({
        "argv": [python_path, script], "capability_names": [format!("api:{PROVIDER}")],
        "cwd": project, "audit_ctx": actor,
    });

    let python_daemon = start_python_daemon(&python, &vault, &server);
    sign_grant_for_running_daemon(&python, &vault, &grant_case);
    let python_run = {
        let (interpreter, root, home, fields) = (
            python.clone(),
            vault.root.clone(),
            vault.home.clone(),
            run_fields.clone(),
        );
        let run =
            thread::spawn(move || python_agent_request(&interpreter, &root, &home, "run", &fields));
        approve_pending_permit(&python, &vault, || {
            python_agent_request(
                &python,
                &vault.root,
                &vault.home,
                "permit_requests",
                &json!({}),
            )
        });
        run.join().unwrap()
    };
    stop_daemon(&vault.root);
    drop(python_daemon);
    let python_events = capability_events(&vault.home);
    let python_observed = server.observed();

    let join = start_rust_daemon(&vault, &server);
    sign_grant_for_running_daemon(&python, &vault, &grant_case);
    let rust_run = {
        let (root, fields) = (vault.root.clone(), run_fields.clone());
        let run = thread::spawn(move || rust_request(&root, "run", &fields));
        approve_pending_permit(&python, &vault, || {
            rust_request(&vault.root, "permit_requests", &json!({}))
        });
        run.join().unwrap()
    };
    stop_daemon(&vault.root);
    join.join().unwrap().unwrap();
    let rust_events = capability_events(&vault.home)[python_events.len()..].to_vec();
    let rust_observed = server.observed()[python_observed.len()..].to_vec();

    let stdout = python_run["stdout"].as_str().unwrap_or("");
    assert!(
        stdout.starts_with("post 200 ") && stdout.contains("\nafter 200 "),
        "python run: {python_run}"
    );
    assert!(
        !stdout.contains(API_SECRET) && stdout.contains("[REDACTED]"),
        "the secret must only reach the provider: {stdout}"
    );
    assert_eq!(
        comparable(rust_run.clone()),
        comparable(python_run.clone()),
        "capability run replies differ"
    );
    let seen = |observed: &[Value]| {
        observed
            .iter()
            .map(|r| {
                (
                    r["method"].clone(),
                    r["path"].clone(),
                    r["authorization"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        seen(&python_observed),
        vec![
            (
                json!("POST"),
                json!("/api/write"),
                json!(format!("Bearer {API_SECRET}"))
            ),
            (
                json!("GET"),
                json!("/api/after"),
                json!(format!("Bearer {API_SECRET}"))
            ),
        ],
        "python provider calls"
    );
    assert_eq!(
        seen(&rust_observed),
        seen(&python_observed),
        "the provider saw different calls"
    );
    assert!(
        !python_events.is_empty(),
        "python wrote no capability_api events"
    );
    assert_eq!(
        distinct_consecutive(rust_events),
        distinct_consecutive(python_events),
        "capability_api audit events differ"
    );
    println!("KV_PARITY_COMPARISONS 1");
}

#[test]
fn capability_run_api_calls_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Stage 6d cap_api parity: set KV_PY_REF");
        return;
    };
    if !bwrap_installed() {
        eprintln!("SKIP Stage 6d cap_api parity: bubblewrap is not installed");
        return;
    }
    let _home_lock = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let server_dir = TestDir(harness::socket_temp_dir("c6s", "x"));
    let server = HttpsServer::start(&python, &server_dir.0);
    let vault = prepare_vault(&python, "c6", &server);
    let project = vault.root.join("project");
    fs::create_dir(&project).unwrap();
    let script = project.join("call.py");
    fs::write(&script, SCRIPT).unwrap();
    let python_path = Path::new(&python).to_path_buf();
    let actor = json!({"source": "mcp", "client_name": "codex", "session_id": "s-6d"});
    let grant_case = json!({
        "argv": [python_path, script], "cwd": project,
        "capability_names": [format!("api:{PROVIDER}")], "actor": actor, "env": "dev",
    });
    let run_fields = json!({
        "argv": [python_path, script], "capability_names": [format!("api:{PROVIDER}")],
        "cwd": project, "audit_ctx": actor,
    });

    let python_daemon = start_python_daemon(&python, &vault, &server);
    sign_grant_for_running_daemon(&python, &vault, &grant_case);
    let python_run = python_agent_request(&python, &vault.root, &vault.home, "run", &run_fields);
    stop_daemon(&vault.root);
    drop(python_daemon);
    let python_events = capability_events(&vault.home);
    let python_observed = server.observed();

    let join = start_rust_daemon(&vault, &server);
    sign_grant_for_running_daemon(&python, &vault, &grant_case);
    let rust_run = rust_request(&vault.root, "run", &run_fields);
    stop_daemon(&vault.root);
    join.join().unwrap().unwrap();
    let rust_events = capability_events(&vault.home)[python_events.len()..].to_vec();
    let rust_observed = server.observed()[python_observed.len()..].to_vec();

    let stdout = python_run["stdout"].as_str().unwrap_or("");
    assert!(stdout.starts_with("first 200 "), "python run: {python_run}");
    assert!(
        !stdout.contains(API_SECRET) && stdout.contains("[REDACTED]"),
        "the secret must only reach the provider: {stdout}"
    );
    assert_eq!(
        comparable(rust_run.clone()),
        comparable(python_run.clone()),
        "capability run replies differ"
    );
    assert_eq!(
        python_observed
            .iter()
            .map(|r| (r["path"].clone(), r["authorization"].clone()))
            .collect::<Vec<_>>(),
        rust_observed
            .iter()
            .map(|r| (r["path"].clone(), r["authorization"].clone()))
            .collect::<Vec<_>>(),
        "the provider saw different calls"
    );
    assert!(
        python_observed
            .iter()
            .all(|r| r["authorization"] == json!(format!("Bearer {API_SECRET}"))),
        "provider calls: {python_observed:?}"
    );
    assert!(
        !python_events.is_empty(),
        "python wrote no capability_api events"
    );
    assert_eq!(
        rust_events, python_events,
        "capability_api audit events differ"
    );
    println!("KV_PARITY_COMPARISONS 1");
}
