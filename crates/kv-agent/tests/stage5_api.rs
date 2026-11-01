#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use kv_agent::{AgentError, TrustContext, run_agent_with_api_caller};
use kv_broker::{ApiCaller, UrlSafety};
use kv_crypto::{Key32, keyfile};
use kv_store::DrawerStore;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{Map, Value, json};
use url::Url;

const PYTHONPATH: &str = "/home/ubuntu/repos/kv-secrets";
const API_SECRET: &str = "stage5a-test-secret-value";
static HOME_LOCK: Mutex<()> = Mutex::new(());

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).expect("test randomness");
        let path = std::env::temp_dir().join(format!(
            "kv-agent-stage5-api-{}-{}",
            std::process::id(),
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }
}

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
    // SAFETY: The test holds HOME_LOCK for the entire lifetime of this mutation.
    unsafe {
        if let Some(home) = home {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }
    }
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v0.4.0")
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("create copied directory");
    fs::set_permissions(destination, fs::metadata(source).unwrap().permissions()).unwrap();
    for item in fs::read_dir(source).unwrap() {
        let item = item.unwrap();
        let source_path = item.path();
        let destination_path = destination.join(item.file_name());
        let kind = item.file_type().unwrap();
        if kind.is_dir() {
            copy_dir(&source_path, &destination_path);
        } else {
            assert!(kind.is_file(), "fixture contains a non-file entry");
            fs::copy(source_path, destination_path).expect("copy fixture file");
        }
    }
}

fn fixture_master_key() -> (Key32, String) {
    let fixture = fixture_root();
    let expected: Value = serde_json::from_slice(
        &fs::read(fixture.join("vaults/basic.expected.json")).expect("fixture metadata"),
    )
    .expect("fixture JSON");
    let passphrase = expected["passphrase"]
        .as_str()
        .expect("fixture passphrase")
        .to_owned();
    let blob = fs::read(fixture.join("vaults/basic/.secrets/key")).expect("fixture key");
    let identity = keyfile::unwrap_v4(&blob, passphrase.as_bytes()).expect("fixture key unwrap");
    (Key32::new(*identity.master_key.as_bytes()), passphrase)
}

fn fixture_rebind(python: &std::ffi::OsStr, root: &Path, home: &Path, passphrase: &str) {
    let output = Command::new(python)
        .arg("-c")
        .arg("from kv.owner_key import relocate_key_file; import sys; relocate_key_file(sys.argv[1],sys.argv[2])")
        .arg(root)
        .arg(passphrase)
        .env("HOME", home)
        .env("PYTHONPATH", PYTHONPATH)
        .output()
        .expect("rebind fixture vault");
    assert!(
        output.status.success(),
        "fixture key rebinding failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fixture_record_created(python: &std::ffi::OsStr, root: &Path, home: &Path) {
    let output = Command::new(python)
        .arg("-c")
        .arg("from kv.vault_origin import record_created; import sys; record_created(sys.argv[1])")
        .arg(root)
        .env("HOME", home)
        .env("PYTHONPATH", PYTHONPATH)
        .output()
        .expect("record fixture vault origin");
    assert!(
        output.status.success(),
        "fixture vault origin setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn configure_vault(
    root: &Path,
    python: &std::ffi::OsStr,
    home: &Path,
    passphrase: &str,
    base_url: &str,
    master: &Key32,
) -> Arc<DrawerStore> {
    let secrets_path = root.join(".secrets");
    copy_dir(&fixture_root().join("vaults/basic/.secrets"), &secrets_path);
    fs::set_permissions(secrets_path.join("key"), fs::Permissions::from_mode(0o600)).unwrap();
    fixture_record_created(python, root, home);
    fixture_rebind(python, root, home, passphrase);

    let config_path = secrets_path.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    let provider = |secret_name: &str| {
        json!({
            "base_url":base_url,
            "secret_name":secret_name,
            "auth_type":"bearer",
            "default_headers":{"Content-Type":"application/json"}
        })
    };
    if !config["providers"].is_object() {
        config["providers"] = json!({});
    }
    let providers = config["providers"].as_object_mut().unwrap();
    providers.insert("stage5-local".into(), provider("API_TOKEN"));
    providers.insert("stage5-missing".into(), provider("MISSING_TOKEN"));
    let http = config["broker_policy"]["http"].as_object_mut().unwrap();
    for (name, secret_name) in [
        ("stage5-local", "API_TOKEN"),
        ("stage5-missing", "MISSING_TOKEN"),
    ] {
        http.insert(
            name.into(),
            json!({
                "origin":base_url,
                "secret_name":secret_name,
                "rules":[{
                    "id":"safe-read",
                    "methods":["GET"],
                    "path_prefix":"/api",
                    "approval":"none"
                }]
            }),
        );
    }
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    kv_store::config_authority::approve_config_unattended(root, master).unwrap();
    let store = Arc::new(DrawerStore::open(
        secrets_path,
        Key32::new(*master.as_bytes()),
    ));
    store
        .set_secret("dev", "API_TOKEN", API_SECRET, 1)
        .expect("store API test secret");
    store
}

struct HttpsServer {
    child: Child,
    port: u16,
    certificate_der: Vec<u8>,
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
            .push(DnType::OrganizationName, "Stage5a test CA");
        let ca = ca_params
            .self_signed(&ca_key_pair)
            .expect("self-sign test CA");
        let server_key_pair = KeyPair::generate().expect("generate test server key");
        let mut server_params =
            CertificateParams::new(vec!["127.0.0.1".into()]).expect("test server parameters");
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        server_params.use_authority_key_identifier_extension = true;
        let server_certificate = server_params
            .signed_by(&server_key_pair, &ca, &ca_key_pair)
            .expect("sign test server certificate");
        let certificate_path = directory.join("test-ca.pem");
        let server_certificate_path = directory.join("test-server.pem");
        let key_path = directory.join("test-server-key.pem");
        let observed_path = directory.join("requests.jsonl");
        fs::write(&certificate_path, ca.pem()).expect("write test CA certificate");
        fs::write(&server_certificate_path, server_certificate.pem())
            .expect("write test server certificate");
        fs::write(&key_path, server_key_pair.serialize_pem()).expect("write test private key");

        const SERVER: &str = r#"
import http.server, json, ssl, sys
cert, key, observed = sys.argv[1:4]
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def do_GET(self):
        with open(observed, "a", encoding="utf-8") as output:
            output.write(json.dumps({"method":self.command,"path":self.path,"authorization":self.headers.get("Authorization")})+"\n")
            output.flush()
        if self.path == "/api/redirect":
            status, body = 302, b'{"redirect":"blocked"}'
            self.send_response(status)
            self.send_header("Location", "/api/success")
            self.send_header("Content-Type", "application/json")
        elif self.path == "/api/not-found":
            status, body = 404, json.dumps({"echo":self.headers.get("Authorization"),"missing":True}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/api/large":
            status, body = 200, b"x" * (4 * 1024 * 1024 + 200)
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
        else:
            status, body = 200, json.dumps({"echo":self.headers.get("Authorization"),"ok":True}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
    do_POST = do_GET
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
"#;
        let log_path = directory.join("https-server.log");
        let stderr = fs::File::create(&log_path).expect("create TLS server log");
        let mut child = Command::new(python)
            .arg("-c")
            .arg(SERVER)
            .arg(&server_certificate_path)
            .arg(&key_path)
            .arg(&observed_path)
            .env("PYTHONPATH", PYTHONPATH)
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("start local HTTPS server");
        let stdout = child.stdout.take().expect("HTTPS server stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read HTTPS server port");
        let port = line.trim().parse().expect("HTTPS server port number");
        Self {
            child,
            port,
            certificate_der: ca.der().as_ref().to_vec(),
            observed_path,
        }
    }

    fn observed(&self) -> Vec<Value> {
        fs::read_to_string(&self.observed_path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("server observed request JSON"))
            .collect()
    }
}

impl Drop for HttpsServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct LocalSafety;

impl UrlSafety for LocalSafety {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        if url.host_str() == Some("127.0.0.1") {
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
        } else {
            Err("test caller only permits localhost".into())
        }
    }
}

struct RunningAgent {
    root: PathBuf,
    join: Option<JoinHandle<Result<Value, AgentError>>>,
}

impl RunningAgent {
    fn stop(&mut self) {
        let _ = kv_proto::agent_request(&self.root, "stop", &Map::new());
        if let Some(join) = self.join.take() {
            join.join()
                .expect("Rust daemon thread")
                .expect("Rust daemon");
        }
    }
}

impl Drop for RunningAgent {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = kv_proto::agent_request(&self.root, "stop", &Map::new());
            let _ = join.join();
        }
    }
}

struct PythonDaemon(Child);

impl Drop for PythonDaemon {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn wait_for_socket(root: &Path) {
    let socket = kv_proto::agent_socket_path(Some(root)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !socket.exists() {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "daemon did not create its Unix socket");
}

fn start_python_daemon(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    certificate: &Path,
    log_path: &Path,
) -> PythonDaemon {
    const DAEMON: &str = r#"
import sys
from kv import providers
from kv.agent import run_agent
from kv.config import get_default_env
from kv.store import SecretStore
from kv.trust import TrustContext
providers._check_url_safety = lambda url: (True, "", "127.0.0.1")
root, passphrase = sys.argv[1:3]
store = SecretStore(root, passphrase=passphrase)
master = store.master_key
store.pin()
store.trust = TrustContext.at_unlock(root, passphrase, master)
run_agent(store, get_default_env(root))
"#;
    let passphrase = fixture_master_key().1;
    let stderr = fs::File::create(log_path).expect("create Python daemon log");
    let child = Command::new(python)
        .arg("-c")
        .arg(DAEMON)
        .arg(root)
        .arg(passphrase)
        .env("HOME", home)
        .env("PYTHONPATH", PYTHONPATH)
        .env("SSL_CERT_FILE", certificate)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("start Python daemon");
    PythonDaemon(child)
}

fn python_api_request(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    certificate: &Path,
    fields: &Value,
) -> Value {
    let output = Command::new(python)
        .arg("-c")
        .arg("import json,sys; from kv.agent import agent_request; fields=json.loads(sys.argv[2]); print(json.dumps(agent_request('api',project_root=sys.argv[1],**fields)))")
        .arg(root)
        .arg(fields.to_string())
        .env("HOME", home)
        .env("PYTHONPATH", PYTHONPATH)
        .env("SSL_CERT_FILE", certificate)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run Python API client");
    assert!(
        output.status.success(),
        "Python API client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Python API reply")
}

fn python_control_request(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    command: &str,
) -> Value {
    let output = Command::new(python)
        .arg("-c")
        .arg("import json,sys; from kv.agent import agent_request; print(json.dumps(agent_request(sys.argv[2],project_root=sys.argv[1])))")
        .arg(root)
        .arg(command)
        .env("HOME", home)
        .env("PYTHONPATH", PYTHONPATH)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run Python daemon control request");
    assert!(
        output.status.success(),
        "Python control request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Python control reply")
}

fn api_cases() -> Vec<(String, Value)> {
    vec![
        (
            "200 JSON echoes the provider credential".into(),
            json!({"provider":"stage5-local","path":"/api/success","method":"GET"}),
        ),
        (
            "404 error body".into(),
            json!({"provider":"stage5-local","path":"/api/not-found","method":"GET"}),
        ),
        (
            "302 redirects are blocked".into(),
            json!({"provider":"stage5-local","path":"/api/redirect","method":"GET"}),
        ),
        (
            "oversized response is truncated".into(),
            json!({"provider":"stage5-local","path":"/api/large","method":"GET"}),
        ),
        (
            "denied path".into(),
            json!({"provider":"stage5-local","path":"/blocked","method":"GET"}),
        ),
        (
            "denied method".into(),
            json!({"provider":"stage5-local","path":"/api/success","method":"POST"}),
        ),
        (
            "missing secret".into(),
            json!({"provider":"stage5-missing","path":"/api/success","method":"GET"}),
        ),
        (
            "unknown provider".into(),
            json!({"provider":"not-configured","path":"/api/success","method":"GET"}),
        ),
        (
            "provider secret placeholder in body".into(),
            json!({
                "provider":"stage5-local",
                "path":"/api/success",
                "method":"GET",
                "body":{"credential":"${API_TOKEN}"}
            }),
        ),
    ]
}

fn rust_api_request(root: &Path, fields: &Value) -> Value {
    let fields = fields.as_object().expect("API fields").clone();
    kv_proto::agent_request(root, "api", &fields).expect("Rust API client")
}

fn api_events(home: &Path) -> Vec<Value> {
    let path = home.join(".kv/audit.jsonl");
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "api_call")
        .map(|mut event| {
            for field in ["ts", "duration_ms"] {
                event.as_object_mut().unwrap().remove(field);
            }
            event
        })
        .collect()
}

fn assert_api_responses_equal(expected: &Value, actual: &Value, label: &str) {
    assert_eq!(actual, expected, "API parity: {label}");
    if label.starts_with("200") {
        assert!(
            !actual.to_string().contains(API_SECRET),
            "provider credential leaked in API response"
        );
    }
}

fn exercise_sequence(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    certificate: &Path,
    python_client: bool,
) -> Vec<(String, Value)> {
    api_cases()
        .into_iter()
        .map(|(label, fields)| {
            let result = if python_client {
                python_api_request(python, root, home, certificate, &fields)
            } else {
                rust_api_request(root, &fields)
            };
            (label, result)
        })
        .collect()
}

#[test]
fn api_broker_matches_python_over_local_https_and_refusals_do_not_send() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 5a API end-to-end parity: set KV_PY_REF");
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap();
    let temp = TestDir::new();
    let mut server = HttpsServer::start(&python, &temp.0);
    let base_url = format!("https://127.0.0.1:{}", server.port);
    let (master, passphrase) = fixture_master_key();

    let rust_root = temp.0.join("rust-vault");
    let rust_home = temp.0.join("rust-home");
    fs::create_dir(&rust_root).unwrap();
    fs::create_dir(&rust_home).unwrap();
    let rust_root = fs::canonicalize(rust_root).unwrap();
    let rust_home = fs::canonicalize(rust_home).unwrap();
    let _rust_home = HomeGuard::set(&rust_home);
    let rust_store = configure_vault(
        &rust_root,
        &python,
        &rust_home,
        &passphrase,
        &base_url,
        &master,
    );
    let rust_trust =
        TrustContext::at_unlock(&rust_root, Some(passphrase.as_bytes()), &master).unwrap();
    let caller = ApiCaller::with_test_ca_for_test(Arc::new(LocalSafety), &server.certificate_der)
        .expect("construct test-only TLS caller");
    let caller = Arc::new(caller);
    let rust_join_root = rust_root.clone();
    let rust_join = thread::spawn(move || {
        run_agent_with_api_caller(rust_join_root, rust_store, master, rust_trust, caller)
    });
    let mut rust_daemon = RunningAgent {
        root: rust_root.clone(),
        join: Some(rust_join),
    };
    wait_for_socket(&rust_root);
    let rust_results = exercise_sequence(
        &python,
        &rust_root,
        &rust_home,
        &temp.0.join("test-ca.pem"),
        true,
    );
    let rust_audit = api_events(&rust_home);
    rust_daemon.stop();

    let python_root = temp.0.join("python-vault");
    let python_home = temp.0.join("python-home");
    fs::create_dir(&python_root).unwrap();
    fs::create_dir(&python_home).unwrap();
    let python_root = fs::canonicalize(python_root).unwrap();
    let python_home = fs::canonicalize(python_home).unwrap();
    let _python_home = HomeGuard::set(&python_home);
    configure_vault(
        &python_root,
        &python,
        &python_home,
        &passphrase,
        &base_url,
        &fixture_master_key().0,
    );
    let mut python_daemon = start_python_daemon(
        &python,
        &python_root,
        &python_home,
        &temp.0.join("test-ca.pem"),
        &temp.0.join("python-daemon.log"),
    );
    wait_for_socket(&python_root);
    let python_results = exercise_sequence(
        &python,
        &python_root,
        &python_home,
        &temp.0.join("test-ca.pem"),
        false,
    );
    let python_audit = api_events(&python_home);
    let _ = python_control_request(&python, &python_root, &python_home, "stop");
    let deadline = Instant::now() + Duration::from_secs(10);
    while python_daemon.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        python_daemon.0.try_wait().unwrap().is_some(),
        "Python daemon did not stop"
    );

    assert_eq!(rust_results.len(), 9);
    assert_eq!(python_results.len(), 9);
    for ((label, rust), (python_label, python_answer)) in rust_results.iter().zip(&python_results) {
        assert_eq!(label, python_label);
        assert_api_responses_equal(python_answer, rust, label);
    }
    assert_eq!(rust_audit.len(), 9);
    assert_eq!(python_audit.len(), 9);
    for (rust, python) in rust_audit.iter().zip(&python_audit) {
        let mut rust_keys = rust.as_object().unwrap().keys().collect::<Vec<_>>();
        let mut python_keys = python.as_object().unwrap().keys().collect::<Vec<_>>();
        rust_keys.sort();
        python_keys.sort();
        assert_eq!(rust_keys, python_keys, "audit field sets differ");
    }
    let without_chain_hashes = |events: &[Value]| {
        events
            .iter()
            .map(|event| {
                let mut event = event.clone();
                event.as_object_mut().unwrap().remove("hash");
                event.as_object_mut().unwrap().remove("prev");
                event
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        without_chain_hashes(&rust_audit),
        without_chain_hashes(&python_audit),
        "API audit fields differ"
    );

    let observed = server.observed();
    assert_eq!(observed.len(), 8, "refused API requests reached the server");
    for request in observed {
        assert_eq!(request["method"], "GET");
        assert_eq!(
            request["authorization"],
            format!("Bearer {API_SECRET}"),
            "allowed request did not carry broker-owned authentication"
        );
        assert!(
            request["path"].as_str().unwrap().starts_with("/api/"),
            "unexpected request target reached local HTTPS server"
        );
    }
    assert!(
        server.child.try_wait().unwrap().is_none(),
        "local HTTPS server stopped unexpectedly"
    );
}
