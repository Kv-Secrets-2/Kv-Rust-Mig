//! Stage 9b-4a: `kv approvals approve <permit_request_id>` against both daemons. Each
//! daemon in turn serves the same fixture vault; an agent's POST asks for a one-call
//! permit, the owner approves it on a terminal with the Rust `kv` and with Python's,
//! and the retried call is sent once. Compared: the terminal transcript (ids and times
//! masked), the exit codes, the daemon's view of the retry.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/owner.rs"]
mod owner;

use std::ffi::OsStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, LazyLock};
use std::thread;
use std::time::{Duration, Instant};

use kv_agent::{TrustContext, run_agent_with_api_caller};
use kv_broker::{ApiCaller, UrlSafety};
use kv_crypto::{Key32, keyfile};
use kv_store::DrawerStore;
use owner::{kv_bin, pty};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{Value, json};
use url::Url;

const HOST: &str = "permit-fixture.example";
const API_SECRET: &str = "permit-fixture-secret";
const YES: &str = "\\[y/N\\] =>y";

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v0.4.0")
}

fn permits_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../kv-agent/tests/fixtures/permits.py")
}

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

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TestDir(PathBuf);
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn wait_until(what: &str, bound: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + bound;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

struct LocalOnly;
impl UrlSafety for LocalOnly {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        if url.host_str() == Some(HOST) {
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
        } else {
            Err("permit fixture only permits its public-shaped hostname".into())
        }
    }
}

/// Provenance is tied to HOME, so vault setup and the Rust daemon run in a child test
/// process with the fixture's private HOME (the stage 5 permit tests' pattern).
#[test]
fn approvals_daemon_helper() {
    let Some(root) = std::env::var_os("KV_APPROVALS_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let master = Key32::new(FIXTURE_KEY.0);
    if std::env::var_os("KV_APPROVALS_SETUP").as_deref() == Some(OsStr::new("1")) {
        kv_store::config_authority::approve_config_unattended(&root, &master).unwrap();
        DrawerStore::open(root.join(".secrets"), Key32::new(FIXTURE_KEY.0))
            .set_secret("dev", "API_TOKEN", API_SECRET, 1)
            .unwrap();
        return;
    }
    let ca = fs::read(std::env::var_os("KV_APPROVALS_CA").unwrap()).unwrap();
    let store = Arc::new(DrawerStore::open(
        root.join(".secrets"),
        Key32::new(FIXTURE_KEY.0),
    ));
    let trust = TrustContext::at_unlock(&root, Some(FIXTURE_KEY.1.as_bytes()), &master).unwrap();
    let caller = ApiCaller::with_test_ca_for_test(Arc::new(LocalOnly), &ca).unwrap();
    run_agent_with_api_caller(root, store, master, trust, Arc::new(caller)).unwrap();
}

struct Scenario {
    _server: ChildGuard,
    temp: TestDir,
    root: PathBuf,
    home: PathBuf,
    control: PathBuf,
    socket: PathBuf,
}

impl Scenario {
    fn new(python: &OsStr) -> Self {
        // Short enough for a Unix socket path: /tmp/kvap<pid>/home/.kv/agent-<hash>.sock.
        let temp = TestDir(std::env::temp_dir().join(format!("kvap{}", std::process::id())));
        let _ = fs::remove_dir_all(&temp.0);
        fs::create_dir(&temp.0).unwrap();
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
            .push(DnType::OrganizationName, "Approvals fixture CA");
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
        let server = ChildGuard(
            Command::new(python)
                .arg("-I")
                .arg(permits_script())
                .arg("server")
                .arg(temp.0.join("server.pem"))
                .arg(temp.0.join("server.key"))
                .arg(control.join("observed.jsonl"))
                .arg(&control)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(fs::File::create(temp.0.join("server.log")).unwrap())
                .spawn()
                .unwrap(),
        );
        wait_until("HTTPS fixture", Duration::from_secs(15), || {
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
        let setup = Command::new(python)
            .args(["-I", "-c", "import sys; from kv.vault_origin import record_created; from kv.owner_key import relocate_key_file; record_created(sys.argv[1]); relocate_key_file(sys.argv[1], sys.argv[2])"])
            .arg(&root)
            .arg(&FIXTURE_KEY.1)
            .env("HOME", &home)
            .output()
            .unwrap();
        assert!(
            setup.status.success(),
            "fixture setup: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let config_path = root.join(".secrets/config.json");
        let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config["providers"]["permit-local"] = json!({
            "base_url": base_url, "secret_name": "API_TOKEN", "auth_type": "bearer"
        });
        config["broker_policy"]["http"]["permit-local"] = json!({
            "origin": base_url, "secret_name": "API_TOKEN",
            "rules": [{"id": "local-write", "methods": ["POST"], "path_prefix": "/api", "approval": "per-call"}]
        });
        config["security"]["approval_mode"] = json!("local-convenience");
        fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let approve = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "approvals_daemon_helper", "--nocapture"])
            .env("KV_APPROVALS_SETUP", "1")
            .env("KV_APPROVALS_ROOT", &root)
            .env("HOME", &home)
            .output()
            .unwrap();
        assert!(
            approve.status.success(),
            "fixture approval: {}",
            String::from_utf8_lossy(&approve.stderr)
        );
        let hash = kv_proto::project_hash(Some(&root)).unwrap();
        let socket = home.join(".kv").join(format!("agent-{hash}.sock"));
        Self {
            _server: server,
            temp,
            root,
            home,
            control,
            socket,
        }
    }

    fn start(&self, python: &OsStr, rust: bool) -> ChildGuard {
        let mut command = if rust {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "approvals_daemon_helper", "--nocapture"])
                .env("KV_APPROVALS_ROOT", &self.root)
                .env("KV_APPROVALS_CA", self.temp.0.join("ca.der"));
            command
        } else {
            let mut command = Command::new(python);
            command
                .arg("-I")
                .arg(permits_script())
                .arg("daemon")
                .arg(&self.root)
                .arg(&FIXTURE_KEY.1)
                .arg(&self.control)
                .arg("protected");
            command
        };
        let log = self.temp.0.join(if rust {
            "rust-daemon.log"
        } else {
            "python-daemon.log"
        });
        let child = ChildGuard(
            command
                .env("HOME", &self.home)
                .env("SSL_CERT_FILE", self.temp.0.join("ca.pem"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(fs::File::create(&log).unwrap())
                .spawn()
                .unwrap(),
        );
        wait_until("daemon socket", Duration::from_secs(30), || {
            self.socket.exists()
        });
        child
    }

    /// Python's `agent_request` from the fixture HOME (the token lives there).
    fn request(&self, python: &OsStr, cmd: &str, fields: &Value) -> Value {
        let output = Command::new(python)
            .args(["-I", "-c", "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request(sys.argv[1], project_root=sys.argv[2], **json.loads(sys.argv[3]))))"])
            .arg(cmd)
            .arg(&self.root)
            .arg(fields.to_string())
            .env("HOME", &self.home)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "agent_request {cmd}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn stop(&self, python: &OsStr, mut daemon: ChildGuard) {
        let _ = self.request(python, "stop", &json!({}));
        wait_until("daemon exit", Duration::from_secs(15), || {
            daemon.0.try_wait().unwrap().is_some()
        });
        drop(daemon);
        // A stale socket from a daemon that did not unlink it would make the next
        // daemon's start look immediate.
        let _ = fs::remove_file(&self.socket);
    }

    fn observed(&self) -> usize {
        fs::read_to_string(self.control.join("observed.jsonl"))
            .unwrap_or_default()
            .lines()
            .count()
    }
}

fn call() -> Value {
    json!({"provider": "permit-local", "path": "/api/items", "method": "POST",
        "body": {"message": "approvals-parity", "count": 1}})
}

/// Ids and times differ between the two daemons; the words must not.
fn masked(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.trim_start().starts_with("Session: ") {
                return "  Session: <nonce>".to_owned();
            }
            line.split(' ')
                .map(|word| {
                    let core = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
                    if core.starts_with("permit_request_") || core.starts_with("permit_") {
                        word.replace(core, "<id>")
                    } else if core.len() >= 19 && core.contains('T') && core.contains(':') {
                        word.replace(core, "<time>")
                    } else {
                        word.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn approving_a_one_call_permit_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP approvals permit parity: set KV_PY_REF");
        return;
    };
    let python_str = python.to_str().unwrap();
    let scenario = Scenario::new(&python);
    let passphrase_rule = format!("Passphrase: =>{}", FIXTURE_KEY.1);
    let mut transcripts = Vec::new();
    for rust_daemon in [false, true] {
        let daemon = scenario.start(&python, rust_daemon);
        for rust_cli in [true, false] {
            let required = scenario.request(&python, "api", &call());
            assert_eq!(required["error_code"], "permit_required", "{required}");
            let request_id = required["request_id"].as_str().unwrap().to_owned();
            let cmd: Vec<&str> = if rust_cli {
                vec![kv_bin()]
            } else {
                vec![python_str, "-m", "kv"]
            };
            let before = scenario.observed();
            let (code, text) = pty(
                python_str,
                &cmd,
                &scenario.home,
                &scenario.root,
                &["approvals", "approve", &request_id],
                &[&passphrase_rule, YES],
            );
            assert_eq!(code, 0, "approve ({rust_daemon},{rust_cli}): {text}");
            assert!(text.contains("One-call permit approved."), "{text}");
            let mut retry = call();
            retry["permit_id"] = required["permit_id"].clone();
            let sent = scenario.request(&python, "api", &retry);
            assert_eq!(
                sent["status"], 200,
                "retry ({rust_daemon},{rust_cli}): {sent}"
            );
            assert_eq!(
                scenario.observed(),
                before + 1,
                "the provider saw the call once"
            );
            let replay = scenario.request(&python, "api", &retry);
            assert_eq!(replay["error_code"], "permit_invalid", "{replay}");
            transcripts.push(masked(&text));
        }
        scenario.stop(&python, daemon);
    }
    // Rust CLI vs Python CLI on each daemon, and each CLI across the two daemons.
    assert_eq!(
        transcripts[0], transcripts[1],
        "CLIs differ on the Python daemon"
    );
    assert_eq!(
        transcripts[2], transcripts[3],
        "CLIs differ on the Rust daemon"
    );
    assert_eq!(
        transcripts[0], transcripts[2],
        "daemons differ for the Rust CLI"
    );
    println!("KV_PARITY_COMPARISONS 1");
}
