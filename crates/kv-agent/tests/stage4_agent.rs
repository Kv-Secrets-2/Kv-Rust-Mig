#![cfg(unix)]

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use kv_agent::{AgentError, TrustContext, run_agent};
use kv_crypto::{Key32, keyfile};
use kv_store::DrawerStore;
use serde_json::{Map, Value, json};

static HOME_LOCK: Mutex<()> = Mutex::new(());

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).expect("test randomness");
        let path = std::env::temp_dir().join(format!(
            "kv-agent-stage4-{}-{}",
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
    // SAFETY: Every caller holds HOME_LOCK for the full lifetime of this mutation.
    unsafe {
        if let Some(home) = home {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }
    }
}

struct RunningAgent {
    root: PathBuf,
    join: Option<JoinHandle<Result<Value, AgentError>>>,
}

impl RunningAgent {
    fn stop_and_join(&mut self) -> Result<Value, AgentError> {
        if self.join.is_none() {
            return Ok(Value::Null);
        }
        let response = kv_proto::agent_request(&self.root, "stop", &Map::new())
            .map_err(|error| AgentError(error.to_string()))?;
        let result = self
            .join
            .take()
            .expect("agent thread")
            .join()
            .map_err(|_| AgentError("agent thread panicked".into()))??;
        assert_eq!(response["stopping"], true);
        Ok(result)
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
        .env("PYTHONPATH", "/home/ubuntu/repos/kv-secrets")
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

fn status_without_run_fields(mut value: Value) -> Value {
    if let Some(status) = value.as_object_mut() {
        for field in ["pid", "session_nonce", "root"] {
            status.remove(field);
        }
    }
    value
}

fn assert_status_fields_equal(expected: &Value, actual: &Value) {
    let expected = expected.as_object().expect("expected status object");
    let actual = actual.as_object().expect("actual status object");
    let mut expected_keys = expected.keys().collect::<Vec<_>>();
    let mut actual_keys = actual.keys().collect::<Vec<_>>();
    for fields in [&mut expected_keys, &mut actual_keys] {
        fields.retain(|key| !matches!(key.as_str(), "pid" | "session_nonce" | "root"));
        fields.sort();
    }
    assert_eq!(expected_keys, actual_keys, "status field sets differ");
    for field in expected_keys {
        assert_eq!(
            expected[field], actual[field],
            "status field differs: {field}"
        );
    }
}

struct DaemonChild(Child);

impl DaemonChild {
    fn wait_for_socket(&mut self, socket: &Path, log: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if socket.exists() {
                return;
            }
            if let Some(status) = self.0.try_wait().expect("check daemon process") {
                panic!(
                    "daemon exited before opening its socket ({status}): {}",
                    fs::read_to_string(log).unwrap_or_default()
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "daemon did not open its socket: {}",
            fs::read_to_string(log).unwrap_or_default()
        );
    }

    fn wait(&mut self) -> ExitStatus {
        self.0.wait().expect("wait for daemon process")
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn spawn_python_daemon(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    passphrase: &str,
    log: &Path,
) -> DaemonChild {
    const PYTHON_DAEMON: &str = r#"
import sys
from kv.agent import run_agent
from kv.config import get_default_env
from kv.store import SecretStore
from kv.trust import TrustContext
root,passphrase=sys.argv[1:3]
store=SecretStore(root,passphrase=passphrase)
master=store.master_key
store.pin()
store.trust=TrustContext.at_unlock(root,passphrase,master)
run_agent(store,get_default_env(root))
"#;
    let stderr = fs::File::create(log).expect("create Python daemon log");
    DaemonChild(
        Command::new(python)
            .arg("-c")
            .arg(PYTHON_DAEMON)
            .arg(root)
            .arg(passphrase)
            .env("HOME", home)
            .env("PYTHONPATH", "/home/ubuntu/repos/kv-secrets")
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("start Python daemon"),
    )
}

fn spawn_rust_daemon(root: &Path, home: &Path, passphrase: &str, log: &Path) -> DaemonChild {
    let stderr = fs::File::create(log).expect("create Rust daemon log");
    DaemonChild(
        Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "rust_daemon_subprocess_helper", "--nocapture"])
            .env("KV_AGENT_CHILD_ROOT", root)
            .env("KV_AGENT_CHILD_PASSPHRASE", passphrase)
            .env("HOME", home)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("start Rust daemon"),
    )
}

fn bad_token_client_request(root: &Path) -> Value {
    let fields = [(
        "token".to_owned(),
        Value::String("not-the-agent-token".into()),
    )]
    .into_iter()
    .collect::<Map<_, _>>();
    kv_proto::agent_request(root, "status", &fields).unwrap()
}

fn raw_socket_request(socket_path: &Path, request: &[u8]) -> Vec<u8> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut socket = UnixStream::connect(socket_path).expect("connect raw agent request");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.write_all(request).expect("write raw agent request");
    socket.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    socket
        .read_to_end(&mut reply)
        .expect("read raw agent reply");
    reply
}

fn malformed_request_cases() -> [Vec<u8>; 3] {
    [vec![b' '; kv_proto::MAX_MSG + 1], b"{".to_vec(), vec![0xff]]
}

fn rebind_fixture_key(python: &std::ffi::OsStr, root: &Path, home: &Path, passphrase: &str) {
    run_python(
        python,
        "import json,sys\nfrom kv.owner_key import relocate_key_file\nprint(json.dumps(relocate_key_file(sys.argv[1],sys.argv[2])))",
        root,
        home,
        &[passphrase],
    );
}

#[test]
fn rust_daemon_subprocess_helper() {
    let (Some(root), Some(passphrase)) = (
        std::env::var_os("KV_AGENT_CHILD_ROOT"),
        std::env::var_os("KV_AGENT_CHILD_PASSPHRASE"),
    ) else {
        return;
    };
    let root = PathBuf::from(root);
    let passphrase = passphrase.to_string_lossy();
    let (master, _) = fixture_master_key();
    let store = Arc::new(DrawerStore::open(
        root.join(".secrets"),
        Key32::new(*master.as_bytes()),
    ));
    let trust = TrustContext::at_unlock(&root, Some(passphrase.as_bytes()), &master).unwrap();
    run_agent(root, store, master, trust).unwrap();
}

#[test]
fn python_client_matches_rust_agent_and_stop_cleans_runtime_files() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 4a daemon parity: set KV_PY_REF");
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap();
    let temp = TestDir::new();
    let home = temp.0.join("home");
    fs::create_dir(&home).unwrap();
    let _home_guard = HomeGuard::set(&home);
    let root = temp.0.join("vault");
    fs::create_dir(&root).unwrap();
    copy_dir(
        &fixture_root().join("vaults/basic/.secrets"),
        &root.join(".secrets"),
    );
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let home = fs::canonicalize(home).unwrap();
    let (master, passphrase) = fixture_master_key();
    run_python(
        &python,
        "import json,sys\nfrom kv import vault_origin\nprint(json.dumps(vault_origin.record_created(sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    rebind_fixture_key(&python, &root, &home, &passphrase);
    kv_store::config_authority::approve_config_unattended(&root, &master).unwrap();
    let store = Arc::new(DrawerStore::open(
        root.join(".secrets"),
        Key32::new(*master.as_bytes()),
    ));
    let trust = TrustContext::at_unlock(&root, Some(passphrase.as_bytes()), &master).unwrap();
    let daemon_root = root.clone();
    let join = thread::spawn(move || run_agent(daemon_root, store, master, trust));
    let mut running = RunningAgent {
        root: root.clone(),
        join: Some(join),
    };

    let socket_path = kv_proto::agent_socket_path(Some(&root)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket_path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        socket_path.exists(),
        "Rust daemon did not create its socket"
    );

    let runtime = kv_proto::runtime_dir().unwrap();
    let token_path = kv_proto::agent_token_path(Some(&root)).unwrap();
    let pid_path = kv_proto::agent_pid_path(Some(&root)).unwrap();
    assert_eq!(
        fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&pid_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    for cmd in ["status", "list", "envs"] {
        let rust_reply =
            kv_proto::agent_request(&root, cmd, &Map::new()).expect("Rust client request");
        let python_reply = run_python(
            &python,
            "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request(sys.argv[2],project_root=sys.argv[1])))",
            &root,
            &home,
            &[cmd],
        );
        if cmd == "status" {
            assert_eq!(
                status_without_run_fields(rust_reply),
                status_without_run_fields(python_reply)
            );
        } else {
            assert_eq!(rust_reply, python_reply);
        }
    }

    let mut invalid = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
    let request = serde_json::to_vec(&json!({
        "cmd":"status",
        "token":"not-the-agent-token",
        "audit_warning":false
    }))
    .unwrap();
    use std::io::{Read, Write};
    invalid.write_all(&request).unwrap();
    invalid.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    invalid.read_to_end(&mut reply).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply).unwrap(),
        json!({"error":"authentication required"})
    );

    assert_eq!(
        kv_proto::agent_request(&root, "lock", &Map::new()).unwrap()["locking"],
        true
    );
    running.stop_and_join().unwrap();
    assert!(!socket_path.exists());
    assert!(!token_path.exists());
    assert!(!pid_path.exists());
}

#[test]
fn agent_status_and_commands_match_in_both_directions() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 4a agent parity: set KV_PY_REF");
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap();
    let temp = TestDir::new();
    let home = temp.0.join("home");
    fs::create_dir(&home).unwrap();
    let _home_guard = HomeGuard::set(&home);
    let root = temp.0.join("vault");
    fs::create_dir(&root).unwrap();
    copy_dir(
        &fixture_root().join("vaults/basic/.secrets"),
        &root.join(".secrets"),
    );
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let home = fs::canonicalize(home).unwrap();
    let (master, passphrase) = fixture_master_key();
    run_python(
        &python,
        "import json,sys\nfrom kv import vault_origin\nprint(json.dumps(vault_origin.record_created(sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    rebind_fixture_key(&python, &root, &home, &passphrase);
    kv_store::config_authority::approve_config_unattended(&root, &master).unwrap();

    let socket_path = kv_proto::agent_socket_path(Some(&root)).unwrap();
    let token_path = kv_proto::agent_token_path(Some(&root)).unwrap();
    let pid_path = kv_proto::agent_pid_path(Some(&root)).unwrap();
    let python_log = temp.0.join("python-agent.log");
    let mut python_daemon = spawn_python_daemon(&python, &root, &home, &passphrase, &python_log);
    python_daemon.wait_for_socket(&socket_path, &python_log);

    let python_status_before = run_python(
        &python,
        "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request('status',project_root=sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    let rust_client_status_before = kv_proto::agent_request(&root, "status", &Map::new()).unwrap();
    assert_status_fields_equal(&python_status_before, &rust_client_status_before);
    assert_eq!(python_status_before["cached_environments"], 0);
    assert_eq!(python_status_before["cached_secrets"], 0);

    let python_list = run_python(
        &python,
        "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request('list',project_root=sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    let rust_list = kv_proto::agent_request(&root, "list", &Map::new()).unwrap();
    assert_eq!(rust_list, python_list);
    let rust_envs = kv_proto::agent_request(&root, "envs", &Map::new()).unwrap();
    let python_envs = run_python(
        &python,
        "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request('envs',project_root=sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    assert_eq!(rust_envs, python_envs);
    assert_eq!(
        bad_token_client_request(&root),
        json!({"error":"authentication required"})
    );

    let python_status_after = run_python(
        &python,
        "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request('status',project_root=sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    let rust_client_status_after = kv_proto::agent_request(&root, "status", &Map::new()).unwrap();
    assert_status_fields_equal(&python_status_after, &rust_client_status_after);
    assert_eq!(python_status_after["cached_environments"], 1);
    assert_eq!(
        python_status_after["cached_secrets"],
        python_status_after["secrets"]
    );

    let malformed_requests = malformed_request_cases();
    let python_error_replies = malformed_requests
        .iter()
        .map(|request| raw_socket_request(&socket_path, request))
        .collect::<Vec<_>>();
    assert_eq!(
        python_error_replies[0],
        br#"{"error": "request exceeds 1048576 bytes"}"#
    );
    assert_eq!(python_error_replies[1], br#"{"error": "invalid JSON"}"#);
    assert_eq!(
        python_error_replies[2],
        br#"{"error": "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"}"#
    );

    assert_eq!(
        kv_proto::agent_request(&root, "lock", &Map::new()).unwrap(),
        json!({"locking":true,"ended":true})
    );
    let python_stop = kv_proto::agent_request(&root, "stop", &Map::new()).unwrap();
    assert_eq!(
        python_stop,
        json!({
            "stopping":true,
            "wait_seconds":10,
            "cut_off":0,
            "ended_runs":[]
        })
    );
    assert!(python_daemon.wait().success());
    assert!(!socket_path.exists());
    assert!(!token_path.exists());
    assert!(!pid_path.exists());

    let rust_log = temp.0.join("rust-agent.log");
    let mut rust_daemon = spawn_rust_daemon(&root, &home, &passphrase, &rust_log);
    rust_daemon.wait_for_socket(&socket_path, &rust_log);

    let rust_status_before = kv_proto::agent_request(&root, "status", &Map::new()).unwrap();
    let python_client_status_before = run_python(
        &python,
        "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request('status',project_root=sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    assert_status_fields_equal(&python_client_status_before, &rust_status_before);
    assert_eq!(rust_status_before["cached_environments"], 0);
    assert_eq!(rust_status_before["cached_secrets"], 0);

    let rust_client_list = kv_proto::agent_request(&root, "list", &Map::new()).unwrap();
    let python_client_list = run_python(
        &python,
        "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request('list',project_root=sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    assert_eq!(python_client_list, rust_client_list);
    let rust_client_envs = kv_proto::agent_request(&root, "envs", &Map::new()).unwrap();
    let python_client_envs = run_python(
        &python,
        "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request('envs',project_root=sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    assert_eq!(python_client_envs, rust_client_envs);
    assert_eq!(
        bad_token_client_request(&root),
        json!({"error":"authentication required"})
    );

    let rust_status_after = kv_proto::agent_request(&root, "status", &Map::new()).unwrap();
    let python_client_status_after = run_python(
        &python,
        "import json,sys\nfrom kv import agent\nprint(json.dumps(agent.agent_request('status',project_root=sys.argv[1])))",
        &root,
        &home,
        &[],
    );
    assert_status_fields_equal(&python_client_status_after, &rust_status_after);
    assert_eq!(rust_status_after["cached_environments"], 1);
    assert_eq!(
        rust_status_after["cached_secrets"],
        rust_status_after["secrets"]
    );
    let rust_error_replies = malformed_requests
        .iter()
        .map(|request| raw_socket_request(&socket_path, request))
        .collect::<Vec<_>>();
    assert_eq!(rust_error_replies, python_error_replies);

    let lock_and_signal = run_python(
        &python,
        r#"
import json,os,signal,sys,time
from kv import agent
root=sys.argv[1]
socket_path=sys.argv[2]
first=agent.agent_request("status",project_root=root)
locked=agent.agent_request("lock",project_root=root)
again=agent.agent_request("status",project_root=root)
pid=first.get("pid")
if locked != {"locking":True,"ended":True} or again.get("pid") != pid:
    raise RuntimeError("Python cmd_lock request sequence was not confirmed")
os.kill(pid,signal.SIGTERM)
deadline=time.monotonic()+5
stopped=False
while time.monotonic()<deadline:
    if not os.path.exists(socket_path):
        stopped=True
        break
    time.sleep(0.05)
print(json.dumps({"lock":locked,"stopped":stopped}))
"#,
        &root,
        &home,
        &[socket_path.to_str().unwrap()],
    );
    assert_eq!(
        lock_and_signal,
        json!({"lock":{"locking":true,"ended":true},"stopped":true})
    );
    assert!(rust_daemon.wait().success());
    assert!(!socket_path.exists());
    assert!(!token_path.exists());
    assert!(!pid_path.exists());

    let stop_log = temp.0.join("rust-stop-agent.log");
    let mut rust_stop_daemon = spawn_rust_daemon(&root, &home, &passphrase, &stop_log);
    rust_stop_daemon.wait_for_socket(&socket_path, &stop_log);
    let rust_stop = kv_proto::agent_request(&root, "stop", &Map::new()).unwrap();
    assert_eq!(rust_stop, python_stop);
    assert!(rust_stop_daemon.wait().success());
    assert!(!socket_path.exists());
    assert!(!token_path.exists());
    assert!(!pid_path.exists());
}

#[test]
fn startup_refusals_match_and_held_pid_file_is_rejected() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 4a startup refusal parity: set KV_PY_REF");
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap();
    let temp = TestDir::new();
    let home = temp.0.join("home");
    fs::create_dir(&home).unwrap();
    let _home_guard = HomeGuard::set(&home);
    let home = fs::canonicalize(home).unwrap();
    let (master, passphrase) = fixture_master_key();

    let unapproved_root = temp.0.join("unapproved-vault");
    fs::create_dir(&unapproved_root).unwrap();
    copy_dir(
        &fixture_root().join("vaults/basic/.secrets"),
        &unapproved_root.join(".secrets"),
    );
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        unapproved_root.join(".secrets/key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let unapproved_root = fs::canonicalize(unapproved_root).unwrap();
    run_python(
        &python,
        "import json,sys\nfrom kv import vault_origin\nprint(json.dumps(vault_origin.record_created(sys.argv[1])))",
        &unapproved_root,
        &home,
        &[],
    );
    rebind_fixture_key(&python, &unapproved_root, &home, &passphrase);
    let unapproved_store = Arc::new(DrawerStore::open(
        unapproved_root.join(".secrets"),
        Key32::new(*master.as_bytes()),
    ));
    let unapproved_trust =
        TrustContext::at_unlock(&unapproved_root, Some(passphrase.as_bytes()), &master).unwrap();
    let rust_refusal = run_agent(
        &unapproved_root,
        unapproved_store,
        Key32::new(*master.as_bytes()),
        unapproved_trust,
    )
    .unwrap_err()
    .to_string();
    let python_refusal = run_python(
        &python,
        r#"
import json,sys
from kv.agent import run_agent
from kv.config import get_default_env
from kv.store import SecretStore
from kv.trust import TrustContext
root,passphrase=sys.argv[1:3]
store=SecretStore(root,passphrase=passphrase)
store.trust=TrustContext.at_unlock(root,passphrase,store.master_key)
try:
    run_agent(store,get_default_env(root))
except Exception as error:
    print(json.dumps(str(error)))
"#,
        &unapproved_root,
        &home,
        &[&passphrase],
    );
    assert_eq!(rust_refusal, python_refusal.as_str().unwrap());

    let approved_root = temp.0.join("approved-vault");
    fs::create_dir(&approved_root).unwrap();
    copy_dir(
        &fixture_root().join("vaults/basic/.secrets"),
        &approved_root.join(".secrets"),
    );
    fs::set_permissions(
        approved_root.join(".secrets/key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let approved_root = fs::canonicalize(approved_root).unwrap();
    run_python(
        &python,
        "import json,sys\nfrom kv import vault_origin\nprint(json.dumps(vault_origin.record_created(sys.argv[1])))",
        &approved_root,
        &home,
        &[],
    );
    rebind_fixture_key(&python, &approved_root, &home, &passphrase);
    kv_store::config_authority::approve_config_unattended(&approved_root, &master).unwrap();

    let runtime = kv_proto::runtime_dir().unwrap();
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let pid_path = kv_proto::agent_pid_path(Some(&approved_root)).unwrap();
    let holder_code = r#"
import fcntl,os,signal,sys,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
stream=open(sys.argv[1],"a+b",buffering=0)
fcntl.lockf(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
stream.seek(0)
stream.truncate()
stream.write(str(os.getpid()).encode())
os.fsync(stream.fileno())
print("ready",flush=True)
time.sleep(30)
"#;
    let holder = Command::new(&python)
        .arg("-c")
        .arg(holder_code)
        .arg(&pid_path)
        .env("HOME", &home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut holder = DaemonChild(holder);
    let mut ready = String::new();
    std::io::BufReader::new(holder.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "ready");

    let store = Arc::new(DrawerStore::open(
        approved_root.join(".secrets"),
        Key32::new(*master.as_bytes()),
    ));
    let trust =
        TrustContext::at_unlock(&approved_root, Some(passphrase.as_bytes()), &master).unwrap();
    let refusal = run_agent(approved_root, store, master, trust)
        .unwrap_err()
        .to_string();
    assert_eq!(
        refusal,
        "Cannot start kv daemon: another kv service for this vault holds its pid file; run 'kv lock' first, or 'kv agent status' for details."
    );
    assert!(holder.0.try_wait().unwrap().is_none());
}
