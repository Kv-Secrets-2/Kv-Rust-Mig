#![cfg(unix)]
//! Stage 6c: the daemon's `run` command against Python 0.4.0 on the same
//! vault, plus the stop that waits for a running program.

#[path = "../../../tests/support/harness.rs"]
mod harness;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kv_agent::{TrustContext, run_agent};
use kv_crypto::{Key32, keyfile};
use kv_store::DrawerStore;
use serde_json::{Map, Value, json};

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
    kv_proto::agent_request(root, cmd, &fields).unwrap()
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

/// A vault both daemons can serve: fixture key rebound here, config approved.
struct Vault {
    _temp: TestDir,
    _home_guard: HomeGuard,
    root: PathBuf,
    home: PathBuf,
    master: Key32,
    passphrase: String,
}

fn prepare_vault(python: &std::ffi::OsStr, tag: &str) -> Vault {
    let temp = TestDir(harness::socket_temp_dir(tag, "home"));
    let home = temp.0.join("home");
    fs::create_dir(&home).unwrap();
    let home_guard = HomeGuard::set(&home);
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
    kv_store::config_authority::approve_config_unattended(&root, &master).unwrap();
    Vault {
        _temp: temp,
        _home_guard: home_guard,
        root,
        home,
        master,
        passphrase,
    }
}

fn start_rust_daemon(vault: &Vault) -> thread::JoinHandle<Result<Value, kv_agent::AgentError>> {
    let store = Arc::new(DrawerStore::open(
        vault.root.join(".secrets"),
        Key32::new(*vault.master.as_bytes()),
    ));
    let master = Key32::new(*vault.master.as_bytes());
    let trust =
        TrustContext::at_unlock(&vault.root, Some(vault.passphrase.as_bytes()), &master).unwrap();
    let root = vault.root.clone();
    let join = thread::spawn(move || run_agent(root, store, master, trust));
    wait_for_socket(&vault.root);
    join
}

fn start_python_daemon(python: &std::ffi::OsStr, vault: &Vault) -> ChildGuard {
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
    let log = fs::File::create(vault.root.join("python-daemon.log")).unwrap();
    let child = Command::new(python)
        .arg("-c")
        .arg(PYTHON_DAEMON)
        .arg(&vault.root)
        .arg(&vault.passphrase)
        .env("HOME", &vault.home)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    wait_for_socket(&vault.root);
    ChildGuard(child)
}

/// Whether the daemon will find a trusted bubblewrap (the same lookup it makes).
fn bwrap_installed() -> bool {
    kv_sandbox::bwrap::bwrap_path().is_some()
}

fn stop_daemon(root: &Path) {
    let _ = rust_request(root, "stop", &json!({"choice": "now"}));
    let socket = kv_proto::agent_socket_path(Some(root)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
}

/// Fields that legitimately differ between the two daemons on one request.
fn comparable(mut value: Value) -> Value {
    if let Some(map) = value.as_object_mut() {
        map.remove("run_id");
        map.remove("audit_warning");
        // Each daemon files its own pending request: a fresh id and its own clock.
        for key in ["approval_request", "policy_request"] {
            if let Some(request) = map.get_mut(key).and_then(Value::as_object_mut) {
                let id = request
                    .get("request_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                request.remove("expires_at");
                if let Some(id) = id {
                    for (_, field) in request.iter_mut() {
                        if let Some(text) = field.as_str() {
                            *field = Value::String(text.replace(&id, "<request_id>"));
                        }
                    }
                }
            }
        }
    }
    value
}

fn run_cases(root: &Path, project: &Path) -> Vec<(&'static str, Value)> {
    let project = project.to_string_lossy().into_owned();
    let secrets_script = Path::new(&root)
        .join(".secrets/evil.py")
        .to_string_lossy()
        .into_owned();
    vec![
        (
            "echo",
            json!({"argv": ["/bin/echo", "hello run"], "env_names": [], "cwd": project}),
        ),
        (
            "exit code",
            json!({"argv": ["/bin/sh", "-c", "exit 3"], "env_names": [], "cwd": project}),
        ),
        (
            "shell with secrets",
            json!({"argv": ["bash", "-c", "env"], "cwd": project}),
        ),
        (
            "relative cwd",
            json!({"argv": ["/bin/echo", "x"], "env_names": [], "cwd": "relative/dir"}),
        ),
        (
            "missing cwd",
            json!({"argv": ["/bin/echo", "x"], "env_names": [], "cwd": format!("{project}/nowhere")}),
        ),
        (
            "script in vault",
            json!({"argv": ["python3", secrets_script], "env_names": [], "cwd": project}),
        ),
        (
            "secrets without grant",
            json!({"argv": ["/bin/echo", "x"], "env_names": ["API_KEY"], "cwd": project,
            "audit_ctx": {"source": "mcp", "client_name": "codex", "session_id": "s-1"}}),
        ),
        (
            "unnamed secrets",
            json!({"argv": ["/bin/echo", "x"], "cwd": project}),
        ),
        (
            "capability without grant",
            json!({"argv": ["/bin/echo", "x"], "capability_names": ["api:openai"], "cwd": project}),
        ),
        (
            "bad capability",
            json!({"argv": ["/bin/echo", "x"], "capability_names": ["ssh:host"], "cwd": project}),
        ),
        (
            "mixed",
            json!({"argv": ["/bin/echo", "x"], "env_names": ["A"], "capability_names": ["api:x"], "cwd": project}),
        ),
        ("argv missing", json!({"cwd": project})),
        (
            "argv too long",
            json!({"argv": (0..51).map(|i| i.to_string()).collect::<Vec<_>>(), "env_names": []}),
        ),
        (
            "private_cwd type",
            json!({"argv": ["/bin/echo", "x"], "env_names": [], "private_cwd": "yes"}),
        ),
    ]
}

#[test]
fn run_replies_match_python_on_the_same_vault() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Stage 6c run parity: set KV_PY_REF");
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let vault = prepare_vault(&python, "r6");
    let project = vault.root.join("project");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("app.py"), "print('hi')\n").unwrap();

    let python_daemon = start_python_daemon(&python, &vault);
    let mut python_replies = Vec::new();
    for (name, fields) in run_cases(&vault.root, &project) {
        python_replies.push((
            name,
            python_agent_request(&python, &vault.root, &vault.home, "run", &fields),
        ));
    }
    let python_tracked = python_agent_request(
        &python,
        &vault.root,
        &vault.home,
        "tracked_files",
        &json!({}),
    );
    let python_check = python_agent_request(
        &python,
        &vault.root,
        &vault.home,
        "check_file",
        &json!({"path": project.join("app.py")}),
    );
    stop_daemon(&vault.root);
    drop(python_daemon);

    let join = start_rust_daemon(&vault);
    let mut filed = 0;
    for ((name, fields), (_, expected)) in run_cases(&vault.root, &project)
        .into_iter()
        .zip(&python_replies)
    {
        let actual = rust_request(&vault.root, "run", &fields);
        assert_eq!(
            comparable(actual.clone()),
            comparable(expected.clone()),
            "run case {name:?} differs"
        );
        if expected.get("approval_request").is_some() {
            // Both daemons filed a pending request of their own for the missing grant.
            assert_eq!(actual["approval_request"]["status"], "pending", "{name:?}");
            assert_ne!(
                actual["approval_request"]["request_id"],
                expected["approval_request"]["request_id"]
            );
            filed += 1;
        }
        if expected.get("run_id").is_some() {
            let id = actual["run_id"].as_str().unwrap_or("");
            assert!(
                id.starts_with("run_") && id.len() == 28,
                "run id shape: {actual}"
            );
        }
    }
    // Without bubblewrap both daemons refuse a secret- or capability-bearing run before
    // admission, so no request is filed; with it, each files its own pending request.
    if bwrap_installed() {
        assert!(
            filed >= 2,
            "secrets and capability cases without a grant file requests: {filed}"
        );
    }
    assert_eq!(
        rust_request(&vault.root, "tracked_files", &json!({})),
        python_tracked
    );
    assert_eq!(
        rust_request(
            &vault.root,
            "check_file",
            &json!({"path": project.join("app.py")})
        ),
        python_check
    );
    stop_daemon(&vault.root);
    join.join().unwrap().unwrap();
}

#[test]
fn stop_waits_for_a_running_program_and_ends_it_on_now() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Stage 6c stop/run: set KV_PY_REF");
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_installed() {
        eprintln!("SKIP Stage 6c stop parity: bubblewrap is not installed, so no run starts");
        return;
    }
    let vault = prepare_vault(&python, "s6r");
    let project = vault.root.join("project");
    fs::create_dir(&project).unwrap();
    let join = start_rust_daemon(&vault);
    let root = vault.root.clone();
    let project_text = project.to_string_lossy().into_owned();
    let runner = thread::spawn(move || {
        rust_request(
            &root,
            "run",
            &json!({"argv": ["/bin/sleep", "30"], "env_names": [], "cwd": project_text}),
        )
    });
    // A stop with nothing in flight stops at once (Python too), so wait for the
    // program itself before asking.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let found = Command::new("pgrep")
            .args(["-f", "^/bin/sleep 30$"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if found {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let first = rust_request(&vault.root, "stop", &json!({}));
    assert_eq!(first["awaiting_choice"], json!(true), "{first}");
    assert_eq!(first["in_flight"], json!(1), "{first}");
    assert_eq!(first["runs"][0]["program"], json!("sleep"), "{first}");
    let started = Instant::now();
    let drained = rust_request(&vault.root, "stop", &json!({"choice": "now"}));
    assert!(started.elapsed() < Duration::from_secs(12), "{drained}");
    assert_eq!(drained["stopping"], json!(true), "{drained}");
    assert_eq!(drained["wait_seconds"], json!(10), "{drained}");
    assert_eq!(
        drained["ended_runs"][0]["program"],
        json!("sleep"),
        "{drained}"
    );
    let reply = runner.join().unwrap();
    assert_eq!(reply["error_code"], json!("run_ended_by_stop"), "{reply}");
    assert_eq!(reply["ended_by_stop"], json!(true), "{reply}");
    assert_eq!(reply["exit_code"], json!(1), "{reply}");
    assert!(
        reply["error"]
            .as_str()
            .unwrap()
            .starts_with("the run was ended because the agent stopped (run run_")
    );
    join.join().unwrap().unwrap();
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

/// A secret-bearing run admitted by an owner-signed grant: the secret reaches the program
/// (under bubblewrap, through the sealed descriptor) and only `[REDACTED]` reaches the caller;
/// the one-use grant is spent; both daemons answer alike.
#[test]
fn secret_bearing_run_with_an_owner_grant_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Stage 6c grant run parity: set KV_PY_REF");
        return;
    };
    if !bwrap_installed() {
        eprintln!("SKIP Stage 6c grant run parity: bubblewrap is not installed");
        return;
    }
    let _home_lock = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let vault = prepare_vault(&python, "g6");
    let project = vault.root.join("project");
    fs::create_dir(&project).unwrap();
    let script = project.join("show.py");
    fs::write(
        &script,
        "import os\nprint('key', os.environ['API_KEY'])\nprint('kept', os.environ.get('MULTILINE'))\nprint('done')\n",
    )
    .unwrap();
    let actor = json!({"source": "mcp", "client_name": "codex", "session_id": "s-1"});
    let grant_case = json!({
        "argv": ["python3", script], "cwd": project, "secret_names": ["API_KEY"],
        "actor": actor, "env": "dev",
    });
    let run_fields = json!({
        "argv": ["python3", script], "env_names": ["API_KEY"], "cwd": project,
        "audit_ctx": actor,
    });

    let python_daemon = start_python_daemon(&python, &vault);
    sign_grant_for_running_daemon(&python, &vault, &grant_case);
    let python_first = python_agent_request(&python, &vault.root, &vault.home, "run", &run_fields);
    let python_second = python_agent_request(&python, &vault.root, &vault.home, "run", &run_fields);
    stop_daemon(&vault.root);
    drop(python_daemon);

    let join = start_rust_daemon(&vault);
    sign_grant_for_running_daemon(&python, &vault, &grant_case);
    let rust_first = rust_request(&vault.root, "run", &run_fields);
    let rust_second = rust_request(&vault.root, "run", &run_fields);
    stop_daemon(&vault.root);
    join.join().unwrap().unwrap();

    assert_eq!(
        python_first.get("stdout").and_then(Value::as_str),
        Some("key [REDACTED]\nkept None\ndone\n"),
        "python first: {python_first}"
    );
    assert_eq!(
        comparable(rust_first.clone()),
        comparable(python_first.clone()),
        "admitted run differs"
    );
    assert_eq!(
        comparable(rust_second.clone()),
        comparable(python_second.clone()),
        "spent-grant run differs"
    );
    assert_eq!(
        python_second["exit_code"],
        json!(1),
        "python second: {python_second}"
    );
}
