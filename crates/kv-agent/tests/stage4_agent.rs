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

fn python_agent_request(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    cmd: &str,
    fields: &Value,
) -> Value {
    run_python(
        python,
        "import json,sys\nfrom kv import agent\nfields=json.loads(sys.argv[3])\nprint(json.dumps(agent.agent_request(sys.argv[2],project_root=sys.argv[1],**fields)))",
        root,
        home,
        &[cmd, &fields.to_string()],
    )
}

fn owner_error_shape(answer: &Value, identity: &kv_crypto::Identity, challenge: &[u8]) -> Value {
    let (kind, fields, tag) = kv_approvals::wire::from_json(answer).expect("signed owner reply");
    assert_eq!(kind, kv_approvals::wire::MessageKind::ErrorV1);
    let key = kv_crypto::derive_labeled_key(&identity.master_key, b"kv-approval:daemon-auth", &[]);
    assert!(kv_approvals::wire::verify(
        key.as_ref(),
        kind,
        &fields,
        &tag
    ));
    let reply_challenge = match fields.get("challenge").expect("reply challenge") {
        kv_approvals::wire::FieldValue::Nonce(value) => value,
        _ => panic!("reply challenge is not a nonce"),
    };
    assert_eq!(reply_challenge, challenge);
    let code = match fields.get("code").expect("error code") {
        kv_approvals::wire::FieldValue::Text(value)
        | kv_approvals::wire::FieldValue::Enum(value) => value.clone(),
        _ => panic!("reply code is not text"),
    };
    let session_nonce = match fields.get("session_nonce").expect("session nonce") {
        kv_approvals::wire::FieldValue::Nonce(value) => value.clone(),
        _ => panic!("session nonce is not a nonce"),
    };
    json!({"kind":kind.name(),"code":code,"challenge":reply_challenge,"session_nonce":session_nonce})
}

fn collect_owner_error_shapes(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    identity: &kv_crypto::Identity,
    python_client: bool,
) -> Vec<Value> {
    let mut cases = Vec::new();
    for challenge in [
        "not-hex".to_owned(),
        "a".repeat(63),
        "a".repeat(65),
        " ".repeat(64),
    ] {
        let expected = vec![0_u8; kv_approvals::wire::NONCE_LEN];
        let fields = json!({"challenge":challenge});
        let answer = if python_client {
            python_agent_request(python, root, home, "owner_channel", &fields)
        } else {
            let fields = fields.as_object().unwrap().clone();
            kv_proto::agent_request(root, "owner_channel", &fields).unwrap()
        };
        cases.push(owner_error_shape(&answer, identity, &expected));
    }

    let challenge = "ab".repeat(kv_approvals::wire::NONCE_LEN);
    let challenge_bytes = challenge
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let fields = json!({"challenge":challenge});
    let answer = if python_client {
        python_agent_request(python, root, home, "owner_grant_register", &fields)
    } else {
        kv_proto::agent_request(
            root,
            "owner_grant_register",
            &fields.as_object().unwrap().clone(),
        )
        .unwrap()
    };
    cases.push(owner_error_shape(&answer, identity, &challenge_bytes));

    let config_path = root.join(".secrets/config.json");
    let original_config = fs::read(&config_path).unwrap();
    let mut changed_config: Value = serde_json::from_slice(&original_config).unwrap();
    changed_config
        .as_object_mut()
        .unwrap()
        .entry("providers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap()
        .insert(
            "stage4b-parity-probe".into(),
            json!({"origin":"https://example.invalid","secret":"PARITY_PROBE"}),
        );
    fs::write(&config_path, serde_json::to_vec(&changed_config).unwrap()).unwrap();
    let challenge = "cd".repeat(kv_approvals::wire::NONCE_LEN);
    let challenge_bytes = challenge
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let fields = json!({"challenge":challenge});
    let answer = if python_client {
        python_agent_request(python, root, home, "owner_channel", &fields)
    } else {
        kv_proto::agent_request(root, "owner_channel", &fields.as_object().unwrap().clone())
            .unwrap()
    };
    cases.push(owner_error_shape(&answer, identity, &challenge_bytes));
    fs::write(config_path, original_config).unwrap();
    cases
}

fn exercise_hard_lock(
    python: &std::ffi::OsStr,
    root: &Path,
    moved: &Path,
    home: &Path,
    python_client: bool,
) -> (Value, Value, Value) {
    fs::rename(root, moved).unwrap();
    let normal = if python_client {
        python_agent_request(python, root, home, "list", &json!({}))
    } else {
        kv_proto::agent_request(root, "list", &Map::new()).unwrap()
    };
    let status = if python_client {
        python_agent_request(python, root, home, "status", &json!({}))
    } else {
        kv_proto::agent_request(root, "status", &Map::new()).unwrap()
    };
    fs::rename(moved, root).unwrap();
    let restored = if python_client {
        python_agent_request(python, root, home, "list", &json!({}))
    } else {
        kv_proto::agent_request(root, "list", &Map::new()).unwrap()
    };
    (normal, status, restored)
}

#[derive(Clone, Copy)]
enum ApprovalKeyMutation {
    Replace,
    Change,
    Delete,
    NonRegular,
}

impl ApprovalKeyMutation {
    fn reason(self) -> &'static str {
        match self {
            Self::Replace => "the approval signing key was replaced",
            Self::Change => "the approval signing key changed",
            Self::Delete => "the approval signing key is gone",
            Self::NonRegular => "the approval signing key cannot be read or is not a regular file",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::Change => "change",
            Self::Delete => "delete",
            Self::NonRegular => "non-regular",
        }
    }
}

fn remove_approval_signing_key(root: &Path) {
    let path = root.join(".secrets/approval_signing_key");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path).unwrap(),
        Ok(_) => fs::remove_file(path).unwrap(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("inspect approval signing key path: {error}"),
    }
}

fn mutate_approval_signing_key(root: &Path, mutation: ApprovalKeyMutation) {
    let path = root.join(".secrets/approval_signing_key");
    match mutation {
        ApprovalKeyMutation::Replace => {
            let replacement = path.with_file_name("approval_signing_key.replacement");
            fs::write(&replacement, b"replacement-key\n").unwrap();
            fs::remove_file(&path).unwrap();
            fs::rename(replacement, path).unwrap();
        }
        ApprovalKeyMutation::Change => fs::write(path, b"changed-key\n").unwrap(),
        ApprovalKeyMutation::Delete => fs::remove_file(path).unwrap(),
        ApprovalKeyMutation::NonRegular => {
            fs::remove_file(&path).unwrap();
            fs::create_dir(path).unwrap();
        }
    }
}

fn approval_key_hard_lock(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    passphrase: &str,
    mutation: ApprovalKeyMutation,
    python_daemon: bool,
    log: &Path,
) -> Value {
    remove_approval_signing_key(root);
    let socket_path = kv_proto::agent_socket_path(Some(root)).unwrap();
    let mut daemon = if python_daemon {
        spawn_python_daemon(python, root, home, passphrase, log)
    } else {
        spawn_rust_daemon(root, home, passphrase, log)
    };
    daemon.wait_for_socket(&socket_path, log);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_path = root.join(".secrets/approval_signing_key");
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let key_file = kv_crypto::Zeroizing::new(fs::read(key_path).unwrap());
        assert!(kv_approvals::artifacts::parse_signing_key(&key_file).is_ok());
    }

    mutate_approval_signing_key(root, mutation);
    let normal = if python_daemon {
        python_agent_request(python, root, home, "list", &json!({}))
    } else {
        kv_proto::agent_request(root, "list", &Map::new()).unwrap()
    };
    assert_eq!(normal["error_code"], "vault_hard_locked");
    assert!(
        normal["error"]
            .as_str()
            .unwrap()
            .contains(mutation.reason()),
        "hard-lock reason for {}: {}",
        mutation.name(),
        normal["error"]
    );
    let status = if python_daemon {
        python_agent_request(python, root, home, "status", &json!({}))
    } else {
        kv_proto::agent_request(root, "status", &Map::new()).unwrap()
    };
    assert_eq!(status["hard_locked"], true);
    if python_daemon {
        assert_eq!(
            python_agent_request(python, root, home, "stop", &json!({}))["stopping"],
            true
        );
    } else {
        assert_eq!(
            kv_proto::agent_request(root, "stop", &Map::new()).unwrap()["stopping"],
            true
        );
    }
    assert!(daemon.wait().success());
    normal
}

fn generated_json(seed: usize, depth: usize) -> Value {
    match seed % 9 {
        0 => Value::Null,
        1 => Value::Bool(seed.is_multiple_of(2)),
        2 => json!(seed as i64 - 32),
        3 => json!(format!("owner-case-{seed}-λ")),
        4 if depth > 0 => Value::Array(
            (0..3)
                .map(|offset| generated_json(seed / 3 + offset + 1, depth - 1))
                .collect(),
        ),
        5 if depth > 0 => {
            let mut object = Map::new();
            object.insert("nested".into(), generated_json(seed + 2, depth - 1));
            object.insert(format!("key-{seed}"), generated_json(seed + 5, depth - 1));
            Value::Object(object)
        }
        6 => json!(format!("{:064x}", seed)),
        7 => json!(vec![seed as u8; seed % 17]),
        _ => json!(seed as f64 / 3.0),
    }
}

fn assert_owner_json_property(socket_path: &Path, identity: &kv_crypto::Identity) {
    let key = kv_crypto::derive_labeled_key(&identity.master_key, b"kv-approval:daemon-auth", &[]);
    for seed in 0_usize..128 {
        let mut request = Map::new();
        request.insert(
            "cmd".into(),
            Value::String(if seed.is_multiple_of(2) {
                "owner_channel".into()
            } else {
                "owner_grant_register".into()
            }),
        );
        request.insert("challenge".into(), generated_json(seed, 3));
        request.insert("providers".into(), generated_json(seed + 7, 2));
        request.insert(format!("extra-{seed}"), generated_json(seed + 11, 3));
        let bytes = serde_json::to_vec(&Value::Object(request)).unwrap();
        let answer = raw_socket_request(socket_path, &bytes);
        if answer.is_empty() {
            continue;
        }
        let answer: Value = serde_json::from_slice(&answer).expect("owner reply JSON");
        let (kind, fields, tag) =
            kv_approvals::wire::from_json(&answer).expect("owner reply is signed");
        assert!(kv_approvals::wire::verify(
            key.as_ref(),
            kind,
            &fields,
            &tag
        ));
    }
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

fn python_open_channel(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    passphrase: &str,
    providers: bool,
) -> Value {
    run_python(
        python,
        "import json,os,sys\nfrom kv.approval_channel import open_channel\nfrom kv.crypto import unwrap_identity_key\nroot,passphrase,providers=sys.argv[1:]\nos.chdir(root)\nwith open(root+'/.secrets/key','rb') as f: blob=f.read()\nu=unwrap_identity_key(blob,passphrase)\nc=open_channel(u,providers=providers=='true')\nprint(json.dumps({'session_nonce':c.session_nonce.hex(),'protected':c.protected,'owner_key_id':c.owner_key_id,'daemon_version':c.daemon_version,'providers':c.providers}))",
        root,
        home,
        &[passphrase, if providers { "true" } else { "false" }],
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn python_check_channel_error(
    python: &std::ffi::OsStr,
    root: &Path,
    home: &Path,
    passphrase: &str,
    answer: &Value,
    challenge: &[u8],
    wrong_key: bool,
) -> Value {
    run_python(
        python,
        "import json,sys\nfrom kv.approval_channel import ChannelError,check_channel\nfrom kv.crypto import unwrap_identity_key\nroot,passphrase,answer,challenge,wrong=sys.argv[1:]\nwith open(root+'/.secrets/key','rb') as f: u=unwrap_identity_key(f.read(),passphrase)\nif wrong=='true': u.master_key=b'\\x5a'*32\ntry:\n check_channel(json.loads(answer),bytes.fromhex(challenge),u)\nexcept ChannelError as error:\n print(json.dumps(str(error)))\nelse:\n print(json.dumps('accepted'))",
        root,
        home,
        &[
            passphrase,
            &answer.to_string(),
            &hex_encode(challenge),
            if wrong_key { "true" } else { "false" },
        ],
    )
}

fn signed_channel_with_location(
    answer: &Value,
    identity: &kv_crypto::Identity,
    location: Vec<u8>,
) -> Value {
    let (kind, mut fields, _) = kv_approvals::wire::from_json(answer).unwrap();
    fields.insert(
        "location".into(),
        kv_approvals::wire::FieldValue::Bytes(location),
    );
    let key = kv_crypto::derive_labeled_key(&identity.master_key, b"kv-approval:daemon-auth", &[]);
    let tag = kv_approvals::wire::mac(key.as_ref(), kind, &fields).unwrap();
    kv_approvals::wire::to_json(kind, &fields, &tag).unwrap()
}

fn assert_channel_matches_python(channel: &kv_proto::Channel, python: &Value) {
    let nonce = python["session_nonce"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(channel.session_nonce, nonce);
    assert_eq!(channel.protected, python["protected"].as_bool().unwrap());
    assert_eq!(
        channel.owner_key_id,
        python["owner_key_id"].as_str().unwrap()
    );
    assert_eq!(
        channel.daemon_version,
        python["daemon_version"].as_str().unwrap()
    );
    let providers = channel
        .providers
        .iter()
        .map(|(name, snapshot)| json!([name, snapshot]))
        .collect::<Vec<_>>();
    assert_eq!(Value::Array(providers), python["providers"]);
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

    let identity = keyfile::unwrap_v4(
        &fs::read(root.join(".secrets/key")).unwrap(),
        passphrase.as_bytes(),
    )
    .unwrap();
    for providers in [false, true] {
        let rust_channel = kv_proto::open_channel(&root, &identity, providers).unwrap();
        let python_channel = python_open_channel(&python, &root, &home, &passphrase, providers);
        assert_channel_matches_python(&rust_channel, &python_channel);
    }
    let challenge = [0x21; kv_approvals::wire::NONCE_LEN];
    let mut fields = Map::new();
    fields.insert("challenge".into(), Value::String(hex_encode(&challenge)));
    let channel_answer = kv_proto::agent_request(&root, "owner_channel", &fields).unwrap();
    let replay_challenge = [0x22; kv_approvals::wire::NONCE_LEN];
    let replay_error = kv_proto::check_channel(&channel_answer, &replay_challenge, &identity)
        .unwrap_err()
        .to_string();
    assert_eq!(
        replay_error,
        "the daemon's answer is for another challenge (a replay)"
    );
    assert_eq!(
        python_check_channel_error(
            &python,
            &root,
            &home,
            &passphrase,
            &channel_answer,
            &replay_challenge,
            false,
        ),
        json!(replay_error)
    );

    let mut wrong_identity = keyfile::unwrap_v4(
        &fs::read(root.join(".secrets/key")).unwrap(),
        passphrase.as_bytes(),
    )
    .unwrap();
    wrong_identity.master_key = Key32::new([0x5a; 32]);
    let wrong_key_error = kv_proto::check_channel(&channel_answer, &challenge, &wrong_identity)
        .unwrap_err()
        .to_string();
    assert_eq!(
        wrong_key_error,
        "the daemon's answer is not signed with this vault's key"
    );
    assert_eq!(
        python_check_channel_error(
            &python,
            &root,
            &home,
            &passphrase,
            &channel_answer,
            &challenge,
            true,
        ),
        json!(wrong_key_error)
    );

    let mismatched_identity_answer =
        signed_channel_with_location(&channel_answer, &identity, b"/another/vault".to_vec());
    let mismatch_error =
        kv_proto::check_channel(&mismatched_identity_answer, &challenge, &identity)
            .unwrap_err()
            .to_string();
    assert_eq!(
        mismatch_error,
        "the daemon serves another vault (its identity differs from this key file)"
    );
    assert_eq!(
        python_check_channel_error(
            &python,
            &root,
            &home,
            &passphrase,
            &mismatched_identity_answer,
            &challenge,
            false,
        ),
        json!(mismatch_error)
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

    let identity = keyfile::unwrap_v4(
        &fs::read(root.join(".secrets/key")).unwrap(),
        passphrase.as_bytes(),
    )
    .unwrap();
    for providers in [false, true] {
        let rust_channel = kv_proto::open_channel(&root, &identity, providers).unwrap();
        let python_channel = python_open_channel(&python, &root, &home, &passphrase, providers);
        assert_channel_matches_python(&rust_channel, &python_channel);
    }
    let python_owner_errors = collect_owner_error_shapes(&python, &root, &home, &identity, true);
    assert_eq!(
        python_owner_errors
            .iter()
            .map(|reply| reply["code"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "bad_request",
            "bad_request",
            "bad_request",
            "bad_request",
            "bad_request",
            "config_authority_changed"
        ]
    );

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
    assert_owner_json_property(&socket_path, &identity);

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

    let identity = keyfile::unwrap_v4(
        &fs::read(root.join(".secrets/key")).unwrap(),
        passphrase.as_bytes(),
    )
    .unwrap();
    for providers in [false, true] {
        let rust_channel = kv_proto::open_channel(&root, &identity, providers).unwrap();
        let python_channel = python_open_channel(&python, &root, &home, &passphrase, providers);
        assert_channel_matches_python(&rust_channel, &python_channel);
    }
    let rust_owner_errors = collect_owner_error_shapes(&python, &root, &home, &identity, false);
    for (index, (python_reply, rust_reply)) in python_owner_errors
        .iter()
        .zip(&rust_owner_errors)
        .enumerate()
    {
        assert_ne!(python_reply["session_nonce"], rust_reply["session_nonce"]);
        if index == 4 {
            assert_eq!(python_reply["code"], "bad_request");
            assert_eq!(rust_reply["code"], "unsupported");
            continue;
        }
        let mut python_reply = python_reply.clone();
        let mut rust_reply = rust_reply.clone();
        python_reply
            .as_object_mut()
            .unwrap()
            .remove("session_nonce");
        rust_reply.as_object_mut().unwrap().remove("session_nonce");
        assert_eq!(python_reply, rust_reply);
    }

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
    assert_owner_json_property(&socket_path, &identity);

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

    let moved_root = temp.0.join("vault-moved");
    let python_hard_lock_log = temp.0.join("python-hard-lock.log");
    let mut python_hard_lock_daemon =
        spawn_python_daemon(&python, &root, &home, &passphrase, &python_hard_lock_log);
    python_hard_lock_daemon.wait_for_socket(&socket_path, &python_hard_lock_log);
    let python_hard_lock = exercise_hard_lock(&python, &root, &moved_root, &home, true);
    assert_eq!(python_hard_lock.0["error_code"], "vault_hard_locked");
    assert!(
        python_hard_lock.0["error"]
            .as_str()
            .unwrap()
            .contains("vault changed under the running daemon")
    );
    assert_eq!(python_hard_lock.1["hard_locked"], true);
    assert_eq!(python_hard_lock.2, python_hard_lock.0);
    assert_eq!(
        python_agent_request(&python, &root, &home, "stop", &json!({}))["stopping"],
        true
    );
    assert!(python_hard_lock_daemon.wait().success());

    let rust_hard_lock_log = temp.0.join("rust-hard-lock.log");
    let mut rust_hard_lock_daemon =
        spawn_rust_daemon(&root, &home, &passphrase, &rust_hard_lock_log);
    rust_hard_lock_daemon.wait_for_socket(&socket_path, &rust_hard_lock_log);
    let rust_hard_lock = exercise_hard_lock(&python, &root, &moved_root, &home, false);
    assert_eq!(rust_hard_lock.0, python_hard_lock.0);
    assert_eq!(rust_hard_lock.1["hard_locked"], true);
    assert_eq!(rust_hard_lock.2, rust_hard_lock.0);
    assert_eq!(
        kv_proto::agent_request(&root, "stop", &Map::new()).unwrap()["stopping"],
        true
    );
    assert!(rust_hard_lock_daemon.wait().success());
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

#[test]
fn approval_signing_key_changes_hard_lock_with_python_reason_parity() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 4b approval-key parity: set KV_PY_REF");
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

    let python_log = temp.0.join("python-approval-key-change.log");
    let python_change = approval_key_hard_lock(
        &python,
        &root,
        &home,
        &passphrase,
        ApprovalKeyMutation::Change,
        true,
        &python_log,
    );
    assert!(
        python_change["error"]
            .as_str()
            .unwrap()
            .contains(ApprovalKeyMutation::Change.reason())
    );
    let rust_log = temp.0.join("rust-approval-key-change.log");
    let rust_change = approval_key_hard_lock(
        &python,
        &root,
        &home,
        &passphrase,
        ApprovalKeyMutation::Change,
        false,
        &rust_log,
    );
    assert_eq!(rust_change, python_change);

    for mutation in [
        ApprovalKeyMutation::Replace,
        ApprovalKeyMutation::Delete,
        ApprovalKeyMutation::NonRegular,
    ] {
        let log = temp
            .0
            .join(format!("rust-approval-key-{}.log", mutation.name()));
        let response =
            approval_key_hard_lock(&python, &root, &home, &passphrase, mutation, false, &log);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains(mutation.reason())
        );
    }
}

#[test]
fn owner_authority_internal_failures_are_signed_internal() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 4b owner authority error classification: set KV_PY_REF");
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
    let log = temp.0.join("rust-owner-authority-error.log");
    let mut daemon = spawn_rust_daemon(&root, &home, &passphrase, &log);
    daemon.wait_for_socket(&socket_path, &log);
    let identity = keyfile::unwrap_v4(
        &fs::read(root.join(".secrets/key")).unwrap(),
        passphrase.as_bytes(),
    )
    .unwrap();
    let config_path = root.join(".secrets/config.json");
    let saved_config = temp.0.join("config.json.saved");
    fs::rename(&config_path, &saved_config).unwrap();
    fs::create_dir(&config_path).unwrap();

    let challenge = [0x37; kv_approvals::wire::NONCE_LEN];
    let fields = [(
        "challenge".to_owned(),
        Value::String(hex_encode(&challenge)),
    )]
    .into_iter()
    .collect::<Map<_, _>>();
    let answer = kv_proto::agent_request(&root, "owner_channel", &fields).unwrap();
    let shape = owner_error_shape(&answer, &identity, &challenge);
    assert_eq!(shape["code"], "internal");

    fs::remove_dir(config_path).unwrap();
    fs::rename(saved_config, root.join(".secrets/config.json")).unwrap();
    assert_eq!(
        kv_proto::agent_request(&root, "stop", &Map::new()).unwrap()["stopping"],
        true
    );
    assert!(daemon.wait().success());
}
