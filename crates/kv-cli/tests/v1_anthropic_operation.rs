//! Standalone v1 fixed-operation gate: a Rust-only vault, daemon, owner CLI and
//! loopback TLS provider. No Python implementation or fixture vault is used.
#![cfg(all(unix, feature = "test-provider-loopback"))]

#[allow(dead_code)]
#[path = "support/owner.rs"]
mod owner;

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use kv_agent::{TrustContext, run_agent_with_api_caller};
use kv_broker::{ApiCaller, UrlSafety};
use kv_crypto::{Identity, Key32, Zeroizing, derive_labeled_key, keyfile};
use kv_store::{DrawerStore, config_authority, vault_origin};
use owner::{kv_bin, pty};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use url::Url;

const PASSPHRASE: &str = "v1 fixture passphrase";
const SECRET: &str = "synthetic-anthropic-test-key";
const HOST: &str = "api.anthropic.com";
const PORT: u16 = 18443;
const INPUT: &str = "count these tokens";
static TEST_LOCK: Mutex<()> = Mutex::new(());
static TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PROVIDER: OnceLock<Provider> = OnceLock::new();

fn wait_until(what: &str, bound: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + bound;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(30));
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn create_vault(root: &Path) -> Key32 {
    let secrets = root.join(".secrets");
    fs::create_dir_all(&secrets).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    vault_origin::record_created(root).unwrap();
    let mut master = [0u8; 32];
    let mut owner_seed = [0u8; 32];
    let mut approval_id = [0u8; 16];
    getrandom::getrandom(&mut master).unwrap();
    getrandom::getrandom(&mut owner_seed).unwrap();
    getrandom::getrandom(&mut approval_id).unwrap();
    let location = config_authority::canonical_location(root).unwrap();
    let identity = Identity {
        master_key: Key32::new(master),
        owner_seed: Zeroizing::new(owner_seed),
        local_approval_id: approval_id,
        location: location.clone(),
    };
    let key = keyfile::wrap_v4(
        &identity,
        PASSPHRASE.as_bytes(),
        &location,
        Some((14, 8, 1)),
    )
    .unwrap();
    write_private(&secrets.join("key"), &key);
    write_private(&secrets.join(".gitignore"), b"key\napproval_signing_key\n");
    let config = json!({
        "version":1,
        "created":"v1-test",
        "default_env":"dev",
        "environments":["dev"],
        "cipher":"chacha20-poly1305",
        "storage":{"format":"drawers"},
        "security":{"passphrase":true,"totp":false,"approval_mode":"local-convenience"},
        "providers":{"anthropic":{"base_url":"https://api.anthropic.com:18443","secret_name":"ANTHROPIC_API_KEY","auth_type":"x-api-key","default_headers":{"Content-Type":"application/json","anthropic-version":"2023-06-01"}}},
        "broker_policy":{"http":{"anthropic":{"origin":"https://api.anthropic.com:18443","secret_name":"ANTHROPIC_API_KEY","rules":[]}}}
    });
    write_private(
        &secrets.join("config.json"),
        serde_json::to_vec_pretty(&config).unwrap().as_slice(),
    );
    fs::create_dir(secrets.join("drawers")).unwrap();
    fs::set_permissions(secrets.join("drawers"), fs::Permissions::from_mode(0o700)).unwrap();
    let master = Key32::new(master);
    config_authority::approve_config_unattended(root, &master).unwrap();
    let store = DrawerStore::open(&secrets, Key32::new(*master.as_bytes()));
    store
        .set_secret("dev", "ANTHROPIC_API_KEY", SECRET, 1)
        .unwrap();
    master
}

struct LoopbackSafety;
impl UrlSafety for LoopbackSafety {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        if url.host_str() == Some(HOST) && url.port_or_known_default() == Some(PORT) {
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
        } else {
            Err("test fixture is loopback-only".into())
        }
    }
}

/// Child modes used so the vault origin and daemon see the fixture HOME.
#[test]
fn v1_fixture_child() {
    let Ok(mode) = std::env::var("KV_V1_MODE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("KV_V1_ROOT").unwrap());
    if mode == "setup" {
        create_vault(&root);
        return;
    }
    if mode == "request" {
        let cmd = std::env::var("KV_V1_REQUEST_CMD").unwrap();
        let fields = match cmd.as_str() {
            "run" => json!({"argv":["/bin/echo","x"]}),
            _ => {
                json!({"provider":"anthropic","method":"POST","path":"/v1/messages/count_tokens","body":{}})
            }
        };
        let answer = if cmd == "legacy-v1" {
            kv_proto::agent_request(
                &root,
                "v1_anthropic_count_tokens",
                json!({"input":INPUT}).as_object().unwrap(),
            )
            .unwrap()
        } else {
            kv_proto::agent_request_framed(&root, &cmd, fields.as_object().unwrap()).unwrap()
        };
        println!("{answer}");
        return;
    }
    assert_eq!(mode, "daemon");
    let ca = fs::read(std::env::var_os("KV_V1_CA").unwrap()).unwrap();
    let master = {
        let blob = fs::read(root.join(".secrets/key")).unwrap();
        let identity = keyfile::unwrap_v4(&blob, PASSPHRASE.as_bytes()).unwrap();
        Key32::new(*identity.master_key.as_bytes())
    };
    let store = Arc::new(DrawerStore::open(
        root.join(".secrets"),
        Key32::new(*master.as_bytes()),
    ));
    let trust = TrustContext::at_unlock(&root, Some(PASSPHRASE.as_bytes()), &master).unwrap();
    let caller = ApiCaller::with_test_ca_for_test(Arc::new(LoopbackSafety), &ca).unwrap();
    run_agent_with_api_caller(root, store, master, trust, Arc::new(caller)).unwrap();
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    home: PathBuf,
    socket: PathBuf,
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Fixture {
    fn new() -> Self {
        let serial = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temp =
            TempDir(std::env::temp_dir().join(format!("kvv1{}-{serial}", std::process::id())));
        let _ = fs::remove_dir_all(&temp.0);
        fs::create_dir(&temp.0).unwrap();
        let root = temp.0.join("vault");
        let home = temp.0.join("home");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&home).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let home = fs::canonicalize(home).unwrap();
        let setup = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "v1_fixture_child", "--nocapture"])
            .env("KV_V1_MODE", "setup")
            .env("KV_V1_ROOT", &root)
            .env("HOME", &home)
            .output()
            .unwrap();
        assert!(
            setup.status.success(),
            "setup: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let hash = kv_proto::project_hash(Some(&root)).unwrap();
        let socket = home.join(".kv").join(format!("agent-{hash}.sock"));
        Self {
            _temp: temp,
            root,
            home,
            socket,
        }
    }

    fn start_daemon(&self) -> ChildGuard {
        self.start_daemon_with_clock_scale(None)
    }

    fn start_daemon_with_clock_scale(&self, clock_scale: Option<&str>) -> ChildGuard {
        let log = self.root.join("daemon.log");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "v1_fixture_child", "--nocapture"])
            .env("KV_V1_MODE", "daemon")
            .env("KV_V1_ROOT", root_for_child(&self.root))
            .env("KV_V1_CA", self.root.join("ca.der"))
            .env("HOME", &self.home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(log).unwrap());
        if let Some(scale) = clock_scale {
            command.env("KV_TEST_PERMIT_CLOCK_SCALE", scale);
        }
        let child = command.spawn().unwrap();
        wait_until("daemon socket", Duration::from_secs(15), || {
            self.socket.exists()
        });
        ChildGuard(child)
    }

    fn kv(&self, args: &[&str]) -> (i32, String) {
        let output = Command::new(kv_bin())
            .args(args)
            .current_dir(&self.root)
            .env("HOME", &self.home)
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        (output.status.code().unwrap_or(-1), text)
    }
}

fn root_for_child(root: &Path) -> PathBuf {
    root.to_path_buf()
}

struct Provider {
    events: Arc<Mutex<Vec<Value>>>,
    ca_der: Vec<u8>,
}

fn start_provider_once() -> Provider {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, PORT)).unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "v1 test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![HOST.into()])
        .unwrap()
        .signed_by(&server_key, &ca, &ca_key)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
    )
    .unwrap();
    let config = Arc::new(config);
    let events = Arc::new(Mutex::new(Vec::new()));
    let thread_events = Arc::clone(&events);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let config = Arc::clone(&config);
            let events = Arc::clone(&thread_events);
            thread::spawn(move || serve_one(&mut stream, config, events));
        }
    });
    Provider {
        events,
        ca_der: ca.der().to_vec(),
    }
}

fn start_provider() -> &'static Provider {
    let provider = PROVIDER.get_or_init(start_provider_once);
    provider.events.lock().unwrap().clear();
    provider
}

fn read_exact_stream(stream: &mut impl Read, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    stream.read_exact(&mut out).unwrap();
    out
}

fn serve_one(
    stream: &mut std::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
    events: Arc<Mutex<Vec<Value>>>,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut tls = rustls::ServerConnection::new(config).unwrap();
    while !tls.wants_write() || tls.is_handshaking() {
        tls.complete_io(stream).unwrap();
        if !tls.is_handshaking() {
            break;
        }
    }
    let mut io = rustls::Stream::new(&mut tls, stream);
    let mut head = Vec::new();
    while !head.windows(4).any(|tail| tail == b"\r\n\r\n") {
        let mut byte = [0u8];
        io.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
        assert!(head.len() < 8192);
    }
    let head_text = String::from_utf8_lossy(&head).into_owned();
    let length = head_text
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower.strip_prefix("content-length:").map(str::to_owned)
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let body = read_exact_stream(&mut io, length);
    let auth = head_text
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("x-api-key:")
                .map(str::trim)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let version = head_text
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("anthropic-version:")
                .map(str::trim)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let path = head_text
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    events.lock().unwrap().push(json!({
        "path":path,
        "auth":auth,
        "version":version,
        "body":String::from_utf8_lossy(&body),
    }));
    if String::from_utf8_lossy(&body).contains("drop after reading") {
        return;
    }
    let response_body = br#"{"input_tokens":7}"#;
    write!(
        io,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        String::from_utf8_lossy(response_body)
    )
    .unwrap();
    io.flush().unwrap();
}

fn token(text: &str, prefix: &str) -> String {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|part| part.starts_with(prefix))
        .max_by_key(|part| part.len())
        .unwrap_or_else(|| panic!("missing {prefix} in {text}"))
        .to_owned()
}

fn operation_args<'a>(permit: Option<&'a str>, input: &'a str) -> Vec<&'a str> {
    let mut args = vec!["api", "anthropic-count-tokens"];
    if let Some(permit) = permit {
        args.extend(["--permit-id", permit]);
    }
    args.push(input);
    args
}

fn permit_token(text: &str) -> String {
    let marker = "--permit-id ";
    let start = text
        .find(marker)
        .unwrap_or_else(|| panic!("missing permit id in {text}"))
        + marker.len();
    text[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

fn admission_journal_dir(fixture: &Fixture) -> PathBuf {
    let hash = kv_proto::project_hash(Some(&fixture.root)).unwrap();
    let key_blob = fs::read(fixture.root.join(".secrets").join("key")).unwrap();
    let identity = keyfile::unwrap_v4(&key_blob, PASSPHRASE.as_bytes()).unwrap();
    let generation = derive_labeled_key(
        &identity.master_key,
        b"kv-audit:vault-generation-v1",
        &[identity.local_approval_id.as_slice()],
    );
    fixture.home.join(".kv").join(format!(
        "admissions-{hash}-{}",
        hex::encode(generation.as_bytes())
    ))
}

fn admission_checkpoint_path(fixture: &Fixture) -> PathBuf {
    let hash = kv_proto::project_hash(Some(&fixture.root)).unwrap();
    let key_blob = fs::read(fixture.root.join(".secrets").join("key")).unwrap();
    let identity = keyfile::unwrap_v4(&key_blob, PASSPHRASE.as_bytes()).unwrap();
    let generation = derive_labeled_key(
        &identity.master_key,
        b"kv-audit:vault-generation-v1",
        &[identity.local_approval_id.as_slice()],
    );
    fixture.home.join(".kv").join(format!(
        "admission-checkpoint-{hash}-{}",
        hex::encode(generation.as_bytes())
    ))
}

#[test]
fn fixed_builtin_operation_is_owner_reviewed_once_and_fail_closed() {
    let _serial = TEST_LOCK.lock().unwrap();
    let provider = start_provider();
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ca.der"), &provider.ca_der).unwrap();
    let _daemon = fixture.start_daemon();
    let count = || provider.events.lock().unwrap().len();

    // Request and owner review use the literal v1 CLI contract.
    let args = operation_args(None, INPUT);
    let (code, text) = fixture.kv(&args);
    assert_eq!(code, 1, "request output: {text}");
    let request_id = token(&text, "permit_request_");
    let permit_id = permit_token(&text);
    assert_eq!(count(), 0, "request alone must not send");

    let (code, inbox) = fixture.kv(&["approvals", "list"]);
    assert_eq!(code, 0, "{inbox}");
    assert!(
        inbox.contains("Pending one-call permit: POST anthropic"),
        "{inbox}"
    );

    let python = owner::python3().expect("python3 is needed only to allocate a test pty");
    let passphrase_rule = format!("Passphrase: =>{PASSPHRASE}");
    let cmd = [kv_bin()];
    let (code, approval) = pty(
        &python,
        &cmd,
        &fixture.home,
        &fixture.root,
        &["approvals", "approve", &request_id],
        &[&passphrase_rule, "\\[y/N\\] =>y"],
    );
    assert_eq!(code, 0, "approval: {approval}");
    assert_eq!(count(), 0, "approval itself must not send");

    let args = operation_args(Some(&permit_id), INPUT);
    let (code, executed) = fixture.kv(&args);
    assert_eq!(code, 0, "execute: {executed}");
    assert!(executed.contains("\"input_tokens\""), "{executed}");
    assert_eq!(count(), 1, "exactly one approved provider request");
    {
        let events = provider.events.lock().unwrap();
        let event = &events[0];
        assert_eq!(event["path"], "/v1/messages/count_tokens");
        assert_eq!(event["auth"], SECRET);
        assert_eq!(event["version"], "2023-06-01");
        assert!(event["body"].as_str().unwrap().contains(INPUT));
    }

    let journal = fs::read_to_string(admission_journal_dir(&fixture).join("audit.jsonl")).unwrap();
    let records = journal
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2, "admission and outcome: {records:?}");
    assert_eq!(records[0]["event"], "privileged_admission");
    assert_eq!(records[1]["event"], "privileged_outcome");
    assert_eq!(records[1]["outcome"], "completed");

    let (code, replay) = fixture.kv(&args);
    assert_ne!(code, 0);
    assert!(replay.contains("permit"), "{replay}");
    assert_eq!(count(), 1, "replay sends nothing");

    let (change_request, fresh_change_permit) = request(&fixture);
    approve_permit(&fixture, &change_request);
    let changed_args = operation_args(Some(&fresh_change_permit), "changed payload");
    let (code, changed) = fixture.kv(&changed_args);
    assert_ne!(code, 0);
    assert_eq!(count(), 1, "changed payload sends nothing: {changed}");

    for cmd in ["run", "api"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "v1_fixture_child", "--nocapture"])
            .env("KV_V1_MODE", "request")
            .env("KV_V1_ROOT", &fixture.root)
            .env("KV_V1_REQUEST_CMD", cmd)
            .env("HOME", &fixture.home)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{cmd} helper: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_line = stdout
            .lines()
            .find(|line| line.starts_with('{'))
            .unwrap_or_else(|| panic!("no JSON response in {stdout}"));
        let refused: Value = serde_json::from_str(json_line).unwrap();
        assert_eq!(
            refused["error_code"], "unsupported_operation",
            "{cmd}: {refused}"
        );
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "v1_fixture_child", "--nocapture"])
        .env("KV_V1_MODE", "request")
        .env("KV_V1_ROOT", &fixture.root)
        .env("KV_V1_REQUEST_CMD", "legacy-v1")
        .env("HOME", &fixture.home)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_line = stdout.lines().find(|line| line.starts_with('{')).unwrap();
    let refused: Value = serde_json::from_str(json_line).unwrap();
    assert_eq!(
        refused["error_code"], "unsupported_wire",
        "legacy wire: {refused}"
    );
    assert_eq!(count(), 1, "legacy operations send nothing");

    let (lock_request, fresh_lock_permit) = request(&fixture);
    approve_permit(&fixture, &lock_request);
    let fresh_lock_args = operation_args(Some(&fresh_lock_permit), INPUT);
    let (_code, lock) = fixture.kv(&["lock"]);
    assert!(
        lock.contains("vault locked") || lock.contains("told to stop"),
        "lock: {lock}"
    );
    let (code, locked) = fixture.kv(&fresh_lock_args);
    assert_ne!(code, 0);
    assert_eq!(count(), 1, "lock sends nothing: {locked}");
    drop(_daemon);
}

#[test]
fn denied_fixed_operation_never_reaches_provider() {
    let _serial = TEST_LOCK.lock().unwrap();
    let provider = start_provider();
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ca.der"), &provider.ca_der).unwrap();
    let _daemon = fixture.start_daemon();
    let args = operation_args(None, INPUT);
    let (code, text) = fixture.kv(&args);
    assert_eq!(code, 1, "request output: {text}");
    let request_id = token(&text, "permit_request_");
    let permit_id = permit_token(&text);
    deny_permit(&fixture, &request_id);
    assert_eq!(provider.events.lock().unwrap().len(), 0);
    let execute = operation_args(Some(&permit_id), INPUT);
    let (code, refused) = fixture.kv(&execute);
    assert_ne!(code, 0);
    assert!(refused.contains("denied"), "{refused}");
    assert_eq!(
        provider.events.lock().unwrap().len(),
        0,
        "denial sends nothing"
    );
}

fn deny_permit(fixture: &Fixture, request_id: &str) {
    let python = owner::python3().expect("python3 is needed only to allocate a test pty");
    let passphrase_rule = format!("Passphrase: =>{PASSPHRASE}");
    let cmd = [kv_bin()];
    let (code, denial) = pty(
        &python,
        &cmd,
        &fixture.home,
        &fixture.root,
        &["approvals", "deny", request_id],
        &[&passphrase_rule],
    );
    assert_eq!(code, 0, "denial: {denial}");
}

fn approve_permit(fixture: &Fixture, request_id: &str) {
    let python = owner::python3().expect("python3 is needed only to allocate a test pty");
    let passphrase_rule = format!("Passphrase: =>{PASSPHRASE}");
    let cmd = [kv_bin()];
    let (code, approval) = pty(
        &python,
        &cmd,
        &fixture.home,
        &fixture.root,
        &["approvals", "approve", request_id],
        &[&passphrase_rule, "\\[y/N\\] =>y"],
    );
    assert_eq!(code, 0, "approval: {approval}");
}

fn request(fixture: &Fixture) -> (String, String) {
    let args = operation_args(None, INPUT);
    let (code, text) = fixture.kv(&args);
    assert_eq!(code, 1, "request output: {text}");
    (token(&text, "permit_request_"), permit_token(&text))
}

#[test]
fn expired_fixed_operation_permit_never_reaches_provider() {
    let _serial = TEST_LOCK.lock().unwrap();
    let provider = start_provider();
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ca.der"), &provider.ca_der).unwrap();
    let _daemon = fixture.start_daemon_with_clock_scale(Some("150"));
    let (request_id, permit_id) = request(&fixture);
    approve_permit(&fixture, &request_id);
    thread::sleep(Duration::from_secs(4));
    let args = operation_args(Some(&permit_id), INPUT);
    let (code, expired) = fixture.kv(&args);
    assert_ne!(code, 0);
    assert!(
        expired.contains("expired") || expired.contains("missing"),
        "expired permit refusal: {expired}"
    );
    assert_eq!(
        provider.events.lock().unwrap().len(),
        0,
        "expiry sends nothing"
    );
}

#[test]
fn audit_write_failure_allows_no_additional_provider_request() {
    let _serial = TEST_LOCK.lock().unwrap();
    let provider = start_provider();
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ca.der"), &provider.ca_der).unwrap();
    let _daemon = fixture.start_daemon();
    let (request_id, permit_id) = request(&fixture);
    approve_permit(&fixture, &request_id);
    fs::create_dir(admission_checkpoint_path(&fixture)).unwrap();
    let args = operation_args(Some(&permit_id), INPUT);
    let (code, first) = fixture.kv(&args);
    assert_ne!(code, 0);
    assert!(
        first.contains("could not be recorded durably"),
        "first audit failure refusal: {first}"
    );
    assert_eq!(
        provider.events.lock().unwrap().len(),
        0,
        "first audit failure sends nothing: {first}"
    );
    let (code, retry) = fixture.kv(&args);
    assert_ne!(code, 0);
    assert_eq!(
        provider.events.lock().unwrap().len(),
        0,
        "audit failure leads to no additional send: {retry}"
    );
}

#[test]
fn uncertain_transport_result_leaves_admission_unknown() {
    let _serial = TEST_LOCK.lock().unwrap();
    let provider = start_provider();
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ca.der"), &provider.ca_der).unwrap();
    let _daemon = fixture.start_daemon();
    let input = "drop after reading";
    let args = operation_args(None, input);
    let (code, text) = fixture.kv(&args);
    assert_eq!(code, 1, "request output: {text}");
    let request_id = token(&text, "permit_request_");
    let permit_id = permit_token(&text);
    approve_permit(&fixture, &request_id);

    let args = operation_args(Some(&permit_id), input);
    let (code, executed) = fixture.kv(&args);
    assert_ne!(code, 0, "dropped response should fail: {executed}");
    assert_eq!(
        provider.events.lock().unwrap().len(),
        1,
        "provider received the uncertain request"
    );

    let journal = fs::read_to_string(admission_journal_dir(&fixture).join("audit.jsonl")).unwrap();
    let events = journal
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        events.len(),
        1,
        "only the admission may be durable: {events:?}"
    );
    assert_eq!(events[0]["event"], "privileged_admission");
}
