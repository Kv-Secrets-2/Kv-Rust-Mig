//! Stage 7 parity: the same JSON-RPC transcripts go to `python -m kv_mcp` and
//! to the Rust server, against the same vault and the same Rust daemon.
#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kv_agent::{TrustContext, run_agent};
use kv_crypto::{Key32, keyfile};
use kv_mcp::server::{Config, serve};
use kv_mcp::tools::Profiles;
use kv_store::DrawerStore;
use serde_json::{Map, Value, json};

static HOME_LOCK: Mutex<()> = Mutex::new(());

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).expect("test randomness");
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path =
            std::env::temp_dir().join(format!("kv-mcp-stage7-{}-{suffix}", std::process::id()));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[allow(unsafe_code)]
fn set_home(home: Option<&std::ffi::OsStr>) {
    // SAFETY: every caller holds HOME_LOCK while HOME is changed and used.
    unsafe {
        match home {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
    }
}

struct HomeGuard(Option<std::ffi::OsString>);

impl HomeGuard {
    fn set(home: &Path) -> Self {
        let previous = std::env::var_os("HOME");
        set_home(Some(home.as_os_str()));
        Self(previous)
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        set_home(self.0.take().as_deref());
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
        let target = destination.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_dir(&item.path(), &target);
        } else {
            fs::copy(item.path(), target).expect("copy fixture file");
        }
    }
}

fn fixture_master_key() -> (Key32, String) {
    let fixture = fixture_root();
    let expected: Value =
        serde_json::from_slice(&fs::read(fixture.join("vaults/basic.expected.json")).unwrap())
            .unwrap();
    let passphrase = expected["passphrase"].as_str().unwrap().to_owned();
    let blob = fs::read(fixture.join("vaults/basic/.secrets/key")).unwrap();
    let identity = keyfile::unwrap_v4(&blob, passphrase.as_bytes()).expect("fixture key unwrap");
    (Key32::new(*identity.master_key.as_bytes()), passphrase)
}

fn run_python(python: &std::ffi::OsStr, code: &str, root: &Path, home: &Path, args: &[&str]) {
    let output = Command::new(python)
        .arg("-c")
        .arg(code)
        .args(args)
        .current_dir(root)
        .env("HOME", home)
        .output()
        .expect("run Python");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A throwaway copy of the v4 fixture vault, approved for this machine.
struct Project {
    _dir: TestDir,
    root: PathBuf,
    home: PathBuf,
    passphrase: String,
}

fn project(python: &std::ffi::OsStr) -> Project {
    use std::os::unix::fs::PermissionsExt;
    let dir = TestDir::new();
    let home = dir.0.join("home");
    fs::create_dir(&home).unwrap();
    let root = dir.0.join("vault");
    fs::create_dir(&root).unwrap();
    copy_dir(
        &fixture_root().join("vaults/basic/.secrets"),
        &root.join(".secrets"),
    );
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let home = fs::canonicalize(home).unwrap();
    let (master, passphrase) = fixture_master_key();
    run_python(
        python,
        "import sys\nfrom kv import vault_origin\nvault_origin.record_created(sys.argv[1])",
        &root,
        &home,
        &[root.to_str().unwrap()],
    );
    run_python(
        python,
        "import sys\nfrom kv.owner_key import relocate_key_file\nrelocate_key_file(sys.argv[1],sys.argv[2])",
        &root,
        &home,
        &[root.to_str().unwrap(), &passphrase],
    );
    let _guard = HomeGuard::set(&home);
    kv_store::config_authority::approve_config_unattended(&root, &master).unwrap();
    Project {
        _dir: dir,
        root,
        home,
        passphrase,
    }
}

struct Daemon {
    child: Child,
    root: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = kv_proto::agent_request(&self.root, "stop", &Map::new());
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_rust_daemon(project: &Project) -> Daemon {
    let log = project.root.parent().unwrap().join("daemon.log");
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "rust_daemon_subprocess_helper", "--nocapture"])
        .env("KV_AGENT_CHILD_ROOT", &project.root)
        .env("KV_AGENT_CHILD_PASSPHRASE", &project.passphrase)
        .env("HOME", &project.home)
        .stdout(Stdio::null())
        .stderr(Stdio::from(fs::File::create(&log).unwrap()))
        .spawn()
        .expect("start Rust daemon");
    let mut daemon = Daemon {
        child,
        root: project.root.clone(),
    };
    let socket = kv_proto::agent_socket_path(Some(&project.root)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    while !socket.exists() {
        if let Some(status) = daemon.child.try_wait().unwrap() {
            panic!(
                "daemon exited ({status}): {}",
                fs::read_to_string(&log).unwrap_or_default()
            );
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not open its socket: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(10));
    }
    daemon
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

fn profiles(flags: &[&str]) -> Profiles {
    let mut profiles = Profiles::new();
    profiles.insert("safe".into());
    for (flag, profile) in [
        ("--allow-execute", "execute"),
        ("--allow-mutate", "mutate"),
        ("--allow-reveal", "reveal"),
    ] {
        if flags.contains(&flag) {
            profiles.insert(profile.into());
        }
    }
    profiles
}

fn normalise_log(log: &[u8]) -> String {
    let text = String::from_utf8_lossy(log);
    let mut out = String::new();
    let mut rest = &*text;
    while let Some(at) = rest.find("duration_ms=") {
        out.push_str(&rest[..at + "duration_ms=".len()]);
        rest = rest[at + "duration_ms=".len()..].trim_start_matches(|ch: char| ch.is_ascii_digit());
        out.push('N');
    }
    out.push_str(rest);
    out.lines()
        .filter(|line| line.starts_with("[kv_mcp]"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn run_python_server(
    python: &std::ffi::OsStr,
    project: &Project,
    flags: &[&str],
    input: &[u8],
) -> (Vec<u8>, String) {
    let mut child = Command::new(python)
        .args(["-m", "kv_mcp"])
        .args(flags)
        .current_dir(&project.root)
        .env("HOME", &project.home)
        .env("PYTHONIOENCODING", "utf-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start python -m kv_mcp");
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    (output.stdout, normalise_log(&output.stderr))
}

fn run_rust_server(project: &Project, flags: &[&str], input: &[u8]) -> (Vec<u8>, String) {
    let config = Config {
        root: project.root.clone(),
        default_env: kv_store::config::get_default_env(&project.root).unwrap(),
        profiles: profiles(flags),
        allow_direct_vault_access: flags.contains(&"--allow-direct-vault-access"),
    };
    let input = input.to_vec();
    let worker = thread::Builder::new()
        .stack_size(kv_mcp::pyval::DECODE_STACK_BYTES)
        .spawn(move || {
            let mut output = Vec::new();
            let mut log = Vec::new();
            serve(&config, std::io::Cursor::new(input), &mut output, &mut log);
            (output, log)
        })
        .unwrap();
    let (output, log) = worker.join().unwrap();
    (output, normalise_log(&log))
}

fn transcript(frames: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.extend_from_slice(frame.as_bytes());
        bytes.push(b'\n');
    }
    bytes
}

fn assert_parity(
    python: &std::ffi::OsStr,
    project: &Project,
    flags: &[&str],
    frames: &[String],
    label: &str,
) -> String {
    let input = transcript(frames);
    let (python_out, python_log) = run_python_server(python, project, flags, &input);
    let (rust_out, rust_log) = run_rust_server(project, flags, &input);
    let python_text = String::from_utf8_lossy(&python_out);
    let rust_text = String::from_utf8_lossy(&rust_out);
    for (index, (expected, actual)) in python_text.lines().zip(rust_text.lines()).enumerate() {
        assert_eq!(actual, expected, "{label}: response {index} differs");
    }
    assert_eq!(rust_out, python_out, "{label}: response streams differ");
    assert_eq!(rust_log, python_log, "{label}: logs differ");
    python_text.into_owned()
}

fn init_frames() -> Vec<String> {
    vec![
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "parity", "version": "1"}}}).to_string(),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
    ]
}

fn call(id: i64, name: &str, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}).to_string()
}

fn protocol_frames() -> Vec<String> {
    let mut frames = vec![
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        json!({"jsonrpc": "2.0", "id": "p", "method": "ping"}).to_string(),
        json!({"jsonrpc": "2.0", "id": null, "method": "tools/list"}).to_string(),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled"}).to_string(),
    ];
    frames.extend(init_frames());
    frames.extend(
        [
            "{",
            "[]",
            "[{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"ping\"}]",
            "3",
            "\"text\"",
            "null",
            "   \t ",
            "\u{feff}{}",
            "{\"id\": 1, \"id\": 2, \"method\": \"ping\"}",
            "{\"jsonrpc\": \"2.0\", \"id\": NaN, \"method\": \"ping\"}",
            "{\"jsonrpc\": \"2.0\", \"id\": 1e400, \"method\": \"ping\"}",
            "{\"jsonrpc\": \"2.0\", \"id\": -0.0, \"method\": \"ping\"}",
            "{\"jsonrpc\": \"2.0\", \"id\": 12345678901234567890123, \"method\": \"ping\"}",
            "{\"jsonrpc\": \"2.0\", \"id\": \"\\u00e9\\ud83d\\ude00\", \"method\": \"ping\"}",
            "{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"ping\"} extra",
            "{'id': 1}",
            "{\"id\": 1, \"method\": \"tools/list\", \"params\": []}",
            "{\"id\": 1, \"method\": \"tools/list\", \"params\": null}",
            "{\"id\": 1, \"method\": 7}",
            "{\"id\": 1}",
            "{\"id\": {\"a\": [1, 2.5]}, \"method\": \"nope/x\"}",
            "{\"method\": \"nope/x\"}",
            "{\"jsonrpc\": \"2.0\", \"id\": 9, \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"1999-01-01\"}}",
            "{\"jsonrpc\": \"2.0\", \"id\": 10, \"method\": \"initialize\", \"params\": {\"protocolVersion\": 5}}",
            "{\"jsonrpc\": \"2.0\", \"id\": 11, \"method\": \"initialize\"}",
            "{\"jsonrpc\": \"2.0\", \"id\": 12, \"method\": \"tools/call\", \"params\": {\"name\": 5}}",
            "{\"jsonrpc\": \"2.0\", \"id\": 13, \"method\": \"tools/call\", \"params\": {\"name\": \"kv_status\", \"arguments\": []}}",
            "{\"jsonrpc\": \"2.0\", \"id\": 14, \"method\": \"tools/call\", \"params\": {\"name\": \"kv_status\", \"arguments\": null}}",
            "{\"jsonrpc\": \"2.0\", \"id\": 15, \"method\": \"tools/call\", \"params\": {\"name\": \"kv_nope\"}}",
            "{\"jsonrpc\": \"2.0\", \"id\": 16, \"method\": \"tools/call\", \"params\": {}}",
            "{\"a\":1}\r{\"id\": 17, \"method\": \"ping\"}\r\n{\"id\": 18, \"method\": \"ping\"}",
        ]
        .map(str::to_owned),
    );
    frames.push(format!("{}1{}", "[".repeat(988), "]".repeat(988)));
    frames
}

fn tool_frames() -> Vec<String> {
    let big = "x".repeat(600 * 1024);
    let headers: Map<String, Value> = (0..65)
        .map(|index| (format!("h{index}"), json!("v")))
        .collect();
    let mut frames = init_frames();
    frames.push(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string());
    let cases = vec![
        ("kv_status", json!({})),
        ("kv_status", json!({"env": "prod"})),
        ("kv_envs", json!({})),
        ("kv_list", json!({})),
        ("kv_list", json!({"env": "prod"})),
        ("kv_list", json!({"env": "missing-env"})),
        ("kv_list", json!({"env": "../escape"})),
        ("kv_list", json!({"env": 5})),
        ("kv_list", json!({"env": ""})),
        ("kv_list", json!({"env": "é".repeat(70)})),
        ("kv_list", json!({"env": null})),
        ("kv_api", json!({})),
        ("kv_api", json!({"provider": "openai"})),
        (
            "kv_api",
            json!({"provider": "openai", "path": "/v1/models"}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "method": "TRACE"}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "method": null}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "body": 5}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "body": big}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "headers": []}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "headers": headers}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "headers": {"a": 1}}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "headers": {"": "v"}}),
        ),
        (
            "kv_api",
            json!({"provider": "nope", "path": "/x", "reason": "r".repeat(513)}),
        ),
        ("kv_api", json!({"provider": 5, "path": "/x"})),
        ("kv_api", json!({"provider": "p".repeat(129), "path": "/x"})),
        (
            "kv_api",
            json!({"provider": "github", "path": "/user", "method": "post", "body": {"a": [1, "é"]}, "permit_id": "x"}),
        ),
        ("kv_run", json!({})),
        ("kv_run", json!({"argv": []})),
        ("kv_run", json!({"argv": "ls"})),
        ("kv_run", json!({"argv": vec!["a"; 51]})),
        ("kv_run", json!({"argv": ["ls", 5]})),
        ("kv_run", json!({"argv": ["ls", "y".repeat(4097)]})),
        ("kv_run", json!({"argv": [""]})),
        ("kv_run", json!({"argv": ["ls"], "env_names": "A"})),
        (
            "kv_run",
            json!({"argv": ["ls"], "env_names": ["A"], "capability_names": ["api:x"]}),
        ),
        (
            "kv_run",
            json!({"argv": ["ls"], "capability_names": vec!["c"; 17]}),
        ),
        ("kv_run", json!({"argv": ["ls"], "cwd": 5})),
        ("kv_run", json!({"argv": ["ls"], "private_cwd": "yes"})),
        ("kv_run", json!({"argv": ["ls"], "reason": 5})),
        (
            "kv_run",
            json!({"argv": ["/usr/bin/must"], "env_names": [""]}),
        ),
        ("kv_run", json!({"argv": ["ls"], "env": "../x"})),
        ("kv_run", json!({"argv": ["ls"], "env_names": []})),
        (
            "kv_run",
            json!({"argv": ["/usr/bin/curl", "https://example.com"], "env_names": ["A"]}),
        ),
        ("kv_run", json!({"argv": ["psql"], "env_names": ["A"]})),
        (
            "kv_run",
            json!({"argv": ["nc"], "env_names": ["A"], "cwd": "/tmp", "private_cwd": true, "reason": "x"}),
        ),
        ("kv_query", json!({"provider": "db", "query": "select 1"})),
        ("kv_ssh", json!({"provider": "h", "command": "ls"})),
        ("kv_set", json!({"key": "A", "value": "b"})),
        ("kv_rm", json!({"key": "A"})),
        ("kv_get", json!({"key": "A"})),
    ];
    for (index, (name, arguments)) in cases.into_iter().enumerate() {
        frames.push(call(100 + index as i64, name, arguments));
    }
    frames
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn value(&mut self, depth: usize) -> Value {
        match self.below(if depth > 2 { 6 } else { 8 }) {
            0 => Value::Null,
            1 => json!(self.below(2) == 0),
            2 => json!(self.next() as i64 % 1000),
            3 => json!((self.next() % 10_000) as f64 / 7.0),
            4 | 5 => json!(self.pick(&[
                "",
                "dev",
                "prod",
                "../x",
                "ls",
                "openai",
                "/v1/models",
                "GET",
                "é\u{1F600}",
                "a b",
                "TRACE",
                "api:x"
            ])),
            6 => Value::Array((0..self.below(4)).map(|_| self.value(depth + 1)).collect()),
            _ => {
                let keys = [
                    "env",
                    "argv",
                    "provider",
                    "path",
                    "method",
                    "body",
                    "headers",
                    "env_names",
                    "capability_names",
                    "cwd",
                    "private_cwd",
                    "reason",
                    "key",
                    "x",
                ];
                Value::Object(
                    (0..self.below(5))
                        .map(|_| (self.pick(&keys).to_owned(), self.value(depth + 1)))
                        .collect(),
                )
            }
        }
    }

    fn frame(&mut self) -> String {
        let methods = [
            "tools/call",
            "tools/call",
            "tools/call",
            "tools/list",
            "ping",
            "initialize",
            "notifications/initialized",
            "resources/list",
            "nope",
        ];
        let tools = [
            "kv_status",
            "kv_envs",
            "kv_list",
            "kv_run",
            "kv_api",
            "kv_query",
            "kv_ssh",
            "kv_set",
            "kv_rm",
            "kv_get",
            "kv_nope",
        ];
        let mut message = Map::new();
        if self.below(10) != 0 {
            message.insert("jsonrpc".into(), json!("2.0"));
        }
        match self.below(10) {
            0 => {}
            1 => {
                message.insert("id".into(), self.value(2));
            }
            _ => {
                message.insert("id".into(), json!(self.below(1000)));
            }
        }
        let method = self.pick(&methods);
        message.insert("method".into(), json!(method));
        let params = if method == "tools/call" && self.below(8) != 0 {
            let mut arguments = self.value(0);
            if let (Value::Object(map), true) = (&mut arguments, self.below(2) == 0) {
                map.insert("argv".into(), json!(["ls", "-l"]));
            }
            json!({"name": self.pick(&tools), "arguments": arguments})
        } else {
            self.value(1)
        };
        if self.below(6) != 0 {
            message.insert("params".into(), params);
        }
        let text = Value::Object(message).to_string();
        match self.below(25) {
            0 => text[..self.below(text.len().max(1))].to_owned(),
            1 => format!("  {text}\t"),
            _ => text,
        }
    }
}

fn fuzz_frames(seed: u64, count: usize) -> Vec<String> {
    let mut rng = Rng(seed);
    let mut frames = if seed.is_multiple_of(2) {
        init_frames()
    } else {
        Vec::new()
    };
    frames.extend((0..count).map(|_| rng.frame()));
    frames
}

fn set_key(project: &Project, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    let path = project.root.join(".secrets/key");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

const ALL_FLAGS: [&str; 4] = [
    "--allow-execute",
    "--allow-mutate",
    "--allow-reveal",
    "--allow-direct-vault-access",
];

#[test]
fn transcripts_match_python_with_and_without_the_daemon() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 7 MCP parity: set KV_PY_REF");
        return;
    };
    let _lock = HOME_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let project = project(&python);
    let _home = HomeGuard::set(&project.home);

    // Daemon not running: every daemon-backed tool says so.
    for flags in [&[][..], &["--allow-execute"][..], &ALL_FLAGS[..]] {
        assert_parity(
            &python,
            &project,
            flags,
            &protocol_frames(),
            "protocol, no daemon",
        );
        let out = assert_parity(&python, &project, flags, &tool_frames(), "tools, no daemon");
        if flags.is_empty() {
            assert!(out.contains("vault agent is not running"), "{out}");
        }
    }

    let daemon = spawn_rust_daemon(&project);
    // The status counts report the daemon's secret cache: warm it first so
    // both servers see the same, run-independent numbers.
    for env in ["dev", "prod"] {
        let mut fields = Map::new();
        fields.insert("env".into(), json!(env));
        kv_proto::agent_request(&project.root, "list", &fields).unwrap();
    }
    for flags in [&[][..], &["--allow-execute"][..], &ALL_FLAGS[..]] {
        assert_parity(
            &python,
            &project,
            flags,
            &protocol_frames(),
            "protocol, daemon",
        );
        let out = assert_parity(&python, &project, flags, &tool_frames(), "tools, daemon");
        assert!(out.contains("project: initialized (via daemon)"), "{out}");
    }
    for seed in 1..=40u64 {
        assert_parity(
            &python,
            &project,
            &["--allow-execute"],
            &fuzz_frames(seed, 60),
            &format!("fuzz seed {seed}, daemon"),
        );
    }
    drop(daemon);
    assert!(
        !kv_proto::agent_socket_path(Some(&project.root))
            .unwrap()
            .exists()
    );
}

#[test]
fn key_kinds_and_fatal_frames_match_python() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 7 MCP key-kind parity: set KV_PY_REF");
        return;
    };
    let _lock = HOME_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let project = project(&python);
    let _home = HomeGuard::set(&project.home);
    let original = fs::read(project.root.join(".secrets/key")).unwrap();
    let mut fatal = init_frames();
    fatal.push(format!("{}1{}", "[".repeat(989), "]".repeat(989)));
    fatal.push(json!({"id": 1, "method": "ping"}).to_string());
    let mut digits = init_frames();
    digits.push(format!("{{\"id\": {}}}", "7".repeat(4301)));
    digits.push(json!({"id": 1, "method": "ping"}).to_string());
    let mut tools_only = init_frames();
    tools_only.push(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string());
    for name in ["kv_query", "kv_ssh", "kv_set", "kv_rm", "kv_get"] {
        tools_only.push(call(2, name, json!({})));
    }
    let restricted: [&[&str]; 2] = [&["--allow-execute"], &ALL_FLAGS];
    let unrestricted: [&[&str]; 2] = [&[], &["--allow-execute"]];
    for (label, key, flag_sets) in [
        ("v4", original.clone(), &restricted),
        ("plaintext", vec![7u8; 32], &unrestricted),
        ("short", b"KVW".to_vec(), &restricted),
        (
            "unknown version",
            b"KVW\x09rest-of-key".to_vec(),
            &restricted,
        ),
        ("v2", b"KVW\x02rest-of-key".to_vec(), &unrestricted),
    ] {
        set_key(&project, &key);
        for flags in flag_sets.iter() {
            assert_parity(
                &python,
                &project,
                flags,
                &tools_only,
                &format!("key {label}"),
            );
            assert_parity(
                &python,
                &project,
                flags,
                &fuzz_frames(99, 40),
                &format!("key {label} fuzz"),
            );
        }
    }
    set_key(&project, &original);
    for (index, frames) in [fatal, digits].iter().enumerate() {
        assert_parity(
            &python,
            &project,
            &[],
            frames,
            &format!("fatal frame {index}"),
        );
    }
    // Python decodes stdin per 8 KiB chunk, so invalid UTF-8 also swallows the
    // earlier lines of its chunk; kv decodes per line. Compare the first frame.
    let bad_utf8 =
        b"{\"id\": 1, \"method\": \"\xff\"}\n{\"id\": 2, \"method\": \"ping\"}\n".to_vec();
    let (python_out, python_log) = run_python_server(&python, &project, &[], &bad_utf8);
    let (rust_out, rust_log) = run_rust_server(&project, &[], &bad_utf8);
    assert_eq!(rust_out, python_out);
    assert!(rust_out.is_empty());
    assert_eq!(rust_log, python_log);
    assert!(
        rust_log.contains("read error: 'utf-8' codec can't decode byte 0xff"),
        "{rust_log}"
    );
    let big = "x".repeat(3 * 1024 * 1024);
    let mut oversized = init_frames();
    oversized.push(json!({"jsonrpc": "2.0", "id": 1, "method": big}).to_string());
    oversized.push(call(2, "kv_list", json!({"env": big})));
    oversized.push(call(3, "kv_status", json!({"padding": big})));
    oversized.push(format!(
        "{{\"id\": 4, \"method\": \"ping\", \"params\": {{\"p\": \"{big}\"}}}}"
    ));
    assert_parity(&python, &project, &[], &oversized, "oversized frames");
}

#[test]
fn rust_server_stops_reading_past_its_line_cap() {
    let config = Config {
        root: PathBuf::from("/nonexistent-kv-mcp-root"),
        default_env: "dev".into(),
        profiles: profiles(&[]),
        allow_direct_vault_access: false,
    };
    let mut input = transcript(&init_frames());
    input.extend(std::iter::repeat_n(
        b' ',
        kv_mcp::server::MAX_LINE_BYTES + 1,
    ));
    input.extend_from_slice(b"\n{\"id\": 9, \"method\": \"ping\"}\n");
    let mut output = Vec::new();
    let mut log = Vec::new();
    kv_mcp::server::serve(&config, input.as_slice(), &mut output, &mut log);
    let output = String::from_utf8(output).unwrap();
    assert_eq!(output.lines().count(), 1, "{output}");
    assert!(output.contains("\"protocolVersion\""));
    let log = String::from_utf8(log).unwrap();
    assert!(
        log.contains(&format!(
            "read error: message exceeds {} bytes",
            kv_mcp::server::MAX_LINE_BYTES
        )),
        "{log}"
    );
    assert!(!log.contains("client disconnected"));
}

#[test]
fn rust_server_answers_without_python() {
    let _lock = HOME_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = TestDir::new();
    let root = dir.0.join("vault");
    fs::create_dir_all(root.join(".secrets")).unwrap();
    let home = dir.0.join("home");
    fs::create_dir(&home).unwrap();
    let _home = HomeGuard::set(&home);
    let config = Config {
        root: root.clone(),
        default_env: "dev".into(),
        profiles: profiles(&["--allow-execute"]),
        allow_direct_vault_access: false,
    };
    let mut frames = init_frames();
    frames.push(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string());
    frames.push(call(2, "kv_status", json!({})));
    frames.extend(fuzz_frames(7, 200));
    let mut output = Vec::new();
    let mut log = Vec::new();
    serve(
        &config,
        std::io::Cursor::new(transcript(&frames)),
        &mut output,
        &mut log,
    );
    let output = String::from_utf8(output).unwrap();
    let mut lines = output.lines();
    assert_eq!(
        lines.next().unwrap(),
        r#"{"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "kv", "version": "0.4.0"}}}"#
    );
    let listed: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "kv_status",
            "kv_envs",
            "kv_list",
            "kv_run",
            "kv_api",
            "kv_query",
            "kv_ssh"
        ]
    );
    assert!(lines.next().unwrap().contains("vault agent is not running"));
    for line in lines {
        let reply: Value = serde_json::from_str(line).expect("every reply is JSON");
        assert_eq!(reply["jsonrpc"], "2.0");
    }
    assert!(
        String::from_utf8(log)
            .unwrap()
            .ends_with("[kv_mcp] client disconnected (EOF)\n")
    );
}
