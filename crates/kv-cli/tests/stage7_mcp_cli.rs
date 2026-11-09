//! `kv mcp-server` against `python -I -m kv_mcp`: argument handling, warnings,
//! the missing-project exit and the startup/EOF log, compared byte for byte.
#![cfg(unix)]
//! Needs `KV_PY_REF` (the reference interpreter); skips without it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("kv-mcp-cli-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(mut command: Command, cwd: &Path, home: &Path) -> Output {
    command
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("KV_MASTER_KEY")
        .env_remove("KV_PASSPHRASE")
        .env("PYTHONIOENCODING", "utf-8")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    for item in fs::read_dir(source).unwrap() {
        let item = item.unwrap();
        let target = destination.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_dir(&item.path(), &target);
        } else {
            fs::copy(item.path(), target).unwrap();
        }
    }
}

fn run_python(python: &std::ffi::OsStr, code: &str, home: &Path, args: &[&str]) {
    let output = Command::new(python)
        .args(["-I", "-c", code])
        .args(args)
        .env("HOME", home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A throwaway copy of the v4 fixture vault, approved for this machine by
/// the reference implementation.
fn approved_vault(python: &std::ffi::OsStr, root: &Path, home: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v0.4.0/vaults");
    copy_dir(&fixture.join("basic/.secrets"), &root.join(".secrets"));
    fs::set_permissions(root.join(".secrets"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    let expected: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.join("basic.expected.json")).unwrap()).unwrap();
    let passphrase = expected["passphrase"].as_str().unwrap();
    let root_text = root.to_str().unwrap();
    run_python(
        python,
        "import sys\nfrom kv import vault_origin\nvault_origin.record_created(sys.argv[1])",
        home,
        &[root_text],
    );
    run_python(
        python,
        "import sys\nfrom kv.owner_key import relocate_key_file\nrelocate_key_file(sys.argv[1],sys.argv[2])",
        home,
        &[root_text, passphrase],
    );
    let blob = fs::read(root.join(".secrets/key")).unwrap();
    let identity = kv_crypto::keyfile::unwrap_v4(&blob, passphrase.as_bytes()).unwrap();
    let master = kv_crypto::Key32::new(*identity.master_key.as_bytes());
    set_home(home);
    kv_store::config_authority::approve_config_unattended(root, &master).unwrap();
}

#[allow(unsafe_code)]
fn set_home(home: &Path) {
    // SAFETY: the only test in this binary; nothing else reads HOME meanwhile.
    unsafe { std::env::set_var("HOME", home) };
}

/// Python dies with a traceback here; kv logs the exception's message.
fn compare_crash(python: &std::ffi::OsStr, cwd: &Path, home: &Path, label: &str) {
    let mut reference = Command::new(python);
    reference.args(["-I", "-m", "kv_mcp"]);
    let mut rust = Command::new(env!("CARGO_BIN_EXE_kv"));
    rust.arg("mcp-server");
    let expected = run(reference, cwd, home);
    let actual = run(rust, cwd, home);
    let traceback = String::from_utf8_lossy(&expected.stderr);
    let last = traceback.lines().last().unwrap();
    let message = last.split_once(": ").unwrap().1;
    assert_eq!(
        String::from_utf8_lossy(&actual.stderr),
        format!("[kv_mcp] error: {message}\n"),
        "{label}"
    );
    assert!(
        actual.stdout.is_empty() && expected.stdout.is_empty(),
        "{label}"
    );
    assert_eq!(
        actual.status.code(),
        expected.status.code(),
        "{label}: exit"
    );
}

fn compare(python: &std::ffi::OsStr, flags: &[&str], cwd: &Path, home: &Path, label: &str) {
    let mut reference = Command::new(python);
    reference.args(["-I", "-m", "kv_mcp"]).args(flags);
    let mut rust = Command::new(env!("CARGO_BIN_EXE_kv"));
    rust.arg("mcp-server").args(flags);
    let expected = run(reference, cwd, home);
    let actual = run(rust, cwd, home);
    assert_eq!(
        String::from_utf8_lossy(&actual.stderr),
        String::from_utf8_lossy(&expected.stderr),
        "{label}: stderr"
    );
    assert_eq!(
        String::from_utf8_lossy(&actual.stdout),
        String::from_utf8_lossy(&expected.stdout),
        "{label}: stdout"
    );
    assert_eq!(
        actual.status.code(),
        expected.status.code(),
        "{label}: exit"
    );
}

#[test]
fn mcp_server_command_line_matches_python() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Stage 7 MCP CLI parity: set KV_PY_REF");
        return;
    };
    let home = TempDir::new("home");
    let empty = TempDir::new("empty");
    let unapproved = TempDir::new("unapproved");
    fs::create_dir(unapproved.0.join(".secrets")).unwrap();
    compare_crash(&python, &unapproved.0, &home.0, "unapproved vault");
    let project = TempDir::new("project");
    approved_vault(&python, &project.0, &home.0);
    let nested = project.0.join("a/b");
    fs::create_dir_all(&nested).unwrap();
    let cases: &[(&str, &[&str], &Path)] = &[
        ("help", &["--help"], &project.0),
        ("short help", &["-h"], &project.0),
        ("unknown flag", &["--bogus", "x"], &project.0),
        ("mutate alone", &["--allow-mutate"], &project.0),
        (
            "reveal alone",
            &["--allow-reveal", "--allow-execute"],
            &project.0,
        ),
        ("no project", &[], &empty.0),
        ("no project, flags", &["--allow-execute"], &empty.0),
        ("safe", &[], &project.0),
        ("nested cwd", &[], &nested),
        ("execute", &["--allow-execute"], &project.0),
        ("direct", &["--allow-direct-vault-access"], &project.0),
        (
            "all",
            &[
                "--allow-execute",
                "--allow-mutate",
                "--allow-reveal",
                "--allow-direct-vault-access",
            ],
            &project.0,
        ),
        (
            "repeated",
            &["--allow-execute", "--allow-execute"],
            &project.0,
        ),
    ];
    for (label, flags, cwd) in cases {
        compare(&python, flags, cwd, &home.0, label);
    }
}
