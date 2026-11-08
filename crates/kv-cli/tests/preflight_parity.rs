//! Complete CLI transcripts, including ANSI colours and pseudo-terminal output.
#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn preflight_cli_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let root = std::env::temp_dir().join(format!("kv-cli-preflight-{}", std::process::id()));
    std::fs::create_dir_all(root.join("home")).unwrap();
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/preflight_probe.py"))
        .env("HOME", root.join("home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = serde_json::json!({"root":root, "binary":env!("CARGO_BIN_EXE_kv"), "version":env!("CARGO_PKG_VERSION")}).to_string();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    eprintln!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "fixtures retained at {}",
        root.display()
    );
    std::fs::remove_dir_all(root).unwrap();
}
