#![cfg(unix)]

#[path = "../../../tests/support/harness.rs"]
mod harness;

use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kv_audit::{Audit, ChainKey, ChainPosition, ChainTrust, VaultIdentity};
use serde_json::{Map, Value, json};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        Self(harness::socket_temp_dir("audit-cli", ""))
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn key() -> ChainKey {
    ChainKey::new([0x42; 32])
}

fn identity() -> VaultIdentity {
    VaultIdentity::new(b"cli-fixture-vault-identity").unwrap()
}

fn write_log(directory: &Path) -> ChainPosition {
    fs::create_dir(directory).unwrap();
    let trust = ChainTrust::new(key(), identity(), ChainPosition::genesis());
    let audit = Audit::with_authenticated_chain(directory, trust);
    let mut fields = Map::new();
    fields.insert("fixture".into(), Value::String("cli".into()));
    audit.emit("verifier-cli", fields).unwrap();
    audit.authenticated_chain_position().unwrap()
}

fn trust_file(root: &Path, position: ChainPosition) -> PathBuf {
    let path = root.join("trust.json");
    let trust = json!({
        "v": 1,
        "key": "42".repeat(32),
        "identity": "636c692d666978747572652d7661756c742d6964656e74697479",
        "head": position.head.to_hex(),
        "count": position.count,
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    use std::io::Write;
    file.write_all(trust.to_string().as_bytes()).unwrap();
    path
}

fn verifier(directory: &Path, trust: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kv-audit-verify"));
    command.arg("--directory").arg(directory);
    if let Some(trust) = trust {
        command.arg("--trust-file").arg(trust);
    }
    command.output().unwrap()
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn verifier_command_distinguishes_valid_missing_truncated_and_lost_history() {
    let temp = Temp::new();
    let directory = temp.0.join("audit");
    let position = write_log(&directory);
    let trust = trust_file(&temp.0, position);

    let valid = verifier(&directory, Some(&trust));
    assert_eq!(valid.status.code(), Some(0));
    assert_eq!(report(&valid)["status"], "valid");
    assert_eq!(report(&valid)["count"], 1);
    assert_eq!(report(&valid)["head"], position.head.to_hex());

    let missing = verifier(&directory, None);
    assert_eq!(missing.status.code(), Some(13));
    assert_eq!(report(&missing)["status"], "missing_trust_state");

    let log = directory.join("audit.jsonl");
    let original = fs::read(&log).unwrap();
    fs::write(&log, &original[..original.len() - 1]).unwrap();
    let truncated = verifier(&directory, Some(&trust));
    assert_eq!(truncated.status.code(), Some(10));
    assert_eq!(report(&truncated)["status"], "truncated");

    fs::write(&log, original).unwrap();
    fs::remove_file(&log).unwrap();
    let lost = verifier(&directory, Some(&trust));
    assert_eq!(lost.status.code(), Some(12));
    assert_eq!(report(&lost)["status"], "continuity_loss");
}

#[test]
fn verifier_command_reports_corruption_and_refuses_exposed_trust_files() {
    let help = Command::new(env!("CARGO_BIN_EXE_kv-audit-verify"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("usage: kv-audit-verify"));

    let temp = Temp::new();
    let directory = temp.0.join("audit");
    let position = write_log(&directory);
    let trust = trust_file(&temp.0, position);

    let log = directory.join("audit.jsonl");
    let bytes = fs::read(&log).unwrap();
    let needle = b"verifier-cli";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap();
    let mut corrupted = bytes;
    corrupted[offset] = b'X';
    fs::write(&log, corrupted).unwrap();
    let output = verifier(&directory, Some(&trust));
    assert_eq!(output.status.code(), Some(11));
    assert_eq!(report(&output)["status"], "corrupted");
    assert_eq!(report(&output)["reason"], "authentication_mismatch");

    let exposed = temp.0.join("exposed-trust.json");
    fs::copy(&trust, &exposed).unwrap();
    let metadata = fs::metadata(&exposed).unwrap();
    let mut permissions = metadata.permissions();
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o644);
    fs::set_permissions(&exposed, permissions).unwrap();
    let refused = verifier(&directory, Some(&exposed));
    assert_eq!(refused.status.code(), Some(64));
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("no group/other access"));
}
