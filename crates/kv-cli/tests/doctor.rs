//! Blackbox regressions for the read-only first-install `kv doctor` check.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/owner.rs"]
mod owner;

use owner::{Scratch, kv_bin};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(scratch: &Scratch, args: &[&str]) -> (i32, String) {
    let output = Command::new(kv_bin())
        .args(args)
        .current_dir(scratch.proj())
        .env("HOME", scratch.home())
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), text)
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn write_file(path: &Path, contents: &[u8], mode: u32) {
    std::fs::write(path, contents).unwrap();
    set_mode(path, mode);
}

fn make_private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    set_mode(path, 0o700);
}

fn valid_config() -> &'static [u8] {
    br#"{
  "default_env": "dev",
  "environments": ["dev"],
  "storage": {"format": "drawers"},
  "security": {"passphrase": true, "totp": false, "approval_mode": "unset"},
  "canary": "CANARY-CONFIG-CONTENTS"
}
"#
}

fn make_valid_vault_shape(scratch: &Scratch) -> PathBuf {
    let secrets = scratch.proj().join(".secrets");
    make_private_dir(&secrets);
    write_file(&secrets.join("key"), b"CANARY-KEY-CONTENTS", 0o600);
    write_file(&secrets.join("config.json"), valid_config(), 0o600);
    write_file(
        &secrets.join("vault-marker"),
        b"CANARY-MARKER-CONTENTS",
        0o600,
    );
    write_file(&secrets.join(".gitignore"), b"*\n!.gitignore\n", 0o600);
    let drawers = secrets.join("drawers");
    make_private_dir(&drawers);
    let dev = drawers.join("dev");
    make_private_dir(&dev);
    write_file(&dev.join("drawer-canary"), b"CANARY-DRAWER-CONTENTS", 0o000);
    secrets
}

fn snapshot_tree(root: &Path) -> Vec<String> {
    fn walk(path: &Path, root: &Path, rows: &mut Vec<String>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let relative = path.strip_prefix(root).unwrap_or(path).display();
        let kind = if metadata.is_dir() {
            "dir"
        } else if metadata.is_file() {
            "file"
        } else if metadata.file_type().is_symlink() {
            "symlink"
        } else {
            "other"
        };
        rows.push(format!(
            "{relative}|{kind}|{}|{}|{}|{}|{}|{}",
            metadata.len(),
            metadata.mode() & 0o777,
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec()
        ));
        if metadata.is_dir() {
            let mut entries = std::fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            entries.sort();
            for entry in entries {
                walk(&entry, root, rows);
            }
        }
    }
    let mut rows = Vec::new();
    walk(root, root, &mut rows);
    rows.sort();
    rows
}

fn trusted_candidate(path: &str) -> Option<PathBuf> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 {
        Some(PathBuf::from(path))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn strace_available() -> bool {
    Command::new("strace")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn sandbox_ready() -> bool {
    let Some(bwrap) = [
        "/usr/bin/bwrap",
        "/bin/bwrap",
        "/usr/local/bin/bwrap",
        "/usr/sbin/bwrap",
        "/sbin/bwrap",
    ]
    .iter()
    .find_map(|path| trusted_candidate(path)) else {
        return false;
    };
    let Some(payload) = ["/usr/bin/true", "/bin/true"]
        .iter()
        .find_map(|path| trusted_candidate(path))
    else {
        return false;
    };
    Command::new(bwrap)
        .args([
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            "/tmp",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--unshare-net",
            "--unshare-pid",
        ])
        .arg(payload)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn doctor_parser_shape_is_minimal() {
    let scratch = Scratch::new("doctor-help");
    let (code, text) = run(&scratch, &["doctor", "--help"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("usage: kv doctor [-h]"), "{text}");

    let (code, text) = run(&scratch, &["doctor", "extra"]);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("unrecognized arguments: extra"), "{text}");
    assert!(text.contains("doctor"), "{text}");
}

#[test]
fn fresh_state_is_expected_before_init() {
    let sandbox_ready = sandbox_ready();
    if cfg!(target_os = "linux") && std::env::var_os("CI").is_some() {
        assert!(
            sandbox_ready,
            "Linux CI must install a trusted working bubblewrap for doctor success-path coverage"
        );
    }
    let scratch = Scratch::new("doctor-fresh");
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    if cfg!(target_os = "linux") && sandbox_ready {
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("0 errors"), "{text}");
    } else {
        assert_eq!(code, 1, "{text}");
    }
    assert!(
        text.contains("fresh user state: ~/.kv has not been created yet"),
        "{text}"
    );
    assert!(
        text.contains("fresh state: no vault found before kv init"),
        "{text}"
    );
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn valid_vault_shape_passes_without_opening_credential_files() {
    let scratch = Scratch::new("doctor-valid");
    make_valid_vault_shape(&scratch);
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    if cfg!(target_os = "linux") && sandbox_ready() {
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("0 errors"), "{text}");
    } else {
        assert_eq!(code, 1, "{text}");
        if cfg!(target_os = "linux") {
            assert!(text.contains("bubblewrap"), "{text}");
        } else {
            assert!(text.contains("Linux is required"), "{text}");
        }
    }
    assert!(
        text.contains("vault key file present (metadata only; contents not read)"),
        "{text}"
    );
    assert!(
        text.contains("vault config file present (metadata only; contents not read)"),
        "{text}"
    );
    assert!(
        text.contains("drawer storage present (entries not opened)"),
        "{text}"
    );
    assert!(text.contains("scope: metadata only"), "{text}");
    assert!(!text.contains("vault config valid"), "{text}");
    for canary in [
        "CANARY-KEY-CONTENTS",
        "CANARY-CONFIG-CONTENTS",
        "CANARY-MARKER-CONTENTS",
        "CANARY-DRAWER-CONTENTS",
    ] {
        assert!(!text.contains(canary), "{text}");
    }
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn config_permission_warning_is_not_hidden_by_validity() {
    let scratch = Scratch::new("doctor-config-mode");
    make_valid_vault_shape(&scratch);
    set_mode(&scratch.proj().join(".secrets").join("config.json"), 0o644);
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    if cfg!(target_os = "linux") && sandbox_ready() {
        assert_eq!(code, 0, "{text}");
    }
    assert!(
        text.contains("vault config privacy needs review: group or other users have access"),
        "{text}"
    );
    assert!(text.contains("scope: metadata only"), "{text}");
    assert!(!text.contains("vault config valid"), "{text}");
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn partial_vault_is_broken_not_fresh() {
    let scratch = Scratch::new("doctor-partial");
    let secrets = scratch.proj().join(".secrets");
    make_private_dir(&secrets);
    write_file(&secrets.join("config.json"), valid_config(), 0o600);
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    assert_eq!(code, 1, "{text}");
    assert!(!text.contains("fresh state: no vault found"), "{text}");
    assert!(text.contains("vault key file missing"), "{text}");
    assert!(text.contains("drawer storage directory missing"), "{text}");
    assert!(text.contains("vault marker missing"), "{text}");
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn wrong_secrets_shape_is_broken_not_fresh() {
    let scratch = Scratch::new("doctor-shape");
    std::fs::write(scratch.proj().join(".secrets"), b"not a directory").unwrap();
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("broken setup: .secrets exists but is not a real directory"),
        "{text}"
    );
    assert!(!text.contains("fresh state: no vault found"), "{text}");
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn config_contents_are_outside_structural_scope() {
    let scratch = Scratch::new("doctor-config");
    make_valid_vault_shape(&scratch);
    write_file(
        &scratch.proj().join(".secrets").join("config.json"),
        b"CANARY-CONFIG-CONTENTS",
        0o600,
    );
    let before = snapshot_tree(&scratch.root);
    let (_code, text) = run(&scratch, &["doctor"]);
    assert!(
        text.contains("vault config file present (metadata only; contents not read)"),
        "{text}"
    );
    assert!(!text.contains("vault config is not valid JSON"), "{text}");
    assert!(!text.contains("CANARY-CONFIG-CONTENTS"), "{text}");
    assert!(text.contains("semantic corruption"), "{text}");
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn unwritable_home_is_unhealthy_before_init() {
    if rustix::process::getuid().as_raw() == 0 {
        eprintln!("SKIP doctor unwritable-home regression: root can write through mode bits");
        return;
    }
    let scratch = Scratch::new("doctor-unwritable-home");
    set_mode(&scratch.home(), 0o555);
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("HOME does not allow creating ~/.kv"),
        "{text}"
    );
    assert!(
        !text.contains("fresh user state: ~/.kv has not been created yet"),
        "{text}"
    );
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn read_only_state_dir_is_repairable_not_false_failure() {
    let scratch = Scratch::new("doctor-repairable-state");
    make_valid_vault_shape(&scratch);
    let state = scratch.home().join(".kv");
    std::fs::create_dir(&state).unwrap();
    set_mode(&state, 0o500);
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    if cfg!(target_os = "linux") && sandbox_ready() {
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("0 errors"), "{text}");
    }
    assert!(text.contains("~/.kv exists and is private"), "{text}");
    assert!(!text.contains("~/.kv cannot be opened"), "{text}");
    assert!(
        !text.contains("does not allow write and search access"),
        "{text}"
    );
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn key_mode_that_unlock_rejects_is_unhealthy() {
    let scratch = Scratch::new("doctor-key-mode");
    make_valid_vault_shape(&scratch);
    set_mode(&scratch.proj().join(".secrets").join("key"), 0o400);
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("vault key file mode is not owner-only 0600; kv unlock will refuse it"),
        "{text}"
    );
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[test]
fn linked_ignore_file_is_unhealthy() {
    let scratch = Scratch::new("doctor-ignore-link");
    let secrets = make_valid_vault_shape(&scratch);
    let ignore = secrets.join(".gitignore");
    std::fs::remove_file(&ignore).unwrap();
    let target = scratch.root.join("shared-ignore");
    std::fs::write(&target, b"*\n!.gitignore\n").unwrap();
    std::os::unix::fs::symlink(&target, &ignore).unwrap();
    let before = snapshot_tree(&scratch.root);
    let (code, text) = run(&scratch, &["doctor"]);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains(".gitignore exists but is not a regular file"),
        "{text}"
    );
    assert_eq!(
        snapshot_tree(&scratch.root),
        before,
        "doctor changed the filesystem"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_does_not_open_vault_paths_on_linux() {
    if !strace_available() {
        eprintln!("SKIP doctor file-access regression: strace is unavailable");
        return;
    }
    let scratch = Scratch::new("doctor-strace");
    let secrets = std::fs::canonicalize(make_valid_vault_shape(&scratch)).unwrap();
    let trace_path = scratch.root.join("doctor.strace");
    let output = Command::new("strace")
        .arg("-f")
        .arg("-o")
        .arg(&trace_path)
        .arg("-e")
        .arg("trace=%file")
        .arg(kv_bin())
        .arg("doctor")
        .current_dir(scratch.proj())
        .env("HOME", scratch.home())
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        output
            .status
            .code()
            .is_some_and(|code| (0..=1).contains(&code)),
        "strace did not run kv doctor to completion: {output:?}"
    );
    let trace = std::fs::read_to_string(&trace_path).unwrap();
    let binary_text = kv_bin();
    let secrets_text = secrets.to_string_lossy();
    assert!(
        trace
            .lines()
            .any(|line| line.contains("execve(") && line.contains(binary_text)),
        "strace did not record launching kv doctor"
    );
    assert!(
        trace
            .lines()
            .any(|line| line.contains(secrets_text.as_ref())),
        "strace did not record doctor inspecting vault metadata"
    );
    let opened = trace
        .lines()
        .filter(|line| {
            let touches_vault = line.contains(secrets_text.as_ref())
                || line.contains("\".secrets")
                || line.contains("./.secrets");
            if !touches_vault {
                return false;
            }
            let Some((prefix, _)) = line.split_once('(') else {
                return false;
            };
            let call = prefix.split_whitespace().last().unwrap_or_default();
            matches!(call, "open" | "openat" | "openat2" | "creat")
        })
        .collect::<Vec<_>>();
    assert!(
        opened.is_empty(),
        "doctor opened vault paths instead of using metadata only:\n{}",
        opened.join("\n")
    );
}
