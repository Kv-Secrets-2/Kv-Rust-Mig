#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use kv_store::config;
use serde_json::json;

#[path = "support/owner.rs"]
mod owner;
use owner::{Scratch, kv_bin, normalise, pty};

const PASS: &str = "Passphrase: =>correct horse battery staple";
const YES: &str = "\\[y/N\\] =>y";

fn probe(python: &std::ffi::OsStr, root: &Path, args: &[&str]) -> String {
    let output = Command::new(python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/approval_mode.py"))
        .arg(root)
        .args(args)
        .env("HOME", root.parent().unwrap().join("home"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "reference probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned()
}

#[test]
fn approval_mode_owner_sequence_matches_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let python = owner::python3().expect("PTY driver interpreter");
    let scratch = Scratch::new("approval");
    let (code, _) = pty(
        &python,
        &[kv_bin()],
        &scratch.home(),
        &scratch.proj(),
        &["init", "--location", "project"],
        &[
            PASS,
            "Confirm: =>correct horse battery staple",
            "stored the key: =>saved",
        ],
    );
    assert_eq!(code, 0);
    probe(&reference, &scratch.proj(), &["snapshot"]);
    let steps: &[(&[&str], &[&str], i32)] = &[
        (&["approval-mode", "status"], &[], 0),
        (&["approval-mode"], &[], 0),
        (
            &["approval-mode", "set", "local-convenience"],
            &["\\[y/N\\] =>N"],
            0,
        ),
        (
            &["approval-mode", "set", "local-convenience"],
            &[
                YES,
                "Passphrase: =>wrong one",
                "Passphrase: =>wrong two",
                "Passphrase: =>wrong three",
            ],
            1,
        ),
        (
            &["approval-mode", "set", "local-convenience"],
            &[YES, PASS],
            0,
        ),
        (&["approval-mode", "set", "local-convenience"], &[], 0),
        (&["approval-mode", "status"], &[], 0),
        (
            &["approval-mode", "set", "unsafe-convenience"],
            &[YES, PASS],
            0,
        ),
        (&["approval-mode", "status"], &[], 0),
        (
            &["approval-mode", "set", "protected-approval"],
            &[YES, PASS],
            0,
        ),
        (&["approval-mode", "set", "local-convenience"], &[], 1),
        (&["approval-mode", "set", "protected-approval"], &[], 0),
        (&["approval-mode", "status"], &[], 0),
    ];
    let mut outputs = Vec::new();
    for command in [
        vec![kv_bin()],
        vec![reference.to_str().unwrap(), "-m", "kv"],
    ] {
        probe(&reference, &scratch.proj(), &["restore"]);
        let mut run = Vec::new();
        for (args, rules, expected) in steps {
            let (code, text) = pty(
                &python,
                &command,
                &scratch.home(),
                &scratch.proj(),
                args,
                rules,
            );
            assert_eq!(code, *expected, "{args:?}: unexpected exit: {text}");
            assert!(
                !text.contains("correct horse battery staple"),
                "passphrase echoed"
            );
            run.push((
                code,
                normalise(&text, &scratch.root),
                std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap(),
            ));
        }
        outputs.push(run);
    }
    assert_eq!(
        outputs[0], outputs[1],
        "owner transcripts/config bytes differ"
    );

    // Compare separate stdout/stderr too, including the no-terminal refusal before protection.
    probe(&reference, &scratch.proj(), &["restore"]);
    for args in [
        vec!["approval-mode", "set", "local-convenience"],
        vec!["approval-mode", "set", "bad"],
        vec!["approval-mode", "set"],
        vec!["approval-mode", "bad"],
        vec!["approval-mode", "-h"],
        vec!["approval-mode", "set", "-h"],
        vec!["approval-mode", "status", "-h"],
    ] {
        let before = std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap();
        let mut outputs = Vec::new();
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            let out = Command::new(command[0])
                .args(&command[1..])
                .args(&args)
                .current_dir(scratch.proj())
                .env("HOME", scratch.home())
                .env("NO_COLOR", "1")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            outputs.push((out.status.code(), out.stdout, out.stderr));
        }
        assert_eq!(outputs[0], outputs[1], "{args:?}");
        assert_eq!(
            before,
            std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap()
        );
    }

    probe(&reference, &scratch.proj(), &["totp"]);
    let before = std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap();
    // Python reaches its code prompt; Rust deliberately refuses rather than bypassing 2FA.
    let (pc, po) = pty(
        &python,
        &[reference.to_str().unwrap(), "-m", "kv"],
        &scratch.home(),
        &scratch.proj(),
        &["approval-mode", "set", "unsafe-convenience"],
        &[
            YES,
            PASS,
            "code.*: =>cancel",
            "code.*: =>cancel",
            "code.*: =>cancel",
        ],
    );
    assert_ne!(pc, 0);
    assert!(po.contains("2FA code is required too"));
    let (rc, ro) = pty(
        &python,
        &[kv_bin()],
        &scratch.home(),
        &scratch.proj(),
        &["approval-mode", "set", "unsafe-convenience"],
        &[],
    );
    assert_eq!(rc, 1);
    assert!(ro.contains(
        "two-factor authentication, which is not supported by this build; nothing was changed"
    ));
    assert_eq!(
        before,
        std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap()
    );
}

#[test]
fn approval_mode_storage_and_authorization_lock_match_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let scratch = Scratch::new("mode-storage");
    std::fs::create_dir(scratch.proj().join(".secrets")).unwrap();
    probe(&reference, &scratch.proj(), &["record-created"]);
    let path = scratch.proj().join(".secrets/config.json");
    for value in [
        json!({}),
        json!({"security": {"approval_mode": null}}),
        json!({"security": {"approval_mode": "invalid"}}),
        json!({"security": {"approval_mode": "unset"}}),
    ] {
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            config::get_approval_mode(scratch.proj()).unwrap(),
            probe(&reference, &scratch.proj(), &["get"])
        );
    }
    std::fs::write(&path, b"{}").unwrap();
    for value in [
        json!({"security": null}),
        json!({"security": []}),
        json!({"security": {"approval_mode": []}}),
        json!({"security": {"approval_mode": {}}}),
    ] {
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = config::get_approval_mode(scratch.proj()).unwrap_err();
        assert_eq!(
            format!("error: {error}"),
            probe(&reference, &scratch.proj(), &["get"])
        );
    }
    std::fs::write(&path, b"{}").unwrap();
    for mode in [
        "local-convenience",
        "local-convenience",
        "protected-approval",
        "unsafe-convenience",
        "unset",
        "",
        "bad",
    ] {
        let before = std::fs::read(&path).unwrap();
        let rust = config::set_approval_mode(scratch.proj(), mode)
            .map(|v| v.to_string())
            .unwrap_or_else(|e| e.to_string());
        let expected = std::fs::read(&path).unwrap();
        std::fs::write(&path, &before).unwrap();
        assert_eq!(rust, probe(&reference, &scratch.proj(), &["set", mode]));
        assert_eq!(expected, std::fs::read(&path).unwrap());
        assert_eq!(
            config::get_approval_mode(scratch.proj()).unwrap(),
            probe(&reference, &scratch.proj(), &["get"])
        );
    }
    {
        let _lock = config::authorization_lock(scratch.proj()).unwrap();
        assert_eq!(probe(&reference, &scratch.proj(), &["try-lock"]), "blocked");
        // Reentrant just like Python's private authorization transactions.
        config::set_approval_mode(scratch.proj(), "local-convenience").unwrap();
    }
    assert_eq!(
        probe(&reference, &scratch.proj(), &["try-lock"]),
        "available"
    );
    let mut child = Command::new(&reference)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/approval_mode.py"))
        .arg(scratch.proj())
        .arg("lock")
        .env("HOME", scratch.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "locked");
    let root = scratch.proj();
    let (send, receive) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        send.send(config::set_approval_mode(root, "protected-approval"))
            .unwrap();
    });
    assert!(
        receive
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err()
    );
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(
        receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap()
            .unwrap()
    );
    writer.join().unwrap();
}
