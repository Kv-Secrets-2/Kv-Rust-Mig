#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Stdio};

use kv_store::config;
use serde_json::{Value, json};

#[path = "support/owner.rs"]
mod owner;
use owner::{Scratch, kv_bin, normalise, pty};

const PASS: &str = "Passphrase: =>correct horse battery staple";
const YES: &str = "\\[y/N\\] =>y";

fn probe(python: &std::ffi::OsStr, root: &Path, script: &str, args: &[&str]) -> String {
    let output = Command::new(python)
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/py")
                .join(script),
        )
        .arg(root)
        .args(args)
        .env("HOME", root.parent().unwrap().join("home"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "reference probe: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end_matches('\n')
        .into()
}

#[test]
fn command_and_network_owner_sequences_match_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let python = owner::python3().expect("PTY driver interpreter");
    let scratch = Scratch::new("allow");
    assert_eq!(
        pty(
            &python,
            &[kv_bin()],
            &scratch.home(),
            &scratch.proj(),
            &["init", "--location", "project"],
            &[
                PASS,
                "Confirm: =>correct horse battery staple",
                "stored the key: =>saved"
            ]
        )
        .0,
        0
    );
    probe(
        &reference,
        &scratch.proj(),
        "approval_mode.py",
        &["snapshot"],
    );
    let steps: &[(&[&str], &[&str], i32, bool)] = &[
        (&["allow"], &[], 0, false),
        (&["allow", ""], &[], 0, false),
        (&["network-allow"], &[], 0, false),
        (&["allow", "python3 app.py"], &["\\[y/N\\] =>N"], 0, false),
        (&["allow", "python3 app.py"], &[YES, PASS], 0, false),
        (&["allow", "python3 app.py"], &[YES, PASS], 0, false),
        (&["allow"], &[], 0, false),
        (&["allow", "python3"], &[], 1, false),
        (&["allow", "*"], &[], 1, false),
        (&["deny", "missing"], &[YES, PASS], 0, false),
        (&["deny", "python3 app.py"], &["\\[y/N\\] =>N"], 0, false),
        (&["deny", "python3 app.py"], &[YES, PASS], 0, false),
        (&["allow"], &[], 0, false),
        (&["deny", "python3"], &[YES, PASS], 0, true),
        (&["allow"], &[], 0, false),
        (&["network-deny", "missing"], &[], 0, false),
        (
            &["network-allow", "twine upload"],
            &["\\[y/N\\] =>N"],
            0,
            false,
        ),
        (&["network-allow", "twine upload"], &[YES, PASS], 0, false),
        (&["network-allow", "twine upload"], &[YES, PASS], 0, false),
        (&["network-allow"], &[], 0, false),
        (
            &["network-deny", "twine upload"],
            &["\\[y/N\\] =>N"],
            0,
            false,
        ),
        (&["network-deny", "twine upload"], &[YES, PASS], 0, false),
        (&["network-allow"], &[], 0, false),
        (&["network-allow", "twine upload"], &[YES, PASS], 0, false),
        (
            &["approval-mode", "set", "protected-approval"],
            &[YES, PASS],
            0,
            false,
        ),
        (&["allow", "python3 app.py"], &[], 1, false),
        (&["allow"], &[], 0, false),
        (&["network-allow", "twine upload"], &[], 1, false),
        (&["network-allow"], &[], 0, false),
        (&["deny", "python3"], &[], 1, true),
        (&["deny", "python3 app.py"], &[YES, PASS], 0, false),
        (&["deny", "missing"], &[YES, PASS], 0, false),
        (&["network-deny", "missing"], &[], 0, false),
        (&["network-deny", "twine upload"], &[YES, PASS], 0, false),
    ];
    let mut runs = Vec::new();
    for command in [
        vec![kv_bin()],
        vec![reference.to_str().unwrap(), "-m", "kv"],
    ] {
        probe(
            &reference,
            &scratch.proj(),
            "approval_mode.py",
            &["restore"],
        );
        let mut run = Vec::new();
        for (args, rules, expected, seed) in steps {
            if *seed {
                probe(
                    &reference,
                    &scratch.proj(),
                    "allow_commands.py",
                    &["seed-broad"],
                );
            }
            let (code, text) = pty(
                &python,
                &command,
                &scratch.home(),
                &scratch.proj(),
                args,
                rules,
            );
            assert_eq!(code, *expected, "{args:?}: {text}");
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
        runs.push(run);
    }
    assert_eq!(runs[0], runs[1], "owner transcripts/config bytes differ");
    assert!(runs[0][4].1.contains("approval mode not chosen"));
    assert!(
        runs[0][13]
            .1
            .contains("removing it can let narrower entries after it apply again")
    );
    probe(
        &reference,
        &scratch.proj(),
        "approval_mode.py",
        &["restore"],
    );
    for args in [
        vec!["allow", "python3 app.py"],
        vec!["deny", "python3 app.py"],
        vec!["network-allow", "twine upload"],
        vec!["network-deny", "missing"],
        vec!["allow", "-h"],
        vec!["deny", "-h"],
        vec!["deny"],
        vec!["network-allow", "-h"],
        vec!["network-deny", "-h"],
        vec!["network-deny"],
    ] {
        let mut outputs = Vec::new();
        let before = std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap();
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            let output = Command::new(command[0])
                .args(&command[1..])
                .args(&args)
                .current_dir(scratch.proj())
                .env("HOME", scratch.home())
                .env("NO_COLOR", "1")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            outputs.push((output.status.code(), output.stdout, output.stderr));
        }
        assert_eq!(outputs[0], outputs[1], "{args:?}");
        assert_eq!(
            before,
            std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap()
        );
    }
    // Python lists malformed entries; Rust deliberately refuses them without rewriting.
    for (field, args) in [
        ("allowed_commands", vec!["allow"]),
        ("network_commands", vec!["network-allow"]),
        ("kv_run_policy", vec!["allow"]),
    ] {
        probe(
            &reference,
            &scratch.proj(),
            "approval_mode.py",
            &["restore"],
        );
        probe(
            &reference,
            &scratch.proj(),
            "allow_commands.py",
            &["malformed", field],
        );
        let before = std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap();
        let (pc, _) = pty(
            &python,
            &[reference.to_str().unwrap(), "-m", "kv"],
            &scratch.home(),
            &scratch.proj(),
            &args,
            &[],
        );
        assert_eq!(pc, 0);
        let (rc, text) = pty(
            &python,
            &[kv_bin()],
            &scratch.home(),
            &scratch.proj(),
            &args,
            &[],
        );
        assert_eq!(rc, 1);
        assert!(text.contains(if field == "kv_run_policy" {
            "must be a string"
        } else {
            "must be a list of command strings"
        }));
        assert_eq!(
            before,
            std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap()
        );
    }
}

#[test]
fn command_policy_storage_matches_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let scratch = Scratch::new("allow-storage");
    std::fs::create_dir(scratch.proj().join(".secrets")).unwrap();
    probe(
        &reference,
        &scratch.proj(),
        "approval_mode.py",
        &["record-created"],
    );
    let path = scratch.proj().join(".secrets/config.json");
    std::fs::write(&path, b"{}").unwrap();
    for (action, pattern) in [
        ("remove", "absent"),
        ("add", "python3 app.py"),
        ("add", "python3 app.py"),
        ("network", "twine upload"),
        ("network", "twine upload"),
        ("add", ""),
        ("remove", ""),
        ("remove", "python3 app.py"),
        ("remove", "absent"),
    ] {
        let before = std::fs::read(&path).unwrap();
        let result = match action {
            "add" => config::add_allowed_command(scratch.proj(), pattern),
            "remove" => config::remove_allowed_command(scratch.proj(), pattern),
            _ => config::add_network_command(scratch.proj(), pattern),
        }
        .unwrap();
        let after = std::fs::read(&path).unwrap();
        std::fs::write(&path, before).unwrap();
        assert_eq!(
            result.to_string(),
            probe(
                &reference,
                &scratch.proj(),
                "allow_commands.py",
                &[action, pattern]
            )
        );
        assert_eq!(after, std::fs::read(&path).unwrap());
        let (policy, allowed) = config::get_run_policy(scratch.proj()).unwrap();
        let expected: Value = serde_json::from_str(&probe(
            &reference,
            &scratch.proj(),
            "allow_commands.py",
            &["get"],
        ))
        .unwrap();
        assert_eq!(json!([policy, allowed]), expected);
    }
}
