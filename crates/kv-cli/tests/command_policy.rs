#![cfg(unix)]
use std::{
    path::Path,
    process::{Command, Stdio},
};
#[path = "support/owner.rs"]
mod owner;
use owner::{Scratch, kv_bin, normalise, pty};
const PASS: &str = "Passphrase: =>correct horse battery staple";
const YES: &str = "\\[y/N\\] =>y";
fn probe(python: &std::ffi::OsStr, root: &Path, name: &str, action: &str) -> String {
    let output = Command::new(python)
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/py")
                .join(name),
        )
        .arg(root)
        .arg(action)
        .env("HOME", root.parent().unwrap().join("home"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "probe: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn bytes(root: &Path) -> (Vec<u8>, Vec<u8>) {
    let config = std::fs::read(root.join(".secrets/config.json")).unwrap();
    let bytes = std::fs::read(root.join(".secrets/policy_requests.json")).unwrap_or_default();
    if bytes.is_empty() {
        return (config, bytes);
    }
    let original = String::from_utf8(bytes).unwrap();
    let mut normal = Vec::new();
    let mut decided = false;
    for line in original.lines() {
        if line.trim_start().starts_with("\"status\":") {
            decided = !line.contains("\"pending\"");
        }
        if decided && line.trim_start().starts_with("\"updated_at\":") {
            normal.push(format!(
                "{}\"updated_at\": \"DECISION_TIME\",",
                " ".repeat(line.len() - line.trim_start().len())
            ));
        } else if decided && line.trim_start().starts_with("\"updated_at_epoch\":") {
            normal.push(format!(
                "{}\"updated_at_epoch\": 0{}",
                " ".repeat(line.len() - line.trim_start().len()),
                if line.ends_with(',') { "," } else { "" }
            ));
        } else {
            normal.push(line.to_owned());
        }
    }
    (config, (normal.join("\n") + "\n").into_bytes())
}
#[test]
fn command_policy_owner_sequences_match_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let driver = owner::python3().unwrap();
    let scratch = Scratch::new("command-policy");
    assert_eq!(
        pty(
            &driver,
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
    probe(&reference, &scratch.proj(), "approval_mode.py", "snapshot");
    type Step<'a> = (&'a [&'a str], &'a [&'a str], i32, Option<&'a str>, bool);
    let steps: Vec<Step> = vec![
        (&["policy"], &[], 0, None, false),
        (&["policy", "list"], &[], 0, Some("seed"), false),
        (
            &["policy", "allow", "pol_cancel"],
            &["\\[y/N\\] =>N"],
            0,
            None,
            false,
        ),
        (
            &[
                "policy",
                "allow",
                "pol_allow",
                "--reason",
                " owner approval ",
            ],
            &[YES, PASS],
            0,
            None,
            true,
        ),
        (&["policy", "allow", "pol_allow"], &[], 1, None, false),
        (&["policy", "list", "--all"], &[], 0, None, false),
        (
            &["policy", "allow", "pol_allow"],
            &[],
            1,
            Some("unallow"),
            false,
        ),
        (&["policy", "list", "--all"], &[], 0, None, false),
        (
            &["policy", "block", "pol_block", "--reason", "kept blocked"],
            &[YES],
            0,
            None,
            true,
        ),
        (&["policy", "deny", "pol_deny"], &[YES], 0, None, true),
        (&["policy", "block", "pol_block"], &[], 1, None, false),
        (&["policy", "allow", "missing"], &[], 1, None, false),
        (&["policy", "block", "missing"], &[], 1, None, false),
        (&["policy", "allow", "pol_expired"], &[], 1, None, false),
        (&["policy", "block", "pol_expired"], &[], 1, None, false),
        (&["policy", "allow", "pol_broad"], &[], 1, None, false),
        (
            &["policy", "block", "pol_cancel"],
            &["\\[y/N\\] =>N"],
            0,
            None,
            false,
        ),
        (
            &["approval-mode", "set", "protected-approval"],
            &[YES, PASS],
            0,
            None,
            false,
        ),
        (&["policy", "allow", "pol_protected"], &[], 1, None, false),
        (&["policy", "block", "pol_protected"], &[YES], 0, None, true),
        (&["policy", "list", "--all"], &[], 0, None, false),
        (&["policy", "prune"], &[], 0, None, false),
        (&["policy", "prune"], &[], 0, Some("single"), false),
        (&["policy", "block", "pol_last"], &[YES], 0, None, true),
        (&["policy", "prune"], &[], 0, None, false),
        (
            &["policy", "block", "pol_last"],
            &[],
            1,
            Some("no-key"),
            false,
        ),
    ];
    let mut runs = Vec::new();
    for command in [
        vec![kv_bin()],
        vec![reference.to_str().unwrap(), "-m", "kv"],
    ] {
        probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
        let mut run = Vec::new();
        for (args, answers, expected, seed, audit) in &steps {
            if let Some(action) = seed {
                probe(&reference, &scratch.proj(), "command_policy.py", action);
            }
            let (code, output) = pty(
                &driver,
                &command,
                &scratch.home(),
                &scratch.proj(),
                args,
                answers,
            );
            assert_eq!(code, *expected, "{args:?}: {output}");
            assert!(!output.contains("correct horse battery staple"));
            let event = if *audit {
                Some(probe(
                    &reference,
                    &scratch.proj(),
                    "command_policy.py",
                    "audit",
                ))
            } else {
                None
            };
            run.push((
                code,
                normalise(&output, &scratch.root),
                bytes(&scratch.proj()),
                event,
            ));
            if *audit {
                let a = pty(
                    &driver,
                    &[kv_bin()],
                    &scratch.home(),
                    &scratch.proj(),
                    &["policy", "list", "--all"],
                    &[],
                );
                let b = pty(
                    &driver,
                    &[reference.to_str().unwrap(), "-m", "kv"],
                    &scratch.home(),
                    &scratch.proj(),
                    &["policy", "list", "--all"],
                    &[],
                );
                assert_eq!(a, b, "cross-implementation read after {args:?}");
            }
        }
        runs.push(run);
    }
    for (i, (rust, python)) in runs[0].iter().zip(&runs[1]).enumerate() {
        assert_eq!(rust, python, "step {i}: {:?}", steps[i].0);
    }
    assert!(
        runs[0]
            .iter()
            .any(|r| r.1.contains("1 pending command-policy request remain"))
    );
    assert!(
        runs[0]
            .iter()
            .any(|r| r.1.contains("0 pending command-policy requests remain"))
    );
    for malformed in ["bad-argv", "bad-cwd"] {
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
            probe(&reference, &scratch.proj(), "command_policy.py", "seed");
            probe(&reference, &scratch.proj(), "command_policy.py", malformed);
            let before = bytes(&scratch.proj());
            let (code, output) = pty(
                &driver,
                &command,
                &scratch.home(),
                &scratch.proj(),
                &["policy", "allow", "pol_allow"],
                &[],
            );
            assert_eq!(code, 1, "{malformed}: {output}");
            assert_eq!(before, bytes(&scratch.proj()));
            let expected = if command[0] == kv_bin() {
                "policy request"
            } else if malformed == "bad-argv" {
                "'int' object is not iterable"
            } else {
                "expected str, bytes or os.PathLike object, not int"
            };
            assert!(output.contains(expected), "{malformed}: {output}");
        }
    }
    for action in ["outside-cwd", "different-cwd"] {
        let mut outputs = Vec::new();
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
            probe(&reference, &scratch.proj(), "command_policy.py", "seed");
            probe(&reference, &scratch.proj(), "command_policy.py", action);
            let before = bytes(&scratch.proj());
            let result = pty(
                &driver,
                &command,
                &scratch.home(),
                &scratch.proj(),
                &["policy", "allow", "pol_allow"],
                &[],
            );
            assert_eq!(result.0, 1, "{action}: {}", result.1);
            assert_eq!(before, bytes(&scratch.proj()));
            outputs.push(result);
        }
        assert_eq!(outputs[0], outputs[1], "{action}");
    }
}
#[test]
fn command_policy_parser_matches_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let scratch = Scratch::new("command-parser");
    let mut cases = vec![vec!["policy", "unknown"]];
    for action in [
        "list", "allow", "block", "deny", "prune", "watch", "request",
    ] {
        cases.push(vec!["policy", action, "-h"]);
    }
    for action in ["allow", "block", "deny"] {
        cases.push(vec!["policy", action]);
        cases.push(vec!["policy", action, "pol_test", "--reason"]);
    }
    cases.push(vec!["policy", "watch", "--interval", "bad"]);
    cases.push(vec!["policy", "watch", "--interval", "bad", "-h"]);
    cases.push(vec!["policy", "request", "--ttl", "bad", "-h"]);
    cases.push(vec![
        "policy", "request", "--ttl", "bad", "--", "python3", "app.py",
    ]);
    for args in cases {
        let files = scratch.policy_files();
        let mut outputs = Vec::new();
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            let output = Command::new(command[0])
                .args(&command[1..])
                .args(&args)
                .env("HOME", scratch.home())
                .env("NO_COLOR", "1")
                .current_dir(scratch.proj())
                .stdin(Stdio::null())
                .output()
                .unwrap();
            outputs.push((output.status.code(), output.stdout, output.stderr));
            assert_eq!(files, scratch.policy_files(), "{args:?}");
        }
        assert_eq!(outputs[0].0, outputs[1].0, "{args:?}");
        if owner::argparse_text_compared() {
            assert_eq!(outputs[0], outputs[1], "{args:?}");
        } else if outputs[0].0 == Some(2) {
            assert_eq!(outputs[0].1, outputs[1].1, "{args:?}");
            for output in &outputs {
                assert!(output.2.starts_with(b"usage: "));
                assert!(String::from_utf8_lossy(&output.2).contains(": error: "));
            }
        } else {
            assert_eq!(outputs[0].0, Some(0), "{args:?}");
            assert!(args.contains(&"-h"));
            assert_eq!(outputs[0].2, outputs[1].2, "{args:?}");
        }
    }
    for args in [
        vec!["policy", "watch", "--all", "--follow", "--interval", "2"],
        vec!["policy", "watch", "--interval", "-2"],
        vec!["policy", "watch", "--interval", "1_000"],
        vec![
            "policy", "request", "--ttl", "-1", "--", "python3", "app.py",
        ],
        vec![
            "policy", "request", "--ttl", "900", "--reason", "test", "--", "python3", "app.py",
        ],
    ] {
        let output = Command::new(kv_bin())
            .args(args)
            .env("HOME", scratch.home())
            .env("NO_COLOR", "1")
            .current_dir(scratch.proj())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("not available in this build"));
    }
}
