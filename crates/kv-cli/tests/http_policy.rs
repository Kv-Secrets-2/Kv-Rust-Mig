#![cfg(unix)]
use std::path::Path;
use std::process::{Command, Stdio};
#[path = "support/owner.rs"]
mod owner;
use owner::{Scratch, kv_bin, normalise, pty};

const PASS: &str = "Passphrase: =>correct horse battery staple";
const YES: &str = "\\[y/N\\] =>y";

fn probe(python: &std::ffi::OsStr, root: &Path, script: &str, action: &str) {
    let output = Command::new(python)
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/py")
                .join(script),
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
}
type Step = (Vec<String>, Vec<&'static str>, i32, Option<&'static str>);
fn step(args: &[&str], confirm: bool, code: i32) -> Step {
    (
        args.iter().map(|s| (*s).into()).collect(),
        if confirm { vec![YES, PASS] } else { vec![] },
        code,
        None,
    )
}
fn add(provider: &str, id: &str, extras: &[&str], confirm: bool, code: i32) -> Step {
    let mut args = vec!["policy", "http", "add", provider, "--id", id];
    args.extend(extras);
    step(&args, confirm, code)
}

#[test]
fn http_policy_owner_sequences_match_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let python = owner::python3().expect("PTY driver");
    let scratch = Scratch::new("http-policy");
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
    probe(&reference, &scratch.proj(), "approval_mode.py", "snapshot");
    let mut cancel = add("github", "user-read", &["--path", "/user"], false, 0);
    cancel.1 = vec!["\\[y/N\\] =>N"];
    let mut steps = vec![
        step(&["policy", "http"], false, 0),
        cancel,
        step(&["policy", "http", "list"], false, 0),
        add("github", "user-read", &["--path", "/user"], true, 0),
        step(&["policy", "http", "list"], false, 0),
        step(&["policy", "http", "list", "github"], false, 0),
        step(&["policy", "http", "list", "unknown"], false, 0),
        add("github", "user-read", &["--path", "/user"], false, 1),
        step(
            &[
                "provider",
                "add",
                "custom",
                "--url",
                "https://1.1.1.1",
                "--secret",
                "TOKEN",
            ],
            true,
            0,
        ),
        step(
            &[
                "provider",
                "add",
                "database",
                "--type",
                "redis",
                "--host",
                "db.example",
                "--secret",
                "TOKEN",
            ],
            true,
            0,
        ),
        add(
            "custom",
            "read-prefix",
            &[
                "--method",
                "get",
                "--method",
                "HEAD",
                "--path-prefix",
                "/v1",
                "--query-key",
                "q",
                "--query-key",
                "page",
                "--header",
                "X-Trace",
                "--header",
                "Accept",
            ],
            true,
            0,
        ),
        add(
            "custom",
            "read",
            &["--method", "GET", "--path", "/user"],
            true,
            0,
        ),
        add(
            "custom",
            "auth-header",
            &["--path", "/header", "--header", "Authorization"],
            true,
            0,
        ),
        step(&["policy", "http", "list"], false, 0),
    ];
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        steps.push(add(
            "custom",
            method,
            &["--method", method, "--path", "/write"],
            true,
            0,
        ));
    }
    steps.push(add(
        "custom",
        "mixed",
        &["--method", "GET", "--method", "POST", "--path", "/write"],
        false,
        1,
    ));
    steps.push(add(
        "custom",
        "method",
        &["--method", "TRACE", "--path", "/write"],
        false,
        1,
    ));
    steps.push(add(
        "custom",
        "method",
        &["--method", "GET", "--method", "get", "--path", "/user"],
        false,
        1,
    ));
    for path in [
        "relative",
        "/user?q=1",
        "/a/../b",
        "/a/%2e%2e/b",
        "//elsewhere",
        "/user#fragment",
        "",
    ] {
        steps.push(add("custom", "bad-path", &["--path", path], false, 1));
    }
    for key in ["_method", "bad key"] {
        steps.push(add(
            "custom",
            "bad-query",
            &["--path", "/user", "--query-key", key],
            false,
            1,
        ));
    }
    for header in ["Host", "Bad_Header"] {
        steps.push(add(
            "custom",
            "bad-header",
            &["--path", "/user", "--header", header],
            false,
            1,
        ));
    }
    steps.push(add(
        "custom",
        "bad-query",
        &["--path", "/user", "--query-key", "q", "--query-key", "q"],
        false,
        1,
    ));
    steps.push(add(
        "custom",
        "bad-header",
        &[
            "--path", "/user", "--header", "X-Trace", "--header", "x-trace",
        ],
        false,
        1,
    ));
    steps.push(add("custom", "bad id", &["--path", "/user"], false, 1));
    steps.push(add("unknown", "read", &["--path", "/user"], false, 1));
    steps.push(add("database", "read", &["--path", "/user"], false, 1));
    steps.push(step(
        &["policy", "http", "remove", "custom", "read"],
        true,
        0,
    ));
    steps.push(step(
        &["policy", "http", "remove", "custom", "missing"],
        false,
        1,
    ));
    steps.push(step(
        &["policy", "http", "rm", "custom", "auth-header"],
        true,
        0,
    ));
    let mut repair = step(&["policy", "http", "remove", "github", "broken"], true, 0);
    repair.3 = Some("repair");
    steps.push(repair);
    let mut cancel = step(
        &["policy", "http", "remove", "github", "user-read"],
        false,
        0,
    );
    cancel.1 = vec!["\\[y/N\\] =>N"];
    steps.push(cancel);
    steps.push(step(
        &["approval-mode", "set", "protected-approval"],
        true,
        0,
    ));
    steps.push(add("github", "blocked", &["--path", "/blocked"], false, 1));
    steps.push(step(
        &["policy", "http", "remove", "custom", "POST"],
        true,
        0,
    ));
    let mut repair = step(&["policy", "http", "rm", "github", "broken"], false, 1);
    repair.3 = Some("repair");
    steps.push(repair);
    steps.push(step(&["policy", "http", "list", "github"], false, 1));
    let mut runs = vec![];
    for command in [
        vec![kv_bin()],
        vec![reference.to_str().unwrap(), "-m", "kv"],
    ] {
        probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
        let mut run = vec![];
        for (args, rules, expected, seed) in &steps {
            if let Some(action) = seed {
                probe(&reference, &scratch.proj(), "http_policy.py", action);
            }
            let args: Vec<_> = args.iter().map(String::as_str).collect();
            let (code, text) = pty(
                &python,
                &command,
                &scratch.home(),
                &scratch.proj(),
                &args,
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
    for (index, (rust, python)) in runs[0].iter().zip(&runs[1]).enumerate() {
        assert_eq!(
            rust, python,
            "HTTP policy step {index}: {:?}",
            steps[index].0
        );
    }
    assert!(
        runs[0]
            .iter()
            .any(|r| r.1.contains("signed one-call permit"))
    );
    assert!(runs[0].iter().any(|r| {
        r.1.contains("removing this rule can let the remaining rules work again")
    }));
    for (seed, args) in [
        ("bad-http", vec!["policy", "http", "list"]),
        ("binding", vec!["policy", "http", "list", "github"]),
        (
            "binding",
            vec![
                "policy", "http", "add", "github", "--id", "read", "--path", "/user",
            ],
        ),
    ] {
        let mut outputs = vec![];
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
            pty(
                &python,
                &command,
                &scratch.home(),
                &scratch.proj(),
                &[
                    "policy", "http", "add", "github", "--id", "read", "--path", "/user",
                ],
                &[YES, PASS],
            );
            probe(&reference, &scratch.proj(), "http_policy.py", seed);
            let before = std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap();
            let (code, text) = pty(
                &python,
                &command,
                &scratch.home(),
                &scratch.proj(),
                &args,
                &[],
            );
            assert_eq!(code, 1);
            assert_eq!(
                before,
                std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap()
            );
            outputs.push(normalise(&text, &scratch.root));
        }
        assert_eq!(outputs[0], outputs[1]);
    }
}

#[test]
fn http_policy_parser_matches_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let scratch = Scratch::new("http-parser");
    let cases = [
        vec!["policy", "-h"],
        vec!["policy", "http", "-h"],
        vec!["policy", "http", "list", "-h"],
        vec!["policy", "http", "add", "-h"],
        vec!["policy", "http", "remove", "-h"],
        vec!["policy", "http", "rm", "-h"],
        vec!["policy", "http", "add"],
        vec!["policy", "http", "add", "github", "--path", "/user"],
        vec!["policy", "http", "add", "github", "--id", "read"],
        vec![
            "policy",
            "http",
            "add",
            "github",
            "--id",
            "read",
            "--path",
            "/user",
            "--path-prefix",
            "/user",
        ],
        vec![
            "policy",
            "http",
            "add",
            "github",
            "--id",
            "read",
            "--path-prefix",
            "/user",
            "--path",
            "/user",
        ],
        vec!["policy", "http", "remove"],
        vec!["policy", "http", "rm", "github"],
        vec!["policy", "http", "other"],
    ];
    for args in cases {
        let mut outputs = vec![];
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
    }
    for action in ["watch", "request"] {
        let mut command = Command::new(kv_bin());
        command.arg("policy");
        if !action.is_empty() {
            command.arg(action);
        }
        let output = command
            .current_dir(scratch.proj())
            .env("HOME", scratch.home())
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("not available in this build"));
    }
}
