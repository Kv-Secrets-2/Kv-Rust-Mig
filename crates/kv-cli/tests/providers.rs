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
        "probe failed: {}",
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

#[test]
fn provider_owner_sequences_match_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let python = owner::python3().expect("PTY driver");
    let scratch = Scratch::new("providers");
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
    let mut steps = vec![
        step(&["provider"], false, 0),
        step(&["provider", "list"], false, 0),
        step(
            &[
                "provider",
                "add",
                "github",
                "--secret",
                "TOKEN",
                "--url",
                "https://1.1.1.1",
            ],
            false,
            1,
        ),
        step(
            &["provider", "add", "missing", "--secret", "TOKEN"],
            false,
            1,
        ),
        step(
            &[
                "provider",
                "add",
                "missing",
                "--secret",
                "",
                "--url",
                "https://1.1.1.1",
            ],
            false,
            1,
        ),
    ];
    for auth in ["bearer", "x-api-key", "query", "basic", "header"] {
        let args = [
            "provider",
            "add",
            auth,
            "--secret",
            "TOKEN",
            "--url",
            "https://1.1.1.1/",
            "--auth",
            auth,
        ];
        if auth == "bearer" {
            let mut cancel = step(&args, false, 0);
            cancel.1 = vec!["\\[y/N\\] =>N"];
            steps.push(cancel);
        }
        steps.push(step(&args, true, 0));
    }
    steps.push(step(
        &[
            "provider",
            "add",
            "bearer",
            "--secret",
            "TOKEN",
            "--url",
            "https://1.1.1.1",
        ],
        false,
        1,
    ));
    for (name, auth, flag, value) in [
        ("query-custom", "query", "--query-param", "token"),
        ("header-custom", "header", "--header-name", "X-Token"),
    ] {
        steps.push(step(
            &[
                "provider",
                "add",
                name,
                "--secret",
                "TOKEN",
                "--url",
                "https://1.1.1.1",
                "--auth",
                auth,
                flag,
                value,
            ],
            true,
            0,
        ));
    }
    for url in [
        "http://1.1.1.1",
        "https://10.1.2.3",
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://[4000::1]",
        "https://[2002::1]",
        "https://1.1.1.1/path",
        "https://user@1.1.1.1",
        "https://1.1.1.1?query",
        "https://1.1.1.1#fragment",
    ] {
        steps.push(step(
            &[
                "provider", "add", "invalid", "--secret", "TOKEN", "--url", url,
            ],
            true,
            1,
        ));
    }
    for (auth, flag, value) in [
        ("query", "--query-param", "_method"),
        ("header", "--header-name", "Host"),
    ] {
        steps.push(step(
            &[
                "provider",
                "add",
                "invalid",
                "--secret",
                "TOKEN",
                "--url",
                "https://1.1.1.1",
                "--auth",
                auth,
                flag,
                value,
            ],
            true,
            1,
        ));
    }
    for ptype in ["postgres", "mysql", "redis", "ssh"] {
        steps.push(step(
            &[
                "provider", "add", "missing", "--type", ptype, "--secret", "TOKEN",
            ],
            false,
            1,
        ));
        if ptype != "redis" {
            steps.push(step(
                &[
                    "provider",
                    "add",
                    "missing",
                    "--type",
                    ptype,
                    "--secret",
                    "TOKEN",
                    "--host",
                    "db.example",
                ],
                false,
                1,
            ));
        }
        if ptype == "postgres" || ptype == "mysql" {
            steps.push(step(
                &[
                    "provider",
                    "add",
                    "missing",
                    "--type",
                    ptype,
                    "--secret",
                    "TOKEN",
                    "--host",
                    "db.example",
                    "--database",
                    "app",
                ],
                false,
                1,
            ));
        }
        let mut args = vec![
            "provider",
            "add",
            ptype,
            "--type",
            ptype,
            "--secret",
            "TOKEN",
            "--host",
            "db.example",
        ];
        if ptype != "redis" {
            args.extend(["--username", "owner"]);
        }
        if ptype == "postgres" || ptype == "mysql" {
            args.extend(["--database", "app"]);
        }
        steps.push(step(&args, true, 0));
    }
    steps.push(step(
        &[
            "provider",
            "add",
            "redis-port",
            "--type",
            "redis",
            "--host",
            "db.example",
            "--port",
            "-1",
            "--database",
            "2",
            "--secret",
            "TOKEN",
        ],
        true,
        0,
    ));
    steps.push(step(
        &[
            "provider",
            "add",
            "ssh-port-zero",
            "--type",
            "ssh",
            "--host",
            "host",
            "--port",
            "0",
            "--username",
            "owner",
            "--secret",
            "TOKEN",
        ],
        true,
        0,
    ));
    steps.push(step(&["provider", "list"], false, 0));
    for name in ["github", "missing"] {
        steps.push(step(&["provider", "rm", name], false, 1));
    }
    let mut cancel = step(&["provider", "rm", "bearer"], false, 0);
    cancel.1 = vec!["\\[y/N\\] =>N"];
    steps.push(cancel);
    steps.push(step(&["provider", "rm", "bearer"], true, 0));
    steps.push(step(&["provider", "rm", "postgres"], true, 0));
    let mut repair = step(&["provider", "rm", "broken"], true, 0);
    repair.3 = Some("invalid-provider");
    steps.push(repair);
    steps.push(step(&["provider", "list"], false, 0));
    steps.push(step(
        &["approval-mode", "set", "protected-approval"],
        true,
        0,
    ));
    steps.push(step(
        &[
            "provider",
            "add",
            "blocked",
            "--secret",
            "TOKEN",
            "--url",
            "https://1.1.1.1",
        ],
        false,
        1,
    ));
    steps.push(step(&["provider", "rm", "mysql"], false, 1));
    let mut runs = vec![];
    for command in [
        vec![kv_bin()],
        vec![reference.to_str().unwrap(), "-m", "kv"],
    ] {
        probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
        let mut run = vec![];
        for (args, rules, expected, seed) in &steps {
            if let Some(action) = seed {
                probe(&reference, &scratch.proj(), "providers.py", action);
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
        assert_eq!(rust, python, "provider step {index}: {:?}", steps[index].0);
    }
    assert!(runs[0].iter().any(|r| r.1.contains("(custom)")));
    assert!(
        runs[0]
            .iter()
            .any(|r| r.1.contains("approval mode not chosen"))
    );
    assert!(runs[0].iter().any(|r| {
        r.1.contains("removing it can let other providers work again")
    }));
    for (seed, expected) in [
        (
            "bad-policy",
            "broker_policy.http in config.json must be an object",
        ),
        (
            "bad-providers",
            "providers in config.json must be an object",
        ),
    ] {
        probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
        probe(&reference, &scratch.proj(), "providers.py", seed);
        let before = std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap();
        let mut outputs = vec![];
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            let (code, text) = pty(
                &python,
                &command,
                &scratch.home(),
                &scratch.proj(),
                &[
                    "provider",
                    "add",
                    "invalid",
                    "--secret",
                    "TOKEN",
                    "--url",
                    "https://1.1.1.1",
                ],
                if seed == "bad-policy" {
                    &[YES, PASS]
                } else {
                    &[]
                },
            );
            assert_eq!(code, 1);
            assert!(text.contains(expected));
            assert_eq!(
                before,
                std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap()
            );
            outputs.push(normalise(&text, &scratch.root));
        }
        assert_eq!(outputs[0], outputs[1]);
    }
    for (seed, args) in [
        ("bad-providers", vec!["provider", "list"]),
        ("bad-entry", vec!["provider", "rm", "broken"]),
    ] {
        probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
        probe(&reference, &scratch.proj(), "providers.py", seed);
        let before = std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap();
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            let (code, _) = pty(
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
        }
    }
    for port in ["9223372036854775808", "١٢"] {
        for command in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            probe(&reference, &scratch.proj(), "approval_mode.py", "restore");
            let before = std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap();
            let rust = command[0] == kv_bin();
            let (code, text) = pty(
                &python,
                &command,
                &scratch.home(),
                &scratch.proj(),
                &[
                    "provider", "add", "port", "--type", "redis", "--host", "host", "--secret",
                    "TOKEN", "--port", port,
                ],
                if rust { &[] } else { &[YES, PASS] },
            );
            assert_eq!(code, if rust { 2 } else { 0 });
            if rust {
                assert!(text.contains("invalid int value"));
                assert_eq!(
                    before,
                    std::fs::read(scratch.proj().join(".secrets/config.json")).unwrap()
                );
            }
        }
    }
}

#[test]
fn provider_parser_matches_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let scratch = Scratch::new("provider-parser");
    let mut cases = vec![
        vec!["provider", "-h"],
        vec!["provider", "add", "-h"],
        vec!["provider", "list", "-h"],
        vec!["provider", "rm", "-h"],
        vec!["provider", "add"],
        vec!["provider", "add", "x"],
        vec!["provider", "rm"],
        vec!["provider", "other"],
    ];
    for (flag, value) in [
        ("--port", "bad"),
        ("--port", "1.5"),
        ("--port", "-1.5"),
        ("--port", "+_1"),
        ("--type", "bad"),
        ("--auth", "bad"),
    ] {
        cases.push(vec![
            "provider", "add", "x", "--secret", "TOKEN", flag, value,
        ]);
    }
    for args in cases {
        let files = scratch.policy_files();
        let mut outputs = vec![];
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
}
