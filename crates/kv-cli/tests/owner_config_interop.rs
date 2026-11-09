#![cfg(all(unix, not(debug_assertions)))]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

#[path = "support/owner.rs"]
mod owner;
use owner::{Scratch, kv_bin, normalise};

const PASS: &str = "Passphrase: =>correct horse battery staple";
const YES: &str = "\\[y/N\\] =>y";

fn run(driver: &str, cmd: &[&str], scratch: &Scratch, args: &[&str], answers: &[&str]) -> String {
    let temp = format!("TMPDIR={}", scratch.root.display());
    let command = ["env", temp.as_str()]
        .into_iter()
        .chain(cmd.iter().copied())
        .collect::<Vec<_>>();
    let (code, text) = owner::pty(
        driver,
        &command,
        &scratch.home(),
        &scratch.proj(),
        args,
        answers,
    );
    assert_eq!(code, 0, "{args:?}: {text}");
    text
}

fn probe(python: &str, scratch: &Scratch, action: &str) -> serde_json::Value {
    let output = Command::new(python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/owner_config_interop.py"))
        .arg(scratch.proj())
        .arg(action)
        .env("HOME", scratch.home())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

struct Daemon<'a> {
    cmd: &'a [&'a str],
    scratch: &'a Scratch,
}
impl Drop for Daemon<'_> {
    fn drop(&mut self) {
        let _ = Command::new(self.cmd[0])
            .args(&self.cmd[1..])
            .arg("lock")
            .env("HOME", self.scratch.home())
            .env("TMPDIR", &self.scratch.root)
            .current_dir(self.scratch.proj())
            .stdin(Stdio::null())
            .output();
    }
}

#[test]
fn owner_configs_unlock_in_both_daemons() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let python = reference.to_str().unwrap();
    let driver = owner::python3().unwrap();
    let short = Path::new("/var/tmp");
    let base = if short.is_dir() {
        short.to_path_buf()
    } else {
        std::env::temp_dir()
    };
    let scratch = Scratch {
        root: base.join(format!("kv-oi-{}", std::process::id())),
    };
    std::fs::create_dir(&scratch.root).unwrap();
    std::fs::set_permissions(&scratch.root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(scratch.home()).unwrap();
    std::fs::create_dir(scratch.proj()).unwrap();
    run(
        &driver,
        &[kv_bin()],
        &scratch,
        &["init", "--location", "project"],
        &[
            PASS,
            "Confirm: =>correct horse battery staple",
            "stored the key: =>saved",
        ],
    );
    probe(python, &scratch, "snapshot");
    let sequence: &[&[&str]] = &[
        &["approval-mode", "set", "local-convenience"],
        &["allow", "python3 app.py"],
        &["network-allow", "python3 app.py"],
        &[
            "provider",
            "add",
            "interop",
            "--url",
            "https://1.1.1.1",
            "--secret",
            "HTTP_TOKEN",
        ],
        &[
            "provider",
            "add",
            "database",
            "--type",
            "postgres",
            "--host",
            "database.example",
            "--username",
            "owner",
            "--database",
            "app",
            "--secret",
            "DB_PASS",
        ],
        &[
            "policy", "http", "add", "interop", "--id", "read", "--method", "GET", "--path",
            "/read",
        ],
        &[
            "policy", "http", "add", "interop", "--id", "write", "--method", "POST", "--path",
            "/write",
        ],
    ];
    let rust = &[kv_bin()][..];
    let py = &[python, "-m", "kv"][..];
    let mut configs = Vec::new();
    let mut transcripts = Vec::new();
    for (writer, reader) in [(rust, py), (py, rust)] {
        probe(python, &scratch, "restore");
        let mut transcript = Vec::new();
        for args in sequence {
            transcript.push(normalise(
                &run(&driver, writer, &scratch, args, &[YES, PASS]),
                &scratch.root,
            ));
        }
        transcripts.push(transcript);
        let path = scratch.proj().join(".secrets/config.json");
        let bytes = std::fs::read(&path).unwrap();
        let config: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let snapshot = kv_broker::load_http_policy_snapshot(&config);
        assert!(snapshot.configured);
        assert_eq!(snapshot.providers, config["broker_policy"]["http"]);
        assert_eq!(
            snapshot.providers["interop"]["rules"][0]["methods"],
            serde_json::json!(["GET"])
        );
        assert_eq!(
            snapshot.providers["interop"]["rules"][1]["methods"],
            serde_json::json!(["POST"])
        );
        assert_eq!(
            snapshot.providers["interop"]["rules"][1]["approval"],
            "per-call"
        );
        let _daemon = Daemon {
            cmd: reader,
            scratch: &scratch,
        };
        run(
            &driver,
            reader,
            &scratch,
            &["vault", "approve-config"],
            &[PASS, YES],
        );
        let unlocked = run(&driver, reader, &scratch, &["unlock"], &[PASS]);
        assert!(unlocked.contains("vault unlocked"), "{unlocked}");
        let status = run(&driver, reader, &scratch, &["status"], &[]);
        assert!(
            status.contains("vault unlocked") && status.contains("agent running"),
            "{status}"
        );
        assert_eq!(
            probe(python, &scratch, "policy"),
            serde_json::json!({
                "configured":true,"providers":snapshot.providers,
                "description":kv_broker::describe_http_policy_snapshot(&snapshot)
            })
        );
        run(&driver, reader, &scratch, &["lock"], &[]);
        assert_eq!(bytes, std::fs::read(path).unwrap());
        configs.push(bytes);
    }
    assert_eq!(configs[0], configs[1]);
    assert_eq!(transcripts[0], transcripts[1]);
}

#[test]
fn owner_config_top_level_help_matches_python() {
    let Some(reference) = kv_test_support::python_reference() else {
        return;
    };
    let scratch = Scratch::new("owner-help");
    let implemented = [
        "init",
        "run",
        "preflight",
        "set",
        "get",
        "ls",
        "rm",
        "unlock",
        "lock",
        "status",
        "export",
        "envs",
        "env",
        "history",
        "backup",
        "vault",
        "approval-mode",
        "allow",
        "deny",
        "network-allow",
        "network-deny",
        "provider",
        "policy",
        "version",
    ];
    let mut cases = vec![
        vec!["-h"],
        vec!["--help"],
        vec!["--owner-config-unknown-option"],
    ];
    for command in [
        "approval-mode",
        "allow",
        "deny",
        "network-allow",
        "network-deny",
        "provider",
        "policy",
    ] {
        cases.push(vec![command, "-h"]);
    }
    for args in cases {
        if args == ["--owner-config-unknown-option"] && !owner::argparse_text_compared() {
            continue;
        }
        let files = scratch.policy_files();
        let mut outputs = Vec::new();
        for cmd in [
            vec![kv_bin()],
            vec![reference.to_str().unwrap(), "-m", "kv"],
        ] {
            let output = Command::new(cmd[0])
                .args(&cmd[1..])
                .args(&args)
                .current_dir(scratch.proj())
                .env("HOME", scratch.home())
                .env("NO_COLOR", "1")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            outputs.push((
                output.status.code(),
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap(),
            ));
            assert_eq!(files, scratch.policy_files(), "{args:?}");
        }
        let usage_error = args == ["--owner-config-unknown-option"];
        assert_eq!(outputs[0].0, outputs[1].0, "{args:?}");
        assert_eq!(outputs[0].0, Some(if usage_error { 2 } else { 0 }));
        if !owner::argparse_text_compared() {
            if usage_error {
                assert_eq!(outputs[0].1, outputs[1].1, "{args:?}");
                for output in &outputs {
                    assert!(output.2.starts_with("usage: "));
                    assert!(output.2.contains(": error: "));
                }
            } else {
                assert_eq!(outputs[0].2, outputs[1].2, "{args:?}");
            }
            continue;
        }
        if usage_error {
            let choices = |text: &str| -> String {
                text.lines()
                    .find_map(|line| {
                        line.trim()
                            .strip_prefix('{')
                            .and_then(|s| s.strip_suffix('}'))
                    })
                    .unwrap()
                    .to_owned()
            };
            let rust = choices(&outputs[0].2);
            let python = choices(&outputs[1].2);
            assert_eq!(
                rust.split(',').collect::<Vec<_>>(),
                python
                    .split(',')
                    .filter(|name| implemented.contains(name))
                    .chain(std::iter::once("mcp-server"))
                    .collect::<Vec<_>>()
            );
            assert_eq!(rust.split(',').count(), implemented.len() + 1);
            outputs[0].2 = outputs[0]
                .2
                .replace(&format!("{{{rust}}}"), "{IMPLEMENTED}");
            outputs[1].2 = outputs[1]
                .2
                .replace(&format!("{{{python}}}"), "{IMPLEMENTED}");
        } else if args.len() == 1 {
            let rust_footer = format!("Version: {}", env!("CARGO_PKG_VERSION"));
            assert_eq!(outputs[0].1.matches(&rust_footer).count(), 1);
            assert_eq!(outputs[1].1.matches("Version: 0.4.0").count(), 1);
            outputs[0].1 = outputs[0].1.replace(&rust_footer, "Version: 0.4.0");
        }
        assert_eq!(outputs[0], outputs[1], "{args:?}");
        assert_eq!(outputs[0].0, Some(if usage_error { 2 } else { 0 }));
    }
}
