//! Rust-native regressions for the Linux v1 CLI discovery surface.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "../../../tests/support/harness.rs"]
mod harness;
#[allow(dead_code)]
#[path = "support/owner.rs"]
mod owner;

use owner::{Scratch, kv_bin, pty, python3};
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

fn assert_absent(text: &str, needles: &[&str]) {
    for needle in needles {
        assert!(!text.contains(needle), "unexpected {needle:?} in:\n{text}");
    }
}

#[test]
fn top_level_help_matches_the_v1_surface() {
    let scratch = Scratch::new("top-help");
    let (code, text) = run(&scratch, &["-h"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("kv approvals list / watch"), "{text}");
    let primary = text
        .split("Primary local commands")
        .nth(1)
        .and_then(|rest| rest.split("Advanced").next())
        .unwrap();
    assert!(!primary.contains("kv export"), "{text}");
    assert_absent(
        &text,
        &[
            "kv run",
            "kv provider",
            "kv policy",
            "kv mcp-server",
            "kv setup",
            "kv 2fa",
            "__agent-child",
        ],
    );
}

#[test]
fn mcp_server_help_is_not_shipped() {
    let scratch = Scratch::new("mcp-help");
    let (code, text) = run(&scratch, &["mcp-server", "--help"]);
    assert_ne!(code, 0, "{text}");
    assert_absent(
        &text,
        &[
            "--allow-execute",
            "--allow-mutate",
            "--allow-reveal",
            "--allow-direct-vault-access",
            "kv_run",
            "kv_query",
            "kv_ssh",
            "database/Redis",
            "remote SSH",
            "subprocess",
        ],
    );
}

#[test]
fn provider_help_is_fixed_endpoint_v1_only() {
    let scratch = Scratch::new("provider-help");
    let (code, text) = run(&scratch, &["provider", "-h"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("{list}"), "{text}");
    assert_absent(&text, &["add", "rm", "custom provider"]);

    let (code, text) = run(&scratch, &["provider", "add", "-h"]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("built-in provider definitions with fixed endpoints"),
        "{text}"
    );
    assert_absent(
        &text,
        &[
            "--url",
            "api.stripe.com",
            "stripe",
            "twilio",
            "postgres",
            "mysql",
            "redis",
            "ssh",
            "database",
        ],
    );
}

#[test]
fn approvals_help_is_one_call_permit_only() {
    let scratch = Scratch::new("approval-help");
    let (code, text) = run(&scratch, &["approvals", "-h"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("one-call permit"), "{text}");
    assert_absent(
        &text,
        &[
            "    request",
            "    page",
            "    pause",
            "    deny",
            "    prune",
            "run grant",
        ],
    );

    let (code, text) = run(&scratch, &["approvals", "approve", "-h"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("One-call permit request ID"), "{text}");
    assert_absent(
        &text,
        &[
            "--reuse",
            "--post-rule",
            "POST wallet",
            "run grant",
            "--max-runs",
        ],
    );

    let (code, text) = run(&scratch, &["approvals", "deny", "-h"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("one-call permit"), "{text}");
    assert!(!text.contains("--reason"), "{text}");
}

#[test]
fn vault_and_env_help_hide_unported_migration_surface() {
    let scratch = Scratch::new("vault-env-help");
    let (code, text) = run(&scratch, &["vault", "-h"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("approve-config"), "{text}");
    assert_absent(
        &text,
        &[
            "approve-local",
            "restore-old-key",
            "relocate",
            "migrate-drawers",
            "backup-drawers",
            "rollback-drawers",
        ],
    );

    let (code, text) = run(&scratch, &["env", "-h"]);
    assert_eq!(code, 0, "{text}");
    assert!(!text.contains("repair-names"), "{text}");
}

#[test]
fn hidden_legacy_vault_action_is_an_unavailable_command_not_syntax() {
    let scratch = Scratch::new("vault-legacy");
    let (code, text) = run(&scratch, &["vault", "approve-local"]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("not available"), "{text}");
    assert!(!text.contains("invalid choice"), "{text}");
}

#[test]
fn init_quick_start_enters_custom_vault_before_owner_commands() {
    let Some(python) = python3() else {
        eprintln!("SKIP pty init regression: python3 with pty/termios is needed");
        return;
    };
    let scratch = Scratch::new("custom-init");
    let vault = scratch.root.join("vault-root");
    let vault_text = vault.to_str().unwrap().to_owned();
    let args = [
        "init",
        "--location",
        "custom",
        "--path",
        vault_text.as_str(),
    ];
    let (code, out) = pty(
        &python,
        &[kv_bin()],
        &scratch.home(),
        &scratch.proj(),
        &args,
        &[
            "Passphrase: =>correct horse battery staple",
            "Confirm: =>correct horse battery staple",
            "stored the key: =>saved",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let cd = format!("cd {vault_text}");
    let cd_pos = out
        .find(&cd)
        .unwrap_or_else(|| panic!("missing {cd:?}:\n{out}"));
    let approve_pos = out
        .find("kv vault approve-config")
        .unwrap_or_else(|| panic!("missing approval step:\n{out}"));
    assert!(cd_pos < approve_pos, "{out}");
    assert_absent(
        &out,
        &[
            "kv run",
            "kv setup",
            "kv 2fa",
            "kv policy",
            "kv provider",
            "kv_api",
            "Python",
        ],
    );
}
