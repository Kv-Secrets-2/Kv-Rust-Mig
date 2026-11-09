//! Black-box tests of the `kv` binary: exit codes and help without a terminal, and the
//! owner flows (init, secrets, history, environments, backups, approve-config and the
//! daemon lifecycle) on a pseudo-terminal driven by `tests/support/ptyrun.py`.
//!
//! With `KV_PY_REF` set to the reference interpreter (kv-secrets 0.4.0 installed), the
//! same script runs through Python too and the outputs must match once timestamps,
//! paths, PIDs, digests and key ids are normalised.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
#[path = "support/owner.rs"]
mod owner;
use owner::{Scratch, kv_bin, normalise, pty, python3};

const PASS: &str = "correct horse battery staple";
const P: &str = "Passphrase: =>correct horse battery staple";
const BACKUP_P: &str = "Passphrase =>correct horse battery staple";
const YES: &str = "\\[y/N\\] =>y";

/// A step of the shared script: arguments, prompt answers, expected exit code.
struct Step {
    args: Vec<String>,
    rules: Vec<&'static str>,
    code: i32,
}

fn step(args: &[&str], rules: &[&'static str], code: i32) -> Step {
    Step {
        args: args.iter().map(|s| (*s).to_owned()).collect(),
        rules: rules.to_vec(),
        code,
    }
}

/// The owner flow both implementations must answer alike. `scratch` holds the backup
/// file and the restore folder; the daemon steps run only in release builds, where the
/// Argon2 key derivation fits the 10 s background-start bound.
fn script(scratch: &Path) -> Vec<Step> {
    let backup = scratch.join("v.kvbackup");
    let backup = backup.to_str().unwrap();
    let restored = scratch.join("restored");
    let restored = restored.to_str().unwrap();
    let mut s = vec![
        step(
            &["init", "--location", "project"],
            &[
                P,
                "Confirm: =>correct horse battery staple",
                "stored the key: =>saved",
            ],
            0,
        ),
        step(&["set", "FOO=bar"], &[P], 0),
        step(&["get", "FOO"], &[P], 0),
        step(&["ls"], &[P], 0),
        step(&["set", "FOO=baz"], &[P], 0),
        step(&["history", "list", "FOO"], &[P], 0),
        step(&["history", "show", "FOO", "1"], &[P], 0),
        step(&["history", "show", "FOO", "abc"], &[P], 1),
        step(&["history", "restore", "FOO", "1"], &[P], 0),
        step(&["get", "FOO"], &[P], 0),
        step(&["rm", "FOO", "--force"], &[P], 0),
        step(&["ls"], &[P], 0),
        step(&["history", "undo-rm", "FOO"], &[P], 0),
        step(&["get", "FOO"], &[P], 0),
        step(&["history", "replace", "FOO=sekrit"], &[P, YES], 0),
        step(&["history", "keep"], &[P], 0),
        step(&["history", "keep", "3"], &[P, YES], 0),
        step(&["history", "keep", "500"], &[P], 1),
        step(&["history", "forget", "FOO"], &[P, YES], 0),
        step(&["history"], &[], 1),
        step(&["env", "create", "work"], &[], 0),
        step(&["env", "create", "work"], &[], 1),
        step(&["env", "default", "work"], &[P], 0),
        step(&["envs"], &[], 0),
        step(&["env", "default", "dev"], &[P], 0),
        step(&["env", "rename", "work", "staging"], &[P, YES], 0),
        step(
            &["env", "delete", "staging"],
            &[P, "name to delete it: =>staging"],
            0,
        ),
        step(&["env", "restore", "staging"], &[P], 0),
        step(
            &["env", "delete", "staging"],
            &[P, "name to delete it: =>staging"],
            0,
        ),
        step(
            &["env", "purge", "staging"],
            &[P, "name to wipe it: =>staging"],
            0,
        ),
        step(&["env", "keep-deleted"], &[], 0),
        step(&["env", "keep-deleted", "999"], &[], 1),
        step(&["env", "copy", "dev", "other"], &[YES, P], 0),
        step(&["set", "BAR=1", "-e", "other"], &[P], 0),
        step(&["envs"], &[], 0),
        step(&["export"], &[P], 0),
        step(&["export", "-e", "other"], &[P], 0),
        step(&["backup"], &[], 1),
        step(&["backup", "create", backup], &[P], 0),
        step(&["backup", "create", backup], &[], 1),
        step(&["backup", "show", backup], &[BACKUP_P], 0),
        step(&["backup", "show", backup], &["Passphrase =>wrong"], 1),
        step(
            &["backup", "restore", backup, restored],
            &[BACKUP_P, "\\[y/N\\] =>n"],
            0,
        ),
        step(
            &["backup", "restore", backup, restored],
            &[BACKUP_P, YES, "stored the key: =>saved"],
            0,
        ),
        step(&["vault", "approve-config"], &[P, YES], 0),
    ];
    if !cfg!(debug_assertions) {
        s.extend([
            step(&["lock"], &[], 0),
            step(&["unlock"], &[P], 0),
            step(&["unlock"], &[P], 0),
            step(&["status"], &[], 0),
            step(&["lock"], &[], 0),
            step(&["lock"], &[], 0),
        ]);
    }
    s
}

/// Locks the vault on drop so a failed test never leaves a daemon behind.
struct LockGuard<'a> {
    python: &'a str,
    cmd: Vec<&'a str>,
    home: PathBuf,
    proj: PathBuf,
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        let _ = pty(
            self.python,
            &self.cmd,
            &self.home,
            &self.proj,
            &["lock"],
            &[],
        );
    }
}

fn run_script(python: &str, cmd: &[&str], scratch: &Scratch) -> Vec<(Step, i32, String)> {
    let _guard = LockGuard {
        python,
        cmd: cmd.to_vec(),
        home: scratch.home(),
        proj: scratch.proj(),
    };
    script(&scratch.root)
        .into_iter()
        .map(|s| {
            let args: Vec<&str> = s.args.iter().map(String::as_str).collect();
            let (code, out) = pty(
                python,
                cmd,
                &scratch.home(),
                &scratch.proj(),
                &args,
                &s.rules,
            );
            (s, code, out)
        })
        .collect()
}

// ── without a terminal ────────────────────────────────────────────────────

#[test]
fn no_arguments_prints_help_and_exits_zero() {
    let out = Command::new(kv_bin()).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("kv init"));
}

#[test]
fn unknown_command_exits_one_and_usage_errors_exit_two() {
    let out = Command::new(kv_bin()).arg("frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let out = Command::new(kv_bin()).arg("set").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("usage: kv set"), "{err}");
    assert!(
        err.contains("the following arguments are required"),
        "{err}"
    );
    for group in ["env", "history", "backup", "vault"] {
        let out = Command::new(kv_bin())
            .args([group, "bogus"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "kv {group} bogus");
        assert!(String::from_utf8_lossy(&out.stderr).contains("invalid choice: 'bogus'"));
        let out = Command::new(kv_bin()).args([group, "-h"]).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "kv {group} -h");
        assert!(String::from_utf8_lossy(&out.stdout).starts_with(&format!("usage: kv {group}")));
    }
}

#[test]
fn owner_commands_refuse_without_a_terminal() {
    let scratch = Scratch::new("notty");
    for args in [
        vec!["history", "list", "X"],
        vec!["backup", "create", "x.kvbackup"],
        vec!["unlock"],
    ] {
        let out = Command::new(kv_bin())
            .args(&args)
            .current_dir(scratch.proj())
            .env("HOME", scratch.home())
            .env("NO_COLOR", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("terminal") || err.contains("not a kv project"),
            "{args:?}: {err}"
        );
    }
}

// ── on a pseudo-terminal ──────────────────────────────────────────────────

#[test]
fn owner_flow_on_a_pty() {
    let Some(python) = python3() else {
        eprintln!("SKIP pty flow: python3 with pty/termios is needed to drive the terminal");
        return;
    };
    let scratch = Scratch::new("flow");
    let results = run_script(&python, &[kv_bin()], &scratch);
    for (s, code, out) in &results {
        assert_eq!(*code, s.code, "kv {}:\n{out}", s.args.join(" "));
    }
    let outputs: Vec<&str> = results.iter().map(|(_, _, out)| out.as_str()).collect();
    // kv get prints the raw value only; kv ls never shows a value.
    assert!(outputs[2].contains("\nbar\n"), "{}", outputs[2]);
    assert!(
        outputs[3].contains("FOO") && !outputs[3].contains("bar"),
        "{}",
        outputs[3]
    );
    assert!(outputs[5].contains("v2") && outputs[5].contains("v1") && !outputs[5].contains("baz"));
    assert!(
        outputs[6].contains("\nbar\n"),
        "history show: {}",
        outputs[6]
    );
    assert!(
        outputs[7].contains("a version is a number shown by"),
        "{}",
        outputs[7]
    );
    assert!(
        outputs[9].contains("\nbar\n"),
        "after restore: {}",
        outputs[9]
    );
    assert!(!outputs[11].contains("FOO"), "after rm: {}", outputs[11]);
    assert!(
        outputs[13].contains("\nbar\n"),
        "after undo-rm: {}",
        outputs[13]
    );
    assert!(outputs[17].contains("history keep must be a whole number from 0 to 100"));
    assert!(
        outputs[19].contains("usage: kv history list|show|restore|undo-rm|replace|forget|keep")
    );
    assert!(outputs[21].contains("already exists"), "{}", outputs[21]);
    assert!(outputs[23].contains("work"), "{}", outputs[23]);
    assert!(
        outputs[31].contains("365") || outputs[31].contains("whole number"),
        "{}",
        outputs[31]
    );
    assert!(outputs[34].contains("other"), "{}", outputs[34]);
    assert!(
        outputs[35].contains("FOO='sekrit'"),
        "export: {}",
        outputs[35]
    );
    assert!(
        outputs[36].contains("BAR='1'"),
        "export other: {}",
        outputs[36]
    );
    assert!(outputs[37].contains("usage: kv backup create FILE | show FILE | restore FILE DIR"));
    assert!(
        outputs[38].contains("backup written and verified"),
        "{}",
        outputs[38]
    );
    assert!(outputs[39].contains("never overwrites"), "{}", outputs[39]);
    assert!(
        outputs[40].contains("backup contents (no values)") && !outputs[40].contains("sekrit"),
        "{}",
        outputs[40]
    );
    assert!(
        outputs[42].contains("cancelled; nothing was written"),
        "{}",
        outputs[42]
    );
    assert!(outputs[43].contains("vault restored"), "{}", outputs[43]);
    assert!(scratch.root.join("restored/.secrets/key").is_file());
    assert!(
        outputs[44].contains("Config authority approved"),
        "{}",
        outputs[44]
    );
    if !cfg!(debug_assertions) {
        assert!(
            outputs[45].contains("vault is already locked"),
            "{}",
            outputs[45]
        );
        assert!(
            outputs[46].contains("vault unlocked") && outputs[46].contains("protected session"),
            "{}",
            outputs[46]
        );
        assert!(
            outputs[47].contains("vault is already unlocked"),
            "{}",
            outputs[47]
        );
        assert!(
            outputs[48].contains("vault unlocked")
                && outputs[48].contains("agent running")
                && outputs[48].contains("1 secret"),
            "{}",
            outputs[48]
        );
        assert!(
            outputs[49].contains("vault locked")
                && outputs[49].contains("secrets cleared from memory"),
            "{}",
            outputs[49]
        );
        assert!(
            outputs[50].contains("vault is already locked"),
            "{}",
            outputs[50]
        );
    }
    for out in &outputs {
        assert!(!out.contains(PASS), "a passphrase was echoed:\n{out}");
    }
}

/// Differential: the same script through kv-secrets 0.4.0 and through this binary.
#[test]
fn owner_flow_matches_python_reference() {
    let Some(py_ref) = kv_test_support::python_reference() else {
        eprintln!("SKIP CLI parity: set KV_PY_REF to the reference interpreter");
        return;
    };
    let py_ref = py_ref.to_string_lossy().into_owned();
    let Some(python) = python3() else {
        eprintln!("SKIP CLI parity: python3 with pty/termios is needed to drive the terminal");
        return;
    };
    let rs = Scratch::new("rs");
    let py = Scratch::new("py");
    let rust = run_script(&python, &[kv_bin()], &rs);
    let reference = run_script(&python, &[py_ref.as_str(), "-m", "kv"], &py);
    assert_eq!(rust.len(), reference.len());
    for ((s, rc, ro), (_, pc, po)) in rust.iter().zip(reference.iter()) {
        let what = format!("kv {}", s.args.join(" "));
        assert_eq!(
            rc, pc,
            "{what}: exit codes\n--- rust\n{ro}\n--- python\n{po}"
        );
        let (rn, pn) = (normalise(ro, &rs.root), normalise(po, &py.root));
        assert_eq!(
            rn, pn,
            "{what}: output differs\n--- rust\n{rn}\n--- python\n{pn}"
        );
    }
}
