//! Negative controls exercise the public helper in isolated child processes.
//! No test changes the process-wide environment used by concurrent tests.

use std::ffi::OsStr;
use std::process::{Command, Output};

fn child(required: &str, reference: Option<&OsStr>) -> Output {
    let executable = std::env::current_exe().expect("test executable");
    let mut command = Command::new(executable);
    command
        .args(["--exact", "reference_child", "--nocapture"])
        .env("KV_TEST_SUPPORT_CHILD", "1")
        .env("KV_PARITY_REQUIRED", required)
        .env_remove("KV_PY_REF");
    if let Some(reference) = reference {
        command.env("KV_PY_REF", reference);
    }
    command.output().expect("run reference control")
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn reference_child() {
    if std::env::var_os("KV_TEST_SUPPORT_CHILD").is_some() {
        let _ = kv_test_support::python_reference();
    }
}

#[test]
fn strict_public_helper_cannot_turn_missing_reference_into_a_pass() {
    let output = child("1", None);
    let text = combined(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("refusing to skip Python parity"), "{text}");
    assert!(!text.contains("KV_PARITY_TEST "), "{text}");
    assert!(!text.contains("KV_PARITY_SKIP "), "{text}");
}

#[test]
fn optional_public_helper_marks_missing_reference_as_a_skip() {
    let output = child("0", None);
    let text = combined(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("KV_PARITY_SKIP reference_child:"), "{text}");
    assert!(!text.contains("KV_PARITY_TEST "), "{text}");
}

#[test]
fn configured_non_python_executable_fails_even_in_optional_mode() {
    let executable = std::env::current_exe().expect("test executable");
    for required in ["0", "1"] {
        let output = child(required, Some(executable.as_os_str()));
        let text = combined(&output);
        assert!(!output.status.success(), "{text}");
        assert!(text.contains("must import kv-secrets 0.4.0"), "{text}");
        assert!(!text.contains("KV_PARITY_TEST "), "{text}");
    }
}

#[test]
fn an_empty_configured_reference_is_not_an_optional_skip() {
    let output = child("0", Some(OsStr::new("")));
    let text = combined(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("KV_PY_REF is configured but empty"), "{text}");
    assert!(!text.contains("KV_PARITY_SKIP "), "{text}");
}
