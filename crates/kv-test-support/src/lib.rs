//! Reference selection for cross-language tests, never linked into the product.
//!
//! Local runs can omit Python. The parity gate sets `KV_PARITY_REQUIRED=1`, so
//! missing reference configuration is a failure instead of a successful no-op.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

static REFERENCES: LazyLock<Mutex<BTreeMap<OsString, Result<(), String>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static REPORTED: LazyLock<Mutex<BTreeSet<String>>> = LazyLock::new(|| Mutex::new(BTreeSet::new()));

/// Return a validated Python reference, or an explicitly reported local skip.
///
/// A configured interpreter must import kv-secrets 0.4.0 even in optional mode.
/// The gate additionally attests the reference source commit and Python version.
/// Each configured comparison emits one inventory marker under its Rust test
/// name; the gate must also check that the test completed successfully.
pub fn python_reference() -> Option<OsString> {
    let required = required_mode(std::env::var_os("KV_PARITY_REQUIRED").as_deref())
        .unwrap_or_else(|message| panic!("{message}"));
    let reference = resolve_reference(required, std::env::var_os("KV_PY_REF"), |python| {
        let mut references = REFERENCES.lock().expect("Python reference cache poisoned");
        references
            .entry(python.to_owned())
            .or_insert_with(|| validate_interpreter(python))
            .clone()
    })
    .unwrap_or_else(|message| panic!("{message}"));

    let current = std::thread::current();
    let test_name = current
        .name()
        .expect("python_reference must be called from a named test thread");
    let mut reported = REPORTED
        .lock()
        .expect("Python reference inventory poisoned");
    if reported.insert(test_name.to_owned()) {
        if reference.is_some() {
            eprintln!("\nKV_PARITY_TEST {test_name}");
        } else {
            eprintln!("\nKV_PARITY_SKIP {test_name}: KV_PY_REF is unset (optional local run)");
        }
    }
    reference
}

fn required_mode(value: Option<&OsStr>) -> Result<bool, String> {
    match value {
        None => Ok(false),
        Some(value) if value == "0" => Ok(false),
        Some(value) if value == "1" => Ok(true),
        Some(_) => Err("KV_PARITY_REQUIRED must be 0 or 1".to_owned()),
    }
}

fn resolve_reference(
    required: bool,
    configured: Option<OsString>,
    validate: impl FnOnce(&OsStr) -> Result<(), String>,
) -> Result<Option<OsString>, String> {
    let Some(python) = configured else {
        return if required {
            Err(
                "KV_PARITY_REQUIRED=1 requires KV_PY_REF; refusing to skip Python parity"
                    .to_owned(),
            )
        } else {
            Ok(None)
        };
    };
    if python.is_empty() {
        return Err("KV_PY_REF is configured but empty".to_owned());
    }
    validate(&python)?;
    Ok(Some(python))
}

fn validate_interpreter(python: &OsStr) -> Result<(), String> {
    let mut child = Command::new(python)
        .args([
            "-I",
            "-c",
            "import importlib.metadata, kv; assert importlib.metadata.version('kv-secrets') == '0.4.0'",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("KV_PY_REF cannot start its interpreter: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(format!(
                    "KV_PY_REF must import kv-secrets 0.4.0 in isolated mode; validation exited {status}"
                ));
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(match result {
                    Err(error) => format!("KV_PY_REF validation could not be observed: {error}"),
                    _ => "KV_PY_REF validation exceeded its 15-second deadline".to_owned(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_mode_refuses_missing_reference_without_running_validation() {
        let error = resolve_reference(true, None, |_| panic!("must not run")).unwrap_err();
        assert!(error.contains("refusing to skip"));
    }

    #[test]
    fn optional_mode_can_omit_reference_without_running_validation() {
        assert_eq!(
            resolve_reference(false, None, |_| panic!("must not run")),
            Ok(None)
        );
    }

    #[test]
    fn empty_or_unusable_configured_reference_fails_in_both_modes() {
        for required in [false, true] {
            assert!(
                resolve_reference(required, Some(OsString::new()), |_| panic!("must not run"))
                    .is_err()
            );
            let error = resolve_reference(required, Some("python".into()), |_| {
                Err("cannot import reference".to_owned())
            })
            .unwrap_err();
            assert_eq!(error, "cannot import reference");
        }
    }

    #[test]
    fn validated_reference_is_preserved_in_both_modes() {
        for required in [false, true] {
            let interpreter = OsString::from("/a reference/python");
            assert_eq!(
                resolve_reference(required, Some(interpreter.clone()), |value| {
                    assert_eq!(value, interpreter.as_os_str());
                    Ok(())
                }),
                Ok(Some(interpreter)),
            );
        }
    }

    #[test]
    fn invalid_strict_mode_setting_does_not_silently_disable_enforcement() {
        assert_eq!(required_mode(None), Ok(false));
        assert_eq!(required_mode(Some(OsStr::new("0"))), Ok(false));
        assert_eq!(required_mode(Some(OsStr::new("1"))), Ok(true));
        assert!(required_mode(Some(OsStr::new("true"))).is_err());
        assert!(required_mode(Some(OsStr::new(""))).is_err());
    }

    #[test]
    fn a_non_python_executable_cannot_pass_reference_validation() {
        let current = std::env::current_exe().expect("test executable");
        let error = validate_interpreter(current.as_os_str()).unwrap_err();
        assert!(error.contains("must import kv-secrets 0.4.0"), "{error}");
    }

    #[test]
    fn a_missing_executable_cannot_pass_reference_validation() {
        let missing = std::env::temp_dir()
            .join(format!("kv-missing-python-{}", std::process::id()))
            .join("python");
        assert!(!missing.exists());
        let error = validate_interpreter(missing.as_os_str()).unwrap_err();
        assert!(error.contains("cannot start"), "{error}");
    }
}
