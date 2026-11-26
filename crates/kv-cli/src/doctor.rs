//! `kv doctor`: a read-only first-install and vault-structure check.
//!
//! This command deliberately does not use the vault's normal config/key loaders: those
//! loaders take locks, repair folders, or decrypt credential material. Doctor uses only
//! filesystem metadata for every vault file; it does not open, parse, or validate the
//! contents of key, config, marker, ignore, or drawer data.

use std::path::{Path, PathBuf};

use kv_sandbox::bwrap::{Isolation, Platform, bwrap_path, probe_isolation};

use crate::project::{CmdResult, Exit};
use crate::ui::{self, Palette};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Severity {
    Pass,
    Warn,
    Fail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Check {
    severity: Severity,
    message: String,
}

impl Check {
    fn pass(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Pass,
            message: message.into(),
        }
    }

    fn warn(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warn,
            message: message.into(),
        }
    }

    fn fail(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Fail,
            message: message.into(),
        }
    }
}

#[cfg(unix)]
fn owner_matches(metadata: &std::fs::Metadata) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.uid() == rustix::process::getuid().as_raw())
}

#[cfg(not(unix))]
fn owner_matches(_metadata: &std::fs::Metadata) -> Option<bool> {
    None
}

#[cfg(unix)]
fn mode_bits(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_bits(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

fn privacy_problem(metadata: &std::fs::Metadata) -> Option<&'static str> {
    if owner_matches(metadata) == Some(false) {
        return Some("owned by another account");
    }
    let mode = mode_bits(metadata)?;
    if mode & 0o077 != 0 {
        return Some("group or other users have access");
    }
    None
}

fn private_file_check(path: &Path, label: &str, pass_message: &str, non_empty: bool) -> Check {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Check::fail(format!("{label} missing; vault setup is incomplete"));
        }
        Err(error) => {
            return Check::fail(format!("{label} cannot be inspected: {error}"));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Check::fail(format!("{label} is not a regular private file"));
    }
    if non_empty && metadata.len() == 0 {
        return Check::fail(format!("{label} is empty; vault setup is incomplete"));
    }
    if owner_matches(&metadata) == Some(false) {
        return Check::fail(format!("{label} is owned by another account"));
    }
    if let Some(problem) = privacy_problem(&metadata) {
        return Check::warn(format!("{label} privacy needs review: {problem}"));
    }
    Check::pass(pass_message.to_owned())
}

fn private_dir_check(path: &Path, label: &str, pass_message: &str) -> Check {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Check::fail(format!("{label} missing; vault setup is incomplete"));
        }
        Err(error) => {
            return Check::fail(format!("{label} cannot be inspected: {error}"));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Check::fail(format!("{label} is not a real private directory"));
    }
    if owner_matches(&metadata) == Some(false) {
        return Check::fail(format!("{label} is owned by another account"));
    }
    if let Some(problem) = privacy_problem(&metadata) {
        return Check::warn(format!("{label} privacy needs review: {problem}"));
    }
    Check::pass(pass_message.to_owned())
}

fn find_secrets_entry() -> Result<Option<(PathBuf, PathBuf)>, (PathBuf, std::io::Error)> {
    let mut root = std::env::current_dir().map_err(|error| (PathBuf::new(), error))?;
    loop {
        let candidate = root.join(".secrets");
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => return Ok(Some((root, candidate))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err((candidate, error)),
        }
        if !root.pop() {
            return Ok(None);
        }
    }
}

fn vault_checks() -> Vec<Check> {
    let entry = match find_secrets_entry() {
        Ok(entry) => entry,
        Err((path, error)) if path.as_os_str().is_empty() => {
            return vec![Check::fail(format!(
                "working directory cannot be inspected: {error}"
            ))];
        }
        Err((path, error)) => {
            return vec![Check::fail(format!(
                ".secrets candidate at {} cannot be inspected: {error}",
                path.display()
            ))];
        }
    };
    let Some((root, secrets)) = entry else {
        return vec![Check::pass("fresh state: no vault found before kv init")];
    };
    let metadata = match std::fs::symlink_metadata(&secrets) {
        Ok(metadata) => metadata,
        Err(error) => {
            return vec![Check::fail(format!(
                ".secrets cannot be inspected: {error}"
            ))];
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return vec![Check::fail(
            "broken setup: .secrets exists but is not a real directory",
        )];
    }

    let mut checks = vec![
        Check::pass(format!("vault found at {}", root.display())),
        private_dir_check(&secrets, "vault directory", "vault directory private"),
    ];
    let key = secrets.join("key");
    checks.push(private_file_check(
        &key,
        "vault key file",
        "vault key file present (metadata only; contents not read)",
        true,
    ));
    checks.push(private_file_check(
        &secrets.join("config.json"),
        "vault config",
        "vault config file present (metadata only; contents not read)",
        true,
    ));
    checks.push(private_dir_check(
        &secrets.join("drawers"),
        "drawer storage directory",
        "drawer storage present (entries not opened)",
    ));
    checks.push(private_file_check(
        &secrets.join("vault-marker"),
        "vault marker",
        "vault marker present (metadata only; contents not read)",
        true,
    ));
    if std::fs::symlink_metadata(secrets.join(".gitignore")).is_err() {
        checks.push(Check::warn(
            ".gitignore missing; key and local authority files are not protected from accidental commits",
        ));
    }
    checks
}

fn home_checks() -> Vec<Check> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return vec![Check::fail(
            "HOME is not set; kv cannot keep its local state",
        )];
    };
    let metadata = match std::fs::metadata(&home) {
        Ok(metadata) => metadata,
        Err(error) => return vec![Check::fail(format!("HOME cannot be inspected: {error}"))],
    };
    if !metadata.is_dir() {
        return vec![Check::fail("HOME is not a directory")];
    }
    let kv = home.join(".kv");
    let metadata = match std::fs::symlink_metadata(&kv) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return vec![Check::pass(
                "fresh user state: ~/.kv has not been created yet",
            )];
        }
        Err(error) => {
            return vec![Check::fail(format!("~/.kv cannot be inspected: {error}"))];
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return vec![Check::fail("~/.kv exists but is not a real directory")];
    }
    if owner_matches(&metadata) == Some(false) {
        return vec![Check::fail("~/.kv is owned by another account")];
    }
    if let Some(problem) = privacy_problem(&metadata) {
        return vec![Check::warn(format!(
            "~/.kv privacy needs review: {problem}"
        ))];
    }
    vec![Check::pass("~/.kv exists and is private")]
}

fn host_checks() -> Vec<Check> {
    let mut checks = Vec::new();
    if Platform::current() == Platform::Linux {
        checks.push(Check::pass("Linux platform"));
    } else {
        checks.push(Check::fail("Linux is required for the v1 sandboxed runner"));
        return checks;
    }
    let Some(bwrap) = bwrap_path() else {
        checks.push(Check::fail(
            "bubblewrap missing as a trusted root-owned system install; install your distribution's bubblewrap package (for example, sudo apt install bubblewrap)",
        ));
        return checks;
    };
    match probe_isolation(Some(&bwrap)) {
        Isolation::Bwrap => checks.push(Check::pass(format!("bubblewrap sandbox works ({bwrap})"))),
        Isolation::Unshare => checks.push(Check::fail(
            "bubblewrap check failed; only network-only unshare isolation is available",
        )),
        Isolation::None => checks.push(Check::fail(
            "bubblewrap check failed; no usable sandbox isolation is available",
        )),
    }
    checks
}

fn collect_checks() -> Vec<Check> {
    let mut checks = host_checks();
    checks.extend(home_checks());
    checks.extend(vault_checks());
    checks
}

fn print_check(p: &Palette, check: &Check) {
    match check.severity {
        Severity::Pass => ui::out(&format!(
            "  {}\u{2713}{} {}",
            p.green, p.reset, check.message
        )),
        Severity::Warn => ui::out(&format!("  {}!{} {}", p.yellow, p.reset, check.message)),
        Severity::Fail => ui::out(&format!("  {}\u{2717}{} {}", p.red, p.reset, check.message)),
    }
}

pub fn cmd_doctor(p: &Palette) -> CmdResult {
    ui::header(p, "doctor");
    ui::blank();
    let checks = collect_checks();
    let mut passed = 0usize;
    let mut warnings = 0usize;
    let mut failures = 0usize;
    for check in &checks {
        match check.severity {
            Severity::Pass => passed += 1,
            Severity::Warn => warnings += 1,
            Severity::Fail => failures += 1,
        }
        print_check(p, check);
    }
    ui::blank();
    ui::info(
        "scope: metadata only; no vault file contents are read, so semantic corruption and moved-vault provenance are outside this structural check",
    );
    ui::info(&format!(
        "{passed} passed, {failures} error{}, {warnings} warning{}",
        if failures == 1 { "" } else { "s" },
        if warnings == 1 { "" } else { "s" }
    ));
    if failures == 0 { Ok(()) } else { Err(Exit(1)) }
}
