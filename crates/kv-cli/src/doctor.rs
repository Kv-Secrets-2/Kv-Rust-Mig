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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilePrivacyPolicy {
    Generic,
    VaultKey,
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

#[cfg(unix)]
fn allows_write_search(path: &Path) -> bool {
    rustix::fs::access(
        path,
        rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
    )
    .is_ok()
}

#[cfg(unix)]
fn allows_read(path: &Path) -> bool {
    rustix::fs::access(path, rustix::fs::Access::READ_OK).is_ok()
}

#[cfg(unix)]
fn filesystem_is_read_only(path: &Path) -> Result<bool, rustix::io::Errno> {
    Ok(rustix::fs::statvfs(path)?
        .f_flag
        .contains(rustix::fs::StatVfsMountFlags::RDONLY))
}

#[cfg(target_os = "linux")]
fn has_immutable_attribute(path: &Path) -> Result<bool, rustix::io::Errno> {
    let metadata = rustix::fs::statx(
        rustix::fs::CWD,
        path,
        rustix::fs::AtFlags::NO_AUTOMOUNT | rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        rustix::fs::StatxFlags::empty(),
    )?;
    Ok(metadata
        .stx_attributes_mask
        .contains(rustix::fs::StatxAttributes::IMMUTABLE)
        && metadata
            .stx_attributes
            .contains(rustix::fs::StatxAttributes::IMMUTABLE))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn has_immutable_attribute(_path: &Path) -> Result<bool, rustix::io::Errno> {
    Ok(false)
}

#[cfg(not(unix))]
fn allows_write_search(_path: &Path) -> bool {
    true
}

#[cfg(not(unix))]
fn allows_read(_path: &Path) -> bool {
    true
}

#[cfg(not(unix))]
fn filesystem_is_read_only(_path: &Path) -> Result<bool, std::io::Error> {
    Ok(false)
}

#[cfg(not(unix))]
fn has_immutable_attribute(_path: &Path) -> Result<bool, std::io::Error> {
    Ok(false)
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

fn private_file_check(
    path: &Path,
    label: &str,
    pass_message: &str,
    non_empty: bool,
    privacy_policy: FilePrivacyPolicy,
) -> Check {
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
    match privacy_policy {
        FilePrivacyPolicy::VaultKey => {
            #[cfg(unix)]
            if !kv_store::vault_origin::key_metadata_is_private(&metadata) {
                return Check::fail(format!(
                    "{label} mode is not owner-only 0600; kv unlock will refuse it"
                ));
            }
            #[cfg(not(unix))]
            if let Some(problem) = privacy_problem(&metadata) {
                return Check::warn(format!("{label} privacy needs review: {problem}"));
            }
        }
        FilePrivacyPolicy::Generic => {
            if let Some(problem) = privacy_problem(&metadata) {
                return Check::warn(format!("{label} privacy needs review: {problem}"));
            }
        }
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

fn find_secrets_entry(
    start: &Path,
) -> Result<Option<(PathBuf, PathBuf)>, (PathBuf, std::io::Error)> {
    let mut root = start.to_path_buf();
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

fn ignore_file_check(path: &Path) -> Option<Check> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Some(Check::fail(
                ".gitignore exists but is not a regular file; vault config loading will refuse it",
            ))
        }
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(Check::warn(
            ".gitignore missing; key and local authority files are not protected from accidental commits",
        )),
        Err(error) => Some(Check::fail(format!(
            ".gitignore cannot be inspected: {error}"
        ))),
    }
}

fn vault_checks(start: &Path) -> Vec<Check> {
    let entry = match find_secrets_entry(start) {
        Ok(entry) => entry,
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
        FilePrivacyPolicy::VaultKey,
    ));
    checks.push(private_file_check(
        &secrets.join("config.json"),
        "vault config",
        "vault config file present (metadata only; contents not read)",
        true,
        FilePrivacyPolicy::Generic,
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
        FilePrivacyPolicy::Generic,
    ));
    if let Some(check) = ignore_file_check(&secrets.join(".gitignore")) {
        checks.push(check);
    }
    checks
}

fn home_checks(home: Option<&Path>) -> Vec<Check> {
    let Some(home) = home else {
        return vec![Check::fail(
            "HOME is not set; kv cannot keep its local state",
        )];
    };
    let metadata = match std::fs::metadata(home) {
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
            return vec![if allows_write_search(home) {
                Check::pass("fresh user state: ~/.kv has not been created yet")
            } else {
                Check::fail(
                    "HOME does not allow creating ~/.kv; kv init needs write and search access",
                )
            }];
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
    if !allows_read(&kv) {
        return vec![Check::fail(
            "~/.kv cannot be opened; kv needs read access to repair and maintain local vault state",
        )];
    }
    if !allows_write_search(&kv) {
        match filesystem_is_read_only(&kv) {
            Ok(true) => {
                return vec![Check::fail(
                    "~/.kv is on a read-only filesystem; kv cannot maintain local vault state",
                )];
            }
            Ok(false) => {}
            Err(error) => {
                return vec![Check::fail(format!(
                    "~/.kv filesystem cannot be inspected: {error}"
                ))];
            }
        }
        match has_immutable_attribute(&kv) {
            Ok(true) => {
                return vec![Check::fail(
                    "~/.kv is immutable; kv cannot repair or maintain local vault state",
                )];
            }
            Ok(false) => {}
            Err(error) => {
                return vec![Check::fail(format!(
                    "~/.kv attributes cannot be inspected: {error}"
                ))];
            }
        }
        if mode_bits(&metadata).is_some_and(|mode| mode & 0o300 == 0o300) {
            return vec![Check::fail(
                "~/.kv write/search access is denied despite owner permissions; kv cannot maintain local vault state",
            )];
        }
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

fn collect_checks_for(host: Vec<Check>, home: Option<&Path>, cwd: &Path) -> Vec<Check> {
    let mut checks = host;
    checks.extend(home_checks(home));
    checks.extend(vault_checks(cwd));
    checks
}

fn collect_checks() -> Vec<Check> {
    let host = host_checks();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    match std::env::current_dir() {
        Ok(cwd) => collect_checks_for(host, home.as_deref(), &cwd),
        Err(error) => {
            let mut checks = host;
            checks.extend(home_checks(home.as_deref()));
            checks.push(Check::fail(format!(
                "working directory cannot be inspected: {error}"
            )));
            checks
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(tag: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("kv-doctor-unit-{}-{tag}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("home")).unwrap();
            std::fs::create_dir_all(root.join("proj")).unwrap();
            Self(root)
        }

        fn home(&self) -> PathBuf {
            self.0.join("home")
        }

        fn proj(&self) -> PathBuf {
            self.0.join("proj")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn healthy_pre_init_shape_has_no_failures_without_host_probe() {
        let scratch = TestRoot::new("healthy");
        let checks = collect_checks_for(
            vec![Check::pass("Linux platform")],
            Some(&scratch.home()),
            &scratch.proj(),
        );
        assert!(
            checks.iter().all(|check| check.severity != Severity::Fail),
            "{checks:?}"
        );
        assert!(
            checks
                .iter()
                .any(|check| check.message == "fresh state: no vault found before kv init"),
            "{checks:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_only_state_dir_is_repairable_and_not_a_failure() {
        let scratch = TestRoot::new("repairable-state");
        let state = scratch.home().join(".kv");
        std::fs::create_dir(&state).unwrap();
        set_mode(&state, 0o500);
        let checks = collect_checks_for(
            vec![Check::pass("Linux platform")],
            Some(&scratch.home()),
            &scratch.proj(),
        );
        assert!(
            checks.iter().all(|check| check.severity != Severity::Fail),
            "{checks:?}"
        );
        assert!(
            checks
                .iter()
                .any(|check| check.message == "~/.kv exists and is private"),
            "{checks:?}"
        );
        set_mode(&state, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_state_dir_is_a_failure() {
        if rustix::process::getuid().as_raw() == 0 {
            return;
        }
        let scratch = TestRoot::new("unreadable-state");
        let state = scratch.home().join(".kv");
        std::fs::create_dir(&state).unwrap();
        set_mode(&state, 0o000);
        let checks = collect_checks_for(
            vec![Check::pass("Linux platform")],
            Some(&scratch.home()),
            &scratch.proj(),
        );
        assert!(
            checks.iter().any(|check| {
                check.severity == Severity::Fail && check.message.contains("~/.kv cannot be opened")
            }),
            "{checks:?}"
        );
        set_mode(&state, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_home_without_state_is_a_failure_before_init() {
        if rustix::process::getuid().as_raw() == 0 {
            return;
        }
        let scratch = TestRoot::new("unwritable-home");
        set_mode(&scratch.home(), 0o555);
        let checks = collect_checks_for(
            vec![Check::pass("Linux platform")],
            Some(&scratch.home()),
            &scratch.proj(),
        );
        assert!(
            checks.iter().any(|check| {
                check.severity == Severity::Fail
                    && check.message.contains("HOME does not allow creating ~/.kv")
            }),
            "{checks:?}"
        );
    }
}
