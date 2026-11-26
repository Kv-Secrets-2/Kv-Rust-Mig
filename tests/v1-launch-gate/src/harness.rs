//! Rust-only scaffolding for the v1 launch contract's black-box tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SECRET_NAME: &str = "ANTHROPIC_API_KEY";
pub const PROVIDER: &str = "anthropic";
pub const PROVIDER_PATH: &str = "/v1/messages";
// Provisional loopback seam, intentionally centralized here. The implementation
// must choose a secure, owner-visible test mechanism; the harness must never use
// live provider endpoints or credentials while this contract question is open.
pub const ENDPOINT_OVERRIDE_ENV: &str = "KV_V1_TEST_ANTHROPIC_ORIGIN";
pub const RELEASE_GATE_ENV: &str = "KV_RELEASE_GATE";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Binary under test. `KV_BIN` is the explicit release-gate input; the default is
/// the repository's already-built `target/debug/kv` for local development.
pub fn kv_bin() -> String {
    if let Some(path) = std::env::var_os("KV_BIN").filter(|path| !path.is_empty()) {
        return path.to_string_lossy().into_owned();
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest
        .ancestors()
        .nth(2)
        .expect("release-gate crate has a repository root")
        .join("target/debug/kv");
    assert!(
        candidate.is_file(),
        "kv binary under test not found at {}; build the workspace or set KV_BIN",
        candidate.display()
    );
    candidate.to_string_lossy().into_owned()
}

fn unique_fixture(kind: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    format!("kv-v1-{kind}-fixture-{}-{n}-{nanos:x}", std::process::id())
}

pub struct Scratch {
    pub root: PathBuf,
    passphrase: String,
}

impl Scratch {
    pub fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("{}-{tag}", unique_fixture("scratch")));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("home")).expect("create isolated HOME");
        fs::create_dir_all(root.join("proj")).expect("create isolated project");
        Self {
            root,
            passphrase: unique_fixture("passphrase"),
        }
    }

    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    pub fn proj(&self) -> PathBuf {
        self.root.join("proj")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn synthetic_secret() -> String {
    format!("{}-not-a-live-credential", unique_fixture("secret"))
}

pub fn assert_success(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed with {}; stdout ({} bytes) and stderr ({} bytes) suppressed by the release-gate harness",
        output.status,
        output.stdout.len(),
        output.stderr.len()
    );
}

pub fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn walk_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            walk_files(&path, out);
        } else if kind.is_file() {
            out.push(path);
        }
    }
}

/// Plaintext must not appear in CLI output, invocation arguments, or any file the
/// flow writes. The synthetic value is long enough that an encrypted vault has no
/// realistic chance of containing it by accident.
pub fn assert_secret_absent(
    secret: &str,
    transcripts: &[(&str, &[u8])],
    argv: &[(&str, &[String])],
    roots: &[&Path],
) {
    let needle = secret.as_bytes();
    for (label, bytes) in transcripts {
        assert!(
            !bytes_contain(bytes, needle),
            "sensitive fixture value appeared in {label}"
        );
    }
    for (label, args) in argv {
        assert!(
            !args.iter().any(|arg| arg.contains(secret)),
            "sensitive fixture value appeared in {label} argv"
        );
    }
    for root in roots {
        let mut files = Vec::new();
        walk_files(root, &mut files);
        for path in files {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            assert!(
                !bytes_contain(&bytes, needle),
                "sensitive fixture value appeared in file {}",
                path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_vaults_and_passphrases_are_fresh_per_fixture() {
        let one = Scratch::new("fresh-one");
        let two = Scratch::new("fresh-two");
        assert_ne!(one.root, two.root);
        assert!(one.passphrase() != two.passphrase());
        assert!(one.home().is_dir());
        assert!(two.proj().is_dir());
    }

    #[test]
    fn synthetic_secrets_are_fresh_per_fixture() {
        assert!(synthetic_secret() != synthetic_secret());
    }
}
