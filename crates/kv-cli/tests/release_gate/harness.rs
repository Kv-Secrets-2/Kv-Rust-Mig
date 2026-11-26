//! Rust-only scaffolding for the v1 launch contract's black-box tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const PASSPHRASE: &str = "correct horse battery staple";
pub const SECRET_NAME: &str = "ANTHROPIC_API_KEY";
pub const PROVIDER: &str = "anthropic";
pub const PROVIDER_PATH: &str = "/v1/messages";
// Provisional loopback seam, intentionally centralized here. The implementation
// must choose a secure, owner-visible test mechanism; the harness must never use
// live provider endpoints or credentials while this contract question is open.
pub const ENDPOINT_OVERRIDE_ENV: &str = "KV_V1_TEST_ANTHROPIC_ORIGIN";
pub const RELEASE_GATE_ENV: &str = "KV_RELEASE_GATE";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn kv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kv")
}

pub struct Scratch {
    pub root: PathBuf,
}

impl Scratch {
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "kv-v1-release-gate-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("home")).expect("create isolated HOME");
        fs::create_dir_all(root.join("proj")).expect("create isolated project");
        Self { root }
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
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "kv-v1-synthetic-secret-{}-{n}-not-a-live-credential",
        std::process::id()
    )
}

pub fn assert_success(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
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
            "synthetic provider secret appeared in {label}"
        );
    }
    for (label, args) in argv {
        assert!(
            !args.iter().any(|arg| arg.contains(secret)),
            "synthetic provider secret appeared in {label} argv: {args:?}"
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
                "synthetic provider secret appeared in file {}",
                path.display()
            );
        }
    }
}
