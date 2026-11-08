use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct Scratch {
    pub root: PathBuf,
}

impl Scratch {
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("kv-cli-blackbox-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("proj")).unwrap();
        Scratch { root }
    }
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }
    pub fn proj(&self) -> PathBuf {
        self.root.join("proj")
    }
    #[allow(dead_code)]
    pub fn policy_files(&self) -> [Option<Vec<u8>>; 2] {
        ["config.json", "policy_requests.json"].map(|name| {
            match std::fs::read(self.proj().join(".secrets").join(name)) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("cannot read {name}: {error}"),
            }
        })
    }
}

#[allow(dead_code)]
pub fn argparse_text_compared() -> bool {
    std::env::var("KV_PARITY_MODE").as_deref() != Ok("semantic")
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub fn kv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kv")
}

pub fn python3() -> Option<String> {
    ["python3", "python"].into_iter().find_map(|name| {
        Command::new(name)
            .arg("-c")
            .arg("import pty, termios")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|_| name.to_owned())
    })
}

fn helper() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/ptyrun.py")
}

/// One `kv` command on a pty in `cwd` with `HOME=home`, prompts answered by `rules`
/// (`regex=>answer`, matched in order). Returns (exit code, output).
pub fn pty(
    python: &str,
    cmd: &[&str],
    home: &Path,
    cwd: &Path,
    args: &[&str],
    rules: &[&str],
) -> (i32, String) {
    let output = Command::new(python)
        .arg(helper())
        .arg("--cwd")
        .arg(cwd)
        .arg("--env")
        .arg(format!("HOME={}", home.display()))
        .arg("--env")
        .arg("NO_COLOR=1")
        .arg("--")
        .args(cmd)
        .args(args)
        .arg("--")
        .args(rules)
        .output()
        .expect("ptyrun.py runs");
    let text = String::from_utf8_lossy(&output.stdout).replace('\r', "");
    (output.status.code().unwrap_or(-1), text)
}

pub fn normalise(text: &str, scratch: &Path) -> String {
    let mut t = text.replace(scratch.to_str().unwrap(), "SCRATCH");
    let rules: [(&str, &str); 6] = [
        (r"\d{4}-\d{2}-\d{2}T[\d:.]+(Z|\+00:00)", "STAMP"),
        (r"PID \d+", "PID N"),
        (r"digest [0-9a-f]{16}", "digest D"),
        (r"owner key [0-9a-f]{12}", "owner key K"),
        (r"\b[A-Z0-9]{4}(-[A-Z0-9]{4}){4,}\b", "RECOVERY-KEY"),
        (r"\n\s*\n(\s*\n)+", "\n\n"),
    ];
    for (pattern, replacement) in rules {
        t = regex_lite_replace(&t, pattern, replacement);
    }
    t
}

/// A tiny regex substitute: only the patterns above are needed, so they are matched
/// by hand rather than pulling a regex crate into the CLI's dev-dependencies.
fn regex_lite_replace(text: &str, pattern: &str, replacement: &str) -> String {
    match pattern {
        r"\d{4}-\d{2}-\d{2}T[\d:.]+(Z|\+00:00)" => replace_spans(text, replacement, |b, i| {
            let d = |k: usize| b.get(i + k).is_some_and(u8::is_ascii_digit);
            if !(d(0)
                && d(1)
                && d(2)
                && d(3)
                && b.get(i + 4) == Some(&b'-')
                && d(5)
                && d(6)
                && b.get(i + 7) == Some(&b'-')
                && d(8)
                && d(9)
                && b.get(i + 10) == Some(&b'T'))
            {
                return None;
            }
            let mut j = i + 11;
            while b
                .get(j)
                .is_some_and(|c| c.is_ascii_digit() || *c == b':' || *c == b'.')
            {
                j += 1;
            }
            if b.get(j) == Some(&b'Z') {
                Some(j + 1)
            } else if b[j..].starts_with(b"+00:00") {
                Some(j + 6)
            } else {
                None
            }
        }),
        r"PID \d+" => replace_spans(text, replacement, |b, i| {
            if !b[i..].starts_with(b"PID ") {
                return None;
            }
            let mut j = i + 4;
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            (j > i + 4).then_some(j)
        }),
        r"digest [0-9a-f]{16}" => {
            replace_spans(text, replacement, |b, i| hex_after(b, i, b"digest ", 12))
        }
        r"owner key [0-9a-f]{12}" => {
            replace_spans(text, replacement, |b, i| hex_after(b, i, b"owner key ", 12))
        }
        r"\b[A-Z0-9]{4}(-[A-Z0-9]{4}){4,}\b" => replace_spans(text, replacement, |b, i| {
            if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'-') {
                return None;
            }
            let group = |k: usize| {
                (0..4).all(|q| {
                    b.get(k + q)
                        .is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                })
            };
            if !group(i) {
                return None;
            }
            let mut j = i + 4;
            let mut groups = 1;
            while b.get(j) == Some(&b'-') && group(j + 1) {
                j += 5;
                groups += 1;
            }
            (groups >= 5 && !b.get(j).is_some_and(|c| c.is_ascii_alphanumeric())).then_some(j)
        }),
        _ => {
            let mut out = String::new();
            let mut blank_run = 0;
            for line in text.split('\n') {
                if line.trim().is_empty() {
                    blank_run += 1;
                    if blank_run > 1 {
                        continue;
                    }
                } else {
                    blank_run = 0;
                }
                out.push_str(line);
                out.push('\n');
            }
            out
        }
    }
}

fn hex_after(b: &[u8], i: usize, prefix: &[u8], min: usize) -> Option<usize> {
    if !b[i..].starts_with(prefix) {
        return None;
    }
    let mut j = i + prefix.len();
    while b
        .get(j)
        .is_some_and(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        j += 1;
    }
    (j >= i + prefix.len() + min).then_some(j)
}

fn replace_spans(
    text: &str,
    replacement: &str,
    matcher: impl Fn(&[u8], usize) -> Option<usize>,
) -> String {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if text.is_char_boundary(i)
            && let Some(end) = matcher(b, i)
        {
            out.extend_from_slice(replacement.as_bytes());
            i = end;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}
