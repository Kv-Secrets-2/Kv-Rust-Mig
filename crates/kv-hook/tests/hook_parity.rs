//! Differential test of the whole decision pipeline: every RR3 hook input and
//! the tool-specific hand cases run through Python 0.4.0's `kv.hook._decide`
//! and this crate's `decide`, in the same vault project with the same HOME,
//! and the JSON replies must match exactly.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

struct Fixture {
    home: PathBuf,
    project: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.home.parent().unwrap_or(&self.home));
    }
}

#[cfg(unix)]
fn mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn fixture() -> Fixture {
    let base = std::env::temp_dir().join(format!("kv-hook-parity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let home = base.join("home");
    let project = base.join("proj");
    for dir in [
        home.join(".kv"),
        home.join(".claude"),
        home.join(".codex"),
        home.join(".vscode"),
        home.join("other/.SECRETS"),
        project.join(".secrets/drawers/dev"),
        project.join(".secrets/sub"),
        project.join("src"),
        project.join(".cursor"),
        project.join("sub/.vscode"),
        project.join("other/.secrets"),
        project.join("nope"),
    ] {
        std::fs::create_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    mode(&home.join(".kv"), 0o700);
    for file in [
        ".secrets/key",
        ".secrets/config.json",
        ".secrets/.gitignore",
        ".secrets/drawers/dev/index.kvi",
        ".secrets/run_grants.json",
        ".secrets/x.enc",
        ".secrets/sub/y.kvs.tmp",
        ".secrets/key.tmp",
        "src/app.py",
        "src/\u{e9}.py",
        ".mcp.json",
        ".cursor/mcp.json",
        "sub/.vscode/mcp.json",
        "sub/mcp.json",
        "other/.secrets/key",
        "file.txt",
    ] {
        std::fs::write(project.join(file), b"x").unwrap();
    }
    for file in [
        ".kv/agent-0123456789ab.token",
        ".kv/x.token",
        ".claude/settings.json",
        ".claude.json",
        ".codex/config.toml",
        ".vscode/mcp.json",
        "other/.SECRETS/key",
    ] {
        std::fs::write(home.join(file), b"x").unwrap();
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(".secrets", project.join("link")).unwrap();
        std::os::unix::fs::symlink("loop2", project.join("loop")).unwrap();
        std::os::unix::fs::symlink("loop", project.join("loop2")).unwrap();
        std::os::unix::fs::symlink(".mcp.json", project.join("mcplink")).unwrap();
    }
    Fixture { home, project }
}

fn substitute(value: &Value, fixture: &Fixture) -> Value {
    match value {
        Value::String(text) => Value::String(
            text.replace("{PROJ}", fixture.project.to_str().unwrap())
                .replace("{HOME}", fixture.home.to_str().unwrap()),
        ),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| substitute(item, fixture)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), substitute(item, fixture)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn load_cases(fixture: &Fixture) -> Vec<Value> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cases: Vec<Value> = Vec::new();
    let hand: Vec<Value> = serde_json::from_str(
        &std::fs::read_to_string(root.join("tests/fixtures/tool_cases.json")).unwrap(),
    )
    .unwrap();
    cases.extend(hand.iter().map(|case| substitute(case, fixture)));
    // The RR3 corpus of kv-secrets 0.4.0 (tests/fixtures/rr3/rr3_cases.json), hook inputs only.
    let rr3: Vec<Value> = serde_json::from_str(
        &std::fs::read_to_string(root.join("tests/fixtures/rr3_hook_inputs.json")).unwrap(),
    )
    .unwrap();
    cases.extend(rr3);
    cases
}

#[test]
fn decisions_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let fixture = fixture();
    let cases = load_cases(&fixture);
    let parseable: Vec<(Value, kv_hook::ToolCall)> = cases
        .into_iter()
        .filter_map(|case| {
            let raw = serde_json::to_vec(&case).unwrap();
            kv_hook::ToolCall::parse(&raw).map(|call| (case, call))
        })
        .collect();
    assert!(
        parseable.len() > 100,
        "corpus too small: {}",
        parseable.len()
    );
    assert!(
        rg_on_path(),
        "hook_parity needs ripgrep (`rg`) on PATH: Python's Glob oracle refuses every Glob without it"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(root.join("tests/py/decide_probe.py"))
        .current_dir(&fixture.project)
        .env_clear()
        .env("HOME", &fixture.home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start Python probe");
    {
        let mut stdin = child.stdin.take().unwrap();
        for (case, _) in &parseable {
            stdin
                .write_all(serde_json::to_string(case).unwrap().as_bytes())
                .unwrap();
            stdin.write_all(b"\n").unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "Python probe failed");
    let python_replies: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(python_replies.len(), parseable.len());
    // The Rust side decides in a child of this test binary, from the same
    // working folder and HOME (see `probe_main`).
    let inputs = fixture.home.parent().unwrap().join("inputs.jsonl");
    let replies = fixture.home.parent().unwrap().join("replies.jsonl");
    let mut lines = String::new();
    for (case, _) in &parseable {
        lines.push_str(&serde_json::to_string(case).unwrap());
        lines.push('\n');
    }
    std::fs::write(&inputs, lines).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "probe_main", "--nocapture", "--test-threads=1"])
        .current_dir(&fixture.project)
        .env_clear()
        .env("HOME", &fixture.home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("KV_HOOK_PROBE_IN", &inputs)
        .env("KV_HOOK_PROBE_OUT", &replies)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "Rust probe failed");
    let rust_replies: Vec<Value> = std::fs::read_to_string(&replies)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rust_replies.len(), parseable.len());
    let mut mismatches = Vec::new();
    for (((case, _), expected), actual) in parseable.iter().zip(&python_replies).zip(&rust_replies)
    {
        if actual != expected {
            mismatches.push(format!(
                "input {}\n  python: {}\n  rust:   {}",
                serde_json::to_string(case)
                    .unwrap()
                    .chars()
                    .take(300)
                    .collect::<String>(),
                serde_json::to_string(expected).unwrap(),
                serde_json::to_string(actual).unwrap()
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} hook decisions differ from Python:\n{}",
        mismatches.len(),
        parseable.len(),
        mismatches.join("\n")
    );
}

/// The Rust side of `decisions_match_python`, run as a child process so the
/// working folder and HOME are the fixture's: one reply line per input line.
#[test]
fn probe_main() {
    let (Some(inputs), Some(replies)) = (
        std::env::var_os("KV_HOOK_PROBE_IN"),
        std::env::var_os("KV_HOOK_PROBE_OUT"),
    ) else {
        return;
    };
    let mut out = String::new();
    for line in std::fs::read_to_string(inputs).unwrap().lines() {
        let call = kv_hook::ToolCall::parse(line.as_bytes()).expect("parseable case");
        out.push_str(&serde_json::to_string(&kv_hook::decide(&call).to_json()).unwrap());
        out.push('\n');
    }
    std::fs::write(replies, out).unwrap();
}

fn rg_on_path() -> bool {
    let exe = if cfg!(windows) { "rg.exe" } else { "rg" };
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(exe).is_file()))
        .unwrap_or(false)
}
