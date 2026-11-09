//! Live comparison with the installed Python scanner, including traversal and fences.
#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_preflight::agent_code::scan_agent_code;
use serde_json::{Value, json};

#[test]
fn agent_code_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let mut paths = Vec::new();
    let samples = [
        "os.environ['ANTHROPIC_API_KEY']",
        "os.environ.get(\"OPENAI_API_KEY\")",
        "os.getenv('GOOGLE_API_KEY')",
        "process.env.GOOGLE_CLOUD_API_KEY",
        "process.env['GEMINI_API_KEY']",
        "export GROQ_API_KEY = x",
        "MISTRAL_API_KEY=x",
        "GITHUB_TOKEN=x",
        "anthropic.Anthropic()",
        "openai.OpenAI ()",
        "api_key = 'x'",
        "api_key=os.environ['OPENAI_API_KEY']",
        "api_key=MY_API_KEY",
        "KVClient()",
        "from kv.client import KVClient",
        "kv get X",
        "kv export",
        "kv getter",
        "akv get",
        "xanthropic.Anthropic()",
        "Openai.OpenAI()",
        "api_key=API_KEY",
        "api_keys='x'",
        "os.getenv('UNKNOWN_API_KEY')",
        "process.env[OPENAI_API_KEY]",
        "process.env .OPENAI_API_KEY",
        "process.env.OPENAI_API_KEY_extra",
        "oS.EnViRoN['oPeNaI_aPi_KeY']",
        "export github_token=x",
        "os.getenv('MIſTRAL_API_KEY')",
        "os.getenv('OPENAİ_API_KEY')",
        "os.getenv('OPENAı_API_KEY')",
        "api_Key='x'",
        "api_key=XAPI_KEY",
        "api_key=XAPİ_KEY",
        "\u{301}kv get",
        "\u{200c}kv export",
        "²kv get",
        "\u{1f}OPENAI_API_KEY=x",
        "os.environ[\u{1f}'OPENAI_API_KEY'\u{1f}]",
        "api_key='MIßTRAL_API_KEY'",
        "api_key='OPENAI_API_KEY ANTHROPIC_API_KEY'",
        "openai.OpenAI() # ANTHROPIC_API_KEY",
        "kv get\u{301}",
        "kv get²",
        "nothing to find",
        "",
        "# kv get\r\n# kv export\rKVClient()\nopenai.OpenAI()",
        "kv get\u{85}KVClient()\u{2028}kv export\u{2029}api_key='x'",
        "kv get\u{b}KVClient()\u{c}kv export\u{1c}api_key='x'\u{1d}kv get\u{1e}kv export",
        "api_key=StraßeAPI_KEY",
        "api_key='MIﬆRAL_API_KEY'",
        "os.environ.get('OPENAI_API_KEY_SUFFIX')",
    ];
    let suffixes = [
        "py", "js", "sh", "md", "json", "PY", "ts", "tsx", "jsx", "mjs", "cjs", "bash", "zsh",
        "fish", "mdx", "txt", "toml", "yaml", "yml",
    ];
    for (i, source) in samples.iter().enumerate() {
        let file = root.join(format!("sample-{i:02}.{}", suffixes[i % suffixes.len()]));
        std::fs::write(&file, source).unwrap();
        paths.push(file.to_string_lossy().into_owned());
    }
    for (name, bytes) in [
        ("invalid.py", b"\xff\xfeos.getenv('OPENAI_API_KEY')\n\xed\xa0\x80kv get\n\xf0\x80\x80\x80KVClient()\n\xe2\x82kv export\n\xc2\x85kv get".to_vec()),
        ("nul.py", b"kv get\0\nKVClient()".to_vec()),
        ("large.py", { let mut b = b"kv get\n".to_vec(); b.resize(1_000_001, b' '); b }),
        ("limit.py", { let mut b = b"kv get\n".to_vec(); b.resize(1_000_000, b' '); b }),
        ("ignored.bin", b"kv get".to_vec()),
        (".py", b"kv get".to_vec()),
        ("trailing.py.", b"kv get".to_vec()),
    ] {
        let file = root.join(name);
        std::fs::write(&file, bytes).unwrap();
        paths.push(file.to_string_lossy().into_owned());
    }
    for dir in [
        ".git",
        ".hg",
        ".svn",
        ".secrets",
        ".kv",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "nested/a",
        "a",
        "a-",
        "a./sub",
    ] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
        std::fs::write(root.join(dir).join("hit.py"), "kv get\napi_key='x'").unwrap();
        paths.push(root.join(dir).to_string_lossy().into_owned());
    }
    std::fs::write(root.join("a.py"), "KVClient()").unwrap();
    std::os::unix::fs::symlink(root.join(".secrets/hit.py"), root.join("secret-link.py")).unwrap();
    std::os::unix::fs::symlink(root.join("sample-00.py"), root.join("normal-link.py")).unwrap();
    std::os::unix::fs::symlink(root.join("nested"), root.join("dir-link")).unwrap();
    std::os::unix::fs::symlink(root.join("missing.py"), root.join("dangling.py")).unwrap();
    std::os::unix::fs::symlink(root.join(".secrets"), root.join("secret-dir")).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("outside.py"), "kv export").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("outside.py"),
        root.join("outside-link.py"),
    )
    .unwrap();
    for rel in [
        "",
        "nested",
        ".secrets",
        ".secrets/hit.py",
        "secret-link.py",
        "secret-dir/hit.py",
        "normal-link.py",
        "outside-link.py",
        "dangling.py",
        "missing.py",
        "dir-link",
        "sample-00.py/child",
        "./nested/../sample-00.py",
    ] {
        paths.push(root.join(rel).to_string_lossy().into_owned());
    }
    paths.extend([
        "sample-00.py".into(),
        "./sample-00.py".into(),
        "nested/../sample-00.py".into(),
        "./missing.py".into(),
        ".".into(),
        "~definitely_no_such_kv_user/file.py".into(),
    ]);
    if let Ok(home) = std::env::var("HOME")
        && let Ok(rel) = root.strip_prefix(home)
    {
        paths.push(format!("~/{}/sample-00.py", rel.display()));
    }
    let case = json!({"cwd": root, "paths": paths});
    let mut child = Command::new(python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/agent_code_probe.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = case.to_string();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success());
    let want: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    // Resolve relative spellings without changing process-global cwd in the test runner.
    let current = std::env::current_dir().unwrap();
    for (path, want) in paths.iter().zip(want) {
        let got = if Path::new(path).is_relative() && !path.starts_with('~') {
            // A subprocess preserves Python's relative display and error spellings.
            let exe = std::env::current_exe().unwrap();
            let out = Command::new(exe)
                .args(["--exact", "relative_scan_probe", "--nocapture"])
                .env("KV_SCAN_PROBE", path)
                .current_dir(&root)
                .output()
                .unwrap();
            assert!(out.status.success());
            let stdout = String::from_utf8(out.stdout).unwrap();
            let result = stdout
                .lines()
                .find_map(|line| line.strip_prefix("SCAN_RESULT "))
                .unwrap();
            serde_json::from_str(result).unwrap()
        } else {
            result(path)
        };
        assert_eq!(got, want, "path={path:?}, cwd={current:?}");
    }
    eprintln!(
        "agent-code parity: {} cases compared, {} source samples",
        paths.len(),
        samples.len()
    );
}

fn result(path: &str) -> Value {
    match scan_agent_code(path) {
        Ok(findings) => json!({"findings": findings}),
        Err(error) => json!({"error": error}),
    }
}

#[test]
fn relative_scan_probe() {
    if let Ok(path) = std::env::var("KV_SCAN_PROBE") {
        println!("SCAN_RESULT {}", result(&path));
    }
}
