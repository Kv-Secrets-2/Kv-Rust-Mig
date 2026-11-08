//! Run-risk cards against Python with identical input identities and no output masks.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Stdio};

use kv_preflight::{RunRiskCardOptions, build_run_risk_card};
use serde_json::{Value, json};

#[test]
fn isolated_risk_card_probe() {
    let Some(input) = std::env::var_os("KV_RISK_INPUT") else {
        return;
    };
    let data: Value = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let results: Vec<Value> = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(data["reference"].as_array().unwrap())
        .map(|(case, reference)| {
            let options = &case["options"];
            let argv: Vec<String> = case["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().into())
                .collect();
            build_run_risk_card(
                &argv,
                case["cwd"].as_str(),
                &RunRiskCardOptions {
                    run_identity: &reference["identity"],
                    secret_names: options.get("secret_names"),
                    capability_names: options.get("capability_names"),
                    max_calls: options.get("max_calls"),
                    source: options.get("source"),
                },
            )
            .unwrap()
        })
        .collect();
    std::fs::write(
        std::env::var_os("KV_RISK_OUTPUT").unwrap(),
        serde_json::to_vec(&results).unwrap(),
    )
    .unwrap();
}

#[test]
fn run_risk_cards_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let home = root.join("home");
    std::fs::create_dir(&home).unwrap();
    let cwd = root.to_string_lossy().into_owned();
    let mut cases = Vec::new();
    let sources = [
        "",
        "pass",
        "import openai",
        "import anthropic as a",
        "from .google import x",
        "api_call('openai')",
        "api_call(provider='anthropic')",
        "kv.cap_client.api_call('github')",
        "api_call('openai')\napi_call('anthropic')",
        "api_call('missing')",
        "c=OpenAI()\nc.chat()",
        "anthropic.Anthropic()",
        "openai.chat.completions.create()",
        "for x in range(3):\n api_call('openai')",
        "for x in range(True):\n api_call('github')",
        "for x in xs:\n api_call('google')",
        "while x:\n api_call('openai')",
        "for x in range(2):\n for y in range(3):\n  api_call('openai')",
        "subprocess.run(['ssh','user@host'])",
        "subprocess.Popen(['scp','-P','22','x','host:y'])",
        "import paramiko",
        "os.system('ssh host')",
        "requests.get('https://example.com')",
        "open('out','w')",
        "Path('世界').write_text('x')\nPath('dir').mkdir()",
        "os.getenv('OPENAI_API_KEY')",
        "os.environ['ANTHROPIC_API_KEY']",
        "foo(api_key='OPENAI_API_KEY')",
        "@c.chat()\ndef f():\n c=OpenAI()",
        "ｃ=ＯｐｅｎＡＩ()\nｃ.chat()",
        "x =",
        "\u{feff}api_call('openai')",
        "x\0",
        "api_call(f'openai')",
        "api_call('openai')\r\napi_call('github')",
        "match x:\n case 1:\n  api_call('google')",
    ];
    for (i, source) in sources.iter().enumerate() {
        let path = format!("script-{i}.py");
        std::fs::write(root.join(&path), source).unwrap();
        cases.push(json!({"argv":["python3",path],"cwd":cwd,"options":{}}));
    }
    for (name, source) in [
        (
            "overflow.py",
            format!("for x in range(1{}):\n api_call('openai')", "0".repeat(400)),
        ),
        ("deep.py", format!("{}x", "-".repeat(1000))),
    ] {
        std::fs::write(root.join(name), source).unwrap();
        cases.push(json!({"argv":["python3",name],"cwd":cwd,"options":{}}));
    }
    for options in [
        json!({"secret_names":["B"," A ","A","",null,7],"capability_names":["api:openai","api:openai"],"max_calls":12}),
        json!({"secret_names":null,"capability_names":null,"max_calls":null,"source":null}),
        json!({"secret_names":"bad","capability_names":{"bad":true},"source":true}),
        json!({"capability_names":["api:openai"],"max_calls":" 42 ","source":" request "}),
        json!({"capability_names":["api:openai"],"max_calls":false,"source":12}),
        json!({"capability_names":["api:openai"],"max_calls":1.9,"source":["odd",1]}),
        json!({"capability_names":["api:openai"],"max_calls":{},"source":""}),
        json!({"capability_names":["api:openai"],"max_calls":-3,"source":"x".repeat(100)}),
    ] {
        cases.push(json!({"argv":["python3","script-5.py"],"cwd":cwd,"options":options}));
    }
    for argv in [
        vec![],
        vec!["--"],
        vec!["echo", "hello ' 世界"],
        vec!["python3", "missing.py"],
        vec!["curl", "https://example.com"],
        vec!["ssh", "host"],
        vec!["psql", "db"],
        vec!["sh", "script-5.py"],
        vec!["python3", "-c", "print(1)"],
        vec!["python3", "script-5.py", "  trim  ", ""],
    ] {
        cases.push(json!({"argv":argv,"cwd":cwd,"options":{}}));
    }
    let link = root.join("link");
    symlink(&root, &link).unwrap();
    cases.push(json!({"argv":["python3","script-5.py"],"cwd":link,"options":{}}));
    let project = root.join("project");
    std::fs::create_dir_all(project.join(".secrets")).unwrap();
    std::fs::set_permissions(
        project.join(".secrets"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(
        project.join(".secrets/config.json"),
        r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":["python3 allowed.py"]}}"#,
    )
    .unwrap();
    std::fs::set_permissions(
        project.join(".secrets/config.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    for path in ["allowed.py", "blocked.py"] {
        std::fs::write(project.join(path), "api_call('openai')").unwrap();
        cases.push(json!({"argv":["python3",path],"cwd":project,"options":{}}));
    }
    let input = json!({"projects":[project],"cases":cases}).to_string();
    let mut child = Command::new(python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/risk_card_probe.py"))
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success());
    let reference: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rust_input = root.join("input.json");
    let rust_output = root.join("output.json");
    std::fs::write(
        &rust_input,
        serde_json::to_vec(&json!({"cases":cases,"reference":reference})).unwrap(),
    )
    .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "isolated_risk_card_probe"])
        .env("HOME", &home)
        .env("KV_RISK_INPUT", rust_input)
        .env("KV_RISK_OUTPUT", &rust_output)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated risk-card probe failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let got: Vec<Value> = serde_json::from_slice(&std::fs::read(rust_output).unwrap()).unwrap();
    let mut differences = 0;
    let mut nul_differences = 0;
    let nul_script = format!(
        "script-{}.py",
        sources.iter().position(|s| s.contains('\0')).unwrap()
    );
    for ((case, got), want) in cases.iter().zip(got).zip(reference.as_array().unwrap()) {
        let newer_nul = want["python_version"][1].as_u64().unwrap() >= 12;
        let mut want = want["card"].clone();
        if case["argv"][1] == nul_script && newer_nul {
            assert_eq!(want["extraction_status"], "complete");
            assert!(
                want["limits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|s| s == "Python script could not be parsed; estimates are incomplete.")
            );
            want["extraction_status"] = json!("limited");
            want["facts"] =
                json!({"preflight_error":"source code string cannot contain null bytes"});
            want["uncertainty"] = json!([
                "static-analysis-only",
                "runtime-enforcement-remains-authoritative",
                "preflight-analysis-failed"
            ]);
            want["limits"] = json!(["KV could not complete static preflight for this command."]);
            nul_differences += 1;
        }
        if case["argv"][1] == "deep.py" {
            assert!(
                want["facts"]["preflight_error"]
                    .as_str()
                    .unwrap()
                    .contains("recursion depth")
            );
            assert_eq!(
                got["facts"]["preflight_error"],
                "Python script is nested too deeply for static preflight"
            );
            // Intentional hardening difference: verify every other card field unchanged.
            want["facts"]["preflight_error"] =
                json!("Python script is nested too deeply for static preflight");
            differences += 1;
        }
        assert_eq!(got, want, "case {case}");
    }
    eprintln!(
        "run-risk-card parity: {} cases, {} scripts, {differences} documented depth difference, {nul_differences} version-specific NUL differences",
        cases.len(),
        sources.len() + 2
    );
}
