//! Differential check: reserved/sensitive names, `build_run_env`, the save
//! warning and the framing check against Python 0.4.0.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_sandbox::runenv::{
    RunEnvError, build_run_env, check_run_env_pairs, expected_run_env_args,
    looks_sensitive_env_name, reserved_run_env_name, run_env_save_warning,
};
use serde_json::{Map, Value, json};

fn pairs(value: &Value) -> Vec<(String, String)> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect()
}

fn rust_record(case: &Value) -> Value {
    let secrets = pairs(&case["secrets"]);
    let base = pairs(&case["base"]);
    let names: Vec<&str> = case["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let secret_pairs = || secrets.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    let (env, error) = match build_run_env(
        secret_pairs(),
        base.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    ) {
        Ok(env) => (
            Value::Object(
                env.into_iter()
                    .map(|(k, v)| (k, json!(v)))
                    .collect::<Map<_, _>>(),
            ),
            Value::Null,
        ),
        Err(err) => (Value::Null, json!(err.to_string())),
    };
    let pairs_error = match check_run_env_pairs(secret_pairs()) {
        Ok(()) => Value::Null,
        Err(err @ RunEnvError::Injection { .. }) => json!(err.to_string()),
        Err(other) => panic!("unexpected {other:?}"),
    };
    json!({
        "reserved": names.iter().map(|n| reserved_run_env_name(n)).collect::<Vec<_>>(),
        "sensitive": names.iter().map(|n| looks_sensitive_env_name(n)).collect::<Vec<_>>(),
        "env": env,
        "error": error,
        "warning": run_env_save_warning(names.iter().copied()),
        "pairs_error": pairs_error,
        "args": expected_run_env_args(secret_pairs()),
    })
}

fn corpus() -> String {
    let names = [
        "PATH",
        "path",
        "HOME",
        "DATABASE_URL",
        "LD_PRELOAD",
        "PYTHONPATH",
        "NODE_AUTH_TOKEN",
        "CARGO_REGISTRIES_X_INDEX",
        "CARGO_REGISTRIES_MY-REG_TOKEN",
        "CARGO_REGISTRIES__TOKEN",
        "cargo_registries_a_token",
        "GIT_TOKEN",
        "GIT_DIR",
        "my_api_key",
        "KV_TOKEN",
        "TERM",
        "AWS_SECRET",
        "",
        "A=B",
        "tab\tname",
        "new\nline",
        "ünïcode",
        "x y",
        "SSH_PRIVATE_KEY",
        "SUDO_X",
        "JDK_JAVAC_OPTIONS",
        "QT_PLUGIN_PATH",
        "ok_name",
        "PIP_INDEX_URL",
        "R_LIBS",
        "ßeta",
        "İstanbul",
    ];
    let bases: [&[(&str, &str)]; 4] = [
        &[
            ("PATH", ".:/usr/bin:bin:/bin"),
            ("AWS_SECRET", "x"),
            ("TERM", "xterm"),
            ("Path", "rel"),
        ],
        &[("PATH", ""), ("HOME", "/h")],
        &[],
        &[
            ("PATH", "/a:/b"),
            ("MY_API_KEY", "k"),
            ("SESSION_ID", "s"),
            ("TOKENIZER", "t"),
            ("USER", "u"),
        ],
    ];
    let mut lines = Vec::new();
    for (i, a) in names.iter().enumerate() {
        for b in names.iter().skip(i) {
            let base = bases[(i + b.len()) % bases.len()];
            let base_obj: Map<String, Value> = base
                .iter()
                .map(|(k, v)| ((*k).to_owned(), json!(v)))
                .collect();
            let mut secrets = Map::new();
            secrets.insert((*a).to_owned(), json!("v1"));
            secrets.insert(
                (*b).to_owned(),
                json!(if b.len() % 3 == 0 { "nul\u{0}" } else { "" }),
            );
            lines.push(
                json!({"secrets": secrets, "base": base_obj, "names": [a, b, a]}).to_string(),
            );
        }
    }
    lines.push(json!({"secrets": {}, "base": {}, "names": []}).to_string());
    lines.join("\n") + "\n"
}

#[test]
fn run_env_rules_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus = corpus();
    let cases: Vec<Value> = corpus
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(root.join("tests/py/runenv_probe.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start Python probe");
    let mut stdin = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || stdin.write_all(corpus.as_bytes()));
    let output = child.wait_with_output().unwrap();
    feeder.join().unwrap().unwrap();
    assert!(output.status.success(), "Python probe failed");
    let expected: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(expected.len(), cases.len());
    let mut mismatches = Vec::new();
    for (case, want) in cases.iter().zip(&expected) {
        let got = rust_record(case);
        if &got != want {
            mismatches.push(format!("case {case}\n  python: {want}\n  rust:   {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} run-env records differ from Python:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
