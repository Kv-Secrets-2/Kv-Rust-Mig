//! Differential check: `classify_command` and its helpers against Python 0.4.0
//! over `tests/fixtures/classify_corpus.jsonl`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_sandbox::classify::{
    allowlist_hint_for_argv, classify_command, effective_run_mode, session_denial_reason,
};
use serde_json::{Value, json};

fn rust_record(case: &Value) -> Value {
    let argv: Vec<String> = case["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let allowed: Option<Vec<String>> = case["allowed"].as_array().map(|items| {
        items
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    });
    let secrets = case["secrets"].as_bool().unwrap_or(true);
    let protected = case["protected"].as_bool().unwrap_or(false);
    let count = case["count"].as_i64().unwrap_or(0);
    let decision = classify_command(&argv, allowed.as_deref(), secrets);
    json!({
        "allowed": decision.allowed,
        "mode": decision.mode,
        "reason": decision.reason,
        "handoff": decision.broker_handoff.clone().map_or(Value::Null, Value::Object),
        "session_reason": session_denial_reason(&decision, protected),
        "hint": allowlist_hint_for_argv(&argv),
        "effective": effective_run_mode(decision.mode, count),
    })
}

#[test]
fn classify_decisions_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus =
        std::fs::read_to_string(root.join("tests/fixtures/classify_corpus.jsonl")).unwrap();
    let cases: Vec<Value> = corpus
        .clone()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(cases.len() >= 4000, "corpus too small: {}", cases.len());
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(root.join("tests/py/classify_probe.py"))
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
        "{} of {} classify decisions differ from Python:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
