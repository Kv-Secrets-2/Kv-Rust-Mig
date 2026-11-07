//! Differential check: redaction needles, variants and `redact` against
//! Python 0.4.0 over a generated corpus of secret sets and outputs.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use base64::Engine;
use kv_sandbox::redact::{VariantLimits, build_secret_variants, redact, redaction_needles};
use serde_json::{Value, json};

fn rust_record(case: &Value) -> Value {
    let secrets: Vec<(String, String)> = case["secrets"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect();
    let pairs = || secrets.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    let variants: Vec<Value> = build_secret_variants(pairs(), VariantLimits::default())
        .iter()
        .map(|(v, n)| json!([v, n]))
        .collect();
    json!({
        "needles": redaction_needles(pairs()),
        "redacted": redact(case["text"].as_str().unwrap(), pairs()),
        "variants": variants,
    })
}

fn corpus() -> String {
    let sixty = "x".repeat(60);
    let values = [
        "",
        "a",
        "abc",
        "abcd",
        "hunter2",
        "hunter2!",
        "sk-abc123",
        "sk-abc123-extended",
        "p@ss word/with+plus&amp;=eq",
        "émoji🔑secret",
        "tab\there",
        "new\nline",
        sixty.as_str(),
        "longsecretvalue-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "3132333435363738",
        "AAAA",
        "ZXhhbXBsZQ==",
        "%41%42%43%44",
        "~tilde.dot_under-dash",
        "  spaces  ",
        "дорога",
        "12345678",
    ];
    let mut lines = Vec::new();
    for (i, a) in values.iter().enumerate() {
        for b in values.iter().skip(i) {
            let secrets = json!({"ALPHA": a, "BETA": b});
            let b64 = base64::engine::general_purpose::STANDARD.encode(a.as_bytes());
            let text = format!(
                "out {a} mid {b} b64 {b64} hex {} rev {} q {} end",
                hex::encode(a.as_bytes()),
                a.chars().rev().collect::<String>(),
                kv_sandbox::redact::percent_quote(b, true).to_lowercase(),
            );
            lines.push(json!({"secrets": secrets, "text": text}).to_string());
        }
    }
    lines.push(json!({"secrets": {}, "text": "nothing"}).to_string());
    lines.push(json!({"secrets": {"ONLY": "hunter2!", "DUP": "hunter2!"}, "text": "hunter2! aHVudGVyMiE="}).to_string());
    lines.join("\n") + "\n"
}

#[test]
fn redaction_matches_python() {
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
        .arg(root.join("tests/py/redact_probe.py"))
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
        "{} of {} redaction records differ from Python:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
