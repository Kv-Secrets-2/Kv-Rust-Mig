//! Live comparison of the risk-card port against Python 0.4.0 (`kv/risk_card.py`).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_approvals::risk_card::{minimal_risk_card, normalize_risk_card, summarize_risk_card};
use serde_json::{Value, json};

fn identity() -> Value {
    json!({
        "command_fingerprint": "a".repeat(64),
        "argv": ["python3", "app.py", "--flag", "x".repeat(600)],
        "cwd": "/home/me/proj",
        "run_id": "run_0123",
        "script_kind": "file",
        "script_sha256": "b".repeat(64),
        "script_ref_hash": "c".repeat(64),
        "script_path": "/home/me/proj/app.py",
        "scope": {"env": "dev", "names": ["B", "A"]},
        "unexpected": "dropped?",
    })
}

fn normalize_cases() -> Vec<Value> {
    let long = "y".repeat(2000);
    let many: Vec<String> = (0..80).map(|i| format!("item{i}")).collect();
    let argv_many: Vec<String> = (0..140).map(|i| format!("arg{i}")).collect();
    vec![
        Value::Null,
        json!([]),
        json!("card"),
        json!(7),
        json!({}),
        json!({"version": "1", "generator": 3, "source": true, "extraction_status": null}),
        json!({
            "version": 1, "generator": "kv_risk_card_v1", "source": "preflight",
            "extraction_status": "ok",
            "identity": identity(),
            "scope": {
                "secret_names": ["b", " a ", "", "a", 5, null, "b"],
                "capability_names": "api:openai",
                "raw_secret_injection": "yes",
                "broker_capability": 0,
                "max_calls": "12",
            },
            "facts": {
                "argv": argv_many,
                "network": "1",
                "reads_env": ["X", "Y", "X"],
                "writes_files": many,
                "api": {
                    "providers": ["openai", "anthropic", "openai"],
                    "calls": {"openai": 3, "anthropic": "2", "bad": "x"},
                    "unsafe_methods": ["POST", "post", "GET"],
                    "paths": ["/v1/a", "/v1/b"],
                    "post_bodies": true,
                },
                "ssh": {"hosts": ["h1", "h2"], "commands": ["ls"]},
                "file": {"reads": ["a"], "writes": ["b"], "deletes": []},
                "broker_handoff": {"kind": "cap_client", "module": "kv.cap_client", "calls": 2},
                "subprocess": [["sh", "-c", "x"]],
            },
            "uncertainty": [long.clone(), "", "  spaced  ", 3, null],
            "limits": (0..40).map(|i| json!(format!("limit {i}"))).collect::<Vec<_>>(),
            "extra_top_level": {"ignored": true},
        }),
        json!({
            "version": 2.0, "generator": "", "source": "x",
            "identity": {"argv": "not-a-list", "cwd": 12, "command_fingerprint": ["l"]},
            "scope": {"secret_names": null, "capability_names": [], "max_calls": -3},
            "facts": {"api": {"calls": {"a": 1.5, "b": true, "c": -1, "d": 9007199254740993i64}}},
            "uncertainty": "single-string",
            "limits": "single-limit",
        }),
        json!({
            "version": 1, "identity": {"argv": []}, "scope": {}, "facts": {"network": null},
            "uncertainty": [], "limits": [],
        }),
        json!({
            "version": 1,
            "identity": {"argv": ["ünï", "quote\"d", "tab\tsep", "new\nline"], "cwd": "/ü/path"},
            "scope": {"secret_names": ["ünï", "ascii"], "max_calls": true},
            "facts": {"api": {"providers": "openai", "calls": "many"}, "broker_handoff": "yes"},
        }),
        json!({"version": 1, "facts": {"api": {}, "ssh": {}, "file": {}, "broker_handoff": {}}}),
        json!({"version": 1, "facts": {"api": {"calls": {}}, "ssh": "h", "file": ["x"]}}),
        json!({"version": 1, "scope": {"max_calls": 1e3}}),
        json!({"version": 1, "scope": {"max_calls": "1e3"}}),
        json!({"version": 1, "scope": {"max_calls": " 42 "}}),
        json!({"version": 1, "scope": {"max_calls": "+7"}}),
        json!({"version": 1, "scope": {"max_calls": "-0"}}),
        json!({"version": 1, "scope": {"max_calls": "0x10"}}),
        json!({"version": 1, "scope": {"max_calls": 18446744073709551615u64}}),
        json!({"version": 1, "scope": {"max_calls": -9223372036854775808i64}}),
        json!({"version": 1, "scope": {"max_calls": 2.5}}),
        json!({"version": 1, "scope": {"max_calls": 3.0}}),
        json!({"version": 1, "scope": {"max_calls": false}}),
        json!({"version": 1, "scope": {"max_calls": [1]}}),
        json!({"version": 1, "identity": {"argv": [1, 2.5, true, null, {"k": "v"}, ["n"]]}}),
        json!({"version": 1, "identity": {"argv": ["x".repeat(513)]}}),
        json!({"version": 1, "uncertainty": [" lead", "trail ", "both  "], "limits": [1, 2, 3]}),
    ]
}

fn minimal_cases() -> Vec<Value> {
    vec![
        json!({"run_identity": identity(), "secret_names": ["B", "A", "B"], "capability_names": ["api:x"], "max_calls": 3, "reason": "because"}),
        json!({"run_identity": identity()}),
        json!({"run_identity": {}, "secret_names": [], "capability_names": [], "max_calls": null, "reason": ""}),
        json!({"run_identity": {"argv": ["ls"]}, "capability_names": ["api:x", "api:y"], "max_calls": null, "reason": "r".repeat(400)}),
        json!({"run_identity": {"argv": ["ls"]}, "capability_names": ["api:x"], "max_calls": -1, "reason": "   "}),
        json!({"run_identity": {"cwd": "/p"}, "secret_names": ["only-secret"], "max_calls": 5, "reason": "spaced  out"}),
    ]
}

fn rust_minimal(case: &Value) -> Value {
    let list = |key: &str| -> Option<Vec<String>> {
        case.get(key).and_then(Value::as_array).map(|items| {
            items
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        })
    };
    let secrets = list("secret_names");
    let caps = list("capability_names");
    let reason = case
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("risk_card_not_provided");
    minimal_risk_card(
        &case["run_identity"],
        secrets.as_deref(),
        caps.as_deref(),
        case.get("max_calls"),
        reason,
    )
}

#[test]
fn risk_cards_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let normalize = normalize_cases();
    let minimal = minimal_cases();
    let case = json!({"minimal": minimal, "normalize": normalize, "summarize": normalize});
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/risk_card_probe.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(case.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let want: Value = serde_json::from_slice(&output.stdout).unwrap();

    let mut mismatches = Vec::new();
    let mut python_errors = 0;
    for (i, card) in normalize.iter().enumerate() {
        if want["normalize"][i].get("python_error").is_some() {
            // Python raises on this card; Rust only has to answer without panicking.
            python_errors += 1;
            let _ = normalize_risk_card(Some(card));
            let _ = summarize_risk_card(Some(card));
            continue;
        }
        let got = normalize_risk_card(Some(card));
        if got != want["normalize"][i] {
            mismatches.push(format!(
                "normalize[{i}] input {card}\n  python: {}\n  rust:   {got}",
                want["normalize"][i]
            ));
        }
        let got = json!(summarize_risk_card(Some(card)));
        if got != want["summarize"][i] {
            mismatches.push(format!(
                "summarize[{i}] input {card}\n  python: {}\n  rust:   {got}",
                want["summarize"][i]
            ));
        }
    }
    for (i, case) in minimal.iter().enumerate() {
        let got = rust_minimal(case);
        if got != want["minimal"][i] {
            mismatches.push(format!(
                "minimal[{i}] input {case}\n  python: {}\n  rust:   {got}",
                want["minimal"][i]
            ));
        }
    }
    assert!(
        normalize_risk_card(None) == want["normalize"][0],
        "None card differs from Python's None"
    );
    assert!(
        python_errors <= 2,
        "{python_errors} cards made Python raise; trim the case set"
    );
    assert!(
        mismatches.is_empty(),
        "{} risk-card results differ from Python:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
