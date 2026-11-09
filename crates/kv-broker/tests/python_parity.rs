use std::io::Write;
use std::process::{Command, Stdio};

use kv_broker::{
    HttpPolicySnapshot, evaluate_provider_http_request, hide, hide_cut, hide_value, output_needles,
};
use serde_json::{Value, json};

fn python_results(code: &str, input: &Value) -> Value {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        panic!("KV_PY_REF must be set by the test caller");
    };
    let mut child = Command::new(python)
        .arg("-c")
        .arg(code)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Python reference");
    child
        .stdin
        .take()
        .expect("Python stdin")
        .write_all(&serde_json::to_vec(input).expect("serialize test cases"))
        .expect("write Python input");
    let output = child.wait_with_output().expect("wait for Python reference");
    assert!(
        output.status.success(),
        "Python reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Python JSON output")
}

fn policy_cases() -> Vec<Value> {
    let provider = json!({
        "base_url":"https://api.example.test",
        "secret_name":"TOKEN",
        "auth_type":"bearer",
        "default_headers":{"Accept":"application/json"}
    });
    let valid_entry = json!({
        "origin":"https://api.example.test",
        "secret_name":"TOKEN",
        "rules":[
            {
                "id":"read",
                "methods":["GET","HEAD","OPTIONS"],
                "path_prefix":"/v1/items",
                "allow_query":true,
                "query_keys":["q","page"],
                "allowed_headers":["x-trace"]
            },
            {
                "id":"write",
                "methods":["POST"],
                "path":"/v1/items",
                "approval":"per-call"
            }
        ]
    });
    let methods = ["GET", "POST", "HEAD", "DELETE", "TRACE", ""];
    let targets = [
        "/v1/items",
        "/v1/items/42",
        "/v1/items-other",
        "/elsewhere",
        "/v1/items?q=ok",
        "/v1/items?q=ok&page=2",
        "/v1/items?q=ok&other=1",
        "/v1//items",
        "/v1/%2e",
        "/v1/items?",
        "/v1/items#fragment",
    ];
    let headers = [
        json!({}),
        json!({"X-Trace":"ok"}),
        json!({"X-HTTP-Method-Override":"DELETE"}),
        json!({"Authorization":"caller"}),
    ];
    let mut cases = Vec::new();
    for method in methods {
        for target in targets {
            for header in &headers {
                cases.push(json!({
                    "policy":{"example":valid_entry},
                    "provider":provider,
                    "provider_name":"example",
                    "method":method,
                    "target":target,
                    "headers":header,
                    "body":null
                }));
            }
        }
    }

    let malformed = [
        json!(false),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN"}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[],"extra":true}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[false]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"bad id","methods":["GET"],"path":"/x"}]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"empty","methods":[],"path":"/x"}]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"method","methods":["TRACE"],"path":"/x"}]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"mixed","methods":["GET","POST"],"path":"/x"}]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"selector","methods":["GET"]}]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"encoded","methods":["GET"],"path":"/%2e"}]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"query","methods":["GET"],"path":"/x","allow_query":true,"query_keys":["_method"]}]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"headers","methods":["GET"],"path":"/x","allowed_headers":["host"]}]}),
        json!({"origin":"https://api.example.test","secret_name":"TOKEN","rules":[{"id":"approval","methods":["POST"],"path":"/x"}]}),
    ];
    for entry in malformed {
        cases.push(json!({
            "policy":{"example":entry},
            "provider":provider,
            "provider_name":"example",
            "method":"GET",
            "target":"/x",
            "headers":{},
            "body":null
        }));
    }
    cases
}

#[test]
fn http_policy_matches_python_over_canonical_targets_and_malformed_rules() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP HTTP policy parity: set KV_PY_REF");
        return;
    };
    let _ = python;
    let cases = policy_cases();
    assert!(cases.len() >= 60);
    let script = r#"
import json, sys
from kv.broker_policy import HttpPolicySnapshot, evaluate_provider_http_request
cases = json.load(sys.stdin)
results = []
for case in cases:
    snapshot = HttpPolicySnapshot(case["policy"], True)
    results.append(evaluate_provider_http_request(
        snapshot, case["provider_name"], case["provider"],
        case["method"], case["target"], case.get("body"), case["headers"]))
print(json.dumps(results, separators=(",", ":")))
"#;
    let expected = python_results(script, &Value::Array(cases.clone()));
    let expected = expected.as_array().expect("Python results");
    assert_eq!(expected.len(), cases.len());
    for (index, case) in cases.iter().enumerate() {
        let snapshot = HttpPolicySnapshot {
            providers: case["policy"].clone(),
            configured: true,
            legacy_providers: None,
        };
        let actual = evaluate_provider_http_request(
            &snapshot,
            case["provider_name"].as_str().unwrap(),
            &case["provider"],
            &case["method"],
            &case["target"],
            case.get("body"),
            &case["headers"],
        );
        assert_eq!(
            actual, expected[index],
            "policy parity case {index}: {case}"
        );
    }
}

#[test]
fn provider_table_matches_python_snapshot() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP provider table parity: set KV_PY_REF");
        return;
    };
    let _ = python;
    let config = json!({
        "providers":{
            "local":{
                "base_url":"https://api.example.test/v1/",
                "secret_name":"LOCAL_TOKEN",
                "auth_type":"header",
                "auth_header_name":"X-Local-Key"
            },
            "invalid":{"base_url":"http://not-secure.test","secret_name":"BAD"},
            "broken":false,
            "db":{"provider_type":"postgres","host":"localhost","database":"app","username":"bot","secret_name":"DB_PASS"}
        }
    });
    let script = r#"
import json, sys
from kv.providers import build_provider_table
table, loaded = build_provider_table(None, config=json.load(sys.stdin))
print(json.dumps({"table": table, "loaded": loaded}, separators=(",", ":")))
"#;
    let expected = python_results(script, &config);
    let (table, loaded) = kv_broker::build_provider_table(&config);
    assert_eq!(json!({"table":table,"loaded":loaded}), expected);
}

#[test]
fn redaction_matches_python_for_500_generated_cases() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP redaction parity: set KV_PY_REF");
        return;
    };
    let _ = python;
    let alphabet = ['a', 'b', 'c', '%', '\\', '"', '\'', '\n', 'é', '🦀'];
    let mut state = 0x9e37_79b9_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut cases = Vec::new();
    for index in 0..500 {
        let secret_len = (next() as usize % 9) + 3;
        let secret = (0..secret_len)
            .map(|_| alphabet[next() as usize % alphabet.len()])
            .collect::<String>();
        let mut text = (0..(next() as usize % 36) + 8)
            .map(|_| alphabet[next() as usize % alphabet.len()])
            .collect::<String>();
        match index % 5 {
            0 => text.push_str(&secret),
            1 => text = format!("{secret}{text}{secret}"),
            2 => text = format!("{}{}", secret.repeat(3), text),
            3 => text = format!("{}{}", secret.escape_debug(), text),
            _ => {}
        }
        let value = json!({
            "text":text,
            "nested":[text,{"key":secret}],
            "index":index
        });
        cases.push(json!({
            "secret":secret,
            "text":text,
            "value":value,
            "keep":text.chars().count().saturating_sub(index % 7)
        }));
    }
    let script = r#"
import json, sys
from kv.providers import _output_needles, _hide, _hide_cut, _hide_value
cases = json.load(sys.stdin)
results = []
for case in cases:
    needles = _output_needles({"TOKEN": case["secret"]}, (case["secret"],))
    results.append({
        "hide": _hide(case["text"], needles),
        "cut": _hide_cut(case["text"], needles, keep=case["keep"]),
        "value": _hide_value(case["value"], needles),
    })
print(json.dumps(results, ensure_ascii=False, separators=(",", ":")))
"#;
    let expected = python_results(script, &Value::Array(cases.clone()));
    let expected = expected.as_array().expect("Python redaction results");
    assert_eq!(expected.len(), 500);
    for (index, case) in cases.iter().enumerate() {
        let secret = case["secret"].as_str().unwrap();
        let secrets = json!({"TOKEN":secret});
        let exact = [secret];
        let needles = output_needles(&secrets, &exact);
        let actual = json!({
            "hide":hide(case["text"].as_str().unwrap(),&needles,None),
            "cut":hide_cut(case["text"].as_str().unwrap(),&needles,Some(case["keep"].as_u64().unwrap() as usize)),
            "value":hide_value(&case["value"],&needles)
        });
        assert_eq!(
            actual, expected[index],
            "redaction parity case {index}: {case}"
        );
    }
}
