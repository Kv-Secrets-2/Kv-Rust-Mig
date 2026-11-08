use kv_broker::{
    HttpRuleOptions, http_policy_route_label, http_policy_rule, validate_http_policy_binding,
};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn http_policy_rule_helpers_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let cases = vec![
        json!({"id":"","path":null}),
        json!({"id":"read","path":"/user"}),
        json!({"id":"read","path":"/v1","methods":["get","HEAD"],"query_keys":["q","page"],"allowed_headers":["X-Trace","Accept"]}),
        json!({"id":"prefix","path_prefix":"/v1","methods":["OPTIONS"]}),
        json!({"id":"unsafe","path_prefix":"/v1","methods":["POST","PUT","PATCH","DELETE"]}),
        json!({"id":"mixed","path":"/v1","methods":["GET","POST"]}),
        json!({"id":"unsupported","path":"/v1","methods":["TRACE"]}),
    ];
    let provider = json!({"base_url":"https://1.1.1.1/","secret_name":"TOKEN"});
    let bindings = vec![
        json!({"provider":provider,"entry":{"origin":"https://1.1.1.1","secret_name":"TOKEN","rules":[]}}),
        json!({"provider":provider,"entry":{"rules":[]}}),
        json!({"provider":provider,"entry":{"origin":42,"secret_name":"TOKEN","rules":[]}}),
        json!({"provider":provider,"entry":{"origin":"https://1.1.1.1","secret_name":"OTHER","rules":[]}}),
        json!({"provider":provider,"entry":{"origin":"https://8.8.8.8","secret_name":"TOKEN","rules":[]}}),
    ];
    let input = json!({"rules":cases,"bindings":bindings});
    let mut child = Command::new(python)
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/http_policy.py"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "reference: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut rules = Vec::new();
    let mut labels = Vec::new();
    for case in &cases {
        let strings = |key: &str| {
            case[key]
                .as_array()
                .map(|v| v.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
                .unwrap_or_default()
        };
        let options = HttpRuleOptions {
            id: case["id"].as_str().unwrap().into(),
            methods: strings("methods"),
            path: case["path"].as_str().map(str::to_owned),
            path_prefix: case["path_prefix"].as_str().map(str::to_owned),
            query_keys: strings("query_keys"),
            allowed_headers: strings("allowed_headers"),
        };
        match http_policy_rule(&options) {
            Ok(rule) => {
                labels.push(json!(http_policy_route_label(&rule).unwrap()));
                rules.push(rule);
            }
            Err(reason) => {
                labels.push(Value::Null);
                rules.push(json!({"error":reason}));
            }
        }
    }
    assert_eq!(
        json!({"rules":rules,"labels":labels,
            "bindings":bindings.iter().map(|case| validate_http_policy_binding(&case["entry"], &case["provider"])).collect::<Vec<_>>()
        }),
        expected
    );
}
