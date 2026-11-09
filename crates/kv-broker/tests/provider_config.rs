use kv_broker::{
    build_provider_table, default_http_policy, validate_db_provider, validate_ssh_provider,
};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn result(value: Result<(), String>) -> Value {
    match value {
        Ok(()) => json!([true, ""]),
        Err(reason) => json!([false, reason]),
    }
}

#[test]
fn provider_validation_and_default_policy_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let mut db = vec![
        json!({}),
        json!({"provider_type":"oracle"}),
        json!({"provider_type":42}),
    ];
    let mut ssh = vec![json!({})];
    let mut tables = vec![json!({}), json!({"providers":[]})];
    for ptype in ["postgres", "mysql", "redis", "ssh"] {
        let full = json!({"provider_type":ptype, "host":"db.example", "database":"app", "username":"owner", "secret_name":"TOKEN"});
        if ptype == "ssh" {
            ssh.push(full.clone());
        } else {
            db.push(full.clone());
        }
        for field in ["host", "database", "username", "secret_name"] {
            for value in [
                json!(null),
                json!(false),
                json!(0),
                json!(""),
                json!([]),
                json!({}),
                json!(42),
                json!(true),
            ] {
                let mut case = full.clone();
                case[field] = value;
                if ptype == "ssh" {
                    ssh.push(case.clone());
                } else {
                    db.push(case.clone());
                }
                tables.push(json!({"providers":{"test":case}}));
            }
        }
        tables.push(json!({"providers":{"test":full}}));
    }
    tables.push(json!({"providers":{
        "good":{"provider_type":"http","base_url":"https://1.1.1.1/","secret_name":"TOKEN"},
        "bad":{"provider_type":"http","base_url":"http://1.1.1.1","secret_name":"TOKEN"},
        "github":{"base_url":"https://1.1.1.1","secret_name":"TOKEN"},
        "not-object":42
    }}));
    let input = json!({"db":db,"ssh":ssh,"tables":tables});
    let mut child = Command::new(python)
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/provider_config.py"))
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
    assert_eq!(
        json!({
            "db":db.iter().map(|v| result(validate_db_provider(v))).collect::<Vec<_>>(),
            "ssh":ssh.iter().map(|v| result(validate_ssh_provider(v))).collect::<Vec<_>>(),
            "tables":tables.iter().map(|v| build_provider_table(v).0).collect::<Vec<_>>(),
            "default":default_http_policy(),
        }),
        expected
    );
}
