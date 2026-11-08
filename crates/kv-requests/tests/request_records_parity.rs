use std::io::Write;
use std::process::{Command, Stdio};

use kv_requests::request_records::{RequestRecord, RequestRecords};
use kv_requests::{RequestError, Result};
use serde_json::{Value, json};

fn value(record: RequestRecord) -> Value {
    json!({"request_id": record.request_id, "content_digest": record.content_digest,
        "environment": record.environment, "network": record.network,
        "network_reason": record.network_reason, "expires_at_epoch": record.expires_at_epoch})
}

fn execute(records: &mut RequestRecords, op: &Value) -> Result<Value> {
    Ok(match op["op"].as_str().unwrap() {
        "reset" => {
            *records = RequestRecords::new(op["bound"].as_u64().map(|n| n as usize));
            Value::Null
        }
        "record" => value(records.record(&op["request"], op["now"].as_i64())?),
        "get" => records
            .get(op["id"].as_str().unwrap(), op["now"].as_i64())?
            .map(value)
            .unwrap_or(Value::Null),
        "len" => json!(records.len()?),
        _ => unreachable!(),
    })
}

#[test]
fn request_records_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let request = json!({"request_id":"one", "environment":"dev", "network":false,
        "network_reason":"none", "expires_at_epoch":110,
        "argv":["echo", "雪"], "cwd":"/fixture", "reason":"review"});
    let mut ops = vec![
        json!({"op":"len"}),
        json!({"op":"get","id":"unknown","now":100}),
    ];
    for invalid in [
        Value::Null,
        json!([]),
        json!(true),
        json!(1),
        json!("request"),
        json!({}),
    ] {
        ops.push(json!({"op":"record","request":invalid,"now":100}));
    }
    for field in [
        "request_id",
        "environment",
        "network",
        "network_reason",
        "expires_at_epoch",
    ] {
        let mut missing = request.clone();
        missing.as_object_mut().unwrap().remove(field);
        ops.push(json!({"op":"record","request":missing,"now":100}));
        for invalid in [
            Value::Null,
            json!(""),
            json!([]),
            json!({}),
            json!(true),
            json!(false),
            json!(0),
            json!(1),
            json!(110.0),
            json!("110"),
        ] {
            if (field == "network" && invalid.is_boolean())
                || (field == "expires_at_epoch" && invalid.is_i64())
            {
                continue;
            }
            let mut odd = request.clone();
            odd[field] = invalid;
            ops.push(json!({"op":"record","request":odd,"now":100}));
        }
    }
    ops.push(json!({"op":"reset","bound":2}));
    ops.push(json!({"op":"record","request":request,"now":100}));
    let mut changed = request.clone();
    changed["environment"] = json!("production");
    changed["network"] = json!(true);
    changed["expires_at_epoch"] = json!(999);
    ops.push(json!({"op":"record","request":changed,"now":100}));
    let mut second = request.clone();
    second["request_id"] = json!("two");
    ops.push(json!({"op":"record","request":second,"now":100}));
    let mut third = request.clone();
    third["request_id"] = json!("three");
    ops.push(json!({"op":"record","request":third,"now":100}));
    ops.push(json!({"op":"get","id":"one","now":109}));
    ops.push(json!({"op":"len"}));
    ops.push(json!({"op":"get","id":"one","now":110}));
    ops.push(json!({"op":"len"}));
    ops.push(json!({"op":"record","request":changed,"now":110}));
    // Invalid candidates must not prune existing records.
    ops.push(json!({"op":"record","request":{},"now":1000}));
    ops.push(json!({"op":"len"}));
    ops.push(json!({"op":"record","request":request,"now":1000}));
    ops.push(json!({"op":"len"}));
    ops.push(json!({"op":"get","id":"one","now":1000}));
    for expiry in [
        "-9999999999999999999999999999999",
        "9999999999999999999999999999999",
        "-1",
        "0",
    ] {
        let mut odd = request.clone();
        odd["expires_at_epoch"] = serde_json::from_str(expiry).unwrap();
        odd["request_id"] = json!(expiry);
        odd["environment"] = json!(" ");
        odd["network_reason"] = json!(" ");
        ops.push(json!({"op":"record","request":odd,"now":100}));
        ops.push(json!({"op":"get","id":expiry,"now":100}));
    }
    ops.push(json!({"op":"reset","bound":0}));
    ops.push(json!({"op":"record","request":request,"now":100}));
    ops.push(json!({"op":"reset"}));
    for id in 0..=1000 {
        let mut item = request.clone();
        item["request_id"] = json!(id.to_string());
        ops.push(json!({"op":"record","request":item,"now":100}));
    }
    ops.push(json!({"op":"len"}));
    ops.push(json!({"op":"get","id":"absent","now":110}));
    ops.push(json!({"op":"len"}));

    let mut child = Command::new(python)
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/py/request_records_probe.py"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let bytes = serde_json::to_vec(&ops).unwrap();
    let writer = std::thread::spawn(move || input.write_all(&bytes).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let mut records = RequestRecords::default();
    for (op, expected) in ops.iter().zip(&expected) {
        let actual = match execute(&mut records, op) {
            Ok(value) => json!({"ok":value}),
            Err(error) => {
                json!({"error":error.to_string(), "type":if matches!(error, RequestError::RecordsFull(_)) {"RequestRecordsFull"} else {"ValueError"}})
            }
        };
        assert_eq!(&actual, expected, "operation {op}");
    }
    assert_eq!(ops.len(), expected.len());
    assert!(records.is_empty().unwrap());
}
