#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use base64::{Engine, engine::general_purpose::URL_SAFE};
use kv_requests::{Result, approvals::*};
use serde_json::{Value, json};

struct Hooks;

impl RequestHooks for Hooks {
    fn build_run_risk_card(&self, inputs: &Value) -> Result<Value> {
        Ok(inputs.clone())
    }
    fn normalize_risk_card(&self, card: &Value) -> Result<Value> {
        Ok(card.clone())
    }
    fn normalize_service_calls(
        &self,
        names: &[String],
        max_calls: &Value,
        per_service: &Value,
    ) -> Result<(Value, Value)> {
        if *per_service == json!({"bad": 0}) {
            return Err(kv_requests::RequestError::Invalid(
                "stub service budget refused".into(),
            ));
        }
        let calls = if max_calls.is_null() || *max_calls == 0 {
            json!(names.len())
        } else {
            max_calls.clone()
        };
        let per_service = if per_service.is_null() || *per_service == json!({}) {
            Value::Object(names.iter().map(|n| (n.clone(), json!(1))).collect())
        } else {
            per_service.clone()
        };
        Ok((calls, per_service))
    }
}

fn python(python: &std::ffi::OsStr, root: &Path, op: &Value) -> Value {
    let mut child = Command::new(python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/approval_requests_probe.py"))
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(op).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn rust(root: &Path, op: &Value) -> Value {
    let result = execute(root, op);
    match result {
        Ok(value) => json!({"ok": value}),
        Err(error) => json!({"error": error.to_string().replace(root.to_str().unwrap(), "<root>")}),
    }
}

fn execute(root: &Path, op: &Value) -> Result<Value> {
    let now = op["now"].as_i64();
    Ok(match op["op"].as_str().unwrap() {
        "create" => create_approval_request(
            root,
            &op["options"],
            &Hooks,
            if op["options"]["reuse"] == false {
                Some(&|_| false)
            } else {
                None
            },
        )?,
        "list" => json!(list_approval_requests(
            root,
            op["all"] == true,
            op["missed"] == true,
            now
        )?),
        "get" => json!(get_approval_request(root, &op["id"], now)?),
        "deny" => json!(deny_approval_request(root, &op["id"], &op["reason"], now)?),
        "approve" => json!(mark_approval_request_approved(
            root,
            &op["id"],
            &op["grant_id"],
            &op["reason"],
            now
        )?),
        "mark" => {
            let _lock = kv_store::fsx::lock_storage(&root.join(".secrets"))?;
            json!(mark_request_in_held_lock(
                root,
                &op["id"],
                op["status"].as_str().unwrap(),
                now,
                op.get("fields").unwrap_or(&json!({})),
                op["from_status"].as_str().unwrap_or("pending")
            )?)
        }
        "prune" => json!(prune_approval_requests(root, op["missed"] == true, now)?),
        "unheld" => json!(mark_request_in_held_lock(
            root,
            &json!("id"),
            "denied",
            now,
            &json!({}),
            "pending"
        )?),
        "normalize" => json!([
            normalize_actor(&op["actor"]),
            normalize_reason(&op["reason"])
        ]),
        "digest" => {
            let doc: Value = serde_json::from_slice(&fs::read(approval_store_path(root))?).unwrap();
            json!(
                doc["requests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(request_content_digest)
                    .collect::<std::result::Result<Vec<_>, _>>()?
            )
        }
        "verify" => {
            let doc: Value = serde_json::from_slice(&fs::read(approval_store_path(root))?).unwrap();
            json!(
                doc["requests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| verify_approval_request_integrity(root, r))
                    .collect::<Result<Vec<_>>>()?
            )
        }
        "status" => json!(
            op["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| json!([effective_status(r, now), is_missed_request(r, now)]))
                .collect::<Vec<_>>()
        ),
        "raw" => {
            let path = approval_store_path(root);
            if let Ok(meta) = fs::symlink_metadata(&path) {
                if meta.is_dir() {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    fs::remove_dir(&path)?;
                } else {
                    fs::remove_file(&path)?;
                }
            }
            match op["kind"].as_str().unwrap_or("json") {
                "absent" => {}
                "link" => std::os::unix::fs::symlink("absent-target", &path)?,
                "directory" => {
                    fs::create_dir(&path)?;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                }
                kind => {
                    if kind == "oversized" {
                        fs::File::create(&path)?.set_len(64 * 1024 * 1024 + 1)?;
                    } else if kind == "text" {
                        fs::write(&path, op["text"].as_str().unwrap())?;
                    } else {
                        let mut doc = op["doc"].clone();
                        fn sort(v: &mut Value) {
                            match v {
                                Value::Object(m) => {
                                    m.sort_keys();
                                    for v in m.values_mut() {
                                        sort(v);
                                    }
                                }
                                Value::Array(a) => {
                                    for v in a {
                                        sort(v);
                                    }
                                }
                                _ => {}
                            }
                        }
                        sort(&mut doc);
                        fs::write(&path, kv_store::pyjson::to_vec_indent2_ascii_python(&doc)?)?;
                    }
                    fs::set_permissions(
                        &path,
                        fs::Permissions::from_mode(op["mode"].as_u64().unwrap_or(0o600) as u32),
                    )?;
                }
            }
            Value::Null
        }
        _ => unreachable!(),
    })
}

fn assert_files(a: &Path, b: &Path, step: usize) {
    for name in [APPROVAL_REQUESTS_FILE, ".gitignore"] {
        let a = a.join(".secrets").join(name);
        let b = b.join(".secrets").join(name);
        let meta = fs::symlink_metadata(&a);
        if let Ok(meta) = meta {
            if meta.is_file() && meta.len() <= 64 * 1024 * 1024 {
                assert_eq!(
                    fs::read(&a).unwrap(),
                    fs::read(&b).unwrap(),
                    "{name} step {step}"
                );
            }
            if meta.is_file() {
                assert_eq!(
                    meta.permissions().mode() & 0o777,
                    fs::metadata(b).unwrap().permissions().mode() & 0o777
                );
            }
        } else {
            assert!(fs::symlink_metadata(b).is_err());
        }
    }
}

#[test]
fn approval_requests_match_python() {
    let Some(py) = kv_test_support::python_reference() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("rust");
    let b = dir.path().join("python");
    let mut key = kv_crypto::Zeroizing::new([0; 32]);
    getrandom::getrandom(&mut key[..]).unwrap();
    let encoded = kv_crypto::Zeroizing::new(format!("{}\n", URL_SAFE.encode(&key[..])));
    for root in [&a, &b] {
        fs::create_dir(root).unwrap();
        fs::create_dir(root.join(".secrets")).unwrap();
        fs::set_permissions(root.join(".secrets"), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join(".secrets/approval_signing_key");
        fs::write(&path, encoded.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let base = json!({"run_identity": {"command_fingerprint": "AB".repeat(32), "script_kind": " py ", "script_sha256": "01".repeat(32)},
        "argv": ["python", "héllö.py", ""], "cwd": dir.path(), "secret_names": [" Z ", "A", "Z"],
        "actor": {"source": " agent ", "user_id": "u".repeat(129), "unknown": "discard"}, "reason": "  résumé  ", "source": "MCP", "request_id": " req_one ", "ttl_seconds": 10, "now": 1700000000});
    let create = |overrides: Value| {
        let mut options = base.clone();
        for (k, v) in overrides.as_object().unwrap() {
            options[k] = v.clone();
        }
        json!({"op": "create", "options": options})
    };
    let mut ops = vec![
        json!({"op": "list", "now": 1700000000}),
        json!({"op": "get", "id": "missing", "now": 1700000000}),
        create(json!({})),
        create(json!({"request_id": "reused", "reason": "different", "source": "MCP"})),
        create(json!({"request_id": "req_two", "reuse": false})),
        create(
            json!({"request_id": "req_caps", "secret_names": null, "capability_names": ["api:b", "api:a"], "max_calls": 4, "recommended_ttl_seconds": 10, "network": false, "network_reason": "offline", "environment": "*", "risk_card": {"unicode": "😀", "number": 1.25}}),
        ),
        json!({"op": "verify"}),
        json!({"op": "digest"}),
        json!({"op": "unheld"}),
        json!({"op": "list", "now": 1700000001}),
        json!({"op": "approve", "id": "req_one", "grant_id": 123, "reason": " okay ", "now": 1700000002}),
        json!({"op": "deny", "id": "req_one", "reason": "late", "now": 1700000003}),
        json!({"op": "mark", "id": "req_one", "status": "withdrawn", "from_status": "approved", "fields": {"withdraw_reason": "owner"}, "now": 1700000003}),
        json!({"op": "deny", "id": "req_two", "reason": " no ", "now": 1700000003}),
        json!({"op": "mark", "id": "missing", "status": "denied", "now": 1700000003}),
        json!({"op": "get", "id": " req_one ", "now": 1700000004}),
        json!({"op": "list", "all": true, "now": 1700000010}),
        json!({"op": "list", "missed": true, "now": 1700000010}),
        json!({"op": "prune", "now": 1700000010}),
        json!({"op": "verify"}),
        json!({"op": "prune", "missed": true, "now": 1700000010}),
        json!({"op": "list", "all": true, "now": 1700000010}),
    ];
    for overrides in [
        json!({"ttl_seconds": 0}),
        json!({"ttl_seconds": null}),
        json!({"ttl_seconds": "1_0", "request_id": "underscores"}),
        json!({"ttl_seconds": "١_٠", "request_id": "arabic"}),
        json!({"ttl_seconds": "１０", "request_id": "fullwidth"}),
        json!({"ttl_seconds": "𝟙𝟘", "request_id": "mathematical"}),
        json!({"ttl_seconds": 86401}),
        json!({"ttl_seconds": "bad"}),
        json!({"ttl_seconds": 1.9}),
        json!({"run_identity": []}),
        json!({"run_identity": {}}),
        json!({"run_identity": {"command_fingerprint": 1}}),
        json!({"run_identity": {"command_fingerprint": "a".repeat(63)}}),
        json!({"secret_names": []}),
        json!({"capability_names": ["api:x"]}),
        json!({"secret_names": "bad"}),
        json!({"secret_names": [""]}),
        json!({"secret_names": ["é".repeat(129)]}),
        json!({"calls_per_service": {"a": 1}}),
        json!({"argv": []}),
        json!({"argv": [""]}),
        json!({"argv": [0]}),
        json!({"argv": vec!["x"; 129]}),
        json!({"argv": ["x", "x".repeat(4097)]}),
        json!({"cwd": " "}),
        json!({"request_id": " "}),
        json!({"network": 1}),
        json!({"network": true}),
        json!({"environment": "../bad"}),
        json!({"environment": "a".repeat(129)}),
        json!({"recommended_ttl_seconds": 1}),
        json!({"secret_names": [], "capability_names": ["api:x"], "max_calls": "0"}),
        json!({"secret_names": [], "capability_names": ["api:x"], "max_calls": 9007199254740992u64}),
        json!({"secret_names": [], "capability_names": ["api:x"], "recommended_ttl_seconds": true}),
        json!({"secret_names": [], "capability_names": ["api:x"], "recommended_ttl_seconds": 0}),
        json!({"secret_names": [], "capability_names": ["api:x"], "recommended_ttl_seconds": 253402300799i64}),
        json!({"secret_names": [], "capability_names": ["api:x"], "calls_per_service": {"bad": 0}}),
    ] {
        ops.push(create(overrides));
    }
    ops.push(json!({"op": "status", "now": 100, "records": [
        {}, {"expires_at_epoch": 101}, {"expires_at_epoch": "bad"}, {"status": "approved", "expires_at_epoch": 101},
        {"status": "pending", "approved_grant_id": "g"}, {"status": "pending", "deny_reason": ""},
        {"approved_at": "x", "withdrawn_at_epoch": 0}, {"status": 42}, {"expires_at_epoch": 100 - 86400}, {"expires_at_epoch": 100 - 86399}
    ]}));
    for actor in [
        Value::Null,
        json!([]),
        json!({"source": "\u{001c}é\u{001f}", "client_version": 7, "session_id": "😀".repeat(130)}),
    ] {
        ops.push(
            json!({"op": "normalize", "actor": actor, "reason": " \u{001c}résumé😀".repeat(80)}),
        );
    }
    for reason in [Value::Null, json!(123), json!("   ")] {
        ops.push(json!({"op": "normalize", "actor": {}, "reason": reason}));
    }
    for count in [1000, 1001] {
        let records = vec![
            json!({"request_id": "recovery", "status": "pending", "expires_at_epoch": 1700000100});
            count
        ];
        ops.push(json!({"op": "raw", "doc": {"version": 1, "requests": records}}));
        ops.push(create(json!({})));
        ops.push(json!({"op": "mark", "id": "recovery", "status": "expired", "now": 1700000001, "fields": {"audit": 1.25}}));
        ops.push(json!({"op": "prune", "now": 1700000002}));
    }
    ops.extend([
        json!({"op": "raw", "doc": {"version": true, "requests": [{"request_id": "expired", "expires_at_epoch": 100}, {"request_id": "old", "expires_at_epoch": -90000}]}}),
        json!({"op": "list", "missed": true, "now": 100}),
        json!({"op": "mark", "id": "expired", "status": "denied", "now": 100}),
        json!({"op": "mark", "id": "expired", "status": "custom", "from_status": "expired", "now": 100}),
        json!({"op": "list", "all": true, "now": 100}),
        json!({"op": "prune", "now": 100}),
    ]);
    for doc in [
        json!([]),
        json!({}),
        json!({"version": 2}),
        json!({"version": 1, "requests": {}}),
        json!({"version": 1, "requests": [null]}),
        json!({"version": 1, "requests": vec![json!({}); 1002]}),
    ] {
        ops.push(json!({"op": "raw", "doc": doc}));
        ops.push(json!({"op": "list", "now": 100}));
    }
    for kind in ["text", "oversized", "link", "directory"] {
        ops.push(json!({"op": "raw", "kind": kind, "text": "{broken"}));
        ops.push(json!({"op": "list", "now": 100}));
    }
    ops.extend([
        json!({"op": "raw", "doc": {"version": 1, "requests": []}, "mode": 0o644}),
        json!({"op": "list", "now": 100}),
        json!({"op": "raw", "kind": "absent"}),
        create(json!({})),
    ]);
    for (i, op) in ops.iter().enumerate() {
        let expected = python(&py, &b, op);
        assert_eq!(rust(&a, op), expected, "operation {i}: {}", op["op"]);
        assert_files(&a, &b, i);
    }
    // Cross-read and re-seal the other implementation's file.
    fs::copy(approval_store_path(&b), approval_store_path(&a)).unwrap();
    assert_eq!(rust(&a, &json!({"op": "verify"})), json!({"ok": [true]}));
    let mark = json!({"op": "deny", "id": "req_one", "reason": "cross-read", "now": 1700000001});
    assert_eq!(rust(&a, &mark), json!({"ok": true}));
    fs::copy(approval_store_path(&a), approval_store_path(&b)).unwrap();
    assert_eq!(
        python(&py, &b, &json!({"op": "verify"})),
        json!({"ok": [true]})
    );
    assert_eq!(
        rust(&a, &json!({"op": "list", "all": true, "now": 1700000001})),
        python(
            &py,
            &b,
            &json!({"op": "list", "all": true, "now": 1700000001})
        )
    );
    let fresh = create(json!({"request_id": "fresh", "reuse": false}));
    for root in [&a, &b] {
        fs::write(root.join(".secrets/approval_signing_key"), b"YmFk\n").unwrap();
    }
    assert_eq!(rust(&a, &fresh), python(&py, &b, &fresh));
    assert_eq!(
        rust(&a, &fresh),
        json!({"error": "approval signing key is invalid"})
    );
    for root in [&a, &b] {
        let path = root.join(".secrets/approval_signing_key");
        fs::write(&path, encoded.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert_eq!(rust(&a, &fresh), python(&py, &b, &fresh));
    for root in [&a, &b] {
        fs::remove_file(root.join(".secrets/approval_signing_key")).unwrap();
    }
    let mut actual = rust(&a, &fresh);
    let mut expected = python(&py, &b, &fresh);
    actual["ok"]
        .as_object_mut()
        .unwrap()
        .remove("request_integrity");
    expected["ok"]
        .as_object_mut()
        .unwrap()
        .remove("request_integrity");
    assert_eq!(actual, expected);
    assert_eq!(
        rust(&a, &json!({"op": "verify"})),
        python(&py, &b, &json!({"op": "verify"}))
    );
    assert_eq!(
        fs::read(a.join(".secrets/.gitignore")).unwrap(),
        fs::read(b.join(".secrets/.gitignore")).unwrap()
    );
    for root in [&a, &b] {
        assert_eq!(
            fs::metadata(root.join(".secrets/approval_signing_key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    // Refuse instead of repairing the directory's privacy.
    fs::set_permissions(a.join(".secrets"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        rust(&a, &fresh),
        json!({"error": "the .secrets directory is not private"})
    );
    fs::set_permissions(a.join(".secrets"), fs::Permissions::from_mode(0o700)).unwrap();
}
