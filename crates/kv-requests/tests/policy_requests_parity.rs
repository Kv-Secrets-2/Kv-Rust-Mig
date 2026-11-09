#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_requests::{Result, policy_requests::*};
use kv_store::{StoreError, config};
use serde_json::{Value, json};

fn python(python: &std::ffi::OsStr, root: &Path, op: &Value) -> Value {
    let mut child = Command::new(python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/policy_requests_probe.py"))
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
    match execute(root, op) {
        Ok(value) => json!({"ok": value}),
        Err(error) => json!({"error": error.to_string().replace(root.to_str().unwrap(), "<root>")}),
    }
}

fn execute(root: &Path, op: &Value) -> Result<Value> {
    let now = op["now"].as_i64();
    Ok(match op["op"].as_str().unwrap() {
        "create" => create_policy_request(root, &op["options"])?,
        "pattern" => json!(policy_pattern_for_argv(&op["argv"])?),
        "fingerprint" => json!(request_fingerprint(&op["request"])?),
        "list" => json!(list_policy_requests(root, op["all"] == true, now)?),
        "get" => json!(get_policy_request(root, &op["id"], now)?),
        "mark_allowed" => json!(mark_policy_request_allowed(
            root,
            &op["id"],
            &op["reason"],
            now
        )?),
        "block" => json!(block_policy_request(root, &op["id"], &op["reason"], now)?),
        "mark" => {
            let _lock = kv_store::fsx::lock_storage(&root.join(".secrets"))?;
            json!(mark_request_in_held_lock(
                root,
                &op["id"],
                op["status"].as_str().unwrap(),
                now,
                op.get("fields").unwrap_or(&json!({}))
            )?)
        }
        "prune" => json!(prune_policy_requests(root, now)?),
        "allow" => {
            let target = root.join(op["target"].as_str().unwrap_or("."));
            let snapshot = config::load_config(&target)?;
            if op["stale"] == true {
                fs::OpenOptions::new()
                    .append(true)
                    .open(target.join(".secrets/config.json"))?
                    .write_all(b" ")?;
            }
            let request = get_policy_request(root, &op["id"], now)?;
            let fingerprint = op["expected"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    request
                        .as_ref()
                        .map(|r| request_fingerprint(r).unwrap())
                        .unwrap_or_default()
                });
            json!(allow_policy_request(
                root,
                &op["id"],
                &target,
                AllowPolicyRequest {
                    snapshot: &snapshot,
                    expected_fingerprint: &fingerprint,
                    reason: &op["reason"],
                    now
                },
                |target, pattern| {
                    if op["fail_writer"] == true {
                        return Err(StoreError::ConfigConflict("pattern writer refused".into()));
                    }
                    config::config_transaction(target, |value| {
                        let object = value.as_object_mut().unwrap();
                        let security = object
                            .entry("security")
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .unwrap();
                        let allowed = security
                            .entry("allowed_commands")
                            .or_insert_with(|| json!([]))
                            .as_array_mut()
                            .unwrap();
                        if !allowed.iter().any(|item| item == pattern) {
                            allowed.push(pattern.into());
                            security.insert("kv_run_policy".into(), "allowlist".into());
                        }
                        Ok(())
                    })
                }
            )?)
        }
        "raw" => {
            let path = policy_request_store_path(root);
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
    for name in [POLICY_REQUESTS_FILE, ".gitignore", "config.json"] {
        let a = a.join(".secrets").join(name);
        let b = b.join(".secrets").join(name);
        if let Ok(meta) = fs::symlink_metadata(&a) {
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
fn policy_requests_match_python() {
    let Some(py) = kv_test_support::python_reference() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("rust");
    let b = dir.path().join("python");
    for root in [&a, &b] {
        fs::create_dir(root).unwrap();
        for parent in [root.to_path_buf(), root.join("other")] {
            if parent != *root {
                fs::create_dir(&parent).unwrap();
            }
            let sdir = parent.join(".secrets");
            fs::create_dir(&sdir).unwrap();
            fs::set_permissions(&sdir, fs::Permissions::from_mode(0o700)).unwrap();
            let path = sdir.join("config.json");
            fs::write(&path, b"{}\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::os::unix::fs::symlink(".", root.join("alias")).unwrap();
    }
    let base = json!({"argv": ["python", "-m", "péckage", "run"], "cwd": dir.path(), "actor": {"source": " agent ", "user_id": "😀".repeat(130), "extra": false},
        "request_id": " pol_one ", "ttl_seconds": 10, "now": 1700000000, "reason": " résumé ", "source": "MCP", "command_mode": " guarded ", "command_reason": " not allowed "});
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
        create(json!({"request_id": "reuse", "source": "different", "reason": "ignored"})),
        create(json!({"request_id": "pol_two", "pattern": " python \t task.py \n"})),
        json!({"op": "allow", "id": "pol_one", "now": 1700000001, "expected": "changed"}),
        json!({"op": "allow", "id": "pol_one", "now": 1700000001, "stale": true}),
        json!({"op": "get", "id": "pol_one", "now": 1700000001}),
        json!({"op": "allow", "id": "pol_one", "now": 1700000001, "target": "other"}),
        json!({"op": "allow", "id": "missing", "now": 1700000001}),
        json!({"op": "allow", "id": "pol_one", "now": 1700000001, "reason": " reviewed ", "target": "alias"}),
        json!({"op": "allow", "id": "pol_one", "now": 1700000002}),
        json!({"op": "allow", "id": "pol_one", "now": 1700000002, "expected": "changed"}),
        json!({"op": "block", "id": "pol_one", "now": 1700000002}),
        json!({"op": "mark_allowed", "id": "pol_two", "now": 1700000002, "reason": " okay "}),
        json!({"op": "get", "id": "pol_two", "now": 1700000002}),
        create(json!({"request_id": "pol_three", "pattern": "runner task"})),
        json!({"op": "block", "id": "pol_three", "now": 1700000002, "reason": " no "}),
        json!({"op": "mark", "id": "missing", "status": "blocked", "now": 1700000002}),
        json!({"op": "list", "all": true, "now": 1700000002}),
        create(json!({"request_id": "pol_fail", "pattern": "runner fail"})),
        json!({"op": "allow", "id": "pol_fail", "now": 1700000002, "fail_writer": true}),
        json!({"op": "allow", "id": "pol_fail", "now": 1700000002}),
        create(json!({"request_id": "pol_expire", "pattern": "runner expired"})),
        json!({"op": "mark_allowed", "id": "pol_expire", "now": 1700000010}),
        json!({"op": "list", "now": 1700000010}),
        json!({"op": "list", "all": true, "now": 1700000010}),
        json!({"op": "prune", "now": 1700000010}),
        json!({"op": "list", "all": true, "now": 1700000010}),
    ];
    for (i, pattern) in ["*", "python", "python -m", "sh", "runner *.py"]
        .iter()
        .enumerate()
    {
        let id = format!("broad{i}");
        ops.push(create(json!({"request_id": id, "pattern": pattern})));
        ops.push(json!({"op": "allow", "id": id, "now": 1700000001}));
    }
    for overrides in [
        json!({"ttl_seconds": 0}),
        json!({"ttl_seconds": 86401}),
        json!({"ttl_seconds": "bad"}),
        json!({"ttl_seconds": null}),
        json!({"ttl_seconds": "١_٠", "request_id": "unicode_digits", "pattern": "runner unicode"}),
        json!({"argv": []}),
        json!({"argv": "x"}),
        json!({"argv": [0]}),
        json!({"argv": [""]}),
        json!({"argv": vec!["x"; 129]}),
        json!({"argv": ["x", "é".repeat(2049)]}),
        json!({"pattern": " "}),
        json!({"pattern": true}),
        json!({"pattern": "é".repeat(2049)}),
        json!({"cwd": ""}),
        json!({"cwd": false}),
        json!({"request_id": " "}),
        json!({"request_id": false}),
        json!({"request_id": "pol_one", "pattern": "other script"}),
        json!({"request_id": "odd", "actor": [], "reason": 2, "command_mode": "m".repeat(41), "pattern": " a\u{001c}b "}),
    ] {
        ops.push(create(overrides));
    }
    for value in [
        json!([]),
        json!([""]),
        json!(["python", "-m", "pkg", "sub"]),
        json!(["runner", "é".repeat(2049)]),
        json!("abc"),
        json!({"z": 0, "a": 1}),
        Value::Null,
        json!(true),
        json!(1),
        json!(1.25),
    ] {
        ops.push(json!({"op": "pattern", "argv": value}));
    }
    for request in [
        json!({}),
        json!({"actor": {"é": "😀"}, "reason": "line\n", "argv": ["é"], "created_at_epoch": 1.0e-7, "status": "pending", "effective_status": "ignored"}),
        json!({"status": "blocked", "allowed_pattern": "foo", "expires_at_epoch": true}),
        json!([]),
        Value::Null,
    ] {
        ops.push(json!({"op": "fingerprint", "request": request}));
    }
    for count in [1000, 1001] {
        let records = vec![
            json!({"request_id": "recovery", "status": "pending", "expires_at_epoch": 1700000100});
            count
        ];
        ops.push(json!({"op": "raw", "doc": {"version": 1, "requests": records}}));
        ops.push(create(json!({})));
        ops.push(json!({"op": "mark", "id": "recovery", "status": "custom", "now": 1700000001, "fields": {"audit": 1.25, "none": null}}));
        ops.push(json!({"op": "prune", "now": 1700000002}));
    }
    for doc in [
        json!([]),
        json!({}),
        json!({"version": 2}),
        json!({"version": 1, "requests": {}}),
        json!({"version": 1, "requests": [null]}),
        json!({"version": 1, "requests": vec![json!({}); 1002]}),
        json!({"version": true, "requests": [{"status": 42}, {"status": "", "expires_at_epoch": "2_00"}]}),
    ] {
        ops.push(json!({"op": "raw", "doc": doc}));
        ops.push(json!({"op": "list", "now": 100, "all": true}));
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
        assert_eq!(
            rust(&a, op),
            python(&py, &b, op),
            "operation {i}: {}",
            op["op"]
        );
        assert_files(&a, &b, i);
    }
    fs::copy(policy_request_store_path(&b), policy_request_store_path(&a)).unwrap();
    let query = json!({"op": "get", "id": "pol_one", "now": 1700000001});
    assert_eq!(rust(&a, &query), python(&py, &b, &query));
    assert_eq!(
        rust(
            &a,
            &json!({"op": "block", "id": "pol_one", "now": 1700000001})
        ),
        json!({"ok": true})
    );
    fs::copy(policy_request_store_path(&a), policy_request_store_path(&b)).unwrap();
    assert_eq!(rust(&a, &query), python(&py, &b, &query));
}
