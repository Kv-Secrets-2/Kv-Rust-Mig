#![cfg(unix)]
mod common;
use common::{TestDir, copy_fixture_secrets};
use kv_store::{config, policy_requests as p};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn probe(python: &std::ffi::OsStr, root: &Path, action: &str) -> Value {
    let output = Command::new(python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/policy_requests.py"))
        .arg(root)
        .arg(action)
        .env("HOME", root.parent().unwrap().join("home"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&output.stdout).unwrap()
    }
}
fn remove_ignore(root: &Path) {
    let path = root.join(".secrets/.gitignore");
    let text = fs::read_to_string(&path).unwrap();
    let text = text
        .lines()
        .filter(|s| s.trim_start_matches('/') != "policy_requests.json")
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(path, text).unwrap();
}
#[test]
fn policy_request_storage_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let temp = TestDir::new("policy-store");
    let root = temp.project_root("vault");
    copy_fixture_secrets(&root);
    fs::create_dir(root.parent().unwrap().join("home")).unwrap();
    probe(&python, &root, "init");
    assert_eq!(p::list(&root, true, 1001).unwrap(), Vec::<Value>::new());
    assert_eq!(probe(&python, &root, "read"), json!({"requests":[]}));
    probe(&python, &root, "seed");
    let requests = p::list(&root, true, 1001).unwrap();
    let fingerprint = p::fingerprint(&p::get(&root, "pol_one", 1001).unwrap().unwrap()).unwrap();
    let missing = p::get(&root, "missing", 1001).unwrap();
    remove_ignore(&root);
    let blocked = vec![
        p::block(&root, "pol_one", Some(" a reason "), 1001).unwrap(),
        p::block(&root, "pol_one", None, 1001).unwrap(),
    ];
    let remaining = p::prune(&root, 1001).unwrap();
    let actual = json!({"list":requests,"fingerprint":fingerprint,"missing":missing,"blocked":blocked,"remaining":remaining});
    let bytes = fs::read(p::store_path(&root)).unwrap();
    let ignore = fs::read(root.join(".secrets/.gitignore")).unwrap();
    probe(&python, &root, "seed");
    remove_ignore(&root);
    assert_eq!(actual, probe(&python, &root, "flow"));
    assert_eq!(bytes, fs::read(p::store_path(&root)).unwrap());
    assert_eq!(ignore, fs::read(root.join(".secrets/.gitignore")).unwrap());
    for mode in ["stale", "tamper"] {
        probe(&python, &root, "seed");
        let request = p::get(&root, "pol_one", p::now()).unwrap().unwrap();
        let reviewed = p::fingerprint(&request).unwrap();
        let snapshot = config::load_config(&root).unwrap();
        if mode == "stale" {
            let mut changed = config::load_config(&root).unwrap();
            changed.value["test_change"] = json!(true);
            config::save_config(&root, &mut changed).unwrap();
        } else {
            let path = p::store_path(&root);
            let mut doc: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            doc["requests"][0]["reason"] = json!("changed after review");
            fs::write(path, serde_json::to_vec(&doc).unwrap()).unwrap();
        }
        let before = fs::read(p::store_path(&root)).unwrap();
        let error = p::allow(&root, "pol_one", &root, &snapshot, &reviewed, None, |_| {
            String::new()
        })
        .unwrap_err()
        .to_string();
        assert_eq!(before, fs::read(p::store_path(&root)).unwrap());
        // Both sides must begin with an unchanged config snapshot.
        if mode == "stale" {
            config::config_transaction(&root, |v| {
                v.as_object_mut().unwrap().shift_remove("test_change");
                Ok(())
            })
            .unwrap();
        }
        probe(&python, &root, "seed");
        assert_eq!(json!({"error":error}), probe(&python, &root, mode));
    }
    for version in [json!(true), json!(1.0)] {
        fs::write(
            p::store_path(&root),
            serde_json::to_vec(&json!({"version":version,"requests":[]})).unwrap(),
        )
        .unwrap();
        assert_eq!(p::list(&root, true, 1001).unwrap(), Vec::<Value>::new());
        assert_eq!(probe(&python, &root, "read"), json!({"requests":[]}));
    }
    for doc in [
        json!([]),
        json!({"version":2,"requests":[]}),
        json!({"version":1,"requests":{}}),
        json!({"version":1,"requests":[42]}),
    ] {
        let path = p::store_path(&root);
        fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let before = fs::read(&path).unwrap();
        let error = p::list(&root, true, 1001).unwrap_err().to_string();
        assert_eq!(json!({"error":error}), probe(&python, &root, "read"));
        assert_eq!(before, fs::read(path).unwrap());
    }
    probe(&python, &root, "seed");
    let path = p::store_path(&root);
    let expected = p::list(&root, true, 1001).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        p::list(&root, true, 1001).unwrap_err().to_string(),
        format!("policy request store is not private: {}", path.display())
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(probe(&python, &root, "read"), json!({"requests":expected}));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
