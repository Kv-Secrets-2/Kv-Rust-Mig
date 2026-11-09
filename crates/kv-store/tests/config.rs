mod common;

use std::fs;
use std::process::Command;

use kv_store::{DrawerStore, config, pyjson};
use serde_json::{Value, json};

use common::{TestDir, copy_fixture_secrets, fixture_master_key, fixture_root, hex, key_copy};

#[test]
fn fixture_config_round_trips_byte_for_byte_and_config_snapshots_detect_changes() {
    let temp = TestDir::new("config-cas");
    let root = temp.project_root("vault");
    let secrets = copy_fixture_secrets(&root);
    let original = fs::read(secrets.join("config.json")).expect("fixture config");
    let snapshot = config::load_config(&root).expect("load fixture config");
    assert_eq!(
        pyjson::to_vec_indent2_ascii(&snapshot.value).expect("serialize config"),
        original
    );

    let mut stale = config::load_config(&root).expect("second config snapshot");
    let path = secrets.join("config.json");
    let mut external = original.clone();
    external.push(b' ');
    fs::write(&path, &external).expect("external config edit");
    let error = config::save_config(&root, &mut stale).expect_err("stale config conflict");
    assert_eq!(
        error.to_string(),
        "configuration changed; reload and retry the operation (approval may need repeating)"
    );
    assert_eq!(fs::read(path).expect("read external edit"), external);

    let mut fresh = config::load_config(&root).expect("load edited config");
    fresh.value["unicode"] = json!("münchen 🧪");
    config::save_config(&root, &mut fresh).expect("save fresh snapshot");
    assert!(
        fs::read(secrets.join("config.json"))
            .expect("read saved config")
            .windows("m\\u00fcnchen \\ud83e\\uddea".len())
            .any(|window| window == b"m\\u00fcnchen \\ud83e\\uddea")
    );

    let before_transaction = fs::read(secrets.join("config.json")).unwrap();
    config::config_transaction(&root, |_| Ok(())).expect("unchanged config transaction");
    assert_eq!(
        fs::read(secrets.join("config.json")).unwrap(),
        before_transaction
    );
}

#[test]
fn config_lock_order_reentry_pending_refusal_and_vault_storage_order() {
    let master = fixture_master_key();
    let temp = TestDir::new("config-lock");
    let root = temp.project_root("vault");
    let secrets = copy_fixture_secrets(&root);
    let store = DrawerStore::open(&secrets, master);
    let vault = config::Vault::new(&root, store, config::NoApprovals);

    vault
        .set_secret("staging", "KEY", "value")
        .expect("storage lock may acquire config lock");
    let first = config::config_lock(&root).expect("config lock");
    let second = config::config_lock(&root).expect("same-vault config reentry");
    assert!(matches!(
        vault.set_secret("nested", "KEY", "value"),
        Err(kv_store::StoreError::LockOrder(_))
    ));
    drop(second);
    drop(first);

    fs::write(secrets.join("key-config.pending"), b"pending").expect("pending marker");
    assert!(matches!(
        config::config_lock(&root),
        Err(kv_store::StoreError::KeyConfigPending)
    ));
}

#[test]
fn vault_environment_lifecycle_renames_default_reencrypts_restores_and_purges() {
    let master = fixture_master_key();
    let temp = TestDir::new("vault-lifecycle");
    let root = temp.project_root("vault");
    let secrets = copy_fixture_secrets(&root);
    let store = DrawerStore::open(&secrets, master);
    let vault = config::Vault::new(&root, store, config::NoApprovals);

    vault
        .rename_env("prod", "production")
        .expect("rename non-default");
    assert_eq!(
        vault
            .get_secret("production", "DB_URL")
            .expect("read renamed value")
            .expect("DB_URL present")
            .as_str(),
        "postgres://u:p@h/db"
    );
    vault
        .rename_env("dev", "development")
        .expect("rename default environment");
    assert_eq!(
        vault.get_default_env().expect("renamed default"),
        "development"
    );
    vault
        .set_default_env("production")
        .expect("change default before deletion");
    vault
        .delete_env("development")
        .expect("soft-delete environment");
    assert_eq!(
        vault.list_environments().expect("live environments"),
        vec!["production"]
    );
    vault
        .restore_env("development")
        .expect("restore deleted environment");
    assert!(
        vault
            .get_secret("development", "API_KEY")
            .expect("read restored value")
            .is_some()
    );

    vault
        .delete_env("development")
        .expect("delete before purge");
    assert!(vault.purge_env("development").expect("purge deleted env"));
    assert!(
        vault
            .list_deleted_environments()
            .expect("deleted list")
            .is_empty()
    );
    assert!(matches!(
        vault.get_secret("development", "API_KEY"),
        Err(kv_store::StoreError::EnvMissing(_))
    ));
}

#[test]
fn python_config_writer_and_gitignore_merge_match_rust_byte_for_byte() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Python config parity: set KV_PY_REF to the reference interpreter");
        return;
    };
    let temp = TestDir::new("config-parity");
    let python_root = temp.project_root("python");
    let rust_root = temp.project_root("rust");
    fs::create_dir_all(&python_root).expect("create Python root");
    fs::create_dir_all(&rust_root).expect("create Rust root");
    let script = fixture_root().join("../gen/check_store_parity.py");

    let value: Value = serde_json::from_str(
        r#"{"version":1,"environments":["dev","münchen","🧪"],"default_env":"dev","token":"D:escape\u0001","nested":{"empty":{},"array":[]}}"#,
    )
    .expect("config value");
    let writer_spec = temp.path().join("writer.json");
    fs::write(
        &writer_spec,
        serde_json::to_vec(&json!({"config_writer": value})).expect("writer spec"),
    )
    .expect("write writer spec");
    let output = Command::new(&python)
        .arg(&script)
        .arg(&python_root)
        .arg(&rust_root)
        .arg("00")
        .arg(&writer_spec)
        .output()
        .expect("run Python config writer");
    assert!(
        output.status.success(),
        "Python config writer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        pyjson::to_vec_indent2_ascii(&value).expect("Rust config writer"),
        fs::read(python_root.join(".secrets/config.json")).expect("Python config")
    );

    let cases = json!([
        {
            "name":"empty",
            "existing":"",
            "rules":["/config.json"],
            "writer_tail":true,
            "header":"# Local-only kv runtime records"
        },
        {
            "name":"user-authored",
            "existing":"keep-me\n",
            "rules":["/config.json"],
            "writer_tail":false,
            "header":"# Local-only kv runtime records"
        },
        {
            "name":"negation",
            "existing":"/config.json\n!config.json\n",
            "rules":["/config.json"],
            "writer_tail":false,
            "header":"# Local-only kv runtime records"
        },
        {
            "name":"crlf",
            "existing":"owner rule\r\n",
            "rules":["/config.json"],
            "writer_tail":false,
            "header":"# Local-only kv runtime records"
        },
        {
            "name":"trailing-spaces",
            "existing":"/config.json   \n",
            "rules":["/config.json"],
            "writer_tail":false,
            "header":"# Local-only kv runtime records"
        }
    ]);
    let ignore_spec = temp.path().join("ignore.json");
    fs::write(
        &ignore_spec,
        serde_json::to_vec(&json!({"config_ignores": cases})).expect("ignore spec"),
    )
    .expect("write ignore spec");
    let output = Command::new(&python)
        .arg(&script)
        .arg(&python_root)
        .arg(&rust_root)
        .arg("00")
        .arg(&ignore_spec)
        .output()
        .expect("run Python ignore merger");
    assert!(
        output.status.success(),
        "Python ignore merger failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for case in cases.as_array().expect("case array") {
        let name = case["name"].as_str().expect("case name");
        let rust_secrets = rust_root.join(name).join(".secrets");
        fs::create_dir_all(&rust_secrets).expect("create Rust secrets directory");
        fs::write(
            rust_secrets.join(".gitignore"),
            case["existing"].as_str().expect("existing ignore"),
        )
        .expect("write existing ignore");
        let rules = case["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .map(|rule| rule.as_str().expect("rule"))
            .collect::<Vec<_>>();
        config::update_vault_ignores(
            &rust_secrets,
            &rules,
            case["writer_tail"].as_bool().expect("writer tail"),
            case["header"].as_str(),
        )
        .expect("merge Rust ignore rules");
        assert_eq!(
            fs::read(rust_secrets.join(".gitignore")).expect("Rust ignore output"),
            fs::read(python_root.join(name).join(".secrets").join(".gitignore"))
                .expect("Python ignore output"),
            "ignore output differs for {name}"
        );
    }
}

#[test]
fn python_and_rust_config_aware_environment_lifecycle_match() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP Python Stage 3a parity: set KV_PY_REF to the reference interpreter");
        return;
    };
    let master = fixture_master_key();
    let temp = TestDir::new("stage3a-lifecycle-parity");
    let python_root = temp.project_root("python");
    let rust_root = temp.project_root("rust");
    let python_secrets = copy_fixture_secrets(&python_root);
    let rust_secrets = copy_fixture_secrets(&rust_root);
    let python_store = DrawerStore::open(&python_secrets, key_copy(&master));
    let rust_store = DrawerStore::open(&rust_secrets, key_copy(&master));
    let vault = config::Vault::new(&rust_root, rust_store, config::NoApprovals);
    let operations = vec![
        json!({"op":"add","name":"staging"}),
        json!({"op":"default","name":"staging"}),
        json!({"op":"rename","old":"prod","new":"production"}),
        json!({"op":"rename","old":"staging","new":"stage"}),
        json!({"op":"default","name":"production"}),
        json!({"op":"delete","name":"dev"}),
        json!({"op":"restore","name":"dev"}),
        json!({"op":"delete","name":"stage"}),
        json!({"op":"purge","name":"stage"}),
    ];

    let mut rust_returns = Vec::new();
    for operation in &operations {
        let result = match operation["op"].as_str().expect("operation type") {
            "add" => json!(
                vault
                    .add_environment(operation["name"].as_str().unwrap())
                    .expect("add environment")
            ),
            "default" => {
                vault
                    .set_default_env(operation["name"].as_str().unwrap())
                    .expect("set default");
                Value::Null
            }
            "rename" => {
                vault
                    .rename_env(
                        operation["old"].as_str().unwrap(),
                        operation["new"].as_str().unwrap(),
                    )
                    .expect("rename environment");
                Value::Null
            }
            "delete" => {
                let deleted = vault
                    .delete_env(operation["name"].as_str().unwrap())
                    .expect("delete environment");
                json!({
                    "name":deleted.name,
                    "deleted_at":"TIME",
                    "purge_after":"TIME"
                })
            }
            "restore" => {
                vault
                    .restore_env(operation["name"].as_str().unwrap())
                    .expect("restore environment");
                Value::Null
            }
            "purge" => json!(
                vault
                    .purge_env(operation["name"].as_str().unwrap())
                    .expect("purge environment")
            ),
            other => panic!("unknown operation {other}"),
        };
        rust_returns.push(result);
    }

    let operation_path = temp.path().join("stage3a.json");
    fs::write(
        &operation_path,
        serde_json::to_vec(&json!({"stage3a_lifecycle":operations})).unwrap(),
    )
    .expect("write Stage 3a operations");
    let output = Command::new(python)
        .arg(fixture_root().join("../gen/check_store_parity.py"))
        .arg(&python_root)
        .arg(&rust_root)
        .arg(hex(master.as_bytes()))
        .arg(&operation_path)
        .output()
        .expect("run Python Stage 3a parity script");
    assert!(
        output.status.success(),
        "Python Stage 3a parity failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let python_result: Value = serde_json::from_str(stdout.trim()).expect("Python result JSON");
    assert_eq!(python_result["returns"], json!(rust_returns));
    assert_eq!(
        python_result["environments"],
        json!(vault.list_environments().unwrap())
    );
    assert_eq!(
        python_result["default_env"],
        json!(vault.get_default_env().unwrap())
    );

    let normalize_config = |mut value: Value| {
        if let Some(deleted) = value
            .get_mut("deleted_environments")
            .and_then(Value::as_array_mut)
        {
            for entry in deleted {
                for field in ["deleted_at", "purge_after"] {
                    if entry.get(field).is_some() {
                        entry[field] = Value::String("TIME".into());
                    }
                }
            }
        }
        value
    };
    let python_config = config::load_config(&python_root).unwrap().value;
    let rust_config = config::load_config(&rust_root).unwrap().value;
    assert_eq!(
        normalize_config(python_config),
        normalize_config(rust_config)
    );
    for (env, key) in [("production", "DB_URL"), ("dev", "API_KEY")] {
        let python_value = python_store
            .get_secret(env, key)
            .expect("Python drawer read")
            .map(|value| value.to_string());
        let rust_value = vault
            .get_secret(env, key)
            .expect("Rust drawer read")
            .map(|value| value.to_string());
        assert_eq!(python_value, rust_value, "cross-read {env}/{key}");
    }
    println!("PASS Python Stage 3a lifecycle parity: {}", stdout.trim());
}
