mod common;

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

use kv_crypto::{Key32, decrypt, derive_labeled_key};
use kv_store::{CopyOptions, DrawerStore, StoreError, VersionInfo, VersionState, backup};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use common::{
    TestDir, copy_fixture_secrets, fixture_expected, fixture_master_key, fixture_root, hex,
    key_copy,
};

#[test]
fn python_and_rust_drawer_operations_have_matching_storage_and_cross_reads() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Python drawer parity: set KV_PY_REF to the reference interpreter");
        return;
    };
    let master = fixture_master_key();
    let temp = TestDir::new("parity");
    let python_root = temp.project_root("python");
    let rust_root = temp.project_root("rust");
    let python_secrets = copy_fixture_secrets(&python_root);
    let rust_secrets = copy_fixture_secrets(&rust_root);
    let rust_store = DrawerStore::open(&rust_secrets, key_copy(&master));

    let operations = vec![
        json!({"op":"set","env":"dev","key":"API_KEY","value":"overwritten\n✓","keep":1}),
        json!({"op":"remove","env":"dev","key":"MULTILINE","keep":0}),
        json!({"op":"set","env":"dev","key":"MULTILINE","value":"re-added\nvärde ✓","keep":10}),
        json!({"op":"set","env":"dev","key":"odd/key\\name?","value":"","keep":0}),
        json!({"op":"set","env":"dev","key":"UNICODE","value":"line one\nline two 🙂","keep":10}),
        json!({
            "op":"save_env",
            "env":"dev",
            "keep":1,
            "secrets":{
                "API_KEY":"full replacement\n",
                "NEW_VALUE":"",
                "UNICODE":"ß / emoji 🙂"
            }
        }),
        json!({"op":"remove","env":"dev","key":"API_KEY","keep":0}),
        json!({"op":"set","env":"dev","key":"API_KEY","value":"restored","keep":1}),
    ];

    for operation in &operations {
        let env = operation["env"].as_str().expect("operation env");
        let keep = operation["keep"].as_u64().expect("operation keep") as usize;
        match operation["op"].as_str().expect("operation kind") {
            "set" => {
                let generation = rust_store
                    .set_secret(
                        env,
                        operation["key"].as_str().expect("operation key"),
                        operation["value"].as_str().expect("operation value"),
                        keep,
                    )
                    .expect("Rust set");
                assert!(generation > 0);
            }
            "remove" => {
                rust_store
                    .remove_secret(env, operation["key"].as_str().expect("operation key"), keep)
                    .expect("Rust remove");
            }
            "save_env" => {
                let secrets: BTreeMap<String, String> =
                    serde_json::from_value(operation["secrets"].clone())
                        .expect("operation secrets");
                rust_store
                    .save_env(env, &secrets, keep)
                    .expect("Rust save_env");
            }
            other => panic!("unknown operation {other}"),
        }
    }

    let operation_path = temp.path().join("operations.json");
    fs::write(
        &operation_path,
        serde_json::to_vec(&operations).expect("serialize operations"),
    )
    .expect("write operations");
    let script = fixture_root().join("../gen/check_store_parity.py");
    let output = Command::new(python)
        .arg(script)
        .arg(&python_root)
        .arg(&rust_root)
        .arg(hex(master.as_bytes()))
        .arg(&operation_path)
        .output()
        .expect("run Python parity script");
    assert!(
        output.status.success(),
        "Python parity failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS python parity"), "{stdout}");
    println!("{}", stdout.trim());

    let python_store = DrawerStore::open(&python_secrets, key_copy(&master));
    for env in ["dev", "prod"] {
        assert_eq!(
            live_values(&python_store, env),
            live_values(&rust_store, env),
            "Rust cross-read of Python values for {env}"
        );
        let python_inventory = normalized_inventory(&python_secrets, env, &master);
        let rust_inventory = normalized_inventory(&rust_secrets, env, &master);
        assert_eq!(
            python_inventory, rust_inventory,
            "normalized index for {env}"
        );
    }

    let _keep_key_type_used = Key32::new(*master.as_bytes());
}

#[test]
fn python_and_rust_history_operations_have_matching_results_and_storage() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Python drawer history parity: set KV_PY_REF to the reference interpreter");
        return;
    };
    let master = fixture_master_key();
    let temp = TestDir::new("history-parity");
    let python_root = temp.project_root("python");
    let rust_root = temp.project_root("rust");
    let python_secrets = copy_fixture_secrets(&python_root);
    let rust_secrets = copy_fixture_secrets(&rust_root);
    let rust_store = DrawerStore::open(&rust_secrets, key_copy(&master));

    let operations = vec![
        json!({"op":"set","env":"dev","key":"history","value":"v1","keep":10}),
        json!({"op":"set","env":"dev","key":"history","value":"v2","keep":10}),
        json!({"op":"set","env":"dev","key":"history","value":"v3","keep":10}),
        json!({"op":"list_versions","env":"dev","key":"history"}),
        json!({"op":"get_version","env":"dev","key":"history","version":1}),
        json!({"op":"restore_version","env":"dev","key":"history","version":1,"keep":10}),
        json!({"op":"list_versions","env":"dev","key":"history"}),
        json!({"op":"set","env":"dev","key":"undo","value":"undoable","keep":10}),
        json!({"op":"remove","env":"dev","key":"undo","keep":10}),
        json!({"op":"undo_remove","env":"dev","key":"undo"}),
        json!({"op":"remove","env":"dev","key":"undo","keep":1}),
        json!({"op":"undo_remove","env":"dev","key":"undo"}),
        json!({"op":"set","env":"dev","key":"prune_live","value":"p1","keep":10}),
        json!({"op":"set","env":"dev","key":"prune_live","value":"p2","keep":10}),
        json!({"op":"set","env":"dev","key":"prune_live","value":"p3","keep":10}),
        json!({"op":"set","env":"dev","key":"prune_live","value":"p4","keep":10}),
        json!({"op":"set","env":"dev","key":"prune_live","value":"p5","keep":10}),
        json!({"op":"set","env":"dev","key":"prune_removed","value":"removed","keep":10}),
        json!({"op":"remove","env":"dev","key":"prune_removed","keep":10}),
        json!({"op":"prune_envs","envs":["dev"],"keep":2}),
        json!({"op":"list_versions","env":"dev","key":"prune_live"}),
        json!({"op":"prune_envs","envs":["dev"],"keep":0}),
        json!({"op":"set","env":"dev","key":"forget_key","value":"f1","keep":10}),
        json!({"op":"set","env":"dev","key":"forget_key","value":"f2","keep":10}),
        json!({"op":"set","env":"dev","key":"forget_key","value":"f3","keep":10}),
        json!({"op":"set","env":"dev","key":"forget_sibling","value":"s1","keep":10}),
        json!({"op":"set","env":"dev","key":"forget_sibling","value":"s2","keep":10}),
        json!({"op":"forget_history","env":"dev","key":"forget_key"}),
        json!({"op":"forget_env_history","env":"dev"}),
        json!({"op":"forget_envs_history","envs":["dev","prod"]}),
        json!({"op":"set","env":"dev","key":"replace","value":"r1","keep":10}),
        json!({"op":"set","env":"dev","key":"replace","value":"r2","keep":10}),
        json!({"op":"replace_and_forget","env":"dev","key":"replace","value":"fresh"}),
        json!({"op":"set","env":"dev","key":"python_history","value":"py1","keep":10}),
        json!({"op":"set","env":"dev","key":"python_history","value":"py2","keep":10}),
        json!({"op":"list_versions","env":"dev","key":"python_history"}),
    ];

    let mut rust_results = Vec::with_capacity(operations.len());
    for operation in &operations {
        let env = operation["env"].as_str().unwrap_or("dev");
        let key = operation["key"].as_str().unwrap_or("");
        let result = match operation["op"].as_str().expect("history operation") {
            "set" => {
                let keep = operation["keep"].as_u64().expect("history keep") as usize;
                json!(
                    rust_store
                        .set_secret(
                            env,
                            key,
                            operation["value"].as_str().expect("history value"),
                            keep
                        )
                        .expect("Rust history set")
                )
            }
            "remove" => {
                let keep = operation["keep"].as_u64().expect("history keep") as usize;
                json!(
                    rust_store
                        .remove_secret(env, key, keep)
                        .expect("Rust history remove")
                )
            }
            "list_versions" => {
                versions_value(&rust_store.list_versions(env, key).expect("Rust versions"))
            }
            "get_version" => {
                let value = rust_store
                    .get_version(env, key, operation["version"].as_u64().unwrap())
                    .expect("Rust get version");
                json!(hex(&Sha256::digest(value.as_bytes())))
            }
            "restore_version" => {
                let keep = operation["keep"].as_u64().unwrap() as usize;
                json!(
                    rust_store
                        .restore_version(env, key, operation["version"].as_u64().unwrap(), keep)
                        .expect("Rust restore version")
                )
            }
            "undo_remove" => json!(rust_store.undo_remove(env, key).expect("Rust undo remove")),
            "prune_envs" => {
                let envs = operation["envs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|env| env.as_str().unwrap())
                    .collect::<Vec<_>>();
                json!(
                    rust_store
                        .prune_envs(&envs, operation["keep"].as_u64().unwrap() as usize)
                        .expect("Rust prune environments")
                )
            }
            "forget_history" => json!(
                rust_store
                    .forget_history(env, key)
                    .expect("Rust forget history")
            ),
            "forget_env_history" => json!(
                rust_store
                    .forget_env_history(env)
                    .expect("Rust forget environment history")
            ),
            "forget_envs_history" => {
                let envs = operation["envs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|env| env.as_str().unwrap())
                    .collect::<Vec<_>>();
                json!(
                    rust_store
                        .forget_envs_history(&envs)
                        .expect("Rust forget environments history")
                )
            }
            "replace_and_forget" => json!(
                rust_store
                    .replace_and_forget(
                        env,
                        key,
                        operation["value"].as_str().expect("replacement value")
                    )
                    .expect("Rust replace and forget")
            ),
            other => panic!("unknown history operation {other}"),
        };
        rust_results.push(result);
    }

    let operation_path = temp.path().join("history-operations.json");
    fs::write(&operation_path, serde_json::to_vec(&operations).unwrap()).unwrap();
    let script = fixture_root().join("../gen/check_store_parity.py");
    let output = Command::new(python)
        .arg(script)
        .arg(&python_root)
        .arg(&rust_root)
        .arg(hex(master.as_bytes()))
        .arg(&operation_path)
        .output()
        .expect("run Python history parity script");
    assert!(
        output.status.success(),
        "Python history parity failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS python history parity"), "{stdout}");
    let result: Value = serde_json::from_str(stdout.lines().last().expect("Python result JSON"))
        .expect("parse Python history results");
    assert_eq!(result["returns"], Value::Array(rust_results));
    assert_eq!(
        result["python_written_versions"],
        versions_value(
            &DrawerStore::open(&python_secrets, key_copy(&master))
                .list_versions("dev", "python_history")
                .expect("Rust reads Python versions")
        )
    );
    assert_eq!(result["cross_read_restored"], Value::Bool(true));
    for env in ["dev", "prod"] {
        assert_eq!(
            normalized_inventory(&python_secrets, env, &master),
            normalized_inventory(&rust_secrets, env, &master),
            "history index and record set for {env}"
        );
    }
}

fn versions_value(versions: &[VersionInfo]) -> Value {
    Value::Array(
        versions
            .iter()
            .map(|version| match &version.state {
                VersionState::Current => json!({
                    "version":version.version,
                    "updated":version.updated.as_ref().map(|_| "TIME"),
                    "state":"current"
                }),
                VersionState::Removed { removed } => json!({
                    "version":version.version,
                    "updated":version.updated.as_ref().map(|_| "TIME"),
                    "state":"removed",
                    "removed":removed.as_ref().map(|_| "TIME")
                }),
                VersionState::Old => json!({
                    "version":version.version,
                    "updated":version.updated.as_ref().map(|_| "TIME"),
                    "state":"old"
                }),
            })
            .collect(),
    )
}

fn live_values(store: &DrawerStore, env: &str) -> BTreeMap<String, String> {
    store
        .list_secrets(env)
        .expect("list live values")
        .into_iter()
        .map(|(name, value)| (name, value.to_string()))
        .collect()
}

fn normalized_inventory(secrets_dir: &std::path::Path, env: &str, master: &Key32) -> Value {
    let store = DrawerStore::open(secrets_dir, key_copy(master));
    let env_id = store.env_id(env);
    let env_dir = secrets_dir.join("drawers").join("envs").join(&env_id);
    let blob = fs::read(env_dir.join("index.kvi")).expect("read parity index");
    let key = derive_labeled_key(master, b"kv-drawer:index", &[env.as_bytes()]);
    let plaintext = decrypt(
        &key,
        blob.get(4..).expect("parity index ciphertext"),
        format!("kv-drawer:index:v1:{env}").as_bytes(),
    )
    .expect("decrypt parity index");
    let mut index: Value = serde_json::from_slice(&plaintext).expect("parse parity index");
    let mut references = BTreeMap::new();
    let entries = index
        .get_mut("secrets")
        .and_then(Value::as_object_mut)
        .expect("secrets map");
    for (name, entry) in entries {
        if let Some(object) = entry.as_object_mut() {
            if let (Some(record_id), Some(generation)) = (
                object.get("current_record_id").and_then(Value::as_str),
                object.get("generation").and_then(Value::as_u64),
            ) {
                references.insert(record_id.to_owned(), (name.clone(), generation));
                object.insert(
                    "current_record_id".into(),
                    Value::String(format!("record:{name}:{generation}")),
                );
            }
            object.insert("record_hash".into(), Value::String("HASH".into()));
            for field in ["created", "updated", "deleted"] {
                if object.get(field).is_some() {
                    object.insert(field.into(), Value::String("TIME".into()));
                }
            }
            if let Some(history) = object.get_mut("history").and_then(Value::as_array_mut) {
                for reference in history {
                    if let Some(reference) = reference.as_object_mut() {
                        if let (Some(record_id), Some(generation)) = (
                            reference.get("record_id").and_then(Value::as_str),
                            reference.get("generation").and_then(Value::as_u64),
                        ) {
                            references.insert(record_id.to_owned(), (name.clone(), generation));
                            reference.insert(
                                "record_id".into(),
                                Value::String(format!("record:{name}:{generation}")),
                            );
                        }
                        if reference.get("record_hash").is_some() {
                            reference.insert("record_hash".into(), Value::String("HASH".into()));
                        }
                        if reference.get("updated").is_some() {
                            reference.insert("updated".into(), Value::String("TIME".into()));
                        }
                    }
                }
            }
        }
    }
    if let Some(metadata) = index.get_mut("_meta").and_then(Value::as_object_mut)
        && metadata.get("updated").is_some()
    {
        metadata.insert("updated".into(), Value::String("TIME".into()));
    }

    let records_dir = env_dir.join("records");
    let mut generations = Vec::new();
    for file in fs::read_dir(records_dir).expect("read parity records") {
        let path = file.expect("parity record entry").path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("record filename");
        let record_id = file_name.strip_suffix(".kvs").expect("record extension");
        generations.push(
            references
                .get(record_id)
                .cloned()
                .expect("record reference"),
        );
    }
    generations.sort();
    json!({
        "index": index,
        "record_count": generations.len(),
        "record_generations": generations,
    })
}

#[test]
fn python_and_rust_envtree_copy_checked_copy_and_backup_interoperate() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Python Stage 2c parity: set KV_PY_REF to the reference interpreter");
        return;
    };
    let master = fixture_master_key();
    let passphrase = fixture_expected()["passphrase"]
        .as_str()
        .expect("fixture passphrase")
        .to_owned();
    let temp = TestDir::new("stage2c-parity");
    let python_root = temp.project_root("python");
    let rust_root = temp.project_root("rust");
    let python_copy_root = temp.project_root("python-copy");
    let rust_copy_root = temp.project_root("rust-copy");
    let python_restore_root = temp.project_root("python-restore-python");
    let python_rust_restore_root = temp.project_root("python-restore-rust");
    let rust_restore_root = temp.project_root("rust-restore");
    copy_fixture_secrets(&python_root);
    let rust_secrets = copy_fixture_secrets(&rust_root);
    let python_copy_secrets = copy_fixture_secrets(&python_copy_root);
    let rust_copy_secrets = copy_fixture_secrets(&rust_copy_root);
    let python_restore_secrets = copy_fixture_secrets(&python_restore_root);
    let python_rust_restore_secrets = copy_fixture_secrets(&python_rust_restore_root);
    let rust_restore_secrets = copy_fixture_secrets(&rust_restore_root);
    let rust_store = DrawerStore::open(&rust_secrets, key_copy(&master));
    let rust_copy_store = DrawerStore::open(&rust_copy_secrets, key_copy(&master));

    rust_store
        .copy_env_tree("dev", "staging")
        .expect("Rust environment-tree copy");
    rust_copy_store
        .copy_env_tree("dev", "staging")
        .expect("Rust-only environment-tree copy");
    assert_eq!(
        live_values(&rust_store, "dev"),
        live_values(&rust_store, "staging")
    );
    let records_before_copy =
        normalized_inventory(&rust_secrets, "staging", &master)["record_count"]
            .as_u64()
            .expect("record count before identical copy");
    let created = rust_store
        .copy_env_checked(
            "dev",
            "staging",
            CopyOptions {
                keep_existing: true,
                ..CopyOptions::default()
            },
            1,
            false,
        )
        .expect("Rust checked copy creating destination registration");
    assert!(created.created);
    assert_eq!(
        normalized_inventory(&rust_secrets, "staging", &master)["record_count"],
        json!(records_before_copy),
        "an identical checked copy must not rewrite records"
    );
    rust_store
        .set_secret("staging", "API_KEY", "destination value", 1)
        .expect("set Rust destination value");
    let kept = rust_store
        .copy_env_checked(
            "dev",
            "staging",
            CopyOptions {
                keep_existing: true,
                ..CopyOptions::default()
            },
            1,
            true,
        )
        .expect("Rust checked copy keeping existing value");
    assert_eq!(kept.kept, vec!["API_KEY"]);
    assert!(matches!(
        rust_store.copy_env_checked(
            "dev",
            "staging",
            CopyOptions {
                expect_replaced: Some(Vec::new()),
                expect_keep: Some(1),
                ..CopyOptions::default()
            },
            1,
            true
        ),
        Err(StoreError::CopyChanged(message))
            if message == "environment 'staging' changed while you were deciding; nothing was copied, run the copy again"
    ));
    assert!(matches!(
        rust_store.copy_env_checked(
            "dev",
            "staging",
            CopyOptions {
                expect_replaced: Some(vec!["API_KEY".into()]),
                expect_keep: Some(0),
                ..CopyOptions::default()
            },
            1,
            true
        ),
        Err(StoreError::CopyChanged(message))
            if message == "the history setting changed while you were deciding; nothing was copied, run the copy again"
    ));
    let replaced = rust_store
        .copy_env_checked(
            "dev",
            "staging",
            CopyOptions {
                expect_replaced: Some(vec!["API_KEY".into()]),
                expect_keep: Some(1),
                ..CopyOptions::default()
            },
            1,
            true,
        )
        .expect("Rust checked copy replacing destination value");
    assert_eq!(replaced.replaced, vec!["API_KEY"]);
    rust_store
        .set_secret("staging", "REMOVED", "removed value", 1)
        .expect("set Rust removed snapshot value");
    rust_store
        .remove_secret("staging", "REMOVED", 1)
        .expect("remove Rust snapshot value");

    let rust_backup_path = temp.path().join("rust-backup.kvb");
    let made_from = rust_root.to_string_lossy();
    backup::make_backup_with_setting(
        &rust_store,
        &rust_backup_path,
        backup::BackupOptions {
            envs: &["dev", "prod", "staging"],
            default_env: "dev",
            history_keep: 1,
            passphrase: &passphrase,
            made_from: &made_from,
            setting: [14, 8, 1],
        },
    )
    .expect("make Rust backup");

    let python_backup_path = temp.path().join("python-backup.kvb");
    let operation_path = temp.path().join("stage2c.json");
    let spec = json!({
        "stage2c":true,
        "python_copy_root":python_copy_root,
        "rust_copy_root":rust_copy_root,
        "python_restore_root":python_restore_root,
        "python_rust_restore_root":python_rust_restore_root,
        "python_backup_path":python_backup_path,
        "rust_backup_path":rust_backup_path,
        "passphrase":passphrase,
        "history_keep":1
    });
    fs::write(&operation_path, serde_json::to_vec(&spec).unwrap()).unwrap();
    let script = fixture_root().join("../gen/check_store_parity.py");
    let output = Command::new(python)
        .arg(script)
        .arg(&python_root)
        .arg(&rust_root)
        .arg(hex(master.as_bytes()))
        .arg(&operation_path)
        .output()
        .expect("run Python Stage 2c parity script");
    assert!(
        output.status.success(),
        "Python Stage 2c parity failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS Stage 2c Python parity"), "{stdout}");
    println!("{}", stdout.trim());
    let report: Value =
        serde_json::from_str(stdout.lines().last().expect("parity report")).unwrap();
    assert_eq!(report["keep_copy"]["kept"], json!(["API_KEY"]));
    assert_eq!(report["keep_copy"]["copied"], json!(kept.copied));
    assert_eq!(report["keep_copy"]["created"], json!(kept.created));
    assert_eq!(report["create_copy"]["copied"], json!(created.copied));
    assert_eq!(report["create_copy"]["created"], json!(created.created));
    assert_eq!(report["replace_copy"]["replaced"], json!(["API_KEY"]));
    assert_eq!(report["replace_copy"]["copied"], json!(replaced.copied));
    assert_eq!(report["replace_copy"]["created"], json!(replaced.created));
    assert_eq!(report["replace_mismatch"], json!("CopyChanged"));
    assert_eq!(
        report["keep_setting_mismatch"],
        json!(
            "the history setting changed while you were deciding; nothing was copied, run the copy again"
        )
    );

    let python_copy_store = DrawerStore::open(&python_copy_secrets, key_copy(&master));
    assert_eq!(
        live_values(&python_copy_store, "dev"),
        live_values(&python_copy_store, "staging"),
        "Rust cross-read of Python-copied environment tree"
    );
    assert_eq!(
        normalized_inventory(&python_copy_secrets, "staging", &master),
        normalized_inventory(&rust_copy_secrets, "staging", &master),
        "Python and Rust environment-tree copies"
    );

    let python_plaintext = backup::open_backup_bytes(
        &backup::read_backup_file(&python_backup_path).expect("read Python backup"),
        &passphrase,
    )
    .expect("open Python backup");
    let python_payload = backup::parse_payload(&python_plaintext).expect("parse Python backup");
    assert_eq!(python_payload.state.history_keep, 1);
    let rust_restore_store = DrawerStore::open(&rust_restore_secrets, key_copy(&master));
    for env in ["dev", "prod", "staging"] {
        rust_restore_store
            .clear_env_tree(env)
            .expect("prepare empty Rust restore environment");
    }
    let restored_count = rust_restore_store
        .restore_snapshot(&python_payload.state.environments, 1)
        .expect("restore Python snapshot in Rust");
    assert_eq!(
        restored_count,
        report["python_restore_count"].as_u64().unwrap() as usize
    );

    let python_restore_store = DrawerStore::open(&python_restore_secrets, key_copy(&master));
    let python_rust_restore_store =
        DrawerStore::open(&python_rust_restore_secrets, key_copy(&master));
    for env in ["dev", "prod", "staging"] {
        assert_eq!(
            normalized_inventory(&rust_restore_secrets, env, &master),
            normalized_inventory(&python_restore_secrets, env, &master),
            "Rust restore of Python backup matches Python restore for {env}"
        );
        assert_eq!(
            normalized_inventory(&rust_secrets, env, &master),
            normalized_inventory(&python_rust_restore_secrets, env, &master),
            "Python restore of Rust backup matches Rust source for {env}"
        );
        assert_eq!(
            live_values(&rust_restore_store, env),
            live_values(&python_restore_store, env)
        );
        assert_eq!(
            live_values(&rust_store, env),
            live_values(&python_rust_restore_store, env)
        );
    }
}
