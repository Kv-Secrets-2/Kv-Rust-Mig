mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use kv_crypto::{Key32, decrypt, derive_labeled_key, keyfile};
use kv_store::{CopyOptions, DrawerStore, backup, config, pyjson};
use serde_json::{Value, json};

use common::{
    TestDir, copy_fixture_secrets, fixture_expected, fixture_master_key, fixture_root, hex,
    key_copy,
};

fn run_python(
    python: &std::ffi::OsStr,
    temp: &TestDir,
    root: &Path,
    master: &Key32,
    command: Value,
    label: &str,
) -> Value {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let spec = temp.path().join(format!(
        "{label}-{}.json",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::write(&spec, serde_json::to_vec(&command).unwrap()).unwrap();
    let output = Command::new(python)
        .arg(fixture_root().join("../gen/check_store_parity.py"))
        .arg(root)
        .arg(root)
        .arg(hex(master.as_bytes()))
        .arg(&spec)
        .output()
        .expect("run Python parity subcommand");
    assert!(
        output.status.success(),
        "Python parity subcommand failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Python parity JSON")
}

fn normalize_config(mut value: Value) -> Value {
    if value.get("created").is_some() {
        value["created"] = Value::String("TIME".into());
    }
    if let Some(entries) = value
        .get_mut("deleted_environments")
        .and_then(Value::as_array_mut)
    {
        for entry in entries {
            for field in ["deleted_at", "purge_after"] {
                if entry.get(field).is_some() {
                    entry[field] = Value::String("TIME".into());
                }
            }
        }
    }
    value
}

fn rust_inventory(secrets: &Path, env: &str, master: &Key32) -> Value {
    let store = DrawerStore::open(secrets, key_copy(master));
    let env_id = store.env_id(env);
    let env_dir = secrets.join("drawers").join("envs").join(&env_id);
    let blob = fs::read(env_dir.join("index.kvi")).expect("read Rust index");
    let key = derive_labeled_key(master, b"kv-drawer:index", &[env.as_bytes()]);
    let plaintext = decrypt(
        &key,
        blob.get(4..).expect("index ciphertext"),
        format!("kv-drawer:index:v1:{env}").as_bytes(),
    )
    .expect("decrypt Rust index");
    let mut index: Value = serde_json::from_slice(&plaintext).expect("parse Rust index");
    let mut references = BTreeMap::new();
    for (name, entry) in index["secrets"].as_object_mut().expect("secret map") {
        if let Some((id, generation)) = entry
            .get("current_record_id")
            .and_then(Value::as_str)
            .zip(entry.get("generation").and_then(Value::as_u64))
        {
            references.insert(id.to_owned(), (name.clone(), generation));
            entry["current_record_id"] = Value::String(format!("record:{name}:{generation}"));
        }
        entry["record_hash"] = Value::String("HASH".into());
        for field in ["created", "updated", "deleted"] {
            if entry.get(field).is_some() {
                entry[field] = Value::String("TIME".into());
            }
        }
        if let Some(history) = entry.get_mut("history").and_then(Value::as_array_mut) {
            for reference in history {
                if let Some((id, generation)) = reference
                    .get("record_id")
                    .and_then(Value::as_str)
                    .zip(reference.get("generation").and_then(Value::as_u64))
                {
                    references.insert(id.to_owned(), (name.clone(), generation));
                    reference["record_id"] = Value::String(format!("record:{name}:{generation}"));
                }
                if reference.get("record_hash").is_some() {
                    reference["record_hash"] = Value::String("HASH".into());
                }
                if reference.get("updated").is_some() {
                    reference["updated"] = Value::String("TIME".into());
                }
            }
        }
    }
    if index["_meta"].get("updated").is_some() {
        index["_meta"]["updated"] = Value::String("TIME".into());
    }
    let mut generations = fs::read_dir(env_dir.join("records"))
        .expect("read records")
        .map(|entry| {
            let path = entry.unwrap().path();
            let id = path.file_name().unwrap().to_string_lossy();
            references[id.strip_suffix(".kvs").unwrap()].clone()
        })
        .collect::<Vec<_>>();
    generations.sort();
    json!({
        "index":index,
        "record_count":generations.len(),
        "record_generations":generations
    })
}

fn rust_snapshot(root: &Path, master: &Key32) -> (Value, String, Value) {
    let snapshot = config::load_config(root).unwrap();
    let config = normalize_config(snapshot.value);
    let bytes = String::from_utf8(pyjson::to_vec_indent2_ascii(&config).unwrap()).unwrap();
    let mut names = config["environments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    names.extend(
        config::list_deleted_environments(root)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name),
    );
    names.extend(config::pending_env_wipes(root).unwrap());
    let secrets = root.join(".secrets");
    let mut indexes = serde_json::Map::new();
    for env in names {
        let store = DrawerStore::open(&secrets, key_copy(master));
        let path = secrets
            .join("drawers")
            .join("envs")
            .join(store.env_id(&env))
            .join("index.kvi");
        if path.exists() {
            indexes.insert(env.clone(), rust_inventory(&secrets, &env, master));
        }
    }
    (config, bytes, Value::Object(indexes))
}

fn restored_master(root: &Path, passphrase: &str) -> Key32 {
    let wrapped = fs::read(root.join(".secrets").join("key")).expect("read restored key");
    let identity =
        keyfile::unwrap_v4(&wrapped, passphrase.as_bytes()).expect("unwrap restored key");
    Key32::new(*identity.master_key.as_bytes())
}

fn assert_snapshot(root: &Path, master: &Key32, python: &Value) {
    let (config, bytes, indexes) = rust_snapshot(root, master);
    assert_eq!(python["config"], config, "config values");
    assert_eq!(python["config_bytes"], bytes, "normalized config bytes");
    assert_eq!(python["indexes"], indexes, "normalized indexes");
}

fn restored_values_and_versions(vault: &config::Vault, master: &Key32) -> Value {
    let mut values = serde_json::Map::new();
    let mut versions = serde_json::Map::new();
    let secrets = vault.root.join(".secrets");
    for env in vault.list_environments().unwrap() {
        let live = vault.store.list_secrets(&env).unwrap();
        values.insert(
            env.clone(),
            Value::Object(
                live.iter()
                    .map(|(name, value)| (name.clone(), json!(value.as_str())))
                    .collect(),
            ),
        );
        let inventory = rust_inventory(&secrets, &env, master);
        let entries = inventory["index"]["secrets"].as_object().unwrap();
        let mut env_versions = serde_json::Map::new();
        for (name, entry) in entries {
            if entry.get("current_record_id").is_none() {
                continue;
            }
            let listed = vault.store.list_versions(&env, name).unwrap();
            let values = listed
                .iter()
                .map(|version| {
                    json!({
                        "version":version.version,
                        "value":vault.store.get_version(&env, name, version.version).unwrap().as_str()
                    })
                })
                .collect::<Vec<_>>();
            env_versions.insert(name.clone(), Value::Array(values));
        }
        versions.insert(env, Value::Object(env_versions));
    }
    json!({"values":values,"versions":versions})
}

fn rust_step(vault: &config::Vault, operation: &Value) -> Value {
    let kind = operation["op"].as_str().unwrap();
    let result: Result<Value, kv_store::StoreError> = match kind {
        "history_keep" => vault
            .set_history_keep(operation["keep"].as_u64().unwrap() as usize)
            .map(|n| json!(n)),
        "add" => vault
            .add_environment(operation["name"].as_str().unwrap())
            .map(|value| json!(value)),
        "deleted_keep_days" => vault
            .set_deleted_env_keep_days(operation["days"].as_u64().unwrap())
            .and_then(|()| vault.get_deleted_env_keep_days())
            .map(|days| json!(days)),
        "default" => vault
            .set_default_env(operation["name"].as_str().unwrap())
            .map(|()| Value::Null),
        "rename" => vault
            .rename_env(
                operation["old"].as_str().unwrap(),
                operation["new"].as_str().unwrap(),
            )
            .map(|()| Value::Null),
        "delete" => vault
            .delete_env(operation["name"].as_str().unwrap())
            .map(|entry| {
                json!({
                    "name":entry.name,
                    "deleted_at":"TIME",
                    "purge_after":"TIME"
                })
            }),
        "restore" => vault
            .restore_env(operation["name"].as_str().unwrap())
            .map(|()| Value::Null),
        "purge" => vault
            .purge_env(operation["name"].as_str().unwrap())
            .map(|value| json!(value)),
        "set" => vault
            .set_secret(
                operation["env"].as_str().unwrap(),
                operation["key"].as_str().unwrap(),
                operation["value"].as_str().unwrap(),
            )
            .map(|version| json!(version)),
        "remove" => vault
            .remove_secret(
                operation["env"].as_str().unwrap(),
                operation["key"].as_str().unwrap(),
            )
            .map(|removed| json!(removed)),
        "copy" => vault
            .copy_env_checked(
                operation["source"].as_str().unwrap(),
                operation["destination"].as_str().unwrap(),
                CopyOptions {
                    keep_existing: operation["keep_existing"].as_bool().unwrap_or(false),
                    ..CopyOptions::default()
                },
            )
            .map(|result| {
                json!({
                    "copied":result.copied,
                    "replaced":result.replaced,
                    "kept":result.kept,
                    "created":result.created
                })
            }),
        "queue_wipe" => config::queue_env_wipes(
            &vault.root,
            &operation["names"]
                .as_array()
                .unwrap()
                .iter()
                .map(|name| name.as_str().unwrap().to_owned())
                .collect::<Vec<_>>(),
        )
        .map(|()| Value::Null),
        other => panic!("unknown Rust parity step {other}"),
    };
    match result {
        Ok(value) => json!({"result":value}),
        Err(error) => json!({"error":error.to_string()}),
    }
}

fn compare_step(
    python: &std::ffi::OsStr,
    temp: &TestDir,
    root_python: &Path,
    root_rust: &Path,
    master: &Key32,
    vault: &config::Vault,
    operation: Value,
) {
    let rust_result = rust_step(vault, &operation);
    let python_result = run_python(
        python,
        temp,
        root_python,
        master,
        json!({"stage3a_step":operation}),
        "stage3a-step",
    );
    assert_eq!(
        rust_result,
        if python_result.get("error").is_some() {
            json!({"error":python_result["error"]})
        } else {
            json!({"result":python_result["result"]})
        },
        "result for {}",
        operation["op"]
    );
    assert_snapshot(root_rust, master, &python_result);
}

#[test]
fn python_and_rust_config_lifecycle_steps_match() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP config lifecycle parity: set KV_PY_REF");
        return;
    };
    let master = fixture_master_key();
    let temp = TestDir::new("config-parity-steps");
    let python_root = temp.project_root("python");
    let rust_root = temp.project_root("rust");
    copy_fixture_secrets(&python_root);
    let rust_secrets = copy_fixture_secrets(&rust_root);
    let vault = config::Vault::new(
        &rust_root,
        DrawerStore::open(&rust_secrets, key_copy(&master)),
        config::NoApprovals,
    );
    for operation in [
        json!({"op":"history_keep","keep":2}),
        json!({"op":"history_keep","keep":0}),
        json!({"op":"deleted_keep_days","days":7}),
        json!({"op":"add","name":"temporary"}),
        json!({"op":"deleted_keep_days","days":0}),
        json!({"op":"delete","name":"temporary"}),
        json!({"op":"set","env":"dev","key":"AUTO_PURGE","value":"done"}),
        json!({"op":"deleted_keep_days","days":30}),
        json!({"op":"delete","name":"prod"}),
        json!({"op":"set","env":"prod","key":"REFUSED","value":"no"}),
        json!({"op":"remove","env":"prod","key":"DB_URL"}),
        json!({"op":"rename","old":"dev","new":"development"}),
        json!({"op":"rename","old":"development","new":"DEVELOPMENT"}),
        json!({"op":"queue_wipe","names":["pending"]}),
        json!({"op":"set","env":"pending","key":"REFUSED","value":"no"}),
        json!({"op":"remove","env":"pending","key":"KEY"}),
        json!({"op":"copy","source":"development","destination":"copy"}),
    ] {
        compare_step(
            &python,
            &temp,
            &python_root,
            &rust_root,
            &master,
            &vault,
            operation,
        );
    }
}

#[test]
fn python_and_rust_operations_interleave_on_one_vault_copy() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP interleaved config parity: set KV_PY_REF");
        return;
    };
    let master = fixture_master_key();
    let temp = TestDir::new("config-interleaved");
    let root = temp.project_root("shared");
    let secrets = copy_fixture_secrets(&root);
    let vault = config::Vault::new(
        &root,
        DrawerStore::open(&secrets, key_copy(&master)),
        config::NoApprovals,
    );
    let set = run_python(
        &python,
        &temp,
        &root,
        &master,
        json!({"stage3a_step":{"op":"set","env":"dev","key":"INTERLEAVED","value":"python-value"}}),
        "interleaved",
    );
    assert_snapshot(&root, &master, &set);
    vault.rename_env("prod", "production").unwrap();
    let read = run_python(
        &python,
        &temp,
        &root,
        &master,
        json!({"stage3a_step":{"op":"list_get","env":"dev","key":"INTERLEAVED"}}),
        "interleaved",
    );
    assert_eq!(read["result"]["value"], "python-value");
    assert_snapshot(&root, &master, &read);
    vault.delete_env("production").unwrap();
    let restore = run_python(
        &python,
        &temp,
        &root,
        &master,
        json!({"stage3a_step":{"op":"restore","name":"production"}}),
        "interleaved",
    );
    assert_snapshot(&root, &master, &restore);
    assert_eq!(
        vault
            .get_secret("dev", "INTERLEAVED")
            .unwrap()
            .unwrap()
            .as_str(),
        "python-value"
    );
}

#[test]
fn rust_and_python_backup_restore_interoperate() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
        eprintln!("SKIP backup parity: set KV_PY_REF");
        return;
    };
    let master = fixture_master_key();
    let expected = fixture_expected();
    let passphrase = expected["passphrase"].as_str().unwrap();
    let temp = TestDir::new("config-backup-parity");
    let rust_root = temp.project_root("rust-source");
    let python_root = temp.project_root("python-source");
    let rust_secrets = copy_fixture_secrets(&rust_root);
    copy_fixture_secrets(&python_root);
    let rust_vault = config::Vault::new(
        &rust_root,
        DrawerStore::open(&rust_secrets, key_copy(&master)),
        config::NoApprovals,
    );

    let rust_backup = temp.path().join("rust-backup.kvb");
    rust_vault
        .make_backup_with_setting(
            &rust_backup,
            passphrase,
            &rust_root.to_string_lossy(),
            [14, 8, 1],
        )
        .unwrap();
    let python_rust_target = temp.project_root("python-from-rust");
    let python_rust = run_python(
        &python,
        &temp,
        &python_root,
        &master,
        json!({"stage3a_backup":{
            "op":"restore","path":rust_backup,"target":python_rust_target,
            "passphrase":passphrase
        }}),
        "backup-rust-restore",
    );
    assert_eq!(python_rust["values"]["dev"]["API_KEY"], "sk-test-456");
    assert!(
        !python_rust["versions"]["dev"]["API_KEY"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let rust_from_rust_target = temp.project_root("rust-from-rust");
    let rust_data = backup::parse_payload(
        &backup::open_backup_bytes(&backup::read_backup_file(&rust_backup).unwrap(), passphrase)
            .unwrap(),
    )
    .unwrap();
    let rust_from_rust =
        backup::restore_backup(rust_data, passphrase, &rust_from_rust_target).unwrap();
    let rust_restored_master = restored_master(&rust_from_rust_target, passphrase);
    let (rust_config, rust_config_bytes, rust_indexes) =
        rust_snapshot(&rust_from_rust_target, &rust_restored_master);
    assert_eq!(python_rust["config"], rust_config);
    assert_eq!(python_rust["config_bytes"], rust_config_bytes);
    assert_eq!(python_rust["indexes"], rust_indexes);
    assert_eq!(
        rust_from_rust
            .get_secret("dev", "API_KEY")
            .unwrap()
            .unwrap()
            .as_str(),
        "sk-test-456"
    );
    assert_eq!(
        json!({
            "values":python_rust["values"],
            "versions":python_rust["versions"]
        }),
        restored_values_and_versions(&rust_from_rust, &rust_restored_master)
    );

    let python_backup = temp.path().join("python-backup.kvb");
    run_python(
        &python,
        &temp,
        &python_root,
        &master,
        json!({"stage3a_backup":{
            "op":"make","path":python_backup,"passphrase":passphrase
        }}),
        "backup-python-make",
    );
    let python_restore_target = temp.project_root("python-from-python");
    let python_python = run_python(
        &python,
        &temp,
        &python_root,
        &master,
        json!({"stage3a_backup":{
            "op":"restore","path":python_backup,"target":python_restore_target,
            "passphrase":passphrase
        }}),
        "backup-python-restore",
    );
    let python_plaintext = backup::open_backup_bytes(
        &backup::read_backup_file(&python_backup).unwrap(),
        passphrase,
    )
    .unwrap();
    let python_data = backup::parse_payload(&python_plaintext).unwrap();
    let rust_from_python_target = temp.project_root("rust-from-python");
    let rust_from_python =
        backup::restore_backup(python_data, passphrase, &rust_from_python_target).unwrap();
    let python_restored_master = restored_master(&rust_from_python_target, passphrase);
    let (python_restore_config, python_restore_bytes, python_restore_indexes) =
        rust_snapshot(&rust_from_python_target, &python_restored_master);
    assert_eq!(python_python["config"], python_restore_config);
    assert_eq!(python_python["config_bytes"], python_restore_bytes);
    assert_eq!(python_python["indexes"], python_restore_indexes);
    assert_eq!(
        json!({
            "values":python_python["values"],
            "versions":python_python["versions"]
        }),
        restored_values_and_versions(&rust_from_python, &python_restored_master)
    );
    for env in rust_from_python.list_environments().unwrap() {
        for (name, value) in rust_from_python.store.list_secrets(&env).unwrap() {
            assert_eq!(
                value.as_str(),
                rust_from_python
                    .store
                    .get_secret(&env, &name)
                    .unwrap()
                    .unwrap()
                    .as_str()
            );
            for version in rust_from_python.store.list_versions(&env, &name).unwrap() {
                assert!(
                    rust_from_python
                        .store
                        .get_version(&env, &name, version.version)
                        .is_ok(),
                    "missing {env}/{name} version {}",
                    version.version
                );
            }
        }
    }
}
