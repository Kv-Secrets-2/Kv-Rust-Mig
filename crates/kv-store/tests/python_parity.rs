mod common;

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

use kv_crypto::{Key32, decrypt, derive_labeled_key};
use kv_store::DrawerStore;
use serde_json::{Value, json};

use common::{TestDir, copy_fixture_secrets, fixture_master_key, fixture_root, hex, key_copy};

#[test]
fn python_and_rust_drawer_operations_have_matching_storage_and_cross_reads() {
    let Some(python) = std::env::var_os("KV_PY_REF") else {
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
        .env("PYTHONPATH", "/home/ubuntu/repos/kv-secrets")
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
