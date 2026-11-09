mod common;

use kv_crypto::{Key32, decrypt, derive_labeled_key, encrypt};
use kv_store::{DrawerStore, StoreError, fsx, pyjson};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File};

use common::{TestDir, hex, key_copy};

fn master() -> Key32 {
    Key32::new(std::array::from_fn(|index| index as u8))
}

fn store_in(temp: &TestDir, label: &str) -> (std::path::PathBuf, DrawerStore, Key32) {
    let secrets_dir = temp.project_root(label).join(".secrets");
    fs::create_dir_all(&secrets_dir).expect("create secrets directory");
    let key = master();
    (
        secrets_dir.clone(),
        DrawerStore::open(&secrets_dir, key_copy(&key)),
        key,
    )
}

fn index_path(secrets_dir: &std::path::Path, store: &DrawerStore, env: &str) -> std::path::PathBuf {
    secrets_dir
        .join("drawers")
        .join("envs")
        .join(store.env_id(env))
        .join("index.kvi")
}

fn encrypted_index(master: &Key32, env: &str, plaintext: &[u8]) -> Vec<u8> {
    let key = derive_labeled_key(master, b"kv-drawer:index", &[env.as_bytes()]);
    let ciphertext = encrypt(
        &key,
        plaintext,
        format!("kv-drawer:index:v1:{env}").as_bytes(),
    );
    let mut blob = b"KVI\x01".to_vec();
    blob.extend_from_slice(&ciphertext);
    blob
}

fn write_index(
    secrets_dir: &std::path::Path,
    store: &DrawerStore,
    env: &str,
    master: &Key32,
    index: &Value,
) {
    let path = index_path(secrets_dir, store, env);
    fs::create_dir_all(path.parent().expect("index parent")).expect("create index directory");
    let plaintext = pyjson::to_vec(index).expect("serialize test index");
    fs::write(path, encrypted_index(master, env, &plaintext)).expect("write test index");
}

#[test]
fn malformed_indexes_return_errors_without_panicking() {
    let temp = TestDir::new("bad-index");
    let (secrets_dir, store, key) = store_in(&temp, "copy");
    let path = index_path(&secrets_dir, &store, "dev");
    fs::create_dir_all(path.parent().expect("index parent")).expect("create index directory");

    let mut cases = vec![
        (b"BAD\x01".to_vec(), "bad magic"),
        (b"KVI\x02".to_vec(), "unsupported version"),
        (b"KVI".to_vec(), "truncation"),
    ];
    let non_object = encrypted_index(&key, "dev", b"[]");
    cases.push((non_object, "non-object JSON"));
    let mismatch = json!({"version":1,"env":"other","_meta":{},"secrets":{}});
    cases.push((
        encrypted_index(&key, "dev", &pyjson::to_vec(&mismatch).unwrap()),
        "env mismatch",
    ));
    let empty = json!({"version":1,"env":"dev","_meta":{},"secrets":{}});
    let mut flipped = encrypted_index(&key, "dev", &pyjson::to_vec(&empty).unwrap());
    let last = flipped.len() - 1;
    flipped[last] ^= 0xff;
    cases.push((flipped, "ciphertext flip"));

    for (raw, label) in cases {
        fs::write(&path, raw).expect("write malformed index");
        let result = store.get_secret("dev", "TOKEN");
        assert!(result.is_err(), "{label}");
    }
}

#[test]
fn invalid_record_ids_are_rejected_before_record_path_access() {
    let temp = TestDir::new("bad-record-id");
    let (secrets_dir, store, key) = store_in(&temp, "copy");
    for record_id in [
        "../x".to_owned(),
        format!("r_{}", "A".repeat(64)),
        "r_123".to_owned(),
    ] {
        let index = json!({
            "version":1,
            "env":"dev",
            "_meta":{},
            "secrets":{
                "TOKEN":{
                    "state":"live",
                    "current_record_id":record_id,
                    "generation":1,
                    "record_hash":"0".repeat(64)
                }
            }
        });
        write_index(&secrets_dir, &store, "dev", &key, &index);
        assert!(
            matches!(
                store.get_secret("dev", "TOKEN"),
                Err(StoreError::Corrupt(_))
            ),
            "record id {record_id}"
        );
    }
}

#[test]
fn record_hash_and_metadata_are_verified_before_returning_a_value() {
    let temp = TestDir::new("record-integrity");
    let (secrets_dir, store, key) = store_in(&temp, "copy");
    store.set_secret("dev", "TOKEN", "original", 0).unwrap();

    let path = index_path(&secrets_dir, &store, "dev");
    let raw_index = fs::read(&path).expect("read index");
    let index_key = derive_labeled_key(&key, b"kv-drawer:index", &[b"dev"]);
    let plaintext = decrypt(&index_key, &raw_index[4..], b"kv-drawer:index:v1:dev").unwrap();
    let mut index: Value = serde_json::from_slice(&plaintext).unwrap();
    let record_id = index["secrets"]["TOKEN"]["current_record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let generation = index["secrets"]["TOKEN"]["generation"].as_u64().unwrap();
    let record_path = path
        .parent()
        .unwrap()
        .join("records")
        .join(format!("{record_id}.kvs"));
    let original_record = fs::read(&record_path).unwrap();
    let mut changed = original_record.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    fs::write(&record_path, changed).unwrap();
    assert!(matches!(
        store.get_secret("dev", "TOKEN"),
        Err(StoreError::Corrupt(message)) if message.contains("hash mismatch")
    ));

    let payload = json!({
        "version":1,
        "env":"dev",
        "name":"OTHER",
        "record_id":record_id,
        "generation":generation,
        "updated":"2026-01-01T00:00:00+00:00",
        "value":"original",
        "value_type":"text"
    });
    let record_key = derive_labeled_key(&key, b"kv-drawer:record", &[b"dev", record_id.as_bytes()]);
    let aad = format!("kv-drawer:record\0v1\0dev\0TOKEN\0{record_id}\0{generation}");
    let ciphertext = encrypt(
        &record_key,
        &pyjson::to_vec(&payload).unwrap(),
        aad.as_bytes(),
    );
    let mut replacement = b"KVS\x01".to_vec();
    replacement.extend_from_slice(&ciphertext);
    let hash = hex(&Sha256::digest(&replacement));
    index["secrets"]["TOKEN"]["record_hash"] = Value::String(hash);
    write_index(&secrets_dir, &store, "dev", &key, &index);
    fs::write(&record_path, replacement).unwrap();
    assert!(matches!(
        store.get_secret("dev", "TOKEN"),
        Err(StoreError::Corrupt(message)) if message.contains("metadata mismatch")
    ));
}

#[cfg(unix)]
#[test]
fn symlinked_storage_directories_are_refused() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("symlink-dir");
    let (secrets_dir, store, _) = store_in(&temp, "drawers-link");
    let outside_drawers = temp.path().join("outside-drawers");
    fs::create_dir(&outside_drawers).unwrap();
    symlink(&outside_drawers, secrets_dir.join("drawers")).unwrap();
    assert!(matches!(
        store.set_secret("dev", "TOKEN", "value", 0),
        Err(StoreError::Structure(_))
    ));
    assert_eq!(fs::read_dir(&outside_drawers).unwrap().count(), 0);

    let (secrets_records, store_records, _) = store_in(&temp, "records-link");
    let env_id = store_records.env_id("dev");
    let env_dir = secrets_records.join("drawers").join("envs").join(env_id);
    fs::create_dir_all(&env_dir).unwrap();
    let outside_records = temp.path().join("outside-records");
    fs::create_dir(&outside_records).unwrap();
    symlink(&outside_records, env_dir.join("records")).unwrap();
    assert!(matches!(
        store_records.set_secret("dev", "TOKEN", "value", 0),
        Err(StoreError::Structure(_))
    ));
    assert_eq!(fs::read_dir(&outside_records).unwrap().count(), 0);
}

#[test]
fn over_limit_index_is_rejected() {
    let temp = TestDir::new("large-index");
    let (secrets_dir, store, _) = store_in(&temp, "copy");
    let path = index_path(&secrets_dir, &store, "dev");
    fs::create_dir_all(path.parent().expect("index parent")).unwrap();
    let file = File::create(&path).unwrap();
    file.set_len((fsx::VAULT_FILE_LIMIT + 1) as u64).unwrap();
    assert!(matches!(
        store.get_secret("dev", "TOKEN"),
        Err(StoreError::TooLarge { len, .. }) if len == fsx::VAULT_FILE_LIMIT + 1
    ));
}

#[test]
fn keep_and_environment_validation_are_enforced() {
    let temp = TestDir::new("validation");
    let (_, store, _) = store_in(&temp, "copy");
    assert!(matches!(
        store.set_secret("D:escape", "TOKEN", "value", 1),
        Err(StoreError::InvalidName(_))
    ));
    assert!(store.set_secret("dev", "TOKEN", "value", 101).is_err());
    assert!(store.remove_secret("dev", "TOKEN", 101).is_err());
}
