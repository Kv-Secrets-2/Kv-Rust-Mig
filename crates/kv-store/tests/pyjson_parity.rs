mod common;

use std::collections::BTreeMap;
use std::fs;

use kv_crypto::{decrypt, derive_labeled_key};
use kv_store::pyjson;
use serde_json::Value;

use common::{fixture_master_key, fixture_root};

#[test]
fn every_fixture_index_and_record_reserializes_byte_exactly() {
    let master = fixture_master_key();
    let expected = common::fixture_expected();
    let expected_envs = expected["env_id"]
        .as_object()
        .expect("fixture environment map");
    let mut record_count = 0usize;

    for (env, env_id_value) in expected_envs {
        let env_id = env_id_value.as_str().expect("environment id");
        let env_dir = fixture_root()
            .join("vaults/basic/.secrets/drawers/envs")
            .join(env_id);
        let index_blob = fs::read(env_dir.join("index.kvi")).expect("fixture index file");
        let index_key = derive_labeled_key(&master, b"kv-drawer:index", &[env.as_bytes()]);
        let index_plaintext = decrypt(
            &index_key,
            index_blob.get(4..).expect("index ciphertext"),
            format!("kv-drawer:index:v1:{env}").as_bytes(),
        )
        .expect("decrypt fixture index");
        let index: Value = serde_json::from_slice(&index_plaintext).expect("parse fixture index");
        assert_eq!(
            pyjson::to_vec(&index).expect("serialize fixture index"),
            index_plaintext.as_slice(),
            "index for {env}"
        );

        let mut references = BTreeMap::<String, (String, u64)>::new();
        let entries = index["secrets"].as_object().expect("secrets object");
        for (name, entry) in entries {
            if let (Some(record_id), Some(generation)) = (
                entry.get("current_record_id").and_then(Value::as_str),
                entry.get("generation").and_then(Value::as_u64),
            ) {
                references.insert(record_id.to_owned(), (name.clone(), generation));
            }
            if let Some(history) = entry.get("history").and_then(Value::as_array) {
                for reference in history {
                    if let (Some(record_id), Some(generation)) = (
                        reference.get("record_id").and_then(Value::as_str),
                        reference.get("generation").and_then(Value::as_u64),
                    ) {
                        references.insert(record_id.to_owned(), (name.clone(), generation));
                    }
                }
            }
        }

        let records_dir = env_dir.join("records");
        for file in fs::read_dir(records_dir).expect("fixture records directory") {
            let path = file.expect("fixture record entry").path();
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("fixture record filename");
            let record_id = file_name.strip_suffix(".kvs").expect("record extension");
            let (name, generation) = references
                .get(record_id)
                .expect("record is referenced by fixture index");
            let blob = fs::read(&path).expect("fixture record");
            let record_key = derive_labeled_key(
                &master,
                b"kv-drawer:record",
                &[env.as_bytes(), record_id.as_bytes()],
            );
            let aad = format!("kv-drawer:record\0v1\0{env}\0{name}\0{record_id}\0{generation}");
            let plaintext = decrypt(
                &record_key,
                blob.get(4..).expect("record ciphertext"),
                aad.as_bytes(),
            )
            .expect("decrypt fixture record");
            let record: Value = serde_json::from_slice(&plaintext).expect("parse fixture record");
            assert_eq!(
                pyjson::to_vec(&record).expect("serialize fixture record"),
                plaintext.as_slice(),
                "record {record_id}"
            );
            record_count += 1;
        }
    }

    assert_eq!(record_count, 6);
}
