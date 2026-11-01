mod common;

use std::collections::BTreeMap;
use std::fs;

use kv_crypto::{decrypt, derive_labeled_key};
use kv_store::DrawerStore;
use serde_json::Value;

use common::{TestDir, copy_fixture_secrets, fixture_expected, fixture_master_key, key_copy};

#[test]
fn fixture_vault_matches_python_expected_values_and_generation() {
    let expected = fixture_expected();
    let master = fixture_master_key();
    let temp = TestDir::new("fixture");
    let project_root = temp.project_root("copy");
    let secrets_dir = copy_fixture_secrets(&project_root);
    let store = DrawerStore::open(&secrets_dir, key_copy(&master));

    for env in ["dev", "prod"] {
        assert_eq!(
            store.env_id(env),
            expected["env_id"][env].as_str().expect("expected env id")
        );
        let actual: BTreeMap<String, String> = store
            .list_secrets(env)
            .expect("list fixture secrets")
            .into_iter()
            .map(|(name, value)| (name, value.to_string()))
            .collect();
        let expected_secrets: BTreeMap<String, String> =
            serde_json::from_value(expected["live_secrets"][env].clone())
                .expect("expected secrets map");
        assert_eq!(actual, expected_secrets);
    }

    let removed_name = expected["removed_name"].as_str().expect("removed name");
    assert!(
        !store
            .list_secret_names("dev")
            .expect("list fixture names")
            .iter()
            .any(|name| name == removed_name)
    );
    assert!(
        store
            .get_secret("dev", removed_name)
            .expect("removed fixture secret")
            .is_none()
    );

    let env_id = store.env_id("dev");
    let index_path = secrets_dir
        .join("drawers")
        .join("envs")
        .join(env_id)
        .join("index.kvi");
    let blob = fs::read(index_path).expect("fixture index");
    let index_key = derive_labeled_key(&master, b"kv-drawer:index", &[b"dev"]);
    let plaintext =
        decrypt(&index_key, &blob[4..], b"kv-drawer:index:v1:dev").expect("decrypt fixture index");
    let index: Value = serde_json::from_slice(&plaintext).expect("parse fixture index");
    assert_eq!(
        index["secrets"]["API_KEY"]["generation"].as_u64(),
        expected["api_key_generation"].as_u64()
    );
}
