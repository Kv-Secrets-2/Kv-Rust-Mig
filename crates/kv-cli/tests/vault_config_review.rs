//! Owner config approval must bind the exact bytes the owner reviewed.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/owner.rs"]
mod owner;

use owner::Scratch;
use std::fs;
use std::path::Path;

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    for item in fs::read_dir(source).unwrap() {
        let item = item.unwrap();
        let target = destination.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_dir(&item.path(), &target);
        } else {
            fs::copy(item.path(), target).unwrap();
        }
    }
}

#[test]
fn approval_rejects_config_changed_after_review_and_preserves_prior_approval() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new("config-review");
    let root = scratch.proj();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v0.4.0/vaults");
    copy_dir(&fixture.join("basic/.secrets"), &root.join(".secrets"));
    fs::set_permissions(root.join(".secrets"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    kv_store::vault_origin::record_created(&root).unwrap();
    let expected: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.join("basic.expected.json")).unwrap()).unwrap();
    let passphrase = expected["passphrase"].as_str().unwrap();
    let blob = fs::read(root.join(".secrets/key")).unwrap();
    let identity = kv_crypto::keyfile::unwrap_v4(&blob, passphrase.as_bytes()).unwrap();
    let master = kv_crypto::Key32::new(*identity.master_key.as_bytes());

    kv_store::config_authority::approve_config_unattended(&root, &master).unwrap();
    let approved_before = kv_store::config_authority::approved_authority(&root, &master).unwrap();
    let approval_bytes_before = fs::read(root.join(".secrets/config-authority")).unwrap();
    let review = kv_store::config_authority::review_config(&root).unwrap();
    let config = root.join(".secrets/config.json");
    let original = fs::read(&config).unwrap();
    kv_store::config::config_transaction(&root, |value| {
        value["providers"]["changed-after-review"] =
            serde_json::json!({"base_url":"https://example.invalid","secret_name":"X"});
        Ok(())
    })
    .unwrap();
    let error = kv_store::config_authority::approve_reviewed(&root, &master, &review)
        .unwrap_err()
        .to_string();
    assert!(error.contains("changed"), "{error}");
    assert_eq!(
        kv_store::config_authority::approved_authority(&root, &master).unwrap(),
        approved_before
    );
    assert_eq!(
        fs::read(root.join(".secrets/config-authority")).unwrap(),
        approval_bytes_before
    );

    fs::write(&config, &original).unwrap();
    let formatting_review = kv_store::config_authority::review_config(&root).unwrap();
    let mut whitespace_only = original.clone();
    whitespace_only.extend_from_slice(b"\n\n");
    fs::write(&config, whitespace_only).unwrap();
    let error = kv_store::config_authority::approve_reviewed(&root, &master, &formatting_review)
        .unwrap_err()
        .to_string();
    assert!(error.contains("changed"), "{error}");
    assert_eq!(
        kv_store::config_authority::approved_authority(&root, &master).unwrap(),
        approved_before
    );
    assert_eq!(
        fs::read(root.join(".secrets/config-authority")).unwrap(),
        approval_bytes_before
    );
    fs::write(&config, original).unwrap();
}
