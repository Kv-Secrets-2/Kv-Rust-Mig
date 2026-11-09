mod common;

use std::fs::{self, File};

use kv_crypto::Key32;
use kv_store::DrawerStore;
use kv_store::backup::{self, BackupError, FORMAT_VERSION, HEADER_LEN, MAGIC};
use serde_json::{Value, json};

use common::TestDir;

const PASSPHRASE: &str = "stage2c test passphrase";

fn payload(environments: Vec<Value>, default_env: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "format":"kv-backup",
        "version":FORMAT_VERSION,
        "created_at":"2026-01-02T03:04:05Z",
        "made_from":"/source",
        "default_env":default_env,
        "history_keep":2,
        "environments":environments
    }))
    .unwrap()
}

fn env(name: &str, secrets: Vec<Value>) -> Value {
    json!({"name":name,"secrets":secrets})
}

fn secret(name: &str, versions: Vec<Value>) -> Value {
    json!({"name":name,"state":"live","versions":versions})
}

fn version(number: u64) -> Value {
    json!({"version":number,"updated":"2026-01-02T03:04:05Z","value":"value"})
}

fn simple_payload() -> Vec<u8> {
    payload(vec![env("dev", vec![])], "dev")
}

fn make_test_backup(
    store: &DrawerStore,
    path: impl AsRef<std::path::Path>,
) -> Result<backup::BackupSummary, BackupError> {
    backup::make_backup_with_setting(
        store,
        path,
        backup::BackupOptions {
            envs: &["dev"],
            default_env: "dev",
            history_keep: 0,
            passphrase: PASSPHRASE,
            made_from: "/source",
            setting: [14, 8, 1],
        },
    )
}

#[test]
fn backup_headers_reject_truncation_mutations_and_authentication_failure() {
    let plaintext = simple_payload();
    let valid = backup::seal(&plaintext, PASSPHRASE, [14, 8, 1]).unwrap();
    assert_eq!(&valid[..MAGIC.len()], MAGIC);
    assert_eq!(valid.len(), HEADER_LEN + plaintext.len() + 16);
    assert_eq!(
        backup::open_backup_bytes(&valid, PASSPHRASE)
            .unwrap()
            .as_slice(),
        plaintext
    );

    for length in 0..HEADER_LEN + 16 {
        assert!(
            backup::open_backup_bytes(&valid[..length], PASSPHRASE).is_err(),
            "truncation length {length}"
        );
    }

    let mut bad_magic = valid.clone();
    bad_magic[0] ^= 0xff;
    assert!(backup::open_backup_bytes(&bad_magic, PASSPHRASE).is_err());

    let mut bad_version = valid.clone();
    bad_version[MAGIC.len()] = FORMAT_VERSION + 1;
    assert!(backup::open_backup_bytes(&bad_version, PASSPHRASE).is_err());

    for (offset, invalid) in [(1, 13), (2, 0), (3, 0)] {
        let mut bad_setting = valid.clone();
        bad_setting[MAGIC.len() + offset] = invalid;
        assert!(backup::open_backup_bytes(&bad_setting, PASSPHRASE).is_err());
    }

    let mut bad_tag = valid;
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 0xff;
    assert!(matches!(
        backup::open_backup_bytes(&bad_tag, PASSPHRASE),
        Err(BackupError::Message(message))
            if message == "wrong passphrase, or the backup file is damaged or was changed"
    ));
}

#[test]
fn backup_file_reader_rejects_links_and_oversized_files() {
    let temp = TestDir::new("backup-reader");
    let target = temp.path().join("target.kvb");
    fs::write(&target, b"not a backup").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let link = temp.path().join("link.kvb");
        symlink(&target, &link).unwrap();
        assert!(backup::read_backup_file(&link).is_err());
    }

    let oversized = temp.path().join("oversized.kvb");
    File::create(&oversized)
        .unwrap()
        .set_len((backup::BACKUP_READ_LIMIT + 1) as u64)
        .unwrap();
    assert!(backup::read_backup_file(&oversized).is_err());
}

#[test]
fn parse_payload_rejects_duplicate_names_versions_and_invalid_registry() {
    let duplicated_environments = payload(vec![env("dev", vec![]), env("dev", vec![])], "dev");
    assert!(backup::parse_payload(&duplicated_environments).is_err());

    let duplicated_secrets = payload(
        vec![env(
            "dev",
            vec![
                secret("TOKEN", vec![version(1)]),
                secret("TOKEN", vec![version(1)]),
            ],
        )],
        "dev",
    );
    assert!(backup::parse_payload(&duplicated_secrets).is_err());

    let ascending_versions = payload(
        vec![env(
            "dev",
            vec![secret("TOKEN", vec![version(1), version(2)])],
        )],
        "dev",
    );
    assert!(backup::parse_payload(&ascending_versions).is_err());
    let duplicate_versions = payload(
        vec![env(
            "dev",
            vec![secret("TOKEN", vec![version(2), version(2)])],
        )],
        "dev",
    );
    assert!(backup::parse_payload(&duplicate_versions).is_err());

    let too_many = (1..=102).rev().map(version).collect::<Vec<_>>();
    let too_many_versions = payload(vec![env("dev", vec![secret("TOKEN", too_many)])], "dev");
    assert!(backup::parse_payload(&too_many_versions).is_err());

    let invalid_default = payload(vec![env("dev", vec![])], "prod");
    assert!(backup::parse_payload(&invalid_default).is_err());

    let aliased_environments = payload(vec![env("Dev", vec![]), env("dev", vec![])], "dev");
    assert!(backup::parse_payload(&aliased_environments).is_err());
}

#[test]
fn parse_payload_reports_unreadable_and_unknown_payloads_without_panicking() {
    assert!(backup::parse_payload(b"\xff").is_err());
    assert!(backup::parse_payload(br#"{"format":"other","version":1}"#).is_err());
    assert!(backup::parse_payload(&Value::Null.to_string().into_bytes()).is_err());
}

#[test]
fn backup_creation_refuses_existing_and_in_vault_destinations() {
    let temp = TestDir::new("backup-destination");
    let secrets_dir = temp.path().join(".secrets");
    fs::create_dir(&secrets_dir).unwrap();
    let master = Key32::new(std::array::from_fn(|index| index as u8));
    let store = DrawerStore::open(&secrets_dir, master);
    store.set_secret("dev", "TOKEN", "value", 0).unwrap();

    let inside = secrets_dir.join("inside.kvb");
    assert!(matches!(
        make_test_backup(&store, &inside),
        Err(BackupError::Message(message))
            if message == "a backup file cannot go inside the vault's .secrets folder"
    ));

    let existing = temp.path().join("existing.kvb");
    fs::write(&existing, b"existing").unwrap();
    assert!(matches!(
        make_test_backup(&store, &existing),
        Err(BackupError::Message(message)) if message.contains("already exists")
    ));
}

#[cfg(unix)]
#[test]
fn backup_creation_resolves_symlinked_destination_parents() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("backup-symlink-destination");
    let secrets_dir = temp.path().join(".secrets");
    fs::create_dir(&secrets_dir).unwrap();
    let master = Key32::new(std::array::from_fn(|index| index as u8));
    let store = DrawerStore::open(&secrets_dir, master);
    store.set_secret("dev", "TOKEN", "value", 0).unwrap();
    let link = temp.path().join("secrets-link");
    symlink(&secrets_dir, &link).unwrap();

    assert!(matches!(
        make_test_backup(&store, link.join("backup.kvb")),
        Err(BackupError::Message(message))
            if message == "a backup file cannot go inside the vault's .secrets folder"
    ));
}
