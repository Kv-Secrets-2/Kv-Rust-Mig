use std::ops::Deref;
use std::path::{Component, Path, PathBuf};

use kv_crypto::{
    CryptoError, Identity, Key32, Zeroize, Zeroizing, decrypt_with_nonce, derive_backup_key,
    encrypt_with_nonce, keyfile,
};
use serde_json::{Map, Number, Value, json};
use thiserror::Error;

use crate::{
    BackupEnv, BackupSecret, BackupSecretState, BackupState, BackupVersion, DrawerStore,
    StoreError, fsx, pyjson,
};

pub const MAGIC: &[u8; 8] = b"KVBACKUP";
pub const FORMAT_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 40;
pub const TAG_LEN: usize = 16;
pub const BACKUP_READ_LIMIT: usize = 512 * 1024 * 1024;
pub const DEFAULT_SETTING: [u8; 3] = [17, 8, 1];

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub struct BackupPayload {
    pub created_at: Option<Value>,
    pub made_from: Option<Value>,
    pub state: BackupState,
}

struct ZeroizingJson(Value);

impl Deref for ZeroizingJson {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingJson {
    fn drop(&mut self) {
        zeroize_json_values(&mut self.0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSummary {
    pub name: String,
    pub live: Vec<String>,
    pub removed: Vec<String>,
    pub secrets: usize,
    pub old_versions: usize,
    pub newest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSummary {
    pub created_at: String,
    pub made_from: String,
    pub default_env: String,
    pub history_keep: usize,
    pub environments: Vec<EnvironmentSummary>,
    pub secrets: usize,
    pub versions: usize,
}

pub struct BackupOptions<'a> {
    pub envs: &'a [&'a str],
    pub default_env: &'a str,
    pub history_keep: usize,
    pub passphrase: &'a str,
    pub made_from: &'a str,
    pub setting: [u8; 3],
}

pub fn seal(plaintext: &[u8], passphrase: &str, setting: [u8; 3]) -> Result<Vec<u8>, BackupError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|_| CryptoError::Randomness)?;
    getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&setting);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let key = derive_backup_key(passphrase.as_bytes(), &salt, setting)?;
    let ciphertext = encrypt_with_nonce(&key, &nonce, plaintext, &header);
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

pub fn open_backup_bytes(blob: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    if blob.len() < MAGIC.len() + 1 || blob.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(BackupError::Message("not a kv backup file".into()));
    }
    let version = blob[MAGIC.len()];
    if version != FORMAT_VERSION {
        return Err(BackupError::Message(format!(
            "backup file version {version} is not supported by this kv (it reads version {FORMAT_VERSION})"
        )));
    }
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(BackupError::Message("the backup file is cut short".into()));
    }
    let setting: [u8; 3] = blob[MAGIC.len() + 1..MAGIC.len() + 4]
        .try_into()
        .expect("backup header setting has fixed length");
    let salt: [u8; 16] = blob[MAGIC.len() + 4..MAGIC.len() + 20]
        .try_into()
        .expect("backup header salt has fixed length");
    let nonce: [u8; 12] = blob[MAGIC.len() + 20..HEADER_LEN]
        .try_into()
        .expect("backup header nonce has fixed length");
    let key =
        derive_backup_key(passphrase.as_bytes(), &salt, setting).map_err(|error| match error {
            CryptoError::Header(message) => BackupError::Message(format!(
                "the backup file's key setting is not accepted: {message}"
            )),
            other => BackupError::Crypto(other),
        })?;
    decrypt_with_nonce(&key, &nonce, &blob[HEADER_LEN..], &blob[..HEADER_LEN]).map_err(|error| {
        match error {
            CryptoError::Auth => BackupError::Message(
                "wrong passphrase, or the backup file is damaged or was changed".into(),
            ),
            other => BackupError::Crypto(other),
        }
    })
}

pub fn read_backup_file(path: impl AsRef<Path>) -> Result<Vec<u8>, BackupError> {
    let path = path.as_ref();
    match fsx::read_regular_limit(path, "backup file", BACKUP_READ_LIMIT) {
        Ok(bytes) => Ok(bytes),
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Err(
            BackupError::Message(format!("backup file not found: {}", path.display())),
        ),
        Err(StoreError::Structure(_)) => Err(BackupError::Message(
            "the backup file must be a regular file, not a link".into(),
        )),
        Err(error) => Err(BackupError::Message(format!(
            "cannot read the backup file: {error}"
        ))),
    }
}

pub fn parse_payload(plaintext: &[u8]) -> Result<BackupPayload, BackupError> {
    let data = ZeroizingJson(
        serde_json::from_slice(plaintext)
            .map_err(|_| BackupError::Message("the backup's contents are not readable".into()))?,
    );
    let Some(object) = data.as_object() else {
        return Err(BackupError::Message(
            "the backup's contents are not a kv backup of this version".into(),
        ));
    };
    let version_valid = match object.get("version") {
        Some(Value::Bool(true)) => true,
        Some(Value::Number(number)) => {
            number.as_u64() == Some(u64::from(FORMAT_VERSION))
                || number.as_f64() == Some(f64::from(FORMAT_VERSION))
        }
        _ => false,
    };
    if object.get("format").and_then(Value::as_str) != Some("kv-backup") || !version_valid {
        return Err(BackupError::Message(
            "the backup's contents are not a kv backup of this version".into(),
        ));
    }
    let keep = object
        .get("history_keep")
        .and_then(Value::as_u64)
        .filter(|keep| *keep <= 100)
        .ok_or_else(|| BackupError::Message("the backup's history setting is invalid".into()))?
        as usize;
    let env_values = object
        .get("environments")
        .and_then(Value::as_array)
        .filter(|envs| !envs.is_empty())
        .ok_or_else(|| BackupError::Message("the backup holds no environment".into()))?;
    let mut envs = Vec::with_capacity(env_values.len());
    let mut seen_envs = std::collections::HashSet::new();
    for env_value in env_values {
        let env_obj = env_value.as_object().ok_or_else(|| {
            BackupError::Message("the backup's environment list is invalid".into())
        })?;
        let secret_values = env_obj
            .get("secrets")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                BackupError::Message("the backup's environment list is invalid".into())
            })?;
        let name = text(env_obj.get("name"), "environment name")?;
        crate::envname::validate_env_name(name)
            .map_err(|_| BackupError::Message("the backup names an invalid environment".into()))?;
        if !seen_envs.insert(name.to_owned()) {
            return Err(BackupError::Message(
                "the backup names an environment twice".into(),
            ));
        }
        let mut secrets = Vec::with_capacity(secret_values.len());
        let mut seen_secrets = std::collections::HashSet::new();
        for secret_value in secret_values {
            let secret_obj = secret_value.as_object().ok_or_else(|| {
                BackupError::Message("the backup's secret list is invalid".into())
            })?;
            let state = match secret_obj.get("state").and_then(Value::as_str) {
                Some("live") => BackupSecretState::Live,
                Some("removed") => BackupSecretState::Removed,
                _ => {
                    return Err(BackupError::Message(
                        "the backup's secret list is invalid".into(),
                    ));
                }
            };
            let secret_name = text(secret_obj.get("name"), "secret name")?;
            if !seen_secrets.insert(secret_name.to_owned()) {
                return Err(BackupError::Message(
                    "the backup names a secret twice".into(),
                ));
            }
            let version_values = secret_obj
                .get("versions")
                .and_then(Value::as_array)
                .filter(|versions| !versions.is_empty() && versions.len() <= 101)
                .ok_or_else(|| {
                    BackupError::Message("the backup's version list is invalid".into())
                })?;
            let mut versions = Vec::with_capacity(version_values.len());
            let mut previous = None;
            for version_value in version_values {
                let version_obj = version_value.as_object().ok_or_else(|| {
                    BackupError::Message("the backup's version list is invalid".into())
                })?;
                let value = version_obj
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        BackupError::Message("the backup's version list is invalid".into())
                    })?;
                let number = version_obj
                    .get("version")
                    .and_then(Value::as_u64)
                    .filter(|number| *number >= 1)
                    .ok_or_else(|| {
                        BackupError::Message("the backup's version numbers are invalid".into())
                    })?;
                if previous.is_some_and(|previous| number >= previous) {
                    return Err(BackupError::Message(
                        "the backup's version numbers are invalid".into(),
                    ));
                }
                let updated = text(version_obj.get("updated"), "version date")?;
                previous = Some(number);
                versions.push(BackupVersion {
                    version: number,
                    updated: updated.to_owned(),
                    value: Zeroizing::new(value.to_owned()),
                });
            }
            let removed_at = if state == BackupSecretState::Removed {
                secret_obj
                    .get("removed_at")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            } else {
                None
            };
            secrets.push(BackupSecret {
                name: secret_name.to_owned(),
                state,
                removed_at,
                versions,
            });
        }
        envs.push(BackupEnv {
            name: name.to_owned(),
            secrets,
        });
    }
    let default_env = object
        .get("default_env")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BackupError::Message("the backup's default environment is not in it".into())
        })?
        .to_owned();
    if !seen_envs.contains(default_env.as_str()) {
        return Err(BackupError::Message(
            "the backup's default environment is not in it".into(),
        ));
    }
    let names = envs.iter().map(|env| env.name.clone()).collect::<Vec<_>>();
    crate::envname::validate_environment_registry(&names, &default_env)
        .map_err(|_| BackupError::Message("the backup's environment names are ambiguous".into()))?;
    let created_at = object.get("created_at").cloned();
    let made_from = object.get("made_from").cloned();
    Ok(BackupPayload {
        created_at,
        made_from,
        state: BackupState {
            environments: envs,
            default_env,
            history_keep: keep,
        },
    })
}

pub fn payload_bytes(
    state: &BackupState,
    made_from: &str,
    created_at: &str,
) -> Result<Vec<u8>, BackupError> {
    let mut root = Map::new();
    root.insert("created_at".into(), Value::String(created_at.to_owned()));
    root.insert(
        "default_env".into(),
        Value::String(state.default_env.clone()),
    );
    root.insert(
        "environments".into(),
        environment_values(&state.environments),
    );
    root.insert("format".into(), Value::String("kv-backup".into()));
    root.insert(
        "history_keep".into(),
        Value::Number(Number::from(state.history_keep)),
    );
    root.insert("made_from".into(), Value::String(made_from.to_owned()));
    root.insert(
        "version".into(),
        Value::Number(Number::from(FORMAT_VERSION)),
    );
    let mut value = Value::Object(root);
    let encoded = pyjson::to_vec(&value);
    zeroize_json_values(&mut value);
    encoded.map_err(BackupError::from)
}

pub fn make_backup(
    store: &DrawerStore,
    envs: &[&str],
    default_env: &str,
    history_keep: usize,
    passphrase: &str,
    path: impl AsRef<Path>,
    made_from: &str,
) -> Result<BackupSummary, BackupError> {
    make_backup_with_setting(
        store,
        path,
        BackupOptions {
            envs,
            default_env,
            history_keep,
            passphrase,
            made_from,
            setting: DEFAULT_SETTING,
        },
    )
}

pub fn make_backup_with_setting(
    store: &DrawerStore,
    path: impl AsRef<Path>,
    options: BackupOptions<'_>,
) -> Result<BackupSummary, BackupError> {
    let path = path.as_ref();
    check_destination(store, path)?;
    let state = store.backup_state(options.envs, options.default_env, options.history_keep)?;
    make_backup_from_state_unchecked(
        path,
        state,
        options.passphrase,
        options.made_from,
        options.setting,
    )
}

pub fn make_backup_from_state(
    store: &DrawerStore,
    path: impl AsRef<Path>,
    state: BackupState,
    passphrase: &str,
    made_from: &str,
    setting: [u8; 3],
) -> Result<BackupSummary, BackupError> {
    let path = path.as_ref();
    check_destination(store, path)?;
    make_backup_from_state_unchecked(path, state, passphrase, made_from, setting)
}

fn make_backup_from_state_unchecked(
    path: &Path,
    state: BackupState,
    passphrase: &str,
    made_from: &str,
    setting: [u8; 3],
) -> Result<BackupSummary, BackupError> {
    let created_at = stamp_now();
    let plaintext = Zeroizing::new(payload_bytes(&state, made_from, &created_at)?);
    parse_payload(&plaintext)?;
    let blob = seal(&plaintext, passphrase, setting)?;
    if blob.len() > BACKUP_READ_LIMIT {
        return Err(BackupError::Message(format!(
            "this vault's backup would be {} MiB, more than kv reads back ({} MiB); nothing was written",
            blob.len() / (1024 * 1024),
            BACKUP_READ_LIMIT / (1024 * 1024)
        )));
    }
    match fsx::write_atomic_limit(path, &blob, true, BACKUP_READ_LIMIT, "backup file") {
        Ok(()) => {}
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(BackupError::Message(format!(
                "{} already exists; a backup never overwrites a file",
                path.display()
            )));
        }
        Err(error) => return Err(BackupError::Store(error)),
    }
    let written = open_backup_bytes(&read_backup_file(path)?, passphrase)?;
    if written.as_slice() != plaintext.as_slice() {
        return Err(BackupError::Message(
            "the written backup file did not verify".into(),
        ));
    }
    parse_payload(&written)?;
    Ok(summary(&state, &created_at, made_from))
}

pub fn check_destination(store: &DrawerStore, path: &Path) -> Result<(), BackupError> {
    let absolute = absolute_path(path)?;
    let secrets_dir = absolute_path(store.secrets_dir())?;
    if path_is_within(&absolute, &secrets_dir) {
        return Err(BackupError::Message(
            "a backup file cannot go inside the vault's .secrets folder".into(),
        ));
    }
    if fsx::strictly_present(&absolute)? {
        return Err(BackupError::Message(format!(
            "{} already exists; a backup never overwrites a file",
            path.display()
        )));
    }
    let parent = absolute.parent().ok_or_else(|| {
        BackupError::Message(format!("the folder for {} does not exist", path.display()))
    })?;
    let file_name = absolute.file_name().ok_or_else(|| {
        BackupError::Message(format!("the folder for {} does not exist", path.display()))
    })?;
    let resolved_parent = std::fs::canonicalize(parent).map_err(|_| {
        BackupError::Message(format!("the folder for {} does not exist", path.display()))
    })?;
    if !resolved_parent.is_dir() {
        return Err(BackupError::Message(format!(
            "the folder for {} does not exist",
            path.display()
        )));
    }
    let resolved_secrets = std::fs::canonicalize(store.secrets_dir()).map_err(StoreError::Io)?;
    if path_is_within(&resolved_parent.join(file_name), &resolved_secrets) {
        return Err(BackupError::Message(
            "a backup file cannot go inside the vault's .secrets folder".into(),
        ));
    }
    Ok(())
}

pub fn check_restore_target(target: impl AsRef<Path>) -> Result<PathBuf, BackupError> {
    let path = absolute_path(target.as_ref())?;
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(BackupError::Message(format!(
                    "{} is not a new folder; a restore goes into a new folder only",
                    path.display()
                )));
            }
            if std::fs::read_dir(&path)
                .map_err(StoreError::Io)?
                .next()
                .is_some()
            {
                return Err(BackupError::Message(format!(
                    "{} is not empty; a restore goes into a new folder only",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                BackupError::Message(format!("the folder {} does not exist", path.display()))
            })?;
            let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| {
                BackupError::Message(format!("the folder {} does not exist", parent.display()))
            })?;
            if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
                return Err(BackupError::Message(format!(
                    "the folder {} does not exist",
                    parent.display()
                )));
            }
        }
        Err(error) => return Err(BackupError::Store(StoreError::Io(error))),
    }
    Ok(path)
}

pub fn restore_backup(
    payload: BackupPayload,
    passphrase: &str,
    target: impl AsRef<Path>,
) -> Result<crate::config::Vault, BackupError> {
    crate::envname::validate_environment_registry(
        &payload
            .state
            .environments
            .iter()
            .map(|env| env.name.clone())
            .collect::<Vec<_>>(),
        &payload.state.default_env,
    )
    .map_err(|_| {
        BackupError::Message("the backup's environment names are invalid or ambiguous".into())
    })?;
    if passphrase.is_empty() {
        return Err(BackupError::Message(
            "passphrase is required for new vaults".into(),
        ));
    }
    let root = check_restore_target(target)?;
    match std::fs::create_dir(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(BackupError::Store(StoreError::Io(error))),
    }
    check_restore_target(&root)?;
    fsx::ensure_private_dir(&root)?;
    let root = std::fs::canonicalize(&root).map_err(StoreError::Io)?;
    let secrets = root.join(".secrets");
    fsx::ensure_private_dir(&secrets)?;
    let gitignore = b"# kv \xe2\x80\x94 encrypted secrets management\n# The key file must NEVER be committed\nkey\nrun_grants.json\napproval_signing_key\ncapability_tokens.json\napproval_requests.json\npolicy_requests.json\nstorage.lock\n\n# Encrypted secret data may be committed only while the key remains private\n!*.enc\n!*.kvi\n!*.kvs\n!drawers/\n!drawers/**\n\n# Configuration and its owner approval are local authority, never shared\n/config.json\n/config-authority\n/vault-marker\n\n# Local migration recovery material is encrypted but history-bearing\nmigration-backups/\n\n# Stable writer lock and private atomic-write residue are never versioned\n/config.lock\n/.kv-write-*.tmp\n/key-config.pending\n";
    fsx::write_atomic_limit(
        &secrets.join(".gitignore"),
        gitignore,
        true,
        64 * 1024 * 1024,
        "vault ignore file",
    )?;

    let mut master_bytes = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(master_bytes.as_mut())
        .map_err(|_| BackupError::Crypto(CryptoError::Randomness))?;
    let master = Key32::new(*master_bytes);
    let mut owner_seed = Zeroizing::new([0u8; 32]);
    let mut local_approval_id = Zeroizing::new([0u8; 16]);
    getrandom::getrandom(owner_seed.as_mut())
        .map_err(|_| BackupError::Crypto(CryptoError::Randomness))?;
    getrandom::getrandom(local_approval_id.as_mut())
        .map_err(|_| BackupError::Crypto(CryptoError::Randomness))?;
    let identity = Identity::new(master, *owner_seed, *local_approval_id);
    #[cfg(unix)]
    let location = {
        use std::os::unix::ffi::OsStrExt;
        root.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let location = root.to_string_lossy().as_bytes().to_vec();
    let key_blob = keyfile::wrap_v4(&identity, passphrase.as_bytes(), &location, None)?;
    let store_master = Key32::new(*identity.master_key.as_bytes());
    fsx::write_atomic_limit(
        &secrets.join("key"),
        &key_blob,
        true,
        64 * 1024 * 1024,
        "key file",
    )?;

    let initial = json!({
        "version":1,
        "created":crate::config::timestamp_now(),
        "default_env":"dev",
        "environments":["dev"],
        "cipher":"chacha20-poly1305",
        "storage":{"format":"drawers"},
        "security":{"passphrase":true,"totp":false,"approval_mode":"unset"},
        "broker_policy":{"http":{
            "openai":{"origin":"https://api.openai.com","secret_name":"OPENAI_API_KEY","rules":[]},
            "anthropic":{"origin":"https://api.anthropic.com","secret_name":"ANTHROPIC_API_KEY","rules":[]},
            "google":{"origin":"https://generativelanguage.googleapis.com","secret_name":"GOOGLE_API_KEY","rules":[]},
            "github":{"origin":"https://api.github.com","secret_name":"GITHUB_TOKEN","rules":[]},
            "google-cloud":{"origin":"https://www.googleapis.com","secret_name":"GOOGLE_CLOUD_API_KEY","rules":[]}
        }}
    });
    let config_bytes = pyjson::to_vec_indent2_ascii(&initial)?;
    fsx::write_atomic_limit(
        &secrets.join("config.json"),
        &config_bytes,
        true,
        16 * 1024 * 1024,
        "config file",
    )?;
    fsx::ensure_private_dir(&secrets.join("drawers"))?;

    let store = DrawerStore::open(&secrets, store_master);
    let vault = crate::config::Vault::new(&root, store, crate::config::NoApprovals);
    vault.restore_snapshot(
        &payload.state.environments,
        &payload.state.default_env,
        payload.state.history_keep,
    )?;
    Ok(vault)
}

fn path_is_within(path: &Path, folder: &Path) -> bool {
    let mut path_components = path.components();
    folder.components().all(|folder_component| {
        path_components
            .next()
            .is_some_and(|path_component| same_path_component(path_component, folder_component))
    })
}

#[cfg(windows)]
fn same_path_component(left: Component<'_>, right: Component<'_>) -> bool {
    left.as_os_str().to_string_lossy().to_lowercase()
        == right.as_os_str().to_string_lossy().to_lowercase()
}

#[cfg(not(windows))]
fn same_path_component(left: Component<'_>, right: Component<'_>) -> bool {
    left == right
}

fn absolute_path(path: &Path) -> Result<PathBuf, BackupError> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(StoreError::Io)?.join(path)
    };
    let mut absolute = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                absolute.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                absolute.pop();
            }
        }
    }
    Ok(absolute)
}

fn text<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a str, BackupError> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| BackupError::Message(format!("the backup's {what} is invalid")))
}

fn environment_values(environments: &[BackupEnv]) -> Value {
    Value::Array(
        environments
            .iter()
            .map(|env| {
                let mut value = Map::new();
                value.insert("name".into(), Value::String(env.name.clone()));
                value.insert(
                    "secrets".into(),
                    Value::Array(
                        env.secrets
                            .iter()
                            .map(|secret| {
                                let mut item = Map::new();
                                item.insert("name".into(), Value::String(secret.name.clone()));
                                if secret.state == BackupSecretState::Removed {
                                    item.insert(
                                        "removed_at".into(),
                                        secret
                                            .removed_at
                                            .as_ref()
                                            .map(|removed| Value::String(removed.clone()))
                                            .unwrap_or(Value::Null),
                                    );
                                }
                                item.insert(
                                    "state".into(),
                                    Value::String(match secret.state {
                                        BackupSecretState::Live => "live".into(),
                                        BackupSecretState::Removed => "removed".into(),
                                    }),
                                );
                                item.insert(
                                    "versions".into(),
                                    Value::Array(
                                        secret
                                            .versions
                                            .iter()
                                            .map(|version| {
                                                let mut version_value = Map::new();
                                                version_value.insert(
                                                    "updated".into(),
                                                    Value::String(version.updated.clone()),
                                                );
                                                version_value.insert(
                                                    "value".into(),
                                                    Value::String(version.value.to_string()),
                                                );
                                                version_value.insert(
                                                    "version".into(),
                                                    Value::Number(Number::from(version.version)),
                                                );
                                                Value::Object(version_value)
                                            })
                                            .collect(),
                                    ),
                                );
                                Value::Object(item)
                            })
                            .collect(),
                    ),
                );
                Value::Object(value)
            })
            .collect(),
    )
}

fn summary(state: &BackupState, created_at: &str, made_from: &str) -> BackupSummary {
    let mut environments = Vec::with_capacity(state.environments.len());
    let mut secret_count = 0;
    let mut version_count = 0;
    for env in &state.environments {
        let live = env
            .secrets
            .iter()
            .filter(|secret| secret.state == BackupSecretState::Live)
            .map(|secret| secret.name.clone())
            .collect::<Vec<_>>();
        let removed = env
            .secrets
            .iter()
            .filter(|secret| secret.state == BackupSecretState::Removed)
            .map(|secret| secret.name.clone())
            .collect::<Vec<_>>();
        let dates = env
            .secrets
            .iter()
            .flat_map(|secret| secret.versions.iter().map(|version| &version.updated))
            .cloned()
            .collect::<Vec<_>>();
        secret_count += env.secrets.len();
        version_count += env
            .secrets
            .iter()
            .map(|secret| secret.versions.len())
            .sum::<usize>();
        environments.push(EnvironmentSummary {
            name: env.name.clone(),
            live,
            removed,
            secrets: env.secrets.len(),
            old_versions: env
                .secrets
                .iter()
                .map(|secret| secret.versions.len().saturating_sub(1))
                .sum(),
            newest: dates.into_iter().max(),
        });
    }
    BackupSummary {
        created_at: created_at.to_owned(),
        made_from: made_from.to_owned(),
        default_env: state.default_env.clone(),
        history_keep: state.history_keep,
        environments,
        secrets: secret_count,
        versions: version_count,
    }
}

fn stamp_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn zeroize_json_values(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_values(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_values(value);
            }
        }
        _ => {}
    }
}
