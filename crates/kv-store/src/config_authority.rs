use std::fs;
use std::path::{Path, PathBuf};

use kv_crypto::{Key32, decrypt, derive_labeled_key, encrypt, keyfile};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{StoreError, config, fsx, pyjson, vault_origin};

pub const FILE: &str = "config-authority";
pub const LABEL: &[u8] = b"kv-config-authority:v1";
const RECORD_REFUSAL: &str = "The approved config record cannot be verified here; restore the vault at its approved location from a trusted backup.";

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Internal(String),
}

impl From<StoreError> for AuthorityError {
    fn from(error: StoreError) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<std::io::Error> for AuthorityError {
    fn from(error: std::io::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<vault_origin::VaultOriginError> for AuthorityError {
    fn from(error: vault_origin::VaultOriginError) -> Self {
        Self::Refused(error.to_string())
    }
}

impl From<kv_crypto::CryptoError> for AuthorityError {
    fn from(error: kv_crypto::CryptoError) -> Self {
        Self::Internal(error.to_string())
    }
}

fn invalid_authority() -> AuthorityError {
    AuthorityError::Refused(
        "Config authority is invalid; restore a valid config and run kv vault approve-config."
            .into(),
    )
}

pub fn canonical(value: &Value) -> Result<Vec<u8>, AuthorityError> {
    if contains_non_finite(value) {
        return Err(invalid_authority());
    }
    pyjson::to_vec_python_compact(value, true).map_err(|_| invalid_authority())
}

fn contains_non_finite(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(contains_non_finite),
        Value::Object(values) => values.values().any(contains_non_finite),
        Value::Number(number) => {
            number.is_f64() && number.as_f64().is_none_or(|value| !value.is_finite())
        }
        _ => false,
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>, AuthorityError> {
    value.as_object().ok_or_else(invalid_authority)
}

pub fn authority_state(config_value: &Value) -> Result<Value, AuthorityError> {
    let result: Result<Value, AuthorityError> = (|| {
        let config = object(config_value)?;
        let security_value = config.get("security").cloned().unwrap_or_else(|| json!({}));
        let security = object(&security_value)?;
        let mut remote = config.get("remote").cloned().unwrap_or_else(|| json!({}));
        if let Some(remote_object) = remote.as_object_mut() {
            remote_object.remove("last_sync");
            if let Some(drawer) = remote_object
                .get_mut("drawer_sync")
                .and_then(Value::as_object_mut)
            {
                for field in [
                    "last_revision",
                    "last_manifest_hash",
                    "last_local_snapshot_hash",
                    "last_pushed_at",
                    "synced_at",
                ] {
                    drawer.remove(field);
                }
                if drawer.is_empty() {
                    remote_object.remove("drawer_sync");
                }
            }
        }

        let default_env = config
            .get("default_env")
            .cloned()
            .unwrap_or_else(|| Value::String("dev".into()));
        let providers = config
            .get("providers")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let broker_policy = config.get("broker_policy").cloned().unwrap_or(Value::Null);
        let mut security_state = Map::new();
        for (name, default) in [
            ("kv_run_policy", json!("blocklist")),
            ("allowed_commands", json!([])),
            ("network_commands", json!([])),
            ("approval_mode", json!("unset")),
        ] {
            security_state.insert(name.into(), security.get(name).cloned().unwrap_or(default));
        }
        let state = json!({
            "default_env": default_env,
            "remote": remote,
            "providers": providers,
            "broker_policy": broker_policy,
            "security": Value::Object(security_state)
        });
        canonical(&state)?;
        Ok(state)
    })();
    result.map_err(|_| invalid_authority())
}

pub fn changed_parts(old: Option<&Value>, new: &Value) -> Result<Vec<String>, AuthorityError> {
    let Some(old) = old else {
        return Ok(vec!["no owner-approved fingerprint".into()]);
    };
    let old = object(old).map_err(|_| invalid_authority())?;
    let new = object(new).map_err(|_| invalid_authority())?;
    let mut changed = Vec::new();
    for name in ["providers", "broker_policy", "default_env", "remote"] {
        if canonical(old.get(name).unwrap_or(&Value::Null))?
            != canonical(new.get(name).unwrap_or(&Value::Null))?
        {
            changed.push(name.into());
        }
    }
    let old_security = old
        .get("security")
        .and_then(Value::as_object)
        .ok_or_else(invalid_authority)?;
    let new_security = new
        .get("security")
        .and_then(Value::as_object)
        .ok_or_else(invalid_authority)?;
    for name in [
        "kv_run_policy",
        "allowed_commands",
        "network_commands",
        "approval_mode",
    ] {
        if canonical(old_security.get(name).unwrap_or(&Value::Null))?
            != canonical(new_security.get(name).unwrap_or(&Value::Null))?
        {
            changed.push(name.into());
        }
    }
    Ok(changed)
}

fn authority_path(root: &Path) -> PathBuf {
    root.join(".secrets").join(FILE)
}

fn key_path(root: &Path) -> PathBuf {
    root.join(".secrets").join("key")
}

fn read_authority(root: &Path) -> Result<Option<Vec<u8>>, AuthorityError> {
    match fsx::read_regular(&authority_path(root), "config authority record") {
        Ok(bytes) => Ok(Some(bytes)),
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn canonical_location(root: &Path) -> Result<Vec<u8>, AuthorityError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        Ok(fs::canonicalize(root)?.as_os_str().as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        let path = fs::canonicalize(root)?;
        let text = path.to_str().ok_or_else(|| {
            AuthorityError::Internal("vault path cannot be encoded (lone surrogate)".into())
        })?;
        Ok(text.as_bytes().to_vec())
    }
}

fn aad(root: &Path, local: &Value) -> Result<Vec<u8>, AuthorityError> {
    let local_id = local
        .get("local_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthorityError::Internal("local vault identity is invalid".into()))?;
    let location = hex(&canonical_location(root)?);
    Ok(format!(
        "{}:{}:{}",
        String::from_utf8_lossy(LABEL),
        location,
        local_id
    )
    .into_bytes())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn open_record(
    root: &Path,
    master_key: &Key32,
    blob: Option<&[u8]>,
) -> Result<Option<Value>, AuthorityError> {
    let local = vault_origin::require_local(root)?;
    let Some(digest) = local.get("config_sha256") else {
        return Ok(None);
    };
    if digest.is_null() || digest.as_str() == Some("") {
        return Ok(None);
    }
    let expected_hash = digest
        .as_str()
        .ok_or_else(|| AuthorityError::Refused(RECORD_REFUSAL.into()))?;
    let Some(blob) = blob else {
        return Ok(None);
    };
    if hex(&Sha256::digest(blob)) != expected_hash {
        return Err(AuthorityError::Refused(RECORD_REFUSAL.into()));
    }
    let key = derive_labeled_key(master_key, LABEL, &[]);
    let associated_data =
        aad(root, &local).map_err(|_| AuthorityError::Refused(RECORD_REFUSAL.into()))?;
    let plain = decrypt(&key, blob, &associated_data)
        .map_err(|_| AuthorityError::Refused(RECORD_REFUSAL.into()))?;
    let record: Value = serde_json::from_slice(&plain)
        .map_err(|_| AuthorityError::Refused(RECORD_REFUSAL.into()))?;
    let state = record
        .get("authority")
        .cloned()
        .ok_or_else(|| AuthorityError::Refused(RECORD_REFUSAL.into()))?;
    let keys = state
        .as_object()
        .map(|object| {
            let mut names = object.keys().map(String::as_str).collect::<Vec<_>>();
            names.sort_unstable();
            names
        })
        .unwrap_or_default();
    let mut expected_keys = vec![
        "broker_policy",
        "default_env",
        "providers",
        "remote",
        "security",
    ];
    expected_keys.sort_unstable();
    let canonical_state =
        canonical(&state).map_err(|_| AuthorityError::Refused(RECORD_REFUSAL.into()))?;
    let valid = record.get("version").and_then(Value::as_u64) == Some(1)
        && record.get("sha256").and_then(Value::as_str)
            == Some(hex(&Sha256::digest(canonical_state)).as_str())
        && keys == expected_keys;
    if !valid {
        return Err(AuthorityError::Refused(RECORD_REFUSAL.into()));
    }
    Ok(Some(state))
}

pub fn open(
    root: impl AsRef<Path>,
    master_key: &Key32,
    blob: Option<&[u8]>,
) -> Result<Option<Value>, AuthorityError> {
    open_record(root.as_ref(), master_key, blob)
}

fn is_key_wrapped(root: &Path, strict: bool) -> Result<bool, AuthorityError> {
    match fsx::read_regular_limit(&key_path(root), "key file", 64 * 1024 * 1024) {
        Ok(bytes) => Ok(bytes.len() >= 4 && &bytes[..3] == b"KVW"),
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) if strict => Err(error.into()),
        Err(_) => Ok(false),
    }
}

fn verify_approved(
    root: &Path,
    master_key: &Key32,
    config_snapshot: &config::ConfigSnapshot,
) -> Result<(), AuthorityError> {
    if !is_key_wrapped(root, true)? {
        return Err(AuthorityError::Refused(
            "Config authority requires a passphrase-protected vault; create one with kv init."
                .into(),
        ));
    }
    let old = open_record(root, master_key, read_authority(root)?.as_deref())?;
    let new = authority_state(&config_snapshot.value)?;
    let changed = changed_parts(old.as_ref(), &new)?;
    if !changed.is_empty() {
        return Err(AuthorityError::Refused(format!(
            "Config authority changed ({}); run kv vault approve-config at your terminal before unlocking.",
            changed.join(", ")
        )));
    }
    Ok(())
}

pub fn require_approved(
    root: impl AsRef<Path>,
    master_key: &Key32,
) -> Result<config::ConfigSnapshot, AuthorityError> {
    let root = root.as_ref();
    let snapshot = config::load_config(root)?;
    verify_approved(root, master_key, &snapshot)?;
    Ok(snapshot)
}

pub fn require_current(
    root: impl AsRef<Path>,
    approved_config: &Value,
    master_key: &Key32,
) -> Result<(), AuthorityError> {
    let root = root.as_ref();
    let current = config::load_config(root)?;
    let changed = changed_parts(
        Some(&authority_state(approved_config)?),
        &authority_state(&current.value)?,
    )?;
    if !changed.is_empty() {
        return Err(AuthorityError::Refused(format!(
            "Config authority changed ({}); run kv vault approve-config and restart the daemon.",
            changed.join(", ")
        )));
    }
    verify_approved(root, master_key, &current)
}

/// Approves the current authority without conducting the owner's terminal review.
/// Callers must perform that review themselves before invoking this function.
pub fn approve_config_unattended(
    root: impl AsRef<Path>,
    master_key: &Key32,
) -> Result<(), AuthorityError> {
    let root = root.as_ref();
    let local = vault_origin::require_local(root)?;
    let snapshot = config::load_config(root)?;
    let key_file = fsx::read_regular(&key_path(root), "key file")?;
    let header = keyfile::parse_v4_header(&key_file).map_err(|_| {
        AuthorityError::Internal(
            "Config approval requires a passphrase-protected owner key; create a vault with kv init."
                .into(),
        )
    })?;
    let before = read_authority(root)?;
    let authority = authority_state(&snapshot.value)?;
    config::config_write_guard(root, &snapshot, || {
        let current_key = fsx::read_regular(&key_path(root), "key file")?;
        let current_record =
            read_authority(root).map_err(|error| StoreError::ConfigConflict(error.to_string()))?;
        if current_key != key_file || current_record != before {
            return Err(StoreError::ConfigConflict(
                "Vault approval state changed; review it again with kv vault approve-config."
                    .into(),
            ));
        }
        let record = json!({
            "version":1,
            "authority":authority,
            "sha256":hex(&Sha256::digest(canonical(&authority).map_err(|error| {
                StoreError::ConfigConflict(error.to_string())
            })?))
        });
        let key = derive_labeled_key(master_key, LABEL, &[]);
        let plaintext =
            canonical(&record).map_err(|error| StoreError::ConfigConflict(error.to_string()))?;
        let encrypted = encrypt(
            &key,
            &plaintext,
            &aad(root, &local).map_err(|error| StoreError::ConfigConflict(error.to_string()))?,
        );
        fsx::write_atomic(&authority_path(root), &encrypted, false)?;
        vault_origin::record_config_approval(root, &local, &hex(&Sha256::digest(&encrypted)))
            .map_err(|error| StoreError::ConfigConflict(error.to_string()))?;
        Ok(())
    })?;
    let _ = header;
    Ok(())
}
