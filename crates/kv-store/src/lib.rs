#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use kv_crypto::{
    CryptoError, Key32, Zeroize, Zeroizing, decrypt, derive_labeled_key, encrypt, keyed_blake2b_128,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

pub mod backup;
pub mod envname;
pub mod fsx;
pub mod pyjson;

const DRAWER_INDEX_MAGIC: &[u8; 3] = b"KVI";
const DRAWER_RECORD_MAGIC: &[u8; 3] = b"KVS";
const DRAWER_FORMAT_VERSION: u8 = 1;
const HISTORY_KEEP_MAX: usize = 100;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("corrupt drawer data: {0}")]
    Corrupt(String),
    #[error("unsupported drawer format version {0}")]
    Unsupported(u8),
    #[error("unsafe drawer structure: {0}")]
    Structure(String),
    #[error("{what} is too large ({len} bytes)")]
    TooLarge { what: String, len: usize },
    #[error("invalid environment name: {0}")]
    InvalidName(String),
    #[error("'{key}' has no history in {env}")]
    NoHistory { env: String, key: String },
    #[error("version {0} is not kept")]
    VersionNotKept(u64),
    #[error("'{key}' is not removed in {env}")]
    NotRemoved { env: String, key: String },
    #[error("{0}")]
    CopyChanged(String),
    #[error("environment '{0}' does not exist")]
    EnvMissing(String),
    #[error("environment {0} is not empty; a restore needs a new vault")]
    NotEmpty(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CopyOptions {
    pub keep_existing: bool,
    pub expect_replaced: Option<Vec<String>>,
    pub expect_keep: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CopyRegistration {
    pub source_registered: bool,
    pub destination_registered: bool,
    pub create_destination: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyResult {
    pub copied: usize,
    pub replaced: Vec<String>,
    pub kept: Vec<String>,
    pub created: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupSecretState {
    Live,
    Removed,
}

pub struct BackupVersion {
    pub version: u64,
    pub updated: String,
    pub value: Zeroizing<String>,
}

pub struct BackupSecret {
    pub name: String,
    pub state: BackupSecretState,
    pub removed_at: Option<String>,
    pub versions: Vec<BackupVersion>,
}

pub struct BackupEnv {
    pub name: String,
    pub secrets: Vec<BackupSecret>,
}

pub struct BackupState {
    pub environments: Vec<BackupEnv>,
    pub default_env: String,
    pub history_keep: usize,
}

pub fn plan_copy(
    src_env: &str,
    dst_env: &str,
    src: &BTreeMap<String, String>,
    dst: &BTreeMap<String, String>,
    options: &CopyOptions,
    registration: CopyRegistration,
) -> Result<(BTreeMap<String, String>, CopyResult), StoreError> {
    if !registration.source_registered {
        return Err(StoreError::EnvMissing(src_env.to_owned()));
    }
    if !registration.destination_registered && !registration.create_destination {
        return Err(StoreError::EnvMissing(dst_env.to_owned()));
    }
    let differ: Vec<String> = src
        .iter()
        .filter(|(name, value)| dst.get(*name).is_some_and(|current| current != *value))
        .map(|(name, _)| name.clone())
        .collect();
    let (writes, replaced, kept) = if options.keep_existing {
        (
            src.iter()
                .filter(|(name, _)| !dst.contains_key(*name))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            Vec::new(),
            differ,
        )
    } else {
        if let Some(expected) = &options.expect_replaced {
            let expected: HashSet<&str> = expected.iter().map(String::as_str).collect();
            if differ.iter().any(|name| !expected.contains(name.as_str())) {
                return Err(StoreError::CopyChanged(format!(
                    "environment '{dst_env}' changed while you were deciding; nothing was copied, run the copy again"
                )));
            }
        }
        (
            src.iter()
                .filter(|(name, value)| dst.get(*name) != Some(*value))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            differ,
            Vec::new(),
        )
    };
    let result = CopyResult {
        copied: src.len() - kept.len(),
        replaced,
        kept,
        created: !registration.destination_registered,
    };
    Ok((writes, result))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionState {
    Current,
    Removed { removed: Option<String> },
    Old,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionInfo {
    pub version: u64,
    pub updated: Option<String>,
    pub state: VersionState,
}

pub struct DrawerStore {
    secrets_dir: PathBuf,
    master: Key32,
    #[cfg(test)]
    fail_before_index_save: std::sync::atomic::AtomicBool,
}

impl DrawerStore {
    pub fn open(secrets_dir: impl Into<PathBuf>, master: Key32) -> Self {
        Self {
            secrets_dir: secrets_dir.into(),
            master,
            #[cfg(test)]
            fail_before_index_save: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn secrets_dir(&self) -> &Path {
        &self.secrets_dir
    }

    pub fn env_id(&self, env: &str) -> String {
        let key = derive_labeled_key(&self.master, b"kv-drawer:env-id", &[]);
        format!("e_{}", hex(&keyed_blake2b_128(&key, env.as_bytes())))
    }

    pub fn get_secret(
        &self,
        env: &str,
        key: &str,
    ) -> Result<Option<Zeroizing<String>>, StoreError> {
        envname::validate_env_name(env)?;
        let index = self.load_index(env)?;
        let Some(entry) = index
            .get("secrets")
            .and_then(Value::as_object)
            .and_then(|secrets| secrets.get(key))
        else {
            return Ok(None);
        };
        if !is_live_entry(entry) {
            return Ok(None);
        }
        self.load_current_record(env, key, entry).map(Some)
    }

    pub fn list_secret_names(&self, env: &str) -> Result<Vec<String>, StoreError> {
        envname::validate_env_name(env)?;
        let index = self.load_index(env)?;
        let secrets = index
            .get("secrets")
            .and_then(Value::as_object)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        Ok(secrets
            .iter()
            .filter(|(_, entry)| is_live_entry(entry))
            .map(|(name, _)| name.clone())
            .collect())
    }

    pub fn list_secrets(&self, env: &str) -> Result<Vec<(String, Zeroizing<String>)>, StoreError> {
        envname::validate_env_name(env)?;
        let index = self.load_index(env)?;
        let secrets = index
            .get("secrets")
            .and_then(Value::as_object)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        let mut values = Vec::new();
        for (name, entry) in secrets {
            if is_live_entry(entry) {
                values.push((name.clone(), self.load_current_record(env, name, entry)?));
            }
        }
        Ok(values)
    }

    pub fn set_secret(
        &self,
        env: &str,
        key: &str,
        value: &str,
        keep: usize,
    ) -> Result<u64, StoreError> {
        envname::validate_env_name(env)?;
        validate_keep(keep)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        self.set_locked(env, key, value, keep)
            .map(|(generation, _)| generation)
    }

    fn set_locked(
        &self,
        env: &str,
        key: &str,
        value: &str,
        keep: usize,
    ) -> Result<(u64, Vec<Value>), StoreError> {
        let mut index = self.load_index(env)?;
        let old_entry = index
            .get("secrets")
            .and_then(Value::as_object)
            .and_then(|secrets| secrets.get(key))
            .map(effective_old_entry)
            .transpose()?
            .unwrap_or_else(empty_object);
        let (new_entry, generation, dropped) =
            self.changed_entry(env, key, value, &old_entry, keep)?;
        let secrets = index
            .get_mut("secrets")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        secrets.insert(key.to_owned(), new_entry);
        self.save_index(env, &mut index)?;
        self.wipe_records(env, &dropped)?;
        Ok((generation, dropped))
    }

    pub fn remove_secret(&self, env: &str, key: &str, keep: usize) -> Result<bool, StoreError> {
        envname::validate_env_name(env)?;
        validate_keep(keep)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let mut index = self.load_index(env)?;
        let old_entry = index
            .get("secrets")
            .and_then(Value::as_object)
            .and_then(|secrets| secrets.get(key))
            .cloned();
        let Some(old_entry) = old_entry.filter(is_live_entry) else {
            return Ok(false);
        };
        let (replacement, dropped) = self.removed_entry(&old_entry, keep)?;
        let secrets = index
            .get_mut("secrets")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        let new_entry = match replacement {
            Some(entry) => entry,
            None => forgotten_entry(&old_entry)?,
        };
        secrets.insert(key.to_owned(), new_entry);
        self.save_index(env, &mut index)?;
        self.wipe_records(env, &dropped)?;
        Ok(true)
    }

    /// Caller performs the reserved-name and registered-environment checks.
    pub fn list_versions(&self, env: &str, key: &str) -> Result<Vec<VersionInfo>, StoreError> {
        envname::validate_env_name(env)?;
        let (_index, entry) = self.entry_for_history(env, key)?;
        let version = entry
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| StoreError::Corrupt("drawer generation is invalid".into()))?;
        let removed = entry.get("state").and_then(Value::as_str) == Some("deleted");
        let state = if removed {
            VersionState::Removed {
                removed: entry
                    .get("deleted")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            }
        } else {
            VersionState::Current
        };
        let mut versions = vec![VersionInfo {
            version,
            updated: entry
                .get("updated")
                .and_then(Value::as_str)
                .map(str::to_owned),
            state,
        }];
        if let Some(history) = entry.get("history").and_then(Value::as_array) {
            for reference in history {
                if !reference.is_object() {
                    return Err(StoreError::Corrupt(
                        "drawer history reference is not an object".into(),
                    ));
                }
                let version = reference
                    .get("generation")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| StoreError::Corrupt("drawer generation is invalid".into()))?;
                versions.push(VersionInfo {
                    version,
                    updated: reference
                        .get("updated")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    state: VersionState::Old,
                });
            }
        }
        Ok(versions)
    }

    /// Caller performs the reserved-name and registered-environment checks.
    pub fn get_version(
        &self,
        env: &str,
        key: &str,
        version: u64,
    ) -> Result<Zeroizing<String>, StoreError> {
        envname::validate_env_name(env)?;
        let (_index, entry) = self.entry_for_history(env, key)?;
        self.version_value(env, key, &entry, version)
    }

    /// Caller checks registration/reserved status and supplies the effective history keep.
    pub fn restore_version(
        &self,
        env: &str,
        key: &str,
        version: u64,
        keep: usize,
    ) -> Result<u64, StoreError> {
        envname::validate_env_name(env)?;
        validate_keep(keep)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let (_index, entry) = self.entry_for_history(env, key)?;
        let value = self.version_value(env, key, &entry, version)?;
        self.set_locked(env, key, &value, keep)
            .map(|(generation, _)| generation)
    }

    /// Caller performs the reserved-name and registered-environment checks.
    pub fn undo_remove(&self, env: &str, key: &str) -> Result<u64, StoreError> {
        envname::validate_env_name(env)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let (mut index, entry) = self.entry_for_history(env, key)?;
        if entry.get("state").and_then(Value::as_str) != Some("deleted") {
            return Err(StoreError::NotRemoved {
                env: env.to_owned(),
                key: key.to_owned(),
            });
        }
        let _verified = self.load_current_record(env, key, &entry)?;
        let generation = entry
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| StoreError::Corrupt("drawer generation is invalid".into()))?;
        let mut replacement = entry
            .as_object()
            .cloned()
            .ok_or_else(|| StoreError::Corrupt("drawer entry is not an object".into()))?;
        replacement.insert("state".into(), Value::String("live".into()));
        replacement.remove("deleted");
        index
            .get_mut("secrets")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?
            .insert(key.to_owned(), Value::Object(replacement));
        self.save_index(env, &mut index)?;
        Ok(generation)
    }

    /// Caller checks registration/reserved status; this operation always writes with keep zero.
    pub fn replace_and_forget(
        &self,
        env: &str,
        key: &str,
        value: &str,
    ) -> Result<usize, StoreError> {
        envname::validate_env_name(env)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let index = self.load_index(env)?;
        let old_entry = index
            .get("secrets")
            .and_then(Value::as_object)
            .and_then(|secrets| secrets.get(key))
            .map(effective_old_entry)
            .transpose()?
            .unwrap_or_else(empty_object);
        let max_generation = generation_from_entry(&old_entry)?;
        let orphans = self.orphans_of(env, &index, key, max_generation)?;
        let (_generation, dropped) = self.set_locked(env, key, value, 0)?;
        let count = dropped.len();
        let refs = orphans.into_iter().map(Value::String).collect::<Vec<_>>();
        self.wipe_records(env, &refs)?;
        Ok(count)
    }

    /// Caller performs reserved-name and registered-environment checks.
    pub fn forget_history(&self, env: &str, key: &str) -> Result<usize, StoreError> {
        envname::validate_env_name(env)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let keys = BTreeSet::from([key.to_owned()]);
        self.forget_locked(env, Some(&keys))
    }

    /// Caller performs reserved-name and registered-environment checks.
    pub fn forget_env_history(&self, env: &str) -> Result<usize, StoreError> {
        envname::validate_env_name(env)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        self.forget_locked(env, None)
    }

    /// Caller validates reserved/registered status and supplies all live and deleted envs.
    pub fn forget_envs_history(&self, envs: &[&str]) -> Result<usize, StoreError> {
        for env in envs {
            envname::validate_env_name(env)?;
        }
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let mut total = 0usize;
        for env in envs {
            total += self.forget_locked(env, None)?;
        }
        Ok(total)
    }

    /// Caller validates envs, supplies live/deleted names, and persists the setting after.
    pub fn prune_envs(&self, envs: &[&str], keep: usize) -> Result<usize, StoreError> {
        validate_keep(keep)?;
        for env in envs {
            envname::validate_env_name(env)?;
        }
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let mut total = 0usize;
        for env in envs {
            total += self.prune_env_locked(env, keep)?;
        }
        Ok(total)
    }

    /// Caller supplies and validates the environment without configuration lookups.
    pub fn unreferenced_record_count(&self, env: &str) -> Result<usize, StoreError> {
        envname::validate_env_name(env)?;
        let index = self.load_index(env)?;
        Ok(self.unreferenced_record_ids(env, &index)?.len())
    }

    /// The caller validates the registry and decides whether the environment is registered.
    pub(crate) fn index_present(&self, env: &str) -> Result<bool, StoreError> {
        envname::validate_env_name(env)?;
        fsx::strictly_present(&self.index_path_for_env(env))
    }

    /// The caller holds the storage lock after a drawer-directory rename.
    pub(crate) fn sync_envs_dir(&self) -> Result<(), StoreError> {
        fsx::sync_envs_dir(&self.secrets_dir)
    }

    /// The caller checks registration and approval references before clearing the tree.
    pub fn clear_env_tree(&self, env: &str) -> Result<(), StoreError> {
        envname::validate_env_name(env)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        fsx::clear_env_tree(&self.secrets_dir, &self.env_id(env))
    }

    /// The caller checks both names, handles registration, and holds the storage lock here.
    pub fn copy_env_tree(&self, old: &str, new: &str) -> Result<(), StoreError> {
        envname::validate_env_name(old)?;
        envname::validate_env_name(new)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        if !self.index_present(old)? {
            return Ok(());
        }
        let mut index = self.load_index(old)?;
        self.ensure_env_tree(new)?;
        let secrets = index
            .get_mut("secrets")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        for (name, entry) in secrets {
            let has_current =
                value_is_truthy(entry.get("current_record_id").unwrap_or(&Value::Null));
            let current = has_current.then(|| current_ref(entry));
            let object = entry.as_object_mut().ok_or_else(|| {
                StoreError::Corrupt(format!("drawer index entry is invalid for {old}/{name}"))
            })?;
            if let Some(reference) = current {
                let record_hash = self.recrypt_record(old, new, name, &reference)?;
                object.insert("record_hash".into(), Value::String(record_hash));
            }
            if let Some(history) = object.get_mut("history").and_then(Value::as_array_mut) {
                for reference in history {
                    if !reference.is_object() {
                        return Err(StoreError::Corrupt(
                            "drawer history reference is not an object".into(),
                        ));
                    }
                    let record_hash = self.recrypt_record(old, new, name, reference)?;
                    reference
                        .as_object_mut()
                        .ok_or_else(|| {
                            StoreError::Corrupt("drawer history reference is not an object".into())
                        })?
                        .insert("record_hash".into(), Value::String(record_hash));
                }
            }
        }
        self.save_index(new, &mut index)?;
        self.sync_envs_dir()
    }

    /// Caller supplies validated registered names and the effective history setting.
    pub fn backup_state(
        &self,
        envs: &[&str],
        default_env: &str,
        history_keep: usize,
    ) -> Result<BackupState, StoreError> {
        validate_keep(history_keep)?;
        let names = envs.iter().map(|env| (*env).to_owned()).collect::<Vec<_>>();
        envname::validate_environment_registry(&names, default_env)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let mut environments = Vec::with_capacity(envs.len());
        for env in envs {
            let index = self.load_index(env)?;
            let secrets_map = index
                .get("secrets")
                .and_then(Value::as_object)
                .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
            let mut secrets = Vec::new();
            for (name, entry) in secrets_map {
                if !entry.is_object()
                    || !value_is_truthy(entry.get("current_record_id").unwrap_or(&Value::Null))
                {
                    continue;
                }
                let removed = entry.get("state").and_then(Value::as_str) == Some("deleted");
                if !removed && !is_live_entry(entry) {
                    continue;
                }
                let mut references = vec![current_ref(entry)];
                if let Some(history) = entry.get("history").and_then(Value::as_array) {
                    references.extend(history.iter().cloned());
                }
                let mut versions = Vec::with_capacity(references.len());
                for reference in references {
                    let (version, updated, value) =
                        self.load_record_ref_info(env, name, &reference)?;
                    versions.push(BackupVersion {
                        version,
                        updated,
                        value,
                    });
                }
                secrets.push(BackupSecret {
                    name: name.clone(),
                    state: if removed {
                        BackupSecretState::Removed
                    } else {
                        BackupSecretState::Live
                    },
                    removed_at: if removed {
                        entry
                            .get("deleted")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    } else {
                        None
                    },
                    versions,
                });
            }
            environments.push(BackupEnv {
                name: (*env).to_owned(),
                secrets,
            });
        }
        Ok(BackupState {
            environments,
            default_env: default_env.to_owned(),
            history_keep,
        })
    }

    /// Caller registers every environment and persists the effective keep setting first.
    pub fn restore_snapshot(
        &self,
        environments: &[BackupEnv],
        keep: usize,
    ) -> Result<usize, StoreError> {
        validate_keep(keep)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let mut written = 0usize;
        for env in environments {
            envname::validate_env_name(&env.name)?;
            let mut index = self.load_index(&env.name)?;
            let secrets = index
                .get("secrets")
                .and_then(Value::as_object)
                .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
            if !secrets.is_empty() {
                return Err(StoreError::NotEmpty(env.name.clone()));
            }
            let mut restored = Map::new();
            for secret in &env.secrets {
                if secret.versions.is_empty() {
                    return Err(StoreError::Corrupt("backup secret has no versions".into()));
                }
                let removed = secret.state == BackupSecretState::Removed;
                if removed && keep == 0 {
                    continue;
                }
                let allowed = if removed { keep - 1 } else { keep } + 1;
                let versions = secret.versions.iter().take(allowed).collect::<Vec<_>>();
                let mut records = Vec::with_capacity(versions.len());
                for version in &versions {
                    let (record, _) = self.write_secret_record(
                        &env.name,
                        &secret.name,
                        &version.value,
                        &empty_object(),
                        Some(version.version),
                        Some(&version.updated),
                    )?;
                    let record_id = record.get("current_record_id").cloned().ok_or_else(|| {
                        StoreError::Corrupt("restored record has no record id".into())
                    })?;
                    let mut reference = Map::new();
                    reference.insert("record_id".into(), record_id);
                    reference.insert(
                        "generation".into(),
                        record.get("generation").cloned().unwrap_or(Value::Null),
                    );
                    reference.insert(
                        "record_hash".into(),
                        record.get("record_hash").cloned().unwrap_or(Value::Null),
                    );
                    reference.insert(
                        "updated".into(),
                        record.get("updated").cloned().unwrap_or(Value::Null),
                    );
                    records.push((record, Value::Object(reference)));
                    written += 1;
                }
                let (mut entry, _) = records
                    .first()
                    .cloned()
                    .ok_or_else(|| StoreError::Corrupt("backup secret has no versions".into()))?;
                entry
                    .as_object_mut()
                    .ok_or_else(|| StoreError::Corrupt("restored entry is invalid".into()))?
                    .insert(
                        "created".into(),
                        Value::String(versions.last().expect("non-empty versions").updated.clone()),
                    );
                if records.len() > 1 {
                    entry
                        .as_object_mut()
                        .ok_or_else(|| StoreError::Corrupt("restored entry is invalid".into()))?
                        .insert(
                            "history".into(),
                            Value::Array(
                                records
                                    .into_iter()
                                    .skip(1)
                                    .map(|(_, reference)| reference)
                                    .collect(),
                            ),
                        );
                }
                if removed {
                    let object = entry
                        .as_object_mut()
                        .ok_or_else(|| StoreError::Corrupt("restored entry is invalid".into()))?;
                    object.insert("state".into(), Value::String("deleted".into()));
                    let updated = object
                        .get("updated")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    object.insert(
                        "deleted".into(),
                        Value::String(secret.removed_at.as_deref().unwrap_or(&updated).to_owned()),
                    );
                }
                restored.insert(secret.name.clone(), entry);
            }
            index
                .get_mut("secrets")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?
                .extend(restored);
            self.save_index(&env.name, &mut index)?;
        }
        Ok(written)
    }

    /// Caller checks source existence/registration and performs destination registration first.
    pub fn copy_env_checked(
        &self,
        src: &str,
        dst: &str,
        options: CopyOptions,
        keep: usize,
        dst_registered: bool,
    ) -> Result<CopyResult, StoreError> {
        envname::validate_env_name(src)?;
        envname::validate_env_name(dst)?;
        validate_keep(keep)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let src_index = self.load_index(src)?;
        let dst_index = self.load_index(dst)?;
        let src_values = self.live_values(src, &src_index)?;
        let dst_values = self.live_values(dst, &dst_index)?;
        let (writes, result) = plan_copy(
            src,
            dst,
            &src_values,
            &dst_values,
            &options,
            CopyRegistration {
                source_registered: true,
                destination_registered: dst_registered,
                create_destination: true,
            },
        )?;
        if options
            .expect_keep
            .is_some_and(|expected| !result.replaced.is_empty() && (keep > 0) != (expected > 0))
        {
            return Err(StoreError::CopyChanged(
                "the history setting changed while you were deciding; nothing was copied, run the copy again"
                    .into(),
            ));
        }
        let mut index = dst_index;
        let mut dropped = Vec::new();
        for (name, value) in writes {
            let old_entry = index
                .get("secrets")
                .and_then(Value::as_object)
                .and_then(|secrets| secrets.get(&name))
                .map(effective_old_entry)
                .transpose()?
                .unwrap_or_else(empty_object);
            let (entry, _, old_refs) = self.changed_entry(dst, &name, &value, &old_entry, keep)?;
            index
                .get_mut("secrets")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?
                .insert(name, entry);
            dropped.extend(old_refs);
        }
        self.save_index(dst, &mut index)?;
        self.wipe_records(dst, &dropped)?;
        Ok(result)
    }

    pub fn save_env(
        &self,
        env: &str,
        secrets: &BTreeMap<String, String>,
        keep: usize,
    ) -> Result<(), StoreError> {
        envname::validate_env_name(env)?;
        validate_keep(keep)?;
        let _lock = fsx::lock_storage(&self.secrets_dir)?;
        let mut index = self.load_index(env)?;
        let old_secrets = index
            .get("secrets")
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        let mut final_secrets = Map::new();
        let mut dropped = Vec::new();

        for (name, value) in secrets {
            let old_entry = old_secrets
                .get(name)
                .map(effective_old_entry)
                .transpose()?
                .unwrap_or_else(empty_object);
            let (entry, _, old_refs) = self.changed_entry(env, name, value, &old_entry, keep)?;
            final_secrets.insert(name.clone(), entry);
            dropped.extend(old_refs);
        }

        for (name, entry) in &old_secrets {
            if final_secrets.contains_key(name) {
                continue;
            }
            if is_live_entry(entry) {
                let (replacement, old_refs) = self.removed_entry(entry, keep)?;
                dropped.extend(old_refs);
                final_secrets.insert(
                    name.clone(),
                    match replacement {
                        Some(entry) => entry,
                        None => forgotten_entry(entry)?,
                    },
                );
            } else {
                final_secrets.insert(name.clone(), entry.clone());
            }
        }

        let secrets_object = index
            .get_mut("secrets")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        *secrets_object = final_secrets;
        self.save_index(env, &mut index)?;
        self.wipe_records(env, &dropped)
    }

    fn load_index(&self, env: &str) -> Result<Value, StoreError> {
        let env_id = self.env_id(env);
        let directories = [
            self.secrets_dir.join("drawers"),
            self.secrets_dir.join("drawers").join("envs"),
            self.secrets_dir.join("drawers").join("envs").join(&env_id),
        ];
        for directory in &directories {
            if !fsx::check_directory(directory)? {
                return Ok(empty_index(env));
            }
        }
        let path = self.index_path_for_id(&env_id);
        if !fsx::strictly_present(&path)? {
            return Ok(empty_index(env));
        }
        let raw = read_drawer_file(&path, "drawer index")?;
        if raw.len() < 4 || raw.get(..3) != Some(DRAWER_INDEX_MAGIC.as_slice()) {
            return Err(StoreError::Corrupt(
                "drawer index has bad magic bytes".into(),
            ));
        }
        let version = raw
            .get(3)
            .copied()
            .ok_or_else(|| StoreError::Corrupt("drawer index header is truncated".into()))?;
        if version != DRAWER_FORMAT_VERSION {
            return Err(StoreError::Unsupported(version));
        }
        let plaintext = decrypt(
            &self.index_key(env),
            raw.get(4..)
                .ok_or_else(|| StoreError::Corrupt("drawer index is truncated".into()))?,
            self.index_aad(env).as_bytes(),
        )?;
        let mut index: Value = serde_json::from_slice(&plaintext)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        validate_index(env, &mut index)?;
        Ok(index)
    }

    fn save_index(&self, env: &str, index: &mut Value) -> Result<(), StoreError> {
        self.ensure_env_tree(env)?;
        let secrets = index
            .get("secrets")
            .and_then(Value::as_object)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        let live_count = secrets
            .values()
            .filter(|entry| is_live_entry(entry))
            .count();
        let mut metadata = Map::new();
        metadata.insert("updated".into(), Value::String(now_iso()));
        metadata.insert(
            "count".into(),
            Value::Number(Number::from(live_count as u64)),
        );

        let object = index
            .as_object_mut()
            .ok_or_else(|| StoreError::Corrupt("drawer index payload must be an object".into()))?;
        object.insert("_meta".into(), Value::Object(metadata));
        object.insert(
            "version".into(),
            Value::Number(Number::from(DRAWER_FORMAT_VERSION)),
        );
        object.insert("env".into(), Value::String(env.to_owned()));

        #[cfg(test)]
        if self
            .fail_before_index_save
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StoreError::Io(io::Error::other(
                "injected failure before index publication",
            )));
        }

        let plaintext = Zeroizing::new(pyjson::to_vec(index)?);
        let encrypted = encrypt(
            &self.index_key(env),
            &plaintext,
            self.index_aad(env).as_bytes(),
        );
        let mut blob = Vec::with_capacity(4 + encrypted.len());
        blob.extend_from_slice(DRAWER_INDEX_MAGIC);
        blob.push(DRAWER_FORMAT_VERSION);
        blob.extend_from_slice(&encrypted);
        fsx::write_atomic(&self.index_path_for_env(env), &blob, false)
    }

    fn live_values(
        &self,
        env: &str,
        index: &Value,
    ) -> Result<BTreeMap<String, String>, StoreError> {
        let secrets = index
            .get("secrets")
            .and_then(Value::as_object)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?;
        let mut values = BTreeMap::new();
        for (name, entry) in secrets {
            if is_live_entry(entry) {
                values.insert(
                    name.clone(),
                    self.load_current_record(env, name, entry)?.to_string(),
                );
            }
        }
        Ok(values)
    }

    fn load_record_ref_info(
        &self,
        env: &str,
        key: &str,
        reference: &Value,
    ) -> Result<(u64, String, Zeroizing<String>), StoreError> {
        let generation = reference
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| StoreError::Corrupt("drawer generation is invalid".into()))?;
        let record_id = reference
            .get("record_id")
            .and_then(Value::as_str)
            .ok_or_else(|| StoreError::Corrupt("drawer index entry has no record id".into()))?;
        let mut record_entry = Map::new();
        record_entry.insert(
            "current_record_id".into(),
            Value::String(record_id.to_owned()),
        );
        record_entry.insert("generation".into(), Value::Number(Number::from(generation)));
        record_entry.insert(
            "record_hash".into(),
            reference.get("record_hash").cloned().unwrap_or(Value::Null),
        );
        let (value, payload_updated) =
            self.load_current_record_info(env, key, &Value::Object(record_entry))?;
        let updated = reference
            .get("updated")
            .and_then(Value::as_str)
            .filter(|updated| !updated.is_empty())
            .or(payload_updated.as_deref())
            .ok_or_else(|| StoreError::Corrupt("drawer record updated value is invalid".into()))?
            .to_owned();
        Ok((generation, updated, value))
    }

    fn recrypt_record(
        &self,
        old: &str,
        new: &str,
        key: &str,
        reference: &Value,
    ) -> Result<String, StoreError> {
        let generation = reference
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| StoreError::Corrupt("drawer generation is invalid".into()))?;
        let record_id = reference
            .get("record_id")
            .and_then(Value::as_str)
            .ok_or_else(|| StoreError::Corrupt("drawer index entry has no record id".into()))?;
        fsx::validate_record_id(record_id)?;
        let expected_hash = reference
            .get("record_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| StoreError::Corrupt("drawer index entry has no record hash".into()))?;
        let source = read_drawer_file(&self.record_path(old, record_id)?, "drawer record")?;
        let actual_hash = sha256_hex(&source);
        if !constant_time_equal(expected_hash.as_bytes(), actual_hash.as_bytes()) {
            return Err(StoreError::Corrupt("drawer record hash mismatch".into()));
        }
        let mut payload = self.decrypt_record_payload(old, key, record_id, generation, &source)?;
        payload
            .as_object_mut()
            .ok_or_else(|| StoreError::Corrupt("drawer record payload is invalid".into()))?
            .insert("env".into(), Value::String(new.to_owned()));
        let serialized = pyjson::to_vec(&payload);
        zeroize_value(&mut payload);
        let plaintext = Zeroizing::new(serialized?);
        let encrypted = encrypt(
            &self.record_key(new, record_id),
            &plaintext,
            self.record_aad(new, key, record_id, generation).as_bytes(),
        );
        let mut blob = Vec::with_capacity(4 + encrypted.len());
        blob.extend_from_slice(DRAWER_RECORD_MAGIC);
        blob.push(DRAWER_FORMAT_VERSION);
        blob.extend_from_slice(&encrypted);
        if blob.len() > fsx::VAULT_FILE_LIMIT {
            return Err(StoreError::TooLarge {
                what: "drawer record".into(),
                len: blob.len(),
            });
        }
        let target = self.record_path(new, record_id)?;
        if fsx::strictly_present(&target)? {
            return Err(StoreError::Structure(format!(
                "{} already exists",
                target.display()
            )));
        }
        match fsx::write_atomic(&target, &blob, true) {
            Ok(()) => {}
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StoreError::Structure(format!(
                    "{} already exists",
                    target.display()
                )));
            }
            Err(error) => return Err(error),
        }
        let verified = read_drawer_file(&target, "drawer record")?;
        let mut verified_payload =
            self.decrypt_record_payload(new, key, record_id, generation, &verified)?;
        let verified_bytes = pyjson::to_vec(&verified_payload);
        zeroize_value(&mut verified_payload);
        let verified_bytes = Zeroizing::new(verified_bytes?);
        if verified_bytes.as_slice() != plaintext.as_slice() {
            return Err(StoreError::Corrupt(
                "drawer record verification failed".into(),
            ));
        }
        Ok(sha256_hex(&verified))
    }

    fn changed_entry(
        &self,
        env: &str,
        key: &str,
        value: &str,
        old_entry: &Value,
        keep: usize,
    ) -> Result<(Value, u64, Vec<Value>), StoreError> {
        let (mut entry, generation) =
            self.write_secret_record(env, key, value, old_entry, None, None)?;
        let mut refs = Vec::new();
        if old_entry
            .get("current_record_id")
            .is_some_and(value_is_truthy)
        {
            refs.push(current_ref(old_entry));
            refs.extend(history_refs(old_entry));
        }
        if let Value::Object(object) = &mut entry {
            let kept: Vec<Value> = refs.iter().take(keep).cloned().collect();
            if !kept.is_empty() {
                object.insert("history".into(), Value::Array(kept));
            }
        }
        let dropped = refs.into_iter().skip(keep).collect();
        Ok((entry, generation, dropped))
    }

    fn removed_entry(
        &self,
        entry: &Value,
        keep: usize,
    ) -> Result<(Option<Value>, Vec<Value>), StoreError> {
        if keep == 0 {
            let mut dropped = old_refs(entry);
            dropped.push(current_ref(entry));
            return Ok((None, dropped));
        }

        let mut replacement = entry
            .as_object()
            .cloned()
            .ok_or_else(|| StoreError::Corrupt("drawer entry is not an object".into()))?;
        replacement.insert("state".into(), Value::String("deleted".into()));
        replacement.insert("deleted".into(), Value::String(now_iso()));
        let history = history_refs(entry);
        let kept: Vec<Value> = history.iter().take(keep - 1).cloned().collect();
        if kept.is_empty() {
            replacement.remove("history");
        } else {
            replacement.insert("history".into(), Value::Array(kept));
        }
        let dropped = history.into_iter().skip(keep - 1).collect();
        Ok((Some(Value::Object(replacement)), dropped))
    }

    fn write_secret_record(
        &self,
        env: &str,
        key: &str,
        value: &str,
        old_entry: &Value,
        generation_override: Option<u64>,
        updated_override: Option<&str>,
    ) -> Result<(Value, u64), StoreError> {
        self.ensure_env_tree(env)?;
        let generation = match generation_override {
            Some(generation) => generation,
            None => generation_from_entry(old_entry)?
                .checked_add(1)
                .ok_or_else(|| StoreError::Corrupt("drawer generation overflow".into()))?,
        };
        let now = updated_override
            .filter(|updated| !updated.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(now_iso);

        for _ in 0..10 {
            let mut id_bytes = [0u8; 32];
            getrandom::getrandom(&mut id_bytes).map_err(|_| {
                StoreError::Io(io::Error::other("operating-system randomness unavailable"))
            })?;
            let record_id = format!("r_{}", hex(&id_bytes));
            fsx::validate_record_id(&record_id)?;
            let path = self.record_path(env, &record_id)?;
            if fsx::strictly_present(&path)? {
                let metadata = std::fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    return Err(StoreError::Structure(format!(
                        "{} must not be a symlink",
                        path.display()
                    )));
                }
                continue;
            }

            let mut record = Map::new();
            record.insert(
                "version".into(),
                Value::Number(Number::from(DRAWER_FORMAT_VERSION)),
            );
            record.insert("env".into(), Value::String(env.to_owned()));
            record.insert("name".into(), Value::String(key.to_owned()));
            record.insert("record_id".into(), Value::String(record_id.clone()));
            record.insert("generation".into(), Value::Number(Number::from(generation)));
            record.insert("updated".into(), Value::String(now.clone()));
            record.insert("value".into(), Value::String(value.to_owned()));
            record.insert("value_type".into(), Value::String("text".into()));
            let mut record_value = Value::Object(record);
            let serialized = pyjson::to_vec(&record_value);
            zeroize_value(&mut record_value);
            let plaintext = Zeroizing::new(serialized?);
            let encrypted = encrypt(
                &self.record_key(env, &record_id),
                &plaintext,
                self.record_aad(env, key, &record_id, generation).as_bytes(),
            );
            let mut blob = Vec::with_capacity(4 + encrypted.len());
            blob.extend_from_slice(DRAWER_RECORD_MAGIC);
            blob.push(DRAWER_FORMAT_VERSION);
            blob.extend_from_slice(&encrypted);
            if blob.len() > fsx::VAULT_FILE_LIMIT {
                return Err(StoreError::TooLarge {
                    what: "drawer record".into(),
                    len: blob.len(),
                });
            }

            match fsx::write_atomic(&path, &blob, true) {
                Ok(()) => {}
                Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(error) => return Err(error),
            }

            let verified_blob = read_drawer_file(&path, "drawer record")?;
            let verified_value =
                self.decrypt_record_value(env, key, &record_id, generation, &verified_blob)?;
            if verified_value.as_str() != value {
                return Err(StoreError::Corrupt(
                    "drawer record verification failed".into(),
                ));
            }

            let created = old_entry
                .get("created")
                .filter(|created| value_is_truthy(created))
                .cloned()
                .unwrap_or_else(|| Value::String(now.clone()));
            let mut entry = Map::new();
            entry.insert("current_record_id".into(), Value::String(record_id));
            entry.insert("state".into(), Value::String("live".into()));
            entry.insert("generation".into(), Value::Number(Number::from(generation)));
            entry.insert(
                "record_hash".into(),
                Value::String(sha256_hex(&verified_blob)),
            );
            entry.insert("created".into(), created);
            entry.insert("updated".into(), Value::String(now));
            entry.insert("value_type".into(), Value::String("text".into()));
            return Ok((Value::Object(entry), generation));
        }
        Err(StoreError::Io(io::Error::other(
            "failed to allocate a unique drawer record id",
        )))
    }

    fn load_current_record(
        &self,
        env: &str,
        key: &str,
        entry: &Value,
    ) -> Result<Zeroizing<String>, StoreError> {
        self.load_current_record_info(env, key, entry)
            .map(|(value, _)| value)
    }

    fn load_current_record_info(
        &self,
        env: &str,
        key: &str,
        entry: &Value,
    ) -> Result<(Zeroizing<String>, Option<String>), StoreError> {
        let record_id = entry
            .get("current_record_id")
            .and_then(Value::as_str)
            .ok_or_else(|| StoreError::Corrupt("drawer index entry has no record id".into()))?;
        fsx::validate_record_id(record_id)?;
        let generation = entry
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                StoreError::Corrupt("drawer index entry has invalid generation".into())
            })?;
        let expected_hash = entry
            .get("record_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| StoreError::Corrupt("drawer index entry has no record hash".into()))?;
        let path = self.record_path(env, record_id)?;
        let record_directories = [
            self.secrets_dir.join("drawers"),
            self.secrets_dir.join("drawers").join("envs"),
            self.env_dir_for_id(&self.env_id(env)),
            self.records_dir_for_id(&self.env_id(env)),
        ];
        for directory in &record_directories {
            if !fsx::check_directory(directory)? {
                return Err(StoreError::Corrupt(
                    "drawer record directory is missing".into(),
                ));
            }
        }
        let raw = read_drawer_file(&path, "drawer record")?;
        let actual_hash = sha256_hex(&raw);
        if !constant_time_equal(expected_hash.as_bytes(), actual_hash.as_bytes()) {
            return Err(StoreError::Corrupt("drawer record hash mismatch".into()));
        }
        let mut payload = self.decrypt_record_payload(env, key, record_id, generation, &raw)?;
        let value = payload
            .get_mut("value")
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .ok_or_else(|| StoreError::Corrupt("drawer record value is invalid".into()))?;
        let updated = payload
            .get("updated")
            .and_then(Value::as_str)
            .map(str::to_owned);
        zeroize_value(&mut payload);
        Ok((Zeroizing::new(value), updated))
    }

    fn decrypt_record_value(
        &self,
        env: &str,
        key: &str,
        record_id: &str,
        generation: u64,
        raw: &[u8],
    ) -> Result<Zeroizing<String>, StoreError> {
        let mut payload = self.decrypt_record_payload(env, key, record_id, generation, raw)?;
        let value = payload
            .get_mut("value")
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .ok_or_else(|| StoreError::Corrupt("drawer record value is invalid".into()))?;
        zeroize_value(&mut payload);
        Ok(Zeroizing::new(value))
    }

    fn decrypt_record_payload(
        &self,
        env: &str,
        key: &str,
        record_id: &str,
        generation: u64,
        raw: &[u8],
    ) -> Result<Value, StoreError> {
        if raw.len() < 4 || raw.get(..3) != Some(DRAWER_RECORD_MAGIC.as_slice()) {
            return Err(StoreError::Corrupt(
                "drawer record has bad magic bytes".into(),
            ));
        }
        let version = raw
            .get(3)
            .copied()
            .ok_or_else(|| StoreError::Corrupt("drawer record header is truncated".into()))?;
        if version != DRAWER_FORMAT_VERSION {
            return Err(StoreError::Unsupported(version));
        }
        let encrypted = raw
            .get(4..)
            .ok_or_else(|| StoreError::Corrupt("drawer record is truncated".into()))?;
        let plaintext = decrypt(
            &self.record_key(env, record_id),
            encrypted,
            self.record_aad(env, key, record_id, generation).as_bytes(),
        )?;
        let mut payload: Value = serde_json::from_slice(&plaintext)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        let valid = payload.get("version").and_then(Value::as_u64)
            == Some(u64::from(DRAWER_FORMAT_VERSION))
            && payload.get("env").and_then(Value::as_str) == Some(env)
            && payload.get("name").and_then(Value::as_str) == Some(key)
            && payload.get("record_id").and_then(Value::as_str) == Some(record_id)
            && payload.get("generation").and_then(Value::as_u64) == Some(generation);
        if !valid {
            zeroize_value(&mut payload);
            return Err(StoreError::Corrupt(
                "drawer record metadata mismatch".into(),
            ));
        }
        Ok(payload)
    }

    fn wipe_records(&self, env: &str, refs: &[Value]) -> Result<(), StoreError> {
        let mut record_ids = Vec::new();
        for reference in refs {
            let value = reference
                .as_object()
                .and_then(|object| object.get("record_id"))
                .unwrap_or(reference);
            let record_id = value
                .as_str()
                .ok_or_else(|| StoreError::Corrupt("invalid drawer record id".into()))?;
            fsx::validate_record_id(record_id)?;
            record_ids.push(record_id.to_owned());
        }
        if record_ids.is_empty() {
            return Ok(());
        }
        let env_id = self.env_id(env);
        for record_id in record_ids {
            fsx::unlink_record(&self.secrets_dir, &env_id, &record_id)?;
        }
        Ok(())
    }

    fn ensure_env_tree(&self, env: &str) -> Result<(), StoreError> {
        let env_id = self.env_id(env);
        for directory in [
            self.secrets_dir.join("drawers"),
            self.secrets_dir.join("drawers").join("envs"),
            self.env_dir_for_id(&env_id),
            self.records_dir_for_id(&env_id),
        ] {
            fsx::ensure_private_dir(&directory)?;
        }
        Ok(())
    }

    fn index_key(&self, env: &str) -> Key32 {
        derive_labeled_key(&self.master, b"kv-drawer:index", &[env.as_bytes()])
    }

    fn record_key(&self, env: &str, record_id: &str) -> Key32 {
        derive_labeled_key(
            &self.master,
            b"kv-drawer:record",
            &[env.as_bytes(), record_id.as_bytes()],
        )
    }

    fn index_aad(&self, env: &str) -> String {
        format!("kv-drawer:index:v{DRAWER_FORMAT_VERSION}:{env}")
    }

    fn record_aad(&self, env: &str, key: &str, record_id: &str, generation: u64) -> String {
        format!(
            "kv-drawer:record\0v{DRAWER_FORMAT_VERSION}\0{env}\0{key}\0{record_id}\0{generation}"
        )
    }

    fn index_path_for_id(&self, env_id: &str) -> PathBuf {
        self.env_dir_for_id(env_id).join("index.kvi")
    }

    fn index_path_for_env(&self, env: &str) -> PathBuf {
        self.index_path_for_id(&self.env_id(env))
    }

    fn env_dir_for_id(&self, env_id: &str) -> PathBuf {
        self.secrets_dir.join("drawers").join("envs").join(env_id)
    }

    fn records_dir_for_id(&self, env_id: &str) -> PathBuf {
        self.env_dir_for_id(env_id).join("records")
    }

    fn record_path(&self, env: &str, record_id: &str) -> Result<PathBuf, StoreError> {
        fsx::validate_record_id(record_id)?;
        Ok(self
            .records_dir_for_id(&self.env_id(env))
            .join(format!("{record_id}.kvs")))
    }

    fn entry_for_history(&self, env: &str, key: &str) -> Result<(Value, Value), StoreError> {
        let index = self.load_index(env)?;
        let entry = index
            .get("secrets")
            .and_then(Value::as_object)
            .and_then(|secrets| secrets.get(key))
            .cloned();
        let Some(entry) = entry else {
            return Err(StoreError::NoHistory {
                env: env.to_owned(),
                key: key.to_owned(),
            });
        };
        if !entry.is_object() || !entry.get("current_record_id").is_some_and(value_is_truthy) {
            return Err(StoreError::NoHistory {
                env: env.to_owned(),
                key: key.to_owned(),
            });
        }
        Ok((index, entry))
    }

    fn ref_for_version(&self, entry: &Value, version: u64) -> Result<Value, StoreError> {
        let current = current_ref(entry);
        if current.get("generation").and_then(Value::as_u64) == Some(version) {
            return Ok(current);
        }
        if let Some(history) = entry.get("history").and_then(Value::as_array) {
            for reference in history {
                if reference.get("generation").and_then(Value::as_u64) == Some(version) {
                    return Ok(reference.clone());
                }
            }
        }
        Err(StoreError::VersionNotKept(version))
    }

    fn version_value(
        &self,
        env: &str,
        key: &str,
        entry: &Value,
        version: u64,
    ) -> Result<Zeroizing<String>, StoreError> {
        let reference = self.ref_for_version(entry, version)?;
        let mut record_entry = Map::new();
        for (source, destination) in [
            ("record_id", "current_record_id"),
            ("generation", "generation"),
            ("record_hash", "record_hash"),
        ] {
            let value = reference.get(source).cloned().unwrap_or(Value::Null);
            record_entry.insert(destination.into(), value);
        }
        self.load_current_record(env, key, &Value::Object(record_entry))
    }

    fn pruned_entry(
        &self,
        entry: &Value,
        keep: usize,
    ) -> Result<(Option<Value>, Vec<Value>), StoreError> {
        let mut replacement = entry
            .as_object()
            .cloned()
            .ok_or_else(|| StoreError::Corrupt("drawer entry is not an object".into()))?;
        let history = entry
            .get("history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if entry.get("state").and_then(Value::as_str) == Some("deleted") {
            if keep == 0 {
                return Ok((None, old_refs(entry)));
            }
            let retained: Vec<Value> = history.iter().take(keep - 1).cloned().collect();
            if retained.is_empty() {
                replacement.remove("history");
            } else {
                replacement.insert("history".into(), Value::Array(retained));
            }
            let dropped = history.into_iter().skip(keep - 1).collect();
            return Ok((Some(Value::Object(replacement)), dropped));
        }

        replacement.remove("history");
        let retained: Vec<Value> = history.iter().take(keep).cloned().collect();
        if !retained.is_empty() {
            replacement.insert("history".into(), Value::Array(retained));
        }
        let dropped = history.into_iter().skip(keep).collect();
        Ok((Some(Value::Object(replacement)), dropped))
    }

    fn referenced_record_ids(&self, index: &Value) -> HashSet<String> {
        let mut referenced = HashSet::new();
        let Some(secrets) = index.get("secrets").and_then(Value::as_object) else {
            return referenced;
        };
        for entry in secrets.values().filter(|entry| entry.is_object()) {
            if let Some(record_id) = entry
                .get("current_record_id")
                .and_then(Value::as_str)
                .filter(|record_id| !record_id.is_empty())
            {
                referenced.insert(record_id.to_owned());
            }
            if let Some(history) = entry.get("history").and_then(Value::as_array) {
                for reference in history.iter().filter(|reference| reference.is_object()) {
                    if let Some(record_id) = reference
                        .get("record_id")
                        .and_then(Value::as_str)
                        .filter(|record_id| !record_id.is_empty())
                    {
                        referenced.insert(record_id.to_owned());
                    }
                }
            }
        }
        referenced
    }

    fn unreferenced_record_ids(&self, env: &str, index: &Value) -> Result<Vec<String>, StoreError> {
        let env_id = self.env_id(env);
        let records_dir = self.records_dir_for_id(&env_id);
        if !fsx::check_directory(&records_dir)? {
            return Ok(Vec::new());
        }
        let referenced = self.referenced_record_ids(index);
        let mut found = Vec::new();
        for file in std::fs::read_dir(records_dir)? {
            let name = file?
                .file_name()
                .into_string()
                .ok()
                .filter(|name| name.ends_with(".kvs"));
            let Some(name) = name else {
                continue;
            };
            let record_id = name
                .strip_suffix(".kvs")
                .ok_or_else(|| StoreError::Corrupt("invalid record filename".into()))?;
            if fsx::validate_record_id(record_id).is_err() {
                continue;
            }
            if !referenced.contains(record_id) {
                found.push(record_id.to_owned());
            }
        }
        found.sort();
        Ok(found)
    }

    fn orphans_of(
        &self,
        env: &str,
        index: &Value,
        key: &str,
        max_generation: u64,
    ) -> Result<Vec<String>, StoreError> {
        let Some(last_generation) = max_generation.checked_add(1) else {
            return Err(StoreError::Corrupt("drawer generation overflow".into()));
        };
        let mut found = Vec::new();
        for record_id in self.unreferenced_record_ids(env, index)? {
            let path = self.record_path(env, &record_id)?;
            let Ok(blob) = read_drawer_file(&path, "drawer record") else {
                continue;
            };
            for generation in 1..=last_generation {
                if self
                    .decrypt_record_value(env, key, &record_id, generation, &blob)
                    .is_ok()
                {
                    found.push(record_id);
                    break;
                }
            }
        }
        Ok(found)
    }

    fn forget_locked(
        &self,
        env: &str,
        keys: Option<&BTreeSet<String>>,
    ) -> Result<usize, StoreError> {
        let mut index = self.load_index(env)?;
        let names = index
            .get("secrets")
            .and_then(Value::as_object)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut dropped = Vec::new();
        let mut orphans = Vec::new();
        for key in names {
            if keys.is_some_and(|keys| !keys.contains(&key)) {
                continue;
            }
            let entry = index
                .get("secrets")
                .and_then(Value::as_object)
                .and_then(|secrets| secrets.get(&key))
                .cloned()
                .ok_or_else(|| StoreError::Corrupt("drawer index entry is missing".into()))?;
            if keys.is_some() {
                let max_generation = generation_from_entry(&entry)?;
                orphans.extend(self.orphans_of(env, &index, &key, max_generation)?);
            }
            let (replacement, wipe) = self.pruned_entry(&entry, 0)?;
            dropped.extend(wipe);
            let new_entry = match replacement {
                Some(entry) => entry,
                None => forgotten_entry(&entry)?,
            };
            index
                .get_mut("secrets")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?
                .insert(key, new_entry);
        }
        if keys.is_none() {
            orphans = self.unreferenced_record_ids(env, &index)?;
        }
        if !dropped.is_empty() {
            self.save_index(env, &mut index)?;
        }
        self.wipe_records(env, &dropped)?;
        let referenced = self.referenced_record_ids(&index);
        let orphan_refs = orphans
            .into_iter()
            .filter(|record_id| !referenced.contains(record_id))
            .map(Value::String)
            .collect::<Vec<_>>();
        self.wipe_records(env, &orphan_refs)?;
        Ok(dropped.len())
    }

    fn prune_env_locked(&self, env: &str, keep: usize) -> Result<usize, StoreError> {
        let mut index = self.load_index(env)?;
        let names = index
            .get("secrets")
            .and_then(Value::as_object)
            .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut dropped = Vec::new();
        for key in names {
            let entry = index
                .get("secrets")
                .and_then(Value::as_object)
                .and_then(|secrets| secrets.get(&key))
                .cloned()
                .ok_or_else(|| StoreError::Corrupt("drawer index entry is missing".into()))?;
            let (replacement, wipe) = self.pruned_entry(&entry, keep)?;
            dropped.extend(wipe);
            let new_entry = match replacement {
                Some(entry) => entry,
                None => forgotten_entry(&entry)?,
            };
            index
                .get_mut("secrets")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| StoreError::Corrupt("drawer secrets map is invalid".into()))?
                .insert(key, new_entry);
        }
        if !dropped.is_empty() {
            self.save_index(env, &mut index)?;
            self.wipe_records(env, &dropped)?;
        }
        let orphans = self
            .unreferenced_record_ids(env, &index)?
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        self.wipe_records(env, &orphans)?;
        Ok(dropped.len())
    }

    #[cfg(test)]
    fn fail_next_index_save(&self) {
        self.fail_before_index_save
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn validate_keep(keep: usize) -> Result<(), StoreError> {
    if keep > HISTORY_KEEP_MAX {
        return Err(StoreError::Corrupt(format!(
            "history keep must be 0..={HISTORY_KEEP_MAX}"
        )));
    }
    Ok(())
}

fn read_drawer_file(path: &Path, what: &str) -> Result<Vec<u8>, StoreError> {
    match fsx::read_regular(path, what) {
        Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            Err(StoreError::Corrupt(format!("{what} is missing")))
        }
        result => result,
    }
}

fn validate_index(env: &str, index: &mut Value) -> Result<(), StoreError> {
    let object = index
        .as_object_mut()
        .ok_or_else(|| StoreError::Corrupt("drawer index payload must be an object".into()))?;
    if object.get("version").and_then(Value::as_u64) != Some(u64::from(DRAWER_FORMAT_VERSION)) {
        return Err(StoreError::Corrupt(
            "drawer index payload version is invalid".into(),
        ));
    }
    if object.get("env").and_then(Value::as_str) != Some(env) {
        return Err(StoreError::Corrupt("drawer index env mismatch".into()));
    }
    if !object.get("secrets").is_some_and(Value::is_object) {
        return Err(StoreError::Corrupt(
            "drawer index secrets map is invalid".into(),
        ));
    }
    match object.get("_meta") {
        Some(Value::Object(_)) => {}
        Some(_) => {
            return Err(StoreError::Corrupt(
                "drawer index metadata is invalid".into(),
            ));
        }
        None => {
            object.insert("_meta".into(), Value::Object(Map::new()));
        }
    }
    Ok(())
}

fn empty_index(env: &str) -> Value {
    let mut metadata = Map::new();
    metadata.insert("updated".into(), Value::Null);
    metadata.insert("count".into(), Value::Number(Number::from(0)));
    let mut object = Map::new();
    object.insert(
        "version".into(),
        Value::Number(Number::from(DRAWER_FORMAT_VERSION)),
    );
    object.insert("env".into(), Value::String(env.to_owned()));
    object.insert("_meta".into(), Value::Object(metadata));
    object.insert("secrets".into(), Value::Object(Map::new()));
    Value::Object(object)
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

fn effective_old_entry(entry: &Value) -> Result<Value, StoreError> {
    if !value_is_truthy(entry) {
        return Ok(empty_object());
    }
    if !entry.is_object() {
        return Err(StoreError::Corrupt(
            "drawer index entry is not an object".into(),
        ));
    }
    Ok(entry.clone())
}

fn is_live_entry(entry: &Value) -> bool {
    entry
        .get("state")
        .and_then(Value::as_str)
        .is_some_and(|state| state == "live")
}

fn value_is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => {
            number.as_i64().is_some_and(|number| number != 0)
                || number.as_u64().is_some_and(|number| number != 0)
                || number.as_f64().is_some_and(|number| number != 0.0)
        }
        Value::String(string) => !string.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(items) => !items.is_empty(),
    }
}

fn generation_from_entry(entry: &Value) -> Result<u64, StoreError> {
    let Some(generation) = entry.get("generation") else {
        return Ok(0);
    };
    if !value_is_truthy(generation) {
        return Ok(0);
    }
    match generation {
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| StoreError::Corrupt("drawer generation is invalid".into())),
        Value::Bool(true) => Ok(1),
        Value::String(string) => string
            .parse::<u64>()
            .map_err(|_| StoreError::Corrupt("drawer generation is invalid".into())),
        _ => Err(StoreError::Corrupt("drawer generation is invalid".into())),
    }
}

fn forgotten_entry(entry: &Value) -> Result<Value, StoreError> {
    let generation = generation_from_entry(entry)?;
    let mut object = Map::new();
    object.insert("state".into(), Value::String("forgotten".into()));
    object.insert("generation".into(), Value::Number(Number::from(generation)));
    Ok(Value::Object(object))
}

fn current_ref(entry: &Value) -> Value {
    let mut reference = Map::new();
    reference.insert(
        "record_id".into(),
        entry
            .get("current_record_id")
            .cloned()
            .unwrap_or(Value::Null),
    );
    reference.insert(
        "generation".into(),
        entry.get("generation").cloned().unwrap_or(Value::Null),
    );
    reference.insert(
        "record_hash".into(),
        entry.get("record_hash").cloned().unwrap_or(Value::Null),
    );
    reference.insert(
        "updated".into(),
        entry.get("updated").cloned().unwrap_or(Value::Null),
    );
    Value::Object(reference)
}

fn history_refs(entry: &Value) -> Vec<Value> {
    entry
        .get("history")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|reference| reference.is_object())
        .cloned()
        .collect()
}

fn old_refs(entry: &Value) -> Vec<Value> {
    let mut refs = history_refs(entry);
    if entry.get("state").and_then(Value::as_str) == Some("deleted") {
        refs.insert(0, current_ref(entry));
    }
    refs
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(items) => {
            for item in items {
                zeroize_value(item);
            }
        }
        Value::Object(items) => {
            for item in items.values_mut() {
                zeroize_value(item);
            }
        }
        _ => {}
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let difference = left
        .iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right));
    difference == 0
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn now_iso() -> String {
    let now = OffsetDateTime::now_utc();
    let year = now.year();
    let month = u8::from(now.month());
    let microseconds = now.nanosecond() / 1_000;
    if microseconds == 0 {
        format!(
            "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        )
    } else {
        format!(
            "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}.{microseconds:06}+00:00",
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use kv_crypto::Key32;

    use super::{DrawerStore, StoreError, VersionState};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).expect("test randomness");
            let path = std::env::temp_dir().join(format!("kv-store-unit-{}", super::hex(&random)));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn master() -> Key32 {
        Key32::new(std::array::from_fn(|index| index as u8))
    }

    #[test]
    fn failed_index_save_keeps_old_record_live_after_new_record_publish() {
        let dir = TestDir::new();
        let store = DrawerStore::open(dir.path(), master());
        assert_eq!(store.set_secret("dev", "TOKEN", "old", 10).unwrap(), 1);
        let old_id = store.env_id("dev");
        let old_record_count = fs::read_dir(
            dir.path()
                .join("drawers")
                .join("envs")
                .join(old_id)
                .join("records"),
        )
        .unwrap()
        .count();

        store.fail_next_index_save();
        assert!(matches!(
            store.set_secret("dev", "TOKEN", "new", 10),
            Err(StoreError::Io(_))
        ));
        assert_eq!(
            store
                .get_secret("dev", "TOKEN")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("old")
        );
        let new_record_count = fs::read_dir(
            dir.path()
                .join("drawers")
                .join("envs")
                .join(store.env_id("dev"))
                .join("records"),
        )
        .unwrap()
        .count();
        assert_eq!(new_record_count, old_record_count + 1);
        assert_eq!(store.list_secret_names("dev").unwrap(), vec!["TOKEN"]);
    }

    #[test]
    fn history_versions_restore_and_undo_remove_work() {
        let dir = TestDir::new();
        let store = DrawerStore::open(dir.path(), master());
        store.set_secret("dev", "TOKEN", "v1", 10).unwrap();
        store.set_secret("dev", "TOKEN", "v2", 10).unwrap();
        store.set_secret("dev", "TOKEN", "v3", 10).unwrap();

        let versions = store.list_versions("dev", "TOKEN").unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, 3);
        assert_eq!(versions[0].state, VersionState::Current);
        assert_eq!(versions[2].version, 1);
        assert_eq!(versions[2].state, VersionState::Old);
        assert_eq!(store.get_version("dev", "TOKEN", 1).unwrap().as_str(), "v1");
        assert_eq!(store.restore_version("dev", "TOKEN", 1, 10).unwrap(), 4);
        assert_eq!(
            store
                .get_secret("dev", "TOKEN")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("v1")
        );

        store.remove_secret("dev", "TOKEN", 10).unwrap();
        let removed = store.list_versions("dev", "TOKEN").unwrap();
        assert!(matches!(&removed[0].state, VersionState::Removed { .. }));
        assert_eq!(store.undo_remove("dev", "TOKEN").unwrap(), 4);
        assert_eq!(
            store.list_versions("dev", "TOKEN").unwrap()[0].state,
            VersionState::Current
        );
    }

    #[test]
    fn history_errors_and_version_reads_verify_the_record_hash() {
        let dir = TestDir::new();
        let store = DrawerStore::open(dir.path(), master());
        assert!(matches!(
            store.list_versions("dev", "MISSING"),
            Err(StoreError::NoHistory { .. })
        ));
        assert!(matches!(
            store.get_version("dev", "MISSING", 1),
            Err(StoreError::NoHistory { .. })
        ));

        store.set_secret("dev", "TOKEN", "v1", 10).unwrap();
        assert!(matches!(
            store.get_version("dev", "TOKEN", 2),
            Err(StoreError::VersionNotKept(2))
        ));
        assert!(matches!(
            store.undo_remove("dev", "TOKEN"),
            Err(StoreError::NotRemoved { .. })
        ));

        let index = store.load_index("dev").unwrap();
        let entry = &index["secrets"]["TOKEN"];
        let record_id = entry["current_record_id"].as_str().unwrap();
        let path = store.record_path("dev", record_id).unwrap();
        let mut record = fs::read(path).unwrap();
        let last = record.len() - 1;
        record[last] ^= 1;
        fs::write(store.record_path("dev", record_id).unwrap(), record).unwrap();
        assert!(matches!(
            store.get_version("dev", "TOKEN", 1),
            Err(StoreError::Corrupt(message)) if message.contains("hash mismatch")
        ));
    }

    #[test]
    fn key_scoped_forgetting_and_pruning_clean_only_the_intended_orphans() {
        let dir = TestDir::new();
        let store = DrawerStore::open(dir.path(), master());
        store.set_secret("dev", "TOKEN", "old", 10).unwrap();
        store.fail_next_index_save();
        assert!(store.set_secret("dev", "TOKEN", "new", 10).is_err());
        assert_eq!(store.unreferenced_record_count("dev").unwrap(), 1);
        assert_eq!(store.forget_history("dev", "OTHER").unwrap(), 0);
        assert_eq!(store.unreferenced_record_count("dev").unwrap(), 1);
        assert_eq!(store.forget_history("dev", "TOKEN").unwrap(), 0);
        assert_eq!(store.unreferenced_record_count("dev").unwrap(), 0);

        let second = TestDir::new();
        let store = DrawerStore::open(second.path(), master());
        store.set_secret("dev", "TOKEN", "old", 10).unwrap();
        store.fail_next_index_save();
        assert!(store.set_secret("dev", "TOKEN", "new", 10).is_err());
        assert_eq!(store.unreferenced_record_count("dev").unwrap(), 1);
        assert_eq!(store.prune_envs(&["dev"], 10).unwrap(), 0);
        assert_eq!(store.unreferenced_record_count("dev").unwrap(), 0);
    }
}
