use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use crate::{StoreError, envname, fsx, pyjson};

const CONFIG_FILE: &str = "config.json";
const GITIGNORE_FILE: &str = ".gitignore";
const PENDING_FILE: &str = "key-config.pending";
const CONFIG_LIMIT: usize = 16 * 1024 * 1024;
const IGNORE_LIMIT: usize = 64 * 1024 * 1024;
const HISTORY_KEEP_DEFAULT: usize = 10;
const HISTORY_KEEP_MAX: usize = 100;
const DELETED_KEEP_DEFAULT: u64 = 30;
const DELETED_KEEP_MAX: u64 = 365;
const OLD_IGNORE_RULES: &[&str] = &[
    "migration-backups/",
    "storage.lock",
    "/config.json",
    "/config-authority",
    "/vault-marker",
];
const WRITER_IGNORE_RULES: &[&str] = &["/config.lock", "/.kv-write-*.tmp", "/key-config.pending"];
const IGNORE_HEADER: &str = "# Local-only kv runtime records";
const CONFLICT_ERROR: &str =
    "configuration changed; reload and retry the operation (approval may need repeating)";

pub struct ConfigSnapshot {
    pub value: Value,
    pub path: PathBuf,
    pub digest: [u8; 32],
}

pub struct ConfigLockGuard {
    _lock: fsx::ConfigLock,
}

fn secrets_dir(root: &Path) -> PathBuf {
    root.join(".secrets")
}

fn config_path(root: &Path) -> PathBuf {
    secrets_dir(root).join(CONFIG_FILE)
}

pub fn config_lock(root: impl AsRef<Path>) -> Result<ConfigLockGuard, StoreError> {
    let sdir = secrets_dir(root.as_ref());
    let lock = fsx::lock_config(&sdir)?;
    if fsx::strictly_present(&sdir.join(PENDING_FILE))? {
        return Err(StoreError::KeyConfigPending);
    }
    ensure_config_ignores(&sdir)?;
    Ok(ConfigLockGuard { _lock: lock })
}

pub fn load_config(root: impl AsRef<Path>) -> Result<ConfigSnapshot, StoreError> {
    let root = root.as_ref();
    let _guard = config_lock(root)?;
    let path = config_path(root);
    let raw = fsx::read_regular_limit(&path, "config file", CONFIG_LIMIT)?;
    let value: Value = serde_json::from_slice(&raw).map_err(|_| {
        StoreError::ConfigConflict(format!(
            ".secrets/config.json is corrupted or invalid\n  path: {}\n  fix: restore this file from a copy you trust (e.g. your own backup)\n  do not delete the .secrets folder: it holds your master key and encrypted\n  secrets, and a new vault from 'kv init' cannot read them",
            path.display()
        ))
    })?;
    let path = fs::canonicalize(&path)?;
    Ok(ConfigSnapshot {
        value,
        path,
        digest: Sha256::digest(&raw).into(),
    })
}

pub fn save_config(root: impl AsRef<Path>, config: &mut ConfigSnapshot) -> Result<(), StoreError> {
    let root = root.as_ref();
    let payload = pyjson::to_vec_indent2_ascii(&config.value)?;
    let path = config_path(root);
    config_write_guard(root, config, || {
        write_config(&root.join(".secrets"), &config.value)
    })?;
    config.digest = Sha256::digest(&payload).into();
    config.path = fs::canonicalize(path)?;
    Ok(())
}

pub fn config_write_guard<T>(
    root: &Path,
    config: &ConfigSnapshot,
    operation: impl FnOnce() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let _guard = config_lock(root)?;
    assert_config_current(root, config)?;
    operation()
}

pub fn config_transaction<T>(
    root: impl AsRef<Path>,
    operation: impl FnOnce(&mut Value) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let root = root.as_ref();
    let _guard = config_lock(root)?;
    let mut snapshot = load_config(root)?;
    let before = snapshot.value.clone();
    let result = operation(&mut snapshot.value)?;
    if snapshot.value != before {
        save_config(root, &mut snapshot)?;
    }
    Ok(result)
}

pub(crate) fn assert_config_current(
    root: &Path,
    config: &ConfigSnapshot,
) -> Result<(), StoreError> {
    let path = config_path(root);
    let canonical = fs::canonicalize(&path)?;
    if config.path != canonical {
        return Err(StoreError::ConfigConflict(
            "save_config requires the original load_config snapshot for this vault".into(),
        ));
    }
    let raw = fsx::read_regular_limit(&path, "config file", CONFIG_LIMIT)?;
    if <[u8; 32]>::from(Sha256::digest(&raw)) != config.digest {
        return Err(StoreError::ConfigConflict(CONFLICT_ERROR.into()));
    }
    Ok(())
}

fn config_object(value: &Value) -> Result<&Map<String, Value>, StoreError> {
    value
        .as_object()
        .ok_or_else(|| StoreError::ConfigConflict("config.json must contain a JSON object".into()))
}

fn config_object_mut(value: &mut Value) -> Result<&mut Map<String, Value>, StoreError> {
    value
        .as_object_mut()
        .ok_or_else(|| StoreError::ConfigConflict("config.json must contain a JSON object".into()))
}

fn environment_names(config: &Value) -> Result<Vec<String>, StoreError> {
    config_object(config)?
        .get("environments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            StoreError::ConfigConflict("environments in .secrets/config.json must be a list".into())
        })?
        .iter()
        .map(|name| {
            name.as_str().map(str::to_owned).ok_or_else(|| {
                StoreError::ConfigConflict(
                    "environments in .secrets/config.json must be a list".into(),
                )
            })
        })
        .collect()
}

pub fn add_environment(root: impl AsRef<Path>, name: &str) -> Result<bool, StoreError> {
    envname::validate_env_name(name)?;
    config_transaction(root, |config| {
        let mut names = environment_names(config)?;
        let deleted = deleted_entries(config)?;
        names.extend(deleted.iter().map(|entry| entry.name.clone()));
        envname::validate_registered_name(name, &names)?;
        if environment_names(config)?.iter().any(|entry| entry == name) {
            return Ok(false);
        }
        if let Some(problem) = reserved_env_problem(config, name)? {
            return Err(StoreError::ConfigConflict(problem));
        }
        config_object_mut(config)?
            .entry("environments")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| StoreError::ConfigConflict("environments must be a list".into()))?
            .push(Value::String(name.to_owned()));
        Ok(true)
    })
}

pub fn list_environments(root: impl AsRef<Path>) -> Result<Vec<String>, StoreError> {
    environment_names(&load_config(root)?.value)
}

pub fn get_default_env(root: impl AsRef<Path>) -> Result<String, StoreError> {
    Ok(config_object(&load_config(root)?.value)?
        .get("default_env")
        .and_then(Value::as_str)
        .unwrap_or("dev")
        .to_owned())
}

pub fn set_default_env(root: impl AsRef<Path>, name: &str) -> Result<(), StoreError> {
    config_transaction(root, |config| {
        envname::validate_env_name(name)?;
        if !environment_names(config)?.iter().any(|entry| entry == name) {
            return Err(StoreError::ConfigConflict(format!(
                "environment '{name}' does not exist"
            )));
        }
        config_object_mut(config)?.insert("default_env".into(), Value::String(name.into()));
        Ok(())
    })
}

pub fn get_history_keep(root: impl AsRef<Path>) -> Result<usize, StoreError> {
    let config = load_config(root)?;
    history_keep(&config.value)
}

fn history_keep(config: &Value) -> Result<usize, StoreError> {
    let history = config_object(config)?
        .get("history")
        .and_then(Value::as_object);
    let Some(value) = history.and_then(|history| history.get("keep")) else {
        return Ok(HISTORY_KEEP_DEFAULT);
    };
    let value = value.as_u64().ok_or_else(|| {
        StoreError::ConfigConflict("history.keep in .secrets/config.json must be 0..100".into())
    })? as usize;
    if value > HISTORY_KEEP_MAX {
        return Err(StoreError::ConfigConflict(
            "history.keep in .secrets/config.json must be 0..100".into(),
        ));
    }
    Ok(value)
}

pub fn set_history_keep(root: impl AsRef<Path>, keep: usize) -> Result<(), StoreError> {
    if keep > HISTORY_KEEP_MAX {
        return Err(StoreError::ConfigConflict(
            "history keep must be a whole number from 0 to 100".into(),
        ));
    }
    config_transaction(root, |config| {
        let object = config_object_mut(config)?;
        if !object.get("history").is_some_and(Value::is_object) {
            object.insert("history".into(), json!({}));
        }
        object
            .get_mut("history")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| StoreError::ConfigConflict("history must be an object".into()))?
            .insert("keep".into(), Value::Number(keep.into()));
        Ok(())
    })
}

pub fn get_deleted_env_keep_days(root: impl AsRef<Path>) -> Result<u64, StoreError> {
    let config = load_config(root)?;
    deleted_keep_days(&config.value)
}

fn deleted_keep_days(config: &Value) -> Result<u64, StoreError> {
    let section = config_object(config)?
        .get("env_delete")
        .and_then(Value::as_object);
    let Some(value) = section.and_then(|section| section.get("keep_days")) else {
        return Ok(DELETED_KEEP_DEFAULT);
    };
    let value = value.as_u64().ok_or_else(|| {
        StoreError::ConfigConflict(
            "env_delete.keep_days in .secrets/config.json must be 0..365".into(),
        )
    })?;
    if value > DELETED_KEEP_MAX {
        return Err(StoreError::ConfigConflict(
            "env_delete.keep_days in .secrets/config.json must be 0..365".into(),
        ));
    }
    Ok(value)
}

pub fn set_deleted_env_keep_days(root: impl AsRef<Path>, days: u64) -> Result<(), StoreError> {
    if days > DELETED_KEEP_MAX {
        return Err(StoreError::ConfigConflict(
            "days must be a whole number from 0 to 365".into(),
        ));
    }
    config_transaction(root, |config| {
        let object = config_object_mut(config)?;
        if !object.get("env_delete").is_some_and(Value::is_object) {
            object.insert("env_delete".into(), json!({}));
        }
        object
            .get_mut("env_delete")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| StoreError::ConfigConflict("env_delete must be an object".into()))?
            .insert("keep_days".into(), Value::Number(days.into()));
        Ok(())
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletedEnvironment {
    pub name: String,
    pub deleted_at: String,
    pub purge_after: String,
}

pub(crate) fn deleted_entries(config: &Value) -> Result<Vec<DeletedEnvironment>, StoreError> {
    let entries = config_object(config)?
        .get("deleted_environments")
        .and_then(Value::as_array);
    let Some(entries) = entries else {
        if config_object(config)?.get("deleted_environments").is_some() {
            return Err(StoreError::ConfigConflict(
                "deleted_environments in .secrets/config.json must be a list".into(),
            ));
        }
        return Ok(Vec::new());
    };
    entries
        .iter()
        .map(|entry| {
            let name = entry.get("name").and_then(Value::as_str);
            let deleted_at = entry.get("deleted_at").and_then(Value::as_str);
            let purge_after = entry.get("purge_after").and_then(Value::as_str);
            let (Some(name), Some(deleted_at), Some(purge_after)) = (name, deleted_at, purge_after)
            else {
                return Err(StoreError::ConfigConflict(
                    "deleted_environments in .secrets/config.json is invalid".into(),
                ));
            };
            envname::validate_env_name(name)?;
            parse_timestamp(deleted_at)?;
            parse_timestamp(purge_after)?;
            Ok(DeletedEnvironment {
                name: name.to_owned(),
                deleted_at: deleted_at.to_owned(),
                purge_after: purge_after.to_owned(),
            })
        })
        .collect()
}

pub(crate) fn pending_wipes(config: &Value) -> Result<Vec<String>, StoreError> {
    let Some(value) = config_object(config)?.get("env_wipes_pending") else {
        return Ok(Vec::new());
    };
    let names = value.as_array().ok_or_else(|| {
        StoreError::ConfigConflict("env_wipes_pending in .secrets/config.json is invalid".into())
    })?;
    names
        .iter()
        .map(|name| {
            let name = name.as_str().ok_or_else(|| {
                StoreError::ConfigConflict(
                    "env_wipes_pending in .secrets/config.json is invalid".into(),
                )
            })?;
            envname::validate_env_name(name)?;
            Ok(name.to_owned())
        })
        .collect()
}

pub fn list_deleted_environments(
    root: impl AsRef<Path>,
) -> Result<Vec<DeletedEnvironment>, StoreError> {
    deleted_entries(&load_config(root)?.value)
}

pub fn pending_env_wipes(root: impl AsRef<Path>) -> Result<Vec<String>, StoreError> {
    pending_wipes(&load_config(root)?.value)
}

pub fn reserved_env_problem(config: &Value, name: &str) -> Result<Option<String>, StoreError> {
    if deleted_entries(config)?
        .iter()
        .any(|entry| entry.name == name)
    {
        return Ok(Some(format!(
            "environment '{name}' was deleted; kv env restore {name} brings it back (kv env purge {name} removes it now)"
        )));
    }
    if pending_wipes(config)?.iter().any(|entry| entry == name) {
        return Ok(Some(format!(
            "the files of an earlier environment '{name}' are still being removed; the next vault change finishes it, then retry"
        )));
    }
    Ok(None)
}

pub fn env_rename_problem(
    config: &Value,
    old: &str,
    new: &str,
) -> Result<Option<String>, StoreError> {
    envname::validate_env_name(new)?;
    let environments = environment_names(config)?;
    if !environments.iter().any(|name| name == old) {
        return Ok(Some(format!("environment '{old}' does not exist")));
    }
    if new == old {
        return Ok(Some("the new name is the same as the old one".into()));
    }
    if environments.iter().any(|name| name == new) {
        return Ok(Some(format!("environment '{new}' already exists")));
    }
    if let Some(problem) = reserved_env_problem(config, new)? {
        return Ok(Some(problem));
    }
    let mut others = environments
        .into_iter()
        .filter(|name| name != old)
        .collect::<Vec<_>>();
    others.extend(deleted_entries(config)?.into_iter().map(|entry| entry.name));
    envname::validate_registered_name(new, &others)?;
    Ok(None)
}

pub fn env_delete_problem(config: &Value, name: &str) -> Result<Option<String>, StoreError> {
    if !environment_names(config)?.iter().any(|entry| entry == name) {
        return Ok(Some(format!("environment '{name}' does not exist")));
    }
    if config_object(config)?
        .get("default_env")
        .and_then(Value::as_str)
        .unwrap_or("dev")
        == name
    {
        return Ok(Some(format!(
            "'{name}' is the default environment and cannot be deleted; make another one the default first: kv env default NAME"
        )));
    }
    Ok(None)
}

pub fn begin_env_rename(root: impl AsRef<Path>, old: &str, new: &str) -> Result<(), StoreError> {
    config_transaction(root, |config| {
        if let Some(problem) = env_rename_problem(config, old, new)? {
            return Err(StoreError::ConfigConflict(problem));
        }
        let mut pending = pending_wipes(config)?;
        pending.push(new.to_owned());
        set_pending(config, pending)
    })
}

pub fn commit_env_rename(root: impl AsRef<Path>, old: &str, new: &str) -> Result<(), StoreError> {
    config_transaction(root, |config| {
        let pending = pending_wipes(config)?;
        if !pending.iter().any(|name| name == new) {
            return Err(StoreError::ConfigConflict(format!(
                "the rename to '{new}' was interrupted; retry it"
            )));
        }
        set_pending(
            config,
            pending.into_iter().filter(|name| name != new).collect(),
        )?;
        if let Some(problem) = env_rename_problem(config, old, new)? {
            return Err(StoreError::ConfigConflict(problem));
        }
        let object = config_object_mut(config)?;
        let envs = object
            .get_mut("environments")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| StoreError::ConfigConflict("environments must be a list".into()))?;
        for name in envs {
            if name.as_str() == Some(old) {
                *name = Value::String(new.to_owned());
            }
        }
        if object
            .get("default_env")
            .and_then(Value::as_str)
            .unwrap_or("dev")
            == old
        {
            object.insert("default_env".into(), Value::String(new.to_owned()));
        }
        let mut pending = pending_wipes(config)?;
        pending.push(old.to_owned());
        set_pending(config, pending)
    })
}

pub fn commit_env_delete(
    root: impl AsRef<Path>,
    name: &str,
    deleted_at: &str,
    purge_after: &str,
) -> Result<(), StoreError> {
    config_transaction(root, |config| {
        if let Some(problem) = env_delete_problem(config, name)? {
            return Err(StoreError::ConfigConflict(problem));
        }
        let object = config_object_mut(config)?;
        object
            .get_mut("environments")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| StoreError::ConfigConflict("environments must be a list".into()))?
            .retain(|entry| entry.as_str() != Some(name));
        let mut deleted = deleted_entries(config)?
            .into_iter()
            .map(|entry| {
                json!({"name":entry.name,"deleted_at":entry.deleted_at,"purge_after":entry.purge_after})
            })
            .collect::<Vec<_>>();
        deleted.push(json!({"name":name,"deleted_at":deleted_at,"purge_after":purge_after}));
        config_object_mut(config)?.insert("deleted_environments".into(), Value::Array(deleted));
        Ok(())
    })
}

pub fn commit_env_restore(root: impl AsRef<Path>, name: &str) -> Result<(), StoreError> {
    config_transaction(root, |config| {
        let deleted = deleted_entries(config)?;
        if !deleted.iter().any(|entry| entry.name == name) {
            return Err(StoreError::ConfigConflict(format!(
                "'{name}' is not a deleted environment (kv env restore lists them)"
            )));
        }
        envname::validate_registered_name(name, &environment_names(config)?)?;
        let object = config_object_mut(config)?;
        object.insert(
            "deleted_environments".into(),
            Value::Array(
                deleted
                    .into_iter()
                    .filter(|entry| entry.name != name)
                    .map(|entry| {
                        json!({"name":entry.name,"deleted_at":entry.deleted_at,"purge_after":entry.purge_after})
                    })
                    .collect(),
            ),
        );
        object
            .get_mut("environments")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| StoreError::ConfigConflict("environments must be a list".into()))?
            .push(Value::String(name.to_owned()));
        Ok(())
    })
}

pub fn queue_env_wipes(root: impl AsRef<Path>, names: &[String]) -> Result<(), StoreError> {
    config_transaction(root, |config| {
        let deleted = deleted_entries(config)?;
        for name in names {
            if !deleted.iter().any(|entry| &entry.name == name) {
                return Err(StoreError::ConfigConflict(format!(
                    "'{name}' is not a deleted environment (kv env restore lists them)"
                )));
            }
        }
        config_object_mut(config)?.insert(
            "deleted_environments".into(),
            Value::Array(
                deleted
                    .into_iter()
                    .filter(|entry| !names.contains(&entry.name))
                    .map(|entry| {
                        json!({"name":entry.name,"deleted_at":entry.deleted_at,"purge_after":entry.purge_after})
                    })
                    .collect(),
            ),
        );
        let mut pending = pending_wipes(config)?;
        for name in names {
            if !pending.contains(name) {
                pending.push(name.clone());
            }
        }
        set_pending(config, pending)
    })
}

pub fn clear_env_wipe(root: impl AsRef<Path>, name: &str) -> Result<(), StoreError> {
    config_transaction(root, |config| {
        let pending = pending_wipes(config)?;
        set_pending(
            config,
            pending.into_iter().filter(|entry| entry != name).collect(),
        )
    })
}

fn set_pending(config: &mut Value, pending: Vec<String>) -> Result<(), StoreError> {
    config_object_mut(config)?.insert(
        "env_wipes_pending".into(),
        Value::Array(pending.into_iter().map(Value::String).collect()),
    );
    Ok(())
}

pub(crate) fn ensure_config_ignores(sdir: &Path) -> Result<(), StoreError> {
    update_vault_ignores(sdir, OLD_IGNORE_RULES, true, Some(IGNORE_HEADER))
}

pub(crate) fn write_config(sdir: &Path, value: &Value) -> Result<(), StoreError> {
    let payload = pyjson::to_vec_indent2_ascii(value)?;
    fsx::write_atomic_limit(
        &sdir.join(CONFIG_FILE),
        &payload,
        false,
        CONFIG_LIMIT,
        "config file",
    )
}

pub fn update_vault_ignores(
    sdir: &Path,
    rules: &[&str],
    writer_tail: bool,
    header: Option<&str>,
) -> Result<(), StoreError> {
    let _lock = fsx::lock_config(sdir)?;
    let path = sdir.join(GITIGNORE_FILE);
    let existing = match fsx::read_regular_limit(&path, "vault ignore file", IGNORE_LIMIT) {
        Ok(raw) => String::from_utf8(raw)
            .map_err(|_| StoreError::ConfigConflict("the vault ignore file is not UTF-8".into()))?,
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let normalized = existing.replace("\r\n", "\n");
    let mut required = rules.to_vec();
    let tail: &[&str] = if writer_tail {
        WRITER_IGNORE_RULES
    } else {
        &[]
    };
    if !required.contains(&"/config.lock") && !tail.contains(&"/config.lock") {
        required.push("/config.lock");
    }
    let updated = merge_ignore_rules(&normalized, &required, tail, header);
    if updated != normalized {
        if updated.len() > IGNORE_LIMIT {
            return Err(StoreError::ConfigConflict(
                "the vault ignore file would be larger than kv reads (64 MiB)".into(),
            ));
        }
        fsx::write_atomic_limit(
            &path,
            updated.as_bytes(),
            false,
            IGNORE_LIMIT,
            "vault ignore file",
        )?;
    }
    Ok(())
}

pub(crate) fn merge_ignore_rules(
    existing: &str,
    required: &[&str],
    tail_rules: &[&str],
    header: Option<&str>,
) -> String {
    let missing = required
        .iter()
        .filter(|rule| !tail_rules.contains(rule) && !ignore_rule_present(existing, rule))
        .copied()
        .collect::<Vec<_>>();
    if tail_rules.is_empty() {
        if missing.is_empty() {
            return existing.to_owned();
        }
        let mut output = existing.to_owned();
        if let Some(header) = header.filter(|_| existing.is_empty()) {
            output.push_str(header);
            output.push('\n');
        } else if !existing.is_empty() && !existing.ends_with('\n') {
            output.push('\n');
        }
        for rule in missing {
            output.push_str(rule);
            output.push('\n');
        }
        return output;
    }
    let mut lines = existing.split('\n').collect::<Vec<_>>();
    if lines.last() == Some(&"") {
        let mut end = lines.len().saturating_sub(1);
        while end > 0 && lines[end - 1].is_empty() {
            end -= 1;
        }
        lines.truncate(end + 1);
    }
    let body = lines
        .into_iter()
        .filter(|line| !tail_rules.contains(line))
        .collect::<Vec<_>>()
        .join("\n");
    let mut output = body;
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    for rule in missing.into_iter().chain(tail_rules.iter().copied()) {
        output.push_str(rule);
        output.push('\n');
    }
    output
}

pub(crate) fn ignore_rule_present(existing: &str, rule: &str) -> bool {
    let mut protected = false;
    for raw in existing.split('\n') {
        let mut line = git_trim_trailing_spaces(raw);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(negation) = line.strip_prefix('!') {
            if protected && ignore_negation_matches(negation, rule) {
                protected = false;
            }
        } else {
            if line.starts_with('\\') && matches!(line.as_bytes().get(1), Some(b'!' | b'#')) {
                line = &line[1..];
            }
            let alias = format!("/{}", rule.trim_start_matches('/'));
            let trimmed = rule.trim_start_matches('/');
            if line == rule || line == alias || (rule.ends_with('/') && line == trimmed) {
                protected = true;
            }
        }
    }
    protected
}

pub(crate) fn git_trim_trailing_spaces(line: &str) -> &str {
    let mut run = None;
    let mut chars = line.char_indices();
    while let Some((index, character)) = chars.next() {
        if character == ' ' {
            if run.is_none() {
                run = Some(index);
            }
        } else if character == '\\' {
            run = None;
            chars.next();
        } else {
            run = None;
        }
    }
    run.map_or(line, |index| &line[..index])
}

pub(crate) fn ignore_negation_matches(pattern: &str, rule: &str) -> bool {
    if !pattern
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._/*?-".contains(character))
    {
        return true;
    }
    let mut pattern = pattern.to_ascii_lowercase();
    let target = rule.trim_matches('/').to_ascii_lowercase();
    if pattern.ends_with('/') {
        if !rule.ends_with('/') {
            return false;
        }
        pattern.pop();
    }
    if pattern.contains('/') {
        let anchored = pattern.trim_start_matches('/');
        glob_match(anchored, &target) || glob_match(&anchored.replace("**/", ""), &target)
    } else {
        glob_match(&pattern, &target)
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let (mut p, mut t, mut star, mut retry) = (0usize, 0usize, None, 0usize);
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = t;
        } else if let Some(position) = star {
            p = position + 1;
            retry += 1;
            t = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        StoreError::ConfigConflict("deleted_environments in .secrets/config.json is invalid".into())
    })
}

fn format_python_timestamp(timestamp: OffsetDateTime) -> String {
    let timestamp = timestamp.to_offset(UtcOffset::UTC);
    let micros = timestamp.nanosecond() / 1_000;
    if micros == 0 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            timestamp.year(),
            u8::from(timestamp.month()),
            timestamp.day(),
            timestamp.hour(),
            timestamp.minute(),
            timestamp.second()
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+00:00",
            timestamp.year(),
            u8::from(timestamp.month()),
            timestamp.day(),
            timestamp.hour(),
            timestamp.minute(),
            timestamp.second(),
            micros
        )
    }
}

pub fn timestamp_now() -> String {
    format_python_timestamp(OffsetDateTime::now_utc())
}

pub fn purge_after(days: u64) -> Result<String, StoreError> {
    let timestamp =
        OffsetDateTime::now_utc() + Duration::days(i64::try_from(days).unwrap_or(i64::MAX));
    Ok(format_python_timestamp(timestamp))
}

/// Production must provide an approval-reference index before enabling environment changes.
pub trait ApprovalRefs {
    fn approvals_naming_env(&self, env: &str) -> Result<bool, StoreError>;
}

pub struct NoApprovals;

impl ApprovalRefs for NoApprovals {
    fn approvals_naming_env(&self, _env: &str) -> Result<bool, StoreError> {
        Ok(false)
    }
}

pub struct Vault {
    pub root: PathBuf,
    pub store: crate::DrawerStore,
    pub approvals: Box<dyn ApprovalRefs>,
}

impl Vault {
    pub fn new(
        root: impl Into<PathBuf>,
        store: crate::DrawerStore,
        approvals: impl ApprovalRefs + 'static,
    ) -> Self {
        Self {
            root: root.into(),
            store,
            approvals: Box::new(approvals),
        }
    }

    pub fn list_environments(&self) -> Result<Vec<String>, StoreError> {
        list_environments(&self.root)
    }

    pub fn get_default_env(&self) -> Result<String, StoreError> {
        get_default_env(&self.root)
    }

    pub fn add_environment(&self, name: &str) -> Result<bool, StoreError> {
        add_environment(&self.root, name)
    }

    pub fn set_default_env(&self, name: &str) -> Result<(), StoreError> {
        set_default_env(&self.root, name)
    }

    pub fn list_versions(
        &self,
        env: &str,
        key: &str,
    ) -> Result<Vec<crate::VersionInfo>, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        self.store.list_versions(env, key)
    }

    pub fn get_version(
        &self,
        env: &str,
        key: &str,
        version: u64,
    ) -> Result<kv_crypto::Zeroizing<String>, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        self.store.get_version(env, key, version)
    }

    pub fn restore_version(&self, env: &str, key: &str, version: u64) -> Result<u64, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        self.store
            .restore_version_locked(env, key, version, history_keep(&config)?)
    }

    pub fn undo_remove(&self, env: &str, key: &str) -> Result<u64, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        self.store.undo_remove_locked(env, key)
    }

    pub fn forget_history(&self, env: &str, key: &str) -> Result<usize, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let keys = std::collections::BTreeSet::from([key.to_owned()]);
        self.store.forget_locked(env, Some(&keys))
    }

    pub fn forget_env_history(&self, env: &str) -> Result<usize, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        self.store.forget_locked(env, None)
    }

    pub fn forget_vault_history(&self) -> Result<usize, StoreError> {
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        let mut names = environment_names(&config)?;
        names.extend(
            deleted_entries(&config)?
                .into_iter()
                .map(|entry| entry.name),
        );
        let mut total = 0usize;
        for name in names {
            total += self.store.forget_locked(&name, None)?;
        }
        Ok(total)
    }

    pub fn get_history_keep(&self) -> Result<usize, StoreError> {
        get_history_keep(&self.root)
    }

    pub fn set_history_keep(&self, keep: usize) -> Result<usize, StoreError> {
        if keep > HISTORY_KEEP_MAX {
            return Err(StoreError::ConfigConflict(
                "history keep must be a whole number from 0 to 100".into(),
            ));
        }
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        let mut names = environment_names(&config)?;
        names.extend(
            deleted_entries(&config)?
                .into_iter()
                .map(|entry| entry.name),
        );
        let mut total = 0;
        for name in names {
            total += self.store.prune_env_locked(&name, keep)?;
        }
        set_history_keep(&self.root, keep)?;
        Ok(total)
    }

    pub fn get_deleted_env_keep_days(&self) -> Result<u64, StoreError> {
        get_deleted_env_keep_days(&self.root)
    }

    pub fn set_deleted_env_keep_days(&self, days: u64) -> Result<(), StoreError> {
        set_deleted_env_keep_days(&self.root, days)
    }

    pub fn list_deleted_environments(&self) -> Result<Vec<DeletedEnvironment>, StoreError> {
        list_deleted_environments(&self.root)
    }

    pub fn pending_env_wipes(&self) -> Result<Vec<String>, StoreError> {
        pending_env_wipes(&self.root)
    }

    pub fn copy_env_checked(
        &self,
        source: &str,
        destination: &str,
        options: crate::CopyOptions,
    ) -> Result<crate::CopyResult, StoreError> {
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        let names = environment_names(&config)?;
        if !names.iter().any(|name| name == source) {
            return Err(StoreError::EnvMissing(source.to_owned()));
        }
        Self::check_reserved(&config, source)?;
        Self::check_reserved(&config, destination)?;
        let mut existing = names.clone();
        existing.extend(
            deleted_entries(&config)?
                .into_iter()
                .map(|entry| entry.name),
        );
        let created = !names.iter().any(|name| name == destination);
        if created {
            envname::validate_registered_name(destination, &existing)?;
            add_environment(&self.root, destination)?;
        }
        let keep = history_keep(&load_config(&self.root)?.value)?;
        let mut result =
            self.store
                .copy_env_checked_locked(source, destination, options, keep, true)?;
        result.created = created;
        Ok(result)
    }

    pub fn backup_state(&self) -> Result<crate::BackupState, StoreError> {
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        let names = environment_names(&config)?;
        let default = config_object(&config)?
            .get("default_env")
            .and_then(Value::as_str)
            .unwrap_or("dev")
            .to_owned();
        let keep = history_keep(&config)?;
        let names = names.iter().map(String::as_str).collect::<Vec<_>>();
        self.store.backup_state_locked(&names, &default, keep)
    }

    pub fn make_backup(
        &self,
        path: impl AsRef<Path>,
        passphrase: &str,
        made_from: &str,
    ) -> Result<crate::backup::BackupSummary, crate::backup::BackupError> {
        self.make_backup_with_setting(path, passphrase, made_from, crate::backup::DEFAULT_SETTING)
    }

    pub fn make_backup_with_setting(
        &self,
        path: impl AsRef<Path>,
        passphrase: &str,
        made_from: &str,
        setting: [u8; 3],
    ) -> Result<crate::backup::BackupSummary, crate::backup::BackupError> {
        crate::backup::check_destination(&self.store, path.as_ref())?;
        let state = self.backup_state()?;
        crate::backup::make_backup_from_state(
            &self.store,
            path,
            state,
            passphrase,
            made_from,
            setting,
        )
    }

    pub fn restore_snapshot(
        &self,
        environments: &[crate::BackupEnv],
        default_env: &str,
        keep: usize,
    ) -> Result<usize, StoreError> {
        if keep > HISTORY_KEEP_MAX {
            return Err(StoreError::ConfigConflict(
                "history keep must be a whole number from 0 to 100".into(),
            ));
        }
        let names = environments
            .iter()
            .map(|environment| environment.name.clone())
            .collect::<Vec<_>>();
        envname::validate_environment_registry(&names, default_env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        set_history_keep(&self.root, keep)?;
        config_transaction(&self.root, |config| {
            let object = config_object_mut(config)?;
            object.insert(
                "environments".into(),
                Value::Array(names.iter().cloned().map(Value::String).collect()),
            );
            object.insert("default_env".into(), Value::String(default_env.to_owned()));
            Ok(())
        })?;
        self.store.restore_snapshot_locked(environments, keep)
    }

    fn validate_registered(&self, name: &str) -> Result<Value, StoreError> {
        envname::validate_env_name(name)?;
        let config = load_config(&self.root)?.value;
        let mut names = environment_names(&config)?;
        names.extend(
            deleted_entries(&config)?
                .into_iter()
                .map(|entry| entry.name),
        );
        envname::validate_registered_name(name, &names)?;
        Ok(config)
    }

    fn require_registered(config: &Value, name: &str) -> Result<(), StoreError> {
        if !environment_names(config)?.iter().any(|entry| entry == name) {
            return Err(StoreError::EnvMissing(name.to_owned()));
        }
        Ok(())
    }

    fn check_reserved(config: &Value, name: &str) -> Result<(), StoreError> {
        if let Some(problem) = reserved_env_problem(config, name)? {
            return Err(StoreError::ConfigConflict(problem));
        }
        Ok(())
    }

    fn finish_env_removals_locked(&self) -> Result<(), StoreError> {
        let snapshot = load_config(&self.root)?;
        let config = snapshot.value;
        let deleted = deleted_entries(&config)?;
        let now = OffsetDateTime::now_utc();
        let mut expired = Vec::new();
        for entry in &deleted {
            if parse_timestamp(&entry.purge_after)? <= now {
                expired.push(entry.name.clone());
            }
        }
        if !expired.is_empty() {
            queue_env_wipes(&self.root, &expired)?;
        }
        let pending = pending_wipes(&load_config(&self.root)?.value)?;
        let mut names = pending;
        for name in expired {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        for name in names {
            fsx::clear_env_tree(self.store.secrets_dir(), &self.store.env_id(&name))?;
            clear_env_wipe(&self.root, &name)?;
        }
        Ok(())
    }

    fn check_approval(&self, env: &str) -> Result<(), StoreError> {
        if self.approvals.approvals_naming_env(env)? {
            return Err(StoreError::ConfigConflict(format!(
                "an approval names environment '{env}'; nothing was changed (kv approvals list shows it)"
            )));
        }
        Ok(())
    }

    pub fn get_secret(
        &self,
        env: &str,
        key: &str,
    ) -> Result<Option<kv_crypto::Zeroizing<String>>, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        self.store.get_secret(env, key)
    }

    pub fn set_secret(&self, env: &str, key: &str, value: &str) -> Result<u64, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        Self::check_reserved(&config, env)?;
        let mut names = environment_names(&config)?;
        names.extend(
            deleted_entries(&config)?
                .into_iter()
                .map(|entry| entry.name),
        );
        envname::validate_registered_name(env, &names)?;
        let keep = history_keep(&config)?;
        let (generation, dropped) = self.store.set_locked_unwiped(env, key, value, keep)?;
        add_environment(&self.root, env)?;
        self.store.wipe_records(env, &dropped)?;
        Ok(generation)
    }

    pub fn remove_secret(&self, env: &str, key: &str) -> Result<bool, StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        Self::check_reserved(&config, env)?;
        Self::require_registered(&config, env)?;
        self.store
            .remove_secret_locked(env, key, history_keep(&config)?)
    }

    pub fn save_env(
        &self,
        env: &str,
        secrets: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), StoreError> {
        let config = self.validate_registered(env)?;
        Self::check_reserved(&config, env)?;
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        Self::check_reserved(&config, env)?;
        let mut names = environment_names(&config)?;
        names.extend(
            deleted_entries(&config)?
                .into_iter()
                .map(|entry| entry.name),
        );
        envname::validate_registered_name(env, &names)?;
        let dropped = self
            .store
            .save_env_locked_unwiped(env, secrets, history_keep(&config)?)?;
        add_environment(&self.root, env)?;
        self.store.wipe_records(env, &dropped)?;
        Ok(())
    }

    pub fn rename_env(&self, old: &str, new: &str) -> Result<(), StoreError> {
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        if let Some(problem) = env_rename_problem(&config, old, new)? {
            return Err(StoreError::ConfigConflict(problem));
        }
        self.check_approval(old)?;
        self.check_approval(new)?;
        begin_env_rename(&self.root, old, new)?;
        fsx::clear_env_tree(self.store.secrets_dir(), &self.store.env_id(new))?;
        self.store.copy_env_tree_locked(old, new)?;
        self.store.sync_envs_dir()?;
        commit_env_rename(&self.root, old, new)?;
        fsx::clear_env_tree(self.store.secrets_dir(), &self.store.env_id(old))?;
        clear_env_wipe(&self.root, old)
    }

    pub fn delete_env(&self, name: &str) -> Result<DeletedEnvironment, StoreError> {
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        let config = load_config(&self.root)?.value;
        if let Some(problem) = env_delete_problem(&config, name)? {
            return Err(StoreError::ConfigConflict(problem));
        }
        self.check_approval(name)?;
        let deleted_at = timestamp_now();
        let days = deleted_keep_days(&config)?;
        let purge_after =
            format_python_timestamp(parse_timestamp(&deleted_at)? + Duration::days(days as i64));
        commit_env_delete(&self.root, name, &deleted_at, &purge_after)?;
        Ok(DeletedEnvironment {
            name: name.to_owned(),
            deleted_at,
            purge_after,
        })
    }

    pub fn restore_env(&self, name: &str) -> Result<(), StoreError> {
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        self.finish_env_removals_locked()?;
        self.check_approval(name)?;
        let config = load_config(&self.root)?.value;
        if !deleted_entries(&config)?
            .iter()
            .any(|entry| entry.name == name)
        {
            return Err(StoreError::ConfigConflict(format!(
                "'{name}' is not a deleted environment (kv env restore lists them)"
            )));
        }
        self.store.prune_env_locked(name, history_keep(&config)?)?;
        commit_env_restore(&self.root, name)
    }

    pub fn purge_env(&self, name: &str) -> Result<bool, StoreError> {
        let _lock = fsx::lock_storage(self.store.secrets_dir())?;
        let before = deleted_entries(&load_config(&self.root)?.value)?;
        self.finish_env_removals_locked()?;
        let after = deleted_entries(&load_config(&self.root)?.value)?;
        if before.iter().any(|entry| entry.name == name)
            && !after.iter().any(|entry| entry.name == name)
        {
            return Ok(false);
        }
        if !after.iter().any(|entry| entry.name == name) {
            return Err(StoreError::ConfigConflict(format!(
                "'{name}' is not a deleted environment (kv env restore lists them)"
            )));
        }
        queue_env_wipes(&self.root, &[name.to_owned()])?;
        fsx::clear_env_tree(self.store.secrets_dir(), &self.store.env_id(name))?;
        clear_env_wipe(&self.root, name)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::{Rfc3339, format_python_timestamp};
    use time::OffsetDateTime;

    #[test]
    fn timestamps_preserve_python_isoformat_microseconds() {
        let timestamp =
            OffsetDateTime::parse("2026-11-01T13:20:15.136990+00:00", &Rfc3339).unwrap();
        assert_eq!(
            format_python_timestamp(timestamp),
            "2026-11-01T13:20:15.136990+00:00"
        );
    }
}
