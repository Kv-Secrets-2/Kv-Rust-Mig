//! The two local-only record stores under `.secrets/`: `run_grants.json`
//! (`kv/grants.py` `_read_store`/`_write_store`) and `capability_tokens.json`
//! (`kv/capabilities.py`). Both are private (0600), written atomically as
//! `json.dumps(indent=2, sort_keys=True) + "\n"`, and refused when linked,
//! shared, malformed, oversized or carrying duplicate ids.

use std::fmt;
use std::path::{Path, PathBuf};

use kv_store::config::update_vault_ignores;
use kv_store::{StoreError, fsx, pyjson};
use serde_json::{Map, Value};

pub const PRIVATE_FILE_MODE: u32 = 0o600;
pub const IGNORE_HEADER: &str = "# Local-only kv runtime records";
const VAULT_FILE_LIMIT: usize = fsx::VAULT_FILE_LIMIT;

/// Why a store could not be read or written, with Python's wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreFault {
    /// Python `PermissionError`: the file is a link, not ours, or not 0600.
    NotPrivate(String),
    /// Python `ValueError`: malformed or over-limit content.
    Invalid(String),
    /// Python `OSError` other than the above.
    Io(String),
    /// Python `VaultOriginError`: the vault was not created or approved here.
    Origin(String),
    /// Python `VaultStructureError`: the store path is a link or not a file.
    Structure(String),
    /// Python `UnicodeDecodeError`: the token store is not UTF-8.
    Decode(String),
}

impl StoreFault {
    pub fn message(&self) -> &str {
        match self {
            StoreFault::NotPrivate(m)
            | StoreFault::Invalid(m)
            | StoreFault::Io(m)
            | StoreFault::Origin(m)
            | StoreFault::Structure(m)
            | StoreFault::Decode(m) => m,
        }
    }
}

impl fmt::Display for StoreFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for StoreFault {}

impl From<StoreError> for StoreFault {
    fn from(error: StoreError) -> Self {
        StoreFault::Io(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Grants,
    Tokens,
}

impl StoreKind {
    pub fn filename(self) -> &'static str {
        match self {
            StoreKind::Grants => "run_grants.json",
            StoreKind::Tokens => "capability_tokens.json",
        }
    }

    fn field(self) -> &'static str {
        match self {
            StoreKind::Grants => "grants",
            StoreKind::Tokens => "tokens",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            StoreKind::Grants => "grant store",
            StoreKind::Tokens => "capability token store",
        }
    }

    fn records_noun(self) -> &'static str {
        match self {
            StoreKind::Grants => "grant",
            StoreKind::Tokens => "capability",
        }
    }

    pub const MAX_RECORDS: usize = 1000;
}

pub fn secrets_dir(project_root: &Path) -> PathBuf {
    project_root.join(".secrets")
}

pub fn store_path(project_root: &Path, kind: StoreKind) -> PathBuf {
    secrets_dir(project_root).join(kind.filename())
}

/// Python's `secrets_dir()` refuses a vault that was not created or approved
/// on this machine before any store is read or written.
fn require_local(project_root: &Path) -> Result<(), StoreFault> {
    kv_store::vault_origin::require_local(project_root)
        .map(|_| ())
        .map_err(|error| StoreFault::Origin(error.to_string()))
}

#[cfg(unix)]
fn is_private(metadata: &std::fs::Metadata, check_owner: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    (metadata.mode() & 0o777) == PRIVATE_FILE_MODE
        && (!check_owner || metadata.uid() == rustix::process::getuid().as_raw())
}

#[cfg(not(unix))]
fn is_private(_metadata: &std::fs::Metadata, _check_owner: bool) -> bool {
    // Windows private ACL checks arrive with the Windows stage; refuse until then.
    false
}

/// Read a store's records; an absent file is the empty store.
pub fn read_records(
    project_root: &Path,
    kind: StoreKind,
) -> Result<Vec<Map<String, Value>>, StoreFault> {
    require_local(project_root)?;
    let path = store_path(project_root, kind);
    let shown = path.display().to_string();
    if !fsx::strictly_present(&path)? {
        return Ok(Vec::new());
    }
    let not_private = || StoreFault::NotPrivate(format!("{} is not private: {shown}", kind.noun()));
    let named = std::fs::symlink_metadata(&path).map_err(|e| StoreFault::Io(e.to_string()))?;
    if named.file_type().is_symlink() {
        return Err(StoreFault::Structure(format!(
            ".secrets/{} must be a regular private file, not a symlink or reparse point",
            kind.filename()
        )));
    }
    if !named.is_file() {
        return Err(StoreFault::Structure(format!(
            ".secrets/{} must be a regular private file",
            kind.filename()
        )));
    }
    let (raw, metadata) =
        match fsx::read_regular_limit_with_metadata(&path, kind.noun(), VAULT_FILE_LIMIT) {
            Ok(read) => read,
            Err(StoreError::TooLarge { .. }) => {
                return Err(StoreFault::Invalid(format!(
                    "{} is corrupted: {shown}",
                    kind.noun()
                )));
            }
            Err(_) if kind == StoreKind::Tokens => return Err(not_private()),
            Err(error) => return Err(error.into()),
        };
    // Grants check the mode first; tokens check owner and mode after reading.
    if !is_private(&metadata, kind == StoreKind::Tokens) {
        return Err(not_private());
    }
    let text = match std::str::from_utf8(&raw) {
        Ok(text) => text,
        Err(error) if kind == StoreKind::Tokens => {
            // Python decodes before parsing and lets the UnicodeDecodeError escape.
            return Err(StoreFault::Decode(python_decode_error(&raw, &error)));
        }
        Err(_) => {
            return Err(StoreFault::Invalid(format!(
                "{} is corrupted: {shown}",
                kind.noun()
            )));
        }
    };
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Err(StoreFault::Invalid(format!(
            "{} is corrupted: {shown}",
            kind.noun()
        )));
    };
    let Some(object) = doc.as_object() else {
        return Err(StoreFault::Invalid(format!(
            "{} must be a JSON object",
            kind.noun()
        )));
    };
    if !crate::normalize::py_eq(
        object.get("version").unwrap_or(&Value::Null),
        &Value::from(1),
    ) {
        return Err(StoreFault::Invalid(format!(
            "unsupported {} version",
            kind.noun()
        )));
    }
    let Some(records) = object.get(kind.field()).and_then(Value::as_array) else {
        return Err(StoreFault::Invalid(format!(
            "{} {} must be a list",
            kind.noun(),
            kind.field()
        )));
    };
    if records.len() > StoreKind::MAX_RECORDS {
        return Err(StoreFault::Invalid(format!(
            "{} has too many records",
            kind.noun()
        )));
    }
    let invalid_records = || {
        StoreFault::Invalid(format!(
            "invalid or duplicate {} records",
            kind.records_noun()
        ))
    };
    let objects: Vec<&Map<String, Value>> = records.iter().filter_map(Value::as_object).collect();
    if objects.len() != records.len() {
        return Err(invalid_records());
    }
    let id_key = match kind {
        StoreKind::Grants => "grant_id",
        StoreKind::Tokens => "token_id",
    };
    unique_nonempty_strings(objects.iter().map(|r| r.get(id_key)), true)
        .ok_or_else(invalid_records)?;
    if kind == StoreKind::Tokens {
        unique_nonempty_strings(objects.iter().map(|r| r.get("token_hash")), true)
            .ok_or_else(invalid_records)?;
    }
    unique_nonempty_strings(
        objects
            .iter()
            .filter_map(|r| r.get("admission_id"))
            .map(Some),
        true,
    )
    .ok_or_else(|| {
        StoreFault::Invalid(format!(
            "invalid or duplicate {} admissions",
            kind.records_noun()
        ))
    })?;
    Ok(objects.into_iter().cloned().collect())
}

/// `'utf-8' codec can't decode byte 0x.. in position N: <reason>` as Python words it.
fn python_decode_error(raw: &[u8], error: &std::str::Utf8Error) -> String {
    let position = error.valid_up_to();
    let byte = raw[position];
    if error.error_len().is_none() {
        // A truncated sequence: Python names the whole tail when it spans bytes.
        let last = raw.len() - 1;
        return if last > position {
            format!(
                "'utf-8' codec can't decode bytes in position {position}-{last}: unexpected end of data"
            )
        } else {
            format!(
                "'utf-8' codec can't decode byte 0x{byte:02x} in position {position}: unexpected end of data"
            )
        };
    }
    let reason = if (0x80..=0xBF).contains(&byte) || byte == 0xC0 || byte == 0xC1 || byte >= 0xF5 {
        "invalid start byte"
    } else {
        "invalid continuation byte"
    };
    format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {position}: {reason}")
}

fn unique_nonempty_strings<'a>(
    values: impl Iterator<Item = Option<&'a Value>>,
    required: bool,
) -> Option<()> {
    let mut seen = std::collections::HashSet::new();
    for value in values {
        match value {
            Some(Value::String(text)) if !text.is_empty() => {
                if !seen.insert(text.as_str()) {
                    return None;
                }
            }
            _ if required => return None,
            _ => {}
        }
    }
    Some(())
}

/// Python `json.dumps(sort_keys=True)`: sort every object's keys by code point.
pub fn sorted_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), sorted_keys(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted_keys).collect()),
        other => other.clone(),
    }
}

/// `json.dumps(doc, indent=2, sort_keys=True) + "\n"` as UTF-8 bytes.
pub fn store_bytes(kind: StoreKind, records: &[Map<String, Value>]) -> Result<Vec<u8>, StoreFault> {
    let mut doc = Map::new();
    doc.insert("version".into(), Value::from(1));
    doc.insert(
        kind.field().into(),
        Value::Array(records.iter().cloned().map(Value::Object).collect()),
    );
    // Records hold integers and text only; a float means a record kv did not write.
    pyjson::to_vec_indent2_ascii(&sorted_keys(&Value::Object(doc))).map_err(|_| {
        StoreFault::Invalid(format!(
            "the {} holds a value kv cannot write exactly",
            kind.noun()
        ))
    })
}

/// Replace a store's records atomically (0600), keeping the vault ignore rules.
pub fn write_records(
    project_root: &Path,
    kind: StoreKind,
    records: &[Map<String, Value>],
) -> Result<(), StoreFault> {
    require_local(project_root)?;
    let sdir = secrets_dir(project_root);
    require_dir(&sdir)?;
    update_vault_ignores(&sdir, &[kind.filename()], false, Some(IGNORE_HEADER))?;
    let payload = store_bytes(kind, records)?;
    if payload.len() > VAULT_FILE_LIMIT {
        return Err(StoreFault::Invalid(format!(
            "the {} is larger than kv writes (64 MiB)",
            kind.noun()
        )));
    }
    fsx::write_atomic_limit(
        &store_path(project_root, kind),
        &payload,
        false,
        VAULT_FILE_LIMIT,
        kind.noun(),
    )?;
    Ok(())
}

/// `.secrets` must be a real directory, made 0700 when missing.
fn require_dir(path: &Path) -> Result<(), StoreFault> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(StoreFault::Io(format!(
            "{} must be a real directory",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path)
                    .map_err(|e| StoreFault::Io(e.to_string()))
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir(path).map_err(|e| StoreFault::Io(e.to_string()))
            }
        }
        Err(error) => Err(StoreFault::Io(error.to_string())),
    }
}
