use crate::{StoreError, config, fsx, pyjson};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

const FILE: &str = "policy_requests.json";
const FIELDS: &[&str] = &[
    "request_id",
    "status",
    "pattern",
    "allowed_pattern",
    "argv",
    "cwd",
    "created_at_epoch",
    "expires_at_epoch",
    "command_reason",
    "command_mode",
    "reason",
    "source",
    "actor",
];
fn error(text: impl Into<String>) -> StoreError {
    StoreError::ConfigConflict(text.into())
}
pub fn store_path(root: &Path) -> PathBuf {
    root.join(".secrets").join(FILE)
}
pub fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
pub fn epoch(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
        .or_else(|| value.as_f64().filter(|v| v.is_finite()).map(|v| v as i64))
        .or_else(|| value.as_bool().map(i64::from))
}
pub fn status(request: &Value, now: i64) -> String {
    let raw = &request["status"];
    let truthy = match raw {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Number(value) => value.as_f64() != Some(0.0),
    };
    if truthy && raw != "pending" {
        return crate::approval_refs::py_str(raw);
    }
    if epoch(&request["expires_at_epoch"]).unwrap_or(0) <= now {
        "expired".into()
    } else {
        "pending".into()
    }
}
fn id(raw: &str) -> Result<String, StoreError> {
    if raw.trim().is_empty() {
        return Err(error("request_id must be a non-empty string"));
    }
    Ok(raw.trim().chars().take(80).collect())
}
fn read(root: &Path) -> Result<Vec<Value>, StoreError> {
    let path = store_path(root);
    if !fsx::strictly_present(&path)? {
        return Ok(Vec::new());
    }
    if cfg!(windows) {
        return Err(error(
            "policy request store privacy verification is not available in this build",
        ));
    }
    #[cfg(target_os = "macos")]
    if !exacl::getfacl(&path, None)
        .map_err(|e| error(e.to_string()))?
        .is_empty()
    {
        return Err(error(format!(
            "policy request store is not private: {}",
            path.display()
        )));
    }
    let (raw, metadata) =
        fsx::read_regular_limit_with_metadata(&path, "policy request store", 64 * 1024 * 1024)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(error(format!(
                "policy request store is not private: {}",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let doc: Value = serde_json::from_slice(&raw).map_err(|_| {
        error(format!(
            "policy request store is corrupted: {}",
            path.display()
        ))
    })?;
    if !doc.is_object() {
        return Err(error("policy request store must be a JSON object"));
    }
    if doc.get("version") != Some(&json!(true))
        && doc.get("version").and_then(Value::as_f64) != Some(1.0)
    {
        return Err(error("unsupported policy request store version"));
    }
    let requests = doc["requests"]
        .as_array()
        .ok_or_else(|| error("policy request store requests must be a list"))?;
    if requests.len() > 1001 {
        return Err(error("policy request store has too many records"));
    }
    if requests.iter().any(|v| !v.is_object()) {
        return Err(error("policy request store contains invalid records"));
    }
    Ok(requests.clone())
}
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|k| (k.clone(), sorted(&map[k])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        value => value.clone(),
    }
}
fn pretty(value: &Value, depth: usize) -> Result<String, StoreError> {
    let indent = "  ".repeat(depth);
    let child = "  ".repeat(depth + 1);
    match value {
        Value::Array(items) if !items.is_empty() => Ok(format!(
            "[\n{}\n{indent}]",
            items
                .iter()
                .map(|v| pretty(v, depth + 1).map(|s| format!("{child}{s}")))
                .collect::<Result<Vec<_>, _>>()?
                .join(",\n")
        )),
        Value::Object(items) if !items.is_empty() => Ok(format!(
            "{{\n{}\n{indent}}}",
            items
                .iter()
                .map(|(k, v)| Ok(format!(
                    "{child}{}: {}",
                    pretty(&json!(k), depth + 1)?,
                    pretty(v, depth + 1)?
                )))
                .collect::<Result<Vec<_>, StoreError>>()?
                .join(",\n")
        )),
        _ => Ok(String::from_utf8(pyjson::to_vec_python(value, false)?).expect("ASCII JSON")),
    }
}
fn write(root: &Path, requests: &[Value], previous_count: usize) -> Result<(), StoreError> {
    if requests.len() > if previous_count == 1001 { 1001 } else { 1000 } {
        return Err(error("policy request store has too many records"));
    }
    let payload = format!(
        "{}\n",
        pretty(&sorted(&json!({"version":1,"requests":requests})), 0)?
    )
    .into_bytes();
    let sdir = root.join(".secrets");
    {
        let _guard = config::config_lock(root)?;
        config::update_vault_ignores(
            &sdir,
            &[FILE],
            false,
            Some("# Local-only kv runtime records"),
        )?;
    }
    fsx::write_atomic_limit(
        &store_path(root),
        &payload,
        false,
        64 * 1024 * 1024,
        "the policy request store",
    )
}
fn lock(root: &Path) -> Result<fsx::StorageLock, StoreError> {
    fsx::lock_storage(&root.join(".secrets")).map_err(|e| match e {
        StoreError::Io(ref io) if io.kind() != std::io::ErrorKind::PermissionDenied => {
            error("policy request store is busy or unavailable; retry")
        }
        other => other,
    })
}
pub fn list(root: &Path, include_all: bool, now: i64) -> Result<Vec<Value>, StoreError> {
    Ok(read(root)?
        .into_iter()
        .filter_map(|mut r| {
            let state = status(&r, now);
            if !include_all && state != "pending" {
                return None;
            }
            r["effective_status"] = json!(state);
            Some(r)
        })
        .collect())
}
pub fn get(root: &Path, request_id: &str, now: i64) -> Result<Option<Value>, StoreError> {
    let request_id = id(request_id)?;
    Ok(list(root, true, now)?
        .into_iter()
        .find(|r| r["request_id"] == request_id))
}
pub fn fingerprint(request: &Value) -> Result<String, StoreError> {
    let bound = Value::Object(
        FIELDS
            .iter()
            .map(|key| {
                (
                    (*key).into(),
                    request.get(*key).cloned().unwrap_or(Value::Null),
                )
            })
            .collect(),
    );
    Ok(format!(
        "{:x}",
        Sha256::digest(pyjson::to_vec_python(&bound, true)?)
    ))
}
fn iso(now: i64) -> Result<String, StoreError> {
    let time = OffsetDateTime::from_unix_timestamp(now).map_err(|e| error(e.to_string()))?;
    let format = time::format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]T[hour]:[minute]:[second]Z",
    )
    .map_err(|e| error(e.to_string()))?;
    time.format(&format).map_err(|e| error(e.to_string()))
}
fn mark(
    root: &Path,
    request_id: &str,
    state: &str,
    reason: Option<&str>,
    pattern: Option<&str>,
    now: i64,
) -> Result<bool, StoreError> {
    let request_id = id(request_id)?;
    let mut requests = read(root)?;
    let Some(request) = requests.iter_mut().find(|r| r["request_id"] == request_id) else {
        return Ok(false);
    };
    if status(request, now) != "pending" {
        return Ok(false);
    }
    request["status"] = json!(state);
    request["updated_at"] = json!(iso(now)?);
    request["updated_at_epoch"] = json!(now);
    if let Some(reason) = reason.map(str::trim).filter(|s| !s.is_empty()) {
        request[if state == "allowed" {
            "allow_reason"
        } else {
            "block_reason"
        }] = json!(reason.chars().take(512).collect::<String>());
    }
    if let Some(pattern) = pattern {
        request["allowed_pattern"] = json!(pattern);
    }
    write(root, &requests, requests.len())?;
    Ok(true)
}
pub fn block(
    root: &Path,
    request_id: &str,
    reason: Option<&str>,
    now: i64,
) -> Result<bool, StoreError> {
    let _guard = lock(root)?;
    mark(root, request_id, "blocked", reason, None, now)
}
pub fn prune(root: &Path, now: i64) -> Result<usize, StoreError> {
    let _guard = lock(root)?;
    let requests = read(root)?;
    let current = requests
        .iter()
        .filter(|r| status(r, now) == "pending")
        .cloned()
        .collect::<Vec<_>>();
    if current.len() != requests.len() {
        write(root, &current, requests.len())?;
    }
    Ok(current.len())
}
pub fn allow(
    root: &Path,
    request_id: &str,
    target: &Path,
    snapshot: &config::ConfigSnapshot,
    reviewed: &str,
    reason: Option<&str>,
    broad_reason: impl Fn(&str) -> String,
) -> Result<bool, StoreError> {
    if std::fs::canonicalize(root.join(".secrets"))?
        != std::fs::canonicalize(target.join(".secrets"))?
    {
        return Err(error(
            "a policy decision and its allowlist must share one vault",
        ));
    }
    let _guard = lock(root)?;
    let now = now();
    let request = get(root, request_id, now)?
        .ok_or_else(|| error(format!("command-policy request not found: {request_id}")))?;
    let state = status(&request, now);
    if fingerprint(&request)? != reviewed {
        return Err(error(if state != "pending" {
            format!("command-policy request is now {state}; this command changed nothing")
        } else {
            "command-policy request changed after you reviewed it; nothing was allowed. Review it again.".into()
        }));
    }
    if state != "pending" {
        return Ok(false);
    }
    let raw = request["pattern"]
        .as_str()
        .ok_or_else(|| error("policy pattern must be a non-empty string"))?;
    let pattern = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if pattern.is_empty() {
        return Err(error("policy pattern must be a non-empty string"));
    }
    if pattern.len() > 4096 {
        return Err(error("policy pattern exceeds 4096 bytes"));
    }
    let broad = broad_reason(&pattern);
    if !broad.is_empty() {
        return Err(error(broad));
    }
    config::config_write_guard(target, snapshot, || {
        if !mark(root, request_id, "allowed", reason, Some(&pattern), now)? {
            return Ok(false);
        }
        config::add_allowed_command(target, &pattern)?;
        Ok(true)
    })
}
