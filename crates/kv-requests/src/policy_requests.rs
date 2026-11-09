use std::path::{Path, PathBuf};

use kv_sandbox::classify::{allowlist_hint_for_argv, broad_secret_allowlist_reason};
use kv_store::{StoreError, approval_refs::py_str, config, fsx, pyjson};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::approvals::{
    argv, check_secrets_dir, cwd, epoch, iso, normalize_actor, normalize_reason, private_read,
    py_int, py_trim, short_text, sorted, truthy,
};
use crate::{RequestError, Result, invalid};

pub const POLICY_REQUESTS_FILE: &str = "policy_requests.json";
pub const MAX_STORED_POLICY_REQUESTS: usize = 1000;
pub const DEFAULT_REQUEST_TTL_SECONDS: i64 = 900;
pub const MAX_REQUEST_TTL_SECONDS: i64 = 86400;
pub const FINGERPRINT_FIELDS: &[&str] = &[
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

pub fn policy_request_store_path(root: &Path) -> PathBuf {
    root.join(".secrets").join(POLICY_REQUESTS_FILE)
}

pub fn policy_pattern_for_argv(value: &Value) -> Result<String> {
    // Python first materializes the iterable with list(argv).
    let value = match value {
        Value::String(text) => json!(text.chars().map(|c| c.to_string()).collect::<Vec<_>>()),
        Value::Object(map) => json!(map.keys().collect::<Vec<_>>()),
        Value::Array(_) => value.clone(),
        _ => {
            return Err(invalid(format!(
                "'{}' object is not iterable",
                python_type(value)
            )));
        }
    };
    let normalized = argv(&value)?;
    let parts = normalized
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let pattern = allowlist_hint_for_argv(&parts);
    if pattern.len() > 4096 {
        return Err(invalid("policy pattern exceeds 4096 bytes"));
    }
    Ok(pattern)
}

fn normalize_pattern(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .filter(|s| !py_trim(s).is_empty())
        .ok_or_else(|| invalid("policy pattern must be a non-empty string"))?;
    let pattern = text
        .split(|c: char| c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}'))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if pattern.len() > 4096 {
        return Err(invalid("policy pattern exceeds 4096 bytes"));
    }
    Ok(pattern)
}

fn request_id(value: &Value) -> Result<String> {
    if value.is_null() {
        let mut random = [0; 12];
        getrandom::getrandom(&mut random)
            .map_err(|_| invalid("operating-system randomness unavailable"))?;
        return Ok(format!("pol_{}", hex::encode(random)));
    }
    short_text(value, 80).ok_or_else(|| invalid("request_id must be a non-empty string"))
}

pub fn effective_status(request: &Value, now: Option<i64>) -> String {
    if truthy(&request["status"]) && request["status"] != "pending" {
        return py_str(&request["status"]);
    }
    if py_int(&request["expires_at_epoch"]).unwrap_or(0) <= epoch(now) {
        "expired"
    } else {
        "pending"
    }
    .into()
}

pub fn create_policy_request(root: &Path, options: &Value) -> Result<Value> {
    let ttl = if options.get("ttl_seconds").is_none() {
        DEFAULT_REQUEST_TTL_SECONDS
    } else {
        py_int(&options["ttl_seconds"]).ok_or_else(|| invalid("ttl_seconds must be an integer"))?
    };
    if !(1..=MAX_REQUEST_TTL_SECONDS).contains(&ttl) {
        return Err(invalid("ttl_seconds must be between 1 and 86400"));
    }
    let args = argv(&options["argv"])?;
    let pattern = normalize_pattern(&if truthy(&options["pattern"]) {
        options["pattern"].clone()
    } else {
        policy_pattern_for_argv(&args)?.into()
    })?;
    let mut request = json!({
        "request_id": request_id(&options["request_id"])?,
        "status": "pending", "argv": args, "cwd": cwd(&options["cwd"])?,
        "pattern": pattern, "actor": normalize_actor(&options["actor"]),
        "reason": normalize_reason(&options["reason"]), "source": short_text(&options["source"], 80),
        "command_reason": normalize_reason(&options["command_reason"]),
        "command_mode": short_text(&options["command_mode"], 40),
    });
    request.as_object_mut().unwrap().retain(|_, v| !v.is_null());
    let _lock = store_lock(root)?;
    let now = epoch(if options["now"].is_null() {
        None
    } else {
        Some(py_int(&options["now"]).ok_or_else(|| invalid("now must be an integer"))?)
    });
    for prefix in ["created", "updated", "expires"] {
        let timestamp = if prefix == "expires" {
            now.checked_add(ttl)
                .ok_or_else(|| invalid("timestamp out of range"))?
        } else {
            now
        };
        request[format!("{prefix}_at")] = iso(timestamp)?.into();
        request[format!("{prefix}_at_epoch")] = timestamp.into();
    }
    let mut records = read_store(root)?;
    if let Some(existing) = records.iter().find(|r| {
        effective_status(r, Some(now)) == "pending"
            && ["argv", "cwd", "pattern", "actor"]
                .iter()
                .all(|k| r[*k] == request[*k])
    }) {
        return Ok(existing.clone());
    }
    if records.len() >= MAX_STORED_POLICY_REQUESTS {
        return Err(invalid(
            "policy request store is full (1000 records); review requests, then run 'kv policy prune' to remove expired, allowed, or blocked records",
        ));
    }
    if records
        .iter()
        .any(|r| r["request_id"] == request["request_id"])
    {
        return Err(invalid("policy request id already exists"));
    }
    records.push(request.clone());
    write_store(root, records, 0)?;
    Ok(request)
}

pub fn list_policy_requests(
    root: &Path,
    include_all: bool,
    now: Option<i64>,
) -> Result<Vec<Value>> {
    let now = epoch(now);
    Ok(read_store(root)?
        .into_iter()
        .filter_map(|mut request| {
            let status = effective_status(&request, Some(now));
            if !include_all && status != "pending" {
                return None;
            }
            request["effective_status"] = status.into();
            Some(request)
        })
        .collect())
}

pub fn get_policy_request(root: &Path, id: &Value, now: Option<i64>) -> Result<Option<Value>> {
    let id = request_id(id)?;
    let now = epoch(now);
    for mut request in read_store(root)? {
        if request["request_id"] == id {
            request["effective_status"] = effective_status(&request, Some(now)).into();
            return Ok(Some(request));
        }
    }
    Ok(None)
}

pub fn mark_policy_request_allowed(
    root: &Path,
    id: &Value,
    reason: &Value,
    now: Option<i64>,
) -> Result<bool> {
    let _lock = store_lock(root)?;
    mark_request_in_held_lock(
        root,
        id,
        "allowed",
        now,
        &json!({"allow_reason": normalize_reason(reason)}),
    )
}

pub fn block_policy_request(
    root: &Path,
    id: &Value,
    reason: &Value,
    now: Option<i64>,
) -> Result<bool> {
    let _lock = store_lock(root)?;
    mark_request_in_held_lock(
        root,
        id,
        "blocked",
        now,
        &json!({"block_reason": normalize_reason(reason)}),
    )
}

pub fn mark_request_in_held_lock(
    root: &Path,
    id: &Value,
    status: &str,
    now: Option<i64>,
    fields: &Value,
) -> Result<bool> {
    fsx::require_storage_lock(&root.join(".secrets"))?;
    let id = request_id(id)?;
    let now = epoch(now);
    let mut records = read_store(root)?;
    let count = records.len();
    for request in &mut records {
        if request["request_id"] != id {
            continue;
        }
        if effective_status(request, Some(now)) != "pending" {
            return Ok(false);
        }
        request["status"] = status.into();
        request["updated_at"] = iso(now)?.into();
        request["updated_at_epoch"] = now.into();
        let fields = fields
            .as_object()
            .ok_or_else(|| invalid("fields must be an object"))?;
        for (key, value) in fields {
            if !value.is_null() {
                request[key] = value.clone();
            }
        }
        write_store(root, records, count)?;
        return Ok(true);
    }
    Ok(false)
}

pub fn prune_policy_requests(root: &Path, now: Option<i64>) -> Result<usize> {
    let _lock = store_lock(root)?;
    let now = epoch(now);
    let mut records = read_store(root)?;
    let previous_count = records.len();
    records.retain(|r| effective_status(r, Some(now)) == "pending");
    let remaining = records.len();
    if remaining != previous_count {
        write_store(root, records, previous_count)?;
    }
    Ok(remaining)
}

pub fn request_fingerprint(request: &Value) -> Result<String> {
    if !request.is_object() {
        return Err(invalid(format!(
            "'{}' object has no attribute 'get'",
            python_type(request)
        )));
    }
    let bound = Value::Object(
        FINGERPRINT_FIELDS
            .iter()
            .map(|key| ((*key).to_owned(), request[*key].clone()))
            .collect(),
    );
    Ok(hex::encode(Sha256::digest(pyjson::to_vec_python(
        &bound, true,
    )?)))
}

fn python_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.to_string().contains(['.', 'e', 'E']) => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

pub struct AllowPolicyRequest<'a> {
    pub snapshot: &'a config::ConfigSnapshot,
    pub expected_fingerprint: &'a str,
    pub reason: &'a Value,
    pub now: Option<i64>,
}

/// Marks the decision before calling the application's pattern writer, under both vault locks.
pub fn allow_policy_request(
    root: &Path,
    id: &Value,
    target_root: &Path,
    options: AllowPolicyRequest<'_>,
    add_pattern: impl FnOnce(&Path, &str) -> std::result::Result<(), StoreError>,
) -> Result<bool> {
    if std::fs::canonicalize(root.join(".secrets"))?
        != std::fs::canonicalize(target_root.join(".secrets"))?
    {
        return Err(invalid(
            "a policy decision and its allowlist must share one vault",
        ));
    }
    let _lock = store_lock(root)?;
    let request = get_policy_request(root, id, options.now)?
        .ok_or_else(|| invalid(format!("command-policy request not found: {}", py_str(id))))?;
    let status = request["effective_status"].as_str().unwrap();
    if request_fingerprint(&request)? != options.expected_fingerprint {
        return Err(invalid(if status != "pending" {
            format!("command-policy request is now {status}; this command changed nothing")
        } else {
            "command-policy request changed after you reviewed it; nothing was allowed. Review it again.".into()
        }));
    }
    if status != "pending" {
        return Ok(false);
    }
    let pattern = normalize_pattern(&if truthy(&request["pattern"]) {
        request["pattern"].clone()
    } else {
        json!("")
    })?;
    let broad = broad_secret_allowlist_reason(&pattern);
    if !broad.is_empty() {
        return Err(invalid(broad));
    }
    Ok(config::config_write_guard(
        target_root,
        options.snapshot,
        || {
            let marked = mark_request_in_held_lock(root, &request["request_id"], "allowed", options.now, &json!({"allow_reason": normalize_reason(options.reason), "allowed_pattern": pattern})).map_err(|error| match error {
            RequestError::Store(error) => error,
            other => StoreError::ConfigConflict(other.to_string()),
        })?;
            if !marked {
                return Ok(false);
            }
            add_pattern(target_root, &pattern)?;
            Ok(true)
        },
    )?)
}

fn store_lock(root: &Path) -> Result<fsx::StorageLock> {
    check_secrets_dir(root)?;
    #[cfg(not(unix))]
    {
        Err(invalid(
            "private vault files require Unix permission validation",
        ))
    }
    #[cfg(unix)]
    fsx::lock_storage(&root.join(".secrets")).map_err(|error| match error {
        StoreError::Io(error) if error.kind() != std::io::ErrorKind::PermissionDenied => {
            invalid("policy request store is busy or unavailable; retry")
        }
        other => other.into(),
    })
}

fn read_store(root: &Path) -> Result<Vec<Value>> {
    check_secrets_dir(root)?;
    let path = policy_request_store_path(root);
    if !fsx::strictly_present(&path)? {
        return Ok(vec![]);
    }
    let raw = private_read(&path, "policy request store", fsx::VAULT_FILE_LIMIT)?;
    let doc: Value = serde_json::from_slice(&raw).map_err(|_| {
        invalid(format!(
            "policy request store is corrupted: {}",
            path.display()
        ))
    })?;
    if !doc.is_object() {
        return Err(invalid("policy request store must be a JSON object"));
    }
    if doc["version"] != 1 && doc["version"] != true && doc["version"].as_f64() != Some(1.0) {
        return Err(invalid("unsupported policy request store version"));
    }
    let records = doc["requests"]
        .as_array()
        .ok_or_else(|| invalid("policy request store requests must be a list"))?;
    if records.len() > MAX_STORED_POLICY_REQUESTS + 1 {
        return Err(invalid("policy request store has too many records"));
    }
    if records.iter().any(|r| !r.is_object()) {
        return Err(invalid("policy request store contains invalid records"));
    }
    Ok(records.clone())
}

fn write_store(root: &Path, records: Vec<Value>, previous_count: usize) -> Result<()> {
    if records.len() > if previous_count == 1001 { 1001 } else { 1000 } {
        return Err(invalid("policy request store has too many records"));
    }
    let mut doc = json!({"version": 1, "requests": records});
    sorted(&mut doc);
    let payload = pyjson::to_vec_indent2_ascii_python(&doc)?;
    if payload.len() > fsx::VAULT_FILE_LIMIT {
        return Err(invalid(format!(
            "the policy request store would be {} bytes; a vault file is at most {} bytes",
            payload.len(),
            fsx::VAULT_FILE_LIMIT
        )));
    }
    {
        let _guard = config::config_lock(root)?;
        config::update_vault_ignores(
            &root.join(".secrets"),
            &[POLICY_REQUESTS_FILE],
            false,
            Some("# Local-only kv runtime records"),
        )?;
    }
    let path = policy_request_store_path(root);
    if fsx::strictly_present(&path)? {
        private_read(&path, "policy request store", fsx::VAULT_FILE_LIMIT)?;
    }
    fsx::write_atomic_limit(
        &path,
        &payload,
        false,
        fsx::VAULT_FILE_LIMIT,
        "the policy request store",
    )?;
    Ok(())
}
