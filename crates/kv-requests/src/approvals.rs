use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE};
use kv_approvals::artifacts;
use kv_crypto::Zeroizing;
use kv_store::{approval_refs::py_str, fsx, pyjson};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, invalid};

pub use kv_approvals::wire::request_content_digest;

pub const APPROVAL_REQUESTS_FILE: &str = "approval_requests.json";
pub const MAX_STORED_APPROVAL_REQUESTS: usize = 1000;
pub const DEFAULT_REQUEST_TTL_SECONDS: i64 = 900;
pub const MAX_REQUEST_TTL_SECONDS: i64 = 86400;
pub const MISSED_RETENTION_SECONDS: i64 = 86400;

/// Application-owned risk assessment and capability budget normalization.
pub trait RequestHooks {
    fn build_run_risk_card(&self, inputs: &Value) -> Result<Value>;
    fn normalize_risk_card(&self, card: &Value) -> Result<Value>;
    fn normalize_service_calls(
        &self,
        names: &[String],
        max_calls: &Value,
        calls_per_service: &Value,
    ) -> Result<(Value, Value)>;
}

pub fn approval_store_path(root: &Path) -> PathBuf {
    root.join(".secrets").join(APPROVAL_REQUESTS_FILE)
}

pub fn normalize_reason(value: &Value) -> Option<String> {
    short_text(value, 512)
}

pub fn normalize_actor(actor: &Value) -> Value {
    let mut result = json!({});
    for key in [
        "source",
        "client_name",
        "client_version",
        "session_id",
        "user_id",
    ] {
        if let Some(text) = short_text(&actor[key], 128) {
            result[key] = text.into();
        }
    }
    result
}

pub(crate) fn short_text(value: &Value, limit: usize) -> Option<String> {
    value
        .as_str()
        .map(py_trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(limit).collect())
}

pub(crate) fn py_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}'))
}

pub(crate) fn epoch(now: Option<i64>) -> i64 {
    now.unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp())
}

pub(crate) fn iso(now: i64) -> Result<String> {
    let date = time::OffsetDateTime::from_unix_timestamp(now)
        .map_err(|_| invalid("timestamp out of range"))?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date.year(),
        u8::from(date.month()),
        date.day(),
        date.hour(),
        date.minute(),
        date.second()
    ))
}

pub(crate) fn py_int(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(v) => Some(i64::from(*v)),
        Value::Number(n) => n.as_i64().or_else(|| {
            n.as_f64()
                .filter(|v| v.is_finite())
                .map(|v| v.trunc() as i64)
        }),
        Value::String(s) => {
            let s = s.trim();
            let mut normalized = String::new();
            let chars: Vec<char> = s.chars().map(|c| decimal_digit(c).unwrap_or(c)).collect();
            for (i, c) in chars.iter().copied().enumerate() {
                if c == '_' {
                    if i == 0
                        || i + 1 == chars.len()
                        || !chars[i - 1].is_ascii_digit()
                        || !chars[i + 1].is_ascii_digit()
                    {
                        return None;
                    }
                } else if c.is_ascii_digit() || (i == 0 && matches!(c, '+' | '-')) {
                    normalized.push(c);
                } else {
                    return None;
                }
            }
            normalized.parse().ok().or_else(|| {
                let digits = normalized.trim_start_matches(['+', '-']);
                if digits.is_empty() {
                    None
                } else {
                    Some(if normalized.starts_with('-') {
                        i64::MIN
                    } else {
                        i64::MAX
                    })
                }
            })
        }
        _ => None,
    }
}

fn decimal_digit(c: char) -> Option<char> {
    // Unicode 13 decimal zeroes, matching the canonical Python 3.10 oracle.
    const ZEROES: &[u32] = &[
        0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
        0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
        0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0,
        0xff10, 0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0,
        0x11650, 0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x16a60, 0x16b50,
        0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e950, 0x1fbf0,
    ];
    ZEROES.iter().find_map(|zero| {
        (u32::from(c).checked_sub(*zero))
            .filter(|digit| *digit < 10)
            .map(|digit| char::from(b'0' + digit as u8))
    })
}

pub(crate) fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Number(_) => v.as_f64() != Some(0.0),
    }
}

pub fn effective_status(request: &Value, now: Option<i64>) -> String {
    if !request["withdrawn_at_epoch"].is_null() {
        return "withdrawn".into();
    }
    if [
        "approved_at",
        "approved_at_epoch",
        "approved_grant_id",
        "approval_reason",
    ]
    .iter()
    .any(|k| !request[*k].is_null())
    {
        return "approved".into();
    }
    if ["denied_at", "denied_at_epoch", "deny_reason"]
        .iter()
        .any(|k| !request[*k].is_null())
    {
        return "denied".into();
    }
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

pub fn is_missed_request(request: &Value, now: Option<i64>) -> bool {
    let now = epoch(now);
    effective_status(request, Some(now)) == "expired"
        && py_int(if truthy(&request["expires_at_epoch"]) {
            &request["expires_at_epoch"]
        } else {
            &Value::Null
        })
        .or_else(|| {
            if !truthy(&request["expires_at_epoch"]) {
                Some(0)
            } else {
                None
            }
        })
        .is_some_and(|expires| now < expires.saturating_add(MISSED_RETENTION_SECONDS))
}

fn request_id(value: &Value) -> Result<String> {
    if value.is_null() {
        let mut random = [0; 12];
        getrandom::getrandom(&mut random)
            .map_err(|_| invalid("operating-system randomness unavailable"))?;
        return Ok(format!("req_{}", hex::encode(random)));
    }
    short_text(value, 80).ok_or_else(|| invalid("request_id must be a non-empty string"))
}

fn hash(value: &Value, field: &str, required: bool) -> Result<Option<String>> {
    if value.is_null() {
        return if required {
            Err(invalid(format!("{field} is required")))
        } else {
            Ok(None)
        };
    }
    let s = value
        .as_str()
        .ok_or_else(|| invalid(format!("{field} must be a string")))?
        .to_lowercase();
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(format!("{field} must be a sha256 hex digest")));
    }
    Ok(Some(s))
}

fn identity(value: &Value) -> Result<Value> {
    if !value.is_object() {
        return Err(invalid("run_identity must be an object"));
    }
    let mut result = json!({"command_fingerprint": hash(&value["command_fingerprint"], "command_fingerprint", true)?});
    for field in ["script_sha256", "script_ref_hash"] {
        if let Some(s) = hash(&value[field], field, false)? {
            result[field] = s.into();
        }
    }
    if let Some(s) = short_text(&value["script_kind"], 40) {
        result["script_kind"] = s.into();
    }
    Ok(result)
}

fn scope(value: &Value, field: &str) -> Result<Vec<String>> {
    if value.is_null() {
        return Ok(vec![]);
    }
    let items = value
        .as_array()
        .ok_or_else(|| invalid(format!("{field} must be a list")))?;
    let mut result = BTreeSet::new();
    for (i, item) in items.iter().enumerate() {
        let s = item
            .as_str()
            .filter(|s| !py_trim(s).is_empty())
            .ok_or_else(|| invalid(format!("{field}[{i}] must be a non-empty string")))?;
        if s.len() > 256 {
            return Err(invalid(format!("{field}[{i}] exceeds 256 bytes")));
        }
        result.insert(py_trim(s).to_owned());
    }
    Ok(result.into_iter().collect())
}

pub(crate) fn argv(value: &Value) -> Result<Value> {
    let items = value
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| invalid("argv must be a non-empty list"))?;
    if items.len() > 128 {
        return Err(invalid("argv exceeds 128 items"));
    }
    for (i, item) in items.iter().enumerate() {
        let s = item
            .as_str()
            .ok_or_else(|| invalid(format!("argv[{i}] must be a string")))?;
        if i == 0 && s.is_empty() {
            return Err(invalid("argv[0] must be non-empty"));
        }
        if s.len() > 4096 {
            return Err(invalid(format!("argv[{i}] exceeds 4096 bytes")));
        }
    }
    Ok(value.clone())
}

pub(crate) fn cwd(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .filter(|s| !py_trim(s).is_empty())
        .ok_or_else(|| invalid("cwd must be a non-empty string"))?;
    let resolved = kv_hook::paths::resolve(text)?;
    if resolved.len() > 4096 {
        return Err(invalid("cwd exceeds 4096 bytes"));
    }
    Ok(resolved)
}

fn max_calls(value: &Value) -> Result<Value> {
    let n = if value.is_null() {
        1
    } else {
        py_int(value).ok_or_else(|| invalid("max_calls must be an integer"))?
    };
    if n <= 0 {
        return Err(invalid("max_calls must be positive"));
    }
    if n > 9007199254740991 {
        return Err(invalid(
            "max_calls must be at most 9007199254740991 (the largest exact JSON number)",
        ));
    }
    Ok(n.into())
}

/// Keyword arguments use Python's field names. `run_identity`, `argv` and `cwd` are required.
pub fn create_approval_request(
    root: &Path,
    options: &Value,
    hooks: &dyn RequestHooks,
    reuse_filter: Option<&dyn Fn(&Value) -> bool>,
) -> Result<Value> {
    let ttl = if options.get("ttl_seconds").is_none() {
        DEFAULT_REQUEST_TTL_SECONDS
    } else {
        py_int(&options["ttl_seconds"]).ok_or_else(|| invalid("ttl_seconds must be an integer"))?
    };
    if !(1..=MAX_REQUEST_TTL_SECONDS).contains(&ttl) {
        return Err(invalid("ttl_seconds must be between 1 and 86400"));
    }
    let ident = identity(&options["run_identity"])?;
    let secrets = scope(&options["secret_names"], "secret_names")?;
    let caps = scope(&options["capability_names"], "capability_names")?;
    if secrets.is_empty() && caps.is_empty() {
        return Err(invalid(
            "approval request requires at least one secret or capability",
        ));
    }
    if !secrets.is_empty() && !caps.is_empty() {
        return Err(invalid(
            "approval request cannot mix secrets and capabilities",
        ));
    }
    let per_service = &options["calls_per_service"];
    if !per_service.is_null() && caps.is_empty() {
        return Err(invalid(
            "calls_per_service applies only to capability requests",
        ));
    }
    let (calls, per_service) = if caps.len() > 1 || !per_service.is_null() {
        hooks.normalize_service_calls(&caps, &options["max_calls"], per_service)?
    } else {
        (
            if caps.is_empty() {
                Value::Null
            } else {
                max_calls(&options["max_calls"])?
            },
            Value::Null,
        )
    };
    let args = argv(&options["argv"])?;
    let cwd = cwd(&options["cwd"])?;
    let environment = &options["environment"];
    if !environment.is_null() && environment != "*" {
        let name = environment
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("environment name must be a non-empty string"))?;
        if name.len() > 128 {
            return Err(invalid("env exceeds 128 UTF-8 bytes"));
        }
        if kv_store::envname::has_path_syntax(name) {
            let quoted = py_str(&json!([name]));
            return Err(invalid(format!(
                "invalid environment name: {}; run 'kv env repair-names' to inspect old registrations",
                &quoted[1..quoted.len() - 1]
            )));
        }
    }
    let network = &options["network"];
    if !network.is_null() && !network.is_boolean() {
        return Err(invalid("network must be true or false"));
    }
    let network_reason = if network.is_null() {
        None
    } else {
        short_text(&options["network_reason"], 256)
    };
    if !network.is_null() && network_reason.is_none() {
        return Err(invalid("network_reason is required with network"));
    }
    let card = if !options["risk_card"].is_null() {
        hooks.normalize_risk_card(&options["risk_card"])?
    } else {
        hooks.build_run_risk_card(&json!({"argv": args, "cwd": cwd, "run_identity": ident, "secret_names": secrets, "capability_names": caps, "max_calls": calls, "source": if truthy(&options["source"]) { options["source"].clone() } else { json!("approval_request") }}))?
    };
    let mut request = json!({"request_id": request_id(&options["request_id"])?, "status": "pending", "argv": args, "cwd": cwd,
        "command_fingerprint": ident["command_fingerprint"], "script_kind": ident["script_kind"], "script_sha256": ident["script_sha256"], "script_ref_hash": ident["script_ref_hash"],
        "secret_names": secrets, "capability_names": caps, "actor": normalize_actor(&options["actor"]), "reason": normalize_reason(&options["reason"]),
        "source": short_text(&options["source"], 80), "risk_level": short_text(&options["risk_level"], 40).unwrap_or_else(|| "normal".into()),
        "risk_card": card, "environment": environment, "network": network, "network_reason": network_reason});
    if !caps.is_empty() {
        request["max_calls"] = calls;
    }
    if !per_service.is_null() {
        request["calls_per_service"] = per_service;
    }
    if !options["recommended_ttl_seconds"].is_null() {
        if caps.is_empty() {
            return Err(invalid(
                "a suggested time applies only to capability requests",
            ));
        }
        let n = options["recommended_ttl_seconds"]
            .as_i64()
            .ok_or_else(|| invalid("recommended_ttl_seconds must be an integer"))?;
        if n <= 0 {
            return Err(invalid("recommended_ttl_seconds must be positive"));
        }
        if n > 253402300799 - epoch(None) {
            return Err(invalid(
                "recommended_ttl_seconds must end before the year 10000",
            ));
        }
        request["recommended_ttl_seconds"] = n.into();
    }
    request
        .as_object_mut()
        .unwrap()
        .retain(|_, value| !value.is_null());
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
    for existing in &records {
        if equivalent(existing, &request, now) && verify_approval_request_integrity(root, existing)?
        {
            if reuse_filter.is_none_or(|filter| filter(existing)) {
                return Ok(existing.clone());
            }
            break;
        }
    }
    if records.len() >= MAX_STORED_APPROVAL_REQUESTS {
        return Err(invalid(
            "approval request store is full (1000 records); review requests, then run 'kv approvals prune' to remove approved, denied and withdrawn records, or 'kv approvals prune --missed' to also drop requests that expired undecided, before retrying",
        ));
    }
    request = seal(root, &request)?;
    records.push(request.clone());
    write_store(root, records, 0)?;
    Ok(request)
}

fn equivalent(a: &Value, b: &Value, now: i64) -> bool {
    effective_status(a, Some(now)) == "pending"
        && [
            "command_fingerprint",
            "script_kind",
            "script_sha256",
            "script_ref_hash",
            "argv",
            "cwd",
            "secret_names",
            "capability_names",
            "actor",
            "max_calls",
            "calls_per_service",
            "recommended_ttl_seconds",
            "risk_card",
            "environment",
            "network",
            "network_reason",
        ]
        .iter()
        .all(|key| a[*key] == b[*key])
}

pub fn list_approval_requests(
    root: &Path,
    include_all: bool,
    include_missed: bool,
    now: Option<i64>,
) -> Result<Vec<Value>> {
    let now = epoch(now);
    Ok(read_store(root)?
        .into_iter()
        .filter_map(|mut r| {
            let status = effective_status(&r, Some(now));
            if !include_all
                && status != "pending"
                && !(include_missed && is_missed_request(&r, Some(now)))
            {
                return None;
            }
            r["effective_status"] = status.into();
            Some(r)
        })
        .collect())
}

pub fn get_approval_request(root: &Path, id: &Value, now: Option<i64>) -> Result<Option<Value>> {
    let id = request_id(id)?;
    let now = epoch(now);
    for mut r in read_store(root)? {
        if r["request_id"] == id {
            r["effective_status"] = effective_status(&r, Some(now)).into();
            return Ok(Some(r));
        }
    }
    Ok(None)
}

pub fn mark_approval_request_approved(
    root: &Path,
    id: &Value,
    grant_id: &Value,
    reason: &Value,
    now: Option<i64>,
) -> Result<bool> {
    let fields = json!({"approved_grant_id": py_str(grant_id).chars().take(80).collect::<String>(), "approval_reason": normalize_reason(reason)});
    let _lock = store_lock(root)?;
    mark_request_in_held_lock(root, id, "approved", now, &fields, "pending")
}

pub fn deny_approval_request(
    root: &Path,
    id: &Value,
    reason: &Value,
    now: Option<i64>,
) -> Result<bool> {
    let fields = json!({"deny_reason": normalize_reason(reason)});
    let _lock = store_lock(root)?;
    mark_request_in_held_lock(root, id, "denied", now, &fields, "pending")
}

pub fn mark_request_in_held_lock(
    root: &Path,
    id: &Value,
    status: &str,
    now: Option<i64>,
    fields: &Value,
    from_status: &str,
) -> Result<bool> {
    fsx::require_storage_lock(&root.join(".secrets"))?;
    let id = request_id(id)?;
    let now = epoch(now);
    let mut records = read_store(root)?;
    let count = records.len();
    for r in &mut records {
        if r["request_id"] != id {
            continue;
        }
        if effective_status(r, Some(now)) != from_status {
            return Ok(false);
        }
        r["status"] = status.into();
        r["updated_at"] = iso(now)?.into();
        r["updated_at_epoch"] = now.into();
        if matches!(status, "approved" | "denied" | "withdrawn") {
            r[format!("{status}_at")] = iso(now)?.into();
            r[format!("{status}_at_epoch")] = now.into();
        }
        let fields = fields
            .as_object()
            .ok_or_else(|| invalid("fields must be an object"))?;
        for (k, v) in fields {
            if !v.is_null() {
                r[k] = v.clone();
            }
        }
        *r = seal(root, r)?;
        write_store(root, records, count)?;
        return Ok(true);
    }
    Ok(false)
}

pub fn prune_approval_requests(root: &Path, missed: bool, now: Option<i64>) -> Result<usize> {
    let _lock = store_lock(root)?;
    let now = epoch(now);
    let mut records = read_store(root)?;
    let count = records.len();
    records.retain(|r| {
        effective_status(r, Some(now)) == "pending" || (!missed && is_missed_request(r, Some(now)))
    });
    let pending = records
        .iter()
        .filter(|r| effective_status(r, Some(now)) == "pending")
        .count();
    if records.len() != count {
        write_store(root, records, count)?;
    }
    Ok(pending)
}

fn store_lock(root: &Path) -> Result<fsx::StorageLock> {
    check_secrets_dir(root)?;
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(invalid(
            "private vault files require Unix permission validation",
        ))
    }
    #[cfg(unix)]
    fsx::lock_storage(&root.join(".secrets")).map_err(|e| match e {
        kv_store::StoreError::Io(_) => {
            invalid("approval request store is busy or unavailable; retry the operation")
        }
        other => other.into(),
    })
}

pub(crate) fn check_secrets_dir(root: &Path) -> Result<()> {
    let path = root.join(".secrets");
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("the .secrets path must be a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(invalid("the .secrets directory is not private"));
        }
    }
    #[cfg(target_os = "macos")]
    if !exacl::getfacl(&path, None)?.is_empty() {
        return Err(invalid("the .secrets directory is not private"));
    }
    Ok(())
}

pub(crate) fn private_read(path: &Path, what: &str, limit: usize) -> Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() {
        return Err(invalid("a vault file must be a regular file, not a link"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o777 != 0o600 {
            return Err(invalid(format!(
                "{what} is not private: {}",
                path.display()
            )));
        }
    }
    #[cfg(target_os = "macos")]
    if !exacl::getfacl(path, None)?.is_empty() {
        return Err(invalid(format!(
            "{what} is not private: {}",
            path.display()
        )));
    }
    let (bytes, metadata) =
        fsx::read_regular_limit_with_metadata(path, what, limit).map_err(|e| match e {
            kv_store::StoreError::Structure(_) => invalid("a key file must be a regular file"),
            kv_store::StoreError::TooLarge { .. } => invalid("a key file is larger than any key"),
            other => other.into(),
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(invalid(format!(
                "{what} is not private: {}",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (bytes, metadata);
        return Err(invalid(
            "private vault files require Unix permission validation",
        ));
    }
    #[cfg(unix)]
    Ok(bytes)
}

fn read_store(root: &Path) -> Result<Vec<Value>> {
    check_secrets_dir(root)?;
    let path = approval_store_path(root);
    if !fsx::strictly_present(&path)? {
        return Ok(vec![]);
    }
    let raw = private_read(&path, "approval request store", fsx::VAULT_FILE_LIMIT)?;
    let doc: Value = serde_json::from_slice(&raw).map_err(|_| {
        invalid(format!(
            "approval request store is corrupted: {}",
            path.display()
        ))
    })?;
    if !doc.is_object() {
        return Err(invalid("approval request store must be a JSON object"));
    }
    if doc["version"] != 1 && doc["version"] != true && doc["version"].as_f64() != Some(1.0) {
        return Err(invalid("unsupported approval request store version"));
    }
    let records = doc["requests"]
        .as_array()
        .ok_or_else(|| invalid("approval request store requests must be a list"))?;
    if records.len() > 1001 {
        return Err(invalid("approval request store has too many records"));
    }
    if records.iter().any(|r| !r.is_object()) {
        return Err(invalid("approval request store contains invalid records"));
    }
    Ok(records.clone())
}

pub(crate) fn sorted(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.sort_keys();
            for value in map.values_mut() {
                sorted(value);
            }
        }
        Value::Array(items) => {
            for value in items {
                sorted(value);
            }
        }
        _ => {}
    }
}

fn write_store(root: &Path, records: Vec<Value>, previous_count: usize) -> Result<()> {
    if records.len() > if previous_count == 1001 { 1001 } else { 1000 } {
        return Err(invalid("approval request store has too many records"));
    }
    let mut doc = json!({"version": 1, "requests": records});
    sorted(&mut doc);
    let payload = pyjson::to_vec_indent2_ascii_python(&doc)?;
    if payload.len() > fsx::VAULT_FILE_LIMIT {
        return Err(invalid(format!(
            "the approval request store would be {} bytes; a vault file is at most {} bytes",
            payload.len(),
            fsx::VAULT_FILE_LIMIT
        )));
    }
    kv_store::config::update_vault_ignores(
        &root.join(".secrets"),
        &[APPROVAL_REQUESTS_FILE],
        false,
        Some("# Local-only kv runtime records"),
    )?;
    let path = approval_store_path(root);
    if fsx::strictly_present(&path)? {
        private_read(&path, "approval request store", fsx::VAULT_FILE_LIMIT)?;
    }
    fsx::write_atomic_limit(
        &path,
        &payload,
        false,
        fsx::VAULT_FILE_LIMIT,
        "the approval request store",
    )?;
    Ok(())
}

fn signing_key(root: &Path, create: bool) -> Result<Option<Zeroizing<[u8; 32]>>> {
    check_secrets_dir(root)?;
    let sdir = root.join(".secrets");
    let path = sdir.join("approval_signing_key");
    if !fsx::strictly_present(&path)? {
        if !create {
            return Ok(None);
        }
        kv_store::config::update_vault_ignores(
            &sdir,
            &["approval_signing_key"],
            false,
            Some("# Local-only kv runtime records"),
        )?;
        let mut key = Zeroizing::new([0; 32]);
        getrandom::getrandom(&mut key[..])
            .map_err(|_| invalid("operating-system randomness unavailable"))?;
        let encoded = Zeroizing::new(format!("{}\n", URL_SAFE.encode(&key[..])));
        match fsx::write_atomic_limit(
            &path,
            encoded.as_bytes(),
            true,
            fsx::VAULT_FILE_LIMIT,
            "approval signing key",
        ) {
            Ok(()) => {}
            Err(kv_store::StoreError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let raw = Zeroizing::new(private_read(&path, "approval signing key", 1024 * 1024)?);
    if !raw.is_ascii() {
        return Err(invalid("approval signing key is invalid"));
    }
    Ok(Some(artifacts::parse_signing_key(&raw)?))
}

fn seal(root: &Path, request: &Value) -> Result<Value> {
    let key = signing_key(root, true)?
        .ok_or_else(|| invalid("approval signing key could not be created"))?;
    Ok(artifacts::attach_approval_request_integrity(
        request,
        &key[..],
    )?)
}

pub fn verify_approval_request_integrity(root: &Path, request: &Value) -> Result<bool> {
    let integrity = &request["request_integrity"];
    if !integrity.is_object()
        || integrity["version"] != 1
        || integrity["signer"] != artifacts::SIGNER
        || integrity["signature"]
            .as_str()
            .is_none_or(|s| s.len() != 64)
    {
        return Ok(false);
    }
    let payload = artifacts::approval_request_payload(request)?;
    let canonical = kv_approvals::canonical::artifact_canonical_json(&payload)?;
    if integrity["payload_sha256"] != hex::encode(Sha256::digest(canonical.as_bytes())) {
        return Ok(false);
    }
    Ok(signing_key(root, false)?
        .is_some_and(|key| artifacts::verify_approval_request_integrity(request, &key[..])))
}
