#[cfg(not(windows))]
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Number, Value};

use crate::{StoreError, config::ApprovalRefs, fsx};

#[cfg(not(windows))]
const LIMIT: usize = fsx::VAULT_FILE_LIMIT;
#[cfg(not(windows))]
const LOCKED: &[u8] = b"kv-saved-passes-locked-v1\n";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ApprovalRef {
    pub kind: String,
    pub label: String,
    pub ends_at: Option<String>,
}

pub struct FileApprovalRefs {
    pub root: PathBuf,
}

impl FileApprovalRefs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl ApprovalRefs for FileApprovalRefs {
    fn approvals_naming_env(&self, env: &str) -> Result<bool, StoreError> {
        Ok(!approvals_naming_env(&self.root, env, now_epoch()).is_empty())
    }
}

/// Existing stores on Windows fail closed until vault ACL validation is available there.
/// JSON NaN and Infinity also fail closed because `serde_json` rejects those Python extensions.
pub fn approvals_naming_env(root: &Path, env: &str, now: i64) -> Vec<ApprovalRef> {
    let grants = or_conservative(|| grants(root, env, now), "grant", "the approvals");
    let passes = or_conservative(|| passes(root, env, now), "pass", "the passes");
    let requests = or_conservative(
        || requests(root, env, now),
        "request",
        "the waiting approval requests",
    );
    let saved = or_conservative(|| saved(root), "saved_pass", "the saved approvals");
    [grants, passes, requests, saved].concat()
}

fn or_conservative(
    read: impl FnOnce() -> Result<Vec<ApprovalRef>, ()>,
    kind: &str,
    what: &str,
) -> Vec<ApprovalRef> {
    read().unwrap_or_else(|()| {
        vec![entry(
            kind,
            &format!("{what} could not be read; kv cannot tell what they name"),
            None,
        )]
    })
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

fn entry(kind: &str, label: &str, ends_at: Option<String>) -> ApprovalRef {
    ApprovalRef {
        kind: kind.to_owned(),
        label: label.to_owned(),
        ends_at,
    }
}

fn secrets_dir(root: &Path) -> PathBuf {
    root.join(".secrets")
}

fn read_doc(root: &Path, filename: &str, token_store: bool) -> Result<Option<Value>, ()> {
    let path = secrets_dir(root).join(filename);
    if !fsx::strictly_present(&path).map_err(|_| ())? {
        return Ok(None);
    }
    #[cfg(windows)]
    {
        let _ = (path, token_store);
        return Err(());
    }
    #[cfg(not(windows))]
    {
        if token_store {
            let (raw, metadata) =
                fsx::read_regular_limit_with_metadata(&path, filename, LIMIT).map_err(|_| ())?;
            check_token_privacy(&metadata)?;
            Ok(Some(serde_json::from_slice(&raw).map_err(|_| ())?))
        } else {
            check_mode_and_acl(&path)?;
            let raw = fsx::read_regular_limit(&path, filename, LIMIT).map_err(|_| ())?;
            Ok(Some(serde_json::from_slice(&raw).map_err(|_| ())?))
        }
    }
}

#[cfg(not(windows))]
fn check_mode_and_acl(path: &Path) -> Result<(), ()> {
    let metadata = fs::metadata(path).map_err(|_| ())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o600 {
            return Err(());
        }
    }
    #[cfg(target_os = "macos")]
    if !exacl::getfacl(path, None).map_err(|_| ())?.is_empty() {
        return Err(());
    }
    Ok(())
}

#[cfg(unix)]
fn check_token_privacy(metadata: &fs::Metadata) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o777 != 0o600 {
        return Err(());
    }
    Ok(())
}

fn store_records(
    root: &Path,
    filename: &str,
    field: &str,
    limit: usize,
    token_store: bool,
) -> Result<Option<Vec<Map<String, Value>>>, ()> {
    let Some(document) = read_doc(root, filename, token_store)? else {
        return Ok(None);
    };
    let object = document.as_object().ok_or(())?;
    if !python_is_one(object.get("version")) {
        return Err(());
    }
    let records = object.get(field).and_then(Value::as_array).ok_or(())?;
    if records.len() > limit {
        return Err(());
    }
    let records = records
        .iter()
        .map(|record| record.as_object().cloned().ok_or(()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(records))
}

fn grants(root: &Path, env: &str, now: i64) -> Result<Vec<ApprovalRef>, ()> {
    let Some(records) = store_records(root, "run_grants.json", "grants", 1000, false)? else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    let mut admissions = Vec::new();
    for record in &records {
        let id = record
            .get("grant_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or(())?;
        ids.push(id);
        if let Some(admission) = record.get("admission_id") {
            admissions.push(admission.as_str().filter(|id| !id.is_empty()).ok_or(())?);
        }
    }
    if has_duplicates(&ids) || has_duplicates(&admissions) {
        return Err(());
    }
    let mut found = Vec::new();
    for grant in records {
        let payload = if truthy(grant.get("owner_approval")) {
            let owner = grant
                .get("owner_approval")
                .and_then(Value::as_object)
                .ok_or(())?;
            if truthy(owner.get("payload")) {
                Some(owner.get("payload").and_then(Value::as_object).ok_or(())?)
            } else {
                None
            }
        } else {
            None
        };
        let expires = grant.get("expires_at_epoch");
        if payload
            .and_then(|payload| payload.get("environment"))
            .and_then(Value::as_str)
            != Some(env)
            || !real_int_gt(expires, now)
            || grant.get("status").and_then(Value::as_str) != Some("active")
        {
            continue;
        }
        let scope = scope(&grant)?;
        let id = grant.get("grant_id").ok_or(())?;
        found.push(entry(
            "grant",
            &format!("approval {} ({scope})", py_str(id)),
            iso(expires)?,
        ));
    }
    Ok(found)
}

fn passes(root: &Path, env: &str, now: i64) -> Result<Vec<ApprovalRef>, ()> {
    let Some(records) = store_records(root, "capability_tokens.json", "tokens", 1000, true)? else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    let mut hashes = Vec::new();
    let mut admissions = Vec::new();
    for record in &records {
        ids.push(
            record
                .get("token_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or(())?,
        );
        hashes.push(
            record
                .get("token_hash")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or(())?,
        );
        if let Some(admission) = record.get("admission_id") {
            admissions.push(admission.as_str().filter(|id| !id.is_empty()).ok_or(())?);
        }
    }
    if has_duplicates(&ids) || has_duplicates(&hashes) || has_duplicates(&admissions) {
        return Err(());
    }
    let mut found = Vec::new();
    for token in records {
        let expires = token.get("expires_at_epoch");
        let status = token.get("status");
        let active = status.is_none()
            || status.is_some_and(Value::is_null)
            || status.and_then(Value::as_str) == Some("active");
        if token.get("env_name").and_then(Value::as_str) != Some(env)
            || !real_int_gt(expires, now)
            || !active
        {
            continue;
        }
        found.push(entry(
            "pass",
            &format!(
                "pass {} ({})",
                py_str(token.get("token_id").ok_or(())?),
                token
                    .get("capability_name")
                    .map(py_str)
                    .unwrap_or_else(|| "None".into())
            ),
            iso(expires)?,
        ));
    }
    Ok(found)
}

fn requests(root: &Path, env: &str, now: i64) -> Result<Vec<ApprovalRef>, ()> {
    let Some(records) = store_records(root, "approval_requests.json", "requests", 1001, false)?
    else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for request in records {
        if request.get("environment").and_then(Value::as_str) != Some(env)
            || request_status(&request, now)? != "pending"
        {
            continue;
        }
        let scope = scope(&request)?;
        found.push(entry(
            "request",
            &format!(
                "waiting approval request {} ({scope})",
                request
                    .get("request_id")
                    .map(py_str)
                    .unwrap_or_else(|| "None".into())
            ),
            iso(request.get("expires_at_epoch"))?,
        ));
    }
    Ok(found)
}

fn saved(root: &Path) -> Result<Vec<ApprovalRef>, ()> {
    const UNKNOWN: &str = "saved approvals of interrupted or running jobs \
                            (unlock the vault to list them; kv resume ends them)";
    let path = secrets_dir(root).join("saved_passes.kvs");
    if !fsx::strictly_present(&path).map_err(|_| ())? {
        return Ok(Vec::new());
    }
    #[cfg(windows)]
    {
        let _ = path;
        Ok(vec![entry("saved_pass", UNKNOWN, None)])
    }
    #[cfg(not(windows))]
    {
        if fs::symlink_metadata(&path)
            .map_err(|_| ())?
            .file_type()
            .is_symlink()
        {
            return Err(());
        }
        if check_mode_and_acl(&path).is_err() {
            return Ok(vec![entry("saved_pass", UNKNOWN, None)]);
        }
        match fsx::read_regular_limit(&path, "saved approvals file", LIMIT) {
            Ok(bytes) if bytes == LOCKED => Ok(Vec::new()),
            Ok(_) | Err(_) => Ok(vec![entry("saved_pass", UNKNOWN, None)]),
        }
    }
}

fn scope(record: &Map<String, Value>) -> Result<String, ()> {
    let names = record
        .get("capability_names")
        .filter(|value| truthy(Some(value)))
        .or_else(|| {
            record
                .get("secret_names")
                .filter(|value| truthy(Some(value)))
        });
    match names {
        None => Ok(String::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .map(|values| values.join(", "))
            .ok_or(()),
        Some(Value::String(value)) => Ok(value
            .chars()
            .map(|ch| ch.to_string())
            .collect::<Vec<_>>()
            .join(", ")),
        Some(Value::Object(values)) => Ok(values.keys().cloned().collect::<Vec<_>>().join(", ")),
        _ => Err(()),
    }
}

fn request_status(request: &Map<String, Value>, now: i64) -> Result<&'static str, ()> {
    if marker(request, "withdrawn_at_epoch") {
        return Ok("withdrawn");
    }
    if [
        "approved_at",
        "approved_at_epoch",
        "approved_grant_id",
        "approval_reason",
    ]
    .iter()
    .any(|key| marker(request, key))
    {
        return Ok("approved");
    }
    if ["denied_at", "denied_at_epoch", "deny_reason"]
        .iter()
        .any(|key| marker(request, key))
    {
        return Ok("denied");
    }
    if request
        .get("status")
        .filter(|status| truthy(Some(status)))
        .is_some_and(|status| status.as_str() != Some("pending"))
    {
        return Ok("terminal");
    }
    if !python_int_expiry_gt_now(request.get("expires_at_epoch"), now) {
        Ok("expired")
    } else {
        Ok("pending")
    }
}

fn marker(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).is_some_and(|value| !value.is_null())
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(number)) => number
            .as_f64()
            .map(|value| value != 0.0)
            .unwrap_or_else(|| number.to_string() != "0"),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

fn python_is_one(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(true)) => true,
        Some(Value::Number(number)) => number.as_f64() == Some(1.0),
        _ => false,
    }
}

fn real_int_gt(value: Option<&Value>, now: i64) -> bool {
    let Some(Value::Number(number)) = value else {
        return false;
    };
    if number.is_f64() {
        return false;
    }
    compare_decimal_to_i64(&number.to_string(), now).is_gt()
}

fn python_int_expiry_gt_now(value: Option<&Value>, now: i64) -> bool {
    let Some(value) = value.filter(|value| truthy(Some(value))) else {
        return 0 > now;
    };
    let Some(integer) = to_python_int(value) else {
        return 0 > now;
    };
    compare_decimal_to_i64(&integer, now).is_gt()
}

fn to_python_int(value: &Value) -> Option<String> {
    match value {
        Value::Bool(value) => Some(if *value { "1" } else { "0" }.into()),
        Value::Number(number) if number.is_f64() => {
            let float = number.as_f64()?;
            if !float.is_finite() {
                return None;
            }
            Some(format!("{:.0}", float.trunc()))
        }
        Value::Number(number) => Some(number.to_string()),
        Value::String(value) => {
            let trimmed = value.trim();
            let compact = normalize_python_integer(trimmed)?;
            compact
                .parse::<i128>()
                .ok()
                .map(|v| v.to_string())
                .or_else(|| parse_big_decimal(&compact))
        }
        _ => None,
    }
}

fn normalize_python_integer(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let bytes = value.as_bytes();
    let mut normalized = String::with_capacity(value.len());
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'_' {
            if index == 0
                || index + 1 == bytes.len()
                || !bytes[index - 1].is_ascii_digit()
                || !bytes[index + 1].is_ascii_digit()
            {
                return None;
            }
        } else if byte.is_ascii_digit() || (index == 0 && matches!(byte, b'+' | b'-')) {
            normalized.push(char::from(byte));
        } else {
            return None;
        }
    }
    Some(normalized)
}

fn parse_big_decimal(value: &str) -> Option<String> {
    let digits = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let negative = value.starts_with('-');
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        Some("0".into())
    } else if negative {
        Some(format!("-{digits}"))
    } else {
        Some(digits.into())
    }
}

fn compare_decimal_to_i64(value: &str, other: i64) -> std::cmp::Ordering {
    let Ok(value_num) = value.parse::<i128>() else {
        return if value.starts_with('-') {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    };
    value_num.cmp(&i128::from(other))
}

fn has_duplicates<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut seen = std::collections::HashSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn iso(value: Option<&Value>) -> Result<Option<String>, ()> {
    let Some(Value::Number(number)) = value else {
        return Ok(None);
    };
    if number.is_f64() {
        return Ok(None);
    }
    let epoch = number.to_string().parse::<i64>().map_err(|_| ())?;
    let days = i128::from(epoch).div_euclid(86_400);
    let seconds = i128::from(epoch).rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    if year - 1900 < i128::from(i32::MIN) || year - 1900 > i128::from(i32::MAX) {
        return Err(());
    }
    let hour = seconds / 3_600;
    let minute = seconds % 3_600 / 60;
    let second = seconds % 60;
    Ok(Some(format!(
        "{year}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    )))
}

/// Renders JSON values like Python `str`; Unicode quoting follows the crate's Unicode 16 tables.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(value) => value.clone(),
        Value::Number(number) => py_number(number),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| { format!("{}: {}", py_quote(key), py_repr(value)) })
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn py_repr(value: &Value) -> String {
    match value {
        Value::String(value) => py_quote(value),
        _ => py_str(value),
    }
}

fn py_quote(value: &str) -> String {
    use unicode_general_category::{GeneralCategory as G, get_general_category};
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut result = String::from(quote);
    for ch in value.chars() {
        if ch == '\\' {
            result.push_str("\\\\");
        } else if ch == quote {
            result.push('\\');
            result.push(ch);
        } else if ch == '\n' {
            result.push_str("\\n");
        } else if ch == '\r' {
            result.push_str("\\r");
        } else if ch == '\t' {
            result.push_str("\\t");
        } else {
            let category = get_general_category(ch);
            if ch.is_control()
                || matches!(
                    category,
                    G::Format
                        | G::Surrogate
                        | G::PrivateUse
                        | G::Unassigned
                        | G::LineSeparator
                        | G::ParagraphSeparator
                )
                || (category == G::SpaceSeparator && ch != ' ')
            {
                let code = ch as u32;
                if code <= 0xff {
                    result.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    result.push_str(&format!("\\u{code:04x}"));
                } else {
                    result.push_str(&format!("\\U{code:08x}"));
                }
            } else {
                result.push(ch);
            }
        }
    }
    result.push(quote);
    result
}

fn py_number(number: &Number) -> String {
    if !number.is_f64() {
        return number.to_string();
    }
    let Some(value) = number.as_f64() else {
        return number.to_string();
    };
    let mut rendered = format!("{value:?}");
    if let Some((mantissa, exponent)) = rendered.split_once('e') {
        let exponent = exponent.parse::<i32>().unwrap_or(0);
        let sign = if exponent >= 0 { "+" } else { "-" };
        let magnitude = exponent.unsigned_abs();
        rendered = format!("{mantissa}e{sign}{magnitude:02}");
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::iso;
    use serde_json::json;

    #[test]
    fn iso_matches_linux_gmtime_year_width_and_range() {
        assert_eq!(
            iso(Some(&json!(-62_135_596_800_i64))).unwrap().as_deref(),
            Some("1-01-01T00:00:00Z")
        );
        assert_eq!(
            iso(Some(&json!(-62_135_596_801_i64))).unwrap().as_deref(),
            Some("0-12-31T23:59:59Z")
        );
        assert_eq!(
            iso(Some(&json!(253_402_300_800_i64))).unwrap().as_deref(),
            Some("10000-01-01T00:00:00Z")
        );
        assert!(iso(Some(&json!(4_611_686_018_427_387_904_i64))).is_err());
        assert!(iso(Some(&json!(1_000_000_000_000_000_000_000_i128))).is_err());
    }
}
