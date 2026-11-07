//! Field normalization shared by grants and capability tokens, with Python's
//! exact error wording (`kv/grants.py`, `kv/capabilities.py`, `kv/limits.py`).

use std::fmt;

use serde_json::{Map, Value};

pub const GRANTS_FILE: &str = "run_grants.json";
pub const MAX_STORED_GRANTS: usize = 1000;
pub const DEFAULT_GRANT_TTL_SECONDS: i64 = 5 * 60;
pub const DEFAULT_CAPABILITY_MAX_CALLS: i64 = 1;
pub const WHEN_SPENT: [&str; 2] = ["pause", "end"];
pub const MAX_REASON_LEN: usize = 512;
pub const MAX_ACTOR_VALUE_LEN: usize = 128;
pub const MAX_SCOPE_ITEM_LEN: usize = 256;
pub const ACTOR_FIELDS: [&str; 5] = [
    "source",
    "client_name",
    "client_version",
    "session_id",
    "user_id",
];
/// Largest count kv stores or sums: exact in every JSON reader (`kv/limits.py`).
pub const MAX_COUNT: i64 = kv_approvals::verify::MAX_COUNT;
/// 9999-12-31T23:59:59Z: no end may pass the year 10000.
pub const LATEST_EPOCH: i64 = 253_402_300_799;

/// Python's `ValueError` with its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidValue(pub String);

impl InvalidValue {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InvalidValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidValue {}

fn invalid<T>(message: impl Into<String>) -> Result<T, InvalidValue> {
    Err(InvalidValue::new(message))
}

/// Python's `type(value) is int`: a JSON integer, never a bool or a float.
pub fn as_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// `str.strip()`: Python strips Unicode whitespace on both ends.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

fn is_py_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// `text[:n]` on Python's code points.
pub fn py_truncate(text: &str, chars: usize) -> &str {
    match text.char_indices().nth(chars) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

pub fn check_count(value: Option<&Value>, name: &str) -> Result<i64, InvalidValue> {
    let Some(count) = value.and_then(as_int) else {
        return invalid(format!("{name} must be an integer"));
    };
    if count <= 0 {
        return invalid(format!("{name} must be positive"));
    }
    if count > MAX_COUNT {
        return invalid(format!(
            "{name} must be at most {MAX_COUNT} (the largest exact JSON number)"
        ));
    }
    Ok(count)
}

pub fn check_seconds(value: Option<&Value>, name: &str, now: i64) -> Result<i64, InvalidValue> {
    let Some(seconds) = value.and_then(as_int) else {
        return invalid(format!("{name} must be an integer"));
    };
    if seconds <= 0 {
        return invalid(format!("{name} must be positive"));
    }
    if now.saturating_add(seconds) > LATEST_EPOCH {
        return invalid(format!("{name} must end before the year 10000"));
    }
    Ok(seconds)
}

pub fn validate_hash(
    value: Option<&Value>,
    field: &str,
    required: bool,
) -> Result<Option<String>, InvalidValue> {
    let value = match value {
        None | Some(Value::Null) => {
            if required {
                return invalid(format!("{field} is required"));
            }
            return Ok(None);
        }
        Some(value) => value,
    };
    let Some(text) = value.as_str() else {
        return invalid(format!("{field} must be a string"));
    };
    let lowered = text.to_lowercase();
    if lowered.chars().count() != 64
        || !lowered
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return invalid(format!("{field} must be a sha256 hex digest"));
    }
    Ok(Some(lowered))
}

pub fn normalize_run_identity(run_identity: &Value) -> Result<Map<String, Value>, InvalidValue> {
    let Some(identity) = run_identity.as_object() else {
        return invalid("run_identity must be an object");
    };
    let mut normalized = Map::new();
    let fingerprint = validate_hash(
        identity.get("command_fingerprint"),
        "command_fingerprint",
        true,
    )?
    .expect("required");
    normalized.insert("command_fingerprint".into(), Value::String(fingerprint));
    if let Some(run_id) = identity.get("run_id").and_then(Value::as_str)
        && !run_id.is_empty()
    {
        normalized.insert(
            "run_id".into(),
            Value::String(py_truncate(run_id, 80).to_owned()),
        );
    }
    if let Some(kind) = identity.get("script_kind").and_then(Value::as_str)
        && !kind.is_empty()
    {
        normalized.insert(
            "script_kind".into(),
            Value::String(py_truncate(kind, 40).to_owned()),
        );
    }
    if let Some(sha) = validate_hash(identity.get("script_sha256"), "script_sha256", false)? {
        normalized.insert("script_sha256".into(), Value::String(sha));
    }
    if let Some(hash) = validate_hash(identity.get("script_ref_hash"), "script_ref_hash", false)? {
        normalized.insert("script_ref_hash".into(), Value::String(hash));
    }
    Ok(normalized)
}

pub fn normalize_scope_list(
    value: Option<&Value>,
    field: &str,
) -> Result<Vec<String>, InvalidValue> {
    let items = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return invalid(format!("{field} must be a list")),
    };
    let mut cleaned = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let Some(text) = item.as_str().filter(|t| !py_strip(t).is_empty()) else {
            return invalid(format!("{field}[{i}] must be a non-empty string"));
        };
        if text.len() > MAX_SCOPE_ITEM_LEN {
            return invalid(format!("{field}[{i}] exceeds {MAX_SCOPE_ITEM_LEN} bytes"));
        }
        cleaned.push(py_strip(text).to_owned());
    }
    cleaned.sort();
    cleaned.dedup();
    Ok(cleaned)
}

pub fn normalize_actor(actor: Option<&Value>) -> Result<Map<String, Value>, InvalidValue> {
    let actor = match actor {
        None | Some(Value::Null) => return Ok(Map::new()),
        Some(Value::Object(actor)) => actor,
        Some(_) => return invalid("actor must be an object"),
    };
    let mut normalized = Map::new();
    for field in ACTOR_FIELDS {
        if let Some(text) = actor.get(field).and_then(Value::as_str) {
            let stripped = py_strip(text);
            if !stripped.is_empty() {
                normalized.insert(
                    field.to_owned(),
                    Value::String(py_truncate(stripped, MAX_ACTOR_VALUE_LEN).to_owned()),
                );
            }
        }
    }
    Ok(normalized)
}

/// Every field the grant's actor names must equal the current actor's.
pub fn actor_matches(grant_actor: &Value, current_actor: &Value) -> bool {
    let Some(grant_actor) = grant_actor.as_object() else {
        return false;
    };
    let empty = Map::new();
    let current = current_actor.as_object().unwrap_or(&empty);
    grant_actor
        .iter()
        .all(|(key, value)| py_eq(current.get(key).unwrap_or(&Value::Null), value))
}

/// Python `==` on JSON values: a missing key reads as `None`, and `1`, `1.0`
/// and `True` are equal.
pub fn py_eq(left: &Value, right: &Value) -> bool {
    fn number(value: &Value) -> Option<f64> {
        match value {
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    }
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| py_eq(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).is_some_and(|w| py_eq(v, w)))
        }
        _ => match (number(left), number(right)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
    }
}

pub fn normalize_reason(reason: Option<&Value>) -> Result<String, InvalidValue> {
    match reason {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(py_truncate(py_strip(text), MAX_REASON_LEN).to_owned()),
        Some(_) => invalid("reason must be a string"),
    }
}

pub fn normalize_max_calls(max_calls: Option<&Value>) -> Result<i64, InvalidValue> {
    match max_calls {
        None | Some(Value::Null) => Ok(DEFAULT_CAPABILITY_MAX_CALLS),
        Some(value) => check_count(Some(value), "max_calls"),
    }
}

/// `(total, per_service)`: how a capability approval's calls are counted.
///
/// One service carries no per-service map (`None`), unless its count was left
/// open (`{name: null}` with total 0). Several services need a count each.
pub fn normalize_service_calls(
    capability_names: &[String],
    max_calls: Option<&Value>,
    calls_per_service: Option<&Value>,
) -> Result<(i64, Option<Map<String, Value>>), InvalidValue> {
    let mut names = capability_names.to_vec();
    names.sort();
    names.dedup();
    let per: Map<String, Value> = match calls_per_service {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(per)) => per.clone(),
        Some(_) => return invalid("this approval needs a count for each service"),
    };
    let mut per_keys: Vec<&String> = per.keys().collect();
    per_keys.sort();
    for name in per_keys {
        if !names.contains(name) {
            return invalid(format!("{name} is not named in this approval"));
        }
    }
    for (name, count) in &per {
        if !count.is_null() && !as_int(count).is_some_and(|c| (1..=MAX_COUNT).contains(&c)) {
            return invalid(format!(
                "{name}: a count is a whole number from 1 to {MAX_COUNT}"
            ));
        }
    }
    let max_calls = max_calls.filter(|v| !v.is_null());
    if names.len() <= 1 && !per.is_empty() && per.get(&names[0]).is_none_or(Value::is_null) {
        // `per.get(names[0], 0) is None`: an open count for the one service.
        if per.contains_key(&names[0]) {
            if max_calls.is_some_and(|v| as_int(v) != Some(0)) {
                return invalid("max_calls is not the sum of the per-service counts");
            }
            let mut open = Map::new();
            open.insert(names[0].clone(), Value::Null);
            return Ok((0, Some(open)));
        }
    }
    if names.len() <= 1 {
        if !per.is_empty() {
            let count = per
                .get(&names[0])
                .and_then(as_int)
                .expect("validated above");
            if let Some(wanted) = max_calls
                && as_int(wanted) != Some(count)
            {
                return invalid("max_calls is not the sum of the per-service counts");
            }
            return Ok((count, None));
        }
        return Ok((normalize_max_calls(max_calls)?, None));
    }
    let missing: Vec<&str> = names
        .iter()
        .filter(|name| !per.contains_key(*name))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return invalid(format!(
            "this approval needs a count for each service: missing {}",
            missing.join(", ")
        ));
    }
    let total: i64 = per.values().filter_map(as_int).sum();
    if total > MAX_COUNT {
        return invalid(format!(
            "at most {MAX_COUNT} calls in all per approval ({total} asked)"
        ));
    }
    if let Some(wanted) = max_calls
        && as_int(wanted) != Some(total)
    {
        return invalid("max_calls is not the sum of the per-service counts");
    }
    let mut normalized = Map::new();
    for name in &names {
        normalized.insert(name.clone(), per[name].clone());
    }
    Ok((total, Some(normalized)))
}

pub fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).expect("operating-system randomness");
    hex::encode(buffer)
}

pub fn normalize_grant_id(grant_id: Option<&Value>) -> Result<String, InvalidValue> {
    match grant_id {
        None | Some(Value::Null) => Ok(format!("grant_{}", random_hex(12))),
        Some(Value::String(text)) if !py_strip(text).is_empty() => {
            Ok(py_truncate(py_strip(text), 80).to_owned())
        }
        Some(_) => invalid("grant_id must be a non-empty string"),
    }
}

pub fn script_identity_matches(
    grant: &Map<String, Value>,
    run_identity: &Map<String, Value>,
) -> bool {
    ["script_kind", "script_sha256", "script_ref_hash"]
        .iter()
        .all(|key| {
            py_eq(
                grant.get(*key).unwrap_or(&Value::Null),
                run_identity.get(*key).unwrap_or(&Value::Null),
            )
        })
}

pub fn is_revoked(grant: &Map<String, Value>) -> bool {
    grant.get("status").and_then(Value::as_str) == Some("revoked")
        || ["revoked_at", "revoked_at_epoch", "revoke_reason"]
            .iter()
            .any(|key| grant.get(*key).is_some_and(|v| !v.is_null()))
}

/// Missing or non-integer expiries count as expired.
pub fn is_expired(record: &Map<String, Value>, now_epoch: i64) -> bool {
    match record.get("expires_at_epoch").and_then(|v| match v {
        Value::Number(n) => n.as_i64(),
        Value::Bool(b) => Some(i64::from(*b)),
        _ => None,
    }) {
        Some(expires) => expires <= now_epoch,
        None => true,
    }
}

/// A pausing capability grant stays while the owner may still answer.
pub fn waiting_after_end(grant: &Map<String, Value>, now_epoch: i64) -> bool {
    let wait = grant.get("owner_wait_seconds").and_then(as_int);
    let expires = grant.get("expires_at_epoch").and_then(|v| match v {
        Value::Number(n) => n.as_i64(),
        Value::Bool(b) => Some(i64::from(*b)),
        _ => None,
    });
    match (wait, expires) {
        (Some(wait), Some(expires)) => {
            grant.get("when_spent").and_then(Value::as_str) == Some("pause")
                && now_epoch < expires.saturating_add(wait)
        }
        _ => false,
    }
}

/// `datetime.fromtimestamp(epoch, timezone.utc).isoformat()` for whole seconds.
pub fn iso(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let seconds = epoch.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}+00:00",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_matches_known_instants() {
        assert_eq!(iso(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso(1_793_503_600), "2026-11-01T03:26:40+00:00");
        assert_eq!(iso(LATEST_EPOCH), "9999-12-31T23:59:59+00:00");
    }
}
