//! Risk cards: the owner-facing summary stored in a grant (`kv/risk_card.py`).
//!
//! Only `minimal_risk_card`, `normalize_risk_card` and `summarize_risk_card` are
//! ported here. `build_run_risk_card` reads a static preflight of the command,
//! which belongs to the `kv preflight` stage.

use serde_json::{Map, Value, json};

pub const RISK_CARD_VERSION: i64 = 1;
pub const RISK_CARD_GENERATOR: &str = "kv_risk_card_v1";
pub const MAX_ARGV_ITEMS: usize = 128;
pub const MAX_ARGV_ITEM_CHARS: usize = 512;
pub const MAX_TEXT_CHARS: usize = 1024;
pub const MAX_LIST_ITEMS: usize = 64;
pub const MAX_LIMITS: usize = 16;

const MINIMAL_LIMIT: &str = "This grant was created without command text, so KV could only sign \
                             the exact run identity and scope.";

/// `minimal_risk_card`: the card a grant gets when no risk card was supplied.
pub fn minimal_risk_card(
    run_identity: &Value,
    secret_names: Option<&[String]>,
    capability_names: Option<&[String]>,
    max_calls: Option<&Value>,
    reason: &str,
) -> Value {
    let secret_scope = scope_list(&strings(secret_names));
    let capability_scope = scope_list(&strings(capability_names));
    let mut scope = Map::new();
    scope.insert("secret_names".into(), Value::Array(secret_scope.clone()));
    scope.insert(
        "capability_names".into(),
        Value::Array(capability_scope.clone()),
    );
    scope.insert(
        "raw_secret_injection".into(),
        Value::Bool(!secret_scope.is_empty()),
    );
    scope.insert(
        "broker_capability".into(),
        Value::Bool(!capability_scope.is_empty()),
    );
    if !capability_scope.is_empty() {
        scope.insert("max_calls".into(), int_or_none(max_calls));
    }
    let mut card = Map::new();
    card.insert("version".into(), json!(RISK_CARD_VERSION));
    card.insert("generator".into(), json!(RISK_CARD_GENERATOR));
    card.insert("source".into(), json!("grant-writer"));
    card.insert("extraction_status".into(), json!("not_provided"));
    card.insert("identity".into(), identity_summary(run_identity));
    card.insert("scope".into(), Value::Object(scope));
    card.insert("facts".into(), Value::Object(Map::new()));
    card.insert(
        "uncertainty".into(),
        json!([
            text(&Value::String(reason.to_owned()), 160)
                .unwrap_or_else(|| "risk_card_not_provided".to_owned()),
            "runtime-enforcement-remains-authoritative",
        ]),
    );
    card.insert("limits".into(), json!([MINIMAL_LIMIT]));
    normalize_risk_card(Some(&Value::Object(card)))
}

/// `normalize_risk_card`: bound every field of a caller-supplied card.
pub fn normalize_risk_card(card: Option<&Value>) -> Value {
    let Some(card) = card.and_then(Value::as_object) else {
        return json!({
            "version": RISK_CARD_VERSION,
            "generator": RISK_CARD_GENERATOR,
            "extraction_status": "not_provided",
            "facts": {},
            "uncertainty": ["risk_card_not_provided"],
            "limits": [],
        });
    };
    let mut cleaned = card.clone();
    cleaned.insert("version".into(), json!(RISK_CARD_VERSION));
    let generator =
        text_opt(cleaned.get("generator"), 80).unwrap_or_else(|| RISK_CARD_GENERATOR.to_owned());
    cleaned.insert("generator".into(), Value::String(generator));
    let status =
        text_opt(cleaned.get("extraction_status"), 80).unwrap_or_else(|| "limited".to_owned());
    cleaned.insert("extraction_status".into(), Value::String(status));
    if cleaned.contains_key("source") {
        let value = text_value(cleaned.get("source"), 80);
        cleaned.insert("source".into(), value);
    }
    for key in ["cwd", "command"] {
        if cleaned.contains_key(key) {
            let value = text_value(cleaned.get(key), MAX_TEXT_CHARS);
            cleaned.insert(key.into(), value);
        }
    }
    if cleaned.contains_key("argv") {
        let value = normalize_argv(cleaned.get("argv"));
        cleaned.insert("argv".into(), Value::Array(value));
    }
    let identity = identity_summary(cleaned.get("identity").unwrap_or(&Value::Null));
    cleaned.insert("identity".into(), identity);
    let scope = normalize_scope(cleaned.get("scope"));
    cleaned.insert("scope".into(), scope);
    let facts = normalize_facts(cleaned.get("facts"));
    cleaned.insert("facts".into(), facts);
    let mut uncertainty = string_list(cleaned.get("uncertainty"), MAX_LIST_ITEMS);
    if uncertainty.is_empty() {
        uncertainty = vec![json!("static-analysis-only")];
    }
    cleaned.insert("uncertainty".into(), Value::Array(uncertainty));
    let limits = string_list(cleaned.get("limits"), MAX_LIMITS);
    cleaned.insert("limits".into(), Value::Array(limits));
    Value::Object(drop_empty(cleaned))
}

/// `summarize_risk_card`: the lines the owner reads before approving.
pub fn summarize_risk_card(card: Option<&Value>) -> Vec<String> {
    if card.and_then(Value::as_object).is_none() {
        return vec!["KV risk card: not available".to_owned()];
    }
    let normalized = normalize_risk_card(card);
    let status = normalized
        .get("extraction_status")
        .and_then(Value::as_str)
        .unwrap_or("limited");
    let mut lines = vec![format!("KV risk card: {status}")];
    let empty = Map::new();
    let facts = normalized
        .get("facts")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let raw = facts
        .get("raw_key_findings")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let raw_count = raw.get("count").and_then(Value::as_i64).unwrap_or(0);
    if raw_count != 0 {
        let codes = raw
            .get("codes")
            .and_then(Value::as_array)
            .map(|codes| {
                codes
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let mut line = format!("Raw-key patterns found: {raw_count}");
        if !codes.is_empty() {
            line.push_str(&format!(" ({codes})"));
        }
        lines.push(line);
    }
    let api = facts
        .get("api")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut providers: Vec<_> = api.iter().collect();
    providers.sort_by(|a, b| a.0.cmp(b.0));
    let mut api_bits = Vec::new();
    for (provider, info) in providers {
        let Some(info) = info.as_object() else {
            continue;
        };
        let truthy = |key: &str| info.get(key).is_some_and(truthy);
        if truthy("unknown_call_count") {
            api_bits.push(format!("{provider}: unknown calls"));
        } else if truthy("call_sites") || truthy("brokered") || truthy("direct_sdk") {
            let estimated = match info.get("estimated_calls") {
                Some(Value::Null) | None => "0".to_owned(),
                Some(value) => py_str(value),
            };
            api_bits.push(format!("{provider}: {estimated} estimated call(s)"));
        }
    }
    if !api_bits.is_empty() {
        lines.push(format!("API plan: {}", api_bits.join("; ")));
    }
    let writes = facts
        .get("files")
        .and_then(|files| files.get("writes"))
        .and_then(Value::as_array)
        .map(|items| items.iter().take(5).map(py_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if !writes.is_empty() {
        lines.push(format!("File writes seen: {}", writes.join(", ")));
    }
    let ssh = facts
        .get("ssh")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    if ssh.get("detected").is_some_and(truthy) {
        let hosts = ssh
            .get("hosts")
            .and_then(Value::as_array)
            .map(|items| items.iter().take(5).map(py_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut line = "SSH use seen".to_owned();
        if !hosts.is_empty() {
            line.push_str(&format!(": {}", hosts.join(", ")));
        }
        lines.push(line);
    }
    let uncertainty = normalized
        .get("uncertainty")
        .and_then(Value::as_array)
        .map(|items| items.iter().take(3).map(py_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if !uncertainty.is_empty() {
        lines.push(format!("Uncertainty: {}", uncertainty.join(", ")));
    }
    lines
}

fn strings(names: Option<&[String]>) -> Value {
    match names {
        None => Value::Null,
        Some(items) => Value::Array(items.iter().map(|s| Value::String(s.clone())).collect()),
    }
}

fn identity_summary(run_identity: &Value) -> Value {
    let mut fields = Map::new();
    if let Some(identity) = run_identity.as_object() {
        for key in [
            "command_fingerprint",
            "script_kind",
            "script_sha256",
            "script_ref_hash",
        ] {
            if let Some(Value::String(value)) = identity.get(key)
                && !value.is_empty()
            {
                fields.insert(key.into(), text_value(identity.get(key), 80));
            }
        }
    }
    Value::Object(fields)
}

fn normalize_scope(scope: Option<&Value>) -> Value {
    let empty = Map::new();
    let scope = scope.and_then(Value::as_object).unwrap_or(&empty);
    let secret_names = scope_list(scope.get("secret_names").unwrap_or(&Value::Null));
    let capability_names = scope_list(scope.get("capability_names").unwrap_or(&Value::Null));
    let mut normalized = Map::new();
    normalized.insert("secret_names".into(), Value::Array(secret_names.clone()));
    normalized.insert(
        "capability_names".into(),
        Value::Array(capability_names.clone()),
    );
    normalized.insert(
        "raw_secret_injection".into(),
        Value::Bool(
            scope.get("raw_secret_injection").is_some_and(truthy) || !secret_names.is_empty(),
        ),
    );
    normalized.insert(
        "broker_capability".into(),
        Value::Bool(
            scope.get("broker_capability").is_some_and(truthy) || !capability_names.is_empty(),
        ),
    );
    if !capability_names.is_empty() {
        normalized.insert("max_calls".into(), int_or_none(scope.get("max_calls")));
    }
    Value::Object(normalized)
}

fn normalize_facts(facts: Option<&Value>) -> Value {
    let Some(facts) = facts.and_then(Value::as_object) else {
        return Value::Object(Map::new());
    };
    let empty = Map::new();
    let mut normalized = Map::new();
    if facts.contains_key("command_allowed") {
        normalized.insert(
            "command_allowed".into(),
            Value::Bool(facts.get("command_allowed").is_some_and(truthy)),
        );
    }
    for key in [
        "command_mode",
        "command_reason",
        "script_path",
        "preflight_error",
    ] {
        if facts.contains_key(key) {
            normalized.insert(key.into(), text_value(facts.get(key), MAX_TEXT_CHARS));
        }
    }
    if facts.contains_key("raw_key_findings") {
        let raw = facts
            .get("raw_key_findings")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        normalized.insert(
            "raw_key_findings".into(),
            json!({
                "count": non_negative_int(raw.get("count")),
                "codes": string_list(raw.get("codes"), MAX_LIST_ITEMS),
            }),
        );
    }
    if let Some(api) = facts.get("api").and_then(Value::as_object) {
        normalized.insert("api".into(), api_summary(api));
    }
    if facts.contains_key("ssh") {
        let ssh = facts
            .get("ssh")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        normalized.insert(
            "ssh".into(),
            json!({
                "detected": ssh.get("detected").is_some_and(truthy),
                "hosts": string_list(ssh.get("hosts"), MAX_LIST_ITEMS),
            }),
        );
    }
    if facts.contains_key("files") {
        let files = facts
            .get("files")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        normalized.insert(
            "files".into(),
            json!({"writes": string_list(files.get("writes"), MAX_LIST_ITEMS)}),
        );
    }
    if facts.contains_key("broker_handoff") {
        normalized.insert(
            "broker_handoff".into(),
            broker_handoff_summary(facts.get("broker_handoff")),
        );
    }
    Value::Object(drop_empty(normalized))
}

fn api_summary(api: &Map<String, Value>) -> Value {
    let mut providers: Vec<_> = api.iter().collect();
    providers.sort_by(|a, b| a.0.cmp(b.0));
    let mut summary = Map::new();
    for (provider, info) in providers {
        let Some(info) = info.as_object() else {
            continue;
        };
        let active = [
            "imported",
            "call_sites",
            "unknown_call_count",
            "recommended_max_calls",
            "direct_sdk",
            "brokered",
            "rewrite_required",
        ]
        .iter()
        .any(|key| info.get(*key).is_some_and(truthy));
        if !active {
            continue;
        }
        let name =
            text(&Value::String(provider.clone()), 80).unwrap_or_else(|| "unknown".to_owned());
        summary.insert(
            name,
            json!({
                "imported": info.get("imported").is_some_and(truthy),
                "call_sites": non_negative_int(info.get("call_sites")),
                "estimated_calls": int_or_none(info.get("estimated_calls")),
                "unknown_call_count": info.get("unknown_call_count").is_some_and(truthy),
                "recommended_max_calls": non_negative_int(info.get("recommended_max_calls")),
                "direct_sdk": info.get("direct_sdk").is_some_and(truthy),
                "brokered": info.get("brokered").is_some_and(truthy),
                "rewrite_required": info.get("rewrite_required").is_some_and(truthy),
            }),
        );
    }
    Value::Object(summary)
}

fn broker_handoff_summary(value: Option<&Value>) -> Value {
    let Some(value) = value.and_then(Value::as_object) else {
        return Value::Null;
    };
    let mut summary = Map::new();
    for key in ["recommended_tool", "reason", "provider"] {
        if let Some(field) = value.get(key)
            && !field.is_null()
        {
            summary.insert(key.into(), text_value(Some(field), 200));
        }
    }
    if summary.is_empty() {
        Value::Null
    } else {
        Value::Object(summary)
    }
}

fn scope_list(value: &Value) -> Vec<Value> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    let mut cleaned: Vec<String> = items.iter().filter_map(|item| text(item, 256)).collect();
    cleaned.sort();
    cleaned.dedup();
    cleaned.into_iter().map(Value::String).collect()
}

fn string_list(value: Option<&Value>, max_items: usize) -> Vec<Value> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let cleaned: Vec<String> = items
        .iter()
        .take(max_items)
        .filter_map(|item| text(item, MAX_TEXT_CHARS))
        .collect();
    unique(cleaned).into_iter().map(Value::String).collect()
}

fn normalize_argv(value: Option<&Value>) -> Vec<Value> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .take(MAX_ARGV_ITEMS)
        .map(|item| Value::String(text(item, MAX_ARGV_ITEM_CHARS).unwrap_or_default()))
        .collect()
}

/// `_text`: `str(value).strip()[:max_chars]`, or None for None/blank.
fn text(value: &Value, max_chars: usize) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let text = py_str(value);
    let trimmed = py_strip(&text);
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(max_chars).collect())
}

fn text_opt(value: Option<&Value>, max_chars: usize) -> Option<String> {
    value.and_then(|v| text(v, max_chars))
}

fn text_value(value: Option<&Value>, max_chars: usize) -> Value {
    text_opt(value, max_chars).map_or(Value::Null, Value::String)
}

/// `_int_or_none`: Python `int(value)` for the JSON types, None when it fails.
fn int_or_none(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Bool(flag)) => json!(i64::from(*flag)),
        Some(Value::Number(number)) => {
            if let Some(int) = number.as_i64() {
                json!(int)
            } else if let Some(float) = number.as_f64() {
                if float.is_finite() && float.abs() < 9.0e15 {
                    json!(float.trunc() as i64)
                } else {
                    Value::Null
                }
            } else {
                Value::Null
            }
        }
        Some(Value::String(text)) => {
            let trimmed = py_strip(text).replace('_', "");
            let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(&trimmed);
            if digits.is_empty()
                || !digits.chars().all(|c| c.is_ascii_digit())
                || trimmed.contains("__")
            {
                Value::Null
            } else {
                trimmed.parse::<i64>().map_or(Value::Null, |int| json!(int))
            }
        }
        Some(_) => Value::Null,
    }
}

fn non_negative_int(value: Option<&Value>) -> Value {
    match int_or_none(value) {
        Value::Number(number) if number.as_i64().is_some_and(|int| int >= 0) => {
            Value::Number(number)
        }
        _ => json!(0),
    }
}

fn unique(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn drop_empty(map: Map<String, Value>) -> Map<String, Value> {
    map.into_iter()
        .filter(|(_, value)| match value {
            Value::Null => false,
            Value::Array(items) => !items.is_empty(),
            Value::Object(fields) => !fields.is_empty(),
            _ => true,
        })
        .collect()
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|f| f != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

/// Python `str.strip()`: Unicode whitespace at both ends.
fn py_strip(text: &str) -> &str {
    text.trim_matches(|c: char| {
        c.is_whitespace() || c == '\u{1c}' || c == '\u{1d}' || c == '\u{1e}' || c == '\u{1f}'
    })
}

/// Python `str(value)` for a JSON value (`repr` for lists and objects).
pub(crate) fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => py_repr(other),
    }
}

fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => py_repr_str(text),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| format!("{}: {}", py_repr_str(key), py_repr(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn py_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}
