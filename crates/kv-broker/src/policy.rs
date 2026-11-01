use std::collections::BTreeSet;

use crate::redact::python_repr;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];
const UNSAFE_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];
const BUILTIN_NAMES: &[&str] = &["openai", "anthropic", "google", "github", "google-cloud"];
const METHOD_OVERRIDE_HEADERS: &[&str] = &[
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
    "x-original-url",
    "x-rewrite-url",
    "x-forwarded-uri",
    "x-envoy-original-path",
    "forwarded",
];
const UNSAFE_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
const PROVIDER_FIELDS: &[&str] = &["origin", "secret_name", "rules"];
const RULE_FIELDS: &[&str] = &[
    "id",
    "methods",
    "path",
    "path_prefix",
    "allow_query",
    "query_keys",
    "allowed_headers",
    "approval",
];

#[derive(Clone, Debug)]
pub struct HttpPolicySnapshot {
    pub providers: Value,
    pub configured: bool,
    pub legacy_providers: Option<BTreeSet<String>>,
}

#[derive(Clone, Debug)]
struct Rule {
    id: String,
    methods: BTreeSet<String>,
    selector_name: String,
    selector: String,
    allow_query: bool,
    query_keys: BTreeSet<String>,
    allowed_headers: BTreeSet<String>,
    unsafe_method: bool,
}

pub fn load_http_policy_snapshot(config: &Value) -> HttpPolicySnapshot {
    let legacy = BUILTIN_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let Some(config) = config.as_object() else {
        return HttpPolicySnapshot {
            providers: Value::Null,
            configured: true,
            legacy_providers: None,
        };
    };
    let Some(policy) = config.get("broker_policy") else {
        return HttpPolicySnapshot {
            providers: json!({}),
            configured: false,
            legacy_providers: Some(legacy),
        };
    };
    let Some(policy) = policy.as_object() else {
        return HttpPolicySnapshot {
            providers: Value::Null,
            configured: true,
            legacy_providers: None,
        };
    };
    HttpPolicySnapshot {
        providers: policy.get("http").cloned().unwrap_or_else(|| json!({})),
        configured: true,
        legacy_providers: None,
    }
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let entries = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        python_ascii_string(key),
                        canonical_json(&object[key])
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", entries.join(","))
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::String(text) => python_ascii_string(text),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "null".into()),
    }
}

/// `json.dumps` with `ensure_ascii=True`: everything outside `' '..='~'` becomes `\uXXXX`
/// (UTF-16 units, so astral characters are surrogate pairs), like Python's `ESCAPE_ASCII`.
fn python_ascii_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0_u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

pub fn describe_http_policy_snapshot(snapshot: &HttpPolicySnapshot) -> Value {
    let count = snapshot
        .providers
        .as_object()
        .map_or(0, serde_json::Map::len);
    let digest = Sha256::digest(canonical_json(&snapshot.providers).as_bytes());
    json!({
        "configured":snapshot.configured,
        "provider_count":count,
        "digest":digest[..8].iter().map(|byte| format!("{byte:02x}")).collect::<String>()
    })
}

fn decision_error(code: &str, message: String) -> Value {
    json!({"allowed":false,"error":message,"error_code":code})
}

fn request_invalid(message: String) -> Value {
    decision_error("http_request_invalid", message)
}

fn policy_invalid(message: String) -> Value {
    decision_error("http_policy_invalid", message)
}

fn policy_denied(method: &str, target: &str) -> Value {
    decision_error(
        "http_policy_denied",
        format!("HTTP policy denied {method} {target}"),
    )
}

fn canonical_target(target: &Value, allow_query: bool) -> Result<(String, Option<String>), String> {
    let Some(target) = target.as_str() else {
        return Err("path must be a non-empty string".into());
    };
    if target.is_empty() {
        return Err("path must be a non-empty string".into());
    }
    if target.chars().any(|ch| !(33..=126).contains(&(ch as u32))) {
        return Err("request target must use visible ASCII without spaces".into());
    }
    if target.contains('\\') {
        return Err("path must not contain backslashes".into());
    }
    if target.contains('#') {
        return Err("path must not contain a fragment".into());
    }
    if target.contains('%') {
        return Err("encoded request targets are not supported".into());
    }
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    if !path.starts_with('/') || path.starts_with("//") {
        return Err("path must be origin-relative and start with one slash".into());
    }
    if path.contains("//") {
        return Err("path must not contain duplicate slashes".into());
    }
    if path.contains(';') {
        return Err("path must not contain matrix parameters".into());
    }
    if !path.bytes().all(path_char) {
        return Err("path contains a non-canonical character".into());
    }
    if path
        .split('/')
        .skip(1)
        .any(|part| part == "." || part == "..")
    {
        return Err("path must not contain dot segments".into());
    }
    if let Some(query) = query {
        if !allow_query {
            return Err("query parameters are not allowed".into());
        }
        if query.is_empty() {
            return Err("query string must not be empty".into());
        }
        if !query.bytes().all(query_char) {
            return Err("query contains a non-canonical character".into());
        }
        if query
            .split(['&', ';'])
            .map(|part| part.split('=').next().unwrap_or(""))
            .any(|key| key.eq_ignore_ascii_case("_method"))
        {
            return Err("query method overrides are not allowed".into());
        }
    }
    Ok((path.to_owned(), query.map(str::to_owned)))
}

fn path_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._~!$&'()*+,:=@/-".contains(&b)
}

fn query_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._~!$&'()*+,:=@/?;-".contains(&b)
}

pub fn http_headers_security_error(headers: &Value) -> Option<String> {
    if headers.is_null() {
        return None;
    }
    let Some(headers) = headers.as_object() else {
        return Some("headers must be an object".into());
    };
    let mut normalized = BTreeSet::new();
    for (name, value) in headers {
        if name.is_empty() || !name.bytes().all(header_name_char) {
            return Some(
                "header names must be strict tokens without whitespace or underscores".into(),
            );
        }
        let key = name.to_ascii_lowercase();
        if !normalized.insert(key.clone()) {
            return Some(format!("duplicate header name is not allowed: {name}"));
        }
        if key.starts_with("x-forwarded-") {
            return Some(format!("route-rewrite header is not allowed: {name}"));
        }
        if METHOD_OVERRIDE_HEADERS.contains(&key.as_str()) {
            return Some(format!("method override header is not allowed: {name}"));
        }
        if UNSAFE_HEADERS.contains(&key.as_str()) {
            return Some(format!(
                "transport-controlling header is not allowed: {name}"
            ));
        }
        let Some(value) = value.as_str() else {
            return Some(format!("header value must be a string: {name}"));
        };
        if value.bytes().any(|byte| byte < 32 || byte == 127) {
            return Some(format!("header value contains a control character: {name}"));
        }
    }
    None
}

fn header_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^`|~".contains(&byte)
}

fn validate_request(
    method: &Value,
    target: &Value,
    body: Option<&Value>,
    headers: &Value,
) -> Result<(String, String, Option<String>), String> {
    let Some(method) = method.as_str() else {
        return Err("unsupported HTTP method".into());
    };
    let method = method.to_ascii_uppercase();
    if !SAFE_METHODS.contains(&method.as_str()) && !UNSAFE_METHODS.contains(&method.as_str()) {
        return Err("unsupported HTTP method".into());
    }
    if let Some(error) = http_headers_security_error(headers) {
        return Err(error);
    }
    if SAFE_METHODS.contains(&method.as_str()) && body.is_some_and(|body| !body.is_null()) {
        return Err(format!("{method} requests must not include a body"));
    }
    let (path, query) = canonical_target(target, true)?;
    Ok((method, path, query))
}

pub fn http_request_security_error(
    method: &Value,
    target: &Value,
    body: Option<&Value>,
    headers: &Value,
) -> Option<String> {
    validate_request(method, target, body, headers).err()
}

fn unknown_field(object: &Map<String, Value>, valid: &[&str]) -> Option<String> {
    object
        .keys()
        .filter(|key| !valid.contains(&key.as_str()))
        .min()
        .map(|key| python_repr(key, false))
}

fn validate_provider_policy(value: &Value) -> Result<Vec<Rule>, String> {
    let Some(object) = value.as_object() else {
        return Err("provider HTTP policy must be an object".into());
    };
    if let Some(field) = unknown_field(object, PROVIDER_FIELDS) {
        return Err(format!("unknown provider policy field: {field}"));
    }
    let Some(rules) = object.get("rules").and_then(Value::as_array) else {
        return Err("provider HTTP policy rules must be an array".into());
    };
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, rule) in rules.iter().enumerate() {
        let label = format!("rule {}", index + 1);
        let Some(object) = rule.as_object() else {
            return Err(format!("{label} must be an object"));
        };
        if let Some(field) = unknown_field(object, RULE_FIELDS) {
            return Err(format!("{label} has unknown field: {field}"));
        }
        let Some(id) = object.get("id").and_then(Value::as_str) else {
            return Err(format!("{label} has an invalid id"));
        };
        if !valid_id(id) {
            return Err(format!("{label} has an invalid id"));
        }
        if !seen.insert(id.to_owned()) {
            return Err(format!("duplicate HTTP policy rule id: {id}"));
        }
        let Some(methods) = object.get("methods").and_then(Value::as_array) else {
            return Err(format!("rule '{id}' methods must be a non-empty array"));
        };
        if methods.is_empty() {
            return Err(format!("rule '{id}' methods must be a non-empty array"));
        }
        let mut method_set = BTreeSet::new();
        for method in methods {
            let Some(method) = method.as_str() else {
                return Err(format!("rule '{id}' has an invalid method"));
            };
            if !SAFE_METHODS.contains(&method) && !UNSAFE_METHODS.contains(&method) {
                return Err(format!("rule '{id}' has an invalid method"));
            }
            if !method_set.insert(method.to_owned()) {
                return Err(format!("rule '{id}' has duplicate methods"));
            }
        }
        let has_safe = method_set
            .iter()
            .any(|method| SAFE_METHODS.contains(&method.as_str()));
        let has_unsafe = method_set
            .iter()
            .any(|method| UNSAFE_METHODS.contains(&method.as_str()));
        if has_safe && has_unsafe {
            return Err(format!("rule '{id}' mixes safe and unsafe methods"));
        }
        let approval = object
            .get("approval")
            .and_then(Value::as_str)
            .unwrap_or("none");
        if has_unsafe && approval != "per-call" {
            return Err(format!("rule '{id}' requires approval='per-call'"));
        }
        if has_safe && approval != "none" {
            return Err(format!("rule '{id}' must use approval='none'"));
        }
        let has_path = object.contains_key("path");
        let has_prefix = object.contains_key("path_prefix");
        if has_path == has_prefix {
            return Err(format!("rule '{id}' must set exactly one path selector"));
        }
        let selector_name = if has_path { "path" } else { "path_prefix" };
        let selector_value = object.get(selector_name).unwrap_or(&Value::Null);
        let (selector, query) = canonical_target(selector_value, false)
            .map_err(|error| format!("rule '{id}' has invalid {selector_name}: {error}"))?;
        if query.is_some() {
            return Err(format!(
                "rule '{id}' has invalid {selector_name}: query parameters are not allowed"
            ));
        }
        let allow_query = match object.get("allow_query") {
            None => false,
            Some(Value::Bool(value)) => *value,
            _ => return Err(format!("rule '{id}' allow_query must be a boolean")),
        };
        let Some(query_keys) = object
            .get("query_keys")
            .map_or_else(|| Some(Vec::new()), |value| value.as_array().cloned())
        else {
            return Err(format!("rule '{id}' query_keys must be valid names"));
        };
        let mut query_key_set = BTreeSet::new();
        for key in query_keys {
            let valid = key.as_str().is_some_and(valid_query_key);
            if !valid {
                return Err(format!("rule '{id}' query_keys must be valid names"));
            }
            let key = key.as_str().unwrap_or_default().to_owned();
            if !query_key_set.insert(key) {
                return Err(format!("rule '{id}' has duplicate query_keys"));
            }
        }
        if allow_query && query_key_set.is_empty() {
            return Err(format!("rule '{id}' must constrain allowed query_keys"));
        }
        if !allow_query && !query_key_set.is_empty() {
            return Err(format!("rule '{id}' query_keys require allow_query=true"));
        }
        let Some(allowed_headers) = object
            .get("allowed_headers")
            .map_or_else(|| Some(Vec::new()), |value| value.as_array().cloned())
        else {
            return Err(format!("rule '{id}' allowed_headers must be an array"));
        };
        let mut allowed_header_set = BTreeSet::new();
        for name in allowed_headers {
            if name.as_str().is_none()
                || http_headers_security_error(&json!({name.as_str().unwrap_or(""):"allowed"}))
                    .is_some()
            {
                return Err(format!("rule '{id}' has an invalid allowed header"));
            }
            let name = name.as_str().unwrap_or_default().to_ascii_lowercase();
            if !allowed_header_set.insert(name) {
                return Err(format!("rule '{id}' has duplicate allowed_headers"));
            }
        }
        normalized.push(Rule {
            id: id.into(),
            methods: method_set,
            selector_name: selector_name.into(),
            selector,
            allow_query,
            query_keys: query_key_set,
            allowed_headers: allowed_header_set,
            unsafe_method: has_unsafe,
        });
    }
    Ok(normalized)
}

fn valid_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_query_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
        && !value.eq_ignore_ascii_case("_method")
}

pub fn validate_http_provider_policy(policy: &Value) -> Option<String> {
    validate_provider_policy(policy).err()
}

fn path_matches(rule: &Rule, path: &str) -> bool {
    if rule.selector_name == "path" {
        return path == rule.selector;
    }
    if rule.selector == "/" {
        return true;
    }
    if rule.selector.ends_with('/') {
        return path.starts_with(&rule.selector);
    }
    path == rule.selector || path.starts_with(&format!("{}/", rule.selector))
}

pub fn post_rules_overlap(a: &Value, b: &Value) -> Result<bool, String> {
    let first = validate_provider_policy(&json!({"rules":[a]}))?
        .into_iter()
        .next()
        .ok_or_else(|| "rule must be an object".to_owned())?;
    let second = validate_provider_policy(&json!({"rules":[b]}))?
        .into_iter()
        .next()
        .ok_or_else(|| "rule must be an object".to_owned())?;
    if !first.methods.contains("POST") || !second.methods.contains("POST") {
        return Ok(false);
    }
    let mut witnesses = BTreeSet::new();
    for rule in [&first, &second] {
        witnesses.insert(rule.selector.clone());
        if rule.selector_name == "path_prefix" {
            let folder = if rule.selector.ends_with('/') {
                rule.selector.clone()
            } else {
                format!("{}/", rule.selector)
            };
            witnesses.insert(folder.clone());
            witnesses.insert(format!("{folder}x"));
        }
    }
    Ok(witnesses
        .iter()
        .any(|path| path_matches(&first, path) && path_matches(&second, path)))
}

pub fn evaluate_provider_http_request(
    snapshot: &HttpPolicySnapshot,
    provider_name: &str,
    provider: &Value,
    method: &Value,
    target: &Value,
    body: Option<&Value>,
    headers: &Value,
) -> Value {
    if !provider.is_object() {
        return request_invalid("provider configuration must be an object".into());
    }
    if snapshot.configured
        && let Some(policy) = snapshot
            .providers
            .as_object()
            .and_then(|policies| policies.get(provider_name))
    {
        if !policy.is_object() {
            return policy_invalid("provider HTTP policy must be an object".into());
        }
        let expected_origin = policy.get("origin").and_then(Value::as_str);
        let expected_secret = policy.get("secret_name").and_then(Value::as_str);
        if expected_origin.is_none() || expected_secret.is_none() {
            return policy_invalid("provider HTTP policy must bind origin and secret_name".into());
        }
        let actual_origin = provider.get("base_url").and_then(Value::as_str);
        let actual_secret = provider.get("secret_name").and_then(Value::as_str);
        if actual_origin.map(|value| value.trim_end_matches('/'))
            != expected_origin.map(|value| value.trim_end_matches('/'))
            || actual_secret != expected_secret
        {
            return policy_invalid(
                "provider configuration does not match HTTP policy binding".into(),
            );
        }
    }
    let default_headers = provider
        .get("default_headers")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let caller_headers = if headers.is_null() {
        json!({})
    } else {
        headers.clone()
    };
    let mut effective = Map::new();
    if let Some(defaults) = default_headers.as_object() {
        if let Some(error) = http_headers_security_error(&default_headers) {
            return request_invalid(error);
        }
        let Some(caller) = caller_headers.as_object() else {
            if let Some(error) = http_headers_security_error(&caller_headers) {
                return request_invalid(error);
            }
            unreachable!();
        };
        if let Some(error) = http_headers_security_error(&caller_headers) {
            return request_invalid(error);
        }
        let default_names = defaults
            .keys()
            .map(|name| name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let caller_names = caller
            .keys()
            .map(|name| name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if let Some(name) = default_names.intersection(&caller_names).next() {
            return request_invalid(format!(
                "caller header collides with provider header: {name}"
            ));
        }
        let forbidden = caller_names
            .intersection(&BTreeSet::from([
                "authorization".to_owned(),
                "cookie".to_owned(),
                "proxy-authorization".to_owned(),
                "x-api-key".to_owned(),
            ]))
            .next()
            .cloned();
        if let Some(name) = forbidden {
            return request_invalid(format!(
                "caller authentication header is not allowed: {name}"
            ));
        }
        effective.extend(defaults.clone());
        effective.extend(caller.clone());
        let auth_type = provider
            .get("auth_type")
            .and_then(Value::as_str)
            .unwrap_or("bearer");
        let auth_name = match auth_type {
            "bearer" | "basic" => Some("Authorization".to_owned()),
            "x-api-key" => Some("x-api-key".to_owned()),
            "header" => {
                let Some(name) = provider
                    .get("auth_header_name")
                    .map_or(Some("Authorization"), Value::as_str)
                else {
                    return request_invalid("provider auth header name must be a string".into());
                };
                Some(name.to_owned())
            }
            _ => None,
        };
        if let Some(name) = auth_name {
            if caller_names.contains(&name.to_ascii_lowercase()) {
                return request_invalid(
                    "caller header collides with broker-owned authentication".into(),
                );
            }
            effective.insert(name, Value::String("broker-owned credential".into()));
        }
        if auth_type == "query" && target.as_str().is_some_and(|target| target.contains('?')) {
            let auth_query = provider
                .get("auth_query_param")
                .and_then(Value::as_str)
                .unwrap_or("key");
            let query = target
                .as_str()
                .unwrap_or_default()
                .split_once('?')
                .map_or("", |(_, q)| q);
            if query
                .split(['&', ';'])
                .map(|part| part.split('=').next().unwrap_or(""))
                .any(|name| name == auth_query)
            {
                return request_invalid(
                    "caller query collides with broker-owned authentication".into(),
                );
            }
        }
    } else if !caller_headers.is_object()
        && let Some(error) = http_headers_security_error(&caller_headers)
    {
        return request_invalid(error);
    }
    let names = caller_headers
        .as_object()
        .map(|headers| {
            headers
                .keys()
                .map(|name| name.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    evaluate_http_policy(
        snapshot,
        provider_name,
        method,
        target,
        body,
        &Value::Object(effective),
        Some(names),
    )
}

pub fn evaluate_http_policy(
    snapshot: &HttpPolicySnapshot,
    provider_name: &str,
    method: &Value,
    target: &Value,
    body: Option<&Value>,
    headers: &Value,
    policy_header_names: Option<BTreeSet<String>>,
) -> Value {
    if provider_name.is_empty() {
        return request_invalid("provider must be a non-empty string".into());
    }
    let (method, path, query) = match validate_request(method, target, body, headers) {
        Ok(parsed) => parsed,
        Err(error) => return request_invalid(error),
    };
    let policy_headers = policy_header_names.unwrap_or_else(|| {
        headers
            .as_object()
            .map(|map| map.keys().map(|key| key.to_ascii_lowercase()).collect())
            .unwrap_or_default()
    });
    let Some(policy_map) = snapshot.providers.as_object() else {
        return policy_invalid("HTTP policy snapshot must be an object".into());
    };
    let Some(provider_policy) = policy_map.get(provider_name) else {
        let legacy_allowed = BUILTIN_NAMES.contains(&provider_name)
            && snapshot
                .legacy_providers
                .as_ref()
                .is_none_or(|names| names.contains(provider_name));
        if !snapshot.configured
            && legacy_allowed
            && SAFE_METHODS.contains(&method.as_str())
            && query.is_none()
            && policy_headers.is_empty()
        {
            return json!({"allowed":true,"warning":"legacy_read_only_policy"});
        }
        return policy_denied(&method, target.as_str().unwrap_or_default());
    };
    let rules = match validate_provider_policy(provider_policy) {
        Ok(rules) => rules,
        Err(error) => return policy_invalid(error),
    };
    for rule in rules {
        if !rule.methods.contains(&method) || !path_matches(&rule, &path) {
            continue;
        }
        if query.is_some() && !rule.allow_query {
            continue;
        }
        if let Some(query) = query.as_deref() {
            let keys = query
                .split(['&', ';'])
                .map(|part| part.split('=').next().unwrap_or("").to_owned())
                .collect::<BTreeSet<_>>();
            if !keys.is_subset(&rule.query_keys) {
                continue;
            }
        }
        if !policy_headers.is_subset(&rule.allowed_headers) {
            continue;
        }
        if rule.unsafe_method {
            return json!({
                "allowed":false,
                "error":format!("approval required for {method} {}", target.as_str().unwrap_or_default()),
                "error_code":"http_approval_required",
                "approval_required":true,
                "policy_rule":rule.id
            });
        }
        return json!({"allowed":true,"policy_rule":rule.id});
    }
    policy_denied(&method, target.as_str().unwrap_or_default())
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn describe_digest_escapes_non_ascii_like_python() {
        let snapshot = HttpPolicySnapshot {
            configured: true,
            legacy_providers: None,
            providers: serde_json::json!({"p":{"name":"h\u{e9}llo \u{2713} \u{1F600}","rules":[{"path":"/\u{7f}"}]}}),
        };
        let described = describe_http_policy_snapshot(&snapshot);
        assert_eq!(described["digest"], "82033b13e7c73915");
    }
}
