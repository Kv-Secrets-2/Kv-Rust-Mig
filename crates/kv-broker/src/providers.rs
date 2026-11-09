use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::KEY_PLACEHOLDER;
use crate::policy::http_headers_security_error;

pub type ProviderTable = BTreeMap<String, Value>;

fn builtin_table() -> ProviderTable {
    let entries = [
        (
            "openai",
            json!({
                "base_url":"https://api.openai.com",
                "secret_name":"OPENAI_API_KEY",
                "auth_type":"bearer",
                "default_headers":{"Content-Type":"application/json"}
            }),
        ),
        (
            "anthropic",
            json!({
                "base_url":"https://api.anthropic.com",
                "secret_name":"ANTHROPIC_API_KEY",
                "auth_type":"x-api-key",
                "default_headers":{
                    "Content-Type":"application/json",
                    "anthropic-version":"2023-06-01"
                }
            }),
        ),
        (
            "google",
            json!({
                "base_url":"https://generativelanguage.googleapis.com",
                "secret_name":"GOOGLE_API_KEY",
                "auth_type":"query",
                "auth_query_param":"key",
                "default_headers":{"Content-Type":"application/json"}
            }),
        ),
        (
            "github",
            json!({
                "base_url":"https://api.github.com",
                "secret_name":"GITHUB_TOKEN",
                "auth_type":"bearer",
                "default_headers":{
                    "Accept":"application/vnd.github+json",
                    "X-GitHub-Api-Version":"2022-11-28"
                }
            }),
        ),
        (
            "google-cloud",
            json!({
                "base_url":"https://www.googleapis.com",
                "secret_name":"GOOGLE_CLOUD_API_KEY",
                "auth_type":"query",
                "auth_query_param":"key",
                "default_headers":{"Content-Type":"application/json"}
            }),
        ),
    ];
    entries
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

pub fn is_builtin_provider_name(name: &str) -> bool {
    matches!(
        name,
        "openai" | "anthropic" | "google" | "github" | "google-cloud"
    )
}

pub fn validate_http_provider(config: &Value) -> Result<(), String> {
    let Some(config) = config.as_object() else {
        return Err("provider must be an object".into());
    };
    let Some(base_url) = config.get("base_url").and_then(Value::as_str) else {
        return Err("missing required field: base_url".into());
    };
    if base_url.is_empty() {
        return Err("missing required field: base_url".into());
    }
    if base_url.chars().any(|ch| !('!'..='\u{7e}').contains(&ch)) {
        return Err("base_url must use visible ASCII without spaces".into());
    }
    if base_url.contains('?') || base_url.contains('#') {
        return Err("base_url must not include a query or fragment".into());
    }
    if !config
        .get("secret_name")
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty())
    {
        return Err("missing required field: secret_name".into());
    }
    let parsed = url::Url::parse(base_url).map_err(|_| {
        if base_url.contains(':') && !base_url.contains("://") {
            "base_url has an invalid port".to_owned()
        } else {
            "base_url must include a hostname".to_owned()
        }
    })?;
    if parsed.scheme() != "https" {
        return Err("base_url must use HTTPS".into());
    }
    if parsed.host_str().is_none() {
        return Err("base_url must include a hostname".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("base_url must not include userinfo".into());
    }
    let authority = base_url
        .split_once("://")
        .map(|(_, value)| value.split(['/', '?', '#']).next().unwrap_or(""))
        .unwrap_or("");
    if authority.contains('\\') || authority.contains('%') {
        return Err("base_url has a non-canonical authority".into());
    }
    if authority.ends_with(':') {
        return Err("base_url must not include an empty port".into());
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err("base_url must be an origin without a path".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("base_url must not include a query or fragment".into());
    }
    if parsed.port().is_some_and(|port| port == 0) {
        return Err("base_url has an invalid port".into());
    }

    let auth_type = config
        .get("auth_type")
        .and_then(Value::as_str)
        .unwrap_or("bearer");
    if !matches!(
        auth_type,
        "bearer" | "x-api-key" | "query" | "basic" | "header"
    ) {
        return Err(format!("unsupported auth_type: {auth_type}"));
    }
    let defaults = config
        .get("default_headers")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Some(error) = http_headers_security_error(&defaults) {
        return Err(error);
    }
    let default_names = defaults
        .as_object()
        .into_iter()
        .flat_map(Map::keys)
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let auth_header = match auth_type {
        "bearer" | "basic" => Some("authorization".to_owned()),
        "x-api-key" => Some("x-api-key".to_owned()),
        "header" => {
            let name = config
                .get("auth_header_name")
                .cloned()
                .unwrap_or_else(|| Value::String("Authorization".into()));
            let Some(name) = name.as_str() else {
                return Err("auth_header_name must be a string".into());
            };
            let error = http_headers_security_error(&json!({name:"broker-owned credential"}));
            if let Some(error) = error {
                return Err(error);
            }
            Some(name.to_ascii_lowercase())
        }
        _ => None,
    };
    if auth_header.is_some_and(|name| default_names.contains(&name)) {
        return Err("default_headers must not define the authentication header".into());
    }
    if auth_type == "query" {
        let param = config
            .get("auth_query_param")
            .cloned()
            .unwrap_or_else(|| Value::String("key".into()));
        let valid = param.as_str().is_some_and(|name| {
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
                && !name.eq_ignore_ascii_case("_method")
        });
        if !valid {
            return Err("auth_query_param is invalid".into());
        }
    }
    Ok(())
}

pub fn build_provider_table(config: &Value) -> (ProviderTable, usize) {
    let mut candidate = builtin_table();
    let mut loaded = 0;
    let Some(custom) = config.get("providers").and_then(Value::as_object) else {
        return (candidate, loaded);
    };
    for (name, raw) in custom {
        if name.is_empty() || is_builtin_provider_name(name) {
            continue;
        }
        let Some(raw) = raw.as_object() else {
            continue;
        };
        let ptype = raw
            .get("provider_type")
            .or_else(|| raw.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("http");
        let mut normalized = if ptype == "http" {
            let mut normalized = Map::new();
            normalized.insert("provider_type".into(), Value::String("http".into()));
            for key in ["base_url", "secret_name"] {
                normalized.insert(key.into(), raw.get(key).cloned().unwrap_or(Value::Null));
            }
            normalized.insert(
                "auth_type".into(),
                raw.get("auth_type")
                    .cloned()
                    .unwrap_or_else(|| Value::String("bearer".into())),
            );
            normalized.insert(
                "default_headers".into(),
                raw.get("default_headers")
                    .cloned()
                    .unwrap_or_else(|| json!({"Content-Type":"application/json"})),
            );
            for (key, value) in raw {
                if ![
                    "provider_type",
                    "type",
                    "base_url",
                    "secret_name",
                    "auth_type",
                    "default_headers",
                ]
                .contains(&key.as_str())
                {
                    normalized.insert(key.clone(), value.clone());
                }
            }
            if validate_http_provider(&Value::Object(normalized.clone())).is_err() {
                continue;
            }
            if let Some(base_url) = normalized.get("base_url").and_then(Value::as_str) {
                let base_url = base_url.trim_end_matches('/').to_owned();
                normalized.insert("base_url".into(), Value::String(base_url));
            }
            normalized
        } else {
            let valid =
                match ptype {
                    "postgres" | "mysql" => ["host", "database", "username", "secret_name"]
                        .iter()
                        .all(|field| {
                            raw.get(*field)
                                .is_some_and(|value| !value.is_null() && value != "")
                        }),
                    "redis" => ["host", "secret_name"].iter().all(|field| {
                        raw.get(*field)
                            .is_some_and(|value| !value.is_null() && value != "")
                    }),
                    "ssh" => ["host", "username", "secret_name"].iter().all(|field| {
                        raw.get(*field)
                            .is_some_and(|value| !value.is_null() && value != "")
                    }),
                    _ => false,
                };
            if !valid {
                continue;
            }
            let mut value = Map::new();
            value.insert("provider_type".into(), Value::String(ptype.into()));
            value.extend(raw.clone());
            value
        };
        candidate.insert(name.clone(), Value::Object(std::mem::take(&mut normalized)));
        loaded += 1;
    }
    (candidate, loaded)
}

pub fn load_custom_providers(config: &Value) -> usize {
    build_provider_table(config).1
}

pub fn snapshot_providers(config: &Value) -> ProviderTable {
    build_provider_table(config).0
}

#[allow(clippy::type_complexity)]
pub fn build_auth(
    provider: &Value,
    secret: &str,
) -> Result<(BTreeMap<String, String>, BTreeMap<String, String>), String> {
    let mut headers = BTreeMap::new();
    if let Some(defaults) = provider.get("default_headers").and_then(Value::as_object) {
        for (name, value) in defaults {
            let Some(value) = value.as_str() else {
                return Err(format!("header value must be a string: {name}"));
            };
            headers.insert(name.clone(), value.to_owned());
        }
    }
    let mut query = BTreeMap::new();
    match provider
        .get("auth_type")
        .and_then(Value::as_str)
        .unwrap_or("bearer")
    {
        "bearer" => {
            headers.insert("Authorization".into(), format!("Bearer {secret}"));
        }
        "x-api-key" => {
            headers.insert("x-api-key".into(), secret.to_owned());
        }
        "query" => {
            let name = provider
                .get("auth_query_param")
                .and_then(Value::as_str)
                .unwrap_or("key");
            query.insert(name.to_owned(), secret.to_owned());
        }
        "basic" => {
            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::STANDARD.encode(format!(":{secret}"));
            headers.insert("Authorization".into(), format!("Basic {encoded}"));
        }
        "header" => {
            let name = provider
                .get("auth_header_name")
                .and_then(Value::as_str)
                .unwrap_or("Authorization");
            headers.insert(name.to_owned(), secret.to_owned());
        }
        other => return Err(format!("unsupported auth_type: {other}")),
    }
    Ok((headers, query))
}

pub fn build_url(
    provider: &Value,
    path: &str,
    query_params: &BTreeMap<String, String>,
) -> Result<String, String> {
    let base = provider
        .get("base_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing base_url".to_owned())?;
    let mut url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    if !query_params.is_empty() {
        url.push(if url.contains('?') { '&' } else { '?' });
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in query_params {
            serializer.append_pair(name, value);
        }
        url.push_str(&serializer.finish());
    }
    Ok(url)
}

pub fn shown_auth_url(
    provider: &Value,
    path: &str,
    query_params: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut url = build_url(provider, path, &BTreeMap::new())?;
    if !query_params.is_empty() {
        url.push(if url.contains('?') { '&' } else { '?' });
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for name in query_params.keys() {
            serializer.append_pair(name, KEY_PLACEHOLDER);
        }
        url.push_str(&serializer.finish());
    }
    Ok(url)
}

pub fn contains_provider_secret_template(text: &str, provider_secret_name: &str) -> bool {
    if provider_secret_name.is_empty() {
        return false;
    }
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        rest = &rest[start + 2..];
        let Some(end) = rest.find('}') else {
            return false;
        };
        if &rest[..end] == provider_secret_name {
            return true;
        }
        rest = &rest[end + 1..];
    }
    false
}

pub fn api_body_security_error(provider: &Value, body: Option<&Value>) -> Option<String> {
    let body = body?;
    let secret_name = provider.get("secret_name").and_then(Value::as_str)?;
    if secret_name.is_empty() {
        return None;
    }
    let body_text = match body {
        Value::String(value) => value.clone(),
        _ => body.to_string(),
    };
    contains_provider_secret_template(&body_text, secret_name).then(|| {
        "provider secret templates are not allowed in agent-controlled request bodies".to_owned()
    })
}
