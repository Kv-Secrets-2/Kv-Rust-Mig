use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use url::{Host, Url};

use crate::ERROR_BODY_WITHHELD;
use crate::policy::{http_headers_security_error, http_request_security_error};
use crate::providers::{api_body_security_error, build_auth, build_url, validate_http_provider};
use crate::redact::{hide, hide_cut, hide_value, output_needles};

#[derive(Clone, Debug)]
pub struct ApiRequest<'a> {
    pub provider_name: &'a str,
    pub provider: &'a Value,
    pub secret_value: &'a str,
    pub path: &'a str,
    pub method: &'a str,
    pub body: Option<&'a Value>,
    pub extra_headers: &'a Value,
    pub secrets_for_redact: &'a Value,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

#[doc(hidden)]
pub trait UrlSafety: Send + Sync {
    fn check(&self, url: &Url) -> Result<IpAddr, String>;
}

struct SystemUrlSafety;

impl UrlSafety for SystemUrlSafety {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        check_url_safety(url)
    }
}

#[derive(Clone)]
pub struct ApiCaller {
    safety: Arc<dyn UrlSafety>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl Default for ApiCaller {
    fn default() -> Self {
        Self {
            safety: Arc::new(SystemUrlSafety),
            tls_config: None,
        }
    }
}

impl ApiCaller {
    pub fn new() -> Self {
        Self::default()
    }

    #[doc(hidden)]
    pub fn with_url_safety_for_test(safety: Arc<dyn UrlSafety>) -> Self {
        Self {
            safety,
            tls_config: None,
        }
    }

    #[doc(hidden)]
    pub fn with_test_transport(
        safety: Arc<dyn UrlSafety>,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            safety,
            tls_config: Some(tls_config),
        }
    }

    #[doc(hidden)]
    pub fn with_test_ca_for_test(
        safety: Arc<dyn UrlSafety>,
        certificate_der: &[u8],
    ) -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                certificate_der.to_vec(),
            ))
            .map_err(|error| format!("invalid test CA certificate: {error}"))?;
        let tls_config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|error| format!("invalid test TLS configuration: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            safety,
            tls_config: Some(Arc::new(tls_config)),
        })
    }

    pub fn call(&self, request: ApiRequest<'_>) -> Value {
        let ApiRequest {
            provider_name,
            provider,
            secret_value,
            path,
            method,
            body,
            extra_headers,
            secrets_for_redact,
            timeout,
            max_response_bytes,
        } = request;
        if provider.is_null() {
            return json!({"error":format!("unknown provider: {provider_name}. available: ")});
        }
        if provider
            .get("provider_type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind != "http")
        {
            return json!({"error":format!("provider '{provider_name}' is not an HTTP API provider")});
        }
        if let Err(error) = validate_http_provider(provider) {
            return json!({
                "error":format!("invalid HTTP provider: {error}"),
                "error_code":"http_provider_invalid"
            });
        }
        if let Some(error) = api_body_security_error(provider, body) {
            return json!({"error":error});
        }
        let empty_headers = Value::Object(Default::default());
        let headers = if extra_headers.is_null() {
            &empty_headers
        } else {
            extra_headers
        };
        if let Some(error) = http_request_security_error(
            &Value::String(method.into()),
            &Value::String(path.into()),
            body,
            headers,
        ) {
            return json!({"error":error,"error_code":"http_request_invalid"});
        }
        let body_bytes = match body {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) => Some(text.as_bytes().to_vec()),
            Some(value @ (Value::Array(_) | Value::Object(_))) => {
                Some(python_json(value).into_bytes())
            }
            Some(_) => None,
        };
        let defaults = provider
            .get("default_headers")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Some(error) = http_headers_security_error(&defaults) {
            return json!({"error":error,"error_code":"http_request_invalid"});
        }
        if provider
            .get("auth_type")
            .and_then(Value::as_str)
            .unwrap_or("bearer")
            == "header"
        {
            let header_name = provider
                .get("auth_header_name")
                .cloned()
                .unwrap_or_else(|| Value::String("Authorization".into()));
            let Some(header_name) = header_name.as_str() else {
                return json!({
                    "error":"provider auth header name must be a string",
                    "error_code":"http_request_invalid"
                });
            };
            if let Some(error) =
                http_headers_security_error(&json!({header_name:"broker-owned credential"}))
            {
                return json!({"error":error,"error_code":"http_request_invalid"});
            }
        }
        let (mut auth_headers, auth_query) = match build_auth(provider, secret_value) {
            Ok(auth) => auth,
            Err(error) => return json!({"error":format!("request failed: {error}")}),
        };
        let auth_type = provider
            .get("auth_type")
            .and_then(Value::as_str)
            .unwrap_or("bearer");
        let mut exact = vec![secret_value.to_owned()];
        if auth_type == "query" {
            for value in auth_query.values() {
                let encoded =
                    url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
                exact.push(value.clone());
                exact.push(encoded);
            }
        } else {
            let auth_name = match auth_type {
                "bearer" | "basic" => "authorization".to_owned(),
                "x-api-key" => "x-api-key".to_owned(),
                _ => provider
                    .get("auth_header_name")
                    .and_then(Value::as_str)
                    .unwrap_or("Authorization")
                    .to_ascii_lowercase(),
            };
            for (name, value) in &auth_headers {
                if name.eq_ignore_ascii_case(&auth_name) {
                    exact.push(value.clone());
                    if auth_type == "basic"
                        && let Some(token) = value.strip_prefix("Basic ")
                    {
                        exact.push(token.to_owned());
                        exact.push(token.trim_end_matches('=').to_owned());
                    }
                }
            }
        }
        let caller_names = headers
            .as_object()
            .map(|object| {
                object
                    .keys()
                    .map(|name| name.to_ascii_lowercase())
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        let provider_names = auth_headers
            .keys()
            .map(|name| name.to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(name) = caller_names.intersection(&provider_names).next() {
            return json!({
                "error":format!("caller header collides with provider-owned header: {name}"),
                "error_code":"http_request_invalid"
            });
        }
        if caller_names.iter().any(|name| {
            matches!(
                name.as_str(),
                "authorization" | "cookie" | "proxy-authorization" | "x-api-key"
            )
        }) {
            return json!({
                "error":"caller authentication headers are not allowed",
                "error_code":"http_request_invalid"
            });
        }
        if !auth_query.is_empty() && path.contains('?') {
            let query = path.split_once('?').map_or("", |(_, query)| query);
            let keys = query
                .split(['&', ';'])
                .map(|part| part.split('=').next().unwrap_or(""));
            if auth_query
                .keys()
                .any(|key| keys.clone().any(|candidate| candidate == key))
            {
                return json!({
                    "error":"caller query collides with broker-owned authentication",
                    "error_code":"http_request_invalid"
                });
            }
        }
        let url = match build_url(provider, path, &auth_query) {
            Ok(url) => url,
            Err(error) => return json!({"error":error}),
        };
        let parsed = match Url::parse(&url) {
            Ok(parsed) => parsed,
            Err(_) => return json!({"error":"SSRF blocked: empty hostname"}),
        };
        let pinned_ip = if is_builtin_url(provider) {
            None
        } else {
            match self.safety.check(&parsed) {
                Ok(ip) => Some(ip),
                Err(error) => return json!({"error":format!("SSRF blocked: {error}")}),
            }
        };
        let mut redact = secrets_for_redact.clone();
        if !secret_value.is_empty() {
            if let Some(object) = redact.as_object_mut() {
                object
                    .entry("__provider_credential__")
                    .or_insert_with(|| Value::String(secret_value.to_owned()));
            } else {
                redact = json!({"__provider_credential__":secret_value});
            }
        }
        let exact = exact.iter().map(String::as_str).collect::<Vec<_>>();
        let needles = output_needles(&redact, &exact);
        for (name, value) in headers.as_object().into_iter().flatten() {
            if let Some(value) = value.as_str() {
                auth_headers.insert(name.clone(), value.to_owned());
            }
        }
        if let Some(error) = http_headers_security_error(&Value::Object(
            auth_headers
                .iter()
                .map(|(name, value)| (name.clone(), Value::String(value.clone())))
                .collect(),
        )) {
            return json!({"error":error,"error_code":"http_request_invalid"});
        }
        self.send(
            &url,
            &parsed,
            pinned_ip,
            method,
            body_bytes.as_deref(),
            &auth_headers,
            timeout,
            max_response_bytes,
            &needles,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn send(
        &self,
        url: &str,
        parsed: &Url,
        pinned_ip: Option<IpAddr>,
        method: &str,
        body: Option<&[u8]>,
        headers: &std::collections::BTreeMap<String, String>,
        timeout: Duration,
        limit: usize,
        needles: &crate::Needles,
    ) -> Value {
        let resolver = pinned_ip.map(|ip| PinnedResolver {
            hostname: parsed
                .host_str()
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            ip,
        });
        let mut builder = ureq::AgentBuilder::new().redirects(0).timeout(timeout);
        if let Some(tls_config) = &self.tls_config {
            builder = builder.tls_config(Arc::clone(tls_config));
        }
        if let Some(resolver) = resolver {
            builder = builder.resolver(resolver);
        }
        let agent = builder.build();
        let mut request = agent.request(method, url);
        for (name, value) in headers {
            request = request.set(name, value);
        }
        let result = if let Some(body) = body {
            request.send_bytes(body)
        } else {
            request.call()
        };
        match result {
            Ok(response) => {
                let status = response.status();
                let chunked = is_chunked(&response);
                let mut reader = response.into_reader();
                let (body_text, truncated) = match read_limited(&mut reader, limit, chunked) {
                    Ok(read) => read,
                    Err(error) => return read_failure(&error, timeout),
                };
                let body_value = if truncated {
                    truncated_text(&body_text, needles)
                } else if (300..400).contains(&status) {
                    decode_error_body(&body_text, needles)
                } else {
                    decode_body(&body_text, needles)
                };
                if (300..400).contains(&status) {
                    let mut result = json!({
                        "error":format!("HTTP {status}: redirect blocked"),
                        "status":status,
                        "body":body_value
                    });
                    if truncated {
                        result["response_truncated"] = Value::Bool(true);
                        result["max_response_bytes"] = json!(limit);
                        append_warning(
                            &mut result,
                            &format!("HTTP error response truncated after {limit} bytes"),
                        );
                    }
                    return result;
                }
                let mut result = json!({"status":status,"body":body_value});
                if truncated {
                    result["response_truncated"] = Value::Bool(true);
                    result["max_response_bytes"] = json!(limit);
                    append_warning(
                        &mut result,
                        &format!("HTTP response truncated after {limit} bytes"),
                    );
                }
                result
            }
            Err(ureq::Error::Status(code, response)) => {
                let chunked = is_chunked(&response);
                let mut reader = response.into_reader();
                let (body_text, truncated) = match read_limited(&mut reader, limit, chunked) {
                    Ok(read) => read,
                    Err(error) => return read_failure(&error, timeout),
                };
                let error_body = if truncated {
                    truncated_text(&body_text, needles)
                } else {
                    decode_error_body(&body_text, needles)
                };
                let reason = if (300..400).contains(&code) {
                    "redirect blocked"
                } else {
                    "request failed"
                };
                let mut result = json!({
                    "error":format!("HTTP {code}: {reason}"),
                    "status":code,
                    "body":error_body
                });
                if truncated {
                    result["response_truncated"] = Value::Bool(true);
                    result["max_response_bytes"] = json!(limit);
                    append_warning(
                        &mut result,
                        &format!("HTTP error response truncated after {limit} bytes"),
                    );
                }
                result
            }
            Err(ureq::Error::Transport(error)) => {
                let text = error.to_string().to_ascii_lowercase();
                if text.contains("timeout") || text.contains("timed out") {
                    json!({"error":format!("timeout ({}s)", timeout.as_secs())})
                } else if text.contains("dns")
                    || text.contains("resolve")
                    || text.contains("connect")
                {
                    json!({"error":"connection error"})
                } else {
                    json!({"error":format!("request failed: {}", transport_exception_name(error.kind()))})
                }
            }
        }
    }
}

struct PinnedResolver {
    hostname: String,
    ip: IpAddr,
}

impl ureq::Resolver for PinnedResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let (host, port) = if let Some(bracketed) = netloc.strip_prefix('[') {
            let (host, remainder) = bracketed.split_once(']').ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid pinned host")
            })?;
            let port = remainder
                .strip_prefix(':')
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid pinned port")
                })?;
            (host, port)
        } else {
            let (host, port) = netloc.rsplit_once(':').ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid pinned netloc")
            })?;
            let port = port.parse::<u16>().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid pinned port")
            })?;
            (host, port)
        };
        if !host
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&self.hostname)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "pinned host mismatch",
            ));
        }
        Ok(vec![SocketAddr::new(self.ip, port)])
    }
}

fn transport_exception_name(kind: ureq::ErrorKind) -> &'static str {
    match kind {
        ureq::ErrorKind::Dns => "gaierror",
        ureq::ErrorKind::Io => "OSError",
        ureq::ErrorKind::InvalidUrl => "ValueError",
        ureq::ErrorKind::InvalidProxyUrl => "ValueError",
        ureq::ErrorKind::TooManyRedirects => "HTTPError",
        ureq::ErrorKind::BadStatus => "HTTPError",
        ureq::ErrorKind::HTTP => "HTTPException",
        _ => "OSError",
    }
}

fn is_builtin_url(provider: &Value) -> bool {
    let Some(base_url) = provider.get("base_url").and_then(Value::as_str) else {
        return false;
    };
    matches!(
        base_url,
        "https://api.openai.com"
            | "https://api.anthropic.com"
            | "https://generativelanguage.googleapis.com"
            | "https://api.github.com"
            | "https://www.googleapis.com"
    )
}

fn check_url_safety(url: &Url) -> Result<IpAddr, String> {
    if url.scheme() != "https" {
        return Err(format!("non-HTTPS URL blocked: {}://", url.scheme()));
    }
    let hostname = match url.host() {
        Some(Host::Domain(hostname)) => hostname.to_owned(),
        Some(Host::Ipv4(address)) => address.to_string(),
        Some(Host::Ipv6(address)) => address.to_string(),
        None => String::new(),
    };
    if hostname.is_empty() {
        return Err("empty hostname".into());
    }
    if matches!(
        hostname.to_ascii_lowercase().as_str(),
        "localhost" | "localhost." | "0.0.0.0"
    ) {
        return Err(format!("localhost blocked: {hostname}"));
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = (hostname.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| format!("DNS resolution failed: {hostname}"))?;
    let mut safe = None;
    for address in resolved {
        let ip = address.ip();
        if !is_global(ip) {
            return Err(format!("non-global IP blocked: {ip} ({hostname})"));
        }
        if safe.is_none() {
            safe = Some(ip);
        }
    }
    safe.ok_or_else(|| format!("DNS returned no global address: {hostname}"))
}

fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let n = u32::from(ip);
            let ranges = [
                (Ipv4Addr::new(0, 0, 0, 0), 8),
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(100, 64, 0, 0), 10),
                (Ipv4Addr::new(127, 0, 0, 0), 8),
                (Ipv4Addr::new(169, 254, 0, 0), 16),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
                (Ipv4Addr::new(192, 0, 0, 0), 24),
                (Ipv4Addr::new(192, 0, 2, 0), 24),
                (Ipv4Addr::new(192, 168, 0, 0), 16),
                (Ipv4Addr::new(198, 18, 0, 0), 15),
                (Ipv4Addr::new(198, 51, 100, 0), 24),
                (Ipv4Addr::new(203, 0, 113, 0), 24),
                (Ipv4Addr::new(224, 0, 0, 0), 4),
                (Ipv4Addr::new(240, 0, 0, 0), 4),
            ];
            !ranges.iter().any(|(network, prefix)| {
                let mask = u32::MAX << (32 - prefix);
                n & mask == u32::from(*network) & mask
            })
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && segments[0] & 0xfe00 != 0xfc00
                && segments[0] & 0xffc0 != 0xfe80
                && segments[0] & 0xff00 != 0xff00
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && ip
                    .to_ipv4_mapped()
                    .is_none_or(|mapped| is_global(IpAddr::V4(mapped)))
        }
    }
}

fn is_chunked(response: &ureq::Response) -> bool {
    response
        .header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
}

/// Read at most `limit` bytes and report truncation, like Python's `_read_limited_text`.
///
/// Python's `HTTPResponse.read(amt)` treats a connection that closes before a declared
/// `Content-Length` is reached as end of body (the partial body is the response), but a
/// chunked body cut short raises `IncompleteRead`; every other read failure (reset, TLS
/// error, timeout) raises too. Mirror that: an early EOF is final only for a framed body.
fn read_limited(
    reader: &mut impl Read,
    limit: usize,
    chunked: bool,
) -> std::io::Result<(String, bool)> {
    let mut data = Vec::new();
    match reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut data)
    {
        Ok(_) => {}
        Err(error) if !chunked && error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error),
    }
    let truncated = data.len() > limit;
    data.truncate(limit);
    Ok((String::from_utf8_lossy(&data).into_owned(), truncated))
}

/// Python's `make_api_call` lets a failed body read escape to its generic handlers:
/// `socket.timeout` → `timeout (Ns)`, anything else → `request failed: <ExceptionName>`.
fn read_failure(error: &std::io::Error, timeout: std::time::Duration) -> Value {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => {
            json!({"error":format!("timeout ({}s)", timeout.as_secs())})
        }
        ErrorKind::UnexpectedEof => json!({"error":"request failed: IncompleteRead"}),
        ErrorKind::ConnectionReset => json!({"error":"request failed: ConnectionResetError"}),
        ErrorKind::ConnectionAborted => json!({"error":"request failed: ConnectionAbortedError"}),
        _ => json!({"error":"request failed: OSError"}),
    }
}

fn decode_body(text: &str, needles: &crate::Needles) -> Value {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => hide_value(&value, needles),
        Err(_) => Value::String(hide(text, needles, None)),
    }
}

fn decode_error_body(text: &str, needles: &crate::Needles) -> Value {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => Value::String(
            serde_json::to_string(&hide_value(&value, needles))
                .unwrap_or_else(|_| ERROR_BODY_WITHHELD.to_owned()),
        ),
        Err(_) => Value::String(hide(text, needles, None)),
    }
}

fn truncated_text(text: &str, needles: &crate::Needles) -> Value {
    let keep = text.chars().count().saturating_sub(needles.max_chars());
    Value::String(format!(
        "{}[TRUNCATED]",
        hide_cut(text, needles, Some(keep))
    ))
}

fn append_warning(result: &mut Value, warning: &str) {
    let current = result.get("warning").and_then(Value::as_str).unwrap_or("");
    result["warning"] = Value::String(if current.is_empty() {
        warning.to_owned()
    } else {
        format!("{current}\n{warning}")
    });
}

fn python_json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(value) => python_json_string(value),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(python_json)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!("{}: {}", python_json_string(key), python_json(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn python_json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let value = c as u32;
                if value <= 0xffff {
                    output.push_str(&format!("\\u{value:04x}"));
                } else {
                    let adjusted = value - 0x10000;
                    let high = 0xd800 + (adjusted >> 10);
                    let low = 0xdc00 + (adjusted & 0x3ff);
                    output.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                }
            }
            c => output.push(c),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use super::check_url_safety;
    use serde_json::{Value, json};
    use url::Url;

    #[test]
    fn url_safety_matches_python_for_ip_literals_and_localhost() {
        let Some(python) = std::env::var_os("KV_PY_REF") else {
            eprintln!("SKIP URL safety parity: set KV_PY_REF");
            return;
        };
        let urls = [
            "https://127.0.0.1/",
            "https://10.1.2.3/",
            "https://192.0.2.1/",
            "https://0.0.0.0/",
            "https://[::1]/",
            "https://[fe80::1]/",
            "https://[2001:db8::1]/",
            "https://localhost/",
            "https://localhost./",
            "http://127.0.0.1/",
        ];
        let input = json!(urls);
        let script = r#"
import json, sys
from kv.providers import _check_url_safety
print(json.dumps([_check_url_safety(url) for url in json.load(sys.stdin)]))
"#;
        let mut child = Command::new(python)
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start Python reference");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "Python reference failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        for (index, url) in urls.iter().enumerate() {
            let parsed = Url::parse(url).unwrap();
            let actual = match check_url_safety(&parsed) {
                Ok(ip) => json!([true, "", ip.to_string()]),
                Err(reason) => json!([false, reason, null]),
            };
            assert_eq!(actual, expected[index], "URL safety case: {url}");
        }
    }
}
