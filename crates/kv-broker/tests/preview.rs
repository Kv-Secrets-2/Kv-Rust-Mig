//! Prepared request facts must match the bytes and names approved by Python.

use std::ffi::OsStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kv_broker::{ApiCaller, ApiRequest, UrlSafety};
use serde_json::{Value, json};
use url::Url;

const SECRET: &str = "synthetic-preview-auth-6A9~*+/= token";
const PYTHON_BOUND: Duration = Duration::from_secs(15);

struct PreviewSafety;

impl UrlSafety for PreviewSafety {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("api.openai.com"));
        // Only origin spelling variants need this stub. No DNS or transport
        // belongs to this test; the address is from the documentation range.
        Ok(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
    }
}

fn case(label: &str, body: Option<Value>) -> Value {
    let mut value = json!({
        "label":label,
        "provider":{
            "provider_type":"http",
            "base_url":"https://api.openai.com",
            "secret_name":"PREVIEW_TOKEN",
            "auth_type":"bearer",
            "default_headers":{"Z-Provider":"last", "a-provider":"first"}
        },
        "path":"/v1/KeepCase?z=2&a=1",
        "method":"pOsT",
        "headers":{"Z-Caller":"last", "a-caller":"first"}
    });
    if let Some(body) = body {
        value["body"] = body;
    }
    value
}

fn cases() -> Vec<Value> {
    let mut cases = Vec::new();
    for auth in ["bearer", "basic", "x-api-key", "header", "query"] {
        let mut value = case(&format!("auth-{auth}"), Some(json!({"message":"hello"})));
        value["provider"]["auth_type"] = json!(auth);
        if auth == "header" {
            value["provider"]["auth_header_name"] = json!("X-Preview-Auth");
        }
        cases.push(value);
    }
    let mut default_auth_header = case("header-default-name", None);
    default_auth_header["provider"]["auth_type"] = json!("header");
    cases.push(default_auth_header);

    for path in ["/v1/write", "/v1/write?batch=1"] {
        let mut value = case(&format!("query-tilde-{path}"), Some(json!({})));
        value["provider"]["auth_type"] = json!("query");
        value["provider"]["auth_query_param"] = json!("k~ey");
        value["path"] = json!(path);
        cases.push(value);
    }

    for (label, body) in [
        ("body-absent", None),
        ("body-null", Some(Value::Null)),
        ("body-empty-string", Some(json!(""))),
        ("body-plain-string", Some(json!("literal text, not JSON"))),
        (
            "body-raw-unicode-and-controls",
            Some(json!("é😀\u{007f}\n\r\t\u{0008}\u{000c}\\\"")),
        ),
        ("body-empty-object", Some(json!({}))),
        ("body-empty-array", Some(json!([]))),
        (
            "body-object-insertion-order-and-unicode",
            Some(json!({"z":"é😀\u{007f}", "a":1, "nested":{"z":true,"a":null}})),
        ),
        (
            "body-array-and-nested-object",
            Some(json!([null,true,false,"é\u{007f}",{"z":1,"a":2}])),
        ),
        (
            "body-float-exponent-boundaries",
            Some(json!([
                1.0, -0.0, 1e-4, 1e-5, 1e-7, 1e15, 1e16, 1e20, 1.2345e20
            ])),
        ),
    ] {
        cases.push(case(label, body));
    }

    // Carry these source lexemes as strings in the inter-process envelope.
    // Both runtimes parse the same JSON text independently, so serializing a
    // Rust Number cannot round or rewrite Python's reference input first.
    for (label, body_json) in [
        (
            "body-integer-beyond-u64",
            r#"{"number":18446744073709551616}"#,
        ),
        (
            "body-integer-below-i64",
            r#"{"number":-18446744073709551617}"#,
        ),
        ("body-positive-overflow-exponent", r#"{"number":1e999}"#),
        ("body-negative-overflow-exponent", r#"{"number":-1e999}"#),
        (
            "body-decimal-rounds-to-one",
            r#"{"number":1.00000000000000001}"#,
        ),
        (
            "body-decimal-above-exact-f64-integer",
            r#"{"number":9007199254740993.0}"#,
        ),
    ] {
        let mut value = case(label, None);
        value["body_json"] = json!(body_json);
        cases.push(value);
    }

    for method in ["get", "HeAd", "options", "put", "patch", "delete"] {
        let mut value = case(&format!("method-{method}"), None);
        value["method"] = json!(method);
        cases.push(value);
    }
    for origin in [
        "https://API.OPENAI.COM",
        "https://api.openai.com:443",
        "https://api.openai.com/",
        "https://api.openai.com:8443/",
        "HTTPS://api.openai.com",
    ] {
        let mut value = case(&format!("origin-{origin}"), Some(json!("payload")));
        value["provider"]["base_url"] = json!(origin);
        cases.push(value);
    }
    let mut explicit_content_type = case("explicit-content-type", Some(json!({"count":1.5})));
    explicit_content_type["headers"]["CONTENT-TYPE"] = json!("application/json");
    cases.push(explicit_content_type);
    let mut no_defaults = case("no-default-or-caller-headers", Some(json!("")));
    no_defaults["provider"]
        .as_object_mut()
        .unwrap()
        .remove("default_headers");
    no_defaults["headers"] = json!({});
    cases.push(no_defaults);
    cases
}

struct TemporaryFiles(PathBuf);

impl TemporaryFiles {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kv-preview-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create exclusive preview fixture directory");
        Self(path)
    }
}

impl Drop for TemporaryFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn python_previews(python: &OsStr, cases: &[Value]) -> Vec<Value> {
    const CODE: &str = r#"
import json, socket, ssl, sys, urllib.request
from urllib.parse import urlsplit
from kv import providers

def forbidden(*args, **kwargs):
    raise AssertionError("preview attempted DNS, SSL context, or transport construction")

def safety(url):
    parsed = urlsplit(url)
    assert parsed.scheme == "https" and parsed.hostname == "api.openai.com"
    return True, "", "203.0.113.10"

providers._check_url_safety = safety
socket.getaddrinfo = forbidden
ssl.create_default_context = forbidden
urllib.request.build_opener = forbidden
payload = json.load(sys.stdin)
results = []
for case in payload["cases"]:
    kwargs = dict(provider_name="preview-fixture", secret_value=payload["secret"],
                  path=case["path"], method=case["method"],
                  extra_headers=case["headers"], provider_config=case["provider"],
                  before_send=forbidden, request_check=forbidden, preview_only=True)
    if "body_json" in case:
        kwargs["body"] = json.loads(case["body_json"])
    elif "body" in case:
        kwargs["body"] = case["body"]
    result = providers.make_api_call(**kwargs)
    assert "preview" in result, (case["label"], result)
    preview = result["preview"]
    if preview["body_bytes"] is not None:
        preview["body_bytes"] = list(preview["body_bytes"])
    results.append(preview)
json.dump(results, sys.stdout, ensure_ascii=True)
"#;
    let files = TemporaryFiles::new();
    let stdin = files.0.join("stdin.json");
    let stdout = files.0.join("stdout.json");
    let stderr = files.0.join("stderr.txt");
    fs::write(
        &stdin,
        serde_json::to_vec(&json!({"secret":SECRET,"cases":cases})).unwrap(),
    )
    .unwrap();
    let mut child = ChildGuard(
        Command::new(python)
            .args(["-I", "-B", "-c", CODE])
            .stdin(fs::File::open(stdin).unwrap())
            .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
            .spawn()
            .expect("start Python preview reference"),
    );
    let deadline = Instant::now() + PYTHON_BOUND;
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("check Python reference status") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "Python preview comparison exceeded {PYTHON_BOUND:?}: {}",
            fs::read_to_string(&stderr).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "Python preview comparison failed: {}",
        fs::read_to_string(stderr).unwrap_or_default()
    );
    serde_json::from_slice(&fs::read(stdout).unwrap()).expect("Python preview JSON")
}

#[test]
fn prepared_previews_match_python_reference() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let cases = cases();
    let expected = python_previews(&python, &cases);
    assert_eq!(expected.len(), cases.len());
    let caller = ApiCaller::with_url_safety_for_test(Arc::new(PreviewSafety));
    let redaction = json!({"PREVIEW_TOKEN":SECRET});
    for (case, expected) in cases.iter().zip(expected) {
        let label = case["label"].as_str().unwrap();
        let parsed_body: Option<Value> = case
            .get("body_json")
            .map(|text| serde_json::from_str(text.as_str().unwrap()).expect("raw JSON body"));
        let body = parsed_body.as_ref().or_else(|| case.get("body"));
        let preview = caller
            .preview(ApiRequest {
                provider_name: "preview-fixture",
                provider: &case["provider"],
                secret_value: SECRET,
                path: case["path"].as_str().unwrap(),
                method: case["method"].as_str().unwrap(),
                body,
                extra_headers: &case["headers"],
                secrets_for_redact: &redaction,
                timeout: Duration::from_secs(1),
                max_response_bytes: 1024,
            })
            .unwrap_or_else(|error| panic!("Rust preview failed for {label}: {error}"));
        let body_length = preview.body_length();
        let actual = json!({
            "method":preview.method,
            "url":preview.url,
            "header_names":preview.header_names,
            "body_bytes":preview.body_bytes,
            "body_length":body_length
        });
        for (runtime, value) in [("Rust", &actual), ("Python", &expected)] {
            assert!(
                !value.to_string().contains(SECRET),
                "{runtime} preview exposed its synthetic authentication secret for {label}"
            );
        }
        assert_eq!(actual, expected, "preview case: {label}");
    }
}
