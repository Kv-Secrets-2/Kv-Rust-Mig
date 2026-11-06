use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use caseless::default_case_fold_str;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::canonical::canonical_json;
use crate::permit_session::{CallFacts, PERMIT_TTL_SECONDS, PermitError, SessionBinding};

const FACT_KEYS: &[&str] = &[
    "permit_id",
    "request_id",
    "signer",
    "local_approval_id",
    "location",
    "owner_key_id",
    "session_nonce",
    "environment",
    "provider",
    "provider_digest",
    "method",
    "url",
    "header_names",
    "caller_headers_sha256",
    "body_present",
    "body_sha256",
    "body_length",
    "expires_at_epoch",
    "grant_id",
    "run_id",
];
const MAX_BODY: usize = 512 * 1024;
const MAX_SHOWN: usize = 32768;

fn unsafe_display() -> PermitError {
    PermitError::refused("body or call cannot be shown in full safely")
}

pub(crate) fn build(
    binding: &SessionBinding,
    call: &CallFacts<'_>,
    request_id: &str,
    permit_id: &str,
    wall: f64,
) -> Result<(Value, String), PermitError> {
    if !matches!(call.method, "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(PermitError::refused(
            "a permit requires an unsafe HTTP method",
        ));
    }
    validate_url(call.url)?;
    if call.environment.is_empty()
        || call.provider.is_empty()
        || !call.provider_definition.is_object()
        || binding.providers.get(call.provider) != Some(call.provider_definition)
    {
        return Err(PermitError::refused(
            "provider or environment is not this session's snapshot",
        ));
    }
    let digest =
        crate::wire::provider_digest(call.provider_definition).map_err(|_| unsafe_display())?;
    if call.caller_headers.values().any(|value| !value.is_string()) {
        return Err(PermitError::refused("permit headers are invalid"));
    }
    let body = call.body_bytes.unwrap_or_default();
    if body.len() > MAX_BODY {
        return Err(PermitError::refused("body too large for the service limit"));
    }
    let body_text = std::str::from_utf8(body).map_err(|_| unsafe_display())?;
    let escaped = |value: &str| {
        crate::permit_render::escape_text(value, MAX_SHOWN)
            .map(|shown| shown.len())
            .map_err(|_| unsafe_display())
    };
    let mut shown = escaped(body_text)? + escaped(call.url)? + binding.location.len() + 2048;
    for name in call.header_names {
        shown += escaped(name)?;
    }
    for (name, value) in call.caller_headers {
        shown += escaped(name)? + escaped(value.as_str().expect("validated header"))?;
    }
    if shown > MAX_SHOWN {
        return Err(PermitError::refused(
            "body cannot be shown in full on the approval screen",
        ));
    }
    if !wall.is_finite() || wall < i64::MIN as f64 || wall >= i64::MAX as f64 {
        return Err(unsafe_display());
    }
    let expires = (wall.trunc() as i64)
        .checked_add(PERMIT_TTL_SECONDS)
        .ok_or_else(unsafe_display)?;
    let mut header_names: Vec<String> = call
        .header_names
        .iter()
        .map(|name| default_case_fold_str(name))
        .collect();
    header_names.sort();
    let mut header_pairs: Vec<(String, &str)> = call
        .caller_headers
        .iter()
        .map(|(name, value)| {
            (
                default_case_fold_str(name),
                value.as_str().expect("validated header"),
            )
        })
        .collect();
    header_pairs.sort();
    let header_values = Value::Array(
        header_pairs
            .into_iter()
            .map(|(name, value)| json!([name, value]))
            .collect(),
    );
    let header_digest = canonical_json(&header_values).map_err(|_| unsafe_display())?;
    let facts = json!({
        "permit_id": permit_id, "request_id": request_id,
        "signer": crate::permit::SIGNER,
        "local_approval_id": hex::encode(&binding.local_approval_id),
        "location": hex::encode(&binding.location), "owner_key_id": binding.owner_key_id,
        "session_nonce": hex::encode(binding.session_nonce),
        "environment": call.environment, "provider": call.provider,
        "provider_digest": digest, "method": call.method, "url": call.url,
        "header_names": header_names,
        "caller_headers_sha256": hex::encode(Sha256::digest(header_digest.as_bytes())),
        "body_present": call.body_bytes.is_some(), "body_sha256": hex::encode(Sha256::digest(body)),
        "body_length": body.len(), "expires_at_epoch": expires,
        "grant_id": null, "run_id": null,
    });
    let encoded_facts = canonical_json(&facts).map_err(|_| unsafe_display())?;
    let encoded_headers = canonical_json(&Value::Object(call.caller_headers.clone()))
        .map_err(|_| unsafe_display())?;
    if encoded_facts.len().max(encoded_headers.len()) > crate::wire::MAX_FIELD_BYTES {
        return Err(PermitError::refused(
            "the call cannot be shown in full through the owner channel",
        ));
    }
    crate::permit_render::validate_review(&facts, body_text, call.caller_headers)
        .map_err(|_| unsafe_display())?;
    Ok((facts, body_text.to_owned()))
}

pub(crate) fn verify_artifact(
    binding: &SessionBinding,
    artifact: &Value,
) -> Result<Value, PermitError> {
    let not_signed = || {
        PermitError::new(
            "not_signed",
            "not signed by this vault for this service session",
        )
    };
    let public = binding.owner_public_key.as_ref().ok_or_else(not_signed)?;
    let facts = crate::permit::verified_permit_payload(binding.protected, public, artifact)
        .ok_or_else(not_signed)?;
    let object = facts.as_object().ok_or_else(not_signed)?;
    if object.len() != FACT_KEYS.len()
        || FACT_KEYS.iter().any(|key| !object.contains_key(*key))
        || facts["local_approval_id"] != hex::encode(&binding.local_approval_id)
        || facts["location"] != hex::encode(&binding.location)
        || facts["owner_key_id"] != binding.owner_key_id
        || facts["session_nonce"] != hex::encode(binding.session_nonce)
    {
        return Err(not_signed());
    }
    let provider = facts["provider"]
        .as_str()
        .and_then(|name| binding.providers.get(name))
        .ok_or_else(|| PermitError::new("provider_changed", "permit provider changed"))?;
    let digest = crate::wire::provider_digest(provider)
        .map_err(|_| PermitError::new("provider_changed", "permit provider is invalid"))?;
    if facts["provider_digest"] != digest {
        return Err(PermitError::new(
            "provider_changed",
            "permit provider changed",
        ));
    }
    Ok(facts)
}

/// The validation follows urlsplit/hostname without serializing the URL back
/// through a normalizing parser. The broker separately resolves and pins DNS.
fn validate_url(original: &str) -> Result<(), PermitError> {
    let text: String = original
        .trim_start_matches(|character| character <= '\u{20}')
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n' | '\t'))
        .collect();
    let target = || PermitError::refused("permit URL is not a safe HTTPS target");
    let (scheme, rest) = text
        .split_once(':')
        .filter(|(scheme, _)| {
            !scheme.is_empty()
                && scheme
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
        })
        .unwrap_or(("", &text));
    let authority = rest
        .strip_prefix("//")
        .map(|rest| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    // urlsplit validates brackets and NFKC before the caller checks scheme,
    // userinfo or fragments. Keep that error precedence even for refused URLs.
    if authority.contains('[') != authority.contains(']') {
        return Err(unsafe_display());
    }
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    if authority.contains('[') {
        let host = if let Some((before, bracketed)) = host_port.split_once('[') {
            let (host, suffix) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !before.is_empty() || (!suffix.is_empty() && !suffix.starts_with(':')) {
                return Err(unsafe_display());
            }
            host
        } else {
            host_port.split(':').next().unwrap_or_default()
        };
        if let Some(future) = host.strip_prefix('v') {
            let valid = future.split_once('.').is_some_and(|(version, rest)| {
                !version.is_empty()
                    && version.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && !rest.is_empty()
            });
            if !valid {
                return Err(unsafe_display());
            }
        } else if parse_scoped_ipv6(host).is_none() {
            return Err(unsafe_display());
        }
    }
    let normalized: String = authority
        .chars()
        .filter(|character| !matches!(character, '@' | ':' | '#' | '?'))
        .nfkc()
        .collect();
    if !authority.is_ascii()
        && normalized
            .chars()
            .any(|character| "/?#@:".contains(character))
    {
        return Err(unsafe_display());
    }
    let host = if let Some((_, bracketed)) = host_port.split_once('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    if !scheme.eq_ignore_ascii_case("https")
        || authority.contains('@')
        || text
            .split_once('#')
            .is_some_and(|(_, fragment)| !fragment.is_empty())
    {
        return Err(target());
    }
    let lowered = host.to_lowercase();
    if host.is_empty()
        || matches!(lowered.as_str(), "localhost" | "localhost.")
        || lowered.ends_with(".localhost")
    {
        return Err(target());
    }
    let address = host
        .parse::<IpAddr>()
        .ok()
        .or_else(|| parse_scoped_ipv6(host).map(IpAddr::V6));
    if address.is_some_and(|address| !python_global(address)) {
        return Err(PermitError::refused("permit URL is not a public target"));
    }
    Ok(())
}

fn parse_scoped_ipv6(host: &str) -> Option<Ipv6Addr> {
    let address = if let Some((address, scope)) = host.split_once('%') {
        if scope.is_empty() || scope.contains('%') {
            return None;
        }
        address
    } else {
        host
    };
    address.parse().ok()
}

// CPython 3.10.22 ipaddress.is_global tables (including its maintained IANA
// classification updates). This is an admission check, not DNS resolution.
fn python_global(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            if matches!(address.octets(), [192, 0, 0, 9 | 10]) {
                return true;
            }
            let ranges = [
                ([0, 0, 0, 0], 8),
                ([10, 0, 0, 0], 8),
                ([100, 64, 0, 0], 10),
                ([127, 0, 0, 0], 8),
                ([169, 254, 0, 0], 16),
                ([172, 16, 0, 0], 12),
                ([192, 0, 0, 0], 24),
                ([192, 0, 2, 0], 24),
                ([192, 168, 0, 0], 16),
                ([198, 18, 0, 0], 15),
                ([198, 51, 100, 0], 24),
                ([203, 0, 113, 0], 24),
                ([240, 0, 0, 0], 4),
            ];
            !ranges.into_iter().any(|(network, prefix)| {
                let mask = u32::MAX << (32 - prefix);
                u32::from(address) & mask == u32::from(Ipv4Addr::from(network)) & mask
            })
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return python_global(IpAddr::V4(mapped));
            }
            let in_range = |text: &str, prefix: u32| {
                let network: Ipv6Addr = text.parse().expect("fixed IPv6 network");
                let mask = u128::MAX << (128 - prefix);
                u128::from(address) & mask == u128::from(network) & mask
            };
            if [
                ("2001:1::1", 128),
                ("2001:1::2", 128),
                ("2001:3::", 32),
                ("2001:4:112::", 48),
                ("2001:20::", 28),
                ("2001:30::", 28),
            ]
            .into_iter()
            .any(|(network, prefix)| in_range(network, prefix))
            {
                return true;
            }
            ![
                ("::", 128),
                ("::1", 128),
                ("::ffff:0:0", 96),
                ("64:ff9b:1::", 48),
                ("100::", 64),
                ("2001::", 23),
                ("2001:db8::", 32),
                ("2002::", 16),
                ("3fff::", 20),
                ("fc00::", 7),
                ("fe80::", 10),
            ]
            .into_iter()
            .any(|(network, prefix)| in_range(network, prefix))
        }
    }
}

#[cfg(all(test, unix))]
use crate::test_harness as harness;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;

    fn binding(provider: &Value) -> SessionBinding {
        SessionBinding {
            protected: true,
            owner_public_key: Some([0; 32]),
            owner_key_id: "owner-key".into(),
            local_approval_id: vec![1; 16],
            location: b"/fixture/vault".to_vec(),
            session_nonce: [2; 32],
            providers: Arc::new(BTreeMap::from([("example".into(), provider.clone())])),
        }
    }

    #[test]
    fn permit_facts_and_refusals_match_python() {
        let Some(python) = kv_test_support::python_reference() else {
            return;
        };
        let provider = json!({"base_url":"https://permit-fixture.example","secret_name":"TOKEN","auth_type":"bearer"});
        let base = json!({"environment":"dev","provider":"example","definition":provider,
            "method":"POST","url":"https://permit-fixture.example/api?key=<added-by-kv-not-shown>",
            "header_names":["Authorization","X-Caller"],"headers":{"X-Caller":"välue"},
            "body_hex":hex::encode(b"{\"amount\":1}"),"now":1000.25});
        let mut cases = vec![base.clone()];
        for (key, value) in [
            ("body_hex", Value::Null),
            ("body_hex", json!("")),
            ("body_hex", json!("ff")),
            ("environment", json!("")),
            ("provider", json!("")),
            ("method", json!("GET")),
            ("headers", json!({"X-Caller":1})),
            ("definition", json!({"base_url":"other"})),
            (
                "header_names",
                json!(["Straße", "İ", "X-Caller", "x-caller"]),
            ),
            ("headers", json!({"X-Caller":"a","x-caller":"b"})),
            ("body_hex", json!(hex::encode("é🙂\n"))),
            ("body_hex", json!(hex::encode("a".repeat(31000)))),
            ("body_hex", json!(hex::encode("a".repeat(32769)))),
            ("body_hex", json!(hex::encode("a".repeat(524289)))),
        ] {
            let mut case = base.clone();
            case[key] = value;
            cases.push(case);
        }
        for url in [
            "http://example.com/",
            "https://localhost/",
            "https://x.localhost/",
            "https://localhost./",
            "https://example.com/#fragment",
            "https://example.com/#",
            "https://@example.com/",
            "https://user:pw@example.com/",
            "https://127.0.0.1/",
            "https://100.64.1.1/",
            "https://192.0.0.9/",
            "https://192.0.0.10/",
            "https://192.0.0.11/",
            "https://8.8.8.8/",
            "https://224.0.0.1/",
            "https://[::1]/",
            "https://[2001:db8::1]/",
            "https://[2001:4860:4860::8888]/",
            "https://[2001:3::1]/",
            "https://[64:ff9b:1::1]/",
            "https://[::ffff:8.8.8.8]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[3fff::1]/",
            "https://example.com:invalid/",
            "https://[bad]/",
            "https://user@[bad]/",
            "http://[bad]/",
            "https://[2001:4860::1]suffix/",
            "https://prefix[2001:4860::1]/",
            "https://[2001:4860::1]:ignored:port/",
            "https://[vF.example]/",
            "https://[VF.example]/",
            "https://example.com／evil/",
            "\u{0001}HTTPS://EXAMPLE.com/a\tb",
            "https://[fe80::1%eth0]/",
        ] {
            let mut case = base.clone();
            case["url"] = json!(url);
            cases.push(case);
        }
        let script = r#"
import json,sys,types
from kv import approval_verify as v
data=json.load(sys.stdin)
ctx=types.SimpleNamespace(local_approval_id=bytes([1])*16,location=b'/fixture/vault',owner_key_id='owner-key',session_nonce=bytes([2])*32,provider_snapshot={'example':data['provider']})
out=[]
for case in data['cases']:
    ids=iter(['11'*16,'22'*16]); v.secrets.token_hex=lambda n:next(ids)
    try:
        facts,body=v._permit_facts(ctx,environment=case['environment'],provider=case['provider'],provider_definition=case['definition'],method=case['method'],url=case['url'],header_names=case['header_names'],caller_headers=case['headers'],body_bytes=None if case['body_hex'] is None else bytes.fromhex(case['body_hex']),grant_id=None,run_id=None,now=case['now'])
        out.append({'facts':facts,'body':body})
    except v.AdmissionRefused as e: out.append({'error':str(e),'code':e.code})
print(json.dumps({'python':list(sys.version_info[:2]),'cases':out}))
"#;
        let mut command = Command::new(python);
        command.args(["-I", "-c", script]);
        let input = serde_json::to_vec(&json!({"provider":provider,"cases":cases})).unwrap();
        let output = harness::output(command, &input, Duration::from_secs(30)).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference: Value = serde_json::from_slice(&output.stdout).unwrap();
        let expected = reference["cases"].as_array().unwrap();
        assert_eq!(expected.len(), cases.len());
        let lowercase_future = cases
            .iter()
            .position(|case| case["url"] == "https://[vF.example]/")
            .unwrap();
        let binding = binding(&provider);
        for (index, (case, expected)) in cases.iter().zip(expected).enumerate() {
            let names: Vec<String> = case["header_names"]
                .as_array()
                .unwrap()
                .iter()
                .map(|name| name.as_str().unwrap().into())
                .collect();
            let body = case["body_hex"]
                .as_str()
                .map(|text| hex::decode(text).unwrap());
            let call = CallFacts {
                environment: case["environment"].as_str().unwrap(),
                provider: case["provider"].as_str().unwrap(),
                provider_definition: &case["definition"],
                method: case["method"].as_str().unwrap(),
                url: case["url"].as_str().unwrap(),
                header_names: &names,
                caller_headers: case["headers"].as_object().unwrap(),
                body_bytes: body.as_deref(),
            };
            let actual = match build(
                &binding,
                &call,
                &format!("permit_request_{}", "22".repeat(16)),
                &format!("permit_{}", "11".repeat(16)),
                case["now"].as_f64().unwrap(),
            ) {
                Ok((facts, body)) => json!({"facts":facts,"body":body}),
                Err(error) => json!({"error":error.message,"code":error.code}),
            };
            if reference["python"] == json!([3, 13]) && case["url"] == "https://[VF.example]/" {
                // Python 3.13 newly accepts uppercase V in an IPvFuture host.
                // Keep canonical 3.10 refusal and assert the complete 3.13 result
                // explicitly. The production broker rejects both IPvFuture
                // spellings as non-IPv6 bracketed hosts before permit preview.
                assert_eq!(
                    actual,
                    json!({
                        "error":"body or call cannot be shown in full safely",
                        "code":"refused"
                    })
                );
                let mut accepted = reference["cases"][lowercase_future].clone();
                assert!(accepted["facts"].is_object());
                accepted["facts"]["url"] = case["url"].clone();
                assert_eq!(expected, &accepted, "Python 3.13 uppercase IPvFuture facts");
            } else {
                assert_eq!(
                    &actual, expected,
                    "permit facts case {index}, URL {}",
                    case["url"]
                );
            }
        }
    }
}
