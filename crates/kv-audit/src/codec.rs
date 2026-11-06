//! Python audit record spelling and caller-supplied text policy.
//!
//! Field order is part of the hash format. This follows `kv.audit.emit` and
//! `attribution_fields` at Python reference 9a497d91, not a sorted JSON format.

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

const WITHHELD: &str = "[not recorded: it looks like a key]";
const AGENT_UNKNOWN: &str = "unknown";
const AGENT_WITHHELD: &str = "[agent name not recorded: it looks like a key]";
const REASON_WITHHELD: &str = "[reason not recorded: it looks like a key]";
const MAX_ATTRIBUTION_LEN: usize = 80;
const MAX_AGENT_LEN: usize = 160;
const MAX_AGENT_REASON_LEN: usize = 200;
const KEY_PREFIXES: &[&str] = &[
    "sk-",
    "sk_",
    "rk_",
    "pk_live",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
    "akia",
    "asia",
    "aiza",
    "ya29.",
    "eyj",
    "hf_",
    "lin_api_",
    "r8_",
    "npm_",
    "dop_v1_",
    "pypi-",
    "sg.",
];

// CPython str.isspace/strip/split includes four separators that Rust's
// Unicode White_Space predicate excludes. These are the reference's complete
// whitespace set, unchanged across the supported Python versions.
fn python_whitespace(character: char) -> bool {
    matches!(character, '\u{0009}'..='\u{000d}' | '\u{001c}'..='\u{0020}'
        | '\u{0085}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// Bound caller-supplied identity text using Python's strip and label rules.
///
/// Missing, non-string and whitespace-only values return `None`. Each character
/// outside ASCII letters, digits and `._-:/@+` becomes `_`. The limit counts
/// characters, not UTF-8 bytes; a nonblank value with a zero limit returns `Some("")`.
pub fn label_text(value: Option<&Value>, max_len: usize) -> Option<String> {
    let value = value?.as_str()?.trim_matches(python_whitespace);
    if value.is_empty() {
        return None;
    }
    Some(
        value
            .chars()
            .take(max_len)
            .map(|character| {
                if character.is_ascii_alphanumeric() || "._-:/@+".contains(character) {
                    character
                } else {
                    '_'
                }
            })
            .collect(),
    )
}

fn identifier(value: &str, prefix: &str, digits: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == digits
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn key_prefix(token: &str, length: usize) -> bool {
    length >= 16 && {
        let lowered = token.to_lowercase();
        KEY_PREFIXES
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
    }
}

fn key_token(token: &str) -> bool {
    let length = token.chars().count();
    if key_prefix(token, length) {
        return true;
    }
    if length >= 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return true;
    }
    length >= 24
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_+/=.".contains(&byte))
        && token.bytes().any(|byte| byte.is_ascii_digit())
        && token.bytes().any(|byte| byte.is_ascii_uppercase())
        && token.bytes().any(|byte| byte.is_ascii_lowercase())
}

fn identity_looks_like_key(key: &str, raw: &str, shown: &str) -> bool {
    if key == "session_id" && identifier(shown, "mcp_", 24) {
        return false;
    }
    text_has_key_token(raw, key_token)
}

fn text_has_key_token(raw: &str, is_key: fn(&str) -> bool) -> bool {
    raw.contains("-----BEGIN")
        || raw.split(python_whitespace).any(|token| {
            is_key(token.trim_matches(|character| ".,;:()[]{}<>\"'`".contains(character)))
        })
        || raw
            .split(|character: char| {
                !character.is_ascii_alphanumeric() && !"_+=-".contains(character)
            })
            .any(is_key)
}

// Reasons use Python's broader shape rule, unlike reported identity labels.
fn reason_key_token(token: &str) -> bool {
    let length = token.chars().count();
    key_prefix(token, length)
        || (length >= 24
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_+/=.".contains(&byte))
            && token.bytes().any(|byte| byte.is_ascii_digit())
            && token.bytes().any(|byte| byte.is_ascii_alphabetic()))
}

fn reason_hidden(character: char) -> bool {
    // Python _escape_char escapes C* and Zl/Zp, but keeps space separators (Zs).
    // Reuse the frozen Unicode 13 printability inventory, removing only Zs:
    // interior tabs/newlines and line/paragraph separators must still escape.
    python_nonprintable(character)
        && !matches!(
            character,
            ' ' | '\u{00a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
        )
}

fn reason_piece_length(character: char) -> usize {
    if reason_hidden(character) {
        if u32::from(character) <= 0xffff {
            6
        } else {
            10
        }
    } else {
        1
    }
}

fn safe_reason(value: Option<&Value>) -> Option<String> {
    let raw = value?.as_str()?;
    let value = raw.trim_matches(python_whitespace);
    if value.is_empty() {
        return None;
    }
    // Detection sees the complete raw reason, including text beyond the display
    // bound. It has no access to vault secrets and cannot be a secret oracle.
    if text_has_key_token(raw, reason_key_token) {
        return Some(REASON_WITHHELD.to_owned());
    }
    let size: usize = value.chars().map(reason_piece_length).sum();
    let truncated = size > MAX_AGENT_REASON_LEN;
    let limit = MAX_AGENT_REASON_LEN - usize::from(truncated);
    let mut output = String::new();
    let mut shown = 0;
    for character in value.chars() {
        let length = reason_piece_length(character);
        if shown + length > limit {
            break;
        }
        if reason_hidden(character) {
            let code = u32::from(character);
            if code <= 0xffff {
                output.push_str(&format!("\\u{code:04x}"));
            } else {
                output.push_str(&format!("\\U{code:08x}"));
            }
        } else {
            output.push(character);
        }
        shown += length;
    }
    if truncated {
        output.push('…');
    }
    Some(output)
}

/// Return the Python-compatible `agent` and `agent_reason` attribution fields.
///
/// These are caller-reported claims, not authenticated identities. Credential
/// withholding uses only the supplied text's shape, never vault secret values.
/// Reason escaping follows canonical Python 3.10's Unicode 13 categories.
pub fn requester_fields(actor: Option<&Value>, reason: Option<&Value>) -> Map<String, Value> {
    let mut labels = Vec::new();
    let mut withheld = false;
    if let Some(actor) = actor.and_then(Value::as_object) {
        for (key, label) in [
            ("client_name", "client"),
            ("client_version", "version"),
            ("source", "source"),
            ("session_id", "session"),
        ] {
            let Some(shown) = label_text(actor.get(key), MAX_ATTRIBUTION_LEN) else {
                continue;
            };
            let raw = actor[key].as_str().expect("label_text accepted a string");
            withheld |= identity_looks_like_key(key, raw, &shown);
            labels.push(format!("{label}={shown}"));
        }
    }
    let agent = if withheld {
        AGENT_WITHHELD.to_owned()
    } else if labels.is_empty() {
        AGENT_UNKNOWN.to_owned()
    } else {
        labels.join(" ").chars().take(MAX_AGENT_LEN).collect()
    };
    let mut fields = Map::new();
    fields.insert("agent".to_owned(), Value::String(agent));
    fields.insert(
        "agent_reason".to_owned(),
        safe_reason(reason).map_or(Value::Null, Value::String),
    );
    fields
}

pub(crate) fn sanitize_fields(fields: &mut Map<String, Value>) {
    for key in ["client_name", "client_version", "source", "session_id"] {
        let Some(Value::String(value)) = fields.get(key) else {
            continue;
        };
        let shown = label_text(fields.get(key), MAX_ATTRIBUTION_LEN).unwrap_or_default();
        let replacement = if identity_looks_like_key(key, value, &shown) {
            WITHHELD.to_owned()
        } else {
            shown
        };
        fields.insert(key.to_owned(), Value::String(replacement));
    }
    for key in ["provider", "path", "program", "pattern", "permit_id", "url"] {
        let Some(value) = fields.get(key) else {
            continue;
        };
        if key == "permit_id"
            && value
                .as_str()
                .is_some_and(|value| identifier(value, "permit_", 32))
        {
            continue;
        }
        let looks_like_key = match value {
            Value::String(value) if matches!(key, "path" | "url") => value
                .split('/')
                .any(|part| identity_looks_like_key(key, part, part)),
            Value::String(value) => identity_looks_like_key(key, value, value),
            Value::Array(parts) => parts
                .iter()
                .filter_map(Value::as_str)
                .any(|part| identity_looks_like_key(key, part, part)),
            _ => false,
        };
        if looks_like_key {
            fields.insert(key.to_owned(), Value::String(WITHHELD.to_owned()));
        }
    }
}

/// Spell a serde number as Python's JSON encoder would after json.loads.
/// Arbitrary-precision integer tokens stay integers; float tokens are rounded
/// to IEEE binary64 first, including overflow to Python's accepted Infinity.
fn python_number(number: &Number, representation: bool) -> Result<String, String> {
    let token = number.to_string();
    if matches!(token.as_str(), "Infinity" | "-Infinity" | "NaN") {
        return Ok(if representation {
            match token.as_str() {
                "Infinity" => "inf",
                "-Infinity" => "-inf",
                _ => "nan",
            }
            .to_owned()
        } else {
            token
        });
    }
    if !token.contains(['.', 'e', 'E']) {
        return Ok(if token == "-0" { "0".to_owned() } else { token });
    }
    let float = token.parse::<f64>().map_err(|error| error.to_string())?;
    if float.is_infinite() {
        return Ok(match (representation, float.is_sign_negative()) {
            (true, true) => "-inf",
            (true, false) => "inf",
            (false, true) => "-Infinity",
            (false, false) => "Infinity",
        }
        .to_owned());
    }
    let raw = Number::from_f64(float)
        .ok_or_else(|| "audit number is not representable".to_owned())?
        .to_string();
    let (negative, unsigned) = raw
        .strip_prefix('-')
        .map_or((false, raw.as_str()), |value| (true, value));
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or(Ok((unsigned, 0)), |(mantissa, exponent)| {
            exponent.parse::<i32>().map(|exponent| (mantissa, exponent))
        })
        .map_err(|error| error.to_string())?;
    let decimal_position = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let mut digits: String = mantissa
        .chars()
        .filter(|character| *character != '.')
        .collect();
    let leading_zeroes = digits.bytes().take_while(|byte| *byte == b'0').count();
    digits.drain(..leading_zeroes);
    let decimal_position = decimal_position - leading_zeroes as i32;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    if digits.is_empty() {
        return Ok(if negative { "-0.0" } else { "0.0" }.to_owned());
    }
    let exponent = decimal_position - 1;
    let mut result = String::new();
    if negative {
        result.push('-');
    }
    if (-4..16).contains(&exponent) {
        if decimal_position <= 0 {
            result.push_str("0.");
            result.extend(std::iter::repeat_n('0', (-decimal_position) as usize));
            result.push_str(&digits);
        } else if decimal_position as usize >= digits.len() {
            result.push_str(&digits);
            result.extend(std::iter::repeat_n(
                '0',
                decimal_position as usize - digits.len(),
            ));
            result.push_str(".0");
        } else {
            let split = decimal_position as usize;
            result.push_str(&digits[..split]);
            result.push('.');
            result.push_str(&digits[split..]);
        }
    } else {
        result.push(digits.as_bytes()[0] as char);
        if digits.len() > 1 {
            result.push('.');
            result.push_str(&digits[1..]);
        }
        result.push('e');
        result.push(if exponent < 0 { '-' } else { '+' });
        let magnitude = exponent.unsigned_abs();
        if magnitude < 10 {
            result.push('0');
        }
        result.push_str(&magnitude.to_string());
    }
    Ok(result)
}

fn write_json(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(python_number(number, false)?.as_bytes()),
        Value::String(string) => {
            serde_json::to_writer(output, string).map_err(|error| error.to_string())?
        }
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(items) => {
            output.push(b'{');
            for (index, (key, item)) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|error| error.to_string())?;
                output.push(b':');
                write_json(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub(crate) fn compact_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    write_json(value, &mut output)?;
    Ok(output)
}

fn repr_string(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut result = String::new();
    result.push(quote);
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            character if character == quote => {
                result.push('\\');
                result.push(character);
            }
            character if python_nonprintable(character) => {
                let code = u32::from(character);
                if code <= 0xff {
                    result.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    result.push_str(&format!("\\u{code:04x}"));
                } else {
                    result.push_str(&format!("\\U{code:08x}"));
                }
            }
            character => result.push(character),
        }
    }
    result.push(quote);
    result
}

fn python_repr(value: &Value) -> Result<String, String> {
    Ok(match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => python_number(number, true)?,
        Value::String(value) => repr_string(value),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(python_repr)
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        ),
        Value::Object(items) => format!(
            "{{{}}}",
            items
                .iter()
                .map(|(key, value)| {
                    python_repr(value).map(|value| format!("{}: {value}", repr_string(key)))
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        ),
    })
}

pub(crate) fn python_str(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        _ => python_repr(value),
    }
}

pub(crate) fn encode_entry(
    timestamp: &str,
    event: &str,
    mut fields: Map<String, Value>,
    vault_label: Option<&str>,
    previous: Value,
) -> Result<Vec<u8>, String> {
    sanitize_fields(&mut fields);
    let mut entry = Map::new();
    entry.insert("ts".to_owned(), Value::String(timestamp.to_owned()));
    entry.insert("event".to_owned(), Value::String(event.to_owned()));
    entry.extend(fields);
    if let Some(label) = vault_label {
        entry
            .entry("vault")
            .or_insert_with(|| Value::String(label.to_owned()));
    }
    let mut digest = Sha256::new();
    digest.update(python_str(&previous)?.as_bytes());
    digest.update(b":");
    digest.update(compact_json(&Value::Object(entry.clone()))?);
    let hash: String = digest.finalize()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    entry.insert("hash".to_owned(), Value::String(hash));
    entry.insert("prev".to_owned(), previous);
    let mut output = compact_json(&Value::Object(entry))?;
    output.push(b'\n');
    Ok(output)
}

fn python_nonprintable(character: char) -> bool {
    let code = u32::from(character);
    PYTHON_NONPRINTABLE
        .binary_search_by(|&(first, last)| {
            if code < first {
                std::cmp::Ordering::Greater
            } else if code > last {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

include!("python_nonprintable.rs");

#[cfg(test)]
#[path = "codec/requester_tests.rs"]
mod requester_tests;

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../tests/support/harness.rs"]
mod test_harness;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::process::Command;
    use std::time::Duration;

    fn python(script: &str, input: &Value) -> Option<Value> {
        let python = kv_test_support::python_reference()?;
        let mut command = Command::new(python);
        command.args(["-I", "-c", script]);
        let result = test_harness::output(
            command,
            &serde_json::to_vec(input).unwrap(),
            Duration::from_secs(20),
        )
        .expect("bounded Python codec reference");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        Some(serde_json::from_slice(&result.stdout).expect("Python reference JSON"))
    }

    #[test]
    fn compact_unicode_and_float_spelling() {
        let value: Value = serde_json::from_str(
            r#"{"second":"värde ✓ 🙂\u001b","first":[1.0,-0.0,1e-4,1e-5,1e15,1e16,1e999,-1e999],"huge":123456789012345678901234567890}"#,
        ).unwrap();
        assert_eq!(
            String::from_utf8(compact_json(&value).unwrap()).unwrap(),
            "{\"second\":\"värde ✓ 🙂\\u001b\",\"first\":[1.0,-0.0,0.0001,1e-05,1000000000000000.0,1e+16,Infinity,-Infinity],\"huge\":123456789012345678901234567890}"
        );
    }

    #[test]
    fn withholding_preserves_normal_names_and_valid_identifiers() {
        let mut fields = json!({
            "source": "\u{001c} hello\nworld \u{001f}",
            "client_name": "github-actions-runner-2.321.0",
            "client_version": "AbCdEfGhIjKlMnOpQrStUv12",
            "session_id": "mcp_0123456789abcdef01234567",
            "provider": "sk-0123456789abcdef",
            "path": "/AnOrdinaryLongMixedCasePath/Build12345",
            "permit_id": "permit_0123456789abcdef0123456789abcdef",
            "pattern": ["ordinary", "-----BEGIN PRIVATE KEY-----"]
        })
        .as_object()
        .unwrap()
        .clone();
        sanitize_fields(&mut fields);
        assert_eq!(fields["source"], "hello_world");
        assert_eq!(fields["client_name"], "github-actions-runner-2.321.0");
        assert_eq!(fields["client_version"], WITHHELD);
        assert_eq!(fields["provider"], WITHHELD);
        assert_eq!(fields["pattern"], WITHHELD);
        assert_eq!(fields["session_id"], "mcp_0123456789abcdef01234567");
        assert_eq!(
            fields["permit_id"],
            "permit_0123456789abcdef0123456789abcdef"
        );
        assert_eq!(fields["path"], "/AnOrdinaryLongMixedCasePath/Build12345");
    }

    #[test]
    fn reserved_fields_keep_python_insertion_positions() {
        let fields: Value = serde_json::from_str(
            r#"{"ts":"override","prev":42,"hash":"old","vault":null,"event":"override event"}"#,
        )
        .unwrap();
        let line = encode_entry(
            "timestamp",
            "event",
            fields.as_object().unwrap().clone(),
            Some("label"),
            json!("genesis"),
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["ts", "event", "prev", "hash", "vault"]
        );
        assert_eq!(value["ts"], "override");
        assert_eq!(value["event"], "override event");
        assert_eq!(value["vault"], Value::Null);
        assert_eq!(value["prev"], "genesis");
        assert!(line.ends_with(b"\n"));
    }

    #[test]
    fn attribution_fields_match_python_reference() {
        let texts = [
            "",
            " \t\n",
            "\u{001c}trim separators\u{001f}",
            "client✓🙂\nname",
            "github-actions-runner-2.321.0",
            "AbCdEfGhIjKlMnOpQrStUv12",
            "ordinary words with Uppercase and a build 12345",
            "00000000000000000000000000000000",
            "(sk-0123456789abcdef)",
            "sK-0123456789abcdef",
            "-----BEGIN PRIVATE KEY-----",
            "mcp_0123456789abcdef01234567",
            "permit_0123456789abcdef0123456789abcdef",
            "/AnOrdinaryLongMixedCasePath/Build12345",
            "/public/sk-0123456789abcdef/end",
            "a\u{001c}AbCdEfGhIjKlMnOpQrStUv12\u{001f}b",
        ];
        let mut cases = Vec::new();
        for text in texts {
            let mut fields = Map::new();
            for field in [
                "source",
                "client_name",
                "client_version",
                "session_id",
                "provider",
                "path",
                "program",
                "permit_id",
                "url",
            ] {
                fields.insert(field.to_owned(), json!(text));
            }
            fields.insert(
                "pattern".to_owned(),
                json!(["ordinary", text, null, 7, [text]]),
            );
            fields.insert("untouched".to_owned(), json!(text));
            cases.push(Value::Object(fields));
        }
        cases.push(json!({"source":null,"client_name":12,"client_version":[],"session_id":{},"path":["ordinary",123],"pattern":{"key":"sk-0123456789abcdef"}}));
        cases.push(json!({"source":"x".repeat(90),"client_name":format!("{}sk-0123456789abcdef", "ordinary ".repeat(15))}));
        let Some(expected) = python(
            "import json,sys; from kv.audit import attribution_fields; print(json.dumps([attribution_fields(x) for x in json.load(sys.stdin)],ensure_ascii=False))",
            &json!(cases),
        ) else {
            return;
        };
        let actual: Vec<_> = cases
            .into_iter()
            .map(|mut value| {
                sanitize_fields(value.as_object_mut().unwrap());
                value
            })
            .collect();
        assert_eq!(Value::Array(actual), expected);
    }

    #[test]
    fn numeric_spelling_matches_python_reference() {
        let mut tokens: Vec<String> = [
            "-0",
            "0",
            "-0.0",
            "0.000",
            "1.0000000000000000000001",
            "1e-999",
            "-1e-999",
            "1e999",
            "-1e999",
            "1e-4",
            "1e-5",
            "1e15",
            "1e16",
            "2.2250738585072014e-308",
            "5e-324",
            "1.7976931348623157e308",
            "1234567890123456789012345678901234567890",
            "-1234567890123456789012345678901234567890",
            "Infinity",
            "-Infinity",
            "NaN",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let mut bits = 0x6a09_e667_f3bc_c909_u64;
        for _ in 0..4096 {
            bits = bits
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let value = f64::from_bits(bits);
            if let Some(number) = Number::from_f64(value) {
                tokens.push(number.to_string());
            }
        }
        let Some(expected) = python(
            "import json,sys; print(json.dumps([[json.dumps(json.loads(x),ensure_ascii=False,separators=(',',':')),str(json.loads(x))] for x in json.load(sys.stdin)]))",
            &json!(tokens),
        ) else {
            return;
        };
        for (token, expected) in tokens.iter().zip(expected.as_array().unwrap()) {
            let number = Number::from_string_unchecked(token.clone());
            let value = Value::Number(number);
            let actual = json!([
                String::from_utf8(compact_json(&value).unwrap()).unwrap(),
                python_str(&value).unwrap()
            ]);
            assert_eq!(&actual, expected, "numeric token {token}");
        }
    }

    #[test]
    fn complete_entry_bytes_and_nonstring_previous_hash_match_python() {
        let mut cases = Vec::new();
        let previous_values = vec![
            json!("genesis"),
            json!(null),
            json!(false),
            json!(42),
            json!(-0.0),
            json!([
                "a'b",
                "a\"b",
                "both'\"",
                "back\\slash",
                "\n\r\t\u{0008}\u{000b}\u{000c}\u{007f}\u{00a0}\u{0378}\u{200b}\u{2028}",
                "värde ✓ 🙂",
                null,
                true
            ]),
            json!({"quoted'key":[1.0,1e-7,false],"unicode":"é"}),
        ];
        for previous in previous_values {
            cases.push(json!({"previous":previous,"fields":{
                "provider":"sk-0123456789abcdef","path":"/public/é","client_name":"normal🙂name",
                "payload":{"z":[1.0,-0.0,1e-7,1e16],"a":"✓\n\u{001f}"}
            },"vault":"work"}));
        }
        cases.push(json!({"previous":"genesis","fields":{"ts":"override","event":"override","prev":17,"hash":"old","vault":null},"vault":"work"}));
        let Some(expected) = python(
            r#"
import json,sys
from kv.audit import attribution_fields,_compute_hash
out=[]
for case in json.load(sys.stdin):
    entry={'ts':'2026-11-06T01:02:03Z','event':'api_call',**attribution_fields(case['fields'])}
    if case['vault'] is not None and 'vault' not in entry: entry['vault']=case['vault']
    text=json.dumps(entry,ensure_ascii=False,separators=(',',':'))
    entry['hash']=_compute_hash(text,case['previous'])
    entry['prev']=case['previous']
    out.append(json.dumps(entry,ensure_ascii=False,separators=(',',':'))+'\n')
print(json.dumps(out,ensure_ascii=False))
"#,
            &json!(cases),
        ) else {
            return;
        };
        for (case, expected) in cases.iter().zip(expected.as_array().unwrap()) {
            let actual = encode_entry(
                "2026-11-06T01:02:03Z",
                "api_call",
                case["fields"].as_object().unwrap().clone(),
                case["vault"].as_str(),
                case["previous"].clone(),
            )
            .unwrap();
            assert_eq!(
                String::from_utf8(actual).unwrap(),
                expected.as_str().unwrap(),
                "case {case}"
            );
        }
    }

    #[test]
    fn canonical_python_repr_printability_inventory() {
        let Some(expected) = python(
            r#"
import json,sys,unicodedata
ranges=[]; start=None
for n in range(0x110000):
    if not chr(n).isprintable():
        if start is None: start=n
        end=n
    elif start is not None:
        ranges.append([start,end]); start=None
if start is not None: ranges.append([start,end])
print(json.dumps({'unicode':unicodedata.unidata_version,'ranges':ranges}))
"#,
            &Value::Null,
        ) else {
            return;
        };
        if expected["unicode"] != "13.0.0" {
            eprintln!(
                "repr printability table is canonical Unicode 13.0.0; newer Unicode inventories are not claimed equal"
            );
        } else {
            assert_eq!(json!(PYTHON_NONPRINTABLE), expected["ranges"]);
        }
        // Semantic lanes still compare stable classifications, while only
        // canonical CPython claims equality of the complete inventory.
        for character in [
            ' ', 'é', '✓', '🙂', '\0', '\u{00a0}', '\u{0378}', '\u{200b}',
        ] {
            let codepoint = u64::from(character as u32);
            let reference = expected["ranges"].as_array().unwrap().iter().any(|range| {
                range[0].as_u64().unwrap() <= codepoint && codepoint <= range[1].as_u64().unwrap()
            });
            assert_eq!(python_nonprintable(character), reference, "{character:?}");
        }
        for character in [' ', 'é', '✓', '🙂'] {
            assert!(!python_nonprintable(character));
        }
        for character in ['\0', '\u{00a0}', '\u{0378}', '\u{200b}'] {
            assert!(python_nonprintable(character));
        }
    }
}
