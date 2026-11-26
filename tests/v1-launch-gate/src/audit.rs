//! Fail-closed verifier for kv's hash-chained JSONL audit records.
//!
//! This verifier intentionally treats malformed or non-canonical input as failure;
//! it never guesses at a valid interpretation of a corrupted chain.

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

fn python_number(number: &Number) -> Result<String, String> {
    let token = number.to_string();
    if matches!(token.as_str(), "Infinity" | "-Infinity" | "NaN") {
        return Ok(token);
    }
    if !token.contains(['.', 'e', 'E']) {
        return Ok(if token == "-0" { "0".to_owned() } else { token });
    }
    let float = token.parse::<f64>().map_err(|error| error.to_string())?;
    if float.is_infinite() {
        return Ok(if float.is_sign_negative() {
            "-Infinity".to_owned()
        } else {
            "Infinity".to_owned()
        });
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
        Value::Number(number) => output.extend_from_slice(python_number(number)?.as_bytes()),
        Value::String(string) => {
            serde_json::to_writer(&mut *output, string).map_err(|error| error.to_string())?
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

pub fn compact_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    write_json(value, &mut output)?;
    Ok(output)
}

fn chain_hash(previous: &str, payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(previous.as_bytes());
    digest.update(b":");
    digest.update(payload);
    digest.finalize()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Verify a complete canonical audit log. Returns the number of records.
///
/// Records must be canonical compact JSON with `hash` and `prev` as the final two
/// object fields. That is the shape emitted for real product events; events that
/// smuggle reserved `hash`/`prev` input fields are rejected rather than verified.
pub fn verify_chain(bytes: &[u8]) -> Result<usize, String> {
    if bytes.is_empty() {
        return Err("audit log is empty".to_owned());
    }
    if !bytes.ends_with(b"\n") {
        return Err("audit log is not newline terminated".to_owned());
    }
    let content = &bytes[..bytes.len() - 1];
    if content.is_empty() {
        return Err("audit log has no newline-terminated records".to_owned());
    }
    let mut previous = "genesis".to_owned();
    let mut count = 0usize;
    for (index, line) in content.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            return Err(format!("audit line {} is empty", index + 1));
        }
        let mut value: Value = serde_json::from_slice(line)
            .map_err(|error| format!("audit line {} is not valid JSON: {error}", index + 1))?;
        let (recorded_hash, recorded_prev) = {
            let object = value
                .as_object()
                .ok_or_else(|| format!("audit line {} is not a JSON object", index + 1))?;
            let keys: Vec<&str> = object.keys().map(String::as_str).collect();
            if keys.len() < 2 || keys[keys.len() - 2] != "hash" || keys[keys.len() - 1] != "prev" {
                return Err(format!(
                    "audit line {} does not end with hash and prev fields",
                    index + 1
                ));
            }
            let recorded_hash = object
                .get("hash")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("audit line {} has a non-string hash", index + 1))?
                .to_owned();
            let recorded_prev = object
                .get("prev")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("audit line {} has a non-string prev", index + 1))?
                .to_owned();
            (recorded_hash, recorded_prev)
        };
        if recorded_prev != previous {
            return Err(format!(
                "audit line {} breaks the prev chain (expected {previous}, got {recorded_prev})",
                index + 1
            ));
        }
        let canonical_line = compact_json(&value).map_err(|error| {
            format!("audit line {} cannot be canonicalized: {error}", index + 1)
        })?;
        if canonical_line != line {
            return Err(format!("audit line {} is not canonical JSON", index + 1));
        }
        let object = value
            .as_object_mut()
            .expect("audit object was validated as an object");
        object.shift_remove("hash");
        object.shift_remove("prev");
        let payload = compact_json(&value)
            .map_err(|error| format!("audit line {} payload is invalid: {error}", index + 1))?;
        let expected = chain_hash(&previous, &payload);
        if expected != recorded_hash {
            return Err(format!(
                "audit line {} has a bad hash (expected {expected}, got {recorded_hash})",
                index + 1
            ));
        }
        previous = recorded_hash;
        count += 1;
    }
    if count == 0 {
        return Err("audit log has no records".to_owned());
    }
    Ok(count)
}

pub fn verify_file(path: &Path) -> Result<usize, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("read audit log {}: {error}", path.display()))?;
    verify_chain(&bytes)
}

pub fn encode_test_entry(
    ts: &str,
    event: &str,
    fields: Map<String, Value>,
    previous: &str,
) -> Vec<u8> {
    let mut entry = Map::new();
    entry.insert("ts".to_owned(), Value::String(ts.to_owned()));
    entry.insert("event".to_owned(), Value::String(event.to_owned()));
    entry.extend(fields);
    let payload = compact_json(&Value::Object(entry.clone())).expect("payload canonicalizes");
    entry.insert(
        "hash".to_owned(),
        Value::String(chain_hash(previous, &payload)),
    );
    entry.insert("prev".to_owned(), Value::String(previous.to_owned()));
    let mut line = compact_json(&Value::Object(entry)).expect("entry canonicalizes");
    line.push(b'\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_CHAIN: &str = concat!(
        r#"{"ts":"2026-01-01T00:00:00Z","event":"test","x":1,"hash":"8f29ac37ce7d6819","prev":"genesis"}"#,
        "\n",
        r#"{"ts":"2026-01-01T00:00:01Z","event":"second","items":["a",true,null],"hash":"dfb06525057cff00","prev":"8f29ac37ce7d6819"}"#,
        "\n"
    );

    #[test]
    fn verifies_fixed_two_record_chain() {
        assert_eq!(verify_chain(FIXED_CHAIN.as_bytes()), Ok(2));
    }

    #[test]
    fn rejects_hash_tampering() {
        let tampered = FIXED_CHAIN.replace("\"x\":1", "\"x\":2");
        assert!(
            verify_chain(tampered.as_bytes())
                .unwrap_err()
                .contains("bad hash")
        );
    }

    #[test]
    fn rejects_prev_tampering() {
        let tampered = FIXED_CHAIN.replace("dfb06525057cff00", "0000000000000000");
        assert!(verify_chain(tampered.as_bytes()).is_err());
    }

    #[test]
    fn rejects_noncanonical_whitespace_and_missing_tail() {
        let spaced = FIXED_CHAIN.replacen("{\"ts\"", "{ \"ts\"", 1);
        assert!(
            verify_chain(spaced.as_bytes())
                .unwrap_err()
                .contains("not canonical")
        );
        assert!(verify_chain(FIXED_CHAIN.trim_end().as_bytes()).is_err());
    }

    #[test]
    fn test_encoder_produces_verifiable_chains() {
        let first = encode_test_entry("t1", "one", Map::new(), "genesis");
        let first_json: Value = serde_json::from_slice(&first).unwrap();
        let first_hash = first_json["hash"].as_str().unwrap().to_owned();
        let mut fields = Map::new();
        fields.insert("ok".to_owned(), Value::Bool(true));
        let mut bytes = first;
        bytes.extend(encode_test_entry("t2", "two", fields, &first_hash));
        assert_eq!(verify_chain(&bytes), Ok(2));
    }
}
