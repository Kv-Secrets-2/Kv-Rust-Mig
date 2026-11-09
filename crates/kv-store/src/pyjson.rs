use serde_json::{Number, Value};

use crate::StoreError;

pub fn to_vec(value: &Value) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::new();
    write_value(value, &mut output)?;
    Ok(output)
}

pub fn to_vec_python(value: &Value, sort_keys: bool) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::new();
    write_python(value, &mut output, sort_keys, false)?;
    Ok(output)
}

pub fn to_vec_python_compact(value: &Value, sort_keys: bool) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::new();
    write_python(value, &mut output, sort_keys, true)?;
    Ok(output)
}

fn write_python(
    value: &Value,
    output: &mut Vec<u8>,
    sort_keys: bool,
    compact: bool,
) -> Result<(), StoreError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(python_number(number).as_bytes()),
        Value::String(string) => write_ascii_string(string, output),
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.extend_from_slice(if compact { b"," } else { b", " });
                }
                write_python(item, output, sort_keys, compact)?;
            }
            output.push(b']');
        }
        Value::Object(items) => {
            output.push(b'{');
            let mut entries = items.iter().collect::<Vec<_>>();
            if sort_keys {
                entries.sort_by(|left, right| left.0.cmp(right.0));
            }
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.extend_from_slice(if compact { b"," } else { b", " });
                }
                write_ascii_string(key, output);
                output.extend_from_slice(if compact { b":" } else { b": " });
                write_python(item, output, sort_keys, compact)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn python_number(number: &Number) -> String {
    let raw = number.to_string();
    if !raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        return if raw == "-0" { "0".into() } else { raw };
    }
    // With arbitrary_precision, serde retains a JSON decimal's original text.
    // Python loads that decimal as binary64 before dumping it. Normalize once
    // so lexical precision and overflow cannot change approved body bytes.
    let parsed = raw
        .parse::<f64>()
        .expect("valid JSON floating-point number");
    if parsed.is_infinite() {
        return if parsed.is_sign_negative() {
            "-Infinity"
        } else {
            "Infinity"
        }
        .into();
    }
    let raw = Number::from_f64(parsed)
        .expect("finite JSON number")
        .to_string();
    let (negative, unsigned) = raw
        .strip_prefix('-')
        .map_or((false, raw.as_str()), |value| (true, value));
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, 0), |(mantissa, exponent)| {
            (mantissa, exponent.parse::<i32>().unwrap_or(0))
        });
    let decimal_position = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let mut digits = mantissa
        .bytes()
        .filter(|byte| *byte != b'.')
        .map(char::from)
        .collect::<String>();
    let leading_zeroes = digits.bytes().take_while(|byte| *byte == b'0').count();
    digits.drain(..leading_zeroes);
    let decimal_position = decimal_position - leading_zeroes as i32;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    if digits.is_empty() {
        return if negative { "-0.0" } else { "0.0" }.into();
    }

    let exponent = decimal_position - 1;
    let mut result = String::new();
    if negative {
        result.push('-');
    }
    if (-4..16).contains(&exponent) {
        if decimal_position <= 0 {
            result.push_str("0.");
            result.extend(std::iter::repeat_n(
                '0',
                usize::try_from(-decimal_position).unwrap_or_default(),
            ));
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
    result
}

pub fn to_vec_indent2_ascii(value: &Value) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::new();
    write_indented(value, &mut output, 0)?;
    output.push(b'\n');
    Ok(output)
}

fn write_indented(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<(), StoreError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else if let Some(integer) = number.as_u64() {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else {
                return Err(StoreError::ConfigFloat);
            }
        }
        Value::String(string) => write_ascii_string(string, output),
        Value::Array(items) if items.is_empty() => output.extend_from_slice(b"[]"),
        Value::Array(items) => {
            output.extend_from_slice(b"[\n");
            for (index, item) in items.iter().enumerate() {
                write_indent(output, depth + 1);
                write_indented(item, output, depth + 1)?;
                if index + 1 != items.len() {
                    output.push(b',');
                }
                output.push(b'\n');
            }
            write_indent(output, depth);
            output.push(b']');
        }
        Value::Object(items) if items.is_empty() => output.extend_from_slice(b"{}"),
        Value::Object(items) => {
            output.extend_from_slice(b"{\n");
            for (index, (key, item)) in items.iter().enumerate() {
                write_indent(output, depth + 1);
                write_ascii_string(key, output);
                output.extend_from_slice(b": ");
                write_indented(item, output, depth + 1)?;
                if index + 1 != items.len() {
                    output.push(b',');
                }
                output.push(b'\n');
            }
            write_indent(output, depth);
            output.push(b'}');
        }
    }
    Ok(())
}

fn write_indent(output: &mut Vec<u8>, depth: usize) {
    output.extend(std::iter::repeat_n(b' ', depth * 2));
}

fn write_ascii_string(string: &str, output: &mut Vec<u8>) {
    fn write_escape(code: u16, output: &mut Vec<u8>) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.extend_from_slice(b"\\u");
        output.push(HEX[usize::from((code >> 12) & 0xf)]);
        output.push(HEX[usize::from((code >> 8) & 0xf)]);
        output.push(HEX[usize::from((code >> 4) & 0xf)]);
        output.push(HEX[usize::from(code & 0xf)]);
    }

    output.push(b'"');
    for character in string.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{0008}' => output.extend_from_slice(b"\\b"),
            '\u{000c}' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            character if character <= '\u{001f}' => write_escape(character as u16, output),
            character if character <= '\u{007e}' => output.push(character as u8),
            character if character <= '\u{ffff}' => write_escape(character as u16, output),
            character => {
                let code = character as u32 - 0x1_0000;
                write_escape((0xd800 + (code >> 10)) as u16, output);
                write_escape((0xdc00 + (code & 0x3ff)) as u16, output);
            }
        }
    }
    output.push(b'"');
}

fn write_value(value: &Value, output: &mut Vec<u8>) -> Result<(), StoreError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else if let Some(integer) = number.as_u64() {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else {
                return Err(StoreError::Corrupt(
                    "drawer JSON does not support floating-point values".into(),
                ));
            }
        }
        Value::String(string) => write_string(string, output),
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.extend_from_slice(b", ");
                }
                write_value(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(items) => {
            output.push(b'{');
            let mut sorted = items.iter().collect::<Vec<_>>();
            sorted.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index != 0 {
                    output.extend_from_slice(b", ");
                }
                write_string(key, output);
                output.extend_from_slice(b": ");
                write_value(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn write_string(string: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in string.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{0008}' => output.extend_from_slice(b"\\b"),
            '\u{000c}' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            character if character <= '\u{001f}' => {
                let code = character as u8;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                output.extend_from_slice(b"\\u00");
                output.push(HEX[usize::from(code >> 4)]);
                output.push(HEX[usize::from(code & 0x0f)]);
            }
            character => {
                let mut encoded = [0u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    output.push(b'"');
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{to_vec, to_vec_indent2_ascii, to_vec_python, to_vec_python_compact};

    #[test]
    fn ascii_output_escapes_del_and_normalizes_parsed_decimals() {
        assert_eq!(
            to_vec_python(&json!("\u{007f}"), false).unwrap(),
            b"\"\\u007f\""
        );
        assert_eq!(
            to_vec_python_compact(&json!("\u{007f}"), false).unwrap(),
            b"\"\\u007f\""
        );
        assert_eq!(
            to_vec_indent2_ascii(&json!("\u{007f}")).unwrap(),
            b"\"\\u007f\"\n"
        );
        let value: Value =
            serde_json::from_str("[-0,1.00000000000000001,1e999,-1e999,1e-999]").unwrap();
        assert_eq!(
            to_vec_python(&value, false).unwrap(),
            b"[0, 1.0, Infinity, -Infinity, 0.0]"
        );
    }

    #[test]
    fn python_json_body_serialization_matches_reference() {
        let Some(python) = kv_test_support::python_reference() else {
            return;
        };
        let characters: String = (0..=255)
            .filter_map(char::from_u32)
            .chain(['\u{2028}', '\u{2029}', '中', '🙂'])
            .collect();
        let raw = vec![
            serde_json::to_string(&characters).unwrap(),
            r#"{"z": "\u007f", "é": [1e-6, 1e16, -0.0, 5e-324], "a": {"b": true}}"#.into(),
            "[-0,1.00000000000000001,1e999,-1e999,1e-999,184467440737095516161234567890]".into(),
            "[1e-4,1e-5,1e15,1e16,1.7976931348623157e308,2.2250738585072014e-308]".into(),
        ];
        let script = r#"import json,sys
out=[]
for raw in json.loads(sys.argv[1]):
 value=json.loads(raw)
 for sort in (False, True):
  out.append(json.dumps(value,sort_keys=sort))
  out.append(json.dumps(value,sort_keys=sort,separators=(',',':')))
print(json.dumps(out,ensure_ascii=True))"#;
        let output = std::process::Command::new(python)
            .args(["-I", "-c", script, &serde_json::to_string(&raw).unwrap()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        let mut actual = Vec::new();
        for raw in raw {
            let value: Value = serde_json::from_str(&raw).unwrap();
            for sort in [false, true] {
                actual.push(String::from_utf8(to_vec_python(&value, sort).unwrap()).unwrap());
                actual
                    .push(String::from_utf8(to_vec_python_compact(&value, sort).unwrap()).unwrap());
            }
        }
        assert_eq!(actual, reference);
    }

    #[test]
    fn matches_python_string_escaping_and_raw_unicode() {
        let value = json!(
            "quote: \" slash: / backslash: \\ controls: \u{0000}\u{0001}\u{0008}\u{000c}\n\r\t\u{001f}\u{007f}\u{2028}\u{2029} 🙂"
        );
        assert_eq!(
            to_vec(&value).unwrap(),
            r#""quote: \" slash: / backslash: \\ controls: \u0000\u0001\b\f\n\r\t\u001f   🙂""#
                .as_bytes()
        );
    }

    #[test]
    fn matches_python_nested_objects_arrays_and_codepoint_key_order() {
        let value = json!({
            "é": [],
            "中": {},
            "z": [null, true, false, -1, 2],
            "a": {"": []},
            "ä": "värde",
        });
        assert_eq!(
            to_vec(&value).unwrap(),
            "{\"a\": {\"\": []}, \"z\": [null, true, false, -1, 2], \"ä\": \"värde\", \"é\": [], \"中\": {}}".as_bytes()
        );
        assert_eq!(to_vec(&json!({})).unwrap(), b"{}");
        assert_eq!(to_vec(&json!([])).unwrap(), b"[]");
    }

    #[test]
    fn rejects_floats() {
        assert!(to_vec(&json!(1.25)).is_err());
    }

    #[test]
    fn config_writer_matches_python_indentation_order_and_ascii_escaping() {
        let value: Value =
            serde_json::from_str(r#"{"second":"värde ✓ 🙂","first":{"empty":[],"object":{}}}"#)
                .unwrap();
        assert_eq!(
            to_vec_indent2_ascii(&value).unwrap(),
            b"{\n  \"second\": \"v\\u00e4rde \\u2713 \\ud83d\\ude42\",\n  \"first\": {\n    \"empty\": [],\n    \"object\": {}\n  }\n}\n"
        );
        assert!(to_vec_indent2_ascii(&json!({"number":1.25})).is_err());
    }

    #[test]
    fn python_float_repr_matches_json_dumps_exponent_boundaries() {
        let value = serde_json::json!([1.0, -0.0, 1e-4, 1e-5, 1e-7, 1e15, 1e16, 1.2345e20]);
        assert_eq!(
            to_vec_python(&value, false).unwrap(),
            b"[1.0, -0.0, 0.0001, 1e-05, 1e-07, 1000000000000000.0, 1e+16, 1.2345e+20]"
        );
        assert_eq!(
            to_vec_python_compact(&value, false).unwrap(),
            b"[1.0,-0.0,0.0001,1e-05,1e-07,1000000000000000.0,1e+16,1.2345e+20]"
        );
    }
}
