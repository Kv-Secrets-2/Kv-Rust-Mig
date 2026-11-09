use serde_json::Value;

use crate::StoreError;

pub fn to_vec(value: &Value) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::new();
    write_value(value, &mut output)?;
    Ok(output)
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
            character if character <= '\u{007f}' => output.push(character as u8),
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

    use super::{to_vec, to_vec_indent2_ascii};

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
}
