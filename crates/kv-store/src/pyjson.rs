use serde_json::Value;

use crate::StoreError;

pub fn to_vec(value: &Value) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::new();
    write_value(value, &mut output)?;
    Ok(output)
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
            for (index, (key, item)) in items.iter().enumerate() {
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
    use serde_json::json;

    use super::to_vec;

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
}
