use std::fmt::Write;

use serde_json::{Map, Number, Value};

use crate::ApprovalError;

pub fn canonical_json(value: &Value) -> Result<String, ApprovalError> {
    serialize(value, true)
}

pub fn artifact_canonical_json(value: &Value) -> Result<String, ApprovalError> {
    serialize(value, false)
}

fn serialize(value: &Value, reject_floats: bool) -> Result<String, ApprovalError> {
    let mut output = String::new();
    write_value(value, "$", reject_floats, &mut output)?;
    Ok(output)
}

fn write_value(
    value: &Value,
    path: &str,
    reject_floats: bool,
    output: &mut String,
) -> Result<(), ApprovalError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => {
            if reject_floats && is_float(number) {
                return Err(format!("{path}: float is not allowed in canonical JSON").into());
            }
            output.push_str(&number.to_string());
        }
        Value::String(value) => write_string(value, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_value(item, &format!("{path}[{index}]"), reject_floats, output)?;
            }
            output.push(']');
        }
        Value::Object(items) => write_object(items, path, reject_floats, output)?,
    }
    Ok(())
}

fn write_object(
    items: &Map<String, Value>,
    path: &str,
    reject_floats: bool,
    output: &mut String,
) -> Result<(), ApprovalError> {
    let mut entries: Vec<_> = items.iter().collect();
    entries.sort_unstable_by_key(|(key, _)| *key);

    output.push('{');
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write_string(key, output);
        output.push(':');
        write_value(value, &format!("{path}.{key}"), reject_floats, output)?;
    }
    output.push('}');
    Ok(())
}

fn is_float(number: &Number) -> bool {
    let text = number.to_string();
    text.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E'))
}

fn write_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{001f}' => {
                write!(output, "\\u{:04x}", character as u32).expect("writing to String");
            }
            character if character <= '\u{007e}' => output.push(character),
            character => {
                let mut encoded = [0u16; 2];
                for code_unit in character.encode_utf16(&mut encoded).iter() {
                    write!(output, "\\u{code_unit:04x}").expect("writing to String");
                }
            }
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::canonical_json;
    use serde_json::{Value, json};

    #[test]
    fn canonical_del_is_escaped_for_owner_signatures() {
        assert_eq!(
            canonical_json(&json!({"value":"\u{007f}"})).unwrap(),
            r#"{"value":"\u007f"}"#
        );
    }

    #[test]
    fn canonical_string_bytes_match_python_reference() {
        let Some(python) = kv_test_support::python_reference() else {
            return;
        };
        let characters: String = (0..=255)
            .filter_map(char::from_u32)
            .chain(['\u{2028}', '\u{2029}', '中', '🙂'])
            .collect();
        let value = json!({"z":characters,"\u{007f}":[false,null,18446744073709551615_u64],"a":{}});
        let output = std::process::Command::new(python)
            .args(["-I", "-c", "import json,sys; from kv.approval_wire import canonical_json; print(json.dumps(canonical_json(json.loads(sys.argv[1]))))", &serde_json::to_string(&value).unwrap()])
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(canonical_json(&value).unwrap(), reference.as_str().unwrap());
    }
}
