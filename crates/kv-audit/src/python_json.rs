//! Python's json.loads accepts three non-finite float literals. Keep that
//! compatibility local to historical audit/health reads; wire parsing is not
//! changed. All ordinary syntax and nesting limits are still checked by serde.

use serde_json::{Number, Value};

pub(crate) fn from_slice(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let error = match serde_json::from_slice(bytes) {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    let Ok(source) = std::str::from_utf8(bytes) else {
        return Err(error);
    };
    let literals = ["-Infinity", "Infinity", "NaN"];
    // Markers never occur in the source. Their large integer representation
    // survives arbitrary_precision unchanged, including duplicate object keys.
    let mut candidate = 0_u64;
    let markers = literals.map(|_| {
        loop {
            let marker = format!("987654321012345678909876543210{candidate}");
            candidate += 1;
            if !source.contains(&marker) {
                break marker;
            }
        }
    });
    let mut output = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut replaced = false;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if quoted {
            output.push(byte);
            offset += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        if byte == b'"' {
            quoted = true;
        } else if before_literal(bytes, offset)
            && let Some(index) = literals.iter().position(|literal| {
                bytes[offset..].starts_with(literal.as_bytes())
                    && after_literal(bytes, offset + literal.len())
            })
        {
            output.extend_from_slice(markers[index].as_bytes());
            offset += literals[index].len();
            replaced = true;
            continue;
        }
        output.push(byte);
        offset += 1;
    }
    if !replaced {
        return Err(error);
    }
    let mut value = serde_json::from_slice(&output)?;
    restore(&mut value, &markers, &literals);
    Ok(value)
}

fn before_literal(bytes: &[u8], offset: usize) -> bool {
    offset == 0
        || matches!(
            bytes[offset - 1],
            b' ' | b'\t' | b'\r' | b'\n' | b'[' | b'{' | b':' | b','
        )
}

fn after_literal(bytes: &[u8], offset: usize) -> bool {
    offset == bytes.len()
        || matches!(
            bytes[offset],
            b' ' | b'\t' | b'\r' | b'\n' | b']' | b'}' | b','
        )
}

fn restore(value: &mut Value, markers: &[String; 3], literals: &[&str; 3]) {
    match value {
        Value::Number(number) => {
            if let Some(index) = markers
                .iter()
                .position(|marker| marker == &number.to_string())
            {
                // The only unchecked representations are the three exact
                // Python literals above; no caller-controlled syntax enters it.
                *number = Number::from_string_unchecked(literals[index].to_owned());
            }
        }
        Value::Array(items) => {
            for item in items {
                restore(item, markers, literals);
            }
        }
        Value::Object(items) => {
            for item in items.values_mut() {
                restore(item, markers, literals);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_float_literals_are_local_to_values_and_do_not_collide() {
        let value = from_slice(br#"{"x":NaN,"x":Infinity,"negative":-Infinity,"text":"NaN and \\\"Infinity","marker":9876543210123456789098765432100,"nested":[NaN,2]}"#).unwrap();
        assert_eq!(value["x"].as_number().unwrap().to_string(), "Infinity");
        assert_eq!(
            value["negative"].as_number().unwrap().to_string(),
            "-Infinity"
        );
        assert_eq!(value["nested"][0].as_number().unwrap().to_string(), "NaN");
        assert_eq!(
            value["marker"].as_number().unwrap().to_string(),
            "9876543210123456789098765432100"
        );
        assert_eq!(value["text"], "NaN and \\\"Infinity");
    }

    #[test]
    fn other_invalid_numeric_and_container_syntax_still_fails() {
        for input in [
            "-NaN",
            "+Infinity",
            "Infinitye0",
            "NaN1",
            "nan",
            "[NaN,]",
            "{NaN:1}",
            "[01,NaN]",
            "[--Infinity]",
            "[\u{b}NaN]",
        ] {
            assert!(from_slice(input.as_bytes()).is_err(), "{input:?}");
        }
    }
}
