use std::collections::BTreeSet;

use base64::Engine as _;
use kv_crypto::Zeroizing;
use serde_json::{Map, Number, Value, json};

#[derive(Default)]
pub struct Needles {
    values: Vec<Zeroizing<String>>,
    cut_window: usize,
}

impl Needles {
    fn new(values: BTreeSet<String>, cut_window: usize) -> Self {
        let mut values = values.into_iter().collect::<Vec<_>>();
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self {
            values: values.into_iter().map(Zeroizing::new).collect(),
            cut_window,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &str> {
        self.values.iter().map(|value| value.as_str())
    }

    pub(crate) fn max_chars(&self) -> usize {
        self.cut_window
    }
}

fn escaped_spellings(value: &str) -> BTreeSet<String> {
    let mut result = BTreeSet::from([value.to_owned()]);
    if let Some(quoted) = serde_json::to_string(value)
        .ok()
        .and_then(|s| s.get(1..s.len() - 1).map(str::to_owned))
    {
        result.insert(quoted);
    }
    result.insert(json_ascii_body(value));
    let repr = python_repr(value, false);
    result.insert(repr[1..repr.len() - 1].to_owned());
    let ascii = python_repr(value, true);
    result.insert(ascii[1..ascii.len() - 1].to_owned());
    let appended = python_repr(&format!("{value}\""), false);
    result.insert(appended[1..appended.len() - 2].to_owned());
    result.insert(python_unicode_escape(value));
    let bytes_repr = python_bytes_repr(value.as_bytes());
    result.insert(bytes_repr[1..bytes_repr.len() - 1].to_owned());
    result
}

pub(crate) fn python_repr(value: &str, ascii_only: bool) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut output = String::new();
    output.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            c if c == quote => {
                output.push('\\');
                output.push(c);
            }
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c.is_control() => output.push_str(&format!("\\x{:02x}", c as u32)),
            c if ascii_only && !c.is_ascii() => output.push_str(&python_codepoint_escape(c)),
            c => output.push(c),
        }
    }
    output.push(quote);
    output
}

fn python_codepoint_escape(ch: char) -> String {
    let value = ch as u32;
    if value <= 0xff {
        format!("\\x{value:02x}")
    } else if value <= 0xffff {
        format!("\\u{value:04x}")
    } else {
        format!("\\U{value:08x}")
    }
}

fn json_ascii_body(value: &str) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    let mut output = String::new();
    for ch in quoted[1..quoted.len().saturating_sub(1)].chars() {
        if !ch.is_ascii() {
            let scalar = ch as u32;
            if scalar <= 0xffff {
                output.push_str(&format!("\\u{scalar:04x}"));
            } else {
                let adjusted = scalar - 0x10000;
                output.push_str(&format!(
                    "\\u{:04x}\\u{:04x}",
                    0xd800 + (adjusted >> 10),
                    0xdc00 + (adjusted & 0x3ff)
                ));
            }
        } else {
            output.push(ch);
        }
    }
    output
}

fn python_bytes_repr(bytes: &[u8]) -> String {
    let mut output = String::new();
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    output.push(quote);
    for byte in bytes {
        match *byte {
            b'\\' => output.push_str("\\\\"),
            b'\'' if quote == '\'' => output.push_str("\\'"),
            b'"' if quote == '"' => output.push_str("\\\""),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'\t' => output.push_str("\\t"),
            0x20..=0x7e => output.push(char::from(*byte)),
            other => output.push_str(&format!("\\x{other:02x}")),
        }
    }
    output.push(quote);
    output
}

fn python_unicode_escape(value: &str) -> String {
    let mut output = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            c if c.is_control() => output.push_str(&format!("\\x{:02x}", c as u32)),
            c if !c.is_ascii() => output.push_str(&python_codepoint_escape(c)),
            c => output.push(c),
        }
    }
    output
}

pub fn output_needles(secrets: &Value, exact: &[&str]) -> Needles {
    let mut values = BTreeSet::new();
    let mut cut_window = 0;
    if let Some(secrets) = secrets.as_object() {
        for secret in secrets.values().filter_map(Value::as_str) {
            if !secret.is_empty() {
                cut_window = cut_window.max(secret.chars().count().saturating_mul(12));
            }
            if secret.chars().count() >= 4 {
                for variant in redaction_variants(secret) {
                    if !variant.is_empty() {
                        values.insert(variant);
                    }
                }
            }
        }
    }
    for value in exact.iter().copied().filter(|value| !value.is_empty()) {
        cut_window = cut_window.max(value.chars().count().saturating_mul(12));
        values.extend(escaped_spellings(value));
    }
    cut_window = cut_window.max(
        values
            .iter()
            .map(|needle| needle.chars().count())
            .max()
            .unwrap_or(0),
    );
    Needles::new(values, cut_window)
}

fn redaction_variants(value: &str) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let len = value.chars().count();
    if len >= 4 {
        values.insert(value.to_owned());
        values.insert(value.chars().rev().collect());
        for encoded in [
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes()),
            base64::engine::general_purpose::URL_SAFE.encode(value.as_bytes()),
        ] {
            if encoded.len() >= 8 {
                let unpadded = encoded.trim_end_matches('=');
                values.insert(encoded.clone());
                values.insert(unpadded.to_owned());
                if encoded.len() > 76 {
                    for item in [encoded.as_str(), unpadded] {
                        values.insert(
                            item.as_bytes()
                                .chunks(76)
                                .map(String::from_utf8_lossy)
                                .collect::<Vec<_>>()
                                .join("\n"),
                        );
                        values.insert(
                            item.as_bytes()
                                .chunks(76)
                                .map(String::from_utf8_lossy)
                                .collect::<Vec<_>>()
                                .join("\r\n"),
                        );
                    }
                }
            }
        }
        let hex = hex_encode(value.as_bytes());
        if hex.len() >= 8 {
            values.insert(hex);
        }
        for encoded in [
            percent_encode(value.as_bytes(), false),
            percent_encode(value.as_bytes(), true),
        ] {
            values.insert(encoded.clone());
            values.insert(lowercase_percent_escapes(&encoded));
        }
    }
    values
}

fn percent_encode(bytes: &[u8], plus_for_space: bool) -> String {
    let mut output = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || b"_.-~".contains(byte) {
            output.push(char::from(*byte));
        } else if *byte == b' ' && plus_for_space {
            output.push('+');
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn lowercase_percent_escapes(value: &str) -> String {
    let mut output = value.to_owned();
    let bytes = value.as_bytes();
    for index in 0..bytes.len().saturating_sub(2) {
        if bytes[index] == b'%' {
            output.replace_range(
                index + 1..index + 3,
                &value[index + 1..index + 3].to_ascii_lowercase(),
            );
        }
    }
    output
}

fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn hide(text: &str, needles: &Needles, keep: Option<usize>) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    let end = keep.unwrap_or(chars.len()).min(chars.len());
    if needles.values.is_empty() {
        return chars[..end].iter().collect();
    }
    let mut hidden = vec![false; chars.len()];
    for needle in needles.iter() {
        let needle = needle.chars().collect::<Vec<_>>();
        if needle.is_empty() || needle.len() > chars.len() {
            continue;
        }
        for start in 0..=chars.len() - needle.len() {
            if chars[start..start + needle.len()] == needle {
                hidden[start..start + needle.len()].fill(true);
            }
        }
    }
    let mut output = String::new();
    let mut cursor = 0;
    while cursor < end {
        if !hidden[cursor] {
            output.push(chars[cursor]);
            cursor += 1;
            continue;
        }
        output.push_str("[REDACTED]");
        cursor += 1;
        while cursor < chars.len() && hidden[cursor] {
            cursor += 1;
        }
    }
    output
}

pub fn hide_cut(text: &str, needles: &Needles, keep: Option<usize>) -> String {
    let mut chars = text.chars().collect::<Vec<_>>();
    while chars.last() == Some(&'\u{fffd}') {
        chars.pop();
    }
    let mut stop = keep.unwrap_or(chars.len()).min(chars.len());
    for needle in needles.iter() {
        let needle = needle.chars().collect::<Vec<_>>();
        if needle.is_empty() {
            continue;
        }
        let max = needle.len().saturating_sub(1).min(chars.len());
        for count in (1..=max).rev() {
            if chars[chars.len() - count..] == needle[..count] {
                stop = stop.min(chars.len() - count);
                break;
            }
        }
    }
    let body = chars.iter().collect::<String>();
    hide(&body, needles, Some(stop))
}

pub fn hide_value(value: &Value, needles: &Needles) -> Value {
    match value {
        Value::String(text) => Value::String(hide(text, needles, None)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| hide_value(value, needles))
                .collect(),
        ),
        Value::Object(values) => {
            let mut result = Map::new();
            for (key, value) in values {
                let key = hide(key, needles, None);
                result.insert(key, hide_value(value, needles));
            }
            Value::Object(result)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            let string = match value {
                Value::Null => "None".to_owned(),
                Value::Bool(true) => "True".into(),
                Value::Bool(false) => "False".into(),
                Value::Number(number) => python_number(number),
                _ => unreachable!(),
            };
            let json = value.to_string();
            if hide(&string, needles, None) != string || hide(&json, needles, None) != json {
                Value::String("[REDACTED]".into())
            } else {
                value.clone()
            }
        }
    }
}

fn python_number(number: &Number) -> String {
    number.to_string()
}

pub fn redact_one_secret(secret_name: &str, secret_value: &str) -> Value {
    if secret_value.is_empty() {
        json!({})
    } else {
        json!({secret_name:secret_value})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hides_overlapping_needle_once() {
        let needles = Needles::new(BTreeSet::from(["aba".into()]), 3);
        assert_eq!(hide("ababa", &needles, None), "[REDACTED]");
    }

    #[test]
    fn secret_needles_are_zeroizing() {
        let needles = output_needles(&json!({"x":"secret"}), &["short"]);
        assert!(!needles.values.is_empty());
    }
}
