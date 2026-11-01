//! Python `json` module semantics for MCP frames: a decoder that reproduces
//! CPython 3.10's `json.loads` (C scanner, strict mode) including its exact
//! `JSONDecodeError` texts and character positions, and an encoder that
//! reproduces `json.dumps` output byte for byte.

use indexmap::IndexMap;

/// CPython's recursion limit as reached from `read_message`: 989 nested
/// containers decode, the 990th raises `RecursionError`.
pub const MAX_DEPTH: usize = 989;
/// `sys.get_int_max_str_digits()` default.
pub const MAX_INT_DIGITS: usize = 4300;
/// Stack for a thread that decodes frames: `MAX_DEPTH` recursive levels
/// need far more than a default thread's 2 MiB in debug builds.
pub const DECODE_STACK_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub enum PyValue {
    Null,
    Bool(bool),
    /// Decimal digits of an arbitrary-size integer, normalised as `str(int)`.
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<PyValue>),
    Dict(IndexMap<String, PyValue>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecodeError {
    /// `json.JSONDecodeError`: the full `str(exc)`.
    Json(String),
    /// Any other exception escaping `json.loads` (Python's MCP loop logs it as
    /// a read error and stops).
    Fatal(String),
}

impl PyValue {
    pub fn str(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn int(value: i64) -> Self {
        Self::Int(value.to_string())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&IndexMap<String, PyValue>> {
        match self {
            Self::Dict(value) => Some(value),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&PyValue> {
        self.as_dict().and_then(|dict| dict.get(key))
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(value) => *value,
            Self::Int(digits) => digits != "0",
            Self::Float(value) => *value != 0.0,
            Self::Str(value) => !value.is_empty(),
            Self::List(items) => !items.is_empty(),
            Self::Dict(items) => !items.is_empty(),
        }
    }

    /// `type(value).__name__`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "NoneType",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(_) => "str",
            Self::List(_) => "list",
            Self::Dict(_) => "dict",
        }
    }

    /// The value as a Python int when it is one (bools are ints in Python).
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Self::Bool(value) => Some(i128::from(*value)),
            Self::Int(digits) => digits.parse().ok(),
            _ => None,
        }
    }

    pub fn is_int(&self) -> bool {
        matches!(self, Self::Bool(_) | Self::Int(_))
    }

    /// Conversion for daemon requests. Non-finite floats have no JSON form
    /// and integers beyond `i64`/`u64` are refused rather than rounded.
    pub fn to_json(&self) -> Option<serde_json::Value> {
        use serde_json::Value;
        Some(match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(*value),
            Self::Int(digits) => {
                if let Ok(value) = digits.parse::<i64>() {
                    Value::from(value)
                } else {
                    Value::from(digits.parse::<u64>().ok()?)
                }
            }
            Self::Float(value) => Value::from(serde_json::Number::from_f64(*value)?),
            Self::Str(value) => Value::String(value.clone()),
            Self::List(items) => {
                Value::Array(items.iter().map(Self::to_json).collect::<Option<_>>()?)
            }
            Self::Dict(items) => Value::Object(
                items
                    .iter()
                    .map(|(key, value)| Some((key.clone(), value.to_json()?)))
                    .collect::<Option<_>>()?,
            ),
        })
    }

    pub fn from_json(value: &serde_json::Value) -> Self {
        use serde_json::Value;
        match value {
            Value::Null => Self::Null,
            Value::Bool(value) => Self::Bool(*value),
            Value::Number(number) => {
                if number.is_f64() {
                    Self::Float(number.as_f64().unwrap_or(f64::NAN))
                } else {
                    Self::Int(number.to_string())
                }
            }
            Value::String(value) => Self::Str(value.clone()),
            Value::Array(items) => Self::List(items.iter().map(Self::from_json).collect()),
            Value::Object(items) => Self::Dict(
                items
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::from_json(value)))
                    .collect(),
            ),
        }
    }
}

impl From<&str> for PyValue {
    fn from(value: &str) -> Self {
        Self::Str(value.into())
    }
}

impl From<String> for PyValue {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

impl From<bool> for PyValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for PyValue {
    fn from(value: i64) -> Self {
        Self::int(value)
    }
}

pub fn dict<I, K>(items: I) -> PyValue
where
    I: IntoIterator<Item = (K, PyValue)>,
    K: Into<String>,
{
    PyValue::Dict(items.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

/// `json.loads(text)`.
pub fn loads(text: &str) -> Result<PyValue, DecodeError> {
    let chars: Vec<char> = text.chars().collect();
    let decoder = Decoder { s: &chars };
    if chars.first() == Some(&'\u{feff}') {
        return Err(decoder.error("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0));
    }
    let start = decoder.skip_ws(0);
    let (value, end) = match decoder.scan_once(start, 0) {
        Ok(found) => found,
        Err(Failure::Stop(at)) => return Err(decoder.error("Expecting value", at)),
        Err(Failure::Raised(error)) => return Err(error),
    };
    let end = decoder.skip_ws(end);
    if end != chars.len() {
        return Err(decoder.error("Extra data", end));
    }
    Ok(value)
}

enum Failure {
    Stop(usize),
    Raised(DecodeError),
}

impl From<DecodeError> for Failure {
    fn from(error: DecodeError) -> Self {
        Self::Raised(error)
    }
}

struct Decoder<'a> {
    s: &'a [char],
}

fn is_ws(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '\r')
}

impl Decoder<'_> {
    fn error(&self, message: &str, pos: usize) -> DecodeError {
        let before = &self.s[..pos.min(self.s.len())];
        let lineno = before.iter().filter(|ch| **ch == '\n').count() + 1;
        let colno = match before.iter().rposition(|ch| *ch == '\n') {
            Some(newline) => pos - newline,
            None => pos + 1,
        };
        DecodeError::Json(format!(
            "{message}: line {lineno} column {colno} (char {pos})"
        ))
    }

    fn at(&self, idx: usize) -> Option<char> {
        self.s.get(idx).copied()
    }

    fn skip_ws(&self, mut idx: usize) -> usize {
        while self.at(idx).is_some_and(is_ws) {
            idx += 1;
        }
        idx
    }

    fn matches(&self, idx: usize, word: &str) -> bool {
        (idx..)
            .zip(word.chars())
            .all(|(position, expected)| self.at(position) == Some(expected))
    }

    fn scan_once(&self, idx: usize, depth: usize) -> Result<(PyValue, usize), Failure> {
        let Some(ch) = self.at(idx) else {
            return Err(Failure::Stop(idx));
        };
        match ch {
            '"' => {
                let (value, end) = self.scanstring(idx + 1)?;
                Ok((PyValue::Str(value), end))
            }
            '{' | '[' => {
                if depth >= MAX_DEPTH {
                    let kind = if ch == '{' { "object" } else { "array" };
                    return Err(DecodeError::Fatal(format!(
                        "maximum recursion depth exceeded while decoding a JSON {kind} from a unicode string"
                    ))
                    .into());
                }
                if ch == '{' {
                    self.parse_object(idx + 1, depth + 1)
                } else {
                    self.parse_array(idx + 1, depth + 1)
                }
            }
            'n' if self.matches(idx, "null") => Ok((PyValue::Null, idx + 4)),
            't' if self.matches(idx, "true") => Ok((PyValue::Bool(true), idx + 4)),
            'f' if self.matches(idx, "false") => Ok((PyValue::Bool(false), idx + 5)),
            'N' if self.matches(idx, "NaN") => Ok((PyValue::Float(f64::NAN), idx + 3)),
            'I' if self.matches(idx, "Infinity") => Ok((PyValue::Float(f64::INFINITY), idx + 8)),
            '-' if self.matches(idx, "-Infinity") => {
                Ok((PyValue::Float(f64::NEG_INFINITY), idx + 9))
            }
            _ => self.match_number(idx),
        }
    }

    fn is_digit(&self, idx: usize) -> bool {
        self.at(idx).is_some_and(|ch| ch.is_ascii_digit())
    }

    fn match_number(&self, start: usize) -> Result<(PyValue, usize), Failure> {
        let len = self.s.len();
        let mut idx = start;
        if self.at(idx) == Some('-') {
            idx += 1;
            if idx >= len {
                return Err(Failure::Stop(start));
            }
        }
        match self.at(idx) {
            Some('1'..='9') => {
                idx += 1;
                while self.is_digit(idx) {
                    idx += 1;
                }
            }
            Some('0') => idx += 1,
            _ => return Err(Failure::Stop(start)),
        }
        let mut is_float = false;
        if idx + 1 < len && self.at(idx) == Some('.') && self.is_digit(idx + 1) {
            is_float = true;
            idx += 2;
            while self.is_digit(idx) {
                idx += 1;
            }
        }
        if idx + 1 < len && matches!(self.at(idx), Some('e' | 'E')) {
            let e_start = idx;
            idx += 1;
            if idx + 1 < len && matches!(self.at(idx), Some('-' | '+')) {
                idx += 1;
            }
            while self.is_digit(idx) {
                idx += 1;
            }
            if self.is_digit(idx - 1) {
                is_float = true;
            } else {
                idx = e_start;
            }
        }
        let literal: String = self.s[start..idx].iter().collect();
        if is_float {
            let value = literal.parse::<f64>().unwrap_or(f64::NAN);
            return Ok((PyValue::Float(value), idx));
        }
        let digits = literal.trim_start_matches('-');
        if digits.len() > MAX_INT_DIGITS {
            return Err(DecodeError::Fatal(format!(
                "Exceeds the limit ({MAX_INT_DIGITS}) for integer string conversion: value has {} digits; use sys.set_int_max_str_digits() to increase the limit",
                digits.len()
            ))
            .into());
        }
        let normalised = if digits == "0" { "0".into() } else { literal };
        Ok((PyValue::Int(normalised), idx))
    }

    fn parse_object(&self, mut idx: usize, depth: usize) -> Result<(PyValue, usize), Failure> {
        let mut items = IndexMap::new();
        idx = self.skip_ws(idx);
        if self.at(idx) != Some('}') {
            loop {
                if self.at(idx) != Some('"') {
                    return Err(self
                        .error("Expecting property name enclosed in double quotes", idx)
                        .into());
                }
                let (key, next) = self.scanstring(idx + 1)?;
                idx = self.skip_ws(next);
                if self.at(idx) != Some(':') {
                    return Err(self.error("Expecting ':' delimiter", idx).into());
                }
                idx = self.skip_ws(idx + 1);
                let (value, next) = self.scan_once(idx, depth)?;
                items.insert(key, value);
                idx = self.skip_ws(next);
                if self.at(idx) == Some('}') {
                    break;
                }
                if self.at(idx) != Some(',') {
                    return Err(self.error("Expecting ',' delimiter", idx).into());
                }
                idx = self.skip_ws(idx + 1);
            }
        }
        Ok((PyValue::Dict(items), idx + 1))
    }

    fn parse_array(&self, mut idx: usize, depth: usize) -> Result<(PyValue, usize), Failure> {
        let mut items = Vec::new();
        idx = self.skip_ws(idx);
        if self.at(idx) != Some(']') {
            loop {
                let (value, next) = self.scan_once(idx, depth)?;
                items.push(value);
                idx = self.skip_ws(next);
                if self.at(idx) == Some(']') {
                    break;
                }
                if self.at(idx) != Some(',') {
                    return Err(self.error("Expecting ',' delimiter", idx).into());
                }
                idx = self.skip_ws(idx + 1);
            }
        }
        Ok((PyValue::List(items), idx + 1))
    }

    fn hex4(&self, from: usize, error_at: usize) -> Result<u32, DecodeError> {
        let mut value = 0u32;
        for idx in from..from + 4 {
            let digit = self
                .at(idx)
                .and_then(|ch| ch.to_digit(16))
                .ok_or_else(|| self.error("Invalid \\uXXXX escape", error_at))?;
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn scanstring(&self, mut end: usize) -> Result<(String, usize), DecodeError> {
        let begin = end - 1;
        let len = self.s.len();
        let mut out = String::new();
        loop {
            let mut next = end;
            let mut terminator = None;
            while next < len {
                let ch = self.s[next];
                if ch == '"' || ch == '\\' {
                    terminator = Some(ch);
                    break;
                }
                if (ch as u32) <= 0x1f {
                    return Err(self.error("Invalid control character at", next));
                }
                next += 1;
            }
            let Some(terminator) = terminator else {
                return Err(self.error("Unterminated string starting at", begin));
            };
            out.extend(&self.s[end..next]);
            next += 1;
            if terminator == '"' {
                return Ok((out, next));
            }
            if next == len {
                return Err(self.error("Unterminated string starting at", begin));
            }
            let escape = self.s[next];
            if escape != 'u' {
                end = next + 1;
                let decoded = match escape {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => return Err(self.error("Invalid \\escape", end - 2)),
                };
                out.push(decoded);
                continue;
            }
            next += 1;
            end = next + 4;
            if end >= len {
                return Err(self.error("Invalid \\uXXXX escape", next - 1));
            }
            let mut code = self.hex4(next, end - 5)?;
            if (0xd800..0xdc00).contains(&code)
                && end + 6 < len
                && self.s[end] == '\\'
                && self.s[end + 1] == 'u'
            {
                let low = self.hex4(end + 2, end + 1)?;
                if (0xdc00..0xe000).contains(&low) {
                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                    end += 6;
                }
            }
            match char::from_u32(code) {
                Some(ch) => out.push(ch),
                None => {
                    return Err(
                        self.error("Unpaired surrogate escapes are not accepted by kv", end - 6)
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct DumpOptions {
    pub ensure_ascii: bool,
    pub sort_keys: bool,
    pub indent: Option<usize>,
}

/// `json.dumps(value, ensure_ascii=..., sort_keys=..., indent=...)`.
pub fn dumps(value: &PyValue, options: DumpOptions) -> String {
    let mut out = String::new();
    write_value(value, options, 0, &mut out);
    out
}

/// `json.dumps(value, ensure_ascii=False)` — the MCP wire form.
pub fn dumps_wire(value: &PyValue) -> String {
    dumps(value, DumpOptions::default())
}

fn newline_indent(options: DumpOptions, level: usize, out: &mut String) {
    if let Some(indent) = options.indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', indent * level));
    }
}

fn write_value(value: &PyValue, options: DumpOptions, level: usize, out: &mut String) {
    let item_separator = if options.indent.is_some() { "," } else { ", " };
    match value {
        PyValue::Null => out.push_str("null"),
        PyValue::Bool(true) => out.push_str("true"),
        PyValue::Bool(false) => out.push_str("false"),
        PyValue::Int(digits) => out.push_str(digits),
        PyValue::Float(number) => out.push_str(&json_float(*number)),
        PyValue::Str(text) => write_json_string(text, options.ensure_ascii, out),
        PyValue::List(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(item_separator);
                }
                newline_indent(options, level + 1, out);
                write_value(item, options, level + 1, out);
            }
            newline_indent(options, level, out);
            out.push(']');
        }
        PyValue::Dict(items) => {
            if items.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut entries: Vec<_> = items.iter().collect();
            if options.sort_keys {
                entries.sort_by(|left, right| left.0.cmp(right.0));
            }
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(item_separator);
                }
                newline_indent(options, level + 1, out);
                write_json_string(key, options.ensure_ascii, out);
                out.push_str(": ");
                write_value(item, options, level + 1, out);
            }
            newline_indent(options, level, out);
            out.push('}');
        }
    }
}

pub fn write_json_string(text: &str, ensure_ascii: bool, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if ensure_ascii && !c.is_ascii() => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_float(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value.is_infinite() {
        if value > 0.0 { "Infinity" } else { "-Infinity" }.into()
    } else {
        float_repr(value)
    }
}

/// `repr(float)`: the shortest round-trip digits in Python's layout.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.into();
    }
    let formatted = format!("{value:e}");
    let (negative, unsigned) = formatted
        .strip_prefix('-')
        .map_or((false, formatted.as_str()), |rest| (true, rest));
    let (mantissa, exponent) = unsigned.split_once('e').unwrap_or((unsigned, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|ch| *ch != '.').collect();
    let mut result = String::new();
    if negative {
        result.push('-');
    }
    if digits == "0" {
        result.push_str("0.0");
        return result;
    }
    if (-4..16).contains(&exponent) {
        let decimal_position = exponent + 1;
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
        result.push_str(&digits[..1]);
        if digits.len() > 1 {
            result.push('.');
            result.push_str(&digits[1..]);
        }
        result.push('e');
        result.push(if exponent < 0 { '-' } else { '+' });
        result.push_str(&format!("{:02}", exponent.unsigned_abs()));
    }
    result
}

/// `str(value)` as used in f-strings.
pub fn py_str(value: &PyValue) -> String {
    match value {
        PyValue::Str(text) => text.clone(),
        other => py_repr(other),
    }
}

/// `repr(value)`.
pub fn py_repr(value: &PyValue) -> String {
    match value {
        PyValue::Null => "None".into(),
        PyValue::Bool(true) => "True".into(),
        PyValue::Bool(false) => "False".into(),
        PyValue::Int(digits) => digits.clone(),
        PyValue::Float(number) => float_repr(*number),
        PyValue::Str(text) => str_repr(text),
        PyValue::List(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        PyValue::Dict(items) => format!(
            "{{{}}}",
            items
                .iter()
                .map(|(key, item)| format!("{}: {}", str_repr(key), py_repr(item)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn is_printable(ch: char) -> bool {
    use unicode_general_category::{GeneralCategory as G, get_general_category};
    if ch == ' ' {
        return true;
    }
    !matches!(
        get_general_category(ch),
        G::Control
            | G::Format
            | G::Surrogate
            | G::PrivateUse
            | G::Unassigned
            | G::LineSeparator
            | G::ParagraphSeparator
            | G::SpaceSeparator
    )
}

/// `repr(str)`.
pub fn str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if c.is_ascii() || is_printable(c) => out.push(c),
            c if (c as u32) <= 0xff => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) <= 0xffff => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(quote);
    out
}

/// `str.isspace()` for one character.
pub fn py_isspace(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

/// `str.strip()`.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(py_isspace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_errors_match_python() {
        let cases = [
            ("", "Expecting value: line 1 column 1 (char 0)"),
            (
                "{",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            ("[1,]", "Expecting value: line 1 column 4 (char 3)"),
            (
                "{\"a\" 1}",
                "Expecting ':' delimiter: line 1 column 6 (char 5)",
            ),
            (
                "{\"a\":1 2}",
                "Expecting ',' delimiter: line 1 column 8 (char 7)",
            ),
            (
                "\"abc",
                "Unterminated string starting at: line 1 column 1 (char 0)",
            ),
            ("\"\\x\"", "Invalid \\escape: line 1 column 2 (char 1)"),
            (
                "\"\\u12\"",
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
            (
                "\"a\u{1}\"",
                "Invalid control character at: line 1 column 3 (char 2)",
            ),
            ("1 2", "Extra data: line 1 column 3 (char 2)"),
            ("-", "Expecting value: line 1 column 1 (char 0)"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                loads(input),
                Err(DecodeError::Json(expected.into())),
                "{input}"
            );
        }
    }

    #[test]
    fn numbers_and_strings_round_trip_like_python() {
        let value = loads(r#"{"a": [1, -0, 1.5, 1e400, 1E2, 0.0001, 1e16, "\u00e9\ud83d\ude00"]}"#)
            .unwrap();
        assert_eq!(
            dumps_wire(&value),
            "{\"a\": [1, 0, 1.5, Infinity, 100.0, 0.0001, 1e+16, \"\u{e9}\u{1f600}\"]}"
        );
        assert_eq!(float_repr(1e-5), "1e-05");
        assert_eq!(float_repr(123456789012345680.0), "1.2345678901234568e+17");
        assert_eq!(str_repr("it's"), "\"it's\"");
        assert_eq!(str_repr("a\u{85}b\u{e9}"), "'a\\x85b\u{e9}'");
    }

    #[test]
    fn depth_limit_matches_python() {
        std::thread::Builder::new()
            .stack_size(DECODE_STACK_BYTES)
            .spawn(depth_limit_body)
            .unwrap()
            .join()
            .unwrap();
    }

    fn depth_limit_body() {
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(loads(&ok).is_ok());
        let deep = format!("[{ok}]");
        assert!(matches!(loads(&deep), Err(DecodeError::Fatal(_))));
    }
}
