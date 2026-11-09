//! Complete, escaped permit review cards, matching the pinned Python renderer.
//!
//! This is an admission guard, not a terminal UI. It never truncates the exact
//! call. JSON summaries retain Python string code points, including lone
//! surrogates, until the final visible escaping step.

use std::collections::BTreeMap;

use serde_json::{Map, Number, Value};

pub(crate) const MAX_SHOWN: usize = 8192;
pub(crate) const MAX_PROMPT_SHOWN: usize = 32768;

pub(crate) fn escape_text(value: &str, max_shown: usize) -> Result<String, String> {
    escape_points(value.chars().map(u32::from), max_shown)
}

fn escape_points(value: impl IntoIterator<Item = u32>, max_shown: usize) -> Result<String, String> {
    let mut shown = String::new();
    for code in value {
        match code {
            0x5c => shown.push_str("\\\\"),
            0x0a => shown.push_str("\\n"),
            0x09 => shown.push_str("\\t"),
            0x0d => shown.push_str("\\r"),
            0x20..=0x7e => shown.push(char::from_u32(code).expect("ASCII")),
            0..=0xffff => shown.push_str(&format!("\\u{code:04x}")),
            _ => shown.push_str(&format!("\\U{code:08x}")),
        }
    }
    // Every displayed code point is ASCII, so byte length is character length.
    if shown.len() > max_shown {
        return Err(format!(
            "a value is {} characters long when shown (at most {max_shown} are shown in full)",
            shown.len()
        ));
    }
    Ok(shown)
}

fn field<'a>(facts: &'a Value, key: &str) -> Result<&'a Value, String> {
    facts
        .get(key)
        .ok_or_else(|| format!("missing permit field: {key}"))
}

fn text<'a>(facts: &'a Value, key: &str) -> Result<&'a str, String> {
    field(facts, key)?
        .as_str()
        .ok_or_else(|| format!("permit field is not text: {key}"))
}

fn shown_field(facts: &Value, key: &str) -> Result<String, String> {
    escape_text(text(facts, key)?, MAX_SHOWN)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    // bytes.fromhex accepts ASCII whitespace between bytes, not within one.
    let mut bytes = Vec::new();
    let mut at = 0;
    let source = value.as_bytes();
    while at < source.len() {
        if matches!(source[at], b' ' | b'\t'..=b'\r') {
            at += 1;
            continue;
        }
        let high = source[at].is_ascii_hexdigit().then_some(source[at]);
        let low = source.get(at + 1).copied().filter(u8::is_ascii_hexdigit);
        let (Some(high), Some(low)) = (high, low) else {
            return Err("invalid permit location hex".into());
        };
        bytes.push((hex_digit(high) << 4) | hex_digit(low));
        at += 2;
    }
    Ok(bytes)
}

fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("validated hex digit"),
    }
}

fn filesystem_points(bytes: &[u8]) -> Vec<u32> {
    // POSIX os.fsdecode: UTF-8 with surrogateescape. Do not replace invalid
    // path bytes with U+FFFD, which would hide the owner's exact vault path.
    let mut points = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                points.extend(valid.chars().map(u32::from));
                break;
            }
            Err(error) => {
                let valid = &rest[..error.valid_up_to()];
                points.extend(
                    std::str::from_utf8(valid)
                        .expect("validated UTF-8 prefix")
                        .chars()
                        .map(u32::from),
                );
                rest = &rest[error.valid_up_to()..];
                let invalid = error.error_len().unwrap_or(rest.len());
                points.extend(rest[..invalid].iter().map(|byte| 0xdc00 + u32::from(*byte)));
                rest = &rest[invalid..];
            }
        }
    }
    points
}

pub(crate) fn validate_review(
    facts: &Value,
    body_text: &str,
    caller_headers: &Map<String, Value>,
) -> Result<(), String> {
    render_review(facts, body_text, caller_headers).map(|_| ())
}

pub(crate) fn render_review(
    facts: &Value,
    body_text: &str,
    caller_headers: &Map<String, Value>,
) -> Result<Vec<String>, String> {
    let epoch = field(facts, "expires_at_epoch")?
        .as_i64()
        .ok_or("invalid permit expiry")?;
    let expiry =
        time::OffsetDateTime::from_unix_timestamp(epoch).map_err(|_| "invalid permit expiry")?;
    if !(1..=9999).contains(&expiry.year()) {
        return Err("invalid permit expiry".into());
    }
    let expiry = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        expiry.year(),
        u8::from(expiry.month()),
        expiry.day(),
        expiry.hour(),
        expiry.minute(),
        expiry.second()
    );
    let location = decode_hex(text(facts, "location")?)?;
    let owner = text(facts, "owner_key_id")?;
    let header_names = field(facts, "header_names")?
        .as_array()
        .ok_or("invalid permit header names")?
        .iter()
        .map(|name| {
            escape_text(
                name.as_str().ok_or("invalid permit header name")?,
                MAX_SHOWN,
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut lines = vec![
        "Approve exactly one HTTP call.".into(),
        format!(
            "Vault folder: {}",
            escape_points(filesystem_points(&location), MAX_SHOWN)?
        ),
        format!("Environment: {}", shown_field(facts, "environment")?),
        format!("Provider: {}", shown_field(facts, "provider")?),
        format!(
            "Provider digest: {}",
            shown_field(facts, "provider_digest")?
        ),
        format!("Signer: {}", shown_field(facts, "signer")?),
        format!(
            "Owner key: {}",
            escape_text(
                if owner.is_empty() {
                    "<local approval key>"
                } else {
                    owner
                },
                MAX_SHOWN
            )?
        ),
        format!(
            "Local approval identity: {}",
            shown_field(facts, "local_approval_id")?
        ),
        format!("Method: {}", shown_field(facts, "method")?),
        format!("URL: {}", shown_field(facts, "url")?),
        format!("Header names: {}", header_names.join(", ")),
    ];
    let mut headers = caller_headers.iter().collect::<Vec<_>>();
    headers.sort_unstable_by(|left, right| left.0.cmp(right.0));
    for (name, value) in headers {
        lines.push(format!(
            "Caller header: {} = {}",
            escape_text(name, MAX_SHOWN)?,
            escape_text(
                value.as_str().ok_or("invalid permit caller header")?,
                MAX_SHOWN
            )?
        ));
    }
    let body_length = field(facts, "body_length")?
        .as_number()
        .ok_or("invalid permit body length")?;
    lines.extend([
        format!(
            "Body bytes: {}",
            escape_text(&python_number(&body_length.to_string())?, MAX_SHOWN)?
        ),
        format!(
            "Body present: {}",
            if field(facts, "body_present")?
                .as_bool()
                .ok_or("invalid permit body presence")?
            {
                "yes"
            } else {
                "no"
            }
        ),
        format!("Body SHA-256: {}", shown_field(facts, "body_sha256")?),
        "Exact body (UTF-8; controls are shown as escapes):".into(),
        escape_text(body_text, MAX_PROMPT_SHOWN)?,
    ]);

    match JsonSummary::parse(body_text) {
        Ok(summary) => match &summary.nodes[summary.root] {
            Node::Object { items, .. } => {
                let mut fields = Vec::new();
                for (key, value) in items.iter().take(8) {
                    // Python checks the complete escaped value before replacing
                    // its short summary with a marker. The exact body stays above.
                    let key = escape_points(key.iter().copied(), MAX_PROMPT_SHOWN)?;
                    let shown = summary.display(*value)?;
                    fields.push(format!(
                        "{}={}",
                        if key.len() <= 80 {
                            &key
                        } else {
                            "<long key; see exact body>"
                        },
                        if shown.len() <= 120 {
                            &shown
                        } else {
                            "<long value; see exact body>"
                        }
                    ));
                }
                let suffix = if items.len() > 8 {
                    format!(" (+{} more; see exact body)", items.len() - 8)
                } else {
                    String::new()
                };
                lines.push(format!("JSON fields: {}{suffix}", fields.join(", ")));
            }
            Node::Array(items) => {
                lines.push(format!(
                    "JSON fields: top-level array ({} items; see exact body)",
                    items.len()
                ));
            }
            _ => {}
        },
        Err(ParseError::Invalid) => {} // Python catches JSON ValueError/TypeError.
        Err(ParseError::TooDeep) => {
            // Python's uncaught RecursionError depends on its caller stack.
            // At its default recursion ceiling fail closed, never silently
            // omit a summary or overflow a Rust thread's stack.
            return Err("JSON nesting exceeds the permit review limit".into());
        }
    }
    if !field(facts, "grant_id")?.is_null() {
        lines.push(format!("Grant: {}", shown_field(facts, "grant_id")?));
        lines.push(format!("Run: {}", shown_field(facts, "run_id")?));
    }
    lines.extend([
        format!("Request: {}", shown_field(facts, "request_id")?),
        format!("Permit: {}", shown_field(facts, "permit_id")?),
        format!("Session: {}", shown_field(facts, "session_nonce")?),
        format!("Expires: {}", escape_text(&expiry, MAX_SHOWN)?),
        "This permit ends when the service stops. A failed send is not refunded.".into(),
    ]);
    if lines.iter().map(String::len).sum::<usize>() + lines.len().saturating_sub(1)
        > MAX_PROMPT_SHOWN
    {
        return Err("the complete call cannot be shown in full on the approval screen".into());
    }
    Ok(lines)
}

// A small arena keeps parsing, encoding and destruction iterative. serde_json
// cannot represent Python's lone surrogate strings or its NaN/Infinity values.
type PyString = Vec<u32>;

enum Node {
    Atom(String),
    Text(PyString),
    Array(Vec<usize>),
    Object {
        items: Vec<(PyString, usize)>,
        positions: BTreeMap<PyString, usize>,
    },
}

struct JsonSummary {
    nodes: Vec<Node>,
    root: usize,
}

#[derive(Debug)]
enum ParseError {
    Invalid,
    TooDeep,
}

#[derive(Clone, Copy)]
enum Stage {
    ArrayStart,
    ArrayValue,
    ArrayNext,
    ObjectStart,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectNext,
}

struct Frame {
    node: usize,
    stage: Stage,
    key: Option<PyString>,
}

struct Parser<'a> {
    source: &'a str,
    at: usize,
    nodes: Vec<Node>,
}

impl JsonSummary {
    fn parse(source: &str) -> Result<Self, ParseError> {
        let mut parser = Parser {
            source,
            at: 0,
            nodes: Vec::new(),
        };
        let (root, frame) = parser.value()?;
        let mut frames = frame.into_iter().collect::<Vec<_>>();
        while let Some(frame) = frames.last() {
            if frames.len() > 1000 {
                return Err(ParseError::TooDeep);
            }
            let node = frame.node;
            let stage = frame.stage;
            parser.whitespace();
            match stage {
                Stage::ArrayStart if parser.take(b']') => {
                    frames.pop();
                }
                Stage::ObjectStart if parser.take(b'}') => {
                    frames.pop();
                }
                Stage::ArrayStart | Stage::ArrayValue => {
                    let (child, frame) = parser.value()?;
                    let Node::Array(items) = &mut parser.nodes[node] else {
                        unreachable!()
                    };
                    items.push(child);
                    frames.last_mut().unwrap().stage = Stage::ArrayNext;
                    frames.extend(frame);
                }
                Stage::ArrayNext => {
                    if parser.take(b']') {
                        frames.pop();
                    } else if parser.take(b',') {
                        frames.last_mut().unwrap().stage = Stage::ArrayValue;
                    } else {
                        return Err(ParseError::Invalid);
                    }
                }
                Stage::ObjectStart | Stage::ObjectKey => {
                    let key = parser.string()?;
                    let frame = frames.last_mut().unwrap();
                    frame.key = Some(key);
                    frame.stage = Stage::ObjectColon;
                }
                Stage::ObjectColon => {
                    if !parser.take(b':') {
                        return Err(ParseError::Invalid);
                    }
                    frames.last_mut().unwrap().stage = Stage::ObjectValue;
                }
                Stage::ObjectValue => {
                    let (child, next) = parser.value()?;
                    let frame = frames.last_mut().unwrap();
                    let key = frame.key.take().unwrap();
                    let Node::Object { items, positions } = &mut parser.nodes[node] else {
                        unreachable!()
                    };
                    if let Some(position) = positions.get(&key) {
                        items[*position].1 = child;
                    } else {
                        positions.insert(key.clone(), items.len());
                        items.push((key, child));
                    }
                    frame.stage = Stage::ObjectNext;
                    frames.extend(next);
                }
                Stage::ObjectNext => {
                    if parser.take(b'}') {
                        frames.pop();
                    } else if parser.take(b',') {
                        frames.last_mut().unwrap().stage = Stage::ObjectKey;
                    } else {
                        return Err(ParseError::Invalid);
                    }
                }
            }
        }
        parser.whitespace();
        if parser.at != source.len() {
            return Err(ParseError::Invalid);
        }
        Ok(Self {
            nodes: parser.nodes,
            root,
        })
    }

    fn display(&self, node: usize) -> Result<String, String> {
        if let Node::Text(value) = &self.nodes[node] {
            return escape_points(value.iter().copied(), MAX_PROMPT_SHOWN);
        }
        enum Task<'a> {
            Node(usize),
            Literal(&'a str),
            Quoted(&'a [u32]),
        }
        let mut tasks = vec![Task::Node(node)];
        let mut output = Vec::new();
        while let Some(task) = tasks.pop() {
            match task {
                Task::Literal(value) => output.extend(value.chars().map(u32::from)),
                Task::Quoted(value) => quote_json(value, &mut output),
                Task::Node(node) => match &self.nodes[node] {
                    Node::Atom(value) => tasks.push(Task::Literal(value)),
                    Node::Text(value) => tasks.push(Task::Quoted(value)),
                    Node::Array(items) => {
                        output.push(u32::from('['));
                        tasks.push(Task::Literal("]"));
                        for (index, item) in items.iter().enumerate().rev() {
                            tasks.push(Task::Node(*item));
                            if index > 0 {
                                tasks.push(Task::Literal(", "));
                            }
                        }
                    }
                    Node::Object { items, .. } => {
                        output.push(u32::from('{'));
                        tasks.push(Task::Literal("}"));
                        let mut sorted = items.iter().collect::<Vec<_>>();
                        sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                        for (index, (key, value)) in sorted.into_iter().enumerate().rev() {
                            tasks.push(Task::Node(*value));
                            tasks.push(Task::Literal(": "));
                            tasks.push(Task::Quoted(key));
                            if index > 0 {
                                tasks.push(Task::Literal(", "));
                            }
                        }
                    }
                },
            }
        }
        escape_points(output, MAX_PROMPT_SHOWN)
    }
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while self
            .source
            .as_bytes()
            .get(self.at)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.at += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.source.as_bytes().get(self.at) == Some(&byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Result<(usize, Option<Frame>), ParseError> {
        self.whitespace();
        let mut stage = None;
        let node = match self.source.as_bytes().get(self.at) {
            Some(b'"') => Node::Text(self.string()?),
            Some(b'[') => {
                self.at += 1;
                stage = Some(Stage::ArrayStart);
                Node::Array(Vec::new())
            }
            Some(b'{') => {
                self.at += 1;
                stage = Some(Stage::ObjectStart);
                Node::Object {
                    items: Vec::new(),
                    positions: BTreeMap::new(),
                }
            }
            _ => {
                let rest = &self.source[self.at..];
                if let Some(literal) = ["null", "true", "false", "NaN", "Infinity", "-Infinity"]
                    .into_iter()
                    .find(|literal| rest.starts_with(literal))
                {
                    self.at += literal.len();
                    Node::Atom(literal.to_owned())
                } else {
                    Node::Atom(self.number()?)
                }
            }
        };
        let index = self.nodes.len();
        self.nodes.push(node);
        Ok((
            index,
            stage.map(|stage| Frame {
                node: index,
                stage,
                key: None,
            }),
        ))
    }

    fn number(&mut self) -> Result<String, ParseError> {
        let start = self.at;
        self.take(b'-');
        let digits = self.at;
        if !self.take(b'0') {
            if !self
                .source
                .as_bytes()
                .get(self.at)
                .is_some_and(|byte| matches!(byte, b'1'..=b'9'))
            {
                return Err(ParseError::Invalid);
            }
            self.at += 1;
            self.digits();
        }
        let integer_digits = self.at - digits;
        let mut float = false;
        if self.take(b'.') {
            float = true;
            let before = self.at;
            self.digits();
            if before == self.at {
                return Err(ParseError::Invalid);
            }
        }
        if self.take(b'e') || self.take(b'E') {
            float = true;
            if !self.take(b'+') {
                self.take(b'-');
            }
            let before = self.at;
            self.digits();
            if before == self.at {
                return Err(ParseError::Invalid);
            }
        }
        if !float && integer_digits > 4300 {
            // Python's default integer conversion limit raises ValueError,
            // caught by render_permit_request as an absent JSON summary.
            return Err(ParseError::Invalid);
        }
        python_number(&self.source[start..self.at]).map_err(|_| ParseError::Invalid)
    }

    fn digits(&mut self) {
        while self
            .source
            .as_bytes()
            .get(self.at)
            .is_some_and(u8::is_ascii_digit)
        {
            self.at += 1;
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let bytes = self
            .source
            .as_bytes()
            .get(self.at..self.at + 4)
            .ok_or(ParseError::Invalid)?;
        if !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(ParseError::Invalid);
        }
        self.at += 4;
        Ok(bytes
            .iter()
            .fold(0, |code, byte| (code << 4) | u32::from(hex_digit(*byte))))
    }

    fn string(&mut self) -> Result<PyString, ParseError> {
        if !self.take(b'"') {
            return Err(ParseError::Invalid);
        }
        let mut output = Vec::new();
        loop {
            let byte = *self
                .source
                .as_bytes()
                .get(self.at)
                .ok_or(ParseError::Invalid)?;
            self.at += 1;
            match byte {
                b'"' => return Ok(output),
                b'\\' => {
                    let escaped = *self
                        .source
                        .as_bytes()
                        .get(self.at)
                        .ok_or(ParseError::Invalid)?;
                    self.at += 1;
                    output.push(match escaped {
                        b'"' | b'\\' | b'/' => u32::from(escaped),
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => 10,
                        b'r' => 13,
                        b't' => 9,
                        b'u' => {
                            let high = self.hex4()?;
                            if (0xd800..=0xdbff).contains(&high)
                                && self.source.as_bytes().get(self.at..self.at + 2) == Some(b"\\u")
                            {
                                let before = self.at;
                                self.at += 2;
                                match self.hex4() {
                                    Ok(low) if (0xdc00..=0xdfff).contains(&low) => {
                                        0x10000 + ((high - 0xd800) << 10) + low - 0xdc00
                                    }
                                    _ => {
                                        self.at = before;
                                        high
                                    }
                                }
                            } else {
                                high
                            }
                        }
                        _ => return Err(ParseError::Invalid),
                    });
                }
                0..=0x1f => return Err(ParseError::Invalid),
                0x20..=0x7f => output.push(u32::from(byte)),
                _ => {
                    let character = self.source[self.at - 1..].chars().next().unwrap();
                    self.at += character.len_utf8() - 1;
                    output.push(u32::from(character));
                }
            }
        }
    }
}

fn quote_json(value: &[u32], output: &mut Vec<u32>) {
    output.push(u32::from('"'));
    for code in value {
        let escaped = match *code {
            0x22 => Some("\\\"".to_owned()),
            0x5c => Some("\\\\".to_owned()),
            8 => Some("\\b".to_owned()),
            12 => Some("\\f".to_owned()),
            10 => Some("\\n".to_owned()),
            13 => Some("\\r".to_owned()),
            9 => Some("\\t".to_owned()),
            0..=0x1f => Some(format!("\\u{code:04x}")),
            _ => None,
        };
        if let Some(escaped) = escaped {
            output.extend(escaped.chars().map(u32::from));
        } else {
            output.push(*code);
        }
    }
    output.push(u32::from('"'));
}

fn python_number(token: &str) -> Result<String, String> {
    if matches!(token, "NaN" | "Infinity" | "-Infinity") {
        return Ok(token.to_owned());
    }
    if !token.contains(['.', 'e', 'E']) {
        return Ok(if token == "-0" { "0" } else { token }.to_owned());
    }
    let value = token.parse::<f64>().map_err(|error| error.to_string())?;
    if value.is_infinite() {
        return Ok(if value.is_sign_negative() {
            "-Infinity"
        } else {
            "Infinity"
        }
        .into());
    }
    let raw = Number::from_f64(value)
        .ok_or("invalid JSON summary number")?
        .to_string();
    let (negative, unsigned) = raw
        .strip_prefix('-')
        .map_or((false, raw.as_str()), |v| (true, v));
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or(Ok((unsigned, 0_i32)), |(mantissa, exponent)| {
            exponent.parse::<i32>().map(|exponent| (mantissa, exponent))
        })
        .map_err(|error| error.to_string())?;
    let position = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let mut digits = mantissa
        .chars()
        .filter(|character| *character != '.')
        .collect::<String>();
    let leading = digits.bytes().take_while(|byte| *byte == b'0').count();
    digits.drain(..leading);
    let position = position - leading as i32;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    if digits.is_empty() {
        return Ok(if negative { "-0.0" } else { "0.0" }.into());
    }
    let exponent = position - 1;
    let mut result = if negative {
        "-".to_owned()
    } else {
        String::new()
    };
    if (-4..16).contains(&exponent) {
        if position <= 0 {
            result.push_str("0.");
            result.extend(std::iter::repeat_n('0', (-position) as usize));
            result.push_str(&digits);
        } else if position as usize >= digits.len() {
            result.push_str(&digits);
            result.extend(std::iter::repeat_n('0', position as usize - digits.len()));
            result.push_str(".0");
        } else {
            let split = position as usize;
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
        result.push_str(&format!("{:02}", exponent.unsigned_abs()));
    }
    Ok(result)
}

#[cfg(all(test, unix))]
use crate::test_harness as harness;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn facts() -> Value {
        json!({
            "location":hex::encode(b"/tmp/permit-vault"),
            "environment":"dev","provider":"example","provider_digest":"0".repeat(64),
            "signer":"owner-ed25519-v1","owner_key_id":"owner","local_approval_id":"12",
            "method":"POST","url":"https://example.test/write",
            "header_names":["authorization","x-example"],"body_length":0,
            "body_present":true,"body_sha256":"1".repeat(64),
            "grant_id":null,"run_id":null,
            "request_id":"permit_request_0123456789abcdef0123456789abcdef",
            "permit_id":"permit_0123456789abcdef0123456789abcdef",
            "session_nonce":"2".repeat(64),"expires_at_epoch":1767225600
        })
    }

    #[test]
    fn visible_escaping_and_surrogateescaped_paths_keep_exact_values() {
        assert_eq!(
            escape_text("a\n\t\r\\\u{7f}é😀", 100).unwrap(),
            r"a\n\t\r\\\u007f\u00e9\U0001f600"
        );
        assert!(escape_text("😀", 9).is_err());
        assert_eq!(escape_text("😀", 10).unwrap(), r"\U0001f600");
        let mut facts = facts();
        facts["location"] = json!(hex::encode(b"/v/\xff\xc3(\x80\xe2\x82"));
        let lines = render_review(&facts, "", &Map::new()).unwrap();
        assert_eq!(
            lines[1],
            r"Vault folder: /v/\udcff\udcc3(\udc80\udce2\udc82"
        );
        assert_eq!(lines[lines.len() - 2], "Expires: 2026-01-01T00:00:00+00:00");
    }

    #[test]
    fn per_field_and_complete_card_limits_refuse_without_truncation() {
        let mut facts = facts();
        facts["url"] = json!("x".repeat(MAX_SHOWN));
        assert!(validate_review(&facts, "", &Map::new()).is_ok());
        facts["url"] = json!("x".repeat(MAX_SHOWN + 1));
        assert!(validate_review(&facts, "", &Map::new()).is_err());
        facts["url"] = json!("https://example.test/write");
        let baseline = render_review(&facts, "x", &Map::new())
            .unwrap()
            .join("\n")
            .len()
            - 1;
        let body = "x".repeat(MAX_PROMPT_SHOWN - baseline);
        assert_eq!(
            render_review(&facts, &body, &Map::new())
                .unwrap()
                .join("\n")
                .len(),
            MAX_PROMPT_SHOWN
        );
        assert!(validate_review(&facts, &(body + "x"), &Map::new()).is_err());
    }

    #[test]
    fn python_json_summary_preserves_order_surrogates_nonfinite_and_spacing() {
        let body =
            r#"{"z":1,"a":{"z":"é","a":[1e-7,-0.0,NaN,Infinity,1e999]},"z":2,"\ud800":"\udfff"}"#;
        let lines = render_review(&facts(), body, &Map::new()).unwrap();
        let summary = lines
            .iter()
            .find(|line| line.starts_with("JSON fields:"))
            .unwrap();
        assert_eq!(
            summary,
            r#"JSON fields: z=2, a={"a": [1e-07, -0.0, NaN, Infinity, Infinity], "z": "\u00e9"}, \ud800=\udfff"#
        );
        let nested = format!("{{\"value\":{}0{}}}", "[".repeat(160), "]".repeat(160));
        assert!(
            render_review(&facts(), &nested, &Map::new())
                .unwrap()
                .iter()
                .any(|line| line == "JSON fields: value=<long value; see exact body>")
        );
        let too_deep = format!("{}0{}", "[".repeat(1001), "]".repeat(1001));
        assert!(validate_review(&facts(), &too_deep, &Map::new()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn complete_permit_review_cards_match_python() {
        let Some(python) = kv_test_support::python_reference() else {
            return;
        };
        let bodies = [
            "".to_owned(), "ordinary text".to_owned(), "[]".to_owned(), "{}".to_owned(),
            r#"{"z":1,"a":{"z":"é","a":[1e-7,-0.0,NaN,Infinity,1e999]},"z":2,"\ud800":"\udfff"}"#.to_owned(),
            r#"{"quoted":"a\n\t\r\\b","null":null,"bool":true,"large":123456789012345678901234567890,"zero":-0}"#.to_owned(),
            "{\"control\":\"\u{7f}\",\"emoji\":\"😀\"}".to_owned(),
            r#"{"bad":NaN1}"#.to_owned(),
            format!("{{\"large\":{}}}", "7".repeat(4301)),
            format!("{{\"value\":{}0{}}}", "[".repeat(160), "]".repeat(160)),
            format!("{{\"{}\":\"{}\"}}", "k".repeat(81), "v".repeat(121)),
            r#"{"0":0,"1":1,"2":2,"3":3,"4":4,"5":5,"6":6,"7":7,"8":8}"#.to_owned(),
            format!("{{\"spaced\": [{}]}}", vec!["0"; 12_000].join(",")),
            "x".repeat(MAX_PROMPT_SHOWN),
            "é".repeat(6000),
        ];
        let mut cases = bodies
            .into_iter()
            .map(|body| {
                json!({
                    "facts":facts(),"body_text":body,"caller_headers":{"z":"last","A":"first"}
                })
            })
            .collect::<Vec<_>>();
        let mut path_case = facts();
        path_case["location"] = json!(hex::encode(b"/v/\xff\xc3(\x80\xe2\x82"));
        cases.push(json!({"facts":path_case,"body_text":"","caller_headers":{}}));
        let mut field_case = facts();
        field_case["url"] = json!("x".repeat(MAX_SHOWN + 1));
        cases.push(json!({"facts":field_case,"body_text":"","caller_headers":{}}));
        let mut command = std::process::Command::new(python);
        command.args(["-I", "-c", r#"
import json,sys
from kv.approval_render import render_permit_request
out=[]
for case in json.load(sys.stdin):
    try:
        out.append({"ok":render_permit_request({"facts":case["facts"],"body_text":case["body_text"],"caller_headers":case["caller_headers"]})})
    except (ValueError,TypeError) as exc:
        out.append({"error":str(exc)})
print(json.dumps(out))
"#]);
        let output = harness::output(
            command,
            &serde_json::to_vec(&cases).unwrap(),
            std::time::Duration::from_secs(20),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(expected.len(), cases.len());
        for (index, (case, expected)) in cases.iter().zip(expected).enumerate() {
            let result = render_review(
                &case["facts"],
                case["body_text"].as_str().unwrap(),
                case["caller_headers"].as_object().unwrap(),
            );
            let actual = match result {
                Ok(lines) => json!({"ok":lines}),
                Err(error) => json!({"error":error}),
            };
            assert_eq!(actual, expected, "permit review case {index}");
        }
    }

    /// Deliberate divergence: Python's accepted depth and uncaught recursion
    /// errors depend on its runtime and call stack. Rust always refuses more
    /// than 1000 containers, including bodies newer Python runtimes accept.
    #[cfg(unix)]
    #[test]
    fn excessive_depth_deliberately_refuses_instead_of_python_recursion_error() {
        let Some(python) = kv_test_support::python_reference() else {
            return;
        };
        let mut command = std::process::Command::new(python);
        command.args([
            "-I",
            "-c",
            r#"
import json,sys
from types import SimpleNamespace
from kv import agent
from kv.approval_verify import GrantRegistry
provider={"base_url":"https://example.test","secret_name":"TOKEN","auth_type":"bearer"}
def attempt(depth):
    body="["*depth+"0"+"]"*depth
    registry=GrantRegistry()
    trust=SimpleNamespace(protected=True, observe=lambda:None,
        location=b"/tmp/permit-vault", local_approval_id=b"\x12", owner_key_id="owner",
        session_nonce=b"\x22"*32, provider_snapshot={"example":provider},
        grant_registry=registry)
    calls=[]
    def preview(**kwargs):
        assert kwargs["preview_only"] is True
        calls.append(True)
        return {"preview":{"method":"POST","url":"https://example.test/write",
            "header_names":[],"body_bytes":body.encode()}}
    original=agent._providers_module
    agent._providers_module=lambda:SimpleNamespace(make_api_call=preview)
    try:
        try:
            response,_,_=agent._prepare_api_permit(trust,
                {"provider":"example","method":"POST","path":"/write","body":body},
                provider,"fixture-secret","dev",None)
            outcome=response["error_code"]
        except RecursionError:
            outcome="RecursionError"
    finally:
        agent._providers_module=original
    return {"outcome":outcome,"pending":len(registry.pending_permits()),"previews":len(calls)}
low,high=160,16384
assert attempt(low)["outcome"] == "permit_required"
assert attempt(high)["outcome"] != "permit_required"
while high-low>1:
    mid=(low+high)//2
    if attempt(mid)["outcome"]=="permit_required": low=mid
    else: high=mid
print(json.dumps({"python":list(sys.version_info[:2]),
    "recursion_limit":sys.getrecursionlimit(),"deep":attempt(1001),
    "last_ok_depth":low,"last_ok":attempt(low),
    "first_error_depth":high,"first_error":attempt(high)}))
"#,
        ]);
        let output = harness::output(command, b"", std::time::Duration::from_secs(20)).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let observed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(observed["recursion_limit"], 1000);
        let accepted = json!({"outcome":"permit_required","pending":1,"previews":1});
        let recursive = json!({"outcome":"RecursionError","pending":0,"previews":1});
        let refused = json!({"outcome":"permit_request_refused","pending":0,"previews":1});
        assert!(observed["deep"] == accepted || observed["deep"] == recursive);
        assert!(observed["first_error"] == recursive || observed["first_error"] == refused);
        assert_eq!(observed["last_ok"], accepted);
        let first_error = observed["first_error_depth"].as_u64().unwrap();
        let last_ok = observed["last_ok_depth"].as_u64().unwrap();
        assert_eq!(first_error, last_ok + 1);
        assert!((161..=16384).contains(&first_error));
        if observed["python"] == json!([3, 10]) {
            // The canonical runtime fails at depth1001, whereas newer runtimes
            // may accept it and encounter a different recursion/display limit.
            assert_eq!(observed["deep"], recursive);
            assert_eq!(observed["first_error"], recursive);
            assert!((901..=1001).contains(&first_error));
        }
        eprintln!("Python permit helper depth boundary: {observed}");

        let boundary = format!("{}0{}", "[".repeat(1000), "]".repeat(1000));
        assert!(validate_review(&facts(), &boundary, &Map::new()).is_ok());
        let body = format!("{}0{}", "[".repeat(1001), "]".repeat(1001));
        assert_eq!(
            validate_review(&facts(), &body, &Map::new()).unwrap_err(),
            "JSON nesting exceeds the permit review limit"
        );
        let provider = json!({
            "base_url":"https://example.test","secret_name":"TOKEN","auth_type":"bearer"
        });
        let binding = crate::permit_session::SessionBinding {
            protected: true,
            owner_public_key: None,
            owner_key_id: "owner".into(),
            local_approval_id: vec![0x12],
            location: b"/tmp/permit-vault".to_vec(),
            session_nonce: [0x22; 32],
            providers: std::sync::Arc::new(std::collections::BTreeMap::from([(
                "example".into(),
                provider.clone(),
            )])),
        };
        let headers = Map::new();
        let call = crate::permit_session::CallFacts {
            environment: "dev",
            provider: "example",
            provider_definition: &provider,
            method: "POST",
            url: "https://example.test/write",
            header_names: &[],
            caller_headers: &headers,
            body_bytes: Some(body.as_bytes()),
        };
        let session = crate::permit_session::SessionPermits::new(binding);
        let error = session
            .request(call, None)
            .err()
            .expect("deep body refused");
        assert_eq!(error.code, "refused");
        assert_eq!(error.message, "body or call cannot be shown in full safely");
        assert!(session.pending().is_empty());
    }
}
