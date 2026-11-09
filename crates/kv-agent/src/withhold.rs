//! Error text the daemon may send back (Python `agent.py` `_caller_strings`,
//! `_verbatim_strings`, `_covered`, `_withhold_text`, `_safe_error_text`).
//!
//! Every outer handler formats exception text through this, so redaction does
//! not depend on the exception type. The caller's own strings are masked first
//! (as `<your input>`), so what comes back never depends on whether a caller
//! string matches a vault value: a caller cannot use an error message as an
//! oracle for a secret. Vault values and issued tokens are `[REDACTED]`. A
//! verbatim span (a secret name the caller asked for) is shown as written.

use std::collections::BTreeSet;

use kv_sandbox::runenv::escape_checked;
use serde_json::Value;

pub(crate) const CALLER_TEXT_MARK: &str = "<your input>";
const CALLER_TEXT_MIN: usize = 4;
const UNMASKED_WORDS: [&str; 10] = [
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "true", "false", "null",
];
const FREE_FORM_KEYS: [&str; 4] = ["calls_per_service", "headers", "body", "env_vars"];
pub(crate) const WITHHELD: &str = "the request was refused (details withheld)";

/// Python `json.dumps(text)[1:-1]` (ensure_ascii).
fn json_inner(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Python `repr(text)[1:-1]`.
fn repr_inner(text: &str) -> String {
    let single_quotes = text.contains('\'') && !text.contains('"');
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' if !single_quotes => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

fn add_forms(out: &mut BTreeSet<String>, part: &str) {
    out.insert(part.to_owned());
    out.insert(json_inner(part));
    out.insert(repr_inner(part));
    if let Some(escaped) = escape_checked(part) {
        out.insert(escaped);
    }
}

fn longest_first(set: BTreeSet<String>, min_len: usize) -> Vec<String> {
    let mut items: Vec<String> = set.into_iter().filter(|s| s.len() >= min_len).collect();
    items.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    items
}

/// Python `_verbatim_strings`: a run's validated secret names, as written and
/// as kv's renderers escape them.
pub(crate) fn verbatim_strings(names: Option<&Value>) -> Vec<String> {
    let mut out = BTreeSet::new();
    if let Some(Value::Array(items)) = names {
        for name in items.iter().filter_map(Value::as_str) {
            if !name.is_empty() {
                add_forms(&mut out, name);
            }
        }
    }
    longest_first(out, 0)
}

fn py_number(value: &serde_json::Number) -> String {
    if let Some(i) = value.as_i64() {
        return i.to_string();
    }
    if let Some(u) = value.as_u64() {
        return u.to_string();
    }
    match value.as_f64() {
        Some(f) if f.fract() == 0.0 && f.abs() < 1e16 => format!("{f:.1}"),
        Some(f) => f.to_string(),
        None => value.to_string(),
    }
}

/// Python `_caller_strings`: every string value anywhere in the request
/// (numbers as written too), keys inside its free-form maps, and the path
/// parts and words inside them, as written and as kv's renderers escape
/// them. Only the request's own `cmd` and `method` keep kv's words unmasked.
pub(crate) fn caller_strings(request: &Value, known_commands: &[&str]) -> Vec<String> {
    let mut leaves: Vec<(String, bool)> = Vec::new();
    let mut stack: Vec<(&Value, bool, bool)> = vec![(request, false, false)];
    while let Some((item, free, vocabulary_ok)) = stack.pop() {
        match item {
            Value::Object(map) => {
                for (key, value) in map {
                    if free {
                        leaves.push((key.clone(), false));
                    }
                    stack.push((
                        value,
                        free || FREE_FORM_KEYS.contains(&key.as_str()),
                        std::ptr::eq(item, request) && (key == "cmd" || key == "method"),
                    ));
                }
            }
            Value::Array(items) => stack.extend(items.iter().map(|v| (v, free, false))),
            Value::Bool(_) | Value::Null => {}
            Value::Number(number) => leaves.push((py_number(number), false)),
            Value::String(text) => leaves.push((text.clone(), vocabulary_ok)),
        }
    }
    let mut out = BTreeSet::new();
    for (leaf, vocabulary_ok) in leaves {
        let mut parts: BTreeSet<&str> = BTreeSet::new();
        parts.insert(leaf.as_str());
        parts.extend(leaf.split(|c: char| {
            matches!(c, '\\' | '/' | '=' | ':' | ',' | ';' | '\'' | '"') || c.is_whitespace()
        }));
        for part in parts {
            if part.chars().count() < CALLER_TEXT_MIN {
                continue;
            }
            if vocabulary_ok && (known_commands.contains(&part) || UNMASKED_WORDS.contains(&part)) {
                continue;
            }
            add_forms(&mut out, part);
        }
    }
    longest_first(out, CALLER_TEXT_MIN)
}

/// Python `_covered`: a byte mask of every occurrence of every needle.
fn covered(text: &str, needles: &[String]) -> Vec<bool> {
    let mut marks = vec![false; text.len()];
    for needle in needles.iter().filter(|n| !n.is_empty()) {
        let mut from = 0;
        while let Some(found) = text[from..].find(needle.as_str()) {
            let start = from + found;
            let end = start + needle.len();
            marks[start..end].iter_mut().for_each(|m| *m = true);
            from = start + 1;
            if from > text.len() {
                break;
            }
            while !text.is_char_boundary(from) {
                from += 1;
            }
        }
    }
    marks
}

/// Python `_withhold_text`.
pub(crate) fn withhold_text(
    text: &str,
    caller: &[String],
    secret_needles: &[String],
    verbatim: &[String],
) -> String {
    let keep = covered(text, verbatim);
    let caller_only: Vec<String> = caller
        .iter()
        .filter(|s| !verbatim.contains(s))
        .cloned()
        .collect();
    let mut caller_marks = covered(text, &caller_only);
    for (mark, kept) in caller_marks.iter_mut().zip(&keep) {
        if *kept {
            *mark = false;
        }
    }
    let mut secret = vec![false; text.len()];
    for needle in secret_needles.iter().filter(|n| !n.is_empty()) {
        let mut from = 0;
        while let Some(found) = text[from..].find(needle.as_str()) {
            let start = from + found;
            let end = start + needle.len();
            if !keep[start..end].iter().any(|k| *k) && !caller_marks[start..end].iter().any(|c| *c)
            {
                secret[start..end].iter_mut().for_each(|m| *m = true);
            }
            from = start + 1;
            if from > text.len() {
                break;
            }
            while !text.is_char_boundary(from) {
                from += 1;
            }
        }
    }
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if !(caller_marks[i] || secret[i]) {
            let ch_len = text[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&text[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        let mut j = i;
        let mut has_caller = false;
        while j < bytes.len() && (caller_marks[j] || secret[j]) {
            has_caller |= caller_marks[j];
            j += 1;
        }
        while j < bytes.len() && !text.is_char_boundary(j) {
            j += 1;
        }
        out.push_str(if has_caller {
            CALLER_TEXT_MARK
        } else {
            "[REDACTED]"
        });
        i = j;
    }
    out
}

/// Python `_safe_error_text`: `text` with the caller's strings and every
/// secret needle withheld. A request whose caller strings could not be
/// gathered withholds everything.
pub(crate) fn safe_error_text(
    text: &str,
    caller: Option<&[String]>,
    secret_needles: &[String],
    verbatim: &[String],
) -> String {
    match caller {
        None => WITHHELD.to_owned(),
        Some(caller) => withhold_text(text, caller, secret_needles, verbatim),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn python_string_forms() {
        assert_eq!(json_inner("a\"b\\c\né"), "a\\\"b\\\\c\\n\\u00e9");
        assert_eq!(repr_inner("it's"), "it's");
        assert_eq!(repr_inner("say \"hi\" it's"), "say \"hi\" it\\'s");
        assert_eq!(repr_inner("tab\there"), "tab\\there");
    }

    #[test]
    fn caller_strings_split_paths_and_keep_vocabulary() {
        let request = json!({"cmd": "run", "argv": ["python3", "/home/me/app.py"],
            "env_names": ["TOKEN"], "method": "POST", "n": 1234});
        let strings = caller_strings(&request, &["run"]);
        assert!(strings.contains(&"python3".to_owned()));
        assert!(strings.contains(&"/home/me/app.py".to_owned()));
        assert!(strings.contains(&"home".to_owned()));
        assert!(strings.contains(&"app.py".to_owned()));
        assert!(strings.contains(&"TOKEN".to_owned()));
        assert!(strings.contains(&"1234".to_owned()));
        assert!(!strings.contains(&"POST".to_owned()));
        assert!(!strings.contains(&"run".to_owned()));
        assert!(strings.windows(2).all(|w| w[0].len() >= w[1].len()));
    }

    #[test]
    fn withholds_caller_text_and_secrets_but_shows_verbatim_names() {
        let text =
            "blocked: requested secret not found in environment 'dev': API_KEY (value sk-123456)";
        let caller = vec!["API_KEY".to_owned(), "sk-123456".to_owned()];
        let secrets = vec!["sk-123456".to_owned(), "found".to_owned()];
        let verbatim = vec!["API_KEY".to_owned()];
        assert_eq!(
            withhold_text(text, &caller, &secrets, &verbatim),
            "blocked: requested secret not [REDACTED] in environment 'dev': API_KEY (value <your input>)"
        );
        assert_eq!(safe_error_text("x", None, &[], &[]), WITHHELD);
    }

    #[test]
    fn adjacent_caller_and_secret_spans_merge_into_one_mark() {
        let caller = vec!["abcd".to_owned()];
        let secrets = vec!["efgh".to_owned()];
        assert_eq!(
            withhold_text("say abcdefgh now", &caller, &secrets, &[]),
            "say <your input> now"
        );
        assert_eq!(
            withhold_text("say efgh now", &caller, &secrets, &[]),
            "say [REDACTED] now"
        );
    }
}
