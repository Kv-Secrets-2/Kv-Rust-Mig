//! `kv.sandbox.redact` as the MCP server applies it to kv_run validation
//! errors: each caller word and its common encodings replaced, longest first,
//! by sequential `str.replace`.

use base64::Engine;
use indexmap::IndexSet;

fn add(variants: &mut IndexSet<String>, candidate: String, min_len: usize) {
    if !candidate.is_empty() && candidate.chars().count() >= min_len {
        variants.insert(candidate);
    }
}

fn chunked(value: &str, separator: &str) -> String {
    value
        .as_bytes()
        .chunks(76)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(separator)
}

fn add_base64_family(variants: &mut IndexSet<String>, encoded: String) {
    let unpadded = encoded.trim_end_matches('=').to_owned();
    add(variants, encoded.clone(), 8);
    add(variants, unpadded.clone(), 8);
    if encoded.len() > 76 {
        add(variants, chunked(&encoded, "\n"), 8);
        add(variants, chunked(&encoded, "\r\n"), 8);
        add(variants, chunked(&unpadded, "\n"), 8);
        add(variants, chunked(&unpadded, "\r\n"), 8);
    }
}

fn quote(value: &str, plus_for_space: bool) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~".contains(&byte) {
            out.push(char::from(byte));
        } else if byte == b' ' && plus_for_space {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn lowercase_escapes(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%'
            && index + 2 < chars.len()
            && chars[index + 1..=index + 2]
                .iter()
                .all(|ch| ch.is_ascii_digit() || ('A'..='F').contains(ch))
        {
            out.push('%');
            out.push(chars[index + 1].to_ascii_lowercase());
            out.push(chars[index + 2].to_ascii_lowercase());
            index += 3;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

/// The strings `redact` replaces for these words, longest first.
pub fn needles<'a>(words: impl IntoIterator<Item = &'a str> + Clone) -> Vec<String> {
    let mut variants = IndexSet::new();
    for word in words.clone() {
        if word.chars().count() >= 4 {
            variants.insert(word.to_owned());
        }
    }
    for word in words {
        if word.is_empty() || word.chars().count() < 4 {
            continue;
        }
        add(&mut variants, word.to_owned(), 4);
        add_base64_family(
            &mut variants,
            base64::engine::general_purpose::STANDARD.encode(word.as_bytes()),
        );
        add_base64_family(
            &mut variants,
            base64::engine::general_purpose::URL_SAFE.encode(word.as_bytes()),
        );
        add(&mut variants, hex::encode(word.as_bytes()), 8);
        for encoded in [quote(word, false), quote(word, true)] {
            let lower = lowercase_escapes(&encoded);
            add(&mut variants, encoded, 4);
            add(&mut variants, lower, 4);
        }
        add(&mut variants, word.chars().rev().collect(), 4);
    }
    let mut sorted: Vec<String> = variants.into_iter().collect();
    sorted.sort_by_key(|needle| std::cmp::Reverse(needle.chars().count()));
    sorted
}

pub fn redact<'a>(text: &str, words: impl IntoIterator<Item = &'a str> + Clone) -> String {
    let mut text = text.to_owned();
    for needle in needles(words) {
        text = text.replace(&needle, "[REDACTED]");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_words_and_encodings_sequentially() {
        assert_eq!(
            redact("argv[0] must not be empty must", ["must"]),
            "argv[0] [REDACTED] not be empty [REDACTED]"
        );
        assert_eq!(redact("abc", ["abc"]), "abc");
        assert_eq!(redact("x dGVzdHM= y", ["tests"]), "x [REDACTED] y");
        assert_eq!(redact("a%2fb%2fc", ["a/b/c"]), "[REDACTED]");
    }
}
