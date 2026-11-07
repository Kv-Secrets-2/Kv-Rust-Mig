//! Output redaction (Python `kv/sandbox.py`: `redact`, `redaction_needles`,
//! `build_secret_variants`). Lengths are counted in characters, as Python's
//! `len` does, and a variant keeps the position of its first insertion.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};

pub const REDACTED: &str = "[REDACTED]";

/// Python `build_secret_variants` defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariantLimits {
    pub min_secret_len: usize,
    pub min_encoded_len: usize,
    pub min_hex_len: usize,
    pub min_reversed_len: usize,
}

impl Default for VariantLimits {
    fn default() -> Self {
        Self {
            min_secret_len: 8,
            min_encoded_len: 12,
            min_hex_len: 16,
            min_reversed_len: 8,
        }
    }
}

impl VariantLimits {
    /// The limits `redaction_needles` uses.
    pub const REDACTION: Self = Self {
        min_secret_len: 4,
        min_encoded_len: 8,
        min_hex_len: 8,
        min_reversed_len: 4,
    };
}

/// An insertion-ordered `variant -> secret name` map (a Python dict).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Variants {
    entries: Vec<(String, String)>,
}

impl Variants {
    fn add(&mut self, candidate: String, name: &str, min_len: usize) {
        if candidate.is_empty() || candidate.chars().count() < min_len {
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|(key, _)| *key == candidate) {
            entry.1 = name.to_owned();
        } else {
            self.entries.push((candidate, name.to_owned()));
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `(variant, secret_name)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The first variant found in `window`, with its secret's name.
    pub fn find_in(&self, window: &str) -> Option<(&str, &str)> {
        self.iter().find(|(variant, _)| window.contains(variant))
    }
}

fn add_base64_family(variants: &mut Variants, encoded: &str, name: &str, min_encoded_len: usize) {
    variants.add(encoded.to_owned(), name, min_encoded_len);
    let unpadded = encoded.trim_end_matches('=');
    variants.add(unpadded.to_owned(), name, min_encoded_len);
    if encoded.len() > 76 {
        for text in [encoded, unpadded] {
            let lines: Vec<&str> = text
                .as_bytes()
                .chunks(76)
                .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
                .collect();
            variants.add(lines.join("\n"), name, min_encoded_len);
            variants.add(lines.join("\r\n"), name, min_encoded_len);
        }
    }
}

/// `urllib.parse.quote(value, safe="")`: only `A-Za-z0-9_.-~` stay literal.
pub fn percent_quote(value: &str, plus_for_space: bool) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(byte as char);
            }
            b' ' if plus_for_space => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn lowercase_escapes(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = String::with_capacity(encoded.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1..i + 3]
                .iter()
                .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase() && b.is_ascii_hexdigit())
        {
            out.push('%');
            out.push(bytes[i + 1].to_ascii_lowercase() as char);
            out.push(bytes[i + 2].to_ascii_lowercase() as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Python `build_secret_variants`: plaintext and common encodings of each
/// secret value, in Python's insertion order.
pub fn build_secret_variants<'a, I>(secrets: I, limits: VariantLimits) -> Variants
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut variants = Variants::default();
    for (name, value) in secrets {
        if value.is_empty() || value.chars().count() < limits.min_secret_len {
            continue;
        }
        variants.add(value.to_owned(), name, limits.min_secret_len);
        add_base64_family(
            &mut variants,
            &STANDARD.encode(value.as_bytes()),
            name,
            limits.min_encoded_len,
        );
        add_base64_family(
            &mut variants,
            &URL_SAFE.encode(value.as_bytes()),
            name,
            limits.min_encoded_len,
        );
        variants.add(hex::encode(value.as_bytes()), name, limits.min_hex_len);
        for encoded in [percent_quote(value, false), percent_quote(value, true)] {
            let lowered = lowercase_escapes(&encoded);
            variants.add(encoded, name, limits.min_secret_len);
            variants.add(lowered, name, limits.min_secret_len);
        }
        variants.add(value.chars().rev().collect(), name, limits.min_reversed_len);
    }
    variants
}

/// Python `redaction_needles`: the strings `redact` replaces, longest first.
pub fn redaction_needles<'a, I>(secrets: I) -> Vec<String>
where
    I: IntoIterator<Item = (&'a str, &'a str)> + Clone,
{
    let mut variants = Variants::default();
    for (name, value) in secrets.clone() {
        if !value.is_empty() && value.chars().count() >= 4 {
            variants.add(value.to_owned(), name, 0);
        }
    }
    for (variant, name) in build_secret_variants(secrets, VariantLimits::REDACTION).iter() {
        variants.add(variant.to_owned(), name, 0);
    }
    let mut needles: Vec<String> = variants.entries.into_iter().map(|(k, _)| k).collect();
    needles.sort_by_key(|needle| std::cmp::Reverse(needle.chars().count()));
    needles
}

/// Python `redact`: replace secret values and their encoded variants.
pub fn redact<'a, I>(text: &str, secrets: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str)> + Clone,
{
    let mut text = text.to_owned();
    for needle in redaction_needles(secrets) {
        text = text.replace(&needle, REDACTED);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_needle_wins_and_short_values_are_kept() {
        let secrets = [
            ("A", "sk-abc123"),
            ("B", "sk-abc123-extended"),
            ("C", "abc"),
        ];
        let out = redact("x sk-abc123-extended y sk-abc123 abc", secrets);
        assert_eq!(out, "x [REDACTED] y [REDACTED] abc");
    }

    #[test]
    fn encoded_forms_are_redacted() {
        let secrets = [("K", "hunter2!")];
        let b64 = STANDARD.encode(b"hunter2!");
        let text = format!(
            "{b64} {} {} !2retnuh",
            hex::encode(b"hunter2!"),
            "hunter2%21"
        );
        assert_eq!(
            redact(&text, secrets),
            "[REDACTED] [REDACTED] [REDACTED] [REDACTED]"
        );
        assert_eq!(percent_quote("a b/c", true), "a+b%2Fc");
        assert_eq!(lowercase_escapes("a%2Fb%zz%2f"), "a%2fb%zz%2f");
    }
}
