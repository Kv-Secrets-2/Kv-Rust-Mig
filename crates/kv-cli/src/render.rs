//! `kv/approval_render.py`'s `escape` / `escape_or_marker`: what a stored name looks like
//! on the owner's terminal. Every non-ASCII or control character is a visible escape.

const MAX_SHOWN: usize = 8192;
const VALUE_NOT_SHOWN: &str = "<this value is too long to be shown safely>";

fn escape_checked(value: &str) -> Option<String> {
    let mut shown = String::new();
    for ch in value.chars() {
        let code = u32::from(ch);
        match code {
            0x5c => shown.push_str("\\\\"),
            0x0a => shown.push_str("\\n"),
            0x09 => shown.push_str("\\t"),
            0x0d => shown.push_str("\\r"),
            0x20..=0x7e => shown.push(ch),
            0..=0xffff => shown.push_str(&format!("\\u{code:04x}")),
            _ => shown.push_str(&format!("\\U{code:08x}")),
        }
    }
    (shown.len() <= MAX_SHOWN).then_some(shown)
}

/// `escape_or_marker(value)`: read-only surfaces never print a name raw.
pub fn escape(value: &str) -> String {
    escape_checked(value).unwrap_or_else(|| VALUE_NOT_SHOWN.to_owned())
}

/// Python `str.isprintable()`: no character in categories Cc, Cf, Cs, Co, Cn, Zl, Zp or Zs
/// other than the ASCII space.
pub fn is_printable(text: &str) -> bool {
    use unicode_general_category::{GeneralCategory as G, get_general_category};
    text.chars().all(|c| {
        c == ' '
            || !matches!(
                get_general_category(c),
                G::Control
                    | G::Format
                    | G::Surrogate
                    | G::PrivateUse
                    | G::Unassigned
                    | G::LineSeparator
                    | G::ParagraphSeparator
                    | G::SpaceSeparator
            )
    })
}
