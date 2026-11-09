//! `kv/approval_render.py`'s `escape` / `escape_or_marker`: what a stored name looks like
//! on the owner's terminal. Every non-ASCII or control character is a visible escape.

pub const MAX_SHOWN: usize = 8192;
pub const VALUE_NOT_SHOWN: &str = "<this value is too long to be shown safely>";

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

pub fn has_hidden(value: &str) -> bool {
    value.chars().any(|c| !(' '..='~').contains(&c))
}

pub fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

pub fn run_again_text(argv: &[String]) -> String {
    if !argv.iter().any(|s| has_hidden(s)) {
        return argv
            .iter()
            .map(|s| shell_quote(s))
            .collect::<Vec<_>>()
            .join(" ");
    }
    let parts = argv
        .iter()
        .map(|part| {
            let mut shown = escape(part);
            if shown.is_empty() || shown.contains([' ', '\'', '"']) {
                shown = format!("⟨{shown}⟩");
            }
            if shown.chars().count() > MAX_SHOWN {
                shown = format!("⟨{VALUE_NOT_SHOWN}⟩");
            }
            shown
        })
        .collect::<Vec<_>>();
    format!(
        "{}  (hidden characters are shown as escapes; the line cannot be copied as is)",
        parts.join(" ")
    )
}

pub fn split_command(command: &str) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut quote = None;
    let mut active = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == '\\' && q == '"' {
                let next = chars.next()?;
                if next != '"' && next != '\\' {
                    part.push('\\');
                }
                part.push(next);
            } else {
                part.push(c);
            }
        } else if c == '\'' || c == '"' {
            active = true;
            quote = Some(c);
        } else if c == '\\' {
            active = true;
            part.push(chars.next()?);
        } else if " \t\r\n".contains(c) {
            if active {
                parts.push(std::mem::take(&mut part));
                active = false;
            }
        } else {
            active = true;
            part.push(c);
        }
    }
    if quote.is_some() {
        return None;
    }
    if active {
        parts.push(part);
    }
    Some(parts)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_parts_round_trip() {
        for argv in [vec![], vec![""], vec!["kv", "a'b", "a\\b", "世界\n", "⟨x⟩"]] {
            let argv: Vec<String> = argv.into_iter().map(str::to_owned).collect();
            let command = argv
                .iter()
                .map(|s| shell_quote(s))
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(split_command(&command), Some(argv));
        }
        assert_eq!(split_command("'unclosed"), None);
        assert_eq!(split_command("trailing\\"), None);
        assert_eq!(split_command("\"a\\qb\""), Some(vec!["a\\qb".to_owned()]));
    }

    #[test]
    fn hidden_parts_are_not_copyable() {
        assert_eq!(run_again_text(&[]), "");
        assert_eq!(run_again_text(&["a'b".into()]), "'a'\"'\"'b'");
        assert_eq!(
            run_again_text(&["a\n⟨".into(), "".into()]),
            "a\\n\\u27e8 ⟨⟩  (hidden characters are shown as escapes; the line cannot be copied as is)"
        );
        assert!(
            run_again_text(&[format!("\n{}", "x".repeat(MAX_SHOWN))])
                .starts_with(&format!("⟨{VALUE_NOT_SHOWN}⟩"))
        );
    }
}
