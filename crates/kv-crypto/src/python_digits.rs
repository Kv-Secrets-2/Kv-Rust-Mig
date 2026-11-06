//! Python 3.10 `str.isdigit` compatibility for the canonical Unicode 13 baseline.
//!
//! `char::is_numeric` also accepts fractions and Roman numerals. ASCII-only
//! checks miss superscript, circled, mathematical, and non-ASCII decimal digits.
//! The generated table pins the precise predicate independently of Rust's
//! Unicode database. Newly added Unicode digits are a separate compatibility
//! decision; this does not claim equality with every newer Python database.

include!("python_digit_ranges.rs");

pub(crate) fn is_digit(character: char) -> bool {
    let point = u32::from(character);
    let end = DIGIT_RANGES.partition_point(|&(start, _)| start <= point);
    end != 0 && point <= DIGIT_RANGES[end - 1].1
}

#[cfg(test)]
mod tests {
    use super::{DIGIT_RANGES, is_digit};
    use crate::passphrase_strength;
    use std::collections::BTreeSet;
    use std::io::Write;
    use std::process::{Command, Stdio};

    const NUMERIC_REFUSAL: (bool, &str) = (
        false,
        "all-digit passphrases under 16 characters are too weak",
    );

    #[test]
    fn passphrase_strength_unicode_regressions() {
        // Numeric values that are not digits must not enter the all-digit rule.
        for non_digit in ['Ⅻ', '½', '一', '⑩', '㊿'] {
            assert_eq!(
                passphrase_strength(&format!("12345678901{non_digit}")),
                (true, ""),
                "non-digit U+{:04X}",
                u32::from(non_digit)
            );
        }
        // str.isdigit is broader than ASCII or the Unicode decimal category.
        for digit in ['²', '①', '𝟙', '٤', '۵', '１', '\u{10E60}', '\u{1FBF9}'] {
            assert_eq!(
                passphrase_strength(&format!("12345678901{digit}")),
                NUMERIC_REFUSAL,
                "digit U+{:04X}",
                u32::from(digit)
            );
        }
    }

    #[test]
    fn passphrase_strength_unicode_length_and_rule_precedence() {
        assert_eq!(
            passphrase_strength("１２３４５６７８９０１"),
            (false, "passphrase must be at least 12 characters")
        );
        for passphrase in ["１２３４５６７８９０１２", "１２３４５６７８９０１２３４５"]
        {
            assert_eq!(passphrase_strength(passphrase), NUMERIC_REFUSAL);
        }
        assert_eq!(
            passphrase_strength("１２３４５６７８９０１２３４５６"),
            (true, "")
        );
        assert_eq!(
            passphrase_strength("①①①①①①①①①①①①"),
            (false, "passphrase cannot be a single repeated character")
        );
        assert_eq!(
            passphrase_strength("1234567890"),
            (
                false,
                "this passphrase is too common — it appears in breach databases"
            )
        );
        assert_eq!(passphrase_strength("12345678901a"), (true, ""));
    }

    #[test]
    fn python_digit_table_boundaries_and_order() {
        let mut previous_end = None;
        for &(start, end) in DIGIT_RANGES {
            assert!(start <= end);
            if let Some(previous) = previous_end {
                assert!(previous + 1 < start, "ranges must be sorted and coalesced");
            }
            for point in start..=end {
                assert!(is_digit(char::from_u32(point).unwrap()), "U+{point:04X}");
            }
            assert!(!is_digit(char::from_u32(start - 1).unwrap()));
            assert!(!is_digit(char::from_u32(end + 1).unwrap()));
            previous_end = Some(end);
        }
        assert!(!is_digit('\0'));
        assert!(!is_digit(char::MAX));
    }

    #[test]
    fn passphrase_strength_matches_python_reference_digit_corpus() {
        let Some(python) = kv_test_support::python_reference() else {
            return;
        };
        // Every canonical digit, all range neighbours, and the boundary cases
        // below are stable across the supported reference runtimes. The
        // generator's --check separately exhausts all codepoints on Python 3.10.
        let mut cases = BTreeSet::new();
        for &(start, end) in DIGIT_RANGES {
            for point in start - 1..=end + 1 {
                cases.insert(format!("12345678901{}", char::from_u32(point).unwrap()));
            }
        }
        for value in [
            "12345678901Ⅻ",
            "12345678901½",
            "12345678901一",
            "12345678901⑩",
            "12345678901㊿",
            "12345678901a",
            "１２３４５６７８９０１",
            "１２３４５６７８９０１２",
            "１２３４５６７８９０１２３４５",
            "１２３４５６７８９０１２３４５６",
            "①①①①①①①①①①①①",
            "1234567890",
            "",
        ] {
            cases.insert(value.to_owned());
        }
        let cases: Vec<_> = cases.into_iter().collect();
        let mut child = Command::new(python)
            .args([
                "-I", "-c",
                "import json, sys\nfrom kv.crypto import check_passphrase_strength\njson.dump([check_passphrase_strength(p) for p in json.load(sys.stdin)], sys.stdout)",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start configured Python reference");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&cases).unwrap())
            .unwrap();
        let output = child.wait_with_output().expect("wait for Python reference");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<(bool, String)> =
            serde_json::from_slice(&output.stdout).expect("Python passphrase result array");
        assert_eq!(expected.len(), cases.len(), "all cases must execute");
        for (passphrase, (accepted, reason)) in cases.iter().zip(expected) {
            assert_eq!(
                passphrase_strength(passphrase),
                (accepted, reason.as_str()),
                "{passphrase:?}"
            );
        }
        eprintln!(
            "Python passphrase differential comparisons: {}",
            cases.len()
        );
    }
}
