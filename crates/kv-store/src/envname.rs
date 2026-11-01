use caseless::default_case_fold_str;
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use crate::StoreError;

const WINDOWS_DEVICES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
];

pub fn has_path_syntax(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return true;
    }
    if name.chars().any(|character| {
        matches!(
            get_general_category(character),
            GeneralCategory::Control | GeneralCategory::Format | GeneralCategory::Surrogate
        ) || matches!(character, '\u{2028}' | '\u{2029}')
    }) {
        return true;
    }

    if name
        .chars()
        .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        || name.ends_with(' ')
        || name.ends_with('.')
    {
        return true;
    }

    let basename = name.split('.').next().unwrap_or_default();
    let device_name = basename.trim_end_matches(' ').to_uppercase();
    if WINDOWS_DEVICES.contains(&device_name.as_str()) {
        return true;
    }

    name == "."
        || name == ".."
        || name
            .chars()
            .any(|character| matches!(character, '/' | '\\'))
        || name
            .replace('\\', "/")
            .split('/')
            .any(|component| component == "..")
}

pub fn validate_env_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() {
        return Err(StoreError::InvalidName(
            "environment name must be a non-empty string".into(),
        ));
    }
    if name.len() > 128 {
        return Err(StoreError::InvalidName(
            "environment name exceeds 128 UTF-8 bytes".into(),
        ));
    }
    if has_path_syntax(name) {
        return Err(StoreError::InvalidName(format!(
            "invalid environment name: {name:?}"
        )));
    }
    Ok(())
}

/// Unicode data versions can differ from Python 3.10's `unicodedata` for newly assigned code points.
pub fn portable_name_key(name: &str) -> String {
    let normalized: String = name.nfc().collect();
    default_case_fold_str(&normalized)
}

pub fn validate_registered_name(name: &str, registered: &[String]) -> Result<(), StoreError> {
    validate_env_name(name)?;
    let key = portable_name_key(name);
    if registered
        .iter()
        .any(|other| other != name && portable_name_key(other) == key)
    {
        return Err(StoreError::InvalidName(format!(
            "ambiguous environment name: {name:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{has_path_syntax, portable_name_key, validate_env_name, validate_registered_name};

    #[test]
    fn rejects_path_and_windows_reserved_forms() {
        let too_long = "x".repeat(129);
        for name in [
            "D:escape",
            "CON",
            "com¹",
            "trailing.",
            "trailing ",
            "..",
            "a/b",
            "a\\b",
            "control\u{0001}",
            "format\u{200e}",
            too_long.as_str(),
        ] {
            assert!(has_path_syntax(name), "{name:?}");
            assert!(validate_env_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn registered_aliases_use_casefold_and_nfc() {
        assert_eq!(portable_name_key("Dev"), portable_name_key("dev"));
        assert_eq!(portable_name_key("é"), portable_name_key("e\u{301}"));
        assert!(validate_registered_name("Dev", &["dev".to_owned()]).is_err());
        assert!(validate_registered_name("é", &["e\u{301}".to_owned()]).is_err());
        assert!(validate_registered_name("Dev", &["Dev".to_owned()]).is_ok());
    }
}
