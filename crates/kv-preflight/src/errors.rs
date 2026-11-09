//! Python exception spelling at the preflight boundary.

use kv_sandbox::identity::IdentityError;

use crate::PreflightError;

pub(crate) fn identity_error(cwd: &str, error: IdentityError) -> PreflightError {
    match error {
        IdentityError::HashDeadline => PreflightError::ValueError(error.to_string()),
        IdentityError::Cwd(message) => match kv_sandbox::paths::resolve(cwd) {
            Err(error) => resolve_error(cwd, error),
            Ok(_) => PreflightError::other("OSError", message),
        },
    }
}

pub(crate) fn resolve_error(cwd: &str, error: std::io::Error) -> PreflightError {
    if cwd.contains('\0') {
        return PreflightError::ValueError("embedded null byte".into());
    }
    #[cfg(unix)]
    {
        locate_resolution_error(cwd, error)
    }
    #[cfg(not(unix))]
    PreflightError::other("OSError", error.to_string())
}

#[cfg(unix)]
fn describe(error: std::io::Error, path: &str) -> PreflightError {
    use std::sync::LazyLock;
    static HIDDEN: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"[\p{C}\p{Z}]").unwrap());
    let quote = if path.contains('\'') && !path.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut shown = quote.to_string();
    for c in path.chars() {
        match c {
            '\\' => shown.push_str("\\\\"),
            '\n' => shown.push_str("\\n"),
            '\r' => shown.push_str("\\r"),
            '\t' => shown.push_str("\\t"),
            c if c == quote => {
                shown.push('\\');
                shown.push(c);
            }
            c if c != ' ' && HIDDEN.is_match(&c.to_string()) => {
                let n = u32::from(c);
                if n <= 0xff {
                    shown.push_str(&format!("\\x{n:02x}"));
                } else if n <= 0xffff {
                    shown.push_str(&format!("\\u{n:04x}"));
                } else {
                    shown.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => shown.push(c),
        }
    }
    shown.push(quote);
    let kind = match error.kind() {
        std::io::ErrorKind::NotADirectory => "NotADirectoryError",
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        _ => "OSError",
    };
    let errno = error.raw_os_error().unwrap_or(5);
    let description = kv_hook::paths::strerror(&error);
    let suffix = format!(" (os error {errno})");
    let description = description.strip_suffix(&suffix).unwrap_or(&description);
    PreflightError::other(kind, format!("[Errno {}] {}: {shown}", errno, description))
}

/// Replay only a failed resolution to recover the filename that `io::Error` drops.
#[cfg(unix)]
fn locate_resolution_error(cwd: &str, original: std::io::Error) -> PreflightError {
    use std::collections::BTreeMap;
    let message = original.to_string();
    let fallback = || PreflightError::other("OSError", message.clone());
    let mut current = if cwd.starts_with('/') {
        "/".to_owned()
    } else {
        match kv_hook::paths::getcwd() {
            Ok(cwd) => cwd,
            Err(_) => return fallback(),
        }
    };
    let mut rest: Vec<Option<String>> = cwd.split('/').rev().map(|s| Some(s.to_owned())).collect();
    let mut count = rest.len();
    let mut seen: BTreeMap<String, Option<String>> = BTreeMap::new();
    while count > 0 {
        let Some(name) = rest.pop() else {
            break;
        };
        let Some(name) = name else {
            if let Some(Some(link)) = rest.pop() {
                seen.insert(link, Some(current.clone()));
            }
            continue;
        };
        count -= 1;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            current = kv_hook::paths::dirname(&current).to_owned();
            continue;
        }
        let candidate = kv_hook::paths::join(&current, &name);
        let meta = match std::fs::symlink_metadata(&candidate) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current = candidate;
                continue;
            }
            Err(error) => return describe(error, &candidate),
        };
        if !meta.file_type().is_symlink() {
            if count > 0 && !meta.is_dir() {
                return describe(original, &candidate);
            }
            current = candidate;
            continue;
        }
        if let Some(resolved) = seen.get(&candidate) {
            match resolved {
                None => return describe(original, &candidate),
                Some(resolved) => {
                    current.clone_from(resolved);
                    continue;
                }
            }
        }
        let target =
            match std::fs::read_link(&candidate).and_then(|p| kv_hook::paths::path_to_string(&p)) {
                Ok(target) => target,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    current = candidate;
                    continue;
                }
                Err(error) => return describe(error, &candidate),
            };
        if target.starts_with('/') {
            current = "/".to_owned();
        }
        seen.insert(candidate.clone(), None);
        rest.push(Some(candidate));
        rest.push(None);
        let parts: Vec<_> = target
            .split('/')
            .rev()
            .map(|s| Some(s.to_owned()))
            .collect();
        count += parts.len();
        rest.extend(parts);
    }
    fallback()
}
