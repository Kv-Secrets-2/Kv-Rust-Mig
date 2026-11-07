//! Glob reach analysis of Python `kv/hook.py`: whether a Claude Code `Glob`
//! could select protected or `kv_run`-tracked files. Python asks a real
//! ripgrep (`rg --files --hidden --no-ignore --glob=PATTERN`); this port
//! evaluates the same walk with ripgrep's own `ignore` and `globset`
//! libraries, so no oracle binary has to be found or trusted.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::paths::{self, SEP, dirname, resolve};

/// The glob could not be evaluated trustworthily; callers refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleUnavailable(pub String);

impl std::fmt::Display for OracleUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Python `_RG_TIMEOUT_SECONDS`.
pub const WALK_BUDGET: Duration = Duration::from_secs(10);
/// Python `_RG_MAX_OUTPUT_BYTES`, as a bound on the walk's result.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relative {
    Path(String),
    DifferentVolume,
    Error,
}

/// `os.path.relpath(path, start)` on POSIX (both made absolute lexically).
pub fn relpath(path: &str, start: &str) -> Relative {
    if path.is_empty() {
        return Relative::Error;
    }
    let (Ok(path), Ok(start)) = (paths::abspath(path), paths::abspath(start)) else {
        return Relative::Error;
    };
    let path_parts: Vec<&str> = path.split(SEP).filter(|p| !p.is_empty()).collect();
    let start_parts: Vec<&str> = start.split(SEP).filter(|p| !p.is_empty()).collect();
    let common = path_parts
        .iter()
        .zip(start_parts.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut rel: Vec<&str> = vec![".."; start_parts.len() - common];
    rel.extend(&path_parts[common..]);
    if rel.is_empty() {
        return Relative::Path(".".to_owned());
    }
    Relative::Path(rel.join("/"))
}

/// Python `_glob_split_root`: (base dir, pattern relative to it).
pub fn glob_split_root(pattern: &str) -> (String, String) {
    let Some(meta) = pattern.find(['*', '?', '[', '{']) else {
        return (
            dirname(pattern).to_owned(),
            paths::basename(pattern).to_owned(),
        );
    };
    let literal = &pattern[..meta];
    let Some(cut) = literal.rfind(SEP) else {
        return (String::new(), pattern.to_owned());
    };
    let mut base = literal[..cut].to_owned();
    let rel = pattern[cut + 1..].to_owned();
    if base.is_empty() && cut == 0 {
        base = SEP.to_string();
    }
    (base, rel)
}

/// Python `_glob_effective_root`.
pub fn glob_effective_root(pattern: &str, path: &str) -> (String, String) {
    if paths::is_abs(pattern) {
        let (base, rel) = glob_split_root(pattern);
        if !base.is_empty() {
            return (base, rel);
        }
    }
    (
        if path.is_empty() {
            ".".to_owned()
        } else {
            path.to_owned()
        },
        pattern.to_owned(),
    )
}

/// `rg --files --hidden --no-ignore --glob=PATTERN -- WALK` run in `cwd`:
/// the matching files' paths as ripgrep prints them.
pub fn files_matching(
    pattern: &str,
    cwd: &Path,
    walk: &str,
) -> Result<Vec<String>, OracleUnavailable> {
    if pattern.contains('\0') || walk.contains('\0') {
        return Err(OracleUnavailable("null byte in glob".into()));
    }
    let mut overrides = ignore::overrides::OverrideBuilder::new(cwd);
    overrides
        .add(pattern)
        .map_err(|error| OracleUnavailable(format!("ripgrep rejected the glob: {error}")))?;
    let overrides = overrides
        .build()
        .map_err(|error| OracleUnavailable(format!("ripgrep rejected the glob: {error}")))?;
    let start: PathBuf = if walk == "." {
        cwd.to_path_buf()
    } else {
        cwd.join(walk)
    };
    let mut builder = ignore::WalkBuilder::new(&start);
    builder
        .hidden(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .require_git(false)
        .follow_links(false)
        .overrides(overrides);
    let deadline = Instant::now() + WALK_BUDGET;
    let mut found = Vec::new();
    let mut bytes = 0usize;
    for entry in builder.build() {
        if Instant::now() > deadline {
            return Err(OracleUnavailable(
                "ripgrep did not finish within its time budget".into(),
            ));
        }
        // ripgrep reports a folder it could not read and exits 2; Python's
        // oracle treats that as untrustworthy, so an incomplete walk is one too.
        let entry =
            entry.map_err(|error| OracleUnavailable(format!("ripgrep could not walk: {error}")))?;
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            continue;
        }
        let printed = if walk == "." {
            entry
                .path()
                .strip_prefix(cwd)
                .map(|rel| rel.to_string_lossy().into_owned())
                .unwrap_or_else(|_| entry.path().to_string_lossy().into_owned())
        } else {
            entry
                .path()
                .strip_prefix(cwd)
                .map(|rel| rel.to_string_lossy().into_owned())
                .unwrap_or_else(|_| entry.path().to_string_lossy().into_owned())
        };
        if printed.is_empty() {
            continue;
        }
        bytes += printed.len() + 1;
        if bytes > MAX_OUTPUT_BYTES {
            return Err(OracleUnavailable(
                "ripgrep output exceeded its size cap".into(),
            ));
        }
        found.push(printed);
    }
    Ok(found)
}

/// Python `_glob_reach(pattern, path, target_dir)` -> (reach, checked).
pub fn glob_reach(pattern: &str, path: &str, target_dir: &str) -> (bool, bool) {
    if pattern.is_empty() {
        return (false, true);
    }
    let (root, pat) = glob_effective_root(pattern, path);
    let (Ok(real_root), Ok(real_target)) =
        (paths::resolve_user(&root), paths::resolve_user(target_dir))
    else {
        return (true, false);
    };
    match paths::isdir_strict(&real_target) {
        Ok(false) => return (false, true),
        Err(_) => return (true, false),
        Ok(true) => {}
    }
    match paths::isdir_strict(&real_root) {
        Ok(false) => return (false, true),
        Err(_) => return (true, false),
        Ok(true) => {}
    }
    let walk = if real_root == real_target || real_root.starts_with(&format!("{real_target}/")) {
        ".".to_owned()
    } else {
        match relpath(&real_target, &real_root) {
            Relative::DifferentVolume => return (false, true),
            Relative::Error => return (true, false),
            Relative::Path(rel) => {
                if rel.starts_with("../") || rel == ".." {
                    return (false, true);
                }
                rel
            }
        }
    };
    match files_matching(&pat, Path::new(&real_root), &walk) {
        Ok(files) => (!files.is_empty(), true),
        Err(_) => (true, false),
    }
}

/// Python `_glob_can_reach`.
pub fn glob_can_reach(pattern: &str, path: &str, target_dir: &str) -> bool {
    glob_reach(pattern, path, target_dir).0
}

struct Mirror(PathBuf);

impl Drop for Mirror {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_mirror() -> std::io::Result<Mirror> {
    let base = std::env::temp_dir();
    for attempt in 0..64u32 {
        let name = format!(
            "kv-glob-mirror-{}-{}-{attempt}",
            std::process::id(),
            std::time::SystemTime::UNIX_EPOCH
                .elapsed()
                .map_or(0, |d| d.as_nanos())
        );
        let path = base.join(name);
        match std::fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                }
                return Ok(Mirror(path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::other(
        "could not create a private mirror folder",
    ))
}

/// Python `_glob_selects_tracked`: the (relative path, tracked path) pairs
/// the glob would select among the tracked files.
pub fn glob_selects_tracked(
    pattern: &str,
    path: &str,
    tracked_paths: &[String],
) -> Result<Vec<(String, String)>, OracleUnavailable> {
    let (root, pat) = glob_effective_root(pattern, path);
    let real_root = paths::resolve_user(&root)
        .map_err(|_| OracleUnavailable("unresolvable glob root".into()))?;
    let mut rel_map: Vec<(String, String)> = Vec::new();
    for tracked in tracked_paths {
        let real_tracked = paths::resolve_user(tracked)
            .map_err(|_| OracleUnavailable("unresolvable tracked path".into()))?;
        if Path::new(&real_tracked).is_dir() {
            continue;
        }
        let rel = match relpath(&real_tracked, &real_root) {
            Relative::DifferentVolume => continue,
            Relative::Error => {
                return Err(OracleUnavailable(
                    "could not normalise tracked path against the search root".into(),
                ));
            }
            Relative::Path(rel) => rel,
        };
        if rel.starts_with("../") || rel == ".." {
            continue;
        }
        if let Some(entry) = rel_map.iter_mut().find(|(r, _)| *r == rel) {
            entry.1 = tracked.clone();
        } else {
            rel_map.push((rel, tracked.clone()));
        }
    }
    if rel_map.is_empty() {
        return Ok(Vec::new());
    }
    let materialise = || -> std::io::Result<Vec<String>> {
        let mirror = make_mirror()?;
        let real_mirror = resolve(&mirror.0.to_string_lossy())?;
        let mut rels: Vec<&String> = rel_map.iter().map(|(rel, _)| rel).collect();
        rels.sort();
        for rel in rels {
            let dest = mirror.0.join(rel);
            let parent = dest
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| mirror.0.clone());
            std::fs::create_dir_all(&parent)?;
            if !resolve(&parent.to_string_lossy())?.starts_with(&real_mirror) {
                return Err(std::io::Error::other("tracked path escaped the mirror"));
            }
            std::fs::File::create(&dest)?;
        }
        files_matching(&pat, &mirror.0, ".").map_err(|error| std::io::Error::other(error.0))
    };
    let returned = materialise().map_err(|error| {
        if error.to_string() == "tracked path escaped the mirror" {
            OracleUnavailable("tracked path escaped the mirror".into())
        } else {
            OracleUnavailable(format!(
                "could not materialise tracked-file mirror: {error}"
            ))
        }
    })?;
    let mut hits = Vec::new();
    for got in returned {
        let norm = got.strip_prefix("./").unwrap_or(&got);
        if let Some((rel, tracked)) = rel_map.iter().find(|(rel, _)| rel == norm) {
            hits.push((rel.clone(), tracked.clone()));
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_and_relpaths() {
        assert_eq!(
            glob_split_root("/a/b/*.txt"),
            ("/a/b".to_owned(), "*.txt".to_owned())
        );
        assert_eq!(
            glob_split_root("/*.txt"),
            ("/".to_owned(), "*.txt".to_owned())
        );
        assert_eq!(
            glob_split_root("*.txt"),
            (String::new(), "*.txt".to_owned())
        );
        assert_eq!(
            glob_split_root("/a/b.txt"),
            ("/a".to_owned(), "b.txt".to_owned())
        );
        assert_eq!(
            glob_effective_root("/a/*.txt", "."),
            ("/a".to_owned(), "*.txt".to_owned())
        );
        assert_eq!(
            glob_effective_root("src/*.txt", ""),
            (".".to_owned(), "src/*.txt".to_owned())
        );
        assert_eq!(relpath("/a/b/c", "/a"), Relative::Path("b/c".to_owned()));
        assert_eq!(relpath("/a", "/a/b/c"), Relative::Path("../..".to_owned()));
        assert_eq!(relpath("/a", "/a"), Relative::Path(".".to_owned()));
        assert_eq!(relpath("/x", "/a/b"), Relative::Path("../../x".to_owned()));
    }
}
