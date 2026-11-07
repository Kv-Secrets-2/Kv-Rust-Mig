//! Path answers the sandbox needs (Python `kv/sandbox.py`): overlap and
//! containment after resolution, each caller choosing the answer an error
//! gives, and the "real or as written" spelling the scanners record.

pub use kv_hook::paths::{abspath, is_abs, normpath, resolve};

/// Python `os.path.commonpath([a, b])` for two absolute POSIX paths.
pub fn commonpath(a: &str, b: &str) -> Option<String> {
    if is_abs(a) != is_abs(b) {
        return None;
    }
    let parts = |p: &str| -> Vec<String> {
        p.split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .map(str::to_owned)
            .collect()
    };
    let (pa, pb) = (parts(a), parts(b));
    let common: Vec<&str> = pa
        .iter()
        .zip(&pb)
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x.as_str())
        .collect();
    let prefix = if is_abs(a) { "/" } else { "" };
    Some(format!("{prefix}{}", common.join("/")))
}

/// Python `_paths_overlap`: one is the other or inside it.
pub fn paths_overlap(a: &str, b: &str, on_error: bool) -> bool {
    let (Ok(ra), Ok(rb)) = (resolve(a), resolve(b)) else {
        return on_error;
    };
    if ra == rb {
        return true;
    }
    matches!(commonpath(&ra, &rb), Some(c) if c == ra || c == rb)
}

/// Python `_path_is_or_under`.
pub fn path_is_or_under(path: &str, root: &str, on_error: bool) -> bool {
    let (Ok(rp), Ok(rr)) = (resolve(path), resolve(root)) else {
        return on_error;
    };
    rp == rr || commonpath(&rp, &rr).as_deref() == Some(rr.as_str())
}

/// Python `_real_or_lexical`: the resolved path, or the path as written
/// (made absolute) when it cannot be resolved. Never used to decide a fence.
pub fn real_or_lexical(path: &str) -> String {
    resolve(path)
        .or_else(|_| abspath(path))
        .unwrap_or_else(|_| normpath(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commonpath_matches_python() {
        assert_eq!(commonpath("/a/b/c", "/a/b/d").as_deref(), Some("/a/b"));
        assert_eq!(commonpath("/a", "/b").as_deref(), Some("/"));
        assert_eq!(commonpath("/tmp", "/tmp/x").as_deref(), Some("/tmp"));
        assert_eq!(commonpath("/tmp", "/tmpx").as_deref(), Some("/"));
        assert!(commonpath("/a", "a").is_none());
    }

    #[test]
    fn overlap_and_containment() {
        assert!(paths_overlap("/tmp", "/tmp/x/y", false));
        assert!(!paths_overlap("/tmp", "/var", true));
        assert!(path_is_or_under("/tmp/x", "/tmp", false));
        assert!(!path_is_or_under("/tmp", "/tmp/x", false));
    }
}
