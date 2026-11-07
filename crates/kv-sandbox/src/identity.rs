//! Run identity (Python `kv/sandbox.py`: `_hash_file`, `_script_file_path`,
//! `module_script_path`, `script_candidates`, `_script_identity`,
//! `build_run_identity`).

use std::fmt;
use std::io::Read;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::classify::{BROAD_SECRET_ALLOWLIST_PROGRAMS, PYTHON_MODULE_PROGRAMS, program_name};
use crate::paths::{abspath, inside_secrets, is_abs, resolve};

pub const HASH_CHUNK_SIZE: usize = 1024 * 1024;
pub const HASH_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Python `ValueError("the script could not be hashed in time (N seconds)")`.
    HashDeadline,
    /// `structure.resolve(cwd)` failed (Python raises the `OSError`).
    Cwd(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashDeadline => write!(
                f,
                "the script could not be hashed in time ({} seconds)",
                HASH_DEADLINE.as_secs()
            ),
            Self::Cwd(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for IdentityError {}

fn is_file(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

fn join(base: &str, rel: &str) -> String {
    if is_abs(rel) {
        rel.to_owned()
    } else {
        format!("{}/{rel}", base.trim_end_matches('/'))
    }
}

/// Python `_hash_file`: the SHA-256 hex digest of a regular file, `None`
/// when it is not one or cannot be read, an error past the deadline.
pub fn hash_file(path: &str) -> Result<Option<String>, IdentityError> {
    let started = Instant::now();
    if !is_file(path) {
        return Ok(None);
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return Ok(None);
    };
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK_SIZE];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Ok(None),
        };
        if started.elapsed() > HASH_DEADLINE {
            return Err(IdentityError::HashDeadline);
        }
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(Some(hex::encode(digest.finalize())))
}

/// Python `str.isidentifier` (XID start/continue approximated by Unicode
/// alphabetic/alphanumeric, exact for ASCII).
pub fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_alphanumeric())
}

/// Python `module_script_path`: the one file kv reads for `python -m NAME`.
pub fn module_script_path(module_name: &str, cwd: &str, watched: &[String]) -> Option<String> {
    if module_name.is_empty() || module_name.starts_with('-') {
        return None;
    }
    let parts: Vec<&str> = module_name.split('.').collect();
    if parts.iter().any(|part| !is_identifier(part)) {
        return None;
    }
    let module_root = abspath(&join(cwd, &parts.join("/"))).ok()?;
    [
        format!("{module_root}.py"),
        format!("{module_root}/__main__.py"),
    ]
    .into_iter()
    .find(|path| inside_secrets(path, watched) || is_file(path))
}

/// Python `_script_file_path`: the resolved script an interpreter runs.
pub fn script_file_path(argv: &[String], cwd: &str, watched: &[String]) -> Option<String> {
    let first = argv.first()?;
    let program = program_name(first);
    if !BROAD_SECRET_ALLOWLIST_PROGRAMS.contains(&program.as_str()) || argv.len() < 2 {
        return None;
    }
    let candidate = argv[1].as_str();
    if candidate.is_empty() || candidate.starts_with('-') {
        return None;
    }
    let path = join(cwd, candidate);
    if inside_secrets(&path, watched) {
        return None;
    }
    let path = resolve(&path).ok()?;
    is_file(&path).then_some(path)
}

/// Python `script_candidates`: every file a run would read as its script.
pub fn script_candidates(argv: &[String], cwd: &str, watched: &[String]) -> Vec<String> {
    let Some(first) = argv.first() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let program = program_name(first);
    if argv.len() > 1
        && (BROAD_SECRET_ALLOWLIST_PROGRAMS.contains(&program.as_str())
            || program.starts_with("python"))
    {
        if argv[1] == "-m" && program.starts_with("python") {
            let chosen = argv
                .get(2)
                .and_then(|name| module_script_path(name, cwd, watched));
            found.extend(chosen);
        } else {
            add_candidate(&mut found, cwd, &argv[1]);
        }
    }
    if [".py", ".sh", ".bash", ".zsh"]
        .iter()
        .any(|ext| first.ends_with(ext))
    {
        add_candidate(&mut found, cwd, first);
    }
    found
}

fn add_candidate(found: &mut Vec<String>, cwd: &str, candidate: &str) {
    if !candidate.is_empty() && !candidate.starts_with('-') {
        found.push(join(cwd, candidate));
    }
}

/// Python `_script_identity`: `script_kind` plus `script_sha256` or
/// `script_ref_hash`, or empty.
pub fn script_identity(
    argv: &[String],
    cwd: &str,
    watched: &[String],
) -> Result<Map<String, Value>, IdentityError> {
    let mut out = Map::new();
    let Some(first) = argv.first() else {
        return Ok(out);
    };
    let program = program_name(first);
    if PYTHON_MODULE_PROGRAMS.contains(&program.as_str()) && argv.len() >= 3 && argv[1] == "-m" {
        out.insert("script_kind".into(), json!("python_module"));
        out.insert(
            "script_ref_hash".into(),
            json!(hex::encode(Sha256::digest(argv[2].as_bytes()))),
        );
        return Ok(out);
    }
    let Some(path) = script_file_path(argv, cwd, watched) else {
        return Ok(out);
    };
    let Some(digest) = hash_file(&path)? else {
        return Ok(out);
    };
    out.insert("script_kind".into(), json!("file"));
    out.insert("script_sha256".into(), json!(digest));
    Ok(out)
}

/// The scope fields of Python `build_run_identity`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityScope<'a> {
    pub env_names: Option<&'a [String]>,
    pub secret_scope: Option<Value>,
    pub secrets_injected: bool,
}

/// Python `build_run_identity`: `run_id`, `command_fingerprint` and the
/// script fields. The caller mints `run_id` (`run_` + 24 hex digits).
pub fn build_run_identity(
    argv: &[String],
    cwd: &str,
    scope: &IdentityScope<'_>,
    run_id: &str,
    watched: &[String],
) -> Result<Map<String, Value>, IdentityError> {
    let script = script_identity(argv, cwd, watched)?;
    let env_name_scope = scope.env_names.map(|names| {
        let mut sorted = names.to_vec();
        sorted.sort();
        sorted
    });
    let resolved_cwd = resolve(cwd).map_err(|e| IdentityError::Cwd(e.to_string()))?;
    let payload = json!({
        "argv": argv,
        "cwd": resolved_cwd,
        "env_names": env_name_scope,
        "script_kind": script.get("script_kind").cloned().unwrap_or(Value::Null),
        "script_ref_hash": script.get("script_ref_hash").cloned().unwrap_or(Value::Null),
        "script_sha256": script.get("script_sha256").cloned().unwrap_or(Value::Null),
        "secret_scope": scope.secret_scope.clone().unwrap_or(Value::Null),
        "secrets_injected": scope.secrets_injected,
        "v": 1,
    });
    let encoded = kv_approvals_canonical(&payload);
    let mut identity = Map::new();
    identity.insert("run_id".into(), json!(run_id));
    identity.insert(
        "command_fingerprint".into(),
        json!(hex::encode(Sha256::digest(encoded.as_bytes()))),
    );
    identity.extend(script);
    Ok(identity)
}

/// `json.dumps(payload, sort_keys=True, separators=(",", ":"))` for the
/// identity payload: keys are inserted sorted above, strings carry
/// Python's `ensure_ascii` escapes.
fn kv_approvals_canonical(value: &Value) -> String {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(&n.to_string()),
            Value::String(s) => write_str(s, out),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, key) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(key, out);
                    out.push(':');
                    write(&map[*key], out);
                }
                out.push('}');
            }
        }
    }
    fn write_str(s: &str, out: &mut String) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0c}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                    let mut units = [0u16; 2];
                    for unit in c.encode_utf16(&mut units) {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }
    let mut out = String::new();
    write(value, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_module_paths() {
        assert!(is_identifier("_a1"));
        assert!(!is_identifier("1a"));
        assert!(!is_identifier(""));
        assert!(module_script_path("-x", "/", &[]).is_none());
        assert!(module_script_path("a.b-c", "/", &[]).is_none());
        assert_eq!(
            module_script_path("pkg.mod", "/x/.secrets", &[]).as_deref(),
            Some("/x/.secrets/pkg/mod.py")
        );
    }

    #[test]
    fn canonical_json_matches_python_dumps() {
        let payload = json!({"b": [1, true, null], "a": "é\n\"", "c": {"z": 1, "y": 2}});
        assert_eq!(
            kv_approvals_canonical(&payload),
            r#"{"a":"\u00e9\n\"","b":[1,true,null],"c":{"y":2,"z":1}}"#
        );
    }

    #[test]
    fn module_identity_hashes_the_name() {
        let argv: Vec<String> = ["python3", "-m", "pkg.mod"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let id = script_identity(&argv, "/", &[]).unwrap();
        assert_eq!(id["script_kind"], "python_module");
        assert_eq!(
            id["script_ref_hash"],
            hex::encode(Sha256::digest(b"pkg.mod"))
        );
        let identity =
            build_run_identity(&argv, "/", &IdentityScope::default(), "run_abc", &[]).unwrap();
        assert_eq!(identity["run_id"], "run_abc");
        assert_eq!(identity["command_fingerprint"].as_str().unwrap().len(), 64);
    }
}
