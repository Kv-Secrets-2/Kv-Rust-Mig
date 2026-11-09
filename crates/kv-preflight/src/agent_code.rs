//! Report-only agent code scanning, matching Python `kv.agent_code_scan`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

pub const MAX_SCAN_FILE_BYTES: u64 = 1_000_000;
pub const SCANNED_SUFFIXES: &[&str] = &[
    "py", "js", "ts", "tsx", "jsx", "mjs", "cjs", "sh", "bash", "zsh", "fish", "md", "mdx", "txt",
    "toml", "yaml", "yml", "json",
];
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".secrets",
    ".kv",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
];
const PROVIDERS: &[(&str, &str)] = &[
    ("ANTHROPIC_API_KEY", "anthropic"),
    ("OPENAI_API_KEY", "openai"),
    ("GOOGLE_API_KEY", "google"),
    ("GOOGLE_CLOUD_API_KEY", "google-cloud"),
    ("GEMINI_API_KEY", "google"),
    ("GROQ_API_KEY", "groq"),
    ("MISTRAL_API_KEY", "mistral"),
    ("GITHUB_TOKEN", "github"),
];
const GUIDANCE: &str = "Use kv.cap_client.api_call() inside kv run --capability api:<provider> so the script receives KV_CAP_TOKEN, not the provider key.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentCodeFinding {
    pub path: String,
    pub line: usize,
    pub code: String,
    pub severity: String,
    pub message: String,
    pub guidance: String,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanError {
    #[serde(rename = "type")]
    pub kind: String,
    pub message: String,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ScanError {}

struct Rule {
    code: &'static str,
    severity: &'static str,
    pattern: Regex,
    insensitive: bool,
    message: &'static str,
    guidance: &'static str,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let names = PROVIDERS.iter().map(|(name, _)| *name).collect::<Vec<_>>().join("|");
        let specifications = [
            ("raw-env-read", "high", format!(r#"(?:os\.environ\[\s*["'](?:{names})["']\s*\])|(?:os\.environ\.get\(\s*["'](?:{names})["'])|(?:os\.getenv\(\s*["'](?:{names})["'])|(?:process\.env\.(?:{names}))|(?:process\.env\[\s*["'](?:{names})["']\s*\])"#), true, "direct provider secret environment read", GUIDANCE),
            ("direct-anthropic-sdk", "medium", r"\banthropic\.Anthropic\s*\(".into(), false, "direct Anthropic SDK client", "For agent-run code, call Anthropic with kv.cap_client.api_call() inside kv run --capability api:anthropic instead of SDK env-key discovery."),
            ("direct-openai-sdk", "medium", r"\bopenai\.OpenAI\s*\(".into(), false, "direct OpenAI SDK client", "For agent-run code, call OpenAI with kv.cap_client.api_call() inside kv run --capability api:openai instead of SDK env-key discovery."),
            ("api-key-argument", "high", r#"\bapi_key\s*=\s*(?:os\.environ|os\.getenv|process\.env|["']|[A-Za-z_][A-Za-z0-9_]*API_KEY)"#.into(), true, "explicit API key argument", GUIDANCE),
            ("raw-key-shell-export", "high", format!(r"(?:^|\s)(?:export\s+)?(?:{names})\s*="), true, "provider key shell assignment/export", "Do not ask users to paste/export API keys for agent workflows; use kv set plus capability/brokered use."),
            ("broad-kv-client", "medium", r"\bKVClient\s*\(|from\s+kv\.client\s+import\s+KVClient".into(), false, "broad daemon-auth KVClient in script", "Untrusted/generated scripts should use kv.cap_client.api_call() with scoped capability tokens, not broad daemon auth."),
            ("plaintext-secret-command", "high", r"\bkv\s+(?:get|export)\b".into(), false, "plaintext secret CLI command", "Agents should not use reveal/export paths; ask the user or use brokered tools."),
        ];
        specifications.into_iter().map(|(code, severity, pattern, insensitive, message, guidance)| {
            // Python's Unicode word class excludes combining marks and join controls.
            let pattern = pattern.replace(r"\b", r"(?:^|[^\p{L}\p{N}_])");
            // The final boundary in the CLI rule is a right boundary.
            let pattern = if code == "plaintext-secret-command" {
                pattern.strip_suffix(r"(?:^|[^\p{L}\p{N}_])").unwrap().to_owned() + r"(?:$|[^\p{L}\p{N}_])"
            } else { pattern };
            let pattern = pattern.replace(r"\s", r"[\s\x1c-\x1f]");
            Rule { code, severity, pattern: Regex::new(&format!("{}{}", if insensitive { "(?i)" } else { "" }, pattern)).unwrap(), insensitive, message, guidance }
        }).collect()
    })
}

fn error(kind: &str, message: String) -> ScanError {
    ScanError {
        kind: kind.into(),
        message,
    }
}

fn expand(path: &Path) -> Result<PathBuf, ScanError> {
    let name = path.to_string_lossy();
    let expanded = PathBuf::from(
        kv_hook::paths::expanduser(&name)
            .map_err(|_| error("RuntimeError", "Could not determine home directory.".into()))?,
    );
    // pathlib removes redundant separators and `.` but retains `..`.
    let mut normalized = PathBuf::new();
    for part in expanded.components() {
        if part != std::path::Component::CurDir {
            normalized.push(part.as_os_str());
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }
    Ok(normalized)
}

fn walk(folder: &Path, files: &mut Vec<PathBuf>) -> Result<(), ScanError> {
    let entries = std::fs::read_dir(folder).map_err(|e| io_error(e, folder))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_error(e, folder))?;
        let path = entry.path();
        let name = entry.file_name();
        if name == ".secrets" {
            continue;
        }
        if path.is_symlink() {
            files.push(path);
        } else if path.is_dir() {
            if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                walk(&path, files)?;
            }
        } else {
            files.push(path);
        }
    }
    Ok(())
}

fn io_error(e: std::io::Error, path: &Path) -> ScanError {
    let kind = match e.kind() {
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        _ => "OSError",
    };
    let description = match e.kind() {
        std::io::ErrorKind::NotFound => "No such file or directory",
        std::io::ErrorKind::PermissionDenied => "Permission denied",
        std::io::ErrorKind::NotADirectory => "Not a directory",
        _ => "Input/output error",
    };
    error(
        kind,
        format!(
            "[Errno {}] {}: '{}'",
            e.raw_os_error().unwrap_or(5),
            description,
            path.display()
        ),
    )
}

/// Standalone CLI scans have no registered vault watchers.
pub fn scan_agent_code(path: impl AsRef<Path>) -> Result<Vec<AgentCodeFinding>, ScanError> {
    scan_agent_code_with_watched_vaults(path, &[])
}

pub fn scan_agent_code_with_watched_vaults(
    path: impl AsRef<Path>,
    watched_vaults: &[String],
) -> Result<Vec<AgentCodeFinding>, ScanError> {
    let root = expand(path.as_ref())?;
    if kv_sandbox::paths::inside_secrets(&root.to_string_lossy(), watched_vaults) {
        return Err(error(
            "FileNotFoundError",
            format!(
                "agent-code path refused (inside the vault's .secrets): {}",
                root.display()
            ),
        ));
    }
    if !root.exists() {
        return Err(error(
            "FileNotFoundError",
            format!("agent-code path not found: {}", root.display()),
        ));
    }
    let base = if root.is_dir() {
        root.as_path()
    } else {
        root.parent().unwrap_or(Path::new("."))
    };
    let mut files = Vec::new();
    if root.is_file() {
        files.push(root.clone());
    } else {
        walk(&root, &mut files)?;
    }
    files.sort_by(|a, b| a.components().cmp(b.components()));
    let mut findings = Vec::new();
    for path in files {
        if kv_sandbox::paths::inside_secrets(&path.to_string_lossy(), watched_vaults)
            || !path.is_file()
        {
            continue;
        }
        let Some(suffix) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if suffix.is_empty() || !SCANNED_SUFFIXES.contains(&suffix.to_lowercase().as_str()) {
            continue;
        }
        if !path
            .metadata()
            .is_ok_and(|m| m.len() <= MAX_SCAN_FILE_BYTES)
        {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        let rel = path.strip_prefix(base).unwrap_or(&path).to_string_lossy();
        for (index, line) in text
            .split([
                '\n', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
            ])
            .enumerate()
        {
            // Python IGNORECASE additionally equates dotted/dotless I with ASCII i.
            let folded = line.replace(['\u{130}', '\u{131}'], "i");
            for rule in rules() {
                if rule
                    .pattern
                    .is_match(if rule.insensitive { &folded } else { line })
                {
                    let upper = line.to_uppercase();
                    let provider = match rule.code {
                        "direct-anthropic-sdk" => Some("anthropic"),
                        "direct-openai-sdk" => Some("openai"),
                        _ => PROVIDERS
                            .iter()
                            .find(|(name, _)| upper.contains(name))
                            .map(|(_, provider)| *provider),
                    };
                    findings.push(AgentCodeFinding {
                        path: rel.to_string(),
                        line: index + 1,
                        code: rule.code.into(),
                        severity: rule.severity.into(),
                        message: rule.message.into(),
                        guidance: rule.guidance.into(),
                        provider: provider.map(str::to_owned),
                    });
                }
            }
        }
    }
    Ok(findings)
}
