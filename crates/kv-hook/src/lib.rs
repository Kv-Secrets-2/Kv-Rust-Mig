//! Claude Code `PreToolUse` hook: the Rust port of Python 0.4.0 `kv/hook.py`.
//!
//! One JSON tool call arrives on stdin; one JSON reply leaves on stdout.
//! Layer 1 (static) refuses key files and secret-revealing `kv` commands
//! without a daemon; Layer 2 (dynamic) asks the daemon about files created
//! during `kv_run`. Every failure to decide is a refusal, never an allow.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{Map, Value, json};

pub mod dynamic;
pub mod fileaccess;
pub mod glob;
pub mod kvcmd;
pub mod paths;
pub mod reply;
pub mod shell;

pub use reply::Reply;

/// A refusal raised part-way through a check (Python `_deny`, which exits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied(pub String);

impl From<Denied> for Reply {
    fn from(denied: Denied) -> Reply {
        Reply::Deny(denied.0)
    }
}

/// Python `HOOK_SCAN_BUDGET_SECONDS`.
pub const SCAN_BUDGET: Duration = Duration::from_secs(30);

/// Python `MAX_BASH_COMMAND_BYTES`.
pub const MAX_BASH_COMMAND_BYTES: usize = 128 * 1024;

pub const UNREADABLE_INPUT_REASON: &str = "[kv-secrets] blocked: the kv hook could not read the \
    editor's request (empty or not valid JSON) and refuses to guess. Retry the tool call; if \
    this keeps happening, update the editor or re-run 'kv setup claude-code'.";

pub fn budget_reason() -> String {
    format!(
        "[kv-secrets] blocked: checking this command took longer than the hook's time budget \
         ({} s), so the hook refuses it rather than let it through unchecked. Shorten the \
         command, or write large content with your file tools.",
        SCAN_BUDGET.as_secs()
    )
}

pub fn internal_error_reason(kind: &str) -> String {
    format!(
        "[kv-secrets] blocked: the kv hook hit an internal error ({kind}) and refuses to guess. \
         Rephrase the command, or ask the owner to report this."
    )
}

/// A validated Claude Code tool call (Python `main`'s "not a tool call" check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub tool_name: String,
    pub tool_input: Map<String, Value>,
    pub raw: Map<String, Value>,
}

impl ToolCall {
    /// Python: `json.loads(raw)` must give a dict with a non-empty string
    /// `tool_name` and a dict `tool_input`; anything else is unreadable input.
    pub fn parse(raw: &[u8]) -> Option<ToolCall> {
        let Value::Object(data) = serde_json::from_slice::<Value>(raw).ok()? else {
            return None;
        };
        let tool_name = match data.get("tool_name") {
            Some(Value::String(name)) if !name.is_empty() => name.clone(),
            _ => return None,
        };
        let tool_input = match data.get("tool_input") {
            Some(Value::Object(input)) => input.clone(),
            _ => return None,
        };
        Some(ToolCall {
            tool_name,
            tool_input,
            raw: data,
        })
    }
}

/// The reply for one raw stdin payload, in `mode` (Python `main`): every
/// mode other than `pre` allows; `pre` decides under the scan budget.
pub fn reply_for(mode: &str, raw: Vec<u8>) -> Reply {
    let Some(call) = ToolCall::parse(&raw) else {
        if mode != "pre" {
            return Reply::Allow;
        }
        return Reply::Deny(UNREADABLE_INPUT_REASON.to_owned());
    };
    if mode != "pre" {
        return Reply::Allow;
    }
    decide_within_budget(call, SCAN_BUDGET)
}

/// Python `_decide_within_budget`: the decision on its own thread; when the
/// budget runs out the caller prints the refusal and exits, which ends the
/// thread with the process.
pub fn decide_within_budget(call: ToolCall, budget: Duration) -> Reply {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("kv-hook-decide".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let _ = tx.send(decide(&call));
        })
        .map_or_else(
            |error| Reply::Deny(internal_error_reason(&format!("{:?}", error.kind()))),
            |_| match rx.recv_timeout(budget) {
                Ok(reply) => reply,
                Err(mpsc::RecvTimeoutError::Timeout) => Reply::Deny(budget_reason()),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Reply::Deny(internal_error_reason("RuntimeError"))
                }
            },
        )
}

/// Python `_decide`: `_pre_hook`'s reply, a refusal if it panics.
pub fn decide(call: &ToolCall) -> Reply {
    match std::panic::catch_unwind(|| pre_hook(call)) {
        Ok(reply) => reply,
        Err(_) => Reply::Deny(internal_error_reason("RuntimeError")),
    }
}

// ---------------------------------------------------------------------------
// _pre_hook
// ---------------------------------------------------------------------------

use crate::dynamic::{Agent, Arrived, SocketAgent};

const REFUSING_STATES: &[&str] = &[
    "dead",
    "broken",
    "stuck",
    "unknown",
    "unknown-untried",
    "unknown-inconclusive",
    "unchecked",
    "dead-inconclusive",
    "unchecked-inconclusive",
];

/// Python's truthiness for a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `tool_input.get(key, "")` where the code then treats the value as text: a
/// truthy non-string makes Python's string operations raise, which the hook
/// turns into its internal-error refusal.
fn text_field(input: &Map<String, Value>, key: &str, exc: &str) -> Result<String, Reply> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(other) if truthy(other) => Err(Reply::Deny(internal_error_reason(exc))),
        Some(_) => Ok(String::new()),
    }
}

fn deny(reason: impl Into<String>) -> Result<(), Reply> {
    Err(Reply::Deny(reason.into()))
}

fn protected_file_reason(path: &str) -> String {
    format!(
        "[kv-secrets] blocked: '{path}' is a protected kv-secrets file. Use kv_run or kv_api \
         MCP tools to use secrets safely."
    )
}

const VAULT_MANAGEMENT_WORDS: &[&str] = &[
    "init",
    "setup",
    "setup-2fa",
    "2fa",
    "upgrade",
    "import-key",
    "provider",
    "agent",
    "recover",
    "recovery-key",
    "passphrase",
    "vault",
    "sync init",
    "sync login --token-stdin",
    "sync attach-device --token-stdin",
    "sync revoke-device --cloud",
    "sync rotate-device-token --cloud",
    "sync create-attach-token --cloud",
    "lock",
    "unlock",
];
const POLICY_WORDS: &[&str] = &[
    "allow",
    "deny",
    "network-allow",
    "network-deny",
    "grant",
    "approvals",
    "policy",
    "approval-mode",
];

fn static_bash(call: &ToolCall, secrets_dir: Option<&str>) -> Result<(), Reply> {
    let command_value = call.tool_input.get("command");
    if let Some(Value::String(command)) = command_value
        && command.len() > MAX_BASH_COMMAND_BYTES
    {
        {
            return deny(format!(
                "[kv-secrets] blocked: command text is too large to check (over {} KB). Write \
                 large content with your file tools, then run a short command.",
                MAX_BASH_COMMAND_BYTES / 1024
            ));
        }
    }
    let command = text_field(&call.tool_input, "command", "AttributeError")?;
    if command.is_empty() {
        return Ok(());
    }
    let folded = paths::casefold(&command);
    if paths::protected_file_command_patterns()
        .iter()
        .any(|p| p.is_match(&folded))
    {
        return deny(
            "[kv-secrets] blocked: this command names an editor MCP or Claude settings file. \
             Those files are managed by the user, not the agent.",
        );
    }
    let is_git_metadata = fileaccess::is_git_metadata_command(&command);
    let has_expansion = fileaccess::has_shell_expansion(&command);
    let checked_command = if is_git_metadata && !has_expansion {
        fileaccess::strip_git_free_text_values(&command)
    } else {
        command.clone()
    };
    let mut path_candidates = fileaccess::extract_read_targets(&command);
    path_candidates.extend(fileaccess::extract_stdin_redirection_targets(&command));
    path_candidates.extend(fileaccess::extract_all_paths(&checked_command));
    let subcommands = fileaccess::extract_shell_subcommands(&command);
    for subcommand in &subcommands {
        path_candidates.extend(fileaccess::extract_read_targets(subcommand));
        path_candidates.extend(fileaccess::extract_stdin_redirection_targets(subcommand));
        path_candidates.extend(fileaccess::extract_all_paths(subcommand));
    }
    if let Some(pattern) = kvcmd::kv_reveal_pattern(&command) {
        if shell::GENERIC_REASONS.contains(&pattern.as_str()) {
            return deny(format!(
                "[kv-secrets] blocked: {pattern}. The hook refuses shell text it cannot fully \
                 check. Rephrase the command, or write large or unusual text with your file \
                 tools."
            ));
        }
        if POLICY_WORDS.iter().any(|word| pattern.contains(word)) {
            return deny(fileaccess::policy_change_denial_reason(&pattern));
        }
        if VAULT_MANAGEMENT_WORDS
            .iter()
            .any(|word| pattern.contains(word))
        {
            return deny(format!(
                "[kv-secrets] blocked: '{pattern}' is a vault management command. Only the user \
                 can run this directly."
            ));
        }
        return deny(format!(
            "[kv-secrets] blocked: '{pattern}' would reveal secret values. Use kv_api or kv_run \
             MCP tools instead."
        ));
    }
    if kvcmd::has_kv_config_mutation_code(&command) {
        return deny(
            "[kv-secrets] blocked: direct kv.config mutation is a vault management action. Ask \
             the user to run the KV CLI command directly.",
        );
    }
    if let Some(secrets_dir) = secrets_dir {
        for path in &path_candidates {
            if paths::is_protected_path(path, Some(secrets_dir)) {
                return deny(protected_file_reason(path));
            }
            if paths::is_protected_dir_access(path, Some(secrets_dir)) {
                return deny(format!(
                    "[kv-secrets] blocked: '{path}' accesses the protected .secrets directory. \
                     Use kv_run or kv_api MCP tools to use secrets safely."
                ));
            }
            if paths::is_agent_token(path) {
                return deny(paths::AGENT_TOKEN_DENIAL);
            }
        }
    }
    paths::refuse_any_vault_or_token(path_candidates.iter().map(String::as_str))?;
    if command.contains("exec(")
        && [
            "b64decode",
            "b64encode",
            "base64",
            "decode(",
            "fromhex",
            "bytes(",
            "codecs",
            "binascii",
        ]
        .iter()
        .any(|p| command.contains(p))
    {
        return deny(
            "[kv-secrets] blocked: exec() with encoding/decoding detected. This pattern is used \
             to bypass security checks.",
        );
    }
    if kvcmd::has_key_access_code(&checked_command) {
        return deny(
            "[kv-secrets] blocked: command references kv-secrets internal files. Use kv_run or \
             kv_api MCP tools to use secrets safely.",
        );
    }
    if fileaccess::has_glob_path_to_secrets(&command) {
        return deny(
            "[kv-secrets] blocked: glob pattern could resolve to protected files. Use kv_run or \
             kv_api MCP tools to use secrets safely.",
        );
    }
    const VARIABLE_PATH: &str = "[kv-secrets] blocked: file-read command with variable path. Use \
        kv_run or kv_api MCP tools to use secrets safely.";
    if fileaccess::has_variable_path_read(&command) {
        return deny(VARIABLE_PATH);
    }
    for subcommand in &subcommands {
        if fileaccess::has_variable_path_read(subcommand) {
            return deny(VARIABLE_PATH);
        }
    }
    Ok(())
}

fn static_read(call: &ToolCall, secrets_dir: Option<&str>) -> Result<(), Reply> {
    let file_path = text_field(&call.tool_input, "file_path", "TypeError")?;
    if file_path.is_empty() {
        return Ok(());
    }
    if secrets_dir.is_some() && paths::is_protected_path(&file_path, secrets_dir) {
        return deny(protected_file_reason(&file_path));
    }
    paths::refuse_through_vault_folder(&file_path, true)?;
    if paths::is_agent_token(&file_path) {
        return deny(paths::AGENT_TOKEN_DENIAL);
    }
    Ok(())
}

fn static_write(call: &ToolCall, secrets_dir: Option<&str>) -> Result<(), Reply> {
    let file_path = text_field(&call.tool_input, "file_path", "TypeError")?;
    if file_path.is_empty() {
        return Ok(());
    }
    if secrets_dir.is_some() && paths::is_protected_path(&file_path, secrets_dir) {
        return deny(format!(
            "[kv-secrets] blocked: direct modification of '{file_path}' is not allowed. Ask the \
             user to change secrets with kv set in their own terminal."
        ));
    }
    paths::refuse_through_vault_folder(&file_path, false)?;
    if paths::is_hook_config(&file_path) {
        return deny(
            "[kv-secrets] blocked: modifying hook configuration is not allowed. Hook settings \
             are managed by the user, not the agent.",
        );
    }
    let cwd = call.raw.get("cwd");
    let cwd_unusable = cwd.is_some_and(|value| !value.is_string());
    let hook_cwd = cwd.and_then(Value::as_str);
    if cwd_unusable || paths::is_mcp_config(&file_path, hook_cwd) {
        return deny(format!(
            "[kv-secrets] blocked: '{file_path}' holds editor MCP settings that kv set up; the \
             agent may not change them (it could widen kv's tools or point them at another \
             vault). Edit the file yourself, or re-run 'kv setup <editor>'."
        ));
    }
    if paths::is_agent_token(&file_path) {
        return deny("[kv-secrets] blocked: agent auth token is not writable.");
    }
    Ok(())
}

fn search_path(call: &ToolCall) -> Result<(String, bool), Reply> {
    // `tool_input.get("path") or "."`: (path, whether a truthy path was given).
    match call.tool_input.get("path") {
        Some(Value::String(path)) if !path.is_empty() => Ok((path.clone(), true)),
        Some(other) if truthy(other) => Err(Reply::Deny(internal_error_reason("TypeError"))),
        _ => Ok((".".to_owned(), false)),
    }
}

fn static_glob(call: &ToolCall, secrets_dir: Option<&str>) -> Result<(), Reply> {
    let pattern = text_field(&call.tool_input, "pattern", "TypeError")?;
    let (glob_path, given) = search_path(call)?;
    if given
        && let Some(secrets_dir) = secrets_dir
        && paths::path_is_or_inside(&glob_path, secrets_dir)
    {
        return deny("[kv-secrets] blocked: glob path includes .secrets/ directory.");
    }
    paths::refuse_through_vault_folder(&glob_path, false)?;
    let kv_dir = paths::kv_dir();
    if paths::path_is_or_inside(&glob_path, &kv_dir) {
        return deny("[kv-secrets] blocked: glob path accesses kv runtime files.");
    }
    if pattern.is_empty() {
        return Ok(());
    }
    if let Some(secrets_dir) = secrets_dir {
        let (reach, checked) = glob::glob_reach(&pattern, &glob_path, secrets_dir);
        if reach {
            return deny(if checked {
                "[kv-secrets] blocked: glob pattern can match files in the .secrets/ directory."
            } else {
                "[kv-secrets] blocked: could not check whether the glob pattern can match files \
                 in the .secrets/ directory (a folder on its path could not be read); narrow the \
                 pattern or its path."
            });
        }
    }
    let (reach, checked) = glob::glob_reach(&pattern, &glob_path, &kv_dir);
    if reach {
        return deny(if checked {
            "[kv-secrets] blocked: glob pattern can match kv runtime files."
        } else {
            "[kv-secrets] blocked: could not check whether the glob pattern can match kv runtime \
             files (a folder on its path could not be read); narrow the pattern or its path."
        });
    }
    Ok(())
}

fn static_grep(call: &ToolCall, secrets_dir: Option<&str>) -> Result<(), Reply> {
    let (grep_path, _) = search_path(call)?;
    if let Some(secrets_dir) = secrets_dir
        && paths::path_touches(&grep_path, secrets_dir)
    {
        return deny("[kv-secrets] blocked: search path includes .secrets/ directory.");
    }
    paths::refuse_through_vault_folder(&grep_path, false)?;
    if paths::path_touches(&grep_path, &paths::kv_dir()) {
        return deny("[kv-secrets] blocked: search path includes kv runtime files.");
    }
    Ok(())
}

struct Dynamic<'a> {
    agent: Option<&'a dyn Agent>,
    tracked_paths: Vec<String>,
    listing_unknown: bool,
    service_state: Option<String>,
}

impl Dynamic<'_> {
    fn unavailable(&self, what: &str) -> String {
        match &self.service_state {
            Some(state) => dynamic::service_unanswered(what, state),
            None => dynamic::dynamic_unavailable(what),
        }
    }

    /// Python `check_tracked(path, direct)`.
    fn check_tracked(&self, path: &str, direct: bool) -> Result<bool, Reply> {
        if fileaccess::long_paths_open()
            && (fileaccess::extended_spelling(path)
                || self
                    .tracked_paths
                    .iter()
                    .any(|t| fileaccess::extended_spelling(t)))
        {
            return Err(Reply::Deny(format!(
                "[kv-secrets] blocked: kv can't tell whether '{path}' was created during a \
                 secret-injected subprocess (kv_run): extended-length and device paths are \
                 refused while such files exist."
            )));
        }
        if path.len() > fileaccess::DAEMON_PATH_LIMIT {
            let normalized = paths::normpath(path);
            if normalized.len() > fileaccess::DAEMON_PATH_LIMIT {
                return self.over_limit_tracked(&normalized, direct);
            }
        }
        let tracked = self
            .agent
            .and_then(|agent| dynamic::exact_tracked(agent, path));
        match tracked {
            Some(tracked) => Ok(tracked),
            None => Err(Reply::Deny(self.unavailable(&format!(
                "whether '{path}' was created during kv_run"
            )))),
        }
    }

    /// Python `_over_limit_tracked`.
    fn over_limit_tracked(&self, path: &str, direct: bool) -> Result<bool, Reply> {
        if !fileaccess::long_paths_open() {
            return Ok(false);
        }
        let what = "whether a path over 4,096 bytes was created during kv_run";
        if self.listing_unknown {
            return Err(Reply::Deny(self.unavailable(what)));
        }
        match paths::resolve(path) {
            Ok(real) => Ok(self.tracked_paths.contains(&real)),
            Err(_) => {
                if direct {
                    return Err(Reply::Deny(self.unavailable(what)));
                }
                Ok(false)
            }
        }
    }
}

fn keywords_of(tracked_paths: &[String]) -> Vec<String> {
    let mut keywords: Vec<String> = Vec::new();
    let mut add = |keyword: String| {
        if !keywords.contains(&keyword) {
            keywords.push(keyword);
        }
    };
    for tracked_path in tracked_paths {
        let filename = paths::basename(tracked_path).to_owned();
        let stem = match filename.rfind('.') {
            Some(index) if index > 0 && filename[..index].chars().any(|c| c != '.') => {
                filename[..index].to_owned()
            }
            _ => filename.clone(),
        };
        add(filename.clone());
        if stem.chars().count() >= 6 {
            add(stem);
        }
        let chars: Vec<char> = filename.chars().collect();
        for length in 8..=chars.len() {
            for start in 0..=chars.len() - length {
                add(chars[start..start + length].iter().collect());
            }
        }
    }
    keywords
}

fn dynamic_layer(call: &ToolCall, agent: &dyn Agent) -> Result<(), Reply> {
    let (running, arrived) = agent.status_check();
    let mut state = Dynamic {
        agent: Some(agent),
        tracked_paths: Vec::new(),
        listing_unknown: false,
        service_state: None,
    };
    if !running {
        let service_state = agent.service_state(arrived);
        if !REFUSING_STATES.contains(&service_state.as_str()) {
            return Ok(());
        }
        state.service_state = Some(service_state);
        state.agent = None;
        state.listing_unknown = true;
    } else {
        match dynamic::tracked_listing(agent) {
            Some(tracked) if tracked.is_empty() => return Ok(()),
            Some(tracked) => state.tracked_paths = tracked,
            None => state.listing_unknown = true,
        }
    }
    let _ = Arrived::Reply;
    let keywords = keywords_of(&state.tracked_paths);
    match call.tool_name.as_str() {
        "Bash" => {
            let mut command = text_field(&call.tool_input, "command", "TypeError")?;
            let is_git_metadata = fileaccess::is_git_metadata_command(&command);
            let has_expansion = fileaccess::has_shell_expansion(&command);
            for path in fileaccess::bash_path_candidates(&command) {
                if !path.is_empty() && state.check_tracked(&path, false)? {
                    return deny(format!(
                        "[kv-secrets] blocked: '{path}' was created during a secret-injected \
                         subprocess (kv_run). Reading it could expose encoded secret values."
                    ));
                }
            }
            if is_git_metadata && !has_expansion {
                command = fileaccess::strip_git_free_text_values(&command);
            }
            let has_file_access = fileaccess::FILE_ACCESS_PATTERNS
                .iter()
                .any(|p| command.contains(p));
            if has_file_access && state.listing_unknown {
                return deny(state.unavailable("which files file-access code here may reach"));
            }
            if has_file_access {
                for keyword in &keywords {
                    if command.contains(keyword.as_str()) {
                        return deny(format!(
                            "[kv-secrets] blocked: command contains file-access code referencing \
                             '{keyword}' which matches a tracked file."
                        ));
                    }
                }
            }
            let has_encoding = fileaccess::ENCODING_PATTERNS
                .iter()
                .any(|p| command.contains(p));
            if has_file_access && has_encoding {
                return deny(
                    "[kv-secrets] blocked: file-access code with encoding/decoding patterns. This \
                     combination is used to construct obfuscated file paths.",
                );
            }
        }
        "Read" => {
            let file_path = text_field(&call.tool_input, "file_path", "TypeError")?;
            if !file_path.is_empty() && state.check_tracked(&file_path, true)? {
                return deny(format!(
                    "[kv-secrets] blocked: '{file_path}' was created during a secret-injected \
                     subprocess (kv_run)."
                ));
            }
        }
        "Glob" | "Grep" if state.listing_unknown => {
            return deny(state.unavailable("which files this search may reach"));
        }
        "Glob" | "Grep"
            if fileaccess::long_paths_open()
                && (fileaccess::extended_spelling(&search_path(call)?.0)
                    || (call.tool_name == "Glob"
                        && fileaccess::extended_spelling(&text_field(
                            &call.tool_input,
                            "pattern",
                            "TypeError",
                        )?))
                    || state
                        .tracked_paths
                        .iter()
                        .any(|t| fileaccess::extended_spelling(t))) =>
        {
            return deny(
                "[kv-secrets] blocked: kv can't tell whether this search reaches a file created \
                 during a secret-injected subprocess (kv_run): extended-length and device paths \
                 are refused while such files exist.",
            );
        }
        "Glob" => {
            let (glob_path, _) = search_path(call)?;
            let pattern = text_field(&call.tool_input, "pattern", "TypeError")?;
            if !glob_path.is_empty() && !pattern.is_empty() {
                let hits = glob::glob_selects_tracked(&pattern, &glob_path, &state.tracked_paths)
                    .map_err(|exc| {
                    Reply::Deny(format!(
                        "[kv-secrets] blocked: cannot verify this glob against kv_run-tracked \
                             files ({exc}). Refusing to guess."
                    ))
                })?;
                if let Some((rel, _)) = hits.first() {
                    return deny(format!(
                        "[kv-secrets] blocked: glob pattern could match '{rel}', which was created \
                         during a secret-injected subprocess (kv_run)."
                    ));
                }
            }
        }
        "Grep" => {
            let (grep_path, _) = search_path(call)?;
            for tracked_path in &state.tracked_paths {
                if paths::is_path_or_ancestor(&grep_path, tracked_path) {
                    return deny(format!(
                        "[kv-secrets] blocked: search path includes '{}', which was created during \
                         a secret-injected subprocess (kv_run).",
                        paths::basename(tracked_path)
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Python `_pre_hook`, against the daemon `agent` sees.
pub fn pre_hook_with(call: &ToolCall, agent: &dyn Agent) -> Reply {
    let secrets_dir = match paths::find_secrets_dir() {
        Ok(dir) => dir,
        Err(denied) => return denied.into(),
    };
    let result = match call.tool_name.as_str() {
        "Bash" => static_bash(call, secrets_dir.as_deref()),
        "Read" => static_read(call, secrets_dir.as_deref()),
        "Write" | "Edit" => static_write(call, secrets_dir.as_deref()),
        "Glob" => static_glob(call, secrets_dir.as_deref()),
        "Grep" => static_grep(call, secrets_dir.as_deref()),
        _ => Ok(()),
    };
    if let Err(reply) = result {
        return reply;
    }
    match dynamic_layer(call, agent) {
        Ok(()) => Reply::Allow,
        Err(reply) => reply,
    }
}

/// Python `_pre_hook` against this project's daemon (Python's
/// `kv.agent` default project root: the working folder).
pub fn pre_hook(call: &ToolCall) -> Reply {
    pre_hook_with(
        call,
        &SocketAgent {
            root: find_project_root(),
        },
    )
}

/// Python `kv.config.find_project_root`: the nearest folder at or above the
/// working folder whose `.secrets` is a real directory, `None` when there is
/// none (the daemon's "default" project).
pub fn find_project_root() -> Option<std::path::PathBuf> {
    let start = std::env::current_dir().ok()?;
    for path in start.ancestors() {
        if let Ok(metadata) = std::fs::symlink_metadata(path.join(paths::SECRETS_FOLDER))
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
        {
            return Some(path.to_path_buf());
        }
    }
    None
}

pub fn tool_call(tool_name: &str, tool_input: Value) -> ToolCall {
    let raw = json!({"tool_name": tool_name, "tool_input": tool_input});
    ToolCall::parse(&serde_json::to_vec(&raw).expect("json")).expect("valid tool call")
}
