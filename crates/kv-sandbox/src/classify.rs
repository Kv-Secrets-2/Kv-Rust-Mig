//! Command classification before a `kv_run` (Python `kv/sandbox.py`:
//! `classify_command`, `check_command`, `effective_run_mode`, the allowlist
//! matcher and the broker hints). Wording is Python's, byte for byte.

use serde_json::{Map, Value, json};

pub const MODE_WORK: &str = "work";
pub const MODE_BROKERED_ACT: &str = "brokered_act";
pub const MODE_GUARDED_ENV: &str = "guarded_env";
pub const MODE_UNSAFE_ENV: &str = "unsafe_env";
pub const MODE_REVEAL: &str = "reveal";

pub const BLOCKED_SHELLS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "csh", "tcsh", "fish", "ksh", "ash", "busybox",
];
pub const INLINE_CODE_FLAGS: &[(&str, &str)] = &[
    ("python", "-c"),
    ("python3", "-c"),
    ("python2", "-c"),
    ("node", "-e"),
    ("ruby", "-e"),
    ("perl", "-e"),
    ("lua", "-e"),
    ("php", "-r"),
];
pub const PYTHON_MODULE_PROGRAMS: &[&str] = &["python", "python2", "python3", "pypy", "pypy3"];
pub const BROAD_SECRET_ALLOWLIST_PROGRAMS: &[&str] = &[
    "python", "python2", "python3", "pypy", "pypy3", "node", "deno", "bun", "ruby", "perl", "php",
    "lua", "Rscript", "rscript",
];
pub const HTTP_TOOLS: &[&str] = &[
    "curl",
    "wget",
    "fetch",
    "httpie",
    "http",
    "xh",
    "aria2c",
    "lwp-request",
];
pub const REMOTE_SHELL_TOOLS: &[&str] = &["ssh", "scp", "sftp", "rsync"];
pub const RAW_NETWORK_TOOLS: &[&str] = &["nc", "ncat", "netcat", "socat", "telnet", "ftp", "lftp"];
pub const DB_CLIENT_TOOLS: &[&str] = &["psql", "mysql", "redis-cli"];

/// Python `_EXFIL_PATTERNS`, in Python's order (the first match is reported).
pub const EXFIL_PATTERNS: &[&str] = &[
    "printenv >",
    "printenv>>",
    "env >",
    "env>>",
    "export >",
    "export>>",
    "echo $",
    "echo ${",
    "> /tmp/",
    ">> /tmp/",
    "tee /tmp/",
    "tee -a /tmp/",
    "> /var/tmp/",
    ">> /var/tmp/",
    ">/tmp/",
    ">>/tmp/",
    "| base64",
    "| xxd",
    "| od ",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandDecision {
    pub allowed: bool,
    pub mode: &'static str,
    pub reason: String,
    pub broker_handoff: Option<Map<String, Value>>,
}

impl CommandDecision {
    fn allow(mode: &'static str) -> Self {
        Self {
            allowed: true,
            mode,
            reason: String::new(),
            broker_handoff: None,
        }
    }

    fn deny(mode: &'static str, reason: String) -> Self {
        Self {
            allowed: false,
            mode,
            reason,
            broker_handoff: None,
        }
    }

    fn deny_with(mode: &'static str, reason: String, handoff: Option<Map<String, Value>>) -> Self {
        Self {
            allowed: false,
            mode,
            reason,
            broker_handoff: handoff,
        }
    }
}

/// `os.path.basename(x).lower()` on POSIX: the text after the last `/`.
pub fn program_name(argv0: &str) -> String {
    argv0.rsplit('/').next().unwrap_or("").to_lowercase()
}

/// Python `str.split()` with no argument: runs of whitespace separate, and
/// leading/trailing whitespace yields no empty parts. `str.isspace` also counts
/// U+001C..U+001F, which Rust's `char::is_whitespace` does not.
pub fn py_split(text: &str) -> Vec<&str> {
    text.split(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        .filter(|part| !part.is_empty())
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerHint {
    pub kind: &'static str,
    pub program: String,
    pub tool: Option<&'static str>,
    pub reason: &'static str,
    pub action: &'static str,
    pub arguments: Vec<(&'static str, &'static str)>,
}

type HintTable = (
    &'static str,
    Option<&'static str>,
    &'static str,
    &'static str,
    Vec<(&'static str, &'static str)>,
);

pub fn broker_hint_for_argv(argv: &[String]) -> Option<BrokerHint> {
    let first = argv.first()?;
    let program = program_name(first);
    let p = program.as_str();
    let (kind, tool, reason, action, arguments): HintTable = if HTTP_TOOLS.contains(&p) {
        (
            "http",
            Some("kv_api"),
            "authenticated HTTP/API calls",
            "call kv_api with provider, path, method, and body instead of passing secrets to an HTTP CLI",
            vec![
                ("provider", "<configured API provider>"),
                ("path", "<endpoint path>"),
                ("method", "GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE"),
                ("body", "<optional JSON body>"),
            ],
        )
    } else if REMOTE_SHELL_TOOLS.contains(&p) {
        (
            "remote_shell",
            Some("kv_ssh"),
            "remote shell or file-transfer actions",
            "call kv_ssh with a configured SSH provider instead of passing secrets to ssh/scp/sftp/rsync",
            vec![
                ("provider", "<configured SSH provider>"),
                ("command", "<remote command>"),
            ],
        )
    } else if DB_CLIENT_TOOLS.contains(&p) {
        (
            "database",
            Some("kv_query"),
            "database queries",
            "call kv_query with a configured database provider instead of passing secrets to a DB CLI",
            vec![
                ("provider", "<configured database provider>"),
                ("query", "<SQL query or Redis command>"),
            ],
        )
    } else if RAW_NETWORK_TOOLS.contains(&p) {
        (
            "raw_network",
            None,
            "raw network access with injected secrets",
            "use a brokered kv tool or a purpose-built provider instead of raw network utilities",
            vec![],
        )
    } else {
        return None;
    };
    Some(BrokerHint {
        kind,
        program,
        tool,
        reason,
        action,
        arguments,
    })
}

/// Python `broker_handoff_for_argv`: the JSON object a refusal carries.
pub fn broker_handoff_for_argv(argv: &[String]) -> Option<Map<String, Value>> {
    let hint = broker_hint_for_argv(argv)?;
    let mut template = Map::new();
    for (key, value) in &hint.arguments {
        template.insert((*key).to_string(), json!(value));
    }
    let mut handoff = Map::new();
    handoff.insert(
        "recommended_tool".into(),
        hint.tool.map_or(Value::Null, |tool| json!(tool)),
    );
    handoff.insert("blocked_program".into(), json!(hint.program));
    handoff.insert("reason".into(), json!(hint.reason));
    handoff.insert("next_step".into(), json!(hint.action));
    handoff.insert("arguments_template".into(), Value::Object(template));
    handoff.insert(
        "credential_boundary".into(),
        json!("The daemon should use the credential; the agent should not receive the raw secret."),
    );
    Some(handoff)
}

/// Python `parked_tool_message`.
pub fn parked_tool_message(tool_name: Option<&str>) -> Option<String> {
    let label = match tool_name? {
        "kv_query" => "database",
        "kv_ssh" => "remote-shell",
        _ => return None,
    };
    Some(format!(
        "kv will not give this program your secrets, and its {label} tool is not available for \
         vaults with a passphrase in this version."
    ))
}

/// Python `session_denial_reason`: a protected session's refusal names no parked tool.
pub fn session_denial_reason(decision: &CommandDecision, protected_session: bool) -> String {
    if protected_session && let Some(handoff) = &decision.broker_handoff {
        let tool = handoff.get("recommended_tool").and_then(Value::as_str);
        if let Some(message) = parked_tool_message(tool) {
            return message;
        }
    }
    decision.reason.clone()
}

/// Python `_matches_exfil_pattern`: the first pattern found in the lowercased
/// space-joined argv, stripped.
pub fn matches_exfil_pattern(argv: &[String]) -> Option<&'static str> {
    let cmd = argv.join(" ").to_lowercase();
    EXFIL_PATTERNS
        .iter()
        .find(|pattern| cmd.contains(&pattern.to_lowercase()))
        .map(|pattern| pattern.trim())
}

pub fn raw_argv0_is_wrapper_option(argv: &[String]) -> bool {
    argv.first().is_some_and(|first| first.starts_with('-'))
}

/// Python `allowlist_hint_for_argv`.
pub fn allowlist_hint_for_argv(argv: &[String]) -> String {
    let Some(first) = argv.first() else {
        return String::new();
    };
    let mut parts = vec![first.as_str()];
    if argv.len() > 1 {
        parts.push(argv[1].as_str());
    }
    let program = program_name(first);
    if PYTHON_MODULE_PROGRAMS.contains(&program.as_str()) && argv.len() > 2 && argv[1] == "-m" {
        parts.push(argv[2].as_str());
    }
    parts.join(" ")
}

/// Python `broad_secret_allowlist_reason`: "" when the entry is narrow enough.
pub fn broad_secret_allowlist_reason(allowed: &str) -> String {
    let parts = py_split(allowed);
    let Some(first) = parts.first() else {
        return String::new();
    };
    if parts == ["*"] {
        return "wildcard allowlist entry '*' is too broad to receive secrets. Allow an exact \
                command instead, or run with --no-secrets for ordinary work"
            .into();
    }
    let program = program_name(first);
    if BROAD_SECRET_ALLOWLIST_PROGRAMS.contains(&program.as_str()) {
        if parts.len() == 1 {
            return format!(
                "allowlist entry '{allowed}' is too broad to receive secrets. Allow an exact \
                 script or module command instead"
            );
        }
        if PYTHON_MODULE_PROGRAMS.contains(&program.as_str())
            && parts[1] == "-m"
            && parts.len() == 2
        {
            return format!(
                "allowlist entry '{allowed}' is too broad to receive secrets. Include the exact \
                 module and subcommand instead"
            );
        }
        if parts[1] == "-" && parts.len() == 2 {
            return format!(
                "allowlist entry '{allowed}' reads code from stdin and is too broad to receive \
                 secrets. Allow a real script path instead"
            );
        }
    }
    String::new()
}

fn unapproved_broad_interpreter_reason(argv: &[String]) -> String {
    let Some(first) = argv.first() else {
        return String::new();
    };
    let program = program_name(first);
    if BROAD_SECRET_ALLOWLIST_PROGRAMS.contains(&program.as_str()) {
        if argv.len() == 1 {
            return format!(
                "interpreter '{program}' cannot receive secrets without an exact script or \
                 module command"
            );
        }
        if PYTHON_MODULE_PROGRAMS.contains(&program.as_str()) && argv[1] == "-m" {
            return format!(
                "module execution '{program} -m' cannot receive secrets unless an exact module \
                 command is allowlisted"
            );
        }
        if argv[1] == "-" {
            return format!(
                "interpreter '{program} -' reads code from stdin and cannot receive secrets"
            );
        }
    }
    String::new()
}

/// Python `_matching_allowlist_entry`: the first entry argv matches.
pub fn matching_allowlist_entry<'a>(
    argv: &[String],
    allowed_commands: &'a [String],
) -> Option<&'a str> {
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    for allowed in allowed_commands {
        if allowed == "*" {
            return Some(allowed);
        }
        let parts = py_split(allowed);
        let Some(first) = parts.first() else {
            continue;
        };
        if program_name(argv0) != program_name(first)
            && argv0.to_lowercase() != first.to_lowercase()
        {
            continue;
        }
        if parts.len() == 1 {
            return Some(allowed);
        }
        if argv.len() >= parts.len() && (1..parts.len()).all(|i| argv[i] == parts[i]) {
            return Some(allowed);
        }
    }
    None
}

/// Python `_matches_allowlist`.
pub fn matches_allowlist(argv: &[String], allowed_commands: &[String]) -> bool {
    if argv.is_empty() {
        return false;
    }
    if allowed_commands == ["*"] {
        return true;
    }
    matching_allowlist_entry(argv, allowed_commands).is_some()
}

/// Python `classify_command`.
pub fn classify_command(
    argv: &[String],
    allowed_commands: Option<&[String]>,
    secrets_injected: bool,
) -> CommandDecision {
    let Some(first) = argv.first() else {
        return CommandDecision::allow(MODE_WORK);
    };
    if raw_argv0_is_wrapper_option(argv) {
        return CommandDecision::deny(
            MODE_UNSAFE_ENV,
            "blocked for security: command name cannot start with '-' in kv_run. Use an explicit \
             path such as ./-tool when the executable name begins with a dash."
                .into(),
        );
    }
    let program = program_name(first);
    let exfil_pattern = matches_exfil_pattern(argv);
    if !secrets_injected {
        if let Some(pattern) = exfil_pattern {
            return CommandDecision::deny(
                MODE_REVEAL,
                format!("blocked for security: command matches exfiltration pattern '{pattern}'"),
            );
        }
        return CommandDecision::allow(MODE_WORK);
    }
    if BLOCKED_SHELLS.contains(&program.as_str()) {
        return CommandDecision::deny(
            MODE_UNSAFE_ENV,
            format!(
                "blocked for security: shell '{program}' cannot be used with kv_run. Write a \
                 script file and run that instead (e.g., python3 app.py)"
            ),
        );
    }
    if let Some((_, flag)) = INLINE_CODE_FLAGS.iter().find(|(name, _)| *name == program)
        && argv[1..].iter().any(|arg| arg == flag)
    {
        return CommandDecision::deny(
            MODE_UNSAFE_ENV,
            format!(
                "blocked for security: inline code execution ('{program} {flag}') not allowed. \
                 Write your code to a file and run that instead. This check is a short help: \
                 what protects a run with secrets is the owner's approval of its exact words"
            ),
        );
    }
    if let Some(hint) = broker_hint_for_argv(argv) {
        let handoff = broker_handoff_for_argv(argv);
        let (mode, reason) = match hint.kind {
            "http" => (
                MODE_BROKERED_ACT,
                format!(
                    "blocked for security: HTTP client '{program}' should not receive secrets \
                     via kv_run. Use kv_api for authenticated API calls instead"
                ),
            ),
            "remote_shell" => (
                MODE_BROKERED_ACT,
                format!(
                    "blocked for security: remote shell tool '{program}' should not receive \
                     secrets via kv_run. Use kv_ssh for configured SSH targets instead"
                ),
            ),
            "raw_network" => (
                MODE_UNSAFE_ENV,
                format!(
                    "blocked for security: raw network tool '{program}' cannot be used with \
                     secrets. Use a brokered kv tool instead"
                ),
            ),
            _ => (
                MODE_BROKERED_ACT,
                format!(
                    "blocked for security: database client '{program}' should not receive \
                     secrets via kv_run. Use kv_query for configured databases instead"
                ),
            ),
        };
        return CommandDecision::deny_with(mode, reason, handoff);
    }
    if let Some(pattern) = exfil_pattern {
        return CommandDecision::deny(
            MODE_REVEAL,
            format!("blocked for security: command matches exfiltration pattern '{pattern}'"),
        );
    }
    match allowed_commands {
        Some(allowed_commands) => {
            let Some(allowed_match) = matching_allowlist_entry(argv, allowed_commands) else {
                let hint = allowlist_hint_for_argv(argv);
                return CommandDecision::deny(
                    MODE_GUARDED_ENV,
                    format!("blocked: command not in allowlist. Add it with: kv allow \"{hint}\""),
                );
            };
            let broad_reason = broad_secret_allowlist_reason(allowed_match);
            if !broad_reason.is_empty() {
                return CommandDecision::deny(
                    MODE_UNSAFE_ENV,
                    format!("blocked for security: {broad_reason}"),
                );
            }
        }
        None => {
            let unapproved_reason = unapproved_broad_interpreter_reason(argv);
            if !unapproved_reason.is_empty() {
                return CommandDecision::deny(
                    MODE_UNSAFE_ENV,
                    format!("blocked for security: {unapproved_reason}"),
                );
            }
        }
    }
    CommandDecision::allow(MODE_GUARDED_ENV)
}

/// Python `check_command`: `(allowed, reason)`.
pub fn check_command(
    argv: &[String],
    allowed_commands: Option<&[String]>,
    secrets_injected: bool,
) -> (bool, String) {
    let decision = classify_command(argv, allowed_commands, secrets_injected);
    (decision.allowed, decision.reason)
}

/// Python `effective_run_mode`: what actually reached the subprocess.
pub fn effective_run_mode(command_mode: &'static str, injected_secret_count: i64) -> &'static str {
    if command_mode == MODE_GUARDED_ENV && injected_secret_count <= 0 {
        MODE_WORK
    } else {
        command_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_string()).collect()
    }

    #[test]
    fn shells_and_inline_code_are_refused_with_secrets_only() {
        let d = classify_command(&argv(&["/bin/bash", "x.sh"]), None, true);
        assert!(!d.allowed);
        assert_eq!(d.mode, MODE_UNSAFE_ENV);
        assert!(d.reason.starts_with("blocked for security: shell 'bash'"));
        let d = classify_command(&argv(&["/bin/bash", "x.sh"]), None, false);
        assert_eq!(d, CommandDecision::allow(MODE_WORK));
        let d = classify_command(&argv(&["python3", "-c", "1"]), None, true);
        assert!(d.reason.contains("('python3 -c')"));
    }

    #[test]
    fn http_tools_hand_off_to_kv_api() {
        let d = classify_command(&argv(&["curl", "https://x"]), None, true);
        assert_eq!(d.mode, MODE_BROKERED_ACT);
        let handoff = d.broker_handoff.as_ref().unwrap();
        assert_eq!(handoff["recommended_tool"], json!("kv_api"));
        assert_eq!(handoff["blocked_program"], json!("curl"));
        assert_eq!(session_denial_reason(&d, true), d.reason);
        let d = classify_command(&argv(&["psql"]), None, true);
        assert!(session_denial_reason(&d, true).contains("database tool"));
    }

    #[test]
    fn exfil_patterns_apply_without_secrets() {
        let d = classify_command(&argv(&["printenv", ">", "out"]), None, false);
        assert_eq!(d.mode, MODE_REVEAL);
        assert!(d.reason.ends_with("'printenv >'"));
    }

    #[test]
    fn allowlist_prefix_and_broad_entries() {
        let allowed = argv(&["python3 app.py", "npm test"]);
        assert!(
            classify_command(
                &argv(&["/usr/bin/python3", "app.py", "--x"]),
                Some(&allowed),
                true
            )
            .allowed
        );
        let d = classify_command(&argv(&["python3", "-m", "pytest"]), Some(&allowed), true);
        assert_eq!(
            d.reason,
            "blocked: command not in allowlist. Add it with: kv allow \"python3 -m pytest\""
        );
        let d = classify_command(&argv(&["python3", "x.py"]), Some(&argv(&["python3"])), true);
        assert!(d.reason.contains("too broad"));
        let d = classify_command(&argv(&["python3"]), None, true);
        assert!(
            d.reason
                .contains("interpreter 'python3' cannot receive secrets")
        );
        assert!(classify_command(&argv(&["python3", "x.py"]), None, true).allowed);
    }

    #[test]
    fn effective_mode_downgrades_guarded_without_secrets() {
        assert_eq!(effective_run_mode(MODE_GUARDED_ENV, 0), MODE_WORK);
        assert_eq!(effective_run_mode(MODE_GUARDED_ENV, 2), MODE_GUARDED_ENV);
        assert_eq!(effective_run_mode(MODE_REVEAL, 0), MODE_REVEAL);
    }
}
