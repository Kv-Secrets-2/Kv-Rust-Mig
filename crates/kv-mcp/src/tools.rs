//! `kv_mcp.tools`: the tool definitions, profile and vault filtering, and the
//! daemon-mode handlers with Python's exact reply texts.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

use indexmap::IndexMap;

use crate::agent::{self, RequestError};
use crate::pyval::{self, DumpOptions, PyValue, dumps, py_repr, py_str, py_strip};
use crate::redact;
use crate::vault::{self, Kind};

pub const MAX_ARGV_COUNT: usize = 50;
pub const MAX_ARGV_LEN: usize = 4096;
pub const MAX_LIST_KEYS: usize = 1000;
const HIDDEN_ON_PROTECTED: [&str; 5] = ["kv_query", "kv_ssh", "kv_set", "kv_rm", "kv_get"];

pub type Profiles = BTreeSet<String>;
pub type Reply = IndexMap<String, PyValue>;

pub struct Tool {
    pub name: String,
    pub profile: String,
    pub definition: PyValue,
}

/// The ten tools in Python's `TOOLS` order (generated from Python 0.4.0).
pub fn tools() -> &'static [Tool] {
    static TOOLS: OnceLock<Vec<Tool>> = OnceLock::new();
    TOOLS.get_or_init(|| {
        let parsed: serde_json::Value =
            serde_json::from_str(include_str!("data/tools.json")).expect("tools.json is valid");
        parsed
            .as_array()
            .expect("tools.json is a list")
            .iter()
            .map(|tool| {
                let field = |name: &str| PyValue::from_json(&tool[name]);
                Tool {
                    name: tool["name"].as_str().expect("tool name").to_owned(),
                    profile: tool["profile"].as_str().expect("tool profile").to_owned(),
                    definition: pyval::dict([
                        ("name", field("name")),
                        ("description", field("description")),
                        ("inputSchema", field("inputSchema")),
                    ]),
                }
            })
            .collect()
    })
}

pub fn tool(name: &str) -> Option<&'static Tool> {
    tools().iter().find(|tool| tool.name == name)
}

pub fn is_hidden_on_protected(name: &str) -> bool {
    HIDDEN_ON_PROTECTED.contains(&name)
}

/// `get_tools_for_kind(profiles, kind)`.
pub fn tools_for_kind(profiles: &Profiles, kind: Kind) -> Vec<PyValue> {
    tools()
        .iter()
        .filter(|tool| profiles.contains(&tool.profile))
        .filter(|tool| kind == Kind::Unprotected || !is_hidden_on_protected(&tool.name))
        .map(|tool| tool.definition.clone())
        .collect()
}

/// `hidden_tools_for_profiles(profiles)`.
pub fn hidden_tools_for_profiles(profiles: &Profiles) -> Vec<&'static str> {
    HIDDEN_ON_PROTECTED
        .into_iter()
        .filter(|name| tool(name).is_some_and(|tool| profiles.contains(&tool.profile)))
        .collect()
}

/// `hidden_tool_reason(name, kind, reason, profiles)`.
pub fn hidden_tool_reason(
    name: &str,
    kind: Kind,
    reason: &str,
    profiles: Option<&Profiles>,
) -> String {
    let head = format!("{name} is not available on this vault");
    if kind != Kind::Protected {
        return format!(
            "{head}: the vault's key file could not be read as a known key ({reason}). \
             Tell the user to run 'kv status' or 'kv doctor' in a terminal; do not retry \
             or look for another way."
        );
    }
    if vault::PARKED_ON_PROTECTED.contains(&name) {
        return format!(
            "{head}: kv_query and kv_ssh are parked on passphrase-protected (v3/v4) \
             vaults in this release. Tell the user; do not retry or look for another way."
        );
    }
    if name == "kv_get" {
        let use_ = if profiles.is_none_or(|profiles| profiles.contains("execute")) {
            "kv_api or kv_run"
        } else {
            "kv_api"
        };
        return format!(
            "{head}: it needs direct vault access, which passphrase-protected (v3/v4) \
             vaults refuse. Use {use_} so the value never enters your context; \
             do not ask the user for the value."
        );
    }
    let tail = match name {
        "kv_set" => " Ask the user to run 'kv set' in their own terminal.".to_owned(),
        "kv_rm" => " Ask the user to run 'kv rm' in their own terminal.".to_owned(),
        _ => " Tell the user; do not retry or look for another way.".to_owned(),
    };
    format!(
        "{head}: it needs direct vault access, which passphrase-protected (v3/v4) vaults \
         refuse.{tail}"
    )
}

/// `not_offered_log_line(hidden, kind, reason)`.
pub fn not_offered_log_line(hidden: &[&str], kind: Kind, reason: &str) -> String {
    let why_not = vault::why_not_offered(kind, reason);
    if kind == Kind::Protected {
        let mut why = Vec::new();
        if hidden
            .iter()
            .any(|name| vault::PARKED_ON_PROTECTED.contains(name))
        {
            why.push("kv_query and kv_ssh are parked in this release".to_owned());
        }
        let direct: Vec<&str> = hidden
            .iter()
            .copied()
            .filter(|name| vault::DIRECT_ONLY.contains(name))
            .collect();
        if !direct.is_empty() {
            why.push(format!(
                "{} need direct vault access, which such vaults refuse",
                direct.join(", ")
            ));
        }
        return format!(
            "{why_not} these tools are not offered: {} ({})",
            hidden.join(", "),
            why.join("; ")
        );
    }
    format!(
        "these tools are not offered: {}, {why_not}",
        hidden.join(", ")
    )
}

// -- Python semantics the handlers depend on ---------------------------------

/// An exception a handler raised, as the server reports it.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolError {
    InvalidEnvironment(String),
    Outdated(String),
    Exception { type_name: String, message: String },
}

impl From<RequestError> for ToolError {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Outdated(message) => Self::Outdated(message),
            RequestError::Exception { type_name, message } => {
                Self::Exception { type_name, message }
            }
        }
    }
}

type PyResult<T> = Result<T, ToolError>;

fn exception(type_name: &str, message: impl Into<String>) -> ToolError {
    ToolError::Exception {
        type_name: type_name.into(),
        message: message.into(),
    }
}

/// `value.get(key)`: an AttributeError unless `value` is a dict.
fn get<'a>(value: &'a PyValue, key: &str) -> PyResult<Option<&'a PyValue>> {
    match value {
        PyValue::Dict(items) => Ok(items.get(key)),
        other => Err(exception(
            "AttributeError",
            format!("'{}' object has no attribute 'get'", other.type_name()),
        )),
    }
}

fn get_or(value: &PyValue, key: &str, default: PyValue) -> PyResult<PyValue> {
    Ok(get(value, key)?.cloned().unwrap_or(default))
}

fn truthy(value: Option<&PyValue>) -> bool {
    value.is_some_and(PyValue::truthy)
}

fn not_none(value: Option<&PyValue>) -> Option<&PyValue> {
    value.filter(|value| **value != PyValue::Null)
}

/// `iter(value)` as a `for` loop sees it.
fn iterate(value: &PyValue) -> PyResult<Vec<PyValue>> {
    match value {
        PyValue::List(items) => Ok(items.clone()),
        PyValue::Str(text) => Ok(text
            .chars()
            .map(|ch| PyValue::Str(ch.to_string()))
            .collect()),
        PyValue::Dict(items) => Ok(items.keys().cloned().map(PyValue::Str).collect()),
        other => Err(exception(
            "TypeError",
            format!("'{}' object is not iterable", other.type_name()),
        )),
    }
}

/// `separator.join(value)`.
fn join(separator: &str, value: &PyValue) -> PyResult<String> {
    if !matches!(value, PyValue::List(_) | PyValue::Str(_) | PyValue::Dict(_)) {
        return Err(exception("TypeError", "can only join an iterable"));
    }
    let mut parts = Vec::new();
    for (index, item) in iterate(value)?.iter().enumerate() {
        match item {
            PyValue::Str(text) => parts.push(text.clone()),
            other => {
                return Err(exception(
                    "TypeError",
                    format!(
                        "sequence item {index}: expected str instance, {} found",
                        other.type_name()
                    ),
                ));
            }
        }
    }
    Ok(parts.join(separator))
}

fn py_rstrip(text: &str) -> &str {
    text.trim_end_matches(pyval::py_isspace)
}

fn equals_zero(value: &PyValue) -> bool {
    match value {
        PyValue::Int(digits) => digits == "0",
        PyValue::Float(number) => *number == 0.0,
        PyValue::Bool(flag) => !flag,
        _ => false,
    }
}

fn ascii(sort_keys: bool, indent: Option<usize>) -> DumpOptions {
    DumpOptions {
        ensure_ascii: true,
        sort_keys,
        indent,
    }
}

pub fn text_reply(text: impl Into<String>, is_error: bool) -> Reply {
    let mut reply = Reply::new();
    reply.insert(
        "content".into(),
        PyValue::List(vec![pyval::dict([
            ("type", PyValue::str("text")),
            ("text", PyValue::Str(text.into())),
        ])]),
    );
    reply.insert("isError".into(), PyValue::Bool(is_error));
    reply
}

// -- Request validation (kv.agent._validate_agent_request) -------------------

/// `kv.envname.validate_env_name`; the error is `str(InvalidEnvironmentName)`.
pub fn validate_env_name(value: &PyValue) -> Result<&str, String> {
    let name = match value {
        PyValue::Str(name) if !name.is_empty() => name,
        _ => return Err("environment name must be a non-empty string".into()),
    };
    if name.len() > 128 {
        return Err("env exceeds 128 UTF-8 bytes".into());
    }
    if kv_store::envname::has_path_syntax(name) {
        return Err(format!(
            "invalid environment name: {}; run 'kv env repair-names' to inspect old registrations",
            py_repr(value)
        ));
    }
    Ok(name)
}

fn daemon_env_error(text: String) -> String {
    for prefix in ["invalid environment name", "ambiguous environment name"] {
        if text.starts_with(prefix) {
            return format!("{prefix}; run 'kv env repair-names' to inspect old registrations");
        }
    }
    text
}

fn validate_str<'a>(
    value: Option<&'a PyValue>,
    field: &str,
    max_len: usize,
    required: bool,
    allow_empty: bool,
) -> Result<Option<&'a str>, String> {
    let Some(value) = not_none(value) else {
        return if required {
            Err(format!("{field} is required"))
        } else {
            Ok(None)
        };
    };
    let PyValue::Str(text) = value else {
        return Err(format!("{field} must be a string"));
    };
    if !allow_empty && text.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if text.len() > max_len {
        return Err(format!("{field} exceeds {max_len} bytes"));
    }
    Ok(Some(text))
}

fn validate_str_list(
    value: Option<&PyValue>,
    field: &str,
    max_items: usize,
    max_item_len: usize,
) -> Result<(), String> {
    let Some(value) = not_none(value) else {
        return Ok(());
    };
    let PyValue::List(items) = value else {
        return Err(format!("{field} must be a list"));
    };
    if items.len() > max_items {
        return Err(format!("{field} has too many items (max {max_items})"));
    }
    for (index, item) in items.iter().enumerate() {
        validate_str(
            Some(item),
            &format!("{field}[{index}]"),
            max_item_len,
            true,
            false,
        )?;
    }
    Ok(())
}

fn validate_argv(value: Option<&PyValue>) -> Result<(), String> {
    let Some(value) = not_none(value) else {
        return Err("argv is required".into());
    };
    let PyValue::List(items) = value else {
        return Err("argv must be a list".into());
    };
    if items.is_empty() {
        return Err("argv must not be empty".into());
    }
    if items.len() > MAX_ARGV_COUNT {
        return Err(format!("argv has too many items (max {MAX_ARGV_COUNT})"));
    }
    for (index, item) in items.iter().enumerate() {
        validate_str(
            Some(item),
            &format!("argv[{index}]"),
            MAX_ARGV_LEN,
            true,
            index > 0,
        )?;
    }
    Ok(())
}

fn validate_agent_request(request: &Reply) -> Result<(), String> {
    let cmd = request
        .get("cmd")
        .and_then(PyValue::as_str)
        .unwrap_or_default();
    if cmd == "api" && request.contains_key("permit_id") {
        validate_str(request.get("permit_id"), "permit_id", 128, true, false)?;
    }
    if matches!(cmd, "api" | "run") && request.contains_key("reason") {
        validate_str(request.get("reason"), "reason", 512, false, true)?;
    }
    if let Some(env) = not_none(request.get("env")) {
        validate_env_name(env).map_err(daemon_env_error)?;
    }
    validate_str(request.get("env"), "env", 128, false, false)?;
    match cmd {
        "run" => {
            validate_argv(request.get("argv"))?;
            validate_str_list(request.get("env_names"), "env_names", 1000, 256)?;
            validate_str_list(request.get("capability_names"), "capability_names", 16, 256)?;
            let raw = not_none(request.get("env_names"))
                .is_some_and(|names| *names != PyValue::List(Vec::new()));
            if raw && truthy(request.get("capability_names")) {
                return Err("kv_run cannot mix raw secrets and capabilities".into());
            }
            validate_str(request.get("cwd"), "cwd", 4096, false, false)?;
            if not_none(request.get("private_cwd"))
                .is_some_and(|flag| !matches!(flag, PyValue::Bool(_)))
            {
                return Err("private_cwd must be a boolean".into());
            }
        }
        "api" => {
            validate_str(request.get("provider"), "provider", 128, true, false)?;
            validate_str(request.get("path"), "path", 4096, true, false)?;
            let default_method = PyValue::str("GET");
            let method = validate_str(
                Some(request.get("method").unwrap_or(&default_method)),
                "method",
                16,
                true,
                false,
            )?
            .unwrap_or_default();
            if !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
                .contains(&method.to_uppercase().as_str())
            {
                return Err("unsupported method".into());
            }
            if let Some(body) = not_none(request.get("body")) {
                if !matches!(body, PyValue::Dict(_) | PyValue::List(_) | PyValue::Str(_)) {
                    return Err("body must be an object, array, or string".into());
                }
                if dumps(body, ascii(false, None)).len() > 512 * 1024 {
                    return Err("body exceeds 524288 bytes".into());
                }
            }
            if let Some(headers) = not_none(request.get("headers")) {
                let PyValue::Dict(headers) = headers else {
                    return Err("headers must be an object".into());
                };
                if headers.len() > 64 {
                    return Err("headers has too many entries (max 64)".into());
                }
                for (index, (name, value)) in headers.iter().enumerate() {
                    validate_str(
                        Some(&PyValue::Str(name.clone())),
                        "header name",
                        128,
                        true,
                        false,
                    )?;
                    validate_str(
                        Some(value),
                        &format!("headers[{index}] value"),
                        4096,
                        true,
                        true,
                    )?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

// -- Handlers ----------------------------------------------------------------

pub struct Context<'a> {
    pub root: &'a Path,
    pub default_env: &'a str,
}

type Args = IndexMap<String, PyValue>;

/// `_get_env_name(args, default_env)`.
fn env_name(args: &Args, default_env: &str) -> PyResult<String> {
    let value = not_none(args.get("env"))
        .cloned()
        .unwrap_or_else(|| PyValue::str(default_env));
    validate_env_name(&value)
        .map(str::to_owned)
        .map_err(ToolError::InvalidEnvironment)
}

/// `_validate_agent_shape(args, cmd, default_env, **fields)`.
fn validate_shape(
    args: &Args,
    cmd: &str,
    default_env: &str,
    fields: &[(&str, PyValue)],
) -> PyResult<Option<Reply>> {
    let mut request = Reply::new();
    request.insert("cmd".into(), PyValue::str(cmd));
    request.insert("token".into(), PyValue::str("mcp-local"));
    for (name, value) in fields {
        request.insert((*name).to_owned(), value.clone());
    }
    request.insert("env".into(), PyValue::Str(env_name(args, default_env)?));
    Ok(validate_agent_request(&request)
        .err()
        .map(|error| text_reply(format!("error: {error}"), true)))
}

/// `_agent_request_with_audit(args, cmd, **fields)`.
fn audited_request(
    args: &Args,
    context: &Context,
    cmd: &str,
    mut fields: Vec<(&str, PyValue)>,
) -> Result<PyValue, RequestError> {
    if not_none(args.get("env")).is_none() {
        fields.retain(|(name, _)| *name != "env");
    }
    if let Some(audit) = args
        .get("_audit_ctx")
        .filter(|audit| matches!(audit, PyValue::Dict(items) if !items.is_empty()))
    {
        fields.push(("audit_ctx", audit.clone()));
    }
    agent::request(context.root, cmd, &fields)
}

fn handle_status(args: &Args, context: &Context) -> PyResult<Reply> {
    let result = audited_request(args, context, "status", Vec::new())?;
    let providers = join(
        ", ",
        &get_or(&result, "providers", PyValue::List(Vec::new()))?,
    )?;
    let providers = if providers.is_empty() {
        "(none)".to_owned()
    } else {
        providers
    };
    let text = format!(
        "project: initialized (via daemon)\nroot: {}\ndefault_env: {}\nenvironments: {}\nsecrets: {}\nproviders: {}\nrun_policy: {}\nhttp_policy: {}",
        py_str(&get_or(&result, "root", PyValue::str("?"))?),
        context.default_env,
        py_str(&get_or(&result, "environments", PyValue::Null)?),
        py_str(&get_or(&result, "secrets", PyValue::Null)?),
        providers,
        py_str(&get_or(&result, "policy", PyValue::str("?"))?),
        dumps(
            &get_or(&result, "http_policy", PyValue::Dict(IndexMap::new()))?,
            ascii(true, None)
        ),
    );
    Ok(text_reply(text, false))
}

fn handle_envs(args: &Args, context: &Context) -> PyResult<Reply> {
    let result = audited_request(args, context, "envs", Vec::new())?;
    let envs = get_or(&result, "environments", PyValue::List(Vec::new()))?;
    let mut text = if envs.truthy() {
        join("\n", &envs)?
    } else {
        "(no environments)".to_owned()
    };
    for name in iterate(&get_or(
        &result,
        "invalid_environments",
        PyValue::List(Vec::new()),
    )?)? {
        text.push_str(&format!(
            "\n{} (invalid; run kv env repair-names)",
            py_str(&name)
        ));
    }
    Ok(text_reply(text, false))
}

fn handle_list(args: &Args, context: &Context) -> PyResult<Reply> {
    let env = env_name(args, context.default_env)?;
    if let Some(error) = validate_shape(args, "list", context.default_env, &[])? {
        return Ok(error);
    }
    let result = audited_request(args, context, "list", vec![("env", PyValue::Str(env))])?;
    let names = match get_or(&result, "keys", PyValue::List(Vec::new()))? {
        PyValue::List(items) => PyValue::List(items.into_iter().take(MAX_LIST_KEYS).collect()),
        PyValue::Str(text) => PyValue::Str(text.chars().take(MAX_LIST_KEYS).collect()),
        other => {
            return Err(exception(
                "TypeError",
                format!("'{}' object is not subscriptable", other.type_name()),
            ));
        }
    };
    let text = if names.truthy() {
        join("\n", &names)?
    } else {
        "(no secrets)".to_owned()
    };
    Ok(text_reply(text, false))
}

struct BrokerHint {
    tool: Option<&'static str>,
    reason: &'static str,
    action: &'static str,
    arguments: PyValue,
    program: String,
}

fn broker_hint(argv: &[PyValue]) -> Option<BrokerHint> {
    let first = argv.first()?.as_str()?;
    let program = first.rsplit('/').next().unwrap_or(first).to_lowercase();
    let kind = match program.as_str() {
        "curl" | "wget" | "fetch" | "httpie" | "http" | "xh" | "aria2c" | "lwp-request" => "http",
        "ssh" | "scp" | "sftp" | "rsync" => "remote_shell",
        "psql" | "mysql" | "redis-cli" => "database",
        "nc" | "ncat" | "netcat" | "socat" | "telnet" | "ftp" | "lftp" => "raw_network",
        _ => return None,
    };
    let s = PyValue::str;
    let (tool, reason, action, arguments) = match kind {
        "http" => (
            Some("kv_api"),
            "authenticated HTTP/API calls",
            "call kv_api with provider, path, method, and body instead of passing secrets to an HTTP CLI",
            pyval::dict([
                ("provider", s("<configured API provider>")),
                ("path", s("<endpoint path>")),
                ("method", s("GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE")),
                ("body", s("<optional JSON body>")),
            ]),
        ),
        "remote_shell" => (
            Some("kv_ssh"),
            "remote shell or file-transfer actions",
            "call kv_ssh with a configured SSH provider instead of passing secrets to ssh/scp/sftp/rsync",
            pyval::dict([
                ("provider", s("<configured SSH provider>")),
                ("command", s("<remote command>")),
            ]),
        ),
        "database" => (
            Some("kv_query"),
            "database queries",
            "call kv_query with a configured database provider instead of passing secrets to a DB CLI",
            pyval::dict([
                ("provider", s("<configured database provider>")),
                ("query", s("<SQL query or Redis command>")),
            ]),
        ),
        _ => (
            None,
            "raw network access with injected secrets",
            "use a brokered kv tool or a purpose-built provider instead of raw network utilities",
            PyValue::Dict(IndexMap::new()),
        ),
    };
    Some(BrokerHint {
        tool,
        reason,
        action,
        arguments,
        program,
    })
}

fn broker_handoff_for_argv(argv: &[PyValue]) -> PyValue {
    let Some(hint) = broker_hint(argv) else {
        return PyValue::Null;
    };
    pyval::dict([
        (
            "recommended_tool",
            hint.tool.map_or(PyValue::Null, PyValue::str),
        ),
        ("blocked_program", PyValue::Str(hint.program)),
        ("reason", PyValue::str(hint.reason)),
        ("next_step", PyValue::str(hint.action)),
        ("arguments_template", hint.arguments),
        (
            "credential_boundary",
            PyValue::str(
                "The daemon should use the credential; the agent should not receive the raw secret.",
            ),
        ),
    ])
}

/// `_format_kv_run_error(text, argv, mode, broker_handoff, approval_hint)`.
fn format_run_error(text: String, argv: &[PyValue], result: &PyValue) -> PyResult<String> {
    let mode = get(result, "mode")?;
    let given = get(result, "broker_handoff")?;
    let approval_hint = get(result, "approval_hint")?;
    let hint = broker_hint(argv);
    let handoff = match given {
        Some(handoff) if handoff.truthy() => handoff.clone(),
        _ => broker_handoff_for_argv(argv),
    };
    let mut base = text;
    if let Some(mode) = mode.filter(|mode| mode.truthy()) {
        let line = format!("mode: {}", py_str(mode));
        if !base.contains(&line) {
            base = format!("{base}\n{line}");
        }
    }
    if let Some(hint) = hint {
        let mut tool = hint.tool;
        let mut action = hint.action.to_owned();
        if tool.is_some()
            && handoff != PyValue::Null
            && truthy(get(&handoff, "recommended_tool_parked")?)
        {
            tool = None;
            if let Some(next) = get(&handoff, "next_step")?.filter(|next| next.truthy()) {
                action = py_str(next);
            }
        }
        let guidance = match tool {
            Some(tool) => format!("recommended MCP tool: {tool} ({}); {action}.", hint.reason),
            None => format!("recommended next step: {action}."),
        };
        if !base.contains(&guidance) {
            base = format!("{base}\n{guidance}");
        }
    }
    if handoff.truthy() {
        if let Some(providers) =
            get(&handoff, "available_providers")?.filter(|value| value.truthy())
        {
            let line = format!("available broker providers: {}", join(", ", providers)?);
            if !base.contains(&line) {
                base = format!("{base}\n{line}");
            }
        } else if let Some(setup) =
            get(&handoff, "provider_setup_hint")?.filter(|value| value.truthy())
        {
            let line = format!("provider setup needed: {}", py_str(setup));
            if !base.contains(&line) {
                base = format!("{base}\n{line}");
            }
        }
    }
    if let Some(PyValue::Dict(approval)) = approval_hint
        && let Some(PyValue::Str(command)) = approval.get("command")
        && !py_strip(command).is_empty()
        && !base.contains(command.as_str())
    {
        base = format!(
            "{base}\nuser approval needed: review requester, command, folder, and secret/capability scope, then run:\n{command}"
        );
    }
    if !handoff.truthy() || base.contains("broker_handoff:") {
        return Ok(base);
    }
    Ok(format!(
        "{base}\nbroker_handoff:\n{}",
        dumps(&handoff, ascii(true, Some(2)))
    ))
}

const RUN_METADATA: [&str; 14] = [
    "mode",
    "secret_scope",
    "injected_secret_count",
    "run_id",
    "command_fingerprint",
    "script_kind",
    "script_sha256",
    "script_ref_hash",
    "approval_hint",
    "capsule_artifact",
    "capsule_cwd",
    "copied_output_count",
    "capability_name",
    "capability_token_id",
];

fn run_text(result: &PyValue, argv: &[PyValue]) -> PyResult<(String, bool)> {
    if let Some(error) = get(result, "error")? {
        let text = format_run_error(format!("error: {}", py_str(error)), argv, result)?;
        return Ok((text, true));
    }
    let exit_code = get_or(result, "exit_code", PyValue::int(1))?;
    let mut parts = vec![format!("exit code: {}", py_str(&exit_code))];
    for stream in ["stdout", "stderr"] {
        match get_or(result, stream, PyValue::str(""))? {
            PyValue::Str(text) => {
                if !py_strip(&text).is_empty() {
                    parts.push(format!("{stream}:\n{}", py_rstrip(&text)));
                }
            }
            other => {
                return Err(exception(
                    "AttributeError",
                    format!("'{}' object has no attribute 'strip'", other.type_name()),
                ));
            }
        }
    }
    Ok((parts.join("\n"), !equals_zero(&exit_code)))
}

fn handle_run(args: &Args, context: &Context) -> PyResult<Reply> {
    let argv = match args.get("argv") {
        Some(PyValue::List(items)) if !items.is_empty() => items.clone(),
        _ => {
            return Ok(text_reply(
                "error: argv is required and must be an array",
                true,
            ));
        }
    };
    if argv.len() > MAX_ARGV_COUNT {
        return Ok(text_reply(
            format!("error: too many arguments (max {MAX_ARGV_COUNT})"),
            true,
        ));
    }
    for (index, item) in argv.iter().enumerate() {
        let Some(text) = item.as_str() else {
            return Ok(text_reply(
                format!("error: argv[{index}] must be a string"),
                true,
            ));
        };
        if text.chars().count() > MAX_ARGV_LEN {
            return Ok(text_reply(
                format!("error: argv[{index}] exceeds max length ({MAX_ARGV_LEN})"),
                true,
            ));
        }
    }
    let env = env_name(args, context.default_env)?;
    let mut words: Vec<String> = Vec::new();
    for item in &argv {
        if let Some(word) = item.as_str().filter(|word| !word.is_empty()) {
            words.push(word.to_owned());
            let base = word.rsplit('/').next().unwrap_or(word);
            if !base.is_empty() && base != word {
                words.push(base.to_owned());
            }
        }
    }
    if let Some(PyValue::Str(cwd)) = args.get("cwd")
        && !cwd.is_empty()
    {
        words.push(cwd.clone());
    }
    words.push(env.clone());
    for name in ["TMPDIR", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(name)
            && !value.is_empty()
        {
            words.push(value);
        }
    }
    let mut fields: Vec<(&str, PyValue)> = vec![("argv", PyValue::List(argv.clone()))];
    let mut optional: Vec<(&str, PyValue)> = Vec::new();
    for name in ["env_names", "capability_names"] {
        if let Some(value) = not_none(args.get(name)) {
            optional.push((name, value.clone()));
        }
    }
    if let Some(cwd) = args.get("cwd").filter(|cwd| cwd.truthy()) {
        optional.push(("cwd", cwd.clone()));
    }
    if let Some(private) = not_none(args.get("private_cwd")) {
        optional.push(("private_cwd", private.clone()));
    }
    if let Some(reason) = args.get("reason") {
        optional.push(("reason", reason.clone()));
    }
    let mut validation = fields.clone();
    validation.extend(optional.iter().cloned());
    if let Some(mut error) = validate_shape(args, "run", context.default_env, &validation)? {
        if let Some(PyValue::List(content)) = error.get_mut("content")
            && let Some(PyValue::Dict(item)) = content.first_mut()
            && let Some(PyValue::Str(text)) = item.get_mut("text")
        {
            *text = redact::redact(text, words.iter().map(String::as_str));
        }
        return Ok(error);
    }
    fields.push(("env", PyValue::Str(env)));
    fields.extend(optional);
    let mut result = PyValue::Dict(IndexMap::new());
    let (text, is_error) = match audited_request(args, context, "run", fields) {
        Err(RequestError::Outdated(message)) => {
            return Ok(text_reply(format!("error: {message}"), true));
        }
        Err(RequestError::Exception { message, .. }) => {
            (format!("error: agent daemon unavailable — {message}"), true)
        }
        Ok(reply) => {
            result = reply;
            match run_text(&result, &argv) {
                Ok(done) => done,
                Err(ToolError::Exception { message, .. }) => {
                    (format!("error: agent daemon unavailable — {message}"), true)
                }
                Err(other) => return Err(other),
            }
        }
    };
    let mut reply = text_reply(text, is_error);
    for key in RUN_METADATA {
        if let Some(PyValue::Dict(items)) = Some(&result)
            && let Some(value) = items.get(key)
        {
            reply.insert(key.into(), value.clone());
        }
    }
    let mut warnings = Vec::new();
    if let Some(warning) = get(&result, "warning")?.filter(|warning| warning.truthy()) {
        warnings.push(warning.clone());
    }
    let scope = get(&result, "secret_scope")?;
    let count = get_or(&result, "injected_secret_count", PyValue::int(0))?;
    if scope == Some(&PyValue::str("all")) && count.truthy() {
        warnings.push(PyValue::str(
            "env_names was omitted, so kv_run injected every secret in the selected environment. Prefer env_names with the smallest required secret set.",
        ));
    }
    if !warnings.is_empty() {
        reply.insert(
            "warning".into(),
            PyValue::Str(join("\n", &PyValue::List(warnings))?),
        );
    }
    Ok(reply)
}

fn attach_result_warning(mut reply: Reply, result: &PyValue) -> PyResult<Reply> {
    if let Some(warning) = get(result, "warning")?.filter(|warning| warning.truthy()) {
        reply.insert("warning".into(), warning.clone());
    }
    if truthy(get(result, "response_truncated")?) {
        reply.insert("response_truncated".into(), PyValue::Bool(true));
    }
    for key in [
        "max_response_bytes",
        "max_rows",
        "max_columns",
        "max_cell_bytes",
    ] {
        if let Some(value) = not_none(get(result, key)?) {
            reply.insert(key.into(), value.clone());
        }
    }
    for key in [
        "error_code",
        "approval_required",
        "policy_rule",
        "permit_id",
        "request_id",
    ] {
        if let Some(value) = get(result, key)? {
            reply.insert(key.into(), value.clone());
        }
    }
    Ok(reply)
}

fn handle_api(args: &Args, context: &Context) -> PyResult<Reply> {
    let provider = args.get("provider").cloned().unwrap_or(PyValue::Null);
    let path = args.get("path").cloned().unwrap_or(PyValue::Null);
    if !provider.truthy() {
        return Ok(text_reply(
            "error: provider is required (openai, anthropic, google, github, google-cloud)",
            true,
        ));
    }
    if !path.truthy() {
        return Ok(text_reply(
            "error: path is required (e.g. /v1/models)",
            true,
        ));
    }
    let env = env_name(args, context.default_env)?;
    let method = args
        .get("method")
        .cloned()
        .unwrap_or_else(|| PyValue::str("GET"));
    let body = args.get("body").cloned().unwrap_or(PyValue::Null);
    let headers = args
        .get("headers")
        .cloned()
        .unwrap_or_else(|| PyValue::Dict(IndexMap::new()));
    let mut validation = vec![
        ("provider", provider.clone()),
        ("path", path.clone()),
        ("method", method.clone()),
        ("body", body.clone()),
        ("headers", headers.clone()),
    ];
    if let Some(reason) = args.get("reason") {
        validation.push(("reason", reason.clone()));
    }
    if let Some(error) = validate_shape(args, "api", context.default_env, &validation)? {
        return Ok(error);
    }
    let mut fields = vec![
        ("provider", provider),
        ("path", path),
        ("method", method),
        ("body", body),
        ("headers", headers),
        ("env", PyValue::Str(env)),
    ];
    for name in ["permit_id", "reason"] {
        if let Some(value) = args.get(name) {
            fields.push((name, value.clone()));
        }
    }
    let result = match audited_request(args, context, "api", fields) {
        Ok(result) => result,
        Err(RequestError::Outdated(message)) => {
            return Ok(text_reply(format!("error: {message}"), true));
        }
        Err(RequestError::Exception { message, .. }) => {
            return Ok(text_reply(
                format!("error: agent daemon unavailable — {message}"),
                true,
            ));
        }
    };
    let fallible = || -> PyResult<Reply> {
        if let Some(error) = get(&result, "error")? {
            let mut text = format!(
                "HTTP {}: {}",
                py_str(&get_or(&result, "status", PyValue::str("error"))?),
                py_str(error)
            );
            if let Some(body) = get(&result, "body")?.filter(|body| body.truthy()) {
                let shown = match body {
                    PyValue::Dict(_) | PyValue::List(_) => dumps(body, ascii(false, None)),
                    other => py_str(other),
                };
                text = format!("{text}\n{shown}");
            }
            return attach_result_warning(text_reply(text, true), &result);
        }
        let body = get_or(&result, "body", PyValue::Dict(IndexMap::new()))?;
        let text = match &body {
            PyValue::Dict(_) | PyValue::List(_) => dumps(&body, ascii(false, Some(2))),
            other => py_str(other),
        };
        attach_result_warning(text_reply(text, false), &result)
    };
    match fallible() {
        Err(ToolError::Exception { message, .. }) => Ok(text_reply(
            format!("error: agent daemon unavailable — {message}"),
            true,
        )),
        other => other,
    }
}

/// Dispatch one tool call in daemon mode (`HANDLERS[name](args, None, default_env)`).
pub fn call(name: &str, args: &Args, context: &Context) -> PyResult<Reply> {
    match name {
        "kv_status" => handle_status(args, context),
        "kv_envs" => handle_envs(args, context),
        "kv_list" => handle_list(args, context),
        "kv_run" => handle_run(args, context),
        "kv_api" => handle_api(args, context),
        "kv_set" => Ok(text_reply(
            "error: kv_set requires direct vault access (not available in daemon mode). Stop the agent and restart the MCP server, or use the CLI: kv set KEY",
            true,
        )),
        "kv_rm" => Ok(text_reply(
            "error: kv_rm requires direct vault access (not available in daemon mode). Use the CLI: kv rm KEY",
            true,
        )),
        "kv_get" => Ok(text_reply(
            "error: kv_get requires direct vault access (not available in daemon mode). The agent daemon never returns secret values — this is by design.",
            true,
        )),
        _ => Ok(text_reply(
            format!(
                "error: {}",
                hidden_tool_reason(name, Kind::Protected, "", None)
            ),
            true,
        )),
    }
}
