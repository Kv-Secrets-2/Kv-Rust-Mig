//! `kv_mcp.server` and `kv_mcp.protocol`: the stdio JSON-RPC loop.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Instant;

use indexmap::IndexMap;

use crate::agent;
use crate::pyval::{self, DecodeError, PyValue, py_repr, py_str};
use crate::tools::{self, Context, Profiles, ToolError, text_reply};
use crate::vault::{self, Kind};

pub const SUPPORTED_VERSIONS: [&str; 3] = ["2025-11-25", "2025-06-18", "2025-03-26"];
pub const LATEST_VERSION: &str = "2025-11-25";
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
/// Python reads a line of any length; kv stops reading past this.
pub const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;
pub const KV_VERSION: &str = "0.4.0";

pub struct Config {
    pub root: PathBuf,
    pub default_env: String,
    pub profiles: Profiles,
    pub allow_direct_vault_access: bool,
}

enum Line {
    Text(String),
    Eof,
    Error(String),
}

/// `sys.stdin.readline()` on Unix: lines end at `\n` only (CPython opens
/// stdin with `newline="\n"`), strict UTF-8.
fn read_line<R: BufRead>(input: &mut R) -> Line {
    let mut bytes = Vec::new();
    loop {
        let buffer = match input.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Line::Error(error.to_string()),
        };
        if buffer.is_empty() {
            break;
        }
        if let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
            bytes.extend_from_slice(&buffer[..=index]);
            input.consume(index + 1);
            break;
        }
        let length = buffer.len();
        bytes.extend_from_slice(buffer);
        input.consume(length);
        if bytes.len() > MAX_LINE_BYTES {
            return Line::Error(format!("message exceeds {MAX_LINE_BYTES} bytes"));
        }
    }
    if bytes.len() > MAX_LINE_BYTES {
        return Line::Error(format!("message exceeds {MAX_LINE_BYTES} bytes"));
    }
    if bytes.is_empty() {
        return Line::Eof;
    }
    match String::from_utf8(bytes) {
        Ok(text) => Line::Text(text),
        Err(error) => {
            let utf8 = error.utf8_error();
            let at = utf8.valid_up_to();
            let byte = error.as_bytes()[at];
            let why = match utf8.error_len() {
                None => "unexpected end of data",
                Some(_) if (0x80..0xc2).contains(&byte) || byte > 0xf4 => "invalid start byte",
                Some(_) => "invalid continuation byte",
            };
            Line::Error(format!(
                "'utf-8' codec can't decode byte 0x{byte:02x} in position {at}: {why}"
            ))
        }
    }
}

fn response(id: &PyValue, result: PyValue) -> PyValue {
    pyval::dict([
        ("jsonrpc", PyValue::str("2.0")),
        ("id", id.clone()),
        ("result", result),
    ])
}

fn error(id: &PyValue, code: i64, message: impl Into<String>) -> PyValue {
    pyval::dict([
        ("jsonrpc", PyValue::str("2.0")),
        ("id", id.clone()),
        (
            "error",
            pyval::dict([
                ("code", PyValue::int(code)),
                ("message", PyValue::Str(message.into())),
            ]),
        ),
    ])
}

fn session_audit_context(client_info: Option<&PyValue>) -> PyValue {
    let mut random = [0u8; 12];
    getrandom::getrandom(&mut random).expect("system randomness");
    let mut context = IndexMap::new();
    context.insert("source".to_owned(), PyValue::str("mcp"));
    context.insert(
        "session_id".to_owned(),
        PyValue::Str(format!("mcp_{}", hex::encode(random))),
    );
    if let Some(PyValue::Dict(info)) = client_info {
        if let Some(PyValue::Str(name)) = info.get("name") {
            let name = pyval::py_strip(name);
            if !name.is_empty() {
                context.insert(
                    "client_name".into(),
                    PyValue::Str(name.chars().take(80).collect()),
                );
            }
        }
        if let Some(PyValue::Str(version)) = info.get("version") {
            let version = pyval::py_strip(version);
            if !version.is_empty() {
                context.insert(
                    "client_version".into(),
                    PyValue::Str(version.chars().take(40).collect()),
                );
            }
        }
    }
    PyValue::Dict(context)
}

struct Server<'a, W: Write, E: Write> {
    config: &'a Config,
    output: W,
    log: E,
    hidden: Vec<&'static str>,
    seen_kind: Option<(Kind, String)>,
}

impl<W: Write, E: Write> Server<'_, W, E> {
    fn log(&mut self, message: &str) {
        let _ = writeln!(self.log, "[kv_mcp] {message}");
        let _ = self.log.flush();
    }

    fn write(&mut self, message: &PyValue) -> bool {
        let mut line = pyval::dumps_wire(message);
        line.push('\n');
        self.output.write_all(line.as_bytes()).is_ok() && self.output.flush().is_ok()
    }

    fn vault_kind(&mut self) -> (Kind, String) {
        let answer = vault::vault_key_kind(&self.config.root);
        if self.seen_kind.as_ref() == Some(&answer) {
            return answer;
        }
        let (kind, reason) = &answer;
        if !self.hidden.is_empty() && *kind != Kind::Unprotected {
            let line = tools::not_offered_log_line(&self.hidden, *kind, reason);
            self.log(&line);
        } else if !self.hidden.is_empty() && self.seen_kind.is_some() {
            self.log(&format!(
                "the vault's key file reads as unprotected now ({reason}): every enabled tool is offered"
            ));
        }
        self.seen_kind = Some(answer.clone());
        answer
    }

    /// `_resolve_store`: `None` for daemon mode, else the error text.
    fn resolve_store(&self) -> Option<String> {
        if agent::is_agent_running(&self.config.root) {
            return None;
        }
        if !self.config.allow_direct_vault_access {
            return Some(
                "vault agent is not running. Run 'kv unlock' in a terminal. \
                 Direct vault access from MCP is disabled by default."
                    .into(),
            );
        }
        if vault::vault_key_kind(&self.config.root).0 == Kind::Protected {
            return Some(
                "direct vault access is not available for passphrase-protected (v3/v4) vaults. \
                 Run 'kv unlock' in a terminal and use the daemon."
                    .into(),
            );
        }
        Some(
            "direct vault access from MCP is not supported by this kv version (it opens only \
             passphrase-protected v4 vaults, through the daemon). Run 'kv unlock' in a terminal \
             and use the daemon."
                .into(),
        )
    }

    fn tools_call(
        &mut self,
        id: &PyValue,
        params: &IndexMap<String, PyValue>,
        audit: &Option<PyValue>,
    ) -> bool {
        let empty = PyValue::Dict(IndexMap::new());
        let name = params.get("name");
        let arguments = params.get("arguments").unwrap_or(&empty);
        let (Some(PyValue::Str(name)), PyValue::Dict(arguments)) = (name, arguments) else {
            let sent = self.write(&error(
                id,
                INVALID_PARAMS,
                "tools/call needs a string name and an object of arguments",
            ));
            self.log("tools/call -> invalid params");
            return sent;
        };
        let Some(tool) = tools::tool(name) else {
            let sent = self.write(&error(
                id,
                METHOD_NOT_FOUND,
                format!("unknown tool: {name}"),
            ));
            self.log(&format!("tools/call {name} -> unknown tool"));
            return sent;
        };
        let profile = tool.profile.as_str();
        if !self.config.profiles.contains(profile) {
            let mut reason = format!(
                "tool '{name}' requires the '{profile}' profile (enable with --allow-{profile})"
            );
            if tools::is_hidden_on_protected(name) {
                let (kind, why) = self.vault_kind();
                if kind != Kind::Unprotected {
                    reason.push_str(&format!(
                        "; it is not offered {} either way",
                        vault::why_not_offered(kind, &why)
                    ));
                }
            }
            let sent = self.write(&error(id, INVALID_REQUEST, reason));
            self.log(&format!("tools/call {name} -> blocked (profile={profile})"));
            return sent;
        }
        if tools::is_hidden_on_protected(name) {
            let (kind, why) = self.vault_kind();
            if kind != Kind::Unprotected {
                let reason =
                    tools::hidden_tool_reason(name, kind, &why, Some(&self.config.profiles));
                let sent = self.write(&error(id, INVALID_REQUEST, reason));
                self.log(&format!(
                    "tools/call {name} -> blocked (not offered on this vault)"
                ));
                return sent;
            }
        }
        if let Some(problem) = self.resolve_store() {
            let reply = PyValue::Dict(text_reply(format!("error: {problem}"), true));
            let sent = self.write(&response(id, reply));
            self.log(&format!("tools/call {name} -> vault inaccessible"));
            return sent;
        }
        let start = Instant::now();
        let mut call_args = arguments.clone();
        if let Some(audit) = audit {
            call_args.insert("_audit_ctx".into(), audit.clone());
        }
        let context = Context {
            root: &self.config.root,
            default_env: &self.config.default_env,
        };
        let outcome = tools::call(name, &call_args, &context);
        let elapsed = start.elapsed().as_millis();
        match outcome {
            Ok(reply) => {
                let status = if reply.get("isError").is_some_and(PyValue::truthy) {
                    "error"
                } else {
                    "ok"
                };
                let sent = self.write(&response(id, PyValue::Dict(reply)));
                let env = arguments
                    .get("env")
                    .map_or_else(|| self.config.default_env.clone(), py_str);
                self.log(&format!(
                    "tool={name} env={env} duration_ms={elapsed} status={status}"
                ));
                sent
            }
            Err(ToolError::InvalidEnvironment(message)) => {
                let sent = self.write(&response(
                    id,
                    PyValue::Dict(text_reply(format!("error: {message}"), true)),
                ));
                self.log(&format!("tool={name} status=invalid-environment"));
                sent
            }
            Err(ToolError::Outdated(message)) => {
                let sent = self.write(&response(
                    id,
                    PyValue::Dict(text_reply(format!("error: {message}"), true)),
                ));
                self.log(&format!("tool={name} status=outdated-service"));
                sent
            }
            Err(ToolError::Exception { type_name, message }) => {
                let reply = text_reply(format!("internal error: {type_name}"), true);
                let sent = self.write(&response(id, PyValue::Dict(reply)));
                self.log(&format!(
                    "tool={name} duration_ms={elapsed} status=exception error={type_name}: {message}"
                ));
                sent
            }
        }
    }

    fn run<R: BufRead>(&mut self, mut input: R) {
        let profiles: Vec<String> = self
            .config
            .profiles
            .iter()
            .map(|p| py_repr(&PyValue::str(p)))
            .collect();
        self.log(&format!(
            "started (root={}, profiles=[{}], direct_vault_access={})",
            self.config.root.display(),
            profiles.join(", "),
            if self.config.allow_direct_vault_access {
                "True"
            } else {
                "False"
            }
        ));
        self.hidden = tools::hidden_tools_for_profiles(&self.config.profiles);
        self.vault_kind();
        let mut initialized = false;
        let mut audit: Option<PyValue> = None;
        let null = PyValue::Null;
        loop {
            let text = match read_line(&mut input) {
                Line::Eof => {
                    self.log("client disconnected (EOF)");
                    break;
                }
                Line::Error(message) => {
                    self.log(&format!("read error: {message}"));
                    break;
                }
                Line::Text(text) => text,
            };
            let text = pyval::py_strip(&text);
            if text.is_empty() {
                continue;
            }
            let message = match pyval::loads(text) {
                Ok(message) => message,
                Err(DecodeError::Json(why)) => {
                    if !self.write(&error(&null, PARSE_ERROR, format!("parse error: {why}"))) {
                        break;
                    }
                    self.log(&format!("parse error: {why}"));
                    continue;
                }
                Err(DecodeError::Fatal(why)) => {
                    self.log(&format!("read error: {why}"));
                    break;
                }
            };
            let PyValue::Dict(message) = message else {
                let what = if matches!(message, PyValue::List(_)) {
                    "batch requests are not supported"
                } else {
                    "a request must be a JSON object"
                };
                if !self.write(&error(&null, INVALID_REQUEST, what)) {
                    break;
                }
                // Python reads a `null` message as its `JSON_NULL` sentinel.
                let kind = if message == PyValue::Null {
                    "JsonNull"
                } else {
                    message.type_name()
                };
                self.log(&format!(
                    "rejected a message that is not an object ({kind})"
                ));
                continue;
            };
            let method = message.get("method").cloned().unwrap_or(PyValue::Null);
            let method_text = py_str(&method);
            let Some(id) = message.get("id").cloned() else {
                if method == PyValue::str("notifications/initialized") {
                    initialized = true;
                    self.log("client confirmed initialization");
                } else {
                    self.log(&format!("ignored notification: {method_text}"));
                }
                continue;
            };
            let default_params = PyValue::Dict(IndexMap::new());
            let PyValue::Dict(params) = message.get("params").unwrap_or(&default_params) else {
                if !self.write(&error(&id, INVALID_PARAMS, "params must be an object")) {
                    break;
                }
                self.log(&format!("rejected {method_text} (params not an object)"));
                continue;
            };
            let method_is = |name: &str| method == PyValue::str(name);
            let sent = if method_is("initialize") {
                let negotiated = match params.get("protocolVersion") {
                    None => LATEST_VERSION.to_owned(),
                    Some(PyValue::Str(version))
                        if SUPPORTED_VERSIONS.contains(&version.as_str()) =>
                    {
                        version.clone()
                    }
                    Some(_) => LATEST_VERSION.to_owned(),
                };
                audit = Some(session_audit_context(params.get("clientInfo")));
                let result = pyval::dict([
                    ("protocolVersion", PyValue::Str(negotiated.clone())),
                    (
                        "capabilities",
                        pyval::dict([("tools", PyValue::Dict(IndexMap::new()))]),
                    ),
                    (
                        "serverInfo",
                        pyval::dict([
                            ("name", PyValue::str("kv")),
                            ("version", PyValue::str(KV_VERSION)),
                        ]),
                    ),
                ]);
                let sent = self.write(&response(&id, result));
                self.log(&format!("initialized (version={negotiated})"));
                sent
            } else if method_is("notifications/initialized") {
                initialized = true;
                self.log("client confirmed initialization");
                true
            } else if !initialized && !method_is("ping") {
                if id != PyValue::Null {
                    let sent = self.write(&error(&id, INVALID_REQUEST, "server not initialized"));
                    self.log(&format!("rejected {method_text} (not initialized)"));
                    sent
                } else {
                    true
                }
            } else if method_is("tools/list") {
                let kind = self.vault_kind().0;
                let tools = tools::tools_for_kind(&self.config.profiles, kind);
                let count = tools.len();
                let sent = self.write(&response(
                    &id,
                    pyval::dict([("tools", PyValue::List(tools))]),
                ));
                self.log(&format!("tools/list -> {count} tools"));
                sent
            } else if method_is("tools/call") {
                self.tools_call(&id, params, &audit)
            } else if method_is("ping") {
                self.write(&response(&id, PyValue::Dict(IndexMap::new())))
            } else if id != PyValue::Null {
                let sent = self.write(&error(
                    &id,
                    METHOD_NOT_FOUND,
                    format!("unknown method: {method_text}"),
                ));
                self.log(&format!("unknown method: {method_text}"));
                sent
            } else {
                self.log(&format!("unknown notification: {method_text}"));
                true
            };
            if !sent {
                break;
            }
        }
    }
}

/// Serve one MCP session over `input`/`output`, logging to `log`.
pub fn serve<R: BufRead, W: Write, E: Write>(config: &Config, input: R, output: W, log: E) {
    let mut server = Server {
        config,
        output,
        log,
        hidden: Vec::new(),
        seen_kind: None,
    };
    server.run(input);
}
