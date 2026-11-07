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

pub mod fileaccess;
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

/// Python `_pre_hook`.
pub fn pre_hook(call: &ToolCall) -> Reply {
    let _ = call;
    Reply::Allow
}

pub fn tool_call(tool_name: &str, tool_input: Value) -> ToolCall {
    let raw = json!({"tool_name": tool_name, "tool_input": tool_input});
    ToolCall::parse(&serde_json::to_vec(&raw).expect("json")).expect("valid tool call")
}
