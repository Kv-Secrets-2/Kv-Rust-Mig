//! The one typed v1 broker operation. This is deliberately not a general
//! HTTP CLI: the daemon owns provider, method, path and payload shape.

use crate::project::{self, CmdResult};
use crate::ui::{self, Palette};
use serde_json::{Map, json};

pub struct ApiOperationArgs {
    pub input: String,
    pub permit_id: Option<String>,
    pub env: Option<String>,
}

pub const USAGE: &str =
    "usage: kv api anthropic-count-tokens [--permit-id PERMIT_ID] [--env ENV] INPUT";

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn cmd_api_operation(p: &Palette, args: ApiOperationArgs) -> CmdResult {
    let root = project::require_project(p)?;
    let mut fields = Map::new();
    fields.insert("input".into(), json!(args.input));
    if let Some(permit_id) = args.permit_id {
        fields.insert("permit_id".into(), json!(permit_id));
    }
    if let Some(env) = args.env {
        fields.insert("env".into(), json!(env));
    }
    fields.insert(
        "audit_ctx".into(),
        json!({"source":"cli","client_name":"kv"}),
    );
    let answer = kv_proto::agent_request_framed(&root, "v1_anthropic_count_tokens", &fields)
        .map_err(|error| project::fail(p, &error.to_string()))?;
    if answer.get("error_code").and_then(serde_json::Value::as_str) == Some("permit_required") {
        let request_id = answer["request_id"].as_str().unwrap_or("");
        let permit_id = answer["permit_id"].as_str().unwrap_or("");
        ui::error(p, answer["error"].as_str().unwrap_or("approval required"));
        ui::info("Review it: kv approvals list");
        ui::info(&format!("Approve it: kv approvals approve {request_id}"));
        ui::info(&format!("Deny it: kv approvals deny {request_id}"));
        ui::info(&format!(
            "After approval, execute exactly: kv api anthropic-count-tokens --permit-id {permit_id} -- {}",
            shell_quote(&args.input)
        ));
        return Err(project::Exit(1));
    }
    if let Some(error) = answer.get("error").and_then(serde_json::Value::as_str) {
        return Err(project::fail(p, error));
    }
    ui::out(&serde_json::to_string_pretty(&answer).unwrap_or_else(|_| answer.to_string()));
    Ok(())
}
