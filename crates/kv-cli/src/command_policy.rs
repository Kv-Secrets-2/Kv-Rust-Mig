use crate::project::CmdResult;
use crate::ui::Palette;
use crate::{owner_policy as owner, project, render, ui};
use kv_store::{config, policy_requests as store};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub enum CommandPolicyAction {
    List(bool),
    Allow {
        id: String,
        reason: Option<String>,
    },
    Block {
        id: String,
        reason: Option<String>,
        alias: bool,
    },
    Prune,
}
fn text<'a>(request: &'a Value, key: &str, fallback: &'a str) -> &'a str {
    request.get(key).and_then(Value::as_str).unwrap_or(fallback)
}
fn listed(request: &Value, key: &str, fallback: &str) -> String {
    render::escape(text(request, key, fallback))
}
fn shown(p: &Palette, raw: &str) -> CmdResult<String> {
    kv_sandbox::runenv::escape_checked(raw).ok_or_else(|| {
        let length: usize = raw.chars().map(|ch| render::escape(&ch.to_string()).len()).sum();
        project::fail(p, &format!("nothing approved: a value is {length} characters long when shown (at most 8192 are shown in full)"))
    })
}
fn argv(p: &Palette, r: &Value) -> CmdResult<String> {
    if r.get("argv").is_some_and(|v| !v.is_null() && !v.is_array()) {
        return Err(project::fail(p, "policy request argv must be an array"));
    }
    let mut parts = Vec::new();
    for part in r
        .get("argv")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let part = part
            .as_str()
            .ok_or_else(|| project::fail(p, "policy request argv items must be strings"))?;
        parts.push(
            if !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b))
            {
                part.into()
            } else {
                format!("'{}'", part.replace('\'', "'\"'\"'"))
            },
        );
    }
    Ok(parts.join(" "))
}
fn duration(value: i64) -> String {
    let n = value.max(0);
    if n < 60 {
        format!("{n}s")
    } else if n < 3600 {
        format!("{}m", n / 60)
    } else if n < 86400 {
        format!("{}h", n / 3600)
    } else {
        format!("{}d", n / 86400)
    }
}
fn print_request(p: &Palette, r: &Value, now: i64, allowed: Option<&[String]>) -> CmdResult {
    let state = text(r, "effective_status", text(r, "status", "pending"));
    ui::info(&format!(
        "{}{}{} {} {}expires {}{}",
        p.bold,
        listed(r, "request_id", "<unknown>"),
        p.reset,
        render::escape(state),
        p.dim,
        listed(r, "expires_at", "<unknown>"),
        p.reset
    ));
    if let (Some(created), Some(expires)) = (
        store::epoch(&r["created_at_epoch"]),
        store::epoch(&r["expires_at_epoch"]),
    ) {
        if state == "pending" {
            ui::info(&format!(
                "  waiting: asked {} ago, {} left",
                duration(now - created),
                duration(expires - now)
            ));
        }
        if state == "expired" {
            ui::info(&format!(
                "  missed: expired undecided {} ago; the agent can ask again",
                duration(now - expires)
            ));
        }
    }
    let mut labels = Vec::new();
    for (key, label) in [
        ("source", "source"),
        ("client_name", "client"),
        ("session_id", "session"),
    ] {
        if let Some(value) = r
            .get("actor")
            .and_then(|a| a.get(key))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            labels.push(format!("{label}={}", render::escape(value)));
        }
    }
    let actor = if labels.is_empty() {
        format!(
            "{}any caller matching this exact command and scope{}",
            p.yellow, p.reset
        )
    } else {
        labels.join(", ")
    };
    ui::info(&format!("  requester: {actor}"));
    ui::info(&format!(
        "  project: {}{}{}",
        p.dim,
        listed(r, "cwd", "<unknown>"),
        p.reset
    ));
    ui::info(&format!(
        "  command: {}{}{}",
        p.dim,
        render::escape(&argv(p, r)?),
        p.reset
    ));
    ui::info(&format!(
        "  allow shape: {}{}{}",
        p.dim,
        listed(r, "pattern", "<unknown>"),
        p.reset
    ));
    if state == "allowed"
        && let Some(allowed) = allowed
    {
        let shape = text(r, "allowed_pattern", text(r, "pattern", ""));
        ui::info(if allowed.iter().any(|a| a == shape) {
            "  shape currently allowed"
        } else {
            "  shape not currently allowed; run 'kv allow' for it yourself, or ask for a new request"
        });
    }
    for (key, label) in [("command_reason", "blocked because"), ("reason", "note")] {
        if !text(r, key, "").is_empty() {
            ui::info(&format!("  {label}: {}", listed(r, key, "")));
        }
    }
    if state == "pending" {
        ui::info(&format!(
            "  allow command shape: {}kv policy allow {}{}",
            p.dim,
            listed(r, "request_id", "null"),
            p.reset
        ));
        ui::info(&format!(
            "  keep blocked: {}kv policy block {}{}",
            p.dim,
            listed(r, "request_id", "null"),
            p.reset
        ));
    }
    Ok(())
}
fn target(p: &Palette, root: &Path, request: &Value) -> CmdResult<PathBuf> {
    if request
        .get("cwd")
        .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return Err(project::fail(p, "policy request cwd must be a string"));
    }
    let cwd = PathBuf::from(text(request, "cwd", root.to_str().unwrap_or("")));
    let mut current = if cwd.is_absolute() {
        cwd
    } else {
        std::env::current_dir()
            .map_err(|e| project::fail(p, &e.to_string()))?
            .join(cwd)
    };
    loop {
        if current.join(".secrets").is_dir() {
            if std::fs::canonicalize(&current).ok() != std::fs::canonicalize(root).ok() {
                return Err(project::fail(
                    p,
                    "command-policy request cwd belongs to a different kv project; recreate the request from the target project",
                ));
            }
            return Ok(current);
        }
        if !current.pop() {
            return Err(project::fail(
                p,
                &format!("not inside a kv project: {}", listed(request, "cwd", "")),
            ));
        }
    }
}
fn audit(event: &str, r: &Value) {
    let mut fields = kv_audit::requester_fields(r.get("actor"), r.get("reason"));
    fields.insert("attribution".into(), json!("unverified"));
    fields.insert(
        "request_id".into(),
        r.get("request_id").cloned().unwrap_or(Value::Null),
    );
    fields.insert(
        "pattern".into(),
        r.get("pattern").cloned().unwrap_or(Value::Null),
    );
    project::audit_event(event, fields);
}
pub fn run(p: &Palette, action: CommandPolicyAction) -> CmdResult {
    let root = project::require_project(p)?;
    let convert = |e: kv_store::StoreError| project::fail(p, &render::escape(&e.to_string()));
    match action {
        CommandPolicyAction::List(all) => {
            let now = store::now();
            let requests = store::list(&root, all, now).map_err(convert)?;
            let allowlist = if requests.iter().any(|r| r["effective_status"] == "allowed") {
                config::get_run_policy(&root).ok().map(|(mode, patterns)| {
                    if mode == "allowlist" {
                        patterns
                    } else {
                        Vec::new()
                    }
                })
            } else {
                None
            };
            ui::header(p, "command policy inbox");
            let snapshot = project::config_value(p, &root)?;
            owner::print_approval_mode(p, &snapshot.value);
            ui::blank();
            if requests.is_empty() {
                ui::info(&format!(
                    "{}no pending command-policy requests{}",
                    p.dim, p.reset
                ));
                ui::info(&format!(
                    "{}create one: kv preflight --request -- python3 app.py{}",
                    p.dim, p.reset
                ));
                ui::blank();
            }
            for request in requests {
                print_request(p, &request, now, allowlist.as_deref())?;
                ui::blank();
            }
        }
        CommandPolicyAction::Allow { id, reason } => {
            let request = store::get(&root, &id, store::now())
                .map_err(convert)?
                .ok_or_else(|| {
                    project::fail(
                        p,
                        &format!("command-policy request not found: {}", render::escape(&id)),
                    )
                })?;
            if request["effective_status"] == "allowed" {
                let (mode, patterns) = config::get_run_policy(&root).map_err(convert)?;
                if mode != "allowlist"
                    || !patterns.iter().any(|s| {
                        s == text(&request, "allowed_pattern", text(&request, "pattern", ""))
                    })
                {
                    ui::error(
                        p,
                        &format!(
                            "command-policy request {} is already decided, but its command shape is not currently allowed",
                            listed(&request, "request_id", "")
                        ),
                    );
                    ui::info(&format!(
                        "{}run 'kv allow' for that shape yourself, or ask for a new request{}",
                        p.dim, p.reset
                    ));
                    return Err(project::Exit(1));
                }
            }
            if request["effective_status"] != "pending" {
                return Err(project::fail(
                    p,
                    &format!(
                        "command-policy request is not pending: {}",
                        text(&request, "effective_status", "")
                    ),
                ));
            }
            let target = target(p, &root, &request)?;
            let snapshot = project::config_value(p, &target)?;
            owner::block_local_approval_if_protected(p, &target, "command-policy allow")?;
            let pattern = text(&request, "pattern", "");
            let reviewed = store::fingerprint(&request).map_err(convert)?;
            let broad = kv_sandbox::classify::broad_secret_allowlist_reason(pattern);
            if !broad.is_empty() {
                return Err(project::fail(p, &render::escape(&broad)));
            }
            let mut lines = vec![
                "Allow this kv_run command shape for the current project.".into(),
                format!("Command shape: {}{}{}",p.dim,shown(p,pattern)?,p.reset),
                format!("Original command: {}{}{}",p.dim,shown(p,&argv(p,&request)?)?,p.reset),
                format!("Folder: {}{}{}",p.dim,shown(p,text(&request,"cwd","<unknown>"))?,p.reset),
                "This changes only command policy. It does not approve secrets or API access.".into(),
                "After this, secret/API use still needs a separate approval (kv approvals approve or kv grant approve).".into(),
            ];
            if !text(&request, "command_reason", "").is_empty() {
                lines.push(format!(
                    "Blocked because: {}{}{}",
                    p.dim,
                    shown(p, text(&request, "command_reason", ""))?,
                    p.reset
                ));
            }
            owner::warn_if_approval_mode_unset(p, &target)?;
            if !owner::authorize_loosening_change(p, &target, &lines, &snapshot.value)? {
                return Ok(());
            }
            let reason = reason
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("allowed by user via kv policy allow");
            if !store::allow(
                &root,
                text(&request, "request_id", ""),
                &target,
                &snapshot,
                &reviewed,
                Some(reason),
                kv_sandbox::classify::broad_secret_allowlist_reason,
            )
            .map_err(convert)?
            {
                return Err(project::fail(
                    p,
                    "command-policy request changed before it could be allowed (blocked, expired or already decided); nothing was allowed",
                ));
            }
            audit("policy_request_allowed", &request);
            ui::success(
                p,
                &format!(
                    "allowed command shape: {}{}{}",
                    p.bold,
                    render::escape(pattern),
                    p.reset
                ),
            );
            ui::info(&format!(
                "{}next: approve secret/API use separately if the run asks for it{}",
                p.dim, p.reset
            ));
        }
        CommandPolicyAction::Block { id, reason, alias } => {
            owner::refuse_policy_change_without_passphrase(p, &root)?;
            let request = store::get(&root, &id, store::now())
                .map_err(convert)?
                .ok_or_else(|| {
                    project::fail(
                        p,
                        &format!("command-policy request not found: {}", render::escape(&id)),
                    )
                })?;
            if request["effective_status"] != "pending" {
                return Err(project::fail(
                    p,
                    &format!(
                        "command-policy request is not pending: {}",
                        text(&request, "effective_status", "")
                    ),
                ));
            }
            let lines = vec![
                "Keep this kv_run command shape blocked.".into(),
                format!(
                    "Request ID: {}{}{}",
                    p.dim,
                    listed(&request, "request_id", ""),
                    p.reset
                ),
                format!(
                    "Command shape: {}{}{}",
                    p.dim,
                    listed(&request, "pattern", "<unknown>"),
                    p.reset
                ),
                format!(
                    "Original command: {}{}{}",
                    p.dim,
                    render::escape(&argv(p, &request)?),
                    p.reset
                ),
            ];
            if !owner::confirm_decision(p, &lines, "Keep this command blocked? [y/N] ")? {
                return Ok(());
            }
            let default = format!(
                "blocked by user via kv policy {}",
                if alias { "deny" } else { "block" }
            );
            if !store::block(
                &root,
                text(&request, "request_id", ""),
                Some(
                    reason
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .unwrap_or(&default),
                ),
                store::now(),
            )
            .map_err(convert)?
            {
                return Err(project::fail(
                    p,
                    "command-policy request changed before it could be blocked",
                ));
            }
            audit("policy_request_blocked", &request);
            ui::success(
                p,
                &format!(
                    "kept blocked: {}{}{}",
                    p.bold,
                    listed(&request, "pattern", "<unknown>"),
                    p.reset
                ),
            );
        }
        CommandPolicyAction::Prune => {
            let remaining = store::prune(&root, store::now()).map_err(convert)?;
            ui::success(p, "command-policy requests pruned");
            ui::info(&format!(
                "{}{remaining} pending command-policy request{} remain{}",
                p.dim,
                if remaining == 1 { "" } else { "s" },
                p.reset
            ));
        }
    }
    Ok(())
}
