//! `kv approvals`: the owner's inbox and decisions. This stage ports the one-call
//! permit decision (`_approve_call_permit`); approval requests, pauses, the page,
//! deny and prune are refused as not available in this build.

use crate::owner_policy as owner;
use crate::owner_signing::{PermitSigningContext, SigningError};
use crate::project::{self, CmdResult};
use crate::terminal;
use crate::ui::{self, Palette};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(clippy::large_enum_variant)]
pub enum ApprovalsAction {
    List {
        all: bool,
        follow: bool,
        interval: i64,
    },
    Approve {
        request_id: String,
        run_grant_flags: bool,
    },
    Request {
        cmd: Vec<String>,
        secret_names: Vec<String>,
        capability_names: Vec<String>,
        max_calls: Option<i64>,
        calls_per_service: Vec<(String, i64)>,
        ttl: Option<i64>,
        suggest_minutes: Option<i64>,
        cwd: Option<String>,
        source: Option<String>,
        client: Option<String>,
        session_id: Option<String>,
        reason: Option<String>,
        env: Option<String>,
    },
    Unavailable(&'static str),
}

pub fn cmd_approvals(p: &Palette, action: ApprovalsAction) -> CmdResult {
    match action {
        ApprovalsAction::Unavailable(what) => Err(project::fail(
            p,
            &format!("kv approvals {what} is not available in this build"),
        )),
        ApprovalsAction::Approve {
            request_id,
            run_grant_flags,
        } => approve(p, &request_id, run_grant_flags),
        ApprovalsAction::Request {
            cmd,
            secret_names,
            capability_names,
            max_calls,
            calls_per_service,
            ttl,
            suggest_minutes,
            cwd,
            source,
            client,
            session_id,
            reason,
            env,
        } => request_run(
            p,
            cmd,
            secret_names,
            capability_names,
            max_calls,
            calls_per_service,
            ttl,
            suggest_minutes,
            cwd,
            source,
            client,
            session_id,
            reason,
            env,
        ),
        ApprovalsAction::List {
            all,
            follow,
            interval,
        } => {
            // `watch --follow`: refresh until interrupted (Ctrl-C ends the process here;
            // Python catches it and prints a newline).
            if follow {
                loop {
                    list(p, all)?;
                    std::thread::sleep(std::time::Duration::from_secs(interval.max(1) as u64));
                }
            }
            list(p, all)
        }
    }
}

/// Python `_listed`: an external value shown through the renderer.
fn listed(value: &Value) -> String {
    match value {
        Value::String(s) => crate::render::escape(s),
        Value::Null => crate::render::escape("<unknown>"),
        other => crate::render::escape(&other.to_string()),
    }
}

fn duration_text(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}

fn actor_display(p: &Palette, actor: Option<&Value>) -> String {
    let fallback = format!(
        "{}any caller matching this exact command and scope{}",
        p.yellow, p.reset
    );
    let Some(actor) = actor.and_then(Value::as_object).filter(|a| !a.is_empty()) else {
        return fallback;
    };
    let mut labels = Vec::new();
    for (key, label) in [
        ("source", "source"),
        ("client_name", "client"),
        ("session_id", "session"),
    ] {
        if let Some(value) = actor.get(key).filter(|v| !v.is_null() && *v != &json!("")) {
            labels.push(format!("{label}={}", listed(value)));
        }
    }
    if labels.is_empty() {
        fallback
    } else {
        labels.join(", ")
    }
}

fn names(request: &Value, key: &str) -> Vec<String> {
    request[key]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn present(value: Option<&Value>) -> bool {
    value.is_some_and(|v| !v.is_null() && v != &json!("") && v != &json!({}))
}

/// Python `_print_approval_request`.
fn print_request(p: &Palette, request: &Value, now: i64) {
    let status = request["effective_status"]
        .as_str()
        .or(request["status"].as_str())
        .unwrap_or("pending")
        .to_owned();
    let label = if status == "expired" {
        "missed"
    } else {
        status.as_str()
    };
    let id = listed(&request["request_id"]);
    ui::info(&format!(
        "{}{id}{} {} {}expires {}{}",
        p.bold,
        p.reset,
        crate::render::escape(label),
        p.dim,
        listed(&request["expires_at"]),
        p.reset
    ));
    if let (Some(created), Some(expires)) = (
        request["created_at_epoch"].as_i64(),
        request["expires_at_epoch"].as_i64(),
    ) {
        if status == "pending" {
            ui::info(&format!(
                "  waiting: asked {} ago, {} left",
                duration_text(now - created),
                duration_text(expires - now)
            ));
        } else if status == "expired" {
            ui::info(&format!(
                "  missed: expired undecided {} ago; the agent can ask again",
                duration_text(now - expires)
            ));
        }
    }
    match &request["approved_grant_id"] {
        Value::Null => {}
        Value::String(grant) if grant.is_empty() => {}
        // The grant's live state (Python `_approval_grant_line` with the grant list) is not
        // read by this build yet; Python's wording for an unread list.
        Value::String(grant) => ui::info(&format!(
            "  grant {}: state unreadable",
            crate::render::escape(grant)
        )),
        _ => ui::info("  grant reference invalid; state unreadable"),
    }
    ui::info(&format!(
        "  requester: {}",
        actor_display(p, request.get("actor"))
    ));
    ui::info(&format!(
        "  project: {}{}{}",
        p.dim,
        listed(&request["cwd"]),
        p.reset
    ));
    let argv = names(request, "argv")
        .iter()
        .map(|part| crate::render::shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ");
    ui::info(&format!(
        "  command: {}{}{}",
        p.dim,
        crate::render::escape(&argv),
        p.reset
    ));
    let secrets = names(request, "secret_names");
    let capabilities = names(request, "capability_names");
    let scope = if !secrets.is_empty() {
        format!("secrets: {}", secrets.join(", "))
    } else if !capabilities.is_empty() {
        format!("capabilities: {}", capabilities.join(", "))
    } else {
        "no secret scope".to_owned()
    };
    ui::info(&format!("  scope: {}", crate::render::escape(&scope)));
    if !capabilities.is_empty() {
        let budget = request
            .get("max_calls")
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or(json!(1));
        ui::info(&format!("  call budget: {}", listed(&budget)));
    }
    if present(request.get("script_sha256")) {
        ui::info(&format!(
            "  script hash: {}{}{}",
            p.dim,
            listed(&request["script_sha256"]),
            p.reset
        ));
    } else if present(request.get("script_ref_hash")) {
        ui::info(&format!(
            "  script reference hash: {}{}{}",
            p.dim,
            listed(&request["script_ref_hash"]),
            p.reset
        ));
    } else {
        ui::info(&format!(
            "  {}no script file hash detected{}",
            p.yellow, p.reset
        ));
    }
    let risk = request
        .get("risk_level")
        .filter(|v| !v.is_null())
        .cloned()
        .unwrap_or(json!("normal"));
    ui::info(&format!("  risk: {}", listed(&risk)));
    if present(request.get("risk_card")) {
        for line in kv_approvals::risk_card::summarize_risk_card(request.get("risk_card")) {
            ui::info(&format!("  {}", crate::render::escape(&line)));
        }
    }
    if present(request.get("reason")) {
        ui::info(&format!("  note: {}", listed(&request["reason"])));
    }
    if status == "pending" {
        ui::info(&format!(
            "  approve: {}kv approvals approve {id}{}",
            p.dim, p.reset
        ));
        ui::info(&format!(
            "  deny: {}kv approvals deny {id}{}",
            p.dim, p.reset
        ));
    }
}

fn field(value: &Value, key: &str) -> String {
    listed(value.get(key).unwrap_or(&json!("")))
}

/// Python `kv approvals list`: the inbox (pending one-call permits and paused jobs from the
/// service, then the approval requests on disk).
fn list(p: &Palette, all: bool) -> CmdResult {
    let root = project::require_project(p)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (pending_calls, paused_jobs) =
        match kv_proto::agent_request_framed(&root, "permit_requests", &Map::new()) {
            Ok(reply) => (
                reply["requests"].as_array().cloned().unwrap_or_default(),
                reply["pauses"].as_array().cloned().unwrap_or_default(),
            ),
            Err(_) => (Vec::new(), Vec::new()),
        };
    let requests = kv_requests::approvals::list_approval_requests(&root, all, true, Some(now))
        .map_err(|e| project::fail(p, &e.to_string()))?;
    ui::header(p, "approval inbox");
    let config =
        kv_store::config::load_config(&root).map_err(|e| project::fail(p, &e.to_string()))?;
    owner::print_approval_mode(p, &config.value);
    ui::blank();
    for call in &pending_calls {
        ui::info(&format!(
            "Pending one-call permit: {} {}",
            field(call, "method"),
            field(call, "provider")
        ));
        ui::info(&format!(
            "This call needs your approval. Ask the owner to run: kv approvals approve {}",
            field(call, "request_id")
        ));
        ui::blank();
    }
    for job in &paused_jobs {
        let wants = if job["reason"] == json!("time") {
            format!(
                "wants {} more minutes",
                job["wants_seconds"].as_i64().unwrap_or(0) / 60
            )
        } else {
            format!(
                "wants {} more {} calls",
                job["wants_calls"].as_i64().unwrap_or(0),
                field(job, "capability")
            )
        };
        ui::info(&format!("Paused job: {} {wants}", field(job, "script")));
        ui::info(&format!(
            "Answer it: kv approvals approve {}  (or kv approvals deny ...)",
            field(job, "request_id")
        ));
        ui::blank();
    }
    if requests.is_empty() && pending_calls.is_empty() && paused_jobs.is_empty() {
        ui::info(&format!("{}no pending approval requests{}", p.dim, p.reset));
        ui::info(&format!(
            "{}create one: kv preflight --request -- python3 app.py{}",
            p.dim, p.reset
        ));
        ui::blank();
        return Ok(());
    }
    for request in &requests {
        print_request(p, request, now);
        ui::blank();
    }
    Ok(())
}

fn approve(p: &Palette, request_id: &str, run_grant_flags: bool) -> CmdResult {
    let root = project::require_project(p)?;
    // NOPASS: before any request is read or shown.
    if !owner::vault_has_passphrase(&root) {
        return Err(project::fail(
            p,
            kv_approvals::permit_session::NO_PASSPHRASE_REFUSAL,
        ));
    }
    if !request_id.starts_with("permit_request_") {
        return approve_run_grant(p, &root, request_id, run_grant_flags);
    }
    owner::block_local_approval_if_protected(p, &root, "permit approval")?;
    terminal::check_owner_terminal().map_err(|e| project::fail(p, &e.to_string()))?;
    if run_grant_flags {
        return Err(project::fail(
            p,
            "run-grant flags cannot be used for a one-call permit",
        ));
    }
    let mut audit_fields = Map::new();
    audit_fields.insert("request_id".into(), json!(request_id));
    let mut event = "call_permit_abandoned";
    let outcome = (|| -> CmdResult {
        // `_owner_getpass` then `prompt_unwrapped`: one attempt, no "verified" line.
        let passphrase =
            project::read_owner_secret(p, &format!("  {}Passphrase{}: ", p.yellow, p.reset))?;
        let identity = project::unlock_identity(&root, passphrase.as_bytes())
            .map_err(|e| project::fail(p, &e))?;
        let ctx =
            PermitSigningContext::begin(&root, identity).map_err(|e| signing_failure(p, e))?;
        let record = ctx
            .permit_record(request_id)
            .map_err(|e| signing_failure(p, e))?;
        // AU2: the asking agent and its reason, from the service's authenticated record.
        if let Some(requester) = &record.requester {
            for (key, value) in requester {
                audit_fields.insert(key.clone(), value.clone());
            }
        }
        for key in [
            "permit_id",
            "provider",
            "method",
            "body_length",
            "body_sha256",
        ] {
            audit_fields.insert(key.into(), record.facts[key].clone());
        }
        if let Some(url) = record.facts["url"].as_str() {
            let shown = url.split(['?', '#']).next().unwrap_or(url);
            audit_fields.insert("url".into(), json!(shown));
        }
        let lines = kv_approvals::permit_review::render_review(
            &record.facts,
            &record.body_text,
            &record.caller_headers,
        )
        .map_err(|e| project::fail(p, &e))?;
        // Python asks for a TOTP or backup code here when 2FA is on (a permit is always an
        // unsafe call); this build has no second factor, so it refuses instead of skipping it.
        if owner::two_factor_configured(&root) {
            return Err(project::fail(
                p,
                "two-factor approval is not available in this build; nothing was signed",
            ));
        }
        if !owner::confirm_decision(p, &lines, "Sign this one-call permit? [y/N] ")? {
            event = "call_permit_denied";
            return Ok(());
        }
        // The mode is re-checked right before signing, as Python does under its
        // authorization lock.
        owner::block_local_approval_if_protected(p, &root, "permit approval")?;
        let permit = ctx
            .sign_permit(&record)
            .map_err(|e| signing_failure(p, e))?;
        let status = match ctx.register_permit(&permit) {
            Ok(status) => status,
            Err(SigningError::Unconfirmed(reason)) => {
                // An answer was lost: the service may hold the permit.
                event = "call_permit_outcome_unknown";
                let until = permit["payload"]["expires_at_epoch"].as_i64().unwrap_or(0);
                ui::error(
                    p,
                    &format!(
                        "{} Last answer: {}",
                        outcome_unknown_text(until),
                        crate::render::escape(&reason)
                    ),
                );
                return Err(project::Exit(1));
            }
            Err(error) => return Err(signing_failure(p, error)),
        };
        event = "call_permit_approved";
        if status == "already-registered" {
            ui::info("Permit already registered; this does not reset a spent permit.");
        } else {
            ui::success(p, "One-call permit approved.");
        }
        ui::info(&format!(
            "Permit ID: {}",
            permit["payload"]["permit_id"].as_str().unwrap_or("")
        ));
        Ok(())
    })();
    project::audit_event(event, audit_fields);
    outcome
}

/// Create a daemon-recorded exact-run approval request. The daemon recomputes
/// the identity and network decision, writes the file, and keeps the session
/// record a later signature must match.
#[allow(clippy::too_many_arguments)]
fn request_run(
    p: &Palette,
    cmd: Vec<String>,
    secret_names: Vec<String>,
    capability_names: Vec<String>,
    max_calls: Option<i64>,
    calls_per_service: Vec<(String, i64)>,
    ttl: Option<i64>,
    suggest_minutes: Option<i64>,
    cwd: Option<String>,
    source: Option<String>,
    client: Option<String>,
    session_id: Option<String>,
    reason: Option<String>,
    env: Option<String>,
) -> CmdResult {
    let root = project::require_project(p)?;
    for capability in &capability_names {
        if !capability.starts_with("api:") {
            return Err(project::fail(
                p,
                &format!("unsupported capability {capability}"),
            ));
        }
    }
    if !secret_names.is_empty() && !capability_names.is_empty() {
        return Err(project::fail(
            p,
            "approval request cannot mix secrets and capabilities",
        ));
    }
    if secret_names.is_empty() && capability_names.is_empty() {
        return Err(project::fail(
            p,
            "approval request requires at least one secret or capability",
        ));
    }
    let cwd_text = match cwd {
        Some(cwd) => cwd,
        None => std::env::current_dir()
            .map_err(|e| project::fail(p, &e.to_string()))?
            .to_string_lossy()
            .into_owned(),
    };
    let cwd_path = if kv_sandbox::paths::is_abs(&cwd_text) {
        std::path::PathBuf::from(cwd_text)
    } else {
        std::env::current_dir()
            .map_err(|e| project::fail(p, &e.to_string()))?
            .join(cwd_text)
    };
    let cwd_text = kv_sandbox::paths::real_or_lexical(&cwd_path.to_string_lossy());
    let scope = kv_sandbox::identity::IdentityScope {
        env_names: Some(&secret_names),
        secret_scope: Some(json!(if secret_names.is_empty() {
            "capability"
        } else {
            "selected"
        })),
        secrets_injected: true,
    };
    let watched = vec![root.to_string_lossy().into_owned()];
    let identity = kv_sandbox::identity::build_run_identity(
        &cmd,
        &cwd_text,
        &scope,
        "run_cli_request",
        &watched,
    )
    .map_err(|e| project::fail(p, &e.to_string()))?;
    let mut actor = Map::new();
    if let Some(source) = source {
        actor.insert("source".into(), json!(source));
    }
    if let Some(client) = client {
        actor.insert("client_name".into(), json!(client));
    }
    if let Some(session_id) = session_id {
        actor.insert("session_id".into(), json!(session_id));
    }
    let mut fields = Map::new();
    fields.insert("run_identity".into(), Value::Object(identity));
    fields.insert("argv".into(), json!(cmd));
    fields.insert("cwd".into(), json!(cwd_text));
    fields.insert("secret_names".into(), json!(secret_names));
    fields.insert("capability_names".into(), json!(capability_names));
    fields.insert("actor".into(), Value::Object(actor));
    fields.insert(
        "reason".into(),
        json!(reason.unwrap_or_else(|| "created by kv approvals request".into())),
    );
    fields.insert("source".into(), json!("cli_request"));
    fields.insert(
        "risk_level".into(),
        json!(if capability_names.is_empty() {
            "raw_secret"
        } else {
            "brokered_api"
        }),
    );
    if let Some(ttl) = ttl {
        fields.insert("ttl_seconds".into(), json!(ttl));
    }
    if let Some(max_calls) = max_calls {
        fields.insert("max_calls".into(), json!(max_calls));
    }
    if !calls_per_service.is_empty() {
        let per: Map<String, Value> = calls_per_service
            .into_iter()
            .map(|(name, count)| (name, json!(count)))
            .collect();
        fields.insert("calls_per_service".into(), Value::Object(per));
    }
    if let Some(minutes) = suggest_minutes {
        fields.insert("recommended_ttl_seconds".into(), json!(minutes * 60));
    }
    let mut outgoing = Map::new();
    outgoing.insert("request".into(), Value::Object(fields));
    let environment = match env {
        Some(env) => env,
        None => project::default_env(&project::config_value(p, &root)?.value),
    };
    outgoing.insert("environment".into(), json!(environment));
    let answer = kv_proto::agent_request_framed(&root, "record_request", &outgoing)
        .map_err(|e| project::fail(p, &e.to_string()))?;
    if let Some(error) = answer.get("error").and_then(Value::as_str) {
        return Err(project::fail(p, error));
    }
    let Some(request) = answer.get("request") else {
        return Err(project::fail(p, "the daemon did not record the request"));
    };
    let id = request["request_id"].as_str().unwrap_or("");
    ui::success(
        p,
        &format!("approval request created: {}", crate::render::escape(id)),
    );
    ui::info(&format!("Approve it: kv approvals approve {id}"));
    project::audit_event(
        "approval_request_created",
        Map::from_iter([
            ("request_id".into(), json!(id)),
            (
                "scope".into(),
                json!(if request["capability_names"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty())
                {
                    "capability"
                } else {
                    "secret"
                }),
            ),
            ("source".into(), json!("cli_request")),
        ]),
    );
    Ok(())
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

fn run_identity_from_request(request: &Value) -> Value {
    let mut identity = Map::new();
    for key in [
        "command_fingerprint",
        "script_kind",
        "script_sha256",
        "script_ref_hash",
    ] {
        if let Some(value) = request.get(key).filter(|value| !value.is_null()) {
            identity.insert(key.into(), value.clone());
        }
    }
    Value::Object(identity)
}

/// Approve one exact run as a one-use grant. v1 intentionally has no standing
/// grants or reusable-run flags: the signed authority is one admission and the
/// capability budget already carried by the request.
fn approve_run_grant(
    p: &Palette,
    root: &std::path::Path,
    request_id: &str,
    run_grant_flags: bool,
) -> CmdResult {
    if run_grant_flags {
        return Err(project::fail(
            p,
            "run-grant reuse, wallet and override flags are not part of this v1 approval; approve the exact one-shot request without flags",
        ));
    }
    owner::block_local_approval_if_protected(p, root, "run approval")?;
    terminal::check_owner_terminal().map_err(|e| project::fail(p, &e.to_string()))?;
    let id = json!(request_id);
    let Some(request) = kv_requests::approvals::get_approval_request(root, &id, None)
        .map_err(|e| project::fail(p, &e.to_string()))?
    else {
        return Err(project::fail(p, "no such approval request"));
    };
    if !kv_requests::approvals::verify_approval_request_integrity(root, &request)
        .map_err(|e| project::fail(p, &e.to_string()))?
    {
        return Err(project::fail(
            p,
            "approval request integrity check failed; nothing was approved",
        ));
    }
    if request["effective_status"].as_str() != Some("pending") {
        return Err(project::fail(p, "approval request is not pending"));
    }
    if !request.get("argv").is_some_and(Value::is_array)
        || request
            .get("command_fingerprint")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(project::fail(p, "approval request is not a run request"));
    }

    let mut audit_fields = Map::new();
    audit_fields.insert("request_id".into(), json!(request_id));
    let mut event = "run_grant_abandoned";
    let outcome = (|| -> CmdResult {
        let passphrase =
            project::read_owner_secret(p, &format!("  {}Passphrase{}: ", p.yellow, p.reset))?;
        let identity = project::unlock_identity(root, passphrase.as_bytes())
            .map_err(|e| project::fail(p, &e))?;
        let master_key = kv_crypto::Key32::new(*identity.master_key.as_bytes());
        let owner_seed = *identity.owner_seed;
        let local_approval_id = identity.local_approval_id;
        let location = identity.location.clone();
        let ctx = PermitSigningContext::begin(root, identity).map_err(|e| signing_failure(p, e))?;
        let record = ctx
            .request_record(&request)
            .map_err(|e| signing_failure(p, e))?;
        let capability_names = names(&request, "capability_names");
        let providers = ctx
            .provider_definitions(&capability_names)
            .map_err(|e| signing_failure(p, e))?;

        print_request(p, &request, now_epoch());
        let mut lines = vec![
            "This approval is for one run only. It does not make a standing grant.".to_owned(),
            format!(
                "Scope: {} secret(s), {} brokered provider capability(ies).",
                names(&request, "secret_names").len(),
                capability_names.len()
            ),
        ];
        if let Some(expiry) = request.get("expires_at").and_then(Value::as_str) {
            lines.push(format!(
                "Request expires: {}",
                crate::render::escape(expiry)
            ));
        }
        if owner::two_factor_configured(root) {
            return Err(project::fail(
                p,
                "two-factor approval is not available in this build; nothing was signed",
            ));
        }
        if !owner::confirm_decision(p, &lines, "Sign this one-run grant? [y/N] ")? {
            let _ = kv_requests::approvals::deny_approval_request(
                root,
                &id,
                &json!("owner declined at review"),
                None,
            );
            event = "run_grant_denied";
            ui::info("Request denied.");
            return Ok(());
        }
        owner::block_local_approval_if_protected(p, root, "run approval")?;

        let ttl = request
            .get("recommended_ttl_seconds")
            .and_then(Value::as_i64)
            .filter(|ttl| *ttl > 0)
            .unwrap_or(300);
        let now = now_epoch();
        let ends_at_epoch = now + ttl;
        let calls_per_run = if capability_names.is_empty() {
            Value::Null
        } else {
            request
                .get("max_calls")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| json!(1))
        };
        let provider_digest_map = providers.clone();
        let owner_sign = |grant: Map<String, Value>| {
            let signed = ctx
                .sign_grant(
                    &Value::Object(grant),
                    &request,
                    &record,
                    Value::Null,
                    calls_per_run.clone(),
                    &provider_digest_map,
                )
                .map_err(|error| kv_grants::normalize::InvalidValue::new(error.message()))?;
            signed
                .as_object()
                .cloned()
                .ok_or_else(|| kv_grants::normalize::InvalidValue::new("signed grant is invalid"))
        };

        let key_path = root.join(".secrets/approval_signing_key");
        let key_bytes = std::fs::read(&key_path)
            .map_err(|_| project::fail(p, "approval signing key is missing or unreadable"))?;
        let signing_key = kv_approvals::artifacts::parse_signing_key(&key_bytes)
            .map_err(|e| project::fail(p, &e.to_string()))?;
        let state_key = kv_crypto::derive_labeled_key(&master_key, b"kv-approval:grant-state", &[]);
        let provider_table: BTreeMap<String, Value> = providers
            .iter()
            .map(|(name, definition)| (name.clone(), definition.clone()))
            .collect();
        let public =
            kv_approvals::owner::owner_public_key(&kv_approvals::owner::OwnerSeed::new(owner_seed));
        let session_nonce: [u8; 32] = ctx
            .channel
            .session_nonce
            .as_slice()
            .try_into()
            .map_err(|_| project::fail(p, "the daemon session nonce is invalid"))?;
        let binding = kv_approvals::permit_session::SessionBinding {
            protected: true,
            owner_public_key: Some(public),
            owner_key_id: ctx.channel.owner_key_id.clone(),
            local_approval_id: local_approval_id.to_vec(),
            location,
            session_nonce,
            providers: std::sync::Arc::new(provider_table.clone()),
        };
        let ledger = kv_grants::ledger::Ledger::new();
        let grant_ctx = kv_grants::grants::GrantContext {
            root,
            signing_key: signing_key.as_ref(),
            state_key: state_key.as_ref(),
            binding: &binding,
            ledger: &ledger,
            providers: &provider_table,
        };
        let create = kv_grants::grants::CreateGrant {
            secret_names: Some(request["secret_names"].clone()),
            capability_names: Some(request["capability_names"].clone()),
            actor: request.get("actor").cloned(),
            reason: request.get("reason").cloned(),
            ttl_seconds: Some(json!(ttl)),
            max_calls: request.get("max_calls").cloned(),
            risk_card: request.get("risk_card").cloned(),
            usage_mode: Some(json!("once")),
            max_runs: None,
            post_wallet: None,
            calls_per_service: request.get("calls_per_service").cloned(),
            when_spent: if capability_names.is_empty() {
                None
            } else {
                Some(json!("end"))
            },
            owner_wait_seconds: if capability_names.is_empty() {
                None
            } else {
                Some(json!(ttl))
            },
            ends_at_epoch: Some(json!(ends_at_epoch)),
        };
        let grant = kv_grants::grants::create_run_grant(
            &grant_ctx,
            &run_identity_from_request(&request),
            &create,
            Some(&owner_sign),
            now,
        )
        .map_err(|e| project::fail(p, &e.to_string()))?;
        let marked = kv_requests::approvals::mark_approval_request_approved(
            root,
            &id,
            &grant["grant_id"],
            &json!("owner approved"),
            None,
        )
        .map_err(|e| project::fail(p, &e.to_string()))?;
        if !marked {
            // `create_run_grant` has already materialized the owner-signed artifact.
            // Fail closed by revoking that artifact before reporting the storage race;
            // approval and grant creation cannot share one public kv-grants transaction.
            let _ = kv_grants::grants::revoke_run_grant(
                &grant_ctx,
                grant["grant_id"].as_str().unwrap_or(""),
                Some(&json!("approval request changed before it was closed")),
                now,
                "immediate",
            );
            return Err(project::fail(
                p,
                "the approval request changed while it was being approved; retry only after reviewing a fresh request",
            ));
        }
        let status = match ctx.register_grant(&Value::Object(grant.clone())) {
            Ok(status) => status,
            Err(SigningError::Unconfirmed(reason)) => {
                event = "run_grant_outcome_unknown";
                ui::error(
                    p,
                    &format!(
                        "outcome unknown: this grant may be live with the daemon. {} ",
                        crate::render::escape(&reason)
                    ),
                );
                return Err(project::Exit(1));
            }
            Err(error) => return Err(signing_failure(p, error)),
        };
        event = "run_grant_approved";
        if status == "already-registered" {
            ui::info("Grant already registered with the daemon.");
        } else {
            ui::success(p, "One-run grant approved and registered.");
        }
        ui::info(&format!(
            "Grant ID: {}",
            grant["grant_id"].as_str().unwrap_or("")
        ));
        Ok(())
    })();
    project::audit_event(event, audit_fields);
    outcome
}

/// Python `_permit_outcome_unknown_text` (the time is shown in UTC here; Python shows the
/// local zone).
fn outcome_unknown_text(expires_at_epoch: i64) -> String {
    let until = time::OffsetDateTime::from_unix_timestamp(expires_at_epoch)
        .map(|t| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        })
        .unwrap_or_else(|_| "an unknown time".to_owned());
    format!(
        "outcome unknown: this permit may be live until {until} (it can run its one call once). kv lock ends it for any call not yet made; a call already under way is not stopped. Check that kv lock says \"vault locked\"."
    )
}

fn signing_failure(p: &Palette, error: SigningError) -> project::Exit {
    project::fail(p, error.message())
}
