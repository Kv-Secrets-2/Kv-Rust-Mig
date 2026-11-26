//! `kv approvals`: the owner's inbox and decisions. This stage ports the one-call
//! permit decision (`_approve_call_permit`); approval requests, pauses, the page,
//! deny and prune are refused as not available in this build.

use crate::owner_policy as owner;
use crate::owner_signing::{PermitSigningContext, SigningError};
use crate::project::{self, CmdResult};
use crate::terminal;
use crate::ui::{self, Palette};
use serde_json::{Map, Value, json};

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
    Deny {
        request_id: String,
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
        ApprovalsAction::Deny { request_id } => deny(p, &request_id),
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
            "{}create one: kv api anthropic-count-tokens INPUT{}",
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

/// Deny a pending one-call permit with the owner key over the authenticated
/// owner channel. Denial is terminal in the daemon's permit state machine.
fn deny(p: &Palette, request_id: &str) -> CmdResult {
    let root = project::require_project(p)?;
    if !owner::vault_has_passphrase(&root) {
        return Err(project::fail(
            p,
            kv_approvals::permit_session::NO_PASSPHRASE_REFUSAL,
        ));
    }
    terminal::check_owner_terminal().map_err(|e| project::fail(p, &e.to_string()))?;
    if !request_id.starts_with("permit_request_") {
        return Err(project::fail(
            p,
            "denying run grants and paused jobs is not available in this build; a one-call permit (permit_request_...) is",
        ));
    }
    owner::block_local_approval_if_protected(p, &root, "permit denial")?;
    let passphrase =
        project::read_owner_secret(p, &format!("  {}Passphrase{}: ", p.yellow, p.reset))?;
    let identity =
        project::unlock_identity(&root, passphrase.as_bytes()).map_err(|e| project::fail(p, &e))?;
    let ctx = PermitSigningContext::begin(&root, identity).map_err(|e| signing_failure(p, e))?;
    let record = ctx
        .permit_record(request_id)
        .map_err(|e| signing_failure(p, e))?;
    let denial = ctx
        .sign_denial(&record)
        .map_err(|e| signing_failure(p, e))?;
    ctx.register_denial(&denial, &record)
        .map_err(|e| signing_failure(p, e))?;
    project::audit_event(
        "call_permit_denied",
        Map::from_iter([
            ("request_id".into(), json!(request_id)),
            ("permit_id".into(), record.facts["permit_id"].clone()),
        ]),
    );
    ui::success(p, "One-call permit denied.");
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
        return Err(project::fail(
            p,
            "approving run grants and paused jobs is not available in this build; a one-call permit (permit_request_...) is",
        ));
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
