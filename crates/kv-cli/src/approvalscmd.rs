//! `kv approvals`: the owner's inbox and decisions. This stage ports the one-call
//! permit decision (`_approve_call_permit`); approval requests, pauses, the page,
//! deny and prune are refused as not available in this build.

use crate::owner_policy as owner;
use crate::owner_signing::{PermitSigningContext, SigningError};
use crate::project::{self, CmdResult};
use crate::terminal;
use crate::ui::{self, Palette};
use serde_json::{Map, json};

pub enum ApprovalsAction {
    Approve {
        request_id: String,
        run_grant_flags: bool,
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
    }
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
        let (identity, _passphrase) = project::prompt_verified_passphrase(p, &root)?;
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
                ui::error(p, &format!("no permit confirmed: {reason}"));
                ui::info(&format!(
                    "{}the service may still hold this permit; check with kv approvals list{}",
                    p.dim, p.reset
                ));
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

fn signing_failure(p: &Palette, error: SigningError) -> project::Exit {
    project::fail(p, error.message())
}
