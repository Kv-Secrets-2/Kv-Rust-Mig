//! Python `_create_run_approval_request` and `_create_run_policy_request`: the pending
//! requests the daemon files for the owner when a protected run lacks a grant or is
//! stopped by the command allowlist. Both are written through `kv-requests`; neither
//! loads a secret.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value, json};

use kv_requests::approvals::{self, RequestHooks};
use kv_requests::policy_requests;
use kv_requests::{RequestError, Result};

use crate::run::RunCtx;

const MISSING_GRANT_REASON: &str = "created after missing kv_run grant";
const POLICY_BLOCK_REASON: &str = "created after kv_run command-policy block";
const CONTINUATION_PREFIX: &str = "continues interrupted job ";

/// Python `_run_grant_actor_fields`: the actor fields safe to show in approval guidance.
pub(crate) fn grant_actor_fields(actor: &Map<String, Value>) -> Map<String, Value> {
    let mut fields = Map::new();
    for (key, limit) in [("source", 24), ("client_name", 80), ("session_id", 80)] {
        if let Some(text) = actor.get(key).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                fields.insert(
                    key.into(),
                    json!(trimmed.chars().take(limit).collect::<String>()),
                );
            }
        }
    }
    fields
}

/// Python `_request_network` in a trust context: the unlock snapshot's
/// `network_commands`, first matching entry.
pub(crate) fn request_network(approved: &Value, argv: &[String]) -> (bool, String) {
    let entries = approved
        .get("security")
        .and_then(|security| security.get("network_commands"))
        .and_then(Value::as_array);
    if let Some(entries) = entries {
        for entry in entries.iter().filter_map(Value::as_str) {
            if !entry.is_empty()
                && kv_sandbox::classify::matches_allowlist(
                    argv,
                    std::slice::from_ref(&entry.to_owned()),
                )
            {
                return (true, entry.to_owned());
            }
        }
    }
    (false, "none".to_owned())
}

/// Python `saved_passes._continued_job`: the job a `kv resume` continuation reason names.
fn continued_job(reason: Option<&str>) -> Option<&str> {
    let job = reason?.strip_prefix(CONTINUATION_PREFIX)?;
    let hex = job.strip_prefix("job_")?;
    (hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(job)
}

/// The risk-card and service-call helpers Python's `create_approval_request` imports.
struct Hooks;

impl RequestHooks for Hooks {
    fn build_run_risk_card(&self, inputs: &Value) -> Result<Value> {
        let argv: Vec<String> = inputs["argv"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let options = kv_preflight::RunRiskCardOptions {
            run_identity: &inputs["run_identity"],
            secret_names: inputs.get("secret_names"),
            capability_names: inputs.get("capability_names"),
            max_calls: inputs.get("max_calls"),
            source: inputs.get("source"),
        };
        kv_preflight::build_run_risk_card(&argv, inputs["cwd"].as_str(), &options)
            .map_err(|error| RequestError::Invalid(error.to_string()))
    }

    fn normalize_risk_card(&self, card: &Value) -> Result<Value> {
        Ok(kv_approvals::risk_card::normalize_risk_card(Some(card)))
    }

    fn normalize_service_calls(
        &self,
        names: &[String],
        max_calls: &Value,
        calls_per_service: &Value,
    ) -> Result<(Value, Value)> {
        let (total, per_service) = kv_grants::normalize::normalize_service_calls(
            names,
            Some(max_calls),
            Some(calls_per_service),
        )
        .map_err(|error| RequestError::Invalid(error.to_string()))?;
        Ok((
            json!(total),
            per_service.map(Value::Object).unwrap_or(Value::Null),
        ))
    }
}

fn request_reason<'a>(ctx: &'a RunCtx<'_>) -> Option<&'a str> {
    ctx.request.get("reason").and_then(Value::as_str)
}

/// Python `_create_run_approval_request`: file (or reuse) the pending approval request
/// for a secret- or capability-bearing run without a grant, record it for this session,
/// and audit it. `None` when the run asked for nothing to approve; an `error` object when
/// the store refused it (the run's refusal still stands).
pub(crate) fn create_run_approval_request(
    ctx: &RunCtx<'_>,
    run_identity: &Map<String, Value>,
    argv: &[String],
    run_cwd: &str,
    env_names: Option<&[String]>,
    capability_names: &[String],
    actor: &Map<String, Value>,
) -> Option<Value> {
    let capabilities: Vec<String> = capability_names
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if env_names.is_none_or(<[String]>::is_empty) && capabilities.is_empty() {
        return None;
    }
    let secret_names: Vec<String> = env_names
        .unwrap_or(&[])
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut max_calls = if capabilities.is_empty() {
        Value::Null
    } else {
        json!(1)
    };
    // Build A, A3: a run naming several services asks for 1 call each.
    let calls_per_service = if capabilities.len() > 1 {
        let per: Map<String, Value> = capabilities
            .iter()
            .map(|name| (name.clone(), json!(1)))
            .collect();
        max_calls = json!(per.len());
        Value::Object(per)
    } else {
        Value::Null
    };
    let (network, network_reason) = request_network(ctx.approved, argv);
    let source = json!("daemon_missing_grant");
    let identity = Value::Object(run_identity.clone());
    let secret_scope = json!(secret_names);
    let capability_scope = json!(capabilities);
    let card_options = kv_preflight::RunRiskCardOptions {
        run_identity: &identity,
        secret_names: Some(&secret_scope),
        capability_names: Some(&capability_scope),
        max_calls: Some(&max_calls),
        source: Some(&source),
    };
    let reason = request_reason(ctx)
        .unwrap_or(MISSING_GRANT_REASON)
        .to_owned();
    let shown_actor = grant_actor_fields(actor);
    let filed = kv_preflight::build_run_risk_card(argv, Some(run_cwd), &card_options)
        .map_err(|error| RequestError::Invalid(error.to_string()))
        .and_then(|risk_card| {
            let options = json!({
                "run_identity": identity,
                "argv": argv,
                "cwd": run_cwd,
                "secret_names": secret_names,
                "capability_names": capabilities,
                "actor": shown_actor,
                "source": source,
                "reason": reason,
                "risk_level": if capabilities.is_empty() { "raw_secret" } else { "brokered_api" },
                "max_calls": max_calls,
                "risk_card": risk_card,
                "environment": ctx.env,
                "network": network,
                "network_reason": network_reason,
                "calls_per_service": calls_per_service,
            });
            let records = &ctx.shared.requests;
            let reuse = |existing: &Value| -> bool {
                // Python `_reuse_filter`: only a request this session recorded, and never
                // across a `kv resume` continuation.
                let existing_reason = existing.get("reason").and_then(Value::as_str);
                if (continued_job(Some(MISSING_GRANT_REASON)).is_some()
                    || continued_job(existing_reason).is_some())
                    && existing_reason != Some(MISSING_GRANT_REASON)
                {
                    return false;
                }
                existing
                    .get("request_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| matches!(records.get(id, None), Ok(Some(_))))
            };
            let request =
                approvals::create_approval_request(ctx.root, &options, &Hooks, Some(&reuse))?;
            records.record(&request, None)?;
            Ok(request)
        });
    let request = match filed {
        Ok(request) => request,
        Err(error) => {
            return Some(json!({"error": format!("approval request not stored: {error}")}));
        }
    };
    let mut fields = Map::new();
    fields.insert("request_id".into(), request["request_id"].clone());
    fields.insert(
        "scope".into(),
        json!(if capabilities.is_empty() {
            "secret"
        } else {
            "capability"
        }),
    );
    fields.insert("requested_secret_count".into(), json!(secret_names.len()));
    fields.insert("capability_count".into(), json!(capabilities.len()));
    fields.extend(shown_actor);
    fields.extend(kv_audit::requester_fields(
        Some(&Value::Object(actor.clone())),
        request.get("reason"),
    ));
    let _ = ctx.audit.emit("approval_request_created", fields);
    let id = request["request_id"].as_str().unwrap_or_default();
    Some(json!({
        "request_id": request["request_id"],
        "status": request["status"],
        "expires_at": request["expires_at"],
        "inbox_command": "kv approvals watch",
        "approve_command": format!("kv approvals approve {id}"),
        "message": "A pending approval request was created. The user can approve or deny it from their own terminal.",
    }))
}

/// Python `_record_request`: a caller-described approval request, written and
/// recorded by the daemon after the daemon recomputes its exact run identity and
/// network decision. The caller supplies facts, never authority.
pub(crate) fn record_request(
    root: &Path,
    root_text: &str,
    approved: &Value,
    shared: &crate::Shared,
    trust: &crate::TrustContext,
    request: &Map<String, Value>,
) -> Value {
    if !trust.protected {
        return json!({"error":kv_approvals::permit_session::NO_PASSPHRASE_REFUSAL,"error_code":"no_passphrase"});
    }
    const ALLOWED: &[&str] = &[
        "run_identity",
        "argv",
        "cwd",
        "secret_names",
        "capability_names",
        "actor",
        "reason",
        "source",
        "risk_level",
        "ttl_seconds",
        "max_calls",
        "risk_card",
        "calls_per_service",
        "recommended_ttl_seconds",
    ];
    let Some(fields_value) = request.get("request").filter(|value| value.is_object()) else {
        return json!({"error":"record_request needs a request object"});
    };
    let mut fields = fields_value.as_object().cloned().unwrap_or_default();
    if fields.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return json!({"error":"record_request needs a request object"});
    }
    let Some(run_identity) = fields.remove("run_identity") else {
        return json!({"error":"record_request needs a request object"});
    };
    let argv: Vec<String> = fields
        .get("argv")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let Some(cwd) = fields.get("cwd").and_then(Value::as_str) else {
        return json!({"error":"record_request needs a request object"});
    };
    if !kv_sandbox::paths::is_abs(cwd) {
        return json!({"error":"working directory must be an absolute path"});
    }
    let watched = [root_text.to_owned()];
    if kv_sandbox::paths::inside_secrets_as_written(cwd, &watched) {
        return json!({"error":"working directory must not be inside a vault folder"});
    }
    let Ok(request_cwd) = kv_sandbox::paths::resolve(cwd) else {
        return json!({"error":"the working directory could not be resolved"});
    };
    if kv_sandbox::paths::inside_secrets_as_written(&request_cwd, &watched) {
        return json!({"error":"working directory must not be inside a vault folder"});
    }
    fields.insert("cwd".into(), json!(request_cwd));
    let (network, network_reason) = request_network(approved, &argv);
    let secret_names: Vec<String> = fields
        .get("secret_names")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let scope = kv_sandbox::identity::IdentityScope {
        env_names: Some(&secret_names),
        secret_scope: Some(json!(if secret_names.is_empty() {
            "capability"
        } else {
            "selected"
        })),
        secrets_injected: true,
    };
    let computed = match kv_sandbox::identity::build_run_identity(
        &argv,
        fields["cwd"].as_str().unwrap_or(""),
        &scope,
        "run_request_record",
        &watched,
    ) {
        Ok(identity) => identity,
        Err(error) => return json!({"error":error.to_string()}),
    };
    let identity_matches = run_identity.as_object().is_some_and(|supplied| {
        [
            "command_fingerprint",
            "script_kind",
            "script_sha256",
            "script_ref_hash",
        ]
        .iter()
        .all(|key| supplied.get(*key) == computed.get(*key))
    });
    if !identity_matches {
        return json!({"error":"run_identity does not match the command, folder, scope and script"});
    }
    fields.insert("run_identity".into(), run_identity);
    fields.insert(
        "environment".into(),
        request.get("environment").cloned().unwrap_or(Value::Null),
    );
    fields.insert("network".into(), json!(network));
    fields.insert("network_reason".into(), json!(network_reason));
    let created = approvals::create_approval_request(root, &Value::Object(fields), &Hooks, None);
    match created {
        Ok(created) => {
            if let Err(error) = shared.requests.record(&created, None) {
                return json!({"error":error.to_string()});
            }
            json!({"request":created})
        }
        Err(error) => json!({"error":error.to_string()}),
    }
}

/// Python `_create_run_policy_request`: file the pending command-policy request for an
/// allowlist block. `None` when the block is not the allowlist's.
pub(crate) fn create_run_policy_request(
    ctx: &RunCtx<'_>,
    argv: &[String],
    run_cwd: &str,
    command_reason: &str,
    command_mode: &str,
    actor: &Map<String, Value>,
) -> Option<Value> {
    if !command_reason.contains("command not in allowlist") {
        return None;
    }
    let shown_actor = grant_actor_fields(actor);
    let reason = request_reason(ctx).unwrap_or(POLICY_BLOCK_REASON);
    let filed = policy_requests::policy_pattern_for_argv(&json!(argv)).and_then(|pattern| {
        policy_requests::create_policy_request(
            ctx.root,
            &json!({
                "argv": argv,
                "cwd": run_cwd,
                "pattern": pattern,
                "actor": shown_actor,
                "source": "daemon_policy_block",
                "reason": reason,
                "command_reason": command_reason,
                "command_mode": command_mode,
            }),
        )
    });
    let request = match filed {
        Ok(request) => request,
        Err(error) => {
            return Some(json!({"error": format!("policy request not stored: {error}")}));
        }
    };
    let mut fields = Map::new();
    fields.insert("request_id".into(), request["request_id"].clone());
    fields.insert("pattern".into(), request["pattern"].clone());
    fields.extend(shown_actor);
    fields.extend(kv_audit::requester_fields(
        Some(&Value::Object(actor.clone())),
        request.get("reason"),
    ));
    let _ = ctx.audit.emit("policy_request_created", fields);
    let id = request["request_id"].as_str().unwrap_or_default();
    Some(json!({
        "request_id": request["request_id"],
        "status": request["status"],
        "expires_at": request["expires_at"],
        "inbox_command": "kv policy watch",
        "allow_command": format!("kv policy allow {id}"),
        "block_command": format!("kv policy block {id}"),
        "message": "A pending command-policy request was created. The user can allow the command shape or keep it blocked from their own terminal. This does not approve secrets or API access.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_fields_are_trimmed_and_bounded() {
        let actor: Map<String, Value> = serde_json::from_value(json!({
            "source": format!("  {}  ", "s".repeat(40)),
            "client_name": " codex ",
            "session_id": "",
            "version": "1.0",
        }))
        .unwrap();
        let shown = grant_actor_fields(&actor);
        assert_eq!(shown["source"].as_str().unwrap().len(), 24);
        assert_eq!(shown["client_name"], "codex");
        assert!(!shown.contains_key("session_id"));
        assert!(!shown.contains_key("version"));
    }

    #[test]
    fn continuation_reasons_name_a_job() {
        let id = format!("job_{}", "a".repeat(32));
        assert_eq!(
            continued_job(Some(&format!("{CONTINUATION_PREFIX}{id}"))),
            Some(id.as_str())
        );
        assert_eq!(
            continued_job(Some("continues interrupted job job_xyz")),
            None
        );
        assert_eq!(continued_job(Some(MISSING_GRANT_REASON)), None);
        assert_eq!(continued_job(None), None);
    }

    #[test]
    fn network_decision_takes_the_first_matching_entry() {
        let approved = json!({"security": {"network_commands": ["", "git push", "python3"]}});
        let argv = |s: &str| s.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            request_network(&approved, &argv("python3 app.py")),
            (true, "python3".to_owned())
        );
        assert_eq!(
            request_network(&approved, &argv("curl x")),
            (false, "none".to_owned())
        );
        assert_eq!(
            request_network(&json!({}), &argv("python3 app.py")),
            (false, "none".to_owned())
        );
    }
}
