//! Python `_handle_capability_api_call`: a script-facing HTTP API call authenticated by
//! the run's capability token (`KV_CAP_TOKEN`), never by the daemon token. The token is
//! checked before the provider secret is read and charged only at send time, inside the
//! committed work window.
//!
//! Stage 6d-1 covers the policy-allowed calls. Not ported yet, each answered with a fixed
//! refusal that sends and charges nothing: a capability run's one-call permits
//! (`_prepare_api_permit` with grant and run ids), pauses and saved passes
//! (`_spent_pass_answer`, `_owner_held_answer`, `_ended_wait_answer`, `_refused_job_answer`,
//! `_save_part2`) and POST wallets (`_wallet_*`).

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kv_approvals::permit_session::{SessionBinding, SessionPermits};
use kv_grants::capabilities::{
    ConsumeOptions, Release, consume_capability_token, require_verified, token_hash, validate_token,
};
use kv_grants::grants::GrantContext;
use kv_store::DrawerStore;
use serde_json::{Map, Value, json};

use crate::lifecycle::{CommitError, Lifecycle};
use crate::{API_TIMEOUT, ConnectionGuard, SecretCache, Shared, TrustContext, permits, run};

pub(crate) struct CapCtx<'a> {
    pub(crate) root: &'a Path,
    pub(crate) store: &'a DrawerStore,
    pub(crate) cache: &'a Mutex<SecretCache>,
    pub(crate) trust: &'a TrustContext,
    pub(crate) providers: &'a kv_broker::ProviderTable,
    pub(crate) policy: &'a kv_broker::HttpPolicySnapshot,
    pub(crate) caller: &'a kv_broker::ApiCaller,
    pub(crate) permits: &'a SessionPermits,
    pub(crate) lifecycle: &'a Arc<Lifecycle>,
    pub(crate) connection: &'a ConnectionGuard,
    pub(crate) shared: &'a Shared,
    pub(crate) env: &'a str,
    pub(crate) request: &'a Map<String, Value>,
}

const NO_TOKEN: &str =
    "token is missing, expired, consumed, revoked, or scoped to a different run/provider";

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn denied(reason: impl std::fmt::Display) -> Value {
    json!({"error": format!("capability denied: {reason}")})
}

pub(crate) fn handle(ctx: &CapCtx<'_>) -> Value {
    let request = ctx.request;
    let provider_name = request
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(provider) = ctx.providers.get(provider_name) else {
        return json!({
            "error": format!(
                "unknown provider: {provider_name}. available: {}",
                ctx.providers.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        });
    };
    if provider
        .get("provider_type")
        .and_then(Value::as_str)
        .unwrap_or("http")
        != "http"
    {
        return json!({"error": format!("provider '{provider_name}' is not an HTTP API provider")});
    }
    if let Some(error) = kv_broker::api_body_security_error(provider, request.get("body")) {
        return json!({"error": error});
    }
    let headers = request.get("headers").cloned().unwrap_or_else(|| json!({}));
    let method = request
        .get("method")
        .cloned()
        .unwrap_or_else(|| json!("GET"));
    let path = request.get("path").cloned().unwrap_or_else(|| json!("/"));
    let decision = kv_broker::evaluate_provider_http_request(
        ctx.policy,
        provider_name,
        provider,
        &method,
        &path,
        request.get("body"),
        &headers,
    );
    let per_call =
        decision.get("error_code").and_then(Value::as_str) == Some("http_approval_required");
    if !per_call
        && !decision
            .get("allowed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return crate::strip_allowed(decision);
    }
    let capability_name = format!("api:{provider_name}");

    // The token is checked (not charged) before any secret is read. Without a passphrase
    // no token was ever issued, so the lookup's own words answer.
    let token = request
        .get("capability_token")
        .cloned()
        .unwrap_or(Value::Null);
    let hash = match validate_token(&token) {
        Ok(token) => token_hash(token),
        Err(error) => return denied(error.message()),
    };
    let Some(signing_key) = ctx.trust.approval_signing_key.as_ref() else {
        return denied(NO_TOKEN);
    };
    let binding = SessionBinding {
        protected: ctx.trust.protected,
        owner_public_key: ctx.trust.owner_public_key,
        owner_key_id: ctx.trust.owner_key_id.clone(),
        local_approval_id: ctx.trust.local_approval_id.clone(),
        location: ctx.trust.location.clone(),
        session_nonce: *ctx.trust.session_nonce,
        providers: Arc::new(ctx.providers.clone()),
    };
    let grant_ctx = GrantContext {
        root: ctx.root,
        signing_key: &signing_key[..],
        state_key: ctx.trust.grant_state_key.as_bytes(),
        binding: &binding,
        ledger: &ctx.shared.ledger,
        providers: ctx.providers,
    };
    let actor = Value::Object(run::actor_fields(request));
    let env_value = Value::String(ctx.env.to_owned());
    let run_identity = request.get("run_identity").cloned().unwrap_or(Value::Null);
    let consumed = match consume_capability_token(
        &grant_ctx,
        &token,
        &run_identity,
        &json!(capability_name),
        now_epoch(),
        ConsumeOptions {
            actor: Some(&actor),
            env_name: Some(&env_value),
            require_parent: true,
            provider_config: Some(provider),
            charge: false,
            allow_spent: false,
            wallet_entry: None,
        },
    ) {
        Ok(consumed) => consumed,
        Err(error) => return denied(error),
    };
    let Some(record) = consumed.record else {
        return denied(consumed.denial);
    };
    let verified = consumed.verified;
    if verified.as_ref().is_some_and(|v| v.post_wallet.is_some()) {
        return denied("POST wallets are not supported by this kv service yet");
    }
    let token_id = record.get("token_id").cloned().unwrap_or(Value::Null);
    let remaining = record
        .get("remaining_calls")
        .cloned()
        .unwrap_or(Value::Null);
    let unconsumed = |mut error: Value| {
        if let Some(object) = error.as_object_mut() {
            object.insert("capability_consumed".into(), json!(false));
            object.insert("capability_remaining_calls".into(), remaining.clone());
        }
        error
    };
    if request.contains_key("permit_id") && !per_call {
        return json!({
            "error":"this call does not match a one-call permit",
            "error_code":"permit_invalid"
        });
    }
    if per_call && let Err(error) = ctx.permits.precheck(request.get("permit_id")) {
        return unconsumed(permits::precheck_error(error));
    }

    let secret_name = provider
        .get("secret_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let lookup = match ctx.cache.lock() {
        Ok(mut cache) => cache.get(ctx.store, ctx.env, secret_name),
        Err(_) => return json!({"error":"secret cache is unavailable"}),
    };
    let secret_value = match lookup {
        Ok(Some(secret)) if !secret.is_empty() => secret,
        Ok(_) => {
            return json!({
                "error": format!("secret '{secret_name}' not found in env '{}'", ctx.env),
                "capability_name": capability_name,
                "capability_token_id": token_id,
                "capability_consumed": false,
            });
        }
        Err(error) => return json!({"error": error.to_string()}),
    };
    if per_call {
        return unconsumed(json!({
            "error":"one-call permits for capability runs are not supported by this kv service yet",
            "error_code":"permit_request_refused"
        }));
    }

    // `_granted_api_call`: the pass's verified grant must cover this call and this provider
    // definition before anything is charged or sent.
    let digest = kv_approvals::wire::provider_digest(provider).ok();
    let release = Release {
        kind: "transport",
        grant_id: record.get("grant_id").and_then(Value::as_str),
        env_name: ctx.env,
        secret_names: &[],
        capability_name: Some(&capability_name),
        provider_digest: digest.as_deref(),
        sandboxed: None,
        network: None,
    };
    if let Err(error) = require_verified(verified.as_deref(), &release) {
        return denied(error.message());
    }

    let secrets_for_redact = kv_broker::redact_one_secret(secret_name, &secret_value);
    let api_request = kv_broker::ApiRequest {
        provider_name,
        provider,
        secret_value: &secret_value,
        path: path.as_str().unwrap_or("/"),
        method: method.as_str().unwrap_or("GET"),
        body: request.get("body").filter(|body| !body.is_null()),
        extra_headers: &headers,
        secrets_for_redact: &secrets_for_redact,
        timeout: Duration::from_secs(API_TIMEOUT),
        max_response_bytes: kv_broker::MAX_BROKER_RESPONSE_BYTES,
    };
    let charged: RefCell<Option<Map<String, Value>>> = RefCell::new(None);
    let refused = Cell::new(false);
    let mut result = ctx.caller.call_with_checks(
        api_request,
        |_preview| Ok(()),
        |()| {
            // The charge (`spend_pass`, this call's service only) happens inside the
            // commit: a hard lock or a stop refuses the call before anything is sent.
            let committed = ctx
                .lifecycle
                .try_commit_for_with_charge(ctx.connection, || {
                    let pin = ctx.trust.observe_held().map_err(permits::hard_lock_error)?;
                    let record = ctx
                        .shared
                        .ledger
                        .spend_pass(&hash, now_epoch(), Some(&capability_name))
                        .map_err(|error| denied(error.message()))?;
                    charged.replace(Some(record));
                    Ok(pin)
                })
                .map_err(|error| match error {
                    CommitError::Stopping => json!({
                        "error":"the agent is stopping; new requests are refused",
                        "error_code":"agent_stopping",
                    }),
                    CommitError::Charge(refusal) => refusal,
                });
            refused.set(committed.is_err());
            committed
        },
    );
    if refused.get() {
        return result;
    }
    let charged = charged.into_inner();
    if let Some(object) = result.as_object_mut() {
        object.insert("capability_name".into(), json!(capability_name));
        object.insert("capability_token_id".into(), token_id);
        object.insert("capability_consumed".into(), json!(charged.is_some()));
        object.insert(
            "capability_remaining_calls".into(),
            charged
                .as_ref()
                .unwrap_or(&record)
                .get("remaining_calls")
                .cloned()
                .unwrap_or(Value::Null),
        );
        if let Some(warning) = decision.get("warning").and_then(Value::as_str) {
            let current = object
                .get("warning")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            object.insert(
                "warning".into(),
                Value::String(if current.is_empty() {
                    warning.to_owned()
                } else {
                    format!("{current}\n{warning}")
                }),
            );
        }
    }
    result
}

/// The `capability_api` audit event (Python's dispatch after `_handle_capability_api_call`).
/// A provider name kv does not serve is written as "unknown". Python coalesces repeated
/// refusals of one kind (`RefusalCoalescer`); this service writes each one.
pub(crate) fn audit(
    audit: &kv_audit::Audit,
    providers: &kv_broker::ProviderTable,
    permits: &SessionPermits,
    request: &Map<String, Value>,
    response: &Value,
) -> Result<(), kv_audit::LossReason> {
    let provider = request
        .get("provider")
        .and_then(Value::as_str)
        .filter(|name| providers.contains_key(*name))
        .unwrap_or("unknown");
    let mut entry = Map::new();
    entry.insert("provider".into(), json!(provider));
    for key in [
        "capability_name",
        "capability_token_id",
        "error_code",
        "policy_rule",
    ] {
        entry.insert(
            key.into(),
            response.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    entry.insert(
        "capability_consumed".into(),
        json!(
            response
                .get("capability_consumed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        ),
    );
    entry.insert(
        "approval_required".into(),
        json!(
            response
                .get("approval_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        ),
    );
    entry.insert(
        "policy_warning".into(),
        response.get("warning").cloned().unwrap_or(Value::Null),
    );
    entry.insert("error".into(), json!(response.get("error").is_some()));
    if let Some(wallet_entry) = response.get("wallet_entry").filter(|v| !v.is_null()) {
        entry.insert("wallet_entry".into(), wallet_entry.clone());
    }
    entry.extend(run::actor_fields(request));
    entry.extend(permits::audit_fields(permits, request, response));
    audit.emit("capability_api", entry)
}
