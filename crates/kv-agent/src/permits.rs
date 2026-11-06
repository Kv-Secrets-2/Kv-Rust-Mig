//! Ordinary API one-call permits. Authority stays in the session ledger; these
//! helpers translate broker previews and authenticated owner protocol messages.

use super::{AgentError, TrustContext, owner_error, signed_owner};
use kv_approvals::canonical::canonical_json;
use kv_approvals::permit_session::{
    CallFacts, PermitError, SessionBinding, SessionPermits, WaitOver,
};
use kv_approvals::wire::{FieldValue, MessageFields, MessageKind};
use kv_broker::{ApiCaller, ApiPreview, ApiRequest, ProviderTable};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(super) fn for_session(
    trust: &TrustContext,
    providers: Arc<ProviderTable>,
) -> Arc<SessionPermits> {
    Arc::new(SessionPermits::new(SessionBinding {
        protected: trust.protected,
        owner_public_key: trust.owner_public_key,
        owner_key_id: trust.owner_key_id.clone(),
        local_approval_id: trust.local_approval_id.clone(),
        location: trust.location.clone(),
        session_nonce: *trust.session_nonce,
        providers,
    }))
}

fn fields(trust: &TrustContext, challenge: Vec<u8>) -> MessageFields {
    let mut fields = MessageFields::new();
    fields.insert("challenge".into(), FieldValue::Nonce(challenge));
    fields.insert(
        "session_nonce".into(),
        FieldValue::Nonce(trust.session_nonce.to_vec()),
    );
    fields
}

fn canonical(value: &Value) -> Result<FieldValue, AgentError> {
    canonical_json(value)
        .map(FieldValue::Text)
        .map_err(|error| AgentError(error.to_string()))
}

pub(super) fn owner_request(
    trust: &TrustContext,
    permits: &SessionPermits,
    challenge: Vec<u8>,
    request: &Map<String, Value>,
) -> Result<Value, AgentError> {
    let Some(request_id) = request.get("request_id").and_then(Value::as_str) else {
        return owner_error(trust, challenge, "bad_request");
    };
    trust.observe()?;
    let Some(review) = permits.review(request_id) else {
        return owner_error(trust, challenge, "unknown_request");
    };
    let mut fields = fields(trust, challenge);
    fields.insert("request_id".into(), FieldValue::Text(request_id.into()));
    fields.insert("facts_json".into(), canonical(review.facts())?);
    fields.insert(
        "body_text".into(),
        FieldValue::Text(review.body_text().into()),
    );
    fields.insert(
        "caller_headers_json".into(),
        canonical(&Value::Object(review.caller_headers().clone()))?,
    );
    fields.insert(
        "requester_json".into(),
        canonical(review.requester().unwrap_or(&json!({})))?,
    );
    signed_owner(trust, MessageKind::PermitRequestV1, fields)
}

pub(super) fn owner_register(
    trust: &TrustContext,
    permits: &SessionPermits,
    challenge: Vec<u8>,
    request: &Map<String, Value>,
    approved: &Value,
) -> Result<Value, AgentError> {
    // The dispatcher already verified current configuration authority. Only its
    // immutable approved session snapshot supplies the local registration mode.
    trust.observe()?;
    let artifact = request.get("permit").unwrap_or(&Value::Null);
    let protected_mode = approved
        .get("security")
        .and_then(|security| security.get("approval_mode"))
        .and_then(Value::as_str)
        == Some("protected-approval");
    let registration = if protected_mode {
        match permits.registered(artifact) {
            Ok(Some(existing)) => existing,
            Ok(None) => return owner_error(trust, challenge, "protected_mode"),
            Err(error) => return owner_error(trust, challenge, error.code),
        }
    } else {
        match permits.register(artifact) {
            Ok(registration) => registration,
            Err(error) => return owner_error(trust, challenge, error.code),
        }
    };
    let mut fields = fields(trust, challenge);
    fields.insert("permit_id".into(), FieldValue::Text(registration.permit_id));
    fields.insert(
        "request_id".into(),
        FieldValue::Text(registration.request_id),
    );
    fields.insert(
        "payload_digest".into(),
        FieldValue::Text(registration.payload_digest),
    );
    fields.insert(
        "status".into(),
        FieldValue::Enum(registration.status.as_str().into()),
    );
    signed_owner(trust, MessageKind::PermitRegisterAckV1, fields)
}

pub(super) fn call_facts<'a>(
    environment: &'a str,
    provider_name: &'a str,
    provider: &'a Value,
    caller_headers: &'a Map<String, Value>,
    preview: &'a ApiPreview,
) -> CallFacts<'a> {
    CallFacts {
        environment,
        provider: provider_name,
        provider_definition: provider,
        method: &preview.method,
        url: &preview.url,
        header_names: &preview.header_names,
        caller_headers,
        body_bytes: preview.body_bytes.as_deref(),
    }
}

pub(super) fn invalid_error(error: PermitError) -> Value {
    json!({"error":error.message,"error_code":"permit_invalid"})
}

pub(super) fn precheck_error(error: PermitError) -> Value {
    if error.code == "no_passphrase" {
        json!({"error":error.message,"error_code":error.code})
    } else {
        invalid_error(error)
    }
}

pub(super) fn hard_lock_error(error: AgentError) -> Value {
    json!({"error":error.to_string(),"error_code":"vault_hard_locked"})
}

fn required(request_id: &str, permit_id: &str, policy_rule: Option<&Value>) -> Value {
    json!({
        "error":format!("This call needs your approval. Ask the owner to run: kv approvals approve {request_id}"),
        "error_code":"permit_required",
        "approval_required":true,
        "request_id":request_id,
        "permit_id":permit_id,
        "policy_rule":policy_rule,
    })
}

/// Return an approved permit id, or the complete pending/refusal response. The
/// final broker preparation must match again; nothing here debits authority.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare<'request>(
    trust: &TrustContext,
    permits: &SessionPermits,
    audit: &kv_audit::Audit,
    request: &'request Map<String, Value>,
    env: &str,
    caller: &ApiCaller,
    api_request: ApiRequest<'_>,
    policy_rule: Option<&Value>,
) -> Result<&'request str, Value> {
    let permit_id = request.get("permit_id").and_then(Value::as_str);
    if let Some(id) = permit_id
        && let Some(over) = permits.wait_over(id)
    {
        if over == WaitOver::First {
            let mut event = Map::new();
            event.insert("permit_id".into(), json!(id));
            event.insert("grant_id".into(), Value::Null);
            event.insert(
                "capability".into(),
                json!(format!("api:{}", api_request.provider_name)),
            );
            event.insert("providers".into(), json!([api_request.provider_name]));
            event.extend(kv_audit::requester_fields(
                request.get("audit_ctx"),
                request.get("reason"),
            ));
            let _ = audit.emit("owner_wait_gave_up", event);
        }
        return Err(json!({
            "error":"no answer from the owner: this call waited as long as the owner chose, and was not sent",
            "error_code":"owner_wait_gave_up",
        }));
    }
    let preview = caller.preview(api_request.clone())?;
    let empty_headers = Map::new();
    let headers = api_request
        .extra_headers
        .as_object()
        .unwrap_or(&empty_headers);
    let call = call_facts(
        env,
        api_request.provider_name,
        api_request.provider,
        headers,
        &preview,
    );
    let Some(id) = permit_id else {
        trust.observe().map_err(hard_lock_error)?;
        let requester = Value::Object(kv_audit::requester_fields(
            request.get("audit_ctx"),
            request.get("reason"),
        ));
        let created = permits.request(call, Some(&requester)).map_err(
            |error| json!({"error":error.message,"error_code":"permit_request_refused"}),
        )?;
        return Err(required(
            created.request_id(),
            created.permit_id(),
            policy_rule,
        ));
    };
    permits.match_call(id, call).map_err(invalid_error)?;
    if permits.status(id).is_none() {
        let Some(review) = permits.review_by_permit(id) else {
            return Err(
                json!({"error":"permit request is missing or expired","error_code":"permit_invalid"}),
            );
        };
        return Err(required(
            review.request_id(),
            review.permit_id(),
            policy_rule,
        ));
    }
    Ok(id)
}

/// Ordinary API audit events attribute the current caller even for a refused
/// retry. The original requester is retained separately in the owner review.
pub(super) fn audit_fields(
    permits: &SessionPermits,
    request: &Map<String, Value>,
    response: &Value,
) -> Map<String, Value> {
    let asked = response.get("error_code").and_then(Value::as_str) == Some("permit_required");
    let mut fields = Map::new();
    if asked {
        fields.insert(
            "request_id".into(),
            response.get("request_id").cloned().unwrap_or(Value::Null),
        );
        fields.insert(
            "permit_id".into(),
            response.get("permit_id").cloned().unwrap_or(Value::Null),
        );
    } else if request.contains_key("permit_id") {
        let known = request
            .get("permit_id")
            .and_then(Value::as_str)
            .is_some_and(|id| {
                permits.review_by_permit(id).is_some() || permits.status(id).is_some()
            });
        let label = if known {
            kv_audit::label_text(request.get("permit_id"), 80).map_or(Value::Null, Value::String)
        } else {
            json!("[permit id not known to this service]")
        };
        fields.insert("permit_id".into(), label);
    } else {
        return fields;
    }
    fields.extend(kv_audit::requester_fields(
        request.get("audit_ctx"),
        request.get("reason"),
    ));
    fields
}
