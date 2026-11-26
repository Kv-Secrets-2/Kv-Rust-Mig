//! Owner-channel run-grant records and registration. The daemon is the authority
//! on whether a signed approval belongs to this session's recorded request; the
//! CLI signs, but never decides, that binding.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use kv_approvals::permit_session::SessionBinding;
use kv_approvals::verify::{payload_digest, signed_payload};
use kv_approvals::wire::{FieldValue, MessageFields, MessageKind};
use serde_json::{Map, Value};

use super::{AgentError, Shared, TrustContext, owner_error, signed_owner};

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

fn binding(trust: &TrustContext, providers: &kv_broker::ProviderTable) -> SessionBinding {
    SessionBinding {
        protected: trust.protected,
        owner_public_key: trust.owner_public_key,
        owner_key_id: trust.owner_key_id.clone(),
        local_approval_id: trust.local_approval_id.clone(),
        location: trust.location.clone(),
        session_nonce: *trust.session_nonce,
        providers: Arc::new(providers.clone()),
    }
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

pub(super) fn owner_request_record(
    trust: &TrustContext,
    shared: &Shared,
    challenge: Vec<u8>,
    request: &Map<String, Value>,
) -> Result<Value, AgentError> {
    let Some(request_id) = request.get("request_id").and_then(Value::as_str) else {
        return owner_error(trust, challenge, "bad_request");
    };
    trust.observe()?;
    let record = shared
        .requests
        .get(request_id, None)
        .map_err(|error| AgentError(error.to_string()))?;
    let Some(record) = record else {
        return owner_error(trust, challenge, "unknown_request");
    };
    let mut fields = fields(trust, challenge);
    fields.insert("request_id".into(), FieldValue::Text(record.request_id));
    fields.insert(
        "content_digest".into(),
        FieldValue::Text(record.content_digest),
    );
    fields.insert("environment".into(), FieldValue::Text(record.environment));
    fields.insert("network".into(), FieldValue::Bool(record.network));
    fields.insert(
        "network_reason".into(),
        FieldValue::Text(record.network_reason),
    );
    signed_owner(trust, MessageKind::RequestRecordV1, fields)
}

pub(super) fn owner_grant_register(
    trust: &TrustContext,
    shared: &Shared,
    providers: &kv_broker::ProviderTable,
    challenge: Vec<u8>,
    request: &Map<String, Value>,
    approved: &Value,
) -> Result<Value, AgentError> {
    if approved
        .get("security")
        .and_then(|security| security.get("approval_mode"))
        .and_then(Value::as_str)
        == Some("protected-approval")
    {
        return owner_error(trust, challenge, "protected_mode");
    }
    if !trust.protected {
        return owner_error(trust, challenge, "unprotected");
    }
    let Some(grant) = request.get("grant").filter(|grant| grant.is_object()) else {
        return owner_error(trust, challenge, "bad_request");
    };
    trust.observe()?;
    let Some(payload) = signed_payload(&binding(trust, providers), grant) else {
        return owner_error(trust, challenge, "not_signed");
    };
    let Some(digest) = payload_digest(&Value::Object(payload.clone())) else {
        return owner_error(trust, challenge, "bad_request");
    };
    let request_id = payload
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let record = shared
        .requests
        .get(request_id, None)
        .map_err(|error| AgentError(error.to_string()))?;
    let expires = payload.get("request_expires_at_epoch").cloned();
    let matches_record = record.as_ref().is_some_and(|record| {
        record.content_digest
            == payload
                .get("request_digest")
                .and_then(Value::as_str)
                .unwrap_or("")
            && expires == Some(Value::Number(record.expires_at_epoch.clone()))
    });
    if !matches_record {
        return owner_error(trust, challenge, "unknown_request");
    }
    let (status, verified) = match shared.ledger.insert(&payload, &digest, now_epoch()) {
        Ok(registered) => registered,
        Err(error) => return owner_error(trust, challenge, error.code()),
    };
    let mut fields = fields(trust, challenge);
    fields.insert(
        "grant_id".into(),
        FieldValue::Text(verified.grant_id.clone()),
    );
    fields.insert(
        "request_id".into(),
        FieldValue::Text(verified.request_id.clone()),
    );
    fields.insert(
        "payload_digest".into(),
        FieldValue::Text(verified.payload_digest.clone()),
    );
    fields.insert("status".into(), FieldValue::Enum(status.into()));
    signed_owner(trust, MessageKind::GrantRegisterAckV1, fields)
}
