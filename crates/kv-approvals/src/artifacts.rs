use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use kv_crypto::Zeroizing;

use crate::{ApprovalError, canonical::artifact_canonical_json};

pub const SIGNER: &str = "local-project-hmac-v1";
pub const ARTIFACT_VERSION: i64 = 1;

pub fn grant_payload(grant: &Value, artifact_id: &str) -> Result<Value, ApprovalError> {
    let grant = grant
        .as_object()
        .ok_or_else(|| ApprovalError::from("grant must be an object"))?;
    let mut payload = Map::new();
    for (name, value) in [
        ("type", Value::String("kv_run_grant_approval".to_owned())),
        ("version", Value::from(ARTIFACT_VERSION)),
        ("artifact_id", Value::String(artifact_id.to_owned())),
        ("grant_id", get(grant, "grant_id")),
        ("created_at_epoch", get(grant, "created_at_epoch")),
        ("expires_at_epoch", get(grant, "expires_at_epoch")),
        ("created_from_run_id", get(grant, "created_from_run_id")),
        ("command_fingerprint", get(grant, "command_fingerprint")),
        ("script_kind", get(grant, "script_kind")),
        ("script_sha256", get(grant, "script_sha256")),
        ("script_ref_hash", get(grant, "script_ref_hash")),
        ("secret_names", array_or_empty(grant.get("secret_names"))),
        (
            "capability_names",
            array_or_empty(grant.get("capability_names")),
        ),
        ("actor", object_or_empty(grant.get("actor"))),
        ("risk_card", object_or_empty(grant.get("risk_card"))),
    ] {
        payload.insert(name.to_owned(), value);
    }
    for key in ["max_calls", "calls_per_service"] {
        if let Some(value) = grant.get(key).filter(|value| !value.is_null()) {
            payload.insert(key.to_owned(), copy_object_or_value(key, value)?);
        }
    }
    for key in ["usage_mode", "max_runs", "session_nonce"] {
        if let Some(value) = grant.get(key) {
            payload.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(wallet) = grant.get("post_wallet") {
        let Some(entries) = wallet.as_array() else {
            return Err("post_wallet must be a list".into());
        };
        payload.insert(
            "post_wallet".to_owned(),
            Value::Array(
                entries
                    .iter()
                    .map(|entry| object_or_empty(Some(entry)))
                    .collect(),
            ),
        );
    }
    for key in ["when_spent", "owner_wait_seconds"] {
        if let Some(value) = grant.get(key) {
            payload.insert(key.to_owned(), value.clone());
        }
    }
    Ok(Value::Object(payload))
}

fn copy_object_or_value(key: &str, value: &Value) -> Result<Value, ApprovalError> {
    if key == "calls_per_service" {
        if !value.is_object() {
            return Err("calls_per_service must be an object".into());
        }
        Ok(value.clone())
    } else {
        Ok(value.clone())
    }
}

fn get(object: &Map<String, Value>, key: &str) -> Value {
    object.get(key).cloned().unwrap_or(Value::Null)
}

fn array_or_empty(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_array)
        .cloned()
        .map(Value::Array)
        .unwrap_or_else(|| Value::Array(Vec::new()))
}

fn object_or_empty(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_object)
        .cloned()
        .map(Value::Object)
        .unwrap_or_else(|| Value::Object(Map::new()))
}

pub fn attach_grant_approval_artifact(grant: &Value, key: &[u8]) -> Result<Value, ApprovalError> {
    let mut signed = grant
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("grant must be an object"))?;
    let mut random = [0_u8; 12];
    getrandom::getrandom(&mut random).map_err(|error| error.to_string())?;
    let artifact_id = format!("approval_{}", hex::encode(random));
    let payload = grant_payload(grant, &artifact_id)?;
    let payload_bytes = artifact_canonical_json(&payload)?;
    let digest = hex::encode(Sha256::digest(payload_bytes.as_bytes()));
    let signature = hmac_hex(key, payload_bytes.as_bytes())?;
    signed.insert(
        "approval_artifact".to_owned(),
        serde_json::json!({
            "version": ARTIFACT_VERSION,
            "artifact_id": artifact_id,
            "signer": SIGNER,
            "payload_sha256": digest,
            "signature": signature,
        }),
    );
    Ok(Value::Object(signed))
}

pub fn verify_grant_approval_artifact(key: &[u8], grant: &Value) -> bool {
    verify_grant_artifact_inner(key, grant)
}

fn verify_grant_artifact_inner(key: &[u8], grant: &Value) -> bool {
    let Some(object) = grant.as_object() else {
        return false;
    };
    let Some(artifact) = object.get("approval_artifact").and_then(Value::as_object) else {
        return false;
    };
    if artifact.get("version").and_then(Value::as_i64) != Some(ARTIFACT_VERSION)
        || artifact.get("signer").and_then(Value::as_str) != Some(SIGNER)
    {
        return false;
    }
    let Some(artifact_id) = artifact.get("artifact_id").and_then(Value::as_str) else {
        return false;
    };
    if !artifact_id.starts_with("approval_") {
        return false;
    }
    let Some(signature) = artifact.get("signature").and_then(Value::as_str) else {
        return false;
    };
    if signature.len() != 64 {
        return false;
    }
    let Ok(payload) = grant_payload(grant, artifact_id) else {
        return false;
    };
    let Ok(payload_bytes) = artifact_canonical_json(&payload) else {
        return false;
    };
    let digest = hex::encode(Sha256::digest(payload_bytes.as_bytes()));
    if !string_eq(
        artifact
            .get("payload_sha256")
            .and_then(Value::as_str)
            .unwrap_or(""),
        &digest,
    ) {
        return false;
    }
    let Ok(expected) = hmac_hex(key, payload_bytes.as_bytes()) else {
        return false;
    };
    string_eq(signature, &expected)
}

pub fn grant_approval_ref(grant: &Value) -> (Option<String>, Option<String>) {
    if let Some(owner) = grant
        .get("owner_approval")
        .and_then(Value::as_object)
        .and_then(|owner| owner.get("payload"))
        .and_then(Value::as_object)
    {
        let id = owner
            .get("artifact_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let digest = artifact_canonical_json(&Value::Object(owner.clone()))
            .ok()
            .map(|body| hex::encode(Sha256::digest(body.as_bytes())));
        return (id, digest);
    }
    let artifact = grant.get("approval_artifact").and_then(Value::as_object);
    (
        artifact
            .and_then(|artifact| artifact.get("artifact_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        artifact
            .and_then(|artifact| artifact.get("payload_sha256"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
}

pub fn grant_state_payload(grant: &Value) -> Result<Value, ApprovalError> {
    let grant = grant
        .as_object()
        .ok_or_else(|| ApprovalError::from("grant must be an object"))?;
    let (artifact_id, approval_hash) = grant_approval_ref(&Value::Object(grant.clone()));
    let mut payload = Map::new();
    for (key, value) in [
        ("type", Value::String("kv_run_grant_state_v1".to_owned())),
        ("grant_id", get(grant, "grant_id")),
        (
            "artifact_id",
            artifact_id.map(Value::String).unwrap_or(Value::Null),
        ),
        (
            "approval_hash",
            approval_hash.map(Value::String).unwrap_or(Value::Null),
        ),
    ] {
        payload.insert(key.to_owned(), value);
    }
    for key in [
        "status",
        "admission_id",
        "admitted_run_id",
        "admitted_at_epoch",
        "revoke_mode",
        "revoked_at",
        "revoked_at_epoch",
        "revoke_reason",
    ] {
        payload.insert(key.to_owned(), get(grant, key));
    }
    Ok(Value::Object(payload))
}

pub fn attach_grant_state_integrity(grant: &Value, key: &[u8]) -> Result<Value, ApprovalError> {
    let mut signed = grant
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("grant must be an object"))?;
    let payload = grant_state_payload(grant)?;
    signed.insert(
        "state_integrity".to_owned(),
        Value::String(hmac_hex(
            key,
            artifact_canonical_json(&payload)?.as_bytes(),
        )?),
    );
    Ok(Value::Object(signed))
}

pub fn verify_grant_state_integrity(key: &[u8], grant: &Value) -> bool {
    let Some(signature) = grant.get("state_integrity").and_then(Value::as_str) else {
        return false;
    };
    let Ok(payload) = grant_state_payload(grant) else {
        return false;
    };
    let Ok(expected) = hmac_hex(
        key,
        artifact_canonical_json(&payload)
            .unwrap_or_default()
            .as_bytes(),
    ) else {
        return false;
    };
    string_eq(signature, &expected)
}

pub fn attach_token_integrity(record: &Value, key: &[u8]) -> Result<Value, ApprovalError> {
    let mut unsigned = record
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("record must be an object"))?;
    unsigned.remove("token_integrity");
    let payload = serde_json::json!({
        "type": "admitted_capability_v1",
        "record": Value::Object(unsigned.clone()),
    });
    let signature = hmac_hex(key, artifact_canonical_json(&payload)?.as_bytes())?;
    unsigned.insert("token_integrity".to_owned(), Value::String(signature));
    Ok(Value::Object(unsigned))
}

pub fn verify_token_integrity(record: &Value, key: &[u8]) -> bool {
    let Some(object) = record.as_object() else {
        return false;
    };
    let Some(signature) = object.get("token_integrity").and_then(Value::as_str) else {
        return false;
    };
    let mut unsigned = object.clone();
    unsigned.remove("token_integrity");
    let payload = serde_json::json!({
        "type": "admitted_capability_v1",
        "record": Value::Object(unsigned),
    });
    let Ok(body) = artifact_canonical_json(&payload) else {
        return false;
    };
    let Ok(expected) = hmac_hex(key, body.as_bytes()) else {
        return false;
    };
    string_eq(signature, &expected)
}

pub fn approval_request_payload(request: &Value) -> Result<Value, ApprovalError> {
    let request = request
        .as_object()
        .ok_or_else(|| ApprovalError::from("request must be an object"))?;
    let mut payload = Map::new();
    for (key, value) in [
        ("type", Value::String("kv_run_approval_request".to_owned())),
        ("version", Value::from(ARTIFACT_VERSION)),
        ("request_id", get(request, "request_id")),
        ("status", get(request, "status")),
        ("created_at_epoch", get(request, "created_at_epoch")),
        ("updated_at_epoch", get(request, "updated_at_epoch")),
        ("expires_at_epoch", get(request, "expires_at_epoch")),
        ("argv", array_or_empty(request.get("argv"))),
        ("cwd", get(request, "cwd")),
        ("command_fingerprint", get(request, "command_fingerprint")),
        ("script_kind", get(request, "script_kind")),
        ("script_sha256", get(request, "script_sha256")),
        ("script_ref_hash", get(request, "script_ref_hash")),
        ("secret_names", array_or_empty(request.get("secret_names"))),
        (
            "capability_names",
            array_or_empty(request.get("capability_names")),
        ),
        ("actor", object_or_empty(request.get("actor"))),
        ("source", get(request, "source")),
        ("reason", get(request, "reason")),
        ("risk_level", get(request, "risk_level")),
        ("risk_card", object_or_empty(request.get("risk_card"))),
    ] {
        payload.insert(key.to_owned(), value);
    }
    for key in ["max_calls", "calls_per_service", "recommended_ttl_seconds"] {
        if let Some(value) = request.get(key).filter(|value| !value.is_null()) {
            payload.insert(key.to_owned(), value.clone());
        }
    }
    for key in [
        "approved_at_epoch",
        "approved_grant_id",
        "approval_reason",
        "denied_at_epoch",
        "deny_reason",
        "withdrawn_at_epoch",
        "withdraw_reason",
        "approved_usage_mode",
        "approved_ttl_seconds",
        "approved_max_calls",
        "approved_calls_per_service",
    ] {
        if let Some(value) = request.get(key).filter(|value| !value.is_null()) {
            payload.insert(key.to_owned(), value.clone());
        }
    }
    Ok(Value::Object(payload))
}

pub fn attach_approval_request_integrity(
    request: &Value,
    key: &[u8],
) -> Result<Value, ApprovalError> {
    let mut signed = request
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("request must be an object"))?;
    signed.remove("request_integrity");
    let payload = approval_request_payload(&Value::Object(signed.clone()))?;
    let body = artifact_canonical_json(&payload)?;
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    let signature = hmac_hex(key, body.as_bytes())?;
    signed.insert(
        "request_integrity".to_owned(),
        serde_json::json!({
            "version": ARTIFACT_VERSION,
            "signer": SIGNER,
            "payload_sha256": digest,
            "signature": signature,
        }),
    );
    Ok(Value::Object(signed))
}

pub fn verify_approval_request_integrity(request: &Value, key: &[u8]) -> bool {
    let Some(integrity) = request.get("request_integrity").and_then(Value::as_object) else {
        return false;
    };
    if integrity.get("version").and_then(Value::as_i64) != Some(ARTIFACT_VERSION)
        || integrity.get("signer").and_then(Value::as_str) != Some(SIGNER)
    {
        return false;
    }
    let Some(signature) = integrity.get("signature").and_then(Value::as_str) else {
        return false;
    };
    if signature.len() != 64 {
        return false;
    }
    let Ok(payload) = approval_request_payload(request) else {
        return false;
    };
    let Ok(body) = artifact_canonical_json(&payload) else {
        return false;
    };
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    if !string_eq(
        integrity
            .get("payload_sha256")
            .and_then(Value::as_str)
            .unwrap_or(""),
        &digest,
    ) {
        return false;
    }
    let Ok(expected) = hmac_hex(key, body.as_bytes()) else {
        return false;
    };
    string_eq(signature, &expected)
}

pub fn parse_signing_key(blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, ApprovalError> {
    let text = std::str::from_utf8(blob)
        .map_err(|_| ApprovalError::from("approval signing key is invalid"))?
        .trim();
    let normalized = Zeroizing::new(
        text.bytes()
            .filter_map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => Some(byte as char),
                b'-' => Some('+'),
                b'_' => Some('/'),
                _ => None,
            })
            .collect::<String>(),
    );
    let decoded = Zeroizing::new(
        STANDARD
            .decode(normalized.as_bytes())
            .map_err(|_| ApprovalError::from("approval signing key is invalid"))?,
    );
    if decoded.len() != 32 {
        return Err("approval signing key is invalid".into());
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn hmac_hex(key: &[u8], body: &[u8]) -> Result<String, ApprovalError> {
    if key.len() != 32 {
        return Err("HMAC key must be 32 bytes".into());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key sizes");
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn string_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

use sha2::Digest;
