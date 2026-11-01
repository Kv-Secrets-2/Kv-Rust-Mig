use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use kv_crypto::Zeroizing;

use crate::{ApprovalError, artifacts::grant_payload, canonical::canonical_json, wire::frame};

pub const SIGNER: &str = "owner-ed25519-v1";
pub const OWNER_ARTIFACT_VERSION: i64 = 1;
pub const SIGNING_LABEL: &[u8] = b"kv-owner-grant-v1";

pub struct OwnerSeed(Zeroizing<[u8; 32]>);

impl OwnerSeed {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }

    pub fn from_slice(seed: &[u8]) -> Result<Self, ApprovalError> {
        if seed.len() != 32 {
            return Err("owner seed must be 32 bytes".into());
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        secret.copy_from_slice(seed);
        Ok(Self(secret))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct OwnerGrantFields<'a> {
    pub request_id: &'a str,
    pub request_digest: &'a str,
    pub request_expires_at_epoch: Value,
    pub local_approval_id: &'a [u8],
    pub location: &'a [u8],
    pub owner_key_id: &'a str,
    pub environment: &'a str,
    pub network: Value,
    pub network_reason: Value,
    pub max_runs: Value,
    pub calls_per_run: Value,
    pub provider_digests: &'a Value,
    pub session_nonce: &'a [u8],
}

pub fn owner_public_key(seed: &OwnerSeed) -> [u8; 32] {
    SigningKey::from_bytes(seed.as_bytes())
        .verifying_key()
        .to_bytes()
}

pub fn owner_key_id(public_key: &[u8], local_approval_id: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(public_key);
    digest.update(local_approval_id);
    hex::encode(&digest.finalize()[..16])
}

pub fn owner_grant_payload(
    grant: &Value,
    artifact_id: &str,
    fields: &OwnerGrantFields<'_>,
) -> Result<Value, ApprovalError> {
    if !fields.network.is_boolean() {
        return Err("network must be true or false".into());
    }
    if !fields.max_runs.is_null()
        && (!fields.max_runs.is_i64() || fields.max_runs.as_i64().unwrap_or_default() < 1)
    {
        return Err("max_runs must be a positive integer".into());
    }
    if !fields.provider_digests.is_object() {
        return Err("provider_digests must be an object".into());
    }
    let mut payload = grant_payload(grant, artifact_id)?
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("grant payload must be an object"))?;
    payload.insert("signer".to_owned(), Value::String(SIGNER.to_owned()));
    payload.insert(
        "request_id".to_owned(),
        Value::String(fields.request_id.to_owned()),
    );
    payload.insert(
        "request_digest".to_owned(),
        Value::String(fields.request_digest.to_owned()),
    );
    payload.insert(
        "request_expires_at_epoch".to_owned(),
        fields.request_expires_at_epoch.clone(),
    );
    payload.insert(
        "local_approval_id".to_owned(),
        Value::String(hex::encode(fields.local_approval_id)),
    );
    payload.insert(
        "location".to_owned(),
        Value::String(hex::encode(fields.location)),
    );
    payload.insert(
        "owner_key_id".to_owned(),
        Value::String(fields.owner_key_id.to_owned()),
    );
    payload.insert(
        "environment".to_owned(),
        Value::String(fields.environment.to_owned()),
    );
    payload.insert("network".to_owned(), fields.network.clone());
    payload.insert("network_reason".to_owned(), fields.network_reason.clone());
    payload.insert("max_runs".to_owned(), fields.max_runs.clone());
    payload.insert("calls_per_run".to_owned(), fields.calls_per_run.clone());
    let mut providers = fields
        .provider_digests
        .as_object()
        .expect("validated object")
        .clone();
    providers.sort_keys();
    payload.insert("provider_digests".to_owned(), Value::Object(providers));
    payload.insert(
        "session_nonce".to_owned(),
        Value::String(hex::encode(fields.session_nonce)),
    );
    let payload = Value::Object(payload);
    canonical_json(&payload)?;
    Ok(payload)
}

pub fn owner_grant_message(payload: &Value) -> Result<Vec<u8>, ApprovalError> {
    let canonical = canonical_json(payload)?;
    Ok([frame(SIGNING_LABEL), frame(canonical.as_bytes())].concat())
}

pub fn sign_payload(seed: &OwnerSeed, payload: &Value) -> Result<[u8; 64], ApprovalError> {
    let message = owner_grant_message(payload)?;
    Ok(SigningKey::from_bytes(seed.as_bytes())
        .sign(&message)
        .to_bytes())
}

pub fn attach_owner_approval(
    grant: &Value,
    seed: &OwnerSeed,
    fields: &OwnerGrantFields<'_>,
) -> Result<Value, ApprovalError> {
    let mut signed = grant
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("grant must be an object"))?;
    let mut random = [0_u8; 12];
    getrandom::getrandom(&mut random).map_err(|error| error.to_string())?;
    let artifact_id = format!("owner_approval_{}", hex::encode(random));
    let payload = owner_grant_payload(grant, &artifact_id, fields)?;
    let signature = sign_payload(seed, &payload)?;
    signed.insert(
        "owner_approval".to_owned(),
        serde_json::json!({
            "version": OWNER_ARTIFACT_VERSION,
            "signer": SIGNER,
            "payload": payload,
            "signature": hex::encode(signature),
        }),
    );
    Ok(Value::Object(signed))
}

pub fn verified_owner_payload(owner_public_key: &[u8], grant: &Value) -> Option<Value> {
    (|| {
        let grant_object = grant.as_object()?;
        if grant_object.contains_key("post_rule") {
            return None;
        }
        let approval = grant_object.get("owner_approval")?.as_object()?;
        if approval.get("version")?.as_i64()? != OWNER_ARTIFACT_VERSION
            || approval.get("signer")?.as_str()? != SIGNER
        {
            return None;
        }
        let payload = approval.get("payload")?.as_object()?;
        let signature_text = approval.get("signature")?.as_str()?;
        let signature_bytes = decode_python_hex(signature_text)?;
        let signature = Signature::from_slice(&signature_bytes).ok()?;
        let public_bytes: [u8; 32] = owner_public_key.try_into().ok()?;
        let public = VerifyingKey::from_bytes(&public_bytes).ok()?;
        let payload_value = Value::Object(payload.clone());
        let message = owner_grant_message(&payload_value).ok()?;
        public.verify(&message, &signature).ok()?;
        let artifact_id = payload.get("artifact_id")?.as_str()?;
        if !artifact_id.starts_with("owner_approval_") {
            return None;
        }
        let own = grant_payload(grant, artifact_id).ok()?;
        let own = own.as_object()?;
        for (key, value) in own {
            if payload.get(key) != Some(value) {
                return None;
            }
        }
        for key in [
            "max_calls",
            "calls_per_service",
            "usage_mode",
            "post_wallet",
            "when_spent",
            "owner_wait_seconds",
        ] {
            if payload.get(key).is_some_and(|value| !value.is_null()) && !own.contains_key(key) {
                return None;
            }
        }
        if payload.get("usage_mode").and_then(Value::as_str) == Some("reusable")
            && own.get("max_runs") != payload.get("max_runs")
        {
            return None;
        }
        Some(payload_value)
    })()
}

fn decode_python_hex(text: &str) -> Option<Vec<u8>> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    hex::decode(compact).ok()
}

pub fn owner_payload_object(payload: &Value) -> Result<Map<String, Value>, ApprovalError> {
    payload
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("payload must be an object"))
}
