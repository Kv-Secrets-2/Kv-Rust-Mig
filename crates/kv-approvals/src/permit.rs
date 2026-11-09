use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value};

use crate::{ApprovalError, canonical::canonical_json, owner::OwnerSeed, wire::frame};

pub const SIGNER: &str = "owner-ed25519-v1";
pub const PERMIT_LABEL: &[u8] = b"kv-owner-permit-v1";

pub fn permit_message(payload: &Value) -> Result<Vec<u8>, ApprovalError> {
    let canonical = canonical_json(payload)?;
    Ok([frame(PERMIT_LABEL), frame(canonical.as_bytes())].concat())
}

pub fn attach_permit_approval(payload: &Value, seed: &OwnerSeed) -> Result<Value, ApprovalError> {
    let facts = payload.clone();
    if facts.get("signer").and_then(Value::as_str) != Some(SIGNER) {
        return Err("unsupported permit signer".into());
    }
    let message = permit_message(&facts)?;
    let signature = SigningKey::from_bytes(seed.as_bytes())
        .sign(&message)
        .to_bytes();
    Ok(serde_json::json!({
        "version": 1,
        "signer": SIGNER,
        "payload": facts,
        "signature": hex::encode(signature),
    }))
}

pub fn verified_permit_payload(
    protected: bool,
    owner_public_key: &[u8],
    artifact: &Value,
) -> Option<Value> {
    (|| {
        if !protected {
            return None;
        }
        let artifact = artifact.as_object()?;
        if artifact.len() != 4
            || artifact.get("version")?.as_i64()? != 1
            || artifact.get("signer")?.as_str()? != SIGNER
        {
            return None;
        }
        let facts = artifact.get("payload")?.as_object()?;
        let signature_text = artifact.get("signature")?.as_str()?;
        if facts.get("signer")?.as_str()? != SIGNER {
            return None;
        }
        let signature = Signature::from_slice(&decode_hex(signature_text)?).ok()?;
        let public_key: [u8; 32] = owner_public_key.try_into().ok()?;
        let public_key = VerifyingKey::from_bytes(&public_key).ok()?;
        let payload = Value::Object(facts.clone());
        public_key
            .verify(&permit_message(&payload).ok()?, &signature)
            .ok()?;
        Some(payload)
    })()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    hex::decode(compact).ok()
}

pub fn unsigned_payload(payload: &Value) -> Result<Map<String, Value>, ApprovalError> {
    payload
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("payload must be an object"))
}
