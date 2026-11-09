use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use kv_crypto::Zeroizing;

use crate::{
    ApprovalError,
    canonical::canonical_json,
    owner::{OwnerSeed, SIGNER},
    wire::frame,
};

pub const PAUSE_ANSWER_LABEL: &[u8] = b"kv-owner-pause-answer-v1";
pub const PAUSE_RIGHT_LABEL: &[u8] = b"kv-owner-pause-right-v1";
pub const PAUSE_JOB_LABEL: &[u8] = b"kv-pause-job-v1";
pub const PAUSE_RIGHT_KIND: &str = "pause-right-v1";
pub const PAUSE_ANSWER_SEAL_LABEL: &[u8] = b"kv-pause-answer-key-seal-v1";
pub const PAUSE_ANSWER_PROOF_LABEL: &str = "kv-pause-answer-proof-v1";

pub struct PauseContext<'a> {
    pub protected: bool,
    pub owner_public_key: &'a [u8],
}

pub fn pause_answer_message(payload: &Value) -> Result<Vec<u8>, ApprovalError> {
    labeled_message(PAUSE_ANSWER_LABEL, payload)
}

pub fn pause_answer_end(facts: &Value, add_seconds: i64, now: i64) -> Option<i64> {
    if add_seconds == 0 {
        return None;
    }
    let expires = facts
        .get("pass_expires_at_epoch")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    Some(now.max(expires) + add_seconds)
}

pub fn attach_pause_answer(
    facts: &Value,
    seed: &OwnerSeed,
    decision: &str,
    add_calls: i64,
    add_seconds: i64,
    ends_at_epoch: Option<i64>,
) -> Result<Value, ApprovalError> {
    let mut payload = facts
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("pause facts must be an object"))?;
    for key in ["decision", "add_calls", "add_seconds", "ends_at_epoch"] {
        if payload.contains_key(key) {
            return Err("the pause facts already hold an answer".into());
        }
    }
    let end = ends_at_epoch.or_else(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        pause_answer_end(facts, add_seconds, now)
    });
    payload.insert("decision".to_owned(), Value::String(decision.to_owned()));
    payload.insert("add_calls".to_owned(), Value::from(add_calls));
    payload.insert("add_seconds".to_owned(), Value::from(add_seconds));
    payload.insert(
        "ends_at_epoch".to_owned(),
        end.map(Value::from).unwrap_or(Value::Null),
    );
    let payload = Value::Object(payload);
    let signature = SigningKey::from_bytes(seed.as_bytes())
        .sign(&pause_answer_message(&payload)?)
        .to_bytes();
    Ok(signed_artifact(&payload, &signature))
}

pub fn verified_pause_answer(ctx: &PauseContext<'_>, artifact: &Value) -> Option<Value> {
    verify_signed_artifact(ctx, artifact, PAUSE_ANSWER_LABEL, |payload| {
        payload.get("signer").and_then(Value::as_str) == Some(SIGNER)
    })
}

pub fn pause_right_message(payload: &Value) -> Result<Vec<u8>, ApprovalError> {
    labeled_message(PAUSE_RIGHT_LABEL, payload)
}

pub fn attach_pause_right(payload: &Value, seed: &OwnerSeed) -> Result<Value, ApprovalError> {
    let message = pause_right_message(payload)?;
    let signature = SigningKey::from_bytes(seed.as_bytes())
        .sign(&message)
        .to_bytes();
    Ok(signed_artifact(payload, &signature))
}

pub fn verified_pause_right(ctx: &PauseContext<'_>, artifact: &Value) -> Option<Value> {
    verify_signed_artifact(ctx, artifact, PAUSE_RIGHT_LABEL, |payload| {
        payload.as_object().is_some_and(|object| {
            object.len() == 9
                && [
                    "signer",
                    "kind",
                    "local_approval_id",
                    "location",
                    "owner_key_id",
                    "right_public_key",
                    "session_nonce",
                    "holder",
                    "expires_at_epoch",
                ]
                .iter()
                .all(|key| object.contains_key(*key))
                && object.get("signer").and_then(Value::as_str) == Some(SIGNER)
        })
    })
}

pub fn pause_job_message(fields: &Value) -> Result<Vec<u8>, ApprovalError> {
    let object = fields
        .as_object()
        .ok_or_else(|| ApprovalError::from("a pause request has exactly its own fields"))?;
    let expected = ["job_id", "nonce", "right", "session_nonce", "signed_at"];
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err("a pause request has exactly its own fields".into());
    }
    labeled_message(PAUSE_JOB_LABEL, fields)
}

pub fn seal_pause_answer_key(
    daemon_key: &[u8],
    answer_key: &[u8],
    right_public_key: &str,
    session_nonce: &str,
) -> Result<String, ApprovalError> {
    let aad = aad(right_public_key, session_nonce)?;
    let seal_key = derive_seal_key(daemon_key);
    let cipher = Aes256Gcm::new_from_slice(seal_key.as_ref())
        .map_err(|_| ApprovalError::from("invalid daemon key"))?;
    let mut nonce_bytes = [0_u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|error| error.to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: answer_key,
                aad: &aad,
            },
        )
        .map_err(|_| ApprovalError::from("could not seal pause answer key"))?;
    let mut sealed = nonce_bytes.to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(hex::encode(sealed))
}

pub fn open_pause_answer_key(
    daemon_key: &[u8],
    sealed: &str,
    right_public_key: &str,
    session_nonce: &str,
) -> Option<Zeroizing<Vec<u8>>> {
    let raw = decode_hex(sealed)?;
    if raw.len() != 12 + 32 + 16 {
        return None;
    }
    let aad = aad(right_public_key, session_nonce).ok()?;
    let seal_key = derive_seal_key(daemon_key);
    let cipher = Aes256Gcm::new_from_slice(seal_key.as_ref()).ok()?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&raw[..12]),
            Payload {
                msg: &raw[12..],
                aad: &aad,
            },
        )
        .ok()?;
    Some(Zeroizing::new(plaintext))
}

fn derive_seal_key(daemon_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(daemon_key)
        .expect("HMAC accepts arbitrary key sizes");
    mac.update(PAUSE_ANSWER_SEAL_LABEL);
    let digest = mac.finalize().into_bytes();
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&digest);
    key
}

fn aad(right_public_key: &str, session_nonce: &str) -> Result<Vec<u8>, ApprovalError> {
    let text = format!("{right_public_key}\n{session_nonce}");
    if !text.is_ascii() {
        return Err("pause key binding must be ASCII".into());
    }
    Ok(text.into_bytes())
}

pub fn pause_answer_proof(
    answer_key: &[u8],
    kind: &str,
    fields: &Value,
) -> Result<String, ApprovalError> {
    let message = canonical_json(&serde_json::json!({
        "kind": kind,
        "label": PAUSE_ANSWER_PROOF_LABEL,
        "fields": fields,
    }))?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(answer_key)
        .expect("HMAC accepts arbitrary key sizes");
    mac.update(message.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn snapshot_proof_fields(nonce: &str, reply: &Value) -> Result<Value, ApprovalError> {
    let mut body = reply
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("snapshot reply must be an object"))?;
    body.remove("proof");
    let canonical = canonical_json(&Value::Object(body))?;
    let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    Ok(serde_json::json!({"nonce": nonce, "digest": digest}))
}

pub fn pause_answer_proven(answer_key: &[u8], kind: &str, fields: &Value, proof: &str) -> bool {
    if answer_key.len() < 32 {
        return false;
    }
    let Ok(message) = canonical_json(&serde_json::json!({
        "kind": kind,
        "label": PAUSE_ANSWER_PROOF_LABEL,
        "fields": fields,
    })) else {
        return false;
    };
    let Some(proof) = decode_hex(proof) else {
        return false;
    };
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(answer_key) else {
        return false;
    };
    mac.update(message.as_bytes());
    mac.verify_slice(&proof).is_ok()
}

fn verify_signed_artifact(
    ctx: &PauseContext<'_>,
    artifact: &Value,
    label: &[u8],
    payload_check: impl FnOnce(&Value) -> bool,
) -> Option<Value> {
    if !ctx.protected {
        return None;
    }
    let artifact = artifact.as_object()?;
    if artifact.len() != 4
        || artifact.get("version")?.as_i64()? != 1
        || artifact.get("signer")?.as_str()? != SIGNER
    {
        return None;
    }
    let payload = artifact.get("payload")?;
    if !payload.is_object() || !payload_check(payload) {
        return None;
    }
    let signature = decode_hex(artifact.get("signature")?.as_str()?)?;
    let signature = Signature::from_slice(&signature).ok()?;
    let public_key: [u8; 32] = ctx.owner_public_key.try_into().ok()?;
    let public_key = VerifyingKey::from_bytes(&public_key).ok()?;
    public_key
        .verify(&labeled_message(label, payload).ok()?, &signature)
        .ok()?;
    Some(payload.clone())
}

fn signed_artifact(payload: &Value, signature: &[u8; 64]) -> Value {
    serde_json::json!({
        "version": 1,
        "signer": SIGNER,
        "payload": payload,
        "signature": hex::encode(signature),
    })
}

fn labeled_message(label: &[u8], payload: &Value) -> Result<Vec<u8>, ApprovalError> {
    let canonical = canonical_json(payload)?;
    Ok([frame(label), frame(canonical.as_bytes())].concat())
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    hex::decode(compact).ok()
}

pub fn fields_object(fields: &Value) -> Result<Map<String, Value>, ApprovalError> {
    fields
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("fields must be an object"))
}
