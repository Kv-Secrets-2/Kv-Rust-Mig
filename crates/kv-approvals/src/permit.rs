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
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    let mut offset = 0;
    while offset < bytes.len() {
        // bytes.fromhex accepts ASCII whitespace between whole bytes, never
        // between their two nibbles. Its set includes vertical tab.
        while offset < bytes.len()
            && matches!(bytes[offset], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
        {
            offset += 1;
        }
        if offset == bytes.len() {
            break;
        }
        let high = nibble(*bytes.get(offset)?)?;
        let low = nibble(*bytes.get(offset + 1)?)?;
        output.push((high << 4) | low);
        offset += 2;
    }
    Some(output)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn unsigned_payload(payload: &Value) -> Result<Map<String, Value>, ApprovalError> {
    payload
        .as_object()
        .cloned()
        .ok_or_else(|| ApprovalError::from("payload must be an object"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_hex_whitespace_is_only_allowed_between_complete_bytes() {
        let seed = OwnerSeed::new([37; 32]);
        let public = crate::owner::owner_public_key(&seed);
        let artifact =
            attach_permit_approval(&serde_json::json!({"signer":SIGNER}), &seed).unwrap();
        let text = artifact["signature"].as_str().unwrap();
        for space in [" ", "\t", "\r", "\n", "\u{000b}", "\u{000c}"] {
            let mut changed = artifact.clone();
            changed["signature"] = Value::String(format!("{}{}{}", &text[..2], space, &text[2..]));
            assert!(
                verified_permit_payload(true, &public, &changed).is_some(),
                "{space:?}"
            );
            changed["signature"] = Value::String(format!("{}{}{}", &text[..1], space, &text[1..]));
            assert!(
                verified_permit_payload(true, &public, &changed).is_none(),
                "{space:?}"
            );
        }
        let mut changed = artifact;
        let signature = changed["signature"].as_str().unwrap().to_owned();
        changed["signature"] =
            Value::String(format!("{}\u{00a0}{}", &signature[..2], &signature[2..]));
        assert!(verified_permit_payload(true, &public, &changed).is_none());
    }
}
