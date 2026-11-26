//! Python `owner_approval.PermitSigningContext`: the owner's review of a one-call
//! permit over the authenticated owner channel. Only a protected session with the
//! owner key signs anything; every answer from the service is MAC-checked against
//! the challenge it was asked with.

use kv_approvals::canonical::canonical_json;
use kv_approvals::owner::OwnerSeed;
use kv_approvals::permit_review::FACT_KEYS;
use kv_approvals::verify::payload_digest;
use kv_proto::{Channel, ChannelError, check_answer};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const UNPROTECTED: &str =
    "the daemon says this session is UNPROTECTED; nothing is signed (restart it with 'kv unlock')";

#[derive(Debug)]
pub enum SigningError {
    /// `SigningRefused`: nothing was signed.
    Refused(String),
    /// `RegistrationUnconfirmed`: a registration was sent and no proven answer came back.
    Unconfirmed(String),
}

impl SigningError {
    pub fn message(&self) -> &str {
        match self {
            Self::Refused(m) | Self::Unconfirmed(m) => m,
        }
    }
}

fn refused(message: impl Into<String>) -> SigningError {
    SigningError::Refused(message.into())
}

/// The service's authenticated record of a pending permit request.
pub struct PermitRecord {
    pub facts: Value,
    pub body_text: String,
    pub caller_headers: Map<String, Value>,
    pub requester: Option<Map<String, Value>>,
}

pub struct PermitSigningContext {
    root: PathBuf,
    identity: kv_crypto::Identity,
    pub channel: Channel,
}

fn nonce() -> Result<Vec<u8>, SigningError> {
    let mut challenge = vec![0_u8; kv_approvals::wire::NONCE_LEN];
    getrandom::getrandom(&mut challenge)
        .map_err(|_| refused("operating-system randomness unavailable"))?;
    Ok(challenge)
}

impl PermitSigningContext {
    /// `begin`: the unwrapped identity opens the owner channel; an unprotected session refuses.
    pub fn begin(root: &Path, identity: kv_crypto::Identity) -> Result<Self, SigningError> {
        let mut challenge = vec![0_u8; kv_approvals::wire::NONCE_LEN];
        getrandom::getrandom(&mut challenge)
            .map_err(|_| refused("operating-system randomness unavailable"))?;
        let mut fields = Map::new();
        fields.insert("challenge".into(), json!(hex::encode(&challenge)));
        fields.insert("providers".into(), json!(false));
        let answer = kv_proto::agent_request_framed(root, "owner_channel", &fields)
            .map_err(|_| refused("no daemon answered; start it with 'kv unlock' and try again"))?;
        let channel = match kv_proto::check_channel(&answer, &challenge, &identity) {
            Ok(channel) => channel,
            Err(ChannelError::Message(m)) => return Err(refused(m)),
            Err(ChannelError::DaemonRefused(r)) => return Err(refused(r.to_string())),
        };
        if !channel.protected {
            return Err(refused(UNPROTECTED));
        }
        Ok(Self {
            root: root.to_path_buf(),
            identity,
            channel,
        })
    }

    fn send(
        &self,
        cmd: &str,
        mut fields: Map<String, Value>,
    ) -> Result<(Value, Vec<u8>), SigningError> {
        let challenge = nonce()?;
        fields.insert("challenge".into(), json!(hex::encode(&challenge)));
        let answer = kv_proto::agent_request_framed(&self.root, cmd, &fields)
            .map_err(|e| refused(e.to_string()))?;
        Ok((answer, challenge))
    }

    /// `permit_record`: the facts the service will enforce, proven to be this session's
    /// and this request's, with the body and headers the owner is shown.
    pub fn permit_record(&self, request_id: &str) -> Result<PermitRecord, SigningError> {
        let differs = || refused("the call differs from the service's authenticated facts");
        let unverified = || refused("the permit request could not be verified");
        let mut fields = Map::new();
        fields.insert("request_id".into(), json!(request_id));
        let (answer, challenge) = self.send("owner_permit_request", fields)?;
        let fields = check_answer(&answer, &challenge, &self.identity, "permit-request-v1")
            .map_err(|_| unverified())?;
        let text = |key: &str| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(unverified)
        };
        let facts: Value = serde_json::from_str(text("facts_json")?).map_err(|_| unverified())?;
        let headers: Map<String, Value> =
            serde_json::from_str(text("caller_headers_json")?).map_err(|_| unverified())?;
        let body_text = text("body_text")?.to_owned();
        let requester: Value =
            serde_json::from_str(text("requester_json")?).map_err(|_| unverified())?;
        let Some(object) = facts.as_object() else {
            return Err(unverified());
        };
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected: Vec<&str> = FACT_KEYS.to_vec();
        expected.sort_unstable();
        let mut pairs: Vec<Value> = headers
            .iter()
            .map(|(k, v)| json!([k.to_lowercase(), v]))
            .collect();
        pairs.sort_by_key(|pair| pair.to_string());
        let headers_digest = canonical_json(&Value::Array(pairs))
            .map(|text| hex::encode(Sha256::digest(text.as_bytes())))
            .map_err(|_| unverified())?;
        let body = body_text.as_bytes();
        let fact = |key: &str| object.get(key).and_then(Value::as_str).unwrap_or("");
        let nonce_hex = hex::encode(&self.channel.session_nonce);
        if keys != expected
            || fields.get("session_nonce").and_then(Value::as_str) != Some(nonce_hex.as_str())
            || fields.get("request_id").and_then(Value::as_str) != Some(request_id)
            || fact("request_id") != request_id
            || fact("session_nonce") != nonce_hex
            || fact("location") != hex::encode(&self.identity.location)
            || fact("local_approval_id") != hex::encode(self.identity.local_approval_id)
            || fact("owner_key_id") != self.channel.owner_key_id
            || fact("signer") != kv_approvals::permit::SIGNER
            || fact("body_sha256") != hex::encode(Sha256::digest(body))
            || object.get("body_length").and_then(Value::as_i64) != Some(body.len() as i64)
            || fact("caller_headers_sha256") != headers_digest
        {
            return Err(differs());
        }
        Ok(PermitRecord {
            facts,
            body_text,
            caller_headers: headers,
            requester: requester.as_object().cloned(),
        })
    }

    /// `sign_permit`: the owner's signature over the service's facts.
    pub fn sign_permit(&self, record: &PermitRecord) -> Result<Value, SigningError> {
        let seed = OwnerSeed::new(*self.identity.owner_seed);
        kv_approvals::permit::attach_permit_approval(&record.facts, &seed)
            .map_err(|e| refused(e.to_string()))
    }

    /// `register_permit`: two attempts; only an ack naming this exact permit counts.
    /// Returns the service's status (`registered` or `already-registered`).
    pub fn register_permit(&self, permit: &Value) -> Result<String, SigningError> {
        let payload = &permit["payload"];
        let expected = (
            payload["permit_id"].as_str().unwrap_or(""),
            payload["request_id"].as_str().unwrap_or(""),
            payload_digest(payload).unwrap_or_default(),
        );
        let mut reason = String::from("the service did not confirm this exact permit");
        for _ in 0..2 {
            let mut fields = Map::new();
            fields.insert("permit".into(), permit.clone());
            let Ok((answer, challenge)) = self.send("owner_permit_register", fields) else {
                continue;
            };
            match check_answer(
                &answer,
                &challenge,
                &self.identity,
                "permit-register-ack-v1",
            ) {
                Ok(fields) => {
                    let text = |key: &str| fields.get(key).and_then(Value::as_str).unwrap_or("");
                    if text("session_nonce") == hex::encode(&self.channel.session_nonce)
                        && (
                            text("permit_id"),
                            text("request_id"),
                            text("payload_digest").to_owned(),
                        ) == expected
                    {
                        return Ok(text("status").to_owned());
                    }
                }
                Err(error) => reason = error.to_string(),
            }
        }
        Err(SigningError::Unconfirmed(reason))
    }
}
