//! Signed-grant verification shared by admission and the capability broker
//! (`kv/approval_verify.py` core): the verifier context is `SessionBinding`.
//!
//! The runtime ledger (`GrantRegistry`: admissions, paused jobs, saved passes)
//! lives with the daemon's run command.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;
use crate::owner::{SIGNER, verified_owner_payload};
use crate::permit_session::{NO_PASSPHRASE_REFUSAL, SessionBinding};
use crate::wire::provider_digest;

/// Largest count kv stores or sums (`kv/limits.py`): exact in every JSON reader.
pub const MAX_COUNT: i64 = (1 << 53) - 1;
pub const MAX_WALLET_ENTRIES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRefused {
    message: String,
    code: &'static str,
}

impl AdmissionRefused {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: "refused",
        }
    }

    pub fn with_code(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            message: message.into(),
            code,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn code(&self) -> &str {
        self.code
    }
}

impl fmt::Display for AdmissionRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AdmissionRefused {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunFacts {
    pub env_name: Option<String>,
    pub secret_names: Vec<String>,
    pub capability_names: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletEntry {
    pub provider: String,
    pub rule_id: String,
    pub rule_digest: String,
    pub calls: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub grant_id: String,
    pub artifact_id: String,
    pub request_id: String,
    pub payload_digest: String,
    pub session_nonce: Option<String>,
    pub environment: Option<String>,
    pub secret_names: Vec<Value>,
    pub capability_names: Vec<Value>,
    pub network: Option<bool>,
    pub provider_digests: Vec<(String, Value)>,
    pub protected: bool,
    pub post_wallet: Option<Vec<WalletEntry>>,
    pub when_spent: Option<String>,
    pub owner_wait_seconds: Option<i64>,
}

pub fn refuse_unprotected(binding: &SessionBinding) -> Result<(), AdmissionRefused> {
    if binding.protected {
        Ok(())
    } else {
        Err(AdmissionRefused::with_code(
            NO_PASSPHRASE_REFUSAL,
            "no_passphrase",
        ))
    }
}

pub fn payload_digest(payload: &Value) -> Option<String> {
    let text = canonical_json(payload).ok()?;
    Some(hex::encode(Sha256::digest(text.as_bytes())))
}

fn plain_name(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    let rest = chars.as_str();
    rest.len() <= 63
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn hex_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn wallet_entry_key(provider: &str, rule_id: &str) -> String {
    format!("api:{provider}/{rule_id}")
}

pub fn split_wallet_entry_key(key: &Value) -> Option<(String, String)> {
    let key = key.as_str()?.strip_prefix("api:")?;
    let (provider, rule_id) = key.split_once('/')?;
    (plain_name(provider) && plain_name(rule_id)).then(|| (provider.to_owned(), rule_id.to_owned()))
}

fn invalid_wallet() -> AdmissionRefused {
    AdmissionRefused::new("invalid POST wallet scope")
}

/// Validate a signed `post_wallet` scope: 1..=16 complete entries, sorted and
/// unique by `(provider, rule_id)`.
pub fn post_wallet_binding(
    scope: Option<&Value>,
) -> Result<Option<Vec<WalletEntry>>, AdmissionRefused> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    if scope.is_null() {
        return Ok(None);
    }
    let items = scope.as_array().ok_or_else(invalid_wallet)?;
    if items.is_empty() || items.len() > MAX_WALLET_ENTRIES {
        return Err(invalid_wallet());
    }
    let mut bound = Vec::with_capacity(items.len());
    for entry in items {
        let entry = entry.as_object().ok_or_else(invalid_wallet)?;
        if entry.len() != 4
            || !["provider", "rule_id", "rule_digest", "calls"]
                .iter()
                .all(|k| entry.contains_key(*k))
        {
            return Err(invalid_wallet());
        }
        let provider = entry["provider"].as_str().filter(|s| plain_name(s));
        let rule_id = entry["rule_id"].as_str().filter(|s| plain_name(s));
        let digest = entry["rule_digest"].as_str().filter(|s| hex_digest(s));
        let calls = entry["calls"]
            .as_i64()
            .filter(|c| (1..=MAX_COUNT).contains(c));
        match (provider, rule_id, digest, calls) {
            (Some(provider), Some(rule_id), Some(digest), Some(calls)) => {
                bound.push(WalletEntry {
                    provider: provider.to_owned(),
                    rule_id: rule_id.to_owned(),
                    rule_digest: digest.to_owned(),
                    calls,
                });
            }
            _ => return Err(invalid_wallet()),
        }
    }
    let sorted = bound
        .windows(2)
        .all(|pair| (&pair[0].provider, &pair[0].rule_id) < (&pair[1].provider, &pair[1].rule_id));
    if !sorted {
        return Err(invalid_wallet());
    }
    Ok(Some(bound))
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn wallet_agrees(
    payload: &Map<String, Value>,
    wallet: &[WalletEntry],
) -> Result<(), AdmissionRefused> {
    let mut providers: Vec<&str> = wallet.iter().map(|e| e.provider.as_str()).collect();
    providers.sort_unstable();
    providers.dedup();
    let expected: Vec<Value> = providers
        .iter()
        .map(|p| Value::String(format!("api:{p}")))
        .collect();
    let total: i64 = wallet.iter().map(|e| e.calls).sum();
    let names_ok = payload
        .get("capability_names")
        .and_then(Value::as_array)
        .is_some_and(|names| *names == expected);
    let max_calls = payload.get("max_calls").and_then(Value::as_i64);
    if !names_ok
        || truthy(payload.get("secret_names"))
        || payload
            .get("calls_per_service")
            .is_some_and(|v| !v.is_null())
        || max_calls != Some(total)
        || total > MAX_COUNT
    {
        return Err(AdmissionRefused::new(
            "this approval's POST wallet does not match its services and total",
        ));
    }
    Ok(())
}

/// The owner-signed payload of `grant`, if it was signed for this session.
pub fn signed_payload(binding: &SessionBinding, grant: &Value) -> Option<Map<String, Value>> {
    let public_key = binding.owner_public_key.as_ref()?;
    let payload = verified_owner_payload(public_key, grant)?;
    let payload = payload.as_object()?.clone();
    if payload.get("signer").and_then(Value::as_str) != Some(SIGNER) {
        return None;
    }
    let expected = [
        ("local_approval_id", hex::encode(&binding.local_approval_id)),
        ("location", hex::encode(&binding.location)),
        ("owner_key_id", binding.owner_key_id.clone()),
        ("session_nonce", hex::encode(binding.session_nonce)),
    ];
    for (key, value) in expected {
        if payload.get(key).and_then(Value::as_str) != Some(value.as_str()) {
            return None;
        }
    }
    match payload.get("request_id") {
        Some(Value::String(id)) if !id.is_empty() => Some(payload),
        _ => None,
    }
}

/// Why `payload` does not cover `run` against the current provider snapshot.
pub fn run_mismatch(
    payload: &Map<String, Value>,
    run: &RunFacts,
    provider_snapshot: &BTreeMap<String, Value>,
) -> Option<&'static str> {
    let environment = payload.get("environment").unwrap_or(&Value::Null);
    if environment.as_str() != Some("*") {
        match run.env_name.as_deref() {
            Some(name) if !name.is_empty() && environment.as_str() == Some(name) => {}
            _ => return Some("environment"),
        }
    }
    let Some(digests) = payload.get("provider_digests").and_then(Value::as_object) else {
        return Some("provider");
    };
    for capability in &run.capability_names {
        let Some(name) = capability.as_str().and_then(|c| c.strip_prefix("api:")) else {
            return Some("provider");
        };
        let Some(definition) = provider_snapshot.get(name) else {
            return Some("provider");
        };
        let Ok(current) = provider_digest(definition) else {
            return Some("provider");
        };
        if digests.get(name).and_then(Value::as_str) != Some(current.as_str()) {
            return Some("provider");
        }
    }
    None
}

fn required_str(payload: &Map<String, Value>, key: &str) -> Result<String, AdmissionRefused> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AdmissionRefused::new(format!("grant payload lacks {key}")))
}

/// Build the verified view of an owner-signed payload (`_from_payload`).
pub fn from_payload(
    payload: &Map<String, Value>,
    digest: &str,
) -> Result<VerifiedGrant, AdmissionRefused> {
    if payload.contains_key("post_rule") {
        return Err(AdmissionRefused::new(
            "this approval is in the old one-rule POST form, which kv no longer accepts; approve it again",
        ));
    }
    let wallet = post_wallet_binding(payload.get("post_wallet"))?;
    if let Some(wallet) = &wallet {
        wallet_agrees(payload, wallet)?;
    }
    let list = |key: &str| -> Vec<Value> {
        payload
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let provider_digests: Vec<(String, Value)> = payload
        .get("provider_digests")
        .and_then(Value::as_object)
        .map(|m| {
            let mut pairs: Vec<(String, Value)> =
                m.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            pairs
        })
        .unwrap_or_default();
    let when_spent = payload
        .get("when_spent")
        .and_then(Value::as_str)
        .filter(|w| matches!(*w, "pause" | "end"))
        .map(str::to_owned);
    let owner_wait_seconds = payload
        .get("owner_wait_seconds")
        .and_then(Value::as_i64)
        .filter(|s| *s > 0);
    Ok(VerifiedGrant {
        grant_id: required_str(payload, "grant_id")?,
        artifact_id: required_str(payload, "artifact_id")?,
        request_id: required_str(payload, "request_id")?,
        payload_digest: digest.to_owned(),
        session_nonce: payload
            .get("session_nonce")
            .and_then(Value::as_str)
            .map(str::to_owned),
        environment: payload
            .get("environment")
            .and_then(Value::as_str)
            .map(str::to_owned),
        secret_names: list("secret_names"),
        capability_names: list("capability_names"),
        network: payload.get("network").and_then(Value::as_bool),
        provider_digests,
        protected: true,
        post_wallet: wallet,
        when_spent,
        owner_wait_seconds,
    })
}

/// Whether a per-entry POST wallet ledger agrees with its grant record
/// (`_valid_entry_counts`).
pub fn valid_entry_counts(per_entry: &Value, record: &Map<String, Value>) -> bool {
    let Some(per_entry) = per_entry.as_object() else {
        return false;
    };
    if per_entry.is_empty() || per_entry.len() > MAX_WALLET_ENTRIES {
        return false;
    }
    let mut providers = Vec::new();
    let mut total: i64 = 0;
    for (key, count) in per_entry {
        let Some((provider, _rule)) = split_wallet_entry_key(&Value::String(key.clone())) else {
            return false;
        };
        let Some(count) = count.as_i64().filter(|c| (1..=MAX_COUNT).contains(c)) else {
            return false;
        };
        total = total.saturating_add(count);
        providers.push(Value::String(format!("api:{provider}")));
    }
    providers.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    providers.dedup();
    // Python compares the sum with `==`, so an integral float record agrees.
    let max_calls_agrees = record
        .get("max_calls")
        .is_some_and(|value| value.as_i64() == Some(total) || value.as_f64() == Some(total as f64));
    let mut names: Vec<Value> = record
        .get("capability_names")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !names.iter().all(Value::is_string) {
        return false;
    }
    names.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    max_calls_agrees && total <= MAX_COUNT && names == providers
}
