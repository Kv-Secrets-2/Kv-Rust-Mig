//! Capability tokens (`kv/capabilities.py`): the short-lived passes minted at
//! admission that let one run call a brokered service, stored by hash in
//! `capability_tokens.json` and counted by the daemon's ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::Engine;
use kv_approvals::artifacts::{attach_token_integrity, verify_token_integrity};
use kv_approvals::verify::{AdmissionRefused, VerifiedGrant, split_wallet_entry_key};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::grants::{GrantContext, GrantError, token_parent};
use crate::normalize::{
    InvalidValue, MAX_REASON_LEN, actor_matches, check_count, check_seconds, iso, normalize_actor,
    normalize_run_identity, normalize_service_calls, py_eq, py_strip, py_truncate,
    script_identity_matches,
};
use crate::store::{StoreKind, read_records, write_records};

pub const CAPABILITY_TOKENS_FILE: &str = "capability_tokens.json";
pub const TOKEN_PREFIX: &str = "kvcap_";
pub const MAX_STORED_TOKENS: usize = 1000;
pub const DEFAULT_CAPABILITY_TOKEN_TTL_SECONDS: i64 = 60;
pub const DEFAULT_CAPABILITY_MAX_CALLS: i64 = 1;
pub const MAX_CAPABILITY_NAME_LEN: usize = 256;
pub const ENV_CAPABILITY_TOKEN: &str = "KV_CAP_TOKEN";
pub const ENV_CAPABILITY_NAME: &str = "KV_CAPABILITY";
pub const ENV_CAPABILITY_ENV: &str = "KV_CAP_ENV";
pub const ENV_RUN_ID: &str = "KV_CAP_RUN_ID";
pub const ENV_COMMAND_FINGERPRINT: &str = "KV_CAP_COMMAND_FINGERPRINT";
pub const ENV_SCRIPT_KIND: &str = "KV_CAP_SCRIPT_KIND";
pub const ENV_SCRIPT_SHA256: &str = "KV_CAP_SCRIPT_SHA256";
pub const ENV_SCRIPT_REF_HASH: &str = "KV_CAP_SCRIPT_REF_HASH";
pub const ENV_ACTOR_SOURCE: &str = "KV_CAP_ACTOR_SOURCE";
pub const ENV_ACTOR_CLIENT_NAME: &str = "KV_CAP_ACTOR_CLIENT_NAME";
pub const ENV_ACTOR_CLIENT_VERSION: &str = "KV_CAP_ACTOR_CLIENT_VERSION";
pub const ENV_ACTOR_SESSION_ID: &str = "KV_CAP_ACTOR_SESSION_ID";

const IDENTITY_ENV: [(&str, &str); 4] = [
    (ENV_RUN_ID, "run_id"),
    (ENV_SCRIPT_KIND, "script_kind"),
    (ENV_SCRIPT_SHA256, "script_sha256"),
    (ENV_SCRIPT_REF_HASH, "script_ref_hash"),
];
const ACTOR_ENV: [(&str, &str); 4] = [
    (ENV_ACTOR_SOURCE, "source"),
    (ENV_ACTOR_CLIENT_NAME, "client_name"),
    (ENV_ACTOR_CLIENT_VERSION, "client_version"),
    (ENV_ACTOR_SESSION_ID, "session_id"),
];

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// The record without what must never leave the store or the daemon.
pub fn public_record(record: &Map<String, Value>) -> Map<String, Value> {
    record
        .iter()
        .filter(|(key, _)| key.as_str() != "token_hash" && key.as_str() != "token_integrity")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub fn validate_token(token: &Value) -> Result<&str, InvalidValue> {
    let Some(text) = token.as_str().filter(|t| t.starts_with(TOKEN_PREFIX)) else {
        return Err(InvalidValue::new(format!(
            "capability token must start with {TOKEN_PREFIX}"
        )));
    };
    if text.len() > 256 {
        return Err(InvalidValue::new("capability token exceeds 256 bytes"));
    }
    Ok(text)
}

fn random_bytes(count: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; count];
    getrandom::getrandom(&mut buffer).expect("operating system randomness");
    buffer
}

pub fn normalize_token_id(token_id: Option<&Value>) -> Result<String, InvalidValue> {
    match token_id {
        None | Some(Value::Null) => Ok(format!("captok_{}", hex::encode(random_bytes(12)))),
        Some(Value::String(text)) if !py_strip(text).is_empty() => {
            Ok(py_truncate(py_strip(text), 80).to_owned())
        }
        Some(_) => Err(InvalidValue::new("token_id must be a non-empty string")),
    }
}

fn single_line(text: &str) -> bool {
    !text.contains(['\r', '\n', '\0'])
}

pub fn normalize_capability_name(capability_name: &Value) -> Result<String, InvalidValue> {
    let Some(text) = capability_name
        .as_str()
        .map(py_strip)
        .filter(|t| !t.is_empty())
    else {
        return Err(InvalidValue::new(
            "capability_name must be a non-empty string",
        ));
    };
    if !single_line(text) {
        return Err(InvalidValue::new(
            "capability_name must be single-line text",
        ));
    }
    if text.len() > MAX_CAPABILITY_NAME_LEN {
        return Err(InvalidValue::new(format!(
            "capability_name exceeds {MAX_CAPABILITY_NAME_LEN} bytes"
        )));
    }
    Ok(text.to_owned())
}

/// `_normalize_env_name`: `""` for none, else single-line text of at most 128 bytes.
pub fn normalize_env_name(env_name: Option<&Value>) -> Result<String, InvalidValue> {
    let Some(env_name) = env_name.filter(|v| !v.is_null()) else {
        return Ok(String::new());
    };
    let Some(text) = env_name.as_str().map(py_strip).filter(|t| !t.is_empty()) else {
        return Err(InvalidValue::new("env_name must be a non-empty string"));
    };
    if !single_line(text) {
        return Err(InvalidValue::new("env_name must be single-line text"));
    }
    if text.len() > 128 {
        return Err(InvalidValue::new("env_name exceeds 128 bytes"));
    }
    Ok(text.to_owned())
}

pub fn normalize_optional_text(
    value: Option<&Value>,
    max_len: usize,
) -> Result<String, InvalidValue> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(py_truncate(py_strip(text), max_len).to_owned()),
        Some(_) => Err(InvalidValue::new("value must be a string")),
    }
}

pub fn is_token_expired(record: &Map<String, Value>, now: i64) -> bool {
    match record.get("expires_at_epoch").and_then(Value::as_i64) {
        Some(expires) => expires <= now,
        None => true,
    }
}

fn trim_tokens(
    tokens: Vec<Map<String, Value>>,
    now: i64,
    kept: &BTreeSet<String>,
) -> Result<Vec<Map<String, Value>>, GrantError> {
    let current: Vec<Map<String, Value>> = tokens
        .into_iter()
        .filter(|record| {
            !is_token_expired(record, now)
                || record
                    .get("token_hash")
                    .and_then(Value::as_str)
                    .is_some_and(|hash| kept.contains(hash))
        })
        .collect();
    if current.len() >= MAX_STORED_TOKENS {
        return Err(InvalidValue::new(
            "capability token store is full; wait for existing tokens to expire",
        )
        .into());
    }
    Ok(current)
}

fn present<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    record.get(key).filter(|v| !v.is_null())
}

/// The services a token may call: its `capability_names` or its one `capability_name`.
pub fn token_services(record: &Map<String, Value>) -> Vec<Value> {
    if present(record, "calls_per_service").is_some()
        || present(record, "calls_per_entry").is_some()
    {
        return record
            .get("capability_names")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
    }
    match record.get("capability_name") {
        Some(name)
            if !matches!(name, Value::Null | Value::Bool(false)) && name.as_str() != Some("") =>
        {
            vec![name.clone()]
        }
        _ => Vec::new(),
    }
}

/// What a release must stay within (`require_verified`): the verified grant
/// it was admitted under, its secret names and capability, and in a protected
/// session the signed environment and the provider definition's digest.
pub struct Release<'a> {
    pub kind: &'static str,
    pub grant_id: Option<&'a str>,
    pub env_name: &'a str,
    pub secret_names: &'a [String],
    pub capability_name: Option<&'a str>,
    pub provider_digest: Option<&'a str>,
    pub sandboxed: Option<bool>,
    pub network: Option<bool>,
}

impl<'a> Release<'a> {
    pub fn new(kind: &'static str, grant_id: Option<&'a str>, env_name: &'a str) -> Self {
        Self {
            kind,
            grant_id,
            env_name,
            secret_names: &[],
            capability_name: None,
            provider_digest: None,
            sandboxed: None,
            network: None,
        }
    }
}

pub fn require_verified(
    verified: Option<&VerifiedGrant>,
    release: &Release<'_>,
) -> Result<(), AdmissionRefused> {
    let refuse = |what: &str| {
        AdmissionRefused::with_code(
            format!("the approval does not cover this {} ({what})", release.kind),
            "sink_mismatch",
        )
    };
    let Some(verified) = verified else {
        return Err(refuse("no verified approval"));
    };
    if Some(verified.grant_id.as_str()) != release.grant_id {
        return Err(refuse("another approval"));
    }
    if !release.secret_names.iter().all(|name| {
        verified
            .secret_names
            .iter()
            .any(|v| v.as_str() == Some(name))
    }) {
        return Err(refuse("secret names"));
    }
    if let Some(capability) = release.capability_name
        && !verified
            .capability_names
            .iter()
            .any(|v| v.as_str() == Some(capability))
    {
        return Err(refuse("capability"));
    }
    if release.kind == "launch" {
        if release.sandboxed != Some(true) {
            return Err(refuse("sandbox: the run is not inside bubblewrap"));
        }
        if verified.protected
            && (verified.network.is_none()
                || release.network.is_none()
                || release.network != verified.network)
        {
            return Err(refuse("network: not the signed value"));
        }
    }
    if verified.protected {
        if verified.environment.as_deref() != Some("*")
            && verified.environment.as_deref() != Some(release.env_name)
        {
            return Err(refuse("environment"));
        }
        if release.kind == "consume" || release.kind == "transport" {
            let name: String = release
                .capability_name
                .unwrap_or("")
                .chars()
                .skip("api:".len())
                .collect();
            let signed = verified
                .provider_digests
                .iter()
                .find(|(provider, _)| *provider == name)
                .map(|(_, digest)| digest);
            let matches = match (release.provider_digest, signed) {
                (Some(digest), Some(signed)) => signed.as_str() == Some(digest),
                _ => false,
            };
            if !matches {
                return Err(refuse("provider definition"));
            }
        }
    }
    Ok(())
}

/// Everything `_mint_capability_token` takes besides the run and its service.
#[derive(Default)]
pub struct MintRequest<'a> {
    pub actor: Option<Value>,
    pub grant_id: Option<Value>,
    pub reason: Option<Value>,
    pub env_name: Option<Value>,
    pub ttl_seconds: Option<Value>,
    pub max_calls: Option<Value>,
    pub token_id: Option<Value>,
    pub grant_artifact_id: Option<String>,
    pub admission_id: Option<String>,
    pub verified: Option<&'a Arc<VerifiedGrant>>,
    pub calls_per_service: Option<Value>,
    pub calls_per_entry: Option<Value>,
}

fn sorted_map(map: &Map<String, Value>) -> Map<String, Value> {
    map.iter()
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Mint a capability token, persist its record by hash and register the pass;
/// returns the public record with the raw token under `token`.
pub fn mint_capability_token(
    ctx: &GrantContext<'_>,
    run_identity: &Value,
    capability_name: &str,
    request: &MintRequest<'_>,
    now: i64,
) -> Result<Map<String, Value>, GrantError> {
    let default_max = json!(DEFAULT_CAPABILITY_MAX_CALLS);
    let max_calls = request.max_calls.as_ref().unwrap_or(&default_max);
    let mut per_service: Option<Map<String, Value>> = None;
    let mut per_entry: Option<Map<String, Value>> = None;
    let mut providers: Vec<String> = Vec::new();
    let mut call_budget: Option<i64> = None;
    if let Some(entries) = request.calls_per_entry.as_ref() {
        let Some(entries) = entries
            .as_object()
            .filter(|_| request.calls_per_service.is_none())
        else {
            return Err(InvalidValue::new("a POST wallet token counts by entry only").into());
        };
        let ordered = sorted_map(entries);
        let splits: Vec<Option<(String, String)>> = ordered
            .keys()
            .map(|key| split_wallet_entry_key(&Value::String(key.clone())))
            .collect();
        let counts: Vec<Option<i64>> = ordered
            .values()
            .map(|count| count.as_i64().filter(|c| *c >= 1))
            .collect();
        let total: i64 = counts.iter().flatten().sum();
        if ordered.is_empty()
            || splits.iter().any(Option::is_none)
            || counts.iter().any(Option::is_none)
            || !py_eq(max_calls, &json!(total))
        {
            return Err(InvalidValue::new(
                "a POST wallet token needs a count for each entry, adding up to its total",
            )
            .into());
        }
        let set: BTreeSet<String> = splits
            .iter()
            .flatten()
            .map(|(provider, _)| format!("api:{provider}"))
            .collect();
        providers = set.into_iter().collect();
        if !providers.iter().any(|p| p == capability_name) {
            return Err(InvalidValue::new(
                "a POST wallet token needs its own service among the entries'",
            )
            .into());
        }
        call_budget = Some(total);
        per_entry = Some(ordered);
    }
    if let Some(counts) = request.calls_per_service.as_ref() {
        let names: Vec<String> = match counts.as_object() {
            Some(map) => map
                .keys()
                .map(|name| normalize_capability_name(&Value::String(name.clone())))
                .collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        let (budget, normalized) = normalize_service_calls(&names, Some(max_calls), Some(counts))?;
        match normalized {
            Some(normalized) if normalized.contains_key(capability_name) => {
                call_budget = Some(budget);
                per_service = Some(normalized);
            }
            _ => {
                return Err(InvalidValue::new(
                    "a several-service token needs several services, its own first",
                )
                .into());
            }
        }
    }
    let env_name = normalize_env_name(request.env_name.as_ref())?;
    let grant_id = normalize_optional_text(request.grant_id.as_ref(), 80)?;
    if request.grant_artifact_id.is_some() || request.admission_id.is_some() {
        let verified = request.verified.map(Arc::as_ref);
        let covered = |name: &str| {
            let mut release = Release::new("mint", Some(grant_id.as_str()), &env_name);
            release.capability_name = Some(name);
            require_verified(verified, &release)
        };
        for name in per_service
            .as_ref()
            .map(|p| p.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
        {
            covered(&name)?;
        }
        for name in &providers {
            covered(name)?;
        }
        covered(&normalize_capability_name(&Value::String(
            capability_name.to_owned(),
        ))?)?;
    }
    let default_ttl = json!(DEFAULT_CAPABILITY_TOKEN_TTL_SECONDS);
    let ttl = check_seconds(
        Some(request.ttl_seconds.as_ref().unwrap_or(&default_ttl)),
        "ttl_seconds",
        now,
    )?;
    if per_service.is_none() && per_entry.is_none() {
        call_budget = Some(check_count(Some(max_calls), "max_calls")?);
    }
    let raw_token = format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes(32))
    );
    let identity = normalize_run_identity(run_identity)?;
    let mut record = Map::new();
    record.insert(
        "token_id".into(),
        json!(normalize_token_id(request.token_id.as_ref())?),
    );
    record.insert("token_hash".into(), json!(token_hash(&raw_token)));
    record.insert("status".into(), json!("active"));
    record.insert("created_at".into(), json!(iso(now)));
    record.insert("created_at_epoch".into(), json!(now));
    record.insert("expires_at".into(), json!(iso(now + ttl)));
    record.insert("expires_at_epoch".into(), json!(now + ttl));
    for (target, source) in [
        ("created_from_run_id", "run_id"),
        ("command_fingerprint", "command_fingerprint"),
        ("script_kind", "script_kind"),
        ("script_sha256", "script_sha256"),
        ("script_ref_hash", "script_ref_hash"),
    ] {
        if let Some(value) = identity.get(source) {
            record.insert(target.into(), value.clone());
        }
    }
    record.insert(
        "capability_name".into(),
        json!(normalize_capability_name(&Value::String(
            capability_name.to_owned()
        ))?),
    );
    record.insert("env_name".into(), json!(env_name));
    record.insert(
        "actor".into(),
        Value::Object(normalize_actor(request.actor.as_ref())?),
    );
    record.insert("grant_id".into(), json!(grant_id));
    record.insert(
        "reason".into(),
        json!(normalize_optional_text(
            request.reason.as_ref(),
            MAX_REASON_LEN
        )?),
    );
    record.insert(
        "max_calls".into(),
        json!(call_budget.expect("a budget is always set")),
    );
    if let Some(per_service) = per_service {
        record.remove("capability_name");
        record.insert(
            "capability_names".into(),
            Value::Array(per_service.keys().map(|k| json!(k)).collect()),
        );
        record.insert("calls_per_service".into(), Value::Object(per_service));
    }
    if let Some(per_entry) = per_entry {
        record.remove("capability_name");
        record.insert("capability_names".into(), json!(providers));
        record.insert("calls_per_entry".into(), Value::Object(per_entry));
    }
    record.retain(|_, value| !value.is_null() && value.as_str() != Some(""));
    if let (Some(artifact_id), Some(admission_id)) =
        (&request.grant_artifact_id, &request.admission_id)
    {
        record.insert("authority_version".into(), json!(1));
        record.insert("grant_artifact_id".into(), json!(artifact_id));
        record.insert("admission_id".into(), json!(admission_id));
        let sealed = attach_token_integrity(&Value::Object(record), ctx.signing_key)
            .map_err(|error| GrantError::Invalid(InvalidValue::new(error.to_string())))?;
        record = sealed
            .as_object()
            .cloned()
            .expect("sealed record is an object");
    }
    let stored = read_records(ctx.root, StoreKind::Tokens)?;
    if stored.iter().any(|t| {
        t.get("token_id") == record.get("token_id")
            || t.get("token_hash") == record.get("token_hash")
    }) {
        return Err(InvalidValue::new("duplicate capability token").into());
    }
    if let Some(admission_id) = &request.admission_id
        && stored
            .iter()
            .any(|t| t.get("admission_id").and_then(Value::as_str) == Some(admission_id))
    {
        return Err(InvalidValue::new("duplicate capability admission").into());
    }
    let mut tokens = trim_tokens(stored, now, &ctx.ledger.extended_live_tokens(now))?;
    tokens.push(record.clone());
    ctx.ledger.add_pass(&record, now)?;
    write_records(ctx.root, StoreKind::Tokens, &tokens)?;
    let hash = record["token_hash"].as_str().expect("hash is text");
    let live = ctx
        .ledger
        .pass_record(hash, None)
        .expect("the pass was just added");
    let mut public = public_record(&live);
    public.insert("token".into(), json!(raw_token));
    Ok(public)
}

/// How a call presents a token (`consume_capability_token` keyword arguments).
#[derive(Default, Clone, Copy)]
pub struct ConsumeOptions<'a> {
    pub actor: Option<&'a Value>,
    pub env_name: Option<&'a Value>,
    pub require_parent: bool,
    pub provider_config: Option<&'a Value>,
    pub charge: bool,
    pub allow_spent: bool,
    pub wallet_entry: Option<&'a str>,
}

impl ConsumeOptions<'_> {
    pub fn charging() -> Self {
        Self {
            charge: true,
            ..Self::default()
        }
    }
}

/// The outcome of presenting a token: the charged (or inspected) record, or
/// why it was denied, and the parent's verified grant when one was checked.
pub struct Consumed {
    pub record: Option<Map<String, Value>>,
    pub denial: String,
    pub verified: Option<Arc<VerifiedGrant>>,
}

fn wallet_entry_fits(
    record: &Map<String, Value>,
    wallet_entry: Option<&str>,
    capability: &str,
) -> bool {
    let Some(entry) = wallet_entry else {
        return false;
    };
    let Some((provider, _rule)) = split_wallet_entry_key(&Value::String(entry.to_owned())) else {
        return false;
    };
    record
        .get("calls_per_entry")
        .and_then(Value::as_object)
        .is_some_and(|entries| entries.contains_key(entry))
        && format!("api:{provider}") == capability
}

fn contains_service(services: &[Value], capability: &str) -> bool {
    services.iter().any(|s| s.as_str() == Some(capability))
}

/// Consume (or, with `charge: false`, inspect) a matching active token.
pub fn consume_capability_token(
    ctx: &GrantContext<'_>,
    token: &Value,
    run_identity: &Value,
    capability_name: &Value,
    now: i64,
    options: ConsumeOptions<'_>,
) -> Result<Consumed, GrantError> {
    let hash = token_hash(validate_token(token)?);
    let identity = normalize_run_identity(run_identity)?;
    let capability = normalize_capability_name(capability_name)?;
    let actor = Value::Object(normalize_actor(options.actor)?);
    let env_name = normalize_env_name(options.env_name)?;
    let mut denial =
        "token is missing, expired, consumed, revoked, or scoped to a different run/provider"
            .to_owned();
    let mut consumed = None;
    let mut verified: Option<Arc<VerifiedGrant>> = None;
    for stored in read_records(ctx.root, StoreKind::Tokens)? {
        if stored.get("token_hash").and_then(Value::as_str) != Some(hash.as_str()) {
            continue;
        }
        let Some(live) = ctx.ledger.pass_record(&hash, None) else {
            denial = "token is not issued in this service session".to_owned();
            break;
        };
        let sealed = stored
            .get("authority_version")
            .is_some_and(|v| py_eq(v, &json!(1)));
        let stored_value = Value::Object(stored.clone());
        if (options.require_parent || sealed)
            && !verify_token_integrity(&stored_value, ctx.signing_key)
        {
            denial = "token needs a fresh grant approval or has invalid integrity".to_owned();
            break;
        }
        if options.require_parent && !sealed {
            denial = "token needs a fresh grant approval".to_owned();
            break;
        }
        if options.require_parent || sealed {
            let (parent_denial, parent) = token_parent(ctx, &stored)?;
            verified = parent;
            if let Some(parent_denial) = parent_denial {
                denial = parent_denial;
                break;
            }
        }
        if stored.get("status").and_then(Value::as_str) == Some("revoked")
            || live.get("status").and_then(Value::as_str) == Some("revoked")
        {
            denial = "token is revoked".to_owned();
            break;
        }
        let record = live;
        let wallet = present(&record, "calls_per_entry").is_some();
        if wallet && !wallet_entry_fits(&record, options.wallet_entry, &capability) {
            denial = "outside this run's POST wallet".to_owned();
            break;
        }
        let budget_key = if wallet {
            options.wallet_entry.unwrap_or("").to_owned()
        } else {
            capability.clone()
        };
        let mut spent: Option<&str> = None;
        let status = record.get("status").and_then(Value::as_str);
        if status == Some("consumed") {
            if options.allow_spent && !options.charge {
                spent = Some("calls");
            } else {
                denial = "call budget exhausted".to_owned();
                if wallet {
                    denial.push_str(&format!(" for {}", options.wallet_entry.unwrap_or("")));
                } else if contains_service(&token_services(&record), &capability)
                    && present(&record, "calls_per_service").is_some()
                {
                    denial.push_str(&format!(" for {capability}"));
                }
                break;
            }
        }
        let allowed: &[&str] = if spent.is_some() {
            &["active", "consumed"]
        } else {
            &["active"]
        };
        if !status.is_some_and(|s| allowed.contains(&s)) {
            denial = "token is not active".to_owned();
            break;
        }
        if ctx.ledger.time_over(&hash, now) {
            if !(options.allow_spent && !options.charge) {
                denial = "token expired".to_owned();
                break;
            }
            spent = Some("time");
        }
        if !contains_service(&token_services(&record), &capability) {
            denial = "token is scoped to a different provider".to_owned();
            break;
        }
        let record_env = record.get("env_name").and_then(Value::as_str).unwrap_or("");
        if !env_name.is_empty() && record_env != env_name {
            denial = "token is scoped to a different environment".to_owned();
            break;
        }
        if env_name.is_empty() && !record_env.is_empty() {
            denial = "token requires an explicit environment".to_owned();
            break;
        }
        if record.get("command_fingerprint") != identity.get("command_fingerprint") {
            denial = "token is scoped to a different command".to_owned();
            break;
        }
        if !script_identity_matches(&record, &identity) {
            denial = "token is scoped to a different script".to_owned();
            break;
        }
        if let Some(record_actor) = record.get("actor")
            && record_actor.as_object().is_some_and(|a| !a.is_empty())
            && !actor_matches(record_actor, &actor)
        {
            denial = "token is scoped to a different requester".to_owned();
            break;
        }
        if let Some(parent) = &verified {
            let digest = options
                .provider_config
                .and_then(|config| kv_approvals::wire::provider_digest(config).ok());
            let mut release = Release::new(
                "consume",
                record.get("grant_id").and_then(Value::as_str),
                &env_name,
            );
            release.capability_name = Some(&capability);
            release.provider_digest = digest.as_deref();
            if let Err(refused) = require_verified(Some(parent), &release) {
                denial = refused.message().to_owned();
                verified = None;
                break;
            }
        }
        let outcome = if options.charge {
            ctx.ledger.spend_pass(&hash, now, Some(&budget_key))
        } else {
            ctx.ledger
                .pass_record(&hash, Some(&budget_key))
                .ok_or_else(|| AdmissionRefused::new("token is missing or revoked"))
        };
        match outcome {
            Ok(live) => {
                let mut public = public_record(&live);
                if options.allow_spent && !options.charge {
                    if spent.is_none()
                        && public
                            .get("remaining_calls")
                            .is_some_and(|r| py_eq(r, &json!(0)))
                    {
                        spent = Some("calls");
                    }
                    public.insert(
                        "spent".into(),
                        spent.map(|s| json!(s)).unwrap_or(Value::Null),
                    );
                }
                consumed = Some(public);
            }
            Err(refused) => denial = refused.message().to_owned(),
        }
        break;
    }
    let granted = consumed.is_some();
    Ok(Consumed {
        record: consumed,
        denial: if granted { String::new() } else { denial },
        verified: if granted { verified } else { None },
    })
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TokenListFlags {
    pub include_expired: bool,
    pub include_consumed: bool,
    pub include_revoked: bool,
}

/// Token metadata without hashes or seals (`list_capability_tokens`).
pub fn list_capability_tokens(
    ctx: &GrantContext<'_>,
    flags: TokenListFlags,
    now: i64,
) -> Result<Vec<Map<String, Value>>, GrantError> {
    let mut records = Vec::new();
    for stored in read_records(ctx.root, StoreKind::Tokens)? {
        let live = stored
            .get("token_hash")
            .and_then(Value::as_str)
            .and_then(|hash| ctx.ledger.pass_record(hash, None));
        let record = match live {
            Some(mut live) => {
                if stored.get("status").and_then(Value::as_str) == Some("revoked") {
                    live.insert("status".into(), json!("revoked"));
                }
                live
            }
            None => stored,
        };
        let status = record.get("status").and_then(Value::as_str);
        if !flags.include_consumed && status == Some("consumed") {
            continue;
        }
        if !flags.include_revoked && status == Some("revoked") {
            continue;
        }
        if !flags.include_expired && is_token_expired(&record, now) {
            continue;
        }
        records.push(public_record(&record));
    }
    Ok(records)
}

/// Mark a token revoked on disk and in the ledger; true when a record changed.
pub fn revoke_capability_token(
    ctx: &GrantContext<'_>,
    token_id: &Value,
    reason: Option<&Value>,
    now: i64,
) -> Result<bool, GrantError> {
    let Some(token_id) = token_id.as_str().map(py_strip).filter(|t| !t.is_empty()) else {
        return Err(InvalidValue::new("token_id is required").into());
    };
    let mut tokens = read_records(ctx.root, StoreKind::Tokens)?;
    let mut changed = None;
    for (index, record) in tokens.iter_mut().enumerate() {
        if record.get("token_id").and_then(Value::as_str) != Some(token_id)
            || record.get("status").and_then(Value::as_str) == Some("revoked")
        {
            continue;
        }
        let sealed = record
            .get("authority_version")
            .is_some_and(|v| py_eq(v, &json!(1)));
        if sealed && !verify_token_integrity(&Value::Object(record.clone()), ctx.signing_key) {
            return Err(InvalidValue::new("capability token integrity check failed").into());
        }
        record.insert("status".into(), json!("revoked"));
        if let Some(hash) = record.get("token_hash").and_then(Value::as_str) {
            ctx.ledger.revoke_pass(hash);
        }
        record.insert("revoked_at".into(), json!(iso(now)));
        record.insert("revoked_at_epoch".into(), json!(now));
        let revoke_reason = normalize_optional_text(reason, MAX_REASON_LEN)?;
        if !revoke_reason.is_empty() {
            record.insert("revoke_reason".into(), json!(revoke_reason));
        }
        changed = Some((index, sealed));
        break;
    }
    let Some((index, sealed)) = changed else {
        return Ok(false);
    };
    if sealed {
        let resealed =
            attach_token_integrity(&Value::Object(tokens[index].clone()), ctx.signing_key)
                .map_err(|error| GrantError::Invalid(InvalidValue::new(error.to_string())))?;
        tokens[index] = resealed
            .as_object()
            .cloned()
            .expect("sealed record is an object");
    }
    write_records(ctx.root, StoreKind::Tokens, &tokens)?;
    Ok(true)
}

/// The owner extended a pass's time: its record gets the new, later end.
pub fn extend_token_record(
    ctx: &GrantContext<'_>,
    token_hash: &str,
    expires_at_epoch: &Value,
) -> Result<bool, GrantError> {
    let mut tokens = read_records(ctx.root, StoreKind::Tokens)?;
    for record in tokens.iter_mut() {
        if record.get("token_hash").and_then(Value::as_str) != Some(token_hash) {
            continue;
        }
        let current = record
            .get("expires_at_epoch")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let Some(ends) = expires_at_epoch.as_i64().filter(|ends| *ends > current) else {
            return Ok(false);
        };
        let sealed = record
            .get("authority_version")
            .is_some_and(|v| py_eq(v, &json!(1)));
        if sealed && !verify_token_integrity(&Value::Object(record.clone()), ctx.signing_key) {
            return Err(InvalidValue::new("token integrity check failed").into());
        }
        record.insert("expires_at_epoch".into(), json!(ends));
        record.insert("expires_at".into(), json!(iso(ends)));
        record.remove("token_integrity");
        if sealed {
            let resealed = attach_token_integrity(&Value::Object(record.clone()), ctx.signing_key)
                .map_err(|error| GrantError::Invalid(InvalidValue::new(error.to_string())))?;
            *record = resealed
                .as_object()
                .cloned()
                .expect("sealed record is an object");
        }
        write_records(ctx.root, StoreKind::Tokens, &tokens)?;
        return Ok(true);
    }
    Ok(false)
}

/// The environment that lets a script consume its capability (`capability_env_vars`).
pub fn capability_env_vars(
    token: &Value,
    capability_name: &Value,
    run_identity: &Value,
    actor: Option<&Value>,
    env_name: Option<&Value>,
) -> Result<BTreeMap<String, String>, InvalidValue> {
    let token = validate_token(token)?;
    let identity = normalize_run_identity(run_identity)?;
    let joined = match capability_name.as_array() {
        Some(names) => Value::String(
            names
                .iter()
                .map(normalize_capability_name)
                .collect::<Result<Vec<_>, _>>()?
                .join(","),
        ),
        None => capability_name.clone(),
    };
    let mut env = BTreeMap::new();
    env.insert(ENV_CAPABILITY_TOKEN.to_owned(), token.to_owned());
    env.insert(
        ENV_CAPABILITY_NAME.to_owned(),
        normalize_capability_name(&joined)?,
    );
    env.insert(
        ENV_COMMAND_FINGERPRINT.to_owned(),
        identity["command_fingerprint"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
    );
    let env_name = normalize_env_name(env_name)?;
    if !env_name.is_empty() {
        env.insert(ENV_CAPABILITY_ENV.to_owned(), env_name);
    }
    for (variable, key) in IDENTITY_ENV {
        if let Some(value) = identity
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            env.insert(variable.to_owned(), value.to_owned());
        }
    }
    let actor = normalize_actor(actor)?;
    for (variable, key) in ACTOR_ENV {
        if let Some(value) = actor
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            env.insert(variable.to_owned(), value.to_owned());
        }
    }
    Ok(env)
}

/// Non-secret actor metadata carried with a token (`audit_ctx_from_capability_env`).
pub fn audit_ctx_from_capability_env(
    env: &BTreeMap<String, String>,
) -> Result<Map<String, Value>, InvalidValue> {
    let mut ctx = Map::new();
    for (variable, key) in ACTOR_ENV {
        if let Some(value) = env.get(variable).filter(|v| !v.is_empty()) {
            ctx.insert(key.to_owned(), json!(value));
        }
    }
    normalize_actor(Some(&Value::Object(ctx)))
}

/// Run identity from the capability environment (`run_identity_from_capability_env`).
pub fn run_identity_from_capability_env(
    env: &BTreeMap<String, String>,
) -> Result<Map<String, Value>, InvalidValue> {
    let mut identity = Map::new();
    identity.insert(
        "command_fingerprint".into(),
        env.get(ENV_COMMAND_FINGERPRINT)
            .map(|v| json!(v))
            .unwrap_or(Value::Null),
    );
    for (variable, key) in IDENTITY_ENV {
        if let Some(value) = env.get(variable).filter(|v| !v.is_empty()) {
            identity.insert(key.to_owned(), json!(value));
        }
    }
    normalize_run_identity(&Value::Object(identity))
}
