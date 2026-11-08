//! Run grants (`kv/grants.py`): creating, matching, admitting, revoking and
//! pruning the owner-signed records in `run_grants.json`.

use std::fmt;

use kv_approvals::verify::AdmissionRefused;

use crate::normalize::InvalidValue;
use crate::store::StoreFault;

/// Why a grant operation failed, keeping Python's error classes apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// Python `ValueError`.
    Invalid(InvalidValue),
    /// A store could not be read or written.
    Store(StoreFault),
    /// Python `AdmissionRefused`.
    Refused(AdmissionRefused),
    /// Python `GrantSpentError`: token minting failed after admission.
    Spent {
        message: String,
        grant_id: String,
        spent: bool,
        error_type: &'static str,
    },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantError::Invalid(e) => f.write_str(e.message()),
            GrantError::Store(e) => f.write_str(e.message()),
            GrantError::Refused(e) => f.write_str(e.message()),
            GrantError::Spent { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for GrantError {}

impl From<InvalidValue> for GrantError {
    fn from(error: InvalidValue) -> Self {
        GrantError::Invalid(error)
    }
}

impl From<StoreFault> for GrantError {
    fn from(error: StoreFault) -> Self {
        GrantError::Store(error)
    }
}

impl From<AdmissionRefused> for GrantError {
    fn from(error: AdmissionRefused) -> Self {
        GrantError::Refused(error)
    }
}

use std::collections::BTreeSet;
use std::path::Path;

use kv_approvals::permit_session::SessionBinding;
use kv_approvals::risk_card::{minimal_risk_card, normalize_risk_card};
use kv_approvals::verify::{MAX_COUNT, WalletEntry, post_wallet_binding};
use serde_json::{Map, Value, json};

use crate::ledger::Ledger;
use crate::normalize::{
    DEFAULT_GRANT_TTL_SECONDS, MAX_STORED_GRANTS, WHEN_SPENT, check_seconds, is_expired, iso,
    normalize_actor, normalize_grant_id, normalize_reason, normalize_run_identity,
    normalize_scope_list, normalize_service_calls, py_eq, waiting_after_end,
};
use crate::store::{StoreKind, read_records, write_records};

pub const APPROVAL_MODE_PROTECTED: &str = "protected-approval";
const VALID_APPROVAL_MODES: [&str; 4] = [
    "unset",
    "local-convenience",
    APPROVAL_MODE_PROTECTED,
    "unsafe-convenience",
];

/// What every grant operation needs: the vault, its HMAC state key, the
/// daemon session the grants must be signed for, and the daemon's ledger.
pub struct GrantContext<'a> {
    pub root: &'a Path,
    pub signing_key: &'a [u8],
    pub binding: &'a SessionBinding,
    pub ledger: &'a Ledger,
}

/// The owner's request for a new grant (`create_run_grant` keyword arguments);
/// every field is the raw value the caller supplied, validated here.
#[derive(Debug, Clone, Default)]
pub struct CreateGrant {
    pub secret_names: Option<Value>,
    pub capability_names: Option<Value>,
    pub actor: Option<Value>,
    pub reason: Option<Value>,
    pub ttl_seconds: Option<Value>,
    pub max_calls: Option<Value>,
    pub risk_card: Option<Value>,
    pub usage_mode: Option<Value>,
    pub max_runs: Option<Value>,
    pub post_wallet: Option<Value>,
    pub calls_per_service: Option<Value>,
    pub when_spent: Option<Value>,
    pub owner_wait_seconds: Option<Value>,
    pub ends_at_epoch: Option<Value>,
}

/// Signs a grant with the owner's key (`owner_sign` in Python); `None` means
/// the vault has no passphrase and nothing can be approved.
pub type OwnerSign<'a> = &'a dyn Fn(Map<String, Value>) -> Result<Map<String, Value>, InvalidValue>;

/// The approval security mode the owner selected (`config.get_approval_mode`).
pub fn approval_mode(root: &Path) -> Result<String, GrantError> {
    let config = kv_store::config::load_config(root)
        .map_err(|error| GrantError::Store(StoreFault::Io(error.to_string())))?;
    let mode = config
        .value
        .get("security")
        .and_then(|s| s.get("approval_mode"))
        .and_then(Value::as_str)
        .unwrap_or("unset");
    Ok(if VALID_APPROVAL_MODES.contains(&mode) {
        mode.to_owned()
    } else {
        "unset".to_owned()
    })
}

pub fn refuse_if_protected(root: &Path) -> Result<(), GrantError> {
    if approval_mode(root)? == APPROVAL_MODE_PROTECTED {
        return Err(InvalidValue::new(
            "local approval is disabled in protected-approval mode; nothing was granted",
        )
        .into());
    }
    Ok(())
}

fn require_owner_sign(owner_sign: Option<OwnerSign<'_>>) -> Result<OwnerSign<'_>, GrantError> {
    owner_sign.ok_or_else(|| {
        InvalidValue::new(kv_approvals::permit_session::NO_PASSPHRASE_REFUSAL).into()
    })
}

/// Create a grant for one exact run. `owner_sign` is `None` on a vault without
/// a passphrase, which refuses as Python does.
pub fn create_run_grant(
    ctx: &GrantContext<'_>,
    run_identity: &Value,
    request: &CreateGrant,
    owner_sign: Option<OwnerSign<'_>>,
    now: i64,
) -> Result<Map<String, Value>, GrantError> {
    refuse_if_protected(ctx.root)?;
    create_run_grant_locked(ctx, run_identity, request, None, owner_sign, now)
}

pub(crate) fn create_run_grant_locked(
    ctx: &GrantContext<'_>,
    run_identity: &Value,
    request: &CreateGrant,
    grant_id: Option<&Value>,
    owner_sign: Option<OwnerSign<'_>>,
    now: i64,
) -> Result<Map<String, Value>, GrantError> {
    let owner_sign = require_owner_sign(owner_sign)?;
    let usage_mode = match request.usage_mode.as_ref() {
        None => "once",
        Some(Value::String(mode)) if mode == "once" || mode == "reusable" => mode.as_str(),
        Some(_) => return Err(InvalidValue::new("usage_mode must be once or reusable").into()),
    };
    let default_ttl = json!(DEFAULT_GRANT_TTL_SECONDS);
    let ttl = check_seconds(
        Some(request.ttl_seconds.as_ref().unwrap_or(&default_ttl)),
        "ttl_seconds",
        now,
    )?;
    let mut start = now;
    if let Some(ends) = request.ends_at_epoch.as_ref() {
        let Some(ends) = ends.as_i64().filter(|ends| ends - ttl <= now) else {
            return Err(InvalidValue::new(
                "ends_at_epoch must be a whole-second end, at most ttl from now",
            )
            .into());
        };
        if ends <= now {
            return Err(InvalidValue::new(
                "the end shown to the owner has already passed; nothing was granted (approve again)",
            )
            .into());
        }
        start = ends - ttl;
    }
    let secret_names = normalize_scope_list(request.secret_names.as_ref(), "secret_names")?;
    let capability_names =
        normalize_scope_list(request.capability_names.as_ref(), "capability_names")?;
    if secret_names.is_empty() && capability_names.is_empty() {
        return Err(InvalidValue::new(
            "grant requires at least one secret name or capability name",
        )
        .into());
    }
    let identity = normalize_run_identity(run_identity)?;
    let mut wallet = None;
    let (max_calls, per_service) = if let Some(post_wallet) = request.post_wallet.as_ref() {
        let (entries, total) = wallet_scope(
            post_wallet,
            &secret_names,
            &capability_names,
            request.calls_per_service.as_ref(),
            request.max_calls.as_ref(),
        )?;
        wallet = Some(entries);
        (Some(total), None)
    } else if capability_names.is_empty() {
        (None, None)
    } else {
        let (calls, per_service) = normalize_service_calls(
            &capability_names,
            request.max_calls.as_ref(),
            request.calls_per_service.as_ref(),
        )?;
        (Some(calls), per_service)
    };
    if request.calls_per_service.is_some() && capability_names.is_empty() {
        return Err(
            InvalidValue::new("calls_per_service applies only to capability grants").into(),
        );
    }
    let max_calls_value = max_calls.map(|calls| json!(calls));
    let risk_card = match request.risk_card.as_ref() {
        None => minimal_risk_card(
            &Value::Object(identity.clone()),
            Some(&secret_names),
            Some(&capability_names),
            max_calls_value.as_ref(),
            "",
        ),
        Some(card) => bind_risk_card_to_grant(
            &normalize_risk_card(Some(card)),
            &identity,
            &secret_names,
            &capability_names,
            max_calls_value.as_ref(),
        ),
    };
    let mut grant = Map::new();
    grant.insert("grant_id".into(), json!(normalize_grant_id(grant_id)?));
    grant.insert("status".into(), json!("active"));
    grant.insert("usage_mode".into(), json!(usage_mode));
    grant.insert("created_at".into(), json!(iso(start)));
    grant.insert("created_at_epoch".into(), json!(start));
    grant.insert("expires_at".into(), json!(iso(start + ttl)));
    grant.insert("expires_at_epoch".into(), json!(start + ttl));
    for (target, source) in [
        ("created_from_run_id", "run_id"),
        ("command_fingerprint", "command_fingerprint"),
        ("script_kind", "script_kind"),
        ("script_sha256", "script_sha256"),
        ("script_ref_hash", "script_ref_hash"),
    ] {
        if let Some(value) = identity.get(source) {
            grant.insert(target.into(), value.clone());
        }
    }
    grant.insert("secret_names".into(), json!(secret_names));
    grant.insert("capability_names".into(), json!(capability_names));
    grant.insert(
        "actor".into(),
        Value::Object(normalize_actor(request.actor.as_ref())?),
    );
    grant.insert(
        "reason".into(),
        json!(normalize_reason(request.reason.as_ref())?),
    );
    grant.insert("risk_card".into(), risk_card);
    if !capability_names.is_empty()
        && let Some(calls) = max_calls_value.as_ref()
    {
        grant.insert("max_calls".into(), calls.clone());
    }
    if let Some(per_service) = per_service {
        grant.insert("calls_per_service".into(), Value::Object(per_service));
    }
    if let Some(entries) = wallet {
        grant.insert("post_wallet".into(), Value::Array(entries));
    }
    if let Some(max_runs) = request.max_runs.as_ref() {
        match max_runs.as_i64() {
            Some(runs) if usage_mode == "reusable" && runs >= 1 => {
                grant.insert("max_runs".into(), json!(runs));
            }
            _ => {
                return Err(InvalidValue::new(
                    "max_runs applies to reusable grants and must be a positive integer",
                )
                .into());
            }
        }
    }
    if request.when_spent.is_some() || request.owner_wait_seconds.is_some() {
        if capability_names.is_empty() {
            return Err(InvalidValue::new(
                "when_spent and owner_wait_seconds apply to capability grants",
            )
            .into());
        }
        let when_spent = match request.when_spent.as_ref().and_then(Value::as_str) {
            Some(mode) if WHEN_SPENT.contains(&mode) => mode,
            _ => return Err(InvalidValue::new("when_spent must be pause or end").into()),
        };
        grant.insert("when_spent".into(), json!(when_spent));
        let wait = check_seconds(
            request.owner_wait_seconds.as_ref(),
            "owner_wait_seconds",
            now,
        )?;
        grant.insert("owner_wait_seconds".into(), json!(wait));
    }
    grant.retain(|_, value| !value.is_null());
    let grant = owner_sign(grant)?;
    let grant = kv_approvals::artifacts::attach_grant_state_integrity(
        &Value::Object(grant),
        ctx.signing_key,
    )
    .map_err(|error| GrantError::Invalid(InvalidValue::new(error.to_string())))?;
    let grant = grant
        .as_object()
        .cloned()
        .expect("signed grant is an object");
    let stored = read_records(ctx.root, StoreKind::Grants)?;
    if stored
        .iter()
        .any(|existing| existing.get("grant_id") == grant.get("grant_id"))
    {
        return Err(InvalidValue::new("duplicate grant_id").into());
    }
    let mut grants = trim_grants(stored, now, &extended(ctx, now)?)?;
    grants.push(grant.clone());
    write_records(ctx.root, StoreKind::Grants, &grants)?;
    Ok(grant)
}

/// `_wallet_scope`: a POST wallet's entries, ordered and bound, and their total.
fn wallet_scope(
    post_wallet: &Value,
    secret_names: &[String],
    capability_names: &[String],
    calls_per_service: Option<&Value>,
    max_calls: Option<&Value>,
) -> Result<(Vec<Value>, i64), GrantError> {
    let ordered = match post_wallet.as_array() {
        Some(entries)
            if entries.iter().all(|entry| {
                entry.get("provider").is_some_and(Value::is_string)
                    && entry.get("rule_id").is_some_and(Value::is_string)
            }) =>
        {
            let mut sorted = entries.clone();
            sorted.sort_by(|a, b| {
                let key = |e: &Value| {
                    (
                        e["provider"].as_str().unwrap_or("").to_owned(),
                        e["rule_id"].as_str().unwrap_or("").to_owned(),
                    )
                };
                key(a).cmp(&key(b))
            });
            Value::Array(sorted)
        }
        _ => post_wallet.clone(),
    };
    let Some(bound) = post_wallet_binding(Some(&ordered))? else {
        return Err(InvalidValue::new("a POST wallet needs its entries").into());
    };
    if !secret_names.is_empty() || calls_per_service.is_some() {
        return Err(InvalidValue::new(
            "a POST wallet's counts are its entries' counts; it takes no raw secret and no per-service counts",
        )
        .into());
    }
    let services: BTreeSet<String> = bound
        .iter()
        .map(|entry| format!("api:{}", entry.provider))
        .collect();
    if capability_names.to_vec() != services.into_iter().collect::<Vec<_>>() {
        return Err(InvalidValue::new(
            "a POST wallet needs at least one entry for each service of the approval, and none for any other",
        )
        .into());
    }
    let total: i64 = bound.iter().map(|entry| entry.calls).sum();
    if total > MAX_COUNT {
        return Err(InvalidValue::new(format!(
            "at most {MAX_COUNT} calls in all per approval ({total} asked)"
        ))
        .into());
    }
    if let Some(max_calls) = max_calls
        && !py_eq(max_calls, &json!(total))
    {
        return Err(
            InvalidValue::new("max_calls is not the sum of the POST wallet's entries").into(),
        );
    }
    Ok((bound.iter().map(wallet_entry_value).collect(), total))
}

fn wallet_entry_value(entry: &WalletEntry) -> Value {
    json!({
        "provider": entry.provider,
        "rule_id": entry.rule_id,
        "rule_digest": entry.rule_digest,
        "calls": entry.calls,
    })
}

/// `_bind_risk_card_to_grant`: the signed card's identity and scope are the grant's.
fn bind_risk_card_to_grant(
    risk_card: &Value,
    identity: &Map<String, Value>,
    secret_names: &[String],
    capability_names: &[String],
    max_calls: Option<&Value>,
) -> Value {
    let mut bound = risk_card.as_object().cloned().unwrap_or_default();
    let mut card_identity = Map::new();
    for key in [
        "command_fingerprint",
        "script_kind",
        "script_sha256",
        "script_ref_hash",
    ] {
        if let Some(value) = identity.get(key)
            && value.as_str().is_some_and(|text| !text.is_empty())
        {
            card_identity.insert(key.into(), value.clone());
        }
    }
    let mut scope = Map::new();
    scope.insert("secret_names".into(), json!(secret_names));
    scope.insert("capability_names".into(), json!(capability_names));
    scope.insert(
        "raw_secret_injection".into(),
        json!(!secret_names.is_empty()),
    );
    scope.insert(
        "broker_capability".into(),
        json!(!capability_names.is_empty()),
    );
    if !capability_names.is_empty() {
        scope.insert(
            "max_calls".into(),
            max_calls.cloned().unwrap_or(Value::Null),
        );
    }
    bound.insert("identity".into(), Value::Object(card_identity));
    bound.insert("scope".into(), Value::Object(scope));
    normalize_risk_card(Some(&Value::Object(bound)))
}

/// Grant ids the stores must keep past expiry: extended passes still live
/// and grants whose capability tokens have not yet expired.
pub(crate) fn extended(ctx: &GrantContext<'_>, now: i64) -> Result<BTreeSet<String>, GrantError> {
    let mut kept = ctx.ledger.extended_live(now);
    for token in read_records(ctx.root, StoreKind::Tokens)? {
        if token
            .get("expires_at_epoch")
            .and_then(Value::as_i64)
            .is_some_and(|expires| expires > now)
            && let Some(grant_id) = token.get("grant_id").and_then(Value::as_str)
            && !grant_id.is_empty()
        {
            kept.insert(grant_id.to_owned());
        }
    }
    Ok(kept)
}

/// `_trim_grants`: drop expired grants nobody still needs; refuse a full store.
pub(crate) fn trim_grants(
    grants: Vec<Map<String, Value>>,
    now: i64,
    kept: &BTreeSet<String>,
) -> Result<Vec<Map<String, Value>>, GrantError> {
    let current: Vec<Map<String, Value>> = grants
        .into_iter()
        .filter(|grant| {
            !is_expired(grant, now)
                || grant
                    .get("grant_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| kept.contains(id))
                || waiting_after_end(grant, now)
        })
        .collect();
    if current.len() >= MAX_STORED_GRANTS {
        return Err(InvalidValue::new(
            "grant store is full; wait for existing approvals to expire",
        )
        .into());
    }
    Ok(current)
}
