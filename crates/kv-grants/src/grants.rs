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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use kv_approvals::permit_session::SessionBinding;
use kv_approvals::risk_card::{minimal_risk_card, normalize_risk_card};
use kv_approvals::verify::{
    MAX_COUNT, RunFacts, VerifiedGrant, WalletEntry, payload_digest, post_wallet_binding,
    refuse_unprotected, run_mismatch, signed_payload, wallet_entry_key,
};
use serde_json::{Map, Value, json};

use crate::ledger::Ledger;
use crate::normalize::{
    DEFAULT_GRANT_TTL_SECONDS, MAX_STORED_GRANTS, WHEN_SPENT, actor_matches, check_seconds,
    is_expired, is_revoked, iso, normalize_actor, normalize_grant_id, normalize_reason,
    normalize_run_identity, normalize_scope_list, normalize_service_calls, py_eq,
    script_identity_matches, waiting_after_end,
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
    /// The vault's approval signing key (`.secrets/approval_signing_key`):
    /// approval artifacts and token seals.
    pub signing_key: &'a [u8],
    /// The grant-state key: derived from the master key in a protected
    /// session (`kv-approval:grant-state`), the signing key otherwise.
    pub state_key: &'a [u8],
    pub binding: &'a SessionBinding,
    pub ledger: &'a Ledger,
    /// Provider name -> digest, as the daemon snapshotted it at unlock.
    pub providers: &'a BTreeMap<String, Value>,
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
    let grant =
        kv_approvals::artifacts::attach_grant_state_integrity(&Value::Object(grant), ctx.state_key)
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

#[derive(Debug, Clone, Copy, Default)]
pub struct ListFlags {
    pub include_expired: bool,
    pub include_revoked: bool,
    pub include_consumed: bool,
}

fn grant_id_of(grant: &Map<String, Value>) -> &str {
    grant.get("grant_id").and_then(Value::as_str).unwrap_or("")
}

fn runs_used(ctx: &GrantContext<'_>, grant: &Map<String, Value>) -> i64 {
    ctx.ledger
        .run_state(grant_id_of(grant))
        .map(|state| state.used)
        .unwrap_or(0)
}

/// `list_run_grants`: the stored grants with `runs_used`, filtered as asked.
pub fn list_run_grants(
    ctx: &GrantContext<'_>,
    flags: ListFlags,
    now: i64,
) -> Result<Vec<Map<String, Value>>, GrantError> {
    let mut grants = Vec::new();
    for grant in read_records(ctx.root, StoreKind::Grants)? {
        let used = runs_used(ctx, &grant);
        let once = grant.get("usage_mode").and_then(Value::as_str) == Some("once");
        if !flags.include_consumed && once && used != 0 {
            continue;
        }
        if !flags.include_consumed
            && grant.get("status").and_then(Value::as_str) == Some("consumed")
        {
            continue;
        }
        if !flags.include_revoked && is_revoked(&grant) {
            continue;
        }
        if !flags.include_expired && is_expired(&grant, now) {
            continue;
        }
        let mut listed = grant;
        listed.insert("runs_used".into(), json!(used));
        grants.push(listed);
    }
    Ok(grants)
}

/// `_valid_grant`: signed for this daemon session, matching `run` when given,
/// a known usage mode and an intact state seal.
pub fn valid_grant(
    ctx: &GrantContext<'_>,
    grant: &Map<String, Value>,
    run: Option<&RunFacts>,
) -> bool {
    if refuse_unprotected(ctx.binding).is_err() {
        return false;
    }
    let grant_value = Value::Object(grant.clone());
    let Some(payload) = signed_payload(ctx.binding, &grant_value) else {
        return false;
    };
    if let Some(run) = run
        && run_mismatch(&payload, run, ctx.providers).is_some()
    {
        return false;
    }
    matches!(
        grant.get("usage_mode").and_then(Value::as_str),
        Some("once" | "reusable")
    ) && kv_approvals::artifacts::verify_grant_state_integrity(ctx.state_key, &grant_value)
}

/// What a run asks for, normalized once for matching.
pub struct RunRequest {
    pub identity: Map<String, Value>,
    pub secret_names: Vec<String>,
    pub capability_names: Vec<String>,
    pub actor: Map<String, Value>,
}

impl RunRequest {
    pub fn normalize(
        run_identity: &Value,
        secret_names: Option<&Value>,
        capability_names: Option<&Value>,
        actor: Option<&Value>,
    ) -> Result<Self, GrantError> {
        Ok(Self {
            identity: normalize_run_identity(run_identity)?,
            secret_names: normalize_scope_list(secret_names, "secret_names")?,
            capability_names: normalize_scope_list(capability_names, "capability_names")?,
            actor: normalize_actor(actor)?,
        })
    }
}

fn scope_equals(grant: &Map<String, Value>, field: &str, wanted: &[String]) -> bool {
    match grant.get(field) {
        None => wanted.is_empty(),
        Some(value) => py_eq(value, &json!(wanted)),
    }
}

fn actor_allows(grant: &Map<String, Value>, actor: &Map<String, Value>) -> bool {
    match grant.get("actor") {
        Some(grant_actor)
            if !matches!(grant_actor, Value::Null | Value::Bool(false))
                && !(grant_actor.as_object().is_some_and(Map::is_empty)) =>
        {
            actor_matches(grant_actor, &Value::Object(actor.clone()))
        }
        _ => true,
    }
}

/// `find_matching_run_grant`: the first active grant covering this exact run.
pub fn find_matching_run_grant(
    ctx: &GrantContext<'_>,
    request: &RunRequest,
    now: i64,
    run: Option<&RunFacts>,
) -> Result<Option<Map<String, Value>>, GrantError> {
    let flags = ListFlags {
        include_consumed: run.is_some(),
        ..ListFlags::default()
    };
    for grant in list_run_grants(ctx, flags, now)? {
        let grant_id = grant_id_of(&grant);
        if ctx.ledger.revoked(grant_id).is_some() {
            continue;
        }
        let once = grant.get("usage_mode").and_then(Value::as_str) == Some("once");
        if once && runs_used(ctx, &grant) != 0 {
            continue;
        }
        if is_revoked(&grant) || grant.get("status").and_then(Value::as_str) != Some("active") {
            continue;
        }
        if !matches!(
            grant.get("usage_mode").and_then(Value::as_str),
            Some("once" | "reusable")
        ) {
            continue;
        }
        if grant.get("command_fingerprint") != request.identity.get("command_fingerprint") {
            continue;
        }
        if !script_identity_matches(&grant, &request.identity) {
            continue;
        }
        if !scope_equals(&grant, "secret_names", &request.secret_names)
            || !scope_equals(&grant, "capability_names", &request.capability_names)
        {
            continue;
        }
        if !actor_allows(&grant, &request.actor) {
            continue;
        }
        if !valid_grant(ctx, &grant, run) {
            continue;
        }
        return Ok(Some(grant));
    }
    Ok(None)
}

fn resolve_path(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_owned())
}

/// `explain_run_grant_mismatch`: why no grant matched, when a near miss exists.
pub fn explain_run_grant_mismatch(
    ctx: &GrantContext<'_>,
    request: &RunRequest,
    cwd: Option<&str>,
    argv: Option<&[String]>,
    now: i64,
) -> Result<Option<&'static str>, GrantError> {
    let run_cwd = cwd.filter(|c| !c.is_empty()).map(resolve_path);
    let run_argv = argv.map(|a| json!(a));
    let (mut command_seen, mut requested_seen, mut cwd_seen) = (false, false, false);
    for grant in list_run_grants(ctx, ListFlags::default(), now)? {
        if is_revoked(&grant) || !valid_grant(ctx, &grant, None) {
            continue;
        }
        if !actor_allows(&grant, &request.actor) {
            continue;
        }
        let card = grant.get("risk_card").and_then(Value::as_object);
        let grant_cwd = card
            .and_then(|c| c.get("cwd"))
            .and_then(Value::as_str)
            .map(resolve_path);
        let grant_argv = card.and_then(|c| c.get("argv"));
        let same_argv = matches!((&run_argv, grant_argv), (Some(run), Some(grant)) if run == grant);
        let same_cwd = matches!((&run_cwd, &grant_cwd), (Some(run), Some(grant)) if run == grant);
        if !script_identity_matches(&grant, &request.identity) {
            if same_argv || same_cwd {
                command_seen = true;
            }
            continue;
        }
        if !scope_equals(&grant, "secret_names", &request.secret_names)
            || !scope_equals(&grant, "capability_names", &request.capability_names)
        {
            if same_argv && same_cwd {
                requested_seen = true;
            }
            continue;
        }
        if grant.get("command_fingerprint") == request.identity.get("command_fingerprint") {
            continue;
        }
        if same_argv
            && let (Some(run), Some(grant_dir)) = (&run_cwd, &grant_cwd)
            && grant_dir != run
        {
            cwd_seen = true;
        } else if same_argv || same_cwd {
            command_seen = true;
        }
    }
    Ok(if cwd_seen {
        Some("scope mismatch: cwd")
    } else if requested_seen {
        Some(if request.capability_names.is_empty() {
            "scope mismatch: secret"
        } else {
            "scope mismatch: capability"
        })
    } else if command_seen {
        Some("scope mismatch: command")
    } else {
        None
    })
}

/// `revoke_run_grant`: mark a stored grant revoked (no downgrade from
/// immediate) and tell the ledger. Returns whether anything changed.
pub fn revoke_run_grant(
    ctx: &GrantContext<'_>,
    grant_id: &str,
    reason: Option<&Value>,
    now: i64,
    mode: &str,
) -> Result<bool, GrantError> {
    if grant_id.is_empty() {
        return Err(InvalidValue::new("grant_id is required").into());
    }
    if mode != "immediate" && mode != "future" {
        return Err(InvalidValue::new("revoke mode must be immediate or future").into());
    }
    let mut grants = read_records(ctx.root, StoreKind::Grants)?;
    for grant in grants.iter_mut() {
        if grant_id_of(grant) != grant_id {
            continue;
        }
        if !grant.get("owner_approval").is_some_and(Value::is_object) {
            let value = Value::Object(grant.clone());
            if !kv_approvals::artifacts::verify_grant_approval_artifact(ctx.signing_key, &value) {
                return Err(InvalidValue::new("grant approval integrity check failed").into());
            }
            if grant.contains_key("usage_mode")
                && !kv_approvals::artifacts::verify_grant_state_integrity(ctx.state_key, &value)
            {
                return Err(InvalidValue::new("grant state integrity check failed").into());
            }
        }
        if is_revoked(grant) {
            let old_mode = grant
                .get("revoke_mode")
                .and_then(Value::as_str)
                .unwrap_or("future");
            if old_mode == "immediate" || mode == "future" {
                return Ok(false);
            }
        }
        grant.insert("status".into(), json!("revoked"));
        grant.insert("revoke_mode".into(), json!(mode));
        grant.insert("revoked_at".into(), json!(iso(now)));
        grant.insert("revoked_at_epoch".into(), json!(now));
        ctx.ledger.revoke(grant_id, mode);
        if reason.is_some() {
            grant.insert("revoke_reason".into(), json!(normalize_reason(reason)?));
        }
        if grant.contains_key("usage_mode") {
            let sealed = kv_approvals::artifacts::attach_grant_state_integrity(
                &Value::Object(grant.clone()),
                ctx.state_key,
            )
            .map_err(|error| GrantError::Invalid(InvalidValue::new(error.to_string())))?;
            *grant = sealed
                .as_object()
                .cloned()
                .expect("sealed grant is an object");
        }
        write_records(ctx.root, StoreKind::Grants, &grants)?;
        return Ok(true);
    }
    Ok(false)
}

/// `verify_for_admission`: the VerifiedGrant for admitting `run` under
/// `grant`, registering the signed payload in the ledger.
pub fn verify_for_admission(
    ctx: &GrantContext<'_>,
    grant: &Map<String, Value>,
    run: &RunFacts,
    now: i64,
) -> Result<Arc<VerifiedGrant>, GrantError> {
    refuse_unprotected(ctx.binding)?;
    let Some(payload) = signed_payload(ctx.binding, &Value::Object(grant.clone())) else {
        return Err(AdmissionRefused::with_code(
            "not signed by this vault's owner key for this daemon session",
            "not_signed",
        )
        .into());
    };
    if let Some(mismatch) = run_mismatch(&payload, run, ctx.providers) {
        let code = match mismatch {
            "environment" => "environment_mismatch",
            "provider" => "provider_mismatch",
            _ => "mismatch",
        };
        return Err(AdmissionRefused::with_code(
            format!("the signed {mismatch} does not allow this run"),
            code,
        )
        .into());
    }
    let digest = payload_digest(&Value::Object(payload.clone()))
        .ok_or_else(|| AdmissionRefused::new("approval changed or revoked"))?;
    let (_status, verified) = ctx.ledger.insert(&payload, &digest, now)?;
    Ok(verified)
}

/// `parent_verified`: the entry registered at a token's admission in this
/// session; it must be this parent's approval.
pub fn parent_verified(
    ctx: &GrantContext<'_>,
    parent: &Map<String, Value>,
) -> Result<Arc<VerifiedGrant>, AdmissionRefused> {
    refuse_unprotected(ctx.binding)?;
    let artifact_id = kv_approvals::artifacts::grant_approval_ref(&Value::Object(parent.clone())).0;
    match ctx.ledger.get(grant_id_of(parent)) {
        Some(verified) if Some(&verified.artifact_id) == artifact_id.as_ref() => Ok(verified),
        _ => Err(AdmissionRefused::with_code(
            "the token's parent grant is not registered in this daemon session",
            "not_registered",
        )),
    }
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|v| !v.is_null())
}

fn opt_eq(left: Option<&Value>, right: Option<&Value>) -> bool {
    py_eq(left.unwrap_or(&Value::Null), right.unwrap_or(&Value::Null))
}

/// `_require_service_counts`: a grant for several services carries a count
/// for each, in kv's form; a one-service grant carries none.
pub fn require_service_counts(grant: &Map<String, Value>) -> Result<(), GrantError> {
    let names = string_list(grant.get("capability_names"));
    let per = present(grant.get("calls_per_service"));
    if let Some(wallet) = present(grant.get("post_wallet")) {
        wallet_scope(
            wallet,
            &string_list(grant.get("secret_names")),
            &names,
            per,
            grant.get("max_calls"),
        )?;
        return Ok(());
    }
    if names.len() < 2 {
        if let Some(per) = per {
            let blank: Map<String, Value> = names
                .iter()
                .map(|name| (name.clone(), Value::Null))
                .collect();
            if !py_eq(per, &Value::Object(blank)) {
                return Err(
                    InvalidValue::new("a one-service grant carries no per-service counts").into(),
                );
            }
        }
        return Ok(());
    }
    let Some(per) = per else {
        return Err(InvalidValue::new(
            "this grant names several services without a count for each service",
        )
        .into());
    };
    let (_total, normalized) = normalize_service_calls(&names, grant.get("max_calls"), Some(per))?;
    let normalized = normalized.map(Value::Object).unwrap_or(Value::Null);
    if !py_eq(&normalized, per) {
        return Err(
            InvalidValue::new("this grant's per-service counts are not in kv's form").into(),
        );
    }
    Ok(())
}

/// `_token_services_match`: the token's services and counts are its parent's.
pub fn token_services_match(record: &Map<String, Value>, parent: &Map<String, Value>) -> bool {
    let names = parent
        .get("capability_names")
        .cloned()
        .unwrap_or_else(|| json!([]));
    if let Some(wallet) = present(parent.get("post_wallet")) {
        let Some(entries) = wallet.as_array() else {
            return false;
        };
        let mut keyed = Map::new();
        for entry in entries {
            let (Some(provider), Some(rule_id), Some(calls)) = (
                entry.get("provider").and_then(Value::as_str),
                entry.get("rule_id").and_then(Value::as_str),
                entry.get("calls"),
            ) else {
                return false;
            };
            keyed.insert(wallet_entry_key(provider, rule_id), calls.clone());
        }
        return opt_eq(record.get("capability_names"), Some(&names))
            && opt_eq(record.get("calls_per_entry"), Some(&Value::Object(keyed)))
            && present(record.get("calls_per_service")).is_none()
            && !record.contains_key("capability_name");
    }
    if present(record.get("calls_per_entry")).is_some() {
        return false;
    }
    if present(record.get("calls_per_service")).is_some() {
        return opt_eq(record.get("capability_names"), Some(&names))
            && opt_eq(
                record.get("calls_per_service"),
                parent.get("calls_per_service"),
            );
    }
    let single = names.as_array().is_some_and(|list| list.len() == 1);
    single
        && names
            .as_array()
            .unwrap()
            .iter()
            .any(|name| opt_eq(record.get("capability_name"), Some(name)))
        && record.get("capability_name").is_some()
        && present(parent.get("calls_per_service")).is_none()
}

/// `token_parent`: why a capability token's parent grant no longer backs it,
/// or the verified parent.
pub fn token_parent(
    ctx: &GrantContext<'_>,
    record: &Map<String, Value>,
) -> Result<(Option<String>, Option<Arc<VerifiedGrant>>), GrantError> {
    if refuse_unprotected(ctx.binding).is_err() {
        return Ok((
            Some(kv_approvals::permit_session::NO_PASSPHRASE_REFUSAL.to_owned()),
            None,
        ));
    }
    let truthy_str = |key: &str| {
        record
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    let (Some(grant_id), Some(artifact_id), Some(admission_id)) = (
        truthy_str("grant_id"),
        truthy_str("grant_artifact_id"),
        truthy_str("admission_id"),
    ) else {
        return Ok((Some("token needs a fresh grant approval".to_owned()), None));
    };
    let parent = read_records(ctx.root, StoreKind::Grants)?
        .into_iter()
        .find(|grant| grant_id_of(grant) == grant_id);
    let Some(parent) = parent.filter(|parent| valid_grant(ctx, parent, None)) else {
        return Ok((
            Some("parent grant is missing or invalid; request fresh approval".to_owned()),
            None,
        ));
    };
    let parent_value = Value::Object(parent.clone());
    if kv_approvals::artifacts::grant_approval_ref(&parent_value)
        .0
        .as_deref()
        != Some(artifact_id)
    {
        return Ok((
            Some("token belongs to a different grant approval".to_owned()),
            None,
        ));
    }
    if !matches!(
        parent.get("status").and_then(Value::as_str),
        Some("active" | "consumed" | "revoked")
    ) {
        return Ok((Some("parent grant state is invalid".to_owned()), None));
    }
    if is_revoked(&parent) && parent.get("revoke_mode").and_then(Value::as_str) != Some("future") {
        return Ok((Some("parent grant revoked immediately".to_owned()), None));
    }
    let Some(state) = ctx
        .ledger
        .run_state(grant_id)
        .filter(|state| state.admissions.contains(admission_id))
    else {
        return Ok((
            Some("token admission does not match parent grant".to_owned()),
            None,
        ));
    };
    if state.revoked.as_deref() == Some("immediate") {
        return Ok((Some("parent grant revoked immediately".to_owned()), None));
    }
    let empty = json!({});
    if !opt_eq(
        record.get("command_fingerprint"),
        parent.get("command_fingerprint"),
    ) || !script_identity_matches(&parent, record)
        || !token_services_match(record, &parent)
        || !actor_matches(
            parent.get("actor").unwrap_or(&empty),
            record.get("actor").unwrap_or(&empty),
        )
    {
        return Ok((
            Some("token scope does not match parent grant".to_owned()),
            None,
        ));
    }
    Ok(match parent_verified(ctx, &parent) {
        Ok(verified) => (None, Some(verified)),
        Err(refused) => (Some(refused.message().to_owned()), None),
    })
}

pub fn token_parent_denial(
    ctx: &GrantContext<'_>,
    record: &Map<String, Value>,
) -> Result<Option<String>, GrantError> {
    Ok(token_parent(ctx, record)?.0)
}

/// `prune_expired_run_grants`: drop expired grants nobody still needs;
/// returns how many remain.
pub fn prune_expired_run_grants(ctx: &GrantContext<'_>, now: i64) -> Result<usize, GrantError> {
    let grants = read_records(ctx.root, StoreKind::Grants)?;
    let kept = extended(ctx, now)?;
    let before = grants.len();
    let current: Vec<Map<String, Value>> = grants
        .into_iter()
        .filter(|grant| {
            !is_expired(grant, now)
                || kept.contains(grant_id_of(grant))
                || waiting_after_end(grant, now)
        })
        .collect();
    if current.len() != before {
        write_records(ctx.root, StoreKind::Grants, &current)?;
    }
    Ok(current.len())
}

/// A run admitted under a grant: the grant, the ledger's verified entry and
/// the admission id the run's capability token will carry.
#[derive(Debug, Clone)]
pub struct Admission {
    pub grant: Map<String, Value>,
    pub verified: Arc<VerifiedGrant>,
    pub admission_id: String,
    /// The capability token minted for the run, with the raw token under `token`.
    pub issued_capability: Option<Map<String, Value>>,
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).expect("operating system randomness");
    hex::encode(buffer)
}

/// `admit_run_grant`: find the matching grant, check its service counts,
/// verify and count the admission, and mint the run's capability token.
pub fn admit_run_grant(
    ctx: &GrantContext<'_>,
    request: &RunRequest,
    env_name: Option<&str>,
    now: i64,
) -> Result<Option<Admission>, GrantError> {
    if !request.capability_names.is_empty() && env_name.map(str::trim).is_none_or(str::is_empty) {
        return Err(InvalidValue::new("capability admission requires an environment").into());
    }
    let run = RunFacts {
        env_name: env_name.map(str::to_owned),
        secret_names: request.secret_names.clone(),
        capability_names: request.capability_names.iter().map(|n| json!(n)).collect(),
    };
    let Some(grant) = find_matching_run_grant(ctx, request, now, Some(&run))? else {
        return Ok(None);
    };
    require_service_counts(&grant)?;
    let verified = verify_for_admission(ctx, &grant, &run, now)?;
    let admission_id = random_hex(24);
    if read_records(ctx.root, StoreKind::Grants)?
        .iter()
        .any(|g| g.get("admission_id").and_then(Value::as_str) == Some(admission_id.as_str()))
    {
        return Err(InvalidValue::new("duplicate grant admission").into());
    }
    if !request.capability_names.is_empty()
        && read_records(ctx.root, StoreKind::Tokens)?
            .iter()
            .any(|t| t.get("admission_id").and_then(Value::as_str) == Some(admission_id.as_str()))
    {
        return Err(InvalidValue::new("duplicate capability admission").into());
    }
    ctx.ledger.admit(&grant, &verified, &admission_id, now)?;
    let mut issued_capability = None;
    if !request.capability_names.is_empty() {
        let per_entry = verified.post_wallet.as_ref().map(|wallet| {
            wallet
                .iter()
                .map(|entry| {
                    (
                        wallet_entry_key(&entry.provider, &entry.rule_id),
                        json!(entry.calls),
                    )
                })
                .collect::<Map<String, Value>>()
        });
        let expires = grant
            .get("expires_at_epoch")
            .and_then(Value::as_i64)
            .unwrap_or(now);
        let mint = crate::capabilities::MintRequest {
            actor: Some(Value::Object(request.actor.clone())),
            grant_id: grant.get("grant_id").cloned(),
            reason: None,
            env_name: env_name.map(|e| json!(e)),
            ttl_seconds: Some(json!(expires - now)),
            max_calls: Some(grant.get("max_calls").cloned().unwrap_or(json!(1))),
            token_id: None,
            grant_artifact_id: kv_approvals::artifacts::grant_approval_ref(&Value::Object(
                grant.clone(),
            ))
            .0,
            admission_id: Some(admission_id.clone()),
            verified: Some(&verified),
            calls_per_service: grant.get("calls_per_service").cloned(),
            calls_per_entry: per_entry.map(Value::Object),
        };
        let mut services = request.capability_names.clone();
        services.sort();
        match crate::capabilities::mint_capability_token(
            ctx,
            &Value::Object(request.identity.clone()),
            &services[0],
            &mint,
            now,
        ) {
            Ok(token) => issued_capability = Some(token),
            Err(GrantError::Refused(refused)) => return Err(GrantError::Refused(refused)),
            Err(error) => {
                let error_type = match &error {
                    GrantError::Store(fault) => fault.python_type(),
                    _ => "ValueError",
                };
                return Err(GrantError::Spent {
                    message: error.to_string(),
                    grant_id: grant_id_of(&grant).to_owned(),
                    spent: grant.get("usage_mode").and_then(Value::as_str) == Some("once"),
                    error_type,
                });
            }
        }
    }
    Ok(Some(Admission {
        grant,
        verified,
        admission_id,
        issued_capability,
    }))
}
