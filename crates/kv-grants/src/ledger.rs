//! The daemon's in-memory grant ledger (`kv/approval_verify.py` `GrantRegistry`):
//! how many times each approval was admitted, which admissions it gave, and
//! revocations that must hold until the daemon stops. Paused jobs and saved
//! passes join in the capability-client stage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kv_approvals::verify::{AdmissionRefused, VerifiedGrant, from_payload, valid_entry_counts};
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunState {
    pub digest: String,
    pub used: i64,
    pub limit: Option<i64>,
    pub admissions: BTreeSet<String>,
    pub revoked: Option<String>,
}

#[derive(Default)]
struct Inner {
    /// ("grant" | "request" | "artifact", id) -> the verified grant registered under it.
    by_key: BTreeMap<(&'static str, String), Arc<VerifiedGrant>>,
    runs: BTreeMap<String, RunState>,
    revocations: BTreeMap<String, String>,
    /// Grant id -> its end on the monotonic clock, so a wall clock moved back
    /// cannot revive an expired approval.
    grant_mono_end: BTreeMap<String, Instant>,
    /// Grant id -> the latest wall-clock end an extension gave its pass.
    extended_until: BTreeMap<String, i64>,
    /// Token hash -> the live state of a capability pass minted this session.
    passes: BTreeMap<String, PassState>,
}

/// A capability pass as the daemon counts it: calls left in all and, for a
/// several-service or wallet pass, per service or entry.
#[derive(Debug, Clone)]
struct PassState {
    record: Map<String, Value>,
    left: i64,
    revoked: bool,
    time_over: bool,
    mono_end: Instant,
    /// Service or entry key -> calls left (`null`: no limit for that service).
    left_by: Option<Map<String, Value>>,
    used_unlimited: i64,
    wallet: bool,
}

impl PassState {
    fn time_over(&mut self, now_epoch: i64) -> bool {
        let signed_end = self
            .record
            .get("expires_at_epoch")
            .and_then(Value::as_i64)
            .unwrap_or(i64::MIN);
        if self.time_over || signed_end <= now_epoch || Instant::now() >= self.mono_end {
            self.time_over = true;
        }
        self.time_over
    }

    fn unlimited(&self) -> bool {
        self.left_by
            .as_ref()
            .is_some_and(|by| by.values().any(Value::is_null))
    }

    fn public(&self, capability: Option<&str>) -> Map<String, Value> {
        let mut result = self.record.clone();
        let max_calls = self
            .record
            .get("max_calls")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        result.insert("remaining_calls".into(), json!(self.left));
        result.insert(
            "consumed_calls".into(),
            json!(max_calls - self.left + self.used_unlimited),
        );
        let unlimited = self.unlimited();
        if let Some(left_by) = &self.left_by {
            result.insert(
                "remaining_calls_by_service".into(),
                Value::Object(left_by.clone()),
            );
            if let Some(left) = capability.and_then(|c| left_by.get(c)) {
                result.insert("remaining_calls".into(), left.clone());
            } else if unlimited {
                result.insert("remaining_calls".into(), Value::Null);
            }
        }
        if self.revoked {
            result.insert("status".into(), json!("revoked"));
        } else if self.left == 0 && !unlimited {
            result.insert("status".into(), json!("consumed"));
        }
        result
    }

    /// Which count this call is charged to, or why it cannot be charged.
    fn charge_service(&self, capability: Option<&str>) -> Result<Option<String>, AdmissionRefused> {
        let Some(left_by) = &self.left_by else {
            return Ok(None);
        };
        let Some(left) = capability.and_then(|c| left_by.get(c)) else {
            return Err(AdmissionRefused::new(if self.wallet {
                "outside this run's POST wallet"
            } else {
                "token is scoped to a different provider"
            }));
        };
        let capability = capability.expect("found above").to_owned();
        if left.is_null() {
            return Ok(Some(capability));
        }
        if left.as_i64().unwrap_or(0) <= 0 {
            return Err(AdmissionRefused::new(format!(
                "call budget exhausted for {capability}"
            )));
        }
        Ok(Some(capability))
    }

    fn debit(&mut self, service: Option<&str>) {
        if let Some(service) = service {
            let left_by = self
                .left_by
                .as_mut()
                .expect("service passes count by service");
            let left = left_by.get_mut(service).expect("charged service exists");
            if left.is_null() {
                self.used_unlimited += 1;
                return;
            }
            *left = json!(left.as_i64().unwrap_or(0) - 1);
        }
        self.left -= 1;
    }
}

fn valid_service_counts(per_service: &Value, max_calls: i64) -> bool {
    let Some(counts) = per_service.as_object() else {
        return false;
    };
    if counts.is_empty() || (counts.len() < 2 && !counts.values().any(Value::is_null)) {
        return false;
    }
    let mut total: i64 = 0;
    for value in counts.values() {
        if value.is_null() {
            continue;
        }
        match value.as_i64() {
            Some(count) if count >= 1 => total = total.saturating_add(count),
            _ => return false,
        }
    }
    total == max_calls
}

#[derive(Default)]
pub struct Ledger {
    inner: Mutex<Inner>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Count one admission of `grant`, refusing revoked, changed, expired or
    /// used-up approvals and repeated admission ids.
    pub fn admit(
        &self,
        grant: &Map<String, Value>,
        verified: &VerifiedGrant,
        admission_id: &str,
        now_epoch: i64,
    ) -> Result<(), AdmissionRefused> {
        let grant_id = grant
            .get("grant_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AdmissionRefused::new("approval changed or revoked"))?;
        let mut inner = self.lock();
        if inner.revocations.contains_key(grant_id) {
            return Err(AdmissionRefused::new("approval revoked"));
        }
        let once = grant.get("usage_mode").and_then(Value::as_str) == Some("once");
        let limit = if once {
            Some(1)
        } else {
            grant.get("max_runs").and_then(Value::as_i64)
        };
        let state = inner
            .runs
            .entry(grant_id.to_owned())
            .or_insert_with(|| RunState {
                digest: verified.payload_digest.clone(),
                used: 0,
                limit,
                admissions: BTreeSet::new(),
                revoked: None,
            });
        if state.digest != verified.payload_digest || state.revoked.is_some() {
            return Err(AdmissionRefused::new("approval changed or revoked"));
        }
        if let Some(expires) = grant.get("expires_at_epoch").and_then(Value::as_i64) {
            let remaining = expires.saturating_sub(now_epoch).max(0);
            inner
                .grant_mono_end
                .entry(grant_id.to_owned())
                .or_insert_with(|| {
                    Instant::now() + std::time::Duration::from_secs(remaining as u64)
                });
        }
        if inner
            .grant_mono_end
            .get(grant_id)
            .is_some_and(|end| Instant::now() >= *end)
        {
            return Err(AdmissionRefused::new("approval expired"));
        }
        let state = inner.runs.get_mut(grant_id).expect("inserted above");
        if let Some(limit) = state.limit
            && state.used >= limit
        {
            return Err(AdmissionRefused::new(format!(
                "this approval's {limit} runs are used up"
            )));
        }
        if state.admissions.contains(admission_id) {
            return Err(AdmissionRefused::new("duplicate grant admission"));
        }
        state.used += 1;
        state.admissions.insert(admission_id.to_owned());
        Ok(())
    }

    /// Register a signed payload under its grant, request and artifact ids;
    /// the same payload again is fine, a different one under any of those ids
    /// is a conflict.
    pub fn insert(
        &self,
        payload: &Map<String, Value>,
        digest: &str,
        now_epoch: i64,
    ) -> Result<(&'static str, Arc<VerifiedGrant>), AdmissionRefused> {
        let id = |field: &str| {
            payload
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| AdmissionRefused::new("approval changed or revoked"))
        };
        let keys = [
            ("grant", id("grant_id")?),
            ("request", id("request_id")?),
            ("artifact", id("artifact_id")?),
        ];
        let mut inner = self.lock();
        let found: Vec<Option<Arc<VerifiedGrant>>> = keys
            .iter()
            .map(|key| inner.by_key.get(key).cloned())
            .collect();
        if found.iter().all(Option::is_none) {
            let verified = Arc::new(from_payload(payload, digest)?);
            for key in keys {
                inner.by_key.insert(key, Arc::clone(&verified));
            }
            if let Some(expires) = payload.get("expires_at_epoch").and_then(Value::as_i64) {
                let remaining = expires.saturating_sub(now_epoch).max(0);
                inner.grant_mono_end.insert(
                    keys_grant_id(&verified),
                    Instant::now() + std::time::Duration::from_secs(remaining as u64),
                );
            }
            return Ok(("registered", verified));
        }
        if let Some(first) = &found[0]
            && found
                .iter()
                .all(|entry| entry.as_ref().is_some_and(|e| Arc::ptr_eq(e, first)))
            && first.payload_digest == digest
        {
            return Ok(("already-registered", Arc::clone(first)));
        }
        Err(AdmissionRefused::with_code(
            "a grant, request or approval id is already registered with different contents",
            "conflict",
        ))
    }

    /// The verified grant registered under `grant_id`, if any.
    pub fn get(&self, grant_id: &str) -> Option<Arc<VerifiedGrant>> {
        self.lock()
            .by_key
            .get(&("grant", grant_id.to_owned()))
            .cloned()
    }

    pub fn run_state(&self, grant_id: &str) -> Option<RunState> {
        self.lock().runs.get(grant_id).cloned()
    }

    /// The revocation mode recorded for `grant_id`, if any.
    pub fn revoked(&self, grant_id: &str) -> Option<String> {
        self.lock().revocations.get(grant_id).cloned()
    }

    pub fn run_counts(&self) -> BTreeMap<String, i64> {
        self.lock()
            .runs
            .iter()
            .map(|(id, state)| (id.clone(), state.used))
            .collect()
    }

    /// Record a revocation; an immediate one is never downgraded.
    pub fn revoke(&self, grant_id: &str, mode: &str) {
        let mut inner = self.lock();
        if inner.revocations.get(grant_id).map(String::as_str) != Some("immediate") {
            inner
                .revocations
                .insert(grant_id.to_owned(), mode.to_owned());
        }
        if let Some(state) = inner.runs.get_mut(grant_id)
            && state.revoked.as_deref() != Some("immediate")
        {
            state.revoked = Some(mode.to_owned());
        }
    }

    /// Register a freshly minted capability pass (`add_pass`).
    pub fn add_pass(
        &self,
        record: &Map<String, Value>,
        now_epoch: i64,
    ) -> Result<(), AdmissionRefused> {
        let text = |key: &str| {
            record
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        };
        let Some(token_hash) = text("token_hash") else {
            return Err(AdmissionRefused::new("duplicate capability admission"));
        };
        let mut inner = self.lock();
        let duplicate = inner.passes.contains_key(token_hash)
            || inner.passes.values().any(|pass| {
                pass.record.get("token_id") == record.get("token_id")
                    || text("admission_id").is_some_and(|id| {
                        pass.record.get("admission_id").and_then(Value::as_str) == Some(id)
                    })
            });
        if duplicate {
            return Err(AdmissionRefused::new("duplicate capability admission"));
        }
        let Some(max_calls) = record.get("max_calls").and_then(Value::as_i64) else {
            return Err(AdmissionRefused::new("invalid per-service call counts"));
        };
        let start = record
            .get("created_at_epoch")
            .and_then(Value::as_i64)
            .unwrap_or(now_epoch);
        let span = record
            .get("expires_at_epoch")
            .and_then(Value::as_i64)
            .map(|ends| ends.saturating_sub(start).max(0))
            .unwrap_or(0);
        let mut mono_end = Instant::now() + std::time::Duration::from_secs(span as u64);
        if let Some(grant_end) = record
            .get("grant_id")
            .and_then(Value::as_str)
            .and_then(|id| inner.grant_mono_end.get(id))
        {
            mono_end = mono_end.min(*grant_end);
        }
        let per_service = record.get("calls_per_service").filter(|v| !v.is_null());
        let per_entry = record.get("calls_per_entry").filter(|v| !v.is_null());
        let (left_by, wallet) = if let Some(per_entry) = per_entry {
            if per_service.is_some() || !valid_entry_counts(per_entry, record) {
                return Err(AdmissionRefused::new("invalid per-entry call counts"));
            }
            (per_entry.as_object().cloned(), true)
        } else if let Some(per_service) = per_service {
            if !valid_service_counts(per_service, max_calls) {
                return Err(AdmissionRefused::new("invalid per-service call counts"));
            }
            (per_service.as_object().cloned(), false)
        } else {
            (None, false)
        };
        inner.passes.insert(
            token_hash.to_owned(),
            PassState {
                record: record.clone(),
                left: max_calls,
                revoked: false,
                time_over: false,
                mono_end,
                left_by,
                used_unlimited: 0,
                wallet,
            },
        );
        Ok(())
    }

    /// The pass's record with its live counts and status (`pass_record`).
    pub fn pass_record(
        &self,
        token_hash: &str,
        capability: Option<&str>,
    ) -> Option<Map<String, Value>> {
        self.lock()
            .passes
            .get(token_hash)
            .map(|pass| pass.public(capability))
    }

    /// Whether the pass's time is over by its signed end or the monotonic clock.
    /// Python `spend_permit` with a `token_hash`: whether this pass may spend a
    /// one-call permit signed for `grant_id`/`run_id` and `capability`, in the
    /// words Python refuses with. Debits nothing: `spend_pass` follows once the
    /// permit itself is spent.
    pub fn check_pass_for_permit(
        &self,
        token_hash: &str,
        now_epoch: i64,
        capability: &str,
        grant_id: Option<&str>,
        run_id: Option<&str>,
    ) -> Result<(), AdmissionRefused> {
        let mut inner = self.lock();
        let parent_revoked = inner
            .passes
            .get(token_hash)
            .and_then(|pass| pass.record.get("grant_id"))
            .and_then(Value::as_str)
            .and_then(|id| inner.runs.get(id))
            .is_some_and(|run| run.revoked.as_deref() == Some("immediate"));
        let Some(pass) = inner.passes.get_mut(token_hash) else {
            return Err(AdmissionRefused::new(
                "capability pass expired or exhausted",
            ));
        };
        if pass.revoked || pass.time_over(now_epoch) || (pass.left <= 0 && pass.left_by.is_none()) {
            return Err(AdmissionRefused::new(
                "capability pass expired or exhausted",
            ));
        }
        let other = AdmissionRefused::new("this permit belongs to another run or provider");
        if pass.wallet {
            return Err(other);
        }
        let services: Vec<&str> = match &pass.left_by {
            Some(left_by) => left_by.keys().map(String::as_str).collect(),
            None => pass
                .record
                .get("capability_name")
                .and_then(Value::as_str)
                .into_iter()
                .collect(),
        };
        if parent_revoked
            || pass.record.get("grant_id").and_then(Value::as_str) != grant_id
            || pass
                .record
                .get("created_from_run_id")
                .and_then(Value::as_str)
                != run_id
            || !services.contains(&capability)
        {
            return Err(other);
        }
        // `_charge_service` before the debit: an exhausted service refuses here, with the
        // permit still unspent.
        pass.charge_service(Some(capability)).map(|_| ())
    }

    pub fn time_over(&self, token_hash: &str, now_epoch: i64) -> bool {
        self.lock()
            .passes
            .get_mut(token_hash)
            .is_some_and(|pass| pass.time_over(now_epoch))
    }

    /// Charge one call to the pass (`spend_pass`) and return its record.
    pub fn spend_pass(
        &self,
        token_hash: &str,
        now_epoch: i64,
        capability: Option<&str>,
    ) -> Result<Map<String, Value>, AdmissionRefused> {
        let mut inner = self.lock();
        let parent_revoked = |inner: &Inner, pass: &PassState| {
            pass.record
                .get("grant_id")
                .and_then(Value::as_str)
                .and_then(|id| inner.runs.get(id))
                .is_some_and(|run| run.revoked.as_deref() == Some("immediate"))
        };
        let Some(pass) = inner.passes.get(token_hash).filter(|pass| !pass.revoked) else {
            return Err(AdmissionRefused::new("token is missing or revoked"));
        };
        let parent_revoked = parent_revoked(&inner, pass);
        let pass = inner.passes.get_mut(token_hash).expect("found above");
        if pass.time_over(now_epoch) {
            return Err(AdmissionRefused::new("token expired"));
        }
        if parent_revoked {
            return Err(AdmissionRefused::new("parent grant revoked immediately"));
        }
        if pass.left <= 0 && pass.left_by.is_none() {
            return Err(AdmissionRefused::new("call budget exhausted"));
        }
        let service = pass.charge_service(capability)?;
        pass.debit(service.as_deref());
        Ok(pass.public(capability))
    }

    pub fn revoke_pass(&self, token_hash: &str) {
        if let Some(pass) = self.lock().passes.get_mut(token_hash) {
            pass.revoked = true;
        }
    }

    /// Token hashes of passes whose grant was extended and that are still live.
    pub fn extended_live_tokens(&self, now: i64) -> BTreeSet<String> {
        let inner = self.lock();
        let grants: BTreeSet<&str> = inner
            .extended_until
            .iter()
            .filter(|(_, ends)| **ends > now)
            .map(|(id, _)| id.as_str())
            .collect();
        inner
            .passes
            .iter()
            .filter(|(_, pass)| {
                pass.record
                    .get("grant_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| grants.contains(id))
                    && pass
                        .record
                        .get("expires_at_epoch")
                        .and_then(Value::as_i64)
                        .is_some_and(|ends| ends > now)
            })
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    /// Remember that an extension moved `grant_id`'s pass to end at `ends`.
    pub fn extend_until(&self, grant_id: &str, ends: i64) {
        let mut inner = self.lock();
        let entry = inner
            .extended_until
            .entry(grant_id.to_owned())
            .or_insert(ends);
        *entry = (*entry).max(ends);
    }

    /// Grant ids whose extended passes are still live at `now`; the stores
    /// keep those records past their own expiry. (Token hashes and waiting
    /// pauses join with the capability-client stage.)
    pub fn extended_live(&self, now: i64) -> BTreeSet<String> {
        self.lock()
            .extended_until
            .iter()
            .filter(|(_, ends)| **ends > now)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

fn keys_grant_id(verified: &VerifiedGrant) -> String {
    verified.grant_id.clone()
}
