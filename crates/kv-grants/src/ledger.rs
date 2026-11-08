//! The daemon's in-memory grant ledger (`kv/approval_verify.py` `GrantRegistry`):
//! how many times each approval was admitted, which admissions it gave, and
//! revocations that must hold until the daemon stops. Paused jobs and saved
//! passes join in the capability-client stage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kv_approvals::verify::{AdmissionRefused, VerifiedGrant, from_payload};
use serde_json::{Map, Value};

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
