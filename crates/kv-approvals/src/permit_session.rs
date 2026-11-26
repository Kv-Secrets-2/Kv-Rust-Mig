//! Memory-only ordinary HTTP one-call permits for one daemon session.
//!
//! The daemon observes its trust/configuration state before using this registry.
//! Spending belongs inside the daemon's commit locks: lifecycle -> trust pin -> registry.
//! This module never calls the lifecycle or performs transport/filesystem I/O.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::canonical::canonical_json;

pub const MAX_PERMIT_REQUESTS: usize = 1000;
pub const PERMIT_TTL_SECONDS: i64 = 600;
const MAX_REMEMBERED_WAITS: usize = 1000;
pub const NO_PASSPHRASE_REFUSAL: &str = "refused: kv gives approvals, passes and permits only on a passphrase-protected vault unlocked with its passphrase, and never uses one made without it. Run 'kv upgrade-security' if this vault has no passphrase, unlock with the passphrase, then approve again.";

/// Immutable inputs captured when the daemon establishes its trusted session.
/// Retain only the public owner key, never the owner's signing seed.
#[derive(Clone)]
pub struct SessionBinding {
    pub protected: bool,
    pub owner_public_key: Option<[u8; 32]>,
    pub owner_key_id: String,
    pub local_approval_id: Vec<u8>,
    pub location: Vec<u8>,
    pub session_nonce: [u8; 32],
    pub providers: Arc<BTreeMap<String, Value>>,
}

/// Clock inputs stay separate so wall-clock rollback cannot extend authority.
/// Implementations supply finite seconds; monotonic time must not move backward.
pub trait PermitClock: Send + Sync {
    fn wall_seconds(&self) -> f64;
    fn monotonic_seconds(&self) -> f64;
}

pub struct SystemPermitClock;
impl PermitClock for SystemPermitClock {
    fn wall_seconds(&self) -> f64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs_f64(),
            Err(error) => -error.duration().as_secs_f64(),
        }
    }
    fn monotonic_seconds(&self) -> f64 {
        static START: LazyLock<Instant> = LazyLock::new(Instant::now);
        START.elapsed().as_secs_f64()
    }
}

/// Borrowed broker preview plus the original caller headers. The URL is the
/// shown URL, including a literal hidden-auth placeholder where applicable.
pub struct CallFacts<'a> {
    pub environment: &'a str,
    pub provider: &'a str,
    pub provider_definition: &'a Value,
    pub method: &'a str,
    pub url: &'a str,
    pub header_names: &'a [String],
    pub caller_headers: &'a Map<String, Value>,
    pub body_bytes: Option<&'a [u8]>,
    /// A capability run's permit: the grant and run it belongs to (both or neither).
    pub grant_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    /// The owner's chosen wait for a capability run's permit, instead of the default TTL.
    pub wait_seconds: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermitError {
    pub code: &'static str,
    pub message: String,
}
impl PermitError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub(crate) fn refused(message: impl Into<String>) -> Self {
        Self::new("refused", message)
    }
}
impl fmt::Display for PermitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for PermitError {}

/// Facts are read-only copies. Only this module can create authority handles.
pub struct RequestCreated {
    facts: Value,
}
impl RequestCreated {
    pub fn request_id(&self) -> &str {
        self.facts["request_id"].as_str().expect("issued id")
    }
    pub fn permit_id(&self) -> &str {
        self.facts["permit_id"].as_str().expect("issued id")
    }
    pub fn facts(&self) -> &Value {
        &self.facts
    }
}

/// Owned review copy. Changing a caller's copy cannot alter the registry.
pub struct PermitReview {
    facts: Value,
    body_text: String,
    caller_headers: Map<String, Value>,
    requester: Option<Value>,
}
impl PermitReview {
    pub fn request_id(&self) -> &str {
        self.facts["request_id"].as_str().expect("issued id")
    }
    pub fn permit_id(&self) -> &str {
        self.facts["permit_id"].as_str().expect("issued id")
    }
    pub fn facts(&self) -> &Value {
        &self.facts
    }
    pub fn body_text(&self) -> &str {
        &self.body_text
    }
    pub fn caller_headers(&self) -> &Map<String, Value> {
        &self.caller_headers
    }
    pub fn requester(&self) -> Option<&Value> {
        self.requester.as_ref()
    }
}

pub struct MatchedPermit {
    permit_id: String,
    facts: Value,
    canonical: String,
}
impl MatchedPermit {
    pub fn permit_id(&self) -> &str {
        &self.permit_id
    }
    pub fn facts(&self) -> &Value {
        &self.facts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermitStatus {
    Available,
    Spent,
}
impl PermitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Spent => "spent",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStatus {
    Registered,
    AlreadyRegistered,
}
impl RegistrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::AlreadyRegistered => "already-registered",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialStatus {
    Denied,
    AlreadyDenied,
}
impl DenialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::AlreadyDenied => "already-denied",
        }
    }
}

pub struct Denial {
    pub status: DenialStatus,
    pub permit_id: String,
    pub request_id: String,
}

pub struct Registration {
    pub status: RegistrationStatus,
    pub permit_id: String,
    pub request_id: String,
    pub payload_digest: String,
}

pub struct PendingPermit {
    pub request_id: String,
    pub permit_id: String,
    pub provider: String,
    pub method: String,
    pub expires_at_epoch: i64,
}
impl PendingPermit {
    pub fn to_value(&self) -> Value {
        json!({"request_id":self.request_id,"permit_id":self.permit_id,
            "provider":self.provider,"method":self.method,"expires_at_epoch":self.expires_at_epoch})
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitOver {
    First,
    Again,
}

struct Pending {
    facts: Value,
    canonical: String,
    body_text: String,
    caller_headers: Map<String, Value>,
    requester: Option<Value>,
    mono_end: f64,
}
impl Pending {
    fn review(&self) -> PermitReview {
        PermitReview {
            facts: self.facts.clone(),
            body_text: self.body_text.clone(),
            caller_headers: self.caller_headers.clone(),
            requester: self.requester.clone(),
        }
    }
}
struct Registered {
    facts: Value,
    canonical: String,
    spent: bool,
    mono_end: f64,
}
#[derive(Default)]
struct Registry {
    requests: Vec<Pending>,
    permits: BTreeMap<String, Registered>,
    denied_permits: BTreeSet<String>,
    gave_up: VecDeque<(String, bool)>,
}
struct Inner {
    binding: SessionBinding,
    clock: Arc<dyn PermitClock>,
    state: Mutex<Registry>,
}

/// Clones share one session ledger. No method persists permit or request data.
#[derive(Clone)]
pub struct SessionPermits(Arc<Inner>);
impl SessionPermits {
    pub fn new(binding: SessionBinding) -> Self {
        Self::with_clock(binding, Arc::new(SystemPermitClock))
    }
    pub fn with_clock(binding: SessionBinding, clock: Arc<dyn PermitClock>) -> Self {
        Self(Arc::new(Inner {
            binding,
            clock,
            state: Mutex::new(Registry::default()),
        }))
    }
    fn state(&self) -> MutexGuard<'_, Registry> {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn protected(&self) -> Result<(), PermitError> {
        if self.0.binding.protected {
            Ok(())
        } else {
            Err(PermitError::new("no_passphrase", NO_PASSPHRASE_REFUSAL))
        }
    }
    pub fn request(
        &self,
        call: CallFacts<'_>,
        requester: Option<&Value>,
    ) -> Result<RequestCreated, PermitError> {
        self.protected()?;
        let now = self.0.clock.wall_seconds();
        let (request_id, permit_id) = new_ids()?;
        let (facts, body_text) =
            crate::permit_facts::build(&self.0.binding, &call, &request_id, &permit_id, now)?;
        let canonical = canonical(&facts)?;
        let mut state = self.state();
        self.prune(&mut state, now);
        if state.requests.len() >= MAX_PERMIT_REQUESTS {
            return Err(PermitError::refused(
                "the service's permit request records are full",
            ));
        }
        if state.requests.iter().any(|entry| {
            entry.facts["request_id"] == request_id || entry.facts["permit_id"] == permit_id
        }) || state.permits.contains_key(&permit_id)
        {
            return Err(PermitError::refused("duplicate permit request"));
        }
        let mono_end = self.0.clock.monotonic_seconds() + (expiry(&facts) - now);
        state.requests.push(Pending {
            facts: facts.clone(),
            canonical,
            body_text,
            caller_headers: call.caller_headers.clone(),
            requester: requester.cloned(),
            mono_end,
        });
        Ok(RequestCreated { facts })
    }
    pub fn review(&self, request_id: &str) -> Option<PermitReview> {
        let state = self.state();
        let entry = state
            .requests
            .iter()
            .find(|entry| entry.facts["request_id"] == request_id)?;
        let denied = state
            .denied_permits
            .contains(entry.facts["permit_id"].as_str().expect("issued id"));
        (!denied && !self.over(&entry.facts, entry.mono_end, self.0.clock.wall_seconds()))
            .then(|| entry.review())
    }
    pub fn review_by_permit(&self, permit_id: &str) -> Option<PermitReview> {
        let state = self.state();
        let entry = state
            .requests
            .iter()
            .find(|entry| entry.facts["permit_id"] == permit_id)?;
        let denied = state
            .denied_permits
            .contains(entry.facts["permit_id"].as_str().expect("issued id"));
        (!denied && !self.over(&entry.facts, entry.mono_end, self.0.clock.wall_seconds()))
            .then(|| entry.review())
    }
    pub fn pending(&self) -> Vec<PendingPermit> {
        let state = self.state();
        let now = self.0.clock.wall_seconds();
        state
            .requests
            .iter()
            .filter(|entry| {
                !self.over(&entry.facts, entry.mono_end, now)
                    && !state
                        .denied_permits
                        .contains(entry.facts["permit_id"].as_str().expect("issued id"))
                    && !state
                        .permits
                        .contains_key(entry.facts["permit_id"].as_str().expect("issued id"))
            })
            .map(|entry| PendingPermit {
                request_id: entry.facts["request_id"]
                    .as_str()
                    .expect("issued id")
                    .into(),
                permit_id: entry.facts["permit_id"].as_str().expect("issued id").into(),
                provider: entry.facts["provider"]
                    .as_str()
                    .expect("issued provider")
                    .into(),
                method: entry.facts["method"]
                    .as_str()
                    .expect("issued method")
                    .into(),
                expires_at_epoch: entry.facts["expires_at_epoch"]
                    .as_i64()
                    .expect("issued expiry"),
            })
            .collect()
    }
    /// Cheap refusal before the daemon reads a provider credential.
    pub fn precheck(&self, permit_id: Option<&Value>) -> Result<(), PermitError> {
        self.protected()?;
        let Some(permit_id) = permit_id else {
            return Ok(());
        };
        let permit_id = permit_id
            .as_str()
            .filter(|id| id.starts_with("permit_"))
            .ok_or_else(|| PermitError::refused("invalid permit id"))?;
        if self.is_denied(permit_id) {
            return Err(PermitError::refused("the owner denied this permit"));
        }
        if self.review_by_permit(permit_id).is_none() {
            return Err(PermitError::refused("permit request is missing or expired"));
        }
        if self.status(permit_id) == Some(PermitStatus::Spent) {
            return Err(PermitError::refused("permit already spent"));
        }
        Ok(())
    }
    pub fn match_call(
        &self,
        permit_id: &str,
        call: CallFacts<'_>,
    ) -> Result<MatchedPermit, PermitError> {
        self.protected()?;
        if self.is_denied(permit_id) {
            return Err(PermitError::refused("the owner denied this permit"));
        }
        if !permit_id.starts_with("permit_") {
            return Err(PermitError::refused("invalid permit id"));
        }
        let record = self
            .review_by_permit(permit_id)
            .ok_or_else(|| PermitError::refused("permit request is missing or expired"))?;
        let (request_id, fresh_permit_id) = new_ids()?;
        let (mut facts, _) = crate::permit_facts::build(
            &self.0.binding,
            &call,
            &request_id,
            &fresh_permit_id,
            self.0.clock.wall_seconds(),
        )?;
        for key in ["request_id", "permit_id", "expires_at_epoch"] {
            facts[key] = record.facts[key].clone();
        }
        let canonical = canonical(&facts)?;
        if canonical != canonical_json(&record.facts).expect("issued canonical facts") {
            return Err(PermitError::refused(
                "this call differs from the approved permit",
            ));
        }
        if self.status(permit_id) == Some(PermitStatus::Spent) {
            return Err(PermitError::refused("permit already spent"));
        }
        Ok(MatchedPermit {
            permit_id: permit_id.into(),
            facts,
            canonical,
        })
    }
    pub fn is_denied(&self, permit_id: &str) -> bool {
        self.state().denied_permits.contains(permit_id)
    }

    /// Register the owner's signed denial as terminal authority. A denied
    /// request is hidden from review/pending output, cannot be registered, and
    /// any unspent registered permit is revoked.
    pub fn deny(&self, artifact: &Value) -> Result<Denial, PermitError> {
        self.protected()?;
        let Some(public_key) = self.0.binding.owner_public_key else {
            return Err(PermitError::refused("owner permit denial is unavailable"));
        };
        let facts = crate::permit_denial::verified_permit_denial(
            self.0.binding.protected,
            &public_key,
            artifact,
        )
        .ok_or_else(|| PermitError::refused("invalid owner permit denial"))?;
        let Some(object) = facts.as_object() else {
            return Err(PermitError::refused("invalid owner permit denial"));
        };
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        if keys
            != [
                "local_approval_id",
                "location",
                "owner_key_id",
                "permit_id",
                "request_id",
                "session_nonce",
                "signer",
            ]
        {
            return Err(PermitError::refused("invalid owner permit denial"));
        }
        let text = |key: &str| facts.get(key).and_then(Value::as_str).unwrap_or("");
        let request_id = text("request_id");
        let permit_id = text("permit_id");
        if !request_id.starts_with("permit_request_") || !permit_id.starts_with("permit_") {
            return Err(PermitError::refused("invalid owner permit denial"));
        }
        let hex_encode = |bytes: &[u8]| hex::encode(bytes);
        if text("session_nonce") != hex_encode(&self.0.binding.session_nonce)
            || text("location") != hex_encode(&self.0.binding.location)
            || text("local_approval_id") != hex_encode(&self.0.binding.local_approval_id)
            || text("owner_key_id") != self.0.binding.owner_key_id
        {
            return Err(PermitError::refused(
                "the denial is not this session's request",
            ));
        }
        let mut state = self.state();
        let request = state
            .requests
            .iter()
            .find(|entry| {
                entry.facts["request_id"] == request_id && entry.facts["permit_id"] == permit_id
            })
            .ok_or_else(|| PermitError::new("unknown_request", "permit request is missing"))?;
        if state.denied_permits.contains(permit_id) {
            return Ok(Denial {
                status: DenialStatus::AlreadyDenied,
                permit_id: permit_id.into(),
                request_id: request_id.into(),
            });
        }
        if self.over(
            &request.facts,
            request.mono_end,
            self.0.clock.wall_seconds(),
        ) {
            return Err(PermitError::new("expired", "permit request expired"));
        }
        if let Some(existing) = state.permits.get(permit_id) {
            if existing.spent {
                return Err(PermitError::refused("permit already spent"));
            }
            state.permits.remove(permit_id);
        }
        state.denied_permits.insert(permit_id.into());
        Ok(Denial {
            status: DenialStatus::Denied,
            permit_id: permit_id.into(),
            request_id: request_id.into(),
        })
    }

    pub fn register(&self, artifact: &Value) -> Result<Registration, PermitError> {
        self.protected()?;
        let facts = crate::permit_facts::verify_artifact(&self.0.binding, artifact)?;
        let canonical = canonical(&facts)?;
        let mut state = self.state();
        let Some(permit_id) = facts["permit_id"].as_str() else {
            return Err(PermitError::new(
                "unknown_request",
                "the signed permit is not this session's request",
            ));
        };
        if state.denied_permits.contains(permit_id) {
            return Err(PermitError::new(
                "denied",
                "the owner denied this permit; it cannot be approved",
            ));
        }
        let request = state
            .requests
            .iter()
            .find(|entry| entry.facts["request_id"] == facts["request_id"])
            .filter(|entry| entry.canonical == canonical)
            .ok_or_else(|| {
                PermitError::new(
                    "unknown_request",
                    "the signed permit is not this session's request",
                )
            })?;
        if self.over(&facts, request.mono_end, self.0.clock.wall_seconds()) {
            return Err(PermitError::new("expired", "permit request expired"));
        }
        let mono_end = request.mono_end;
        let permit_id = facts["permit_id"].as_str().expect("matches issued facts");
        let status = if let Some(existing) = state.permits.get(permit_id) {
            if existing.canonical != canonical {
                return Err(PermitError::new(
                    "conflict",
                    "permit id already belongs to another request",
                ));
            }
            RegistrationStatus::AlreadyRegistered
        } else {
            state.permits.insert(
                permit_id.into(),
                Registered {
                    facts: facts.clone(),
                    canonical: canonical.clone(),
                    spent: false,
                    mono_end,
                },
            );
            RegistrationStatus::Registered
        };
        Ok(registration(&facts, &canonical, status))
    }
    /// Verified lost-ack lookup. Deliberately does not renew, refund, or expire.
    pub fn registered(&self, artifact: &Value) -> Result<Option<Registration>, PermitError> {
        self.protected()?;
        let facts = crate::permit_facts::verify_artifact(&self.0.binding, artifact)?;
        let canonical = canonical(&facts)?;
        let state = self.state();
        let Some(id) = facts["permit_id"].as_str() else {
            return Ok(None);
        };
        Ok(state
            .permits
            .get(id)
            .filter(|entry| entry.canonical == canonical)
            .map(|_| registration(&facts, &canonical, RegistrationStatus::AlreadyRegistered)))
    }
    /// Stored state only; authorization paths independently enforce both clocks.
    pub fn status(&self, permit_id: &str) -> Option<PermitStatus> {
        self.state().permits.get(permit_id).map(|entry| {
            if entry.spent {
                PermitStatus::Spent
            } else {
                PermitStatus::Available
            }
        })
    }
    /// Must run inside the daemon's lifecycle commit lock, immediately before send.
    pub fn spend(&self, matched: &MatchedPermit) -> Result<(), PermitError> {
        self.protected()?;
        let mut state = self.state();
        if state.denied_permits.contains(&matched.permit_id) {
            return Err(PermitError::refused("the owner denied this permit"));
        }
        let entry = state
            .permits
            .get_mut(&matched.permit_id)
            .ok_or_else(|| PermitError::refused("permit is missing"))?;
        if entry.spent {
            return Err(PermitError::refused("permit already spent"));
        }
        if entry.canonical != matched.canonical || entry.facts["permit_id"] != matched.permit_id {
            return Err(PermitError::refused(
                "this call differs from the approved permit",
            ));
        }
        if self.over(&entry.facts, entry.mono_end, self.0.clock.wall_seconds()) {
            return Err(PermitError::refused("permit expired"));
        }
        if !entry.facts["grant_id"].is_null() || !entry.facts["run_id"].is_null() {
            return Err(PermitError::refused(
                "this permit belongs to a capability run",
            ));
        }
        entry.spent = true;
        Ok(())
    }
    /// Python `spend_permit` for a capability run's call: the permit must have
    /// been signed for this very grant and run. The pass itself is the grant
    /// ledger's to check and debit.
    pub fn spend_for_run(
        &self,
        matched: &MatchedPermit,
        grant_id: &str,
        run_id: &str,
    ) -> Result<(), PermitError> {
        self.protected()?;
        let mut state = self.state();
        if state.denied_permits.contains(&matched.permit_id) {
            return Err(PermitError::refused("the owner denied this permit"));
        }
        let entry = state
            .permits
            .get_mut(&matched.permit_id)
            .ok_or_else(|| PermitError::refused("permit is missing"))?;
        if entry.spent {
            return Err(PermitError::refused("permit already spent"));
        }
        if entry.canonical != matched.canonical || entry.facts["permit_id"] != matched.permit_id {
            return Err(PermitError::refused(
                "this call differs from the approved permit",
            ));
        }
        if self.over(&entry.facts, entry.mono_end, self.0.clock.wall_seconds()) {
            return Err(PermitError::refused("permit expired"));
        }
        if entry.facts["grant_id"].as_str() != Some(grant_id)
            || entry.facts["run_id"].as_str() != Some(run_id)
        {
            return Err(PermitError::refused(
                "this permit belongs to another run or provider",
            ));
        }
        entry.spent = true;
        Ok(())
    }

    pub fn wait_over(&self, permit_id: &str) -> Option<WaitOver> {
        let mut state = self.state();
        if state.permits.contains_key(permit_id) {
            return None;
        }
        if let Some(record) = state
            .requests
            .iter()
            .find(|entry| entry.facts["permit_id"] == permit_id)
        {
            if !self.over(&record.facts, record.mono_end, self.0.clock.wall_seconds()) {
                return None;
            }
            remember_gave_up(&mut state, permit_id);
        }
        let (_, told) = state.gave_up.iter_mut().find(|(id, _)| id == permit_id)?;
        if *told {
            Some(WaitOver::Again)
        } else {
            *told = true;
            Some(WaitOver::First)
        }
    }
    fn over(&self, facts: &Value, mono_end: f64, now: f64) -> bool {
        expiry(facts) <= now || self.0.clock.monotonic_seconds() >= mono_end
    }
    fn prune(&self, state: &mut Registry, now: f64) {
        let mut index = 0;
        while index < state.requests.len() {
            let entry = &state.requests[index];
            if self.over(&entry.facts, entry.mono_end, now) {
                let entry = state.requests.remove(index);
                let id = entry.facts["permit_id"].as_str().expect("issued id");
                if !state.permits.contains_key(id) {
                    remember_gave_up(state, id);
                }
            } else {
                index += 1;
            }
        }
        state
            .permits
            .retain(|_, entry| !self.over(&entry.facts, entry.mono_end, now));
    }
}

fn canonical(facts: &Value) -> Result<String, PermitError> {
    canonical_json(facts)
        .map_err(|_| PermitError::refused("body or call cannot be shown in full safely"))
}
fn expiry(facts: &Value) -> f64 {
    facts["expires_at_epoch"].as_i64().expect("issued expiry") as f64
}
fn registration(facts: &Value, canonical: &str, status: RegistrationStatus) -> Registration {
    use sha2::{Digest, Sha256};
    Registration {
        status,
        permit_id: facts["permit_id"].as_str().expect("issued id").into(),
        request_id: facts["request_id"].as_str().expect("issued id").into(),
        payload_digest: hex::encode(Sha256::digest(canonical.as_bytes())),
    }
}
fn new_ids() -> Result<(String, String), PermitError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| PermitError::refused("operating-system randomness unavailable"))?;
    // Match the reference's independent 16-byte permit and request identifiers.
    Ok((
        format!("permit_request_{}", hex::encode(&bytes[16..])),
        format!("permit_{}", hex::encode(&bytes[..16])),
    ))
}
fn remember_gave_up(state: &mut Registry, permit_id: &str) {
    if !state.gave_up.iter().any(|(id, _)| id == permit_id) {
        state.gave_up.push_back((permit_id.into(), false));
    }
    while state.gave_up.len() > MAX_REMEMBERED_WAITS {
        state.gave_up.pop_front();
    }
}

#[cfg(all(test, unix))]
use crate::test_harness;

#[cfg(test)]
mod tests;
