use super::*;
use crate::owner::{OwnerSeed, owner_key_id, owner_public_key};

struct Clock(Mutex<(f64, f64)>);
impl Clock {
    fn set(&self, wall: f64, mono: f64) {
        *self.0.lock().unwrap() = (wall, mono);
    }
}
impl PermitClock for Clock {
    fn wall_seconds(&self) -> f64 {
        self.0.lock().unwrap().0
    }
    fn monotonic_seconds(&self) -> f64 {
        self.0.lock().unwrap().1
    }
}

struct Fixture {
    registry: SessionPermits,
    clock: Arc<Clock>,
    seed: OwnerSeed,
    provider: Value,
    headers: Map<String, Value>,
    names: Vec<String>,
}
impl Fixture {
    fn new() -> Self {
        let seed = OwnerSeed::new([37; 32]);
        let public = owner_public_key(&seed);
        let provider = json!({"base_url":"https://permit-fixture.example","secret_name":"TOKEN","auth_type":"bearer"});
        let clock = Arc::new(Clock(Mutex::new((1000.25, 20.0))));
        let local = vec![7; 16];
        let binding = SessionBinding {
            protected: true,
            owner_public_key: Some(public),
            owner_key_id: owner_key_id(&public, &local),
            local_approval_id: local,
            location: b"/fixture/vault".to_vec(),
            session_nonce: [9; 32],
            providers: Arc::new(BTreeMap::from([("example".into(), provider.clone())])),
        };
        Self {
            registry: SessionPermits::with_clock(binding, clock.clone()),
            clock,
            seed,
            provider,
            headers: Map::new(),
            names: vec!["Authorization".into(), "Content-Type".into()],
        }
    }
    fn call(&self) -> CallFacts<'_> {
        CallFacts {
            environment: "dev",
            provider: "example",
            provider_definition: &self.provider,
            method: "POST",
            url: "https://permit-fixture.example/api",
            header_names: &self.names,
            caller_headers: &self.headers,
            body_bytes: Some(b"{\"amount\":1}"),
        }
    }
    fn request(&self) -> RequestCreated {
        self.registry
            .request(
                self.call(),
                Some(&json!({"agent":"test","agent_reason":null})),
            )
            .ok()
            .unwrap()
    }
    fn artifact(&self, request: &RequestCreated) -> Value {
        crate::permit::attach_permit_approval(request.facts(), &self.seed).unwrap()
    }
    fn approve(&self, request: &RequestCreated) -> Value {
        let artifact = self.artifact(request);
        assert_eq!(
            self.registry.register(&artifact).ok().unwrap().status,
            RegistrationStatus::Registered
        );
        artifact
    }
}
fn error<T>(result: Result<T, PermitError>) -> PermitError {
    match result {
        Ok(_) => panic!("expected refusal"),
        Err(error) => error,
    }
}

#[test]
fn request_review_pending_and_spending_preserve_exact_owned_facts() {
    let fixture = Fixture::new();
    let request = fixture.request();
    assert_eq!(request.facts()["expires_at_epoch"], 1600);
    assert_eq!(request.facts()["grant_id"], Value::Null);
    assert_eq!(request.facts()["run_id"], Value::Null);
    assert_eq!(fixture.registry.pending().len(), 1);
    let review = fixture.registry.review(request.request_id()).unwrap();
    assert_eq!(review.body_text(), "{\"amount\":1}");
    assert_eq!(
        review.requester().unwrap(),
        &json!({"agent":"test","agent_reason":null})
    );
    let mut exported = review.facts().clone();
    exported["method"] = json!("DELETE");
    assert_eq!(
        fixture
            .registry
            .review(request.request_id())
            .unwrap()
            .facts()["method"],
        "POST"
    );
    let artifact = fixture.approve(&request);
    assert!(fixture.registry.pending().is_empty());
    assert!(
        fixture.registry.review(request.request_id()).is_some(),
        "registration retains the body record"
    );
    let matched = fixture
        .registry
        .match_call(request.permit_id(), fixture.call())
        .ok()
        .unwrap();
    fixture.registry.spend(&matched).unwrap();
    assert_eq!(
        fixture.registry.status(request.permit_id()),
        Some(PermitStatus::Spent)
    );
    assert_eq!(
        fixture.registry.register(&artifact).ok().unwrap().status,
        RegistrationStatus::AlreadyRegistered
    );
    assert_eq!(
        error(fixture.registry.spend(&matched)).message,
        "permit already spent"
    );
}

#[test]
fn expiry_uses_fractional_initial_lifetime_and_both_clocks_without_renewal() {
    let fixture = Fixture::new();
    let request = fixture.request();
    fixture.clock.set(1500.0, 500.0);
    let artifact = fixture.approve(&request);
    let matched = fixture
        .registry
        .match_call(request.permit_id(), fixture.call())
        .ok()
        .unwrap();
    fixture.clock.set(999.0, 619.749);
    assert!(fixture.registry.review(request.request_id()).is_some());
    fixture.clock.set(999.0, 619.75);
    assert!(fixture.registry.review(request.request_id()).is_none());
    assert_eq!(
        error(fixture.registry.spend(&matched)).message,
        "permit expired"
    );
    assert_eq!(error(fixture.registry.register(&artifact)).code, "expired");
    assert_eq!(
        fixture.registry.status(request.permit_id()),
        Some(PermitStatus::Available)
    );
    assert_eq!(
        fixture
            .registry
            .registered(&artifact)
            .ok()
            .flatten()
            .unwrap()
            .status,
        RegistrationStatus::AlreadyRegistered
    );

    let other = Fixture::new();
    let request = other.request();
    let artifact = other.approve(&request);
    other.clock.set(1600.0, 20.0);
    assert_eq!(error(other.registry.register(&artifact)).code, "expired");
    assert!(other.registry.review(request.request_id()).is_none());
}

#[test]
fn altered_retry_fails_without_spending_and_final_debit_is_atomic() {
    let fixture = Fixture::new();
    let request = fixture.request();
    fixture.approve(&request);
    let mut changed = fixture.call();
    changed.body_bytes = Some(b"{\"amount\":2}");
    assert_eq!(
        error(fixture.registry.match_call(request.permit_id(), changed)).message,
        "this call differs from the approved permit"
    );
    assert_eq!(
        fixture.registry.status(request.permit_id()),
        Some(PermitStatus::Available)
    );
    let matched = Arc::new(
        fixture
            .registry
            .match_call(request.permit_id(), fixture.call())
            .ok()
            .unwrap(),
    );
    let gate = Arc::new(std::sync::Barrier::new(16));
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let registry = fixture.registry.clone();
            let matched = matched.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                registry.spend(&matched)
            })
        })
        .collect();
    let answers: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(answers.iter().filter(|answer| answer.is_ok()).count(), 1);
    assert!(
        answers
            .into_iter()
            .filter_map(Result::err)
            .all(|error| error.message == "permit already spent")
    );
}

#[test]
fn capacity_includes_registered_records_and_prunes_before_insertion() {
    let fixture = Fixture::new();
    let first = fixture.request();
    fixture.approve(&first);
    let waiting = fixture.request();
    for _ in 2..MAX_PERMIT_REQUESTS {
        fixture.request();
    }
    assert_eq!(
        error(fixture.registry.request(fixture.call(), None)).message,
        "the service's permit request records are full"
    );
    assert_eq!(fixture.registry.pending().len(), MAX_PERMIT_REQUESTS - 1);
    fixture.clock.set(1700.0, 720.0);
    let fresh = fixture.request();
    assert_eq!(fixture.registry.pending().len(), 1);
    assert_eq!(fixture.registry.pending()[0].permit_id, fresh.permit_id());
    assert_eq!(fixture.registry.status(first.permit_id()), None);
    assert_eq!(fixture.registry.wait_over(first.permit_id()), None);
    assert_eq!(
        fixture.registry.wait_over(waiting.permit_id()),
        Some(WaitOver::First)
    );
    assert_eq!(
        fixture.registry.wait_over(waiting.permit_id()),
        Some(WaitOver::Again)
    );
    assert!(fixture.registry.state().gave_up.len() <= MAX_REMEMBERED_WAITS);
}

#[test]
fn signature_session_provider_and_request_checks_preserve_error_precedence() {
    let fixture = Fixture::new();
    let request = fixture.request();
    for (field, value, code) in [
        ("location", json!("00"), "not_signed"),
        ("session_nonce", json!("00"), "not_signed"),
        ("owner_key_id", json!("other"), "not_signed"),
        ("provider_digest", json!("0".repeat(64)), "provider_changed"),
        ("grant_id", json!("grant_other"), "unknown_request"),
        ("body_present", json!(1), "unknown_request"),
        ("expires_at_epoch", json!(1601), "unknown_request"),
    ] {
        let mut facts = request.facts().clone();
        facts[field] = value;
        let artifact = crate::permit::attach_permit_approval(&facts, &fixture.seed).unwrap();
        assert_eq!(
            error(fixture.registry.register(&artifact)).code,
            code,
            "{field}"
        );
    }
    let mut facts = request.facts().clone();
    facts["extra"] = json!(true);
    assert_eq!(
        error(
            fixture
                .registry
                .register(&crate::permit::attach_permit_approval(&facts, &fixture.seed).unwrap())
        )
        .code,
        "not_signed"
    );
    assert_eq!(fixture.registry.status(request.permit_id()), None);
    fixture.approve(&request);
}

#[test]
fn precheck_and_unprotected_session_fail_before_call_preparation() {
    let fixture = Fixture::new();
    for value in [Value::Null, json!(true), json!(1), json!("other")] {
        assert_eq!(
            error(fixture.registry.precheck(Some(&value))).message,
            "invalid permit id"
        );
    }
    assert!(fixture.registry.precheck(None).is_ok());
    assert_eq!(
        error(fixture.registry.precheck(Some(&json!("permit_missing")))).message,
        "permit request is missing or expired"
    );
    let mut binding = fixture.registry.0.binding.clone();
    binding.protected = false;
    let unprotected = SessionPermits::with_clock(binding, fixture.clock.clone());
    assert_eq!(error(unprotected.precheck(None)).code, "no_passphrase");
    assert_eq!(
        error(unprotected.request(fixture.call(), None)).message,
        NO_PASSPHRASE_REFUSAL
    );
    assert_eq!(
        error(unprotected.register(&Value::Null)).code,
        "no_passphrase"
    );
    assert!(unprotected.pending().is_empty());
}

#[test]
fn absent_and_empty_bodies_are_distinct_even_with_equal_digest() {
    let fixture = Fixture::new();
    let mut call = fixture.call();
    call.body_bytes = None;
    let absent = fixture.registry.request(call, None).ok().unwrap();
    let mut call = fixture.call();
    call.body_bytes = Some(b"");
    let empty = fixture.registry.request(call, None).ok().unwrap();
    assert_eq!(absent.facts()["body_sha256"], empty.facts()["body_sha256"]);
    assert_eq!(absent.facts()["body_present"], false);
    assert_eq!(empty.facts()["body_present"], true);
}

fn pending_json(registry: &SessionPermits) -> Value {
    Value::Array(
        registry
            .pending()
            .iter()
            .map(PendingPermit::to_value)
            .collect(),
    )
}
fn review_json(registry: &SessionPermits, id: &str) -> Value {
    registry.review(id).map_or(Value::Null, |record| {
        json!({"facts":record.facts(),"body_text":record.body_text(),
        "caller_headers":record.caller_headers(),"requester":record.requester()})
    })
}
fn registration_json(result: Result<Registration, PermitError>) -> Value {
    match result {
        Ok(record) => json!([record.status.as_str(), record.permit_id]),
        Err(error) => json!({"error":error.message,"code":error.code}),
    }
}

#[test]
#[cfg(unix)]
fn permit_registry_transitions_and_signature_spelling_match_python() {
    use std::process::Command;
    use std::time::Duration;
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let fixture = Fixture::new();
    let request = fixture.request();
    let artifact = fixture.artifact(&request);
    let mut actual = vec![
        pending_json(&fixture.registry),
        review_json(&fixture.registry, request.request_id()),
    ];
    actual.push(registration_json(fixture.registry.register(&artifact)));
    actual.push(pending_json(&fixture.registry));
    let matched = fixture
        .registry
        .match_call(request.permit_id(), fixture.call())
        .ok()
        .unwrap();
    fixture.registry.spend(&matched).unwrap();
    actual.push(json!(
        fixture
            .registry
            .status(request.permit_id())
            .unwrap()
            .as_str()
    ));
    actual.push(registration_json(fixture.registry.register(&artifact)));
    let refused = error(fixture.registry.spend(&matched));
    actual.push(json!({"error":refused.message,"code":refused.code}));
    fixture.clock.set(999.0, 619.75);
    actual.push(review_json(&fixture.registry, request.request_id()));
    actual.push(registration_json(fixture.registry.register(&artifact)));
    actual.push(json!(
        fixture
            .registry
            .registered(&artifact)
            .ok()
            .flatten()
            .unwrap()
            .permit_id
    ));
    actual.push(json!(
        fixture
            .registry
            .status(request.permit_id())
            .unwrap()
            .as_str()
    ));
    fixture.clock.set(1700.0, 720.0);
    let fresh = fixture.request();
    actual.push(pending_json(&fixture.registry));
    actual.push(json!(
        fixture
            .registry
            .registered(&artifact)
            .ok()
            .flatten()
            .map(|record| record.permit_id)
    ));

    let signature = artifact["signature"].as_str().unwrap();
    let mut spellings = Vec::new();
    for space in [" ", "\t", "\n", "\r", "\u{000b}", "\u{000c}", "\u{00a0}"] {
        for split in [1, 2] {
            let mut changed = artifact.clone();
            changed["signature"] = json!(format!(
                "{}{}{}",
                &signature[..split],
                space,
                &signature[split..]
            ));
            spellings.push(changed);
        }
    }
    let public = owner_public_key(&fixture.seed);
    let verified: Vec<bool> = spellings
        .iter()
        .map(|artifact| crate::permit::verified_permit_payload(true, &public, artifact).is_some())
        .collect();
    let payload = json!({"facts":request.facts(),"fresh":fresh.facts(),"artifact":artifact,"spellings":spellings,
        "public":hex::encode(public),"provider":fixture.provider,"header_names":fixture.names});
    let script = r#"
import json,sys,types
from kv import approval_verify as v, approval_signing as signing
x=json.load(sys.stdin); clock=[1000.25,20.0]
v.time.time=lambda:clock[0]; v.time.monotonic=lambda:clock[1]
r=v.GrantRegistry(); f=x['facts']; fresh=x['fresh']; artifact=x['artifact']
ctx=types.SimpleNamespace(protected=True,owner_public_key=bytes.fromhex(x['public']),local_approval_id=bytes.fromhex(f['local_approval_id']),location=bytes.fromhex(f['location']),owner_key_id=f['owner_key_id'],session_nonce=bytes.fromhex(f['session_nonce']),provider_snapshot={'example':x['provider']},grant_registry=r,observe=lambda:None)
requester={'agent':'test','agent_reason':None}; body='{"amount":1}'
r.add_permit_request(f,body,{},requester=requester,now=clock[0])
def reg():
    try:return v.register_permit(ctx,artifact,now=clock[0])
    except v.AdmissionRefused as e:return {'error':str(e),'code':e.code}
out=[r.pending_permits(),r.permit_request(f['request_id']),reg(),r.pending_permits()]
matched=v.permit_for_call(ctx,f['permit_id'],environment='dev',provider='example',provider_definition=x['provider'],method='POST',url='https://permit-fixture.example/api',header_names=x['header_names'],caller_headers={},body_bytes=body.encode(),grant_id=None,run_id=None)
v.spend_permit(ctx,f['permit_id'],matched)
out += [r.permit_status(f['permit_id']),reg()]
try:v.spend_permit(ctx,f['permit_id'],matched)
except v.AdmissionRefused as e:out.append({'error':str(e),'code':e.code})
clock[:]=[999.0,619.75]
out += [r.permit_request(f['request_id']),reg(),v.registered_permit(ctx,artifact),r.permit_status(f['permit_id'])]
clock[:]=[1700.0,720.0]
r.add_permit_request(fresh,body,{},requester=requester,now=clock[0])
out += [r.pending_permits(),v.registered_permit(ctx,artifact)]
print(json.dumps({'transcript':out,'verified':[signing.verified_permit_payload(ctx,a) is not None for a in x['spellings']]}))
"#;
    let mut command = Command::new(python);
    command.args(["-I", "-c", script]);
    let output = test_harness::output(
        command,
        &serde_json::to_vec(&payload).unwrap(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json!(actual), expected["transcript"]);
    assert_eq!(json!(verified), expected["verified"]);
}
