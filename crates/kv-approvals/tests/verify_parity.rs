//! Live comparison of the approval verifier core against Python 0.4.0
//! (`kv/approval_verify.py`): Rust signs the grants, both sides verify them.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use kv_approvals::owner::{OwnerGrantFields, OwnerSeed, attach_owner_approval};
use kv_approvals::permit_session::SessionBinding;
use kv_approvals::verify::{
    MAX_COUNT, RunFacts, VerifiedGrant, from_payload, payload_digest, post_wallet_binding,
    run_mismatch, signed_payload, split_wallet_entry_key, valid_entry_counts,
};
use serde_json::{Map, Value, json};

fn fixture() -> Value {
    serde_json::from_slice(include_bytes!("../../../fixtures/v0.4.0/approvals.json")).unwrap()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

struct Session {
    seed: OwnerSeed,
    public_key: [u8; 32],
    key_id: String,
    local_approval_id: Vec<u8>,
    location: Vec<u8>,
    nonce: [u8; 32],
}

impl Session {
    fn load(root: &Value) -> Self {
        let inputs = &root["inputs"];
        Self {
            seed: OwnerSeed::from_slice(&hex_bytes(&inputs["seed"])).unwrap(),
            public_key: hex_bytes(&root["owner_public_key"]).try_into().unwrap(),
            key_id: root["owner_key_id"].as_str().unwrap().to_owned(),
            local_approval_id: hex_bytes(&inputs["local_approval_id"]),
            location: hex_bytes(&inputs["location"]),
            nonce: hex_bytes(&inputs["session_nonce"]).try_into().unwrap(),
        }
    }

    fn binding(&self, providers: BTreeMap<String, Value>) -> SessionBinding {
        SessionBinding {
            protected: true,
            owner_public_key: Some(self.public_key),
            owner_key_id: self.key_id.clone(),
            local_approval_id: self.local_approval_id.clone(),
            location: self.location.clone(),
            session_nonce: self.nonce,
            providers: Arc::new(providers),
        }
    }

    fn ctx_json(&self) -> Value {
        json!({
            "protected": true,
            "owner_public_key": hex::encode(self.public_key),
            "local_approval_id": hex::encode(&self.local_approval_id),
            "location": hex::encode(&self.location),
            "owner_key_id": self.key_id,
            "session_nonce": hex::encode(self.nonce),
        })
    }

    fn sign(&self, grant: &Value, environment: &str, max_runs: Value, nonce: &[u8]) -> Value {
        let digests = json!({"openai": "3".repeat(64), "github": "4".repeat(64)});
        let fields = OwnerGrantFields {
            request_id: "req_0001",
            request_digest: &"d".repeat(64),
            request_expires_at_epoch: json!(1793503600),
            local_approval_id: &self.local_approval_id,
            location: &self.location,
            owner_key_id: &self.key_id,
            environment,
            network: json!(false),
            network_reason: Value::Null,
            max_runs,
            calls_per_run: Value::Null,
            provider_digests: &digests,
            session_nonce: nonce,
        };
        attach_owner_approval(grant, &self.seed, &fields).unwrap()
    }
}

fn base_grant(nonce: &[u8]) -> Value {
    json!({
        "grant_id": "grant_0001",
        "created_at_epoch": 1793500000,
        "expires_at_epoch": 1793503600,
        "created_from_run_id": "run_42",
        "command_fingerprint": "a".repeat(64),
        "script_kind": "file",
        "script_sha256": "b".repeat(64),
        "script_ref_hash": null,
        "secret_names": [],
        "capability_names": ["api:openai"],
        "actor": {"name": "agent", "pid": 7},
        "risk_card": {},
        "max_calls": 3,
        "usage_mode": "once",
        "session_nonce": hex::encode(nonce),
        "status": "active",
    })
}

fn with(grant: &Value, edits: Value) -> Value {
    let mut out = grant.as_object().unwrap().clone();
    for (key, value) in edits.as_object().unwrap() {
        if value.is_null() && key.starts_with('-') {
            out.remove(&key[1..]);
        } else {
            out.insert(key.clone(), value.clone());
        }
    }
    Value::Object(out)
}

fn wallet(entries: &[(&str, &str, i64)]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|(p, r, c)| {
                json!({"provider": p, "rule_id": r, "rule_digest": "c".repeat(64), "calls": c})
            })
            .collect(),
    )
}

fn signed_cases(session: &Session) -> Vec<Value> {
    let nonce = session.nonce;
    let base = base_grant(&nonce);
    let one_wallet = wallet(&[("openai", "chat", 3)]);
    let two_wallet = wallet(&[("github", "issues", 1), ("openai", "chat", 2)]);
    let mut cases = vec![
        session.sign(&base, "dev", Value::Null, &nonce),
        session.sign(
            &with(&base, json!({"capability_names": [], "secret_names": ["A", "B"], "-max_calls": null})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(&with(&base, json!({"post_wallet": one_wallet})), "*", Value::Null, &nonce),
        session.sign(
            &with(&base, json!({"post_wallet": one_wallet, "max_calls": 4})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"post_wallet": one_wallet, "secret_names": ["A"]})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"post_wallet": one_wallet, "calls_per_service": {"api:openai": 3}})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(
                &base,
                json!({"post_wallet": two_wallet, "capability_names": ["api:github", "api:openai"]}),
            ),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(
                &base,
                json!({"post_wallet": two_wallet, "capability_names": ["api:openai", "api:github"]}),
            ),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"post_wallet": wallet(&[("openai", "chat", 2), ("github", "issues", 1)]), "capability_names": ["api:github", "api:openai"]})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"post_wallet": wallet(&[("openai", "chat", 2), ("openai", "chat", 1)])})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"post_wallet": [{"calls": 3, "rule": "api:openai/chat"}]})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(&with(&base, json!({"post_wallet": []})), "dev", Value::Null, &nonce),
        session.sign(
            &with(&base, json!({"when_spent": "pause", "owner_wait_seconds": 120})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"when_spent": "end", "owner_wait_seconds": 1})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"when_spent": "bogus", "owner_wait_seconds": 0})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"when_spent": null, "owner_wait_seconds": true})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"owner_wait_seconds": "120"})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"owner_wait_seconds": -5, "when_spent": "pause"})),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(
                &base,
                json!({"capability_names": ["api:github", "api:openai"], "max_calls": 5,
                       "calls_per_service": {"api:github": 2, "api:openai": 3}}),
            ),
            "dev",
            Value::Null,
            &nonce,
        ),
        session.sign(
            &with(&base, json!({"usage_mode": "reusable", "max_runs": 4})),
            "dev",
            json!(4),
            &nonce,
        ),
        session.sign(&base, "dev", Value::Null, &[9u8; 32]),
        with(&session.sign(&base, "dev", Value::Null, &nonce), json!({"max_calls": 9})),
        with(&session.sign(&base, "dev", Value::Null, &nonce), json!({"-owner_approval": null})),
        with(&session.sign(&base, "dev", Value::Null, &nonce), json!({"post_rule": {"x": 1}})),
        json!({}),
        json!([]),
        json!("grant"),
    ];
    let other = OwnerSeed::from_slice(&hex_bytes(&fixture()["inputs"]["other_seed"])).unwrap();
    let foreign = Session {
        seed: other,
        public_key: session.public_key,
        key_id: session.key_id.clone(),
        local_approval_id: session.local_approval_id.clone(),
        location: session.location.clone(),
        nonce,
    };
    cases.push(foreign.sign(&base, "dev", Value::Null, &nonce));
    cases
}

fn wallet_cases() -> Vec<Value> {
    let many: Vec<Value> = (0..17)
        .map(|i| json!({"provider": format!("p{i:02}"), "rule_id": "r", "rule_digest": "c".repeat(64), "calls": 1}))
        .collect();
    vec![
        Value::Null,
        json!([]),
        json!({}),
        json!("api:openai/chat"),
        Value::Array(many.clone()),
        Value::Array(many[..16].to_vec()),
        wallet(&[("openai", "chat", 1)]),
        wallet(&[("a", "b", 1), ("a", "c", 2), ("b", "a", MAX_COUNT)]),
        wallet(&[("a", "c", 1), ("a", "b", 2)]),
        wallet(&[("a", "b", 1), ("a", "b", 2)]),
        wallet(&[("a", "b", 0)]),
        wallet(&[("a", "b", -1)]),
        wallet(&[("a", "b", MAX_COUNT + 1)]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "c".repeat(64), "calls": 2.0}]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "c".repeat(64), "calls": true}]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "c".repeat(64), "calls": "2"}]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "C".repeat(64), "calls": 2}]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "c".repeat(63), "calls": 2}]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "c".repeat(65), "calls": 2}]),
        json!([{"provider": "-a", "rule_id": "b", "rule_digest": "c".repeat(64), "calls": 2}]),
        json!([{"provider": "a".repeat(64), "rule_id": "b", "rule_digest": "c".repeat(64), "calls": 2}]),
        json!([{"provider": "a".repeat(65), "rule_id": "b", "rule_digest": "c".repeat(64), "calls": 2}]),
        json!([{"provider": "ünï", "rule_id": "b", "rule_digest": "c".repeat(64), "calls": 2}]),
        json!([{"provider": "a", "rule_id": "b/c", "rule_digest": "c".repeat(64), "calls": 2}]),
        json!([{"provider": "a", "rule_id": "", "rule_digest": "c".repeat(64), "calls": 2}]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "c".repeat(64), "calls": 2, "extra": 1}]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "c".repeat(64)}]),
        json!([{"provider": 1, "rule_id": "b", "rule_digest": "c".repeat(64), "calls": 2}]),
        json!([["a", "b", "c", 1]]),
        json!([null]),
        json!([{"provider": "a", "rule_id": "b", "rule_digest": "c".repeat(64), "calls": 2}, 5]),
    ]
}

fn entry_count_cases() -> Vec<Value> {
    let record = json!({"max_calls": 3, "capability_names": ["api:openai"]});
    let two = json!({"max_calls": 3, "capability_names": ["api:github", "api:openai"]});
    let big: Map<String, Value> = (0..17)
        .map(|i| (format!("api:p{i:02}/r"), json!(1)))
        .collect();
    vec![
        json!({"per_entry": {"api:openai/chat": 3}, "record": record}),
        json!({"per_entry": {"api:openai/chat": 2, "api:openai/embed": 1}, "record": record}),
        json!({"per_entry": {"api:openai/chat": 2}, "record": record}),
        json!({"per_entry": {"api:openai/chat": 2, "api:github/x": 1}, "record": record}),
        json!({"per_entry": {"api:openai/chat": 2, "api:github/x": 1}, "record": two}),
        json!({"per_entry": {"api:github/x": 1, "api:openai/chat": 2}, "record": {"max_calls": 3, "capability_names": ["api:openai", "api:github"]}}),
        json!({"per_entry": {}, "record": record}),
        json!({"per_entry": Value::Object(big), "record": {"max_calls": 17, "capability_names": (0..17).map(|i| format!("api:p{i:02}")).collect::<Vec<_>>()}}),
        json!({"per_entry": {"api:openai/chat": 0}, "record": {"max_calls": 0, "capability_names": ["api:openai"]}}),
        json!({"per_entry": {"api:openai/chat": 3.0}, "record": record}),
        json!({"per_entry": {"api:openai/chat": true}, "record": {"max_calls": 1, "capability_names": ["api:openai"]}}),
        json!({"per_entry": {"openai/chat": 3}, "record": record}),
        json!({"per_entry": {"api:openai": 3}, "record": record}),
        json!({"per_entry": ["api:openai/chat"], "record": record}),
        json!({"per_entry": {"api:openai/chat": 3}, "record": {"max_calls": 3}}),
        json!({"per_entry": {"api:openai/chat": 3}, "record": {"max_calls": 3, "capability_names": null}}),
        json!({"per_entry": {"api:openai/chat": 3}, "record": {"max_calls": "3", "capability_names": ["api:openai"]}}),
        json!({"per_entry": {"api:openai/chat": 3}, "record": {"max_calls": 3.0, "capability_names": ["api:openai"]}}),
        json!({"per_entry": {"api:openai/chat": MAX_COUNT}, "record": {"max_calls": MAX_COUNT, "capability_names": ["api:openai"]}}),
        json!({"per_entry": {"api:openai/chat": MAX_COUNT, "api:openai/x": 1}, "record": {"max_calls": MAX_COUNT + 1, "capability_names": ["api:openai"]}}),
    ]
}

fn mismatch_cases(definition: &Value, digest: &str) -> Vec<Value> {
    let run = |env: Value, caps: Vec<&str>| json!({"env_name": env, "secret_names": [], "capability_names": caps});
    let snapshot = json!({"openai": definition});
    let good = json!({"environment": "dev", "provider_digests": {"openai": digest}});
    vec![
        json!({"payload": good, "run": run(json!("dev"), vec!["api:openai"]), "snapshot": snapshot}),
        json!({"payload": good, "run": run(json!("prod"), vec!["api:openai"]), "snapshot": snapshot}),
        json!({"payload": good, "run": run(Value::Null, vec![]), "snapshot": snapshot}),
        json!({"payload": good, "run": run(json!(""), vec![]), "snapshot": snapshot}),
        json!({"payload": {"environment": "*", "provider_digests": {"openai": digest}}, "run": run(Value::Null, vec!["api:openai"]), "snapshot": snapshot}),
        json!({"payload": {"environment": "*", "provider_digests": {"openai": digest}}, "run": run(json!("x"), vec![]), "snapshot": snapshot}),
        json!({"payload": {"environment": null, "provider_digests": {}}, "run": run(json!("dev"), vec![]), "snapshot": snapshot}),
        json!({"payload": {"environment": 5, "provider_digests": {}}, "run": run(json!("dev"), vec![]), "snapshot": snapshot}),
        json!({"payload": {"environment": "dev"}, "run": run(json!("dev"), vec![]), "snapshot": snapshot}),
        json!({"payload": {"environment": "dev", "provider_digests": []}, "run": run(json!("dev"), vec![]), "snapshot": snapshot}),
        json!({"payload": {"environment": "dev", "provider_digests": {}}, "run": run(json!("dev"), vec![]), "snapshot": snapshot}),
        json!({"payload": good, "run": run(json!("dev"), vec!["api:github"]), "snapshot": snapshot}),
        json!({"payload": good, "run": run(json!("dev"), vec!["ssh:host"]), "snapshot": snapshot}),
        json!({"payload": good, "run": run(json!("dev"), vec!["api:openai", "api:openai"]), "snapshot": snapshot}),
        json!({"payload": {"environment": "dev", "provider_digests": {"openai": "0".repeat(64)}}, "run": run(json!("dev"), vec!["api:openai"]), "snapshot": snapshot}),
        json!({"payload": good, "run": run(json!("dev"), vec!["api:openai"]), "snapshot": {}}),
        json!({"payload": good, "run": run(json!("dev"), vec!["api:openai"]), "snapshot": {"openai": {"origin": 5}}}),
        json!({"payload": good, "run": run(json!("dev"), vec!["api:openai"]), "snapshot": {"openai": {"origin": "https://api.openai.com", "secret_name": "K", "rules": []}}}),
        json!({"payload": good, "run": run(json!("dev"), vec!["api:openai"]), "snapshot": {"openai": null}}),
        json!({"payload": good, "run": {"env_name": "dev", "secret_names": ["A"], "capability_names": [7]}, "snapshot": snapshot}),
    ]
}

fn split_key_cases() -> Vec<Value> {
    json!([
        "api:openai/chat",
        "api:a/b/c",
        "api:/b",
        "api:a/",
        "API:a/b",
        "openai/chat",
        "",
        "api:a.b-c_d/r.1",
        format!("api:{}/r", "a".repeat(64)),
        format!("api:{}/r", "a".repeat(65)),
        "api:-a/b",
        "api:a/-b",
        "api:ünï/b",
        null,
        5,
        ["api:a/b"],
        "api:a/b\n",
        " api:a/b"
    ])
    .as_array()
    .unwrap()
    .clone()
}

fn verified_json(verified: &VerifiedGrant) -> Value {
    json!({
        "grant_id": verified.grant_id,
        "artifact_id": verified.artifact_id,
        "request_id": verified.request_id,
        "payload_digest": verified.payload_digest,
        "session_nonce": verified.session_nonce,
        "environment": verified.environment,
        "secret_names": verified.secret_names,
        "capability_names": verified.capability_names,
        "network": verified.network,
        "provider_digests": verified.provider_digests.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "protected": verified.protected,
        "post_wallet": verified.post_wallet.as_ref().map(|entries| {
            entries.iter().map(|e| json!([e.provider, e.rule_id, e.rule_digest, e.calls])).collect::<Vec<_>>()
        }),
        "when_spent": verified.when_spent,
        "owner_wait_seconds": verified.owner_wait_seconds,
    })
}

#[test]
fn verifier_core_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let root = fixture();
    let session = Session::load(&root);
    let definition = root["provider_digest"]["definition"].clone();
    let digest = root["provider_digest"]["digest"].as_str().unwrap();
    let signed = signed_cases(&session);
    let wallets = wallet_cases();
    let entry_counts = entry_count_cases();
    let mismatch = mismatch_cases(&definition, digest);
    let split_keys = split_key_cases();
    let case = json!({
        "ctx": session.ctx_json(), "signed": signed, "wallets": wallets,
        "entry_counts": entry_counts, "mismatch": mismatch, "split_keys": split_keys,
    });
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/verify_probe.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(case.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let want: Value = serde_json::from_slice(&output.stdout).unwrap();

    let mut mismatches = Vec::new();
    let mut check = |label: String, got: Value, want: &Value| {
        if got != *want {
            mismatches.push(format!("{label}\n  python: {want}\n  rust:   {got}"));
        }
    };

    let binding = session.binding(BTreeMap::new());
    let mut accepted = 0;
    for (i, grant) in signed.iter().enumerate() {
        let got = match signed_payload(&binding, grant) {
            None => Value::Null,
            Some(payload) => {
                let payload_value = Value::Object(payload.clone());
                let digest = payload_digest(&payload_value).unwrap();
                let mut out = json!({"payload": payload_value, "digest": digest});
                match from_payload(&payload, &digest) {
                    Ok(verified) => {
                        accepted += 1;
                        out["ok"] = verified_json(&verified);
                    }
                    Err(refused) => {
                        out["error"] = json!(refused.message());
                        out["code"] = json!(refused.code());
                    }
                }
                out
            }
        };
        check(format!("signed[{i}]"), got, &want["signed"][i]);
    }
    assert!(accepted >= 8, "only {accepted} signed grants were accepted");

    for (i, scope) in wallets.iter().enumerate() {
        let got = match post_wallet_binding(Some(scope)) {
            Ok(None) => json!({"ok": null}),
            Ok(Some(entries)) => {
                json!({"ok": entries.iter().map(|e| json!([e.provider, e.rule_id, e.rule_digest, e.calls])).collect::<Vec<_>>()})
            }
            Err(refused) => json!({"error": refused.message(), "code": refused.code()}),
        };
        check(format!("wallets[{i}] {scope}"), got, &want["wallets"][i]);
    }
    assert_eq!(
        post_wallet_binding(None).unwrap(),
        None,
        "an absent scope binds to no wallet"
    );

    for (i, item) in entry_counts.iter().enumerate() {
        let got = json!(valid_entry_counts(
            &item["per_entry"],
            item["record"].as_object().unwrap()
        ));
        check(
            format!("entry_counts[{i}] {item}"),
            got,
            &want["entry_counts"][i],
        );
    }

    for (i, item) in mismatch.iter().enumerate() {
        let run = RunFacts {
            env_name: item["run"]["env_name"].as_str().map(str::to_owned),
            secret_names: item["run"]["secret_names"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect(),
            capability_names: item["run"]["capability_names"].as_array().unwrap().clone(),
        };
        let snapshot: BTreeMap<String, Value> = item["snapshot"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let got = json!(run_mismatch(
            item["payload"].as_object().unwrap(),
            &run,
            &snapshot
        ));
        check(format!("mismatch[{i}] {item}"), got, &want["mismatch"][i]);
    }

    for (i, key) in split_keys.iter().enumerate() {
        let got = json!(split_wallet_entry_key(key).map(|(p, r)| json!([p, r])));
        check(
            format!("split_keys[{i}] {key}"),
            got,
            &want["split_keys"][i],
        );
    }

    assert!(
        mismatches.is_empty(),
        "{} verifier results differ from Python:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
