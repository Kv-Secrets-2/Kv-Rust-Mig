//! Live comparison of grants, admission and capability tokens with Python 0.4.0.
//!
//! Python makes a passphrase vault with a protected service session and runs
//! the shared scenario; Rust joins the same session (owner seed, session nonce,
//! keys of that throwaway vault) and runs the scenario on the same vault, then
//! Python checks what Rust wrote.

#![cfg(unix)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use kv_approvals::owner::{OwnerGrantFields, OwnerSeed, attach_owner_approval, owner_public_key};
use kv_approvals::permit_session::SessionBinding;
use kv_approvals::verify::RunFacts;
use kv_grants::capabilities::{
    ConsumeOptions, TokenListFlags, consume_capability_token, list_capability_tokens,
    revoke_capability_token,
};
use kv_grants::grants::{
    CreateGrant, GrantContext, GrantError, ListFlags, RunRequest, admit_run_grant,
    create_run_grant, explain_run_grant_mismatch, find_matching_run_grant, list_run_grants,
    prune_expired_run_grants, revoke_run_grant, valid_grant,
};
use kv_grants::ledger::Ledger;
use kv_grants::normalize::InvalidValue;
use kv_grants::store::{StoreKind, read_records};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const STRIP: [&str; 13] = [
    "command_fingerprint",
    "script_sha256",
    "script_ref_hash",
    "grant_id",
    "token",
    "token_id",
    "token_hash",
    "admission_id",
    "grant_artifact_id",
    "owner_approval",
    "state_integrity",
    "token_integrity",
    "_verified",
];

fn h(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn public(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(k, _)| !STRIP.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), public(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(public).collect()),
        other => other.clone(),
    }
}

fn outcome<T: Into<Value>>(result: Result<T, GrantError>) -> Value {
    match result {
        Ok(value) => json!({"ok": public(&value.into())}),
        Err(GrantError::Spent {
            message,
            spent,
            error_type,
            ..
        }) => json!({"spent": {"message": message, "spent": spent, "error_type": error_type}}),
        Err(GrantError::Invalid(e)) => json!({"error": "ValueError", "message": e.message()}),
        Err(GrantError::Store(e)) => json!({"error": e.python_type(), "message": e.message()}),
        Err(GrantError::Refused(e)) => {
            json!({"error": "AdmissionRefused", "message": e.message()})
        }
    }
}

fn identity(side: &str, tag: &str) -> Value {
    json!({
        "command_fingerprint": h(&format!("{side}:{tag}")),
        "run_id": "run-1",
        "script_kind": "python",
        "script_sha256": h(&format!("{side}:script")),
        "script_ref_hash": h(&format!("{side}:ref")),
    })
}

fn actor() -> Value {
    json!({"source": "mcp", "client_name": "claude", "client_version": "1.0",
           "session_id": "s1", "user_id": "u1"})
}

fn providers() -> BTreeMap<String, Value> {
    [
        (
            "openai".to_owned(),
            json!({"base_url": "https://api.openai.com/", "auth": {"header": "Authorization",
                   "scheme": "Bearer", "secret": "OPENAI_API_KEY"}}),
        ),
        (
            "github".to_owned(),
            json!({"base_url": "https://api.github.com/", "auth": {"header": "Authorization",
                   "scheme": "token", "secret": "GITHUB_TOKEN"}}),
        ),
    ]
    .into_iter()
    .collect()
}

fn run_python(python: &Path, home: &Path, input: &Value) -> Value {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/grants_probe.py");
    let mut child = Command::new(python)
        .arg(&script)
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "python probe failed");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

struct Creation {
    name: &'static str,
    request: CreateGrant,
}

fn creation_cases(cwd: &str) -> Vec<Creation> {
    let wallet = json!([
        {"provider": "openai", "rule_id": "r1", "rule_digest": "a".repeat(64), "calls": 2},
        {"provider": "openai", "rule_id": "r0", "rule_digest": "b".repeat(64), "calls": 1},
    ]);
    let c = |name: &'static str, request: CreateGrant| Creation { name, request };
    vec![
        c(
            "secret_once",
            CreateGrant {
                secret_names: Some(json!(["OPENAI_API_KEY"])),
                reason: Some(json!("r1")),
                ttl_seconds: Some(json!(300)),
                ..Default::default()
            },
        ),
        c(
            "two_services",
            CreateGrant {
                capability_names: Some(json!(["api:openai", "api:github"])),
                calls_per_service: Some(json!({"api:openai": 2, "api:github": null})),
                max_calls: Some(json!(2)),
                usage_mode: Some(json!("reusable")),
                max_runs: Some(json!(3)),
                when_spent: Some(json!("pause")),
                owner_wait_seconds: Some(json!(60)),
                ttl_seconds: Some(json!(600)),
                ..Default::default()
            },
        ),
        c(
            "wallet",
            CreateGrant {
                capability_names: Some(json!(["api:openai"])),
                post_wallet: Some(wallet.clone()),
                max_calls: Some(json!(3)),
                ttl_seconds: Some(json!(300)),
                ..Default::default()
            },
        ),
        c(
            "single_card",
            CreateGrant {
                capability_names: Some(json!(["api:openai"])),
                max_calls: Some(json!(5)),
                ttl_seconds: Some(json!(300)),
                risk_card: Some(json!({"version": 1, "generator": "kv_risk_card_v1",
                    "facts": {"argv": ["python3", "app.py"], "cwd": cwd}})),
                ..Default::default()
            },
        ),
        c(
            "empty_scope",
            CreateGrant {
                reason: Some(json!("x")),
                ..Default::default()
            },
        ),
        c(
            "bad_mode",
            CreateGrant {
                secret_names: Some(json!(["A"])),
                usage_mode: Some(json!("weird")),
                ..Default::default()
            },
        ),
        c(
            "runs_on_once",
            CreateGrant {
                secret_names: Some(json!(["A"])),
                max_runs: Some(json!(2)),
                ..Default::default()
            },
        ),
        c(
            "zero_ttl",
            CreateGrant {
                secret_names: Some(json!(["A"])),
                ttl_seconds: Some(json!(0)),
                ..Default::default()
            },
        ),
        c(
            "ends_past",
            CreateGrant {
                secret_names: Some(json!(["A"])),
                ends_at_epoch: Some(json!(5)),
                ..Default::default()
            },
        ),
        c(
            "counts_no_cap",
            CreateGrant {
                secret_names: Some(json!(["A"])),
                calls_per_service: Some(json!({"api:x": 1})),
                ..Default::default()
            },
        ),
        c(
            "bad_when",
            CreateGrant {
                capability_names: Some(json!(["api:openai"])),
                when_spent: Some(json!("later")),
                owner_wait_seconds: Some(json!(5)),
                ..Default::default()
            },
        ),
        c(
            "wallet_secret",
            CreateGrant {
                secret_names: Some(json!(["A"])),
                capability_names: Some(json!(["api:openai"])),
                post_wallet: Some(wallet.clone()),
                ..Default::default()
            },
        ),
        c(
            "wallet_total",
            CreateGrant {
                capability_names: Some(json!(["api:openai"])),
                post_wallet: Some(wallet),
                max_calls: Some(json!(9)),
                ..Default::default()
            },
        ),
        c(
            "actor_field",
            CreateGrant {
                secret_names: Some(json!(["A"])),
                actor: Some(json!({"source": "x", "bogus": 1})),
                ..Default::default()
            },
        ),
        c(
            "one_service_counts",
            CreateGrant {
                capability_names: Some(json!(["api:openai"])),
                calls_per_service: Some(json!({"api:openai": 2})),
                ..Default::default()
            },
        ),
    ]
}

fn maps(value: Vec<Map<String, Value>>) -> Value {
    Value::Array(value.into_iter().map(Value::Object).collect())
}

fn owned(grant: Map<String, Value>) -> Value {
    Value::Object(grant)
}

fn admission_value(result: Option<kv_grants::grants::Admission>) -> Value {
    match result {
        None => Value::Null,
        Some(admission) => {
            let mut map = admission.grant;
            if let Some(token) = admission.issued_capability {
                map.insert("_issued_capability".into(), Value::Object(token));
            }
            Value::Object(map)
        }
    }
}

struct Side<'a> {
    ctx: &'a GrantContext<'a>,
    now: i64,
    side: &'static str,
    base: &'a Path,
    providers: BTreeMap<String, Value>,
}

impl Side<'_> {
    fn ident(&self, tag: &str) -> Value {
        identity(self.side, tag)
    }

    fn mine(&self, records: Vec<Map<String, Value>>) -> Vec<Map<String, Value>> {
        let fingerprint = self.ident("cmd1")["command_fingerprint"].clone();
        records
            .into_iter()
            .filter(|r| r.get("command_fingerprint") == Some(&fingerprint))
            .collect()
    }

    fn request(&self, scope: &Value, ident: &Value, actor: &Value) -> RunRequest {
        RunRequest::normalize(
            ident,
            scope.get("secret_names"),
            scope.get("capability_names"),
            Some(actor),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn consume(
        &self,
        token: &str,
        ident: &Value,
        capability: &str,
        env: &str,
        charge: bool,
        allow_spent: bool,
        wallet_entry: Option<&str>,
    ) -> Value {
        let actor = actor();
        let env = json!(env);
        let provider = capability.strip_prefix("api:").unwrap_or("");
        let config = self.providers.get(provider);
        let options = ConsumeOptions {
            actor: Some(&actor),
            env_name: Some(&env),
            require_parent: true,
            provider_config: config,
            charge,
            allow_spent,
            wallet_entry,
        };
        match consume_capability_token(
            self.ctx,
            &json!(token),
            ident,
            &json!(capability),
            self.now,
            options,
        ) {
            Ok(consumed) => json!({"ok": public(&json!([
                consumed.record.map(Value::Object),
                consumed.denial,
            ]))}),
            Err(error) => outcome::<Value>(Err(error)),
        }
    }
}

fn scenario(side: &Side<'_>, seed: &OwnerSeed, facts: &Value) -> (Value, Vec<String>) {
    let ctx = side.ctx;
    let now = side.now;
    let digests: Value = side
        .providers
        .iter()
        .map(|(name, d)| {
            (
                name.clone(),
                json!(kv_approvals::wire::provider_digest(d).unwrap()),
            )
        })
        .collect::<Map<String, Value>>()
        .into();
    let counter = Cell::new(0u32);
    let local_approval_id = hex_bytes(&facts["local_approval_id"]);
    let location = hex_bytes(&facts["location"]);
    let nonce = hex_bytes(&facts["session_nonce"]);
    let key_id = facts["owner_key_id"].as_str().unwrap();
    let sign = |grant: Map<String, Value>| -> Result<Map<String, Value>, InvalidValue> {
        counter.set(counter.get() + 1);
        let request_id = format!("approval_{}_{}", side.side, counter.get());
        let fields = OwnerGrantFields {
            request_id: &request_id,
            request_digest: &h(&request_id),
            request_expires_at_epoch: grant["expires_at_epoch"].clone(),
            local_approval_id: &local_approval_id,
            location: &location,
            owner_key_id: key_id,
            environment: "dev",
            network: json!(false),
            network_reason: json!("test"),
            max_runs: grant.get("max_runs").cloned().unwrap_or(Value::Null),
            calls_per_run: grant.get("max_calls").cloned().unwrap_or(Value::Null),
            provider_digests: &digests,
            session_nonce: &nonce,
        };
        attach_owner_approval(&Value::Object(grant), seed, &fields)
            .map(|v| v.as_object().cloned().unwrap())
            .map_err(|e| InvalidValue::new(e.to_string()))
    };
    let ident = side.ident("cmd1");
    let cwd_a = side.base.join("cwd_a").to_string_lossy().into_owned();
    let cwd_b = side.base.join("cwd_b").to_string_lossy().into_owned();
    let mut out = Map::new();
    let mut created = Vec::new();
    for case in creation_cases(&cwd_a) {
        let mut request = case.request;
        if request.actor.is_none() {
            request.actor = Some(actor());
        }
        let result = create_run_grant(ctx, &ident, &request, Some(&sign), now).map(owned);
        created.push(json!([case.name, outcome(result)]));
    }
    out.insert("created".into(), Value::Array(created));
    let all = ListFlags {
        include_expired: true,
        include_revoked: true,
        include_consumed: true,
    };
    let listed = side.mine(list_run_grants(ctx, all, now).unwrap());
    let ids: Vec<String> = listed
        .iter()
        .map(|g| g["grant_id"].as_str().unwrap().to_owned())
        .collect();
    out.insert("ids".into(), json!(ids));
    out.insert("listed".into(), public(&maps(listed)));
    let index = |found: Option<Map<String, Value>>| -> Value {
        found
            .and_then(|g| {
                ids.iter()
                    .position(|id| Some(id.as_str()) == g["grant_id"].as_str())
            })
            .map(|i| json!(i))
            .unwrap_or(Value::Null)
    };
    let scopes: Vec<(&str, Value)> = vec![
        ("secret_once", json!({"secret_names": ["OPENAI_API_KEY"]})),
        (
            "two_services",
            json!({"capability_names": ["api:openai", "api:github"]}),
        ),
        ("wallet", json!({"capability_names": ["api:openai"]})),
        ("single_card", json!({"capability_names": ["api:openai"]})),
    ];
    let act = actor();
    let mut find = Map::new();
    for (name, scope) in &scopes {
        let request = side.request(scope, &ident, &act);
        find.insert(
            (*name).to_owned(),
            index(find_matching_run_grant(ctx, &request, now, None).unwrap()),
        );
    }
    out.insert("find".into(), Value::Object(find));
    let facts_for = |env: &str| RunFacts {
        env_name: Some(env.to_owned()),
        secret_names: vec![],
        capability_names: vec![json!("api:openai")],
    };
    let wallet_scope = &scopes[2].1;
    out.insert(
        "find_run".into(),
        json!([
            index(
                find_matching_run_grant(
                    ctx,
                    &side.request(wallet_scope, &ident, &act),
                    now,
                    Some(&facts_for("dev"))
                )
                .unwrap()
            ),
            index(
                find_matching_run_grant(
                    ctx,
                    &side.request(wallet_scope, &ident, &act),
                    now,
                    Some(&facts_for("prod"))
                )
                .unwrap()
            ),
            index(
                find_matching_run_grant(
                    ctx,
                    &side.request(&scopes[0].1, &ident, &json!({"source": "other"})),
                    now,
                    None
                )
                .unwrap()
            ),
        ]),
    );
    let other = {
        let mut o = ident.as_object().cloned().unwrap();
        o.insert(
            "command_fingerprint".into(),
            json!(h(&format!("{}:cmd2", side.side))),
        );
        Value::Object(o)
    };
    let app = ["python3".to_owned(), "app.py".to_owned()];
    let ls = ["ls".to_owned()];
    let cap = json!({"capability_names": ["api:openai"]});
    let sec = json!({"secret_names": ["OTHER"]});
    out.insert(
        "explain".into(),
        json!([
            explain_run_grant_mismatch(
                ctx,
                &side.request(&cap, &other, &act),
                Some(&cwd_a),
                Some(&app),
                now
            )
            .unwrap(),
            explain_run_grant_mismatch(
                ctx,
                &side.request(&cap, &other, &act),
                Some(&cwd_b),
                Some(&app),
                now
            )
            .unwrap(),
            explain_run_grant_mismatch(
                ctx,
                &side.request(&sec, &other, &act),
                Some(&cwd_a),
                Some(&app),
                now
            )
            .unwrap(),
            explain_run_grant_mismatch(
                ctx,
                &side.request(&sec, &other, &act),
                Some(&cwd_b),
                Some(&ls),
                now
            )
            .unwrap(),
        ]),
    );
    let mut steps: Vec<Value> = Vec::new();
    let two = json!({"capability_names": ["api:openai", "api:github"]});
    let admit = |scope: &Value, env: Option<&str>| {
        admit_run_grant(ctx, &side.request(scope, &ident, &act), env, now)
    };
    let token_of = |value: &Value| -> String {
        value["ok"]["_issued_capability"]["token"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_default()
    };
    let admitted = admit(&two, Some("dev"));
    let raw_token = admitted
        .as_ref()
        .ok()
        .and_then(|a| a.as_ref())
        .and_then(|a| a.issued_capability.as_ref())
        .and_then(|t| t.get("token"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    let token_id = admitted
        .as_ref()
        .ok()
        .and_then(|a| a.as_ref())
        .and_then(|a| a.issued_capability.as_ref())
        .and_then(|t| t.get("token_id"))
        .cloned()
        .unwrap_or(Value::Null);
    steps.push(json!(["admit_two", outcome(admitted.map(admission_value))]));
    let _ = token_of;
    let c = |name: &str,
             cap: &str,
             env: &str,
             ident_: &Value,
             charge: bool,
             spent: bool,
             entry: Option<&str>,
             token: &str| {
        json!([
            name,
            side.consume(token, ident_, cap, env, charge, spent, entry)
        ])
    };
    steps.push(c(
        "c_openai_1",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        None,
        &raw_token,
    ));
    steps.push(c(
        "c_github",
        "api:github",
        "dev",
        &ident,
        true,
        false,
        None,
        &raw_token,
    ));
    steps.push(c(
        "c_openai_2",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        None,
        &raw_token,
    ));
    steps.push(c(
        "c_openai_3",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        None,
        &raw_token,
    ));
    steps.push(c(
        "c_stripe",
        "api:stripe",
        "dev",
        &ident,
        true,
        false,
        None,
        &raw_token,
    ));
    steps.push(c(
        "c_prod",
        "api:openai",
        "prod",
        &ident,
        true,
        false,
        None,
        &raw_token,
    ));
    steps.push(c(
        "c_other_cmd",
        "api:openai",
        "dev",
        &other,
        true,
        false,
        None,
        &raw_token,
    ));
    steps.push(c(
        "c_inspect",
        "api:openai",
        "dev",
        &ident,
        false,
        true,
        None,
        &raw_token,
    ));
    let all_tokens = TokenListFlags {
        include_expired: true,
        include_consumed: true,
        include_revoked: true,
    };
    steps.push(json!([
        "tokens",
        outcome(list_capability_tokens(ctx, all_tokens, now).map(|t| maps(side.mine(t))))
    ]));
    steps.push(json!([
        "revoke_token",
        outcome(revoke_capability_token(
            ctx,
            &token_id,
            Some(&json!("done")),
            now
        ))
    ]));
    steps.push(c(
        "c_revoked",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        None,
        &raw_token,
    ));
    steps.push(json!([
        "admit_two_again",
        outcome(admit(&two, Some("dev")).map(admission_value))
    ]));
    steps.push(json!([
        "revoke_two",
        outcome(revoke_run_grant(
            ctx,
            &ids[1],
            Some(&json!("stop")),
            now,
            "immediate"
        ))
    ]));
    steps.push(json!([
        "revoke_two_again",
        outcome(revoke_run_grant(ctx, &ids[1], None, now, "future"))
    ]));
    steps.push(json!([
        "admit_two_revoked",
        outcome(admit(&two, Some("dev")).map(admission_value))
    ]));
    steps.push(json!([
        "admit_secret",
        outcome(admit(&scopes[0].1, None).map(admission_value))
    ]));
    steps.push(json!([
        "admit_secret_again",
        outcome(admit(&scopes[0].1, None).map(admission_value))
    ]));
    let wallet_admitted = admit(wallet_scope, Some("dev"));
    let wallet_token = wallet_admitted
        .as_ref()
        .ok()
        .and_then(|a| a.as_ref())
        .and_then(|a| a.issued_capability.as_ref())
        .and_then(|t| t.get("token"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    steps.push(json!([
        "admit_wallet",
        outcome(wallet_admitted.map(admission_value))
    ]));
    steps.push(c(
        "w_r1",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        Some("api:openai/r1"),
        &wallet_token,
    ));
    steps.push(c(
        "w_r0_a",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        Some("api:openai/r0"),
        &wallet_token,
    ));
    steps.push(c(
        "w_r0_b",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        Some("api:openai/r0"),
        &wallet_token,
    ));
    steps.push(c(
        "w_none",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        None,
        &wallet_token,
    ));
    steps.push(c(
        "w_wrong",
        "api:openai",
        "dev",
        &ident,
        true,
        false,
        Some("api:github/r1"),
        &wallet_token,
    ));
    steps.push(json!([
        "listed_after",
        outcome(list_run_grants(ctx, all, now).map(|g| maps(side.mine(g))))
    ]));
    let others = read_records(ctx.root, StoreKind::Grants).unwrap().len()
        - side
            .mine(read_records(ctx.root, StoreKind::Grants).unwrap())
            .len();
    steps.push(json!([
        "prune",
        outcome(prune_expired_run_grants(ctx, now).map(|n| json!(n - others)))
    ]));
    steps.push(json!([
        "tokens_after",
        outcome(list_capability_tokens(ctx, all_tokens, now).map(|t| maps(side.mine(t))))
    ]));
    out.insert("steps".into(), Value::Array(steps));
    (Value::Object(out), ids)
}

fn diff(path: &str, want: &Value, got: &Value, out: &mut Vec<String>) {
    match (want, got) {
        (Value::Object(w), Value::Object(g)) => {
            for key in w.keys().chain(g.keys().filter(|k| !w.contains_key(*k))) {
                let sub = format!("{path}.{key}");
                match (w.get(key), g.get(key)) {
                    (Some(a), Some(b)) => diff(&sub, a, b, out),
                    (a, b) => out.push(format!("{sub}\n  python: {a:?}\n  rust:   {b:?}")),
                }
            }
        }
        (Value::Array(w), Value::Array(g)) if w.len() == g.len() => {
            for (i, (a, b)) in w.iter().zip(g).enumerate() {
                diff(&format!("{path}[{i}]"), a, b, out);
            }
        }
        _ if want == got => {}
        _ => out.push(format!("{path}\n  python: {want}\n  rust:   {got}")),
    }
}

/// The vault-origin records both sides consult live under `HOME`, so the
/// comparison runs in a child of this test binary whose `HOME` is a fresh
/// directory shared with the Python probe.
#[test]
fn grants_and_tokens_match_python() {
    let Some(base) = std::env::var_os("KV_GRANTS_PARITY_BASE") else {
        let Some(python) = kv_test_support::python_reference() else {
            return;
        };
        let tmp = tempfile::Builder::new()
            .prefix("kvgrants")
            .tempdir()
            .unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let home = base.join("home");
        std::fs::create_dir(&home).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "grants_and_tokens_match_python",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("HOME", &home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("KV_PY_REF", python)
            .env("KV_GRANTS_PARITY_BASE", &base)
            .output()

            .unwrap();
        assert!(
            output.status.success(),
            "the comparison failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };
    let base = PathBuf::from(base);
    let home = base.join("home");
    let python = PathBuf::from(std::env::var_os("KV_PY_REF").unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let providers = providers();
    let python_out = run_python(
        &python,
        &home,
        &json!({"mode": "scenario", "base": base, "now": now, "providers": providers}),
    );
    let facts = &python_out["facts"];
    let root = PathBuf::from(facts["root"].as_str().unwrap());
    let seed = OwnerSeed::from_slice(&hex_bytes(&facts["seed"])).unwrap();
    let public_key = owner_public_key(&seed);
    assert_eq!(
        hex::encode(public_key),
        facts["owner_public_key"].as_str().unwrap()
    );
    let binding = SessionBinding {
        protected: true,
        owner_public_key: Some(public_key),
        owner_key_id: facts["owner_key_id"].as_str().unwrap().to_owned(),
        local_approval_id: hex_bytes(&facts["local_approval_id"]),
        location: hex_bytes(&facts["location"]),
        session_nonce: hex_bytes(&facts["session_nonce"]).try_into().unwrap(),
        providers: Arc::new(providers.clone()),
    };
    let signing_key = hex_bytes(&facts["signing_key"]);
    let state_key = hex_bytes(&facts["state_key"]);
    let ledger = Ledger::new();
    let ctx = GrantContext {
        root: &root,
        signing_key: &signing_key,
        state_key: &state_key,
        binding: &binding,
        ledger: &ledger,
        providers: &providers,
    };
    // Rust joins the session: Python's grants are valid here and its tokens sealed.
    let python_ids: Vec<String> = python_out["results"]["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let stored = read_records(&root, StoreKind::Grants).unwrap();
    for id in &python_ids {
        let grant = stored
            .iter()
            .find(|g| g["grant_id"].as_str() == Some(id))
            .expect("python grant stored");
        assert!(
            valid_grant(&ctx, grant, None),
            "python grant {id} valid in rust"
        );
    }
    let py_ident = identity("py", "cmd1");
    let found = find_matching_run_grant(
        &ctx,
        &RunRequest::normalize(
            &py_ident,
            Some(&json!(["OPENAI_API_KEY"])),
            None,
            Some(&actor()),
        )
        .unwrap(),
        now,
        None,
    )
    .unwrap()
    .expect("python's secret grant matches in rust");
    assert_eq!(found["grant_id"].as_str(), Some(python_ids[0].as_str()));
    for token in read_records(&root, StoreKind::Tokens).unwrap() {
        assert!(
            kv_approvals::artifacts::verify_token_integrity(
                &Value::Object(token.clone()),
                &signing_key
            ),
            "python token sealed for rust"
        );
    }

    let side = Side {
        ctx: &ctx,
        now,
        side: "rs",
        base: &base,
        providers: providers.clone(),
    };
    let (rust_out, rust_ids) = scenario(&side, &seed, facts);
    let mut mismatches = Vec::new();
    let mut want = python_out["results"].clone();
    let mut got = rust_out;
    want.as_object_mut().unwrap().remove("ids");
    got.as_object_mut().unwrap().remove("ids");
    diff("results", &want, &got, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "{} grant results differ from Python:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );

    // Python rejoins the session and checks what Rust wrote.
    let cross = run_python(
        &python,
        &home,
        &json!({"mode": "cross", "base": base, "now": now, "providers": providers,
                "root": root, "session_nonce": facts["session_nonce"], "grant_ids": rust_ids,
                "identity": identity("rs", "cmd1"), "scope": {"secret_names": ["OPENAI_API_KEY"]}}),
    );
    for id in &rust_ids {
        assert_eq!(
            cross["valid"][id],
            json!(true),
            "rust grant {id} valid in python"
        );
        assert_eq!(
            cross["state"][id],
            json!(true),
            "rust grant {id} state seal in python"
        );
    }
    let tokens = cross["tokens"].as_array().unwrap();
    assert!(
        !tokens.is_empty() && tokens.iter().all(|t| *t == json!(true)),
        "rust tokens sealed for python: {tokens:?}"
    );
    assert_eq!(cross["found"].as_str(), Some(rust_ids[0].as_str()));
}
