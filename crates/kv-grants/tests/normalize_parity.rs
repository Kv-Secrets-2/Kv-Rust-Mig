//! Live comparison of grant field normalization against Python 0.4.0 (`kv/grants.py`).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_grants::normalize::{
    LATEST_EPOCH, MAX_COUNT, actor_matches, check_count, check_seconds, is_expired, is_revoked,
    iso, normalize_actor, normalize_grant_id, normalize_reason, normalize_run_identity,
    normalize_scope_list, normalize_service_calls, script_identity_matches, validate_hash,
    waiting_after_end,
};
use serde_json::{Value, json};

fn ok_or_error<T: serde::Serialize>(
    result: Result<T, kv_grants::normalize::InvalidValue>,
) -> Value {
    match result {
        Ok(value) => json!({"ok": value}),
        Err(error) => json!({"error": error.message()}),
    }
}

fn hash(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

#[test]
fn normalization_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let fp = hash('a');
    let identity = json!([
        null, [], "x", 5,
        {},
        {"command_fingerprint": fp},
        {"command_fingerprint": fp.to_uppercase(), "run_id": "r".repeat(100), "script_kind": "k".repeat(50),
         "script_sha256": hash('B'), "script_ref_hash": hash('c'), "extra": 1},
        {"command_fingerprint": fp, "run_id": "", "script_kind": "", "script_sha256": null, "script_ref_hash": null},
        {"command_fingerprint": fp, "run_id": 7, "script_kind": ["x"], "script_sha256": ""},
        {"command_fingerprint": fp, "script_sha256": "g".repeat(64)},
        {"command_fingerprint": fp, "script_ref_hash": "a".repeat(63)},
        {"command_fingerprint": fp, "script_ref_hash": 12},
        {"command_fingerprint": 12},
        {"command_fingerprint": "a".repeat(65)},
        {"command_fingerprint": null},
        {"command_fingerprint": fp, "run_id": "ü".repeat(90), "script_kind": "ünï"},
    ]);
    let scope = json!([
        null,
        [],
        "name",
        {},
        5,
        ["b", "a", "b", " c "],
        ["", "a"],
        ["  ", "a"],
        [1],
        [null],
        ["a", ["b"]],
        ["x".repeat(256)],
        ["x".repeat(257)],
        ["ü".repeat(128)],
        ["ü".repeat(129)],
        ["B", "a", "A", "b"],
        ["\u{a0}pad\u{a0}", "pad"],
        ["tab\t", "tab"],
        ["ünï", "uni"],
    ]);
    let actor = json!([
        null, {}, [], "agent", 3,
        {"source": "mcp", "client_name": " Claude ", "client_version": "1.0", "session_id": "s", "user_id": "u", "pid": 7, "name": "x"},
        {"source": "", "client_name": "   ", "client_version": 5, "session_id": null, "user_id": ["u"]},
        {"source": "x".repeat(200), "client_name": "ü".repeat(200)},
        {"source": "\u{a0}spaced\u{a0}"},
    ]);
    let actor_match = json!([
        [{}, {}], [{}, null], [{}, "x"], [null, {}], ["x", {}],
        [{"source": "a"}, {"source": "a"}], [{"source": "a"}, {"source": "a", "extra": 1}],
        [{"source": "a"}, {"source": "b"}], [{"source": "a"}, {}], [{"source": "a", "user_id": "u"}, {"source": "a"}],
        [{"source": null}, {"source": null}], [{"source": null}, {}], [{"source": 1}, {"source": 1.0}], [{"source": true}, {"source": 1}],
    ]);
    let reason = json!([
        null,
        "",
        "  why  ",
        5,
        [],
        "r".repeat(600),
        "ü".repeat(600),
        "\n lead"
    ]);
    let service_calls = json!([
        [[], null, null],
        [["api:a"], null, null],
        [["api:a"], 3, null],
        [["api:a"], 0, null],
        [["api:a"], -1, null],
        [["api:a"], "3", null],
        [["api:a"], true, null],
        [["api:a"], 3.0, null],
        [["api:a"], MAX_COUNT, null],
        [["api:a"], MAX_COUNT + 1, null],
        [["api:a"], null, {"api:a": 3}],
        [["api:a"], 3, {"api:a": 3}],
        [["api:a"], 4, {"api:a": 3}],
        [["api:a"], null, {"api:a": null}],
        [["api:a"], 0, {"api:a": null}],
        [["api:a"], 2, {"api:a": null}],
        [["api:a"], null, {"api:b": 3}],
        [["api:a"], null, {"api:a": 0}],
        [["api:a"], null, {"api:a": true}],
        [["api:a"], null, {"api:a": 2.0}],
        [["api:a"], null, {"api:a": "2"}],
        [["api:a"], null, []],
        [["api:a"], null, "x"],
        [["api:a", "api:b"], null, null],
        [["api:a", "api:b"], null, {"api:a": 1}],
        [["api:b", "api:a"], null, {"api:a": 1, "api:b": 2}],
        [["api:a", "api:b"], 3, {"api:a": 1, "api:b": 2}],
        [["api:a", "api:b"], 4, {"api:a": 1, "api:b": 2}],
        [["api:a", "api:b"], null, {"api:a": 1, "api:b": null}],
        [["api:a", "api:b"], null, {"api:a": MAX_COUNT, "api:b": 1}],
        [["api:a", "api:b"], null, {"api:a": 1, "api:b": 2, "api:c": 3}],
        [["api:a", "api:a", "api:b"], null, {"api:a": 1, "api:b": 2}],
        [["api:a", "api:b", "api:c"], null, {"api:a": 1}],
    ]);
    let count = json!([
        null,
        0,
        1,
        -1,
        5,
        "5",
        5.0,
        true,
        MAX_COUNT,
        MAX_COUNT + 1,
        [],
        {}
    ]);
    let seconds = json!([
        [null, 0],
        [0, 0],
        [1, 0],
        [-1, 0],
        ["1", 0],
        [1.0, 0],
        [true, 0],
        [LATEST_EPOCH, 0],
        [LATEST_EPOCH + 1, 0],
        [1, LATEST_EPOCH],
        [1, LATEST_EPOCH - 1],
        [300, 1_793_500_000],
    ]);
    let hash_cases = json!([
        [null, false],
        [null, true],
        [hash('a'), false],
        [hash('A'), true],
        [hash('g'), false],
        ["a".repeat(63), false],
        ["a".repeat(65), false],
        [5, false],
        [["x"], true],
        ["", false],
        ["ａ".repeat(64), false],
    ]);
    let grant_id = json!([null, "", "  ", "g", " g ", "g".repeat(100), 5, [], {"id": 1}]);
    let revoked = json!([
        {}, {"status": "revoked"}, {"status": "active"}, {"status": "active", "revoked_at": "x"},
        {"revoked_at_epoch": 0}, {"revoke_reason": ""}, {"revoke_reason": null}, {"revoked_at": null, "status": "consumed"},
        {"revoke_mode": "future"},
    ]);
    let expired = json!([
        [{}, 10], [{"expires_at_epoch": 10}, 10], [{"expires_at_epoch": 11}, 10], [{"expires_at_epoch": 9}, 10],
        [{"expires_at_epoch": "11"}, 10], [{"expires_at_epoch": 11.0}, 10], [{"expires_at_epoch": true}, 0],
        [{"expires_at_epoch": true}, 1], [{"expires_at_epoch": null}, 10], [{"expires_at_epoch": -5}, -10],
    ]);
    let waiting = json!([
        [{}, 10],
        [{"when_spent": "pause", "owner_wait_seconds": 5, "expires_at_epoch": 10}, 14],
        [{"when_spent": "pause", "owner_wait_seconds": 5, "expires_at_epoch": 10}, 15],
        [{"when_spent": "end", "owner_wait_seconds": 5, "expires_at_epoch": 10}, 12],
        [{"when_spent": "pause", "owner_wait_seconds": "5", "expires_at_epoch": 10}, 12],
        [{"when_spent": "pause", "owner_wait_seconds": true, "expires_at_epoch": 10}, 10],
        [{"when_spent": "pause", "owner_wait_seconds": 5, "expires_at_epoch": "10"}, 12],
        [{"when_spent": "pause", "owner_wait_seconds": 5, "expires_at_epoch": true}, 3],
        [{"when_spent": "pause", "owner_wait_seconds": 5.0, "expires_at_epoch": 10}, 12],
        [{"when_spent": "pause", "owner_wait_seconds": -20, "expires_at_epoch": 10}, 5],
    ]);
    let script_match = json!([
        [{}, {}],
        [{"script_kind": "file"}, {"script_kind": "file"}],
        [{"script_kind": "file"}, {}],
        [{"script_kind": null}, {}],
        [{"script_sha256": hash('a')}, {"script_sha256": hash('a'), "script_kind": "x"}],
        [{"script_ref_hash": hash('a'), "other": 1}, {"script_ref_hash": hash('a'), "other": 2}],
        [{"script_sha256": 1}, {"script_sha256": 1.0}],
        [{"script_sha256": true}, {"script_sha256": 1}],
    ]);
    let iso_cases = json!([
        0,
        1,
        59,
        86_399,
        86_400,
        951_782_400,
        1_793_500_000,
        LATEST_EPOCH,
        4_102_444_800i64,
        -1,
        -86_401
    ]);

    let case = json!({
        "identity": identity, "scope": scope, "actor": actor, "actor_match": actor_match,
        "reason": reason, "service_calls": service_calls, "count": count, "seconds": seconds,
        "hash": hash_cases, "grant_id": grant_id, "revoked": revoked, "expired": expired,
        "waiting": waiting, "script_match": script_match, "iso": iso_cases,
    });
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/normalize_probe.py"))
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
    let mut check = |section: &str, i: usize, input: &Value, got: Value| {
        let wanted = &want[section][i];
        if got != *wanted {
            mismatches.push(format!(
                "{section}[{i}] input {input}\n  python: {wanted}\n  rust:   {got}"
            ));
        }
    };
    let arr = |v: &Value| v.as_array().unwrap().clone();
    for (i, v) in arr(&identity).iter().enumerate() {
        check("identity", i, v, ok_or_error(normalize_run_identity(v)));
    }
    for (i, v) in arr(&scope).iter().enumerate() {
        check(
            "scope",
            i,
            v,
            ok_or_error(normalize_scope_list(Some(v), "secret_names")),
        );
    }
    for (i, v) in arr(&actor).iter().enumerate() {
        check("actor", i, v, ok_or_error(normalize_actor(Some(v))));
    }
    for (i, v) in arr(&actor_match).iter().enumerate() {
        check("actor_match", i, v, json!(actor_matches(&v[0], &v[1])));
    }
    for (i, v) in arr(&reason).iter().enumerate() {
        check("reason", i, v, ok_or_error(normalize_reason(Some(v))));
    }
    for (i, v) in arr(&service_calls).iter().enumerate() {
        let names: Vec<String> = v[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_owned())
            .collect();
        let got = normalize_service_calls(&names, Some(&v[1]), Some(&v[2]))
            .map(|(total, per)| json!([total, per]));
        check("service_calls", i, v, ok_or_error(got));
    }
    for (i, v) in arr(&count).iter().enumerate() {
        check(
            "count",
            i,
            v,
            ok_or_error(check_count(Some(v), "max_calls")),
        );
    }
    for (i, v) in arr(&seconds).iter().enumerate() {
        check(
            "seconds",
            i,
            v,
            ok_or_error(check_seconds(
                Some(&v[0]),
                "ttl_seconds",
                v[1].as_i64().unwrap(),
            )),
        );
    }
    for (i, v) in arr(&hash_cases).iter().enumerate() {
        check(
            "hash",
            i,
            v,
            ok_or_error(validate_hash(
                Some(&v[0]),
                "script_sha256",
                v[1].as_bool().unwrap(),
            )),
        );
    }
    for (i, v) in arr(&grant_id).iter().enumerate() {
        let got = normalize_grant_id(Some(v));
        if v.is_null() {
            let id = got.unwrap();
            assert!(
                id.starts_with("grant_") && id.len() == 30,
                "random grant id shape: {id}"
            );
            let wanted = want["grant_id"][i]["ok"].as_str().unwrap();
            assert!(wanted.starts_with("grant_") && wanted.len() == 30);
            continue;
        }
        check("grant_id", i, v, ok_or_error(got));
    }
    for (i, v) in arr(&revoked).iter().enumerate() {
        check("revoked", i, v, json!(is_revoked(v.as_object().unwrap())));
    }
    for (i, v) in arr(&expired).iter().enumerate() {
        check(
            "expired",
            i,
            v,
            json!(is_expired(
                v[0].as_object().unwrap(),
                v[1].as_i64().unwrap()
            )),
        );
    }
    for (i, v) in arr(&waiting).iter().enumerate() {
        check(
            "waiting",
            i,
            v,
            json!(waiting_after_end(
                v[0].as_object().unwrap(),
                v[1].as_i64().unwrap()
            )),
        );
    }
    for (i, v) in arr(&script_match).iter().enumerate() {
        check(
            "script_match",
            i,
            v,
            json!(script_identity_matches(
                v[0].as_object().unwrap(),
                v[1].as_object().unwrap()
            )),
        );
    }
    for (i, v) in arr(&iso_cases).iter().enumerate() {
        check("iso", i, v, json!(iso(v.as_i64().unwrap())));
    }
    assert!(
        mismatches.is_empty(),
        "{} normalization results differ from Python:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
