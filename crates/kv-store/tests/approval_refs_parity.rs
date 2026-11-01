mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use kv_store::{DrawerStore, approval_refs, config};
use serde_json::{Value, json};

use common::{TestDir, copy_fixture_secrets, fixture_master_key, fixture_root, key_copy};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn python() -> std::ffi::OsString {
    std::env::var_os("KV_PY_REF").expect("KV_PY_REF must name the Python reference interpreter")
}

fn run_python(python: &std::ffi::OsStr, temp: &TestDir, root: &Path, command: Value) -> Value {
    let spec = temp.path().join(format!(
        "approval-refs-{}.json",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(
        &spec,
        serde_json::to_vec(&command).expect("serialize Python command"),
    )
    .expect("write Python command");
    let output = Command::new(python)
        .arg(fixture_root().join("../gen/check_store_parity.py"))
        .arg(root)
        .arg(root)
        .arg("00")
        .arg(&spec)
        .output()
        .expect("run Python approval reference");
    assert!(
        output.status.success(),
        "Python approval reference failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse Python reference JSON")
}

fn compare(python: &std::ffi::OsStr, temp: &TestDir, root: &Path, env: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64;
    let rust = serde_json::to_value(approval_refs::approvals_naming_env(root, env, now))
        .expect("serialize Rust approval references");
    let reference = run_python(python, temp, root, json!({"approval_refs":{"env":env}}));
    assert_eq!(rust, reference, "approval references for {env}");
}

fn compare_both(python: &std::ffi::OsStr, temp: &TestDir, root: &Path) {
    for env in ["dev", "prod"] {
        compare(python, temp, root, env);
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write private store");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set store mode");
    }
}

fn write_store(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(".secrets").join(name);
    write_private(&path, bytes);
    path
}

fn json_store(root: &Path, name: &str, value: &Value) -> PathBuf {
    write_store(
        root,
        name,
        &serde_json::to_vec(value).expect("serialize store"),
    )
}

fn reset(root: &Path, name: &str) {
    let path = root.join(".secrets").join(name);
    if path.is_dir() {
        fs::remove_dir_all(path).expect("remove store directory");
    } else if path.exists() || fs::symlink_metadata(&path).is_ok() {
        fs::remove_file(path).expect("remove store");
    }
}

fn expires(now: i64, offset: i64) -> Value {
    json!(now + offset)
}

fn grant(id: Value, env: Value, expiry: Value, status: Value, scope: Value) -> Value {
    json!({
        "grant_id":id,
        "owner_approval":{"payload":{"environment":env}},
        "expires_at_epoch":expiry,
        "status":status,
        "capability_names":scope
    })
}

fn valid_grant_store(records: Vec<Value>) -> Value {
    json!({"version":1,"grants":records})
}

fn valid_token(id: Value, env: Value, expiry: Value, status: Value) -> Value {
    json!({
        "token_id":id,
        "token_hash":format!("hash-{}", id),
        "env_name":env,
        "expires_at_epoch":expiry,
        "status":status,
        "capability_name":"files:read"
    })
}

#[test]
#[cfg(unix)]
fn approval_stores_match_python_for_valid_invalid_and_conservative_inputs() {
    let python = python();
    let temp = TestDir::new("approval-refs-parity");
    let root = temp.project_root("vault");
    copy_fixture_secrets(&root);
    let secrets = root.join(".secrets");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64;

    compare_both(&python, &temp, &root);

    json_store(&root, "run_grants.json", &valid_grant_store(vec![]));
    json_store(
        &root,
        "capability_tokens.json",
        &json!({"version":1,"tokens":[]}),
    );
    json_store(
        &root,
        "approval_requests.json",
        &json!({"version":1,"requests":[]}),
    );
    compare_both(&python, &temp, &root);

    let grants = valid_grant_store(vec![
        grant(
            json!("g-dev"),
            json!("dev"),
            expires(now, 3600),
            json!("active"),
            json!(["read", "write"]),
        ),
        grant(
            json!("g-prod"),
            json!("prod"),
            expires(now, 3600),
            json!("active"),
            json!(["prod"]),
        ),
        grant(
            json!("g-wild"),
            json!("*"),
            expires(now, 3600),
            json!("active"),
            json!(["wild"]),
        ),
        grant(
            json!("g-expired"),
            json!("dev"),
            expires(now, -3600),
            json!("active"),
            json!(["old"]),
        ),
        grant(
            json!("g-revoked"),
            json!("dev"),
            expires(now, 3600),
            json!("revoked"),
            json!(["revoked"]),
        ),
        json!({"grant_id":"g-missing-owner","expires_at_epoch":now+3600,"status":"active"}),
        json!({"grant_id":"g-empty-owner","owner_approval":"","expires_at_epoch":now+3600,"status":"active"}),
        json!({"grant_id":"g-empty-list","owner_approval":[],"expires_at_epoch":now+3600,"status":"active"}),
        grant(
            json!("g-string-scope"),
            json!("dev"),
            expires(now, 3600),
            json!("active"),
            json!("xy"),
        ),
        grant(
            json!("g-dict-scope"),
            json!("dev"),
            expires(now, 3600),
            json!("active"),
            json!({"one":1,"two":2}),
        ),
        json!({"grant_id":"g-secret-scope","owner_approval":{"payload":{"environment":"dev"}},
               "expires_at_epoch":now+3600,"status":"active","capability_names":[],"secret_names":["fallback"]}),
        grant(
            json!("g-bool-expiry"),
            json!("dev"),
            json!(true),
            json!("active"),
            json!(["ignored"]),
        ),
        grant(
            json!("g-float-expiry"),
            json!("dev"),
            json!(12.0),
            json!("active"),
            json!(["ignored"]),
        ),
        grant(
            json!("g-string-expiry"),
            json!("dev"),
            json!("9999999999"),
            json!("active"),
            json!(["ignored"]),
        ),
        grant(
            json!("g-year-10000"),
            json!("dev"),
            json!(253402300800_i64),
            json!("active"),
            json!(["future"]),
        ),
    ]);
    json_store(&root, "run_grants.json", &grants);
    compare_both(&python, &temp, &root);
    reset(&root, "run_grants.json");

    for bad_owner in [json!("x"), json!({"payload":"x"})] {
        json_store(
            &root,
            "run_grants.json",
            &valid_grant_store(vec![
                json!({"grant_id":"bad-owner","owner_approval":bad_owner,"expires_at_epoch":now+3600,"status":"active"}),
            ]),
        );
        compare_both(&python, &temp, &root);
        reset(&root, "run_grants.json");
    }
    for bad_scope in [json!(3), json!(["ok", 3])] {
        json_store(
            &root,
            "run_grants.json",
            &valid_grant_store(vec![grant(
                json!("bad-scope"),
                json!("dev"),
                expires(now, 3600),
                json!("active"),
                bad_scope,
            )]),
        );
        compare_both(&python, &temp, &root);
        reset(&root, "run_grants.json");
    }
    json_store(
        &root,
        "run_grants.json",
        &valid_grant_store(vec![
            json!({"grant_id":"g-duplicate","owner_approval":{},"admission_id":"same"}),
            json!({"grant_id":"g-duplicate","owner_approval":{},"admission_id":"same"}),
        ]),
    );
    compare_both(&python, &temp, &root);
    reset(&root, "run_grants.json");
    json_store(
        &root,
        "run_grants.json",
        &valid_grant_store(vec![json!({"grant_id":17,"owner_approval":{}})]),
    );
    compare_both(&python, &temp, &root);
    reset(&root, "run_grants.json");

    let tokens = json!({"version":1,"tokens":[
        valid_token(json!("t-dev"),json!("dev"),expires(now,3600),json!("active")),
        valid_token(json!("t-null"),json!("dev"),expires(now,3600),Value::Null),
        json!({"token_id":"t-missing-status","token_hash":"hash-missing","env_name":"dev",
               "expires_at_epoch":now+3600,"capability_name":"files:write"}),
        {"token_id":"t-missing-capability","token_hash":"hash-no-cap","env_name":"dev",
         "expires_at_epoch":now+3600,"status":"active"},
        valid_token(json!("t-prod"),json!("prod"),expires(now,3600),json!("active")),
        valid_token(json!("t-expired"),json!("dev"),expires(now,-3600),json!("active")),
        valid_token(json!("t-revoked"),json!("dev"),expires(now,3600),json!("revoked")),
        valid_token(json!("t-bool"),json!("dev"),json!(true),json!("active")),
        valid_token(json!("t-float"),json!("dev"),json!(12.0),json!("active")),
        valid_token(json!("t-string"),json!("dev"),json!("9999999999"),json!("active"))
    ]});
    json_store(&root, "capability_tokens.json", &tokens);
    compare_both(&python, &temp, &root);
    reset(&root, "capability_tokens.json");
    json_store(
        &root,
        "capability_tokens.json",
        &json!({"version":1,"tokens":[
            valid_token(json!(17),json!("dev"),expires(now,3600),json!("active"))
        ]}),
    );
    compare_both(&python, &temp, &root);
    reset(&root, "capability_tokens.json");

    let requests = json!({"version":1,"requests":[
        {"request_id":"r-dev","environment":"dev","expires_at_epoch":now+3600,"capability_names":["read"]},
        {"request_id":5,"environment":"dev","expires_at_epoch":now+3600,"secret_names":["secret"]},
        {"request_id":"r-prod","environment":"prod","expires_at_epoch":now+3600,"secret_names":["prod"]},
        {"request_id":"r-approved","environment":"dev","expires_at_epoch":now+3600,"approved_at":false},
        {"request_id":"r-denied","environment":"dev","expires_at_epoch":now+3600,"deny_reason":""},
        {"request_id":"r-withdrawn","environment":"dev","expires_at_epoch":now+3600,"withdrawn_at_epoch":0},
        {"request_id":"r-status","environment":"dev","expires_at_epoch":now+3600,"status":"complete"},
        {"request_id":"r-under","environment":"dev","expires_at_epoch":" 1_9 ","secret_names":["expired"]},
        {"request_id":"r-invalid-int","environment":"dev","expires_at_epoch":"x","secret_names":["expired"]},
        {"request_id":"r-float","environment":"dev","expires_at_epoch":19.9,"secret_names":["expired"]},
        {"request_id":"r-list-scope","environment":"dev","expires_at_epoch":now+3600,"secret_names":"xy"},
        {"request_id":"r-dict-scope","environment":"dev","expires_at_epoch":now+3600,"capability_names":{"a":1,"b":2}},
        {"request_id":"r-no-scope","environment":"dev","expires_at_epoch":now+3600}
    ]});
    json_store(&root, "approval_requests.json", &requests);
    compare_both(&python, &temp, &root);
    reset(&root, "approval_requests.json");

    for name in [
        "run_grants.json",
        "capability_tokens.json",
        "approval_requests.json",
    ] {
        let wrong_version = json!({"version":2,"records":[]});
        json_store(&root, name, &wrong_version);
        compare_both(&python, &temp, &root);
        reset(&root, name);

        write_store(&root, name, b"[]");
        compare_both(&python, &temp, &root);
        reset(&root, name);

        for bytes in [
            b"{\"version\":1,\"grants\":NaN}".as_slice(),
            b"\xef\xbb\xbf{}".as_slice(),
            b"\xff".as_slice(),
        ] {
            write_store(&root, name, bytes);
            compare_both(&python, &temp, &root);
            reset(&root, name);
        }
        json_store(&root, name, &json!({"version":1}));
        compare_both(&python, &temp, &root);
        reset(&root, name);
    }

    write_store(
        &root,
        "run_grants.json",
        br#"{"version":2,"version":1,"grants":[]}"#,
    );
    compare_both(&python, &temp, &root);
    reset(&root, "run_grants.json");

    let too_many = (0..1001)
        .map(|index| json!({"grant_id":format!("g-{index}"),"owner_approval":{}}))
        .collect::<Vec<_>>();
    json_store(&root, "run_grants.json", &valid_grant_store(too_many));
    compare_both(&python, &temp, &root);
    reset(&root, "run_grants.json");

    let too_many_tokens = (0..1001)
        .map(|index| {
            valid_token(
                json!(format!("t-{index}")),
                json!("dev"),
                json!(now + 3600),
                json!("active"),
            )
        })
        .collect::<Vec<_>>();
    json_store(
        &root,
        "capability_tokens.json",
        &json!({"version":1,"tokens":too_many_tokens}),
    );
    compare_both(&python, &temp, &root);
    reset(&root, "capability_tokens.json");
    let too_many_requests = (0..1002)
        .map(|index| json!({"request_id":index,"environment":"dev","expires_at_epoch":now+3600}))
        .collect::<Vec<_>>();
    json_store(
        &root,
        "approval_requests.json",
        &json!({"version":1,"requests":too_many_requests}),
    );
    compare_both(&python, &temp, &root);
    reset(&root, "approval_requests.json");

    json_store(
        &root,
        "capability_tokens.json",
        &json!({"version":1,"tokens":[
            valid_token(json!("duplicate"),json!("dev"),expires(now,3600),json!("active")),
            valid_token(json!("duplicate"),json!("dev"),expires(now,3600),json!("active"))
        ]}),
    );
    compare_both(&python, &temp, &root);
    reset(&root, "capability_tokens.json");
    json_store(
        &root,
        "capability_tokens.json",
        &json!({"version":1,"tokens":[
            {"token_id":"unique-a","token_hash":"duplicate-hash","env_name":"dev","expires_at_epoch":now+3600},
            {"token_id":"unique-b","token_hash":"duplicate-hash","env_name":"dev","expires_at_epoch":now+3600}
        ]}),
    );
    compare_both(&python, &temp, &root);
    reset(&root, "capability_tokens.json");
    json_store(
        &root,
        "capability_tokens.json",
        &json!({"version":1,"tokens":[
            {"token_id":"unique-a","token_hash":"hash-a","admission_id":"same","env_name":"dev"},
            {"token_id":"unique-b","token_hash":"hash-b","admission_id":"same","env_name":"dev"}
        ]}),
    );
    compare_both(&python, &temp, &root);
    reset(&root, "capability_tokens.json");

    let huge = format!(
        r#"{{"version":1,"grants":[{{"grant_id":"huge","owner_approval":{{"payload":{{"environment":"dev"}}}},"expires_at_epoch":{},"status":"active"}}]}}"#,
        "1".to_owned() + &"0".repeat(30)
    );
    write_store(&root, "run_grants.json", huge.as_bytes());
    compare_both(&python, &temp, &root);
    reset(&root, "run_grants.json");
    let wide_time = r#"{"version":1,"grants":[{"grant_id":"wide","owner_approval":{"payload":{"environment":"dev"}},"expires_at_epoch":4611686018427387904,"status":"active"}]}"#;
    write_store(&root, "run_grants.json", wide_time.as_bytes());
    compare_both(&python, &temp, &root);
    reset(&root, "run_grants.json");

    for literal in ["NaN", "Infinity"] {
        let extended = format!(
            r#"{{"version":1,"grants":[{{"grant_id":"extended","owner_approval":{{"payload":{{"environment":"dev"}}}},"expires_at_epoch":{literal},"status":"active"}}]}}"#
        );
        write_store(&root, "run_grants.json", extended.as_bytes());
        let rust = approval_refs::approvals_naming_env(&root, "dev", now);
        assert_eq!(rust.len(), 1, "serde_json extension input fails closed");
        assert_eq!(rust[0].kind, "grant");
        assert_eq!(
            run_python(
                &python,
                &temp,
                &root,
                json!({"approval_refs":{"env":"dev"}})
            ),
            json!([]),
            "Python accepts {literal} but does not treat it as an integer expiry"
        );
        reset(&root, "run_grants.json");
    }

    let oversized = vec![b' '; 64 * 1024 * 1024 + 1];
    write_store(&root, "run_grants.json", &oversized);
    compare(&python, &temp, &root, "dev");
    reset(&root, "run_grants.json");

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for name in [
            "run_grants.json",
            "capability_tokens.json",
            "approval_requests.json",
        ] {
            let path = write_store(&root, name, br#"{"version":1}"#);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen mode");
            compare_both(&python, &temp, &root);
            reset(&root, name);

            let target_name = format!("target-{name}");
            write_store(&root, &target_name, br#"{"version":1}"#);
            symlink(secrets.join(&target_name), secrets.join(name)).expect("create store link");
            compare_both(&python, &temp, &root);
            reset(&root, name);
            reset(&root, &target_name);
        }

        let locked = write_store(&root, "locked-source", b"kv-saved-passes-locked-v1\n");
        symlink(&locked, secrets.join("saved_passes.kvs")).expect("create saved-store link");
        compare_both(&python, &temp, &root);
        reset(&root, "saved_passes.kvs");
        reset(&root, "locked-source");
    }

    for name in [
        "run_grants.json",
        "capability_tokens.json",
        "approval_requests.json",
    ] {
        fs::create_dir(secrets.join(name)).expect("create store directory");
        compare_both(&python, &temp, &root);
        reset(&root, name);
    }

    for saved in [
        None,
        Some(b"kv-saved-passes-locked-v1\n".as_slice()),
        Some(b"kv-saved-passes-locked-v1\n\n".as_slice()),
        Some(b"random bytes".as_slice()),
    ] {
        reset(&root, "saved_passes.kvs");
        if let Some(bytes) = saved {
            write_store(&root, "saved_passes.kvs", bytes);
        }
        compare_both(&python, &temp, &root);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        reset(&root, "saved_passes.kvs");
        let path = write_store(&root, "saved_passes.kvs", b"kv-saved-passes-locked-v1\n");
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("loosen saved mode");
        compare_both(&python, &temp, &root);
    }
}

#[test]
fn python_string_rendering_matches_generated_json_values() {
    let python = python();
    let temp = TestDir::new("approval-pystr");
    let root = temp.project_root("root");
    fs::create_dir_all(&root).expect("create root");
    let values = json!([
        null, true, false, 0, -12, 1.0, 0.0001, 1.0e-5, 1.0e16, 1.5e-7,
        "", "plain", "quote's", "double\"", "both'\"", "line\nbreak\t",
        "münchen ✓", "\u{200b}", "\u{0001}",
        [null, true, "str", ["nested", 1]],
        {"b":false,"a":[1,"x"]}
    ]);
    let expected = run_python(&python, &temp, &root, json!({"py_str":values.clone()}));
    let actual = values
        .as_array()
        .expect("generated JSON values")
        .iter()
        .map(approval_refs::py_str)
        .collect::<Vec<_>>();
    assert_eq!(serde_json::to_value(actual).unwrap(), expected);
}

fn vault(root: &Path) -> config::Vault {
    let master = fixture_master_key();
    let secrets = root.join(".secrets");
    let store = DrawerStore::open(&secrets, key_copy(&master));
    config::Vault::open(root, store)
}

fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>, u32)> {
    fn collect(root: &Path, path: &Path, files: &mut Vec<(PathBuf, Vec<u8>, u32)>) {
        for item in fs::read_dir(path).expect("read snapshot directory") {
            let path = item.expect("read directory entry").path();
            if path.is_dir() {
                collect(root, &path, files);
            } else if path.is_file() {
                let metadata = fs::metadata(&path).expect("read snapshot metadata");
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::MetadataExt;
                    metadata.mode() & 0o7777
                };
                #[cfg(windows)]
                let mode = if metadata.permissions().readonly() {
                    1
                } else {
                    0
                };
                files.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(&path).expect("read snapshot file"),
                    mode,
                ));
            }
        }
    }
    let mut files = Vec::new();
    collect(root, &root.join(".secrets"), &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn add_matching_request(root: &Path, env: &str) {
    write_store(
        root,
        "approval_requests.json",
        &serde_json::to_vec(&json!({"version":1,"requests":[{
            "request_id":"r","environment":env,"expires_at_epoch":
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()+3600,
            "secret_names":["KEY"]
        }]})).unwrap(),
    );
}

fn assert_refused_without_changes(
    root: &Path,
    operation: impl FnOnce(&config::Vault) -> Result<(), kv_store::StoreError>,
) {
    assert_refused_named_without_changes(root, "dev", operation);
}

fn assert_refused_named_without_changes(
    root: &Path,
    env: &str,
    operation: impl FnOnce(&config::Vault) -> Result<(), kv_store::StoreError>,
) {
    let vault = vault(root);
    write_private(&root.join(".secrets/config.lock"), b"");
    write_private(&root.join(".secrets/storage.lock"), b"");
    let _ = config::load_config(root).expect("prime config lock");
    let before = snapshot(root);
    let error = operation(&vault).expect_err("approval should refuse environment change");
    assert_eq!(
        error.to_string(),
        format!(
            "an approval names environment '{env}'; nothing was changed (kv approvals list shows it)"
        )
    );
    assert_eq!(
        snapshot(root),
        before,
        "refusal must not mutate vault files"
    );
}

#[cfg(unix)]
#[test]
fn rename_also_refuses_when_the_destination_is_named() {
    let temp = TestDir::new("approval-rename-destination");
    let root = temp.project_root("vault");
    copy_fixture_secrets(&root);
    add_matching_request(&root, "development");
    assert_refused_named_without_changes(&root, "development", |vault| {
        vault.rename_env("dev", "development")
    });
}

#[test]
fn vault_env_changes_refuse_named_or_unreadable_stores_and_leave_disk_unchanged() {
    let temp = TestDir::new("approval-vault-refusal");
    for source in ["request", "saved"] {
        for action in ["rename", "delete", "restore"] {
            let root = temp.project_root(&format!("{source}-{action}"));
            copy_fixture_secrets(&root);
            let setup = vault(&root);
            if action == "delete" || action == "restore" {
                setup.set_default_env("prod").expect("change default");
            }
            if action == "restore" {
                setup
                    .delete_env("dev")
                    .expect("delete before restore check");
            }
            if source == "saved" {
                write_store(&root, "saved_passes.kvs", b"random bytes");
            } else {
                add_matching_request(&root, "dev");
            }
            match action {
                "rename" => assert_refused_without_changes(&root, |vault| {
                    vault.rename_env("dev", "development")
                }),
                "delete" => assert_refused_without_changes(&root, |vault| {
                    vault.delete_env("dev").map(|_| ())
                }),
                _ => assert_refused_without_changes(&root, |vault| vault.restore_env("dev")),
            }
        }
    }
}

#[test]
fn vault_env_changes_allow_absent_or_locked_saved_file_and_ungated_operations_stay_open() {
    for saved in [None, Some(b"kv-saved-passes-locked-v1\n".as_slice())] {
        for action in ["rename", "delete", "restore"] {
            if cfg!(windows) && saved.is_some() {
                continue;
            }
            let temp = TestDir::new("approval-vault-allowed");
            let root = temp.project_root("vault");
            copy_fixture_secrets(&root);
            if action == "restore" {
                vault(&root)
                    .delete_env("prod")
                    .expect("delete before restore");
            }
            if let Some(bytes) = saved {
                write_store(&root, "saved_passes.kvs", bytes);
            }
            let vault = vault(&root);
            match action {
                "rename" => vault
                    .rename_env("prod", "production")
                    .expect("rename allowed"),
                "delete" => {
                    vault.delete_env("prod").expect("delete allowed");
                }
                _ => vault.restore_env("prod").expect("restore allowed"),
            }
        }
    }

    let temp = TestDir::new("approval-vault-ungated");
    let root = temp.project_root("vault");
    copy_fixture_secrets(&root);
    add_matching_request(&root, "prod");
    let vault = vault(&root);
    vault
        .set_default_env("prod")
        .expect("default change is ungated");
    vault
        .set_deleted_env_keep_days(45)
        .expect("keep-days change is ungated");
    reset(&root, "approval_requests.json");
    vault
        .set_default_env("dev")
        .expect("default change back is ungated");
    vault
        .delete_env("prod")
        .expect("delete without a prod-named approval");
    add_matching_request(&root, "prod");
    assert!(vault.purge_env("prod").expect("purge is ungated"));
}
