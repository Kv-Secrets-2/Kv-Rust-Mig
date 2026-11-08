//! Live comparison of the grant and capability-token stores against Python 0.4.0.
//!
//! Both sides run with `HOME` pointed at a temporary state directory, so the
//! vault-origin records that gate every store access are shared: the Python
//! probe gets it from the environment, the Rust side re-executes this test
//! binary as `rust_probe`.

#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kv_grants::store::{StoreFault, StoreKind, read_records, store_bytes, write_records};
use serde_json::{Map, Value, json};

type WriteSet<'a> = (StoreKind, PathBuf, &'a Vec<Map<String, Value>>);

fn kind_name(kind: StoreKind) -> &'static str {
    match kind {
        StoreKind::Grants => "grants",
        StoreKind::Tokens => "tokens",
    }
}

fn kind_of(value: &Value) -> StoreKind {
    match value.as_str().unwrap() {
        "grants" => StoreKind::Grants,
        _ => StoreKind::Tokens,
    }
}

fn record(id: &str, extra: Value) -> Value {
    let mut map = Map::new();
    map.insert("grant_id".into(), json!(id));
    map.insert("token_id".into(), json!(id));
    map.insert("token_hash".into(), json!(format!("h-{id}")));
    for (k, v) in extra.as_object().unwrap() {
        map.insert(k.clone(), v.clone());
    }
    Value::Object(map)
}

fn doc(kind: StoreKind, records: Value) -> Value {
    json!({"version": 1, kind_name(kind): records})
}

fn new_vault(root: &Path) {
    let sdir = root.join(".secrets");
    std::fs::create_dir_all(&sdir).unwrap();
    std::fs::set_permissions(&sdir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn setup(
    base: &Path,
    name: &str,
    kind: StoreKind,
    body: Option<&[u8]>,
    mode: u32,
) -> (String, StoreKind, PathBuf) {
    let root = base.join(name);
    new_vault(&root);
    if let Some(body) = body {
        let path = root.join(".secrets").join(kind.filename());
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    (name.to_owned(), kind, root)
}

fn read_cases(base: &Path) -> Vec<(String, StoreKind, PathBuf)> {
    let mut cases = Vec::new();
    for kind in [StoreKind::Grants, StoreKind::Tokens] {
        let tag = kind_name(kind);
        let text = |value: &Value| Some(serde_json::to_vec(value).unwrap());
        let mut add = |suffix: &str, body: Option<Vec<u8>>, mode: u32| {
            cases.push(setup(
                base,
                &format!("{tag}_{suffix}"),
                kind,
                body.as_deref(),
                mode,
            ));
        };
        add("absent", None, 0o600);
        add("empty_list", text(&doc(kind, json!([]))), 0o600);
        add(
            "valid",
            text(&doc(
                kind,
                json!([
                    record(
                        "a",
                        json!({"x": "ünï", "n": 1.5, "nested": {"z": [1, {"y": null}]}})
                    ),
                    record("b", json!({"admission_id": "adm1"}))
                ]),
            )),
            0o600,
        );
        add("mode_644", text(&doc(kind, json!([]))), 0o644);
        add("mode_400", text(&doc(kind, json!([]))), 0o400);
        add("mode_700", text(&doc(kind, json!([]))), 0o700);
        add("not_json", Some(b"{not json".to_vec()), 0o600);
        add(
            "bad_utf8",
            Some(b"{\"version\": 1, \"x\": \"\xff\"}".to_vec()),
            0o600,
        );
        add("empty_file", Some(Vec::new()), 0o600);
        add(
            "bad_utf8_cont",
            Some(b"{\"version\": 1, \"x\": \"\xe2\x28\xa1\"}".to_vec()),
            0o600,
        );
        add(
            "bad_utf8_end",
            Some(b"{\"version\": 1, \"x\": \"\xe2\x82".to_vec()),
            0o600,
        );
        add("bad_utf8_f5", Some(b"\xf5".to_vec()), 0o600);
        add("list_doc", text(&json!([1, 2])), 0o600);
        add(
            "version_str",
            text(&json!({"version": "1", "grants": [], "tokens": []})),
            0o600,
        );
        add(
            "version_float",
            text(&json!({"version": 1.0, "grants": [], "tokens": []})),
            0o600,
        );
        add(
            "version_true",
            text(&json!({"version": true, "grants": [], "tokens": []})),
            0o600,
        );
        add(
            "version_2",
            text(&json!({"version": 2, "grants": [], "tokens": []})),
            0o600,
        );
        add("no_field", text(&json!({"version": 1})), 0o600);
        add(
            "field_dict",
            text(&json!({"version": 1, "grants": {}, "tokens": {}})),
            0o600,
        );
        add("non_dict_record", text(&doc(kind, json!([1]))), 0o600);
        add(
            "missing_id",
            text(&doc(kind, json!([{"token_hash": "h"}]))),
            0o600,
        );
        add(
            "empty_id",
            text(&doc(kind, json!([record("", json!({}))]))),
            0o600,
        );
        add(
            "int_id",
            text(&doc(
                kind,
                json!([{"grant_id": 5, "token_id": 5, "token_hash": "h"}]),
            )),
            0o600,
        );
        add(
            "dup_id",
            text(&doc(
                kind,
                json!([
                    record("a", json!({"token_hash": "h1"})),
                    record("a", json!({"token_hash": "h2"}))
                ]),
            )),
            0o600,
        );
        add(
            "dup_hash",
            text(&doc(
                kind,
                json!([
                    record("a", json!({"token_hash": "h"})),
                    record("b", json!({"token_hash": "h"}))
                ]),
            )),
            0o600,
        );
        add(
            "missing_hash",
            text(&doc(kind, json!([{"grant_id": "a", "token_id": "a"}]))),
            0o600,
        );
        add(
            "dup_admission",
            text(&doc(
                kind,
                json!([
                    record("a", json!({"admission_id": "x"})),
                    record("b", json!({"admission_id": "x"}))
                ]),
            )),
            0o600,
        );
        add(
            "empty_admission",
            text(&doc(
                kind,
                json!([record("a", json!({"admission_id": ""}))]),
            )),
            0o600,
        );
        add(
            "null_admission",
            text(&doc(
                kind,
                json!([record("a", json!({"admission_id": null}))]),
            )),
            0o600,
        );
        let many: Vec<Value> = (0..1001)
            .map(|i| record(&format!("r{i}"), json!({})))
            .collect();
        add("too_many", text(&doc(kind, Value::Array(many))), 0o600);
        let full: Vec<Value> = (0..1000)
            .map(|i| record(&format!("r{i}"), json!({})))
            .collect();
        add("exactly_max", text(&doc(kind, Value::Array(full))), 0o600);
        add(
            "extra_keys",
            text(&json!({"version": 1, "grants": [], "tokens": [], "other": {"k": 1}})),
            0o600,
        );
        let linked = setup(base, &format!("{tag}_symlink"), kind, None, 0o600);
        let target = base
            .join(format!("{tag}_valid"))
            .join(".secrets")
            .join(kind.filename());
        std::os::unix::fs::symlink(&target, linked.2.join(".secrets").join(kind.filename()))
            .unwrap();
        cases.push(linked);
        let dir = setup(base, &format!("{tag}_dir"), kind, None, 0o600);
        std::fs::create_dir(dir.2.join(".secrets").join(kind.filename())).unwrap();
        cases.push(dir);
    }
    cases.push(("unregistered".to_owned(), StoreKind::Grants, {
        let root = base.join("unregistered");
        new_vault(&root);
        root
    }));
    cases
}

fn write_record_sets() -> Vec<Vec<Map<String, Value>>> {
    let obj = |v: Value| v.as_object().unwrap().clone();
    vec![
        vec![],
        vec![obj(record(
            "a",
            json!({"z": 1, "a": "ünï \u{1f600} \"q\" \\ \n", "m": {"b": [1, -2, 18446744073709551615u64, true, null], "a": {}}}),
        ))],
        vec![
            obj(record(
                "b",
                json!({"n": 9007199254740993i64, "big": -9223372036854775808i64, "neg": -5, "s": "\u{7f}\u{80}\u{2028}"}),
            )),
            obj(record("a", json!({}))),
        ],
    ]
}

fn rust_read(root: &Path, kind: StoreKind) -> Value {
    match read_records(root, kind) {
        Ok(records) => json!({"ok": records}),
        Err(StoreFault::NotPrivate(m)) => json!({"error": "PermissionError", "message": m}),
        Err(StoreFault::Invalid(m)) => json!({"error": "ValueError", "message": m}),
        Err(StoreFault::Io(m)) => json!({"error": "OSError", "message": m}),
        Err(StoreFault::Origin(m)) => json!({"error": "VaultOriginError", "message": m}),
        Err(StoreFault::Structure(m)) => json!({"error": "VaultStructureError", "message": m}),
        Err(StoreFault::Decode(m)) => json!({"error": "UnicodeDecodeError", "message": m}),
    }
}

/// The Rust side of the comparison, run in a child whose `HOME` is the test's.
#[test]
fn rust_probe() {
    let Some(input) = std::env::var_os("KV_GRANTS_STORE_PROBE_IN") else {
        return;
    };
    let case: Value = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let reads: Vec<Value> = case["reads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            rust_read(
                Path::new(item["root"].as_str().unwrap()),
                kind_of(&item["kind"]),
            )
        })
        .collect();
    let writes: Vec<Value> = case["writes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let records: Vec<Map<String, Value>> = item["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_object().unwrap().clone())
                .collect();
            let root = Path::new(item["root"].as_str().unwrap());
            let kind = kind_of(&item["kind"]);
            match write_records(root, kind, &records) {
                Ok(()) => {
                    json!({"ok": true, "reread": read_records(root, kind).unwrap() == records})
                }
                Err(error) => json!({"error": error.message()}),
            }
        })
        .collect();
    let cross: Vec<Value> = case["cross"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            rust_read(
                Path::new(item["root"].as_str().unwrap()),
                kind_of(&item["kind"]),
            )
        })
        .collect();
    let out = std::env::var_os("KV_GRANTS_STORE_PROBE_OUT").unwrap();
    std::fs::write(
        out,
        json!({"reads": reads, "writes": writes, "cross": cross}).to_string(),
    )
    .unwrap();
}

fn run_python(python: &Path, home: &Path, script: &Path, stdin: &[u8]) -> Vec<u8> {
    let mut child = Command::new(python)
        .arg("-I")
        .arg(script)
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "python probe failed");
    output.stdout
}

#[test]
fn stores_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let python = PathBuf::from(python);
    let tmp = tempfile::Builder::new()
        .prefix("kvstore")
        .tempdir()
        .unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let home = base.join("home");
    std::fs::create_dir(&home).unwrap();
    let cases = read_cases(&base);
    let sets = write_record_sets();
    let mut writes: Vec<WriteSet<'_>> = Vec::new();
    let mut rust_writes: Vec<WriteSet<'_>> = Vec::new();
    for kind in [StoreKind::Grants, StoreKind::Tokens] {
        for (i, records) in sets.iter().enumerate() {
            for (prefix, list) in [("w", &mut writes), ("r", &mut rust_writes)] {
                let root = base.join(format!("{prefix}_{}_{i}", kind_name(kind)));
                new_vault(&root);
                std::fs::write(
                    root.join(".secrets").join(".gitignore"),
                    "# existing\n/config.lock\n",
                )
                .unwrap();
                list.push((kind, root, records));
            }
        }
    }
    // Every vault but "unregistered" is created on this machine before either side touches it.
    let roots: Vec<&Path> = cases
        .iter()
        .filter(|(name, _, _)| name != "unregistered")
        .map(|(_, _, root)| root.as_path())
        .chain(
            writes
                .iter()
                .chain(&rust_writes)
                .map(|(_, root, _)| root.as_path()),
        )
        .collect();
    let register = base.join("register.py");
    std::fs::write(
        &register,
        "import json, sys\nfrom kv import vault_origin\nfor root in json.loads(sys.stdin.read()):\n    vault_origin.record_created(root)\nprint('[]')\n",
    )
    .unwrap();
    run_python(
        &python,
        &home,
        &register,
        json!(roots).to_string().as_bytes(),
    );

    let reads: Vec<Value> = cases
        .iter()
        .map(|(_, kind, root)| json!({"kind": kind_name(*kind), "root": root}))
        .collect();
    let describe = |list: &[WriteSet<'_>]| -> Vec<Value> {
        list.iter()
            .map(|(kind, root, records)| json!({"kind": kind_name(*kind), "root": root, "records": records}))
            .collect()
    };
    let python_case = json!({"reads": reads, "writes": describe(&writes)});
    let probe = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/store_probe.py");
    let want: Value = serde_json::from_slice(&run_python(
        &python,
        &home,
        &probe,
        python_case.to_string().as_bytes(),
    ))
    .unwrap();
    for (i, result) in want["writes"].as_array().unwrap().iter().enumerate() {
        assert_eq!(*result, json!({"ok": true}), "python write {i} failed");
    }

    let rust_case =
        json!({"reads": reads, "writes": describe(&rust_writes), "cross": describe(&writes)});
    let rust_in = base.join("rust_in.json");
    let rust_out = base.join("rust_out.json");
    std::fs::write(&rust_in, rust_case.to_string()).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "rust_probe", "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("KV_GRANTS_STORE_PROBE_IN", &rust_in)
        .env("KV_GRANTS_STORE_PROBE_OUT", &rust_out)
        .output()

        .unwrap();
    assert!(
        output.status.success(),
        "rust probe failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let got: Value = serde_json::from_slice(&std::fs::read(&rust_out).unwrap()).unwrap();

    let mut mismatches = Vec::new();
    for (i, (name, _, _)) in cases.iter().enumerate() {
        if got["reads"][i] != want["reads"][i] {
            mismatches.push(format!(
                "read {name}\n  python: {}\n  rust:   {}",
                want["reads"][i], got["reads"][i]
            ));
        }
    }
    for (i, (kind, root, records)) in writes.iter().enumerate() {
        assert_eq!(
            got["writes"][i],
            json!({"ok": true, "reread": true}),
            "rust write {i} failed"
        );
        // Rust reads Python's store back as the same records.
        assert_eq!(
            got["cross"][i],
            json!({"ok": records}),
            "rust reads python's store {i}"
        );
        let python_bytes = std::fs::read(root.join(".secrets").join(kind.filename())).unwrap();
        let python_ignore = std::fs::read(root.join(".secrets").join(".gitignore")).unwrap();
        let rust_root = &rust_writes[i].1;
        let rust_path = rust_root.join(".secrets").join(kind.filename());
        let rust_bytes = std::fs::read(&rust_path).unwrap();
        let mode = std::fs::metadata(&rust_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rust store mode");
        if rust_bytes != python_bytes {
            mismatches.push(format!(
                "write {i} {}\n  python: {}\n  rust:   {}",
                kind.filename(),
                String::from_utf8_lossy(&python_bytes),
                String::from_utf8_lossy(&rust_bytes)
            ));
        }
        assert_eq!(store_bytes(*kind, records).unwrap(), rust_bytes);
        let rust_ignore = std::fs::read(rust_root.join(".secrets").join(".gitignore")).unwrap();
        if rust_ignore != python_ignore {
            mismatches.push(format!(
                "ignore {i}\n  python: {:?}\n  rust:   {:?}",
                String::from_utf8_lossy(&python_ignore),
                String::from_utf8_lossy(&rust_ignore)
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} store results differ from Python:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
