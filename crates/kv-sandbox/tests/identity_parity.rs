//! Live comparison of run identity against Python 0.4.0 (`kv.sandbox`).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_sandbox::identity::{
    IdentityScope, build_run_identity, hash_file, module_script_path, script_file_path,
    script_identity,
};
use serde_json::{Value, json};

#[test]
fn identity_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let tmp = tempfile::Builder::new()
        .prefix("kvid")
        .tempdir_in("/tmp")
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let cwd = root.to_str().unwrap().to_owned();
    let s = |rel: &str| {
        if rel.is_empty() {
            cwd.clone()
        } else {
            format!("{cwd}/{rel}")
        }
    };
    std::fs::create_dir_all(s("pkg")).unwrap();
    std::fs::create_dir_all(s("sub/deep")).unwrap();
    std::fs::create_dir_all(s(".secrets")).unwrap();
    std::fs::write(s("script.py"), "print('hi')\n").unwrap();
    std::fs::write(s("mod.py"), "x = 1\n").unwrap();
    std::fs::write(s("pkg/__main__.py"), "print('pkg')\n").unwrap();
    std::fs::write(s("sub/deep/tool.py"), "y = 2\n").unwrap();
    std::fs::write(s(".secrets/hidden.py"), "secret\n").unwrap();
    std::fs::write(s("big.bin"), vec![0xA5u8; 3 * 1024 * 1024 + 17]).unwrap();
    std::fs::write(s("empty.py"), "").unwrap();
    std::os::unix::fs::symlink(s("script.py"), s("link.py")).unwrap();
    std::os::unix::fs::symlink(s("missing.py"), s("dangling.py")).unwrap();

    let files: Vec<String> = [
        "script.py",
        "mod.py",
        "pkg/__main__.py",
        "sub/deep/tool.py",
        ".secrets/hidden.py",
        "big.bin",
        "empty.py",
        "link.py",
        "dangling.py",
        "missing.py",
        "pkg",
        "",
    ]
    .iter()
    .map(|rel| s(rel))
    .collect();
    let argvs: Vec<Vec<String>> = vec![
        vec![],
        vec!["python3".into()],
        vec!["python3".into(), "script.py".into()],
        vec!["python".into(), "./script.py".into()],
        vec!["/usr/bin/python3".into(), s("script.py")],
        vec!["PYTHON3".into(), "script.py".into()],
        vec!["python3".into(), "link.py".into()],
        vec!["python3".into(), "dangling.py".into()],
        vec!["python3".into(), "missing.py".into()],
        vec!["python3".into(), "empty.py".into()],
        vec!["python3".into(), "big.bin".into()],
        vec!["python3".into(), "sub/deep/tool.py".into()],
        vec!["python3".into(), ".secrets/hidden.py".into()],
        vec!["python3".into(), s(".secrets/hidden.py")],
        vec!["python3".into(), "pkg".into()],
        vec!["python3".into(), "-c".into(), "print(1)".into()],
        vec!["python3".into(), "-m".into(), "mod".into()],
        vec!["python3".into(), "-m".into(), "pkg".into()],
        vec!["python3".into(), "-m".into(), "nope".into()],
        vec!["python3".into(), "-m".into(), "bad-name".into()],
        vec!["python3".into(), "-m".into()],
        vec!["python3".into(), "-u".into(), "script.py".into()],
        vec!["node".into(), "script.py".into()],
        vec!["bash".into(), "script.py".into()],
        vec!["ruby".into(), "script.py".into()],
        vec!["perl".into(), "script.py".into()],
        vec!["sh".into(), "mod.py".into()],
        vec!["pytest".into(), "script.py".into()],
        vec!["python3".into(), "".into()],
    ];
    let modules: Vec<String> = [
        "mod",
        "pkg",
        "nope",
        "bad-name",
        "-mod",
        "",
        "sub.deep.tool",
        "sub.deep",
        "pkg.__main__",
        ".secrets.hidden",
        "mod.py",
    ]
    .iter()
    .map(|m| m.to_string())
    .collect();
    let scopes = json!([
        {"env_names": null, "secret_scope": null, "secrets_injected": true},
        {"env_names": ["b", "a"], "secret_scope": {"env": "dev", "names": ["b", "a"]}, "secrets_injected": true},
        {"env_names": [], "secret_scope": null, "secrets_injected": false},
        {"env_names": ["ünï", "a"], "secret_scope": "ünïcode", "secrets_injected": true},
    ]);
    let run_id = "run_0123456789abcdef01234567";
    let case = json!({
        "cwd": cwd, "files": files, "argvs": argvs, "modules": modules,
        "run_id": run_id, "scopes": scopes,
    });
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/identity_probe.py"))
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

    let watched: Vec<String> = vec![];
    let hashes: serde_json::Map<String, Value> = files
        .iter()
        .map(|path| (path.clone(), json!(hash_file(path).unwrap())))
        .collect();
    assert_eq!(Value::Object(hashes), want["hashes"], "hash_file");

    let script_paths: Vec<Value> = argvs
        .iter()
        .map(|argv| json!(script_file_path(argv, &cwd, &watched)))
        .collect();
    assert_eq!(
        json!(script_paths),
        want["script_paths"],
        "script_file_path"
    );

    let module_paths: Vec<Value> = modules
        .iter()
        .map(|name| json!(module_script_path(name, &cwd, &watched)))
        .collect();
    assert_eq!(
        json!(module_paths),
        want["module_paths"],
        "module_script_path"
    );

    let identities: Vec<Value> = argvs
        .iter()
        .map(|argv| Value::Object(script_identity(argv, &cwd, &watched).unwrap()))
        .collect();
    assert_eq!(json!(identities), want["identities"], "script_identity");

    let scope_values: Vec<(Option<Vec<String>>, Option<Value>, bool)> = scopes
        .as_array()
        .unwrap()
        .iter()
        .map(|scope| {
            (
                scope["env_names"].as_array().map(|names| {
                    names
                        .iter()
                        .map(|n| n.as_str().unwrap().to_owned())
                        .collect()
                }),
                (!scope["secret_scope"].is_null()).then(|| scope["secret_scope"].clone()),
                scope["secrets_injected"].as_bool().unwrap(),
            )
        })
        .collect();
    for (i, argv) in argvs.iter().enumerate() {
        for (j, (env_names, secret_scope, injected)) in scope_values.iter().enumerate() {
            let scope = IdentityScope {
                env_names: env_names.as_deref(),
                secret_scope: secret_scope.clone(),
                secrets_injected: *injected,
            };
            let got = build_run_identity(argv, &cwd, &scope, run_id, &watched).unwrap();
            assert_eq!(
                Value::Object(got),
                want["run_identities"][i][j],
                "build_run_identity argv={argv:?} scope={j}"
            );
        }
    }
    eprintln!(
        "identity parity: {} files, {} argvs, {} modules, {} scopes",
        files.len(),
        argvs.len(),
        modules.len(),
        scope_values.len()
    );
}
