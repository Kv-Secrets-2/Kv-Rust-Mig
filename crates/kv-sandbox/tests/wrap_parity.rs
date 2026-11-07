//! Differential check: the bubblewrap command line, its refusals and
//! `launch_facts` against Python 0.4.0 over a generated host layout.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_sandbox::bwrap::{
    Isolation, Platform, SandboxHost, WeakFlagReader, WrapOptions, launch_facts, wrap_argv,
};
use serde_json::{Map, Value, json};

fn rust_record(case: &Value) -> Value {
    let env: BTreeMap<String, String> = case["env"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect();
    let home = env.get("HOME").cloned().unwrap_or_else(|| "/".to_owned());
    let host = SandboxHost {
        method: match case["method"].as_str().unwrap() {
            "bwrap" => Isolation::Bwrap,
            "unshare" => Isolation::Unshare,
            _ => Isolation::None,
        },
        bwrap: case["bwrap"].as_str().map(str::to_owned),
        platform: Platform::Linux,
        kv_dir: format!("{home}/.kv"),
        home,
        cwd: "/".to_owned(),
        environ: env,
    };
    let str_opt = |key: &str| case[key].as_str().map(str::to_owned);
    let options = WrapOptions {
        network: case["network"].as_bool().unwrap(),
        secrets_dir: str_opt("secrets_dir"),
        cwd: str_opt("cwd"),
        protect_home_credentials: case["protect_home"].as_bool().unwrap(),
        readonly_file_overlays: case["overlays"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p[0].as_str().unwrap().to_owned(),
                    p[1].as_str().unwrap().to_owned(),
                )
            })
            .collect(),
        private_tmp: case["private_tmp"].as_bool().unwrap(),
        cwd_bind_source: str_opt("cwd_bind_source"),
        secrets_injected: case["secrets_injected"].as_bool().unwrap(),
        weak_flag_reader: if case["reader"] == "mcp" {
            WeakFlagReader::Mcp
        } else {
            WeakFlagReader::Service
        },
    };
    let argv: Vec<String> = case["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    match wrap_argv(&argv, &options, &host) {
        Ok(wrapped) => {
            let (sandboxed, network) = launch_facts(&wrapped, None, host.bwrap.as_deref());
            json!({"wrapped": wrapped, "error": Value::Null, "facts": [sandboxed, network]})
        }
        Err(err) => json!({"wrapped": Value::Null, "error": err.message(), "facts": Value::Null}),
    }
}

fn layout(root: &Path) -> (String, String, String, String, String) {
    let home = root.join("home");
    for dir in [
        ".ssh",
        ".aws",
        ".kv",
        ".kv/cache",
        "project",
        "project/.secrets",
        "bind",
    ] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    std::fs::write(home.join(".netrc"), "machine x").unwrap();
    std::fs::write(home.join(".kv/agent.token"), "t").unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(home.join(".kv/agent-1.sock")).unwrap();
    std::fs::write(home.join("project/.secrets/key"), "k").unwrap();
    std::fs::write(home.join("project/run.py"), "print(1)").unwrap();
    std::fs::write(home.join("project/.secrets/inside.py"), "x").unwrap();
    let s = |p: &str| home.join(p).to_str().unwrap().to_owned();
    (
        s(""),
        s("project"),
        s("project/.secrets"),
        s("project/run.py"),
        s("bind"),
    )
}

#[test]
fn wrapper_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tmp = tempfile::Builder::new()
        .prefix("kvwrap")
        .tempdir_in("/tmp")
        .unwrap();
    let (home, project, secrets, script, bind) = layout(tmp.path());
    let inside = format!("{secrets}/inside.py");
    let mut cases = Vec::new();
    let envs: Vec<Map<String, Value>> = [
        vec![],
        vec![
            ("TMPDIR", "/tmp/work/"),
            ("TMP", "/tmp/work"),
            ("UV_CACHE_DIR", ""),
        ],
        vec![
            ("TMPDIR", "/tmp"),
            ("TEMP", "/var/tmp/x"),
            ("UV_CACHE_DIR", "/c"),
        ],
        vec![
            ("TMPDIR", &format!("/tmp/{}", "a".repeat(300))),
            ("KV_RUN_ALLOW_WEAK_SANDBOX", " ON "),
        ],
        vec![
            ("TMPDIR", "/tmp/kvrun/x"),
            ("TEMP", "/tmp/../tmp/y"),
            ("KV_RUN_ALLOW_WEAK_SANDBOX", "0"),
        ],
        vec![("TMPDIR", &project), ("KV_RUN_ALLOW_WEAK_SANDBOX", "true")],
    ]
    .into_iter()
    .map(|pairs| {
        let mut env: Map<String, Value> = Map::new();
        env.insert("HOME".to_owned(), json!(home));
        env.insert("PATH".to_owned(), json!("/usr/bin:/bin"));
        for (k, v) in pairs {
            env.insert(k.to_owned(), json!(v));
        }
        env
    })
    .collect();
    let overlays_sets: Vec<Vec<[String; 2]>> = vec![
        vec![],
        vec![[script.clone(), "/tmp/kvrun/run.py".to_owned()]],
        vec![[script.clone(), script.clone()]],
        vec![[script.clone(), inside.clone()]],
        vec![[format!("{project}/missing.py"), script.clone()]],
    ];
    for (method, bwrap) in [
        ("bwrap", Some("/usr/bin/bwrap")),
        ("bwrap", None),
        ("unshare", None),
        ("none", None),
    ] {
        for env in &envs {
            for overlays in &overlays_sets {
                for flags in 0..16u8 {
                    let network = flags & 1 != 0;
                    let private_tmp = flags & 2 != 0;
                    let protect_home = flags & 4 != 0;
                    let secrets_injected = flags & 8 != 0;
                    let cwd = if flags % 5 == 0 {
                        "/tmp/kvcwd"
                    } else {
                        project.as_str()
                    };
                    let cwd_bind = if flags % 7 == 0 {
                        Some(bind.as_str())
                    } else {
                        None
                    };
                    cases.push(json!({
                        "argv": ["python3", "run.py"],
                        "network": network,
                        "secrets_dir": if flags % 3 == 0 { Value::Null } else { json!(secrets) },
                        "cwd": cwd,
                        "protect_home": protect_home,
                        "overlays": overlays,
                        "private_tmp": private_tmp,
                        "cwd_bind_source": cwd_bind,
                        "secrets_injected": secrets_injected,
                        "reader": if flags % 2 == 0 { "service" } else { "mcp" },
                        "method": method,
                        "bwrap": bwrap,
                        "env": env,
                    }));
                }
            }
        }
    }
    cases.push(json!({"argv": ["ls"], "network": false, "secrets_dir": Value::Null, "cwd": "relative", "protect_home": false, "overlays": [], "private_tmp": false, "cwd_bind_source": Value::Null, "secrets_injected": false, "reader": "service", "method": "bwrap", "bwrap": "/usr/bin/bwrap", "env": envs[0]}));
    cases.push(json!({"argv": ["ls"], "network": false, "secrets_dir": Value::Null, "cwd": project, "protect_home": false, "overlays": [], "private_tmp": false, "cwd_bind_source": format!("{project}/missing"), "secrets_injected": false, "reader": "service", "method": "bwrap", "bwrap": "/usr/bin/bwrap", "env": envs[0]}));
    let corpus = cases
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(root.join("tests/py/wrap_probe.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start Python probe");
    let mut stdin = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || stdin.write_all(corpus.as_bytes()));
    let output = child.wait_with_output().unwrap();
    feeder.join().unwrap().unwrap();
    assert!(output.status.success(), "Python probe failed");
    let expected: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(expected.len(), cases.len());
    let mut mismatches = Vec::new();
    for (case, want) in cases.iter().zip(&expected) {
        let got = rust_record(case);
        if &got != want {
            mismatches.push(format!("case {case}\n  python: {want}\n  rust:   {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} wrapper records differ from Python:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
