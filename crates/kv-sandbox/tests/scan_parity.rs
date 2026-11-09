//! Differential check of the leak scanners against Python 0.4.0 on one
//! generated layout (fresh and old files, nested folders, a `.secrets`
//! subtree, a folder link, invalid UTF-8, encoded secrets, exclusions).
#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_sandbox::scan::{
    collect_changed_files, collect_new_files, leak_report, scan_leaked_files, scan_specific_files,
    snapshot_files,
};
use serde_json::{Value, json};

#[test]
fn scanners_match_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let tmp = tempfile::Builder::new()
        .prefix("kvscan")
        .tempdir_in("/tmp")
        .unwrap();
    let root = tmp.path().join("proj");
    for dir in ["sub/deep", ".secrets", "excl", "temp"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    let secret = "s3cr3t-value-XYZ";
    let b64 = "czNjcjN0LXZhbHVlLVhZWg==";
    std::fs::write(root.join("plain.txt"), format!("hello {secret} there")).unwrap();
    std::fs::write(root.join("enc.txt"), format!("token={b64}")).unwrap();
    std::fs::write(root.join("clean.txt"), "nothing here").unwrap();
    let mut bin = vec![0xffu8, 0xfe, b'a'];
    bin.extend_from_slice(secret.as_bytes());
    bin.extend_from_slice(&[0xc3, 0x28]);
    std::fs::write(root.join("bin.dat"), bin).unwrap();
    std::fs::write(root.join("sub/deep/d.txt"), secret).unwrap();
    std::fs::write(root.join(".secrets/leak.txt"), secret).unwrap();
    std::fs::write(root.join("excl/x.txt"), secret).unwrap();
    std::fs::write(
        root.join("temp/t.txt"),
        secret.chars().rev().collect::<String>(),
    )
    .unwrap();
    std::fs::write(root.join("old.txt"), secret).unwrap();
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    std::fs::File::options()
        .write(true)
        .open(root.join("old.txt"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    std::os::unix::fs::symlink(root.join("sub"), root.join("linkdir")).unwrap();
    std::os::unix::fs::symlink(root.join("plain.txt"), root.join("linkfile")).unwrap();
    let s = |p: &str| root.join(p).to_str().unwrap().to_owned();
    let before_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        - 600.0;
    let secrets: Vec<(String, String)> = vec![
        ("API_KEY".to_owned(), secret.to_owned()),
        ("SHORT".to_owned(), "ab".to_owned()),
    ];
    let scan_dirs = vec![s(""), s("temp"), s("missing")];
    let exclude_dirs = vec![s("excl")];
    let specific = vec![
        s("plain.txt"),
        s("clean.txt"),
        s("missing.txt"),
        s("bin.dat"),
    ];
    let key = [0x42u8; 16];
    let case = json!({
        "secrets": secrets.iter().cloned().collect::<BTreeMap<_, _>>(),
        "before_time": before_time,
        "scan_dirs": scan_dirs,
        "exclude_dirs": exclude_dirs,
        "snapshot_dirs": [s("")],
        "specific": specific,
        "cwd": s(""),
        "temp_dirs": [s("temp")],
        "key_hex": hex::encode(key),
    });
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/scan_probe.py"))
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

    let pairs = || secrets.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    let snapshot = snapshot_files(&[s("")]);
    let got_snapshot: BTreeMap<String, Value> = snapshot
        .iter()
        .map(|(k, (size, m, c))| (k.clone(), json!([size, m, c])))
        .collect();
    assert_eq!(json!(got_snapshot), want["snapshot"], "snapshot");
    let shifted: BTreeMap<_, _> = snapshot
        .iter()
        .map(|(k, (size, m, c))| (k.clone(), (*size, *m, c - 1)))
        .collect();
    let changed: Vec<String> = collect_changed_files(&shifted, &[s("")])
        .into_iter()
        .collect();
    assert_eq!(json!(changed), want["changed"], "changed");
    let new: Vec<String> = collect_new_files(before_time, &scan_dirs)
        .into_iter()
        .collect();
    assert_eq!(json!(new), want["new"], "new");
    let mut leaked = scan_leaked_files(pairs(), before_time, &scan_dirs, &exclude_dirs);
    leaked.sort();
    assert_eq!(json!(leaked), want["leaked"], "leaked");
    let specific_hits = scan_specific_files(&specific, pairs());
    assert_eq!(json!(specific_hits), want["specific"], "specific");
    let (warning, records) = leak_report(&leaked, Some(&s("")), &[s("temp")], &key);
    assert_eq!(json!([warning, records]), want["report"], "report");
    assert!(!leaked.is_empty() && !new.is_empty());
}
