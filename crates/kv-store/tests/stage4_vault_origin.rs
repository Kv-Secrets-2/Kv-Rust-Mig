#![allow(unsafe_code)]

mod common;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::sync::Mutex;

#[cfg(unix)]
use common::{TestDir, copy_fixture_secrets, fixture_master_key, hex};
#[cfg(unix)]
use kv_store::config_authority;
#[cfg(unix)]
use kv_store::vault_origin;
#[cfg(unix)]
use serde_json::{Value, json};

#[cfg(unix)]
static HOME_LOCK: Mutex<()> = Mutex::new(());

#[cfg(unix)]
struct HomeGuard(Option<std::ffi::OsString>);

#[cfg(unix)]
impl Drop for HomeGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(previous_home) = self.0.take() {
                std::env::set_var("HOME", previous_home);
            } else {
                std::env::remove_var("HOME");
            }
        }
    }
}

#[cfg(unix)]
fn python(python: &std::ffi::OsStr, code: &str, root: &Path, home: &Path) -> Value {
    let output = Command::new(python)
        .arg("-c")
        .arg(code)
        .arg(root)
        .env("HOME", home)
        .output()
        .expect("run Python reference");
    assert!(
        output.status.success(),
        "Python reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Python JSON")
}

#[cfg(unix)]
fn python_with_master(
    python: &std::ffi::OsStr,
    code: &str,
    root: &Path,
    home: &Path,
    master: &[u8],
) -> Value {
    let output = Command::new(python)
        .arg("-c")
        .arg(code)
        .arg(root)
        .env("HOME", home)
        .env("MASTER_KEY", hex(master))
        .output()
        .expect("run Python reference");
    assert!(
        output.status.success(),
        "Python reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Python JSON")
}

#[cfg(unix)]
fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn provenance_records_interoperate_with_python() {
    let Some(python_path) = std::env::var_os("KV_PY_REF") else {
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap();
    let temp = TestDir::new("stage4-origin");
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let previous_home = std::env::var_os("HOME");
    unsafe {
        std::env::set_var("HOME", &home);
    }
    let _home_guard = HomeGuard(previous_home);
    let root = temp.project_root("vault");
    copy_fixture_secrets(&root);
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    let root = fs::canonicalize(root).unwrap();

    let py_create = r#"
import json,sys
from kv import vault_origin
print(json.dumps(vault_origin.record_created(sys.argv[1])))
"#;
    python(&python_path, py_create, &root, &home);
    vault_origin::require_local(&root).unwrap();

    let rust_record = vault_origin::record_created(&root).unwrap();
    let record_name = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(root.to_str().unwrap().as_bytes());
        let mut name = String::from("vault-origin-");
        for byte in digest {
            name.push_str(&format!("{byte:02x}"));
        }
        name.push_str(".json");
        name
    };
    let rust_bytes = fs::read(home.join(".kv").join(&record_name)).unwrap();
    let py_rewrite = r#"
import json,sys
from kv import vault_origin
record=vault_origin.require_local(sys.argv[1])
sys.stdout.buffer.write(json.dumps(record,sort_keys=True).encode())
"#;
    let output = Command::new(&python_path)
        .arg("-c")
        .arg(py_rewrite)
        .arg(&root)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(rust_bytes, output.stdout);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        rust_record
    );
    assert!(vault_origin::require_local(&root).is_ok());
}

#[cfg(unix)]
#[test]
fn config_authority_records_open_in_both_implementations() {
    let Some(python_path) = std::env::var_os("KV_PY_REF") else {
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap();
    let temp = TestDir::new("stage4-authority");
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let previous_home = std::env::var_os("HOME");
    unsafe {
        std::env::set_var("HOME", &home);
    }
    let _home_guard = HomeGuard(previous_home);
    let root = temp.project_root("vault");
    copy_fixture_secrets(&root);
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let master = fixture_master_key();
    vault_origin::record_created(&root).unwrap();

    let float_state = json!({
        "values":[1.0,-0.0,1e-4,1e-5,1e-7,1e15,1e16,1.2345e20]
    });
    let py_canonical = r#"
import json,sys
from kv import config_authority
state={"values":[1.0,-0.0,1e-4,1e-5,1e-7,1e15,1e16,1.2345e20]}
print(json.dumps(config_authority.canonical(state).decode("ascii")))
"#;
    assert_eq!(
        python(&python_path, py_canonical, &root, &home),
        Value::String(
            String::from_utf8(config_authority::canonical(&float_state).unwrap()).unwrap()
        )
    );

    config_authority::approve_config_unattended(&root, &master).unwrap();
    let approved = config_authority::require_approved(&root, &master).unwrap();

    let py_open = r#"
import json,os,sys
from kv import config_authority
root=sys.argv[1]
with open(config_authority._path(root),"rb") as stream:
    blob=stream.read()
state=config_authority._open(root,bytes.fromhex(os.environ["MASTER_KEY"]),blob)
print(json.dumps(state,sort_keys=True))
"#;
    let python_state = python_with_master(&python_path, py_open, &root, &home, master.as_bytes());
    assert_eq!(
        python_state,
        config_authority::authority_state(&approved.value).unwrap()
    );

    let py_approve = r#"
import hashlib,json,os,sys
from kv import config,config_authority,crypto,vault_origin
from kv.fssec import write_private_atomic
root=sys.argv[1]
master=bytes.fromhex(os.environ["MASTER_KEY"])
local=vault_origin.require_local(root)
state=config_authority.authority_state(config.load_config(root))
record={"version":1,"authority":state,"sha256":hashlib.sha256(config_authority.canonical(state)).hexdigest()}
blob=crypto.encrypt(crypto.derive_labeled_key(master,config_authority.LABEL),
                    config_authority.canonical(record),config_authority._aad(root,local))
write_private_atomic(config_authority._path(root),blob,binary=True)
vault_origin.record_config_approval(root,local,hashlib.sha256(blob).hexdigest())
print(json.dumps(state,sort_keys=True))
"#;
    let python_state =
        python_with_master(&python_path, py_approve, &root, &home, master.as_bytes());
    let rust_snapshot = config_authority::require_approved(&root, &master).unwrap();
    assert_eq!(
        python_state,
        config_authority::authority_state(&rust_snapshot.value).unwrap()
    );

    let original = rust_snapshot.value.clone();
    let mut changed = kv_store::config::load_config(&root).unwrap();
    changed.value["providers"] = json!({
        "stage4-probe":{"base_url":"https://example.test","secret_name":"PROBE"}
    });
    kv_store::config::save_config(&root, &mut changed).unwrap();
    let expected = "Config authority changed (providers); run kv vault approve-config at your terminal before unlocking.";
    assert_eq!(
        config_authority::require_approved(&root, &master)
            .err()
            .unwrap()
            .to_string(),
        expected
    );
    let py_check = r#"
import json,os,sys
from kv import config_authority
try:
    config_authority.require_approved(sys.argv[1],master_key=bytes.fromhex(os.environ["MASTER_KEY"]))
except Exception as error:
    print(json.dumps(str(error)))
"#;
    assert_eq!(
        python_with_master(&python_path, py_check, &root, &home, master.as_bytes()),
        Value::String(expected.into())
    );

    let mut changed = kv_store::config::load_config(&root).unwrap();
    changed.value = original;
    kv_store::config::save_config(&root, &mut changed).unwrap();
    let local = vault_origin::require_local(&root).unwrap();
    vault_origin::record_config_approval(&root, &local, "00").unwrap();
    let expected = "The approved config record cannot be verified here; restore the vault at its approved location from a trusted backup.";
    assert_eq!(
        config_authority::require_approved(&root, &master)
            .err()
            .unwrap()
            .to_string(),
        expected
    );
    assert_eq!(
        python_with_master(&python_path, py_check, &root, &home, master.as_bytes()),
        Value::String(expected.into())
    );
}

#[cfg(unix)]
#[test]
fn unsafe_key_refusal_persists_exposed_provenance() {
    let Some(python_path) = std::env::var_os("KV_PY_REF") else {
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap();
    let temp = TestDir::new("stage4-exposed");
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let previous_home = std::env::var_os("HOME");
    unsafe {
        std::env::set_var("HOME", &home);
    }
    let _home_guard = HomeGuard(previous_home);
    let root = temp.project_root("vault");
    copy_fixture_secrets(&root);
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    let root = fs::canonicalize(root).unwrap();
    python(
        &python_path,
        "import json,sys\nfrom kv import vault_origin\nprint(json.dumps(vault_origin.record_created(sys.argv[1])))",
        &root,
        &home,
    );

    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o644)).unwrap();
    let key_refusal = "The key was readable outside its owner or is not private; rotate any affected credentials and create a new vault with kv init.";
    assert_eq!(
        vault_origin::require_local(&root).unwrap_err().to_string(),
        key_refusal
    );
    fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    let exposed_refusal = "The key was previously exposed; rotate any affected credentials and create a new vault with kv init.";
    assert_eq!(
        vault_origin::require_local(&root).unwrap_err().to_string(),
        exposed_refusal
    );

    let py_refusal = r#"
import json,sys
from kv import vault_origin
try:
    vault_origin.require_local(sys.argv[1])
except Exception as error:
    print(json.dumps(str(error)))
"#;
    assert_eq!(
        python(&python_path, py_refusal, &root, &home),
        Value::String(exposed_refusal.into())
    );
}

#[cfg(unix)]
#[test]
fn missing_moved_and_git_tracked_vaults_refuse_like_python() {
    let Some(python_path) = std::env::var_os("KV_PY_REF") else {
        return;
    };
    let _home_lock = HOME_LOCK.lock().unwrap();
    let temp = TestDir::new("stage4-origin-tamper");
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let previous_home = std::env::var_os("HOME");
    unsafe {
        std::env::set_var("HOME", &home);
    }
    let _home_guard = HomeGuard(previous_home);
    use std::os::unix::fs::PermissionsExt;

    let py_refusal = r#"
import json,sys
from kv import vault_origin
try:
    vault_origin.require_local(sys.argv[1])
except Exception as error:
    print(json.dumps(str(error)))
"#;
    let missing_rust = temp.project_root("missing-rust");
    copy_fixture_secrets(&missing_rust);
    fs::set_permissions(
        missing_rust.join(".secrets/key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let missing_rust = fs::canonicalize(missing_rust).unwrap();
    let rust_error = vault_origin::require_local(&missing_rust)
        .unwrap_err()
        .to_string();

    let missing_python = temp.project_root("missing-python");
    copy_fixture_secrets(&missing_python);
    fs::set_permissions(
        missing_python.join(".secrets/key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let missing_python = fs::canonicalize(missing_python).unwrap();
    let python_error = python(&python_path, py_refusal, &missing_python, &home);
    assert_eq!(python_error, Value::String(rust_error));

    let source = temp.project_root("moved-source");
    copy_fixture_secrets(&source);
    fs::set_permissions(
        source.join(".secrets/key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let source = fs::canonicalize(source).unwrap();
    python(
        &python_path,
        "import json,sys\nfrom kv import vault_origin\nprint(json.dumps(vault_origin.record_created(sys.argv[1])))",
        &source,
        &home,
    );
    let moved = temp.project_root("moved-copy");
    copy_tree(&source, &moved);
    let moved = fs::canonicalize(moved).unwrap();
    let rust_error = vault_origin::require_local(&moved).unwrap_err().to_string();
    let python_error = python(&python_path, py_refusal, &moved, &home);
    assert_eq!(python_error, Value::String(rust_error));

    let tracked_rust = temp.project_root("tracked-rust");
    let tracked_python = temp.project_root("tracked-python");
    for root in [&tracked_rust, &tracked_python] {
        copy_fixture_secrets(root);
        fs::set_permissions(root.join(".secrets/key"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let tracked_rust = fs::canonicalize(tracked_rust).unwrap();
    let tracked_python = fs::canonicalize(tracked_python).unwrap();
    for root in [&tracked_rust, &tracked_python] {
        python(
            &python_path,
            "import json,sys\nfrom kv import vault_origin\nprint(json.dumps(vault_origin.record_created(sys.argv[1])))",
            root,
            &home,
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["init", "-q"])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["add", "-f", "--", ".secrets/key"])
                .status()
                .unwrap()
                .success()
        );
    }
    let rust_error = vault_origin::require_local(&tracked_rust)
        .unwrap_err()
        .to_string();
    let python_error = python(&python_path, py_refusal, &tracked_python, &home);
    assert_eq!(python_error, Value::String(rust_error.clone()));
    assert!(
        rust_error.contains("tracked by git"),
        "unexpected tracked-key refusal: {rust_error}"
    );

    let exposed_record = r#"
import json,sys
from kv import vault_origin
with vault_origin._open_folder(create=False) as folder:
    record=vault_origin._read(folder,vault_origin.identity(sys.argv[1]))
print(json.dumps(record,sort_keys=True))
"#;
    let record = python(&python_path, exposed_record, &tracked_rust, &home);
    assert_eq!(record["exposed"], true);
}
