#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use kv_crypto::{Key32, keyfile};
use serde_json::Value;

pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v0.4.0")
}

pub fn fixture_expected() -> Value {
    serde_json::from_slice(
        &fs::read(fixture_root().join("vaults/basic.expected.json")).expect("fixture expected"),
    )
    .expect("fixture JSON")
}

pub fn fixture_master_key() -> Key32 {
    let expected = fixture_expected();
    let passphrase = expected["passphrase"].as_str().expect("fixture passphrase");
    let wrapped_key =
        fs::read(fixture_root().join("vaults/basic/.secrets/key")).expect("fixture wrapped key");
    let identity =
        keyfile::unwrap_v4(&wrapped_key, passphrase.as_bytes()).expect("unwrap fixture key");
    Key32::new(*identity.master_key.as_bytes())
}

pub fn key_copy(master: &Key32) -> Key32 {
    Key32::new(*master.as_bytes())
}

pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new(label: &str) -> Self {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).expect("test randomness");
        let path = std::env::temp_dir().join(format!(
            "kv-store-{label}-{}-{}",
            std::process::id(),
            hex(&random)
        ));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn project_root(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn copy_fixture_secrets(project_root: &Path) -> PathBuf {
    fs::create_dir_all(project_root).expect("create project root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(project_root, fs::Permissions::from_mode(0o700))
            .expect("make copied project private");
    }
    let source = fixture_root().join("vaults/basic/.secrets");
    let destination = project_root.join(".secrets");
    copy_dir_all(&source, &destination).expect("copy fixture secrets");
    destination
}

pub fn copy_dir_all(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::metadata(source)?.permissions())?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(std::io::Error::other(
                "fixture copy encountered an unexpected symlink",
            ));
        }
        if file_type.is_dir() {
            copy_dir_all(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
        } else {
            return Err(std::io::Error::other(
                "fixture copy encountered a non-regular entry",
            ));
        }
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex digit");
            let low = (pair[1] as char).to_digit(16).expect("hex digit");
            ((high << 4) | low) as u8
        })
        .collect()
}
