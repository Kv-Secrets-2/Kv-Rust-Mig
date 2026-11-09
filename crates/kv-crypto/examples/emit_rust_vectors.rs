use kv_crypto::{Identity, Key32, encrypt, keyfile, totp};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[(byte >> 4) as usize]));
        output.push(char::from(DIGITS[(byte & 15) as usize]));
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: emit_rust_vectors <output-directory>",
            )
        })?;
    fs::create_dir_all(&output_dir)?;

    let passphrase = b"stage1-rust-key-passphrase";
    let location = b"/rust/vector/vault";
    let identity = Identity::new(Key32::new([0x11; 32]), [0x22; 32], [0x33; 16]);
    let key_blob = keyfile::wrap_v4(&identity, passphrase, location, Some((14, 8, 1)))?;
    fs::write(output_dir.join("key-v4.kvw"), &key_blob)?;

    let aead_key = Key32::new(std::array::from_fn(|index| index as u8));
    let aead_aad = "rust-to-python-aead";
    let aead_plaintext = b"Rust kv-crypto reverse-direction vector";
    let aead_blob = encrypt(&aead_key, aead_plaintext, aead_aad.as_bytes());
    fs::write(output_dir.join("aead.bin"), &aead_blob)?;

    let totp_passphrase = b"stage1-rust-totp-passphrase";
    let totp_secret = "JBSWY3DPEHPK3PXP";
    let totp_blob = totp::encrypt_secret_v3(totp_secret, totp_passphrase, Some((14, 8, 1)))?;
    fs::write(output_dir.join("totp-v3.bin"), &totp_blob)?;

    let metadata = json!({
        "key": {
            "file": "key-v4.kvw",
            "passphrase": String::from_utf8_lossy(passphrase),
            "location_hex": hex(location),
            "master_key_hex": hex(identity.master_key.as_bytes()),
            "owner_seed_hex": hex(&identity.owner_seed[..]),
            "local_approval_id_hex": hex(&identity.local_approval_id),
        },
        "aead": {
            "file": "aead.bin",
            "key_hex": hex(aead_key.as_bytes()),
            "aad": aead_aad,
            "plaintext_hex": hex(aead_plaintext),
        },
        "totp": {
            "file": "totp-v3.bin",
            "passphrase": String::from_utf8_lossy(totp_passphrase),
            "secret": totp_secret,
            "setting": [14, 8, 1],
        }
    });
    fs::write(
        output_dir.join("vectors.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    println!("rust_outputs={}", output_dir.display());
    println!("files=key-v4.kvw,aead.bin,totp-v3.bin,vectors.json");
    Ok(())
}
