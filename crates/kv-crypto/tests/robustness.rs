use kv_crypto::{
    CryptoError, Identity, Key32, decrypt, encrypt, export_key, import_key, keyfile, recovery, totp,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v0.4.0")
}

fn fixture_json(name: &str) -> Value {
    serde_json::from_slice(&fs::read(fixture_root().join(name)).unwrap()).unwrap()
}

fn hex_bytes(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    getrandom::getrandom(&mut bytes).unwrap();
    bytes
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).unwrap();
    bytes
}

fn random_length() -> usize {
    usize::from(u16::from_ne_bytes(random_array())) % 4097
}

#[test]
fn v4_keyfile_mutations_are_rejected_without_panicking() {
    let fixtures = fixture_json("keys.json");
    let positives = fixtures["positive"].as_array().unwrap();
    assert_eq!(positives.len(), 6);

    let mut lowest_setting = None;
    for vector in positives {
        let file_name = vector["file_name"].as_str().unwrap();
        let raw = fs::read(fixture_root().join("keys").join(file_name)).unwrap();
        let header = keyfile::parse_v4_header(&raw).unwrap();
        let setting_offset = 6 + header.location.len();
        let salt_offset = setting_offset + 3;
        let nonce_offset = salt_offset + 16;
        let ciphertext_offset = nonce_offset + 12;
        assert_eq!(raw.len() - ciphertext_offset, 96, "{file_name}");

        for prefix_length in 0..raw.len() {
            assert!(
                keyfile::parse_v4_header(&raw[..prefix_length]).is_err(),
                "{file_name}: truncation to {prefix_length} bytes"
            );
        }

        for offset in 0..ciphertext_offset {
            let mut mutated = raw.clone();
            mutated[offset] ^= 0xff;
            let parsed = keyfile::parse_v4_header(&mutated);
            let should_parse = (6..setting_offset).contains(&offset) || offset >= salt_offset;
            assert_eq!(
                parsed.is_ok(),
                should_parse,
                "{file_name}: header byte {offset}"
            );
        }

        for offset in ciphertext_offset..raw.len() {
            let mut mutated = raw.clone();
            mutated[offset] ^= 0xff;
            assert!(
                keyfile::parse_v4_header(&mutated).is_ok(),
                "{file_name}: ciphertext byte {offset}"
            );
        }

        for extra_length in [1, 16] {
            let mut appended = raw.clone();
            appended.extend(std::iter::repeat_n(0, extra_length));
            assert!(
                keyfile::parse_v4_header(&appended).is_err(),
                "{file_name}: appended {extra_length} bytes"
            );
        }

        if lowest_setting.is_none() && vector["setting"][0].as_u64() == Some(14) {
            lowest_setting = Some((raw, vector["passphrase"].as_str().unwrap().to_owned()));
        }
    }

    if let Some((raw, passphrase)) = lowest_setting {
        let header = keyfile::parse_v4_header(&raw).unwrap();
        let location_start = 6;
        let location_end = location_start + header.location.len();
        let salt_start = location_end + 3;
        let nonce_start = salt_start + 16;
        let ciphertext_start = nonce_start + 12;
        let candidates = [
            location_start,
            location_end - 1,
            salt_start,
            salt_start + 15,
            nonce_start,
            nonce_start + 11,
            ciphertext_start,
            raw.len() - 1,
        ];

        for offset in candidates {
            let mut mutated = raw.clone();
            mutated[offset] ^= 0xff;
            assert!(keyfile::parse_v4_header(&mutated).is_ok());
            assert!(
                matches!(
                    keyfile::unwrap_v4(&mutated, passphrase.as_bytes()),
                    Err(CryptoError::Auth)
                ),
                "mutated byte {offset}"
            );
        }
    }
}

#[test]
fn aead_truncations_and_byte_flips_return_auth_errors() {
    let vector = &fixture_json("aead.json")["vectors"][0];
    let key = Key32::new(
        hex_bytes(vector["key_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    let aad = vector["aad"].as_str().unwrap().as_bytes();
    let blob = hex_bytes(vector["blob_hex"].as_str().unwrap());

    assert!(decrypt(&key, &blob, aad).is_ok());
    for truncated_bytes in 0..=40 {
        let prefix_length = blob.len().saturating_sub(truncated_bytes);
        let result = decrypt(&key, &blob[..prefix_length], aad);
        if truncated_bytes == 0 {
            assert!(result.is_ok());
        } else {
            assert!(
                matches!(result, Err(CryptoError::Auth)),
                "{truncated_bytes}"
            );
        }
    }

    for offset in 0..blob.len() {
        let mut mutated = blob.clone();
        mutated[offset] ^= 0xff;
        assert!(
            matches!(decrypt(&key, &mutated, aad), Err(CryptoError::Auth)),
            "mutated byte {offset}"
        );
    }
}

#[test]
fn import_recovery_and_totp_malformed_inputs_return_errors() {
    let key = Key32::new(random_array());
    let exported = export_key(&key);
    for prefix_length in 0..exported.len() {
        assert!(import_key(&exported[..prefix_length]).is_err());
    }
    for input in ["", "!", "kvkey_", "kvkey_!!!!!!!!!!!!!!!!!!!!!!!!!!!!"] {
        assert!(import_key(input).is_err());
    }

    let recovery_token = recovery::generate().unwrap();
    for prefix_length in 0..recovery_token.len() {
        assert!(recovery::parse(&recovery_token[..prefix_length]).is_err());
    }
    for input in ["", "!", "kvrecovery_", "not base32", "é"] {
        assert!(recovery::parse(input).is_err());
    }

    let passphrase = b"robustness-test-passphrase";
    let totp_blob =
        totp::encrypt_secret_v3("JBSWY3DPEHPK3PXP", passphrase, Some((14, 8, 1))).unwrap();
    for prefix_length in 0..totp_blob.len() {
        assert!(totp::decrypt_secret_v3(&totp_blob[..prefix_length], passphrase).is_err());
    }
    for input in [
        Vec::new(),
        vec![0; 64],
        b"KVT".to_vec(),
        b"KVT\x03".to_vec(),
    ] {
        assert!(totp::decrypt_secret_v3(&input, passphrase).is_err());
    }
    let mut invalid_setting = totp_blob;
    invalid_setting[4] = u8::MAX;
    assert!(totp::decrypt_secret_v3(&invalid_setting, passphrase).is_err());
}

#[test]
fn randomized_crypto_roundtrips() {
    const ITERATIONS: usize = 200;

    for _ in 0..ITERATIONS {
        let key = Key32::new(random_array());
        let aad = random_bytes(random_length());
        let plaintext = random_bytes(random_length());
        let blob = encrypt(&key, &plaintext, &aad);
        assert_eq!(
            decrypt(&key, &blob, &aad).unwrap().as_slice(),
            plaintext.as_slice()
        );
        let mut wrong_aad = aad.clone();
        wrong_aad.push(0);
        assert!(matches!(
            decrypt(&key, &blob, &wrong_aad),
            Err(CryptoError::Auth)
        ));

        let imported = import_key(&export_key(&key)).unwrap();
        assert!(key == imported);

        let recovery_token = recovery::generate().unwrap();
        let wrapped = recovery::wrap_master_key(&key, &recovery_token).unwrap();
        let recovered = recovery::unwrap_master_key(&wrapped, &recovery_token).unwrap();
        assert!(key == recovered);
    }

    let passphrase = b"randomized-v4-roundtrip-passphrase";
    for _ in 0..2 {
        let identity = Identity::new(Key32::new(random_array()), random_array(), random_array());
        let location = random_bytes(1 + random_length() % 4096);
        let blob = keyfile::wrap_v4(&identity, passphrase, &location, Some((14, 8, 1))).unwrap();
        let recovered = keyfile::unwrap_v4(&blob, passphrase).unwrap();
        assert!(identity.master_key == recovered.master_key);
        assert_eq!(&identity.owner_seed[..], &recovered.owner_seed[..]);
        assert_eq!(identity.local_approval_id, recovered.local_approval_id);
    }
}
