use blake2::Blake2bMac;
use blake2::digest::{Mac as BlakeMac, consts::U16};
use data_encoding::{BASE64_NOPAD, BASE64URL};
use kv_crypto::{
    CryptoError, Identity, Key32, backup_codes, decrypt, derive_env_key, derive_labeled_key,
    encrypt, export_key, import_key, keyfile, passphrase_strength, recovery, totp,
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

fn hex_string(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 15) as usize]));
    }
    output
}

fn key32(hex: &str) -> Key32 {
    Key32::new(hex_bytes(hex).try_into().unwrap())
}

#[test]
fn every_labeled_key_vector_matches_python() {
    let data = fixture_json("labeled_keys.json");
    let mut count = 0;
    for master in data["vectors"].as_array().unwrap() {
        let key = key32(master["master_key_hex"].as_str().unwrap());
        for vector in master["vectors"].as_array().unwrap() {
            let parts: Vec<Vec<u8>> = vector["parts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|part| match part["type"].as_str().unwrap() {
                    "str" => part["value"].as_str().unwrap().as_bytes().to_vec(),
                    "bytes" => hex_bytes(part["hex"].as_str().unwrap()),
                    other => panic!("unexpected fixture part type {other}"),
                })
                .collect();
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            let derived =
                derive_labeled_key(&key, vector["label"].as_str().unwrap().as_bytes(), &refs);
            assert_eq!(
                hex_string(derived.as_bytes()),
                vector["derived_key_hex"].as_str().unwrap()
            );
            count += 1;
        }
    }
    assert_eq!(count, 18);
    let env_key = derive_env_key(
        &key32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        "dev",
    );
    assert_eq!(
        hex_string(env_key.as_bytes()),
        "80570e8ac0eb6a2bf5f4d5de516b6803fbbacf2e0bf4feb6ba4f4b4866295946"
    );
}

#[test]
fn every_aead_fixture_vector_matches_python() {
    let data = fixture_json("aead.json");
    for vector in data["vectors"].as_array().unwrap() {
        let key = key32(vector["key_hex"].as_str().unwrap());
        let plaintext = decrypt(
            &key,
            &hex_bytes(vector["blob_hex"].as_str().unwrap()),
            vector["aad"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(
            plaintext.as_slice(),
            hex_bytes(vector["plaintext_hex"].as_str().unwrap())
        );
    }
    let first_key = key32(data["vectors"][0]["key_hex"].as_str().unwrap());
    for vector in data["tampered"].as_array().unwrap() {
        assert_eq!(vector["python_outcome"], "InvalidTag");
        let original = hex_bytes(vector["original_blob_hex"].as_str().unwrap());
        assert!(decrypt(&first_key, &original, b"tamper-aad").is_ok());
        let tampered = hex_bytes(vector["tampered_blob_hex"].as_str().unwrap());
        assert!(matches!(
            decrypt(&first_key, &tampered, b"tamper-aad"),
            Err(CryptoError::Auth)
        ));
    }
}

#[test]
fn every_keyfile_fixture_matches_its_rust_category() {
    let data = fixture_json("keys.json");
    let key_root = fixture_root().join("keys");
    let mut count = 0;
    for vector in data["positive"].as_array().unwrap() {
        let raw = fs::read(key_root.join(vector["file_name"].as_str().unwrap())).unwrap();
        let header = keyfile::parse_v4_header(&raw).unwrap();
        assert_eq!(
            header.location,
            hex_bytes(vector["location_hex"].as_str().unwrap())
        );
        let setting = vector["setting"].as_array().unwrap();
        assert_eq!(
            header.setting,
            (
                setting[0].as_u64().unwrap() as u8,
                setting[1].as_u64().unwrap() as u8,
                setting[2].as_u64().unwrap() as u8,
            )
        );
        assert_eq!(header.salt.len(), 16);
        assert_eq!(header.nonce.len(), 12);
        let identity =
            keyfile::unwrap_v4(&raw, vector["passphrase"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(
            hex_string(identity.master_key.as_bytes()),
            vector["expected"]["master_key_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex_string(&identity.owner_seed[..]),
            vector["expected"]["owner_seed_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex_string(&identity.local_approval_id),
            vector["expected"]["local_approval_id_hex"]
                .as_str()
                .unwrap()
        );
        count += 1;
    }
    assert_eq!(count, 6);

    for vector in data["negative"].as_array().unwrap() {
        let raw = fs::read(key_root.join(vector["file_name"].as_str().unwrap())).unwrap();
        let expected = vector["rust_expected"].as_str().unwrap();
        match expected {
            "header_error" => {
                assert!(
                    matches!(keyfile::parse_v4_header(&raw), Err(CryptoError::Header(_))),
                    "{}",
                    vector["name"]
                );
            }
            "unsupported_version" => {
                assert!(
                    matches!(
                        keyfile::parse_v4_header(&raw),
                        Err(CryptoError::UnsupportedVersion(_))
                    ),
                    "{}",
                    vector["name"]
                );
            }
            "auth_error" => {
                assert!(keyfile::parse_v4_header(&raw).is_ok(), "{}", vector["name"]);
                let passphrase = data["positive"][0]["passphrase"].as_str().unwrap();
                assert!(
                    matches!(
                        keyfile::unwrap_v4(&raw, passphrase.as_bytes()),
                        Err(CryptoError::Auth)
                    ),
                    "{}",
                    vector["name"]
                );
            }
            other => panic!("unexpected Rust category {other}"),
        }
        count += 1;
    }
    assert_eq!(count, 23);
}

#[test]
fn every_totp_fixture_matches_python_or_the_v3_version_boundary() {
    let data = fixture_json("totp.json");
    for vector in data["codes"].as_array().unwrap() {
        assert_eq!(
            totp::code(
                vector["secret"].as_str().unwrap(),
                vector["time"].as_i64().unwrap()
            )
            .unwrap(),
            vector["code"].as_str().unwrap()
        );
    }
    for vector in data["uris"].as_array().unwrap() {
        assert_eq!(
            totp::uri(
                vector["secret"].as_str().unwrap(),
                vector["account"].as_str().unwrap(),
                vector["issuer"].as_str().unwrap(),
            )
            .unwrap(),
            vector["uri"].as_str().unwrap()
        );
    }
    for vector in data["encrypted_v3"].as_array().unwrap() {
        let raw = BASE64URL
            .decode(vector["blob_base64"].as_str().unwrap().as_bytes())
            .unwrap();
        assert_eq!(raw, hex_bytes(vector["blob_hex"].as_str().unwrap()));
        let secret =
            totp::decrypt_secret_v3(&raw, vector["passphrase"].as_str().unwrap().as_bytes())
                .unwrap();
        assert_eq!(
            secret.as_slice(),
            vector["secret"].as_str().unwrap().as_bytes()
        );
    }
    for vector in data["negative"].as_array().unwrap() {
        let raw = BASE64URL
            .decode(vector["blob_base64"].as_str().unwrap().as_bytes())
            .unwrap();
        let result =
            totp::decrypt_secret_v3(&raw, vector["passphrase"].as_str().unwrap().as_bytes());
        match vector["name"].as_str().unwrap() {
            "real-v2-blob" => assert!(matches!(result, Err(CryptoError::UnsupportedVersion(2)))),
            "v3-truncated-by-one" => {
                assert!(matches!(result, Err(CryptoError::Auth)))
            }
            "v3-tag-byte-flipped" => assert!(matches!(result, Err(CryptoError::Auth))),
            name => panic!("unexpected negative TOTP fixture {name}"),
        }
    }
}

#[test]
fn every_recovery_fixture_matches_python() {
    let data = fixture_json("recovery.json");
    for vector in data["wrapped_keys"].as_array().unwrap() {
        let parsed = recovery::parse(vector["token"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex_string(parsed.as_bytes()),
            vector["parsed_recovery_key_hex"].as_str().unwrap()
        );
        let master = recovery::unwrap_master_key(
            vector["wrapped_base64"].as_str().unwrap(),
            vector["token"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex_string(master.as_bytes()),
            vector["master_key_hex"].as_str().unwrap()
        );
        let generated = recovery::generate().unwrap();
        let wrapped = recovery::wrap_master_key(&master, &generated).unwrap();
        assert!(recovery::unwrap_master_key(&wrapped, &generated).unwrap() == master);
    }
    for vector in data["malformed_tokens"].as_array().unwrap() {
        assert!(
            recovery::parse(vector["token"].as_str().unwrap()).is_err(),
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn every_backup_and_key_sharing_fixture_matches_python() {
    let data = fixture_json("backup_codes.json");
    for vector in data["codes"].as_array().unwrap() {
        let code = vector["code"].as_str().unwrap();
        assert_eq!(
            backup_codes::normalize(code),
            vector["normalized"].as_str().unwrap()
        );
        assert_eq!(
            backup_codes::hash(code).unwrap(),
            vector["sha256_hex"].as_str().unwrap()
        );
    }
    for vector in data["passphrase_strength"].as_array().unwrap() {
        let (ok, reason) = passphrase_strength(vector["passphrase"].as_str().unwrap());
        assert_eq!(ok, vector["ok"].as_bool().unwrap());
        assert_eq!(reason, vector["reason"].as_str().unwrap());
    }
    for vector in data["key_export_import"].as_array().unwrap() {
        let master = key32(vector["master_key_hex"].as_str().unwrap());
        let token = export_key(&master);
        assert_eq!(token, vector["token"].as_str().unwrap());
        let imported = import_key(&token).unwrap();
        assert!(imported == master);
        assert!(import_key(token.strip_prefix("kvkey_").unwrap()).unwrap() == master);
        assert!(import_key(&BASE64_NOPAD.encode(master.as_bytes())).unwrap() == master);
        assert_eq!(
            hex_string(imported.as_bytes()),
            vector["imported_key_hex"].as_str().unwrap()
        );
    }
    for vector in data["malformed_key_tokens"].as_array().unwrap() {
        assert!(
            import_key(vector["token"].as_str().unwrap()).is_err(),
            "{}",
            vector["name"]
        );
    }
}

fn drawer_env_id(master: &Key32, env: &str) -> String {
    let key = derive_labeled_key(master, b"kv-drawer:env-id", &[]);
    let mut mac = <Blake2bMac<U16> as BlakeMac>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(env.as_bytes());
    format!("e_{}", hex_string(&mac.finalize().into_bytes()))
}

#[test]
fn drawer_vault_indexes_records_and_env_ids_match_python() {
    let expected = fixture_json("vaults/basic.expected.json");
    let root = fixture_root().join("vaults/basic/.secrets");
    let key_blob = fs::read(root.join("key")).unwrap();
    let header = keyfile::parse_v4_header(&key_blob).unwrap();
    assert_eq!(
        header.location,
        hex_bytes(expected["location_hex"].as_str().unwrap())
    );
    let identity = keyfile::unwrap_v4(
        &key_blob,
        expected["passphrase"].as_str().unwrap().as_bytes(),
    )
    .unwrap();

    for (env, expected_id) in expected["env_id"].as_object().unwrap() {
        let expected_id = expected_id.as_str().unwrap();
        let computed_id = drawer_env_id(&identity.master_key, env);
        assert_eq!(computed_id, expected_id);
        let env_dir = root.join("drawers/envs").join(expected_id);
        let index_blob = fs::read(env_dir.join("index.kvi")).unwrap();
        assert_eq!(&index_blob[..4], b"KVI\x01");
        let index_key =
            derive_labeled_key(&identity.master_key, b"kv-drawer:index", &[env.as_bytes()]);
        let index_aad = format!("kv-drawer:index:v1:{env}");
        let index_plaintext = decrypt(&index_key, &index_blob[4..], index_aad.as_bytes()).unwrap();
        let index: Value = serde_json::from_slice(&index_plaintext).unwrap();
        assert_eq!(index["env"].as_str().unwrap(), env);
        assert_eq!(index["version"].as_u64().unwrap(), 1);

        let expected_secrets = expected["live_secrets"][env].as_object().unwrap();
        let entries = index["secrets"].as_object().unwrap();
        for (name, value) in expected_secrets {
            let entry = &entries[name];
            assert_eq!(entry["state"], "live");
            if name == "API_KEY" {
                assert_eq!(
                    entry["generation"].as_u64().unwrap(),
                    expected["api_key_generation"].as_u64().unwrap()
                );
            }
            let record_id = entry["current_record_id"].as_str().unwrap();
            let generation = entry["generation"].as_u64().unwrap();
            let record_blob =
                fs::read(env_dir.join("records").join(format!("{record_id}.kvs"))).unwrap();
            assert_eq!(&record_blob[..4], b"KVS\x01");
            let record_key = derive_labeled_key(
                &identity.master_key,
                b"kv-drawer:record",
                &[env.as_bytes(), record_id.as_bytes()],
            );
            let record_aad =
                format!("kv-drawer:record\0v1\0{env}\0{name}\0{record_id}\0{generation}");
            let record_plaintext =
                decrypt(&record_key, &record_blob[4..], record_aad.as_bytes()).unwrap();
            let record: Value = serde_json::from_slice(&record_plaintext).unwrap();
            assert_eq!(record["env"].as_str().unwrap(), env.as_str());
            assert_eq!(record["name"].as_str().unwrap(), name.as_str());
            assert_eq!(record["record_id"], record_id);
            assert_eq!(record["generation"].as_u64().unwrap(), generation);
            assert_eq!(&record["value"], value);
        }

        let live_names: Vec<&str> = entries
            .iter()
            .filter_map(|(name, entry)| (entry["state"] == "live").then_some(name.as_str()))
            .collect();
        let mut expected_names: Vec<&str> = expected_secrets.keys().map(String::as_str).collect();
        expected_names.sort_unstable();
        let mut actual_names = live_names;
        actual_names.sort_unstable();
        assert_eq!(actual_names, expected_names);
        if env == "dev" {
            let removed = expected["removed_name"].as_str().unwrap();
            assert_ne!(entries[removed]["state"], "live");
        }
    }
}

fn random_bytes(output: &mut [u8]) {
    getrandom::getrandom(output).unwrap();
}

#[test]
fn randomized_aead_roundtrips() {
    for _ in 0..64 {
        let mut key_bytes = [0u8; 32];
        random_bytes(&mut key_bytes);
        let key = Key32::new(key_bytes);
        let mut plaintext = vec![0u8; usize::from(key_bytes[0]) * 4];
        let mut aad = vec![0u8; usize::from(key_bytes[1])];
        random_bytes(&mut plaintext);
        random_bytes(&mut aad);
        let blob = encrypt(&key, &plaintext, &aad);
        assert_eq!(decrypt(&key, &blob, &aad).unwrap().as_slice(), plaintext);
    }
}

#[test]
fn random_keyfile_mutations_never_panic() {
    let identity = Identity::new(Key32::new([0x31; 32]), [0x52; 32], [0x73; 16]);
    let blob = keyfile::wrap_v4(
        &identity,
        b"mutation test passphrase",
        b"/test/location",
        Some((14, 8, 1)),
    )
    .unwrap();
    for _ in 0..64 {
        let mut random = [0u8; 8];
        random_bytes(&mut random);
        let index = u64::from_le_bytes(random) as usize % blob.len();
        let mask = (random[0] | 1).rotate_left(1);
        let mut mutated = blob.clone();
        mutated[index] ^= mask;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = keyfile::parse_v4_header(&mutated);
            let _ = keyfile::unwrap_v4(&mutated, b"mutation test passphrase");
        }));
        assert!(result.is_ok(), "mutation at byte {index} panicked");
    }
}
