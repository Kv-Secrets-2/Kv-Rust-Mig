#![forbid(unsafe_code)]

use blake2::Blake2bMac;
use blake2::digest::{
    Mac as BlakeMac,
    consts::{U16, U32},
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;
pub use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("{0}")]
    Header(String),
    #[error("authentication failed")]
    Auth,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u8),
    #[error("operating-system randomness unavailable")]
    Randomness,
    #[error("key derivation failed")]
    Kdf,
}

pub struct Key32(Zeroizing<[u8; 32]>);

impl Key32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Key32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for Key32 {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Zeroize for Key32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.as_bytes().ct_eq(other.as_bytes()))
    }
}

impl Eq for Key32 {}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    pub master_key: Key32,
    pub owner_seed: Zeroizing<[u8; 32]>,
    pub local_approval_id: [u8; 16],
}

impl Identity {
    pub fn new(master_key: Key32, owner_seed: [u8; 32], local_approval_id: [u8; 16]) -> Self {
        Self {
            master_key,
            owner_seed: Zeroizing::new(owner_seed),
            local_approval_id,
        }
    }
}

fn randomness(output: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(output).map_err(|_| CryptoError::Randomness)
}

fn keyed_blake2b_32(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac =
        <Blake2bMac<U32> as BlakeMac>::new_from_slice(key).expect("BLAKE2b accepts a 32-byte key");
    mac.update(message);
    let mut digest = mac.finalize().into_bytes();
    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    output
}

pub fn keyed_blake2b_128(key: &Key32, msg: &[u8]) -> [u8; 16] {
    let mut mac = <Blake2bMac<U16> as BlakeMac>::new_from_slice(key.as_bytes())
        .expect("BLAKE2b accepts a 32-byte key");
    mac.update(msg);
    let mut digest = mac.finalize().into_bytes();
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    output
}

fn frame_fields<'a>(fields: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut output = Vec::new();
    for field in fields {
        output.extend_from_slice(&(field.len() as u64).to_be_bytes());
        output.extend_from_slice(field);
    }
    output
}

pub fn derive_labeled_key(master: &Key32, label: &[u8], parts: &[&[u8]]) -> Key32 {
    let mut mac = <Blake2bMac<U32> as BlakeMac>::new_from_slice(master.as_bytes())
        .expect("BLAKE2b accepts a 32-byte key");
    mac.update(&frame_fields(
        std::iter::once(label).chain(parts.iter().copied()),
    ));
    let mut digest = mac.finalize().into_bytes();
    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Key32::from_zeroizing(output)
}

pub fn derive_env_key(master: &Key32, env: &str) -> Key32 {
    Key32::from_zeroizing(keyed_blake2b_32(master.as_bytes(), env.as_bytes()))
}

fn validate_setting(setting: (u8, u8, u8)) -> Result<(), CryptoError> {
    let (log2_n, r, p) = setting;
    if !(14..=17).contains(&log2_n) || r != 8 || p != 1 {
        return Err(CryptoError::Header(format!(
            "scrypt setting out of bounds: log2 N {log2_n}, r {r}, p {p}"
        )));
    }
    Ok(())
}

fn setting_bytes(setting: (u8, u8, u8)) -> [u8; 3] {
    [setting.0, setting.1, setting.2]
}

fn derive_scrypt(
    passphrase: &[u8],
    salt: &[u8; 16],
    setting: (u8, u8, u8),
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    validate_setting(setting)?;
    let params = scrypt::Params::new(setting.0, u32::from(setting.1), u32::from(setting.2), 32)
        .map_err(|_| CryptoError::Kdf)?;
    let mut output = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(passphrase, salt, &params, output.as_mut()).map_err(|_| CryptoError::Kdf)?;
    Ok(output)
}

fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Auth)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Auth)
}

fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Auth)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Auth)
}

pub fn encrypt(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    randomness(&mut nonce).expect("operating-system randomness unavailable");
    let mut blob = nonce.to_vec();
    let ciphertext = aead_seal(key.as_bytes(), &nonce, plaintext, aad)
        .expect("ChaCha20-Poly1305 accepts a 32-byte key and 12-byte nonce");
    blob.extend_from_slice(&ciphertext);
    blob
}

pub fn decrypt(key: &Key32, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < 12 + 16 {
        return Err(CryptoError::Auth);
    }
    let nonce: &[u8; 12] = blob[..12].try_into().map_err(|_| CryptoError::Auth)?;
    let plaintext = aead_open(key.as_bytes(), nonce, &blob[12..], aad)?;
    Ok(Zeroizing::new(plaintext))
}

pub mod keyfile {
    use super::*;

    const MAGIC: &[u8; 4] = b"KVW\x04";
    const MAX_LOCATION_LEN: usize = 4096;
    const PLAINTEXT_LEN: usize = 80;
    const CIPHERTEXT_LEN: usize = PLAINTEXT_LEN + 16;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct V4Header {
        pub location: Vec<u8>,
        pub setting: (u8, u8, u8),
        pub salt: [u8; 16],
        pub nonce: [u8; 12],
    }

    pub fn parse_v4_header(blob: &[u8]) -> Result<V4Header, CryptoError> {
        if blob.len() < 4 || &blob[..3] != b"KVW" {
            return Err(CryptoError::Header("not a wrapped key (bad magic)".into()));
        }
        if blob[3] != 4 {
            return Err(CryptoError::UnsupportedVersion(blob[3]));
        }
        if blob.len() < 6 {
            return Err(CryptoError::Header("v4 key header is truncated".into()));
        }

        let location_len = usize::from(u16::from_be_bytes([blob[4], blob[5]]));
        if location_len == 0 || location_len > MAX_LOCATION_LEN {
            return Err(CryptoError::Header(
                "v4 key location length out of bounds".into(),
            ));
        }
        let expected_len = 6usize
            .checked_add(location_len)
            .and_then(|len| len.checked_add(3 + 16 + 12 + CIPHERTEXT_LEN))
            .ok_or_else(|| CryptoError::Header("v4 key file has the wrong length".into()))?;
        if blob.len() != expected_len {
            return Err(CryptoError::Header(
                "v4 key file has the wrong length".into(),
            ));
        }

        let setting_offset = 6 + location_len;
        let setting = (
            blob[setting_offset],
            blob[setting_offset + 1],
            blob[setting_offset + 2],
        );
        validate_setting(setting)?;
        let salt_offset = setting_offset + 3;
        let nonce_offset = salt_offset + 16;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&blob[salt_offset..nonce_offset]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[nonce_offset..nonce_offset + 12]);
        Ok(V4Header {
            location: blob[6..setting_offset].to_vec(),
            setting,
            salt,
            nonce,
        })
    }

    fn aad(location: &[u8], setting: (u8, u8, u8)) -> Vec<u8> {
        let setting = setting_bytes(setting);
        frame_fields([
            b"kv-master-key+owner-seed-v4".as_slice(),
            MAGIC,
            location,
            &setting,
        ])
    }

    pub fn wrap_v4(
        identity: &Identity,
        passphrase: &[u8],
        location: &[u8],
        setting: Option<(u8, u8, u8)>,
    ) -> Result<Vec<u8>, CryptoError> {
        if location.is_empty() || location.len() > MAX_LOCATION_LEN {
            return Err(CryptoError::Header(
                "v4 key location length out of bounds".into(),
            ));
        }
        let setting = setting.unwrap_or((17, 8, 1));
        validate_setting(setting)?;
        let setting_bytes = setting_bytes(setting);
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        randomness(&mut salt)?;
        randomness(&mut nonce)?;
        let wrapping_key = derive_scrypt(passphrase, &salt, setting)?;
        let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_LEN]);
        plaintext[..32].copy_from_slice(identity.master_key.as_bytes());
        plaintext[32..64].copy_from_slice(&identity.owner_seed[..]);
        plaintext[64..].copy_from_slice(&identity.local_approval_id);
        let ciphertext = aead_seal(
            &wrapping_key,
            &nonce,
            &plaintext[..],
            &aad(location, setting),
        )?;

        let mut blob = Vec::with_capacity(
            6 + location.len() + 3 + salt.len() + nonce.len() + ciphertext.len(),
        );
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&(location.len() as u16).to_be_bytes());
        blob.extend_from_slice(location);
        blob.extend_from_slice(&setting_bytes);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    pub fn unwrap_v4(blob: &[u8], passphrase: &[u8]) -> Result<Identity, CryptoError> {
        let header = parse_v4_header(blob)?;
        let wrapping_key = derive_scrypt(passphrase, &header.salt, header.setting)?;
        let aad = aad(&header.location, header.setting);
        let ciphertext_offset = 6 + header.location.len() + 3 + 16 + 12;
        let plaintext = Zeroizing::new(aead_open(
            &wrapping_key,
            &header.nonce,
            &blob[ciphertext_offset..],
            &aad,
        )?);
        if plaintext.len() != PLAINTEXT_LEN {
            return Err(CryptoError::Header(
                "v4 key plaintext has the wrong length".into(),
            ));
        }
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&plaintext[..32]);
        let mut owner_seed = Zeroizing::new([0u8; 32]);
        owner_seed.copy_from_slice(&plaintext[32..64]);
        let mut local_approval_id = Zeroizing::new([0u8; 16]);
        local_approval_id.copy_from_slice(&plaintext[64..]);
        Ok(Identity {
            master_key: Key32::from_zeroizing(master_key),
            owner_seed,
            local_approval_id: *local_approval_id,
        })
    }
}

pub mod totp {
    use super::*;
    use data_encoding::BASE32;
    use hmac::{Hmac, Mac as HmacMac};
    use sha1::Sha1;

    const MAGIC: &[u8; 4] = b"KVT\x03";
    const MIN_SECRET_LEN: usize = 16;
    const MAX_SECRET_LEN: usize = 128;
    const HEADER_LEN: usize = 4 + 3 + 16 + 12;

    fn decode_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        BASE32
            .decode(secret.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Header("TOTP secret is not valid base32".into()))
    }

    pub fn code(secret_b32: &str, unix_time: i64) -> Result<String, CryptoError> {
        if unix_time < 0 {
            return Err(CryptoError::Header(
                "TOTP timestamp must not be negative".into(),
            ));
        }
        let key = decode_secret(secret_b32)?;
        let counter = (unix_time as u64) / 30;
        let mut mac =
            <Hmac<Sha1> as HmacMac>::new_from_slice(&key[..]).map_err(|_| CryptoError::Kdf)?;
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0x0f);
        let binary = u32::from_be_bytes([
            digest[offset],
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]) & 0x7fff_ffff;
        Ok(format!("{:06}", binary % 1_000_000))
    }

    fn percent_encode(text: &str) -> String {
        let mut output = String::new();
        for byte in text.as_bytes() {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(byte) {
                output.push(char::from(*byte));
            } else {
                use std::fmt::Write;
                let _ = write!(&mut output, "%{byte:02X}");
            }
        }
        output
    }

    pub fn uri(secret: &str, account: &str, issuer: &str) -> Result<String, CryptoError> {
        if issuer.contains(':') {
            return Err(CryptoError::Header(
                "TOTP issuer must not contain ':'".into(),
            ));
        }
        if account.contains(':') {
            return Err(CryptoError::Header(
                "TOTP account must not contain ':'".into(),
            ));
        }
        Ok(format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            percent_encode(issuer),
            percent_encode(account),
            percent_encode(secret),
            percent_encode(issuer),
        ))
    }

    fn aad(setting: (u8, u8, u8)) -> Vec<u8> {
        let setting = setting_bytes(setting);
        frame_fields([b"kv-totp-secret-v3".as_slice(), MAGIC, &setting])
    }

    pub fn encrypt_secret_v3(
        secret_b32: &str,
        passphrase: &[u8],
        setting: Option<(u8, u8, u8)>,
    ) -> Result<Vec<u8>, CryptoError> {
        let _decoded_secret = decode_secret(secret_b32)?;
        let plaintext = secret_b32.as_bytes();
        if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&plaintext.len()) {
            return Err(CryptoError::Header(
                "TOTP secret has an unexpected length for TOTP v3".into(),
            ));
        }
        let setting = setting.unwrap_or((17, 8, 1));
        validate_setting(setting)?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        randomness(&mut salt)?;
        randomness(&mut nonce)?;
        let wrapping_key = derive_scrypt(passphrase, &salt, setting)?;
        let ciphertext = aead_seal(&wrapping_key, &nonce, plaintext, &aad(setting))?;
        let mut blob = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&setting_bytes(setting));
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    pub fn decrypt_secret_v3(
        blob: &[u8],
        passphrase: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if blob.len() < 4 || &blob[..3] != b"KVT" {
            return Err(CryptoError::Header("TOTP blob has bad magic".into()));
        }
        if blob[3] != 3 {
            return Err(CryptoError::UnsupportedVersion(blob[3]));
        }
        if blob.len() < HEADER_LEN + 16 + MIN_SECRET_LEN {
            return Err(CryptoError::Header(
                "TOTP v3 blob has the wrong length".into(),
            ));
        }
        let plaintext_len = blob.len() - HEADER_LEN - 16;
        if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&plaintext_len) {
            return Err(CryptoError::Header(
                "TOTP v3 blob has the wrong length".into(),
            ));
        }
        let setting = (blob[4], blob[5], blob[6]);
        validate_setting(setting)?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&blob[7..23]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[23..35]);
        let wrapping_key = derive_scrypt(passphrase, &salt, setting)?;
        let plaintext = Zeroizing::new(aead_open(
            &wrapping_key,
            &nonce,
            &blob[HEADER_LEN..],
            &aad(setting),
        )?);
        if plaintext.len() != plaintext_len || decode_secret_bytes(&plaintext).is_err() {
            return Err(CryptoError::Header(
                "TOTP secret is not valid ASCII base32".into(),
            ));
        }
        Ok(plaintext)
    }

    fn decode_secret_bytes(secret: &[u8]) -> Result<(), CryptoError> {
        if !secret.is_ascii() {
            return Err(CryptoError::Header(
                "TOTP secret must be ASCII base32".into(),
            ));
        }
        BASE32
            .decode(secret)
            .map(Zeroizing::new)
            .map(|_| ())
            .map_err(|_| CryptoError::Header("TOTP secret is not valid base32".into()))
    }
}

pub mod recovery {
    use super::*;
    use data_encoding::{BASE32, BASE32_NOPAD, BASE64URL};

    const PREFIX: &str = "kvrecovery_";
    const MAGIC: &[u8; 4] = b"KVR\x01";
    const AAD: &[u8] = b"kv-recovery-key";

    pub fn generate() -> Result<String, CryptoError> {
        let mut key = Zeroizing::new([0u8; 32]);
        randomness(key.as_mut())?;
        let encoded = BASE32_NOPAD.encode(&key[..]);
        let grouped = encoded
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).expect("base32 is ASCII"))
            .collect::<Vec<_>>()
            .join("-");
        Ok(format!("{PREFIX}{grouped}"))
    }

    pub fn parse(token: &str) -> Result<Key32, CryptoError> {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::Header("recovery key is empty".into()));
        }
        let body = trimmed.strip_prefix(PREFIX).unwrap_or(trimmed);
        let normalized: String = body
            .chars()
            .filter(|character| *character != '-')
            .flat_map(char::to_uppercase)
            .collect();
        let padding = "=".repeat((8 - normalized.len() % 8) % 8);
        let padded = format!("{normalized}{padding}");
        let decoded = BASE32
            .decode(padded.as_bytes())
            .or_else(|_| BASE32_NOPAD.decode(normalized.as_bytes()))
            .map_err(|_| CryptoError::Header("invalid recovery key encoding".into()))?;
        let decoded = Zeroizing::new(decoded);
        if decoded.len() != 32 {
            return Err(CryptoError::Header(format!(
                "invalid recovery key length: expected 32 bytes, got {}",
                decoded.len()
            )));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&decoded);
        Ok(Key32::from_zeroizing(bytes))
    }

    pub fn wrap_master_key(
        master_key: &Key32,
        recovery_token: &str,
    ) -> Result<String, CryptoError> {
        let recovery_key = parse(recovery_token)?;
        let mut nonce = [0u8; 12];
        randomness(&mut nonce)?;
        let ciphertext = aead_seal(recovery_key.as_bytes(), &nonce, master_key.as_bytes(), AAD)?;
        let mut blob = Vec::with_capacity(MAGIC.len() + nonce.len() + ciphertext.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(BASE64URL.encode(&blob))
    }

    pub fn unwrap_master_key(
        wrapped_base64: &str,
        recovery_token: &str,
    ) -> Result<Key32, CryptoError> {
        let blob = BASE64URL
            .decode(wrapped_base64.as_bytes())
            .map_err(|_| CryptoError::Header("invalid recovery blob encoding".into()))?;
        if blob.len() < 4 || &blob[..4] != MAGIC {
            return Err(CryptoError::Header("invalid recovery blob".into()));
        }
        if blob.len() < 4 + 12 {
            return Err(CryptoError::Header("recovery blob is truncated".into()));
        }
        let recovery_key = parse(recovery_token)?;
        let nonce: &[u8; 12] = blob[4..16]
            .try_into()
            .map_err(|_| CryptoError::Header("recovery blob is truncated".into()))?;
        let plaintext =
            Zeroizing::new(aead_open(recovery_key.as_bytes(), nonce, &blob[16..], AAD)?);
        if plaintext.len() != 32 {
            return Err(CryptoError::Header(
                "recovered master key has the wrong length".into(),
            ));
        }
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&plaintext);
        Ok(Key32::from_zeroizing(master_key))
    }
}

pub mod backup_codes {
    use super::*;
    use sha2::{Digest, Sha256};

    pub fn normalize(code: &str) -> String {
        code.trim().replace(['-', ' '], "").to_uppercase()
    }

    pub fn hash(code: &str) -> Result<String, CryptoError> {
        let normalized = normalize(code);
        if normalized.is_empty() {
            return Err(CryptoError::Header("backup code is empty".into()));
        }
        if !normalized.is_ascii() {
            return Err(CryptoError::Header(
                "backup code must contain ASCII characters".into(),
            ));
        }
        let digest = Sha256::digest(normalized.as_bytes());
        Ok(encode_hex(&digest))
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty12",
    "iloveyou",
    "sunshine",
    "princess",
    "football",
    "charlie",
    "shadow12",
    "passw0rd",
    "trustno1",
    "letmein1",
    "dragon12",
    "baseball",
    "master12",
    "michael1",
    "jennifer",
    "jordan23",
    "superman",
    "harley12",
    "password1",
    "password2",
    "password3",
    "qwerty123",
    "abc12345",
    "monkey12",
    "shadow123",
    "12341234",
    "11111111",
    "00000000",
    "abcdefgh",
    "qwertyui",
    "asdfghjk",
    "zxcvbnm1",
    "admin123",
    "test1234",
    "welcome1",
    "mustang1",
    "access14",
    "hello123",
    "charlie1",
    "donald12",
    "love1234",
    "ashley12",
    "michael!",
    "internet",
    "whatever",
    "starwars",
    "computer",
    "corvette",
    "maverick",
    "samantha",
    "steelers",
    "dolphins",
    "jackson1",
    "1q2w3e4r",
    "q1w2e3r4",
    "1qaz2wsx",
    "zaq1xsw2",
    "pass1234",
    "passpass",
    "testtest",
    "changeme",
    "welcome!",
    "baseball1",
    "football1",
    "basketball",
    "qwert123",
    "1234qwer",
    "abcd1234",
    "dragon123",
    "monkey123",
    "shadow1234",
    "sunshine1",
    "princess1",
    "password!",
    "password@",
    "p@ssw0rd",
    "p@ssword",
    "passw0rd!",
    "secret12",
    "secret123",
    "mysecret",
    "12345678!",
    "iloveyou1",
    "trustno1!",
    "letmein!",
];

pub fn passphrase_strength(passphrase: &str) -> (bool, &'static str) {
    let normalized = passphrase.trim().to_lowercase();
    if COMMON_PASSWORDS.contains(&normalized.as_str()) {
        return (
            false,
            "this passphrase is too common — it appears in breach databases",
        );
    }
    let length = passphrase.chars().count();
    if length < 12 {
        return (false, "passphrase must be at least 12 characters");
    }
    let mut chars = passphrase.chars();
    if let Some(first) = chars.next()
        && chars.all(|character| character == first)
    {
        return (false, "passphrase cannot be a single repeated character");
    }
    if passphrase.chars().all(char::is_numeric) && length < 16 {
        return (
            false,
            "all-digit passphrases under 16 characters are too weak",
        );
    }
    (true, "")
}

pub fn export_key(master_key: &Key32) -> String {
    use data_encoding::BASE64URL_NOPAD;
    format!("kvkey_{}", BASE64URL_NOPAD.encode(master_key.as_bytes()))
}

pub fn import_key(token: &str) -> Result<Key32, CryptoError> {
    use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD};
    let (body, prefixed) = match token.strip_prefix("kvkey_") {
        Some(body) => (body, true),
        None => (token, false),
    };
    let encoded = body.strip_suffix('=').unwrap_or(body);
    let url_safe = encoded
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    let standard = encoded
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/');
    if encoded.len() != 43
        || body.len() > 44
        || (body.ends_with('=') && body.len() != 44)
        || (prefixed && !url_safe)
        || (!url_safe && !standard)
    {
        return Err(CryptoError::Header("invalid master key text".into()));
    }
    let decoded = if url_safe {
        BASE64URL_NOPAD.decode(encoded.as_bytes())
    } else {
        BASE64_NOPAD.decode(encoded.as_bytes())
    }
    .map_err(|_| CryptoError::Header("invalid master key text".into()))?;
    let decoded = Zeroizing::new(decoded);
    let canonical = if url_safe {
        BASE64URL_NOPAD.encode(&decoded)
    } else {
        BASE64_NOPAD.encode(&decoded)
    };
    if decoded.len() != 32 || canonical != encoded {
        return Err(CryptoError::Header(
            "invalid master key text: non-canonical final character".into(),
        ));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&decoded);
    Ok(Key32::from_zeroizing(bytes))
}

#[cfg(test)]
mod tests {
    use super::{Key32, keyed_blake2b_128};

    #[test]
    fn keyed_blake2b_128_matches_python_hashlib_vector() {
        let key = Key32::new(std::array::from_fn(|index| index as u8));
        assert_eq!(
            keyed_blake2b_128(&key, b"dev"),
            [
                0xec, 0xe2, 0xe1, 0x9c, 0xd5, 0x74, 0x6d, 0xb8, 0x71, 0xe3, 0x30, 0x86, 0x79, 0xca,
                0x9f, 0x52,
            ]
        );
    }
}
