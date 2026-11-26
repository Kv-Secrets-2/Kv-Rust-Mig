//! Versioned authenticated audit-chain format and verifier.
//!
//! The format is anchored by a broker-supplied secret chain key, an opaque
//! broker-supplied vault identity, and an independently trusted head/count.
//! Without that complete trust tuple the verifier returns
//! [`ChainVerification::MissingTrustState`] instead of calling the log valid.

use std::fmt;
use std::io::Read;
use std::path::Path;

use hmac::{Hmac, Mac as HmacMac};
use serde::Serialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::fs::{Directory, LOG};

pub const CHAIN_FORMAT_VERSION: u64 = 1;
pub const MAX_CHAIN_ENTRY_BYTES: usize = 1024 * 1024;
pub const MAX_VAULT_IDENTITY_BYTES: usize = 4096;

const DOMAIN: &[u8] = b"kv-audit-chain-v1\0";
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const TAIL_READ_CHUNK_BYTES: usize = 8192;
const MAX_CHAIN_JSON_DEPTH: usize = 127;

type HmacSha256 = Hmac<Sha256>;

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        output.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex_decode_lower(text: &str, bytes: &mut [u8]) -> bool {
    if text.len() != bytes.len() * 2 {
        return false;
    }
    for (index, output) in bytes.iter_mut().enumerate() {
        let high = hex_nibble(text.as_bytes()[index * 2]);
        let low = hex_nibble(text.as_bytes()[index * 2 + 1]);
        let (Some(high), Some(low)) = (high, low) else {
            return false;
        };
        *output = (high << 4) | low;
    }
    true
}

/// Lowercase hexadecimal input was not exactly the expected byte length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HexError;

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid lowercase hexadecimal value")
    }
}

impl std::error::Error for HexError {}

/// A full-width chain digest. `GENESIS` is the position before record one;
/// it is never emitted as a record digest.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct ChainHead([u8; 32]);

impl ChainHead {
    pub const GENESIS: Self = Self([0; 32]);

    pub fn from_hex(text: &str) -> Result<Self, HexError> {
        let mut bytes = [0; 32];
        if !hex_decode_lower(text, &mut bytes) {
            return Err(HexError);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex_encode(&self.0)
    }
}

impl fmt::Debug for ChainHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for ChainHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for ChainHead {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

/// A broker-verified position in the chain. Count is the number of records
/// and head is the full-width authenticated digest of the last record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ChainPosition {
    pub count: u64,
    pub head: ChainHead,
}

impl ChainPosition {
    pub const fn genesis() -> Self {
        Self {
            count: 0,
            head: ChainHead::GENESIS,
        }
    }
}

/// Secret chain-authentication key supplied by the broker. The plaintext is
/// never shown by `Debug` and is zeroized when this value is dropped.
pub struct ChainKey(Zeroizing<[u8; 32]>);

impl ChainKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for ChainKey {
    fn clone(&self) -> Self {
        Self::new(*self.0)
    }
}

impl fmt::Debug for ChainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChainKey(<redacted>)")
    }
}

/// The broker's opaque vault identity bytes. The audit log stores only its
/// full-width SHA-256 digest; the raw identity remains a verifier input.
#[derive(Clone, Eq, PartialEq)]
pub struct VaultIdentity(Vec<u8>);

impl VaultIdentity {
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, IdentityError> {
        let bytes = bytes.as_ref();
        if bytes.is_empty() {
            return Err(IdentityError::Empty);
        }
        if bytes.len() > MAX_VAULT_IDENTITY_BYTES {
            return Err(IdentityError::TooLarge);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn digest_bytes(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }

    pub fn digest_hex(&self) -> String {
        hex_encode(&self.digest_bytes())
    }
}

impl fmt::Debug for VaultIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VaultIdentity(digest={}, len={})",
            self.digest_hex(),
            self.0.len()
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    Empty,
    TooLarge,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "vault identity is empty",
            Self::TooLarge => "vault identity exceeds its bound",
        })
    }
}

impl std::error::Error for IdentityError {}

/// Complete trust tuple needed to authenticate or extend a chain. The broker
/// must supply all three parts from its own trusted state: key, vault identity,
/// and the independently maintained expected position.
pub struct ChainTrust {
    key: ChainKey,
    identity: VaultIdentity,
    position: ChainPosition,
}

impl ChainTrust {
    pub fn new(key: ChainKey, identity: VaultIdentity, position: ChainPosition) -> Self {
        Self {
            key,
            identity,
            position,
        }
    }

    pub fn identity(&self) -> &VaultIdentity {
        &self.identity
    }

    pub fn position(&self) -> ChainPosition {
        self.position
    }

    pub(crate) fn key(&self) -> &ChainKey {
        &self.key
    }

    pub(crate) fn into_key_identity_position(self) -> (ChainKey, VaultIdentity, ChainPosition) {
        (self.key, self.identity, self.position)
    }
}

impl Clone for ChainTrust {
    fn clone(&self) -> Self {
        Self::new(self.key.clone(), self.identity.clone(), self.position)
    }
}

impl fmt::Debug for ChainTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainTrust")
            .field("key", &self.key)
            .field("identity", &self.identity)
            .field("position", &self.position)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainCorruption {
    EmptyLine,
    MalformedJson,
    NonCanonical,
    InvalidShape,
    UnsupportedVersion,
    WrongVault,
    BadSequence,
    BrokenLink,
    AuthenticationMismatch,
    OversizedEntry,
    MissingBrokerField,
}

impl ChainCorruption {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmptyLine => "empty_line",
            Self::MalformedJson => "malformed_json",
            Self::NonCanonical => "non_canonical",
            Self::InvalidShape => "invalid_shape",
            Self::UnsupportedVersion => "unsupported_version",
            Self::WrongVault => "wrong_vault",
            Self::BadSequence => "bad_sequence",
            Self::BrokenLink => "broken_link",
            Self::AuthenticationMismatch => "authentication_mismatch",
            Self::OversizedEntry => "oversized_entry",
            Self::MissingBrokerField => "missing_broker_field",
        }
    }
}

impl fmt::Display for ChainCorruption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ChainCorruption {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainReadFailure {
    FolderRefused,
    FileRefused,
    ReadFailed,
}

impl ChainReadFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FolderRefused => "folder_refused",
            Self::FileRefused => "file_refused",
            Self::ReadFailed => "read_failed",
        }
    }
}

/// Observational relationship between a verified final position and the
/// independently trusted checkpoint. These labels never claim a cause, deletion,
/// rollback, or whether one history is an ancestor of another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainPositionMismatch {
    /// No complete records were observed while the checkpoint expected at least one.
    AbsentOrEmptyHistory,
    /// A nonempty verified history ended before the checkpoint count.
    ShortNonemptyHistory,
    /// The verified history has the checkpoint count but a different head.
    ConflictingCheckpoint,
    /// The verified history ended after the checkpoint count.
    BeyondCheckpoint,
}

impl ChainPositionMismatch {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AbsentOrEmptyHistory => "absent_or_empty_history",
            Self::ShortNonemptyHistory => "short_nonempty_history",
            Self::ConflictingCheckpoint => "conflicting_checkpoint",
            Self::BeyondCheckpoint => "beyond_checkpoint",
        }
    }
}

impl fmt::Display for ChainPositionMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ChainPositionMismatch {}

fn position_mismatch(expected: ChainPosition, actual: ChainPosition) -> ChainPositionMismatch {
    if actual.count == 0 && expected.count != 0 {
        ChainPositionMismatch::AbsentOrEmptyHistory
    } else if actual.count < expected.count {
        ChainPositionMismatch::ShortNonemptyHistory
    } else if actual.count == expected.count {
        ChainPositionMismatch::ConflictingCheckpoint
    } else {
        ChainPositionMismatch::BeyondCheckpoint
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainStatus {
    MissingTrustState,
    Valid,
    Truncated,
    Corrupted,
    ContinuityLoss,
    Unreadable,
}

impl ChainStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingTrustState => "missing_trust_state",
            Self::Valid => "valid",
            Self::Truncated => "truncated",
            Self::Corrupted => "corrupted",
            Self::ContinuityLoss => "continuity_loss",
            Self::Unreadable => "unreadable",
        }
    }
}

/// Verification result. `Truncated` is reserved for an incomplete final
/// record. A syntactically complete but internally valid chain that does not
/// reach the independently trusted position is `ContinuityLoss`; this includes
/// deleted, replaced, extra, or rolled-back complete records. Its `mismatch`
/// label is observational only and never claims cause or ancestry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainVerification {
    MissingTrustState,
    Valid {
        position: ChainPosition,
    },
    Truncated {
        line: u64,
        valid_entries: u64,
    },
    Corrupted {
        line: u64,
        valid_entries: u64,
        reason: ChainCorruption,
    },
    ContinuityLoss {
        expected: ChainPosition,
        actual: ChainPosition,
        valid_entries: u64,
        mismatch: ChainPositionMismatch,
    },
    Unreadable {
        reason: ChainReadFailure,
    },
}

impl ChainVerification {
    pub fn status(self) -> ChainStatus {
        match self {
            Self::MissingTrustState => ChainStatus::MissingTrustState,
            Self::Valid { .. } => ChainStatus::Valid,
            Self::Truncated { .. } => ChainStatus::Truncated,
            Self::Corrupted { .. } => ChainStatus::Corrupted,
            Self::ContinuityLoss { .. } => ChainStatus::ContinuityLoss,
            Self::Unreadable { .. } => ChainStatus::Unreadable,
        }
    }

    pub fn is_valid(self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

fn write_frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            output.extend_from_slice(crate::codec::python_number(number, false)?.as_bytes())
        }
        Value::String(string) => {
            serde_json::to_writer(&mut *output, string).map_err(|error| error.to_string())?
        }
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(items) => {
            output.push(b'{');
            let mut entries: Vec<_> = items.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (key, item)) in entries.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|error| error.to_string())?;
                output.push(b':');
                write_canonical_json(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn json_container_depth(value: &Value) -> usize {
    let mut deepest = 0_usize;
    let mut pending = vec![(value, 0_usize)];
    while let Some((value, parent_depth)) = pending.pop() {
        let depth = if matches!(value, Value::Array(_) | Value::Object(_)) {
            parent_depth + 1
        } else {
            parent_depth
        };
        deepest = deepest.max(depth);
        match value {
            Value::Array(items) => {
                pending.extend(items.iter().map(|item| (item, depth)));
            }
            Value::Object(items) => {
                pending.extend(items.values().map(|item| (item, depth)));
            }
            _ => {}
        }
    }
    deepest
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn authentication_preimage(
    identity: &VaultIdentity,
    sequence: u64,
    previous: ChainHead,
    content_bytes: &[u8],
) -> Vec<u8> {
    let mut output =
        Vec::with_capacity(DOMAIN.len() + identity.as_bytes().len() + content_bytes.len() + 72);
    output.extend_from_slice(DOMAIN);
    write_frame(&mut output, identity.as_bytes());
    output.extend_from_slice(&sequence.to_be_bytes());
    write_frame(&mut output, previous.as_bytes());
    write_frame(&mut output, content_bytes);
    output
}

fn authentication_mac(
    key: &ChainKey,
    identity: &VaultIdentity,
    sequence: u64,
    previous: ChainHead,
    content_bytes: &[u8],
) -> [u8; 32] {
    let preimage = authentication_preimage(identity, sequence, previous, content_bytes);
    let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(&preimage);
    mac.finalize().into_bytes().into()
}

fn authentication_matches(
    key: &ChainKey,
    identity: &VaultIdentity,
    sequence: u64,
    previous: ChainHead,
    content_bytes: &[u8],
    expected: ChainHead,
) -> bool {
    let preimage = authentication_preimage(identity, sequence, previous, content_bytes);
    let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(&preimage);
    mac.verify_slice(expected.as_bytes()).is_ok()
}

fn valid_hex_digest(value: Option<&Value>) -> Option<ChainHead> {
    ChainHead::from_hex(value?.as_str()?).ok()
}

struct ParsedEntry {
    position: ChainPosition,
    previous: ChainHead,
}

fn parse_entry(
    line: &[u8],
    key: &ChainKey,
    identity: &VaultIdentity,
) -> Result<ParsedEntry, ChainCorruption> {
    if line.is_empty() {
        return Err(ChainCorruption::EmptyLine);
    }
    if line.len() > MAX_CHAIN_ENTRY_BYTES {
        return Err(ChainCorruption::OversizedEntry);
    }
    if line.first().is_some_and(|byte| byte.is_ascii_whitespace())
        || line.last().is_some_and(|byte| byte.is_ascii_whitespace())
    {
        return Err(ChainCorruption::NonCanonical);
    }
    let value = crate::python_json::from_slice(line).map_err(|_| ChainCorruption::MalformedJson)?;
    let object = value.as_object().ok_or(ChainCorruption::InvalidShape)?;
    if !object.get("ts").is_some_and(Value::is_string)
        || !object
            .get("event")
            .is_some_and(|event| event.as_str().is_some_and(|event| !event.is_empty()))
    {
        return Err(ChainCorruption::MissingBrokerField);
    }
    let chain = object
        .get("chain")
        .and_then(Value::as_object)
        .ok_or(ChainCorruption::InvalidShape)?;
    if chain.len() != 5 {
        return Err(ChainCorruption::InvalidShape);
    }
    if chain.get("v").and_then(Value::as_u64) != Some(CHAIN_FORMAT_VERSION) {
        return Err(ChainCorruption::UnsupportedVersion);
    }
    let sequence = chain
        .get("seq")
        .and_then(Value::as_u64)
        .filter(|sequence| *sequence > 0)
        .ok_or(ChainCorruption::InvalidShape)?;
    let vault = valid_hex_digest(chain.get("vault")).ok_or(ChainCorruption::InvalidShape)?;
    let previous = valid_hex_digest(chain.get("prev")).ok_or(ChainCorruption::InvalidShape)?;
    let recorded = valid_hex_digest(chain.get("hash")).ok_or(ChainCorruption::InvalidShape)?;
    if vault.as_bytes() != &identity.digest_bytes() {
        return Err(ChainCorruption::WrongVault);
    }
    let mut content = object.clone();
    content.remove("chain");
    let content_value = Value::Object(content);
    let content_bytes =
        canonical_json(&content_value).map_err(|_| ChainCorruption::InvalidShape)?;
    if !authentication_matches(key, identity, sequence, previous, &content_bytes, recorded) {
        return Err(ChainCorruption::AuthenticationMismatch);
    }
    let canonical = canonical_json(&value).map_err(|_| ChainCorruption::InvalidShape)?;
    if canonical != line {
        return Err(ChainCorruption::NonCanonical);
    }
    Ok(ParsedEntry {
        position: ChainPosition {
            count: sequence,
            head: recorded,
        },
        previous,
    })
}

fn verify_line(
    line: &[u8],
    trust: &ChainTrust,
    expected_sequence: u64,
    previous: ChainHead,
) -> Result<ChainPosition, ChainCorruption> {
    let parsed = parse_entry(line, trust.key(), trust.identity())?;
    if parsed.position.count != expected_sequence {
        return Err(ChainCorruption::BadSequence);
    }
    if parsed.previous != previous {
        return Err(ChainCorruption::BrokenLink);
    }
    Ok(parsed.position)
}

fn corrupted(line: u64, valid_entries: u64, reason: ChainCorruption) -> ChainVerification {
    ChainVerification::Corrupted {
        line,
        valid_entries,
        reason,
    }
}

fn finish(position: ChainPosition, trust: &ChainTrust) -> ChainVerification {
    if position == trust.position() {
        ChainVerification::Valid { position }
    } else {
        ChainVerification::ContinuityLoss {
            expected: trust.position(),
            actual: position,
            valid_entries: position.count,
            mismatch: position_mismatch(trust.position(), position),
        }
    }
}

/// Verify newline-delimited chain bytes from any reader. This API performs no
/// filesystem mutation and is suitable for in-memory fixtures. Passing `None`
/// is an explicit missing-trust result, never a valid-history result.
pub fn verify_reader(mut reader: impl Read, trust: Option<&ChainTrust>) -> ChainVerification {
    let Some(trust) = trust else {
        return ChainVerification::MissingTrustState;
    };
    let mut current = ChainPosition::genesis();
    let mut valid_entries = 0_u64;
    let mut line_number = 0_u64;
    let mut pending = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            if newline > MAX_CHAIN_ENTRY_BYTES {
                return corrupted(
                    line_number + 1,
                    valid_entries,
                    ChainCorruption::OversizedEntry,
                );
            }
            let mut line: Vec<u8> = pending.drain(..=newline).collect();
            line.pop();
            line_number = line_number.saturating_add(1);
            match verify_line(&line, trust, valid_entries.saturating_add(1), current.head) {
                Ok(position) => {
                    current = position;
                    valid_entries = valid_entries.saturating_add(1);
                }
                Err(reason) => return corrupted(line_number, valid_entries, reason),
            }
        }
        if pending.len() > MAX_CHAIN_ENTRY_BYTES {
            return corrupted(
                line_number + 1,
                valid_entries,
                ChainCorruption::OversizedEntry,
            );
        }
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => pending.extend_from_slice(&chunk[..count]),
            Err(_) => {
                return ChainVerification::Unreadable {
                    reason: ChainReadFailure::ReadFailed,
                };
            }
        }
    }
    if !pending.is_empty() {
        return ChainVerification::Truncated {
            line: line_number.saturating_add(1),
            valid_entries,
        };
    }
    finish(current, trust)
}

/// Verify bytes already held in memory.
pub fn verify_bytes(bytes: &[u8], trust: Option<&ChainTrust>) -> ChainVerification {
    verify_reader(bytes, trust)
}

/// Verify `audit.jsonl` in an audit directory without creating, chmodding, or
/// otherwise mutating it. A missing directory or log is the empty chain: valid
/// only against a trusted genesis position and a continuity loss otherwise.
pub fn verify_directory(
    directory: impl AsRef<Path>,
    trust: Option<&ChainTrust>,
) -> ChainVerification {
    let Some(trust) = trust else {
        return ChainVerification::MissingTrustState;
    };
    let empty: &[u8] = b"";
    let directory = match Directory::open(directory.as_ref(), false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return verify_reader(empty, Some(trust));
        }
        Err(_) => {
            return ChainVerification::Unreadable {
                reason: ChainReadFailure::FolderRefused,
            };
        }
    };
    match directory.open_single_read(LOG) {
        Ok(file) => verify_reader(file, Some(trust)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            verify_reader(empty, Some(trust))
        }
        Err(_) => ChainVerification::Unreadable {
            reason: ChainReadFailure::FileRefused,
        },
    }
}

#[derive(Debug)]
pub(crate) struct EncodedEntry {
    pub(crate) bytes: Vec<u8>,
    pub(crate) position: ChainPosition,
}

pub(crate) fn encode_authenticated_entry(
    timestamp: &str,
    event: &str,
    mut fields: Map<String, Value>,
    key: &ChainKey,
    identity: &VaultIdentity,
    position: ChainPosition,
) -> Result<EncodedEntry, String> {
    if event.is_empty() {
        return Err("audit event is empty".into());
    }
    if fields
        .keys()
        .any(|key| matches!(key.as_str(), "ts" | "event" | "chain"))
    {
        return Err("audit metadata uses a broker-owned field".into());
    }
    crate::codec::sanitize_fields(&mut fields);
    let mut content = Map::new();
    content.insert("ts".into(), Value::String(timestamp.into()));
    content.insert("event".into(), Value::String(event.into()));
    content.extend(fields);
    let content_value = Value::Object(content.clone());
    if json_container_depth(&content_value) > MAX_CHAIN_JSON_DEPTH {
        return Err("authenticated audit entry exceeds its nesting bound".into());
    }
    let content_bytes = canonical_json(&content_value)?;
    let sequence = position
        .count
        .checked_add(1)
        .ok_or_else(|| "audit chain sequence exhausted".to_owned())?;
    let digest = authentication_mac(key, identity, sequence, position.head, &content_bytes);
    let head = ChainHead(digest);
    let mut chain = Map::new();
    chain.insert(
        "v".into(),
        Value::Number(Number::from(CHAIN_FORMAT_VERSION)),
    );
    chain.insert("vault".into(), Value::String(identity.digest_hex()));
    chain.insert("seq".into(), Value::Number(Number::from(sequence)));
    chain.insert("prev".into(), Value::String(position.head.to_hex()));
    chain.insert("hash".into(), Value::String(head.to_hex()));
    let mut record = content;
    record.insert("chain".into(), Value::Object(chain));
    let mut bytes = canonical_json(&Value::Object(record))?;
    if bytes.len() > MAX_CHAIN_ENTRY_BYTES {
        return Err("authenticated audit entry exceeds its bound".into());
    }
    bytes.push(b'\n');
    Ok(EncodedEntry {
        bytes,
        position: ChainPosition {
            count: sequence,
            head,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TailFailure {
    Refused,
    Unauthenticated,
}

fn read_exact_at(file: &std::fs::File, buffer: &mut [u8], start: u64) -> Result<(), TailFailure> {
    use std::os::unix::fs::FileExt;

    let mut read = 0_usize;
    while read < buffer.len() {
        let got = file
            .read_at(&mut buffer[read..], start + read as u64)
            .map_err(|_| TailFailure::Refused)?;
        if got == 0 {
            return Err(TailFailure::Unauthenticated);
        }
        read += got;
    }
    Ok(())
}

fn read_tail_line(directory: &Directory) -> Result<Option<Vec<u8>>, TailFailure> {
    let file = match directory.open_single_read(LOG) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(TailFailure::Refused),
    };
    let length = file.metadata().map_err(|_| TailFailure::Refused)?.len();
    if length == 0 {
        return Ok(None);
    }
    let mut final_byte = [0_u8; 1];
    read_exact_at(&file, &mut final_byte, length - 1)?;
    if final_byte[0] != b'\n' {
        return Err(TailFailure::Unauthenticated);
    }

    let mut position = length - 1;
    let mut line_len = 0_usize;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    while position > 0 {
        let capacity = MAX_CHAIN_ENTRY_BYTES + 1 - line_len;
        let read_len = (position as usize).min(TAIL_READ_CHUNK_BYTES).min(capacity);
        let start = position - read_len as u64;
        let mut chunk = vec![0_u8; read_len];
        read_exact_at(&file, &mut chunk, start)?;
        if let Some(newline) = chunk.iter().rposition(|byte| *byte == b'\n') {
            let suffix = &chunk[newline + 1..];
            let total = line_len + suffix.len();
            if total == 0 || total > MAX_CHAIN_ENTRY_BYTES {
                return Err(TailFailure::Unauthenticated);
            }
            let mut line = Vec::with_capacity(total);
            line.extend_from_slice(suffix);
            for part in chunks.iter().rev() {
                line.extend_from_slice(part);
            }
            return Ok(Some(line));
        }
        line_len += read_len;
        chunks.push(chunk);
        if line_len > MAX_CHAIN_ENTRY_BYTES {
            return Err(TailFailure::Unauthenticated);
        }
        position = start;
    }

    if line_len == 0 {
        return Err(TailFailure::Unauthenticated);
    }
    let mut line = Vec::with_capacity(line_len);
    for part in chunks.iter().rev() {
        line.extend_from_slice(part);
    }
    Ok(Some(line))
}

/// Authenticate only the durable tail and return its claimed position. This is
/// sufficient for append when the caller independently knows the expected
/// position: equality with that position is the rollback/replay check.
pub(crate) fn authenticated_tail_position(
    directory: &Directory,
    key: &ChainKey,
    identity: &VaultIdentity,
) -> Result<ChainPosition, TailFailure> {
    let Some(line) = read_tail_line(directory)? else {
        return Ok(ChainPosition::genesis());
    };
    parse_entry(&line, key, identity)
        .map(|entry| entry.position)
        .map_err(|_| TailFailure::Unauthenticated)
}

#[cfg(test)]
mod tests;
