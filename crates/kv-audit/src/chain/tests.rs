use super::*;
use crate::{Audit, LossReason};
use serde_json::{Map, Value};
use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kv-audit-chain-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("isolated chain test directory");
        Self(path)
    }

    fn audit_dir(&self) -> PathBuf {
        self.0.join("audit")
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn key() -> ChainKey {
    ChainKey::new([0x42; 32])
}

fn other_key() -> ChainKey {
    ChainKey::new([0x24; 32])
}

fn identity() -> VaultIdentity {
    VaultIdentity::new(b"fixture-vault-identity").unwrap()
}

fn other_identity() -> VaultIdentity {
    VaultIdentity::new(b"other-vault-identity").unwrap()
}

fn trust(position: ChainPosition) -> ChainTrust {
    ChainTrust::new(key(), identity(), position)
}

fn fields(entries: &[(&str, &str)]) -> Map<String, Value> {
    let mut output = Map::new();
    for (key, value) in entries {
        output.insert((*key).into(), Value::String((*value).into()));
    }
    output
}

fn try_encode_at(
    event: &str,
    entries: Map<String, Value>,
    position: ChainPosition,
) -> Result<EncodedEntry, String> {
    encode_authenticated_entry(
        "2026-01-02T03:04:05Z",
        event,
        entries,
        &key(),
        &identity(),
        position,
    )
}

fn encode_at(event: &str, entries: Map<String, Value>, position: ChainPosition) -> EncodedEntry {
    try_encode_at(event, entries, position).unwrap()
}

fn generated_chain(count: u64) -> (Vec<u8>, ChainPosition) {
    let mut output = Vec::new();
    let mut position = ChainPosition::genesis();
    for sequence in 1..=count {
        let encoded = encode_at(
            &format!("event-{sequence}"),
            fields(&[("seq", "unchanged"), ("writer", "fixture")]),
            position,
        );
        output.extend_from_slice(&encoded.bytes);
        position = encoded.position;
    }
    (output, position)
}

fn split_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn replace_once(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), replacement.len());
    let position = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("mutation needle is present");
    let mut output = bytes.to_vec();
    output[position..position + needle.len()].copy_from_slice(replacement);
    output
}

fn corruption_reason(bytes: &[u8], position: ChainPosition) -> ChainCorruption {
    match verify_bytes(bytes, Some(&trust(position))) {
        ChainVerification::Corrupted { reason, .. } => reason,
        other => panic!("expected corruption, got {other:?}"),
    }
}

#[test]
fn authenticated_entries_are_full_width_canonical_keyed_and_identity_bound() {
    let mut reversed = Map::new();
    reversed.insert("z".into(), Value::String("last".into()));
    reversed.insert("a".into(), Value::String("first".into()));
    let mut forward = Map::new();
    forward.insert("a".into(), Value::String("first".into()));
    forward.insert("z".into(), Value::String("last".into()));
    let one = encode_at("event", reversed, ChainPosition::genesis());
    let same = encode_at("event", forward, ChainPosition::genesis());
    assert_eq!(
        one.bytes, same.bytes,
        "metadata insertion order must not affect canonical authentication bytes"
    );
    assert!(one.bytes.ends_with(b"\n"));
    let line = &one.bytes[..one.bytes.len() - 1];
    let text = std::str::from_utf8(line).unwrap();
    assert!(
        text.starts_with("{\"a\":") && text.contains("\"chain\":{\"hash\":"),
        "record is not canonical sorted JSON: {text}"
    );
    let record: Value = serde_json::from_slice(line).unwrap();
    let chain = record["chain"].as_object().unwrap();
    assert_eq!(chain.len(), 5);
    assert_eq!(chain["v"], 1);
    assert_eq!(chain["seq"], 1);
    assert_eq!(chain["prev"].as_str().unwrap(), ChainHead::GENESIS.to_hex());
    assert_eq!(chain["vault"].as_str().unwrap(), identity().digest_hex());
    let hash = chain["hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(
        hash.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(record["event"], "event");
    assert_eq!(record["ts"], "2026-01-02T03:04:05Z");
    assert_eq!(one.position.count, 1);
    assert_eq!(one.position.head.to_hex(), hash);

    let two = encode_at("event-two", Map::new(), one.position);
    let second: Value = serde_json::from_slice(&two.bytes[..two.bytes.len() - 1]).unwrap();
    assert_eq!(second["chain"]["prev"], hash);
    assert_eq!(second["chain"]["seq"], 2);
    assert_ne!(second["chain"]["hash"], hash);

    let with_other_key = encode_authenticated_entry(
        "2026-01-02T03:04:05Z",
        "event",
        Map::new(),
        &other_key(),
        &identity(),
        ChainPosition::genesis(),
    )
    .unwrap();
    let with_other_identity = encode_authenticated_entry(
        "2026-01-02T03:04:05Z",
        "event",
        Map::new(),
        &key(),
        &other_identity(),
        ChainPosition::genesis(),
    )
    .unwrap();
    assert_ne!(with_other_key.position.head, one.position.head);
    assert_ne!(with_other_identity.position.head, one.position.head);
}

#[test]
fn authenticated_entry_matches_an_independent_hmac_vector() {
    let encoded = encode_authenticated_entry(
        "2026-01-02T03:04:05Z",
        "cli",
        Map::new(),
        &key(),
        &identity(),
        ChainPosition::genesis(),
    )
    .unwrap();
    assert_eq!(
        encoded.position.head.to_hex(),
        "6baab941db1142058d1e4da82b9fb42042d65413c3af83c607f5d89388e9ea53"
    );
    assert_eq!(
        std::str::from_utf8(&encoded.bytes).unwrap(),
        concat!(
            "{\"chain\":{\"hash\":\"6baab941db1142058d1e4da82b9fb42042d65413c3af83c607f5d89388e9ea53\",",
            "\"prev\":\"0000000000000000000000000000000000000000000000000000000000000000\",",
            "\"seq\":1,\"v\":1,\"vault\":\"08fb2ab0efe7b8aaf4d8fb2cfc956e429c82eac04d94e9ffe00835014578ae93\"},",
            "\"event\":\"cli\",\"ts\":\"2026-01-02T03:04:05Z\"}\n"
        )
    );
}

#[test]
fn broker_owned_fields_empty_events_and_oversized_records_are_refused() {
    for reserved in ["ts", "event", "chain"] {
        let mut entries = Map::new();
        entries.insert(reserved.into(), Value::String("caller-controlled".into()));
        assert_eq!(
            try_encode_at("event", entries, ChainPosition::genesis()).unwrap_err(),
            "audit metadata uses a broker-owned field"
        );
    }
    assert_eq!(
        try_encode_at("", Map::new(), ChainPosition::genesis()).unwrap_err(),
        "audit event is empty"
    );
    let mut oversized = Map::new();
    oversized.insert(
        "large".into(),
        Value::String("x".repeat(MAX_CHAIN_ENTRY_BYTES)),
    );
    assert_eq!(
        try_encode_at("event", oversized, ChainPosition::genesis()).unwrap_err(),
        "authenticated audit entry exceeds its bound"
    );
}

#[test]
fn authenticated_entries_enforce_the_verifier_nesting_bound() {
    fn nested(depth: usize) -> Value {
        let mut value = Value::from(0);
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        value
    }

    let mut accepted_fields = Map::new();
    accepted_fields.insert("nested".into(), nested(126));
    let accepted = try_encode_at("deep", accepted_fields, ChainPosition::genesis()).unwrap();
    assert_eq!(
        verify_bytes(&accepted.bytes, Some(&trust(accepted.position))),
        ChainVerification::Valid {
            position: accepted.position
        }
    );

    let mut rejected_fields = Map::new();
    rejected_fields.insert("nested".into(), nested(127));
    assert_eq!(
        try_encode_at("deep", rejected_fields, ChainPosition::genesis()).unwrap_err(),
        "authenticated audit entry exceeds its nesting bound"
    );
}

#[test]
fn valid_history_and_empty_history_are_distinct_from_missing_trust_state() {
    let (bytes, position) = generated_chain(2);
    assert_eq!(
        verify_bytes(&bytes, Some(&trust(position))),
        ChainVerification::Valid { position }
    );
    assert_eq!(
        verify_bytes(&bytes, None),
        ChainVerification::MissingTrustState
    );
    assert_eq!(
        verify_bytes(b"", Some(&trust(ChainPosition::genesis()))),
        ChainVerification::Valid {
            position: ChainPosition::genesis()
        }
    );
    assert_eq!(
        verify_bytes(b"", None),
        ChainVerification::MissingTrustState
    );
}

#[test]
fn truncation_is_distinct_from_complete_record_loss() {
    let (bytes, final_position) = generated_chain(2);
    let mut missing_newline = bytes.clone();
    missing_newline.pop();
    assert_eq!(
        verify_bytes(&missing_newline, Some(&trust(final_position))),
        ChainVerification::Truncated {
            line: 2,
            valid_entries: 1
        }
    );

    let lines = split_lines(&bytes);
    let partial_length = lines[0].len() + 1 + 17;
    assert_eq!(
        verify_bytes(&bytes[..partial_length], Some(&trust(final_position))),
        ChainVerification::Truncated {
            line: 2,
            valid_entries: 1
        }
    );

    let (_, first_position) = generated_chain(1);
    let first_only_length = lines[0].len() + 1;
    assert_eq!(
        verify_bytes(&bytes[..first_only_length], Some(&trust(final_position))),
        ChainVerification::ContinuityLoss {
            expected: final_position,
            actual: first_position,
            valid_entries: 1,
            mismatch: ChainPositionMismatch::ShortNonemptyHistory
        }
    );
}

#[test]
fn malformed_shape_authentication_sequence_link_vault_and_canonical_corruption_are_classified() {
    let (bytes, final_position) = generated_chain(2);
    assert_eq!(
        corruption_reason(b"{\"event\":\n", final_position),
        ChainCorruption::MalformedJson
    );
    assert_eq!(
        corruption_reason(b"\n", final_position),
        ChainCorruption::EmptyLine
    );

    let mut spaced = bytes.clone();
    spaced.insert(1, b' ');
    assert_eq!(
        corruption_reason(&spaced, final_position),
        ChainCorruption::NonCanonical
    );

    let changed_content = replace_once(&bytes, b"event-1", b"event_1");
    assert_eq!(
        corruption_reason(&changed_content, final_position),
        ChainCorruption::AuthenticationMismatch
    );

    let lines = split_lines(&bytes);
    let mut swapped = lines[1].clone();
    swapped.push(b'\n');
    swapped.extend_from_slice(&lines[0]);
    swapped.push(b'\n');
    assert_eq!(
        corruption_reason(&swapped, final_position),
        ChainCorruption::BadSequence
    );

    let forked_position = ChainPosition {
        count: 0,
        head: ChainHead([9; 32]),
    };
    let forked = encode_at("event-1", Map::new(), forked_position);
    assert_eq!(
        corruption_reason(&forked.bytes, final_position),
        ChainCorruption::BrokenLink
    );

    let wrong_vault = encode_authenticated_entry(
        "2026-01-02T03:04:05Z",
        "event-1",
        Map::new(),
        &key(),
        &other_identity(),
        ChainPosition::genesis(),
    )
    .unwrap();
    assert_eq!(
        corruption_reason(&wrong_vault.bytes, final_position),
        ChainCorruption::WrongVault
    );

    let wrong_key = encode_authenticated_entry(
        "2026-01-02T03:04:05Z",
        "event-1",
        Map::new(),
        &other_key(),
        &identity(),
        ChainPosition::genesis(),
    )
    .unwrap();
    assert_eq!(
        corruption_reason(&wrong_key.bytes, final_position),
        ChainCorruption::AuthenticationMismatch
    );

    let unsupported = replace_once(&bytes, b"\"v\":1", b"\"v\":2");
    assert_eq!(
        corruption_reason(&unsupported, final_position),
        ChainCorruption::UnsupportedVersion
    );

    let mut bad_vault = identity().digest_hex();
    bad_vault.replace_range(0..1, "G");
    let invalid_hex = replace_once(
        &bytes,
        identity().digest_hex().as_bytes(),
        bad_vault.as_bytes(),
    );
    assert_eq!(
        corruption_reason(&invalid_hex, final_position),
        ChainCorruption::InvalidShape
    );

    let missing_event = replace_once(&bytes, b"\"event\"", b"\"evXnt\"");
    assert_eq!(
        corruption_reason(&missing_event, final_position),
        ChainCorruption::MissingBrokerField
    );
}

#[test]
fn continuity_loss_covers_missing_extra_and_fabricated_complete_histories() {
    let (_, first_position) = generated_chain(1);
    let (bytes, final_position) = generated_chain(2);
    let lines = split_lines(&bytes);

    let mut first_only = lines[0].clone();
    first_only.push(b'\n');
    assert_eq!(
        verify_bytes(&first_only, Some(&trust(final_position))),
        ChainVerification::ContinuityLoss {
            expected: final_position,
            actual: first_position,
            valid_entries: 1,
            mismatch: ChainPositionMismatch::ShortNonemptyHistory
        }
    );

    let (three_bytes, third_position) = generated_chain(3);
    assert_eq!(
        verify_bytes(&three_bytes, Some(&trust(final_position))),
        ChainVerification::ContinuityLoss {
            expected: final_position,
            actual: third_position,
            valid_entries: 3,
            mismatch: ChainPositionMismatch::BeyondCheckpoint
        }
    );

    let fabricated = encode_at("fabricated", Map::new(), ChainPosition::genesis());
    assert_eq!(
        verify_bytes(&fabricated.bytes, Some(&trust(first_position))),
        ChainVerification::ContinuityLoss {
            expected: first_position,
            actual: fabricated.position,
            valid_entries: 1,
            mismatch: ChainPositionMismatch::ConflictingCheckpoint
        }
    );

    assert_eq!(
        verify_bytes(b"", Some(&trust(first_position))),
        ChainVerification::ContinuityLoss {
            expected: first_position,
            actual: ChainPosition::genesis(),
            valid_entries: 0,
            mismatch: ChainPositionMismatch::AbsentOrEmptyHistory
        }
    );
}

struct AlwaysFailingRead;

impl io::Read for AlwaysFailingRead {
    fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected"))
    }
}

struct PartialThenFailingRead {
    bytes: &'static [u8],
}

impl io::Read for PartialThenFailingRead {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.bytes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "injected"));
        }
        let count = self.bytes.len().min(output.len());
        output[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn injected_reader_failures_are_unreadable_not_valid_or_truncated() {
    let position = ChainPosition::genesis();
    assert_eq!(
        verify_reader(AlwaysFailingRead, Some(&trust(position))),
        ChainVerification::Unreadable {
            reason: ChainReadFailure::ReadFailed
        }
    );
    assert_eq!(
        verify_reader(
            PartialThenFailingRead {
                bytes: b"{\"partial\""
            },
            Some(&trust(position))
        ),
        ChainVerification::Unreadable {
            reason: ChainReadFailure::ReadFailed
        }
    );
}

#[test]
fn directory_verification_is_read_only_and_refuses_unsafe_log_names() {
    let temp = Temp::new();
    let directory = temp.audit_dir();
    let genesis = ChainPosition::genesis();
    assert_eq!(
        verify_directory(&directory, Some(&trust(genesis))),
        ChainVerification::Valid { position: genesis }
    );
    assert!(!directory.exists(), "probe created a missing directory");

    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let log = directory.join("audit.jsonl");
    fs::write(&log, b"").unwrap();
    assert_eq!(
        verify_directory(&directory, Some(&trust(genesis))),
        ChainVerification::Valid { position: genesis }
    );
    let alias = directory.join("alias");
    fs::hard_link(&log, &alias).unwrap();
    assert_eq!(
        verify_directory(&directory, Some(&trust(genesis))),
        ChainVerification::Unreadable {
            reason: ChainReadFailure::FileRefused
        }
    );
    fs::remove_file(&alias).unwrap();

    let victim = temp.0.join("victim");
    fs::write(&victim, b"unchanged").unwrap();
    fs::remove_file(&log).unwrap();
    symlink(&victim, &log).unwrap();
    assert_eq!(
        verify_directory(&directory, Some(&trust(genesis))),
        ChainVerification::Unreadable {
            reason: ChainReadFailure::FileRefused
        }
    );
    assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    let names: Vec<_> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "read-only verification created sidecars");
}

#[test]
fn writer_advances_position_and_refuses_a_rolled_back_tail_before_appending() {
    let temp = Temp::new();
    let directory = temp.audit_dir();
    let audit = Audit::with_authenticated_chain(&directory, trust(ChainPosition::genesis()));
    audit
        .emit_at(
            "first",
            fields(&[("writer", "fixture")]),
            "2026-01-02T03:04:05Z",
        )
        .unwrap();
    let log = directory.join("audit.jsonl");
    let first_bytes = fs::read(&log).unwrap();
    let first_position = audit.authenticated_chain_position().unwrap();
    assert_eq!(first_position.count, 1);

    audit
        .emit_at("second", Map::new(), "2026-01-02T03:04:06Z")
        .unwrap();
    let final_position = audit.authenticated_chain_position().unwrap();
    assert_eq!(final_position.count, 2);
    assert_eq!(
        verify_directory(&directory, Some(&trust(final_position))),
        ChainVerification::Valid {
            position: final_position
        }
    );

    fs::write(&log, &first_bytes).unwrap();
    assert_eq!(
        audit.emit("third", Map::new()),
        Err(LossReason::ChainUnauthenticated)
    );
    assert_eq!(fs::read(&log).unwrap(), first_bytes);
}

#[test]
fn authenticated_writer_preserves_the_vault_label_metadata_rule() {
    let temp = Temp::new();
    let directory = temp.audit_dir();
    let audit = Audit::with_authenticated_chain(&directory, trust(ChainPosition::genesis()));
    audit.set_vault_label(Some("work"));
    audit
        .emit_at("labeled", Map::new(), "2026-01-02T03:04:05Z")
        .unwrap();
    let bytes = fs::read(directory.join("audit.jsonl")).unwrap();
    let record: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
    assert_eq!(record["vault"], "work");
    assert_eq!(
        verify_bytes(
            &bytes,
            Some(&trust(audit.authenticated_chain_position().unwrap()))
        ),
        ChainVerification::Valid {
            position: audit.authenticated_chain_position().unwrap()
        }
    );
}

#[test]
fn writer_scans_a_tail_record_across_read_chunks_before_appending() {
    let temp = Temp::new();
    let directory = temp.audit_dir();
    let audit = Audit::with_authenticated_chain(&directory, trust(ChainPosition::genesis()));
    let mut large = Map::new();
    large.insert("padding".into(), Value::String("x".repeat(20_000)));
    audit
        .emit_at("large-tail", large, "2026-01-02T03:04:05Z")
        .unwrap();
    audit
        .emit_at("after-large-tail", Map::new(), "2026-01-02T03:04:06Z")
        .unwrap();
    let position = audit.authenticated_chain_position().unwrap();
    assert_eq!(position.count, 2);
    assert_eq!(
        verify_bytes(
            &fs::read(directory.join("audit.jsonl")).unwrap(),
            Some(&trust(position))
        ),
        ChainVerification::Valid { position }
    );
}

#[test]
fn writer_refuses_corrupt_and_partial_tails_before_appending() {
    for partial in [true, false] {
        let temp = Temp::new();
        let directory = temp.audit_dir();
        let audit = Audit::with_authenticated_chain(&directory, trust(ChainPosition::genesis()));
        audit
            .emit_at("first", Map::new(), "2026-01-02T03:04:05Z")
            .unwrap();
        let log = directory.join("audit.jsonl");
        let original = fs::read(&log).unwrap();
        let mut mutated = original.clone();
        if partial {
            mutated.pop();
        } else {
            let index = mutated
                .windows(b"first".len())
                .position(|window| window == b"first")
                .unwrap();
            mutated[index] = b'F';
        }
        fs::write(&log, &mutated).unwrap();
        assert_eq!(
            audit.emit("second", Map::new()),
            Err(LossReason::ChainUnauthenticated),
            "partial={partial}"
        );
        assert_eq!(fs::read(&log).unwrap(), mutated, "partial={partial}");
    }
}

#[test]
fn externally_valid_appends_do_not_extend_a_stale_trusted_position() {
    let temp = Temp::new();
    let directory = temp.audit_dir();
    let first = Audit::with_authenticated_chain(&directory, trust(ChainPosition::genesis()));
    first
        .emit_at("first", Map::new(), "2026-01-02T03:04:05Z")
        .unwrap();
    let first_position = first.authenticated_chain_position().unwrap();

    let second = Audit::with_authenticated_chain(&directory, trust(first_position));
    second
        .emit_at("second", Map::new(), "2026-01-02T03:04:06Z")
        .unwrap();
    assert_eq!(
        first.emit("third", Map::new()),
        Err(LossReason::ChainUnauthenticated)
    );
    assert_eq!(
        verify_directory(
            &directory,
            Some(&trust(second.authenticated_chain_position().unwrap()))
        ),
        ChainVerification::Valid {
            position: second.authenticated_chain_position().unwrap()
        }
    );
}

#[test]
fn nonfinite_python_numbers_round_trip_through_canonical_authenticated_records() {
    let mut entries = Map::new();
    entries.insert(
        "overflow".into(),
        serde_json::from_str::<Value>("1e999").unwrap(),
    );
    let encoded = encode_at("numbers", entries, ChainPosition::genesis());
    assert!(
        String::from_utf8(encoded.bytes.clone())
            .unwrap()
            .contains("\"overflow\":Infinity")
    );
    assert_eq!(
        verify_bytes(&encoded.bytes, Some(&trust(encoded.position))),
        ChainVerification::Valid {
            position: encoded.position
        }
    );
}

#[test]
fn input_validation_and_key_debugging_do_not_expose_or_accept_ambiguous_material() {
    assert_eq!(format!("{:?}", key()), "ChainKey(<redacted>)");
    assert_eq!(VaultIdentity::new(b"").unwrap_err(), IdentityError::Empty);
    assert_eq!(
        VaultIdentity::new(vec![0; MAX_VAULT_IDENTITY_BYTES + 1]).unwrap_err(),
        IdentityError::TooLarge
    );
    let head = ChainHead::GENESIS.to_hex();
    assert_eq!(ChainHead::from_hex(&head).unwrap(), ChainHead::GENESIS);
    let letters = "ab".repeat(32);
    assert!(ChainHead::from_hex(&letters).is_ok());
    assert!(ChainHead::from_hex(&letters.to_uppercase()).is_err());
    assert!(ChainHead::from_hex(&head[..62]).is_err());
}
