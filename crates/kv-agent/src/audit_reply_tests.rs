//! Exercise warning delivery at the daemon's real serialization/write boundary.

use super::*;
use std::io;
use std::net::Shutdown;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

struct FailedAudit {
    directory: PathBuf,
    audit: kv_audit::Audit,
}

impl FailedAudit {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("kv-agent-audit-{}", token_hex(16).unwrap()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        fs::create_dir(directory.join("audit.jsonl")).unwrap();
        let audit = kv_audit::Audit::new(&directory);
        let fixture = Self { directory, audit };
        fixture.lose_record();
        fixture
    }

    fn lose_record(&self) {
        assert_eq!(
            self.audit.emit("api_call", serde_json::Map::new()),
            Err(kv_audit::LossReason::FileRefused)
        );
    }

    fn recover_then_fail_again(&self) {
        let log = self.directory.join("audit.jsonl");
        fs::remove_dir(&log).unwrap();
        self.audit
            .emit("recovered", serde_json::Map::new())
            .unwrap();
        fs::remove_file(&log).unwrap();
        fs::create_dir(&log).unwrap();
        self.lose_record();
    }
}

impl Drop for FailedAudit {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn reply(audit: &kv_audit::Audit, response: &Value, wants_warning: bool) -> Value {
    let mut bytes = Vec::new();
    write_audited_reply(&mut bytes, response, audit, wants_warning).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn consume_warning(audit: &kv_audit::Audit) {
    assert_eq!(
        reply(audit, &json!({"ok":true}), true),
        json!({"ok":true,"audit_warning":kv_audit::AUDIT_WARNING})
    );
}

fn assert_no_warning(audit: &kv_audit::Audit) {
    assert_eq!(reply(audit, &json!({"ok":true}), true), json!({"ok":true}));
}

#[test]
fn opt_out_and_non_object_replies_leave_the_warning_owed() {
    let fixture = FailedAudit::new();
    let original = json!({"status":200,"body":{"ok":true}});
    assert_eq!(reply(&fixture.audit, &original, false), original);
    for response in [Value::Null, json!([1, 2]), json!("scalar")] {
        assert_eq!(reply(&fixture.audit, &response, true), response);
    }
    consume_warning(&fixture.audit);
    assert_no_warning(&fixture.audit);
}

#[test]
fn warning_is_delivered_once_per_failure_transition() {
    let fixture = FailedAudit::new();
    fixture.lose_record();
    consume_warning(&fixture.audit);
    fixture.lose_record();
    assert_no_warning(&fixture.audit);

    fixture.recover_then_fail_again();
    consume_warning(&fixture.audit);
    assert_no_warning(&fixture.audit);
}

#[test]
fn separate_undelivered_transitions_are_not_collapsed_into_one_warning() {
    let fixture = FailedAudit::new();
    fixture.recover_then_fail_again();
    consume_warning(&fixture.audit);
    consume_warning(&fixture.audit);
    assert_no_warning(&fixture.audit);
}

struct PartialWriteFailure {
    bytes: Vec<u8>,
    limit: usize,
    flushed: bool,
}

impl Write for PartialWriteFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let accepted = bytes.len().min(self.limit - self.bytes.len());
        if accepted == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "test peer closed",
            ));
        }
        self.bytes.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushed = true;
        Ok(())
    }
}

#[test]
fn failed_partial_send_returns_the_warning_for_one_later_reply() {
    let fixture = FailedAudit::new();
    let complete = kv_store::pyjson::to_vec_python(
        &json!({"ok":true,"audit_warning":kv_audit::AUDIT_WARNING}),
        false,
    )
    .unwrap();
    let mut writer = PartialWriteFailure {
        bytes: Vec::new(),
        limit: complete.len() - 1,
        flushed: false,
    };
    assert!(write_audited_reply(&mut writer, &json!({"ok":true}), &fixture.audit, true).is_err());
    assert_eq!(writer.bytes, complete[..complete.len() - 1]);
    assert!(
        !writer.flushed,
        "flush must not turn a partial write into delivery"
    );
    consume_warning(&fixture.audit);
    assert_no_warning(&fixture.audit);
}

#[derive(Default)]
struct FlushFailure {
    bytes: Vec<u8>,
    flushes: usize,
}

impl Write for FlushFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "test flush failed",
        ))
    }
}

#[test]
fn failed_flush_returns_the_warning_even_after_all_bytes_were_written() {
    let fixture = FailedAudit::new();
    let mut writer = FlushFailure::default();
    assert!(write_audited_reply(&mut writer, &json!({"ok":true}), &fixture.audit, true).is_err());
    assert_eq!(writer.flushes, 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&writer.bytes).unwrap()["audit_warning"],
        kv_audit::AUDIT_WARNING
    );
    consume_warning(&fixture.audit);
    assert_no_warning(&fixture.audit);
}

#[test]
fn oversized_reply_replacement_carries_the_warning_within_the_wire_limit() {
    let fixture = FailedAudit::new();
    let response = json!({"payload":"x".repeat(kv_proto::MAX_AGENT_RESPONSE_BYTES)});
    let mut bytes = Vec::new();
    write_audited_reply(&mut bytes, &response, &fixture.audit, true).unwrap();
    assert!(bytes.len() <= kv_proto::MAX_AGENT_RESPONSE_BYTES);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"error":"response too large", "response_truncated":true,
            "max_response_bytes":kv_proto::MAX_AGENT_RESPONSE_BYTES,
            "audit_warning":kv_audit::AUDIT_WARNING})
    );
    assert_no_warning(&fixture.audit);
}

#[test]
fn exact_limit_reply_survives_when_its_warning_does_not_fit() {
    let fixture = FailedAudit::new();
    let overhead = kv_store::pyjson::to_vec_python(&json!({"payload":""}), false)
        .unwrap()
        .len();
    let response = json!({"payload":"x".repeat(kv_proto::MAX_AGENT_RESPONSE_BYTES - overhead)});
    let expected = kv_store::pyjson::to_vec_python(&response, false).unwrap();
    assert_eq!(expected.len(), kv_proto::MAX_AGENT_RESPONSE_BYTES);
    let mut bytes = Vec::new();
    write_audited_reply(&mut bytes, &response, &fixture.audit, true).unwrap();
    assert_eq!(
        bytes, expected,
        "a warning must not replace an otherwise valid bounded reply"
    );
    consume_warning(&fixture.audit);
    assert_no_warning(&fixture.audit);
}

fn trust_context() -> TrustContext {
    TrustContext {
        session_nonce: Zeroizing::new([0; 32]),
        daemon_auth_key: Key32::new([0; 32]),
        grant_state_key: Key32::new([0; 32]),
        token_key: Key32::new([0; 32]),
        protected: false,
        owner_key_id: String::new(),
        local_approval_id: Vec::new(),
        location: Vec::new(),
        version: "0.4.0".into(),
        pin: Arc::new(TrustPin {
            state: Mutex::new(PinState {
                root: PathBuf::from("."),
                folder_id: (0, 0),
                folder: None,
                key_id: None,
                key_digest: None,
                approval_key_id: None,
                approval_key_digest: None,
                latched: Some("fixture vault changed".into()),
                closed: true,
            }),
        }),
    }
}

fn socket_pair() -> (UnixStream, UnixStream) {
    let (client, server) = UnixStream::pair().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    (client, server)
}

fn read_socket_reply(client: &mut UnixStream, server: &UnixStream) -> Value {
    server.shutdown(Shutdown::Write).unwrap();
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn signed_owner_replies_keep_their_mac_and_leave_pending_warnings_alone() {
    for retired in [false, true] {
        let fixture = FailedAudit::new();
        let trust = trust_context();
        let lifecycle = Lifecycle::new();
        if retired {
            lifecycle.retire();
        }
        let cache = Mutex::new(SecretCache::default());
        let (mut client, mut server) = socket_pair();
        let mut workers = WorkerTracker::new();
        let connection = workers.register_connection(&server).unwrap();
        let response = owner_error(&trust, vec![1; wire::NONCE_LEN], "unsupported").unwrap();
        let hard_lock = owner_error(&trust, vec![1; wire::NONCE_LEN], "hard_locked").unwrap();
        let replies = Replies {
            lifecycle: &lifecycle,
            connection: &connection,
            trust: &trust,
            cache: &cache,
            cmd: "owner_channel",
            audit: &fixture.audit,
            audit_warning: true,
        };
        replies
            .write_with_hard_lock(&mut server, &response, Some(&hard_lock))
            .unwrap();
        let received = read_socket_reply(&mut client, &server);
        assert_eq!(received, if retired { hard_lock } else { response });
        let (kind, fields, tag) = wire::from_json(&received).unwrap();
        assert!(wire::verify(
            trust.daemon_auth_key.as_ref(),
            kind,
            &fields,
            &tag
        ));
        consume_warning(&fixture.audit);
        assert_no_warning(&fixture.audit);
    }
}

#[test]
fn retired_ordinary_reply_attaches_warning_to_the_hard_lock_replacement() {
    let fixture = FailedAudit::new();
    let trust = trust_context();
    let lifecycle = Lifecycle::new();
    lifecycle.retire();
    let cache = Mutex::new(SecretCache::default());
    let (mut client, mut server) = socket_pair();
    let mut workers = WorkerTracker::new();
    let connection = workers.register_connection(&server).unwrap();
    let replies = Replies {
        lifecycle: &lifecycle,
        connection: &connection,
        trust: &trust,
        cache: &cache,
        cmd: "list",
        audit: &fixture.audit,
        audit_warning: true,
    };
    replies
        .write(&mut server, &json!({"keys":["secret-bearing-result"]}))
        .unwrap();
    assert_eq!(
        read_socket_reply(&mut client, &server),
        json!({"error":"fixture vault changed", "error_code":"vault_hard_locked",
            "audit_warning":kv_audit::AUDIT_WARNING})
    );
    assert_no_warning(&fixture.audit);
}

fn dispatch(audit: &kv_audit::Audit, request: Value, retired: bool) -> Value {
    let (mut client, mut server) = socket_pair();
    client
        .write_all(&serde_json::to_vec(&request).unwrap())
        .unwrap();
    let lifecycle = Lifecycle::new();
    if retired {
        lifecycle.retire();
    }
    let mut workers = WorkerTracker::new();
    let connection = workers.register_connection(&server).unwrap();
    let approved = json!({});
    handle_connection(
        &mut server,
        Path::new("."),
        "",
        &DrawerStore::open(".", Key32::new([0; 32])),
        &Mutex::new(SecretCache::default()),
        &Key32::new([0; 32]),
        &trust_context(),
        &approved,
        &Zeroizing::new("fixture-token".into()),
        &kv_broker::build_provider_table(&approved).0,
        &kv_broker::load_http_policy_snapshot(&approved),
        &kv_broker::ApiCaller::new(),
        audit,
        &lifecycle,
        &connection,
        &json!({}),
        Duration::from_secs(2),
    )
    .unwrap();
    read_socket_reply(&mut client, &server)
}

#[test]
fn request_opt_in_requires_json_true_rather_than_a_truthy_value() {
    let fixture = FailedAudit::new();
    for value in [
        Value::Null,
        json!(false),
        json!(1),
        json!("yes"),
        json!([]),
        json!({}),
    ] {
        let response = dispatch(
            &fixture.audit,
            json!({"cmd":"status", "token":"wrong", "audit_warning":value}),
            false,
        );
        assert_eq!(response, json!({"error":"authentication required"}));
    }
    let response = dispatch(
        &fixture.audit,
        json!({"cmd":"status", "token":"wrong", "audit_warning":true}),
        false,
    );
    assert_eq!(
        response,
        json!({"error":"authentication required", "audit_warning":kv_audit::AUDIT_WARNING})
    );
    assert_no_warning(&fixture.audit);
}

#[test]
fn enforcement_stopping_and_stop_controls_never_consume_warnings() {
    let fixture = FailedAudit::new();
    assert_eq!(
        dispatch(
            &fixture.audit,
            json!({"cmd":"enforcement", "audit_warning":true}),
            false
        ),
        json!({"enforcement":kv_proto::ENFORCEMENT_GENERATION})
    );
    let refused = dispatch(
        &fixture.audit,
        json!({"cmd":"status", "audit_warning":true}),
        true,
    );
    assert_eq!(
        refused,
        json!({"error":"the agent is stopping; new requests are refused", "error_code":"agent_stopping"})
    );
    let stopped = dispatch(
        &fixture.audit,
        json!({"cmd":"stop", "token":"fixture-token", "choice":"now", "audit_warning":true}),
        false,
    );
    assert_eq!(
        stopped,
        json!({"stopping":true,"wait_seconds":10,"cut_off":0,"ended_runs":[]})
    );
    consume_warning(&fixture.audit);
    assert_no_warning(&fixture.audit);
}
