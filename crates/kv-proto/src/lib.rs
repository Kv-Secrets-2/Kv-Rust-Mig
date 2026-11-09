use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_MSG: usize = 1024 * 1024;
pub const MAX_AGENT_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const ENFORCEMENT_GENERATION: u64 = 3;
pub const OUTDATED_SERVICE_REFUSAL: &str = "refused: the kv service running for this project was started before this kv update and does not enforce its current rules, so it is not used. Run 'kv unlock' to replace it (it is stopped and the current one started; the vault and its files are kept).";
pub const OWNER_ENDPOINTS: &[&str] = &[
    "owner_channel",
    "owner_request_record",
    "owner_grant_register",
    "owner_permit_request",
    "owner_permit_register",
    "owner_pause_request",
    "owner_pause_answer",
    "owner_http_rule",
    "owner_revoke",
    "owner_retire",
    "owner_end_job",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    pub session_nonce: Vec<u8>,
    pub protected: bool,
    pub owner_key_id: String,
    pub daemon_version: String,
    pub providers: Vec<(String, String)>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    DaemonRefused(#[from] DaemonRefused),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the daemon refused: {code}")]
pub struct DaemonRefused {
    pub code: String,
}

pub fn check_answer(
    answer: &Value,
    challenge: &[u8],
    unwrapped: &kv_crypto::Identity,
    expect: &str,
) -> Result<Map<String, Value>, ChannelError> {
    let (kind, fields, tag) = kv_approvals::wire::from_json(answer)
        .map_err(|_| ChannelError::Message("the daemon's answer is not a signed message".into()))?;
    let key = kv_crypto::derive_labeled_key(&unwrapped.master_key, b"kv-approval:daemon-auth", &[]);
    if !kv_approvals::wire::verify(key.as_ref(), kind, &fields, &tag) {
        return Err(ChannelError::Message(
            "the daemon's answer is not signed with this vault's key".into(),
        ));
    }
    let answer_challenge = fields
        .get("challenge")
        .and_then(|value| match value {
            kv_approvals::wire::FieldValue::Nonce(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| {
            ChannelError::Message("the daemon's answer is not a signed message".into())
        })?;
    if answer_challenge != challenge {
        return Err(ChannelError::Message(
            "the daemon's answer is for another challenge (a replay)".into(),
        ));
    }
    if kind == kv_approvals::wire::MessageKind::ErrorV1 {
        let code = fields
            .get("code")
            .and_then(|value| match value {
                kv_approvals::wire::FieldValue::Text(code)
                | kv_approvals::wire::FieldValue::Enum(code) => Some(code.clone()),
                _ => None,
            })
            .unwrap_or_default();
        return Err(ChannelError::DaemonRefused(DaemonRefused { code }));
    }
    if kind.name() != expect {
        return Err(ChannelError::Message(format!(
            "the daemon answered {}, not {expect}",
            kind.name()
        )));
    }
    let mut output = Map::new();
    for (name, value) in fields {
        output.insert(name, wire_value_json(value));
    }
    Ok(output)
}

fn wire_value_json(value: kv_approvals::wire::FieldValue) -> Value {
    match value {
        kv_approvals::wire::FieldValue::Nonce(bytes)
        | kv_approvals::wire::FieldValue::Bytes(bytes) => Value::String(hex::encode(bytes)),
        kv_approvals::wire::FieldValue::Text(text) | kv_approvals::wire::FieldValue::Enum(text) => {
            Value::String(text)
        }
        kv_approvals::wire::FieldValue::Bool(value) => Value::Bool(value),
        kv_approvals::wire::FieldValue::List(items) => Value::Array(
            items
                .into_iter()
                .map(|item| Value::Array(item.into_iter().map(wire_value_json).collect()))
                .collect(),
        ),
    }
}

pub fn check_channel(
    answer: &Value,
    challenge: &[u8],
    unwrapped: &kv_crypto::Identity,
) -> Result<Channel, ChannelError> {
    let fields = check_answer(answer, challenge, unwrapped, "channel-v1")?;
    let protected = fields.get("mode").and_then(Value::as_str) == Some("protected");
    let owner_key_id = fields
        .get("owner_key_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if protected {
        let seed = kv_approvals::owner::OwnerSeed::from_slice(&unwrapped.owner_seed[..])
            .map_err(|error| ChannelError::Message(error.to_string()))?;
        let expected = kv_approvals::owner::owner_key_id(
            &kv_approvals::owner::owner_public_key(&seed),
            &unwrapped.local_approval_id,
        );
        let local = fields
            .get("local_approval_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let location = fields
            .get("location")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if owner_key_id != expected
            || local != hex::encode(unwrapped.local_approval_id)
            || location != hex::encode(&unwrapped.location)
        {
            return Err(ChannelError::Message(
                "the daemon serves another vault (its identity differs from this key file)".into(),
            ));
        }
    }
    let providers = fields
        .get("providers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let pair = item.as_array()?;
            Some((
                pair.first()?.as_str()?.to_owned(),
                pair.get(1)?.as_str()?.to_owned(),
            ))
        })
        .collect();
    Ok(Channel {
        session_nonce: fields
            .get("session_nonce")
            .and_then(Value::as_str)
            .and_then(|value| hex::decode(value).ok())
            .unwrap_or_default(),
        protected,
        owner_key_id,
        daemon_version: fields
            .get("daemon_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        providers,
    })
}

pub fn open_channel(
    root: impl AsRef<Path>,
    unwrapped: &kv_crypto::Identity,
    providers: bool,
) -> Result<Channel, ChannelError> {
    let mut challenge = vec![0_u8; kv_approvals::wire::NONCE_LEN];
    getrandom::getrandom(&mut challenge)
        .map_err(|_| ChannelError::Message("operating-system randomness unavailable".into()))?;
    let mut fields = Map::new();
    fields.insert("challenge".into(), Value::String(hex::encode(&challenge)));
    fields.insert("providers".into(), Value::Bool(providers));
    let answer = agent_request(root, "owner_channel", &fields).map_err(|_| {
        ChannelError::Message("no daemon answered; start it with 'kv unlock' and try again".into())
    })?;
    check_channel(&answer, &challenge, unwrapped)
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("{0}")]
    Message(String),
    #[error("request exceeds {MAX_MSG} bytes")]
    RequestTooLarge,
    #[error("agent response exceeds {MAX_AGENT_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    #[error("request is not one JSON document: {0}")]
    InvalidJson(String),
    #[error("{0}")]
    InvalidUtf8(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn runtime_dir() -> Result<PathBuf, ProtocolError> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| ProtocolError::Message("HOME is not set".into()))?;
    Ok(PathBuf::from(home).join(".kv"))
}

fn root_string(root: &Path) -> Result<String, ProtocolError> {
    root.to_str()
        .map(str::to_owned)
        .ok_or_else(|| ProtocolError::Message("project root cannot be encoded".into()))
}

pub fn project_hash(root: Option<&Path>) -> Result<String, ProtocolError> {
    let Some(root) = root else {
        return Ok("default".into());
    };
    let root = root_string(root)?;
    if root.is_empty() {
        return Ok("default".into());
    }
    let digest = Sha256::digest(root.as_bytes());
    Ok(hex(&digest)[..12].to_owned())
}

pub fn agent_socket_path(root: Option<&Path>) -> Result<PathBuf, ProtocolError> {
    Ok(runtime_dir()?.join(format!("agent-{}.sock", project_hash(root)?)))
}

pub fn agent_token_path(root: Option<&Path>) -> Result<PathBuf, ProtocolError> {
    Ok(runtime_dir()?.join(format!("agent-{}.token", project_hash(root)?)))
}

pub fn agent_pid_path(root: Option<&Path>) -> Result<PathBuf, ProtocolError> {
    Ok(runtime_dir()?.join(format!("agent-{}.pid", project_hash(root)?)))
}

pub fn agent_port(root: Option<&Path>) -> Result<u16, ProtocolError> {
    let Some(root) = root else {
        return Ok(19742);
    };
    let root = root_string(root)?;
    if root.is_empty() {
        return Ok(19742);
    }
    let digest: [u8; 32] = Sha256::digest(root.as_bytes()).into();
    let [a, b, c, d, ..] = digest;
    let prefix = u32::from_be_bytes([a, b, c, d]);
    Ok(19200 + (prefix % 800) as u16)
}

#[cfg(unix)]
fn private_token(path: &Path, runtime: &Path) -> String {
    use rustix::fs::{Mode, OFlags, open};
    use std::os::unix::fs::MetadataExt;

    let Ok(directory) = std::fs::symlink_metadata(runtime) else {
        return String::new();
    };
    if !directory.is_dir()
        || directory.file_type().is_symlink()
        || directory.uid() != rustix::process::getuid().as_raw()
        || directory.mode() & 0o777 != 0o700
    {
        return String::new();
    }
    let Ok(fd) = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return String::new();
    };
    let mut file = std::fs::File::from(fd);
    let Ok(metadata) = file.metadata() else {
        return String::new();
    };
    let Ok(named) = std::fs::symlink_metadata(path) else {
        return String::new();
    };
    if !metadata.is_file()
        || named.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || (metadata.dev(), metadata.ino()) != (named.dev(), named.ino())
    {
        return String::new();
    }
    let mut bytes = Vec::new();
    if Read::by_ref(&mut file)
        .take(4096)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return String::new();
    }
    String::from_utf8_lossy(&bytes).trim().to_owned()
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

pub fn read_request<R: Read>(reader: &mut R) -> Result<Option<Value>, ProtocolError> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            if bytes.is_empty() {
                return Ok(None);
            }
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| ProtocolError::InvalidJson(error.to_string()));
        }
        if bytes.len().saturating_add(read) > MAX_MSG {
            return Err(ProtocolError::RequestTooLarge);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Err(error) = std::str::from_utf8(&bytes) {
            return Err(ProtocolError::InvalidUtf8(python_utf8_error(&bytes, error)));
        }
        match serde_json::from_slice(&bytes) {
            Ok(value) => return Ok(Some(value)),
            Err(error) if error.is_eof() => {}
            Err(error) => return Err(ProtocolError::InvalidJson(error.to_string())),
        }
    }
}

fn python_utf8_error(bytes: &[u8], error: std::str::Utf8Error) -> String {
    let position = error.valid_up_to();
    if error.error_len().is_none() {
        let end = bytes.len().saturating_sub(1);
        if end == position {
            return format!(
                "UnicodeDecodeError: 'utf-8' codec can't decode byte 0x{:02x} in position {position}: unexpected end of data",
                bytes[position]
            );
        }
        return format!(
            "UnicodeDecodeError: 'utf-8' codec can't decode bytes in position {position}-{end}: unexpected end of data"
        );
    }
    let byte = bytes[position];
    let reason = if (0xc2..=0xf4).contains(&byte) {
        "invalid continuation byte"
    } else {
        "invalid start byte"
    };
    format!(
        "UnicodeDecodeError: 'utf-8' codec can't decode byte 0x{byte:02x} in position {position}: {reason}"
    )
}

pub fn reply_bytes(response: &Value) -> Result<Vec<u8>, ProtocolError> {
    let bytes = kv_store::pyjson::to_vec_python(response, false)
        .map_err(|error| ProtocolError::Message(error.to_string()))?;
    if bytes.len() <= MAX_AGENT_RESPONSE_BYTES {
        return Ok(bytes);
    }
    let mut replacement = Map::new();
    replacement.insert("error".into(), Value::String("response too large".into()));
    replacement.insert("response_truncated".into(), Value::Bool(true));
    replacement.insert(
        "max_response_bytes".into(),
        Value::Number(MAX_AGENT_RESPONSE_BYTES.into()),
    );
    kv_store::pyjson::to_vec_python(&Value::Object(replacement), false)
        .map_err(|error| ProtocolError::Message(error.to_string()))
}

pub fn write_reply<W: Write>(writer: &mut W, response: &Value) -> Result<(), ProtocolError> {
    writer.write_all(&reply_bytes(response)?)?;
    writer.flush()?;
    Ok(())
}

#[cfg(unix)]
fn exchange(root: &Path, request: &Value) -> Result<Value, ProtocolError> {
    use std::os::unix::net::UnixStream;

    let path = agent_socket_path(Some(root))?;
    let mut socket = UnixStream::connect(path)?;
    let payload = kv_store::pyjson::to_vec_python(request, false)
        .map_err(|error| ProtocolError::Message(error.to_string()))?;
    if payload.len() > MAX_MSG {
        return Err(ProtocolError::RequestTooLarge);
    }
    socket.write_all(&payload)?;
    socket.shutdown(std::net::Shutdown::Write)?;
    read_reply(&mut socket)
}

#[cfg(windows)]
fn exchange(_root: &Path, _request: &Value) -> Result<Value, ProtocolError> {
    Err(ProtocolError::Message(
        "agent TCP transport is not yet supported on Windows".into(),
    ))
}

pub fn agent_request(
    root: impl AsRef<Path>,
    cmd: &str,
    fields: &Map<String, Value>,
) -> Result<Value, ProtocolError> {
    #[cfg(windows)]
    {
        let _ = (root, cmd, fields);
        return Err(ProtocolError::Message(
            "agent TCP transport is not yet supported on Windows".into(),
        ));
    }
    #[cfg(unix)]
    {
        let root = root.as_ref();
        if !matches!(cmd, "status" | "lock" | "stop") {
            let enforcement = exchange(root, &json!({"cmd":"enforcement"}))?;
            if enforcement
                .get("enforcement")
                .and_then(Value::as_u64)
                .is_none_or(|generation| generation < ENFORCEMENT_GENERATION)
            {
                return Err(ProtocolError::Message(OUTDATED_SERVICE_REFUSAL.into()));
            }
        }
        let runtime = runtime_dir()?;
        let token_path = agent_token_path(Some(root))?;
        let token = private_token(&token_path, &runtime);
        let mut request = Map::new();
        request.insert("cmd".into(), Value::String(cmd.into()));
        request.insert("token".into(), Value::String(token));
        for (name, value) in fields {
            request.insert(name.clone(), value.clone());
        }
        request.entry("audit_warning").or_insert(Value::Bool(false));
        exchange(root, &Value::Object(request))
    }
}

#[cfg(unix)]
fn read_reply<R: Read>(reader: &mut R) -> Result<Value, ProtocolError> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > MAX_AGENT_RESPONSE_BYTES {
            return Err(ProtocolError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    serde_json::from_slice(&bytes).map_err(ProtocolError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_returns_one_complete_document_and_rejects_trailing_data() {
        assert!(
            read_request(&mut &b"{\"a\":1} trailing"[..])
                .unwrap_err()
                .to_string()
                .starts_with("request is not one JSON document:")
        );
        assert_eq!(
            read_request(&mut &b" {\"a\":1} \n"[..]).unwrap(),
            Some(json!({"a":1}))
        );
    }

    #[test]
    fn invalid_utf8_error_matches_python_json_loads() {
        let error = read_request(&mut &b"\xff"[..]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        );
    }

    #[test]
    fn empty_project_root_uses_default_hash_and_port() {
        assert_eq!(project_hash(Some(Path::new(""))).unwrap(), "default");
        assert_eq!(agent_port(Some(Path::new(""))).unwrap(), 19742);
    }

    #[test]
    fn arbitrary_request_bytes_never_panic() {
        let mut random = [0u8; 2048];
        for size in 0..random.len() {
            getrandom::getrandom(&mut random[..size]).expect("random test data");
            let bytes = &random[..size];
            assert!(
                std::panic::catch_unwind(|| {
                    let _ = read_request(&mut &bytes[..]);
                })
                .is_ok()
            );
        }
    }
}
