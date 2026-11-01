#[cfg(unix)]
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::{LazyLock, Mutex};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};

use kv_approvals::owner::{OwnerSeed, owner_key_id, owner_public_key};
use kv_approvals::wire::{self, FieldValue, MessageFields, MessageKind};
use kv_crypto::{Key32, Zeroizing, derive_labeled_key, keyfile};
use kv_store::DrawerStore;
#[cfg(unix)]
use kv_store::config_authority;
use serde_json::{Value, json};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use subtle::ConstantTimeEq;
use thiserror::Error;

#[cfg(unix)]
const START_REFUSAL_PREFIX: &str = "Cannot start kv daemon:";
#[cfg(unix)]
const SHORT_STOP_WAIT_SECONDS: u64 = 10;
#[cfg(unix)]
const AGENT_VERSION: &str = "0.4.0";
#[cfg(unix)]
const API_TIMEOUT: u64 = 120;

#[cfg(unix)]
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(API_TIMEOUT + 10);

#[cfg(unix)]
static STOP_SIGNAL_REQUESTED: LazyLock<Arc<AtomicBool>> =
    LazyLock::new(|| Arc::new(AtomicBool::new(false)));

#[cfg(unix)]
struct StopSignalGuard(signal_hook::SigId);

#[cfg(unix)]
impl StopSignalGuard {
    fn install() -> Result<Self, AgentError> {
        STOP_SIGNAL_REQUESTED.store(false, Ordering::Release);
        let id = signal_hook::flag::register(
            signal_hook::consts::SIGTERM,
            Arc::clone(&STOP_SIGNAL_REQUESTED),
        )
        .map_err(|error| AgentError(error.to_string()))?;
        Ok(Self(id))
    }
}

#[cfg(unix)]
impl Drop for StopSignalGuard {
    fn drop(&mut self) {
        signal_hook::low_level::unregister(self.0);
        STOP_SIGNAL_REQUESTED.store(false, Ordering::Release);
    }
}

#[cfg(unix)]
#[derive(Default)]
struct SecretCache {
    environments: BTreeMap<String, BTreeMap<String, Zeroizing<String>>>,
}

#[cfg(unix)]
impl SecretCache {
    fn names(&mut self, store: &DrawerStore, env: &str) -> Result<Vec<String>, AgentError> {
        if !self.environments.contains_key(env) {
            let secrets = store
                .list_secrets(env)?
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            self.environments.insert(env.to_owned(), secrets);
        }
        Ok(self.environments[env].keys().cloned().collect())
    }

    fn counts(&self) -> (usize, usize) {
        (
            self.environments.len(),
            self.environments.values().map(BTreeMap::len).sum(),
        )
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct AgentError(pub String);

impl From<std::io::Error> for AgentError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<kv_proto::ProtocolError> for AgentError {
    fn from(error: kv_proto::ProtocolError) -> Self {
        Self(error.to_string())
    }
}

impl From<kv_store::StoreError> for AgentError {
    fn from(error: kv_store::StoreError) -> Self {
        Self(error.to_string())
    }
}

pub struct TrustContext {
    pub session_nonce: Zeroizing<[u8; 32]>,
    pub daemon_auth_key: Key32,
    pub grant_state_key: Key32,
    pub token_key: Key32,
    pub protected: bool,
    pub owner_key_id: String,
    pub local_approval_id: Vec<u8>,
    pub location: Vec<u8>,
    pub version: String,
    #[cfg(unix)]
    pin: Arc<TrustPin>,
}

#[cfg(unix)]
struct TrustPin {
    state: std::sync::Mutex<PinState>,
}

#[cfg(unix)]
struct PinState {
    root: std::path::PathBuf,
    folder_id: (u64, u64),
    folder: File,
    key_id: Option<(u64, u64)>,
    key_digest: Option<[u8; 32]>,
    latched: Option<String>,
    closed: bool,
}

impl TrustContext {
    pub fn at_unlock(
        root: impl AsRef<Path>,
        passphrase: Option<&[u8]>,
        master_key: &Key32,
    ) -> Result<Self, AgentError> {
        let root = root.as_ref();
        #[cfg(unix)]
        let root_path = fs::canonicalize(root)?;
        #[cfg(unix)]
        let folder = File::open(&root_path)?;
        #[cfg(unix)]
        let folder_metadata = folder.metadata()?;
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        let key_path = root.join(".secrets").join("key");
        let blob = fs::read(key_path)?;
        #[cfg(unix)]
        let key_metadata = fs::symlink_metadata(root.join(".secrets").join("key"))?;
        #[cfg(unix)]
        let key_id = (key_metadata.dev(), key_metadata.ino());
        #[cfg(unix)]
        let key_digest: [u8; 32] = Sha256::digest(&blob).into();
        let mut owner_id = String::new();
        let mut local_approval_id = Vec::new();
        let mut location = root.to_string_lossy().as_bytes().to_vec();
        let protected = match passphrase {
            Some(passphrase) => {
                let identity = keyfile::unwrap_v4(&blob, passphrase)
                    .map_err(|_| AgentError("the passphrase did not open this vault".into()))?;
                if identity.master_key != *master_key {
                    return Err(AgentError(
                        "the key file changed while unlocking; try again".into(),
                    ));
                }
                let seed = OwnerSeed::from_slice(&identity.owner_seed[..])
                    .map_err(|error| AgentError(error.to_string()))?;
                let public = owner_public_key(&seed);
                owner_id = owner_key_id(&public, &identity.local_approval_id);
                local_approval_id = identity.local_approval_id.to_vec();
                if !identity.location.is_empty() {
                    location = identity.location.clone();
                }
                true
            }
            None => false,
        };
        let mut nonce = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut nonce[..])
            .map_err(|_| AgentError("operating-system randomness unavailable".into()))?;
        let output = Self {
            session_nonce: nonce,
            daemon_auth_key: derive_labeled_key(master_key, b"kv-approval:daemon-auth", &[]),
            grant_state_key: derive_labeled_key(master_key, b"kv-approval:grant-state", &[]),
            token_key: derive_labeled_key(master_key, b"kv-approval:token", &[]),
            protected,
            owner_key_id: owner_id,
            local_approval_id,
            location,
            version: "0.4.0".to_owned(),
            #[cfg(unix)]
            pin: Arc::new(TrustPin {
                state: std::sync::Mutex::new(PinState {
                    root: root_path,
                    folder_id: (folder_metadata.dev(), folder_metadata.ino()),
                    folder,
                    key_id: Some(key_id),
                    key_digest: Some(key_digest),
                    latched: None,
                    closed: false,
                }),
            }),
        };
        Ok(output)
    }

    #[cfg(unix)]
    pub fn observe(&self) -> Result<(), AgentError> {
        let mut state = self
            .pin
            .state
            .lock()
            .map_err(|_| AgentError("the vault could not be checked (LockPoisoned)".into()))?;
        if let Some(reason) = &state.latched {
            return Err(AgentError(reason.clone()));
        }
        let reason = if state.closed {
            Some("the vault folder pin is closed".to_owned())
        } else {
            let metadata = match fs::symlink_metadata(&state.root) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Self::latch_locked(&mut state, "the vault folder is gone");
                }
                Err(_) => {
                    return Self::latch_locked(&mut state, "the vault folder cannot be checked");
                }
            };
            if metadata.file_type().is_symlink() {
                Some("the vault path now contains a link".to_owned())
            } else if (metadata.dev(), metadata.ino()) != state.folder_id {
                Some("the vault folder was replaced or moved".to_owned())
            } else if state.folder.metadata().map(|m| m.nlink()).unwrap_or(0) == 0 {
                Some("the vault folder was deleted".to_owned())
            } else {
                let key_path = state.root.join(".secrets").join("key");
                match (fs::symlink_metadata(&key_path), fs::read(&key_path)) {
                    (Err(error), _) if error.kind() == std::io::ErrorKind::NotFound => {
                        Some("the key file is gone".to_owned())
                    }
                    (Err(_), _) => Some("the key file cannot be read".to_owned()),
                    (Ok(metadata), Ok(blob)) => {
                        if Some((metadata.dev(), metadata.ino())) != state.key_id {
                            Some("the key file was replaced".to_owned())
                        } else if Some(Sha256::digest(&blob).into()) != state.key_digest {
                            Some("the key file changed".to_owned())
                        } else {
                            None
                        }
                    }
                    (Ok(_), Err(_)) => Some("the key file cannot be read".to_owned()),
                }
            }
        };
        if let Some(reason) = reason {
            return Self::latch_locked(&mut state, &reason);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn latch_locked(state: &mut PinState, reason: &str) -> Result<(), AgentError> {
        let message = state.latched.get_or_insert_with(|| {
            format!(
                "vault changed under the running daemon ({reason}); kv refuses all requests. Stop the daemon and unlock again."
            )
        });
        Err(AgentError(message.clone()))
    }

    #[cfg(unix)]
    pub fn hard_locked(&self) -> Option<String> {
        self.pin
            .state
            .lock()
            .ok()
            .and_then(|state| state.latched.clone())
    }

    /// Retire the held folder pin. Work-window waiting is deferred until stage 6.
    #[cfg(unix)]
    pub fn close(&self) {
        if let Ok(mut state) = self.pin.state.lock() {
            state.closed = true;
        }
    }
}

#[allow(unsafe_code)]
pub fn protect_process_memory() -> Value {
    let mut status = json!({
        "enabled":false,
        "supported":false,
        "verified":false,
        "method":"none",
        "reason":""
    });
    #[cfg(target_os = "linux")]
    {
        status["supported"] = Value::Bool(true);
        status["method"] = Value::String("prctl(PR_SET_DUMPABLE=0)".into());
        // SAFETY: PR_SET_DUMPABLE accepts scalar arguments and requires no pointers.
        let set = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if set != 0 {
            let error = std::io::Error::last_os_error();
            status["reason"] = Value::String(error.to_string());
            return status;
        }
        // SAFETY: PR_GET_DUMPABLE accepts scalar arguments and requires no pointers.
        let current = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        if current == 0 {
            status["enabled"] = Value::Bool(true);
            status["verified"] = Value::Bool(true);
        } else if current < 0 {
            status["enabled"] = Value::Bool(true);
            status["reason"] = Value::String("enabled, but verification failed".into());
        } else {
            status["reason"] = Value::String(format!("kernel still reports dumpable={current}"));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        status["reason"] = Value::String("not supported on this platform".into());
    }
    status
}

#[cfg(unix)]
/// Serves the foreground daemon; in-flight work draining is deferred to Stage 6.
pub fn run_agent(
    root: impl AsRef<Path>,
    store: Arc<DrawerStore>,
    master_key: Key32,
    trust: TrustContext,
) -> Result<Value, AgentError> {
    let memory_hardening = protect_process_memory();
    let root = fs::canonicalize(root.as_ref())?;
    let root_text = root
        .to_str()
        .ok_or_else(|| AgentError("project root cannot be encoded".into()))?
        .to_owned();
    let approved = config_authority::require_approved(&root, &master_key)
        .map_err(|error| AgentError(format!("{START_REFUSAL_PREFIX} {error}")))?;
    ensure_runtime_dir()?;
    let pid_path = kv_proto::agent_pid_path(Some(&root))?;
    let pid = std::process::id();
    let mut pid_file = take_pid_file(&pid_path, pid)?;
    let token = Arc::new(Zeroizing::new(token_hex(32)?));
    let token_path = kv_proto::agent_token_path(Some(&root))?;
    write_private(&token_path, token.as_bytes())?;
    let socket_path = kv_proto::agent_socket_path(Some(&root))?;
    remove_owned_stale_socket(&socket_path)?;
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .map_err(|_| AgentError("Cannot start kv daemon: make its Unix socket path available in an owner-only runtime folder (0700), then run 'kv unlock' again.".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    }
    rustix::net::listen(&listener, 20).map_err(|error| AgentError(error.to_string()))?;
    listener.set_nonblocking(true)?;
    let socket_meta = fs::symlink_metadata(&socket_path)?;
    let socket_id = file_identity(&socket_meta);
    let stopping = Arc::new(AtomicBool::new(false));
    let _signal_guard = StopSignalGuard::install()?;
    let trust = Arc::new(trust);
    let master_key = Arc::new(master_key);
    let approved = Arc::new(approved.value);
    let cache = Arc::new(Mutex::new(SecretCache::default()));
    let mut workers = Vec::new();

    while !stopping.load(Ordering::Acquire) && !STOP_SIGNAL_REQUESTED.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut connection, _)) => {
                let stopping = Arc::clone(&stopping);
                let cache = Arc::clone(&cache);
                let trust = Arc::clone(&trust);
                let master_key = Arc::clone(&master_key);
                let approved = Arc::clone(&approved);
                let store = Arc::clone(&store);
                let token = Arc::clone(&token);
                let root = root.clone();
                let root_text = root_text.clone();
                let memory_hardening = memory_hardening.clone();
                workers.push(thread::spawn(move || {
                    let _ = handle_connection(
                        &mut connection,
                        &root,
                        &root_text,
                        &store,
                        &cache,
                        &master_key,
                        &trust,
                        &approved,
                        &token,
                        &stopping,
                        &memory_hardening,
                        CONNECTION_TIMEOUT,
                    );
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                stopping.store(true, Ordering::Release);
                return Err(AgentError(error.to_string()));
            }
        }
    }
    stopping.store(true, Ordering::Release);
    drop(listener);
    for worker in workers {
        let _ = worker.join();
    }
    remove_if_matches(&token_path, token.as_str())?;
    remove_if_matches(&pid_path, &pid.to_string())?;
    remove_socket_if_matches(&socket_path, socket_id);
    let _ = pid_file.flush();
    Ok(memory_hardening)
}

#[cfg(windows)]
pub fn run_agent(
    _root: impl AsRef<Path>,
    _store: Arc<DrawerStore>,
    _master_key: Key32,
    _trust: TrustContext,
) -> Result<Value, AgentError> {
    Err(AgentError(
        "agent TCP transport is not yet supported on Windows".into(),
    ))
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn handle_connection(
    stream: &mut std::os::unix::net::UnixStream,
    root: &Path,
    root_text: &str,
    store: &DrawerStore,
    cache: &Mutex<SecretCache>,
    master_key: &Key32,
    trust: &TrustContext,
    approved: &Value,
    token: &Zeroizing<String>,
    stopping: &AtomicBool,
    memory_hardening: &Value,
    request_timeout: Duration,
) -> Result<(), AgentError> {
    let request = match read_request_with_timeout(stream, request_timeout) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            let _ = kv_proto::write_reply(stream, &request_error_response(&error));
            return Ok(());
        }
    };
    let Some(request) = request.as_object() else {
        kv_proto::write_reply(stream, &json!({"error":"request must be a JSON object"}))?;
        return Ok(());
    };
    let cmd = request.get("cmd").and_then(Value::as_str).unwrap_or("");
    if cmd == "enforcement" {
        kv_proto::write_reply(
            stream,
            &json!({"enforcement":kv_proto::ENFORCEMENT_GENERATION}),
        )?;
        return Ok(());
    }
    if stopping.load(Ordering::Acquire) && cmd != "stop" {
        kv_proto::write_reply(
            stream,
            &json!({
                "error":"the agent is stopping; new requests are refused",
                "error_code":"agent_stopping"
            }),
        )?;
        return Ok(());
    }
    if kv_proto::OWNER_ENDPOINTS.contains(&cmd) {
        let _ = serve_owner_endpoint(stream, cmd, request, trust, root, approved, master_key);
        return Ok(());
    }
    if cmd != "status"
        && cmd != "stop"
        && let Err(error) = trust.observe()
    {
        kv_proto::write_reply(
            stream,
            &json!({"error":error.to_string(),"error_code":"vault_hard_locked"}),
        )?;
        return Ok(());
    }
    if !matches!(cmd, "status" | "stop" | "lock")
        && let Err(error) = config_authority::require_current(root, approved, master_key)
    {
        kv_proto::write_reply(
            stream,
            &json!({
                "error":error.to_string(),
                "error_code":"config_authority_changed"
            }),
        )?;
        return Ok(());
    }
    let supplied = request.get("token").and_then(Value::as_str).unwrap_or("");
    if supplied.len() > 128 || !bool::from(supplied.as_bytes().ct_eq(token.as_bytes())) {
        kv_proto::write_reply(stream, &json!({"error":"authentication required"}))?;
        return Ok(());
    }
    if cmd.is_empty() || cmd.len() > 32 {
        kv_proto::write_reply(stream, &json!({"error":"cmd must be a string"}))?;
        return Ok(());
    }
    let known = [
        "run",
        "list",
        "envs",
        "status",
        "api",
        "query",
        "ssh",
        "cap_api",
        "check_file",
        "tracked_files",
        "record_request",
        "stop",
        "permit_requests",
        "lock",
        "dashboard_snapshot",
        "owner_pause_right",
        "pause_job",
        "owner_pause_history",
        "refuse_permit",
    ];
    if !known.contains(&cmd) {
        kv_proto::write_reply(stream, &json!({"error":"unknown command"}))?;
        return Ok(());
    }
    if let Some(env) = request.get("env").and_then(Value::as_str)
        && kv_store::envname::validate_env_name(env).is_err()
    {
        kv_proto::write_reply(stream, &json!({"error":"invalid environment name"}))?;
        return Ok(());
    }
    let response = match cmd {
        "status" => match cache.lock() {
            Ok(cache) => {
                status_response(root_text, store, approved, trust, memory_hardening, &cache)
            }
            Err(_) => json!({"error":"secret cache is unavailable"}),
        },
        "list" => {
            let env = request
                .get("env")
                .and_then(Value::as_str)
                .or_else(|| approved.get("default_env").and_then(Value::as_str))
                .unwrap_or("dev");
            match cache.lock() {
                Ok(mut cache) => match cache.names(store, env) {
                    Ok(keys) => json!({"keys":keys,"env":env}),
                    Err(error) => json!({"error":error.to_string()}),
                },
                Err(_) => json!({"error":"secret cache is unavailable"}),
            }
        }
        "envs" => {
            let environments = approved
                .get("environments")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            json!({"environments":environments,"invalid_environments":[]})
        }
        "lock" => json!({"locking":true,"ended":true}),
        "stop" => {
            if request
                .get("choice")
                .and_then(Value::as_str)
                .is_some_and(|choice| choice != "now" && choice != "wait")
            {
                json!({"error":"choice must be 'wait' or 'now'"})
            } else {
                stopping.store(true, Ordering::Release);
                json!({
                    "stopping":true,
                    "wait_seconds":SHORT_STOP_WAIT_SECONDS,
                    "cut_off":0,
                    "ended_runs":[]
                })
            }
        }
        other => json!({"error":format!("{other} is not supported by this kv service yet")}),
    };
    kv_proto::write_reply(stream, &response)?;
    Ok(())
}

#[cfg(unix)]
fn owner_challenge(request: &serde_json::Map<String, Value>) -> Option<Vec<u8>> {
    let text = request.get("challenge")?.as_str()?;
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..32)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok())
        .collect::<Option<Vec<_>>>()
}

#[cfg(unix)]
fn signed_owner(
    trust: &TrustContext,
    kind: MessageKind,
    fields: MessageFields,
) -> Result<Value, AgentError> {
    let tag = wire::mac(trust.daemon_auth_key.as_ref(), kind, &fields)
        .map_err(|error| AgentError(error.to_string()))?;
    wire::to_json(kind, &fields, &tag).map_err(|error| AgentError(error.to_string()))
}

#[cfg(unix)]
fn owner_error(trust: &TrustContext, challenge: Vec<u8>, code: &str) -> Result<Value, AgentError> {
    let mut fields = MessageFields::new();
    fields.insert("challenge".into(), FieldValue::Nonce(challenge));
    fields.insert(
        "session_nonce".into(),
        FieldValue::Nonce(trust.session_nonce.to_vec()),
    );
    fields.insert("code".into(), FieldValue::Text(code.to_owned()));
    signed_owner(trust, MessageKind::ErrorV1, fields)
}

#[cfg(unix)]
fn serve_owner_endpoint(
    stream: &mut std::os::unix::net::UnixStream,
    cmd: &str,
    request: &serde_json::Map<String, Value>,
    trust: &TrustContext,
    root: &Path,
    approved: &Value,
    master_key: &Key32,
) -> Result<(), AgentError> {
    let challenge = owner_challenge(request).unwrap_or_else(|| vec![0; wire::NONCE_LEN]);
    let hard_locked = owner_error(trust, challenge.clone(), "hard_locked");
    let too_large = owner_error(trust, challenge.clone(), "response_too_large");
    let (Ok(hard_locked), Ok(too_large)) = (hard_locked, too_large) else {
        eprintln!("owner endpoint {cmd}: cannot sign an error; closing without an answer");
        return Ok(());
    };
    let answer = (|| {
        if owner_challenge(request).is_none() {
            return owner_error(trust, challenge.clone(), "bad_request");
        }
        if trust.observe().is_err() {
            return Ok(hard_locked.clone());
        }
        if config_authority::require_current(root, approved, master_key).is_err() {
            return owner_error(trust, challenge.clone(), "config_authority_changed");
        }
        if cmd != "owner_channel" {
            return owner_error(trust, challenge.clone(), "unsupported");
        }
        let mut fields = MessageFields::new();
        fields.insert("challenge".into(), FieldValue::Nonce(challenge.clone()));
        fields.insert(
            "session_nonce".into(),
            FieldValue::Nonce(trust.session_nonce.to_vec()),
        );
        fields.insert(
            "mode".into(),
            FieldValue::Enum(if trust.protected {
                "protected".into()
            } else {
                "unprotected".into()
            }),
        );
        fields.insert(
            "owner_key_id".into(),
            FieldValue::Text(trust.owner_key_id.clone()),
        );
        fields.insert(
            "local_approval_id".into(),
            FieldValue::Bytes(trust.local_approval_id.clone()),
        );
        fields.insert("location".into(), FieldValue::Bytes(trust.location.clone()));
        fields.insert(
            "daemon_version".into(),
            FieldValue::Text(trust.version.clone()),
        );
        fields.insert("providers".into(), FieldValue::List(owner_providers(root)));
        signed_owner(trust, MessageKind::ChannelV1, fields)
    })();
    let answer = match answer {
        Ok(answer) => answer,
        Err(_) => {
            eprintln!("owner endpoint {cmd}: internal error (details withheld)");
            match owner_error(trust, challenge, "internal") {
                Ok(answer) => answer,
                Err(_) => return Ok(()),
            }
        }
    };
    let raw = kv_store::pyjson::to_vec_python(&answer, false)
        .map_err(|error| AgentError(error.to_string()))?;
    let replacement = if raw.len() > kv_proto::MAX_AGENT_RESPONSE_BYTES {
        too_large
    } else {
        answer
    };
    kv_proto::write_reply(stream, &replacement)?;
    Ok(())
}

#[cfg(unix)]
fn owner_providers(root: &Path) -> Vec<Vec<FieldValue>> {
    let mut providers: BTreeMap<String, Value> = BTreeMap::new();
    providers.insert(
        "anthropic".into(),
        json!({"auth_type":"x-api-key","base_url":"https://api.anthropic.com","default_headers":{"Content-Type":"application/json","anthropic-version":"2023-06-01"},"secret_name":"ANTHROPIC_API_KEY"}),
    );
    providers.insert(
        "github".into(),
        json!({"auth_type":"bearer","base_url":"https://api.github.com","default_headers":{"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"},"secret_name":"GITHUB_TOKEN"}),
    );
    providers.insert(
        "google".into(),
        json!({"auth_query_param":"key","auth_type":"query","base_url":"https://generativelanguage.googleapis.com","default_headers":{"Content-Type":"application/json"},"secret_name":"GOOGLE_API_KEY"}),
    );
    providers.insert(
        "google-cloud".into(),
        json!({"auth_query_param":"key","auth_type":"query","base_url":"https://www.googleapis.com","default_headers":{"Content-Type":"application/json"},"secret_name":"GOOGLE_CLOUD_API_KEY"}),
    );
    providers.insert(
        "openai".into(),
        json!({"auth_type":"bearer","base_url":"https://api.openai.com","default_headers":{"Content-Type":"application/json"},"secret_name":"OPENAI_API_KEY"}),
    );
    if let Ok(snapshot) = kv_store::config::load_config(root)
        && let Some(custom) = snapshot.value.get("providers").and_then(Value::as_object)
    {
        for (name, value) in custom {
            providers.insert(name.clone(), value.clone());
        }
    }
    providers
        .into_iter()
        .filter_map(|(name, value)| {
            let canonical = kv_approvals::canonical::canonical_json(&value).ok()?;
            Some(vec![
                FieldValue::Text(name.to_owned()),
                FieldValue::Text(canonical),
            ])
        })
        .collect()
}

#[cfg(unix)]
fn read_request_with_timeout(
    stream: &mut std::os::unix::net::UnixStream,
    timeout: Duration,
) -> Result<Option<Value>, kv_proto::ProtocolError> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    kv_proto::read_request(stream)
}

#[cfg(unix)]
fn request_error_response(error: &kv_proto::ProtocolError) -> Value {
    match error {
        kv_proto::ProtocolError::RequestTooLarge => {
            json!({"error":format!("request exceeds {} bytes", kv_proto::MAX_MSG)})
        }
        kv_proto::ProtocolError::InvalidJson(_) | kv_proto::ProtocolError::Json(_) => {
            json!({"error":"invalid JSON"})
        }
        kv_proto::ProtocolError::InvalidUtf8(error) => json!({"error":error}),
        kv_proto::ProtocolError::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            json!({"error":"TimeoutError: timed out"})
        }
        kv_proto::ProtocolError::Io(error) => json!({"error":format!("OSError: {error}")}),
        other => json!({"error":other.to_string()}),
    }
}

#[cfg(unix)]
fn status_response(
    root: &str,
    _store: &DrawerStore,
    config: &Value,
    trust: &TrustContext,
    memory_hardening: &Value,
    cache: &SecretCache,
) -> Value {
    let environments = config
        .get("environments")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let policy = config
        .get("security")
        .and_then(Value::as_object)
        .and_then(|security| security.get("kv_run_policy"))
        .cloned()
        .unwrap_or_else(|| Value::String("blocklist".into()));
    let providers = ["anthropic", "github", "google", "google-cloud", "openai"]
        .into_iter()
        .collect::<Vec<_>>();
    let mut providers = providers
        .into_iter()
        .map(|name| Value::String(name.into()))
        .collect::<Vec<_>>();
    if let Some(custom) = config.get("providers").and_then(Value::as_object) {
        for name in custom.keys() {
            if !providers.iter().any(|value| value.as_str() == Some(name)) {
                providers.push(Value::String(name.clone()));
            }
        }
    }
    providers.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    let http_policy = http_policy_status(config);
    let (cached_environments, cached_secrets) = cache.counts();
    json!({
        "running":true,
        "session_nonce":hex(&trust.session_nonce[..]),
        "runs_used":{},
        "pid":std::process::id(),
        "root":root,
        "environments":environments,
        "cached_environments":cached_environments,
        "secrets":cached_secrets,
        "cached_secrets":cached_secrets,
        "providers":providers,
        "policy":policy,
        "memory_hardening":memory_hardening,
        "http_policy":http_policy,
        "version":AGENT_VERSION,
        "enforcement":kv_proto::ENFORCEMENT_GENERATION,
        "session":if trust.protected {"protected"} else {"unprotected"},
        "hard_locked":trust.hard_locked().is_some(),
        "runs":[]
    })
}

#[cfg(unix)]
fn http_policy_status(config: &Value) -> Value {
    let configured = config.get("broker_policy").is_some();
    let providers = config
        .get("broker_policy")
        .and_then(Value::as_object)
        .and_then(|policy| policy.get("http"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let provider_count = providers.as_object().map_or(0, serde_json::Map::len);
    let digest = config_authority::canonical(&providers)
        .map(|canonical| {
            use sha2::{Digest, Sha256};
            Sha256::digest(canonical)
        })
        .map(|digest| {
            digest[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .unwrap_or_default();
    json!({
        "configured":configured,
        "provider_count":provider_count,
        "digest":digest
    })
}

#[cfg(unix)]
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

#[cfg(unix)]
fn token_hex(bytes: usize) -> Result<String, AgentError> {
    let mut random = vec![0u8; bytes];
    getrandom::getrandom(&mut random)
        .map_err(|_| AgentError("operating-system randomness unavailable".into()))?;
    Ok(hex(&random))
}

#[cfg(unix)]
fn ensure_runtime_dir() -> Result<std::path::PathBuf, AgentError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let path = kv_proto::runtime_dir()?;
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(AgentError(
            "the agent runtime directory must be a real directory owned by this account".into(),
        ));
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> Result<(), AgentError> {
    use rustix::fs::{Mode, OFlags, fchmod, open};

    let fd = open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| AgentError(error.to_string()))?;
    let mut file = File::from(fd);
    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|error| AgentError(error.to_string()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn remove_owned_stale_socket(path: &Path) -> Result<(), AgentError> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;

    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::getuid().as_raw()
            {
                return Err(AgentError(
                    "Cannot start kv daemon: make its Unix socket path available in an owner-only runtime folder (0700), then run 'kv unlock' again.".into(),
                ));
            }
            fs::remove_file(path)?;
            Ok(())
        }
    }
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(unix)]
fn remove_if_matches(path: &Path, expected: &str) -> Result<(), AgentError> {
    use std::os::unix::fs::MetadataExt;

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::getuid().as_raw()
        && bytes == expected.as_bytes()
    {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn remove_socket_if_matches(path: &Path, expected: (u64, u64)) {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;

    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_socket()
        && (metadata.dev(), metadata.ino()) == expected
    {
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
fn take_pid_file(path: &Path, pid: u32) -> Result<File, AgentError> {
    use rustix::fs::{Mode, OFlags, fchmod, open};

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let fd = open(
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| AgentError(error.to_string()))?;
        let mut file = File::from(fd);
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|error| AgentError(error.to_string()))?;
        match set_record_lock(&file) {
            Ok(()) => {
                file.set_len(0)?;
                file.seek(SeekFrom::Start(0))?;
                write!(file, "{pid}")?;
                file.sync_all()?;
                return Ok(file);
            }
            Err(_) => {
                if let Some(holder) = lock_holder(&file)
                    && holder > 0
                    && holder != pid as libc::pid_t
                {
                    let _ = signal_holder(&file, holder);
                }
                if Instant::now() >= deadline {
                    return Err(AgentError("Cannot start kv daemon: another kv service for this vault holds its pid file; run 'kv lock' first, or 'kv agent status' for details.".into()));
                }
                drop(file);
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

#[cfg(unix)]
fn set_record_lock(file: &File) -> Result<(), AgentError> {
    rustix::fs::fcntl_lock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|error| AgentError(error.to_string()))
}

#[cfg(unix)]
fn lock_holder(file: &File) -> Option<libc::pid_t> {
    let requested = rustix::process::Flock::from(rustix::process::FlockType::WriteLock);
    let blocking = rustix::process::fcntl_getlk(file, &requested).ok()??;
    let pid = rustix::process::Pid::as_raw(blocking.pid) as libc::pid_t;
    (pid > 0).then_some(pid)
}

#[cfg(unix)]
fn signal_holder(file: &File, holder: libc::pid_t) -> bool {
    if lock_holder(file) != Some(holder) {
        return false;
    }
    let Some(pid) = rustix::process::Pid::from_raw(holder) else {
        return false;
    };
    if let Err(error) = rustix::process::kill_process(pid, rustix::process::Signal::TERM)
        && error.kind() != std::io::ErrorKind::PermissionDenied
    {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if lock_holder(file) != Some(holder) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_has_python_memory_status_shape() {
        let status = protect_process_memory();
        assert!(status.get("enabled").is_some());
        assert!(status.get("supported").is_some());
        assert!(status.get("verified").is_some());
        assert!(status.get("method").is_some());
        assert!(status.get("reason").is_some());
    }

    #[cfg(unix)]
    #[test]
    fn silent_connection_times_out_and_closes() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let store = DrawerStore::open(".", Key32::new([0; 32]));
        let cache = Mutex::new(SecretCache::default());
        let master_key = Key32::new([0; 32]);
        let trust = TrustContext {
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
                state: std::sync::Mutex::new(PinState {
                    root: std::path::PathBuf::from("."),
                    folder_id: (0, 0),
                    folder: File::open(".").unwrap(),
                    key_id: None,
                    key_digest: None,
                    latched: None,
                    closed: false,
                }),
            }),
        };
        let approved = json!({});
        let token = Zeroizing::new(String::new());
        let stopping = AtomicBool::new(false);
        let memory_hardening = json!({});
        let timeout = Duration::from_millis(100);
        let started = Instant::now();
        let worker = thread::spawn(move || {
            handle_connection(
                &mut server,
                Path::new("."),
                "",
                &store,
                &cache,
                &master_key,
                &trust,
                &approved,
                &token,
                &stopping,
                &memory_hardening,
                timeout,
            )
        });
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(reply, br#"{"error": "TimeoutError: timed out"}"#);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
