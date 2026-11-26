#[cfg(unix)]
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use base64::Engine as _;
#[cfg(unix)]
use base64::engine::general_purpose::URL_SAFE;
use kv_approvals::owner::{OwnerSeed, owner_key_id, owner_public_key};
#[cfg(unix)]
use kv_approvals::permit_session::SessionPermits;
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
mod admission;
#[cfg(all(unix, test))]
mod audit_reply_tests;
#[cfg(unix)]
mod capapi;
#[cfg(unix)]
mod capture;
#[cfg(unix)]
mod lifecycle;
#[cfg(unix)]
mod permits;
#[cfg(unix)]
mod requests;
#[cfg(unix)]
mod run;
#[cfg(unix)]
mod runs;
#[cfg(unix)]
mod tracked;
#[cfg(unix)]
mod withhold;
#[cfg(unix)]
use lifecycle::{
    CommitError, ConnectionGuard, LONG_WAIT_SECONDS, Lifecycle, Phase, StopChoice, StopPlan,
    WorkerTracker,
};

#[cfg(unix)]
pub const START_REFUSAL_PREFIX: &str = "Cannot start kv daemon:";
#[cfg(unix)]
const AGENT_VERSION: &str = "0.4.0";
#[cfg(unix)]
const API_TIMEOUT: u64 = 120;

#[cfg(unix)]
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(API_TIMEOUT + 10);

#[cfg(unix)]
struct StopSignalGuard {
    registrations: Vec<signal_hook::SigId>,
    requested: Arc<AtomicBool>,
}

#[cfg(unix)]
impl StopSignalGuard {
    fn install() -> Result<Self, AgentError> {
        let mut guard = Self {
            registrations: Vec::new(),
            requested: Arc::new(AtomicBool::new(false)),
        };
        for signal in [
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGHUP,
        ] {
            guard.registrations.push(
                signal_hook::flag::register(signal, Arc::clone(&guard.requested))
                    .map_err(|error| AgentError(error.to_string()))?,
            );
        }
        Ok(guard)
    }

    fn requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

#[cfg(unix)]
impl Drop for StopSignalGuard {
    fn drop(&mut self) {
        for id in self.registrations.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

#[cfg(unix)]
#[derive(Default)]
struct SecretCache {
    environments: BTreeMap<String, BTreeMap<String, Zeroizing<String>>>,
    markers: BTreeMap<String, Option<[u8; 32]>>,
}

#[cfg(unix)]
impl SecretCache {
    /// `_SecretCache.get_env_secrets`: the cached environment, read again whenever its
    /// storage marker differs from the one recorded with the values (another `kv set`,
    /// `kv rm`, history or env command, from either implementation).
    fn environment(
        &mut self,
        store: &DrawerStore,
        env: &str,
    ) -> Result<&BTreeMap<String, Zeroizing<String>>, AgentError> {
        let current = store.env_storage_marker(env);
        // No marker (no index, or one that cannot be read) is never fresh: read again so
        // an index that appears corrupt reports its error instead of a cached empty list.
        let fresh = current.is_some()
            && self.environments.contains_key(env)
            && self.markers.get(env).is_some_and(|seen| *seen == current);
        if !fresh {
            self.environments.remove(env);
            self.markers.remove(env);
            let (secrets, marker) = read_bound(store, env)?;
            self.environments.insert(env.to_owned(), secrets);
            self.markers.insert(env.to_owned(), marker);
        }
        Ok(&self.environments[env])
    }

    fn names(&mut self, store: &DrawerStore, env: &str) -> Result<Vec<String>, AgentError> {
        Ok(self.environment(store, env)?.keys().cloned().collect())
    }

    /// Python `get_env_secrets`: every secret of one environment.
    fn env_secrets(
        &mut self,
        store: &DrawerStore,
        env: &str,
    ) -> Result<BTreeMap<String, Zeroizing<String>>, AgentError> {
        if !self.environments.contains_key(env) {
            let secrets = store
                .list_secrets(env)?
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            self.environments.insert(env.to_owned(), secrets);
        }
        Ok(self.environments[env].clone())
    }

    /// Python `redaction_secrets`: every cached value, for error text.
    fn redaction_values(&self) -> Vec<String> {
        self.environments
            .values()
            .flat_map(|items| items.values().map(|v| v.to_string()))
            .collect()
    }

    fn counts(&self) -> (usize, usize) {
        (
            self.environments.len(),
            self.environments.values().map(BTreeMap::len).sum(),
        )
    }

    fn get(
        &mut self,
        store: &DrawerStore,
        env: &str,
        name: &str,
    ) -> Result<Option<Zeroizing<String>>, AgentError> {
        Ok(self.environment(store, env)?.get(name).cloned())
    }
}

/// `_SecretCache._read_bound`: the values with the marker of the version read; the
/// marker before and after the read must agree, else it is read again.
#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn read_bound(
    store: &DrawerStore,
    env: &str,
) -> Result<(BTreeMap<String, Zeroizing<String>>, Option<[u8; 32]>), AgentError> {
    for _ in 0..3 {
        let before = store.env_storage_marker(env);
        let secrets = store
            .list_secrets(env)?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        if store.env_storage_marker(env) == before {
            return Ok((secrets, before));
        }
    }
    Err(AgentError(
        "the environment's storage changed while kv read it".into(),
    ))
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
    pub owner_public_key: Option<[u8; 32]>,
    pub owner_key_id: String,
    pub local_approval_id: Vec<u8>,
    pub location: Vec<u8>,
    pub version: String,
    /// The pinned approval signing key (`.secrets/approval_signing_key`),
    /// which seals approval artifacts and capability tokens.
    pub approval_signing_key: Option<Zeroizing<[u8; 32]>>,
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
    folder: Option<File>,
    key_id: Option<(u64, u64)>,
    key_digest: Option<[u8; 32]>,
    approval_key_id: Option<(u64, u64)>,
    approval_key_digest: Option<[u8; 32]>,
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
        let mut owner_public = None;
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
                owner_public = Some(public);
                local_approval_id = identity.local_approval_id.to_vec();
                if !identity.location.is_empty() {
                    location = identity.location.clone();
                }
                true
            }
            None => false,
        };
        #[cfg(unix)]
        let (approval_key_pin, approval_signing_key) =
            pin_approval_signing_key(&root_path, &folder)?;
        #[cfg(not(unix))]
        let approval_signing_key = None;
        let mut nonce = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut nonce[..])
            .map_err(|_| AgentError("operating-system randomness unavailable".into()))?;
        let output = Self {
            session_nonce: nonce,
            daemon_auth_key: derive_labeled_key(master_key, b"kv-approval:daemon-auth", &[]),
            grant_state_key: derive_labeled_key(master_key, b"kv-approval:grant-state", &[]),
            token_key: derive_labeled_key(master_key, b"kv-approval:token", &[]),
            protected,
            owner_public_key: owner_public,
            owner_key_id: owner_id,
            local_approval_id,
            location,
            version: "0.4.0".to_owned(),
            approval_signing_key,
            #[cfg(unix)]
            pin: Arc::new(TrustPin {
                state: std::sync::Mutex::new(PinState {
                    root: root_path,
                    folder_id: (folder_metadata.dev(), folder_metadata.ino()),
                    folder: Some(folder),
                    key_id: Some(key_id),
                    key_digest: Some(key_digest),
                    approval_key_id: approval_key_pin.0,
                    approval_key_digest: approval_key_pin.1,
                    latched: None,
                    closed: false,
                }),
            }),
        };
        Ok(output)
    }

    #[cfg(unix)]
    pub fn observe(&self) -> Result<(), AgentError> {
        self.observe_held().map(drop)
    }

    /// Keep the checked pin locked through permit debit and publication of the
    /// committed work window. The lifecycle gate drops this guard before HTTP.
    #[cfg(unix)]
    fn observe_held(&self) -> Result<std::sync::MutexGuard<'_, PinState>, AgentError> {
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
                Err(_) => return Err(Self::latch_locked(&mut state, "the vault folder is gone")),
            };
            if metadata.file_type().is_symlink() {
                Some("the vault path now contains a link".to_owned())
            } else if (metadata.dev(), metadata.ino()) != state.folder_id {
                Some("the vault folder was replaced or moved".to_owned())
            } else {
                match state.folder.as_ref() {
                    Some(folder) => match folder.metadata() {
                        Err(error) => {
                            return Err(Self::latch_locked(
                                &mut state,
                                &format!(
                                    "the vault could not be checked ({})",
                                    python_io_exception_name(&error)
                                ),
                            ));
                        }
                        Ok(metadata) if metadata.nlink() == 0 => {
                            Some("the vault folder was deleted".to_owned())
                        }
                        Ok(_) => {
                            let key_path = state.root.join(".secrets").join("key");
                            match (fs::symlink_metadata(&key_path), fs::read(&key_path)) {
                                (Err(error), _) if error.kind() == std::io::ErrorKind::NotFound => {
                                    Some("the key file is gone".to_owned())
                                }
                                (Err(_), _) => Some("the key file cannot be read".to_owned()),
                                (Ok(metadata), Ok(blob)) => {
                                    if Some((metadata.dev(), metadata.ino())) != state.key_id {
                                        Some("the key file was replaced".to_owned())
                                    } else if Some(Sha256::digest(&blob).into()) != state.key_digest
                                    {
                                        Some("the key file changed".to_owned())
                                    } else {
                                        approval_key_difference(&state, folder).map(str::to_owned)
                                    }
                                }
                                (Ok(_), Err(_)) => Some("the key file cannot be read".to_owned()),
                            }
                        }
                    },
                    None => Some("the vault folder pin is closed".to_owned()),
                }
            }
        };
        if let Some(reason) = reason {
            return Err(Self::latch_locked(&mut state, &reason));
        }
        Ok(state)
    }

    #[cfg(unix)]
    fn latch_locked(state: &mut PinState, reason: &str) -> AgentError {
        let message = state.latched.get_or_insert_with(|| {
            format!(
                "vault changed under the running daemon ({reason}); kv refuses all requests. Stop the daemon and unlock again."
            )
        });
        AgentError(message.clone())
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
            state.folder.take();
        }
    }
}

#[cfg(unix)]
const APPROVAL_KEY_RELATIVE: &str = ".secrets/approval_signing_key";
#[cfg(unix)]
const APPROVAL_KEY_READ_LIMIT: u64 = 1024 * 1024;
#[cfg(unix)]
type ApprovalKeyFileId = (u64, u64);
#[cfg(unix)]
type ApprovalKeyPin = (Option<ApprovalKeyFileId>, Option<[u8; 32]>);
#[cfg(unix)]
type ApprovalKeyFile = (Zeroizing<Vec<u8>>, ApprovalKeyFileId);

#[cfg(unix)]
fn file_id_component<T: TryInto<u64>>(value: T) -> Option<u64> {
    value.try_into().ok()
}

#[cfg(unix)]
enum ApprovalKeyReadError {
    Io(std::io::Error),
    NotRegular,
    TooLarge,
}

#[cfg(unix)]
enum EnsureApprovalKeyError {
    Structural(AgentError),
    Ignorable,
}

#[cfg(unix)]
impl From<std::io::Error> for ApprovalKeyReadError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// The pinned approval signing key file and, when it parsed, the key itself.
#[cfg(unix)]
type PinnedApprovalKey = (ApprovalKeyPin, Option<Zeroizing<[u8; 32]>>);

#[cfg(unix)]
fn pin_approval_signing_key(root: &Path, folder: &File) -> Result<PinnedApprovalKey, AgentError> {
    match ensure_approval_signing_key(root, folder) {
        Ok(()) | Err(EnsureApprovalKeyError::Ignorable) => {}
        Err(EnsureApprovalKeyError::Structural(error)) => return Err(error),
    }
    match read_approval_signing_key(folder) {
        Ok(Some((blob, file_id))) => {
            let key = kv_approvals::artifacts::parse_signing_key(&blob).ok();
            Ok(((Some(file_id), Some(Sha256::digest(&blob).into())), key))
        }
        Ok(None) | Err(ApprovalKeyReadError::TooLarge) => Ok(((None, None), None)),
        Err(ApprovalKeyReadError::NotRegular) => Err(AgentError(
            "the approval signing key must be a regular file".into(),
        )),
        Err(ApprovalKeyReadError::Io(error)) => Err(AgentError(error.to_string())),
    }
}

#[cfg(unix)]
fn ensure_approval_signing_key(root: &Path, folder: &File) -> Result<(), EnsureApprovalKeyError> {
    use rustix::fs::{AtFlags, Mode, OFlags, fchmod, fsync, openat, statat};
    use std::os::fd::AsFd;

    let secrets_path = root.join(".secrets");
    let secrets_metadata = match fs::symlink_metadata(&secrets_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&secrets_path).map_err(|_| EnsureApprovalKeyError::Ignorable)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&secrets_path, fs::Permissions::from_mode(0o700))
                    .map_err(|_| EnsureApprovalKeyError::Ignorable)?;
            }
            fs::symlink_metadata(&secrets_path).map_err(|_| EnsureApprovalKeyError::Ignorable)?
        }
        Err(_) => return Err(EnsureApprovalKeyError::Ignorable),
    };
    if !secrets_metadata.is_dir() {
        return Err(EnsureApprovalKeyError::Structural(AgentError(
            "the .secrets path must be a real directory".into(),
        )));
    }
    match statat(folder, APPROVAL_KEY_RELATIVE, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => return Ok(()),
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(_) => return Err(EnsureApprovalKeyError::Ignorable),
    }
    let _ = kv_store::config::update_vault_ignores(
        &secrets_path,
        &["approval_signing_key"],
        false,
        Some("# Local-only kv runtime records"),
    );

    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(&mut key[..]).map_err(|_| EnsureApprovalKeyError::Ignorable)?;
    let encoded = Zeroizing::new(format!("{}\n", URL_SAFE.encode(&key[..])));
    let fd = match openat(
        folder,
        APPROVAL_KEY_RELATIVE,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::EXIST => return Ok(()),
        Err(_) => return Err(EnsureApprovalKeyError::Ignorable),
    };
    let mut file = File::from(fd);
    if fchmod(&file, Mode::RUSR | Mode::WUSR).is_err()
        || file.write_all(encoded.as_bytes()).is_err()
        || file.sync_all().is_err()
    {
        return Err(EnsureApprovalKeyError::Ignorable);
    }
    let secrets_dir = openat(
        folder,
        ".secrets",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| EnsureApprovalKeyError::Ignorable)?;
    fsync(secrets_dir.as_fd()).map_err(|_| EnsureApprovalKeyError::Ignorable)?;
    Ok(())
}

#[cfg(unix)]
fn read_approval_signing_key(
    folder: &File,
) -> Result<Option<ApprovalKeyFile>, ApprovalKeyReadError> {
    use rustix::fs::{AtFlags, Mode, OFlags, openat, statat};
    use std::os::unix::fs::MetadataExt;

    let fd = match openat(
        folder,
        APPROVAL_KEY_RELATIVE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => {
            return Err(ApprovalKeyReadError::Io(std::io::Error::from_raw_os_error(
                error.raw_os_error(),
            )));
        }
    };
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ApprovalKeyReadError::NotRegular);
    }
    if metadata.len() > APPROVAL_KEY_READ_LIMIT {
        return Err(ApprovalKeyReadError::TooLarge);
    }
    let named =
        statat(folder, APPROVAL_KEY_RELATIVE, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
            ApprovalKeyReadError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
        })?;
    let named_file_id = (
        file_id_component(named.st_dev),
        file_id_component(named.st_ino),
    );
    if (named.st_mode & 0o170000) != 0o100000
        || named_file_id != (Some(metadata.dev()), Some(metadata.ino()))
    {
        return Err(ApprovalKeyReadError::NotRegular);
    }
    let mut blob = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(APPROVAL_KEY_READ_LIMIT + 1)
        .read_to_end(&mut blob)?;
    if blob.len() as u64 > APPROVAL_KEY_READ_LIMIT {
        return Err(ApprovalKeyReadError::TooLarge);
    }
    Ok(Some((blob, (metadata.dev(), metadata.ino()))))
}

#[cfg(unix)]
fn approval_key_difference(state: &PinState, folder: &File) -> Option<&'static str> {
    match read_approval_signing_key(folder) {
        Err(ApprovalKeyReadError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            state
                .approval_key_digest
                .map(|_| "the approval signing key is gone")
        }
        Err(_) => Some("the approval signing key cannot be read or is not a regular file"),
        Ok(None) => state
            .approval_key_digest
            .map(|_| "the approval signing key is gone"),
        Ok(Some((_, _))) if state.approval_key_digest.is_none() => {
            Some("an approval signing key appeared")
        }
        Ok(Some((_, file_id))) if Some(file_id) != state.approval_key_id => {
            Some("the approval signing key was replaced")
        }
        Ok(Some((blob, _))) if Some(Sha256::digest(&blob).into()) != state.approval_key_digest => {
            Some("the approval signing key changed")
        }
        Ok(Some(_)) => None,
    }
}

#[cfg(unix)]
fn python_io_exception_name(error: &std::io::Error) -> &'static str {
    // Python maps these io::ErrorKinds to the matching OSError subclass; other OS errors use OSError.
    match error.kind() {
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        _ => "OSError",
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
/// Serves the foreground daemon and drains committed work within the owner's
/// chosen stop budget. Unfinished workers retain their trust pins until they end.
pub fn run_agent(
    root: impl AsRef<Path>,
    store: Arc<DrawerStore>,
    master_key: Key32,
    trust: TrustContext,
) -> Result<Value, AgentError> {
    run_agent_with_api_caller(
        root,
        store,
        master_key,
        trust,
        Arc::new(kv_broker::ApiCaller::new()),
    )
}

#[cfg(unix)]
#[doc(hidden)]
pub fn run_agent_with_api_caller(
    root: impl AsRef<Path>,
    store: Arc<DrawerStore>,
    master_key: Key32,
    trust: TrustContext,
    api_caller: Arc<kv_broker::ApiCaller>,
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
    let lifecycle = Lifecycle::new();
    let shared = Arc::new(Shared::new());
    let signal_guard = StopSignalGuard::install()?;
    let trust = Arc::new(trust);
    let master_key = Arc::new(master_key);
    let approved = Arc::new(approved.value);
    #[cfg(feature = "test-provider-loopback")]
    let mut provider_table = kv_broker::build_provider_table(&approved).0;
    #[cfg(not(feature = "test-provider-loopback"))]
    let provider_table = kv_broker::build_provider_table(&approved).0;
    #[cfg(feature = "test-provider-loopback")]
    if let Some(anthropic) = provider_table.get_mut("anthropic") {
        anthropic["base_url"] = json!(v1_anthropic_base_url());
    }
    let providers = Arc::new(provider_table);
    let permits = permits::for_session(&trust, Arc::clone(&providers));
    let http_policy = Arc::new(kv_broker::load_http_policy_snapshot(&approved));
    let cache = Arc::new(Mutex::new(SecretCache::default()));
    let audit = kv_audit::Audit::new(kv_proto::runtime_dir()?);
    let admissions = admission::admission_journal(&root, &master_key, &trust)?;
    let mut workers = WorkerTracker::new();
    let mut accept_error = None;

    loop {
        if signal_guard.requested() {
            lifecycle.signal_stop();
        }
        lifecycle.expire_choice();
        workers.reap_finished();
        if matches!(lifecycle.phase(), Phase::Draining | Phase::Retired) {
            break;
        }
        match listener.accept() {
            Ok((mut connection, _)) => {
                let connection_guard = match workers.register_connection(&connection) {
                    Ok(guard) => guard,
                    Err(error) => {
                        accept_error = Some(AgentError(error.to_string()));
                        lifecycle.signal_stop();
                        break;
                    }
                };
                let worker_lifecycle = Arc::clone(&lifecycle);
                let worker_shared = Arc::clone(&shared);
                let cache = Arc::clone(&cache);
                let trust = Arc::clone(&trust);
                let master_key = Arc::clone(&master_key);
                let approved = Arc::clone(&approved);
                let store = Arc::clone(&store);
                let token = Arc::clone(&token);
                let providers = Arc::clone(&providers);
                let permits = Arc::clone(&permits);
                let http_policy = Arc::clone(&http_policy);
                let api_caller = Arc::clone(&api_caller);
                let audit = audit.clone();
                let admissions = admissions.clone();
                let root = root.clone();
                let root_text = root_text.clone();
                let memory_hardening = memory_hardening.clone();
                let worker = thread::Builder::new()
                    .name("kv-request".into())
                    .spawn(move || {
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
                            &providers,
                            &permits,
                            &http_policy,
                            &api_caller,
                            &audit,
                            Some(&admissions),
                            &worker_lifecycle,
                            &worker_shared,
                            &connection_guard,
                            &memory_hardening,
                            CONNECTION_TIMEOUT,
                        );
                    });
                match worker {
                    Ok(worker) => workers.track_worker(worker),
                    Err(error) => {
                        lifecycle.signal_stop();
                        accept_error = Some(AgentError(error.to_string()));
                        break;
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                lifecycle.signal_stop();
                accept_error = Some(AgentError(error.to_string()));
                break;
            }
        }
    }
    drop(listener);
    // Clean every owned runtime name before draining, even when another cleanup
    // fails. New daemon lifetimes must not inherit this one's listener or token.
    let token_cleanup = remove_if_matches(&token_path, token.as_str());
    let pid_cleanup = remove_if_matches(&pid_path, &pid.to_string());
    remove_socket_if_matches(&socket_path, socket_id);
    let _ = pid_file.flush();
    drop(pid_file);
    workers.shutdown_idle();
    // Poll the shared deadline so a signal can shorten an owner's long wait.
    // Stop handlers wait on the same state and never start a second budget.
    let drain = loop {
        if signal_guard.requested() {
            lifecycle.signal_stop();
        }
        if let Some(outcome) =
            lifecycle.poll_drain(Duration::from_millis(20), &|| shared.runs.count_live())
        {
            break outcome;
        }
        // Live kv_run programs are work this drain waits for too: each is ended
        // inside the same deadline (Python `_retire_trust_context`).
        if lifecycle.stop_budget().is_some() {
            shared.runs.end_due_runs(&lifecycle);
        }
        workers.reap_finished();
    };
    shared.runs.end_due_runs(&lifecycle);
    if drain.cut_off != 0 {
        workers.shutdown_non_control();
    }
    lifecycle.retire();
    // Programs the stop ended whose own path did not finish before the service
    // leaves: one end record each (Python `_fallback_run_records`).
    for entry in shared.runs.fallback_records() {
        let mut fields = serde_json::Map::new();
        fields.insert("program".into(), json!(entry.program));
        fields.insert("run_id".into(), json!(entry.run_id));
        fields.insert("ended_by".into(), json!("stop"));
        fields.insert("cleanup_finished".into(), json!(false));
        let _ = audit.emit("run_ended_by_stop", fields);
    }
    // Give the stop answer and already-prepared retirement refusals a separate,
    // bounded delivery allowance. No new data-bearing reply can be committed.
    let answers_until = Instant::now() + Duration::from_secs(2);
    while !workers.is_empty() && Instant::now() < answers_until {
        workers.reap_finished();
        thread::sleep(Duration::from_millis(10));
    }
    workers.shutdown_all();
    workers.reap_finished();
    // A synchronous resolver cannot be forcibly cancelled safely. Its worker
    // remains retired, owns its keys/pin, and cannot commit another send/reply.
    // The control reply reports the actual committed count at the cutoff.
    let _ = workers.into_retired().reap_in_background();
    token_cleanup?;
    pid_cleanup?;
    if let Some(error) = accept_error {
        return Err(error);
    }
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

/// Python's `_stopping` latch: set from the first stop (or signal) on.
#[cfg(unix)]
fn stopping_latched(lifecycle: &Lifecycle) -> bool {
    !matches!(lifecycle.phase(), lifecycle::Phase::Running)
}

/// Daemon-wide state every connection shares (Python's closures over
/// `run_agent` locals): the tracked-file list for the hook.
#[cfg(unix)]
pub(crate) struct Shared {
    pub(crate) tracked: tracked::Tracked,
    pub(crate) runs: runs::Runs,
    pub(crate) ledger: kv_grants::ledger::Ledger,
    pub(crate) host: kv_sandbox::bwrap::SandboxHost,
    /// Python `trust.request_records`: the approval requests this session filed.
    pub(crate) requests: kv_requests::request_records::RequestRecords,
}

#[cfg(unix)]
impl Shared {
    pub(crate) fn new() -> Self {
        Self {
            tracked: tracked::Tracked::new(),
            runs: runs::Runs::new(),
            ledger: kv_grants::ledger::Ledger::new(),
            host: kv_sandbox::bwrap::SandboxHost::detect(),
            requests: kv_requests::request_records::RequestRecords::new(None),
        }
    }
}

#[cfg(unix)]
const V1_COUNT_TOKENS_CMD: &str = "v1_anthropic_count_tokens";
#[cfg(unix)]
const V1_COUNT_TOKENS_PATH: &str = "/v1/messages/count_tokens";
#[cfg(unix)]
const V1_COUNT_TOKENS_MODEL: &str = "claude-3-5-haiku-latest";
#[cfg(unix)]
const V1_COUNT_TOKENS_RULE: &str = "v1-anthropic-count-tokens";

/// Build the one typed v1 broker operation. Callers supply text and optional
/// approval state only; provider, method, path, headers, model and payload
/// shape are fixed here so a client cannot turn this into arbitrary HTTP.
#[cfg(unix)]
fn v1_count_tokens_call(
    request: &serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>, Value> {
    const ALLOWED: &[&str] = &[
        "cmd",
        "token",
        "audit_warning",
        "env",
        "permit_id",
        "input",
        "audit_ctx",
        "reason",
    ];
    if request.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(
            json!({"error":"unsupported field for the fixed v1 broker operation","error_code":"unsupported_operation"}),
        );
    }
    let Some(input) = request.get("input").and_then(Value::as_str) else {
        return Err(json!({"error":"input must be a string","error_code":"invalid_operation"}));
    };
    if input.is_empty() || input.len() > 16 * 1024 {
        return Err(
            json!({"error":"input must be 1..16384 bytes","error_code":"invalid_operation"}),
        );
    }
    if let Some(permit_id) = request.get("permit_id")
        && permit_id
            .as_str()
            .is_none_or(|id| id.is_empty() || id.len() > 128)
    {
        return Err(
            json!({"error":"permit_id must be a string of at most 128 bytes","error_code":"invalid_operation"}),
        );
    }
    let mut operation = serde_json::Map::new();
    operation.insert("provider".into(), json!("anthropic"));
    operation.insert("method".into(), json!("POST"));
    operation.insert("path".into(), json!(V1_COUNT_TOKENS_PATH));
    operation.insert("headers".into(), json!({}));
    operation.insert(
        "body".into(),
        json!({
            "model": V1_COUNT_TOKENS_MODEL,
            "messages": [{"role":"user", "content": input}],
        }),
    );
    for key in ["env", "permit_id", "audit_ctx", "reason"] {
        if let Some(value) = request.get(key) {
            operation.insert(key.into(), value.clone());
        }
    }
    Ok(operation)
}

#[cfg(unix)]
fn v1_anthropic_base_url() -> &'static str {
    // Production is fixed to the real Anthropic origin. The test-only feature
    // keeps the same host name but moves the fixture to a fixed high loopback
    // port; it is never enabled in release builds and has no runtime override.
    #[cfg(feature = "test-provider-loopback")]
    {
        "https://api.anthropic.com:18443"
    }
    #[cfg(not(feature = "test-provider-loopback"))]
    {
        "https://api.anthropic.com"
    }
}

#[cfg(unix)]
fn v1_count_tokens_provider() -> (kv_broker::ProviderTable, kv_broker::HttpPolicySnapshot) {
    let base_url = v1_anthropic_base_url();
    let builtin = kv_broker::snapshot_providers(&json!({}));
    let mut provider = builtin.get("anthropic").cloned().unwrap_or_else(|| {
        json!({
            "base_url":"https://api.anthropic.com",
            "secret_name":"ANTHROPIC_API_KEY",
            "auth_type":"x-api-key",
            "default_headers":{"Content-Type":"application/json","anthropic-version":"2023-06-01"}
        })
    });
    provider["base_url"] = json!(base_url);
    let mut providers = kv_broker::ProviderTable::new();
    providers.insert("anthropic".into(), provider);
    let policy = kv_broker::HttpPolicySnapshot {
        configured: true,
        legacy_providers: None,
        providers: json!({
            "anthropic": {
                "origin":base_url,
                "secret_name":"ANTHROPIC_API_KEY",
                "rules":[{
                    "id":V1_COUNT_TOKENS_RULE,
                    "methods":["POST"],
                    "path":V1_COUNT_TOKENS_PATH,
                    "approval":"per-call"
                }]
            }
        }),
    };
    (providers, policy)
}

#[cfg(unix)]
fn permit_is_denied(permits: &SessionPermits, permit_id: Option<&Value>) -> bool {
    permit_id
        .and_then(Value::as_str)
        .is_some_and(|permit_id| permits.is_denied(permit_id))
}

#[cfg(unix)]
fn permit_denied_response() -> Value {
    json!({"error":"the owner denied this permit; it is never sent","error_code":"permit_denied"})
}

#[cfg(unix)]
#[cfg(unix)]
fn zeroize_json_value(value: &mut Value) {
    use kv_crypto::Zeroize as _;
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_json_value),
        Value::Object(object) => object.values_mut().for_each(zeroize_json_value),
        _ => {}
    }
}

/// Framed transport wipes its byte buffers; this guard owns the parsed JSON
/// values those buffers became and wipes strings on every exit path.
#[cfg(unix)]
struct ZeroizedRequest(Value);

#[cfg(unix)]
impl Drop for ZeroizedRequest {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
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
    providers: &kv_broker::ProviderTable,
    permits: &SessionPermits,
    http_policy: &kv_broker::HttpPolicySnapshot,
    api_caller: &kv_broker::ApiCaller,
    audit: &kv_audit::Audit,
    admissions: Option<&kv_audit::AdmissionJournal>,
    lifecycle: &Arc<Lifecycle>,
    shared: &Shared,
    connection: &ConnectionGuard,
    memory_hardening: &Value,
    request_timeout: Duration,
) -> Result<(), AgentError> {
    let mut deadline = Instant::now() + request_timeout;
    let mut replies = Replies {
        lifecycle,
        connection,
        trust,
        cache,
        cmd: "",
        audit,
        audit_warning: false,
        wire: kv_proto::RequestWire::FramedV1,
        deadline,
    };
    let request = match kv_proto::read_broker_request_until(stream, deadline) {
        Ok(Some(request)) => {
            replies.wire = request.wire;
            ZeroizedRequest(request.value)
        }
        Ok(None) => return Ok(()),
        Err(error) => {
            let _ = replies.write(stream, &request_error_response(&error));
            return Ok(());
        }
    };
    if !connection.mark_dispatching() {
        return Ok(());
    }
    let Some(request) = request.0.as_object() else {
        replies.write(stream, &json!({"error":"request must be a JSON object"}))?;
        return Ok(());
    };
    let cmd = request.get("cmd").and_then(Value::as_str).unwrap_or("");
    if cmd == "stop" {
        // The initial deadline bounds receipt of a complete request. A valid
        // stop can then wait through the lifecycle's long drain before its
        // control outcome is written, so it needs a fresh drain-plus-reply
        // budget rather than the already elapsed request deadline.
        deadline = Instant::now() + Duration::from_secs(LONG_WAIT_SECONDS) + request_timeout;
        replies.deadline = deadline;
    }
    replies.cmd = cmd;
    replies.audit_warning = request.get("audit_warning") == Some(&Value::Bool(true));
    if cmd == "enforcement" {
        connection.mark_control();
        kv_proto::write_broker_response_until(
            stream,
            &json!({"enforcement":kv_proto::ENFORCEMENT_GENERATION}),
            replies.wire,
            deadline,
        )?;
        return Ok(());
    }
    if lifecycle.phase() != Phase::Running && cmd != "stop" {
        connection.mark_control();
        kv_proto::write_broker_response_until(
            stream,
            &json!({
                "error":"the agent is stopping; new requests are refused",
                "error_code":"agent_stopping"
            }),
            replies.wire,
            deadline,
        )?;
        return Ok(());
    }
    let broker_v1_command = cmd == V1_COUNT_TOKENS_CMD
        || cmd == "permit_requests"
        || kv_proto::OWNER_ENDPOINTS.contains(&cmd);
    if broker_v1_command && replies.wire != kv_proto::RequestWire::FramedV1 {
        replies.write(
            stream,
            &json!({
                "error":"v1 broker operations require framed KVIP IPC",
                "error_code":"unsupported_wire"
            }),
        )?;
        return Ok(());
    }
    if kv_proto::OWNER_ENDPOINTS.contains(&cmd) {
        let _ = serve_owner_endpoint(
            stream, cmd, request, trust, root, approved, master_key, providers, permits, shared,
            &replies,
        );
        return Ok(());
    }
    if cmd != "status"
        && cmd != "stop"
        && let Err(error) = trust.observe()
    {
        replies.write(
            stream,
            &json!({"error":error.to_string(),"error_code":"vault_hard_locked"}),
        )?;
        return Ok(());
    }
    if !matches!(cmd, "status" | "stop" | "lock")
        && let Err(error) = config_authority::require_current(root, approved, master_key)
    {
        replies.write(
            stream,
            &json!({
                "error":error.to_string(),
                "error_code":"config_authority_changed"
            }),
        )?;
        return Ok(());
    }
    // v1 has one typed broker operation. Legacy arbitrary HTTP, database/SSH
    // broker commands and process execution are refused at the daemon boundary
    // even if an older client or CLI still knows how to ask for them.
    if matches!(cmd, "api" | "cap_api" | "query" | "ssh" | "run") {
        replies.write(
            stream,
            &json!({
                "error":"unsupported legacy operation in v1; use the fixed built-in broker operation",
                "error_code":"unsupported_operation",
                "exit_code":1,
            }),
        )?;
        return Ok(());
    }
    // Script-facing broker capabilities are authenticated by the scoped capability token
    // itself, never by the daemon token: secret-bearing capsules hide ~/.kv.
    if cmd == "cap_api" {
        if let Err(error) = validate_http_call_request(request, true) {
            replies.write(stream, &json!({"error":error}))?;
            return Ok(());
        }
        let env = request
            .get("env")
            .and_then(Value::as_str)
            .or_else(|| approved.get("default_env").and_then(Value::as_str))
            .unwrap_or("dev");
        let registered = kv_store::config::list_environments(root).unwrap_or_default();
        if let Err(error) = kv_store::envname::validate_registered_name(env, &registered) {
            // `_daemon_env_error`: the reason without the caller's text.
            let text = error.to_string();
            let shown = if text.starts_with("ambiguous environment name") {
                "ambiguous environment name"
            } else {
                "invalid environment name"
            };
            replies.write(stream, &json!({"error":shown}))?;
            return Ok(());
        }
        let response = capapi::handle(&capapi::CapCtx {
            root,
            store,
            cache,
            trust,
            providers,
            policy: http_policy,
            caller: api_caller,
            permits,
            lifecycle,
            connection,
            shared,
            audit,
            env,
            request,
        });
        let _ = capapi::audit(audit, providers, permits, request, &response);
        replies.write(stream, &response)?;
        return Ok(());
    }
    let supplied = request.get("token").and_then(Value::as_str).unwrap_or("");
    if supplied.len() > 128 || !bool::from(supplied.as_bytes().ct_eq(token.as_bytes())) {
        replies.write(stream, &json!({"error":"authentication required"}))?;
        return Ok(());
    }
    if cmd == "api"
        && let Err(error) = validate_api_request(request)
    {
        replies.write(stream, &json!({"error":error}))?;
        return Ok(());
    }
    if cmd == "run"
        && let Err(error) = validate_run_request(request)
    {
        replies.write(stream, &json!({"error":error,"exit_code":1}))?;
        return Ok(());
    }
    if cmd.is_empty() || cmd.len() > 32 {
        replies.write(stream, &json!({"error":"cmd must be a string"}))?;
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
        "stop",
        "permit_requests",
        V1_COUNT_TOKENS_CMD,
        "lock",
        "dashboard_snapshot",
        "owner_pause_right",
        "pause_job",
        "owner_pause_history",
    ];
    if !known.contains(&cmd) {
        replies.write(stream, &json!({"error":"unknown command"}))?;
        return Ok(());
    }
    if let Some(env) = request.get("env").and_then(Value::as_str)
        && kv_store::envname::validate_env_name(env).is_err()
    {
        replies.write(stream, &json!({"error":"invalid environment name"}))?;
        return Ok(());
    }
    let response = match cmd {
        "status" => match cache.lock() {
            Ok(cache) => status_response(
                root_text,
                store,
                approved,
                trust,
                memory_hardening,
                &cache,
                providers,
                http_policy,
                shared,
            ),
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
        "lock" => {
            if let Ok(mut cache) = cache.lock() {
                cache.environments.clear();
            }
            json!({"locking":true,"ended":true})
        }
        "run" => {
            // Python: the run's work window opens at admission and closes once the
            // program has started; the hard-lock pin is observed under it.
            let work = match lifecycle.try_commit_for_with_charge(connection, || {
                trust.observe_held().map_err(permits::hard_lock_error)
            }) {
                Ok(work) => work,
                Err(CommitError::Stopping) => {
                    replies.write(
                        stream,
                        &json!({
                            "error":"the agent is stopping; new requests are refused",
                            "error_code":"agent_stopping",
                            "exit_code":1,
                        }),
                    )?;
                    return Ok(());
                }
                Err(CommitError::Charge(mut refusal)) => {
                    if refusal.is_object() {
                        refusal["exit_code"] = json!(1);
                    }
                    replies.write(stream, &refusal)?;
                    return Ok(());
                }
            };
            let env = request
                .get("env")
                .and_then(Value::as_str)
                .or_else(|| approved.get("default_env").and_then(Value::as_str))
                .unwrap_or("dev");
            let outcome = run::handle_run(run::RunCtx {
                root,
                root_text,
                store,
                cache,
                trust,
                approved,
                providers,
                audit,
                lifecycle,
                shared,
                env,
                request,
                known_commands: &known,
                work: Some(work),
            });
            if outcome.control {
                // A stop-time answer rides the control lane, as Python's does.
                connection.mark_control();
                kv_proto::write_broker_response_until(
                    stream,
                    &outcome.response,
                    replies.wire,
                    deadline,
                )?;
                return Ok(());
            }
            outcome.response
        }
        "permit_requests" => json!({
            "requests": permits.pending().iter().map(|pending| pending.to_value()).collect::<Vec<_>>(),
            "pauses": [],
        }),
        V1_COUNT_TOKENS_CMD => {
            let api_started = std::time::Instant::now();
            let env = request
                .get("env")
                .and_then(Value::as_str)
                .or_else(|| approved.get("default_env").and_then(Value::as_str))
                .unwrap_or("dev");
            match v1_count_tokens_call(request) {
                Err(error) => error,
                Ok(operation) => {
                    let (operation_providers, operation_policy) = v1_count_tokens_provider();
                    let response = api_call_response(
                        &operation,
                        env,
                        store,
                        cache,
                        &operation_providers,
                        &operation_policy,
                        api_caller,
                        trust,
                        permits,
                        shared,
                        audit,
                        admissions,
                        lifecycle,
                        connection,
                    );
                    let _ = audit_api_call(
                        audit,
                        &operation,
                        env,
                        &response,
                        api_started.elapsed().as_millis() as u64,
                        permits,
                    );
                    response
                }
            }
        }
        "api" => {
            let api_started = std::time::Instant::now();
            let env = request
                .get("env")
                .and_then(Value::as_str)
                .or_else(|| approved.get("default_env").and_then(Value::as_str))
                .unwrap_or("dev");
            let response = api_call_response(
                request,
                env,
                store,
                cache,
                providers,
                http_policy,
                api_caller,
                trust,
                permits,
                shared,
                audit,
                admissions,
                lifecycle,
                connection,
            );
            // The writer implements Python's drop/count/warn policy. An audit
            // refusal cannot undo a provider operation that already happened.
            let _ = audit_api_call(
                audit,
                request,
                env,
                &response,
                api_started.elapsed().as_millis() as u64,
                permits,
            );
            response
        }
        "stop" => {
            let choice = match request.get("choice") {
                None | Some(Value::Null) => None,
                Some(Value::String(choice)) if choice == "wait" => Some(StopChoice::Wait),
                Some(Value::String(choice)) if choice == "now" => Some(StopChoice::Now),
                _ => {
                    replies.write(stream, &json!({"error":"choice must be 'wait' or 'now'"}))?;
                    return Ok(());
                }
            };
            // Register the reply as control before retirement can close idle
            // sockets. Control answers contain no vault data or work authority.
            connection.mark_control();
            let response = match lifecycle.request_stop(choice, shared.runs.count_running()) {
                StopPlan::AwaitingChoice { in_flight } => {
                    json!({"in_flight":in_flight,"awaiting_choice":true,
                        "runs":shared.runs.running_brief()})
                }
                StopPlan::AlreadyStopping { wait_seconds } => {
                    json!({"stopping":true,"wait_seconds":wait_seconds,
                        "runs":shared.runs.running_brief()})
                }
                StopPlan::Drain { .. } => {
                    let outcome = shared.runs.drain(lifecycle);
                    json!({"stopping":true,"wait_seconds":outcome.wait_seconds,
                        "cut_off":outcome.cut_off,"ended_runs":shared.runs.ended_brief()})
                }
            };
            kv_proto::write_broker_response_until(stream, &response, replies.wire, deadline)?;
            return Ok(());
        }
        "tracked_files" => shared.tracked.tracked_files(stopping_latched(lifecycle)),
        "check_file" => match request.get("path") {
            Some(Value::String(path)) => shared.tracked.check_file(
                path,
                std::slice::from_ref(&root_text.to_owned()),
                stopping_latched(lifecycle),
            ),
            _ => json!({"error": "check_file requires a path"}),
        },
        other => json!({"error":format!("{other} is not supported by this kv service yet")}),
    };
    replies.write(stream, &response)?;
    Ok(())
}

/// Ordinary replies are committed work too. A stop and this final admission
/// share the lifecycle lock, so preparing an answer never grants permission to
/// send it after retirement. Enforcement and stop controls use a separate lane.
#[cfg(unix)]
struct Replies<'a> {
    lifecycle: &'a Arc<Lifecycle>,
    connection: &'a ConnectionGuard,
    trust: &'a TrustContext,
    cache: &'a Mutex<SecretCache>,
    cmd: &'a str,
    audit: &'a kv_audit::Audit,
    audit_warning: bool,
    wire: kv_proto::RequestWire,
    deadline: Instant,
}

#[cfg(unix)]
impl Replies<'_> {
    fn write(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        response: &Value,
    ) -> Result<(), AgentError> {
        self.write_with_hard_lock(stream, response, None)
    }

    fn write_with_hard_lock(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        response: &Value,
        signed_hard_lock: Option<&Value>,
    ) -> Result<(), AgentError> {
        if let Ok(_window) = self
            .lifecycle
            .try_commit_for_with_charge(self.connection, || {
                // A different worker may have latched the pin after this answer
                // was prepared. Check that state under the same admission gate,
                // retaining the pin until the reply's committed window is visible.
                let pin = self.trust.pin.state.lock().map_err(|_| ())?;
                if pin.latched.is_some() || pin.closed {
                    return Err(());
                }
                Ok(pin)
            })
        {
            write_audited_reply(
                stream,
                response,
                self.audit,
                self.audit_warning && signed_hard_lock.is_none(),
                self.wire,
                self.deadline,
            )?;
            return Ok(());
        }
        // As in Python, never acknowledge a hard lock while earlier committed
        // work remains. The foreground stop can close this socket sooner.
        let wait_budget = self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(135));
        if wait_budget.is_zero() || self.lifecycle.wait_for_open_work(wait_budget) != 0 {
            return Ok(());
        }
        if let Ok(mut cache) = self.cache.lock() {
            cache.environments.clear();
        }
        let replacement = if let Some(signed) = signed_hard_lock {
            signed.clone()
        } else if self.cmd == "status" {
            let mut value = response.clone();
            if let Some(object) = value.as_object_mut() {
                object.insert("hard_locked".into(), json!(true));
                for key in ["cached_secrets", "secrets", "cached_environments"] {
                    object.insert(key.into(), json!(0));
                }
            }
            value
        } else {
            let reason = self
                .trust
                .pin
                .state
                .lock()
                .ok()
                .and_then(|state| state.latched.clone())
                .unwrap_or_else(|| "vault changed under the running daemon".into());
            let mut value = json!({"error":reason,"error_code":"vault_hard_locked"});
            if self.cmd == "run" {
                value["exit_code"] = json!(1);
            }
            value
        };
        write_audited_reply(
            stream,
            &replacement,
            self.audit,
            self.audit_warning && signed_hard_lock.is_none(),
            self.wire,
            self.deadline,
        )?;
        Ok(())
    }
}

#[cfg(unix)]
fn prepare_audited_reply(
    response: &Value,
    audit: &kv_audit::Audit,
    wants_warning: bool,
) -> Result<(Value, Option<kv_audit::WarningLease>), AgentError> {
    let serialize = |value: &Value| {
        kv_store::pyjson::to_vec_python(value, false).map_err(|error| AgentError(error.to_string()))
    };
    let mut answer = response.clone();
    if serialize(&answer)?.len() > kv_proto::MAX_AGENT_RESPONSE_BYTES {
        answer = json!({"error":"response too large", "response_truncated":true,
            "max_response_bytes":kv_proto::MAX_AGENT_RESPONSE_BYTES});
        serialize(&answer)?;
    }
    // Lease only after the final bounded/hard-lock answer is chosen. Its Drop
    // returns an undelivered warning on serialization, write, or flush failure.
    let mut warning = if wants_warning && answer.is_object() {
        audit.take_warning()
    } else {
        None
    };
    if let Some(lease) = &warning {
        answer["audit_warning"] = json!(lease.as_str());
        let with_warning = serialize(&answer)?;
        if with_warning.len() > kv_proto::MAX_AGENT_RESPONSE_BYTES {
            if let Some(object) = answer.as_object_mut() {
                object.remove("audit_warning");
            }
            // Keep the original bounded response; the warning remains owed.
            drop(warning.take());
        }
    }
    Ok((answer, warning))
}

#[cfg(unix)]
fn write_audited_reply(
    stream: &mut std::os::unix::net::UnixStream,
    response: &Value,
    audit: &kv_audit::Audit,
    wants_warning: bool,
    wire: kv_proto::RequestWire,
    deadline: Instant,
) -> Result<(), AgentError> {
    let (answer, warning) = prepare_audited_reply(response, audit, wants_warning)?;
    kv_proto::write_broker_response_until(stream, &answer, wire, deadline)?;
    if let Some(warning) = warning {
        warning.delivered();
    }
    Ok(())
}

#[cfg(all(unix, test))]
fn write_legacy_audited_reply<W: Write>(
    writer: &mut W,
    response: &Value,
    audit: &kv_audit::Audit,
    wants_warning: bool,
) -> Result<(), AgentError> {
    let (answer, warning) = prepare_audited_reply(response, audit, wants_warning)?;
    let encoded = kv_store::pyjson::to_vec_python(&answer, false)
        .map_err(|error| AgentError(error.to_string()))?;
    writer.write_all(&encoded)?;
    writer.flush()?;
    if let Some(warning) = warning {
        warning.delivered();
    }
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
#[allow(clippy::too_many_arguments)]
fn serve_owner_endpoint(
    stream: &mut std::os::unix::net::UnixStream,
    cmd: &str,
    request: &serde_json::Map<String, Value>,
    trust: &TrustContext,
    root: &Path,
    approved: &Value,
    master_key: &Key32,
    providers: &kv_broker::ProviderTable,
    permits: &SessionPermits,
    _shared: &Shared,
    replies: &Replies<'_>,
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
        match config_authority::require_current(root, approved, master_key) {
            Ok(()) => {}
            Err(config_authority::AuthorityError::Refused(_)) => {
                return owner_error(trust, challenge.clone(), "config_authority_changed");
            }
            Err(config_authority::AuthorityError::Internal(_)) => {
                return Err(AgentError("owner authority check failed".into()));
            }
        }
        match cmd {
            "owner_permit_request" => {
                return permits::owner_request(trust, permits, challenge.clone(), request);
            }
            "owner_permit_register" => {
                return permits::owner_register(
                    trust,
                    permits,
                    challenge.clone(),
                    request,
                    approved,
                );
            }
            "owner_permit_deny" => {
                return permits::owner_deny(trust, permits, challenge.clone(), request);
            }
            "owner_channel" => {}
            _ => return owner_error(trust, challenge.clone(), "unsupported"),
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
        let provider_fields = if request.get("providers").and_then(Value::as_bool) == Some(true) {
            owner_providers(providers)
        } else {
            Vec::new()
        };
        fields.insert("providers".into(), FieldValue::List(provider_fields));
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
    replies.write_with_hard_lock(stream, &replacement, Some(&hard_locked))?;
    Ok(())
}

#[cfg(unix)]
fn owner_providers(providers: &kv_broker::ProviderTable) -> Vec<Vec<FieldValue>> {
    providers
        .iter()
        .filter_map(|(name, value)| {
            let canonical = kv_approvals::canonical::canonical_json(value).ok()?;
            Some(vec![
                FieldValue::Text(name.to_owned()),
                FieldValue::Text(canonical),
            ])
        })
        .collect()
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
#[allow(clippy::too_many_arguments)]
fn status_response(
    root: &str,
    _store: &DrawerStore,
    config: &Value,
    trust: &TrustContext,
    memory_hardening: &Value,
    cache: &SecretCache,
    provider_snapshot: &kv_broker::ProviderTable,
    http_policy_snapshot: &kv_broker::HttpPolicySnapshot,
    shared: &Shared,
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
    let providers = provider_snapshot
        .keys()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let http_policy = kv_broker::describe_http_policy_snapshot(http_policy_snapshot);
    let (cached_environments, cached_secrets) = cache.counts();
    json!({
        "running":true,
        "session_nonce":hex(&trust.session_nonce[..]),
        "runs_used":shared.ledger.run_counts(),
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
        // The live kv_run programs, so a stop can say what it ends.
        "runs":shared.runs.running_brief()
    })
}

#[cfg(unix)]
/// Python `_validate_request` for `run`: `_validate_argv`, `_validate_str_list`
/// and `_validate_str` with the reference's limits and wording.
fn validate_run_request(request: &serde_json::Map<String, Value>) -> Result<(), String> {
    const MAX_ARGV_COUNT: usize = 50;
    const MAX_ARGV_LEN: usize = 4096;
    const MAX_ENV_NAMES_COUNT: usize = 1000;
    const MAX_SECRET_NAME_LEN: usize = 256;
    const MAX_CAPABILITY_NAMES_COUNT: usize = 16;
    const MAX_CAPABILITY_NAME_LEN: usize = 256;
    const MAX_CWD_LEN: usize = 4096;

    fn check_str(
        value: Option<&Value>,
        field: &str,
        max_len: usize,
        required: bool,
        allow_empty: bool,
    ) -> Result<(), String> {
        let value = match value {
            None | Some(Value::Null) => {
                return if required {
                    Err(format!("{field} is required"))
                } else {
                    Ok(())
                };
            }
            Some(value) => value,
        };
        let Some(text) = value.as_str() else {
            return Err(format!("{field} must be a string"));
        };
        if !allow_empty && text.is_empty() {
            return Err(format!("{field} must not be empty"));
        }
        if text.len() > max_len {
            return Err(format!("{field} exceeds {max_len} bytes"));
        }
        Ok(())
    }

    fn check_str_list(
        value: Option<&Value>,
        field: &str,
        max_items: usize,
        max_item_len: usize,
    ) -> Result<(), String> {
        let items = match value {
            None | Some(Value::Null) => return Ok(()),
            Some(Value::Array(items)) => items,
            Some(_) => return Err(format!("{field} must be a list")),
        };
        if items.len() > max_items {
            return Err(format!("{field} has too many items (max {max_items})"));
        }
        for (i, item) in items.iter().enumerate() {
            check_str(
                Some(item),
                &format!("{field}[{i}]"),
                max_item_len,
                true,
                false,
            )?;
        }
        Ok(())
    }

    let argv = match request.get("argv") {
        None | Some(Value::Null) => return Err("argv is required".into()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err("argv must be a list".into()),
    };
    if argv.is_empty() {
        return Err("argv must not be empty".into());
    }
    if argv.len() > MAX_ARGV_COUNT {
        return Err(format!("argv has too many items (max {MAX_ARGV_COUNT})"));
    }
    for (i, item) in argv.iter().enumerate() {
        check_str(Some(item), &format!("argv[{i}]"), MAX_ARGV_LEN, true, i > 0)?;
    }
    check_str_list(
        request.get("env_names"),
        "env_names",
        MAX_ENV_NAMES_COUNT,
        MAX_SECRET_NAME_LEN,
    )?;
    check_str_list(
        request.get("capability_names"),
        "capability_names",
        MAX_CAPABILITY_NAMES_COUNT,
        MAX_CAPABILITY_NAME_LEN,
    )?;
    let raw_secrets =
        matches!(request.get("env_names"), Some(Value::Array(items)) if !items.is_empty());
    let capabilities =
        matches!(request.get("capability_names"), Some(Value::Array(items)) if !items.is_empty());
    if raw_secrets && capabilities {
        return Err("kv_run cannot mix raw secrets and capabilities".into());
    }
    check_str(request.get("cwd"), "cwd", MAX_CWD_LEN, false, false)?;
    match request.get("private_cwd") {
        None | Some(Value::Null) | Some(Value::Bool(_)) => {}
        Some(_) => return Err("private_cwd must be a boolean".into()),
    }
    Ok(())
}

fn validate_api_request(request: &serde_json::Map<String, Value>) -> Result<(), String> {
    validate_http_call_request(request, false)
}

/// `_validate_agent_request` for `api` (daemon token) and `cap_api` (capability token).
fn validate_http_call_request(
    request: &serde_json::Map<String, Value>,
    capability: bool,
) -> Result<(), String> {
    fn string_field<'a>(
        request: &'a serde_json::Map<String, Value>,
        field: &str,
        max: usize,
        required: bool,
        allow_empty: bool,
    ) -> Result<Option<&'a str>, String> {
        let Some(value) = request.get(field) else {
            return if required {
                Err(format!("{field} is required"))
            } else {
                Ok(None)
            };
        };
        if value.is_null() {
            return if required {
                Err(format!("{field} is required"))
            } else {
                Ok(None)
            };
        }
        let Some(value) = value.as_str() else {
            return Err(format!("{field} must be a string"));
        };
        if !allow_empty && value.is_empty() {
            return Err(format!("{field} must not be empty"));
        }
        if value.len() > max {
            return Err(format!("{field} exceeds {max} bytes"));
        }
        Ok(Some(value))
    }
    if request.contains_key("permit_id") {
        string_field(request, "permit_id", 128, true, false)?;
    }
    if request.contains_key("reason") {
        string_field(request, "reason", 512, false, true)?;
    }
    if capability {
        if request.contains_key("pause_id") {
            string_field(request, "pause_id", 128, true, false)?;
        }
        string_field(request, "capability_token", 256, true, false)?;
    }
    string_field(request, "provider", 128, true, false)?;
    string_field(request, "path", 4096, true, false)?;
    let method = string_field(request, "method", 16, false, false)?.unwrap_or("GET");
    if !["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
        .contains(&method.to_ascii_uppercase().as_str())
    {
        return Err("unsupported method".into());
    }
    if let Some(body) = request.get("body").filter(|body| !body.is_null()) {
        if !body.is_object() && !body.is_array() && !body.is_string() {
            return Err("body must be an object, array, or string".into());
        }
        if kv_store::pyjson::to_vec_python(body, false).map_or(0, |bytes| bytes.len()) > 512 * 1024
        {
            return Err("body exceeds 524288 bytes".into());
        }
    }
    if let Some(headers) = request.get("headers").filter(|headers| !headers.is_null()) {
        let Some(headers) = headers.as_object() else {
            return Err("headers must be an object".into());
        };
        if headers.len() > 64 {
            return Err("headers has too many entries (max 64)".into());
        }
        for (index, (name, value)) in headers.iter().enumerate() {
            if name.is_empty() {
                return Err("header name must not be empty".into());
            }
            if name.len() > 128 {
                return Err("header name exceeds 128 bytes".into());
            }
            let Some(value) = value.as_str() else {
                return Err(format!("headers[{index}] value must be a string"));
            };
            if value.len() > 4096 {
                return Err(format!("headers[{index}] value exceeds 4096 bytes"));
            }
        }
    }
    if capability && !request.get("run_identity").is_some_and(Value::is_object) {
        return Err("run_identity must be an object".into());
    }
    Ok(())
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn api_call_response(
    request: &serde_json::Map<String, Value>,
    env: &str,
    store: &DrawerStore,
    cache: &Mutex<SecretCache>,
    providers: &kv_broker::ProviderTable,
    policy: &kv_broker::HttpPolicySnapshot,
    caller: &kv_broker::ApiCaller,
    trust: &TrustContext,
    permits: &SessionPermits,
    _shared: &Shared,
    audit: &kv_audit::Audit,
    admissions: Option<&kv_audit::AdmissionJournal>,
    lifecycle: &Arc<Lifecycle>,
    connection: &ConnectionGuard,
) -> Value {
    let provider_name = request
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("");
    if provider_name.is_empty() {
        return json!({"error":"provider is required (e.g. openai, anthropic, google)"});
    }
    let Some(provider) = providers.get(provider_name) else {
        return json!({
            "error":format!(
                "unknown provider: {provider_name}. available: {}",
                providers.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        });
    };
    if provider
        .get("provider_type")
        .and_then(Value::as_str)
        .unwrap_or("http")
        != "http"
    {
        return json!({"error":format!("provider '{provider_name}' is not an HTTP API provider")});
    }
    if let Some(error) = kv_broker::api_body_security_error(provider, request.get("body")) {
        return json!({"error":error});
    }
    let headers = request.get("headers").cloned().unwrap_or_else(|| json!({}));
    let method = request
        .get("method")
        .cloned()
        .unwrap_or_else(|| json!("GET"));
    let path = request.get("path").cloned().unwrap_or_else(|| json!("/"));
    let decision = kv_broker::evaluate_provider_http_request(
        policy,
        provider_name,
        provider,
        &method,
        &path,
        request.get("body"),
        &headers,
    );
    let per_call =
        decision.get("error_code").and_then(Value::as_str) == Some("http_approval_required");
    if !per_call
        && !decision
            .get("allowed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return strip_allowed(decision);
    }
    if request.contains_key("permit_id") && !per_call {
        return json!({
            "error":"this call does not match a one-call permit",
            "error_code":"permit_invalid"
        });
    }
    if per_call && permit_is_denied(permits, request.get("permit_id")) {
        return permit_denied_response();
    }
    if per_call && let Err(error) = permits.precheck(request.get("permit_id")) {
        return permits::precheck_error(error);
    }
    let secret_name = provider
        .get("secret_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let lookup = match cache.lock() {
        Ok(mut cache) => cache.get(store, env, secret_name),
        Err(_) => return json!({"error":"secret cache is unavailable"}),
    };
    let secret_value = match lookup {
        Ok(Some(secret)) if !secret.is_empty() => secret,
        Ok(_) => return json!({"error":format!("secret '{secret_name}' not found in env '{env}'")}),
        Err(error) => return json!({"error":error.to_string()}),
    };
    let secrets_for_redact = kv_broker::redact_one_secret(secret_name, &secret_value);
    let api_request = kv_broker::ApiRequest {
        provider_name,
        provider,
        secret_value: &secret_value,
        path: path.as_str().unwrap_or("/"),
        method: method.as_str().unwrap_or("GET"),
        body: request.get("body").filter(|body| !body.is_null()),
        extra_headers: &headers,
        secrets_for_redact: &secrets_for_redact,
        timeout: Duration::from_secs(API_TIMEOUT),
        max_response_bytes: kv_broker::MAX_BROKER_RESPONSE_BYTES,
    };
    let permit_id = if per_call {
        match permits::prepare(
            trust,
            permits,
            audit,
            request,
            env,
            caller,
            api_request.clone(),
            decision.get("policy_rule"),
            None,
        ) {
            Ok(id) => Some(id),
            Err(response) => return response,
        }
    } else {
        None
    };
    // Publish the dispatch window before bounded audit I/O so retirement cannot
    // pass it. The final pin, denial, expiry and one-call spend are rechecked in
    // the inner transport gate below.
    let operation_window = match lifecycle
        .try_commit_for_with_charge(connection, || Ok::<(), std::convert::Infallible>(()))
    {
        Ok(window) => window,
        Err(_) => {
            return json!({
                "error":"the agent is stopping; new requests are refused",
                "error_code":"agent_stopping",
            });
        }
    };
    let admission = if per_call {
        let Some(admissions) = admissions else {
            return json!({
                "error":"the privileged action could not be recorded durably; it was not sent",
                "error_code":"audit_admission_failed",
                "audit_admission_error":"missing_admission_journal",
            });
        };
        let mut metadata = serde_json::Map::new();
        metadata.insert("provider".into(), json!(provider_name));
        metadata.insert("method".into(), method.clone());
        metadata.insert("path".into(), path.clone());
        metadata.insert("env".into(), json!(env));
        if let Some(id) = permit_id {
            metadata.insert("permit_id_sha256".into(), json!(hex(&Sha256::digest(id))));
        }
        match admissions.admit("broker.http.anthropic.count_tokens", metadata) {
            Ok(admission) => Some(admission),
            Err(error) => {
                return json!({
                    "error":"the privileged action could not be recorded durably; it was not sent",
                    "error_code":"audit_admission_failed",
                    "audit_admission_error":error.as_str(),
                });
            }
        }
    } else {
        None
    };
    let empty_headers = serde_json::Map::new();
    let caller_headers = headers.as_object().unwrap_or(&empty_headers);
    let callback_refused = std::cell::Cell::new(false);
    let transport_started = std::cell::Cell::new(false);
    let perform_call = || {
        caller.call_with_checks(
            api_request,
            |preview| {
                let checked = permit_id
                    .map(|id| {
                        permits
                            .match_call(
                                id,
                                permits::call_facts(
                                    env,
                                    provider_name,
                                    provider,
                                    caller_headers,
                                    preview,
                                    None,
                                ),
                            )
                            .map_err(permits::invalid_error)
                    })
                    .transpose();
                callback_refused.set(checked.is_err());
                checked
            },
            |matched| {
                let committed = operation_window
                    .charge_committed(|| {
                        let _pin = trust.observe_held().map_err(permits::hard_lock_error)?;
                        if matched.is_some() && permit_is_denied(permits, request.get("permit_id"))
                        {
                            return Err(permit_denied_response());
                        }
                        if let Some(matched) = matched {
                            permits.spend(&matched).map_err(permits::invalid_error)?;
                        }
                        Ok(())
                    })
                    .map_err(|error| match error {
                        CommitError::Stopping => json!({
                            "error":"the agent is stopping; new requests are refused",
                            "error_code":"agent_stopping",
                        }),
                        CommitError::Charge(refusal) => refusal,
                    });
                callback_refused.set(committed.is_err());
                transport_started.set(committed.is_ok());
                committed
            },
        )
    };
    let mut result = if let Some(admission) = admission {
        let execution = admission.run(|_| perform_call());
        let output = execution.output().clone();
        let outcome = if output.get("status").is_some() {
            Some(kv_audit::TerminalOutcome::Completed)
        } else if !transport_started.get() {
            Some(kv_audit::TerminalOutcome::Failed)
        } else {
            None
        };
        let mut outcome_metadata = serde_json::Map::new();
        outcome_metadata.insert("provider".into(), json!(provider_name));
        outcome_metadata.insert("method".into(), method.clone());
        outcome_metadata.insert("path".into(), path.clone());
        outcome_metadata.insert("env".into(), json!(env));
        for key in ["status", "error_code"] {
            if let Some(value) = output.get(key) {
                outcome_metadata.insert(key.into(), value.clone());
            }
        }
        match outcome {
            Some(outcome) => match execution.finish(outcome, outcome_metadata) {
                Ok(output) => output,
                Err(error) => {
                    let outcome_error = error.error;
                    let mut output = error.into_output();
                    output["audit_outcome_error"] = json!(outcome_error.as_str());
                    output
                }
            },
            None => {
                // A transport or response-read failure can mean the provider already
                // applied the request. Leave the admitted effect unknown rather than
                // recording a definite failure.
                drop(execution);
                output
            }
        }
    } else {
        perform_call()
    };
    // Python's matching/admission exceptions bypass policy-warning attachment;
    // a transport result (including an HTTP failure) still receives the warning.
    if callback_refused.get() {
        return result;
    }
    if let Some(warning) = decision.get("warning").and_then(Value::as_str) {
        let current = result.get("warning").and_then(Value::as_str).unwrap_or("");
        result["warning"] = Value::String(if current.is_empty() {
            warning.to_owned()
        } else {
            format!("{current}\n{warning}")
        });
    }
    result
}

#[cfg(unix)]
fn strip_allowed(mut decision: Value) -> Value {
    if let Some(object) = decision.as_object_mut() {
        object.remove("allowed");
    }
    decision
}

#[cfg(unix)]
fn audit_api_call(
    audit: &kv_audit::Audit,
    request: &serde_json::Map<String, Value>,
    env: &str,
    response: &Value,
    duration_ms: u64,
    permits: &SessionPermits,
) -> Result<(), kv_audit::LossReason> {
    let mut entry = serde_json::Map::new();
    entry.insert(
        "provider".into(),
        request
            .get("provider")
            .cloned()
            .unwrap_or_else(|| json!("?")),
    );
    entry.insert(
        "path".into(),
        request.get("path").cloned().unwrap_or_else(|| json!("/")),
    );
    entry.insert(
        "method".into(),
        request
            .get("method")
            .cloned()
            .unwrap_or_else(|| json!("GET")),
    );
    entry.insert(
        "status".into(),
        response.get("status").cloned().unwrap_or(json!(0)),
    );
    entry.insert(
        "error_code".into(),
        response.get("error_code").cloned().unwrap_or(Value::Null),
    );
    entry.insert(
        "policy_rule".into(),
        response.get("policy_rule").cloned().unwrap_or(Value::Null),
    );
    entry.insert(
        "approval_required".into(),
        response
            .get("approval_required")
            .and_then(Value::as_bool)
            .map_or(Value::Bool(false), Value::Bool),
    );
    entry.insert(
        "policy_warning".into(),
        response.get("warning").cloned().unwrap_or(Value::Null),
    );
    entry.insert("duration_ms".into(), json!(duration_ms));
    entry.insert("env".into(), json!(env));
    entry.insert("error".into(), json!(response.get("error").is_some()));
    if let Some(context) = request.get("audit_ctx").and_then(Value::as_object) {
        for (key, limit) in [
            ("source", 24),
            ("client_name", 80),
            ("client_version", 40),
            ("session_id", 80),
        ] {
            if let Some(value) = context.get(key).and_then(Value::as_str) {
                let value = value.trim_matches(|character: char| {
                    character.is_whitespace() || matches!(character, '\u{001c}'..='\u{001f}')
                });
                if !value.is_empty() {
                    entry.insert(
                        key.into(),
                        Value::String(value.chars().take(limit).collect()),
                    );
                }
            }
        }
    }
    entry.extend(permits::audit_fields(permits, request, response));
    audit.emit("api_call", entry)
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
    use rustix::fs::{Mode, OFlags, open};
    use std::os::unix::fs::MetadataExt;

    // A replaced FIFO or oversized file must not hold shutdown in a pathname
    // read. Validate the opened inode before reading only the expected bytes.
    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) => return Ok(()),
        Err(error) => return Err(AgentError(error.to_string())),
    };
    let mut file = File::from(fd);
    let opened = file.metadata()?;
    if !opened.is_file() || opened.uid() != rustix::process::getuid().as_raw() {
        return Ok(());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    let named = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if named.is_file()
        && file_identity(&opened) == file_identity(&named)
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

    #[cfg(unix)]
    #[test]
    fn secret_cache_reloads_after_another_writer_changes_the_environment() {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "kv-agent-cache-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let master = || Key32::new(std::array::from_fn(|index| index as u8));
        let daemon = DrawerStore::open(&dir, master());
        let writer = DrawerStore::open(&dir, master());
        let mut cache = SecretCache::default();

        assert!(cache.names(&daemon, "dev").unwrap().is_empty());
        writer.set_secret("dev", "A", "one", 10).unwrap();
        assert_eq!(cache.names(&daemon, "dev").unwrap(), ["A"]);
        assert_eq!(
            cache.get(&daemon, "dev", "A").unwrap().unwrap().as_str(),
            "one"
        );

        writer.set_secret("dev", "A", "two", 10).unwrap();
        writer.set_secret("dev", "B", "three", 10).unwrap();
        assert_eq!(
            cache.get(&daemon, "dev", "A").unwrap().unwrap().as_str(),
            "two"
        );
        assert_eq!(cache.names(&daemon, "dev").unwrap(), ["A", "B"]);

        assert!(writer.remove_secret("dev", "A", 10).unwrap());
        assert!(cache.get(&daemon, "dev", "A").unwrap().is_none());
        assert_eq!(cache.names(&daemon, "dev").unwrap(), ["B"]);

        writer.restore_version("dev", "A", 2, 10).unwrap();
        assert_eq!(
            cache.get(&daemon, "dev", "A").unwrap().unwrap().as_str(),
            "two"
        );
        assert_eq!(cache.counts(), (1, 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn io_errors_use_python_exception_names() {
        assert_eq!(
            python_io_exception_name(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            "FileNotFoundError"
        );
        assert_eq!(
            python_io_exception_name(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            "PermissionError"
        );
        assert_eq!(
            python_io_exception_name(&std::io::Error::other("unexpected")),
            "OSError"
        );
    }

    #[cfg(unix)]
    #[test]
    fn checked_trust_pin_stays_held_until_admission_releases_it() {
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let directory =
            Directory(std::env::temp_dir().join(format!("kv-pin-{}", token_hex(16).unwrap())));
        fs::create_dir(&directory.0).unwrap();
        fs::create_dir(directory.0.join(".secrets")).unwrap();
        let key_path = directory.0.join(".secrets/key");
        let blob = b"synthetic pinned key bytes";
        fs::write(&key_path, blob).unwrap();
        let folder = File::open(&directory.0).unwrap();
        let folder_metadata = folder.metadata().unwrap();
        let key_metadata = fs::metadata(&key_path).unwrap();
        let trust = Arc::new(TrustContext {
            session_nonce: Zeroizing::new([0; 32]),
            daemon_auth_key: Key32::new([0; 32]),
            grant_state_key: Key32::new([0; 32]),
            token_key: Key32::new([0; 32]),
            protected: false,
            owner_public_key: None,
            owner_key_id: String::new(),
            local_approval_id: Vec::new(),
            location: Vec::new(),
            version: "0.4.0".into(),
            approval_signing_key: None,
            pin: Arc::new(TrustPin {
                state: Mutex::new(PinState {
                    root: directory.0.clone(),
                    folder_id: (folder_metadata.dev(), folder_metadata.ino()),
                    folder: Some(folder),
                    key_id: Some((key_metadata.dev(), key_metadata.ino())),
                    key_digest: Some(Sha256::digest(blob).into()),
                    approval_key_id: None,
                    approval_key_digest: None,
                    latched: None,
                    closed: false,
                }),
            }),
        });
        // The ordinary observer still releases the mutex before returning.
        trust.observe().unwrap();
        assert!(trust.pin.state.try_lock().is_ok());
        let checked = trust.observe_held().unwrap();
        assert!(matches!(
            trust.pin.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        fs::write(&key_path, b"synthetic changed key bytes").unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let (finished, observed) = std::sync::mpsc::channel();
        let observer_trust = Arc::clone(&trust);
        let observer = thread::spawn(move || {
            started.send(()).unwrap();
            finished.send(observer_trust.observe()).unwrap();
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            observed.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(checked.latched.is_none());
        drop(checked);
        let error = observed
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("the key file changed"));
        observer.join().unwrap();
        assert!(trust.hard_locked().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn closing_trust_context_retires_folder_descriptor() {
        let context = TrustContext {
            session_nonce: Zeroizing::new([0; 32]),
            daemon_auth_key: Key32::new([0; 32]),
            grant_state_key: Key32::new([0; 32]),
            token_key: Key32::new([0; 32]),
            protected: false,
            owner_public_key: None,
            owner_key_id: String::new(),
            local_approval_id: Vec::new(),
            location: Vec::new(),
            version: "0.4.0".into(),
            approval_signing_key: None,
            pin: Arc::new(TrustPin {
                state: std::sync::Mutex::new(PinState {
                    root: std::path::PathBuf::from("."),
                    folder_id: (0, 0),
                    folder: Some(File::open(".").unwrap()),
                    key_id: None,
                    key_digest: None,
                    approval_key_id: None,
                    approval_key_digest: None,
                    latched: None,
                    closed: false,
                }),
            }),
        };
        context.close();
        let state = context.pin.state.lock().unwrap();
        assert!(state.folder.is_none());
        drop(state);
        assert_eq!(
            context.observe().unwrap_err().to_string(),
            "vault changed under the running daemon (the vault folder pin is closed); kv refuses all requests. Stop the daemon and unlock again."
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_cleanup_preserves_replaced_links_and_never_reads_a_fifo() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join(format!("kv-cleanup-{}", token_hex(16).unwrap()));
        fs::create_dir(&directory).unwrap();
        let target = directory.join("target");
        let name = directory.join("token");
        fs::write(&target, "expected-token").unwrap();
        symlink(&target, &name).unwrap();
        remove_if_matches(&name, "expected-token").unwrap();
        assert!(
            fs::symlink_metadata(&name)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"expected-token");
        fs::remove_file(&name).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&name)
                .status()
                .unwrap()
                .success()
        );
        remove_if_matches(&name, "expected-token").unwrap();
        assert!(fs::symlink_metadata(&name).is_ok());
        fs::remove_file(&name).unwrap();
        fs::write(&name, "replacement-token").unwrap();
        remove_if_matches(&name, "expected-token").unwrap();
        assert_eq!(fs::read(&name).unwrap(), b"replacement-token");
        fs::write(&name, "expected-token").unwrap();
        remove_if_matches(&name, "expected-token").unwrap();
        assert!(!name.exists());
        fs::remove_dir_all(&directory).unwrap();
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
            owner_public_key: None,
            owner_key_id: String::new(),
            local_approval_id: Vec::new(),
            location: Vec::new(),
            version: "0.4.0".into(),
            approval_signing_key: None,
            pin: Arc::new(TrustPin {
                state: std::sync::Mutex::new(PinState {
                    root: std::path::PathBuf::from("."),
                    folder_id: (0, 0),
                    folder: Some(File::open(".").unwrap()),
                    key_id: None,
                    key_digest: None,
                    approval_key_id: None,
                    approval_key_digest: None,
                    latched: None,
                    closed: false,
                }),
            }),
        };
        let approved = json!({});
        let token = Zeroizing::new(String::new());
        let providers = Arc::new(kv_broker::build_provider_table(&approved).0);
        let permits = permits::for_session(&trust, Arc::clone(&providers));
        let http_policy = kv_broker::load_http_policy_snapshot(&approved);
        let api_caller = kv_broker::ApiCaller::new();
        let audit = kv_audit::Audit::new(".");
        let lifecycle = Lifecycle::new();
        let shared = Shared::new();
        let mut workers = WorkerTracker::new();
        let connection = workers.register_connection(&server).unwrap();
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
                &providers,
                &permits,
                &http_policy,
                &api_caller,
                &audit,
                None,
                &lifecycle,
                &shared,
                &connection,
                &memory_hardening,
                timeout,
            )
        });
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(
            reply,
            Vec::<u8>::new(),
            "the one absolute connection deadline is already spent when the request read times out"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn stop_wait_outcome_survives_the_initial_request_deadline() {
        use std::os::unix::net::UnixStream;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let store = DrawerStore::open(".", Key32::new([0; 32]));
        let cache = Mutex::new(SecretCache::default());
        let master_key = Key32::new([0; 32]);
        let trust = TrustContext {
            session_nonce: Zeroizing::new([0; 32]),
            daemon_auth_key: Key32::new([0; 32]),
            grant_state_key: Key32::new([0; 32]),
            token_key: Key32::new([0; 32]),
            protected: false,
            owner_public_key: None,
            owner_key_id: String::new(),
            local_approval_id: Vec::new(),
            location: Vec::new(),
            version: "0.4.0".into(),
            approval_signing_key: None,
            pin: Arc::new(TrustPin {
                state: std::sync::Mutex::new(PinState {
                    root: std::path::PathBuf::from("."),
                    folder_id: (0, 0),
                    folder: Some(File::open(".").unwrap()),
                    key_id: None,
                    key_digest: None,
                    approval_key_id: None,
                    approval_key_digest: None,
                    latched: None,
                    closed: false,
                }),
            }),
        };
        let approved = json!({});
        let token = Zeroizing::new(String::new());
        let providers = Arc::new(kv_broker::build_provider_table(&approved).0);
        let permits = permits::for_session(&trust, Arc::clone(&providers));
        let http_policy = kv_broker::load_http_policy_snapshot(&approved);
        let api_caller = kv_broker::ApiCaller::new();
        let audit = kv_audit::Audit::new(".");
        let lifecycle = Lifecycle::with_test_waits(
            Duration::from_millis(10),
            Duration::from_millis(150),
            Duration::from_millis(10),
        );
        let work = lifecycle.try_commit().unwrap();
        let shared = Shared::new();
        let mut workers = WorkerTracker::new();
        let connection = workers.register_connection(&server).unwrap();
        let memory_hardening = json!({});
        let timeout = Duration::from_millis(30);
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
                &providers,
                &permits,
                &http_policy,
                &api_caller,
                &audit,
                None,
                &lifecycle,
                &shared,
                &connection,
                &memory_hardening,
                timeout,
            )
        });
        let write_deadline = Instant::now() + Duration::from_secs(1);
        kv_proto::write_frame_request_until(
            &mut client,
            &json!({"cmd":"stop","choice":"wait"}),
            write_deadline,
        )
        .unwrap();
        let response = kv_proto::read_frame_response_until(
            &mut client,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(response["stopping"], true);
        assert_eq!(response["cut_off"], 1);
        worker.join().unwrap().unwrap();
        drop(work);
    }
}
