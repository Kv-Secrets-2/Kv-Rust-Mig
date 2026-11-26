//! Broker-owned durable audit admission wiring.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use kv_audit::{
    ChainHead, ChainKey, ChainPosition, CheckpointFailure, TrustedCheckpoint, VaultIdentity,
};
use kv_crypto::{Key32, derive_labeled_key};

use super::{AgentError, TrustContext};

const CHECKPOINT_VERSION: &str = "kv-audit-checkpoint-v1";
const MAX_CHECKPOINT_BYTES: usize = 256;

struct FileCheckpoint {
    path: PathBuf,
    directory: PathBuf,
}

impl FileCheckpoint {
    fn new(path: PathBuf, directory: PathBuf) -> Self {
        Self { path, directory }
    }

    fn temporary_path(&self) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        self.directory.join(format!(
            ".admission-checkpoint-{}-{serial}.tmp",
            std::process::id()
        ))
    }
}

impl TrustedCheckpoint for FileCheckpoint {
    fn load_durable(&mut self) -> Result<ChainPosition, CheckpointFailure> {
        use rustix::fs::{Mode, OFlags, open};

        let fd = match open(
            &self.path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(ChainPosition::genesis()),
            Err(_) => return Err(CheckpointFailure::ReadFailed),
        };
        let mut file = File::from(fd);
        if !file
            .metadata()
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
        {
            return Err(CheckpointFailure::Invalid);
        }
        let mut bytes = Vec::new();
        if std::io::Read::by_ref(&mut file)
            .take(MAX_CHECKPOINT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() > MAX_CHECKPOINT_BYTES
        {
            return Err(CheckpointFailure::ReadFailed);
        }
        let text = String::from_utf8(bytes).map_err(|_| CheckpointFailure::Invalid)?;
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() != 3 || lines[0] != CHECKPOINT_VERSION {
            return Err(CheckpointFailure::Invalid);
        }
        let count = lines[1]
            .parse::<u64>()
            .map_err(|_| CheckpointFailure::Invalid)?;
        let head = ChainHead::from_hex(lines[2]).map_err(|_| CheckpointFailure::Invalid)?;
        if count == 0 && head != ChainHead::GENESIS {
            return Err(CheckpointFailure::Invalid);
        }
        Ok(ChainPosition { count, head })
    }

    fn publish_durable(&mut self, position: ChainPosition) -> Result<(), CheckpointFailure> {
        use rustix::fs::{Mode, OFlags, fchmod, open};

        let temporary = self.temporary_path();
        let fd = open(
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| CheckpointFailure::WriteFailed)?;
        let mut file = File::from(fd);
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|_| CheckpointFailure::WriteFailed)?;
        let contents = format!(
            "{CHECKPOINT_VERSION}\n{}\n{}\n",
            position.count,
            position.head.to_hex()
        );
        file.write_all(contents.as_bytes())
            .map_err(|_| CheckpointFailure::WriteFailed)?;
        file.sync_all().map_err(|_| CheckpointFailure::SyncFailed)?;
        drop(file);
        let rename_result = fs::rename(&temporary, &self.path);
        if rename_result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(CheckpointFailure::WriteFailed);
        }
        let directory = File::open(&self.directory).map_err(|_| CheckpointFailure::SyncFailed)?;
        directory
            .sync_all()
            .map_err(|_| CheckpointFailure::SyncFailed)
    }
}

pub(crate) fn admission_journal(
    root: &Path,
    master_key: &Key32,
    trust: &TrustContext,
) -> Result<kv_audit::AdmissionJournal, AgentError> {
    let runtime = kv_proto::runtime_dir()?;
    let project = kv_proto::project_hash(Some(root))?;
    let journal_directory = runtime.join(format!("admissions-{project}"));
    let checkpoint_path = runtime.join(format!("admission-checkpoint-{project}"));
    let chain_key = derive_labeled_key(master_key, b"kv-audit:chain-v1", &[&trust.location]);
    let key = ChainKey::new(*chain_key.as_bytes());
    let identity = VaultIdentity::new(&trust.location)
        .map_err(|error| AgentError(format!("audit vault identity is invalid: {error}")))?;
    let checkpoint = FileCheckpoint::new(checkpoint_path, runtime);
    Ok(kv_audit::AdmissionJournal::new(
        journal_directory,
        key,
        identity,
        checkpoint,
    ))
}
