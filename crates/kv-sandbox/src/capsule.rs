//! Private copies a secret-bearing run works from (Python `kv/sandbox.py`:
//! `_harden_capsule_dir`, `prepare_run_artifact_capsule`,
//! `_find_private_cwd_symlink_escape`, `private_cwd_requested`,
//! `checked_run_cwd`, `prepare_run_cwd_capsule`).

use std::collections::BTreeMap;
use std::io::{Read, Write};

use sha2::{Digest, Sha256};

use crate::bwrap::RunRefusal;
use crate::identity::{HASH_CHUNK_SIZE, script_file_path};
use crate::paths::{inside_secrets, inside_secrets_as_written, path_is_or_under, resolve};
use crate::scan::{Fingerprint, snapshot_files, temp_scan_dirs};

pub const RUN_CWD_IN_VAULT: &str = "working directory refused: it is inside the vault's .secrets";

/// Python `RunArtifactCapsule`: a private copy of the approved script,
/// bound read-only over the original inside the sandbox.
#[derive(Debug, Default)]
pub struct RunArtifactCapsule {
    pub capsule_dir: Option<tempfile::TempDir>,
    pub readonly_file_overlays: Vec<(String, String)>,
    pub script_sha256: Option<String>,
}

/// Python `RunCwdCapsule`: the checked working folder and, for a private
/// cwd run, its copy plus the snapshots the copy-back compares.
#[derive(Debug, Default)]
pub struct RunCwdCapsule {
    pub capsule_dir: Option<tempfile::TempDir>,
    pub original_cwd: String,
    pub private_cwd: Option<String>,
    pub private_snapshot: BTreeMap<String, Fingerprint>,
    pub original_snapshot: BTreeMap<String, Fingerprint>,
}

impl RunCwdCapsule {
    /// The folder the child runs in (Python `effective_cwd`).
    pub fn effective_cwd(&self) -> &str {
        self.private_cwd.as_deref().unwrap_or(&self.original_cwd)
    }
}

/// Python `_harden_capsule_dir`: open the folder itself (no link), check it
/// is a folder this user owns, make it private.
#[cfg(unix)]
pub fn harden_capsule_dir(path: &str) -> Result<(), RunRefusal> {
    use rustix::fs::{Mode, OFlags, fchmod, fstat, open};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| {
        RunRefusal::fixed(
            "blocked for security: the run's private folder could not be opened as a folder \
                 kv made",
        )
    })?;
    let st = fstat(&fd).map_err(|_| {
        RunRefusal::fixed("blocked for security: the run's private folder is not a folder kv made")
    })?;
    let is_dir = rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory;
    if !is_dir || st.st_uid != rustix::process::getuid().as_raw() {
        return Err(RunRefusal::fixed(
            "blocked for security: the run's private folder is not a folder kv made",
        ));
    }
    fchmod(&fd, Mode::RWXU).map_err(|_| {
        RunRefusal::fixed("blocked for security: the run's private folder is not a folder kv made")
    })
}

#[cfg(not(unix))]
pub fn harden_capsule_dir(_path: &str) -> Result<(), RunRefusal> {
    Err(RunRefusal::fixed(
        "blocked for security: the run's private folder is not a folder kv made",
    ))
}

/// Python `prepare_run_artifact_capsule`.
pub fn prepare_run_artifact_capsule(
    argv: &[String],
    cwd: &str,
    expected_sha256: Option<&str>,
    secrets_injected: bool,
    watched: &[String],
) -> Result<RunArtifactCapsule, RunRefusal> {
    if !secrets_injected {
        return Ok(RunArtifactCapsule::default());
    }
    let Some(script_path) = script_file_path(argv, cwd, watched) else {
        return Ok(RunArtifactCapsule::default());
    };
    fn failed<E>(_: E) -> RunRefusal {
        RunRefusal::fixed("blocked for security: private run artifact failed")
    }
    let capsule = tempfile::Builder::new()
        .prefix("kv-run-capsule-")
        .tempdir()
        .map_err(failed)?;
    let capsule_dir = capsule
        .path()
        .to_str()
        .ok_or_else(|| failed(()))?
        .to_owned();
    harden_capsule_dir(&capsule_dir)?;
    let dest_name = script_path
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or("script");
    let capsule_script = format!("{capsule_dir}/{dest_name}");
    let mut src = std::fs::File::open(&script_path).map_err(failed)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut dst = options.open(&capsule_script).map_err(failed)?;
    #[cfg(unix)]
    rustix::fs::fchmod(&dst, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).map_err(failed)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK_SIZE];
    loop {
        let read = src.read(&mut buffer).map_err(failed)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        dst.write_all(&buffer[..read]).map_err(failed)?;
    }
    dst.flush().map_err(failed)?;
    drop(dst);
    let copied = hex::encode(digest.finalize());
    if expected_sha256.is_some_and(|expected| !expected.is_empty() && expected != copied) {
        return Err(RunRefusal::fixed(
            "blocked for security: script changed after approval. Ask the user to review and \
             approve the updated script.",
        ));
    }
    Ok(RunArtifactCapsule {
        capsule_dir: Some(capsule),
        readonly_file_overlays: vec![(capsule_script, script_path)],
        script_sha256: Some(copied),
    })
}

/// Python `_find_private_cwd_symlink_escape`: the first link under `root`
/// (skipping `.secrets`) that leads outside it, or cannot be resolved.
pub fn find_private_cwd_symlink_escape(root: &str) -> Option<(String, String)> {
    let root_real = resolve(root).ok()?;
    fn walk(dirpath: &str, root_real: &str) -> Option<(String, String)> {
        let entries = std::fs::read_dir(dirpath).ok()?;
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name == ".secrets" {
                continue;
            }
            let path = format!("{}/{name}", dirpath.trim_end_matches('/'));
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return Some(match resolve(&path) {
                    Err(_) => (path, "(could not be resolved)".to_owned()),
                    Ok(target) if !path_is_or_under(&target, root_real, false) => (path, target),
                    Ok(_) => continue,
                });
            } else if meta.is_dir()
                && let Some(found) = walk(&path, root_real)
            {
                return Some(found);
            }
        }
        None
    }
    walk(&root_real, &root_real)
}

/// Python `private_cwd_requested`.
pub fn private_cwd_requested(value: Option<bool>, environ_value: Option<&str>) -> bool {
    match value {
        Some(flag) => flag,
        None => matches!(
            environ_value.map(|v| v.trim().to_lowercase()).as_deref(),
            Some("1" | "true" | "yes" | "on")
        ),
    }
}

/// Python `checked_run_cwd`: `(folder, None)` or `(None, why)`.
pub fn checked_run_cwd(cwd: &str, watched: &[String]) -> Result<String, &'static str> {
    if inside_secrets(cwd, watched) {
        return Err(RUN_CWD_IN_VAULT);
    }
    let resolved = resolve(cwd).map_err(|_| RUN_CWD_IN_VAULT)?;
    if inside_secrets_as_written(&resolved, watched) {
        return Err(RUN_CWD_IN_VAULT);
    }
    Ok(resolved)
}

/// `shutil.copytree(src, dst, symlinks=True, ignore=.secrets)`.
fn copy_tree(src: &str, dst: &str) -> std::io::Result<()> {
    std::fs::create_dir(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".secrets" {
            continue;
        }
        let from = entry.path();
        let to = std::path::Path::new(dst).join(&name);
        let meta = std::fs::symlink_metadata(&from)?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&from)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &to)?;
            #[cfg(not(unix))]
            let _ = target;
        } else if meta.is_dir() {
            copy_tree(
                from.to_str().unwrap_or_default(),
                to.to_str().unwrap_or_default(),
            )?;
        } else if meta.is_file() {
            std::fs::copy(&from, &to)?;
        } else {
            return Err(std::io::Error::other(format!(
                "`{}` is a special file (named pipe, socket or device)",
                from.display()
            )));
        }
    }
    Ok(())
}

/// Python `prepare_run_cwd_capsule`.
pub fn prepare_run_cwd_capsule(
    cwd: &str,
    secrets_injected: bool,
    private_cwd: bool,
    watched: &[String],
) -> Result<RunCwdCapsule, RunRefusal> {
    let original_cwd = resolve(cwd).map_err(|e| RunRefusal::fixed(e.to_string()))?;
    if inside_secrets_as_written(&original_cwd, watched) {
        return Err(RunRefusal::fixed(
            "blocked for security: the working directory is inside a vault folder",
        ));
    }
    if !secrets_injected || !private_cwd {
        return Ok(RunCwdCapsule {
            original_cwd,
            ..RunCwdCapsule::default()
        });
    }
    if !std::fs::metadata(&original_cwd)
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return Err(RunRefusal {
            parts: vec![
                ("working directory not found: ".to_owned(), false),
                (original_cwd, true),
            ],
        });
    }
    if find_private_cwd_symlink_escape(&original_cwd).is_some() {
        return Err(RunRefusal::fixed(
            "blocked for security: private cwd contains symlink outside project: <link withheld> \
             -> <target withheld>",
        ));
    }
    fn failed<E>(_: E) -> RunRefusal {
        RunRefusal::fixed("blocked for security: private cwd capsule failed: <detail withheld>")
    }
    let parent = resolve(&temp_scan_dirs(&[])[0]).map_err(failed)?;
    let capsule = tempfile::Builder::new()
        .prefix("kv-run-cwd-")
        .tempdir_in(&parent)
        .map_err(failed)?;
    let capsule_dir = capsule
        .path()
        .to_str()
        .ok_or_else(|| failed(()))?
        .to_owned();
    harden_capsule_dir(&capsule_dir).map_err(failed)?;
    let private_cwd_path = format!("{capsule_dir}/cwd");
    copy_tree(&original_cwd, &private_cwd_path).map_err(failed)?;
    harden_capsule_dir(&private_cwd_path).map_err(failed)?;
    Ok(RunCwdCapsule {
        capsule_dir: Some(capsule),
        private_snapshot: snapshot_files(std::slice::from_ref(&private_cwd_path)),
        original_snapshot: snapshot_files(std::slice::from_ref(&original_cwd)),
        original_cwd,
        private_cwd: Some(private_cwd_path),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwd_checks() {
        assert_eq!(
            checked_run_cwd("/tmp/x/.secrets/y", &[]),
            Err(RUN_CWD_IN_VAULT)
        );
        assert_eq!(
            checked_run_cwd("/definitely/missing/dir", &[]),
            Err(RUN_CWD_IN_VAULT).or(Ok("/definitely/missing/dir".to_owned()))
        );
        assert!(private_cwd_requested(None, Some(" Yes ")));
        assert!(!private_cwd_requested(Some(false), Some("1")));
    }

    #[test]
    fn private_cwd_copy_and_escape() {
        let tmp = tempfile::Builder::new()
            .prefix("kvcap")
            .tempdir_in("/tmp")
            .unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(proj.join("sub")).unwrap();
        std::fs::create_dir_all(proj.join(".secrets")).unwrap();
        std::fs::write(proj.join("a.txt"), "a").unwrap();
        std::fs::write(proj.join(".secrets/k"), "k").unwrap();
        let cwd = proj.to_str().unwrap();
        let capsule = prepare_run_cwd_capsule(cwd, true, true, &[]).unwrap();
        let private = capsule.private_cwd.clone().unwrap();
        assert!(std::path::Path::new(&private).join("a.txt").is_file());
        assert!(!std::path::Path::new(&private).join(".secrets").exists());
        assert_eq!(capsule.private_snapshot.len(), 1);
        std::os::unix::fs::symlink("/etc", proj.join("sub/out")).unwrap();
        let err = prepare_run_cwd_capsule(cwd, true, true, &[]).unwrap_err();
        assert!(err.message().contains("symlink outside project"));
        assert!(
            prepare_run_cwd_capsule(cwd, false, true, &[])
                .unwrap()
                .private_cwd
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_cwd_refuses_named_pipes() {
        let tmp = tempfile::Builder::new()
            .prefix("kvcap")
            .tempdir_in("/tmp")
            .unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("a.txt"), "a").unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(proj.join("pipe"))
            .status()
            .unwrap();
        assert!(status.success());
        let cwd = proj.to_str().unwrap();
        let err = prepare_run_cwd_capsule(cwd, true, true, &[]).unwrap_err();
        assert!(err.message().contains("private cwd capsule failed"));
    }

    #[test]
    fn artifact_capsule_copies_and_checks_hash() {
        let tmp = tempfile::Builder::new()
            .prefix("kvart")
            .tempdir_in("/tmp")
            .unwrap();
        let script = tmp.path().join("run.py");
        std::fs::write(&script, "print(1)\n").unwrap();
        let argv = vec!["python3".to_owned(), "run.py".to_owned()];
        let cwd = tmp.path().to_str().unwrap();
        let capsule = prepare_run_artifact_capsule(&argv, cwd, None, true, &[]).unwrap();
        let sha = capsule.script_sha256.clone().unwrap();
        assert_eq!(capsule.readonly_file_overlays.len(), 1);
        assert!(prepare_run_artifact_capsule(&argv, cwd, Some(&sha), true, &[]).is_ok());
        let err = prepare_run_artifact_capsule(&argv, cwd, Some("00"), true, &[]).unwrap_err();
        assert!(
            err.message()
                .starts_with("blocked for security: script changed after approval")
        );
        assert!(
            prepare_run_artifact_capsule(&argv, cwd, None, false, &[])
                .unwrap()
                .capsule_dir
                .is_none()
        );
    }
}
