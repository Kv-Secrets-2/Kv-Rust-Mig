//! `kv backup ...`: Python `cmd_backup`, `_backup_summary_lines` and `_backup_open`.

use std::path::{Path, PathBuf};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::envcmd::history_confirm;
use crate::init::{install_recovery_key, print_recovery_key_box};
use crate::project::{self, CmdResult, Exit, audit_event, get_store, quiet_error, require_project};
use crate::terminal::{self, PromptError};
use crate::ui::{self, Palette};
use crate::{fsutil, registry};
use kv_crypto::keyfile;
use kv_store::backup::{
    BackupPayload, BackupSummary, check_restore_target, open_backup_bytes, parse_payload,
    read_backup_file, restore_backup, summary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupAction {
    None,
    Create { file: String },
    Show { file: String },
    Restore { file: String, dir: String },
}

fn plural(n: usize) -> &'static str {
    if n != 1 { "s" } else { "" }
}

fn absolute(path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        fsutil::normalize(path)
    } else {
        match std::env::current_dir() {
            Ok(cwd) => fsutil::normalize(&cwd.join(path)),
            Err(_) => path.to_path_buf(),
        }
    }
}

/// `backup.check_destination(root, path)`, done before the passphrase prompt as Python does.
fn check_destination(root: &Path, file: &str) -> Result<(), String> {
    let full = absolute(file);
    let sdir = root.join(".secrets");
    let inside = |path: &Path, dir: &Path| path == dir || path.starts_with(dir);
    let real_full = std::fs::canonicalize(&full).unwrap_or_else(|_| full.clone());
    let real_sdir = std::fs::canonicalize(&sdir).unwrap_or_else(|_| sdir.clone());
    if inside(&full, &sdir) || inside(&real_full, &real_sdir) {
        return Err("a backup file cannot go inside the vault's .secrets folder".into());
    }
    if std::fs::symlink_metadata(file).is_ok() {
        return Err(format!(
            "{file} already exists; a backup never overwrites a file"
        ));
    }
    match full.parent() {
        Some(parent) if parent.is_dir() => Ok(()),
        _ => Err(format!("the folder for {file} does not exist")),
    }
}

/// `_backup_summary_lines`: names, counts and dates of a backup; never a value.
fn summary_lines(p: &Palette, info: &BackupSummary) {
    let made = if info.created_at.is_empty() {
        "?"
    } else {
        info.created_at.as_str()
    };
    ui::info(&format!("{}Made{}       {made}", p.yellow, p.reset));
    if !info.made_from.is_empty() {
        ui::info(&format!(
            "{}From{}       {}",
            p.yellow, p.reset, info.made_from
        ));
    }
    ui::info(&format!(
        "{}Default{}    {}   {}(history keeps {} old values per secret){}",
        p.yellow, p.reset, info.default_env, p.dim, info.history_keep, p.reset
    ));
    ui::blank();
    for env in &info.environments {
        let removed = env.removed.len();
        ui::info(&format!(
            "{}{}{}  {} secret{}{}, {} old value{}{}{}{}",
            p.bold,
            env.name,
            p.reset,
            env.secrets,
            plural(env.secrets),
            if removed > 0 {
                format!(" ({removed} removed)")
            } else {
                String::new()
            },
            env.old_versions,
            plural(env.old_versions),
            p.dim,
            env.newest
                .as_deref()
                .map(|n| format!("  newest change {n}"))
                .unwrap_or_default(),
            p.reset
        ));
        for name in &env.live {
            ui::info(&format!("    {name}"));
        }
        for name in &env.removed {
            ui::info(&format!("    {name} {}(removed){}", p.dim, p.reset));
        }
    }
    ui::blank();
}

/// `_backup_open`: the passphrase of the backed-up vault, then the file.
fn backup_open(p: &Palette, file: &str) -> CmdResult<(BackupPayload, Zeroizing<String>)> {
    let passphrase = terminal::getpass(&format!(
        "  {}Passphrase{} {}(of the backed-up vault){}: ",
        p.yellow, p.reset, p.dim, p.reset
    ))
    .map(Zeroizing::new)
    .map_err(|e| match e {
        PromptError::Eof => quiet_error(p, ""),
        other => quiet_error(p, &other.to_string()),
    })?;
    let blob = read_backup_file(file).map_err(|e| quiet_error(p, &e.to_string()))?;
    let plain =
        open_backup_bytes(&blob, &passphrase).map_err(|e| quiet_error(p, &e.to_string()))?;
    let payload = parse_payload(&plain).map_err(|e| quiet_error(p, &e.to_string()))?;
    Ok((payload, passphrase))
}

fn payload_summary(payload: &BackupPayload) -> BackupSummary {
    let text = |v: &Option<Value>| v.as_ref().and_then(Value::as_str).unwrap_or("").to_owned();
    summary(
        &payload.state,
        &text(&payload.created_at),
        &text(&payload.made_from),
    )
}

fn counts(info: &BackupSummary) -> serde_json::Map<String, Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("environments".into(), Value::from(info.environments.len()));
    fields.insert("secrets".into(), Value::from(info.secrets));
    fields.insert("versions".into(), Value::from(info.versions));
    fields
}

pub fn cmd_backup(p: &Palette, action: BackupAction) -> CmdResult {
    if !terminal::stdin_is_tty() {
        ui::error(p, "kv backup needs an interactive terminal (owner only)");
        ui::info(&format!(
            "{}run it yourself from a terminal{}",
            p.dim, p.reset
        ));
        return Err(Exit(1));
    }
    match action {
        BackupAction::None => Err(quiet_error(
            p,
            "usage: kv backup create FILE | show FILE | restore FILE DIR",
        )),
        BackupAction::Create { file } => create(p, &file),
        BackupAction::Show { file } => {
            let (payload, _passphrase) = backup_open(p, &file)?;
            ui::blank();
            ui::header(p, "backup contents (no values)");
            ui::blank();
            summary_lines(p, &payload_summary(&payload));
            Ok(())
        }
        BackupAction::Restore { file, dir } => restore(p, &file, &dir),
    }
}

fn create(p: &Palette, file: &str) -> CmdResult {
    let root = require_project(p)?;
    check_destination(&root, file).map_err(|m| quiet_error(p, &m))?;
    let opened = get_store(p)?;
    let made_from = fsutil::normalize(&root);
    let info = opened
        .vault
        .make_backup(file, &opened.passphrase, &made_from.to_string_lossy())
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let stamp = registry::now_stamp();
    let problem = record_backup_made(&root, &stamp);
    audit_event("backup_made", counts(&info));
    ui::success(
        p,
        &format!("backup written and verified: {}", absolute(file).display()),
    );
    ui::info(&format!(
        "{} environments, {} secrets, {} values with history",
        info.environments.len(),
        info.secrets,
        info.versions
    ));
    ui::info(&format!(
        "{}It opens with this vault's passphrase as it is now; keep the file somewhere other than this computer.{}",
        p.dim, p.reset
    ));
    ui::info(&format!(
        "{}Older backup files are not changed: a version wiped since one was made (kv history forget) is still in it.{}",
        p.dim, p.reset
    ));
    if let Some(problem) = problem {
        ui::warn(
            p,
            &format!("the list of vaults was not updated with this backup's date ({problem})"),
        );
    }
    ui::blank();
    Ok(())
}

/// `backup.record_backup_made`: the vault's own config, then the list of vaults (SEAM S4).
fn record_backup_made(root: &Path, stamp: &str) -> Option<String> {
    let own = kv_store::config::config_transaction(root, |config| {
        let backup = match config.get("backup") {
            Some(Value::Object(map)) => map.clone(),
            _ => serde_json::Map::new(),
        };
        let mut backup = backup;
        backup.insert("last_backup_at".into(), Value::String(stamp.to_owned()));
        if let Some(map) = config.as_object_mut() {
            map.insert("backup".into(), Value::Object(backup));
        }
        Ok(())
    });
    if let Err(e) = own {
        return Some(format!("this vault's own record too: {e}"));
    }
    registry::record_backup(root, stamp).err()
}

fn restore(p: &Palette, file: &str, dir: &str) -> CmdResult {
    let target = check_restore_target(dir).map_err(|e| quiet_error(p, &e.to_string()))?;
    let (payload, passphrase) = backup_open(p, file)?;
    let info = payload_summary(&payload);
    ui::blank();
    ui::header(p, "backup contents (no values)");
    ui::blank();
    summary_lines(p, &info);
    if !history_confirm(
        p,
        &format!("Restore into a new vault at {}?", target.display()),
    )? {
        ui::info("cancelled; nothing was written");
        return Ok(());
    }
    let vault = restore_backup(payload, &passphrase, &target)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let root = vault.root().to_path_buf();
    let blob = std::fs::read(project::key_path(&root))
        .map_err(|e| quiet_error(p, &format!("restore failed: {e}")))?;
    let identity = keyfile::unwrap_v4(&blob, passphrase.as_bytes())
        .map_err(|e| quiet_error(p, &format!("restore failed: {e}")))?;
    let master = kv_crypto::Key32::new(*identity.master_key.as_bytes());
    let (token, wrap) = install_recovery_key(p, &root, &master)?;
    audit_event("backup_restored", counts(&info));
    ui::blank();
    ui::success(
        p,
        &format!("vault restored: {}", root.join(".secrets").display()),
    );
    ui::info(&format!(
        "{}It opens with the same passphrase. Approvals, grants, 2FA and policy settings are not in a backup; set them again.{}",
        p.dim, p.reset
    ));
    ui::blank();
    print_recovery_key_box(p, &token, false, &root, &wrap)?;
    ui::blank();
    Ok(())
}
