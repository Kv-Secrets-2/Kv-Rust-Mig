//! `kv history ...`: Python `cmd_history` and its helpers (owner only, drawer vaults).

use std::path::Path;

use serde_json::{Map, Value};

use crate::envcmd::{history_backups_note, history_confirm};
use crate::project::{
    self, CmdResult, audit_event, get_env, get_store, quiet_error, require_project,
};
use crate::terminal::{self, PromptError};
use crate::ui::{self, Palette};
use kv_store::VersionState;

const HISTORY_KEEP_MAX: i64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryAction {
    None,
    List {
        key: String,
        env: Option<String>,
    },
    Show {
        key: String,
        version: String,
        env: Option<String>,
    },
    Restore {
        key: String,
        version: String,
        env: Option<String>,
    },
    UndoRm {
        key: String,
        env: Option<String>,
    },
    Replace {
        secret: String,
        env: Option<String>,
    },
    Forget {
        key: Option<String>,
        all: bool,
        vault: bool,
        env: Option<String>,
    },
    Keep {
        count: Option<String>,
    },
}

fn plural(n: usize) -> &'static str {
    if n != 1 { "s" } else { "" }
}

fn prompt_failure(p: &Palette, error: PromptError) -> project::Exit {
    match error {
        PromptError::Eof => quiet_error(p, ""),
        other => quiet_error(p, &other.to_string()),
    }
}

/// `_history_version_arg`: a positive integer, else a hint and exit 1.
fn version_arg(p: &Palette, text: &str) -> CmdResult<u64> {
    let version = text.trim().parse::<i64>().unwrap_or(0);
    if version < 1 {
        return Err(quiet_error(
            p,
            "a version is a number shown by: kv history list KEY",
        ));
    }
    Ok(version as u64)
}

/// `_history_residue_note`: a key-scoped wipe cannot always tell whose crash residue a
/// record is: say so.
fn residue_note(p: &Palette, opened: &project::Opened, env: &str) -> CmdResult {
    let left = opened
        .vault
        .store
        .unreferenced_record_count(env)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    if left > 0 {
        ui::warn(
            p,
            &format!(
                "{left} record file{} in {env} {} named by no secret (left by an interrupted write); kv history forget --all -e {env} wipes {}",
                plural(left),
                if left != 1 { "are" } else { "is" },
                if left != 1 { "them" } else { "it" }
            ),
        );
    }
    Ok(())
}

fn fields(items: &[(&str, Value)]) -> Map<String, Value> {
    let mut map = Map::new();
    for (name, value) in items {
        map.insert((*name).to_owned(), value.clone());
    }
    map
}

fn forgotten(scope: &str, extra: &[(&str, Value)], versions: usize) {
    let mut items = vec![("scope", Value::String(scope.to_owned()))];
    items.extend(extra.iter().cloned());
    items.push(("versions", Value::from(versions)));
    audit_event("secret_history_forgotten", fields(&items));
}

pub fn cmd_history(p: &Palette, action: HistoryAction) -> CmdResult {
    if action == HistoryAction::None {
        return Err(quiet_error(
            p,
            "usage: kv history list|show|restore|undo-rm|replace|forget|keep ...",
        ));
    }
    let root = require_project(p)?;
    if !terminal::stdin_is_tty() {
        ui::error(p, "kv history needs an interactive terminal (owner only)");
        ui::info(&format!(
            "{}run it yourself from a terminal{}",
            p.dim, p.reset
        ));
        return Err(project::Exit(1));
    }
    let opened = get_store(p)?;

    match action {
        HistoryAction::None => Ok(()),
        HistoryAction::Keep { count } => keep(p, &root, &opened, count.as_deref()),
        HistoryAction::Forget {
            key,
            all,
            vault: true,
            ..
        } => {
            if key.is_some() || all {
                return Err(quiet_error(p, "use one of: KEY, --all, --vault"));
            }
            if !history_confirm(
                p,
                "Wipe the old values of every secret in every environment?",
            )? {
                ui::info("cancelled");
                return Ok(());
            }
            let wiped = opened
                .vault
                .forget_vault_history()
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            forgotten("vault", &[], wiped);
            ui::success(
                p,
                &format!("wiped {wiped} old value{} in this vault", plural(wiped)),
            );
            history_backups_note(p, &root);
            Ok(())
        }
        HistoryAction::Forget { key, all, env, .. } => {
            let env = get_env(p, env.as_deref())?;
            if key.is_some() == all {
                return Err(quiet_error(p, "use one of: KEY, --all, --vault"));
            }
            if let Some(key) = key {
                if !history_confirm(p, &format!("Wipe the old values of '{key}' in {env}?"))? {
                    ui::info("cancelled");
                    return Ok(());
                }
                let wiped = opened
                    .vault
                    .forget_history(&env, &key)
                    .map_err(|e| quiet_error(p, &e.to_string()))?;
                forgotten(
                    "secret",
                    &[
                        ("env", Value::String(env.clone())),
                        ("secret", Value::String(key.clone())),
                    ],
                    wiped,
                );
                ui::success(
                    p,
                    &format!(
                        "wiped {wiped} old value{} of {}{key}{}",
                        plural(wiped),
                        p.bold,
                        p.reset
                    ),
                );
                residue_note(p, &opened, &env)?;
            } else {
                if !history_confirm(p, &format!("Wipe the old values of every secret in {env}?"))? {
                    ui::info("cancelled");
                    return Ok(());
                }
                let wiped = opened
                    .vault
                    .forget_env_history(&env)
                    .map_err(|e| quiet_error(p, &e.to_string()))?;
                forgotten("env", &[("env", Value::String(env.clone()))], wiped);
                ui::success(
                    p,
                    &format!("wiped {wiped} old value{} in {env}", plural(wiped)),
                );
            }
            history_backups_note(p, &root);
            Ok(())
        }
        HistoryAction::Replace { secret, env } => {
            let env = get_env(p, env.as_deref())?;
            let (key, value) = match secret.split_once('=') {
                Some((key, value)) => (key.to_owned(), zeroize::Zeroizing::new(value.to_owned())),
                None => {
                    ui::out(&format!("\n  {}\u{250c} {env} \u{2510}{}", p.dim, p.reset));
                    let value = terminal::getpass(&format!("  {}New value{}: ", p.yellow, p.reset))
                        .map_err(|e| prompt_failure(p, e))?;
                    (secret.clone(), zeroize::Zeroizing::new(value))
                }
            };
            if key.is_empty() {
                return Err(quiet_error(p, "key cannot be empty"));
            }
            if !history_confirm(
                p,
                &format!("Replace '{key}' in {env} and wipe all its old values?"),
            )? {
                ui::info("cancelled");
                return Ok(());
            }
            let wiped = opened
                .vault
                .store
                .replace_and_forget(&env, &key, &value)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            project::audit_secret_event(&root, "secret_changed", &env, &key);
            forgotten(
                "secret",
                &[
                    ("env", Value::String(env.clone())),
                    ("secret", Value::String(key.clone())),
                ],
                wiped,
            );
            ui::success(
                p,
                &format!(
                    "{}{key}{}{} replaced {}({env}){}{}; wiped {wiped} old value{}{}",
                    p.bold,
                    p.reset,
                    p.green,
                    p.dim,
                    p.reset,
                    p.green,
                    plural(wiped),
                    p.reset
                ),
            );
            residue_note(p, &opened, &env)?;
            history_backups_note(p, &root);
            Ok(())
        }
        HistoryAction::List { key, env } => {
            let env = get_env(p, env.as_deref())?;
            let versions = opened
                .vault
                .list_versions(&env, &key)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            ui::header(p, &format!("{key} {}({env}){}", p.dim, p.reset));
            ui::blank();
            for item in versions {
                let (state, when) = match &item.state {
                    VersionState::Current => ("current", item.updated.clone()),
                    VersionState::Removed { removed } => ("removed", removed.clone()),
                    VersionState::Old => ("old", item.updated.clone()),
                };
                ui::out(&format!(
                    "  {}v{}{}  {:<8}{}{}{}",
                    p.yellow,
                    item.version,
                    p.reset,
                    state,
                    p.dim,
                    when.unwrap_or_default(),
                    p.reset
                ));
            }
            ui::blank();
            Ok(())
        }
        HistoryAction::Show { key, version, env } => {
            let env = get_env(p, env.as_deref())?;
            let version = version_arg(p, &version)?;
            let value = opened
                .vault
                .get_version(&env, &key, version)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            ui::out(&value);
            Ok(())
        }
        HistoryAction::Restore { key, version, env } => {
            let env = get_env(p, env.as_deref())?;
            let version = version_arg(p, &version)?;
            let new_version = opened
                .vault
                .restore_version(&env, &key, version)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            audit_event(
                "secret_restored_version",
                fields(&[
                    ("env", Value::String(env.clone())),
                    ("secret", Value::String(key.clone())),
                    ("version", Value::from(version)),
                    ("new_version", Value::from(new_version)),
                ]),
            );
            ui::success(
                p,
                &format!(
                    "{}{key}{}{} restored from v{version} as v{new_version} {}({env}){}",
                    p.bold, p.reset, p.green, p.dim, p.reset
                ),
            );
            Ok(())
        }
        HistoryAction::UndoRm { key, env } => {
            let env = get_env(p, env.as_deref())?;
            let version = opened
                .vault
                .undo_remove(&env, &key)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            audit_event(
                "secret_restored_version",
                fields(&[
                    ("env", Value::String(env.clone())),
                    ("secret", Value::String(key.clone())),
                    ("version", Value::from(version)),
                    ("undo", Value::String("rm".to_owned())),
                ]),
            );
            ui::success(
                p,
                &format!(
                    "{}{key}{}{} is back {}({env}, v{version}){}",
                    p.bold, p.reset, p.green, p.dim, p.reset
                ),
            );
            Ok(())
        }
    }
}

fn keep(p: &Palette, root: &Path, opened: &project::Opened, count: Option<&str>) -> CmdResult {
    let current = opened
        .vault
        .get_history_keep()
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let Some(count) = count else {
        ui::info(&format!(
            "History keeps the last {}{current}{} old values of each secret {}(0 keeps none; kv history keep N changes it){}",
            p.bold, p.reset, p.dim, p.reset
        ));
        return Ok(());
    };
    let keep = count.trim().parse::<i64>().unwrap_or(-1);
    if !(0..=HISTORY_KEEP_MAX).contains(&keep) {
        return Err(quiet_error(
            p,
            &format!("history keep must be a whole number from 0 to {HISTORY_KEEP_MAX}"),
        ));
    }
    let keep = keep as usize;
    if keep < current
        && !history_confirm(
            p,
            &format!(
                "Keep {keep} old values per secret? Older ones are wiped now and cannot be recovered."
            ),
        )?
    {
        ui::info("cancelled");
        return Ok(());
    }
    let wiped = opened
        .vault
        .set_history_keep(keep)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    if wiped > 0 {
        forgotten(
            "vault",
            &[
                ("reason", Value::String("keep_setting".to_owned())),
                ("keep", Value::from(keep)),
            ],
            wiped,
        );
    }
    ui::success(
        p,
        &format!(
            "history keeps {keep} old value{} per secret {}({wiped} wiped){}",
            plural(keep),
            p.dim,
            p.reset
        ),
    );
    history_backups_note(p, root);
    Ok(())
}
