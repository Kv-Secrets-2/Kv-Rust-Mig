//! `kv env ...`: Python `cmd_env`, `_env_copy` and `_cmd_env_owner`.
//!
//! `kv env repair-names` is not ported: it repairs registrations left by pre-drawer
//! releases, which this build never creates.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use kv_store::approval_refs::approvals_naming_env;
use kv_store::config::{self, env_delete_problem, env_rename_problem};
use kv_store::{CopyOptions, envname};

use crate::project::{self, CmdResult, audit_event, get_store, quiet_error, require_project};
use crate::render;
use crate::terminal::{self, PromptError};
use crate::ui::{self, Palette};

const DELETED_ENV_KEEP_DAYS_MAX: u64 = 365;

pub enum EnvAction {
    Create {
        name: String,
    },
    Copy {
        src: String,
        dst: String,
        replace: bool,
        keep_existing: bool,
        create: bool,
    },
    Rename {
        old: String,
        new: String,
    },
    Delete {
        name: String,
    },
    Restore {
        name: Option<String>,
    },
    Purge {
        name: String,
    },
    Default {
        name: Option<String>,
    },
    KeepDeleted {
        days: Option<String>,
    },
}

pub fn cmd_env(p: &Palette, action: EnvAction) -> CmdResult {
    match action {
        EnvAction::Create { name } => env_create(p, &name),
        EnvAction::Copy {
            src,
            dst,
            replace,
            keep_existing,
            create,
        } => env_copy(p, &src, &dst, replace, keep_existing, create),
        other => env_owner(p, other),
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn env_create(p: &Palette, name: &str) -> CmdResult {
    let root = require_project(p)?;
    let added = config::add_environment(&root, name).map_err(|e| quiet_error(p, &e.to_string()))?;
    if added {
        let mut fields = Map::new();
        fields.insert("env".into(), Value::String(name.to_owned()));
        audit_event("env_created", fields);
        ui::success(p, &format!("created environment: {name}"));
        Ok(())
    } else {
        Err(quiet_error(
            p,
            &format!("environment '{name}' already exists"),
        ))
    }
}

/// `_copy_name`: the name itself when printable, else its Python `repr`.
fn copy_name(name: &str) -> String {
    if render::is_printable(name) {
        name.to_owned()
    } else {
        crate::secrets::py_repr(name)
    }
}

/// `_copy_answer`: a stripped, lower-cased line; "" at EOF.
fn copy_answer(p: &Palette, question: &str) -> CmdResult<String> {
    match terminal::input(question) {
        Ok(line) => Ok(line.trim().to_lowercase()),
        Err(PromptError::Eof) => Ok(String::new()),
        Err(e) => Err(quiet_error(p, &e.to_string())),
    }
}

fn copy_cancelled(p: &Palette) -> CmdResult {
    ui::info("cancelled; nothing copied");
    Err(quiet_error(p, ""))
}

fn env_copy(
    p: &Palette,
    src: &str,
    dst: &str,
    replace: bool,
    keep_existing_flag: bool,
    create_flag: bool,
) -> CmdResult {
    let root = require_project(p)?;
    let envs = config::list_environments(&root).map_err(|e| quiet_error(p, &e.to_string()))?;
    envname::validate_registered_name(src, &envs).map_err(|e| quiet_error(p, &e.to_string()))?;
    envname::validate_registered_name(dst, &envs).map_err(|e| quiet_error(p, &e.to_string()))?;
    let usable = usable_environment_names(&envs);
    let have = usable
        .iter()
        .map(|e| copy_name(e))
        .collect::<Vec<_>>()
        .join(", ");
    if !envs.iter().any(|e| e == src) {
        ui::error(
            p,
            &format!(
                "environment '{}' does not exist; nothing copied",
                copy_name(src)
            ),
        );
        ui::info(&format!("You have: {have}"));
        return Err(quiet_error(p, ""));
    }
    if src == dst {
        return Err(quiet_error(
            p,
            &format!(
                "'{}' and '{}' are the same environment; nothing copied",
                copy_name(src),
                copy_name(dst)
            ),
        ));
    }
    let create = !envs.iter().any(|e| e == dst);
    if create && !create_flag {
        let closest = closest_env(dst, &usable);
        let hint = match closest {
            Some(c) => format!(" Did you mean '{}'?", copy_name(c)),
            None => String::new(),
        };
        if !terminal::stdin_is_tty() {
            ui::error(
                p,
                &format!(
                    "environment '{}' does not exist; nothing copied",
                    copy_name(dst)
                ),
            );
            ui::info(&format!("You have: {have}.{hint}"));
            ui::info("No terminal to ask on: pass --create to create it.");
            return Err(quiet_error(p, ""));
        }
        ui::info(&format!(
            "Environment '{}' does not exist. You have: {have}.{hint}",
            copy_name(dst)
        ));
        let answer = copy_answer(
            p,
            &format!("  Create new environment '{}'? [y/N] ", copy_name(dst)),
        )?;
        if answer != "y" && answer != "yes" {
            return copy_cancelled(p);
        }
    }
    let opened = get_store(p)?;
    let mut keep_existing = keep_existing_flag;
    let mut shown_keep: Option<usize> = None;
    let replaced = copy_conflicts(p, &opened, &envs, src, dst)?;
    if !replaced.is_empty() && !(replace || keep_existing_flag) {
        let count = replaced.len();
        ui::info(&format!(
            "{count} secret{} in {} would be replaced:",
            plural(count),
            copy_name(dst)
        ));
        for name in &replaced {
            ui::out(&format!("    {}", copy_name(name)));
        }
        let keep = opened
            .vault
            .get_history_keep()
            .map_err(|e| quiet_error(p, &e.to_string()))?;
        shown_keep = Some(keep);
        if keep == 0 {
            ui::info(&format!(
                "{}The history setting is 0 (kv history keep): replaced values are not kept.{}",
                p.dim, p.reset
            ));
        } else {
            ui::info(&format!(
                "{}Replaced values are kept as old versions (kv history list NAME -e {}).{}",
                p.dim,
                copy_name(dst),
                p.reset
            ));
        }
        if !terminal::stdin_is_tty() {
            return Err(quiet_error(
                p,
                "no terminal to ask on: pass --replace or --keep-existing; nothing copied",
            ));
        }
        let answer = copy_answer(p, "  [r]eplace / [k]eep existing / [c]ancel: ")?;
        if ["k", "keep", "keep existing"].contains(&answer.as_str()) {
            keep_existing = true;
        } else if !["r", "replace"].contains(&answer.as_str()) {
            return copy_cancelled(p);
        }
    }
    let result = opened
        .vault
        .copy_env_checked(
            src,
            dst,
            CopyOptions {
                keep_existing,
                expect_replaced: Some(replaced),
                expect_keep: shown_keep,
            },
        )
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    if result.created {
        let mut fields = Map::new();
        fields.insert("env".into(), Value::String(dst.to_owned()));
        audit_event("env_created", fields);
    }
    let mut fields = Map::new();
    fields.insert("src".into(), Value::String(src.to_owned()));
    fields.insert("dst".into(), Value::String(dst.to_owned()));
    fields.insert("copied".into(), Value::from(result.copied));
    fields.insert(
        "replaced".into(),
        Value::Array(result.replaced.iter().cloned().map(Value::String).collect()),
    );
    fields.insert(
        "kept".into(),
        Value::Array(result.kept.iter().cloned().map(Value::String).collect()),
    );
    audit_event("env_copied", fields);
    ui::success(
        p,
        &format!(
            "copied {} secrets from {} to {}",
            result.copied,
            copy_name(src),
            copy_name(dst)
        ),
    );
    if !result.replaced.is_empty() {
        ui::info(&format!(
            "replaced {} existing value(s) in {}",
            result.replaced.len(),
            copy_name(dst)
        ));
    }
    if !result.kept.is_empty() {
        ui::info(&format!(
            "kept {} existing value(s) in {}",
            result.kept.len(),
            copy_name(dst)
        ));
    }
    Ok(())
}

/// `Store.copy_conflicts`: names present in both whose values differ, sorted; never a value.
fn copy_conflicts(
    p: &Palette,
    opened: &project::Opened,
    envs: &[String],
    src: &str,
    dst: &str,
) -> CmdResult<Vec<String>> {
    if !envs.iter().any(|e| e == dst) {
        return Ok(Vec::new());
    }
    let store = &opened.vault.store;
    let source = store
        .list_secrets(src)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let target = store
        .list_secrets(dst)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let mut out: Vec<String> = source
        .iter()
        .filter(|(k, v)| {
            target
                .iter()
                .any(|(tk, tv)| tk == k && tv.as_str() != v.as_str())
        })
        .map(|(k, _)| k.clone())
        .collect();
    out.sort();
    Ok(out)
}

/// `_copy_closest_env`: `difflib.SequenceMatcher(None, a, b).ratio()` maximum (no junk;
/// autojunk never applies to names under 200 characters). Ties keep the first, as `max` does.
fn closest_env<'a>(name: &str, envs: &'a [String]) -> Option<&'a String> {
    let folded = casefold(name);
    let mut best: Option<(&String, f64)> = None;
    for env in envs {
        let ratio = sequence_ratio(&folded, &casefold(env));
        match best {
            Some((_, b)) if ratio <= b => {}
            _ => best = Some((env, ratio)),
        }
    }
    best.map(|(e, _)| e)
}

fn casefold(text: &str) -> Vec<char> {
    caseless::default_case_fold_str(text).chars().collect()
}

fn sequence_ratio(a: &[char], b: &[char]) -> f64 {
    let total = a.len() + b.len();
    if total == 0 {
        return 1.0;
    }
    let matches = matching_blocks(a, b, 0, a.len(), 0, b.len());
    2.0 * matches as f64 / total as f64
}

/// Sum of matching-block sizes, mirroring `SequenceMatcher.get_matching_blocks` with
/// `find_longest_match` (earliest `i`, then earliest `j`, among the longest).
fn matching_blocks(
    a: &[char],
    b: &[char],
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> usize {
    let (i, j, k) = longest_match(a, b, alo, ahi, blo, bhi);
    if k == 0 {
        return 0;
    }
    let mut total = k;
    if alo < i && blo < j {
        total += matching_blocks(a, b, alo, i, blo, j);
    }
    if i + k < ahi && j + k < bhi {
        total += matching_blocks(a, b, i + k, ahi, j + k, bhi);
    }
    total
}

#[allow(clippy::needless_range_loop)] // index arithmetic mirrors difflib
fn longest_match(
    a: &[char],
    b: &[char],
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> (usize, usize, usize) {
    let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
    let mut j2len: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for i in alo..ahi {
        let mut newj2len = std::collections::HashMap::new();
        for j in blo..bhi {
            if b[j] != a[i] {
                continue;
            }
            let k = j2len.get(&j.wrapping_sub(1)).copied().unwrap_or(0) + 1;
            if j == 0 && k != 1 {
                continue;
            }
            newj2len.insert(j, k);
            if k > bestsize {
                besti = i + 1 - k;
                bestj = j + 1 - k;
                bestsize = k;
            }
        }
        j2len = newj2len;
    }
    (besti, bestj, bestsize)
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `_env_refuse_while_approvals` (SEAM S1).
fn refuse_while_approvals(p: &Palette, root: &Path, names: &[&str]) -> CmdResult {
    let now = now_epoch();
    let mut found = Vec::new();
    for name in names {
        for item in approvals_naming_env(root, name, now) {
            found.push((*name, item));
        }
    }
    if found.is_empty() {
        return Ok(());
    }
    let n = found.len();
    ui::error(
        p,
        &format!(
            "{n} approval{} name{} this environment; nothing was changed",
            plural(n),
            if n != 1 { "" } else { "s" }
        ),
    );
    for (name, item) in &found {
        let ends = match &item.ends_at {
            Some(ends) => format!("ends {}", render::escape(ends)),
            None => "no end date: it lasts until you end it".to_owned(),
        };
        ui::info(&format!(
            "  {}: {}  {}(environment {}; {ends}){}",
            render::escape(if item.kind.is_empty() {
                "approval"
            } else {
                &item.kind
            }),
            render::escape(&item.label),
            p.dim,
            render::escape(name),
            p.reset
        ));
    }
    ui::info(&format!(
        "{}End them first (kv approvals list shows them; end each one, or wait until it ends), then run this again.{}",
        p.dim, p.reset
    ));
    Err(quiet_error(p, ""))
}

/// `_env_typed_name`: Ok(true) when the owner typed the name back.
fn typed_name(p: &Palette, name: &str, what: &str) -> CmdResult<bool> {
    let typed = terminal::input(&format!("  Type the environment's name to {what} it: "))
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    if typed != name {
        ui::info("cancelled (the name did not match)");
        return Ok(false);
    }
    Ok(true)
}

/// `_history_confirm`.
pub fn history_confirm(p: &Palette, question: &str) -> CmdResult<bool> {
    let answer = terminal::input(&format!("  {question} [y/N] "))
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let answer = answer.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// `_history_backups_note` (B5): backups made earlier keep what they held.
pub fn history_backups_note(p: &Palette, root: &Path) {
    let held = std::fs::read_dir(root.join(".secrets").join("migration-backups"))
        .map(|mut it| it.next().is_some())
        .unwrap_or(false);
    if held {
        ui::info(&format!(
            "{}Drawer migration backups made earlier (.secrets/migration-backups) still hold what they held; this does not change them.{}",
            p.dim, p.reset
        ));
    }
    if crate::registry::last_backup_at(root).is_some() {
        ui::info(&format!(
            "{}Backup files made earlier with kv backup still hold the old values they held; this does not change them.{}",
            p.dim, p.reset
        ));
    }
}

fn stop_daemon_first(p: &Palette, keeps: &str) -> CmdResult {
    Err(quiet_error(
        p,
        &format!(
            "stop the vault daemon first: kv agent stop {}(it keeps {keeps} while it runs){}",
            p.dim, p.reset
        ),
    ))
}

/// Python `int()` on the command line: whitespace, sign, digits with single underscores.
fn python_int(text: &str) -> Option<i64> {
    let t = text.trim();
    let (neg, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    if !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let value: i64 = cleaned.parse().ok()?;
    Some(if neg { -value } else { value })
}

fn env_owner(p: &Palette, action: EnvAction) -> CmdResult {
    let root = require_project(p)?;
    match &action {
        EnvAction::Default { name: None } => {
            let config = project::config_value(p, &root)?;
            ui::info(&format!(
                "The default environment is {}{}{} {}(kv env default NAME changes it){}",
                p.bold,
                render::escape(&project::default_env(&config.value)),
                p.reset,
                p.dim,
                p.reset
            ));
            return Ok(());
        }
        EnvAction::KeepDeleted { days: None } => {
            let days = config::get_deleted_env_keep_days(&root)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            ui::info(&format!(
                "A deleted environment is kept {}{days}{} day{} {}(kv env keep-deleted DAYS changes it for later deletions){}",
                p.bold,
                p.reset,
                if days != 1 { "s" } else { "" },
                p.dim,
                p.reset
            ));
            return Ok(());
        }
        EnvAction::Restore { name: None } => {
            let deleted = config::list_deleted_environments(&root)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            if deleted.is_empty() {
                ui::info("No deleted environments.");
            }
            for entry in &deleted {
                ui::info(&format!(
                    "  {}  {}deleted {}; purged after {}{}",
                    render::escape(&entry.name),
                    p.dim,
                    render::escape(&entry.deleted_at),
                    render::escape(&entry.purge_after),
                    p.reset
                ));
            }
            if !deleted.is_empty() {
                ui::info(&format!(
                    "{}kv env restore NAME brings one back; kv env purge NAME wipes it now{}",
                    p.dim, p.reset
                ));
            }
            return Ok(());
        }
        _ => {}
    }
    let action_name = match &action {
        EnvAction::Rename { .. } => "rename",
        EnvAction::Delete { .. } => "delete",
        EnvAction::Restore { .. } => "restore",
        EnvAction::Purge { .. } => "purge",
        EnvAction::Default { .. } => "default",
        EnvAction::KeepDeleted { .. } => "keep-deleted",
        _ => unreachable!(),
    };
    if !terminal::stdin_is_tty() {
        ui::error(
            p,
            &format!("kv env {action_name} needs an interactive terminal (owner only)"),
        );
        ui::info(&format!(
            "{}run it yourself from a terminal{}",
            p.dim, p.reset
        ));
        return Err(quiet_error(p, ""));
    }
    match action {
        EnvAction::Default { name: Some(name) } => {
            if project::is_agent_running(&root) {
                return stop_daemon_first(p, "the default environment");
            }
            let opened = get_store(p)?;
            envname::validate_env_name(&name).map_err(|e| quiet_error(p, &e.to_string()))?;
            opened
                .vault
                .set_default_env(&name)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            ui::success(p, &format!("default environment: {name}"));
            Ok(())
        }
        EnvAction::KeepDeleted { days: Some(text) } => {
            let days = python_int(&text).unwrap_or(-1);
            if !(0..=DELETED_ENV_KEEP_DAYS_MAX as i64).contains(&days) {
                return Err(quiet_error(
                    p,
                    &format!("days must be a whole number from 0 to {DELETED_ENV_KEEP_DAYS_MAX}"),
                ));
            }
            let opened = get_store(p)?;
            opened
                .vault
                .set_deleted_env_keep_days(days as u64)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            ui::success(
                p,
                &format!(
                    "deleted environments are kept {days} day{} {}(from the next deletion on){}",
                    if days != 1 { "s" } else { "" },
                    p.dim,
                    p.reset
                ),
            );
            Ok(())
        }
        other => {
            if project::is_agent_running(&root) {
                return stop_daemon_first(p, "the environment list");
            }
            env_owner_drawers(p, &root, other)
        }
    }
}

fn env_owner_drawers(p: &Palette, root: &Path, action: EnvAction) -> CmdResult {
    let config = project::config_value(p, root)?.value;
    match action {
        EnvAction::Rename { old, new } => {
            if let Some(problem) = env_rename_problem(&config, &old, &new)
                .map_err(|e| quiet_error(p, &e.to_string()))?
            {
                return Err(quiet_error(p, &problem));
            }
            refuse_while_approvals(p, root, &[&old, &new])?;
            let opened = get_store(p)?;
            if !history_confirm(
                p,
                &format!(
                    "Rename environment '{old}' to '{new}'? Its secrets and their history move with it."
                ),
            )? {
                ui::info("cancelled");
                return Ok(());
            }
            opened
                .vault
                .rename_env(&old, &new)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            let mut fields = Map::new();
            fields.insert("from_env".into(), Value::String(old.clone()));
            fields.insert("to_env".into(), Value::String(new.clone()));
            audit_event("env_renamed", fields);
            ui::success(p, &format!("renamed {old} to {}{new}{}", p.bold, p.reset));
            let after = project::config_value(p, root)?;
            if project::default_env(&after.value) == new {
                ui::info(&format!(
                    "{}{new} is the default environment{}",
                    p.dim, p.reset
                ));
            }
            Ok(())
        }
        EnvAction::Delete { name } => {
            if let Some(problem) =
                env_delete_problem(&config, &name).map_err(|e| quiet_error(p, &e.to_string()))?
            {
                return Err(quiet_error(p, &problem));
            }
            refuse_while_approvals(p, root, &[&name])?;
            let opened = get_store(p)?;
            let days = config::get_deleted_env_keep_days(root)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            ui::warn(
                p,
                &format!(
                    "Deleting environment '{name}' and its secrets. It can be restored for {days} day{} (kv env restore {name}); after that the next vault change wipes it.",
                    if days != 1 { "s" } else { "" }
                ),
            );
            if !typed_name(p, &name, "delete")? {
                return Ok(());
            }
            let entry = opened
                .vault
                .delete_env(&name)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            let mut fields = Map::new();
            fields.insert("env".into(), Value::String(name.clone()));
            fields.insert(
                "purge_after".into(),
                Value::String(entry.purge_after.clone()),
            );
            audit_event("env_deleted", fields);
            ui::success(
                p,
                &format!(
                    "deleted {name} {}(kv env restore {name} until {}){}",
                    p.dim, entry.purge_after, p.reset
                ),
            );
            Ok(())
        }
        EnvAction::Restore { name: Some(name) } => {
            if !is_deleted(p, root, &name)? {
                return Err(quiet_error(
                    p,
                    &format!("'{name}' is not a deleted environment (kv env restore lists them)"),
                ));
            }
            refuse_while_approvals(p, root, &[&name])?;
            let opened = get_store(p)?;
            opened
                .vault
                .restore_env(&name)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            let mut fields = Map::new();
            fields.insert("env".into(), Value::String(name.clone()));
            audit_event("env_restored", fields);
            ui::success(p, &format!("restored {}{name}{}", p.bold, p.reset));
            Ok(())
        }
        EnvAction::Purge { name } => {
            if !is_deleted(p, root, &name)? {
                return Err(quiet_error(
                    p,
                    &format!("'{name}' is not a deleted environment (kv env restore lists them)"),
                ));
            }
            let opened = get_store(p)?;
            ui::warn(
                p,
                &format!("Wiping deleted environment '{name}' now. This cannot be undone."),
            );
            if !typed_name(p, &name, "wipe")? {
                return Ok(());
            }
            let wiped = opened
                .vault
                .purge_env(&name)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            if wiped {
                let mut fields = Map::new();
                fields.insert("env".into(), Value::String(name.clone()));
                fields.insert("reason".into(), Value::String("owner".into()));
                audit_event("env_purged", fields);
                ui::success(p, &format!("wiped {name}"));
            } else {
                ui::success(
                    p,
                    &format!(
                        "wiped {name} {}(it was past its date: this vault change wiped it){}",
                        p.dim, p.reset
                    ),
                );
            }
            history_backups_note(p, root);
            Ok(())
        }
        _ => unreachable!(),
    }
}

fn is_deleted(p: &Palette, root: &Path, name: &str) -> CmdResult<bool> {
    let deleted =
        config::list_deleted_environments(root).map_err(|e| quiet_error(p, &e.to_string()))?;
    Ok(deleted.iter().any(|entry| entry.name == name))
}

/// `envname.split_environment_names(...)[0]`: names without path syntax whose portable
/// key is unique among the registered names.
fn usable_environment_names(names: &[String]) -> Vec<String> {
    let mut groups: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for name in names {
        if !envname::has_path_syntax(name) {
            *groups.entry(envname::portable_name_key(name)).or_insert(0) += 1;
        }
    }
    names
        .iter()
        .filter(|name| {
            !envname::has_path_syntax(name)
                && groups
                    .get(&envname::portable_name_key(name))
                    .copied()
                    .unwrap_or(0)
                    == 1
        })
        .cloned()
        .collect()
}
