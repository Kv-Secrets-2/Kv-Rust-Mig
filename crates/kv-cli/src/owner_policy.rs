use std::path::Path;

use kv_store::{config, config_authority};
use serde_json::Value;

use crate::project::{self, CmdResult};
use crate::terminal;
use crate::ui::{self, Palette};

pub fn approval_mode_title(mode: &str) -> &str {
    match mode {
        "local-convenience" => "local convenience",
        "protected-approval" => "protected approval",
        "unsafe-convenience" => "unsafe convenience",
        _ => "not chosen",
    }
}

pub fn approval_mode_summary(mode: &str) -> &str {
    match mode {
        "local-convenience" => {
            "local terminal/app approvals allowed; use only when agents cannot control this desktop"
        }
        "protected-approval" => {
            "local approval commands are blocked; use an owner-controlled protected channel when available"
        }
        "unsafe-convenience" => {
            "same-session approvals allowed by explicit override; not safe against desktop-controlling agents"
        }
        _ => {
            "approval mode not chosen — run kv approval-mode set local-convenience or protected-approval"
        }
    }
}

pub fn approval_mode_strength(mode: &str) -> u8 {
    match mode {
        "protected-approval" => 2,
        "unsafe-convenience" => 0,
        _ => 1,
    }
}

pub fn print_approval_mode(p: &Palette, value: &Value) {
    let mode = config::approval_mode(value);
    let marker = if matches!(mode, "local-convenience" | "protected-approval") {
        ui::dot_on(p)
    } else {
        format!("{}!{}", p.yellow, p.reset)
    };
    ui::info(&format!(
        "  {marker} approval mode {}— {}: {}{}",
        p.dim,
        approval_mode_title(mode),
        approval_mode_summary(mode),
        p.reset
    ));
}

#[allow(dead_code)]
pub fn warn_if_approval_mode_unset(p: &Palette, root: &Path) -> CmdResult {
    if config::get_approval_mode(root).map_err(|e| project::fail(p, &e.to_string()))? == "unset" {
        ui::warn(p, "approval mode not chosen");
        ui::info(&format!(
            "{}choose local-convenience only if agents cannot control your browser/terminal/desktop; choose protected-approval otherwise{}",
            p.dim, p.reset
        ));
    }
    Ok(())
}

pub fn block_local_approval_if_protected(p: &Palette, root: &Path, action: &str) -> CmdResult {
    if config::get_approval_mode(root).map_err(|e| project::fail(p, &e.to_string()))?
        != "protected-approval"
    {
        return Ok(());
    }
    ui::error(
        p,
        &format!("local {action} is disabled in protected-approval mode"),
    );
    ui::info(&format!(
        "{}This project is configured as if an AI agent may control the desktop/terminal. Agents may request, but approval must come from a protected owner channel. That channel is not implemented yet.{}",
        p.dim, p.reset
    ));
    ui::info(&format!(
        "{}Deny/block/revoke/list paths still work. The kv CLI refuses a local change out of protected-approval.{}",
        p.dim, p.reset
    ));
    Err(project::Exit(1))
}

pub fn confirm_decision(p: &Palette, lines: &[String], prompt: &str) -> CmdResult<bool> {
    terminal::check_owner_terminal().map_err(|e| project::fail(p, &e.to_string()))?;
    for line in lines {
        ui::info(line);
    }
    ui::blank();
    let answer = terminal::owner_input(&format!("  {prompt}"))
        .map_err(|e| project::fail(p, &e.to_string()))?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        ui::info("cancelled");
        return Ok(false);
    }
    ui::blank();
    Ok(true)
}

fn key_is_wrapped(p: &Palette, root: &Path) -> CmdResult<(bool, bool)> {
    let path = project::key_path(root);
    match std::fs::metadata(&path) {
        Ok(meta) => Ok((
            meta.is_file(),
            config_authority::is_key_wrapped(root, true)
                .map_err(|e| project::fail(p, &e.to_string()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((false, false)),
        Err(e) => Err(project::fail(p, &e.to_string())),
    }
}

pub fn refuse_policy_change_without_passphrase(p: &Palette, root: &Path) -> CmdResult {
    let (present, wrapped) = key_is_wrapped(p, root)?;
    if wrapped {
        return Ok(());
    }
    ui::error(
        p,
        "refused: kv changes a project's security policy only on a passphrase-protected vault. Run 'kv upgrade-security' if this vault has no passphrase, then try again.",
    );
    if !present {
        ui::info(
            "This vault has no key file here (its key came from KV_MASTER_KEY): 'kv import-key' writes one protected with a passphrase.",
        );
    }
    Err(project::Exit(1))
}

fn two_factor_on(value: &Value) -> bool {
    let Some(security) = value.get("security") else {
        return false;
    };
    let Some(security) = security.as_object() else {
        return true;
    };
    security.get("totp").is_some_and(|v| match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
    })
}

fn loosening_needs_code(root: &Path, snapshot: &Value) -> bool {
    two_factor_on(snapshot)
        || config::load_config(root)
            .map(|s| two_factor_on(&s.value))
            .unwrap_or(true)
}

pub fn authorize_policy_change(
    p: &Palette,
    root: &Path,
    lines: &[String],
    removes_authority: bool,
) -> CmdResult<bool> {
    authorize(p, root, lines, removes_authority, None)
}

pub fn authorize_loosening_change(
    p: &Palette,
    root: &Path,
    lines: &[String],
    snapshot: &Value,
) -> CmdResult<bool> {
    authorize(p, root, lines, false, Some(snapshot))
}

fn authorize(
    p: &Palette,
    root: &Path,
    lines: &[String],
    removes_authority: bool,
    loosening: Option<&Value>,
) -> CmdResult<bool> {
    if !removes_authority {
        refuse_policy_change_without_passphrase(p, root)?;
    }
    let (_, wrapped) = key_is_wrapped(p, root)?;
    let mut lines = lines.to_vec();
    lines.push("This changes the security policy for the current project.".into());
    if wrapped {
        lines.push(format!(
            "{}Your passphrase is required to confirm it.{}",
            p.dim, p.reset
        ));
    }
    terminal::check_owner_terminal().map_err(|e| project::fail(p, &e.to_string()))?;
    let refuse_code = || {
        project::fail(
            p,
            "this change loosens the project's rules and requires two-factor authentication, which is not supported by this build; nothing was changed",
        )
    };
    if loosening.is_some_and(|s| loosening_needs_code(root, s)) {
        return Err(refuse_code());
    }
    if !confirm_decision(p, &lines, "Apply this policy change? [y/N] ")? {
        return Ok(false);
    }
    if wrapped {
        project::prompt_verified_passphrase(p, root)?;
        if loosening.is_some_and(|s| loosening_needs_code(root, s)) {
            return Err(refuse_code());
        }
    }
    Ok(true)
}

pub fn cmd_approval_mode(p: &Palette, mode: Option<&str>) -> CmdResult {
    let root = project::require_project(p)?;
    let snapshot = project::config_value(p, &root)?;
    let current = config::get_approval_mode(&root).map_err(|e| project::fail(p, &e.to_string()))?;
    let Some(mode) = mode else {
        ui::header(p, "approval mode");
        ui::blank();
        ui::info(&format!("{}Current{}", p.white, p.reset));
        print_approval_mode(p, &snapshot.value);
        ui::blank();
        ui::info(&format!("{}Modes{}", p.white, p.reset));
        for (name, color, description) in [
            (
                "local-convenience",
                p.green,
                "local approvals allowed; not safe if agents control this desktop",
            ),
            (
                "protected-approval",
                p.green,
                "local approvals blocked; use for OpenClaw/full-desktop agents",
            ),
            (
                "unsafe-convenience",
                p.yellow,
                "explicit same-session override; convenience only",
            ),
        ] {
            ui::info(&format!(
                "  {color}{name}{}  {}{description}{}",
                p.reset, p.dim, p.reset
            ));
        }
        ui::blank();
        return Ok(());
    };
    if current == mode {
        ui::info(&format!("approval mode already set: {mode}"));
        return Ok(());
    }
    block_local_approval_if_protected(p, &root, "approval-mode change")?;
    let mut lines = vec![
        "Set this project's approval security mode.".into(),
        format!(
            "Current: {}{}{}",
            p.dim,
            approval_mode_title(&current),
            p.reset
        ),
        format!("New mode: {}{mode}{}", p.dim, p.reset),
    ];
    let details = match mode {
        "local-convenience" => [
            "Use only when agents cannot control this computer's browser, terminal, mouse, keyboard, or desktop.",
            "Local CLI/app approvals will be allowed.",
        ],
        "protected-approval" => [
            "Use when an agent may control this computer's browser, terminal, mouse, keyboard, or desktop.",
            "Local CLI/app approvals that grant access will be blocked until a protected owner channel exists.",
        ],
        "unsafe-convenience" => [
            "This is an explicit convenience override for same-session approvals.",
            "It is not safe against agents that can control the approval surface.",
        ],
        _ => return Err(project::fail(p, &format!("invalid approval mode: {mode}"))),
    };
    lines.extend(details.map(str::to_owned));
    let authorized = if approval_mode_strength(mode) < approval_mode_strength(&current) {
        authorize_loosening_change(p, &root, &lines, &snapshot.value)?
    } else {
        authorize_policy_change(p, &root, &lines, false)?
    };
    if !authorized {
        return Ok(());
    }
    let changed = (|| {
        let _authorization = config::authorization_lock(&root)?;
        config::config_write_guard(&root, &snapshot, || config::set_approval_mode(&root, mode))
    })()
    .map_err(|e: kv_store::StoreError| project::fail(p, &e.to_string()))?;
    if changed {
        ui::success(
            p,
            &format!("approval mode set: {}{mode}{}", p.bold, p.reset),
        );
    } else {
        ui::info(&format!("approval mode already set: {mode}"));
    }
    Ok(())
}
