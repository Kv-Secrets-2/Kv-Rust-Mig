//! The vault a command works on: `find_project_root`, `_require_project`, `_get_env`,
//! `_prepare_vault_access` and `_get_store` from `kv/cli.py`.

use std::path::{Path, PathBuf};

use kv_crypto::{Key32, keyfile};
use kv_store::config::{ConfigSnapshot, Vault, load_config};
use kv_store::{DrawerStore, envname, vault_origin};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::terminal::{self, PromptError};
use crate::ui::{self, Palette};

/// A command ended: Python's `sys.exit(code)` after its own output.
#[derive(Debug)]
pub struct Exit(pub i32);

pub type CmdResult<T = ()> = Result<T, Exit>;

pub fn fail(p: &Palette, msg: &str) -> Exit {
    ui::error(p, msg);
    Exit(1)
}

/// `_quiet_error`: stderr, else stdout, never an error of its own.
/// `_error(msg); sys.exit(1)`; an empty message is a bare `sys.exit(1)`.
pub fn quiet_error(p: &Palette, msg: &str) -> Exit {
    if !msg.is_empty() {
        ui::error(p, msg);
    }
    Exit(1)
}

/// `config._is_real_vault_directory`: a directory reached without a link.
fn is_real_vault_directory(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.is_dir(),
        Err(_) => false,
    }
}

/// `find_project_root()`: walk up from the working directory looking for `.secrets/`.
pub fn find_project_root() -> Option<PathBuf> {
    let mut path = std::env::current_dir().ok()?;
    loop {
        if is_real_vault_directory(&path.join(".secrets")) {
            return Some(path);
        }
        if !path.pop() {
            return None;
        }
    }
}

/// `_require_project()`.
pub fn require_project(p: &Palette) -> CmdResult<PathBuf> {
    let Some(root) = find_project_root() else {
        ui::error(p, "not a kv project (no .secrets/ found)");
        ui::info(&format!("{}run 'kv init' to initialize{}", p.dim, p.reset));
        return Err(Exit(1));
    };
    vault_origin::require_local(&root).map_err(|e| quiet_error(p, &e.to_string()))?;
    Ok(root)
}

pub fn secrets_dir(root: &Path) -> PathBuf {
    root.join(".secrets")
}

pub fn key_path(root: &Path) -> PathBuf {
    secrets_dir(root).join("key")
}

pub fn config_value(p: &Palette, root: &Path) -> CmdResult<ConfigSnapshot> {
    load_config(root).map_err(|e| quiet_error(p, &e.to_string()))
}

pub fn default_env(config: &Value) -> String {
    config
        .get("default_env")
        .and_then(Value::as_str)
        .unwrap_or("dev")
        .to_owned()
}

/// `_get_env(args)`: the `-e` value or the project's default, validated.
pub fn get_env(p: &Palette, env: Option<&str>) -> CmdResult<String> {
    let name = match env {
        Some(name) => name.to_owned(),
        None => {
            let root = require_project(p)?;
            default_env(&config_value(p, &root)?.value)
        }
    };
    envname::validate_env_name(&name).map_err(|e| quiet_error(p, &e.to_string()))?;
    Ok(name)
}

/// `_prepare_vault_access(root)` for the commands in `_VAULT_RECOVERY_COMMANDS`.
pub fn prepare_vault_access(p: &Palette, root: &Path) -> CmdResult {
    vault_origin::require_local(root).map_err(|e| quiet_error(p, &e.to_string()))?;
    let pending = load_config(root)
        .ok()
        .and_then(|snapshot| {
            snapshot
                .value
                .get("security")?
                .get("recovery_delivery_pending")?
                .as_bool()
        })
        .unwrap_or(false);
    if pending {
        eprintln!(
            "kv: Recovery key display was interrupted or unconfirmed; run kv recovery-key rotate after login."
        );
    }
    Ok(())
}

pub fn is_agent_running(root: &Path) -> bool {
    kv_mcp::agent::is_agent_running(root)
}

/// `agent_request(cmd, **fields)` against this project's daemon.
pub fn agent_request(root: &Path, cmd: &str, fields: Map<String, Value>) -> Option<Value> {
    kv_proto::agent_request(root, cmd, &fields).ok()
}

fn attempts_label(remaining: u32) -> String {
    let noun = if remaining == 1 {
        "attempt"
    } else {
        "attempts"
    };
    format!("{remaining} {noun} remaining")
}

fn quiet_warn(p: &Palette, msg: &str) {
    ui::out(&format!("  {}!{} {msg}", p.yellow, p.reset));
}

/// `owner_key.master_key_from_blob`: the key file must belong to this folder.
fn identity_check(root: &Path, identity: &kv_crypto::Identity) -> Result<(), String> {
    let here = kv_store::config_authority::canonical_location(root)
        .map_err(|e| format!("cannot check vault path component: {e}"))?;
    if identity.location != here {
        return Err(format!(
            "this key file was written for {}; open the vault as that folder, or run 'kv vault relocate' to bind it here",
            render_location(&identity.location)
        ));
    }
    Ok(())
}

fn render_location(location: &[u8]) -> String {
    String::from_utf8_lossy(location).into_owned()
}

/// `_prompt_verified_passphrase(root, check_identity=True, read=_owner_getpass)`.
fn prompt_verified_passphrase(p: &Palette, root: &Path) -> CmdResult<kv_crypto::Identity> {
    let blob = std::fs::read(key_path(root))
        .map_err(|e| quiet_error(p, &format!("cannot open the key file: {e}")))?;
    let max_attempts = 3u32;
    for attempt in 1..=max_attempts {
        let passphrase = read_owner_secret(p, &format!("  {}Passphrase{}: ", p.yellow, p.reset))?;
        match keyfile::unwrap_v4(&blob, passphrase.as_bytes()) {
            Ok(identity) => {
                identity_check(root, &identity).map_err(|m| quiet_error(p, &m))?;
                ui::out(&format!("  {}verified{}\n", p.green, p.reset));
                return Ok(identity);
            }
            Err(
                error @ (kv_crypto::CryptoError::Header(_)
                | kv_crypto::CryptoError::UnsupportedVersion(_)),
            ) => {
                return Err(quiet_error(
                    p,
                    &format!("cannot open the key file: {error}"),
                ));
            }
            Err(_) => {
                let remaining = max_attempts - attempt;
                if remaining > 0 {
                    quiet_warn(
                        p,
                        &format!(
                            "wrong passphrase or damaged key file \u{2014} {}",
                            attempts_label(remaining)
                        ),
                    );
                    ui::blank();
                    continue;
                }
                return Err(quiet_error(p, "wrong passphrase or damaged key file"));
            }
        }
    }
    Err(Exit(1))
}

fn read_owner_secret(p: &Palette, prompt: &str) -> CmdResult<Zeroizing<String>> {
    match terminal::owner_read_secret(prompt) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(PromptError::Eof) => Err(quiet_error(p, "")),
        Err(PromptError::Refused(msg)) => Err(quiet_error(p, &msg)),
        Err(PromptError::Io(e)) => Err(quiet_error(p, &e.to_string())),
    }
}

#[allow(dead_code)]
pub struct Opened {
    pub root: PathBuf,
    pub vault: Vault,
    pub config: ConfigSnapshot,
}

/// `_get_store()`: the passphrase-protected vault opened at the terminal.
pub fn get_store(p: &Palette) -> CmdResult<Opened> {
    let root = require_project(p)?;
    if !terminal::stdin_is_tty() {
        if is_agent_running(&root) {
            ui::error(p, "this command requires interactive passphrase input");
            ui::info(&format!(
                "{}use kv_api or kv_run MCP tools instead (they use the daemon){}",
                p.dim, p.reset
            ));
        } else {
            ui::error(
                p,
                "vault is locked and no terminal available for passphrase",
            );
            ui::info(&format!(
                "{}start the daemon first: kv unlock (from a terminal){}",
                p.dim, p.reset
            ));
            ui::info(&format!(
                "{}then use kv_api or kv_run \u{2014} they don't need a passphrase{}",
                p.dim, p.reset
            ));
        }
        return Err(Exit(1));
    }
    let config = config_value(p, &root)?;
    let has_totp = config
        .value
        .get("security")
        .and_then(|s| s.get("totp"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let lock_type = if has_totp {
        "passphrase, then a code"
    } else {
        "passphrase"
    };
    let what = if is_agent_running(&root) {
        "authenticate to access values"
    } else {
        "vault locked"
    };
    ui::out(&format!(
        "\n  {}{}kv{} {}--{} {what} {}({lock_type}){}\n",
        p.bold, p.cyan, p.reset, p.dim, p.reset, p.dim, p.reset
    ));
    if has_totp {
        return Err(quiet_error(
            p,
            "two-factor unlock is not supported by this build yet; use the Python kv for this vault",
        ));
    }
    let identity = prompt_verified_passphrase(p, &root)?;
    let master = Key32::new(*identity.master_key.as_bytes());
    let vault = Vault::open(root.clone(), DrawerStore::open(secrets_dir(&root), master));
    ui::out(&format!("  {}unlocked{}\n", p.green, p.reset));
    Ok(Opened {
        root,
        vault,
        config,
    })
}

/// `_audit_secret_event`: names only, best effort.
pub fn audit_secret_event(_root: &Path, event: &str, env: &str, secret: &str) {
    let mut fields = Map::new();
    fields.insert("env".into(), Value::String(env.to_owned()));
    fields.insert("secret".into(), Value::String(secret.to_owned()));
    audit_event(event, fields);
}

/// `audit.emit(event, **fields)` into `~/.kv/audit.jsonl`; failures are ignored.
pub fn audit_event(event: &str, fields: Map<String, Value>) {
    let Ok(dir) = kv_proto::runtime_dir() else {
        return;
    };
    let _ = kv_audit::Audit::new(dir).emit(event, fields);
}
