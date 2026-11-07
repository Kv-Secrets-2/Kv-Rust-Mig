//! `kv vault approve-config`: Python `config_authority.approve_config`, the one `kv vault`
//! action a drawer-only vault needs before its first `kv unlock`. The migration and
//! old-key actions are not part of this build.

use serde_json::Value;

use kv_store::config_authority;

use crate::project::{self, CmdResult, Exit, quiet_error, require_project};
use crate::registry::sort_keys;
use crate::terminal::{self, PromptError};
use crate::ui::{self, Palette};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultAction {
    None,
    ApproveConfig,
    Unported(String),
}

fn ascii_json(value: &Value) -> String {
    kv_store::pyjson::to_vec_indent2_ascii(&sort_keys(value.clone()))
        .map(|bytes| String::from_utf8_lossy(&bytes).trim_end().to_owned())
        .unwrap_or_else(|_| "null".to_owned())
}

/// `show_state(tty, title, state)`.
fn show_state(title: &str, state: Option<&Value>) {
    ui::out(&format!(
        "{title}:\n{}",
        ascii_json(state.unwrap_or(&Value::Null))
    ));
}

pub fn cmd_vault(p: &Palette, action: VaultAction) -> CmdResult {
    match action {
        VaultAction::None => {
            ui::header(p, "vault");
            ui::blank();
            ui::info(
                "  kv vault approve-config    Review and approve config authority with your passphrase",
            );
            ui::blank();
            Ok(())
        }
        VaultAction::Unported(name) => Err(quiet_error(
            p,
            &format!(
                "kv vault {name} is not available in this build: drawer vaults made by kv init need no migration or old key"
            ),
        )),
        VaultAction::ApproveConfig => approve_config(p),
    }
}

fn approve_config(p: &Palette) -> CmdResult {
    let root = require_project(p)?;
    kv_store::vault_origin::require_local(&root).map_err(|e| quiet_error(p, &e.to_string()))?;
    let snapshot =
        kv_store::config::load_config(&root).map_err(|e| quiet_error(p, &e.to_string()))?;
    let proposed = config_authority::authority_state(&snapshot.value)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let real = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let shown = serde_json::to_string(&real.to_string_lossy()).unwrap_or_default();
    ui::out(&format!(
        "Review and approve where this vault may send credentials.\nVault: {shown}"
    ));
    let passphrase = match terminal::owner_read_secret("Passphrase: ") {
        Ok(text) if text.is_empty() => {
            return Err(quiet_error(
                p,
                "No passphrase was entered; retry the approval in your terminal.",
            ));
        }
        Ok(text) => zeroize::Zeroizing::new(text),
        Err(PromptError::Eof) => {
            return Err(quiet_error(
                p,
                "No passphrase was entered; retry the approval in your terminal.",
            ));
        }
        Err(other) => return Err(quiet_error(p, &other.to_string())),
    };
    let identity = project::unlock_identity(&root, passphrase.as_bytes()).map_err(|_| {
        quiet_error(
            p,
            "The passphrase did not open this vault here; check the passphrase and vault location.",
        )
    })?;
    drop(passphrase);
    let master = kv_crypto::Key32::new(*identity.master_key.as_bytes());
    let previous = config_authority::approved_authority(&root, &master)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    show_state("Previously approved authority", previous.as_ref());
    show_state(
        "Proposed authority (origins, secret bindings and policy)",
        Some(&proposed),
    );
    let answer = match terminal::input("Approve this exact authority? [y/N] ") {
        Ok(text) => text,
        Err(PromptError::Eof) => String::new(),
        Err(other) => return Err(quiet_error(p, &other.to_string())),
    };
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        return Err(quiet_error(
            p,
            "Config approval cancelled; restore the approved config or run kv vault approve-config again.",
        ));
    }
    config_authority::approve_config_unattended(&root, &master).map_err(|e| {
        let _ = Exit(1);
        quiet_error(p, &e.to_string())
    })?;
    ui::out("Config authority approved; restart with kv lock and kv unlock.");
    Ok(())
}
