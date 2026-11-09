//! `kv init` from `kv/cli.py` and `config._init_project`: a v4 key file bound to its folder,
//! drawer storage, a recovery key, and the vault list entry.

use std::path::{Path, PathBuf};

use kv_crypto::{Identity, Key32, keyfile, passphrase_strength, recovery};
use kv_store::config::{self, load_config, save_config, timestamp_now, write_config};
use kv_store::{config_authority, vault_origin};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::fsutil::{mkdir_private, write_private_atomic};
use crate::project::{CmdResult, Exit, fail, quiet_error};
use crate::terminal::{self, PromptError};
use crate::ui::{self, BoxStyle, Palette};

pub const GITIGNORE_CONTENT: &str = "# kv \u{2014} encrypted secrets management
# The key file must NEVER be committed
key
run_grants.json
approval_signing_key
capability_tokens.json
approval_requests.json
policy_requests.json
storage.lock

# Encrypted secret data may be committed only while the key remains private
!*.enc
!*.kvi
!*.kvs
!drawers/
!drawers/**

# Configuration and its owner approval are local authority, never shared
/config.json
/config-authority
/vault-marker

# Local migration recovery material is encrypted but history-bearing
migration-backups/

# Stable writer lock and private atomic-write residue are never versioned
/config.lock
/.kv-write-*.tmp
/key-config.pending
";

const CANCEL_INPUTS: &[&str] = &["q", "quit", "exit"];

fn is_cancel_input(value: &str) -> bool {
    CANCEL_INPUTS.contains(&value.trim().to_lowercase().as_str())
}

fn prompt_failure(p: &Palette, error: PromptError) -> Exit {
    match error {
        PromptError::Eof => quiet_error(p, ""),
        PromptError::Refused(msg) => quiet_error(p, &msg),
        PromptError::Io(e) => quiet_error(p, &e.to_string()),
    }
}

/// `os.path.abspath`: absolute and normalized, nothing resolved.
fn abspath(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut out = PathBuf::new();
    for part in joined.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn expanduser(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix('~')
        && (rest.is_empty() || rest.starts_with('/'))
        && let Some(home) = home_dir()
    {
        return home.join(rest.trim_start_matches('/'));
    }
    PathBuf::from(path)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn is_within(path: &Path, parent: &Path) -> bool {
    abspath(path).starts_with(abspath(parent))
}

fn prompt_choice(p: &Palette, prompt: &str, choices: &[&str]) -> CmdResult<Option<String>> {
    loop {
        let choice = match terminal::input(prompt) {
            Ok(text) => text.trim().to_owned(),
            Err(PromptError::Eof) => return Ok(None),
            Err(e) => return Err(prompt_failure(p, e)),
        };
        if choice.is_empty() || is_cancel_input(&choice) {
            return Ok(None);
        }
        if choices.contains(&choice.as_str()) {
            return Ok(Some(choice));
        }
        ui::warn(p, &format!("choose one of: {}", choices.join(", ")));
    }
}

fn prompt_cancelable_text(p: &Palette, prompt: &str) -> CmdResult<Option<String>> {
    match terminal::input(prompt) {
        Ok(text) => {
            let value = text.trim().to_owned();
            Ok((!value.is_empty() && !is_cancel_input(&value)).then_some(value))
        }
        Err(PromptError::Eof) => Ok(None),
        Err(e) => Err(prompt_failure(p, e)),
    }
}

struct Target {
    location: String,
    root: PathBuf,
    workspace: PathBuf,
}

fn resolve_init_target(
    p: &Palette,
    location: Option<&str>,
    path: Option<&str>,
) -> CmdResult<Target> {
    let workspace = std::env::current_dir()
        .map(|d| abspath(&d))
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let home = abspath(&home_dir().unwrap_or_else(|| PathBuf::from("~")));
    if path.is_some() && !matches!(location, None | Some("custom")) {
        return Err(fail(p, "--path requires --location custom"));
    }
    let mut custom_path = path.map(str::to_owned);
    let location = match location {
        Some(location) => location.to_owned(),
        None => {
            if !terminal::stdin_is_tty() {
                ui::error(
                    p,
                    "kv init needs an explicit vault location in non-interactive mode",
                );
                ui::info(&format!(
                    "{}use one of: kv init --location global | project | custom --path PATH{}",
                    p.dim, p.reset
                ));
                return Err(Exit(1));
            }
            ui::out(&format!(
                "  {}Where should your vault live?{}",
                p.white, p.reset
            ));
            ui::info(&format!(
                "  {}1{}  Global       {}shared from {}/.secrets{}",
                p.yellow,
                p.reset,
                p.dim,
                home.display(),
                p.reset
            ));
            ui::info(&format!(
                "  {}2{}  This project {}scoped to {}{}",
                p.yellow,
                p.reset,
                p.dim,
                workspace.display(),
                p.reset
            ));
            ui::info(&format!(
                "  {}3{}  Custom       {}choose your own root path{}",
                p.yellow, p.reset, p.dim, p.reset
            ));
            ui::blank();
            let choice = prompt_choice(
                p,
                &format!("  {}Choose [1-3], or Enter/q to cancel:{} ", p.dim, p.reset),
                &["1", "2", "3"],
            )?;
            let Some(choice) = choice else {
                ui::info("cancelled");
                return Err(Exit(0));
            };
            ui::blank();
            match choice.as_str() {
                "1" => "global",
                "2" => "project",
                _ => "custom",
            }
            .to_owned()
        }
    };
    let root = match location.as_str() {
        "global" => home,
        "project" => workspace.clone(),
        "custom" => {
            if custom_path.is_none() {
                if !terminal::stdin_is_tty() {
                    return Err(fail(
                        p,
                        "--location custom requires --path in non-interactive mode",
                    ));
                }
                custom_path = prompt_cancelable_text(
                    p,
                    &format!("  {}Path{} (Enter/q to cancel): ", p.yellow, p.reset),
                )?;
                ui::blank();
            }
            let Some(custom) = custom_path else {
                ui::info("cancelled");
                return Err(Exit(0));
            };
            if custom.trim().is_empty() {
                return Err(fail(p, "custom vault path cannot be empty"));
            }
            abspath(&expanduser(&custom))
        }
        other => return Err(fail(p, &format!("unknown init location: {other}"))),
    };
    if root.exists() && !root.is_dir() {
        return Err(fail(
            p,
            &format!("target path is not a directory: {}", root.display()),
        ));
    }
    Ok(Target {
        location,
        root,
        workspace,
    })
}

fn print_location_summary(p: &Palette, target: &Target) {
    let secrets_path = target.root.join(".secrets");
    let root = target.root.display();
    match target.location.as_str() {
        "global" => {
            ui::info(&format!("{}Global vault{}", p.white, p.reset));
            ui::info(&format!(
                "  Secrets will live at {}{}{}",
                p.green,
                secrets_path.display(),
                p.reset
            ));
            ui::info(&format!(
                "  Projects under {}{root}{} can discover this vault automatically.",
                p.dim, p.reset
            ));
            if !is_within(&target.workspace, &target.root) {
                ui::warn(
                    p,
                    &format!(
                        "your current workspace is outside {root}; it will not discover this vault automatically"
                    ),
                );
            }
        }
        "project" => {
            ui::info(&format!("{}Project vault{}", p.white, p.reset));
            ui::info(&format!(
                "  Secrets will live at {}{}{}",
                p.green,
                secrets_path.display(),
                p.reset
            ));
            ui::info("  Only this directory and its subdirectories will use this vault.");
        }
        _ => {
            ui::info(&format!("{}Custom vault{}", p.white, p.reset));
            ui::info(&format!(
                "  Secrets will live at {}{}{}",
                p.green,
                secrets_path.display(),
                p.reset
            ));
            ui::info(&format!(
                "  Projects under {}{root}{} can discover this vault automatically.",
                p.dim, p.reset
            ));
            if !is_within(&target.workspace, &target.root) {
                ui::warn(
                    p,
                    "your current workspace is outside the custom root; choose a parent path if you want this project to use it",
                );
            }
        }
    }
    ui::blank();
}

/// `_prompt_new_passphrase()`.
pub fn prompt_new_passphrase(
    p: &Palette,
    first_label: &str,
    confirm_label: &str,
) -> CmdResult<Zeroizing<String>> {
    let passphrase = terminal::getpass(&format!("  {}{first_label}{}: ", p.yellow, p.reset))
        .map(Zeroizing::new)
        .map_err(|e| prompt_failure(p, e))?;
    if passphrase.is_empty() {
        return Err(fail(p, "passphrase is required for new vaults"));
    }
    let confirm = terminal::getpass(&format!("  {}{confirm_label}{}:    ", p.yellow, p.reset))
        .map(Zeroizing::new)
        .map_err(|e| prompt_failure(p, e))?;
    if *passphrase != *confirm {
        return Err(fail(p, "passphrases don't match"));
    }
    let (ok, reason) = passphrase_strength(&passphrase);
    if !ok {
        return Err(fail(p, reason));
    }
    Ok(passphrase)
}

fn default_http_policy() -> Value {
    let mut policy = Map::new();
    for (name, origin, secret) in [
        ("openai", "https://api.openai.com", "OPENAI_API_KEY"),
        (
            "anthropic",
            "https://api.anthropic.com",
            "ANTHROPIC_API_KEY",
        ),
        (
            "google",
            "https://generativelanguage.googleapis.com",
            "GOOGLE_API_KEY",
        ),
        ("github", "https://api.github.com", "GITHUB_TOKEN"),
        (
            "google-cloud",
            "https://www.googleapis.com",
            "GOOGLE_CLOUD_API_KEY",
        ),
    ] {
        policy.insert(
            name.to_owned(),
            json!({"origin": origin, "secret_name": secret, "rules": []}),
        );
    }
    Value::Object(policy)
}

fn io_fail(p: &Palette, what: &str, error: impl std::fmt::Display) -> Exit {
    quiet_error(p, &format!("{what}: {error}"))
}

/// `config._init_project(root, passphrase, wrap_master_key=True, storage_format="drawers")`.
fn init_project(p: &Palette, root: &Path, passphrase: &str) -> CmdResult<Key32> {
    let sdir = root.join(".secrets");
    if std::fs::symlink_metadata(&sdir).is_ok() {
        return Err(quiet_error(
            p,
            &format!("already initialized: {}", sdir.display()),
        ));
    }
    if !root.exists() {
        std::fs::create_dir_all(root).map_err(|e| io_fail(p, "cannot create the vault root", e))?;
    }
    mkdir_private(&sdir).map_err(|e| io_fail(p, "cannot create .secrets", e))?;
    vault_origin::record_created(root).map_err(|e| quiet_error(p, &e.to_string()))?;
    write_private_atomic(&sdir.join(".gitignore"), GITIGNORE_CONTENT.as_bytes())
        .map_err(|e| io_fail(p, "cannot write .gitignore", e))?;
    let mut master_bytes = Zeroizing::new([0u8; 32]);
    let mut owner_seed = Zeroizing::new([0u8; 32]);
    let mut approval_id = [0u8; 16];
    getrandom::getrandom(master_bytes.as_mut())
        .and_then(|()| getrandom::getrandom(owner_seed.as_mut()))
        .and_then(|()| getrandom::getrandom(&mut approval_id))
        .map_err(|e| io_fail(p, "cannot read randomness", e))?;
    let location =
        config_authority::canonical_location(root).map_err(|e| quiet_error(p, &e.to_string()))?;
    let identity = Identity {
        master_key: Key32::new(*master_bytes),
        owner_seed,
        local_approval_id: approval_id,
        location: location.clone(),
    };
    let blob = keyfile::wrap_v4(&identity, passphrase.as_bytes(), &location, None)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    write_private_atomic(&sdir.join("key"), &blob)
        .map_err(|e| io_fail(p, "cannot write the key file", e))?;
    let config = json!({
        "version": 1,
        "created": timestamp_now(),
        "default_env": "dev",
        "environments": ["dev"],
        "cipher": "chacha20-poly1305",
        "storage": {"format": "drawers"},
        "security": {"passphrase": true, "totp": false, "approval_mode": "unset"},
        "broker_policy": {"http": default_http_policy()},
    });
    write_config(&sdir, &config).map_err(|e| quiet_error(p, &e.to_string()))?;
    mkdir_private(&sdir.join("drawers")).map_err(|e| io_fail(p, "cannot create drawers", e))?;
    Ok(Key32::new(*identity.master_key.as_bytes()))
}

/// `_install_recovery_key(root, master_key)`: the token and the saved wrap.
pub fn install_recovery_key(
    p: &Palette,
    root: &Path,
    master: &Key32,
) -> CmdResult<(Zeroizing<String>, String)> {
    let token = recovery::generate()
        .map(Zeroizing::new)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    let wrap =
        recovery::wrap_master_key(master, &token).map_err(|e| quiet_error(p, &e.to_string()))?;
    let mut snapshot = load_config(root).map_err(|e| quiet_error(p, &e.to_string()))?;
    {
        let security = snapshot
            .value
            .as_object_mut()
            .and_then(|obj| {
                obj.entry("security")
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
            })
            .ok_or_else(|| quiet_error(p, "config.json security section is not an object"))?;
        security.insert("recovery".into(), Value::Bool(true));
        security.insert("recovery_key_wrap".into(), Value::String(wrap.clone()));
        security.insert("recovery_delivery_pending".into(), Value::Bool(true));
    }
    save_config(root, &mut snapshot).map_err(|e| quiet_error(p, &e.to_string()))?;
    Ok((token, wrap))
}

/// `_print_recovery_key_box(recovery_key, root=root, config=config)`.
pub fn print_recovery_key_box(
    p: &Palette,
    token: &str,
    rotated: bool,
    root: &Path,
    wrap: &str,
) -> CmdResult {
    let heading = if rotated {
        "New recovery key generated."
    } else {
        "Recovery key generated."
    };
    let mut saved = false;
    if !terminal::stdout_is_tty() {
        ui::info("standard output is not a terminal \u{2014} the recovery key was not shown");
    } else {
        ui::boxed(
            p,
            &[
                heading,
                "Store it somewhere safe now.",
                "It can reset a forgotten passphrase.",
                "Shown once \u{2014} copy it before you continue.",
            ],
            BoxStyle::Warn,
        );
        ui::blank();
        ui::out(&format!("  {}{token}{}", p.value, p.reset));
        ui::blank();
        let reply = match terminal::input("  Type saved when you have stored the key: ") {
            Ok(reply) => Some(reply),
            Err(_) => {
                ui::blank();
                None
            }
        };
        saved = reply.as_deref().map(str::trim) == Some("saved");
        if !saved {
            ui::warn(p, "the recovery key was not marked as saved");
        }
    }
    config::config_transaction(root, |current| {
        if let Some(security) = current.get_mut("security").and_then(Value::as_object_mut)
            && saved
            && security.get("recovery_key_wrap").and_then(Value::as_str) == Some(wrap)
        {
            security.remove("recovery_delivery_pending");
        }
        Ok(())
    })
    .map_err(|e| quiet_error(p, &e.to_string()))
}

pub fn cmd_init(p: &Palette, location: Option<&str>, path: Option<&str>) -> CmdResult {
    ui::blank();
    ui::out(&format!(
        "  {}{}\u{2591}\u{2592}\u{2593} kv {}{}\u{2014} vault setup{}",
        p.bold, p.cyan, p.reset, p.dim, p.reset
    ));
    ui::blank();
    let target = resolve_init_target(p, location, path)?;
    let check_path = target.root.join(".secrets");
    if std::fs::symlink_metadata(&check_path).is_ok() {
        ui::error(p, "vault already exists at the selected location");
        ui::info(&format!("{}{}{}", p.dim, check_path.display(), p.reset));
        return Err(Exit(1));
    }
    print_location_summary(p, &target);
    ui::info("Create a passphrase to protect your vault.");
    ui::info(&format!(
        "{}This encrypts your master key at rest.{}",
        p.dim, p.reset
    ));
    ui::blank();
    let passphrase = prompt_new_passphrase(p, "Passphrase", "Confirm")?;
    let master = init_project(p, &target.root, &passphrase)?;
    let (token, wrap) = install_recovery_key(p, &target.root, &master)?;
    if let Err(_reason) = crate::registry::register_vault(&target.root, &target.location) {
        ui::warn(
            p,
            "could not update the list of vaults (~/.kv/vaults.json); the vault itself is fine",
        );
    }
    ui::blank();
    ui::success(p, "vault created");
    ui::info(&format!(
        "{}Vault{}      {}",
        p.yellow,
        p.reset,
        check_path.display()
    ));
    if target.root != target.workspace {
        ui::info(&format!(
            "{}Workspace{}  {}",
            p.yellow,
            p.reset,
            target.workspace.display()
        ));
    }
    ui::blank();
    print_recovery_key_box(p, &token, false, &target.root, &wrap)?;
    ui::blank();
    ui::info(&format!("{}Quick start:{}", p.white, p.reset));
    ui::cmd(p, "kv unlock", "Open your vault");
    ui::cmd(p, "kv set API_KEY", "Store a secret");
    ui::cmd(
        p,
        "kv run --no-secrets -- python app.py",
        "Run ordinary work without vault secrets",
    );
    ui::blank();
    ui::info(&format!("{}HTTP API policy:{}", p.white, p.reset));
    ui::info("  New vaults deny every kv_api route.");
    ui::info(&format!(
        "  Before using kv_api, add an exact rule with {}kv policy http add{} (it is saved in {}{}{}).",
        p.green,
        p.reset,
        p.green,
        check_path.join("config.json").display(),
        p.reset
    ));
    ui::info("  Review with kv vault approve-config, then start or restart the daemon.");
    ui::blank();
    ui::info(&format!("{}Environments:{}", p.white, p.reset));
    ui::info(&format!(
        "  You have one environment: {}dev{} (default)",
        p.green, p.reset
    ));
    ui::info(&format!(
        "  {}Create more: kv env create work{}",
        p.dim, p.reset
    ));
    ui::blank();
    Ok(())
}
