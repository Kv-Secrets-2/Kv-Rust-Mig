//! `kv set` / `get` / `ls` / `rm` / `export` / `envs` from `kv/cli.py`.

use std::io::Write;
use std::path::Path;

use kv_store::envname::{has_path_syntax, portable_name_key};
use serde_json::{Map, Value};

use crate::project::{self, CmdResult, Exit, fail, get_env, get_store, quiet_error};
use crate::reserved_env;
use crate::terminal::{self, PromptError};
use crate::ui::{self, Palette};

const MASK: &str = "\u{25cf}\u{25cf}\u{25cf}\u{25cf}\u{25cf}\u{25cf}\u{25cf}\u{25cf}";

/// Python `repr()` of a str for the names `cmd_envs` shows.
pub fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn prompt_failure(p: &Palette, error: PromptError) -> Exit {
    match error {
        PromptError::Eof => quiet_error(p, ""),
        PromptError::Refused(msg) => quiet_error(p, &msg),
        PromptError::Io(e) => quiet_error(p, &e.to_string()),
    }
}

fn reserved_run_env_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    if reserved_env::RESERVED_RUN_ENV_EXEMPTIONS.contains(&upper.as_str()) {
        return false;
    }
    if reserved_env::RESERVED_RUN_ENV_NAMES.contains(&upper.as_str()) {
        return true;
    }
    if let Some(middle) = upper.strip_prefix("CARGO_REGISTRIES_") {
        let token = middle.strip_suffix("_TOKEN").is_some_and(|m| {
            !m.is_empty()
                && m.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        });
        return !token;
    }
    reserved_env::RESERVED_RUN_ENV_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
}

fn plain_shell_word(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// `sandbox.run_env_save_warning(key)` for one name.
fn run_env_save_warning(key: &str) -> Option<String> {
    if !reserved_run_env_name(key) {
        return None;
    }
    let shown = crate::render::escape(key);
    let candidate = format!("MY_{}", key.to_uppercase());
    let advice = if !reserved_run_env_name(&candidate) && plain_shell_word(&candidate) {
        format!(
            "save it under another name, for example {}.",
            crate::render::escape(&candidate)
        )
    } else {
        "save it under a plain name of letters, digits and underscores.".to_owned()
    };
    Some(format!(
        "kv saved {shown}, but will not hand it to a program run through kv: programs read {shown} when they start. To pass it to a run, {advice}"
    ))
}

pub fn cmd_set(p: &Palette, secret: &str, env: Option<&str>) -> CmdResult {
    let opened = get_store(p)?;
    let env = get_env(p, env)?;
    let (key, value) = match secret.split_once('=') {
        Some((key, value)) => (key.to_owned(), zeroize::Zeroizing::new(value.to_owned())),
        None => {
            ui::out(&format!("\n  {}\u{250c} {env} \u{2510}{}", p.dim, p.reset));
            let value = terminal::getpass(&format!("  {}Value{}: ", p.yellow, p.reset))
                .map_err(|e| prompt_failure(p, e))?;
            (secret.to_owned(), zeroize::Zeroizing::new(value))
        }
    };
    if key.is_empty() {
        return Err(fail(p, "key cannot be empty"));
    }
    opened
        .vault
        .set_secret(&env, &key, &value)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    project::audit_secret_event(&opened.root, "secret_changed", &env, &key);
    ui::success(
        p,
        &format!(
            "{}{key}{}{} saved {}({env}) [encrypted]{}",
            p.bold, p.reset, p.green, p.dim, p.reset
        ),
    );
    if let Some(warning) = run_env_save_warning(&key) {
        ui::warn(p, &warning);
    }
    ui::blank();
    Ok(())
}

pub fn cmd_get(p: &Palette, key: &str, env: Option<&str>) -> CmdResult {
    let opened = get_store(p)?;
    let env = get_env(p, env)?;
    let value = opened
        .vault
        .get_secret(&env, key)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    match value {
        Some(value) => {
            ui::out(&value);
            Ok(())
        }
        None => Err(fail(p, &format!("'{key}' not found in {env}"))),
    }
}

fn print_names(p: &Palette, env: &str, names: &[String]) {
    if names.is_empty() {
        ui::header(p, &format!("{env} {}(empty){}", p.dim, p.reset));
        ui::blank();
        ui::info(&format!(
            "{}no secrets set \u{2014} add one: kv set API_KEY{}",
            p.dim, p.reset
        ));
        ui::blank();
        return;
    }
    let plural = if names.len() != 1 { "s" } else { "" };
    ui::header(p, &format!("{env} ({} secret{plural})", names.len()));
    ui::blank();
    let max_key = names.iter().map(|k| k.chars().count()).max().unwrap_or(0);
    for key in names {
        let pad = max_key + 2 - key.chars().count();
        ui::out(&format!(
            "  {}{key}{}{}{}{MASK}{}",
            p.yellow,
            " ".repeat(pad),
            p.reset,
            p.muted,
            p.reset
        ));
    }
    ui::blank();
}

pub fn cmd_ls(p: &Palette, env: Option<&str>, reveal: bool) -> CmdResult {
    let env = match env {
        Some(env) if !env.is_empty() => env.to_owned(),
        _ => {
            let root = project::require_project(p)?;
            project::default_env(&project::config_value(p, &root)?.value)
        }
    };
    if !reveal
        && let Some(root) = project::find_project_root()
        && project::is_agent_running(&root)
    {
        let mut fields = Map::new();
        fields.insert("env".into(), Value::String(env.clone()));
        if let Some(result) = project::agent_request(&root, "list", fields) {
            let names: Vec<String> = result
                .get("keys")
                .and_then(Value::as_array)
                .map(|keys| {
                    keys.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            print_names(p, &env, &names);
            return Ok(());
        }
    }
    let opened = get_store(p)?;
    let secrets = opened
        .vault
        .store
        .list_secrets(&env)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    if secrets.is_empty() {
        print_names(p, &env, &[]);
        return Ok(());
    }
    if !reveal {
        let names: Vec<String> = secrets.iter().map(|(k, _)| k.clone()).collect();
        print_names(p, &env, &names);
        return Ok(());
    }
    let plural = if secrets.len() != 1 { "s" } else { "" };
    ui::header(p, &format!("{env} ({} secret{plural})", secrets.len()));
    ui::blank();
    for (key, value) in &secrets {
        ui::kv_line(p, key, value, "");
    }
    ui::blank();
    Ok(())
}

pub fn cmd_rm(p: &Palette, key: &str, env: Option<&str>, force: bool) -> CmdResult {
    let opened = get_store(p)?;
    let env = get_env(p, env)?;
    if !force {
        let answer = terminal::input(&format!("  Remove '{key}' from {env}? [y/N] "))
            .map_err(|e| prompt_failure(p, e))?;
        let answer = answer.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            ui::info("cancelled");
            return Ok(());
        }
    }
    let removed = opened
        .vault
        .remove_secret(&env, key)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    if removed {
        project::audit_secret_event(&opened.root, "secret_removed", &env, key);
        ui::success(
            p,
            &format!(
                "removed {}{key}{}{} from {env}{}",
                p.bold, p.reset, p.green, p.reset
            ),
        );
        Ok(())
    } else {
        Err(fail(p, &format!("'{key}' not found in {env}")))
    }
}

fn quote_dotenv_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(unix)]
fn write_private_file(path: &Path, content: &str) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::OwnedFd;
    let fd: OwnedFd = rustix::fs::open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    )?;
    let st = rustix::fs::fstat(&fd)?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_file() || st.st_nlink != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "[Errno 22] not a regular file with a single name: '{}'",
                path.display()
            ),
        ));
    }
    rustix::fs::ftruncate(&fd, 0)?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)
}

pub fn cmd_export(p: &Palette, env: Option<&str>, output: Option<&str>) -> CmdResult {
    let opened = get_store(p)?;
    let env = get_env(p, env)?;
    let secrets = opened
        .vault
        .store
        .list_secrets(&env)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    if secrets.is_empty() {
        return Err(fail(p, &format!("no secrets in {env}")));
    }
    let mut sorted: Vec<&(String, zeroize::Zeroizing<String>)> = secrets.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let invalid: Vec<&str> = sorted
        .iter()
        .filter(|(k, _)| !plain_shell_word(k))
        .map(|(k, _)| k.as_str())
        .collect();
    if !invalid.is_empty() {
        let plural = if invalid.len() != 1 { "s" } else { "" };
        return Err(fail(
            p,
            &format!(
                "cannot export invalid shell variable name{plural}: {}",
                invalid.join(", ")
            ),
        ));
    }
    let mut content = String::new();
    for (key, value) in &sorted {
        content.push_str(key);
        content.push('=');
        content.push_str(&quote_dotenv_value(value));
        content.push('\n');
    }
    match output {
        Some(path) if !path.is_empty() => {
            write_private_file(Path::new(path), &content)
                .map_err(|e| quiet_error(p, &e.to_string()))?;
            ui::success(p, &format!("exported {} secrets to {path}", secrets.len()));
        }
        _ => {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(content.as_bytes());
            let _ = out.flush();
        }
    }
    Ok(())
}

/// `envname.split_environment_names`.
fn split_environment_names(names: &[String]) -> (Vec<String>, Vec<String>) {
    let mut groups: std::collections::HashMap<String, std::collections::HashSet<&str>> =
        std::collections::HashMap::new();
    for name in names {
        if !has_path_syntax(name) {
            groups
                .entry(portable_name_key(name))
                .or_default()
                .insert(name);
        }
    }
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for name in names {
        let bad = has_path_syntax(name)
            || groups
                .get(&portable_name_key(name))
                .is_some_and(|g| g.len() > 1);
        if bad {
            invalid.push(name.clone());
        } else if !valid.contains(name) {
            valid.push(name.clone());
        }
    }
    (valid, invalid)
}

pub fn cmd_envs(p: &Palette) -> CmdResult {
    let root = project::require_project(p)?;
    let names =
        kv_store::config::list_environments(&root).map_err(|e| quiet_error(p, &e.to_string()))?;
    let unlocked = project::is_agent_running(&root);
    ui::header(p, "environments");
    ui::blank();
    let (envs, invalid) = split_environment_names(&names);
    let configured_default = project::default_env(&project::config_value(p, &root)?.value);
    if has_path_syntax(&configured_default) || !envs.contains(&configured_default) {
        ui::warn(
            p,
            &format!(
                "{} (unusable default; run kv env repair-names)",
                py_repr(&configured_default)
            ),
        );
    }
    for env in &invalid {
        ui::warn(
            p,
            &format!("{} (invalid registration; unavailable)", py_repr(env)),
        );
    }
    if !invalid.is_empty() {
        ui::info("Run 'kv env repair-names' to preview config-only recovery.");
    }
    if unlocked {
        let mut failed = false;
        for env in &envs {
            let mut fields = Map::new();
            fields.insert("env".into(), Value::String(env.clone()));
            match project::agent_request(&root, "list", fields) {
                Some(result) => {
                    let count = result
                        .get("keys")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len);
                    let plural = if count != 1 { "s" } else { "" };
                    ui::info(&format!(
                        "  {} {}{env}{}  {}{count} secret{plural}{}",
                        ui::dot_on(p),
                        p.green,
                        p.reset,
                        p.dim,
                        p.reset
                    ));
                }
                None => {
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            for env in &envs {
                ui::info(&format!("  {} {}{env}{}", ui::dot_on(p), p.green, p.reset));
            }
        }
    } else {
        for env in &envs {
            ui::info(&format!(
                "  {} {env}  {}(locked){}",
                ui::dot_off(p),
                p.dim,
                p.reset
            ));
        }
    }
    ui::blank();
    ui::info(&format!("{}Commands:{}", p.dim, p.reset));
    ui::cmd(p, "kv env create <name>", "Create new environment");
    ui::cmd(p, "kv set -e <env> KEY", "Store in specific environment");
    ui::cmd(p, "kv run -e <env> CMD", "Run with specific environment");
    ui::blank();
    Ok(())
}
