//! `kv unlock`, `kv lock`, `kv status`: Python `cmd_unlock`, `cmd_lock`, `cmd_status`.
//!
//! The daemon is `kv_agent::run_agent` in this same binary: `kv unlock` forks it into
//! the background (or runs it in the foreground with `-f`), `kv lock` asks it to lock
//! and then stops it by signal, exactly as the Python CLI does.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use zeroize::Zeroizing;

#[cfg(unix)]
use kv_agent::START_REFUSAL_PREFIX;
use kv_agent::{TrustContext, run_agent};
use kv_crypto::Key32;
use kv_store::{DrawerStore, config_authority, envname};

use crate::project::{
    self, CmdResult, Exit, agent_request, config_value, is_agent_running, quiet_error,
    require_project, secrets_dir,
};
use crate::terminal;
use crate::ui::{self, Palette};

/// `_STOP_FALLBACK_WAIT_SECONDS`.
const STOP_FALLBACK_WAIT: Duration = Duration::from_secs(5);
/// `_await_background_start(bound=10.0)`.
const BACKGROUND_START_BOUND: Duration = Duration::from_secs(10);

fn dot_on(p: &Palette) -> String {
    format!("{}\u{25cf}{}", p.green, p.reset)
}

fn dot_off(p: &Palette) -> String {
    format!("{}\u{25cb}{}", p.muted, p.reset)
}

fn plural(n: usize) -> &'static str {
    if n != 1 { "s" } else { "" }
}

fn status_request(root: &Path) -> Option<Value> {
    let reply = agent_request(root, "status", Map::new())?;
    (reply.is_object() && reply.get("error").is_none()).then_some(reply)
}

/// `enforcement_is_current(reply)`.
fn enforcement_is_current(reply: &Value) -> bool {
    reply
        .get("enforcement")
        .and_then(Value::as_u64)
        .is_some_and(|value| value >= kv_proto::ENFORCEMENT_GENERATION)
}

/// `_agent_secret_cache_label(status)`.
fn cache_label(status: &Value) -> String {
    let secrets = status
        .get("cached_secrets")
        .or_else(|| status.get("secrets"))
        .cloned()
        .unwrap_or_else(|| Value::String("?".into()));
    let sec_part = match secrets.as_u64() {
        Some(n) => format!("{n} secret{}", plural(n as usize)),
        None => format!("{} secrets", project::py_text(&secrets)),
    };
    match status.get("cached_environments").and_then(Value::as_u64) {
        Some(n) => format!("{sec_part} cached across {n} env{}", plural(n as usize)),
        None => sec_part,
    }
}

/// `_request_lock(agent_request)`: true when the service confirmed every pass ended.
fn request_lock(root: &Path) -> bool {
    agent_request(root, "lock", Map::new()).is_some_and(|answer| {
        answer.get("locking") == Some(&Value::Bool(true))
            && answer.get("ended") == Some(&Value::Bool(true))
    })
}

/// `_stop_service_by_signal(pid, agent_request)` without pidfds: the service is asked
/// again for its pid just before the TERM, and "gone" means `kill(pid, 0)` finds nothing.
#[cfg(unix)]
fn stop_service_by_signal(root: &Path, pid: i64) -> bool {
    use rustix::process::{Pid, Signal, kill_process, test_kill_process};
    let Some(target) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return false;
    };
    let again = status_request(root).and_then(|s| s.get("pid")?.as_i64());
    if again != Some(pid) {
        return false;
    }
    if kill_process(target, Signal::TERM).is_err() {
        return false;
    }
    let end = Instant::now() + STOP_FALLBACK_WAIT;
    while Instant::now() < end {
        if test_kill_process(target) == Err(rustix::io::Errno::SRCH) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg(not(unix))]
fn stop_service_by_signal(_root: &Path, _pid: i64) -> bool {
    false
}

fn service_files_present(root: &Path) -> bool {
    [
        kv_proto::agent_pid_path(Some(root)),
        kv_proto::agent_token_path(Some(root)),
        kv_proto::agent_socket_path(Some(root)),
    ]
    .into_iter()
    .any(|path| path.is_ok_and(|path| std::fs::symlink_metadata(path).is_ok()))
}

// ── kv unlock ─────────────────────────────────────────────────────────────

/// The hidden child of a background `kv unlock`: the parent has already verified the
/// passphrase at the terminal and hands it over on stdin, so nothing here prompts.
pub const AGENT_CHILD: &str = "__agent-child";

struct Unlocked {
    store: Arc<DrawerStore>,
    master: Key32,
    trust: TrustContext,
}

/// The silent half of `_agent_unlock()`: key file, config authority, trust context.
fn open_for_agent(
    root: &Path,
    identity: &kv_crypto::Identity,
    passphrase: &[u8],
) -> Result<(Unlocked, bool), String> {
    let master = Key32::new(*identity.master_key.as_bytes());
    config_authority::require_approved(root, &master).map_err(|e| e.to_string())?;
    let trust = TrustContext::at_unlock(root, Some(passphrase), &master)
        .map_err(|e| format!("cannot establish the daemon's trust context: {}", e.0))?;
    let protected = trust.protected;
    let store = Arc::new(DrawerStore::open(
        secrets_dir(root),
        Key32::new(*identity.master_key.as_bytes()),
    ));
    Ok((
        Unlocked {
            store,
            master,
            trust,
        },
        protected,
    ))
}

/// `_agent_unlock()`: passphrase at the terminal, the config authority check and the
/// daemon's trust context. Returns the passphrase too, for the background child.
fn agent_unlock(p: &Palette, root: &Path) -> CmdResult<(Unlocked, Zeroizing<String>)> {
    if !terminal::stdin_is_tty() {
        ui::error(p, "kv unlock requires a terminal for passphrase input");
        ui::info(&format!(
            "{}run this from an interactive terminal, not a script or MCP{}",
            p.dim, p.reset
        ));
        return Err(Exit(1));
    }
    let config = config_value(p, root)?;
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
    ui::header(p, &format!("agent unlock ({lock_type})"));
    ui::blank();
    if has_totp {
        return Err(quiet_error(
            p,
            "two-factor unlock is not supported by this build yet; use the Python kv for this vault",
        ));
    }
    let (identity, passphrase) = project::prompt_verified_passphrase(p, root)?;
    let (unlocked, protected) =
        open_for_agent(root, &identity, passphrase.as_bytes()).map_err(|m| quiet_error(p, &m))?;
    if protected {
        let shown: String = unlocked.trust.owner_key_id.chars().take(12).collect();
        ui::info(&format!(
            "{}protected session (owner key {shown}){}",
            p.dim, p.reset
        ));
    } else {
        ui::warn(
            p,
            "UNPROTECTED session: this vault has no passphrase-protected v3/v4 key; approvals are refused",
        );
    }
    Ok((unlocked, passphrase))
}

pub fn cmd_unlock(p: &Palette, foreground: bool, install: bool) -> CmdResult {
    let root = require_project(p)?;
    if is_agent_running(&root) {
        let status = status_request(&root);
        match &status {
            Some(status) if !enforcement_is_current(status) => {
                let pid = status.get("pid").and_then(Value::as_i64);
                let shown = pid.map_or_else(|| "None".to_owned(), |n| n.to_string());
                ui::header(
                    p,
                    &format!(
                        "a kv service started before this kv update is running (PID {shown}); replacing it"
                    ),
                );
                let mut stopped = false;
                if let Some(pid) = pid.filter(|n| *n > 0) {
                    request_lock(&root);
                    stopped = stop_service_by_signal(&root, pid);
                }
                if !stopped {
                    ui::error(
                        p,
                        &format!(
                            "the older kv service is not proven stopped (PID {shown}), so nothing was started"
                        ),
                    );
                    ui::info(&format!(
                        "{}it was told to stop; run 'kv lock' again to check; see 'kv agent status'{}",
                        p.dim, p.reset
                    ));
                    return Err(Exit(1));
                }
                ui::info(&format!(
                    "{}the older service stopped; starting the current one{}",
                    p.dim, p.reset
                ));
            }
            _ => {
                let label = status
                    .as_ref()
                    .map_or_else(|| "? secrets".to_owned(), cache_label);
                ui::header(
                    p,
                    &format!("vault is already unlocked {}({label}){}", p.dim, p.reset),
                );
                ui::blank();
                return Ok(());
            }
        }
    }
    if install {
        return Err(quiet_error(
            p,
            "kv unlock --install is only for a vault without a passphrase; this vault has one",
        ));
    }
    let (unlocked, passphrase) = agent_unlock(p, &root)?;
    if foreground {
        drop(passphrase);
        run_agent(&root, unlocked.store, unlocked.master, unlocked.trust)
            .map_err(|e| quiet_error(p, &e.0))?;
        return Ok(());
    }
    drop(unlocked);
    start_background(p, &root, &passphrase)
}

/// `kv __agent-child`: run the daemon for the vault in the current folder with the
/// passphrase read from stdin. A start refusal is printed on stdout for the parent.
pub fn cmd_agent_child(p: &Palette) -> CmdResult {
    use std::io::Read;
    let root = require_project(p)?;
    let mut passphrase = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut passphrase)
        .map_err(|e| quiet_error(p, &e.to_string()))?;
    if passphrase.ends_with('\n') {
        passphrase.pop();
    }
    let (unlocked, _) = project::unlock_identity(&root, passphrase.as_bytes())
        .and_then(|identity| open_for_agent(&root, &identity, passphrase.as_bytes()))
        .map_err(|m| {
            println!("{m}");
            Exit(1)
        })?;
    drop(passphrase);
    run_agent(&root, unlocked.store, unlocked.master, unlocked.trust).map_err(|e| {
        println!("{}", e.0);
        Exit(1)
    })?;
    Ok(())
}

/// The background start: this same binary as a detached child in its own process
/// group, stdin the passphrase, stdout the refusal channel, stderr closed.
#[cfg(unix)]
fn start_background(p: &Palette, root: &Path, passphrase: &str) -> CmdResult {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe =
        std::env::current_exe().map_err(|e| quiet_error(p, &format!("failed to unlock: {e}")))?;
    let mut child = Command::new(exe)
        .arg(AGENT_CHILD)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| quiet_error(p, &format!("failed to unlock: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(passphrase.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let (started, refusal) = await_background_start(root, &mut child);
    if started {
        ui::blank();
        ui::success(p, "vault unlocked");
        ui::info(&format!("{}close with: kv lock{}", p.dim, p.reset));
        ui::blank();
    } else {
        if let Some(refusal) = refusal {
            ui::error(p, &refusal);
        }
        ui::error(p, "failed to unlock");
    }
    Ok(())
}

#[cfg(not(unix))]
fn start_background(p: &Palette, _root: &Path, _passphrase: &str) -> CmdResult {
    Err(quiet_error(
        p,
        "background unlock is not supported on this platform yet; use kv unlock --foreground",
    ))
}

/// `_await_background_start(refusal_read)`: `(true, None)` once the daemon answers;
/// `(false, refusal)` once the child refused or ended, or the bound passed.
#[cfg(unix)]
fn await_background_start(root: &Path, child: &mut std::process::Child) -> (bool, Option<String>) {
    use std::io::Read;
    let deadline = Instant::now() + BACKGROUND_START_BOUND;
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if is_agent_running(root) {
            return (true, None);
        }
        if child.try_wait().ok().flatten().is_some() {
            let mut text = String::new();
            if let Some(mut out) = child.stdout.take() {
                let _ = out.read_to_string(&mut text);
            }
            let text = text.trim_end().to_owned();
            return (
                false,
                text.starts_with(START_REFUSAL_PREFIX).then_some(text),
            );
        }
        if Instant::now() >= deadline {
            return (false, None);
        }
    }
}

// ── kv lock ───────────────────────────────────────────────────────────────

pub fn cmd_lock(p: &Palette) -> CmdResult {
    let root = require_project(p)?;
    if !is_agent_running(&root) {
        ui::header(p, "vault is already locked");
        if service_files_present(&root) {
            ui::info(&format!(
                "{}service files are in the runtime folder \u{2014} a stopped service can leave them; 'kv unlock' tries to start a fresh one and write its files over what was left{}",
                p.dim, p.reset
            ));
        }
        ui::blank();
        return Ok(());
    }
    let Some(status) = agent_request(&root, "status", Map::new()) else {
        ui::error(p, "could not lock: the service did not answer");
        return Ok(());
    };
    let Some(pid) = status
        .get("pid")
        .and_then(Value::as_i64)
        .filter(|n| *n != 0)
    else {
        ui::error(p, "could not determine agent PID");
        return Ok(());
    };
    let confirmed = request_lock(&root);
    if !stop_service_by_signal(&root, pid) {
        ui::header(
            p,
            if confirmed {
                "every pass was ended, but the lock is not confirmed: the service has not stopped yet"
            } else {
                "the lock is not confirmed: the service has not stopped yet"
            },
        );
        ui::info(&format!(
            "{}it was told to stop (PID {pid}); run 'kv lock' again to check; see 'kv agent status'{}",
            p.dim, p.reset
        ));
        ui::blank();
        return Ok(());
    }
    ui::blank();
    ui::success(p, "vault locked");
    ui::info(&format!("{}secrets cleared from memory{}", p.dim, p.reset));
    ui::blank();
    Ok(())
}

// ── kv status ─────────────────────────────────────────────────────────────

struct StorageHealth {
    format: String,
    level: &'static str,
    messages: Vec<String>,
}

/// `storage_health.inspect_storage_health(root)` for the formats this build knows.
fn inspect_storage_health(root: &Path, config: &Value) -> StorageHealth {
    let sdir = secrets_dir(root);
    let format = config
        .get("storage")
        .and_then(|s| s.get("format"))
        .and_then(Value::as_str)
        .unwrap_or("env-bundle")
        .to_owned();
    if format != "drawers" {
        return StorageHealth {
            format: format.clone(),
            level: "recovery-needed",
            messages: vec![format!("Unsupported storage format: {format}.")],
        };
    }
    let drawers = std::fs::symlink_metadata(sdir.join("drawers")).is_ok();
    let env_bundles = std::fs::read_dir(&sdir).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().ends_with(".enc"))
    });
    let backups = std::fs::read_dir(sdir.join("migration-backups"))
        .is_ok_and(|mut entries| entries.next().is_some());
    let mut level = "clean";
    let mut messages =
        vec!["Storage uses drawer format; legacy raw cloud sync is blocked.".to_owned()];
    if !drawers {
        level = "recovery-needed";
        messages = vec![
            "Config says drawers but no drawer artifacts were found; storage may be incomplete."
                .to_owned(),
            "Run kv doctor and use a verified migration backup if recovery is needed.".to_owned(),
        ];
    } else if env_bundles {
        messages.push("Legacy .enc bundles are retained as rollback material.".to_owned());
    }
    if backups {
        messages.push("Migration backup material is present.".to_owned());
    }
    StorageHealth {
        format,
        level,
        messages,
    }
}

fn storage_marker(p: &Palette, level: &str) -> String {
    match level {
        "clean" => dot_on(p),
        "recovery-needed" => format!("{}\u{2717}{}", p.red, p.reset),
        _ => format!("{}!{}", p.yellow, p.reset),
    }
}

fn print_storage(p: &Palette, health: &StorageHealth, always_messages: bool) {
    ui::info(&format!("{}Storage{}", p.white, p.reset));
    ui::info(&format!(
        "  {} {}  {}\u{2014} {}; raw sync blocked{}",
        storage_marker(p, health.level),
        health.format,
        p.dim,
        health.level,
        p.reset
    ));
    if always_messages || health.level != "clean" {
        for message in &health.messages {
            ui::info(&format!("    {}{message}{}", p.dim, p.reset));
        }
    }
}

/// `_print_approval_inbox_counts(root)`: pending and missed requests in
/// `.secrets/approval_requests.json`.
fn print_approval_inbox(p: &Palette, root: &Path) {
    // `_print_approval_inbox_counts`: pending and missed requests by their effective
    // status (expiry, approval, denial and withdrawal included), read as the store is.
    let requests = match kv_requests::approvals::list_approval_requests(root, false, true, None) {
        Ok(requests) => requests,
        Err(_) => {
            ui::info(&format!(
                "  {}?{} approval inbox unreadable {}\u{2014} kv approvals{}",
                p.yellow, p.reset, p.dim, p.reset
            ));
            return;
        }
    };
    let pending = requests
        .iter()
        .filter(|r| r.get("effective_status").and_then(Value::as_str) == Some("pending"))
        .count();
    let missed = requests.len() - pending;
    let marker = if requests.is_empty() {
        dot_on(p)
    } else {
        format!("{}!{}", p.yellow, p.reset)
    };
    ui::info(&format!(
        "  {marker} approval inbox: {pending} pending, {missed} missed {}\u{2014} kv approvals{}",
        p.dim, p.reset
    ));
}

/// `_agent_memory_hardening_label(status)`.
fn memory_hardening_label(status: &Value) -> (bool, String) {
    let hardening = status.get("memory_hardening").filter(|v| v.is_object());
    let text = |key: &str| {
        hardening
            .and_then(|h| h.get(key))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let flag = |key: &str| {
        hardening
            .and_then(|h| h.get(key))
            .is_some_and(|v| v.as_bool() == Some(true))
    };
    let method = text("method").unwrap_or_else(|| "not reported".to_owned());
    if flag("enabled") {
        if flag("verified") {
            return (true, method);
        }
        let reason = text("reason").unwrap_or_else(|| "verification unavailable".to_owned());
        return (true, format!("{method}; {reason}"));
    }
    (
        false,
        text("reason").unwrap_or_else(|| "not reported by daemon".to_owned()),
    )
}

/// `_agent_http_policy_label(status)`.
fn http_policy_label(status: &Value) -> String {
    let Some(policy) = status.get("http_policy").and_then(Value::as_object) else {
        return "not reported by daemon".to_owned();
    };
    if policy.is_empty() {
        return "not reported by daemon".to_owned();
    }
    let mode = if policy.get("configured").and_then(Value::as_bool) == Some(true) {
        "configured"
    } else {
        "legacy compatibility"
    };
    let count = policy
        .get("provider_count")
        .map_or_else(|| "?".to_owned(), project::py_text);
    let digest = policy
        .get("digest")
        .map_or_else(|| "?".to_owned(), project::py_text);
    let suffix = if count == "1" { "" } else { "s" };
    format!("{mode}; {count} provider{suffix}; digest {digest}")
}

pub fn cmd_status(p: &Palette) -> CmdResult {
    let root = require_project(p)?;
    let (config, config_error) = match kv_store::config::load_config(&root) {
        Ok(snapshot) => (snapshot.value, None),
        Err(error) => (Value::Object(Map::new()), Some(error.to_string())),
    };
    let envs: Vec<String> = config
        .get("environments")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(project::py_text).collect())
        .unwrap_or_default();
    let security = config.get("security").cloned().unwrap_or(Value::Null);
    let key_exists = std::fs::metadata(project::key_path(&root)).is_ok_and(|m| m.is_file());
    let wrapped = key_exists;
    let unlocked = is_agent_running(&root);
    ui::header(p, "status");
    ui::blank();
    if let Some(error) = &config_error {
        ui::error(p, &format!("Config metadata unreadable: {error}"));
        ui::blank();
    }
    let mut agent_status = None;
    if unlocked {
        ui::out(&format!(
            "  {} {}vault unlocked{} \u{2014} agent running",
            dot_on(p),
            p.bold,
            p.reset
        ));
        agent_status = status_request(&root);
        if let Some(status) = &agent_status
            && !enforcement_is_current(status)
        {
            ui::warn(
                p,
                "this kv service was started before this kv update and does not enforce its current rules; 'kv unlock' replaces it",
            );
        }
    } else if wrapped {
        ui::out(&format!(
            "  {} {}vault locked{}",
            dot_off(p),
            p.bold,
            p.reset
        ));
    } else {
        ui::out(&format!(
            "  {}\u{2717}{} {}no key found{}",
            p.red, p.reset, p.bold, p.reset
        ));
    }
    ui::blank();
    ui::info(&format!("{}Security{}", p.white, p.reset));
    if wrapped {
        ui::info(&format!("  {} passphrase", dot_on(p)));
    }
    if config_error.is_some() {
        let q = format!("{}?{}", p.yellow, p.reset);
        ui::info(&format!("  {q} 2FA unknown (config unreadable)"));
        if wrapped {
            ui::info(&format!("  {q} recovery key unknown (config unreadable)"));
        }
        ui::info(&format!("  {q} approval mode unknown (config unreadable)"));
        ui::blank();
        print_storage(p, &inspect_storage_health(&root, &config), true);
        return Err(Exit(1));
    }
    let truthy = |key: &str| {
        security
            .get(key)
            .is_some_and(|v| !matches!(v, Value::Null | Value::Bool(false)) && v != &Value::from(0))
    };
    if truthy("totp") {
        ui::info(&format!(
            "  {} 2FA {}\u{2014} kv's own prompts ask for a code; the key is locked by your passphrase alone{}",
            dot_on(p),
            p.dim,
            p.reset
        ));
        match security.get("backup_codes") {
            Some(codes) if !matches!(codes, Value::Null | Value::Bool(false)) => {
                let remaining = codes
                    .get("codes")
                    .and_then(Value::as_array)
                    .map_or(0, |list| {
                        list.iter()
                            .filter(|c| c.get("used").and_then(Value::as_bool) != Some(true))
                            .count()
                    });
                let label = if remaining == 1 { "code" } else { "codes" };
                ui::info(&format!(
                    "  {} backup codes {}\u{2014} {remaining} {label} remaining{}",
                    dot_on(p),
                    p.dim,
                    p.reset
                ));
            }
            _ => ui::info(&format!(
                "  {} backup codes {}\u{2014} kv 2fa backup-codes rotate{}",
                dot_off(p),
                p.dim,
                p.reset
            )),
        }
    } else {
        ui::info(&format!(
            "  {} 2FA {}\u{2014} kv 2fa enable{}",
            dot_off(p),
            p.dim,
            p.reset
        ));
    }
    if wrapped && truthy("recovery_key_wrap") {
        ui::info(&format!("  {} recovery key", dot_on(p)));
    } else if wrapped {
        ui::info(&format!(
            "  {} recovery key {}\u{2014} kv recovery-key rotate{}",
            dot_off(p),
            p.dim,
            p.reset
        ));
    }
    crate::owner_policy::print_approval_mode(p, &config);
    print_approval_inbox(p, &root);
    if let Some(status) = &agent_status {
        let (ok, label) = memory_hardening_label(status);
        let marker = if ok {
            dot_on(p)
        } else {
            format!("{}!{}", p.yellow, p.reset)
        };
        ui::info(&format!(
            "  {marker} daemon memory hardening {}\u{2014} {label}{}",
            p.dim, p.reset
        ));
    }
    ui::blank();
    print_storage(p, &inspect_storage_health(&root, &config), false);
    ui::blank();
    ui::info(&format!("{}Sync{}", p.white, p.reset));
    ui::info(&format!(
        "  {}!{} drawer sync not initialized {}\u{2014} kv sync init{}",
        p.yellow, p.reset, p.dim, p.reset
    ));
    ui::info(&format!(
        "    {}Run kv sync init to create a local drawer sync identity.{}",
        p.dim, p.reset
    ));
    ui::blank();
    ui::info(&format!("{}Environments{}", p.white, p.reset));
    let (valid, invalid): (Vec<&String>, Vec<&String>) = envs
        .iter()
        .partition(|name| !envname::has_path_syntax(name));
    for env in &invalid {
        ui::warn(p, &format!("'{env}' (invalid registration; unavailable)"));
    }
    if !invalid.is_empty() {
        ui::info("Run 'kv env repair-names' to preview config-only recovery.");
    }
    if unlocked {
        let mut counts = Vec::with_capacity(valid.len());
        for env in &valid {
            let mut fields = Map::new();
            fields.insert("env".into(), Value::String((*env).clone()));
            let count = agent_request(&root, "list", fields)
                .filter(|reply| reply.get("error").is_none())
                .and_then(|reply| reply.get("keys")?.as_array().map(Vec::len));
            counts.push(count);
        }
        if counts.iter().all(Option::is_some) {
            for (env, count) in valid.iter().zip(counts) {
                let count = count.unwrap_or(0);
                ui::info(&format!(
                    "  {} {}{env}{}  {}{count} secret{}{}",
                    dot_on(p),
                    p.green,
                    p.reset,
                    p.dim,
                    plural(count),
                    p.reset
                ));
            }
        } else {
            for env in &valid {
                ui::info(&format!("  {} {}{env}{}", dot_on(p), p.green, p.reset));
            }
        }
    } else {
        for env in &valid {
            ui::info(&format!(
                "  {} {env}  {}(locked){}",
                dot_off(p),
                p.dim,
                p.reset
            ));
        }
    }
    ui::blank();
    if let Some(status) = &agent_status {
        ui::info(&format!("{}Loaded broker authority{}", p.white, p.reset));
        let providers = status
            .get("providers")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(project::py_text)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "(none)".to_owned());
        ui::info(&format!(
            "  {}Providers{}    {providers}",
            p.yellow, p.reset
        ));
        ui::info(&format!(
            "  {}Run policy{}   {}",
            p.yellow,
            p.reset,
            status
                .get("policy")
                .map_or_else(|| "?".to_owned(), project::py_text)
        ));
        ui::info(&format!(
            "  {}HTTP policy{}  {}",
            p.yellow,
            p.reset,
            http_policy_label(status)
        ));
        ui::blank();
    }
    Ok(())
}
