//! The daemon's `run` command: Python `agent.py`'s `kv_run` path, from the
//! request's shape to the program's reply.
//!
//! Order matters and is Python's: the command is classified before anything
//! is loaded; a run with secrets or a capability needs bubblewrap, then a
//! live grant is admitted (one admission attempt, spent even if the start
//! fails later); only then are secrets selected or a token minted, and they
//! reach the target program alone, through the sealed args descriptor the
//! trusted wrapper reads — never the wrapper's own environment. The launch
//! argv is checked against the admitted approval (sandbox and network facts
//! included) and checked again after the descriptor's payload is merged in.
//! Output is redacted and the temp folders and the project folder are
//! scanned for leaked values before the reply; files the run created are
//! tracked for the Claude Code hook.
//!
//! Not here yet (later stages): approval and policy *requests* for a refused
//! run, saved passes, and the broker-handoff provider enrichment.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kv_approvals::permit_session::{NO_PASSPHRASE_REFUSAL, SessionBinding};
use kv_approvals::verify::VerifiedGrant;
use kv_crypto::Zeroizing;
use kv_grants::capabilities::{Release, capability_env_vars, require_verified, token_hash};
use kv_grants::grants::{
    Admission, GrantContext, GrantError, RunRequest, admit_run_grant, explain_run_grant_mismatch,
};
use kv_sandbox::bwrap::{
    WeakFlagReader, WrapOptions, effective_launch_argv, inject_run_env, launch_facts,
    secret_run_sandbox_error, wrap_argv,
};
use kv_sandbox::capsule::{
    RunArtifactCapsule, RunCwdCapsule, checked_run_cwd, prepare_run_artifact_capsule,
    prepare_run_cwd_capsule, private_cwd_requested,
};
use kv_sandbox::classify::{
    CommandDecision, classify_command, effective_run_mode, matches_allowlist, program_name,
    session_denial_reason,
};
use kv_sandbox::identity::{IdentityScope, build_run_identity, script_candidates};
use kv_sandbox::paths::{inside_secrets, resolve};
use kv_sandbox::redact::{redact, redaction_needles};
use kv_sandbox::runenv::{build_run_env, decode_args_bytes, expected_run_env_args};
use kv_sandbox::scan::{
    Tracking, collect_changed_files, leak_report, scan_leaked_files, scan_specific_files,
    snapshot_files, temp_scan_dirs, track_new_files,
};
use kv_sandbox::sealed::read_args_fd;
use kv_store::DrawerStore;
use serde_json::{Map, Value, json};

use crate::capture::{self, Launch, MAX_RUN_OUTPUT_BYTES};
use crate::lifecycle::{Lifecycle, WorkGuard};
use crate::runs::{Slot, new_slot};
use crate::withhold;
use crate::{SecretCache, Shared, TrustContext, stopping_latched};

/// Python `_TEMP_TRACKING_BUDGET_SECONDS`.
const TEMP_TRACKING_BUDGET: Duration = Duration::from_secs(2);
const TEMP_TRACKING_INCOMPLETE_WARNING: &str = "[SECURITY] kv could not finish checking the temp folders for files this run created: it stopped after 2 seconds because the folders are very large. Until a later run's check finishes, the kv hook refuses your agent's searches and its reads of files in the temp folders kv could not check, because kv cannot confirm which of them this run created. kv's scan for leaked secret values is separate and is not affected.";

/// What one connection hands the run path.
pub(crate) struct RunCtx<'a> {
    pub(crate) root: &'a Path,
    pub(crate) root_text: &'a str,
    pub(crate) store: &'a DrawerStore,
    pub(crate) cache: &'a Mutex<SecretCache>,
    pub(crate) trust: &'a TrustContext,
    pub(crate) approved: &'a Value,
    pub(crate) providers: &'a BTreeMap<String, Value>,
    pub(crate) audit: &'a kv_audit::Audit,
    pub(crate) lifecycle: &'a Arc<Lifecycle>,
    pub(crate) shared: &'a Shared,
    pub(crate) env: &'a str,
    pub(crate) request: &'a Map<String, Value>,
    pub(crate) known_commands: &'a [&'a str],
    /// The committed work window; closed once the program has started.
    pub(crate) work: Option<WorkGuard>,
}

/// The reply and whether it goes out on the control lane (a stop-time answer).
pub(crate) struct RunOutcome {
    pub(crate) response: Value,
    pub(crate) control: bool,
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn now_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn new_run_id() -> String {
    let mut bytes = [0u8; 12];
    getrandom::getrandom(&mut bytes).expect("operating system randomness");
    format!("run_{}", crate::hex(&bytes))
}

/// Python `_printable_run_id`.
fn printable_run_id(run_id: Option<&Value>) -> &str {
    match run_id.and_then(Value::as_str) {
        Some(id)
            if id.len() == 28
                && id.starts_with("run_")
                && id[4..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) =>
        {
            id
        }
        _ => "unknown",
    }
}

/// Python `_audit_fields`: sanitized client/session metadata.
pub(crate) fn actor_fields(request: &Map<String, Value>) -> Map<String, Value> {
    let mut fields = Map::new();
    if let Some(context) = request.get("audit_ctx").and_then(Value::as_object) {
        for (key, limit) in [
            ("source", 24),
            ("client_name", 80),
            ("client_version", 40),
            ("session_id", 80),
        ] {
            if let Some(value) = context.get(key).and_then(Value::as_str) {
                let value = value.trim();
                if !value.is_empty() {
                    fields.insert(
                        key.into(),
                        Value::String(value.chars().take(limit).collect()),
                    );
                }
            }
        }
    }
    fields
}

/// Python `_run_secret_scope_label`.
fn secret_scope_label(env_names: Option<&[String]>, capabilities: &[String]) -> &'static str {
    if !capabilities.is_empty() {
        "capability"
    } else {
        match env_names {
            Some([]) => "none",
            Some(_) => "selected",
            None => "all",
        }
    }
}

/// Python `_run_blocked_audit_fields` (count-only).
fn blocked_fields(
    scope: &str,
    env_names: Option<&[String]>,
    broker_handoff: Option<&Map<String, Value>>,
    available_secret_count: Option<usize>,
) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("secret_scope".into(), json!(scope));
    fields.insert(
        "requested_secret_count".into(),
        json!(env_names.map(<[String]>::len)),
    );
    fields.insert(
        "available_secret_count".into(),
        json!(available_secret_count),
    );
    fields.insert("injected_secret_count".into(), json!(0));
    fields.insert("secrets_loaded".into(), json!(false));
    if let Some(handoff) = broker_handoff {
        fields.insert(
            "broker_handoff_tool".into(),
            handoff
                .get("recommended_tool")
                .cloned()
                .filter(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                .unwrap_or_else(|| json!("none")),
        );
    }
    fields
}

/// Python `_run_grant_denial_reason`.
fn grant_denial_reason(
    env_names: Option<&[String]>,
    capabilities: &[String],
    hint: Option<&str>,
) -> String {
    let hint = hint.map(|h| format!(" ({h})")).unwrap_or_default();
    if !capabilities.is_empty() {
        return format!(
            "blocked: no matching live kv_run grant for this exact command and capability scope{hint}. Ask the user to approve it with: kv grant approve --capability NAME -- COMMAND..."
        );
    }
    if env_names.is_none() {
        return "blocked: secret-bearing kv_run must name secrets explicitly before a grant can be checked. Use --secret NAME / env_names, or --no-secrets for ordinary work.".to_owned();
    }
    format!(
        "blocked: no matching live kv_run grant for this exact command and secret scope{hint}. Ask the user to approve it with: kv grant approve --secret NAME -- COMMAND..."
    )
}

/// Python `shlex.quote`.
fn shell_quote(part: &str) -> String {
    if !part.is_empty()
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c))
    {
        return part.to_owned();
    }
    format!("'{}'", part.replace('\'', "'\"'\"'"))
}

/// Python `_run_grant_approval_hint`.
fn approval_hint(
    argv: &[String],
    cwd: &str,
    env_names: Option<&[String]>,
    actor: &Map<String, Value>,
    capabilities: &[String],
) -> Option<Value> {
    if env_names.is_none_or(<[String]>::is_empty) && capabilities.is_empty() {
        return None;
    }
    let secret_names: BTreeSet<&String> = env_names.unwrap_or(&[]).iter().collect();
    let mut shown_actor = Map::new();
    for key in ["source", "client_name", "session_id"] {
        if let Some(value) = actor.get(key) {
            shown_actor.insert(key.into(), value.clone());
        }
    }
    let resolved = resolve(cwd).unwrap_or_else(|_| cwd.to_owned());
    let mut parts: Vec<String> = vec!["kv", "grant", "approve", "--cwd"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    parts.push(resolved.clone());
    for (key, flag) in [
        ("source", "--source"),
        ("client_name", "--client"),
        ("session_id", "--session-id"),
    ] {
        if let Some(value) = shown_actor.get(key).and_then(Value::as_str) {
            parts.push(flag.to_owned());
            parts.push(value.to_owned());
        }
    }
    for name in &secret_names {
        parts.push("--secret".to_owned());
        parts.push((*name).clone());
    }
    for name in capabilities {
        parts.push("--capability".to_owned());
        parts.push(name.clone());
    }
    let distinct: BTreeSet<&String> = capabilities.iter().collect();
    if distinct.len() > 1 {
        for name in &distinct {
            parts.push("--max-calls-for".to_owned());
            parts.push(format!("{name}=1"));
        }
    }
    parts.push("--".to_owned());
    parts.extend(argv.iter().cloned());
    let command = parts
        .iter()
        .map(|p| shell_quote(p))
        .collect::<Vec<_>>()
        .join(" ");
    Some(json!({
        "action": "ask_user_to_approve",
        "command": command,
        "cwd": resolved,
        "secret_names": secret_names,
        "capability_names": capabilities,
        "actor": shown_actor,
        "message": "Ask the user to review this requester, command, folder, and secret scope in their terminal before approving.",
    }))
}

/// Python `_get_allowlist`: the allowed commands when the policy is `allowlist`.
fn allowlist(approved: &Value) -> Option<Vec<String>> {
    let security = approved.get("security")?.as_object()?;
    if security.get("kv_run_policy").and_then(Value::as_str) != Some("allowlist") {
        return None;
    }
    Some(
        security
            .get("allowed_commands")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// Python `config.is_network_allowed`.
fn network_allowed(approved: &Value, argv: &[String]) -> bool {
    let commands: Vec<String> = approved
        .get("security")
        .and_then(Value::as_object)
        .and_then(|security| security.get("network_commands"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    !commands.is_empty() && matches_allowlist(argv, &commands)
}

/// Python `_should_use_private_cwd`.
fn should_use_private_cwd(
    credential_bearing: bool,
    capability_run: bool,
    requested: Option<bool>,
) -> bool {
    if !credential_bearing {
        return false;
    }
    match requested {
        Some(false) => false,
        Some(true) => true,
        None if capability_run => true,
        None => private_cwd_requested(None, std::env::var("KV_RUN_PRIVATE_CWD").ok().as_deref()),
    }
}

struct Redaction {
    caller: Vec<String>,
    verbatim: Vec<String>,
    issued: Vec<String>,
}

impl Redaction {
    /// Python `_safe_error_text`.
    fn safe(&self, text: &str, cache: &Mutex<SecretCache>) -> String {
        let mut values = match cache.lock() {
            Ok(cache) => cache.redaction_values(),
            Err(_) => return withhold::WITHHELD.to_owned(),
        };
        values.extend(self.issued.iter().cloned());
        let pairs: Vec<(String, String)> = values
            .into_iter()
            .enumerate()
            .map(|(i, v)| (format!("\0value-{i}"), v))
            .collect();
        let needles = redaction_needles(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        withhold::safe_error_text(text, Some(&self.caller), &needles, &self.verbatim)
    }
}

fn merge(mut base: Map<String, Value>, extra: &Map<String, Value>) -> Map<String, Value> {
    for (key, value) in extra {
        base.insert(key.clone(), value.clone());
    }
    base
}

fn error_response(
    error: String,
    mode: Option<&str>,
    identity: &Map<String, Value>,
) -> Map<String, Value> {
    let mut response = Map::new();
    response.insert("error".into(), json!(error));
    response.insert("exit_code".into(), json!(1));
    if let Some(mode) = mode {
        response.insert("mode".into(), json!(mode));
    }
    merge(response, identity)
}

fn emit(audit: &kv_audit::Audit, event: &str, fields: Map<String, Value>) {
    // The writer implements Python's drop/count/warn policy.
    let _ = audit.emit(event, fields);
}

fn run_blocked_fields(
    program: &str,
    reason: &str,
    mode: &str,
    env: &str,
    parts: &[&Map<String, Value>],
) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("program".into(), json!(program));
    fields.insert("reason".into(), json!(reason));
    fields.insert("mode".into(), json!(mode));
    fields.insert("env".into(), json!(env));
    for part in parts {
        fields = merge(fields, part);
    }
    fields
}

/// Python `_select_run_secrets`.
#[allow(clippy::type_complexity)]
fn select_run_secrets(
    cache: &Mutex<SecretCache>,
    store: &DrawerStore,
    env: &str,
    env_names: Option<&[String]>,
) -> Result<
    (
        BTreeMap<String, Zeroizing<String>>,
        Vec<(String, Zeroizing<String>)>,
        &'static str,
    ),
    (String, Option<usize>),
> {
    if env_names == Some(&[]) {
        return Ok((BTreeMap::new(), Vec::new(), "none"));
    }
    let all = match cache.lock() {
        Ok(mut cache) => cache
            .env_secrets(store, env)
            .map_err(|e| (format!("blocked: {e}"), None))?,
        Err(_) => return Err(("secret cache is unavailable".to_owned(), None)),
    };
    match env_names {
        Some(names) => {
            let mut requested: Vec<&String> = Vec::new();
            for name in names {
                if !requested.contains(&name) {
                    requested.push(name);
                }
            }
            let mut missing: Vec<&String> = requested
                .iter()
                .copied()
                .filter(|name| !all.contains_key(*name))
                .collect();
            if !missing.is_empty() {
                missing.sort();
                let plural = if missing.len() != 1 { "s" } else { "" };
                let listed = missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err((
                    format!(
                        "blocked: requested secret{plural} not found in environment '{env}': {listed}"
                    ),
                    Some(all.len()),
                ));
            }
            let selected = requested
                .into_iter()
                .map(|name| (name.clone(), all[name].clone()))
                .collect();
            Ok((all, selected, "selected"))
        }
        None => {
            let selected = all.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            Ok((all, selected, "all"))
        }
    }
}

enum GrantLookup {
    NotNeeded,
    Admitted(Admission),
    Denied {
        reason: String,
        spent: Option<(String, bool, &'static str)>,
    },
}

/// Python `_find_run_grant` with `admit=True`.
#[allow(clippy::too_many_arguments)]
fn find_run_grant(
    ctx: &RunCtx<'_>,
    identity: &Map<String, Value>,
    env_names: Option<&[String]>,
    capabilities: &[String],
    actor: &Map<String, Value>,
    cwd: &str,
    argv: &[String],
    now: i64,
) -> GrantLookup {
    if env_names == Some(&[]) && capabilities.is_empty() {
        return GrantLookup::NotNeeded;
    }
    let denied = |reason: String| GrantLookup::Denied {
        reason,
        spent: None,
    };
    if !capabilities.is_empty() {
        if env_names.is_some_and(|names| !names.is_empty()) {
            return denied("blocked: kv_run cannot mix raw secrets and capabilities".into());
        }
        if capabilities
            .iter()
            .any(|name| !name.starts_with("api:") || name == "api:")
        {
            return denied(
                "blocked: kv_run capability mode currently supports only api:<provider> capabilities"
                    .into(),
            );
        }
    } else if env_names.is_none() {
        return denied(grant_denial_reason(None, &[], None));
    }
    if !ctx.trust.protected {
        return denied(NO_PASSPHRASE_REFUSAL.to_owned());
    }
    let Some(signing_key) = ctx.trust.approval_signing_key.as_ref() else {
        return denied(
            "blocked: could not verify kv_run grant: the approval signing key is not available"
                .into(),
        );
    };
    let binding = SessionBinding {
        protected: ctx.trust.protected,
        owner_public_key: ctx.trust.owner_public_key,
        owner_key_id: ctx.trust.owner_key_id.clone(),
        local_approval_id: ctx.trust.local_approval_id.clone(),
        location: ctx.trust.location.clone(),
        session_nonce: *ctx.trust.session_nonce,
        providers: Arc::new(ctx.providers.clone()),
    };
    let grant_ctx = GrantContext {
        root: ctx.root,
        signing_key: &signing_key[..],
        state_key: ctx.trust.grant_state_key.as_bytes(),
        binding: &binding,
        ledger: &ctx.shared.ledger,
        providers: ctx.providers,
    };
    let identity_value = Value::Object(identity.clone());
    let secret_names = if capabilities.is_empty() {
        Some(json!(env_names.unwrap_or(&[])))
    } else {
        None
    };
    let capability_names = (!capabilities.is_empty()).then(|| json!(capabilities));
    let actor_value = Value::Object(actor.clone());
    let request = match RunRequest::normalize(
        &identity_value,
        secret_names.as_ref(),
        capability_names.as_ref(),
        Some(&actor_value),
    ) {
        Ok(request) => request,
        Err(error) => return denied(format!("blocked: could not verify kv_run grant: {error}")),
    };
    match admit_run_grant(&grant_ctx, &request, Some(ctx.env), now) {
        Ok(Some(admission)) => GrantLookup::Admitted(admission),
        Ok(None) => {
            let hint = explain_run_grant_mismatch(&grant_ctx, &request, Some(cwd), Some(argv), now)
                .ok()
                .flatten();
            denied(grant_denial_reason(env_names, capabilities, hint))
        }
        Err(error) => {
            let spent = match &error {
                GrantError::Spent {
                    grant_id,
                    spent,
                    error_type,
                    ..
                } if !capabilities.is_empty() => Some((grant_id.clone(), *spent, *error_type)),
                _ => None,
            };
            GrantLookup::Denied {
                reason: format!("blocked: could not verify kv_run grant: {error}"),
                spent,
            }
        }
    }
}

/// Python `_granted_run_network`.
fn granted_run_network(
    verified: Option<&VerifiedGrant>,
    approved: &Value,
    argv: &[String],
    capability_run: bool,
    no_secret: bool,
) -> Result<bool, String> {
    if let Some(verified) = verified
        && verified.protected
    {
        return verified.network.ok_or_else(|| {
            "blocked for security: the approval's signed network value is not true or false"
                .to_owned()
        });
    }
    Ok(network_allowed(approved, argv) || capability_run || no_secret)
}

struct Launched {
    result: capture::BoundedRunResult,
}

enum LaunchFailure {
    /// Python `AdmissionRefused` / `ReservedRunEnvNameError` /
    /// `RunEnvInjectionError` / the descriptor checks: `blocked: ...`.
    Blocked(String),
    /// The program could not be started: `command not found`.
    NotFound,
    /// Anything else after the process may have started.
    Other(String),
}

/// Python `_launch_run_child` + `_run_bounded_capture`.
#[allow(clippy::too_many_arguments)]
fn launch_run_child(
    ctx: &mut RunCtx<'_>,
    run_argv: &[String],
    secrets: &[(String, Zeroizing<String>)],
    capability_env: &BTreeMap<String, String>,
    verified: Option<&VerifiedGrant>,
    grant_id: Option<&str>,
    capability_name: Option<&str>,
    cwd: &str,
    slot: &Slot,
) -> Result<Launched, LaunchFailure> {
    let trusted = ctx.shared.host.bwrap.as_deref();
    let secret_pairs: Vec<(&str, &str)> = secrets
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let base_env: Vec<(String, String)> = std::env::vars().collect();
    let mut launch_argv = run_argv.to_vec();
    let mut sealed = None;
    let launcher_env;
    if !secrets.is_empty() || !capability_env.is_empty() {
        let (sandboxed, network) = launch_facts(run_argv, None, trusted);
        let secret_names: Vec<String> = secrets.iter().map(|(k, _)| k.clone()).collect();
        let release = Release {
            secret_names: &secret_names,
            capability_name: if capability_env.is_empty() {
                None
            } else {
                capability_name
            },
            sandboxed: Some(sandboxed),
            network,
            ..Release::new("launch", grant_id, ctx.env)
        };
        require_verified(verified, &release)
            .map_err(|refused| LaunchFailure::Blocked(format!("blocked: {}", refused.message())))?;
        let mut child_env: BTreeMap<String, String> = secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        child_env.extend(capability_env.iter().map(|(k, v)| (k.clone(), v.clone())));
        let mut run_env = build_run_env(
            secret_pairs.iter().copied(),
            base_env.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        )
        .map_err(|error| LaunchFailure::Blocked(format!("blocked: {error}")))?;
        run_env.extend(capability_env.iter().map(|(k, v)| (k.clone(), v.clone())));
        let (argv_with_args, injected, fd) = inject_run_env(run_argv, &child_env, trusted)
            .map_err(|error| LaunchFailure::Blocked(format!("blocked: {error}")))?;
        launch_argv = argv_with_args;
        if let Some(fd) = fd {
            let borrowed = fd.as_fd().ok_or_else(|| {
                LaunchFailure::Blocked(
                    "blocked: the sealed args descriptor is not available".into(),
                )
            })?;
            let args_bytes = read_args_fd(borrowed)
                .map_err(|error| LaunchFailure::Blocked(format!("blocked: {error}")))?;
            let expected =
                expected_run_env_args(child_env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            if decode_args_bytes(&args_bytes).ok().as_ref() != Some(&expected) {
                return Err(LaunchFailure::Blocked(
                    "blocked for security: the args descriptor's payload is not the checked one"
                        .into(),
                ));
            }
            let raw = fd.raw().unwrap_or(-1);
            let trusted_name = trusted.unwrap_or("");
            let checked_argv =
                effective_launch_argv(&launch_argv, &args_bytes, Some((raw, trusted_name)))
                    .map_err(LaunchFailure::Blocked)?;
            if launch_facts(&checked_argv, Some(&args_bytes), trusted) != (sandboxed, network) {
                return Err(LaunchFailure::Blocked(
                    "blocked for security: the launched command did not match the checked one"
                        .into(),
                ));
            }
            sealed = Some(fd);
        }
        launcher_env = run_env
            .into_iter()
            .filter(|(name, _)| !injected.contains_key(name))
            .collect::<BTreeMap<_, _>>();
    } else {
        launcher_env = build_run_env(
            std::iter::empty::<(&str, &str)>(),
            base_env.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        )
        .map_err(|error| LaunchFailure::Blocked(format!("blocked: {error}")))?;
    }
    let launch = Launch {
        argv: &launch_argv,
        env: &launcher_env,
        cwd: Some(Path::new(cwd)),
        pass_fd: sealed.as_ref().and_then(|fd| fd.as_fd()),
    };
    let spawned = capture::spawn(&launch);
    if let Some(mut fd) = sealed {
        fd.close();
    }
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LaunchFailure::NotFound);
        }
        Err(error) => return Err(LaunchFailure::Other(error.to_string())),
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    ctx.shared.runs.register(ctx.lifecycle, slot, child);
    // The program exists: its committed window closes here (Python
    // `_register_run` swaps the window for the slot).
    drop(ctx.work.take());
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        return Err(LaunchFailure::Other(
            "the run's output pipes were not created".into(),
        ));
    };
    let result = capture::capture(slot, stdout, stderr)
        .map_err(|error| LaunchFailure::Other(error.to_string()))?;
    Ok(Launched { result })
}

fn str_list(value: Option<&Value>) -> Option<Vec<String>> {
    match value {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        ),
        Some(_) => None,
    }
}

/// The whole `run` command. The request is already validated.
pub(crate) fn handle_run(mut ctx: RunCtx<'_>) -> RunOutcome {
    let request = ctx.request;
    let plain = |response: Map<String, Value>| RunOutcome {
        response: Value::Object(response),
        control: false,
    };
    let redaction = Redaction {
        caller: withhold::caller_strings(&Value::Object(request.clone()), ctx.known_commands),
        verbatim: withhold::verbatim_strings(request.get("env_names")),
        issued: Vec::new(),
    };
    let mut redaction = redaction;
    let watched = vec![ctx.root_text.to_owned()];
    let env = ctx.env;
    let audit = ctx.audit;

    // ---- request shape (Python's run_request build) ----
    let argv = str_list(request.get("argv")).unwrap_or_default();
    if argv.is_empty() {
        return plain(error_response("argv required".into(), None, &Map::new()));
    }
    let req_cwd = request.get("cwd").and_then(Value::as_str);
    if req_cwd.is_some_and(|cwd| !cwd.starts_with('/')) {
        return plain(error_response(
            "working directory must be an absolute path".into(),
            None,
            &Map::new(),
        ));
    }
    let cwd_text = match req_cwd {
        Some(cwd) => cwd.to_owned(),
        None => std::env::current_dir()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/".to_owned()),
    };
    let run_cwd = match checked_run_cwd(&cwd_text, &watched) {
        Ok(cwd) => cwd,
        Err(error) => return plain(error_response(error.to_owned(), None, &Map::new())),
    };
    if req_cwd.is_some() && !std::fs::metadata(&run_cwd).is_ok_and(|m| m.is_dir()) {
        return plain(error_response(
            format!(
                "working directory not found: {}",
                req_cwd.unwrap_or_default()
            ),
            None,
            &Map::new(),
        ));
    }
    if script_candidates(&argv, &run_cwd, &watched)
        .iter()
        .any(|path| inside_secrets(path, &watched))
    {
        return plain(error_response(
            "script refused: it is inside the vault's .secrets".into(),
            None,
            &Map::new(),
        ));
    }
    let mut env_names = str_list(request.get("env_names"));
    let capabilities: Vec<String> = {
        let set: BTreeSet<String> = str_list(request.get("capability_names"))
            .unwrap_or_default()
            .into_iter()
            .collect();
        set.into_iter().collect()
    };
    if !capabilities.is_empty() && env_names.is_none() {
        env_names = Some(Vec::new());
    }
    let no_secret = env_names.as_deref() == Some(&[]) && capabilities.is_empty();
    let capability_run = !capabilities.is_empty();
    let credential_bearing = !no_secret;
    let requested_scope = secret_scope_label(env_names.as_deref(), &capabilities);
    let allowed = allowlist(ctx.approved);
    let decision: CommandDecision = classify_command(&argv, allowed.as_deref(), credential_bearing);
    let program = program_name(&argv[0]);
    let actor = actor_fields(request);
    let run_id = new_run_id();
    let identity_scope = IdentityScope {
        env_names: env_names.as_deref(),
        secret_scope: Some(json!(requested_scope)),
        secrets_injected: credential_bearing,
    };
    let pre_identity = match build_run_identity(&argv, &run_cwd, &identity_scope, &run_id, &watched)
    {
        Ok(identity) => identity,
        Err(error) => {
            let reason = redaction.safe(&error.to_string(), ctx.cache);
            return plain(error_response(reason, None, &Map::new()));
        }
    };

    // ---- the command's class ----
    if !decision.allowed {
        let protected = ctx.trust.protected;
        let policy_requestable = decision.reason.contains("command not in allowlist");
        let error = if !protected && policy_requestable {
            NO_PASSPHRASE_REFUSAL.to_owned()
        } else {
            session_denial_reason(&decision, protected)
        };
        let mut response = error_response(error, Some(decision.mode), &pre_identity);
        if let Some(handoff) = &decision.broker_handoff {
            response.insert("broker_handoff".into(), Value::Object(handoff.clone()));
        }
        if protected
            && let Some(policy_request) = crate::requests::create_run_policy_request(
                &ctx,
                &argv,
                &run_cwd,
                &decision.reason,
                decision.mode,
                &actor,
            )
        {
            response.insert("policy_request".into(), policy_request);
        }
        let fields = run_blocked_fields(
            &program,
            &decision.reason,
            decision.mode,
            env,
            &[
                &blocked_fields(
                    requested_scope,
                    env_names.as_deref(),
                    decision.broker_handoff.as_ref(),
                    None,
                ),
                &pre_identity,
                &actor,
            ],
        );
        emit(audit, "run_blocked", fields);
        return plain(response);
    }

    // ---- bubblewrap for a run with secrets or a capability ----
    if credential_bearing && let Some(sandbox_error) = secret_run_sandbox_error(&ctx.shared.host) {
        let fields = run_blocked_fields(
            &program,
            sandbox_error,
            decision.mode,
            env,
            &[
                &blocked_fields(requested_scope, env_names.as_deref(), None, None),
                &pre_identity,
                &actor,
            ],
        );
        emit(audit, "run_blocked", fields);
        return plain(error_response(
            sandbox_error.to_owned(),
            Some(decision.mode),
            &pre_identity,
        ));
    }

    // ---- the grant ----
    let now = now_epoch();
    let admission = match find_run_grant(
        &ctx,
        &pre_identity,
        env_names.as_deref(),
        &capabilities,
        &actor,
        &run_cwd,
        &argv,
        now,
    ) {
        GrantLookup::NotNeeded => None,
        GrantLookup::Admitted(admission) => Some(admission),
        GrantLookup::Denied { reason, spent } => {
            let mut response = error_response(reason.clone(), Some(decision.mode), &pre_identity);
            let approvable = reason != NO_PASSPHRASE_REFUSAL && ctx.trust.protected;
            if approvable
                && let Some(hint) =
                    approval_hint(&argv, &run_cwd, env_names.as_deref(), &actor, &capabilities)
            {
                response.insert("approval_hint".into(), hint);
            }
            if approvable
                && let Some(approval_request) = crate::requests::create_run_approval_request(
                    &ctx,
                    &pre_identity,
                    &argv,
                    &run_cwd,
                    env_names.as_deref(),
                    &capabilities,
                    &actor,
                )
            {
                response.insert("approval_request".into(), approval_request);
            }
            let mut spent_link = Map::new();
            if let Some((grant_id, was_spent, error_type)) = spent {
                spent_link.insert("grant_id".into(), json!(grant_id));
                let mut fields = Map::new();
                fields.insert("program".into(), json!(program));
                fields.insert("error_type".into(), json!(error_type));
                fields.insert("env".into(), json!(env));
                fields.insert("grant_spent".into(), json!(was_spent));
                fields = merge(fields, &spent_link);
                fields = merge(fields, &pre_identity);
                fields = merge(fields, &actor);
                emit(audit, "run_admission_failed", fields);
            }
            let mut fields = run_blocked_fields(
                &program,
                &reason,
                decision.mode,
                env,
                &[
                    &spent_link,
                    &blocked_fields(requested_scope, env_names.as_deref(), None, None),
                    &pre_identity,
                    &actor,
                ],
            );
            fields.insert("grant_required".into(), json!(true));
            emit(audit, "run_blocked", fields);
            return plain(response);
        }
    };
    let grant_id: Option<String> = admission
        .as_ref()
        .and_then(|a| a.grant.get("grant_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let verified: Option<Arc<VerifiedGrant>> = admission.as_ref().map(|a| Arc::clone(&a.verified));
    let issued_token: Option<String> = admission
        .as_ref()
        .and_then(|a| a.issued_capability.as_ref())
        .and_then(|c| c.get("token"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(token) = &issued_token {
        redaction.issued.push(token.clone());
    }
    let mut grant_link = Map::new();
    if let Some(id) = &grant_id {
        grant_link.insert("grant_id".into(), json!(id));
    }
    if let Some(admission) = &admission {
        let mut fields = Map::new();
        fields.insert("program".into(), json!(program));
        fields.insert(
            "usage_mode".into(),
            admission
                .grant
                .get("usage_mode")
                .cloned()
                .unwrap_or(Value::Null),
        );
        fields.insert("mode".into(), json!(decision.mode));
        fields.insert("env".into(), json!(env));
        fields = merge(fields, &grant_link);
        fields = merge(fields, &pre_identity);
        fields = merge(fields, &actor);
        emit(audit, "run_admitted", fields);
    }
    // A token's pass ends with its run, however the run ends.
    let pass_hash = issued_token.as_deref().map(token_hash);
    let outcome = run_admitted(
        &mut ctx,
        &mut redaction,
        RunPlan {
            argv: &argv,
            run_cwd: &run_cwd,
            env_names: env_names.as_deref(),
            capabilities: &capabilities,
            no_secret,
            capability_run,
            credential_bearing,
            requested_scope,
            decision: &decision,
            program: &program,
            actor: &actor,
            pre_identity: &pre_identity,
            run_id: &run_id,
            admission: admission.as_ref(),
            grant_id: grant_id.as_deref(),
            verified: verified.as_deref(),
            grant_link: &grant_link,
            watched: &watched,
        },
    );
    if let Some(hash) = pass_hash {
        ctx.shared.ledger.revoke_pass(&hash);
    }
    outcome
}

struct RunPlan<'a> {
    argv: &'a [String],
    run_cwd: &'a str,
    env_names: Option<&'a [String]>,
    capabilities: &'a [String],
    no_secret: bool,
    capability_run: bool,
    credential_bearing: bool,
    requested_scope: &'static str,
    decision: &'a CommandDecision,
    program: &'a str,
    actor: &'a Map<String, Value>,
    pre_identity: &'a Map<String, Value>,
    run_id: &'a str,
    admission: Option<&'a Admission>,
    grant_id: Option<&'a str>,
    verified: Option<&'a VerifiedGrant>,
    grant_link: &'a Map<String, Value>,
    watched: &'a [String],
}

/// From the admitted grant to the reply (Python's `try:` after
/// `run_admitted`): capsules, wrapper, token, secrets, launch, scans.
fn run_admitted(ctx: &mut RunCtx<'_>, redaction: &mut Redaction, plan: RunPlan<'_>) -> RunOutcome {
    let plain = |response: Map<String, Value>| RunOutcome {
        response: Value::Object(response),
        control: false,
    };
    let env = ctx.env;
    let audit = ctx.audit;
    let decision = plan.decision;
    let blocked = |ctx: &RunCtx<'_>,
                   reason: String,
                   response: Map<String, Value>,
                   extra: &[&Map<String, Value>]| {
        let mut parts: Vec<&Map<String, Value>> = Vec::new();
        parts.extend_from_slice(extra);
        let fields = run_blocked_fields(plan.program, &reason, decision.mode, env, &parts);
        emit(ctx.audit, "run_blocked", fields);
        plain(response)
    };
    let capability_name = plan.capabilities.first().map(String::as_str);
    let use_private_cwd = should_use_private_cwd(
        plan.credential_bearing,
        plan.capability_run,
        ctx.request.get("private_cwd").and_then(Value::as_bool),
    );

    // ---- capsules and the wrapper ----
    let prepared: Result<(RunCwdCapsule, RunArtifactCapsule, Vec<String>, bool), String> = (|| {
        let network = granted_run_network(
            plan.verified,
            ctx.approved,
            plan.argv,
            plan.capability_run,
            plan.no_secret,
        )?;
        let cwd_capsule = prepare_run_cwd_capsule(
            plan.run_cwd,
            plan.credential_bearing,
            use_private_cwd,
            plan.watched,
        )
        .map_err(|e| e.to_string())?;
        let expected_sha = plan
            .pre_identity
            .get("script_sha256")
            .and_then(Value::as_str);
        let artifact = prepare_run_artifact_capsule(
            plan.argv,
            plan.run_cwd,
            expected_sha,
            plan.credential_bearing,
            plan.watched,
        )
        .map_err(|e| e.to_string())?;
        let options = WrapOptions {
            network,
            secrets_dir: Some(
                kv_grants::store::secrets_dir(ctx.root)
                    .to_string_lossy()
                    .into_owned(),
            ),
            cwd: Some(plan.run_cwd.to_owned()),
            protect_home_credentials: plan.credential_bearing,
            readonly_file_overlays: artifact.readonly_file_overlays.clone(),
            private_tmp: plan.credential_bearing,
            cwd_bind_source: Some(cwd_capsule.bind_source().to_owned()),
            secrets_injected: plan.credential_bearing,
            weak_flag_reader: WeakFlagReader::Service,
        };
        let run_argv =
            wrap_argv(plan.argv, &options, &ctx.shared.host).map_err(|e| e.to_string())?;
        Ok((cwd_capsule, artifact, run_argv, network))
    })();
    let (mut cwd_capsule, mut artifact_capsule, run_argv, _network) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let reason = redaction.safe(&error, ctx.cache);
            let response = error_response(reason.clone(), Some(decision.mode), plan.pre_identity);
            return blocked(
                ctx,
                reason,
                response,
                &[
                    &blocked_fields(plan.requested_scope, plan.env_names, None, None),
                    plan.grant_link,
                    plan.pre_identity,
                    plan.actor,
                ],
            );
        }
    };
    let cleanup = |cwd_capsule: &mut RunCwdCapsule, artifact: &mut RunArtifactCapsule| {
        artifact.cleanup();
        cwd_capsule.cleanup();
    };

    // ---- the capability token's environment ----
    let mut capability_env: BTreeMap<String, String> = BTreeMap::new();
    let mut capability_redaction: Vec<(String, String)> = Vec::new();
    let mut capability_token_id: Option<String> = None;
    if plan.capability_run {
        let minted = plan
            .admission
            .and_then(|a| a.issued_capability.as_ref())
            .and_then(|c| {
                c.get("token")
                    .and_then(Value::as_str)
                    .map(|t| (t.to_owned(), c))
            });
        let outcome = match minted {
            None => Err("capability admission did not issue a token".to_owned()),
            Some((token, record)) => {
                let distinct: BTreeSet<&String> = plan.capabilities.iter().collect();
                let names = if distinct.len() > 1 {
                    json!(distinct)
                } else {
                    json!(capability_name)
                };
                capability_env_vars(
                    &json!(token),
                    &names,
                    &Value::Object(plan.pre_identity.clone()),
                    Some(&Value::Object(plan.actor.clone())),
                    Some(&json!(env)),
                )
                .inspect(|_| {
                    capability_redaction.push(("KV_CAP_TOKEN".into(), token.clone()));
                    capability_token_id = record
                        .get("token_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                })
                .map_err(|e| e.message().to_owned())
            }
        };
        match outcome {
            Ok(vars) => capability_env = vars,
            Err(error) => {
                cleanup(&mut cwd_capsule, &mut artifact_capsule);
                let reason = redaction.safe(
                    &format!("blocked: could not mint capability token: {error}"),
                    ctx.cache,
                );
                let mut response =
                    error_response(reason.clone(), Some(decision.mode), plan.pre_identity);
                response.insert("secret_scope".into(), json!(plan.requested_scope));
                response.insert("injected_secret_count".into(), json!(0));
                return blocked(
                    ctx,
                    reason,
                    response,
                    &[
                        &blocked_fields(plan.requested_scope, plan.env_names, None, None),
                        plan.grant_link,
                        plan.pre_identity,
                        plan.actor,
                    ],
                );
            }
        }
    }

    // ---- the secrets ----
    let (all_env_secrets, secrets, mut secret_scope) =
        match select_run_secrets(ctx.cache, ctx.store, env, plan.env_names) {
            Ok(selected) => selected,
            Err((error, available)) => {
                cleanup(&mut cwd_capsule, &mut artifact_capsule);
                let reason = redaction.safe(&error, ctx.cache);
                let mut response =
                    error_response(reason.clone(), Some(decision.mode), plan.pre_identity);
                response.insert("secret_scope".into(), json!(plan.requested_scope));
                response.insert("injected_secret_count".into(), json!(0));
                return blocked(
                    ctx,
                    reason,
                    response,
                    &[
                        &blocked_fields(plan.requested_scope, plan.env_names, None, available),
                        plan.grant_link,
                        plan.pre_identity,
                        plan.actor,
                    ],
                );
            }
        };
    if plan.capability_run {
        secret_scope = "capability";
    }
    let mut redaction_map: Vec<(String, String)> = all_env_secrets
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect();
    redaction_map.extend(capability_redaction);
    let run_mode = if plan.capability_run {
        decision.mode
    } else {
        effective_run_mode(decision.mode, secrets.len() as i64)
    };
    let run_identity = match build_run_identity(
        plan.argv,
        plan.run_cwd,
        &IdentityScope {
            env_names: plan.env_names,
            secret_scope: Some(json!(secret_scope)),
            secrets_injected: plan.credential_bearing,
        },
        plan.run_id,
        plan.watched,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            cleanup(&mut cwd_capsule, &mut artifact_capsule);
            let reason = redaction.safe(&error.to_string(), ctx.cache);
            return plain(error_response(
                reason,
                Some(decision.mode),
                plan.pre_identity,
            ));
        }
    };
    let mut grant_fields = plan.grant_link.clone();
    if let Some(name) = capability_name {
        grant_fields.insert("capability_name".into(), json!(name));
    }
    if let Some(id) = &capability_token_id {
        grant_fields.insert("capability_token_id".into(), json!(id));
    }
    if !artifact_capsule.readonly_file_overlays.is_empty() {
        grant_fields.insert("capsule_artifact".into(), json!(true));
    }
    if cwd_capsule.enabled() {
        grant_fields.insert("capsule_cwd".into(), json!(true));
    }
    let temp_dirs = temp_scan_dirs(&["/var/tmp".to_owned(), "/dev/shm".to_owned()]);
    let before_time = now_secs_f64();
    let started = Instant::now();
    let cwd_scan_root = cwd_capsule.scan_root().to_owned();
    let cwd_diff_needed = !redaction_map.is_empty() || cwd_capsule.enabled();
    let cwd_snapshot = if cwd_capsule.enabled() {
        cwd_capsule.private_snapshot.clone()
    } else if cwd_diff_needed {
        snapshot_files(std::slice::from_ref(&cwd_scan_root))
    } else {
        BTreeMap::new()
    };
    let scan_excludes: Vec<String> = if cwd_capsule.enabled() {
        cwd_capsule.private_cwd.iter().cloned().collect()
    } else {
        Vec::new()
    };
    let trusted = ctx.shared.host.bwrap.as_deref();
    let (sandboxed, _) = launch_facts(&run_argv, None, trusted);
    let contained = sandboxed
        && run_argv
            .iter()
            .position(|t| t == "--")
            .is_some_and(|sep| run_argv[..sep].iter().any(|t| t == "--unshare-pid"));
    let slot = new_slot(
        Some(plan.run_id.to_owned()),
        plan.program,
        !redaction_map.is_empty(),
        Some(sandboxed),
        contained,
    );
    let redaction_pairs: Vec<(&str, &str)> = redaction_map
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let base_response =
        |mode: &str, scope: &str, injected: usize, identity: &Map<String, Value>| {
            let mut response = Map::new();
            response.insert("mode".into(), json!(mode));
            response.insert("secret_scope".into(), json!(scope));
            response.insert("injected_secret_count".into(), json!(injected));
            merge(response, identity)
        };

    // ---- launch ----
    let launched = launch_run_child(
        ctx,
        &run_argv,
        &secrets,
        &capability_env,
        plan.verified,
        plan.grant_id,
        capability_name,
        plan.run_cwd,
        &slot,
    );
    drop(ctx.work.take());
    let registered = slot.lock().map(|s| s.proc.is_some()).unwrap_or(false);
    let ended_by_stop = registered && ctx.shared.runs.collected(&slot);
    let stopping = stopping_latched(ctx.lifecycle);
    let finish = |ctx: &RunCtx<'_>, outcome: RunOutcome| {
        if registered {
            ctx.shared.runs.unregister(ctx.lifecycle, &slot);
        }
        outcome
    };
    let result = match launched {
        Ok(launched) => launched.result,
        Err(LaunchFailure::Blocked(reason)) => {
            cleanup(&mut cwd_capsule, &mut artifact_capsule);
            let reason = redaction.safe(&reason, ctx.cache);
            let response = error_response(reason.clone(), None, &run_identity);
            let fields = run_blocked_fields(
                plan.program,
                &reason,
                decision.mode,
                env,
                &[&grant_fields, &run_identity, plan.actor],
            );
            emit(audit, "run_blocked", fields);
            return finish(ctx, plain(response));
        }
        Err(LaunchFailure::NotFound) => {
            cleanup(&mut cwd_capsule, &mut artifact_capsule);
            let response = error_response(
                format!("command not found: {}", plan.argv[0]),
                None,
                &run_identity,
            );
            return finish(ctx, plain(response));
        }
        Err(LaunchFailure::Other(error)) => {
            cleanup(&mut cwd_capsule, &mut artifact_capsule);
            let reason = redaction.safe(&error, ctx.cache);
            let run_id = printable_run_id(run_identity.get("run_id")).to_owned();
            let response = if registered && ended_by_stop {
                if ctx.shared.runs.claim_record(&slot) {
                    let mut fields = Map::new();
                    fields.insert("program".into(), json!(plan.program));
                    fields.insert("ended_by".into(), json!("stop"));
                    fields.insert("capture_failed".into(), json!(true));
                    fields.insert("error_type".into(), json!("CaptureError"));
                    fields.insert("env".into(), json!(env));
                    fields.insert("mode".into(), json!(run_mode));
                    fields.insert("secret_scope".into(), json!(secret_scope));
                    fields.insert("injected_secret_count".into(), json!(secrets.len()));
                    fields = merge(fields, &grant_fields);
                    fields = merge(fields, &run_identity);
                    fields = merge(fields, plan.actor);
                    emit(audit, "run_ended_by_stop", fields);
                }
                let mut response =
                    base_response(run_mode, secret_scope, secrets.len(), &run_identity);
                response.insert(
                    "error".into(),
                    json!(format!("the run was ended because the agent stopped (run {run_id}); kv could not collect its output")),
                );
                response.insert("error_code".into(), json!("run_ended_by_stop"));
                response.insert("exit_code".into(), json!(1));
                response.insert("ended_by_stop".into(), json!(true));
                response
            } else if registered && stopping {
                let mut response = error_response(
                    format!("the run failed while the agent was stopping (run {run_id}): {reason}"),
                    None,
                    &run_identity,
                );
                response.insert("error_code".into(), json!("run_failed_during_stop"));
                response
            } else {
                error_response(reason, None, &run_identity)
            };
            return finish(
                ctx,
                RunOutcome {
                    response: Value::Object(response),
                    control: registered,
                },
            );
        }
    };

    // ---- output, leaks, tracking ----
    let stdout = if result.stdout.is_empty() {
        String::new()
    } else {
        redact(&result.stdout, redaction_pairs.iter().copied())
    };
    let stderr = if result.stderr.is_empty() {
        String::new()
    } else {
        redact(&result.stderr, redaction_pairs.iter().copied())
    };
    let secret_scan = !redaction_map.is_empty();
    if secret_scan {
        ctx.shared.runs.set_scanning(&slot, true);
    }
    let mut leaked = scan_leaked_files(
        redaction_pairs.iter().copied(),
        before_time,
        &temp_dirs,
        &scan_excludes,
    );
    let changed_cwd_files = if cwd_diff_needed {
        collect_changed_files(&cwd_snapshot, std::slice::from_ref(&cwd_scan_root))
    } else {
        BTreeSet::new()
    };
    let changed_list: Vec<String> = changed_cwd_files.iter().cloned().collect();
    let cwd_leaked = scan_specific_files(&changed_list, redaction_pairs.iter().copied());
    let leaked_paths: Vec<String> = cwd_leaked.iter().map(|(path, _)| path.clone()).collect();
    leaked.extend(cwd_leaked);
    let copy_result = cwd_capsule
        .enabled()
        .then(|| cwd_capsule.copy_back(&changed_cwd_files, &leaked_paths));
    let mut leak_warning = String::new();
    let mut leak_records = Vec::new();
    if !leaked.is_empty() {
        ctx.shared
            .tracked
            .add_files(leaked.iter().map(|(path, _)| path.clone()));
        for (path, _) in &leaked {
            let _ = std::fs::remove_file(path);
        }
        // Keyed per call, as Python does, so the reference is not a path oracle.
        let mut report_key = [0u8; 16];
        getrandom::getrandom(&mut report_key).expect("operating system randomness");
        let (warning, records) =
            leak_report(&leaked, Some(&cwd_scan_root), &temp_dirs, &report_key);
        leak_warning = warning;
        leak_records = records;
    }
    if secret_scan {
        ctx.shared.runs.set_scanning(&slot, false);
    }
    let mut copy_warnings = Vec::new();
    if let Some(copy) = &copy_result {
        if !copy.blocked.is_empty() {
            copy_warnings.push(format!(
                "[SECURITY] private cwd copy-back blocked {} unsafe file(s)",
                copy.blocked.len()
            ));
        }
        if !copy.conflicts.is_empty() {
            copy_warnings.push(format!(
                "[SECURITY] private cwd copy-back skipped {} file(s) because the real project changed during the run",
                copy.conflicts.len()
            ));
        }
    }
    let mut output_warning = copy_warnings.join("\n");
    if result.stdout_truncated || result.stderr_truncated {
        let mut streams = Vec::new();
        if result.stdout_truncated {
            streams.push("stdout");
        }
        if result.stderr_truncated {
            streams.push("stderr");
        }
        let truncation = format!(
            "[SECURITY] truncated {} after {MAX_RUN_OUTPUT_BYTES} bytes per stream",
            streams.join("/")
        );
        output_warning = [output_warning, truncation]
            .into_iter()
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
    }
    let mut tracking_fields = Map::new();
    let mut tracking_warning = String::new();
    if stopping_latched(ctx.lifecycle) {
        tracking_fields.insert("temp_tracking".into(), json!("skipped"));
        tracking_fields.insert("temp_tracking_ended_by".into(), json!("stopping"));
        ctx.shared.tracked.note_gap(&temp_dirs, before_time);
    } else {
        let since = ctx
            .shared
            .tracked
            .gap_since()
            .map_or(before_time, |gap| gap.min(before_time));
        let mut found = BTreeSet::new();
        let lifecycle = ctx.lifecycle;
        let tracking = track_new_files(
            since,
            &temp_dirs,
            &mut found,
            &scan_excludes,
            Some(Instant::now() + TEMP_TRACKING_BUDGET),
            || stopping_latched(lifecycle),
        );
        ctx.shared.tracked.add_files(found);
        match &tracking {
            Tracking::Complete => ctx.shared.tracked.clear_gap(),
            Tracking::Stopping { unfinished } | Tracking::TimeBound { unfinished } => {
                ctx.shared.tracked.note_gap(unfinished, since);
                tracking_fields.insert("temp_tracking".into(), json!("incomplete"));
                tracking_fields.insert("temp_tracking_ended_by".into(), json!(tracking.reason()));
                if matches!(tracking, Tracking::TimeBound { .. }) {
                    tracking_warning = TEMP_TRACKING_INCOMPLETE_WARNING.to_owned();
                }
            }
        }
    }
    cleanup(&mut cwd_capsule, &mut artifact_capsule);
    let duration_ms = started.elapsed().as_millis() as u64;
    let exit_code = result.status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        -result.status.signal().unwrap_or(1)
    });
    let late_sent = slot.lock().map(|s| s.late_sent).unwrap_or(false);
    let mut leak_check_fields = Map::new();
    if late_sent {
        leak_check_fields.insert("leak_check".into(), json!("finished_after_reply"));
    }
    let common_fields = |extra: &[(&str, Value)]| {
        let mut fields = Map::new();
        fields.insert("program".into(), json!(plan.program));
        for (key, value) in extra {
            fields.insert((*key).into(), value.clone());
        }
        fields.insert("duration_ms".into(), json!(duration_ms));
        fields.insert("env".into(), json!(env));
        fields.insert("mode".into(), json!(run_mode));
        fields.insert("secret_scope".into(), json!(secret_scope));
        fields.insert("injected_secret_count".into(), json!(secrets.len()));
        fields = merge(fields, &tracking_fields);
        fields = merge(fields, &leak_check_fields);
        fields = merge(fields, &grant_fields);
        fields = merge(fields, &run_identity);
        merge(fields, plan.actor)
    };
    let outcome = if ended_by_stop {
        let run_id = printable_run_id(run_identity.get("run_id")).to_owned();
        if ctx.shared.runs.claim_record(&slot) {
            emit(
                audit,
                "run_ended_by_stop",
                common_fields(&[("exit_code", json!(exit_code)), ("ended_by", json!("stop"))]),
            );
        }
        let mut response = base_response(run_mode, secret_scope, secrets.len(), &run_identity);
        response.insert(
            "error".into(),
            json!(format!(
                "the run was ended because the agent stopped (run {run_id})"
            )),
        );
        response.insert("error_code".into(), json!("run_ended_by_stop"));
        response.insert("exit_code".into(), json!(1));
        response.insert("ended_by_stop".into(), json!(true));
        RunOutcome {
            response: Value::Object(response),
            control: true,
        }
    } else {
        let mut response = base_response(run_mode, secret_scope, secrets.len(), &run_identity);
        response.insert("exit_code".into(), json!(exit_code));
        response.insert("stdout".into(), json!(stdout));
        response.insert("stderr".into(), json!(stderr));
        if !artifact_capsule.readonly_file_overlays.is_empty() {
            response.insert("capsule_artifact".into(), json!(true));
        }
        if grant_fields.contains_key("capsule_cwd") {
            response.insert("capsule_cwd".into(), json!(true));
            if let Some(copy) = &copy_result {
                response.insert("copied_output_count".into(), json!(copy.copied.len()));
            }
        }
        if let Some(name) = capability_name {
            response.insert("capability_name".into(), json!(name));
        }
        if let Some(id) = &capability_token_id {
            response.insert("capability_token_id".into(), json!(id));
        }
        emit(
            audit,
            "run_exec",
            common_fields(&[("exit_code", json!(exit_code))]),
        );
        if !tracking_warning.is_empty() {
            response.insert("temp_tracking".into(), json!("incomplete"));
        }
        let warnings: Vec<&str> = [
            leak_warning.as_str(),
            output_warning.as_str(),
            tracking_warning.as_str(),
        ]
        .into_iter()
        .filter(|w| !w.is_empty())
        .collect();
        if !warnings.is_empty() {
            response.insert("warning".into(), json!(warnings.join("\n")));
        }
        RunOutcome {
            response: Value::Object(response),
            control: false,
        }
    };
    for record in leak_records {
        emit(audit, "leak_file", merge(record, plan.actor));
    }
    finish(ctx, outcome)
}
