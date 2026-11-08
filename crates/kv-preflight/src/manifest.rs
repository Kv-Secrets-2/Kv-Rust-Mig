use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use kv_sandbox::identity::{IdentityScope, build_run_identity, module_script_path};
use kv_sandbox::paths::{abspath, inside_secrets};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, ToPrimitive, Zero};
use serde_json::{Value, json};

use crate::agent_code::scan_agent_code;
use crate::analysis::analyze;

pub const PROVIDERS: &[&str] = &["anthropic", "github", "google", "google-cloud", "openai"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightError {
    TooDeep,
    ValueError(String),
    OverflowError,
    Other { kind: String, message: String },
}
impl PreflightError {
    pub fn kind(&self) -> &str {
        match self {
            Self::TooDeep => "TooDeep",
            Self::ValueError(_) => "ValueError",
            Self::OverflowError => "OverflowError",
            Self::Other { kind, .. } => kind,
        }
    }
    pub(crate) fn other(kind: &str, message: impl Into<String>) -> Self {
        Self::Other {
            kind: kind.into(),
            message: message.into(),
        }
    }
}
impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooDeep => f.write_str("Python script is nested too deeply for static preflight"),
            Self::ValueError(message) | Self::Other { message, .. } => f.write_str(message),
            Self::OverflowError => f.write_str("int too large to convert to float"),
        }
    }
}
impl std::error::Error for PreflightError {}

#[derive(Debug, Clone)]
pub struct ApiNeed {
    pub provider: String,
    pub imported: bool,
    pub call_sites: usize,
    pub estimated_calls: Option<BigInt>,
    pub unknown_call_count: bool,
    pub recommended_max_calls: BigInt,
    pub direct_sdk: bool,
    pub brokered: bool,
    pub rewrite_required: bool,
}
pub(crate) fn integer(n: &BigInt) -> Value {
    serde_json::from_str(&n.to_string()).expect("integer JSON")
}
impl ApiNeed {
    fn new(provider: &str) -> Self {
        Self {
            provider: provider.into(),
            imported: false,
            call_sites: 0,
            estimated_calls: Some(BigInt::zero()),
            unknown_call_count: false,
            recommended_max_calls: BigInt::zero(),
            direct_sdk: false,
            brokered: false,
            rewrite_required: false,
        }
    }
    pub fn as_dict(&self) -> Value {
        json!({"provider": self.provider, "imported": self.imported, "call_sites": self.call_sites, "estimated_calls": if self.unknown_call_count { Value::Null } else { self.estimated_calls.as_ref().map(integer).unwrap_or(Value::Null) }, "unknown_call_count": self.unknown_call_count, "recommended_max_calls": integer(&self.recommended_max_calls), "direct_sdk": self.direct_sdk, "brokered": self.brokered, "rewrite_required": self.rewrite_required})
    }
}

#[derive(Debug, Clone)]
pub struct PreflightManifest {
    pub argv: Vec<String>,
    pub cwd: String,
    pub command_display: String,
    pub identity: Value,
    pub command_allowed: bool,
    pub command_mode: String,
    pub command_reason: Option<String>,
    pub broker_handoff: Option<Value>,
    pub script_path: Option<String>,
    pub raw_key_exposure: String,
    pub api: BTreeMap<String, ApiNeed>,
    pub ssh_detected: bool,
    pub ssh_hosts: Vec<String>,
    pub file_writes: Vec<String>,
    pub raw_key_findings: usize,
    pub raw_key_finding_codes: Vec<String>,
    pub raw_key_finding_providers: Vec<String>,
    pub limits: Vec<String>,
}
impl PreflightManifest {
    pub fn as_dict(&self) -> Value {
        let capabilities: Vec<Value> = if recommendation_blocked_reason(self).is_none() {
            self.api.values().filter(|n| n.recommended_max_calls > BigInt::zero()).map(|n| json!({"capability": format!("api:{}", n.provider), "max_calls": integer(&n.recommended_max_calls)})).collect()
        } else {
            vec![]
        };
        let approvals = approval_command(self);
        let runs = run_command(self);
        json!({"command": self.command_display, "argv": self.argv, "cwd": self.cwd, "identity": self.identity, "command_allowed": self.command_allowed, "command_mode": self.command_mode, "command_reason": self.command_reason, "broker_handoff": self.broker_handoff, "script_path": self.script_path, "raw_key_exposure": self.raw_key_exposure, "api": self.api.iter().map(|(k,v)| (k.clone(), v.as_dict())).collect::<serde_json::Map<_,_>>(), "ssh": {"detected": self.ssh_detected, "hosts": self.ssh_hosts}, "files": {"writes": self.file_writes}, "raw_key_findings": {"count": self.raw_key_findings, "codes": self.raw_key_finding_codes, "providers": self.raw_key_finding_providers}, "recommended_approval": {"capabilities": capabilities, "raw_keys_exposed": false, "approval_command": if approvals.len() == 1 { approvals.first() } else { None }, "approval_commands": approvals, "run_command": if runs.len() == 1 { runs.first() } else { None }, "run_commands": runs, "blocked_reason": recommendation_blocked_reason(self)}, "agent_guidance": agent_guidance(self), "limits": self.limits})
    }
}

pub fn recommendation_blocked_reason(m: &PreflightManifest) -> Option<&'static str> {
    if !m.command_allowed {
        Some("command is not eligible for secret-bearing kv_run")
    } else if m.raw_key_findings > 0 {
        Some("raw-key findings must be rewritten before broker capability approval")
    } else {
        None
    }
}
fn apply_recommendation_guards(m: &mut PreflightManifest) {
    if recommendation_blocked_reason(m).is_none() {
        return;
    }
    for need in m.api.values_mut() {
        if need.recommended_max_calls > BigInt::zero() || need.brokered || need.direct_sdk {
            if m.raw_key_finding_providers.contains(&need.provider) || need.direct_sdk {
                need.rewrite_required = true;
            }
            need.recommended_max_calls = BigInt::zero();
        }
    }
    if !m.command_allowed {
        m.limits.push("No broker approval is recommended because the command is not eligible for secret-bearing kv_run.".into());
    }
    if m.raw_key_findings > 0 {
        m.limits.push("No broker approval is recommended until raw-key/direct-secret patterns are rewritten to kv.cap_client.".into());
    }
}
pub(crate) fn format_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|s| {
            if !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b))
            {
                s.clone()
            } else {
                format!("'{}'", s.replace('\'', "'\"'\"'"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn suggested_commands(m: &PreflightManifest, approval: bool) -> Vec<String> {
    if recommendation_blocked_reason(m).is_some() {
        return vec![];
    }
    m.api
        .values()
        .filter(|n| n.recommended_max_calls > BigInt::zero())
        .map(|n| {
            let mut parts: Vec<String> = if approval {
                vec!["kv".into(), "grant".into(), "approve".into()]
            } else {
                vec!["kv".into(), "run".into()]
            };
            parts.extend([
                "--cwd".into(),
                m.cwd.clone(),
                "--capability".into(),
                format!("api:{}", n.provider),
            ]);
            if approval {
                parts.extend(["--max-calls".into(), n.recommended_max_calls.to_string()]);
            }
            parts.push("--".into());
            parts.extend(m.argv.clone());
            format_argv(&parts)
        })
        .collect()
}
pub fn approval_command(m: &PreflightManifest) -> Vec<String> {
    suggested_commands(m, true)
}
pub fn run_command(m: &PreflightManifest) -> Vec<String> {
    suggested_commands(m, false)
}
pub fn agent_guidance(m: &PreflightManifest) -> Vec<String> {
    let providers: Vec<_> = m
        .api
        .values()
        .filter(|n| {
            n.imported
                || n.call_sites > 0
                || n.direct_sdk
                || n.brokered
                || n.rewrite_required
                || m.raw_key_finding_providers.contains(&n.provider)
        })
        .collect();
    if providers.is_empty() && m.raw_key_findings == 0 {
        return vec![];
    }
    let mut guidance = vec!["For AI/API scripts, do not request provider key env vars. Use kv.cap_client.api_call() inside kv run --capability api:<provider> so the script receives KV_CAP_TOKEN, not the provider key.".into()];
    let mut rewrites = false;
    let mut runnable = false;
    for n in &providers {
        if m.raw_key_finding_providers.contains(&n.provider) || n.direct_sdk || n.rewrite_required {
            rewrites = true;
            let p = &n.provider;
            guidance.push(format!("Rewrite {p} SDK/raw-key calls to from kv.cap_client import api_call; api_call('{p}', ...), then run with kv run --capability api:{p}."));
        }
    }
    for n in &providers {
        if n.recommended_max_calls > BigInt::zero() {
            runnable = true;
            guidance.push(format!("Approve and run {} through capability mode, not raw env injection: kv run --capability api:{} -- {}.", n.provider, n.provider, m.command_display));
        }
    }
    if m.command_allowed && !providers.is_empty() && !runnable && !rewrites {
        guidance.push("Static analysis found API-related imports but no brokered call budget. Do not add raw provider env vars just to make the script run.".into());
    }
    guidance
}

pub(crate) fn budget(estimate: &BigInt) -> Result<BigInt, PreflightError> {
    if estimate <= &BigInt::zero() {
        return Ok(BigInt::zero());
    }
    if estimate == &BigInt::from(1) {
        return Ok(estimate.clone());
    }
    let float = estimate
        .to_f64()
        .filter(|f| f.is_finite())
        .ok_or(PreflightError::OverflowError)?;
    let scaled = float * 1.10;
    let rounded = BigInt::from_f64(scaled.ceil()).ok_or_else(|| {
        PreflightError::other("OverflowError", "cannot convert float infinity to integer")
    })?;
    Ok(estimate.max(&rounded).clone())
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Array(_) => "list",
        Value::String(_) => "str",
        Value::Bool(_) => "bool",
        Value::Number(_) => "int",
        Value::Object(_) => "dict",
    }
}

fn allowed_commands(cwd: &str) -> Result<Option<Vec<Value>>, PreflightError> {
    let mut root = Path::new(cwd);
    loop {
        if std::fs::symlink_metadata(root.join(".secrets")).is_ok_and(|m| m.is_dir()) {
            break;
        }
        let Some(parent) = root.parent() else {
            return Ok(None);
        };
        root = parent;
    }
    kv_store::vault_origin::require_local(root)
        .map_err(|e| PreflightError::other("VaultOriginError", e.to_string()))?;
    let config = kv_store::config::load_config(root)
        .map_err(|e| match e {
            kv_store::StoreError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PreflightError::other(
                    "FileNotFoundError",
                    format!(
                        "[Errno 2] No such file or directory: '{}'",
                        root.join(".secrets/config.json").display()
                    ),
                )
            }
            _ => PreflightError::ValueError(e.to_string()),
        })?
        .value;
    let object = config.as_object().ok_or_else(|| {
        PreflightError::other(
            "AttributeError",
            format!("'{}' object has no attribute 'get'", type_name(&config)),
        )
    })?;
    let empty = json!({});
    let security = object.get("security").unwrap_or(&empty);
    let security = security.as_object().ok_or_else(|| {
        PreflightError::other(
            "AttributeError",
            format!("'{}' object has no attribute 'get'", type_name(security)),
        )
    })?;
    if security
        .get("kv_run_policy")
        .and_then(Value::as_str)
        .unwrap_or("blocklist")
        != "allowlist"
    {
        return Ok(None);
    }
    let empty = json!([]);
    let allowed = security.get("allowed_commands").unwrap_or(&empty);
    match allowed {
        Value::Array(items) => Ok(Some(items.clone())),
        Value::String(s) => Ok(Some(s.chars().map(|c| json!(c.to_string())).collect())),
        Value::Object(m) => Ok(Some(m.keys().map(|k| json!(k)).collect())),
        _ => Err(PreflightError::other(
            "TypeError",
            format!("'{}' object is not iterable", type_name(allowed)),
        )),
    }
}
fn script_path(argv: &[String], cwd: &str) -> Option<String> {
    let first = argv.first()?;
    let program = first.rsplit('/').next()?.to_lowercase();
    let candidate = if program.starts_with("python") && argv.len() > 1 {
        if argv[1] == "-m" {
            return argv
                .get(2)
                .and_then(|m| module_script_path(m, cwd, &[]))
                .filter(|p| !inside_secrets(p, &[]));
        }
        (!argv[1].starts_with('-')).then_some(argv[1].as_str())
    } else {
        [".py", ".sh", ".bash", ".zsh"]
            .iter()
            .any(|s| first.ends_with(s))
            .then_some(first.as_str())
    }?;
    if candidate.is_empty() {
        return None;
    }
    let path = if Path::new(candidate).is_absolute() {
        candidate.to_owned()
    } else {
        format!("{cwd}/{candidate}")
    };
    let path = abspath(&path).ok()?;
    (!inside_secrets(&path, &[]) && Path::new(&path).is_file()).then_some(path)
}
pub(crate) fn read_text(path: &str) -> std::io::Result<String> {
    Ok(String::from_utf8_lossy(&std::fs::read(path)?)
        .replace("\r\n", "\n")
        .replace('\r', "\n"))
}

pub fn preflight_command(
    argv: &[String],
    cwd: Option<&str>,
) -> Result<PreflightManifest, PreflightError> {
    let argv = if argv.first().is_some_and(|s| s == "--") {
        &argv[1..]
    } else {
        argv
    };
    if argv.is_empty() {
        return Err(PreflightError::ValueError(
            "preflight requires a command".into(),
        ));
    }
    let cwd = abspath(cwd.filter(|s| !s.is_empty()).unwrap_or("."))
        .map_err(|e| PreflightError::other("OSError", e.to_string()))?;
    let allowed = allowed_commands(&cwd)?;
    let mut decision = kv_sandbox::classify_command(argv, None, true);
    if decision.allowed
        && let Some(allowed) = &allowed
    {
        let mut prefixes = Vec::new();
        for value in allowed {
            let prefix = value
                .as_str()
                .ok_or_else(|| {
                    PreflightError::other(
                        "AttributeError",
                        format!("'{}' object has no attribute 'split'", type_name(value)),
                    )
                })?
                .to_owned();
            let matched =
                kv_sandbox::classify::matching_allowlist_entry(argv, std::slice::from_ref(&prefix))
                    .is_some();
            prefixes.push(prefix);
            if matched {
                break;
            }
        }
        decision = kv_sandbox::classify_command(argv, Some(&prefixes), true);
    }
    let mut nonce = [0; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| PreflightError::other("OSError", e.to_string()))?;
    let identity = build_run_identity(
        argv,
        &cwd,
        &IdentityScope {
            env_names: Some(&[]),
            secret_scope: Some(json!("capability")),
            secrets_injected: true,
        },
        &format!("run_{}", hex::encode(nonce)),
        &[],
    )
    .map_err(|e| PreflightError::ValueError(e.to_string()))?;
    let path = script_path(argv, &cwd);
    let mut m = PreflightManifest {
        argv: argv.to_vec(), cwd, command_display: format_argv(argv),
        identity: Value::Object(identity), command_allowed: decision.allowed,
        command_mode: decision.mode.into(), command_reason: Some(decision.reason),
        broker_handoff: decision.broker_handoff.map(Value::Object), script_path: path.clone(),
        raw_key_exposure: "no".into(),
        api: PROVIDERS.iter().map(|p| (p.to_string(), ApiNeed::new(p))).collect(),
        ssh_detected: false, ssh_hosts: vec![], file_writes: vec![], raw_key_findings: 0,
        raw_key_finding_codes: vec![], raw_key_finding_providers: vec![],
        limits: vec![
            "Static preflight can miss dynamic imports, branches, plugins, config-driven calls, and runtime-built network requests.".into(),
            "Runtime grants and capability-token enforcement remain the security boundary.".into(),
            "Time is a deadman control; call budget is the primary approval control.".into(),
        ],
    };
    if allowed.is_some() {
        m.limits.push(
            "Project allowlist policy is active; command_allowed reflects the current allowlist."
                .into(),
        );
    }
    if let Some(path) = path {
        let findings = scan_agent_code(&path).unwrap_or_default();
        m.raw_key_findings = findings.len();
        m.raw_key_finding_codes = findings
            .iter()
            .map(|f| f.code.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        m.raw_key_finding_providers = findings
            .iter()
            .filter_map(|f| f.provider.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if path.ends_with(".py") {
            match read_text(&path) {
                Ok(text) => {
                    if !analyze(&text, &mut m)? {
                        m.limits.push(
                            "Python script could not be parsed; estimates are incomplete.".into(),
                        );
                    }
                }
                Err(_) => m
                    .limits
                    .push("Python script could not be parsed; estimates are incomplete.".into()),
            }
        } else if let Ok(text) = read_text(&path) {
            m.ssh_detected = ["ssh", "scp", "sftp", "rsync"]
                .iter()
                .any(|p| text.contains(&format!("{p} ")));
        }
    }
    apply_recommendation_guards(&mut m);
    if m.api
        .values()
        .filter(|n| n.recommended_max_calls > BigInt::zero())
        .count()
        > 1
    {
        m.limits.push("This run uses several api:<provider> capabilities: approve them in one approval with a count for each (kv grant approve --capability api:A --capability api:B --max-calls-for api:A=N --max-calls-for api:B=M).".into());
    }
    Ok(m)
}

/// Python `json.dumps(indent=2, sort_keys=True, ensure_ascii=True)`, without a trailing newline.
pub fn manifest_json(manifest: &PreflightManifest) -> String {
    fn string(s: &str, out: &mut String) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\x08' => out.push_str("\\b"),
                '\x0c' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (' '..='~').contains(&c) => out.push(c),
                c => {
                    for unit in c.encode_utf16(&mut [0; 2]) {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
            }
        }
        out.push('"');
    }
    fn write(v: &Value, depth: usize, out: &mut String) {
        let pad = |n| " ".repeat(n * 2);
        match v {
            Value::String(s) => string(s, out),
            Value::Array(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (i, v) in items.iter().enumerate() {
                    out.push_str(&pad(depth + 1));
                    write(v, depth + 1, out);
                    out.push_str(if i + 1 == items.len() { "\n" } else { ",\n" });
                }
                out.push_str(&pad(depth));
                out.push(']');
            }
            Value::Object(items) if !items.is_empty() => {
                out.push_str("{\n");
                let sorted: BTreeMap<_, _> = items.iter().collect();
                for (i, (k, v)) in sorted.into_iter().enumerate() {
                    out.push_str(&pad(depth + 1));
                    string(k, out);
                    out.push_str(": ");
                    write(v, depth + 1, out);
                    out.push_str(if i + 1 == items.len() { "\n" } else { ",\n" });
                }
                out.push_str(&pad(depth));
                out.push('}');
            }
            _ => out.push_str(&v.to_string()),
        }
    }
    let mut out = String::new();
    write(&manifest.as_dict(), 0, &mut out);
    out
}
