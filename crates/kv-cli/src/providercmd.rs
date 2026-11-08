use crate::owner_policy as owner;
use crate::project::{self, CmdResult};
use crate::ui::{self, Palette};
use kv_broker::{
    build_provider_table, check_url_safety, default_http_policy, is_builtin_provider_name,
    validate_db_provider, validate_http_provider, validate_ssh_provider,
};
use kv_mcp::vault::{self, Kind};
use kv_store::config;
use serde_json::{Value, json};

#[derive(Debug, Clone, Default)]
pub struct ProviderOptions {
    pub name: String,
    pub provider_type: String,
    pub url: Option<String>,
    pub host: Option<String>,
    pub port: Option<Value>,
    pub database: Option<String>,
    pub username: Option<String>,
    pub secret: Option<String>,
    pub auth: String,
    pub query_param: Option<String>,
    pub header_name: Option<String>,
}

pub enum ProviderAction {
    List,
    Add(Box<ProviderOptions>),
    Remove(String),
}

fn required(p: &Palette, value: &Option<String>, field: &str) -> Result<String, project::Exit> {
    value
        .as_ref()
        .filter(|v| !v.is_empty())
        .cloned()
        .ok_or_else(|| project::fail(p, &format!("missing required provider field: --{field}")))
}

fn display_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "None".into(),
        Some(Value::Bool(true)) => "True".into(),
        Some(Value::Bool(false)) => "False".into(),
        Some(value) => value.to_string(),
        None => "?".into(),
    }
}

fn display_target(ptype: &str, provider: &Value) -> String {
    let get = |key| display_value(provider.get(key));
    match ptype {
        "http" => get("base_url"),
        "postgres" | "mysql" => format!(
            "{}@{}:{}/{}",
            get("username"),
            get("host"),
            get("port"),
            get("database")
        ),
        "redis" => format!("{}:{}", get("host"), get("port")),
        "ssh" => format!("{}@{}:{}", get("username"), get("host"), get("port")),
        _ => "?".into(),
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

pub fn cmd_provider(p: &Palette, action: ProviderAction) -> CmdResult {
    let root = project::require_project(p)?;
    let mut snapshot = project::config_value(p, &root)?;
    if !snapshot.value.is_object() {
        return Err(project::fail(p, "config must be an object"));
    }
    match action {
        ProviderAction::List => {
            if snapshot
                .value
                .get("providers")
                .is_some_and(|v| !v.is_object())
            {
                return Err(project::fail(
                    p,
                    "providers in config.json must be an object",
                ));
            }
            let table = build_provider_table(&snapshot.value).0;
            let custom = snapshot.value.get("providers").and_then(Value::as_object);
            ui::header(p, &format!("providers ({})", table.len()));
            ui::blank();
            for (name, provider) in table {
                let tag = if custom.is_some_and(|v| v.contains_key(&name)) {
                    format!(" {}(custom){}", p.dim, p.reset)
                } else {
                    String::new()
                };
                let ptype = provider
                    .get("provider_type")
                    .and_then(Value::as_str)
                    .unwrap_or("http");
                let detail = if ptype == "http" {
                    provider
                        .get("auth_type")
                        .and_then(Value::as_str)
                        .unwrap_or(ptype)
                } else {
                    ptype
                };
                ui::info(&format!(
                    "  {}{name}{}{tag}  {}{detail}  {}{}",
                    p.green,
                    p.reset,
                    p.dim,
                    display_value(provider.get("secret_name")),
                    p.reset
                ));
            }
            ui::blank();
        }
        ProviderAction::Remove(name) => {
            let provider = snapshot
                .value
                .get("providers")
                .and_then(|v| v.get(&name))
                .cloned();
            let Some(provider) = provider else {
                ui::error(p, &format!("'{name}' is not a custom provider"));
                ui::info(&format!(
                    "{}built-in providers cannot be removed{}",
                    p.dim, p.reset
                ));
                return Err(project::Exit(1));
            };
            if !provider.is_object() {
                return Err(project::fail(
                    p,
                    "provider in config.json must be an object",
                ));
            }
            let ptype = provider
                .get("provider_type")
                .map(|v| v.as_str().unwrap_or(""))
                .unwrap_or("http");
            owner::block_local_approval_if_protected(p, &root, "provider remove")?;
            owner::warn_if_approval_mode_unset(p, &root)?;
            let mut lines = vec![
                "Remove this custom provider from the current project.".into(),
                format!("{}{name} -> {}{}", p.dim, display_target(ptype, &provider), p.reset),
                "Brokered calls using this provider stop working once the daemon restarts; a running daemon may keep using it until then.".into(),
            ];
            let authorized = if !build_provider_table(&snapshot.value).0.contains_key(&name) {
                lines.push("kv does not load this provider now (its entry, or another, is invalid); removing it can let other providers work again.".into());
                owner::authorize_loosening_change(p, &root, &lines, &snapshot.value)?
            } else {
                owner::authorize_policy_change(p, &root, &lines, false)?
            };
            if !authorized {
                return Ok(());
            }
            let providers = snapshot
                .value
                .get_mut("providers")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| project::fail(p, "providers in config.json must be an object"))?;
            providers.shift_remove(&name);
            if ptype == "http"
                && let Some(http) = snapshot
                    .value
                    .get_mut("broker_policy")
                    .and_then(|v| v.get_mut("http"))
                    .and_then(Value::as_object_mut)
            {
                http.shift_remove(&name);
            }
            config::save_config(&root, &mut snapshot)
                .map_err(|e| project::fail(p, &e.to_string()))?;
            ui::success(p, &format!("removed provider: {name}"));
        }
        ProviderAction::Add(args) => {
            owner::block_local_approval_if_protected(p, &root, "provider add")?;
            if snapshot
                .value
                .get("providers")
                .is_some_and(|v| !v.is_object())
            {
                return Err(project::fail(
                    p,
                    "providers in config.json must be an object",
                ));
            }
            let name = &args.name;
            if is_builtin_provider_name(name) {
                return Err(project::fail(
                    p,
                    &format!("provider name is reserved and cannot be replaced: {name}"),
                ));
            }
            if snapshot
                .value
                .get("providers")
                .is_some_and(|v| v.get(name).is_some())
            {
                return Err(project::fail(
                    p,
                    &format!("provider already exists; remove it before re-adding: {name}"),
                ));
            }
            let ptype = args.provider_type.as_str();
            let port = |default| {
                args.port
                    .clone()
                    .filter(|v| v != &json!(0))
                    .unwrap_or(json!(default))
            };
            let (mut provider, policy_text) = match ptype {
                "http" => {
                    let mut v = json!({
                        "provider_type": "http",
                        "base_url": required(p, &args.url, "url")?,
                        "secret_name": required(p, &args.secret, "secret")?,
                        "auth_type": args.auth,
                    });
                    if args.auth == "query" {
                        v["auth_query_param"] = json!(
                            args.query_param
                                .as_deref()
                                .filter(|s| !s.is_empty())
                                .unwrap_or("key")
                        );
                    }
                    if args.auth == "header" {
                        v["auth_header_name"] = json!(
                            args.header_name
                                .as_deref()
                                .filter(|s| !s.is_empty())
                                .unwrap_or("Authorization")
                        );
                    }
                    (
                        v,
                        "This changes how kv_api can route credentialed requests.",
                    )
                }
                "postgres" | "mysql" => (
                    json!({
                        "provider_type": ptype,
                        "host": required(p, &args.host, "host")?,
                        "port": port(if ptype == "postgres" {5432} else {3306}),
                        "database": required(p, &args.database, "database")?,
                        "username": required(p, &args.username, "username")?,
                        "secret_name": required(p, &args.secret, "secret")?,
                    }),
                    "This changes how kv_query can connect to databases.",
                ),
                "redis" => (
                    json!({
                        "provider_type": "redis",
                        "host": required(p, &args.host, "host")?,
                        "port": port(6379),
                        "database": args.database.as_deref().filter(|s| !s.is_empty()).map(|s| json!(s)).unwrap_or(json!(0)),
                        "secret_name": required(p, &args.secret, "secret")?,
                    }),
                    "This changes how kv_query can connect to Redis.",
                ),
                "ssh" => (
                    json!({
                        "provider_type": "ssh",
                        "host": required(p, &args.host, "host")?,
                        "port": port(22),
                        "username": required(p, &args.username, "username")?,
                        "secret_name": required(p, &args.secret, "secret")?,
                    }),
                    "This changes how kv_ssh can connect to remote hosts.",
                ),
                _ => {
                    return Err(project::fail(
                        p,
                        &format!("unsupported provider type: {ptype}"),
                    ));
                }
            };
            let target = display_target(ptype, &provider);
            owner::warn_if_approval_mode_unset(p, &root)?;
            if !owner::authorize_loosening_change(
                p,
                &root,
                &[
                    "Add this custom provider to the current project.".into(),
                    format!("{}{name} ({ptype}) -> {target}{}", p.dim, p.reset),
                    policy_text.into(),
                ],
                &snapshot.value,
            )? {
                return Ok(());
            }
            match ptype {
                "http" => {
                    validate_http_provider(&provider).map_err(|reason| {
                        project::fail(p, &format!("provider configuration invalid: {reason}"))
                    })?;
                    let origin = provider["base_url"]
                        .as_str()
                        .unwrap_or("")
                        .trim_end_matches('/')
                        .to_owned();
                    provider["base_url"] = json!(origin);
                    let parsed = url::Url::parse(&format!("{origin}/test"))
                        .map_err(|e| project::fail(p, &format!("provider URL blocked: {e}")))?;
                    if let Err(reason) = check_url_safety(&parsed) {
                        ui::error(p, &format!("provider URL blocked: {reason}"));
                        ui::info(&format!(
                            "{}custom HTTP providers must use HTTPS and public endpoints{}",
                            p.dim, p.reset
                        ));
                        return Err(project::Exit(1));
                    }
                }
                "ssh" => validate_ssh_provider(&provider).map_err(|reason| {
                    project::fail(p, &format!("SSH provider invalid: {reason}"))
                })?,
                _ => validate_db_provider(&provider).map_err(|reason| {
                    project::fail(p, &format!("database provider invalid: {reason}"))
                })?,
            }
            let cfg = snapshot
                .value
                .as_object_mut()
                .ok_or_else(|| project::fail(p, "config must be an object"))?;
            let providers = cfg
                .entry("providers")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(|| project::fail(p, "providers in config.json must be an object"))?;
            providers.insert(name.clone(), provider.clone());
            let providers = providers.clone();
            if ptype == "http" {
                let broker = cfg
                    .entry("broker_policy")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .ok_or_else(|| {
                        project::fail(p, "broker_policy in config.json must be an object")
                    })?;
                let http = broker
                    .entry("http")
                    .or_insert_with(default_http_policy)
                    .as_object_mut()
                    .ok_or_else(|| {
                        project::fail(p, "broker_policy.http in config.json must be an object")
                    })?;
                for (name, custom) in providers {
                    if !custom.is_object() {
                        continue;
                    }
                    let custom_type = custom
                        .get("provider_type")
                        .filter(|v| truthy(v))
                        .or_else(|| custom.get("type").filter(|v| truthy(v)))
                        .map(|v| v.as_str().unwrap_or(""))
                        .unwrap_or("http");
                    if custom_type == "http" {
                        http.entry(name).or_insert_with(|| json!({
                            "origin": custom.get("base_url"), "secret_name": custom.get("secret_name"), "rules": [],
                        }));
                    }
                }
            }
            config::save_config(&root, &mut snapshot)
                .map_err(|e| project::fail(p, &e.to_string()))?;
            ui::success(p, &format!("provider added: {}{name}{}", p.bold, p.reset));
            ui::info(&format!("{}type:     {ptype}{}", p.dim, p.reset));
            ui::info(&format!("{}target:   {target}{}", p.dim, p.reset));
            let secret = display_value(provider.get("secret_name"));
            ui::info(&format!("{}secret:   {secret}{}", p.dim, p.reset));
            if ptype == "http" {
                ui::info(&format!("{}auth:     {}{}", p.dim, args.auth, p.reset));
                ui::info(&format!(
                    "{}policy:   deny all until an HTTP rule is configured{}",
                    p.dim, p.reset
                ));
            }
            ui::blank();
            ui::info(&format!(
                "{}Store the credential: kv set {secret}{}",
                p.dim, p.reset
            ));
            if ptype == "http" {
                ui::info(&format!(
                    "{}Next:                kv policy http add {name} --id read-example --method GET --path /...{}",
                    p.dim, p.reset
                ));
                ui::info(&format!(
                    "{}Then:                run kv vault approve-config, restart the daemon and call kv_api(provider=\"{name}\", path=\"/...\"){}",
                    p.dim, p.reset
                ));
            } else {
                let (kind, reason) = vault::vault_key_kind(&root);
                let tool = if ptype == "ssh" { "kv_ssh" } else { "kv_query" };
                if kind == Kind::Unreadable {
                    ui::info(&format!(
                        "{}MCP:                 {tool} is not offered {}{}",
                        p.dim,
                        vault::why_not_offered(kind, &reason),
                        p.reset
                    ));
                } else if kind != Kind::Unprotected {
                    ui::info(&format!(
                        "{}MCP:                 {tool} is parked on passphrase-protected (v3/v4) vaults in this release and is not offered; this provider is not usable by an agent yet{}",
                        p.dim, p.reset
                    ));
                } else {
                    ui::info(&format!(
                        "{}MCP:                 re-run your editor's kv setup with --allow-execute{}",
                        p.dim, p.reset
                    ));
                    let actions = if ptype == "ssh" {
                        "remote commands"
                    } else {
                        "database/Redis operations"
                    };
                    ui::warn(
                        p,
                        &format!(
                            "{tool} allows arbitrary {actions}; action policy is not implemented"
                        ),
                    );
                    let call = if ptype == "ssh" { "command" } else { "query" };
                    ui::info(&format!(
                        "{}Then:                {tool}(provider=\"{name}\", {call}=\"...\"){}",
                        p.dim, p.reset
                    ));
                }
            }
            ui::blank();
        }
    }
    Ok(())
}
