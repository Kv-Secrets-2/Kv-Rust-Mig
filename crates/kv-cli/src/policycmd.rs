use crate::owner_policy as owner;
use crate::project::{self, CmdResult};
use crate::ui::{self, Palette};
use kv_broker::{
    HttpRuleOptions, build_provider_table, default_http_policy, http_policy_route_label,
    http_policy_rule, validate_http_policy_binding, validate_http_provider_policy,
};
use kv_store::config;
use serde_json::{Map, Value, json};

pub enum PolicyAction {
    Command(crate::command_policy::CommandPolicyAction),
    Unavailable,
    HttpList(Option<String>),
    HttpAdd {
        provider: String,
        rule: Box<HttpRuleOptions>,
    },
    HttpRemove {
        provider: String,
        id: String,
    },
}

fn read_http(p: &Palette, config: &Value) -> CmdResult<Map<String, Value>> {
    let Some(broker) = config.get("broker_policy") else {
        return Ok(Map::new());
    };
    let broker = broker
        .as_object()
        .ok_or_else(|| project::fail(p, "broker_policy in config.json must be an object"))?;
    let Some(http) = broker.get("http") else {
        return Ok(Map::new());
    };
    http.as_object()
        .cloned()
        .ok_or_else(|| project::fail(p, "broker_policy.http in config.json must be an object"))
}

fn load_provider(p: &Palette, config: &Value, name: &str) -> CmdResult<Value> {
    let Some(provider) = build_provider_table(config).0.remove(name) else {
        ui::error(p, &format!("unknown provider: {name}"));
        ui::info(&format!(
            "{}configure custom providers with: kv provider add NAME --url URL --secret SECRET_NAME{}",
            p.dim, p.reset
        ));
        return Err(project::Exit(1));
    };
    if provider
        .get("provider_type")
        .and_then(Value::as_str)
        .unwrap_or("http")
        != "http"
    {
        ui::error(p, &format!("provider '{name}' is not an HTTP API provider"));
        ui::info(&format!(
            "{}HTTP policy rules apply only to kv_api providers{}",
            p.dim, p.reset
        ));
        return Err(project::Exit(1));
    }
    Ok(provider)
}

fn validate(p: &Palette, name: &str, entry: &Value) -> CmdResult {
    if let Some(reason) = validate_http_provider_policy(entry) {
        return Err(project::fail(
            p,
            &format!("HTTP policy invalid for {name}: {reason}"),
        ));
    }
    Ok(())
}

fn entry_for_provider<'a>(
    p: &Palette,
    config: &'a mut Value,
    name: &str,
    provider: &Value,
) -> CmdResult<&'a mut Value> {
    let config = config
        .as_object_mut()
        .ok_or_else(|| project::fail(p, "config must be an object"))?;
    let broker = config
        .entry("broker_policy")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| project::fail(p, "broker_policy in config.json must be an object"))?;
    let http = broker
        .entry("http")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| project::fail(p, "broker_policy.http in config.json must be an object"))?;
    if !http.contains_key(name) {
        for (key, value) in default_http_policy()
            .as_object()
            .expect("default HTTP policy")
        {
            http.entry(key.clone()).or_insert_with(|| value.clone());
        }
        http.entry(name.to_owned()).or_insert_with(|| {
            json!({
                "origin":provider["base_url"].as_str().unwrap_or("").trim_end_matches('/'),
                "secret_name":provider.get("secret_name"),"rules":[],
            })
        });
    }
    let entry = http.get_mut(name).expect("HTTP entry inserted");
    let entry = entry
        .as_object_mut()
        .ok_or_else(|| project::fail(p, &format!("broker_policy.http.{name} must be an object")))?;
    let matching = provider.get("base_url").and_then(Value::as_str).is_some()
        && provider
            .get("secret_name")
            .and_then(Value::as_str)
            .is_some()
        && entry
            .get("origin")
            .and_then(Value::as_str)
            .map(|v| v.trim_end_matches('/'))
            == provider
                .get("base_url")
                .and_then(Value::as_str)
                .map(|v| v.trim_end_matches('/'))
        && entry.get("secret_name") == provider.get("secret_name");
    if !matching {
        ui::error(
            p,
            &format!("broker_policy.http.{name} does not match provider configuration"),
        );
        ui::info(&format!(
            "{}remove and re-add the provider, or repair .secrets/config.json in a trusted editor{}",
            p.dim, p.reset
        ));
        return Err(project::Exit(1));
    }
    if !entry.entry("rules").or_insert_with(|| json!([])).is_array() {
        return Err(project::fail(
            p,
            &format!("broker_policy.http.{name}.rules must be an array"),
        ));
    }
    Ok(http.get_mut(name).expect("HTTP entry inserted"))
}

fn label(p: &Palette, rule: &Value) -> CmdResult<String> {
    http_policy_route_label(rule).map_err(|e| project::fail(p, &e))
}

fn print_provider(p: &Palette, name: &str, entry: &Value) -> CmdResult {
    ui::info(&format!(
        "{}{name}{}  {}{}  {}{}",
        p.green,
        p.reset,
        p.dim,
        entry["origin"].as_str().unwrap_or("?"),
        entry["secret_name"].as_str().unwrap_or("?"),
        p.reset
    ));
    let rules = entry["rules"].as_array().expect("validated rules");
    if rules.is_empty() {
        ui::info(&format!(
            "  {}deny all: no HTTP rules configured{}",
            p.dim, p.reset
        ));
        return Ok(());
    }
    for rule in rules {
        let mut extras = Vec::new();
        let join = |field: &str| {
            rule[field]
                .as_array()
                .map(|v| {
                    v.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default()
        };
        if rule["allow_query"] == json!(true) {
            extras.push(format!("query:{}", join("query_keys")));
        }
        if rule["allowed_headers"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
        {
            extras.push(format!("headers:{}", join("allowed_headers")));
        }
        let extra = if extras.is_empty() {
            String::new()
        } else {
            format!("  {}{}{}", p.dim, extras.join("; "), p.reset)
        };
        ui::info(&format!(
            "  {}{}{}  {}{extra}",
            p.yellow,
            rule["id"].as_str().unwrap_or("<missing>"),
            p.reset,
            label(p, rule)?
        ));
    }
    Ok(())
}

pub fn cmd_policy(p: &Palette, action: PolicyAction) -> CmdResult {
    if let PolicyAction::Command(action) = action {
        return crate::command_policy::run(p, action);
    }
    if matches!(action, PolicyAction::Unavailable) {
        return Err(project::fail(
            p,
            "command policy is not available in this build",
        ));
    }
    let root = project::require_project(p)?;
    let mut snapshot = project::config_value(p, &root)?;
    match action {
        PolicyAction::HttpList(filter) => {
            let http = read_http(p, &snapshot.value)?;
            ui::header(p, "HTTP broker policy");
            ui::blank();
            if let Some(name) = filter.filter(|v| !v.is_empty()) {
                let Some(entry) = http.get(&name) else {
                    ui::info(&format!(
                        "{}no HTTP policy entry for provider: {name}{}",
                        p.dim, p.reset
                    ));
                    return Ok(());
                };
                valid_list_entry(p, &snapshot.value, &name, entry)?;
                print_provider(p, &name, entry)?;
            } else if http.is_empty() {
                ui::info(&format!(
                    "{}no explicit HTTP policy configured{}",
                    p.dim, p.reset
                ));
                ui::info(&format!(
                    "{}add one: kv policy http add github --id user-read --method GET --path /user{}",
                    p.dim, p.reset
                ));
            } else {
                let mut names = http.keys().collect::<Vec<_>>();
                names.sort();
                for name in names {
                    let entry = &http[name];
                    valid_list_entry(p, &snapshot.value, name, entry)?;
                    print_provider(p, name, entry)?;
                }
            }
            ui::blank();
        }
        PolicyAction::HttpAdd {
            provider: name,
            rule: options,
        } => {
            owner::block_local_approval_if_protected(p, &root, "HTTP policy add")?;
            let provider = load_provider(p, &snapshot.value, &name)?;
            let entry = entry_for_provider(p, &mut snapshot.value, &name, &provider)?;
            let rules = entry["rules"].as_array().expect("entry rules");
            if rules
                .iter()
                .any(|r| r.get("id").and_then(Value::as_str) == Some(&options.id))
            {
                return Err(project::fail(
                    p,
                    &format!("HTTP policy rule already exists for {name}: {}", options.id),
                ));
            }
            let rule = match http_policy_rule(&options) {
                Ok(rule) => rule,
                Err(reason) => {
                    ui::error(p, &reason);
                    ui::info(&format!(
                        "{}supported methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT{}",
                        p.dim, p.reset
                    ));
                    return Err(project::Exit(1));
                }
            };
            let mut candidate = entry.clone();
            candidate["rules"]
                .as_array_mut()
                .expect("entry rules")
                .push(rule.clone());
            validate(p, &name, &candidate)?;
            let unsafe_rule = rule["approval"] == "per-call";
            let mut lines = vec![
                if unsafe_rule { "Add this HTTP broker policy rule." } else { "Add this read-only HTTP broker policy rule." }.into(),
                format!("Provider: {}{name}{}", p.dim, p.reset),
                format!("Rule: {}{}  {}{}", p.dim, options.id, label(p, &rule)?, p.reset),
                "Only matching kv_api calls can use this provider credential.".into(),
                if unsafe_rule { "Unsafe rules require a signed one-call permit; this rule alone never approves a mutation." } else { "Unsafe HTTP methods and mutation permits are not approved by this command." }.into(),
            ];
            if !options.query_keys.is_empty() {
                lines.push(format!(
                    "Allowed query keys: {}{}{}",
                    p.dim,
                    options.query_keys.join(", "),
                    p.reset
                ));
            }
            if !options.allowed_headers.is_empty() {
                lines.push(format!(
                    "Allowed caller headers: {}{}{}",
                    p.dim,
                    options.allowed_headers.join(", "),
                    p.reset
                ));
            }
            owner::warn_if_approval_mode_unset(p, &root)?;
            if !owner::authorize_loosening_change(p, &root, &lines, &snapshot.value)? {
                return Ok(());
            }
            entry_for_provider(p, &mut snapshot.value, &name, &provider)?["rules"]
                .as_array_mut()
                .expect("entry rules")
                .push(rule);
            config::save_config(&root, &mut snapshot)
                .map_err(|e| project::fail(p, &e.to_string()))?;
            ui::success(
                p,
                &format!(
                    "HTTP policy rule added: {}{name}/{}{}",
                    p.bold, options.id, p.reset
                ),
            );
            reload_note(p);
        }
        PolicyAction::HttpRemove { provider: name, id } => {
            let provider = load_provider(p, &snapshot.value, &name)?;
            let entry = entry_for_provider(p, &mut snapshot.value, &name, &provider)?;
            let rules = entry["rules"].as_array().expect("entry rules");
            let Some(index) = rules
                .iter()
                .position(|r| r.get("id").and_then(Value::as_str) == Some(&id))
            else {
                return Err(project::fail(
                    p,
                    &format!("HTTP policy rule not found for {name}: {id}"),
                ));
            };
            let removed = rules[index].clone();
            let mut candidate = entry.clone();
            candidate["rules"]
                .as_array_mut()
                .expect("entry rules")
                .remove(index);
            validate(p, &name, &candidate)?;
            let repair = validate_http_provider_policy(entry).is_some();
            let mut lines = vec![
                "Remove this HTTP broker policy rule.".into(),
                format!("Provider: {}{name}{}", p.dim, p.reset),
                format!("Rule: {}{id}  {}{}", p.dim, label(p, &removed)?, p.reset),
                "Matching kv_api calls will be denied after the daemon reloads this policy.".into(),
            ];
            if repair {
                owner::block_local_approval_if_protected(p, &root, "HTTP policy repair")?;
                lines.push("This provider's current HTTP rules are invalid, so kv denies all its calls; removing this rule can let the remaining rules work again.".into());
            }
            owner::warn_if_approval_mode_unset(p, &root)?;
            let authorized = if repair {
                owner::authorize_loosening_change(p, &root, &lines, &snapshot.value)?
            } else {
                owner::authorize_policy_change(p, &root, &lines, false)?
            };
            if !authorized {
                return Ok(());
            }
            entry_for_provider(p, &mut snapshot.value, &name, &provider)?["rules"]
                .as_array_mut()
                .expect("entry rules")
                .remove(index);
            config::save_config(&root, &mut snapshot)
                .map_err(|e| project::fail(p, &e.to_string()))?;
            ui::success(
                p,
                &format!("HTTP policy rule removed: {}{name}/{id}{}", p.bold, p.reset),
            );
            reload_note(p);
        }
        PolicyAction::Unavailable | PolicyAction::Command(_) => unreachable!(),
    }
    Ok(())
}

fn valid_list_entry(p: &Palette, config: &Value, name: &str, entry: &Value) -> CmdResult {
    if !entry.is_object() {
        return Err(project::fail(
            p,
            &format!("broker_policy.http.{name} must be an object"),
        ));
    }
    validate(p, name, entry)?;
    let provider = load_provider(p, config, name)?;
    if let Some(reason) = validate_http_policy_binding(entry, &provider) {
        return Err(project::fail(
            p,
            &format!("HTTP policy invalid for {name}: {reason}"),
        ));
    }
    Ok(())
}

fn reload_note(p: &Palette) {
    ui::info(&format!(
        "{}run kv vault approve-config, then restart the daemon before using this policy{}",
        p.dim, p.reset
    ));
}
