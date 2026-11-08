use kv_sandbox::classify::broad_secret_allowlist_reason;
use kv_store::config;
use serde_json::json;

use crate::owner_policy as owner;
use crate::project::{self, CmdResult};
use crate::ui::{self, Palette};

const NETWORK_CHANGE_NOTE: &str = "on a vault with a passphrase, kv_run uses this only after a restart (kv lock, then kv unlock) and a fresh approval of the run";

pub fn cmd_allow(p: &Palette, pattern: Option<&str>) -> CmdResult {
    let root = project::require_project(p)?;
    let Some(pattern) = pattern.filter(|s| !s.is_empty()) else {
        let (policy, allowed) =
            config::get_run_policy(&root).map_err(|e| project::fail(p, &e.to_string()))?;
        ui::header(p, &format!("kv_run policy: {policy}"));
        ui::blank();
        if policy == "allowlist" {
            if allowed.is_empty() {
                ui::info(&format!(
                    "{}no commands allowed — kv_run will block every run that receives secrets{}",
                    p.dim, p.reset
                ));
                ui::info(&format!(
                    "{}add commands: kv allow \"python3 app.py\"{}",
                    p.dim, p.reset
                ));
            } else {
                for command in allowed {
                    ui::info(&format!("{}✓{} {command}", p.green, p.reset));
                }
            }
        } else {
            ui::info(&format!(
                "{}using blocklist mode (shells and network tools are blocked in runs that receive secrets){}",
                p.dim, p.reset
            ));
            ui::info(&format!(
                "{}switch to allowlist: kv allow \"python3 app.py\"{}",
                p.dim, p.reset
            ));
        }
        ui::blank();
        return Ok(());
    };
    let snapshot = project::config_value(p, &root)?;
    owner::block_local_approval_if_protected(p, &root, "command allow")?;
    let reason = broad_secret_allowlist_reason(pattern);
    if !reason.is_empty() {
        ui::error(p, &reason);
        ui::info(&format!(
            "{}allow an exact command instead, for example: kv allow \"python3 app.py\"{}",
            p.dim, p.reset
        ));
        ui::info(&format!(
            "{}for ordinary no-secret work, use: kv run --no-secrets -- <command>{}",
            p.dim, p.reset
        ));
        return Err(project::Exit(1));
    }
    owner::warn_if_approval_mode_unset(p, &root)?;
    if !owner::authorize_loosening_change(p, &root, &[
        "Allow this kv_run command pattern for the current project.".into(),
        format!("{}{pattern}{}", p.dim, p.reset),
        "This puts the project's kv_run in allowlist mode: commands that receive secrets and are not on the list are then blocked.".into(),
    ], &snapshot.value)? { return Ok(()); }
    let changed = config::config_write_guard(&root, &snapshot, || {
        config::add_allowed_command(&root, pattern)
    })
    .map_err(|e| project::fail(p, &e.to_string()))?;
    if changed {
        ui::success(p, &format!("allowed: {}{pattern}{}", p.bold, p.reset));
        ui::info(&format!(
            "{}kv_run policy set to: allowlist{}",
            p.dim, p.reset
        ));
    } else {
        ui::info(&format!("already allowed: {pattern}"));
    }
    Ok(())
}

pub fn cmd_deny(p: &Palette, pattern: &str) -> CmdResult {
    let root = project::require_project(p)?;
    let snapshot = project::config_value(p, &root)?;
    let mut lines = vec![
        "Remove this kv_run command pattern from the current project allowlist.".into(),
        format!("{}{pattern}{}", p.dim, p.reset),
        "Matching commands will stop working unless allowed again.".into(),
    ];
    let authorized = if !broad_secret_allowlist_reason(pattern).is_empty() {
        owner::block_local_approval_if_protected(p, &root, "allowlist repair")?;
        lines.push("This entry is too broad to receive secrets and blocks matching runs; removing it can let narrower entries after it apply again.".into());
        owner::authorize_loosening_change(p, &root, &lines, &snapshot.value)?
    } else {
        owner::authorize_policy_change(p, &root, &lines, false)?
    };
    if !authorized {
        return Ok(());
    }
    let changed = config::config_write_guard(&root, &snapshot, || {
        config::remove_allowed_command(&root, pattern)
    })
    .map_err(|e| project::fail(p, &e.to_string()))?;
    if changed {
        ui::success(p, &format!("removed: {}{pattern}{}", p.bold, p.reset));
    } else {
        ui::error(p, &format!("not in allowlist: {pattern}"));
    }
    Ok(())
}

pub fn cmd_network_allow(p: &Palette, pattern: Option<&str>) -> CmdResult {
    let root = project::require_project(p)?;
    let snapshot = project::config_value(p, &root)?;
    let Some(pattern) = pattern.filter(|s| !s.is_empty()) else {
        let commands = config::command_patterns(&snapshot.value, "network_commands")
            .map_err(|e| project::fail(p, &e.to_string()))?;
        ui::header(p, "network-allowed commands");
        ui::blank();
        if commands.is_empty() {
            ui::info(&format!(
                "{}no commands on the network list{}",
                p.dim, p.reset
            ));
            ui::info(&format!(
                "{}add one: kv network-allow \"twine upload\"{}",
                p.dim, p.reset
            ));
        } else {
            for command in commands {
                ui::info(&format!("  {}✓{} {command}", p.green, p.reset));
            }
        }
        ui::blank();
        ui::info(&format!(
            "{}this list is not the only rule: kv_run runs without secrets and capability runs may also get network{}",
            p.dim, p.reset
        ));
        if owner::vault_has_passphrase(&root) {
            ui::info(&format!("{}{NETWORK_CHANGE_NOTE}{}", p.dim, p.reset));
        }
        ui::blank();
        return Ok(());
    };
    owner::block_local_approval_if_protected(p, &root, "network allow")?;
    owner::warn_if_approval_mode_unset(p, &root)?;
    if !owner::authorize_loosening_change(
        p,
        &root,
        &[
            "Allow outbound network access for this kv_run command pattern.".into(),
            format!("{}{pattern}{}", p.dim, p.reset),
            "Matching commands will be able to make outbound connections.".into(),
        ],
        &snapshot.value,
    )? {
        return Ok(());
    }
    let changed = config::config_write_guard(&root, &snapshot, || {
        config::add_network_command(&root, pattern)
    })
    .map_err(|e| project::fail(p, &e.to_string()))?;
    if changed {
        ui::success(
            p,
            &format!("network access allowed: {}{pattern}{}", p.bold, p.reset),
        );
        if !owner::vault_has_passphrase(&root) {
            ui::info(&format!(
                "{}this command can now make outbound connections during kv_run{}",
                p.dim, p.reset
            ));
        }
    } else {
        ui::info(&format!("already allowed: {pattern}"));
    }
    if owner::vault_has_passphrase(&root) {
        ui::info(&format!("{}{NETWORK_CHANGE_NOTE}{}", p.dim, p.reset));
    }
    Ok(())
}

pub fn cmd_network_deny(p: &Palette, pattern: &str) -> CmdResult {
    let root = project::require_project(p)?;
    let mut snapshot = project::config_value(p, &root)?;
    let mut commands = config::command_patterns(&snapshot.value, "network_commands")
        .map_err(|e| project::fail(p, &e.to_string()))?;
    let Some(index) = commands.iter().position(|entry| entry == pattern) else {
        ui::error(p, &format!("not in network-allowed list: {pattern}"));
        return Ok(());
    };
    if !owner::authorize_policy_change(
        p,
        &root,
        &[
            "Revoke outbound network access for this kv_run command pattern.".into(),
            format!("{}{pattern}{}", p.dim, p.reset),
            "Matching commands will return to network-isolated execution.".into(),
        ],
        false,
    )? {
        return Ok(());
    }
    commands.remove(index);
    snapshot.value["security"]["network_commands"] = json!(commands);
    config::save_config(&root, &mut snapshot).map_err(|e| project::fail(p, &e.to_string()))?;
    ui::success(
        p,
        &format!("network access revoked: {}{pattern}{}", p.bold, p.reset),
    );
    Ok(())
}
