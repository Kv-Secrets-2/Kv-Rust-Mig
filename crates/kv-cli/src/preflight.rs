//! Report-only planning; request creation is deliberately unavailable in this build.

use serde_json::Value;

use crate::project::{CmdResult, fail};
use crate::render::{self, VALUE_NOT_SHOWN};
use crate::ui::{self, Palette};

pub fn repr(value: &str) -> String {
    crate::secrets::py_repr(value)
        .chars()
        .map(|c| {
            if !c.is_ascii() && !render::is_printable(&c.to_string()) {
                let code = u32::from(c);
                if code <= 0xff {
                    format!("\\x{code:02x}")
                } else if code <= 0xffff {
                    format!("\\u{code:04x}")
                } else {
                    format!("\\U{code:08x}")
                }
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[derive(Default)]
pub struct Args {
    pub cwd: Option<String>,
    pub json: bool,
    pub request: bool,
    pub cmd: Vec<String>,
}

pub fn is_integer(value: &str) -> bool {
    use unicode_general_category::{GeneralCategory, get_general_category};
    let value =
        value.trim_matches(|c: char| c.is_whitespace() && !('\u{1c}'..='\u{1f}').contains(&c));
    let value = value.strip_prefix(['+', '-']).unwrap_or(value);
    let mut digit = false;
    let mut count = 0;
    for c in value.chars() {
        if get_general_category(c) == GeneralCategory::DecimalNumber {
            digit = true;
            count += 1;
        } else if c == '_' && digit {
            digit = false;
        } else {
            return false;
        }
    }
    digit && count <= 4300
}

pub fn run(p: &Palette, mut args: Args) -> CmdResult {
    if args.cmd.first().is_some_and(|s| s == "--") {
        args.cmd.remove(0);
    }
    if args.request {
        let cwd = std::env::current_dir().map_err(|e| fail(p, &e.to_string()))?;
        let cwd = crate::fsutil::normalize(
            &cwd.join(args.cwd.as_deref().filter(|s| !s.is_empty()).unwrap_or(".")),
        );
        let mut root = cwd.clone();
        loop {
            if std::fs::symlink_metadata(root.join(".secrets")).is_ok_and(|m| m.is_dir()) {
                break;
            }
            if !root.pop() {
                return Err(fail(
                    p,
                    &format!(
                        "not inside a kv project: {}",
                        render::escape(&cwd.to_string_lossy())
                    ),
                ));
            }
        }
        return Err(fail(
            p,
            "kv preflight --request is not supported by this kv build yet; run kv preflight without --request",
        ));
    }
    let manifest = kv_preflight::preflight_command(&args.cmd, args.cwd.as_deref())
        .map_err(|e| fail(p, &e.to_string()))?;
    if args.json {
        ui::out(&kv_preflight::manifest_json(&manifest));
    } else {
        print_text(p, &manifest.as_dict());
    }
    Ok(())
}

const NOT_SHOWN_NOTE: &str = "The full command is too long to show here; kv preflight --json shows it, and kv preflight --request files it.";

fn command_line(command: &str) -> String {
    let Some(parts) = render::split_command(command) else {
        return render::escape(command);
    };
    let text = render::run_again_text(&parts);
    if text.chars().count() > render::MAX_SHOWN {
        VALUE_NOT_SHOWN.to_owned()
    } else {
        text
    }
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
fn flag(v: &Value) -> bool {
    v.as_bool().unwrap_or(false)
}
fn list(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn escaped_list(v: &Value) -> String {
    list(v)
        .iter()
        .map(|s| render::escape(text(s)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_text(p: &Palette, data: &Value) {
    let (dim, bold, reset) = (p.dim, p.bold, p.reset);
    ui::header(p, "preflight");
    ui::blank();
    for (label, field) in [
        ("Command", "command"),
        ("Folder", "cwd"),
        ("Script", "script_path"),
    ] {
        if field != "script_path" || !text(&data[field]).is_empty() {
            ui::info(&format!(
                "{label}: {dim}{}{reset}",
                render::escape(text(&data[field]))
            ));
        }
    }
    ui::info(&format!("Command mode: {}", text(&data["command_mode"])));
    if !flag(&data["command_allowed"]) {
        ui::warn(
            p,
            &format!(
                "Command is not eligible for secret-bearing kv_run: {}",
                render::escape(text(&data["command_reason"]))
            ),
        );
    }
    let raw = &data["raw_key_findings"];
    let has_raw = raw["count"].as_u64().unwrap_or(0) > 0;
    if has_raw {
        ui::warn(
            p,
            "Raw key exposure: rewrite required before broker capability approval",
        );
    } else {
        ui::info("Raw key exposure: no  (capability mode: script receives KV_CAP_TOKEN only)");
    }
    ui::blank();
    ui::info(&format!("{bold}Detected needs{reset}"));
    let mut api: Vec<_> = data["api"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.iter())
        .collect();
    api.sort_by_key(|(provider, _)| *provider);
    let mut any_api = false;
    for (provider, need) in &api {
        if !(flag(&need["imported"])
            || need["call_sites"].as_u64().unwrap_or(0) > 0
            || flag(&need["direct_sdk"])
            || flag(&need["brokered"]))
        {
            continue;
        }
        any_api = true;
        let (estimate, recommendation) = if flag(&need["unknown_call_count"]) {
            ("unknown".to_owned(), "choose max-calls manually".to_owned())
        } else {
            (
                need["estimated_calls"].to_string(),
                need["recommended_max_calls"].to_string(),
            )
        };
        ui::info(&format!(
            "- api:{}  calls={estimate}  recommended_max_calls={recommendation}",
            render::escape(provider)
        ));
        if flag(&need["imported"]) && need["call_sites"].as_u64().unwrap_or(0) == 0 {
            ui::info(&format!(
                "  {dim}imported but no detected API call site; recommend 0 calls{reset}"
            ));
        }
        if flag(&need["direct_sdk"]) {
            ui::info(&format!(
                "  {}!{reset} direct SDK usage detected; rewrite to kv.cap_client.api_call before approving capability mode",
                p.yellow
            ));
        }
        if flag(&need["brokered"]) {
            ui::info(&format!(
                "  {dim}brokered kv.cap_client/api_call usage detected{reset}"
            ));
        }
    }
    if !any_api {
        ui::info("- api: none detected");
    }
    let guidance = list(&data["agent_guidance"]);
    if !guidance.is_empty() {
        ui::blank();
        ui::info(&format!("{bold}Agent guidance{reset}"));
        for line in guidance {
            let line = text(line);
            let shown = render::escape(line);
            if render::has_hidden(line) {
                ui::info(&format!(
                    "- {dim}{shown}{reset}  (shown escaped; the command cannot be copied as is)"
                ));
            } else {
                ui::info(&format!(
                    "- {dim}{}{reset}",
                    if shown == VALUE_NOT_SHOWN {
                        &shown
                    } else {
                        line
                    }
                ));
            }
        }
    }
    let ssh = &data["ssh"];
    if flag(&ssh["detected"]) {
        let hosts = if list(&ssh["hosts"]).is_empty() {
            "unknown".to_owned()
        } else {
            escaped_list(&ssh["hosts"])
        };
        ui::info(&format!("- ssh: detected  hosts={hosts}"));
    } else {
        ui::info("- ssh: not detected");
    }
    let writes = &data["files"]["writes"];
    ui::info(&format!(
        "- file writes: {}",
        if list(writes).is_empty() {
            "none detected".to_owned()
        } else {
            escaped_list(writes)
        }
    ));
    if has_raw {
        ui::warn(
            p,
            &format!(
                "Raw-key patterns detected: {} ({})",
                raw["count"],
                escaped_list(&raw["codes"])
            ),
        );
    } else {
        ui::info("- raw key access: not detected");
    }
    let approval = &data["recommended_approval"];
    ui::blank();
    ui::info(&format!("{bold}Recommended approval{reset}"));
    if !list(&approval["approval_commands"]).is_empty() {
        let mut lines: Vec<_> = list(&approval["approval_commands"])
            .iter()
            .chain(list(&approval["run_commands"]))
            .map(|s| command_line(text(s)))
            .collect();
        if let Some(last) = lines.iter().rposition(|s| s == VALUE_NOT_SHOWN) {
            lines.insert(last + 1, NOT_SHOWN_NOTE.to_owned());
        }
        for line in lines {
            ui::info(&format!("{dim}{line}{reset}"));
        }
    } else {
        ui::info(&format!(
            "{dim}No broker capability approval recommended from static evidence.{reset}"
        ));
        if !text(&approval["blocked_reason"]).is_empty() {
            ui::info(&format!(
                "{dim}Reason: {}.{reset}",
                render::escape(text(&approval["blocked_reason"]))
            ));
        }
        if api.iter().any(|(_, need)| flag(&need["rewrite_required"])) {
            ui::info(&format!(
                "{dim}Rewrite direct SDK/raw-key calls to kv.cap_client before granting broker capabilities.{{RESET}}"
            ));
        }
    }
    ui::blank();
    ui::info(&format!("{bold}Limits{reset}"));
    for limit in list(&data["limits"]) {
        ui::info(&format!("- {dim}{}{reset}", render::escape(text(limit))));
    }
}
