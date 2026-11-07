//! `_show_help` (plain `kv`) and `_show_cli_help` (`kv -h`) from `kv/cli.py`.

use crate::project::{find_project_root, is_agent_running};
use crate::ui::{self, BoxStyle, Palette};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn banner(p: &Palette, tagline: &str) {
    ui::blank();
    ui::out(&format!(
        "  {}{}\u{2591}\u{2592}\u{2593} kv {}{}\u{2014} {tagline}{}",
        p.bold, p.cyan, p.reset, p.dim, p.reset
    ));
    ui::blank();
}

fn section(p: &Palette, title: &str) {
    ui::out(&format!("  {}{title}{}", p.white, p.reset));
}

pub fn show_help(p: &Palette) {
    let root = find_project_root();
    banner(p, "encrypted secrets for developers");
    let Some(root) = root else {
        ui::boxed(
            p,
            &[
                "No vault found in this directory.",
                "",
                "Get started:  kv init",
            ],
            BoxStyle::Warn,
        );
        ui::blank();
        return;
    };
    if is_agent_running(&root) {
        ui::out(&format!(
            "  {} vault unlocked \u{2014} agent running",
            ui::dot_on(p)
        ));
    } else {
        ui::out(&format!(
            "  {} vault locked {}\u{2014} run 'kv unlock' to open{}",
            ui::dot_off(p),
            p.dim,
            p.reset
        ));
    }
    ui::blank();
    section(p, "Getting started");
    ui::cmd(p, "kv init", "Set up a new vault");
    ui::cmd(
        p,
        "kv 2fa enable",
        "Optional: add authenticator + backup codes",
    );
    ui::cmd(
        p,
        "kv setup EDITOR",
        "Connect Claude Code, Codex, Cursor, VS Code",
    );
    ui::cmd(p, "kv unlock", "Open vault (start agent)");
    ui::cmd(p, "kv lock", "Close vault (stop agent)");
    ui::blank();
    section(p, "Manage secrets");
    ui::cmd(p, "kv set KEY", "Store a secret (hidden input)");
    ui::cmd(p, "kv ls", "List secret names");
    ui::cmd(p, "kv rm KEY", "Delete a secret");
    ui::blank();
    section(p, "Use secrets");
    ui::cmd(p, "kv_api", "AI agent makes API call (key stays in daemon)");
    ui::cmd(
        p,
        "kv preflight",
        "Plan broker capabilities before running a script",
    );
    ui::cmd(
        p,
        "kv approvals watch",
        "User-owned inbox for pending secret-use requests",
    );
    ui::cmd(
        p,
        "kv policy watch",
        "Review blocked command-policy requests",
    );
    ui::cmd(
        p,
        "kv approval-mode",
        "Choose local vs protected approval boundary",
    );
    ui::cmd(
        p,
        "kv run --secret NAME",
        "Run approved command with scoped secrets",
    );
    ui::cmd(p, "kv status", "See vault, recovery, and backup-code state");
    ui::blank();
    section(p, "Environments");
    ui::cmd(p, "kv envs", "List environments");
    ui::cmd(p, "kv env create NAME", "Create new environment");
    ui::blank();
    section(p, "Security & diagnostics");
    ui::cmd(p, "kv doctor", "Run health checks");
    ui::cmd(p, "kv audit", "View audit log");
    ui::cmd(p, "kv recovery-key rotate", "Rotate recovery material");
    ui::cmd(p, "kv provider list", "Show API providers");
    ui::blank();
    ui::out(&format!(
        "  {}v{VERSION} \u{2014} kvsecure.com{}",
        p.dim, p.reset
    ));
    ui::blank();
}

pub fn show_cli_help(p: &Palette) {
    banner(p, "credential broker for developers and AI agents");
    section(p, "Quick start");
    ui::cmd(p, "kv init", "Create a vault and choose where it lives");
    ui::cmd(p, "kv set OPENAI_API_KEY", "Store a secret");
    ui::cmd(p, "kv unlock", "Start the daemon");
    ui::cmd(p, "kv setup claude-code", "Connect an editor explicitly");
    ui::blank();
    section(p, "Primary local commands");
    ui::cmd(
        p,
        "kv 2fa enable",
        "Optional: add authenticator + backup codes",
    );
    ui::cmd(p, "kv recovery-key rotate", "Rotate recovery material");
    ui::cmd(
        p,
        "kv passphrase reset",
        "Reset passphrase with the recovery key",
    );
    ui::cmd(p, "kv ls / get / rm", "Inspect or update stored secrets");
    ui::cmd(p, "kv status / doctor", "Check vault health and setup");
    ui::cmd(p, "kv audit", "Inspect audit events (a hash-chained log)");
    ui::blank();
    section(p, "Editor setup");
    ui::cmd(
        p,
        "kv setup EDITOR",
        "Supports claude-code, codex, cursor, vscode, and more",
    );
    ui::cmd(p, "kv mcp", "Print MCP config instead of writing it");
    ui::blank();
    section(p, "Advanced");
    ui::cmd(p, "kv provider ...", "Custom API/database/SSH providers");
    ui::cmd(p, "kv env ...", "Multiple environments in one vault");
    ui::cmd(
        p,
        "kv vault migrate-drawers --dry-run",
        "Check an older vault's drawer migration safely",
    );
    ui::cmd(p, "kv grant ...", "Approve or revoke exact kv_run grants");
    ui::cmd(p, "kv approvals ...", "Review pending approval requests");
    ui::cmd(p, "kv policy ...", "Allow or keep blocking command shapes");
    ui::cmd(p, "kv approval-mode ...", "Set approval security mode");
    ui::cmd(
        p,
        "kv preflight -- CMD",
        "Report broker capability needs before approval",
    );
    ui::cmd(
        p,
        "kv run --secret NAME",
        "Sandboxed subprocess with approved scoped secrets",
    );
    ui::blank();
    ui::info(
        "Experimental cloud-sync commands remain available but are intentionally omitted here.",
    );
    ui::info(&format!(
        "{}Use 'kv COMMAND --help' for per-command flags. Version: {VERSION}{}",
        p.dim, p.reset
    ));
    ui::blank();
}
