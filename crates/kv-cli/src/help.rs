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
    ui::cmd(p, "kv unlock", "Open vault (start agent)");
    ui::cmd(p, "kv lock", "Close vault (stop agent)");
    ui::cmd(p, "kv status", "See vault, recovery, and backup state");
    ui::blank();
    section(p, "Manage secrets");
    ui::cmd(p, "kv set KEY", "Store a secret (hidden input)");
    ui::cmd(p, "kv ls", "List secret names");
    ui::cmd(p, "kv rm KEY", "Delete a secret");
    ui::cmd(p, "kv history list KEY", "A secret's earlier values");
    ui::blank();
    section(p, "Environments");
    ui::cmd(p, "kv envs", "List environments");
    ui::cmd(p, "kv env create NAME", "Create new environment");
    ui::blank();
    section(p, "Vault");
    ui::cmd(p, "kv backup create", "Write an encrypted backup file");
    ui::cmd(
        p,
        "kv vault approve-config",
        "Approve where this vault may send credentials",
    );
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
    ui::blank();
    section(p, "Primary local commands");
    ui::cmd(p, "kv ls / get / rm", "Inspect or update stored secrets");
    ui::cmd(
        p,
        "kv approvals list / watch",
        "Review one-call permit requests",
    );
    ui::cmd(p, "kv status", "Check vault health");
    ui::cmd(
        p,
        "kv lock",
        "Stop the daemon and clear secrets from memory",
    );
    ui::blank();
    section(p, "Advanced");
    ui::cmd(p, "kv env ...", "Multiple environments in one vault");
    ui::cmd(p, "kv history ...", "Earlier values, undo and forget");
    ui::cmd(p, "kv backup ...", "Encrypted backup files and restore");
    ui::cmd(p, "kv export", "Print an environment's secrets");
    ui::cmd(
        p,
        "kv vault approve-config",
        "Approve where this vault may send credentials",
    );
    ui::blank();
    ui::info("This Linux v1 surface is intentionally limited to supported local vault commands.");
    ui::info(&format!(
        "{}Use 'kv COMMAND --help' for per-command flags. Version: {VERSION}{}",
        p.dim, p.reset
    ));
    ui::blank();
}
