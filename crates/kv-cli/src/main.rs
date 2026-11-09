//! The `kv` binary: `kv/cli.py`'s `main()` and `build_parser()` for the commands this
//! build carries, plus the MCP server on stdio.

mod args;
mod backup;
mod envcmd;
mod fsutil;
mod help;
mod history;
mod hook;
mod init;
mod lifecycle;
mod preflight;
mod project;
mod registry;
mod render;
mod reserved_env;
mod secrets;
mod terminal;
mod ui;
mod vaultcmd;

use project::Exit;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let p = ui::palette();
    if argv.len() == 1 && (argv[0] == "-h" || argv[0] == "--help") {
        help::show_cli_help(&p);
        std::process::exit(0);
    }
    if argv.first().map(String::as_str) == Some("mcp-server") {
        std::process::exit(kv_mcp::main(&argv[1..]));
    }
    let code = match args::parse(&argv) {
        Err(args::ParseError::Usage(text)) => {
            eprint!("{text}");
            2
        }
        Err(args::ParseError::Version) => {
            ui::out(&format!("kv {}", help::VERSION));
            0
        }
        Err(args::ParseError::Help(text)) => {
            print!("{text}");
            0
        }
        Err(args::ParseError::Unknown) => {
            help::show_help(&p);
            1
        }
        Ok(None) => {
            help::show_help(&p);
            0
        }
        Ok(Some(command)) => match run(&p, command) {
            Ok(()) => 0,
            Err(Exit(code)) => code,
        },
    };
    std::process::exit(code);
}

fn run(p: &ui::Palette, command: args::Command) -> Result<(), Exit> {
    use args::Command::*;
    if command.needs_vault_access()
        && let Some(root) = project::find_project_root()
    {
        project::prepare_vault_access(p, &root)?;
    }
    match command {
        Version => {
            ui::out(&format!("kv {}", help::VERSION));
            Ok(())
        }
        Init { location, path } => init::cmd_init(p, location.as_deref(), path.as_deref()),
        Set { secret, env } => secrets::cmd_set(p, &secret, env.as_deref()),
        Get { key, env } => secrets::cmd_get(p, &key, env.as_deref()),
        Ls { env, reveal } => secrets::cmd_ls(p, env.as_deref(), reveal),
        Rm { key, env, force } => secrets::cmd_rm(p, &key, env.as_deref(), force),
        Export { env, output } => secrets::cmd_export(p, env.as_deref(), output.as_deref()),
        Envs => secrets::cmd_envs(p),
        Env(action) => envcmd::cmd_env(p, action),
        History(action) => history::cmd_history(p, action),
        Backup(action) => backup::cmd_backup(p, action),
        Unlock {
            foreground,
            install,
        } => lifecycle::cmd_unlock(p, foreground, install),
        Lock => lifecycle::cmd_lock(p),
        Status => lifecycle::cmd_status(p),
        AgentChild => lifecycle::cmd_agent_child(p),
        Hook { mode } => hook::cmd_hook(&mode),
        Vault(action) => vaultcmd::cmd_vault(p, action),
        Preflight(args) => preflight::run(p, args),
    }
}
