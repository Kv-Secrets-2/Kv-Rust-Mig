//! The kv MCP server (Python `kv_mcp`): newline-delimited JSON-RPC on stdio,
//! answering byte for byte as Python 0.4.0 does and delegating every tool to
//! the vault daemon through `kv-proto`.

pub mod agent;
pub mod pyerr;
pub mod pyval;
pub mod redact;
pub mod server;
pub mod tools;
pub mod vault;

use std::io::Write;

const USAGE: &str = "usage: kv_mcp [-h] [--allow-execute] [--allow-mutate] [--allow-reveal]\n              [--allow-direct-vault-access]\n";
const HELP: &str = "\nkv MCP server — encrypted secrets for AI agents\n\noptions:\n  -h, --help            show this help message and exit\n  --allow-execute       Enable execute tools (kv_run; kv_query and kv_ssh are\n                        parked and not offered on passphrase-protected v3/v4\n                        vaults, the kind kv init makes) — WARNING: allows\n                        subprocess, database/Redis, and remote SSH actions\n  --allow-mutate        Enable direct-only mutate tools (kv_set, kv_rm);\n                        requires --allow-direct-vault-access and a stopped\n                        daemon\n  --allow-reveal        Enable direct-only reveal tools (kv_get); requires\n                        --allow-direct-vault-access and a stopped daemon; not\n                        available on passphrase-protected (v3/v4) vaults —\n                        WARNING: exposes secret values to AI\n  --allow-direct-vault-access\n                        Allow the MCP server to open the vault directly when\n                        the daemon is absent (less safe than daemon mode;\n                        refused for passphrase-protected v3/v4 vaults)\n";
const EXECUTE_WARNING: &str = "WARNING: --allow-execute is enabled.\n  The AI agent can call kv_run, which runs local programs.\n  kv_query and kv_ssh are parked on passphrase-protected (v3/v4) vaults (every\n  vault kv init makes) and are not offered there.\n  On an older vault (a plaintext or v1/v2 key file) they are offered (not parked\n  there): arbitrary database/Redis and remote SSH actions, no action policy yet.\n  kv_api is policy-checked.\n";
const REVEAL_WARNING: &str = "WARNING: --allow-reveal is enabled.\n  On an older vault (a plaintext or v1/v2 key file) the AI agent can call\n  kv_get to read secret values in plaintext\n  (kv_get does not work on passphrase-protected v3/v4 vaults).\n  On a passphrase-protected (v3/v4) vault kv_get is not offered.\n  Prefer kv_api when possible, or enable --allow-execute and use\n  kv_run only when a subprocess genuinely needs the secret.\n";
const DIRECT_WARNING: &str = "WARNING: --allow-direct-vault-access is enabled.\n  The MCP server may open the vault directly if the daemon is absent\n  (not a passphrase-protected v3/v4 vault: direct access refuses those).\n  This is less safe than daemon mode because secrets can live in the MCP process.\n";
const DIRECT_ONLY_WARNING: &str = "WARNING: mutate/reveal profiles are direct-vault only.\n  Direct access refuses passphrase-protected (v3/v4) vaults (every vault\n  kv init makes), so kv_set, kv_rm and kv_get are not offered there.\n  On an older vault they work only while the daemon is stopped; an older\n  wrapped vault also needs KV_PASSPHRASE in the MCP process, which any\n  program running as you can read.\n  Prefer kv set/rm/get in a trusted terminal.\n";

fn usage_error(message: &str) -> i32 {
    eprintln!("{USAGE}kv_mcp: error: {message}");
    2
}

fn log(message: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "[kv_mcp] {message}");
    let _ = stderr.flush();
}

/// `python -m kv_mcp [flags]`: returns the process exit status.
pub fn main(args: &[String]) -> i32 {
    let (mut execute, mut mutate, mut reveal, mut direct) = (false, false, false, false);
    let mut unknown = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--allow-execute" => execute = true,
            "--allow-mutate" => mutate = true,
            "--allow-reveal" => reveal = true,
            "--allow-direct-vault-access" => direct = true,
            "-h" | "--help" => {
                print!("{USAGE}{HELP}");
                return 0;
            }
            other => unknown.push(other.to_owned()),
        }
    }
    if !unknown.is_empty() {
        return usage_error(&format!("unrecognized arguments: {}", unknown.join(" ")));
    }
    if (mutate || reveal) && !direct {
        return usage_error(
            "--allow-mutate/--allow-reveal require --allow-direct-vault-access; prefer kv set/rm/get in a terminal",
        );
    }
    let mut profiles = tools::Profiles::new();
    profiles.insert("safe".into());
    for (enabled, name) in [(execute, "execute"), (mutate, "mutate"), (reveal, "reveal")] {
        if enabled {
            profiles.insert(name.into());
        }
    }
    for (enabled, text) in [
        (execute, EXECUTE_WARNING),
        (reveal, REVEAL_WARNING),
        (direct, DIRECT_WARNING),
        (mutate || reveal, DIRECT_ONLY_WARNING),
    ] {
        if enabled {
            eprintln!("{text}");
        }
    }
    let Some(root) = agent::find_project_root() else {
        log("error: no kv project found (run 'kv init' first)");
        return 1;
    };
    // Python's `get_default_env` -> `secrets_dir` checks the vault's local
    // origin first (`require_local`) and dies on its exception.
    if let Err(error) = kv_store::vault_origin::require_local(&root) {
        log(&format!("error: {error}"));
        return 1;
    }
    let default_env = match kv_store::config::get_default_env(&root) {
        Ok(env) => env,
        Err(error) => {
            log(&format!("error: {error}"));
            return 1;
        }
    };
    let config = server::Config {
        root,
        default_env,
        profiles,
        allow_direct_vault_access: direct,
    };
    let worker = std::thread::Builder::new()
        .stack_size(pyval::DECODE_STACK_BYTES)
        .spawn(move || {
            let stdin = std::io::stdin().lock();
            let stdout = std::io::stdout().lock();
            server::serve(&config, stdin, stdout, std::io::stderr());
        });
    match worker.map(|handle| handle.join()) {
        Ok(Ok(())) => 0,
        _ => 1,
    }
}
