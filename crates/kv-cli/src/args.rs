//! `build_parser()` for the commands this build carries, with argparse's messages.

use crate::policycmd::PolicyAction;
use crate::providercmd::{ProviderAction, ProviderOptions};
use kv_broker::HttpRuleOptions;

pub enum Command {
    Preflight(crate::preflight::Args),
    Version,
    Init {
        location: Option<String>,
        path: Option<String>,
    },
    Set {
        secret: String,
        env: Option<String>,
    },
    Get {
        key: String,
        env: Option<String>,
    },
    Ls {
        env: Option<String>,
        reveal: bool,
    },
    Rm {
        key: String,
        env: Option<String>,
        force: bool,
    },
    Export {
        env: Option<String>,
        output: Option<String>,
    },
    Envs,
    Unlock {
        foreground: bool,
        install: bool,
    },
    Lock,
    Status,
    ApprovalMode(Option<String>),
    Allow(Option<String>),
    Deny(String),
    NetworkAllow(Option<String>),
    NetworkDeny(String),
    Provider(crate::providercmd::ProviderAction),
    Policy(PolicyAction),
    Approvals(crate::approvalscmd::ApprovalsAction),
    AgentChild,
    Hook {
        mode: String,
    },
    Run {
        env: Option<String>,
        cwd: Option<String>,
        private_cwd: Option<bool>,
        quiet: bool,
        secret_names: Option<Vec<String>>,
        no_secrets: bool,
        capability_names: Vec<String>,
        cmd: Vec<String>,
    },
    Vault(crate::vaultcmd::VaultAction),
    Env(crate::envcmd::EnvAction),
    History(crate::history::HistoryAction),
    Backup(crate::backup::BackupAction),
}

impl Command {
    /// `_VAULT_RECOVERY_COMMANDS`: `_prepare_vault_access` runs before the handler.
    pub fn needs_vault_access(&self) -> bool {
        matches!(
            self,
            Command::Set { .. }
                | Command::Get { .. }
                | Command::Ls { .. }
                | Command::Rm { .. }
                | Command::Export { .. }
                | Command::History(_)
                | Command::Backup(_)
        )
    }
}

pub enum ParseError {
    /// argparse printed usage and an error (stderr, exit 2); the text is complete.
    Usage(String),
    /// `kv --version`.
    Version,
    /// `kv CMD -h`: the subparser's help (stdout, exit 0).
    Help(String),
    /// An unknown command name: `_show_help`, exit 1.
    Unknown,
}

const USAGE_TOP: &str = "usage: kv [-h] [--version]\n          {init,set,get,ls,rm,history,backup,run,preflight,policy,approval-mode,export,envs,env,vault,status,version,unlock,lock,allow,deny,network-allow,network-deny,provider,mcp-server}\n          ...\n";

struct Spec {
    name: &'static str,
    usage: &'static str,
    help: &'static str,
    positionals: &'static [&'static str],
    env: bool,
    flags: &'static [(&'static str, &'static str)],
    options: &'static [(&'static str, &'static str)],
}

const ENV_HELP: &str = "  -e ENV, --env ENV  Environment (default: the project's default)\n";

const SPECS: &[Spec] = &[
    Spec {
        name: "preflight",
        usage: "usage: kv preflight [-h] [--cwd CWD] [--json] [--request]\n                    [--request-ttl REQUEST_TTL] [--env ENV] [--source SOURCE]\n                    [--client CLIENT] [--session-id SESSION_ID]\n                    [--reason REASON]\n                    ...\n",
        help: "\npositional arguments:\n  cmd                   Command to inspect\n\noptions:\n  -h, --help            show this help message and exit\n  --cwd CWD             Working directory for the command (default: current\n                        directory)\n  --json                Emit machine-readable JSON\n  --request             Create pending approval request(s) for brokered\n                        recommendations\n  --request-ttl REQUEST_TTL\n                        Pending request lifetime in seconds (default: 900)\n  --env ENV             Environment the requested run uses (default: the\n                        project's default)\n  --source SOURCE       Optional requester source to bind, such as mcp\n  --client CLIENT       Optional client name to bind, such as codex\n  --session-id SESSION_ID\n                        Optional agent/session ID to bind\n  --reason REASON       Human note stored with created approval requests\n",
        positionals: &[],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "allow",
        usage: "usage: kv allow [-h] [pattern]\n",
        help: "\npositional arguments:\n  pattern     Command to allow (e.g., 'python3 app.py')\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["?pattern"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "deny",
        usage: "usage: kv deny [-h] pattern\n",
        help: "\npositional arguments:\n  pattern     Command to remove\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["pattern"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "network-allow",
        usage: "usage: kv network-allow [-h] [pattern]\n",
        help: "\nAllow outbound network access for a kv_run command. With no argument, list the\ncommands allowed. On a vault with a passphrase, kv_run uses a change only\nafter a restart (kv lock, then kv unlock) and a fresh approval of the run.\n\npositional arguments:\n  pattern     Command to allow network (e.g., 'twine upload')\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["?pattern"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "network-deny",
        usage: "usage: kv network-deny [-h] pattern\n",
        help: "\npositional arguments:\n  pattern     Command to revoke network from\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["pattern"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "init",
        usage: "usage: kv init [-h] [--location {global,project,custom}] [--path PATH]\n",
        help: "\noptions:\n  -h, --help            show this help message and exit\n",
        positionals: &[],
        env: false,
        flags: &[],
        options: &[
            (
                "--location",
                "  --location {global,project,custom}\n                        Vault root: home directory, current project, or a\n                        custom path\n",
            ),
            (
                "--path",
                "  --path PATH           Custom vault root path (requires --location custom)\n",
            ),
        ],
    },
    Spec {
        name: "set",
        usage: "usage: kv set [-h] [-e ENV] secret\n",
        help: "\npositional arguments:\n  secret             KEY=VALUE or just KEY (prompts for value)\n\noptions:\n  -h, --help         show this help message and exit\n",
        positionals: &["secret"],
        env: true,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "get",
        usage: "usage: kv get [-h] [-e ENV] key\n",
        help: "\npositional arguments:\n  key                Secret key name\n\noptions:\n  -h, --help         show this help message and exit\n",
        positionals: &["key"],
        env: true,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "ls",
        usage: "usage: kv ls [-h] [-e ENV] [--reveal]\n",
        help: "\noptions:\n  -h, --help         show this help message and exit\n",
        positionals: &[],
        env: true,
        flags: &[("--reveal", "  --reveal           Show decrypted values\n")],
        options: &[],
    },
    Spec {
        name: "rm",
        usage: "usage: kv rm [-h] [-e ENV] [-f] key\n",
        help: "\npositional arguments:\n  key                Secret key to remove\n\noptions:\n  -h, --help         show this help message and exit\n",
        positionals: &["key"],
        env: true,
        flags: &[("-f", "  -f, --force        Skip confirmation\n")],
        options: &[],
    },
    Spec {
        name: "export",
        usage: "usage: kv export [-h] [-e ENV] [-o OUTPUT]\n",
        help: "\noptions:\n  -h, --help         show this help message and exit\n",
        positionals: &[],
        env: true,
        flags: &[],
        options: &[(
            "-o",
            "  -o OUTPUT, --output OUTPUT\n                     Write to file instead of stdout\n",
        )],
    },
    Spec {
        name: "envs",
        usage: "usage: kv envs [-h]\n",
        help: "\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &[],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "unlock",
        usage: "usage: kv unlock [-h] [--foreground] [--install]\n",
        help: "\noptions:\n  -h, --help        show this help message and exit\n",
        positionals: &[],
        env: false,
        flags: &[
            (
                "--foreground",
                "  --foreground, -f  Run in foreground (show logs, block terminal)\n",
            ),
            (
                "--install",
                "  --install         Auto-start on login (Linux, systemd; not available on\n                    macOS; only for a vault without a passphrase)\n",
            ),
        ],
        options: &[],
    },
    Spec {
        name: "lock",
        usage: "usage: kv lock [-h]\n",
        help: "\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &[],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "status",
        usage: "usage: kv status [-h]\n",
        help: "\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &[],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "version",
        usage: "usage: kv version [-h]\n",
        help: "\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &[],
        env: false,
        flags: &[],
        options: &[],
    },
];

fn spec_error(spec: &Spec, message: &str) -> ParseError {
    ParseError::Usage(format!(
        "{}kv {}: error: {message}\n",
        spec.usage, spec.name
    ))
}

fn top_error(message: &str) -> ParseError {
    ParseError::Usage(format!("{USAGE_TOP}kv: error: {message}\n"))
}

struct Parsed {
    positionals: Vec<String>,
    env: Option<String>,
    flags: Vec<&'static str>,
    options: Vec<(&'static str, String)>,
}

fn parse_spec(spec: &Spec, rest: &[String]) -> Result<Parsed, ParseError> {
    let mut parsed = Parsed {
        positionals: Vec::new(),
        env: None,
        flags: Vec::new(),
        options: Vec::new(),
    };
    let mut i = 0;
    let mut only_positionals = false;
    while i < rest.len() {
        let arg = &rest[i];
        if !only_positionals && arg == "--" {
            only_positionals = true;
            i += 1;
            continue;
        }
        if !only_positionals && arg.starts_with('-') && arg.len() > 1 {
            if arg == "-h" || arg == "--help" {
                let mut help = String::from(spec.usage);
                help.push_str(spec.help);
                if spec.env {
                    help.push_str(ENV_HELP);
                }
                for (_, text) in spec.flags {
                    help.push_str(text);
                }
                for (_, text) in spec.options {
                    help.push_str(text);
                }
                return Err(ParseError::Help(help));
            }
            let (name, inline) = match arg.split_once('=') {
                Some((name, value)) if arg.starts_with("--") => {
                    (name.to_owned(), Some(value.to_owned()))
                }
                _ => (arg.clone(), None),
            };
            if spec.env && (name == "-e" || name == "--env") {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        i += 1;
                        match rest.get(i) {
                            Some(value) if !(value.starts_with('-') && value.len() > 1) => {
                                value.clone()
                            }
                            _ => {
                                return Err(spec_error(
                                    spec,
                                    "argument -e/--env: expected one argument",
                                ));
                            }
                        }
                    }
                };
                parsed.env = Some(value);
                i += 1;
                continue;
            }
            if let Some((flag, _)) = spec.flags.iter().find(|(flag, text)| {
                *flag == name
                    || text
                        .trim_start()
                        .split(',')
                        .map(|s| s.trim().split(' ').next().unwrap_or(""))
                        .any(|alias| alias == name)
            }) {
                parsed.flags.push(flag);
                i += 1;
                continue;
            }
            if let Some((option, text)) = spec.options.iter().find(|(option, text)| {
                *option == name
                    || text
                        .trim_start()
                        .split(',')
                        .map(|s| s.trim().split(' ').next().unwrap_or(""))
                        .any(|alias| alias == name)
            }) {
                let aliases: Vec<&str> = text
                    .trim_start()
                    .split(',')
                    .map(|s| s.trim().split(' ').next().unwrap_or(""))
                    .collect();
                let value = match inline {
                    Some(value) => value,
                    None => {
                        i += 1;
                        match rest.get(i) {
                            Some(value)
                                if !(value.starts_with('-') && value.len() > 1)
                                    || (matches!(
                                        spec.name,
                                        "provider add" | "policy watch" | "policy request"
                                    ) && negative_number(value)) =>
                            {
                                value.clone()
                            }
                            _ => {
                                return Err(spec_error(
                                    spec,
                                    &format!(
                                        "argument {}: expected one argument",
                                        aliases.join("/")
                                    ),
                                ));
                            }
                        }
                    }
                };
                if spec.name == "provider add" {
                    validate_provider_option(spec, option, &value)?;
                }
                if matches!(spec.name, "policy watch" | "policy request")
                    && matches!(*option, "--interval" | "--ttl")
                {
                    let raw = value.trim();
                    let digits = raw.strip_prefix(['+', '-']).unwrap_or(raw).as_bytes();
                    if digits.is_empty()
                        || !digits.iter().enumerate().all(|(i, b)| {
                            b.is_ascii_digit()
                                || (*b == b'_'
                                    && i > 0
                                    && i + 1 < digits.len()
                                    && digits[i - 1].is_ascii_digit()
                                    && digits[i + 1].is_ascii_digit())
                        })
                    {
                        return Err(spec_error(
                            spec,
                            &format!("argument {option}: invalid int value: '{value}'"),
                        ));
                    }
                }
                if spec.name == "policy http add" && matches!(*option, "--path" | "--path-prefix") {
                    let other = if *option == "--path" {
                        "--path-prefix"
                    } else {
                        "--path"
                    };
                    if parsed.options.iter().any(|(name, _)| *name == other) {
                        return Err(spec_error(
                            spec,
                            &format!("argument {option}: not allowed with argument {other}"),
                        ));
                    }
                }
                parsed.options.push((option, value));
                i += 1;
                continue;
            }
            return Err(top_error(&format!(
                "unrecognized arguments: {}",
                rest[i..].join(" ")
            )));
        }
        parsed.positionals.push(arg.clone());
        i += 1;
    }
    let required = spec
        .positionals
        .iter()
        .filter(|name| !name.starts_with('?'))
        .count();
    let missing_secret =
        spec.name == "provider add" && !parsed.options.iter().any(|(key, _)| *key == "--secret");
    let missing_id =
        spec.name == "policy http add" && !parsed.options.iter().any(|(key, _)| *key == "--id");
    if parsed.positionals.len() < required || missing_secret || missing_id {
        let mut missing: Vec<&str> = spec
            .positionals
            .iter()
            .copied()
            .take(required)
            .skip(parsed.positionals.len())
            .collect();
        if missing_secret {
            missing.push("--secret");
        }
        if missing_id {
            missing.push("--id");
        }
        return Err(spec_error(
            spec,
            &format!(
                "the following arguments are required: {}",
                missing.join(", ")
            ),
        ));
    }
    if spec.name == "policy http add"
        && !parsed
            .options
            .iter()
            .any(|(name, _)| matches!(*name, "--path" | "--path-prefix"))
    {
        return Err(spec_error(
            spec,
            "one of the arguments --path --path-prefix is required",
        ));
    }
    if parsed.positionals.len() > spec.positionals.len() {
        return Err(top_error(&format!(
            "unrecognized arguments: {}",
            parsed.positionals[spec.positionals.len()..].join(" ")
        )));
    }
    Ok(parsed)
}

pub fn parse(argv: &[String]) -> Result<Option<Command>, ParseError> {
    let Some(first) = argv.first() else {
        return Ok(None);
    };
    if first == "--version" {
        return Err(ParseError::Version);
    }
    if first.starts_with('-') {
        return Err(top_error(&format!(
            "unrecognized arguments: {}",
            argv.join(" ")
        )));
    }
    if first == "env" {
        return parse_env(&argv[1..]);
    }
    if first == "approval-mode" {
        return parse_approval_mode(&argv[1..]);
    }
    if first == "provider" {
        return parse_provider(&argv[1..]);
    }
    if first == "policy" {
        return parse_policy(&argv[1..]);
    }
    if first == "approvals" {
        return parse_approvals(&argv[1..]);
    }
    if first == "history" {
        return parse_history(&argv[1..]);
    }
    if first == "backup" {
        return parse_backup(&argv[1..]);
    }
    if first == "vault" {
        return parse_vault(&argv[1..]);
    }
    if first == "hook" {
        let mode = argv.get(1).cloned().unwrap_or_else(|| "pre".to_owned());
        return Ok(Some(Command::Hook { mode }));
    }
    if first == "run" {
        return parse_run(&argv[1..]);
    }
    if first == crate::lifecycle::AGENT_CHILD {
        return Ok(Some(Command::AgentChild));
    }
    let Some(spec) = SPECS.iter().find(|spec| spec.name == first.as_str()) else {
        return Err(ParseError::Unknown);
    };
    if spec.name == "preflight" {
        return parse_preflight(spec, &argv[1..]);
    }
    let parsed = parse_spec(spec, &argv[1..])?;
    let mut positionals = parsed.positionals.into_iter();
    let option = |name: &str| {
        parsed
            .options
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    if spec.name == "init"
        && let Some(location) = option("--location")
        && !["global", "project", "custom"].contains(&location.as_str())
    {
        return Err(spec_error(
            spec,
            &format!(
                "argument --location: invalid choice: '{location}' (choose from 'global', 'project', 'custom')"
            ),
        ));
    }
    Ok(Some(match spec.name {
        "init" => Command::Init {
            location: option("--location"),
            path: option("--path"),
        },
        "set" => Command::Set {
            secret: positionals.next().unwrap_or_default(),
            env: parsed.env,
        },
        "get" => Command::Get {
            key: positionals.next().unwrap_or_default(),
            env: parsed.env,
        },
        "ls" => Command::Ls {
            env: parsed.env,
            reveal: parsed.flags.contains(&"--reveal"),
        },
        "rm" => Command::Rm {
            key: positionals.next().unwrap_or_default(),
            env: parsed.env,
            force: parsed.flags.contains(&"-f"),
        },
        "export" => Command::Export {
            env: parsed.env,
            output: parsed
                .options
                .into_iter()
                .find(|(name, _)| *name == "-o")
                .map(|(_, value)| value),
        },
        "envs" => Command::Envs,
        "unlock" => Command::Unlock {
            foreground: parsed.flags.contains(&"--foreground"),
            install: parsed.flags.contains(&"--install"),
        },
        "lock" => Command::Lock,
        "status" => Command::Status,
        "allow" => Command::Allow(positionals.next()),
        "deny" => Command::Deny(positionals.next().unwrap_or_default()),
        "network-allow" => Command::NetworkAllow(positionals.next()),
        "network-deny" => Command::NetworkDeny(positionals.next().unwrap_or_default()),
        _ => Command::Version,
    }))
}

fn parse_preflight(spec: &Spec, rest: &[String]) -> Result<Option<Command>, ParseError> {
    const NAMES: &[&str] = &[
        "--help",
        "--cwd",
        "--json",
        "--request",
        "--request-ttl",
        "--env",
        "--source",
        "--client",
        "--session-id",
        "--reason",
    ];
    let mut args = crate::preflight::Args::default();
    let mut unknown = Vec::new();
    let mut i = 0;
    while let Some(arg) = rest.get(i) {
        if arg == "--" || !arg.starts_with('-') || arg == "-" || negative_number(arg) {
            args.cmd = rest[i..].to_vec();
            break;
        }
        if let Some(value) = arg.strip_prefix("-h").filter(|s| !s.is_empty()) {
            return Err(spec_error(
                spec,
                &format!(
                    "argument -h/--help: ignored explicit argument {}",
                    crate::preflight::repr(value.strip_prefix('=').unwrap_or(value))
                ),
            ));
        }
        let (name, inline) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(n, v)| (n, Some(v)));
        let matches: Vec<_> = NAMES
            .iter()
            .copied()
            .filter(|n| {
                *n == name
                    || (name.starts_with("--") && n.starts_with(name))
                    || (name == "-h" && *n == "--help")
            })
            .collect();
        let name = if NAMES.contains(&name) {
            name
        } else {
            match matches.as_slice() {
                [name] => name,
                [] => {
                    unknown.push(arg.clone());
                    i += 1;
                    continue;
                }
                _ => {
                    return Err(spec_error(
                        spec,
                        &format!(
                            "ambiguous option: {name} could match {}",
                            matches.join(", ")
                        ),
                    ));
                }
            }
        };
        if ["--help", "--json", "--request"].contains(&name) {
            if let Some(value) = inline {
                let name = if name == "--help" { "-h/--help" } else { name };
                return Err(spec_error(
                    spec,
                    &format!(
                        "argument {name}: ignored explicit argument {}",
                        crate::preflight::repr(value)
                    ),
                ));
            }
            match name {
                "--help" => return Err(ParseError::Help(format!("{}{}", spec.usage, spec.help))),
                "--json" => args.json = true,
                _ => args.request = true,
            }
        } else {
            let value = if let Some(value) = inline {
                value
            } else {
                i += 1;
                match rest.get(i) {
                    Some(value)
                        if !value.starts_with('-') || value == "-" || negative_number(value) =>
                    {
                        value
                    }
                    _ => {
                        return Err(spec_error(
                            spec,
                            &format!("argument {name}: expected one argument"),
                        ));
                    }
                }
            };
            if name == "--request-ttl" && !crate::preflight::is_integer(value) {
                return Err(spec_error(
                    spec,
                    &format!(
                        "argument --request-ttl: invalid int value: {}",
                        crate::preflight::repr(value)
                    ),
                ));
            }
            if name == "--cwd" {
                args.cwd = Some(value.to_owned());
            }
        }
        i += 1;
    }
    if !unknown.is_empty() {
        return Err(preflight_top_error(&format!(
            "unrecognized arguments: {}",
            unknown.join(" ")
        )));
    }
    Ok(Some(Command::Preflight(args)))
}

fn negative_number(value: &str) -> bool {
    use unicode_general_category::{GeneralCategory, get_general_category};
    let Some(number) = value.strip_prefix('-') else {
        return false;
    };
    let digits = |s: &str| {
        s.chars()
            .all(|c| get_general_category(c) == GeneralCategory::DecimalNumber)
    };
    match number.split_once('.') {
        Some((whole, fraction)) => digits(whole) && !fraction.is_empty() && digits(fraction),
        None => !number.is_empty() && digits(number),
    }
}

fn preflight_top_error(message: &str) -> ParseError {
    ParseError::Usage(format!(
        "usage: kv [-h] [--version]\n          {{init,set,get,ls,rm,history,backup,run,preflight,cap,approvals,policy,approval-mode,grant,export,import,envs,env,vault,status,doctor,audit,export-key,import-key,version,mcp,setup,setup-2fa,2fa,recovery-key,passphrase,recover,upgrade-security,agent,unlock,lock,resume,allow,deny,network-allow,network-deny,provider,signup,login,logout,push,pull,remote,sync,team,token}}\n          ...\nkv: error: {message}\n"
    ))
}

const ENV_USAGE: &str = "usage: kv env [-h]\n              {create,copy,repair-names,rename,delete,restore,purge,default,keep-deleted}\n              ...\n";

const ENV_HELP_TEXT: &str = "\npositional arguments:\n  {create,copy,repair-names,rename,delete,restore,purge,default,keep-deleted}\n    create              Create a new environment\n    copy                Copy secrets between environments\n    repair-names        Preview recovery of invalid environment registrations\n    rename              Rename an environment, keeping its secrets and history\n    delete              Delete an environment (recoverable for a while)\n    restore             Bring a deleted environment back (no name: list them)\n    purge               Wipe a deleted environment now\n    default             Show or set the default environment\n    keep-deleted        Show or set how many days a deleted environment is\n                        kept\n\noptions:\n  -h, --help            show this help message and exit\n";

const NAME_HELP: &str = "\npositional arguments:\n  name        Environment name\n\noptions:\n  -h, --help  show this help message and exit\n";

const ENV_SPECS: &[Spec] = &[
    Spec {
        name: "env create",
        usage: "usage: kv env create [-h] name\n",
        help: NAME_HELP,
        positionals: &["name"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "env copy",
        usage: "usage: kv env copy [-h] [--replace | --keep-existing] [--create] src dst\n",
        help: "\npositional arguments:\n  src              Source environment\n  dst              Destination environment\n\noptions:\n  -h, --help       show this help message and exit\n",
        positionals: &["src", "dst"],
        env: false,
        flags: &[
            (
                "--replace",
                "  --replace        Replace values DST already holds (drawer vaults keep them\n                   as history)\n",
            ),
            (
                "--keep-existing",
                "  --keep-existing  Copy only names DST lacks; keep DST's existing values\n",
            ),
            (
                "--create",
                "  --create         Create DST if it does not exist\n",
            ),
        ],
        options: &[],
    },
    Spec {
        name: "env rename",
        usage: "usage: kv env rename [-h] old new\n",
        help: "\npositional arguments:\n  old         Current name\n  new         New name\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["old", "new"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "env delete",
        usage: "usage: kv env delete [-h] name\n",
        help: NAME_HELP,
        positionals: &["name"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "env restore",
        usage: "usage: kv env restore [-h] [name]\n",
        help: NAME_HELP,
        positionals: &["?name"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "env purge",
        usage: "usage: kv env purge [-h] name\n",
        help: NAME_HELP,
        positionals: &["name"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "env default",
        usage: "usage: kv env default [-h] [name]\n",
        help: NAME_HELP,
        positionals: &["?name"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "env keep-deleted",
        usage: "usage: kv env keep-deleted [-h] [days]\n",
        help: "\npositional arguments:\n  days        Days (0-365)\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["?days"],
        env: false,
        flags: &[],
        options: &[],
    },
];

/// `kv env ...`: argparse's sub-subparser. No action lists environments (`cmd_envs`);
/// `repair-names` is recognised but not ported (legacy registrations never occur here).
fn parse_env(rest: &[String]) -> Result<Option<Command>, ParseError> {
    use crate::envcmd::EnvAction;
    let Some(action) = rest.first() else {
        return Ok(Some(Command::Envs));
    };
    if action == "-h" || action == "--help" {
        return Err(ParseError::Help(format!("{ENV_USAGE}{ENV_HELP_TEXT}")));
    }
    if action == "repair-names" {
        return Err(ParseError::Usage(format!(
            "{ENV_USAGE}kv env: error: repair-names is not available in this build: it repairs registrations left by pre-drawer releases\n"
        )));
    }
    let Some(spec) = ENV_SPECS
        .iter()
        .find(|spec| spec.name.strip_prefix("env ") == Some(action.as_str()))
    else {
        return Err(ParseError::Usage(format!(
            "{ENV_USAGE}kv env: error: argument env_action: invalid choice: '{action}' (choose from 'create', 'copy', 'repair-names', 'rename', 'delete', 'restore', 'purge', 'default', 'keep-deleted')\n"
        )));
    };
    let parsed = parse_spec(spec, &rest[1..])?;
    let mut pos = parsed.positionals.into_iter();
    let has = |flag: &str| parsed.flags.contains(&flag);
    Ok(Some(Command::Env(match action.as_str() {
        "create" => EnvAction::Create {
            name: pos.next().unwrap_or_default(),
        },
        "copy" => {
            if has("--replace") && has("--keep-existing") {
                let second = rest[1..]
                    .iter()
                    .filter(|a| *a == "--replace" || *a == "--keep-existing")
                    .nth(1)
                    .map(String::as_str)
                    .unwrap_or("--keep-existing");
                let first = if second == "--replace" {
                    "--keep-existing"
                } else {
                    "--replace"
                };
                return Err(spec_error(
                    spec,
                    &format!("argument {second}: not allowed with argument {first}"),
                ));
            }
            EnvAction::Copy {
                src: pos.next().unwrap_or_default(),
                dst: pos.next().unwrap_or_default(),
                replace: has("--replace"),
                keep_existing: has("--keep-existing"),
                create: has("--create"),
            }
        }
        "rename" => EnvAction::Rename {
            old: pos.next().unwrap_or_default(),
            new: pos.next().unwrap_or_default(),
        },
        "delete" => EnvAction::Delete {
            name: pos.next().unwrap_or_default(),
        },
        "restore" => EnvAction::Restore { name: pos.next() },
        "purge" => EnvAction::Purge {
            name: pos.next().unwrap_or_default(),
        },
        "default" => EnvAction::Default { name: pos.next() },
        _ => EnvAction::KeepDeleted { days: pos.next() },
    })))
}

const HISTORY_USAGE: &str =
    "usage: kv history [-h] {list,show,restore,undo-rm,replace,forget,keep} ...\n";

const APPROVAL_MODE_USAGE: &str = "usage: kv approval-mode [-h] {status,set} ...\n";
const APPROVAL_MODE_SET_SPEC: Spec = Spec {
    name: "approval-mode set",
    usage: "usage: kv approval-mode set [-h]\n                            {local-convenience,protected-approval,unsafe-convenience}\n",
    help: "\npositional arguments:\n  {local-convenience,protected-approval,unsafe-convenience}\n                        Approval mode for this project\n\noptions:\n  -h, --help            show this help message and exit\n",
    positionals: &["mode"],
    env: false,
    flags: &[],
    options: &[],
};
const APPROVAL_MODE_STATUS_SPEC: Spec = Spec {
    name: "approval-mode status",
    usage: "usage: kv approval-mode status [-h]\n",
    help: "\noptions:\n  -h, --help  show this help message and exit\n",
    positionals: &[],
    env: false,
    flags: &[],
    options: &[],
};

const PROVIDER_USAGE: &str = "usage: kv provider [-h] {add,list,rm} ...\n";
const PROVIDER_ADD: Spec = Spec {
    name: "provider add",
    usage: "usage: kv provider add [-h] [--type {http,postgres,mysql,redis,ssh}]\n                       [--url URL] [--host HOST] [--port PORT]\n                       [--database DATABASE] [--username USERNAME] --secret\n                       SECRET [--auth {bearer,x-api-key,query,basic,header}]\n                       [--query-param QUERY_PARAM] [--header-name HEADER_NAME]\n                       name\n",
    help: "\npositional arguments:\n  name                  Provider name (e.g., stripe, twilio)\n\noptions:\n  -h, --help            show this help message and exit\n",
    positionals: &["name"],
    env: false,
    flags: &[],
    options: &[
        (
            "--type",
            "  --type {http,postgres,mysql,redis,ssh}\n                        Provider type (default: http)\n",
        ),
        (
            "--url",
            "  --url URL             HTTP base URL (e.g., https://api.stripe.com)\n",
        ),
        (
            "--host",
            "  --host HOST           Database/Redis/SSH host\n",
        ),
        (
            "--port",
            "  --port PORT           Database/Redis/SSH port\n",
        ),
        (
            "--database",
            "  --database DATABASE   Database name or Redis DB number\n",
        ),
        (
            "--username",
            "  --username USERNAME   Database or SSH username\n",
        ),
        (
            "--secret",
            "  --secret SECRET       Secret name in vault (e.g., STRIPE_SECRET_KEY,\n                        DB_PASSWORD, SSH_KEY)\n",
        ),
        (
            "--auth",
            "  --auth {bearer,x-api-key,query,basic,header}\n                        HTTP auth type (default: bearer)\n",
        ),
        (
            "--query-param",
            "  --query-param QUERY_PARAM\n                        Query param name (for --auth query)\n",
        ),
        (
            "--header-name",
            "  --header-name HEADER_NAME\n                        Header name (for --auth header)\n",
        ),
    ],
};
const PROVIDER_RM: Spec = Spec {
    name: "provider rm",
    usage: "usage: kv provider rm [-h] name\n",
    help: "\npositional arguments:\n  name        Provider name to remove\n\noptions:\n  -h, --help  show this help message and exit\n",
    positionals: &["name"],
    env: false,
    flags: &[],
    options: &[],
};
const PROVIDER_LIST: Spec = Spec {
    name: "provider list",
    usage: "usage: kv provider list [-h]\n",
    help: "\noptions:\n  -h, --help  show this help message and exit\n",
    positionals: &[],
    env: false,
    flags: &[],
    options: &[],
};

fn provider_port(value: &str) -> Option<i64> {
    let value = value.trim();
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    value.replace('_', "").parse().ok()
}

fn validate_provider_option(spec: &Spec, key: &str, value: &str) -> Result<(), ParseError> {
    let choices: &[&str] = match key {
        "--type" => &["http", "postgres", "mysql", "redis", "ssh"],
        "--auth" => &["bearer", "x-api-key", "query", "basic", "header"],
        "--port" => {
            if provider_port(value).is_none() {
                return Err(spec_error(
                    spec,
                    &format!("argument --port: invalid int value: '{value}'"),
                ));
            }
            return Ok(());
        }
        _ => return Ok(()),
    };
    if !choices.contains(&value) {
        return Err(spec_error(
            spec,
            &format!(
                "argument {key}: invalid choice: '{value}' (choose from {})",
                choices
                    .iter()
                    .map(|v| format!("'{v}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    Ok(())
}

const POLICY_USAGE: &str =
    "usage: kv policy [-h] {http,list,watch,request,allow,block,deny,prune} ...\n";
const HTTP_USAGE: &str = "usage: kv policy http [-h] {list,add,remove,rm} ...\n";
const HTTP_LIST: Spec = Spec {
    name: "policy http list",
    usage: "usage: kv policy http list [-h] [provider]\n",
    help: "\npositional arguments:\n  provider    Optional provider name\n\noptions:\n  -h, --help  show this help message and exit\n",
    positionals: &["?provider"],
    env: false,
    flags: &[],
    options: &[],
};
const HTTP_REMOVE: Spec = Spec {
    name: "policy http remove",
    usage: "usage: kv policy http remove [-h] provider rule_id\n",
    help: "\npositional arguments:\n  provider    HTTP provider name\n  rule_id     Rule id to remove\n\noptions:\n  -h, --help  show this help message and exit\n",
    positionals: &["provider", "rule_id"],
    env: false,
    flags: &[],
    options: &[],
};
const HTTP_ADD: Spec = Spec {
    name: "policy http add",
    usage: "usage: kv policy http add [-h] --id RULE_ID [--method METHODS]\n                          (--path PATH | --path-prefix PATH_PREFIX)\n                          [--query-key QUERY_KEYS] [--header ALLOWED_HEADERS]\n                          provider\n",
    help: "\npositional arguments:\n  provider              HTTP provider name, such as github or a custom\n                        provider\n\noptions:\n  -h, --help            show this help message and exit\n",
    positionals: &["provider"],
    env: false,
    flags: &[],
    options: &[
        ("--id", "  --id RULE_ID          Rule id, e.g. user-read\n"),
        (
            "--method",
            "  --method METHODS      Allowed method; repeat to add more (default: GET).\n                        POST, PUT, PATCH or DELETE make an unsafe rule; unsafe\n                        calls need owner approval\n",
        ),
        (
            "--path",
            "  --path PATH           Exact origin-relative path, e.g. /user\n",
        ),
        (
            "--path-prefix",
            "  --path-prefix PATH_PREFIX\n                        Segment-aware origin-relative path prefix\n",
        ),
        (
            "--query-key",
            "  --query-key QUERY_KEYS\n                        Allowed query key; repeat for each key\n",
        ),
        (
            "--header",
            "  --header ALLOWED_HEADERS\n                        Allowed caller header; repeat for each header\n",
        ),
    ],
};

const APPROVALS_USAGE: &str = "usage: kv approvals [-h]\n                    {list,watch,request,approve,page,pause,deny,prune} ...\n";
const APPROVALS_CHOICES: &[&str] = &[
    "list", "watch", "request", "approve", "page", "pause", "deny", "prune",
];
const APPROVE_USAGE: &str = "usage: kv approvals approve [-h] [--reuse] [--ttl TTL] [--no-call-limit]\n                            [--when-spent {pause,end}]\n                            [--wait-minutes WAIT_MINUTES]\n                            [--wait-seconds WAIT_SECONDS]\n                            [--add-calls ADD_CALLS]\n                            [--add-minutes ADD_MINUTES]\n                            [--max-calls MAX_CALLS]\n                            [--max-calls-for SERVICE=N]\n                            [--post-rule api:PROVIDER/RULE=N]\n                            [--max-runs MAX_RUNS] [--reason REASON]\n                            request_id\n";

const APPROVALS_HELP: &[(&str, &str)] = &[
    (
        "list",
        "usage: kv approvals list [-h] [--all]\n\noptions:\n  -h, --help  show this help message and exit\n  --all       Include approved, denied, and expired requests\n",
    ),
    (
        "watch",
        "usage: kv approvals watch [-h] [--all] [--follow] [--interval INTERVAL]\n\noptions:\n  -h, --help           show this help message and exit\n  --all                Include approved, denied, and expired requests\n  --follow             Keep refreshing until interrupted\n  --interval INTERVAL  Refresh interval for --follow\n",
    ),
    (
        "request",
        "usage: kv approvals request [-h] [--secret NAME] [--capability api:PROVIDER]\n                            [--max-calls MAX_CALLS]\n                            [--max-calls-for SERVICE=N] [--ttl TTL]\n                            [--suggest-minutes SUGGEST_MINUTES] [--cwd CWD]\n                            [--source SOURCE] [--client CLIENT]\n                            [--session-id SESSION_ID] [--reason REASON]\n                            [--env ENV]\n                            ...\n\npositional arguments:\n  cmd                   Command requesting approval\n\noptions:\n  -h, --help            show this help message and exit\n  --secret NAME         Secret name requested for this run (repeatable)\n  --capability api:PROVIDER\n                        Broker capability requested for this run\n  --max-calls MAX_CALLS\n                        Requested call budget for broker capability\n  --max-calls-for SERVICE=N\n                        Requested calls for one service of several\n                        (repeatable), e.g. api:openai=10\n  --ttl TTL             Pending request lifetime in seconds (default: 900)\n  --suggest-minutes SUGGEST_MINUTES\n                        The time limit the agent suggests for the approval, in\n                        minutes (shown to the owner; the owner decides)\n  --cwd CWD             Working directory for the command (default: current\n                        directory)\n  --source SOURCE       Optional requester source to bind, such as mcp\n  --client CLIENT       Optional client name to bind, such as codex\n  --session-id SESSION_ID\n                        Optional agent/session ID to bind\n  --reason REASON       Human note stored with the request\n  --env ENV             Environment the requested run uses (default: the\n                        project's default)\n",
    ),
    (
        "approve",
        "usage: kv approvals approve [-h] [--reuse] [--ttl TTL] [--no-call-limit]\n                            [--when-spent {pause,end}]\n                            [--wait-minutes WAIT_MINUTES]\n                            [--wait-seconds WAIT_SECONDS]\n                            [--add-calls ADD_CALLS]\n                            [--add-minutes ADD_MINUTES]\n                            [--max-calls MAX_CALLS]\n                            [--max-calls-for SERVICE=N]\n                            [--post-rule api:PROVIDER/RULE=N]\n                            [--max-runs MAX_RUNS] [--reason REASON]\n                            request_id\n\npositional arguments:\n  request_id            Approval request ID\n\noptions:\n  -h, --help            show this help message and exit\n  --reuse               Allow matching runs until expiry; call budget is per\n                        run (default: one run)\n  --ttl TTL             Grant lifetime in seconds (default: the agent's\n                        suggestion, else kv's: 300)\n  --no-call-limit       No call count for the service(s) named: any number of\n                        calls until the time limit (the approval screen shows\n                        a red caution)\n  --when-spent {pause,end}\n                        When calls or time run out: pause the job and ask you\n                        (default on a passphrase-protected vault), or end it\n  --wait-minutes WAIT_MINUTES\n                        How long a paused job or a call waits for your answer\n                        (default 60)\n  --wait-seconds WAIT_SECONDS\n                        The same wait, in seconds\n  --add-calls ADD_CALLS\n                        Answering a paused job: calls to add (default: what it\n                        asked)\n  --add-minutes ADD_MINUTES\n                        Answering a paused job: minutes to add (default: what\n                        it asked)\n  --max-calls MAX_CALLS\n                        Override broker capability call budget\n  --max-calls-for SERVICE=N\n                        Calls per run for one service of several (repeatable),\n                        e.g. api:openai=10\n  --post-rule api:PROVIDER/RULE=N\n                        One entry of a POST wallet (repeatable): up to N POST\n                        calls per run to one HTTP rule of one service, with\n                        any body. Every service of the approval needs an\n                        entry; the counts are the entries' (do not use --max-\n                        calls, --max-calls-for or --no-call-limit with it)\n  --max-runs MAX_RUNS   With --reuse: how many runs the grant allows (required\n                        on a passphrase-protected vault)\n  --reason REASON       Human note stored with the grant\n",
    ),
    (
        "page",
        "usage: kv approvals page [-h] [--no-browser]\n\noptions:\n  -h, --help    show this help message and exit\n  --no-browser  Print the one-time link only; do not open a browser\n",
    ),
    (
        "pause",
        "usage: kv approvals pause [-h] [job_id]\n\npositional arguments:\n  job_id      The job to pause (from the list)\n\noptions:\n  -h, --help  show this help message and exit\n",
    ),
    (
        "deny",
        "usage: kv approvals deny [-h] [--reason REASON] request_id\n\npositional arguments:\n  request_id       Approval request ID\n\noptions:\n  -h, --help       show this help message and exit\n  --reason REASON  Human note stored with the denial\n",
    ),
    (
        "prune",
        "usage: kv approvals prune [-h] [--missed]\n\noptions:\n  -h, --help  show this help message and exit\n  --missed    Also remove requests that expired undecided (missed) now\n",
    ),
];

fn parse_approvals(rest: &[String]) -> Result<Option<Command>, ParseError> {
    use crate::approvalscmd::ApprovalsAction;
    let Some(action) = rest.first() else {
        return Ok(Some(Command::Approvals(ApprovalsAction::Unavailable(
            "list",
        ))));
    };
    if action == "-h" || action == "--help" {
        return Err(ParseError::Help(format!(
            "{APPROVALS_USAGE}\npositional arguments:\n  {{list,watch,request,approve,page,pause,deny,prune}}\n    list                List pending approval requests\n    watch               Show the terminal approval inbox\n    request             Create a pending approval request\n    approve             Approve a pending run grant or one-call permit\n    page                Approve requests on a local page in your browser (one-\n                        use link)\n    pause               Pause a running counted job at once (it goes on only\n                        after kv approvals approve); without a job: list the\n                        running jobs\n    deny                Deny a pending request, or refuse a paused job more\n                        calls or time\n    prune               Remove decided request records; missed requests are\n                        kept 24 h after expiry\n\noptions:\n  -h, --help            show this help message and exit\n"
        )));
    }
    let Some(choice) = APPROVALS_CHOICES.iter().find(|c| *c == action) else {
        return Err(ParseError::Usage(format!(
            "{APPROVALS_USAGE}kv approvals: error: argument approvals_action: invalid choice: '{action}' (choose from 'list', 'watch', 'request', 'approve', 'page', 'pause', 'deny', 'prune')\n"
        )));
    };
    let rest = &rest[1..];
    if rest.iter().any(|v| v == "-h" || v == "--help") {
        let help = APPROVALS_HELP
            .iter()
            .find(|(name, _)| name == choice)
            .map(|(_, help)| *help)
            .unwrap_or("");
        return Err(ParseError::Help(help.to_owned()));
    }
    if *choice != "approve" {
        return Ok(Some(Command::Approvals(ApprovalsAction::Unavailable(
            choice,
        ))));
    }
    let mut request_id = None;
    let mut run_grant_flags = false;
    let mut skip = false;
    for (i, value) in rest.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        if value.starts_with("--") {
            run_grant_flags = true;
            if !value.contains('=')
                && !matches!(value.as_str(), "--reuse" | "--no-call-limit")
                && i + 1 < rest.len()
            {
                skip = true;
            }
            continue;
        }
        if request_id.replace(value.clone()).is_some() {
            return Err(ParseError::Usage(format!(
                "{APPROVE_USAGE}kv approvals approve: error: unrecognized arguments: {value}\n"
            )));
        }
    }
    let Some(request_id) = request_id else {
        return Err(ParseError::Usage(format!(
            "{APPROVE_USAGE}kv approvals approve: error: the following arguments are required: request_id\n"
        )));
    };
    Ok(Some(Command::Approvals(ApprovalsAction::Approve {
        request_id,
        run_grant_flags,
    })))
}

fn parse_policy(rest: &[String]) -> Result<Option<Command>, ParseError> {
    if rest.first().is_some_and(|v| v == "-h" || v == "--help") {
        return Err(ParseError::Help(format!(
            "{POLICY_USAGE}\npositional arguments:\n  {{http,list,watch,request,allow,block,deny,prune}}\n    http                Manage HTTP broker route rules\n    list                List pending command-policy requests\n    watch               Show the terminal command-policy inbox\n    request             Create a blocked command-policy request\n    allow               Allow a pending command shape\n    block               Keep a pending command shape blocked\n    deny                ==SUPPRESS==\n    prune               Remove non-pending and expired policy request records\n\noptions:\n  -h, --help            show this help message and exit\n"
        )));
    }
    if rest.first().map(String::as_str) != Some("http") {
        return parse_command_policy(rest);
    }
    let rest = &rest[1..];
    let Some(action) = rest.first() else {
        return Ok(Some(Command::Policy(PolicyAction::HttpList(None))));
    };
    if action == "-h" || action == "--help" {
        return Err(ParseError::Help(format!(
            "{HTTP_USAGE}\npositional arguments:\n  {{list,add,remove,rm}}\n    list                List HTTP broker route rules\n    add                 Add an HTTP broker route rule; unsafe calls need owner\n                        approval\n    remove (rm)         Remove an HTTP broker route rule\n\noptions:\n  -h, --help            show this help message and exit\n"
        )));
    }
    let spec = match action.as_str() {
        "list" => &HTTP_LIST,
        "add" => &HTTP_ADD,
        "remove" | "rm" => &HTTP_REMOVE,
        _ => {
            return Err(ParseError::Usage(format!(
                "{HTTP_USAGE}kv policy http: error: argument http_policy_action: invalid choice: '{action}' (choose from 'list', 'add', 'remove', 'rm')\n"
            )));
        }
    };
    let parsed = parse_spec(spec, &rest[1..])?;
    let option = |key| {
        parsed
            .options
            .iter()
            .rev()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.clone())
    };
    let repeated = |key| {
        parsed
            .options
            .iter()
            .filter(|(name, _)| *name == key)
            .map(|(_, value)| value.clone())
            .collect()
    };
    let mut pos = parsed.positionals.into_iter();
    let provider = pos.next();
    let action = match action.as_str() {
        "list" => PolicyAction::HttpList(provider),
        "add" => PolicyAction::HttpAdd {
            provider: provider.unwrap_or_default(),
            rule: Box::new(HttpRuleOptions {
                id: option("--id").unwrap_or_default(),
                methods: repeated("--method"),
                path: option("--path"),
                path_prefix: option("--path-prefix"),
                query_keys: repeated("--query-key"),
                allowed_headers: repeated("--header"),
            }),
        },
        _ => PolicyAction::HttpRemove {
            provider: provider.unwrap_or_default(),
            id: pos.next().unwrap_or_default(),
        },
    };
    Ok(Some(Command::Policy(action)))
}

fn parse_command_policy(rest: &[String]) -> Result<Option<Command>, ParseError> {
    use crate::command_policy::CommandPolicyAction as Action;
    let Some(name) = rest.first() else {
        return Ok(Some(Command::Policy(PolicyAction::Command(Action::List(
            false,
        )))));
    };
    let mut spec = Spec {
        name: "policy list",
        usage: "usage: kv policy list [-h] [--all]\n",
        help: "\noptions:\n  -h, --help  show this help message and exit\n",
        env: false,
        positionals: &[],
        flags: &[(
            "--all",
            "  --all       Include allowed, blocked, and expired requests\n",
        )],
        options: &[],
    };
    match name.as_str() {
        "list" => {}
        "allow" | "block" | "deny" => {
            spec.name = match name.as_str() {
                "allow" => "policy allow",
                "block" => "policy block",
                _ => "policy deny",
            };
            spec.usage = match name.as_str() {
                "allow" => "usage: kv policy allow [-h] [--reason REASON] request_id\n",
                "block" => "usage: kv policy block [-h] [--reason REASON] request_id\n",
                _ => "usage: kv policy deny [-h] [--reason REASON] request_id\n",
            };
            spec.help = "\npositional arguments:\n  request_id       Command-policy request ID\n\noptions:\n  -h, --help       show this help message and exit\n";
            spec.positionals = &["request_id"];
            spec.flags = &[];
            spec.options = &[(
                "--reason",
                "  --reason REASON  Human note stored with the decision\n",
            )];
        }
        "prune" => {
            spec.name = "policy prune";
            spec.usage = "usage: kv policy prune [-h]\n";
            spec.flags = &[];
        }
        "watch" => {
            spec.name = "policy watch";
            spec.usage = "usage: kv policy watch [-h] [--all] [--follow] [--interval INTERVAL]\n";
            spec.help = "\noptions:\n  -h, --help           show this help message and exit\n";
            spec.flags = &[
                (
                    "--all",
                    "  --all                Include allowed, blocked, and expired requests\n",
                ),
                (
                    "--follow",
                    "  --follow             Keep refreshing until interrupted\n",
                ),
            ];
            spec.options = &[(
                "--interval",
                "  --interval INTERVAL  Refresh interval for --follow\n",
            )];
        }
        "request" => {
            spec.name = "policy request";
            spec.usage = "usage: kv policy request [-h] [--ttl TTL] [--cwd CWD] [--source SOURCE]\n                         [--client CLIENT] [--session-id SESSION_ID]\n                         [--reason REASON]\n                         ...\n";
            spec.help = "\npositional arguments:\n  cmd                   Command requesting policy review\n\noptions:\n  -h, --help            show this help message and exit\n";
            spec.flags = &[];
            spec.options = &[
                (
                    "--ttl",
                    "  --ttl TTL             Pending request lifetime in seconds (default: 900)\n",
                ),
                (
                    "--cwd",
                    "  --cwd CWD             Working directory for the command (default: current\n                        directory)\n",
                ),
                (
                    "--source",
                    "  --source SOURCE       Optional requester source to bind, such as mcp\n",
                ),
                (
                    "--client",
                    "  --client CLIENT       Optional client name to bind, such as codex\n",
                ),
                (
                    "--session-id",
                    "  --session-id SESSION_ID\n                        Optional agent/session ID to bind\n",
                ),
                (
                    "--reason",
                    "  --reason REASON       Human note stored with the request\n",
                ),
            ];
        }
        _ => {
            return Err(ParseError::Usage(format!(
                "{POLICY_USAGE}kv policy: error: argument policy_action: invalid choice: '{name}' (choose from 'http', 'list', 'watch', 'request', 'allow', 'block', 'deny', 'prune')\n"
            )));
        }
    }
    let mut args = &rest[1..];
    if name == "request" {
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--" || !args[i].starts_with('-') {
                break;
            }
            if matches!(args[i].as_str(), "-h" | "--help") {
                i += 1;
                break;
            }
            i += if args[i].contains('=') { 1 } else { 2 };
        }
        args = &args[..i.min(args.len())];
    }
    let parsed = parse_spec(&spec, args)?;
    let reason = parsed
        .options
        .iter()
        .rev()
        .find(|(key, _)| *key == "--reason")
        .map(|(_, v)| v.clone());
    let id = parsed.positionals.first().cloned().unwrap_or_default();
    let action = match name.as_str() {
        "list" => PolicyAction::Command(Action::List(parsed.flags.contains(&"--all"))),
        "allow" => PolicyAction::Command(Action::Allow { id, reason }),
        "block" | "deny" => PolicyAction::Command(Action::Block {
            id,
            reason,
            alias: name == "deny",
        }),
        "prune" => PolicyAction::Command(Action::Prune),
        _ => PolicyAction::Unavailable,
    };
    Ok(Some(Command::Policy(action)))
}

fn parse_provider(rest: &[String]) -> Result<Option<Command>, ParseError> {
    let Some(action) = rest.first() else {
        return Ok(Some(Command::Provider(ProviderAction::List)));
    };
    if action == "-h" || action == "--help" {
        return Err(ParseError::Help(format!(
            "{PROVIDER_USAGE}\npositional arguments:\n  {{add,list,rm}}\n    add          Add a custom provider\n    list         List all providers\n    rm           Remove a custom provider\n\noptions:\n  -h, --help     show this help message and exit\n"
        )));
    }
    let spec = match action.as_str() {
        "add" => &PROVIDER_ADD,
        "rm" => &PROVIDER_RM,
        "list" => &PROVIDER_LIST,
        _ => {
            return Err(ParseError::Usage(format!(
                "{PROVIDER_USAGE}kv provider: error: argument provider_action: invalid choice: '{action}' (choose from 'add', 'list', 'rm')\n"
            )));
        }
    };
    let parsed = parse_spec(spec, &rest[1..])?;
    let option = |key| {
        parsed
            .options
            .iter()
            .rev()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.clone())
    };
    let name = parsed.positionals.first().cloned().unwrap_or_default();
    let action = match action.as_str() {
        "rm" => ProviderAction::Remove(name),
        "list" => ProviderAction::List,
        _ => ProviderAction::Add(Box::new(ProviderOptions {
            name,
            provider_type: option("--type").unwrap_or_else(|| "http".into()),
            url: option("--url"),
            host: option("--host"),
            port: option("--port")
                .and_then(|v| provider_port(&v))
                .map(serde_json::Value::from),
            database: option("--database"),
            username: option("--username"),
            secret: option("--secret"),
            auth: option("--auth").unwrap_or_else(|| "bearer".into()),
            query_param: option("--query-param"),
            header_name: option("--header-name"),
        })),
    };
    Ok(Some(Command::Provider(action)))
}

fn parse_approval_mode(rest: &[String]) -> Result<Option<Command>, ParseError> {
    let Some(action) = rest.first() else {
        return Ok(Some(Command::ApprovalMode(None)));
    };
    if action == "-h" || action == "--help" {
        return Err(ParseError::Help(format!(
            "{APPROVAL_MODE_USAGE}\npositional arguments:\n  {{status,set}}\n    status      Show approval security mode\n    set         Set approval security mode\n\noptions:\n  -h, --help    show this help message and exit\n"
        )));
    }
    let spec = match action.as_str() {
        "set" => &APPROVAL_MODE_SET_SPEC,
        "status" => &APPROVAL_MODE_STATUS_SPEC,
        _ => {
            return Err(ParseError::Usage(format!(
                "{APPROVAL_MODE_USAGE}kv approval-mode: error: argument approval_mode_action: invalid choice: '{action}' (choose from 'status', 'set')\n"
            )));
        }
    };
    let parsed = parse_spec(spec, &rest[1..])?;
    let mode = parsed.positionals.into_iter().next();
    if let Some(mode) = mode.as_deref()
        && ![
            "local-convenience",
            "protected-approval",
            "unsafe-convenience",
        ]
        .contains(&mode)
    {
        return Err(spec_error(
            spec,
            &format!(
                "argument mode: invalid choice: '{mode}' (choose from 'local-convenience', 'protected-approval', 'unsafe-convenience')"
            ),
        ));
    }
    Ok(Some(Command::ApprovalMode(mode)))
}

const HISTORY_HELP_TEXT: &str = "\npositional arguments:\n  {list,show,restore,undo-rm,replace,forget,keep}\n    list                List a secret's versions (no values)\n    show                Print one old value (owner terminal only)\n    restore             Put an old value back as the current one\n    undo-rm             Bring back a removed secret\n    replace             Change a secret and wipe all its old values\n    forget              Wipe old values: one secret, --all in an environment,\n                        or --vault\n    keep                Show or set how many old values to keep (0..100)\n\noptions:\n  -h, --help            show this help message and exit\n";

const KEY_HELP: &str = "\npositional arguments:\n  key                Secret key name\n\noptions:\n  -h, --help         show this help message and exit\n";

const KEY_VERSION_HELP: &str = "\npositional arguments:\n  key                Secret key name\n  version            Version number from kv history list\n\noptions:\n  -h, --help         show this help message and exit\n";

const HISTORY_SPECS: &[Spec] = &[
    Spec {
        name: "history list",
        usage: "usage: kv history list [-h] [-e ENV] key\n",
        help: KEY_HELP,
        positionals: &["key"],
        env: true,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "history show",
        usage: "usage: kv history show [-h] [-e ENV] key version\n",
        help: KEY_VERSION_HELP,
        positionals: &["key", "version"],
        env: true,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "history restore",
        usage: "usage: kv history restore [-h] [-e ENV] key version\n",
        help: KEY_VERSION_HELP,
        positionals: &["key", "version"],
        env: true,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "history undo-rm",
        usage: "usage: kv history undo-rm [-h] [-e ENV] key\n",
        help: KEY_HELP,
        positionals: &["key"],
        env: true,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "history replace",
        usage: "usage: kv history replace [-h] [-e ENV] secret\n",
        help: "\npositional arguments:\n  secret             KEY=VALUE or just KEY (prompts for value)\n\noptions:\n  -h, --help         show this help message and exit\n",
        positionals: &["secret"],
        env: true,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "history forget",
        usage: "usage: kv history forget [-h] [--all] [--vault] [-e ENV] [key]\n",
        // argparse lists --all/--vault before -e: their text lives here, not in `flags`.
        help: "\npositional arguments:\n  key                Secret key name\n\noptions:\n  -h, --help         show this help message and exit\n  --all              Every secret in the environment\n  --vault            Every environment\n",
        positionals: &["?key"],
        env: true,
        flags: &[("--all", ""), ("--vault", "")],
        options: &[],
    },
    Spec {
        name: "history keep",
        usage: "usage: kv history keep [-h] [count]\n",
        help: "\npositional arguments:\n  count       Old values to keep per secret (0 keeps none)\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["?count"],
        env: false,
        flags: &[],
        options: &[],
    },
];

/// `kv history ...`: argparse's sub-subparser; no action is reported by `cmd_history`.
fn parse_history(rest: &[String]) -> Result<Option<Command>, ParseError> {
    use crate::history::HistoryAction;
    let Some(action) = rest.first() else {
        return Ok(Some(Command::History(HistoryAction::None)));
    };
    if action == "-h" || action == "--help" {
        return Err(ParseError::Help(format!(
            "{HISTORY_USAGE}{HISTORY_HELP_TEXT}"
        )));
    }
    let Some(spec) = HISTORY_SPECS
        .iter()
        .find(|spec| spec.name.strip_prefix("history ") == Some(action.as_str()))
    else {
        return Err(ParseError::Usage(format!(
            "{HISTORY_USAGE}kv history: error: argument history_action: invalid choice: '{action}' (choose from 'list', 'show', 'restore', 'undo-rm', 'replace', 'forget', 'keep')\n"
        )));
    };
    let parsed = parse_spec(spec, &rest[1..])?;
    let env = parsed.env;
    let mut pos = parsed.positionals.into_iter();
    let has = |flag: &str| parsed.flags.contains(&flag);
    Ok(Some(Command::History(match action.as_str() {
        "list" => HistoryAction::List {
            key: pos.next().unwrap_or_default(),
            env,
        },
        "show" => HistoryAction::Show {
            key: pos.next().unwrap_or_default(),
            version: pos.next().unwrap_or_default(),
            env,
        },
        "restore" => HistoryAction::Restore {
            key: pos.next().unwrap_or_default(),
            version: pos.next().unwrap_or_default(),
            env,
        },
        "undo-rm" => HistoryAction::UndoRm {
            key: pos.next().unwrap_or_default(),
            env,
        },
        "replace" => HistoryAction::Replace {
            secret: pos.next().unwrap_or_default(),
            env,
        },
        "forget" => HistoryAction::Forget {
            key: pos.next(),
            all: has("--all"),
            vault: has("--vault"),
            env,
        },
        _ => HistoryAction::Keep { count: pos.next() },
    })))
}

const BACKUP_USAGE: &str = "usage: kv backup [-h] {create,show,restore} ...\n";

const BACKUP_HELP_TEXT: &str = "\npositional arguments:\n  {create,show,restore}\n    create              Write an encrypted backup file of this vault\n    show                List what a backup file holds (no values)\n    restore             Make a new vault in a new folder from a backup file\n\noptions:\n  -h, --help            show this help message and exit\n";

const BACKUP_SPECS: &[Spec] = &[
    Spec {
        name: "backup create",
        usage: "usage: kv backup create [-h] file\n",
        help: "\npositional arguments:\n  file        The new backup file (never overwritten)\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["file"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "backup show",
        usage: "usage: kv backup show [-h] file\n",
        help: "\npositional arguments:\n  file        A backup file\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["file"],
        env: false,
        flags: &[],
        options: &[],
    },
    Spec {
        name: "backup restore",
        usage: "usage: kv backup restore [-h] file dir\n",
        help: "\npositional arguments:\n  file        A backup file\n  dir         A new folder (absent or empty)\n\noptions:\n  -h, --help  show this help message and exit\n",
        positionals: &["file", "dir"],
        env: false,
        flags: &[],
        options: &[],
    },
];

fn parse_backup(rest: &[String]) -> Result<Option<Command>, ParseError> {
    use crate::backup::BackupAction;
    let Some(action) = rest.first() else {
        return Ok(Some(Command::Backup(BackupAction::None)));
    };
    if action == "-h" || action == "--help" {
        return Err(ParseError::Help(format!(
            "{BACKUP_USAGE}{BACKUP_HELP_TEXT}"
        )));
    }
    let Some(spec) = BACKUP_SPECS
        .iter()
        .find(|spec| spec.name.strip_prefix("backup ") == Some(action.as_str()))
    else {
        return Err(ParseError::Usage(format!(
            "{BACKUP_USAGE}kv backup: error: argument backup_action: invalid choice: '{action}' (choose from 'create', 'show', 'restore')\n"
        )));
    };
    let parsed = parse_spec(spec, &rest[1..])?;
    let mut pos = parsed.positionals.into_iter();
    Ok(Some(Command::Backup(match action.as_str() {
        "create" => BackupAction::Create {
            file: pos.next().unwrap_or_default(),
        },
        "show" => BackupAction::Show {
            file: pos.next().unwrap_or_default(),
        },
        _ => BackupAction::Restore {
            file: pos.next().unwrap_or_default(),
            dir: pos.next().unwrap_or_default(),
        },
    })))
}

const VAULT_USAGE: &str = "usage: kv vault [-h]\n                {approve-local,approve-config,restore-old-key,relocate,migrate-drawers,backup-drawers,rollback-drawers}\n                ...\n";

const VAULT_HELP_TEXT: &str = "\npositional arguments:\n  {approve-local,approve-config,restore-old-key,relocate,migrate-drawers,backup-drawers,rollback-drawers}\n    approve-local       Approve a supplied vault on this machine at your\n                        terminal\n    approve-config      Review and approve config authority with your\n                        passphrase\n    restore-old-key     Put the saved old key back so kv 0.3.0 opens this\n                        vault (Linux only)\n    relocate            Bind a moved vault's key file to this folder\n    migrate-drawers     Migrate env-bundle vaults to drawer storage\n    backup-drawers      Create private migration backup before drawer migration\n    rollback-drawers    Verify or restore a drawer migration backup\n\noptions:\n  -h, --help            show this help message and exit\n";

const VAULT_ACTIONS: &[&str] = &[
    "approve-local",
    "approve-config",
    "restore-old-key",
    "relocate",
    "migrate-drawers",
    "backup-drawers",
    "rollback-drawers",
];

fn parse_vault(rest: &[String]) -> Result<Option<Command>, ParseError> {
    use crate::vaultcmd::VaultAction;
    let Some(action) = rest.first() else {
        return Ok(Some(Command::Vault(VaultAction::None)));
    };
    if action == "-h" || action == "--help" {
        return Err(ParseError::Help(format!("{VAULT_USAGE}{VAULT_HELP_TEXT}")));
    }
    if !VAULT_ACTIONS.contains(&action.as_str()) {
        let choices = VAULT_ACTIONS
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ParseError::Usage(format!(
            "{VAULT_USAGE}kv vault: error: argument vault_action: invalid choice: '{action}' (choose from {choices})\n"
        )));
    }
    if action == "approve-config" {
        if let Some(extra) = rest.get(1) {
            if extra == "-h" || extra == "--help" {
                return Err(ParseError::Help(
                    "usage: kv vault approve-config [-h]\n\noptions:\n  -h, --help  show this help message and exit\n".to_owned(),
                ));
            }
            return Err(ParseError::Usage(format!(
                "{USAGE_TOP}kv: error: unrecognized arguments: {}\n",
                rest[1..].join(" ")
            )));
        }
        return Ok(Some(Command::Vault(VaultAction::ApproveConfig)));
    }
    Ok(Some(Command::Vault(VaultAction::Unported(action.clone()))))
}

const RUN_USAGE: &str = "usage: kv run [-h] [-e ENV] [--cwd CWD] [--private-cwd | --no-private-cwd]\n              [-q] [--secret NAME | --no-secrets | --capability api:PROVIDER]\n              ...\n";
const RUN_HELP: &str = "\npositional arguments:\n  cmd                   Command to run\n\noptions:\n  -h, --help            show this help message and exit\n  -e ENV, --env ENV     Environment (default: the project's default)\n  --cwd CWD             Working directory for the command (default: current\n                        directory)\n  --private-cwd         Run secret-bearing commands in a private cwd copy and\n                        copy back safe outputs\n  --no-private-cwd      Disable the private cwd copy for this run (capability\n                        runs use it by default)\n  -q, --quiet           Suppress kv output\n  --secret NAME         Inject only this secret name (repeatable; must appear\n                        before COMMAND)\n  --no-secrets          Run without injecting secrets (must appear before\n                        COMMAND)\n  --capability api:PROVIDER\n                        Inject a temporary broker token for api:<provider>\n                        instead of raw secrets\n";

fn run_error(message: &str) -> ParseError {
    ParseError::Usage(format!("{RUN_USAGE}kv run: error: {message}\n"))
}

/// `kv run`: argparse options before the command, then `REMAINDER` (the
/// command itself, kept verbatim from its first token or `--`).
fn parse_run(rest: &[String]) -> Result<Option<Command>, ParseError> {
    let mut env = None;
    let mut cwd = None;
    let mut private_cwd: Option<bool> = None;
    let mut private_flag: Option<&str> = None;
    let mut quiet = false;
    let mut secret_names: Option<Vec<String>> = None;
    let mut no_secrets = false;
    let mut capability_names: Vec<String> = Vec::new();
    let mut scope_flag: Option<&str> = None;
    let mut i = 0;
    let exclusive =
        |standing: &mut Option<&'static str>, flag: &'static str| -> Result<(), ParseError> {
            match standing {
                Some(other) if *other != flag => Err(run_error(&format!(
                    "argument {flag}: not allowed with argument {other}"
                ))),
                _ => {
                    *standing = Some(flag);
                    Ok(())
                }
            }
        };
    while i < rest.len() {
        let arg = &rest[i];
        if arg == "--" || !arg.starts_with('-') || arg.len() == 1 {
            break;
        }
        if arg == "-h" || arg == "--help" {
            return Err(ParseError::Help(format!("{RUN_USAGE}{RUN_HELP}")));
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if arg.starts_with("--") => {
                (name.to_owned(), Some(value.to_owned()))
            }
            _ => (arg.clone(), None),
        };
        let take_value = |aliases: &str, i: &mut usize| -> Result<String, ParseError> {
            if let Some(value) = &inline {
                return Ok(value.clone());
            }
            *i += 1;
            match rest.get(*i) {
                Some(value) if !(value.starts_with('-') && value.len() > 1) => Ok(value.clone()),
                _ => Err(run_error(&format!(
                    "argument {aliases}: expected one argument"
                ))),
            }
        };
        match name.as_str() {
            "-e" | "--env" => env = Some(take_value("-e/--env", &mut i)?),
            "--cwd" => cwd = Some(take_value("--cwd", &mut i)?),
            "--private-cwd" => {
                exclusive(&mut private_flag, "--private-cwd")?;
                private_cwd = Some(true);
            }
            "--no-private-cwd" => {
                exclusive(&mut private_flag, "--no-private-cwd")?;
                private_cwd = Some(false);
            }
            "-q" | "--quiet" => quiet = true,
            "--secret" => {
                let value = take_value("--secret", &mut i)?;
                exclusive(&mut scope_flag, "--secret")?;
                secret_names.get_or_insert_with(Vec::new).push(value);
            }
            "--no-secrets" => {
                exclusive(&mut scope_flag, "--no-secrets")?;
                no_secrets = true;
            }
            "--capability" => {
                let value = take_value("--capability", &mut i)?;
                exclusive(&mut scope_flag, "--capability")?;
                capability_names.push(value);
            }
            _ => {
                return Err(top_error(&format!(
                    "unrecognized arguments: {}",
                    rest[i..].join(" ")
                )));
            }
        }
        i += 1;
    }
    Ok(Some(Command::Run {
        env,
        cwd,
        private_cwd,
        quiet,
        secret_names,
        no_secrets,
        capability_names,
        cmd: rest[i..].to_vec(),
    }))
}
