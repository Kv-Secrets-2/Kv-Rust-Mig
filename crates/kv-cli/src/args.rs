//! `build_parser()` for the commands this build carries, with argparse's messages.

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
    AgentChild,
    Hook {
        mode: String,
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

const USAGE_TOP: &str = "usage: kv [-h] [--version]\n          {init,set,get,ls,rm,unlock,lock,status,export,envs,env,history,backup,vault,version,mcp-server}\n          ...\n";

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

/// argparse `_parse_optional`: `--name=value` and `-x=value` split at the first `=`
/// when the left side is an option; otherwise a single-dash argument longer than two
/// characters whose first two name a value-taking option (`-eprod`, `-oFILE`) carries
/// the rest as its value. Boolean flags take no attached value: `-fx` stays unknown.
fn split_option(spec: &Spec, arg: &str) -> (String, Option<String>) {
    let takes_value = |name: &str| {
        (spec.env && (name == "-e" || name == "--env"))
            || spec.options.iter().any(|(option, text)| {
                *option == name
                    || text
                        .trim_start()
                        .split(',')
                        .map(|s| s.trim().split(' ').next().unwrap_or(""))
                        .any(|alias| alias == name)
            })
    };
    let is_option = |name: &str| {
        takes_value(name)
            || spec.flags.iter().any(|(flag, text)| {
                *flag == name
                    || text
                        .trim_start()
                        .split(',')
                        .map(|s| s.trim().split(' ').next().unwrap_or(""))
                        .any(|alias| alias == name)
            })
    };
    if let Some((name, value)) = arg.split_once('=')
        && (arg.starts_with("--") || is_option(name))
    {
        return (name.to_owned(), Some(value.to_owned()));
    }
    if let (Some(short), Some(value)) = (arg.get(..2), arg.get(2..))
        && !arg.starts_with("--")
        && !value.is_empty()
        && takes_value(short)
    {
        return (short.to_owned(), Some(value.to_owned()));
    }
    (arg.to_owned(), None)
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
            let (name, inline) = split_option(spec, arg);
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
            if let Some((flag, text)) = spec.flags.iter().find(|(flag, text)| {
                *flag == name
                    || text
                        .trim_start()
                        .split(',')
                        .map(|s| s.trim().split(' ').next().unwrap_or(""))
                        .any(|alias| alias == name)
            }) {
                if let Some(value) = inline {
                    let mut aliases: Vec<&str> = text
                        .trim_start()
                        .split(',')
                        .map(|s| s.trim().split(' ').next().unwrap_or(""))
                        .filter(|alias| !alias.is_empty())
                        .collect();
                    if aliases.is_empty() {
                        aliases.push(flag);
                    }
                    return Err(spec_error(
                        spec,
                        &format!(
                            "argument {}: ignored explicit argument {}",
                            aliases.join("/"),
                            crate::secrets::py_repr(&value)
                        ),
                    ));
                }
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
                            Some(value) if !(value.starts_with('-') && value.len() > 1) => {
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
    if parsed.positionals.len() < required {
        let missing: Vec<&str> = spec.positionals[parsed.positionals.len()..required].to_vec();
        return Err(spec_error(
            spec,
            &format!(
                "the following arguments are required: {}",
                missing.join(", ")
            ),
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
            .rev()
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
                .rev()
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

#[cfg(test)]
mod tests {
    use super::{Command, ParseError, parse};

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn usage_error(items: &[&str]) -> String {
        match parse(&args(items)) {
            Err(ParseError::Usage(text)) => text,
            _ => panic!("expected a usage error for {items:?}"),
        }
    }

    #[test]
    fn boolean_flags_refuse_an_explicit_value_like_argparse() {
        assert!(
            usage_error(&["rm", "KEY", "--force=false"]).ends_with(
                "kv rm: error: argument -f/--force: ignored explicit argument 'false'\n"
            )
        );
        assert!(
            usage_error(&["ls", "--reveal=true"])
                .ends_with("kv ls: error: argument --reveal: ignored explicit argument 'true'\n")
        );
        assert!(usage_error(&["rm", "KEY", "--force="]).contains("ignored explicit argument ''"));
        assert!(usage_error(&["rm", "-fx", "KEY"]).contains("unrecognized arguments: -fx KEY"));
        assert!(
            usage_error(&["history", "forget", "KEY", "--all=true"])
                .contains("error: argument --all: ignored explicit argument 'true'")
        );
        assert!(matches!(
            parse(&args(&["rm", "KEY", "--force"])),
            Ok(Some(Command::Rm { force: true, .. }))
        ));
    }

    #[test]
    fn value_options_take_attached_values_and_the_last_occurrence_wins_like_argparse() {
        let parsed = |args: &[&str]| {
            let argv: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
            match parse(&argv) {
                Ok(Some(command)) => command,
                _ => panic!("{args:?} should parse"),
            }
        };
        for args in [
            &["export", "-eprod", "-oFILE"][..],
            &["export", "-e=prod", "-o=FILE"],
            &["export", "-e", "prod", "-o", "FILE"],
            &["export", "--env=prod", "--output=FILE"],
            &[
                "export",
                "-o",
                "first.env",
                "-e",
                "dev",
                "-o",
                "FILE",
                "-eprod",
            ],
        ] {
            match parsed(args) {
                Command::Export { env, output } => {
                    assert_eq!(env.as_deref(), Some("prod"), "{args:?}");
                    assert_eq!(output.as_deref(), Some("FILE"), "{args:?}");
                }
                _ => panic!("{args:?}"),
            }
        }
        match parsed(&["export", "-eprod=x"]) {
            Command::Export { env, .. } => assert_eq!(env.as_deref(), Some("prod=x")),
            _ => panic!("-eprod=x"),
        }
        match parsed(&["init", "--location", "global", "--location", "project"]) {
            Command::Init { location, .. } => assert_eq!(location.as_deref(), Some("project")),
            _ => panic!("--location twice"),
        }
    }
}
