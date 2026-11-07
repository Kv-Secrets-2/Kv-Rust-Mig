//! `build_parser()` for the commands this build carries, with argparse's messages.

pub enum Command {
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
    Env(crate::envcmd::EnvAction),
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

const USAGE_TOP: &str = "usage: kv [-h] [--version]\n          {init,set,get,ls,rm,unlock,lock,status,export,envs,env,history,backup,version,mcp-server}\n          ...\n";

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
    let Some(spec) = SPECS.iter().find(|spec| spec.name == first.as_str()) else {
        return Err(ParseError::Unknown);
    };
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
        _ => Command::Version,
    }))
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
    let has = |flag: &str| parsed.flags.iter().any(|f| *f == flag);
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
