//! The run environment (Python `kv/sandbox.py` R-184): inherited names that
//! never reach a child, secret names that would steer how a program starts,
//! the framing check for `--setenv` operands, and the sealed args payload.

use std::collections::BTreeMap;
use std::fmt;

pub const SENSITIVE_ENV_EXACT: &[&str] = &[
    "KV_MASTER_KEY",
    "KV_ALLOW_ENV_MASTER_KEY",
    "KV_PASSPHRASE",
    "KV_TOKEN",
];
pub const SENSITIVE_ENV_FRAGMENTS: &[&str] = &[
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSPHRASE",
    "CREDENTIAL",
    "AUTH",
    "SESSION",
    "COOKIE",
    "BEARER",
];

pub const RESERVED_RUN_ENV_NAMES: &[&str] = &[
    "PATH",
    "LIBPATH",
    "SHLIB_PATH",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "LOCPATH",
    "NLSPATH",
    "HOSTALIASES",
    "MALLOC_TRACE",
    "ENV",
    "BASH_ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PROMPT_COMMAND",
    "PS4",
    "IFS",
    "CDPATH",
    "HOME",
    "SHELL",
    "ZDOTDIR",
    "FPATH",
    "GLOBIGNORE",
    "CLASSPATH",
    "CORENABLEPROFILING",
    "COR_PROFILER",
    "COR_PROFILER_PATH",
    "COR_ENABLE_PROFILING",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "MANPAGER",
    "BROWSER",
    "TERMINAL",
    "FCEDIT",
    "VIMINIT",
    "EXINIT",
    "MVIMINIT",
    "GVIMINIT",
    "TERMINFO",
    "TERMINFO_DIRS",
    "INPUTRC",
    "GOPATH",
    "GOROOT",
    "GOENV",
    "GOCACHE",
    "GOMODCACHE",
    "GOFLAGS",
    "GOTOOLCHAIN",
    "GOEXPERIMENT",
    "MAKEFILES",
    "MAKEFLAGS",
    "COMSPEC",
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
    "PSMODULEPATH",
    "PSEXECUTIONPOLICYPREFERENCE",
    "XMODIFIERS",
    "GNUPGHOME",
    "IRBRC",
    "GEM_HOME",
    "GEM_PATH",
    "GEM_SPEC_CACHE",
    "TK_LIBRARY",
    "LESSOPEN",
    "LESSCLOSE",
    "RUBYOPT",
    "RUBYLIB",
    "RUBYPATH",
    "RUBYSHELL",
    "TCL_LIBRARY",
    "PHPRC",
    "PHP_INI_SCAN_DIR",
    "PERLLIB",
    "PERLDB",
    "R_HOME",
    "R_ENVIRON",
    "R_ENVIRON_USER",
    "R_PROFILE",
    "R_PROFILE_USER",
    "R_LIBS",
    "R_LIBS_SITE",
    "R_LIBS_USER",
    "R_TESTS",
    "R_BATCHSAVE",
    "R_BROWSER",
    "R_PDFVIEWER",
    "R_ZIPCMD",
    "R_UNZIPCMD",
    "R_BZIPCMD",
    "R_GZIPCMD",
    "R_TEXI2DVICMD",
    "R_RD4PDF",
    "R_PAPERSIZE",
    "R_KEEP_PKG_SOURCE",
    "R_HISTORY",
    "R_UNZIP",
    "R_ZIP",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "KRB5CCNAME",
    "RUSTFLAGS",
    "CARGO",
    "RUSTC",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTFMT",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "HTTP_TIMEOUT",
    "TERM",
    "FORCE_COLOR",
    "NO_COLOR",
    "UV_THREADPOOL_SIZE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TZ",
    "NO_PROXY",
    "SSLKEYLOGFILE",
    "PREFIX",
    "JDK_JAVAC_OPTIONS",
];
pub const RESERVED_RUN_ENV_EXEMPTIONS: &[&str] = &[
    "NODE_AUTH_TOKEN",
    "JAVA_KEYSTORE_PASSWORD",
    "SSH_PRIVATE_KEY",
    "GIT_TOKEN",
    "SUDO_PASSWORD",
    "CARGO_REGISTRY_TOKEN",
];
pub const RESERVED_RUN_ENV_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "PYTHON",
    "NODE_",
    "JAVA_",
    "SSH_",
    "SUDO_",
    "GIT_",
    "RUST_",
    "RUSTC_",
    "CARGO_",
    "LUA_",
    "TCLLIBPATH",
    "DOTNET_",
    "COMPLUS_",
    "CORECLR_",
    "MONO_",
    "RUBY_",
    "PERL5",
    "RUSTUP_",
    "BUNDLE_",
    "OPENSSL_",
    "BASH_FUNC_",
    "XDG_",
    "KRB5_",
    "GTK_",
    "GDK_",
    "GIO_",
    "QT_",
    "NPM_CONFIG_",
    "PIP_",
];

/// Python `os.defpath` entries that are absolute, `:`-joined.
pub const ABSOLUTE_DEFAULT_PATH: &str = "/bin:/usr/bin";

/// Python `str.upper()` is Unicode-aware, as is Rust's.
fn upper(name: &str) -> String {
    name.to_uppercase()
}

/// Python `_looks_sensitive_env_name`.
pub fn looks_sensitive_env_name(name: &str) -> bool {
    let upper = upper(name);
    SENSITIVE_ENV_EXACT.contains(&upper.as_str())
        || SENSITIVE_ENV_FRAGMENTS
            .iter()
            .any(|fragment| upper.contains(fragment))
}

fn cargo_registries_token_name(upper: &str) -> bool {
    let Some(rest) = upper.strip_prefix("CARGO_REGISTRIES_") else {
        return false;
    };
    let Some(middle) = rest.strip_suffix("_TOKEN") else {
        return false;
    };
    !middle.is_empty()
        && middle
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Python `_reserved_run_env_name`: a secret under this name steers how a
/// program starts and is refused whole.
pub fn reserved_run_env_name(name: &str) -> bool {
    let upper = upper(name);
    let u = upper.as_str();
    if RESERVED_RUN_ENV_EXEMPTIONS.contains(&u) {
        return false;
    }
    if RESERVED_RUN_ENV_NAMES.contains(&u) {
        return true;
    }
    if u.starts_with("CARGO_REGISTRIES_") {
        return !cargo_registries_token_name(u);
    }
    RESERVED_RUN_ENV_PREFIXES
        .iter()
        .any(|prefix| u.starts_with(prefix))
}

const MAX_SHOWN: usize = 8192;

/// Python `kv.approval_render.escape`: printable ASCII stays, everything
/// else becomes a visible escape; `None` when the result is too long to show.
pub fn escape_checked(value: &str) -> Option<String> {
    let mut shown = String::new();
    for ch in value.chars() {
        let code = u32::from(ch);
        match code {
            0x5c => shown.push_str("\\\\"),
            0x0a => shown.push_str("\\n"),
            0x09 => shown.push_str("\\t"),
            0x0d => shown.push_str("\\r"),
            0x20..=0x7e => shown.push(ch),
            0..=0xffff => shown.push_str(&format!("\\u{code:04x}")),
            _ => shown.push_str(&format!("\\U{code:08x}")),
        }
    }
    (shown.len() <= MAX_SHOWN).then_some(shown)
}

/// Python `_shown_run_env_name`.
pub fn shown_run_env_name(name: &str) -> String {
    escape_checked(name).unwrap_or_else(|| "a name too long to show".to_owned())
}

/// Python `repr(str)` for the shown (already escaped, printable ASCII) name.
fn py_repr(shown: &str) -> String {
    if shown.contains('\'') && !shown.contains('"') {
        format!("\"{shown}\"")
    } else {
        format!("'{}'", shown.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

/// Python `_plain_shell_word`.
pub fn plain_shell_word(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && check_run_env_pairs([(name, "")]).is_ok()
}

/// Python `run_env_save_warning`: the save-time warning for names a run
/// would refuse; `None` when none of the names warns.
pub fn run_env_save_warning<'a, I: IntoIterator<Item = &'a str>>(names: I) -> Option<String> {
    let mut warned: Vec<&str> = Vec::new();
    for name in names {
        if reserved_run_env_name(name) && !warned.contains(&name) {
            warned.push(name);
        }
    }
    let first = *warned.first()?;
    let advice = {
        let candidate = format!("MY_{}", first.to_uppercase());
        if !reserved_run_env_name(&candidate)
            && check_run_env_pairs([(candidate.as_str(), "")]).is_ok()
        {
            format!(
                "save it under another name, for example {}.",
                shown_run_env_name(&candidate)
            )
        } else {
            "save it under a plain name of letters, digits and underscores.".to_owned()
        }
    };
    if warned.len() == 1 {
        let shown = shown_run_env_name(first);
        return Some(format!(
            "kv saved {shown}, but will not hand it to a program run through kv: programs \
             read {shown} when they start. To pass it to a run, {advice}"
        ));
    }
    let listed = warned
        .iter()
        .map(|name| py_repr(&shown_run_env_name(name)))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "kv saved {listed}, but will not hand them to a program run through kv: programs read \
         these names when they start. To pass one to a run, {advice}"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEnvError {
    /// Python `ReservedRunEnvNameError`.
    ReservedName { names: Vec<String> },
    /// Python `RunEnvInjectionError`.
    Injection { secret_name: String, why: String },
    /// Python `SealedArgsUnavailableError`.
    SealedArgsUnavailable,
    /// Python `ArgsDescriptorWriteError`: the system's own message.
    ArgsDescriptorWrite(String),
}

impl fmt::Display for RunEnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedName { names } => {
                let listed = names
                    .iter()
                    .map(|name| py_repr(&shown_run_env_name(name)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let first = names.first().map(String::as_str).unwrap_or("");
                let advice = if plain_shell_word(first) {
                    format!(
                        "`kv set <NEW_NAME>` stores the same value under a new name, then `kv rm \
                         {first}` removes the old name."
                    )
                } else {
                    "store the same value under a new name, then remove the old one.".to_owned()
                };
                write!(
                    f,
                    "kv will not hand a secret to a program under the name {listed}: that name \
                     changes how programs start — a program, its interpreter, its loader or its \
                     shell reads it before the program runs. Rename the secret and ask again: \
                     {advice}"
                )
            }
            Self::Injection { secret_name, why } => write!(
                f,
                "kv will not hand the secret {} to a program: {why}. Rename the secret or store a \
                 different value and ask again: `kv set <NAME>` stores a value, `kv rm <NAME>` \
                 removes the old name.",
                py_repr(&shown_run_env_name(secret_name))
            ),
            Self::SealedArgsUnavailable => f.write_str(
                "blocked for security: this system cannot hand secrets to a sandboxed run \
                 through a sealed descriptor",
            ),
            Self::ArgsDescriptorWrite(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RunEnvError {}

/// Python `build_run_env`: the inherited environment without secret-looking
/// names, PATH reduced to absolute entries, then the selected secrets.
/// `base_env` is the inherited environment (Python reads `os.environ`).
pub fn build_run_env<'a, B, S>(
    secrets: S,
    base_env: B,
) -> Result<BTreeMap<String, String>, RunEnvError>
where
    B: IntoIterator<Item = (&'a str, &'a str)>,
    S: IntoIterator<Item = (&'a str, &'a str)> + Clone,
{
    let mut env: BTreeMap<String, String> = base_env
        .into_iter()
        .filter(|(name, _)| !looks_sensitive_env_name(name))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let path_names: Vec<String> = env
        .keys()
        .filter(|name| upper(name) == "PATH")
        .cloned()
        .collect();
    for name in path_names {
        let kept = env[&name]
            .split(':')
            .filter(|entry| entry.starts_with('/'))
            .collect::<Vec<_>>()
            .join(":");
        env.insert(
            name,
            if kept.is_empty() {
                ABSOLUTE_DEFAULT_PATH.to_owned()
            } else {
                kept
            },
        );
    }
    let mut blocked: Vec<String> = secrets
        .clone()
        .into_iter()
        .filter(|(name, _)| reserved_run_env_name(name))
        .map(|(name, _)| name.to_owned())
        .collect();
    if !blocked.is_empty() {
        blocked.sort();
        return Err(RunEnvError::ReservedName { names: blocked });
    }
    for (name, value) in secrets {
        env.insert(name.to_owned(), value.to_owned());
    }
    Ok(env)
}

/// Python `_check_run_env_pairs`: every pair must be one `--setenv` operand pair.
pub fn check_run_env_pairs<'a, I: IntoIterator<Item = (&'a str, &'a str)>>(
    env: I,
) -> Result<(), RunEnvError> {
    for (name, value) in env {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(RunEnvError::Injection {
                secret_name: name.to_owned(),
                why: "its name cannot be an environment name".to_owned(),
            });
        }
        if value.contains('\0') {
            return Err(RunEnvError::Injection {
                secret_name: name.to_owned(),
                why: "its value carries a NUL byte, which no environment entry can hold".to_owned(),
            });
        }
    }
    Ok(())
}

/// Python `expected_run_env_args`: the `--setenv NAME VALUE` triples, in order.
pub fn expected_run_env_args<'a, I: IntoIterator<Item = (&'a str, &'a str)>>(
    env: I,
) -> Vec<String> {
    let mut args = Vec::new();
    for (name, value) in env {
        args.push("--setenv".to_owned());
        args.push(name.to_owned());
        args.push(value.to_owned());
    }
    args
}

/// The NUL-terminated payload the sealed descriptor carries.
pub fn encode_args_bytes(args: &[String]) -> Vec<u8> {
    let mut data = Vec::new();
    for arg in args {
        data.extend_from_slice(arg.as_bytes());
        data.push(0);
    }
    data
}

/// Python `decode_args_bytes`: one NUL ends each argument; a payload without
/// its final separator is truncated and refused.
pub fn decode_args_bytes(data: &[u8]) -> Result<Vec<String>, String> {
    let Some(body) = data.strip_suffix(b"\0") else {
        return Err("the args descriptor's payload does not end with its separator".to_owned());
    };
    body.split(|b| *b == 0)
        .map(|part| {
            std::str::from_utf8(part)
                .map(str::to_owned)
                .map_err(|_| "the args descriptor's payload is not UTF-8".to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_names_follow_python_rules() {
        assert!(reserved_run_env_name("path"));
        assert!(reserved_run_env_name("LD_PRELOAD"));
        assert!(reserved_run_env_name("CARGO_REGISTRIES_X_INDEX"));
        assert!(!reserved_run_env_name("CARGO_REGISTRIES_MY-REG_TOKEN"));
        assert!(!reserved_run_env_name("NODE_AUTH_TOKEN"));
        assert!(!reserved_run_env_name("DATABASE_URL"));
        assert!(looks_sensitive_env_name("my_api_key"));
        assert!(!looks_sensitive_env_name("HOME"));
    }

    #[test]
    fn run_env_filters_and_fixes_path() {
        let base = [
            ("PATH", ".:/usr/bin:bin:/bin"),
            ("AWS_SECRET", "x"),
            ("TERM", "xterm"),
        ];
        let env = build_run_env([("DATABASE_URL", "pg://")], base).unwrap();
        assert_eq!(env["PATH"], "/usr/bin:/bin");
        assert!(!env.contains_key("AWS_SECRET"));
        assert_eq!(env["DATABASE_URL"], "pg://");
        let err = build_run_env([("PYTHONPATH", "x"), ("HOME", "y")], base).unwrap_err();
        assert!(err.to_string().contains("'HOME', 'PYTHONPATH'"), "{err}");
        assert!(err.to_string().contains("`kv rm HOME`"));
        let empty = build_run_env([], [("PATH", "rel")]).unwrap();
        assert_eq!(empty["PATH"], ABSOLUTE_DEFAULT_PATH);
    }

    #[test]
    fn args_payload_round_trips_and_refuses_truncation() {
        let args = expected_run_env_args([("A", "1"), ("B", "")]);
        assert_eq!(args, ["--setenv", "A", "1", "--setenv", "B", ""]);
        let data = encode_args_bytes(&args);
        assert_eq!(decode_args_bytes(&data).unwrap(), args);
        assert!(decode_args_bytes(b"--setenv\0A\x001").is_err());
        assert!(check_run_env_pairs([("A=B", "x")]).is_err());
        assert!(check_run_env_pairs([("A", "x\0y")]).is_err());
    }

    #[test]
    fn save_warning_wording() {
        let one = run_env_save_warning(["PATH"]).unwrap();
        assert!(
            one.starts_with("kv saved PATH, but will not hand it"),
            "{one}"
        );
        assert!(one.ends_with("for example MY_PATH."), "{one}");
        assert!(run_env_save_warning(["DATABASE_URL"]).is_none());
        let two = run_env_save_warning(["HOME", "LD_X", "HOME"]).unwrap();
        assert!(two.starts_with("kv saved 'HOME', 'LD_X', but"), "{two}");
    }
}
