//! The bubblewrap command line (Python `kv/sandbox.py`: `_BWRAP_OPTIONS`,
//! `_emit_bwrap_option`, `wrap_argv`, `launch_facts`, the sandbox refusals).
//! Everything that reads the host goes through [`SandboxHost`], so the
//! builder is pure and the parity probes can fix what the host says.

use std::collections::BTreeMap;
use std::fmt;

use crate::paths::{is_abs, normpath, paths_overlap, resolve};
use crate::runenv::decode_args_bytes;

pub const PRIVATE_TMP: &str = "/tmp";
pub const TEMP_ENV_NAMES: &[&str] = &["TMPDIR", "TEMP", "TMP"];
pub const RUN_UV_CACHE_NAME: &str = "kv-run-uv-cache";
const PATH_MAX_BYTES: usize = 4096;
const NAME_MAX_BYTES: usize = 255;

pub const BWRAP_CANDIDATES: &[&str] = &[
    "/usr/bin/bwrap",
    "/bin/bwrap",
    "/usr/local/bin/bwrap",
    "/usr/sbin/bwrap",
    "/sbin/bwrap",
];
/// Python `BWRAP_PROBE_ARGV[1:]`.
pub const BWRAP_PROBE_TAIL: &[&str] = &[
    "--ro-bind",
    "/",
    "/",
    "--tmpfs",
    "/tmp",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--unshare-net",
    "--unshare-pid",
    "true",
];

pub const SENSITIVE_HOME_DIRS: &[&str] = &[
    ".aws",
    ".azure",
    ".claude",
    ".codex",
    ".config/gcloud",
    ".config/gh",
    ".cursor",
    ".docker",
    ".gnupg",
    ".kube",
    ".local/share/keyrings",
    ".password-store",
    ".ssh",
];
pub const SENSITIVE_HOME_FILES: &[&str] = &[
    ".curlrc",
    ".git-credentials",
    ".gitconfig",
    ".my.cnf",
    ".netrc",
    ".npmrc",
    ".pgpass",
    ".pypirc",
    ".wgetrc",
];

/// Python `_BWRAP_OPTIONS`: each option kv writes with, per operand, whether
/// it must be an absolute path.
pub fn option_shape(option: &str) -> Option<&'static [bool]> {
    Some(match option {
        "--ro-bind" | "--bind" => &[true, true],
        "--tmpfs" | "--dev" | "--proc" | "--dir" => &[true],
        "--setenv" => &[false, false],
        "--args" => &[false],
        "--unshare-pid" | "--die-with-parent" | "--unshare-net" => &[],
        _ => return None,
    })
}

/// A `kv_run` refusal split into fixed wording and dynamic fields
/// (Python `RunRefusalError(*refusal_parts)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRefusal {
    pub parts: Vec<(String, bool)>,
}

impl RunRefusal {
    pub fn fixed(text: impl Into<String>) -> Self {
        Self {
            parts: vec![(text.into(), false)],
        }
    }

    pub fn message(&self) -> String {
        self.parts.iter().map(|(text, _)| text.as_str()).collect()
    }
}

impl fmt::Display for RunRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for RunRefusal {}

/// Python `_emit_bwrap_option`: the only way an option reaches the wrapper.
pub fn emit_bwrap_option(option: &str, operands: &[&str]) -> Result<Vec<String>, RunRefusal> {
    let Some(shape) = option_shape(option) else {
        return Err(RunRefusal::fixed(format!(
            "blocked for security: {option} is not a bubblewrap option kv writes"
        )));
    };
    if operands.len() != shape.len() {
        return Err(RunRefusal::fixed(format!(
            "blocked for security: {option} takes {} operand(s), not {}",
            shape.len(),
            operands.len()
        )));
    }
    for (operand, must_be_abs) in operands.iter().zip(shape) {
        if *must_be_abs && !is_abs(operand) {
            return Err(RunRefusal::fixed(format!(
                "blocked for security: {option} operand <operand withheld> is not the absolute \
                 path the table requires"
            )));
        }
    }
    let mut out = vec![option.to_owned()];
    out.extend(operands.iter().map(|s| (*s).to_owned()));
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    Bwrap,
    Unshare,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }
}

/// Which kv process reads `KV_RUN_ALLOW_WEAK_SANDBOX` (Python `weak_flag_reader`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WeakFlagReader {
    #[default]
    Service,
    Mcp,
}

impl WeakFlagReader {
    fn where_to_set(self) -> &'static str {
        match self {
            Self::Service => {
                "set KV_RUN_ALLOW_WEAK_SANDBOX=1 in a terminal, then restart kv's service from \
                 that terminal: kv lock, then kv unlock. The service takes the setting only when \
                 it starts, so setting it where you type kv run does not reach a service that is \
                 already running."
            }
            Self::Mcp => {
                "set KV_RUN_ALLOW_WEAK_SANDBOX=1 in your editor's settings for the kv MCP server, \
                 then restart that server from your editor. The server takes the setting only \
                 when it starts."
            }
        }
    }
}

/// What the host offers: probed once, then read by the pure builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxHost {
    pub method: Isolation,
    /// The trusted absolute bubblewrap (Python `bwrap_path()`), if any.
    pub bwrap: Option<String>,
    pub platform: Platform,
    /// The inherited environment (only `TMPDIR`/`TEMP`/`TMP`/`UV_CACHE_DIR`
    /// and `KV_RUN_ALLOW_WEAK_SANDBOX` are read).
    pub environ: BTreeMap<String, String>,
    pub home: String,
    pub kv_dir: String,
    pub cwd: String,
}

impl SandboxHost {
    pub fn allow_weak_sandbox(&self) -> bool {
        matches!(
            self.environ
                .get("KV_RUN_ALLOW_WEAK_SANDBOX")
                .map(|v| v.trim().to_lowercase())
                .as_deref(),
            Some("1" | "true" | "yes" | "on")
        )
    }

    fn env(&self, name: &str) -> Option<&str> {
        self.environ.get(name).map(String::as_str)
    }
}

const SECRET_RUN_SANDBOX_ERROR: &str = "blocked for security: a run that receives secrets or a capability token needs bubblewrap (bwrap) filesystem and network sandboxing, which this host does not provide; KV_RUN_ALLOW_WEAK_SANDBOX does not apply to such runs. On Linux, install bubblewrap from the system's packages (a root-owned install such as /usr/bin/bwrap; a copy in a user-owned folder is not used). Sandboxes for macOS and Windows are planned.";
const SECRET_RUN_SANDBOX_ERROR_OFF_LINUX: &str = "blocked for security: a run that receives secrets or a capability token needs bubblewrap (bwrap) filesystem and network sandboxing, which this system does not provide; KV_RUN_ALLOW_WEAK_SANDBOX does not apply to such runs. Running a program with a secret is not available on this system in this version. Sandboxes for macOS and Windows are planned.";
const SECRET_RUN_SANDBOX_ERROR_MACOS: &str = "blocked for security: a run that receives secrets or a capability token needs bubblewrap (bwrap) filesystem and network sandboxing, which is Linux-only; kv has no sandbox for macOS in this version, and KV_RUN_ALLOW_WEAK_SANDBOX does not apply to such runs. Running a program with a secret is not available on this system in this version. Sandboxes for macOS and Windows are planned.\nWhat works on macOS: your stored secrets (kv set, kv get, kv ls), the editor hook (kv setup claude-code), and brokered calls (kv_api; kv_query and kv_ssh are parked on passphrase-protected vaults in this release), where kv uses the secret for the call and returns only the result.";

/// Python `_secret_run_sandbox_error_text`.
pub fn secret_run_sandbox_error_text(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => SECRET_RUN_SANDBOX_ERROR,
        Platform::MacOs => SECRET_RUN_SANDBOX_ERROR_MACOS,
        Platform::Other => SECRET_RUN_SANDBOX_ERROR_OFF_LINUX,
    }
}

/// Python `secret_run_sandbox_error`: `None` when secret-bearing runs can start.
pub fn secret_run_sandbox_error(host: &SandboxHost) -> Option<&'static str> {
    if host.method == Isolation::Bwrap && host.bwrap.is_some() {
        return None;
    }
    Some(secret_run_sandbox_error_text(host.platform))
}

/// Python `_strong_sandbox_error`.
pub fn strong_sandbox_error(
    method: Isolation,
    platform: Platform,
    reader: WeakFlagReader,
) -> String {
    let where_to_set = reader.where_to_set();
    if platform == Platform::MacOs {
        return format!(
            "blocked for safety: kv cannot put a program in a sandbox on macOS in this version, \
             so kv run is refused.\nA run without secrets can be allowed without any sandbox: \
             {where_to_set} The program then runs like any other program of yours, with access \
             to all your files.\nA run that receives secrets is always refused on macOS."
        );
    }
    if method == Isolation::Unshare {
        return format!(
            "blocked for security: kv_run requires bubblewrap (bwrap) for filesystem sandboxing. \
             Network-only isolation via unshare is not enough because the subprocess could still \
             read .secrets/ and ~/.kv. Install bubblewrap, or set KV_RUN_ALLOW_WEAK_SANDBOX=1 to \
             let a run without secrets go ahead without any sandbox (the program then runs with \
             access to all your files and the network) (a run that receives secrets always needs \
             bubblewrap). To allow it, {where_to_set}"
        );
    }
    format!(
        "blocked for security: kv_run requires bubblewrap (bwrap) for filesystem sandboxing. No \
         supported sandbox is available on this host. Install bubblewrap, or set \
         KV_RUN_ALLOW_WEAK_SANDBOX=1 to let a run without secrets go ahead without any sandbox \
         (the program then runs with access to all your files and the network) (a run that \
         receives secrets always needs bubblewrap). To allow it, {where_to_set}"
    )
}

fn is_dir(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

fn is_file(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

fn join(base: &str, rel: &str) -> String {
    format!("{}/{rel}", base.trim_end_matches('/'))
}

/// Python `_bwrap_home_credential_hides`.
pub fn home_credential_hides(home: &str, cwd: &str) -> Result<Vec<String>, RunRefusal> {
    let home = resolve(home)
        .map_err(|_| RunRefusal::fixed("blocked for security: sandbox paths must be absolute"))?;
    let cwd = resolve(cwd)
        .map_err(|_| RunRefusal::fixed("blocked for security: sandbox paths must be absolute"))?;
    let mut args = Vec::new();
    let mut seen = Vec::new();
    for rel in SENSITIVE_HOME_DIRS {
        let path = join(&home, rel);
        if seen.contains(&path) || !is_dir(&path) || paths_overlap(&path, &cwd, false) {
            continue;
        }
        args.extend(emit_bwrap_option("--tmpfs", &[&path])?);
        seen.push(path);
    }
    for rel in SENSITIVE_HOME_FILES {
        let path = join(&home, rel);
        if seen.contains(&path) || !is_file(&path) || paths_overlap(&path, &cwd, false) {
            continue;
        }
        args.extend(emit_bwrap_option("--ro-bind", &["/dev/null", &path])?);
        seen.push(path);
    }
    Ok(args)
}

/// Python `_bwrap_kv_runtime_hides`: hide `~/.kv` except the daemon sockets.
pub fn kv_runtime_hides(kv_dir: &str) -> Result<Vec<String>, RunRefusal> {
    let Ok(kv_dir) = resolve(kv_dir) else {
        return Ok(Vec::new());
    };
    if !is_dir(&kv_dir) {
        return Ok(Vec::new());
    }
    let Ok(entries) = std::fs::read_dir(&kv_dir) else {
        return emit_bwrap_option("--tmpfs", &[&kv_dir]);
    };
    // Directory order, as Python's `os.listdir` reads it.
    let names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    let mut args = Vec::new();
    for name in names {
        let path = join(&kv_dir, &name);
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let kind = meta.file_type();
        #[cfg(unix)]
        let is_socket = {
            use std::os::unix::fs::FileTypeExt;
            kind.is_socket()
        };
        #[cfg(not(unix))]
        let is_socket = false;
        if is_socket && name.starts_with("agent-") && name.ends_with(".sock") {
            continue;
        }
        if kind.is_dir() {
            args.extend(emit_bwrap_option("--tmpfs", &[&path])?);
        } else if kind.is_file() {
            args.extend(emit_bwrap_option("--ro-bind", &["/dev/null", &path])?);
        } else {
            return emit_bwrap_option("--tmpfs", &[&kv_dir]);
        }
    }
    Ok(args)
}

/// Python `_can_use_private_tmp`.
pub fn can_use_private_tmp(cwd: &str) -> bool {
    !paths_overlap(PRIVATE_TMP, cwd, true)
}

fn has_dotdot(value: &str) -> bool {
    value.split('/').any(|part| part == "..")
}

fn strictly_under_private_tmp(path: &str) -> bool {
    path != PRIVATE_TMP
        && crate::paths::commonpath(path, PRIVATE_TMP).as_deref() == Some(PRIVATE_TMP)
}

/// Python `_lexical_private_tmp_folder`.
pub fn lexical_private_tmp_folder(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.is_empty() || !is_abs(value) || has_dotdot(value) {
        return None;
    }
    let folder = format!("/{}", normpath(value).trim_start_matches('/'));
    strictly_under_private_tmp(&folder).then_some(folder)
}

/// Python `_private_tmp_folder_block_reason`.
pub fn private_tmp_folder_block_reason(folder: &str, avoid: &[String]) -> Option<&'static str> {
    if folder.len() >= PATH_MAX_BYTES || folder.split('/').any(|part| part.len() > NAME_MAX_BYTES) {
        return Some("it is longer than the filesystem allows");
    }
    if avoid
        .iter()
        .any(|taken| folder == taken || folder.starts_with(&format!("{taken}/")))
    {
        return Some("it is at or below the place of an approved script under /tmp");
    }
    None
}

/// Python `_temp_var_link_block_reason`.
pub fn temp_var_link_block_reason(value: Option<&str>) -> Option<&'static str> {
    let value = value?;
    if value.is_empty() || !is_abs(value) || has_dotdot(value) {
        return None;
    }
    match resolve(value) {
        Ok(resolved) if strictly_under_private_tmp(&resolved) => Some("it is a link into /tmp"),
        Ok(_) => None,
        Err(_) => Some("kv cannot tell where this link leads"),
    }
}

/// Python `_inherited_private_tmp_dirs`.
pub fn inherited_private_tmp_dirs(host: &SandboxHost, avoid: &[String]) -> Vec<String> {
    let mut folders: Vec<String> = Vec::new();
    for name in TEMP_ENV_NAMES {
        let Some(folder) = lexical_private_tmp_folder(host.env(name)) else {
            continue;
        };
        if folders.contains(&folder) || private_tmp_folder_block_reason(&folder, avoid).is_some() {
            continue;
        }
        folders.push(folder);
    }
    folders
}

/// Python `_unprovidable_inherited_temp_names`: `(name, value, reason)`.
pub fn unprovidable_inherited_temp_names(
    host: &SandboxHost,
    avoid: &[String],
) -> Vec<(String, String, &'static str)> {
    let mut refused = Vec::new();
    let mut folders: Vec<String> = Vec::new();
    for name in TEMP_ENV_NAMES {
        let value = host.env(name);
        if let Some(folder) = lexical_private_tmp_folder(value) {
            if folders.contains(&folder) {
                continue;
            }
            match private_tmp_folder_block_reason(&folder, avoid) {
                None => folders.push(folder),
                Some(reason) => {
                    refused.push(((*name).to_owned(), value.unwrap_or("").to_owned(), reason));
                }
            }
            continue;
        }
        if let Some(reason) = temp_var_link_block_reason(value) {
            refused.push(((*name).to_owned(), value.unwrap_or("").to_owned(), reason));
        }
    }
    refused
}

/// Python `_temp_name_refusal_parts`.
pub fn temp_name_refusal_parts(name: &str, value: &str, reason: &str) -> Vec<(String, bool)> {
    let shown = if value.chars().count() <= 72 {
        value.to_owned()
    } else {
        format!("{}...", value.chars().take(69).collect::<String>())
    };
    vec![
        (format!("{name}="), false),
        (shown, true),
        (
            format!(
                " cannot be provided inside the sandbox ({reason}); set {name} to a folder under \
                 /tmp or unset it, then run again."
            ),
            false,
        ),
    ]
}

/// The run-specific inputs of Python `wrap_argv`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WrapOptions {
    pub network: bool,
    pub secrets_dir: Option<String>,
    pub cwd: Option<String>,
    pub protect_home_credentials: bool,
    pub readonly_file_overlays: Vec<(String, String)>,
    pub private_tmp: bool,
    pub cwd_bind_source: Option<String>,
    pub secrets_injected: bool,
    pub weak_flag_reader: WeakFlagReader,
}

/// Python `wrap_argv`: the full command line that starts `argv` in the sandbox.
pub fn wrap_argv(
    argv: &[String],
    options: &WrapOptions,
    host: &SandboxHost,
) -> Result<Vec<String>, RunRefusal> {
    if let Some(error) = options
        .secrets_injected
        .then(|| secret_run_sandbox_error(host))
        .flatten()
    {
        return Err(RunRefusal::fixed(error));
    }
    let method = host.method;
    if method != Isolation::Bwrap && !host.allow_weak_sandbox() {
        return Err(RunRefusal::fixed(strong_sandbox_error(
            method,
            host.platform,
            options.weak_flag_reader,
        )));
    }
    if method != Isolation::Bwrap && options.private_tmp {
        return Err(RunRefusal::fixed(
            "blocked for security: private temporary output requires bubblewrap (bwrap) \
             filesystem sandboxing.",
        ));
    }
    if method != Isolation::Bwrap && !options.readonly_file_overlays.is_empty() {
        return Err(RunRefusal::fixed(
            "blocked for security: private run artifacts require bubblewrap (bwrap) filesystem \
             sandboxing.",
        ));
    }
    match method {
        Isolation::Bwrap => {
            let Some(program) = host.bwrap.as_deref() else {
                return Err(RunRefusal::fixed(if options.secrets_injected {
                    secret_run_sandbox_error_text(host.platform).to_owned()
                } else {
                    strong_sandbox_error(Isolation::None, host.platform, options.weak_flag_reader)
                }));
            };
            let cwd = options.cwd.clone().unwrap_or_else(|| host.cwd.clone());
            let cwd_bind_source = options
                .cwd_bind_source
                .clone()
                .unwrap_or_else(|| cwd.clone());
            let mut paths: Vec<&str> = vec![&cwd, &cwd_bind_source];
            paths.extend(options.secrets_dir.as_deref());
            for (source, destination) in &options.readonly_file_overlays {
                paths.push(source);
                paths.push(destination);
            }
            if paths.iter().any(|p| !is_abs(p)) {
                return Err(RunRefusal::fixed(
                    "blocked for security: sandbox paths must be absolute",
                ));
            }
            if !is_dir(&cwd_bind_source) {
                return Err(RunRefusal::fixed(
                    "blocked for security: private cwd bind source is missing",
                ));
            }
            let use_private_tmp = options.private_tmp && can_use_private_tmp(&cwd);
            let mut prefix = vec![program.to_owned()];
            prefix.extend(emit_bwrap_option("--ro-bind", &["/", "/"])?);
            if use_private_tmp {
                let overlay_files: Vec<String> = options
                    .readonly_file_overlays
                    .iter()
                    .map(|(_, destination)| destination.clone())
                    .collect();
                if options.secrets_injected {
                    let refused = unprovidable_inherited_temp_names(host, &overlay_files);
                    if !refused.is_empty() {
                        let mut parts = Vec::new();
                        for (name, value, reason) in &refused {
                            if !parts.is_empty() {
                                parts.push((" ".to_owned(), false));
                            }
                            parts.extend(temp_name_refusal_parts(name, value, reason));
                        }
                        return Err(RunRefusal { parts });
                    }
                }
                prefix.extend(emit_bwrap_option("--tmpfs", &[PRIVATE_TMP])?);
                for folder in inherited_private_tmp_dirs(host, &overlay_files) {
                    prefix.extend(emit_bwrap_option("--dir", &[&folder])?);
                }
                if host.env("UV_CACHE_DIR").is_none_or(str::is_empty) {
                    let cache = join(PRIVATE_TMP, RUN_UV_CACHE_NAME);
                    prefix.extend(emit_bwrap_option("--setenv", &["UV_CACHE_DIR", &cache])?);
                }
            } else {
                prefix.extend(emit_bwrap_option("--bind", &[PRIVATE_TMP, PRIVATE_TMP])?);
            }
            prefix.extend(emit_bwrap_option("--bind", &[&cwd_bind_source, &cwd])?);
            if let Some(secrets_dir) = options.secrets_dir.as_deref().filter(|d| is_dir(d)) {
                prefix.extend(emit_bwrap_option("--tmpfs", &[secrets_dir])?);
            }
            for (source, destination) in &options.readonly_file_overlays {
                if !is_file(source) || !is_file(destination) {
                    return Err(RunRefusal::fixed(
                        "blocked for security: private run artifact is missing",
                    ));
                }
                let inside_secrets = options
                    .secrets_dir
                    .as_deref()
                    .is_some_and(|secrets_dir| paths_overlap(destination, secrets_dir, true));
                if inside_secrets {
                    return Err(RunRefusal::fixed(
                        "blocked for security: scripts inside .secrets cannot be exposed to \
                         kv_run",
                    ));
                }
                prefix.extend(emit_bwrap_option("--ro-bind", &[source, destination])?);
            }
            prefix.extend(emit_bwrap_option("--dev", &["/dev"])?);
            prefix.extend(emit_bwrap_option("--proc", &["/proc"])?);
            prefix.extend(emit_bwrap_option("--unshare-pid", &[])?);
            prefix.extend(emit_bwrap_option("--die-with-parent", &[])?);
            prefix.extend(kv_runtime_hides(&host.kv_dir)?);
            if options.protect_home_credentials {
                prefix.extend(home_credential_hides(&host.home, &cwd)?);
            }
            if !options.network {
                prefix.extend(emit_bwrap_option("--unshare-net", &[])?);
            }
            prefix.push("--".to_owned());
            prefix.extend(argv.iter().cloned());
            Ok(prefix)
        }
        Isolation::Unshare if !options.network => {
            let mut out: Vec<String> = ["unshare", "--user", "--net", "--"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
            out.extend(argv.iter().cloned());
            Ok(out)
        }
        _ => Ok(argv.to_vec()),
    }
}

/// Python `_args_option_indexes`: positions of `--args` options before the
/// `--` separator, stepping over each known option's operands.
pub fn args_option_indexes(argv: &[String]) -> Vec<usize> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let token = argv[i].as_str();
        if token == "--" {
            break;
        }
        if token == "--args" {
            found.push(i);
        }
        i += 1 + option_shape(token).map_or(0, <[bool]>::len);
    }
    found
}

/// Python `_wrapper_separator_index`: where the trusted wrapper's `--` sits.
pub fn wrapper_separator_index(argv: &[String], trusted_bwrap: Option<&str>) -> Option<usize> {
    if argv.first().map(String::as_str) != trusted_bwrap.filter(|_| !argv.is_empty()) {
        return None;
    }
    let mut i = 0;
    while i < argv.len() {
        let token = argv[i].as_str();
        if token == "--" {
            return Some(i);
        }
        i += 1 + option_shape(token).map_or(0, <[bool]>::len);
    }
    None
}

/// Python `_effective_launch_argv`. Without `args_fd` every `--args N`
/// (N digits) is replaced by the descriptor's arguments; with it, only
/// kv's own `--args FD` right before the trusted wrapper's `--` may stand.
pub fn effective_launch_argv(
    argv: &[String],
    args_bytes: &[u8],
    args_fd: Option<(i32, &str)>,
) -> Result<Vec<String>, String> {
    let Some((fd, trusted)) = args_fd else {
        let indexes = args_option_indexes(argv);
        let mut merged = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            let is_option = indexes.contains(&i)
                && argv
                    .get(i + 1)
                    .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
            if is_option {
                merged.extend(decode_args_bytes(args_bytes)?);
                i += 2;
            } else {
                merged.push(argv[i].clone());
                i += 1;
            }
        }
        return Ok(merged);
    };
    let sep = wrapper_separator_index(argv, Some(trusted));
    let owned = sep.is_some_and(|sep| {
        sep >= 2 && argv[sep - 2] == "--args" && argv[sep - 1] == fd.to_string()
    });
    let others = args_option_indexes(argv)
        .into_iter()
        .any(|i| Some(i + 2) != sep);
    let payload = decode_args_bytes(args_bytes)?;
    if !owned || others || !args_option_indexes(&payload).is_empty() {
        return Err(
            "blocked for security: an --args option sits outside kv's own position".to_owned(),
        );
    }
    let sep = sep.expect("owned implies a separator");
    let mut merged = argv[..sep - 2].to_vec();
    merged.extend(payload);
    merged.extend(argv[sep..].iter().cloned());
    Ok(merged)
}

/// Python `launch_facts`: `(sandboxed, network)`; `(false, None)` for any
/// command line that is not the trusted bubblewrap read as it reads it.
pub fn launch_facts(
    run_argv: &[String],
    args_bytes: Option<&[u8]>,
    trusted_bwrap: Option<&str>,
) -> (bool, Option<bool>) {
    let mut argv = run_argv.to_vec();
    if !args_option_indexes(&argv).is_empty() {
        let Some(bytes) = args_bytes else {
            return (false, None);
        };
        match effective_launch_argv(&argv, bytes, None) {
            Ok(merged) => argv = merged,
            Err(_) => return (false, None),
        }
    }
    let Some(trusted) = trusted_bwrap else {
        return (false, None);
    };
    if argv.first().map(String::as_str) != Some(trusted) {
        return (false, None);
    }
    let mut i = 1;
    let mut network = true;
    while i < argv.len() {
        let token = argv[i].as_str();
        if token == "--" {
            return if i + 1 < argv.len() {
                (true, Some(network))
            } else {
                (false, None)
            };
        }
        let Some(shape) = option_shape(token) else {
            return (false, None);
        };
        let operands = &argv[i + 1..(i + 1 + shape.len()).min(argv.len())];
        if operands.len() != shape.len()
            || operands
                .iter()
                .zip(shape)
                .any(|(o, must_be_abs)| *must_be_abs && !is_abs(o))
        {
            return (false, None);
        }
        if token == "--unshare-net" {
            network = false;
        }
        i += 1 + shape.len();
    }
    (false, None)
}

/// Python `_trusted_system_path`: the resolved path when it is a root-owned
/// regular file that group and others cannot write, every folder above it
/// root-owned and not group/other writable; else `None`. POSIX only.
#[cfg(unix)]
pub fn trusted_system_path(path: &str) -> Option<String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let real = kv_hook::paths::resolve(path).ok()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_flags())
        .open(&real)
        .ok()?;
    let st = file.metadata().ok()?;
    drop(file);
    if !st.is_file() || st.uid() != 0 || st.mode() & 0o022 != 0 {
        return None;
    }
    let named = std::fs::symlink_metadata(&real).ok()?;
    if (named.dev(), named.ino()) != (st.dev(), st.ino()) {
        return None;
    }
    let mut folder = kv_hook::paths::dirname(&real).to_owned();
    loop {
        let dst = std::fs::symlink_metadata(&folder).ok()?;
        if !dst.is_dir() || dst.uid() != 0 || dst.mode() & 0o022 != 0 {
            return None;
        }
        let parent = kv_hook::paths::dirname(&folder).to_owned();
        if parent == folder {
            return Some(real);
        }
        folder = parent;
    }
}

#[cfg(unix)]
fn libc_flags() -> i32 {
    use rustix::fs::OFlags;
    (OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC).bits() as i32
}

#[cfg(not(unix))]
pub fn trusted_system_path(_path: &str) -> Option<String> {
    None
}

/// Python `bwrap_path`: the first trusted candidate.
pub fn bwrap_path() -> Option<String> {
    BWRAP_CANDIDATES.iter().find_map(|c| trusted_system_path(c))
}

/// Python `_trusted_program`.
pub fn trusted_program(candidates: &[&str]) -> Option<String> {
    candidates.iter().find_map(|c| trusted_system_path(c))
}

/// Python `_probe_isolation`: run the trusted `true` inside each tier.
pub fn probe_isolation(bwrap: Option<&str>) -> Isolation {
    use std::process::{Command, Stdio};
    let Some(payload) = trusted_program(&["/usr/bin/true", "/bin/true"]) else {
        return Isolation::None;
    };
    let run = |program: &str, args: &[&str]| -> bool {
        let mut command = Command::new(program);
        command
            .args(args)
            .arg(&payload)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir("/")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");
        let Ok(mut child) = command.spawn() else {
            return false;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    };
    if let Some(bwrap) = bwrap {
        let tail = &BWRAP_PROBE_TAIL[..BWRAP_PROBE_TAIL.len() - 1];
        if run(bwrap, tail) {
            return Isolation::Bwrap;
        }
    }
    let unshare = trusted_program(&["/usr/bin/unshare", "/bin/unshare"]);
    if unshare.is_some_and(|unshare| run(&unshare, &["--user", "--net"])) {
        return Isolation::Unshare;
    }
    Isolation::None
}

impl SandboxHost {
    /// Probe this host once (Python's module-level caches).
    pub fn detect() -> Self {
        let bwrap = bwrap_path();
        let method = probe_isolation(bwrap.as_deref());
        let environ: BTreeMap<String, String> = std::env::vars().collect();
        let home = kv_hook::paths::home_dir().unwrap_or_else(|| "/".to_owned());
        Self {
            method,
            bwrap,
            platform: Platform::current(),
            kv_dir: join(&home, ".kv"),
            home,
            cwd: kv_hook::paths::getcwd().unwrap_or_else(|_| "/".to_owned()),
            environ,
        }
    }
}

/// Python `inject_run_env`: the run argv that delivers `env` to the target only.
///
/// The pairs are written as NUL-separated `--setenv NAME VALUE` triples into a
/// sealed memfd that only the trusted wrapper inherits; the visible argv gains
/// `--args N` right before the `--` separator that ends the wrapper's own
/// options. Without the trusted wrapper (no separator kv owns) the argv comes
/// back unchanged with nothing moved; whether such a run may receive secrets at
/// all is the launch check's decision (`launch_facts` refuses it). A pair that
/// cannot be one environment operand is refused before any descriptor is made.
/// The caller owns the returned descriptor: it must stay open until the child
/// has started and be closed on every earlier exit.
#[allow(clippy::type_complexity)]
pub fn inject_run_env(
    run_argv: &[String],
    env: &BTreeMap<String, String>,
    trusted_bwrap: Option<&str>,
) -> Result<
    (
        Vec<String>,
        BTreeMap<String, String>,
        Option<crate::sealed::SealedArgsFd>,
    ),
    crate::runenv::RunEnvError,
> {
    let argv = run_argv.to_vec();
    if env.is_empty() {
        return Ok((argv, BTreeMap::new(), None));
    }
    let Some(sep) = wrapper_separator_index(&argv, trusted_bwrap) else {
        return Ok((argv, BTreeMap::new(), None));
    };
    crate::runenv::check_run_env_pairs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))?;
    let fd = crate::sealed::SealedArgsFd::new(&crate::runenv::expected_run_env_args(
        env.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    ))?;
    let Some(number) = fd.raw() else {
        return Err(crate::runenv::RunEnvError::SealedArgsUnavailable);
    };
    let mut launch = argv[..sep].to_vec();
    launch.push("--args".to_owned());
    launch.push(number.to_string());
    launch.extend_from_slice(&argv[sep..]);
    Ok((launch, env.clone(), Some(fd)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(method: Isolation) -> SandboxHost {
        SandboxHost {
            method,
            bwrap: Some("/usr/bin/bwrap".to_owned()),
            platform: Platform::Linux,
            environ: BTreeMap::new(),
            home: "/nonexistent-home".to_owned(),
            kv_dir: "/nonexistent-home/.kv".to_owned(),
            cwd: "/".to_owned(),
        }
    }

    #[test]
    fn option_table_is_enforced() {
        assert!(emit_bwrap_option("--chdir", &["/x"]).is_err());
        assert!(emit_bwrap_option("--tmpfs", &["rel"]).is_err());
        assert!(emit_bwrap_option("--tmpfs", &[]).is_err());
        assert_eq!(
            emit_bwrap_option("--setenv", &["A", "b"]).unwrap(),
            ["--setenv", "A", "b"]
        );
    }

    #[test]
    fn wrap_and_facts_round_trip() {
        let argv = vec!["python3".to_owned(), "app.py".to_owned()];
        let options = WrapOptions {
            cwd: Some("/".to_owned()),
            ..WrapOptions::default()
        };
        let wrapped = wrap_argv(&argv, &options, &host(Isolation::Bwrap)).unwrap();
        assert_eq!(wrapped[0], "/usr/bin/bwrap");
        assert_eq!(&wrapped[1..4], ["--ro-bind", "/", "/"]);
        assert!(wrapped.contains(&"--unshare-net".to_owned()));
        assert_eq!(
            launch_facts(&wrapped, None, Some("/usr/bin/bwrap")),
            (true, Some(false))
        );
        assert_eq!(
            launch_facts(&wrapped, None, Some("/bin/bwrap")),
            (false, None)
        );
        assert_eq!(
            launch_facts(&argv, None, Some("/usr/bin/bwrap")),
            (false, None)
        );
    }

    #[test]
    fn weak_hosts_refuse_without_the_flag() {
        let argv = vec!["ls".to_owned()];
        let err = wrap_argv(&argv, &WrapOptions::default(), &host(Isolation::None)).unwrap_err();
        assert!(
            err.message()
                .starts_with("blocked for security: kv_run requires bubblewrap")
        );
        let mut weak = host(Isolation::Unshare);
        weak.environ
            .insert("KV_RUN_ALLOW_WEAK_SANDBOX".into(), "Yes".into());
        assert_eq!(
            wrap_argv(&argv, &WrapOptions::default(), &weak).unwrap(),
            ["unshare", "--user", "--net", "--", "ls"]
        );
        let secret = WrapOptions {
            secrets_injected: true,
            ..WrapOptions::default()
        };
        assert_eq!(
            wrap_argv(&argv, &secret, &weak).unwrap_err().message(),
            SECRET_RUN_SANDBOX_ERROR
        );
    }

    #[test]
    fn temp_folder_rules() {
        assert_eq!(
            lexical_private_tmp_folder(Some("/tmp/work/")).as_deref(),
            Some("/tmp/work")
        );
        assert!(lexical_private_tmp_folder(Some("/tmp")).is_none());
        assert!(lexical_private_tmp_folder(Some("/tmp/../etc")).is_none());
        assert!(lexical_private_tmp_folder(Some("/tmpx/a")).is_none());
        let avoid = vec!["/tmp/run".to_owned()];
        assert!(private_tmp_folder_block_reason("/tmp/run/x", &avoid).is_some());
        assert!(private_tmp_folder_block_reason("/tmp/runx", &avoid).is_none());
        let parts = temp_name_refusal_parts("TMPDIR", &"a".repeat(80), "why");
        assert_eq!(parts[1].0.len(), 72);
    }
}
