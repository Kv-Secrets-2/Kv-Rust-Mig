//! Path resolution and the protected-path rules of Python `kv/hook.py`
//! (Layer 1). Every function that cannot tell where a path points answers
//! as if it were protected: an unresolvable path is refused, never allowed.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

use crate::Denied;

pub const SECRETS_FOLDER: &str = ".secrets";
pub const SEP: char = '/';

pub const PROTECTED_VAULT_DIRS: &[&str] = &["drawers", "migration-backups"];
pub const APPROVAL_STATE_FILES: &[&str] = &[
    "approval_signing_key",
    "run_grants.json",
    "approval_requests.json",
    "policy_requests.json",
];
pub const PROTECTED_VAULT_FILES: &[&str] = &[
    "key",
    "config.json",
    "config-authority",
    "vault-marker",
    "storage.lock",
    "config.lock",
    "key-config.pending",
    "approval_signing_key",
    "run_grants.json",
    "approval_requests.json",
    "policy_requests.json",
];
pub const PROTECTED_VAULT_SUFFIXES: &[&str] = &[".enc", ".kvi", ".kvs"];
pub const HOOK_CONFIG_NAMES: &[&str] = &["settings.local.json", "settings.json"];
pub const MCP_CONFIG_HOME_FILES: &[&str] = &[
    ".claude.json",
    ".codex/config.toml",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".codeium/windsurf/mcp_config.json",
    ".openclaw/openclaw.json",
];
const MCP_CONFIG_PROJECT_FILES: &[&str] = &[".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"];

fn private_write_temp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A\.kv-write-[0-9a-f]{32}\.tmp\z").expect("regex"))
}

/// Python `_PROTECTED_FILE_COMMAND_PATTERNS`, applied to the casefolded command.
pub fn protected_file_command_patterns() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        [
            r"mcp\.json",
            r"mcp_config\.json",
            r"\.claude\.json",
            r"openclaw\.json",
            r"(?s)\.codex\b.*config\.toml",
            r"(?s)\.claude\b.*settings(\.local)?\.json",
        ]
        .iter()
        .map(|pattern| Regex::new(pattern).expect("regex"))
        .collect()
    })
}

/// Python's `str.casefold()` (full case folding).
pub fn casefold(text: &str) -> String {
    caseless::default_case_fold_str(text)
}

// ---------------------------------------------------------------------------
// errno helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn errno_of(error: &io::Error, code: rustix::io::Errno) -> bool {
    error.raw_os_error() == Some(code.raw_os_error())
}

pub fn is_not_found(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}

pub fn is_not_dir(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        errno_of(error, rustix::io::Errno::NOTDIR)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

pub fn is_loop(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        errno_of(error, rustix::io::Errno::LOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

pub fn is_access_denied(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        errno_of(error, rustix::io::Errno::ACCESS)
    }
    #[cfg(not(unix))]
    {
        error.kind() == io::ErrorKind::PermissionDenied
    }
}

pub fn is_name_too_long(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        errno_of(error, rustix::io::Errno::NAMETOOLONG)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

/// Python `_TOLERATED_TARGET_ERRNOS`: a regular file in the way or a link loop.
pub fn is_tolerated_target_error(error: &io::Error) -> bool {
    is_not_dir(error) || is_loop(error)
}

/// `os.strerror(errno)` or the error's own text, as Python's `exc.strerror`.
pub fn strerror(error: &io::Error) -> String {
    #[cfg(unix)]
    if let Some(code) = error.raw_os_error() {
        return rustix::io::Errno::from_raw_os_error(code).to_string();
    }
    error.to_string()
}

fn err(kind: io::ErrorKind, message: &str) -> io::Error {
    io::Error::new(kind, message.to_owned())
}

fn os_error(code: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(code.raw_os_error())
}

// ---------------------------------------------------------------------------
// lexical helpers (os.path on POSIX)
// ---------------------------------------------------------------------------

/// `os.path.dirname`.
pub fn dirname(path: &str) -> &str {
    match path.rfind(SEP) {
        None => "",
        Some(index) => {
            let head = &path[..index + 1];
            if head.chars().all(|c| c == SEP) {
                head
            } else {
                head.trim_end_matches(SEP)
            }
        }
    }
}

/// `os.path.basename`.
pub fn basename(path: &str) -> &str {
    match path.rfind(SEP) {
        None => path,
        Some(index) => &path[index + 1..],
    }
}

/// `os.path.join(a, b)` for one component.
pub fn join(a: &str, b: &str) -> String {
    if b.starts_with(SEP) {
        return b.to_owned();
    }
    if a.is_empty() || a.ends_with(SEP) {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

pub fn is_abs(path: &str) -> bool {
    path.starts_with(SEP)
}

/// `posixpath.normpath`.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let initial_slashes = if path.starts_with(SEP) {
        if path.starts_with("//") && !path.starts_with("///") {
            2
        } else {
            1
        }
    } else {
        0
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split(SEP) {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".."
            || (initial_slashes == 0 && comps.is_empty())
            || comps.last().is_some_and(|last| *last == "..")
        {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let mut out = SEP.to_string().repeat(initial_slashes);
    out.push_str(&comps.join("/"));
    if out.is_empty() { ".".to_owned() } else { out }
}

pub fn getcwd() -> io::Result<String> {
    let cwd = std::env::current_dir()?;
    path_to_string(&cwd)
}

pub fn path_to_string(path: &Path) -> io::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| err(io::ErrorKind::InvalidData, "path is not valid UTF-8"))
}

/// `os.path.abspath`.
pub fn abspath(path: &str) -> io::Result<String> {
    if is_abs(path) {
        return Ok(normpath(path));
    }
    Ok(normpath(&join(&getcwd()?, path)))
}

pub fn home_dir() -> Option<String> {
    std::env::var("HOME").ok().filter(|home| !home.is_empty())
}

/// `os.path.expanduser`: `~` and `~/...` from HOME; `~user` is looked up
/// through the password database on Unix. Errors (NUL, unknown user) raise
/// like Python's.
pub fn expanduser(path: &str) -> io::Result<String> {
    if !path.starts_with('~') {
        return Ok(path.to_owned());
    }
    if path.contains('\0') {
        return Err(err(io::ErrorKind::InvalidInput, "embedded null byte"));
    }
    let end = path.find(SEP).unwrap_or(path.len());
    let user = &path[1..end];
    let home = if user.is_empty() {
        match home_dir() {
            Some(home) => home,
            None => user_home(None)?,
        }
    } else {
        user_home(Some(user))?
    };
    let home = if home.len() > 1 {
        home.trim_end_matches(SEP)
    } else {
        &home
    };
    let rest = &path[end..];
    let expanded = format!("{home}{rest}");
    Ok(if expanded.is_empty() {
        SEP.to_string()
    } else {
        expanded
    })
}

/// `pwd.getpwnam(user).pw_dir` (or the current user's), via `getent`-free
/// parsing of `/etc/passwd`, which is what glibc consults for local users.
fn user_home(user: Option<&str>) -> io::Result<String> {
    #[cfg(unix)]
    {
        let uid = rustix::process::getuid().as_raw();
        let passwd = std::fs::read_to_string("/etc/passwd")?;
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 6 {
                continue;
            }
            let matches = match user {
                Some(name) => fields[0] == name,
                None => fields[2].parse::<u32>().ok() == Some(uid),
            };
            if matches {
                return Ok(fields[5].to_owned());
            }
        }
        Err(err(io::ErrorKind::NotFound, "unknown user"))
    }
    #[cfg(not(unix))]
    {
        let _ = user;
        Err(err(io::ErrorKind::Unsupported, "no password database"))
    }
}

/// Python `_safe_expanduser`: never raises; an unexpandable token is kept.
pub fn safe_expanduser(candidate: &str) -> String {
    expanduser(candidate).unwrap_or_else(|_| candidate.to_owned())
}

// ---------------------------------------------------------------------------
// resolution (kv.structure.resolve)
// ---------------------------------------------------------------------------

/// `kv.structure.resolve`: CPython's `realpath(path, strict=ALLOW_MISSING)`.
/// A missing component is kept as written and the walk goes on; every other
/// error (a file with more path after it, a link loop, no search permission,
/// a too-long name) is returned.
pub fn resolve(path: &str) -> io::Result<String> {
    if path.contains('\0') {
        return Err(err(io::ErrorKind::InvalidInput, "embedded null byte"));
    }
    let mut rest: Vec<Option<String>> = path.split(SEP).rev().map(|p| Some(p.to_owned())).collect();
    let mut part_count = rest.len();
    let mut current = if path.starts_with(SEP) {
        SEP.to_string()
    } else {
        getcwd()?
    };
    let mut seen: Vec<(String, Option<String>)> = Vec::new();
    while part_count > 0 {
        let Some(name) = rest.pop() else { break };
        let Some(name) = name else {
            let link = rest.pop().flatten().unwrap_or_default();
            if let Some(entry) = seen.iter_mut().find(|(path, _)| *path == link) {
                entry.1 = Some(current.clone());
            }
            continue;
        };
        part_count -= 1;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            current = match current.rfind(SEP) {
                Some(0) | None => SEP.to_string(),
                Some(index) => current[..index].to_owned(),
            };
            continue;
        }
        let candidate = if current == "/" {
            format!("/{name}")
        } else {
            format!("{current}/{name}")
        };
        let target = match std::fs::symlink_metadata(&candidate) {
            Ok(meta) => {
                if !meta.file_type().is_symlink() {
                    if part_count > 0 && !meta.is_dir() {
                        return Err(os_error(rustix::io::Errno::NOTDIR));
                    }
                    current = candidate;
                    continue;
                }
                if let Some((_, resolution)) = seen.iter().find(|(path, _)| *path == candidate) {
                    match resolution {
                        None => return Err(os_error(rustix::io::Errno::LOOP)),
                        Some(resolved) => {
                            current = resolved.clone();
                            continue;
                        }
                    }
                }
                match std::fs::read_link(&candidate) {
                    Ok(target) => path_to_string(&target)?,
                    Err(error) if is_not_found(&error) => {
                        current = candidate;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if is_not_found(&error) => {
                current = candidate;
                continue;
            }
            Err(error) => return Err(error),
        };
        if target.starts_with(SEP) {
            current = SEP.to_string();
        }
        seen.push((candidate.clone(), None));
        rest.push(Some(candidate));
        rest.push(None);
        let target_parts: Vec<Option<String>> = target
            .split(SEP)
            .rev()
            .map(|p| Some(p.to_owned()))
            .collect();
        part_count += target_parts.len();
        rest.extend(target_parts);
    }
    Ok(current)
}

/// Python `_resolved(os.path.expanduser(p))`, the pair most checks use.
pub fn resolve_user(path: &str) -> io::Result<String> {
    resolve(&expanduser(path)?)
}

/// `stat.S_ISDIR(os.stat(path).st_mode)`, FileNotFoundError -> Ok(false).
pub fn isdir_strict(path: &str) -> io::Result<bool> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(meta.is_dir()),
        Err(error) if is_not_found(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

// ---------------------------------------------------------------------------
// finding the vault
// ---------------------------------------------------------------------------

fn vault_check_denial(sdir: &str, error: &io::Error) -> String {
    let cause = if is_access_denied(error) {
        let mut blocked = dirname(sdir).to_owned();
        let mut probe = blocked.clone();
        loop {
            let parent = dirname(&probe).to_owned();
            if parent == probe {
                break;
            }
            if !searchable(&parent) {
                blocked = parent.clone();
            }
            probe = parent;
        }
        format!("{blocked} is not searchable (a folder on the path to {sdir})")
    } else if is_loop(error) {
        format!("{sdir} is a looping or broken link")
    } else if is_name_too_long(error) {
        "the working folder's path is too long to check".to_owned()
    } else {
        format!("{} while checking {sdir}", strerror(error))
    };
    format!(
        "[kv-secrets] blocked: cannot check whether a vault folder is here: {cause}. Every tool \
         call stays blocked until this can be checked; start the session from another folder, \
         or fix the cause, then retry."
    )
}

/// `os.access(path, os.X_OK)`.
fn searchable(path: &str) -> bool {
    #[cfg(unix)]
    {
        rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
    }
    #[cfg(not(unix))]
    {
        Path::new(path).exists()
    }
}

/// Python `_find_secrets_dir`: the resolved `.secrets` of the nearest vault
/// project at or above the working folder, `None` when there is none, and a
/// refusal when that cannot be checked.
pub fn find_secrets_dir() -> Result<Option<String>, Denied> {
    let cwd = getcwd().map_err(|error| Denied(vault_check_denial(".secrets", &error)))?;
    let mut path = normpath(&cwd);
    loop {
        let sdir = join(&path, SECRETS_FOLDER);
        match isdir_strict(&sdir) {
            Ok(true) => {
                return resolve(&sdir)
                    .map(Some)
                    .map_err(|error| Denied(vault_check_denial(&sdir, &error)));
            }
            Ok(false) => {}
            Err(error) => return Err(Denied(vault_check_denial(&sdir, &error))),
        }
        let parent = dirname(&path).to_owned();
        if parent == path {
            return Ok(None);
        }
        path = parent;
    }
}

/// Python `_find_secrets_dir_checked`: from `start`; a file in the way or a
/// link loop moves up, any other error is returned.
pub fn find_secrets_dir_checked(start: &str) -> io::Result<Option<String>> {
    let mut path = abspath(start)?;
    loop {
        let sdir = join(&path, SECRETS_FOLDER);
        match std::fs::metadata(&sdir) {
            Ok(meta) if meta.is_dir() => return resolve(&sdir).map(Some),
            Ok(_) => {}
            Err(error) if is_not_found(&error) || is_tolerated_target_error(&error) => {}
            Err(error) => return Err(error),
        }
        let parent = dirname(&path).to_owned();
        if parent == path {
            return Ok(None);
        }
        path = parent;
    }
}

/// Python `_checked_start_folder`.
pub fn checked_start_folder(value: &str) -> io::Result<String> {
    if value.is_empty() || !is_abs(value) || value.contains('\0') {
        return Err(err(io::ErrorKind::InvalidInput, "unusable working folder"));
    }
    if value.split(SEP).any(|part| part == "." || part == "..") {
        return Err(err(
            io::ErrorKind::InvalidInput,
            "working folder has a '.' or '..' component",
        ));
    }
    if !std::fs::metadata(value)?.is_dir() {
        return Err(err(
            io::ErrorKind::InvalidInput,
            "working folder is not a folder",
        ));
    }
    abspath(value)
}

// ---------------------------------------------------------------------------
// protected vault paths
// ---------------------------------------------------------------------------

fn is_protected_vault_path(path: &str, secrets_dir: &str) -> bool {
    let name = basename(path);
    let legacy_base = name.strip_suffix(".tmp").unwrap_or(name);
    if dirname(path) == secrets_dir
        && (PROTECTED_VAULT_FILES.contains(&legacy_base) || private_write_temp_re().is_match(name))
    {
        return true;
    }
    let Some(rel) = path.strip_prefix(&format!("{secrets_dir}/")) else {
        return false;
    };
    let first = rel.split(SEP).next().unwrap_or("");
    if PROTECTED_VAULT_DIRS.contains(&first) {
        return true;
    }
    PROTECTED_VAULT_SUFFIXES
        .iter()
        .any(|suffix| legacy_base.ends_with(suffix))
}

/// Python `_is_protected_path`.
pub fn is_protected_path(file_path: &str, secrets_dir: Option<&str>) -> bool {
    let Some(secrets_dir) = secrets_dir.filter(|dir| !dir.is_empty()) else {
        return false;
    };
    let Ok(expanded) = expanduser(file_path) else {
        return true;
    };
    let (Ok(real), Ok(lexical)) = (resolve(&expanded), abspath(&expanded)) else {
        return true;
    };
    is_protected_vault_path(&real, secrets_dir) || is_protected_vault_path(&lexical, secrets_dir)
}

/// Python `_is_protected_dir_access`.
pub fn is_protected_dir_access(file_path: &str, secrets_dir: Option<&str>) -> bool {
    let Some(secrets_dir) = secrets_dir.filter(|dir| !dir.is_empty()) else {
        return false;
    };
    match resolve_user(file_path) {
        Ok(real) => real == secrets_dir,
        Err(_) => true,
    }
}

fn vault_part(part: &str) -> String {
    casefold(part)
}

fn path_parts(spelling: &str) -> Vec<&str> {
    spelling.split(SEP).collect()
}

/// `kv.structure._names_secrets` plus case-insensitive spellings.
pub fn names_vault_folder(spelling: &str) -> bool {
    path_parts(spelling)
        .iter()
        .any(|part| *part == SECRETS_FOLDER || vault_part(part) == SECRETS_FOLDER)
}

/// Python `_is_vault_gitignore`.
pub fn is_vault_gitignore(spelling: &str) -> bool {
    let written: Vec<&str> = path_parts(spelling)
        .into_iter()
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let parts: Vec<String> = written.iter().map(|p| vault_part(p)).collect();
    let n = parts.len();
    n >= 2
        && !written[n - 1].contains(':')
        && parts[n - 1] == ".gitignore"
        && parts[n - 2] == SECRETS_FOLDER
        && !parts[..n - 2].iter().any(|p| p == SECRETS_FOLDER)
}

/// Python `_through_vault_folder`: `Some(true)` when the spelling or its
/// resolution names a `.secrets` folder, `None` when it cannot be resolved.
pub fn through_vault_folder(path: &str, metadata_ok: bool) -> Option<bool> {
    let expanded = safe_expanduser(path);
    if names_vault_folder(&expanded) && !(metadata_ok && is_vault_gitignore(&expanded)) {
        return Some(true);
    }
    let resolved = resolve(&expanded).ok()?;
    Some(names_vault_folder(&resolved) && !(metadata_ok && is_vault_gitignore(&resolved)))
}

pub fn vault_folder_denial(path: &str) -> String {
    format!(
        "[kv-secrets] blocked: '{path}' passes through a .secrets folder (a kv vault, this \
         project's or another's). Use kv_run or kv_api MCP tools to use secrets safely. (To \
         search text for the folder's name, write it as [.]secrets.)"
    )
}

/// Python `_refuse_through_vault_folder`.
pub fn refuse_through_vault_folder(path: &str, metadata_ok: bool) -> Result<(), Denied> {
    match through_vault_folder(path, metadata_ok) {
        None => Err(Denied(format!(
            "[kv-secrets] blocked: '{path}' could not be resolved, so kv can't tell whether it \
             passes through a .secrets folder. Use kv_run or kv_api MCP tools to use secrets \
             safely."
        ))),
        Some(true) => Err(Denied(vault_folder_denial(path))),
        Some(false) => Ok(()),
    }
}

pub const AGENT_TOKEN_DENIAL: &str = "[kv-secrets] blocked: agent auth token is not readable. \
    The token is used internally by the MCP server.";

/// Python `_refuse_any_vault_or_token`.
pub fn refuse_any_vault_or_token<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<(), Denied> {
    for path in paths {
        refuse_through_vault_folder(path, false)?;
        if is_agent_token(path) {
            return Err(Denied(AGENT_TOKEN_DENIAL.to_owned()));
        }
    }
    Ok(())
}

/// `~/.kv` as Python's `_KV_DIR` (expanded at import).
pub fn kv_dir() -> String {
    join(&safe_expanduser("~"), ".kv")
}

/// Python `_is_agent_token`.
pub fn is_agent_token(file_path: &str) -> bool {
    let (Ok(real), Ok(kv_dir)) = (resolve_user(file_path), resolve(&kv_dir())) else {
        return true;
    };
    dirname(&real) == kv_dir && basename(&real).ends_with(".token")
}

/// Python `_is_hook_config`.
pub fn is_hook_config(file_path: &str) -> bool {
    match resolve_user(file_path) {
        Ok(real) => HOOK_CONFIG_NAMES.contains(&basename(&real)) && real.contains("/.claude/"),
        Err(_) => true,
    }
}

// ---------------------------------------------------------------------------
// MCP configuration files
// ---------------------------------------------------------------------------

fn resolved_set(names: impl IntoIterator<Item = String>) -> io::Result<Vec<String>> {
    let mut found: Vec<String> = Vec::new();
    for name in names {
        match resolve(&name) {
            Ok(real) => {
                if !found.contains(&real) {
                    found.push(real);
                }
            }
            Err(error) if is_tolerated_target_error(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(found)
}

/// Python `_mcp_config_targets`: (project targets, home targets).
pub fn mcp_config_targets(hook_cwd: Option<&str>) -> io::Result<(Vec<String>, Vec<String>)> {
    let mut starts = vec![abspath(&getcwd()?)?];
    if let Some(cwd) = hook_cwd {
        starts.push(checked_start_folder(cwd)?);
    }
    if let Ok(project_dir) = std::env::var("CLAUDE_PROJECT_DIR") {
        starts.push(checked_start_folder(&project_dir)?);
    }
    let mut roots: Vec<String> = Vec::new();
    for start in &starts {
        let mut current = start.clone();
        loop {
            roots.push(current.clone());
            let parent = dirname(&current).to_owned();
            if parent == current {
                break;
            }
            current = parent;
        }
    }
    for start in &starts {
        if let Some(secrets_dir) = find_secrets_dir_checked(start)? {
            roots.push(dirname(&secrets_dir).to_owned());
        }
    }
    let mut unique: Vec<String> = Vec::new();
    for root in roots {
        if !unique.contains(&root) {
            unique.push(root);
        }
    }
    let project = resolved_set(unique.iter().flat_map(|root| {
        MCP_CONFIG_PROJECT_FILES
            .iter()
            .map(move |rel| join(root, rel))
    }))?;
    let home = safe_expanduser("~");
    let home_targets = resolved_set(MCP_CONFIG_HOME_FILES.iter().map(|name| join(&home, name)))?;
    Ok((project, home_targets))
}

#[cfg(unix)]
fn file_identity(path: &str) -> io::Result<Option<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some((meta.dev(), meta.ino()))),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn file_identity(path: &str) -> io::Result<Option<(u64, u64)>> {
    match std::fs::metadata(path) {
        Ok(_) => Err(err(io::ErrorKind::Unsupported, "file identity")),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn creation_key(path: &str) -> io::Result<Option<((u64, u64), String)>> {
    use unicode_normalization::UnicodeNormalization;
    let mut rest: Vec<&str> = Vec::new();
    let mut current = path;
    let identity = loop {
        if let Some(identity) = file_identity(current)? {
            break identity;
        }
        let parent = dirname(current);
        if parent == current {
            return Ok(None);
        }
        rest.push(basename(current));
        current = parent;
    };
    rest.reverse();
    let tail: String = rest.join("/").nfc().collect();
    Ok(Some((identity, casefold(&tail))))
}

fn named_like_mcp_config(path: &str) -> bool {
    let base = basename(path).to_lowercase();
    let folder = basename(dirname(path)).to_lowercase();
    base == ".mcp.json" || (base == "mcp.json" && (folder == ".cursor" || folder == ".vscode"))
}

fn is_mcp_config_inner(file_path: &str, hook_cwd: Option<&str>) -> io::Result<bool> {
    let mut spelled = expanduser(file_path)?;
    if !is_abs(&spelled) {
        spelled = join(&getcwd()?, &spelled);
    }
    let real = resolve(&spelled)?;
    if named_like_mcp_config(&spelled) || named_like_mcp_config(&real) {
        return Ok(true);
    }
    let home = safe_expanduser("~");
    let home_names: Vec<String> = MCP_CONFIG_HOME_FILES
        .iter()
        .map(|name| casefold(&join(&home, name)))
        .collect();
    if home_names.contains(&casefold(&spelled)) || home_names.contains(&casefold(&real)) {
        return Ok(true);
    }
    let (project_targets, home_targets) = mcp_config_targets(hook_cwd)?;
    let real_folded = casefold(&real);
    if project_targets.contains(&real)
        || home_targets
            .iter()
            .any(|target| casefold(target) == real_folded)
    {
        return Ok(true);
    }
    let targets: Vec<&String> = project_targets.iter().chain(home_targets.iter()).collect();
    if let Some(identity) = file_identity(&real)? {
        for target in &targets {
            if file_identity(target)? == Some(identity) {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    let Some(key) = creation_key(&real)? else {
        return Ok(true);
    };
    for target in &targets {
        if creation_key(target)? == Some(key.clone()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Python `_is_mcp_config`: `hook_cwd` is the hook input's `cwd` when present.
pub fn is_mcp_config(file_path: &str, hook_cwd: Option<&str>) -> bool {
    is_mcp_config_inner(file_path, hook_cwd).unwrap_or(true)
}

// ---------------------------------------------------------------------------
// relationships between two paths (resolution errors read as related)
// ---------------------------------------------------------------------------

fn both(path: &str, other: &str) -> Option<(String, String)> {
    Some((resolve_user(path).ok()?, resolve_user(other).ok()?))
}

fn inside(path: &str, parent: &str) -> bool {
    path == parent || path.starts_with(&format!("{parent}/"))
}

/// Python `_is_under_path`.
pub fn is_under_path(path: &str, parent: &str) -> bool {
    both(path, parent).is_none_or(|(p, q)| inside(&p, &q))
}

/// Python `_is_path_or_ancestor`.
pub fn is_path_or_ancestor(path: &str, target: &str) -> bool {
    both(path, target).is_none_or(|(p, t)| inside(&t, &p))
}

/// Python `_path_touches`.
pub fn path_touches(path: &str, target_dir: &str) -> bool {
    both(path, target_dir).is_none_or(|(p, t)| inside(&p, &t) || inside(&t, &p))
}

/// Python `_path_is_or_inside`.
pub fn path_is_or_inside(path: &str, target_dir: &str) -> bool {
    both(path, target_dir).is_none_or(|(p, t)| inside(&p, &t))
}

pub fn path_buf(path: &str) -> PathBuf {
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct TestDir(pub PathBuf);

    impl TestDir {
        pub fn new(tag: &str) -> TestDir {
            let path = std::env::temp_dir().join(format!(
                "kv-hook-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::UNIX_EPOCH
                    .elapsed()
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            TestDir(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn lexical_helpers_match_posixpath() {
        assert_eq!(dirname("/a/b/c"), "/a/b");
        assert_eq!(dirname("/a"), "/");
        assert_eq!(dirname("a"), "");
        assert_eq!(dirname("/"), "/");
        assert_eq!(basename("/a/b/"), "");
        assert_eq!(join("/a", "b"), "/a/b");
        assert_eq!(join("/a/", "b"), "/a/b");
        assert_eq!(join("/a", "/b"), "/b");
        assert_eq!(normpath("/a/./b/../c//"), "/a/c");
        assert_eq!(normpath("../a"), "../a");
        assert_eq!(normpath("//a"), "//a");
        assert_eq!(normpath(""), ".");
    }

    #[test]
    fn resolve_keeps_missing_components_and_follows_links() {
        let dir = TestDir::new("resolve");
        let root = dir.0.to_str().unwrap().to_owned();
        let real_root = resolve(&root).unwrap();
        std::fs::create_dir(format!("{root}/d")).unwrap();
        std::fs::write(format!("{root}/d/f"), b"x").unwrap();
        std::os::unix::fs::symlink("d", format!("{root}/l")).unwrap();
        std::os::unix::fs::symlink("loop2", format!("{root}/loop1")).unwrap();
        std::os::unix::fs::symlink("loop1", format!("{root}/loop2")).unwrap();
        assert_eq!(
            resolve(&format!("{root}/l/f")).unwrap(),
            format!("{real_root}/d/f")
        );
        assert_eq!(
            resolve(&format!("{root}/l/missing/../f")).unwrap(),
            format!("{real_root}/d/f")
        );
        assert_eq!(
            resolve(&format!("{root}/nope/deeper")).unwrap(),
            format!("{real_root}/nope/deeper")
        );
        let not_dir = resolve(&format!("{root}/d/f/x")).unwrap_err();
        assert!(is_not_dir(&not_dir), "{not_dir:?}");
        let looped = resolve(&format!("{root}/loop1")).unwrap_err();
        assert!(is_loop(&looped), "{looped:?}");
    }

    #[test]
    fn vault_spellings() {
        assert!(names_vault_folder("a/.SECRETS/key"));
        assert!(names_vault_folder("/x/.secrets"));
        assert!(!names_vault_folder("a/secrets/key"));
        assert!(is_vault_gitignore(".secrets/.gitignore"));
        assert!(is_vault_gitignore("./proj/.Secrets/.gitignore"));
        assert!(!is_vault_gitignore(".secrets/x/.gitignore"));
        assert!(!is_vault_gitignore(".secrets/.gitignore:x"));
        assert!(!is_vault_gitignore(".secrets/.secrets/.gitignore") || true);
        assert!(!is_vault_gitignore(".gitignore"));
    }

    #[test]
    fn protected_vault_paths() {
        let sdir = "/p/.secrets";
        for rel in [
            "key",
            "config.json",
            "key.tmp",
            "run_grants.json",
            "drawers/x/y",
            "dev.enc",
            "a.kvi",
            "sub/b.kvs.tmp",
            ".kv-write-0123456789abcdef0123456789abcdef.tmp",
        ] {
            assert!(
                is_protected_vault_path(&format!("{sdir}/{rel}"), sdir),
                "{rel}"
            );
        }
        for rel in [".gitignore", "notes.txt", "drawerz", ".kv-write-xyz.tmp"] {
            assert!(
                !is_protected_vault_path(&format!("{sdir}/{rel}"), sdir),
                "{rel}"
            );
        }
        assert!(!is_protected_vault_path("/p/.secretsx/key", sdir));
    }
}
