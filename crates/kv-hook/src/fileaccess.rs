//! File-access rules of Python `kv/hook.py`'s static layer: which words of a
//! Bash command name files, git's file-taking options, globs that could reach
//! protected names, variable paths, and the shell substitutions a command
//! contains. All of it adds reasons to refuse; none of it clears anything.

use std::sync::OnceLock;

use regex::Regex;

use crate::kvcmd::{is_shell_env_assignment, shlex_split};
use crate::paths::{self, basename, safe_expanduser};

pub const SHELL_OPERATORS: &[&str] = &["|", ">", ">>", "<", "&&", "||", ";", "2>&1"];
pub const FILE_READ_COMMANDS: &[&str] = &[
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "xxd",
    "hexdump",
    "od",
    "diff",
    "wc",
    "file",
    "stat",
    "md5sum",
    "sha256sum",
    "sha1sum",
    "awk",
    "base32",
    "base64",
    "cut",
    "strings",
    "cp",
    "mv",
    "sed",
    "tee",
];
pub const GIT_FILE_FLAGS: &[&str] = &["-F", "--file", "-t", "--template"];
const GIT_FILE_LONG_FLAGS: &[&str] = &["--file", "--template", "--pathspec-from-file", "--output"];
const ENV_OPTIONS_WITH_VALUE: &[&str] = &["-C", "-S", "-u", "--chdir", "--split-string", "--unset"];
const GIT_GLOBAL_OPTIONS_WITH_VALUE: &[&str] = &[
    "-c",
    "-C",
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
];
pub const ENCODING_PATTERNS: &[&str] = &[
    "base64",
    "b64decode",
    "b64encode",
    "bytes.fromhex",
    "fromhex",
    ".hex()",
    "binascii",
    "codecs.decode",
    "rot13",
    "chr(",
    "ord(",
    "bytearray",
    "decode(",
    "encode(",
];
pub const FILE_ACCESS_PATTERNS: &[&str] = &[
    "open(",
    ".read(",
    "os.path",
    "pathlib",
    "glob.",
    "glob(",
    "shutil.",
    "with open",
    "readlines",
    "readline",
    "read_bytes",
    "scandir",
    "listdir",
    "walk(",
];
pub const DAEMON_PATH_LIMIT: usize = 4096;

/// Python `_PROTECTED_NAMES`.
pub fn protected_names() -> &'static [String] {
    static NAMES: OnceLock<Vec<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut names: Vec<String> = [
            ".secrets",
            "key",
            "key.tmp",
            "dev.enc.tmp",
            "config.json",
            "config-authority",
            "vault-marker",
            "agent.token",
            "storage.lock",
            "config.lock",
            "key-config.pending",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        names.push(format!(".kv-write-{}.tmp", "a".repeat(32)));
        names.extend(
            ["drawers", "migration-backups", "index.kvi", "secret.kvs"]
                .iter()
                .map(|s| (*s).to_owned()),
        );
        names.extend(paths::APPROVAL_STATE_FILES.iter().map(|s| (*s).to_owned()));
        names.extend(
            paths::APPROVAL_STATE_FILES
                .iter()
                .map(|s| format!("{s}.tmp")),
        );
        names
    })
}

pub fn is_operator(token: &str) -> bool {
    SHELL_OPERATORS.contains(&token)
}

/// Python `_shell_words`: `shlex.split`, or whitespace words when it fails.
pub fn shell_words(command: &str) -> Vec<String> {
    shlex_split(command).unwrap_or_else(|_| command.split_whitespace().map(str::to_owned).collect())
}

/// `shlex.quote`.
pub fn shlex_quote(text: &str) -> String {
    if text.is_empty() {
        return "''".to_owned();
    }
    let safe = text.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-')
    });
    if safe {
        return text.to_owned();
    }
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}

/// `shlex.join`.
pub fn shlex_join(words: &[String]) -> String {
    words
        .iter()
        .map(|word| shlex_quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn rstrip_punct(word: &str) -> &str {
    word.trim_end_matches([',', ':', ')'])
}

fn path_fragment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\A(?:~|\.{1,2}|/)[^\s|&;<>"'`()]+"#).expect("regex"))
}

/// `_PATH_FRAGMENT_RE.finditer(part)`: the negative lookbehind done by hand.
fn path_fragments(part: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut previous: Option<char> = None;
    let mut at = 0;
    while at < part.len() {
        let c = part[at..].chars().next().expect("char");
        let boundary = !previous.is_some_and(|p| p.is_ascii_alphanumeric() || p == '_');
        if boundary {
            if let Some(m) = path_fragment_re().find(&part[at..]) {
                found.push(m.as_str());
                let end = at + m.end();
                previous = part[..end].chars().next_back();
                at = end;
                continue;
            }
        }
        previous = Some(c);
        at += c.len_utf8();
    }
    found
}

/// Python `_extract_all_paths`.
pub fn extract_all_paths(command: &str) -> Vec<String> {
    let mut paths_found: Vec<String> = Vec::new();
    for part in shell_words(command) {
        if part.starts_with('-') || is_operator(&part) {
            continue;
        }
        let mut candidates: Vec<&str> = Vec::new();
        if part.contains('/') || part.starts_with('.') || part.starts_with('~') {
            candidates.push(&part);
        }
        candidates.extend(path_fragments(&part));
        for candidate in candidates {
            let expanded = safe_expanduser(rstrip_punct(candidate));
            if !paths_found.contains(&expanded) {
                paths_found.push(expanded);
            }
        }
    }
    paths_found
}

/// Python `_find_git_command_index`.
pub fn find_git_command_index(tokens: &[String], start: usize) -> Option<usize> {
    let mut i = start;
    while i < tokens.len() && is_shell_env_assignment(&tokens[i]) {
        i += 1;
    }
    if i < tokens.len() && basename(&tokens[i]) == "env" {
        i += 1;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if tok == "--" {
                i += 1;
                break;
            }
            if is_shell_env_assignment(tok) {
                i += 1;
                continue;
            }
            if ENV_OPTIONS_WITH_VALUE.contains(&tok) {
                i += 2;
                continue;
            }
            if ENV_OPTIONS_WITH_VALUE
                .iter()
                .any(|opt| opt.starts_with("--") && tok.starts_with(&format!("{opt}=")))
            {
                i += 1;
                continue;
            }
            if tok.starts_with('-') && tok != "-" {
                i += 1;
                continue;
            }
            break;
        }
    }
    (i < tokens.len() && basename(&tokens[i]) == "git").then_some(i)
}

/// Python `_find_git_subcommand`: (index, subcommand) or (None, "").
pub fn find_git_subcommand(tokens: &[String], git_index: Option<usize>) -> (Option<usize>, String) {
    let git_index = match git_index {
        Some(index) => Some(index),
        None => find_git_command_index(tokens, 0),
    };
    let Some(git_index) = git_index else {
        return (None, String::new());
    };
    if git_index >= tokens.len() || basename(&tokens[git_index]) != "git" {
        return (None, String::new());
    }
    let mut i = git_index + 1;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if tok == "--" {
            i += 1;
            break;
        }
        if !tok.starts_with('-') || tok == "-" {
            return (Some(i), tok.to_owned());
        }
        if GIT_GLOBAL_OPTIONS_WITH_VALUE.contains(&tok) {
            i += 2;
            continue;
        }
        if GIT_GLOBAL_OPTIONS_WITH_VALUE
            .iter()
            .any(|opt| opt.starts_with("--") && tok.starts_with(&format!("{opt}=")))
        {
            i += 1;
            continue;
        }
        i += 1;
    }
    if i < tokens.len() {
        return (Some(i), tokens[i].clone());
    }
    (None, String::new())
}

fn is_git_metadata_subcommand(subcommand: &str) -> bool {
    matches!(subcommand, "commit" | "tag" | "log")
}

fn quoted_region_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?s)\\.|'[^']*'|"(?:\\.|[^"\\])*""#).expect("regex"))
}

fn metachar_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[;&|<>()`\n]").expect("regex"))
}

/// Python `_is_git_metadata_command`.
pub fn is_git_metadata_command(command: &str) -> bool {
    let Ok(tokens) = shlex_split(command) else {
        return false;
    };
    let unquoted = quoted_region_re().replace_all(command, "");
    if metachar_re().is_match(&unquoted) {
        return false;
    }
    if tokens.len() < 2 {
        return false;
    }
    let (_, subcommand) = find_git_subcommand(&tokens, None);
    is_git_metadata_subcommand(&subcommand)
}

/// Python `_strip_git_free_text_values`.
pub fn strip_git_free_text_values(command: &str) -> String {
    let Ok(tokens) = shlex_split(command) else {
        return command.to_owned();
    };
    let (index, subcommand) = find_git_subcommand(&tokens, None);
    let (Some(index), true) = (index, is_git_metadata_subcommand(&subcommand)) else {
        return command.to_owned();
    };
    let mut kept: Vec<String> = tokens[..=index].to_vec();
    let mut i = index + 1;
    while i < tokens.len() {
        let token = tokens[i].as_str();
        if token == "--" {
            kept.extend(tokens[i..].iter().cloned());
            break;
        }
        if subcommand == "commit" || subcommand == "tag" {
            if token == "-m" || token == "--message" {
                i += 2;
                continue;
            }
            if token.starts_with("-m") || token.starts_with("--message=") {
                i += 1;
                continue;
            }
        } else {
            if token == "--format" || token == "--grep" {
                i += 2;
                continue;
            }
            if token.starts_with("--format=")
                || token.starts_with("--grep=")
                || token.starts_with("--pretty=")
            {
                i += 1;
                continue;
            }
        }
        kept.push(token.to_owned());
        i += 1;
    }
    shlex_join(&kept)
}

/// Python `_git_file_flag_value`: (flag, value glued to the token).
pub fn git_file_flag_value(token: &str) -> (Option<&'static str>, Option<String>) {
    let (option, inline) = match token.split_once('=') {
        Some((option, inline)) => (option, Some(inline)),
        None => (token, None),
    };
    if option.len() > 2 && option.starts_with("--") {
        if let Some(flag) = GIT_FILE_LONG_FLAGS
            .iter()
            .find(|flag| flag.starts_with(option))
        {
            return (Some(flag), inline.map(str::to_owned));
        }
        return (None, None);
    }
    for short in ["-F", "-t"] {
        if let Some(rest) = token.strip_prefix(short) {
            return (Some(short), (!rest.is_empty()).then(|| rest.to_owned()));
        }
    }
    (None, None)
}

/// Python `_git_line_range_file`.
pub fn git_line_range_file(value: &str) -> Option<String> {
    let after = value.rsplit_once(':').map_or(value, |(_, after)| after);
    (!after.is_empty()).then(|| after.to_owned())
}

fn push_target(targets: &mut Vec<String>, word: &str) {
    targets.push(safe_expanduser(rstrip_punct(word)));
}

/// Python `_extract_read_targets`.
pub fn extract_read_targets(command: &str) -> Vec<String> {
    let parts = shell_words(command);
    let mut targets = Vec::new();
    let mut i = 0;
    while i < parts.len() {
        let token = parts[i].as_str();
        if is_operator(token) {
            i += 1;
            continue;
        }
        let name = basename(token);
        if FILE_READ_COMMANDS.contains(&name) {
            let mut j = i + 1;
            while j < parts.len() && !is_operator(&parts[j]) {
                if !parts[j].starts_with('-') {
                    push_target(&mut targets, &parts[j]);
                }
                j += 1;
            }
            i = j;
            continue;
        }
        let (sub_index, subcommand) = find_git_subcommand(&parts, Some(i));
        if name == "git" && is_git_metadata_subcommand(&subcommand) {
            let mut j = sub_index.unwrap_or(i) + 1;
            while j < parts.len() && !is_operator(&parts[j]) {
                let arg = parts[j].as_str();
                let (flag, value) = git_file_flag_value(arg);
                if flag.is_some() {
                    if value.is_none() && j + 1 < parts.len() {
                        let next = parts[j + 1].as_str();
                        if !is_operator(next) {
                            push_target(&mut targets, next);
                        }
                        j += 2;
                        continue;
                    }
                    if let Some(value) = value {
                        if !value.is_empty() {
                            push_target(&mut targets, &value);
                        }
                    }
                    j += 1;
                    continue;
                }
                if arg.starts_with("-L") && arg.len() > 2 {
                    if let Some(path) = git_line_range_file(&arg[2..]) {
                        targets.push(safe_expanduser(&path));
                    }
                    j += 1;
                    continue;
                }
                if arg == "-L" && j + 1 < parts.len() && !is_operator(&parts[j + 1]) {
                    if let Some(path) = git_line_range_file(&parts[j + 1]) {
                        targets.push(safe_expanduser(&path));
                    }
                    j += 2;
                    continue;
                }
                if arg == "--" {
                    let mut k = j + 1;
                    while k < parts.len() && !is_operator(&parts[k]) {
                        push_target(&mut targets, &parts[k]);
                        k += 1;
                    }
                    j = k;
                    break;
                }
                j += 1;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    targets
}

/// Python `_extract_stdin_redirection_targets`.
pub fn extract_stdin_redirection_targets(command: &str) -> Vec<String> {
    let parts = shell_words(command);
    let mut targets = Vec::new();
    let mut i = 0;
    while i < parts.len() {
        if parts[i] == "<" && i + 1 < parts.len() {
            if !is_operator(&parts[i + 1]) {
                push_target(&mut targets, &parts[i + 1]);
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    targets
}

/// Python `_git_file_flag_dollar`.
fn git_file_flag_dollar(tokens: &[String]) -> Vec<bool> {
    let n = tokens.len();
    let mut found = vec![false; n + 2];
    for j in (0..n).rev() {
        let arg = tokens[j].as_str();
        if is_operator(arg) {
            found[j] = false;
        } else if GIT_FILE_FLAGS.contains(&arg) && j + 1 < n {
            let value = tokens[j + 1].as_str();
            found[j] = (!is_operator(value) && value.contains('$')) || found[j + 2];
        } else {
            let matched = GIT_FILE_FLAGS
                .iter()
                .any(|flag| arg.starts_with(&format!("{flag}=")));
            let dollar = matched
                && arg
                    .split_once('=')
                    .is_some_and(|(_, value)| value.contains('$'));
            found[j] = dollar || found[j + 1];
        }
    }
    found
}

/// Python `_has_variable_path_read`.
pub fn has_variable_path_read(command: &str) -> bool {
    let tokens = shell_words(command);
    let n = tokens.len();
    let mut reader_dollar = vec![false; n + 1];
    for k in (0..n).rev() {
        let arg = tokens[k].as_str();
        if matches!(arg, "|" | ">" | ">>" | "&&" | "||" | ";") {
            reader_dollar[k] = false;
        } else if arg.starts_with('-') {
            reader_dollar[k] = reader_dollar[k + 1];
        } else {
            reader_dollar[k] = arg.contains('$') || reader_dollar[k + 1];
        }
    }
    let mut git_dollar: Option<Vec<bool>> = None;
    for (i, token) in tokens.iter().enumerate() {
        let name = basename(token);
        if FILE_READ_COMMANDS.contains(&name) && reader_dollar[i + 1] {
            return true;
        }
        let (sub_index, subcommand) = find_git_subcommand(&tokens, Some(i));
        if name == "git" && is_git_metadata_subcommand(&subcommand) {
            let found = git_dollar.get_or_insert_with(|| git_file_flag_dollar(&tokens));
            if found[sub_index.unwrap_or(i) + 1] {
                return true;
            }
        }
    }
    false
}

/// Python `fnmatch.fnmatchcase`.
pub fn fnmatchcase(name: &str, pattern: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    fn class_matches(set: &[char], c: char) -> Option<bool> {
        // Python's translate: "!" negates; a leading "^" or "[" is a literal.
        let (negate, body) = match set.first() {
            Some('!') => (true, &set[1..]),
            _ => (false, set),
        };
        if body.is_empty() {
            return Some(false);
        }
        if body == ['*'] {
            return Some(true);
        }
        let mut matched = false;
        let mut i = 0;
        while i < body.len() {
            if i + 2 < body.len() && body[i + 1] == '-' {
                let (lo, hi) = (body[i], body[i + 2]);
                if lo <= c && c <= hi {
                    matched = true;
                }
                i += 3;
            } else {
                if body[i] == c {
                    matched = true;
                }
                i += 1;
            }
        }
        Some(matched != negate)
    }
    fn matches(name: &[char], pattern: &[char]) -> bool {
        if pattern.is_empty() {
            return name.is_empty();
        }
        match pattern[0] {
            '*' => (0..=name.len()).any(|k| matches(&name[k..], &pattern[1..])),
            '?' => !name.is_empty() && matches(&name[1..], &pattern[1..]),
            '[' => {
                let mut j = 1;
                if j < pattern.len() && pattern[j] == '!' {
                    j += 1;
                }
                if j < pattern.len() && pattern[j] == ']' {
                    j += 1;
                }
                while j < pattern.len() && pattern[j] != ']' {
                    j += 1;
                }
                if j >= pattern.len() {
                    return !name.is_empty()
                        && name[0] == '['
                        && matches(&name[1..], &pattern[1..]);
                }
                let set = &pattern[1..j];
                !name.is_empty()
                    && class_matches(set, name[0]).unwrap_or(false)
                    && matches(&name[1..], &pattern[j + 1..])
            }
            literal => !name.is_empty() && name[0] == literal && matches(&name[1..], &pattern[1..]),
        }
    }
    matches(&name, &pattern)
}

/// Python `_glob_matches_private_temp`.
pub fn glob_matches_private_temp(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    if chars.len() > 256 {
        return true;
    }
    let mut alphabet: Vec<Vec<char>> = ".kv-write-".chars().map(|c| vec![c]).collect();
    alphabet.extend(std::iter::repeat_n(
        "0123456789abcdef".chars().collect::<Vec<_>>(),
        32,
    ));
    alphabet.extend(".tmp".chars().map(|c| vec![c]));
    let len = alphabet.len();
    let mut reachable: Vec<usize> = vec![0];
    let mut i = 0;
    while i < chars.len() && !reachable.is_empty() {
        let start = i;
        let c = chars[i];
        i += 1;
        if c == '*' {
            let low = *reachable.iter().min().expect("non-empty");
            reachable = (low..=len).collect();
            continue;
        }
        if c == '[' {
            let mut end = i;
            if end < chars.len() && (chars[end] == '!' || chars[end] == '^') {
                end += 1;
            }
            if end < chars.len() && chars[end] == ']' {
                end += 1;
            }
            while end < chars.len() && chars[end] != ']' {
                if end + 1 < chars.len()
                    && chars[end] == '['
                    && matches!(chars[end + 1], ':' | '.' | '=')
                {
                    let closer = [chars[end + 1], ']'];
                    if let Some(close) = (end + 2..chars.len().saturating_sub(1))
                        .find(|&k| chars[k] == closer[0] && chars[k + 1] == closer[1])
                    {
                        end = close + 2;
                        continue;
                    }
                }
                end += 1;
            }
            if end < chars.len() {
                i = end + 1;
            }
        }
        let mut token: String = chars[start..i].iter().collect();
        if token.starts_with("[^") {
            token = format!("[!{}", &token[2..]);
        }
        if token.starts_with('[')
            && ["[:", "[.", "[="]
                .iter()
                .any(|form| token[1..].contains(form))
        {
            let low = *reachable.iter().min().expect("non-empty");
            reachable = (low..=len).collect();
            continue;
        }
        let mut next: Vec<usize> = Vec::new();
        for &pos in &reachable {
            if pos < len
                && alphabet[pos]
                    .iter()
                    .any(|c| fnmatchcase(&c.to_string(), &token))
                && !next.contains(&(pos + 1))
            {
                next.push(pos + 1);
            }
        }
        reachable = next;
    }
    reachable.contains(&len)
}

/// Python `_has_glob_path_to_secrets`.
pub fn has_glob_path_to_secrets(command: &str) -> bool {
    let tokens = shell_words(command);
    if !tokens
        .iter()
        .any(|t| FILE_READ_COMMANDS.contains(&basename(t)))
    {
        return false;
    }
    for token in &tokens {
        if token.starts_with('-')
            || matches!(token.as_str(), "|" | ">" | ">>" | "<" | "&&" | "||" | ";")
        {
            continue;
        }
        if !token.contains(['*', '?', '[']) {
            continue;
        }
        for part in token.replace('\\', "/").split('/') {
            if !part.contains(['*', '?', '[']) {
                continue;
            }
            if glob_matches_private_temp(part) {
                return true;
            }
            if protected_names()
                .iter()
                .any(|protected| fnmatchcase(protected, part))
            {
                return true;
            }
        }
    }
    false
}

/// Python `_extract_shell_subcommands`.
pub fn extract_shell_subcommands(command: &str) -> Vec<String> {
    let text: Vec<char> = command.chars().collect();
    let n = text.len();
    let prefixes = ["$(", "<(", ">("];
    let starts = |at: usize, prefix: &str| {
        let p: Vec<char> = prefix.chars().collect();
        at + p.len() <= n && text[at..at + p.len()] == p[..]
    };
    let mut subcommands = Vec::new();
    let mut i = 0;
    let mut single = false;
    let mut double = false;
    while i < n {
        if single {
            if text[i] == '\'' {
                single = false;
            }
            i += 1;
            continue;
        }
        if text[i] == '\\' {
            i += 2;
            continue;
        }
        if text[i] == '\'' && !double {
            single = true;
            i += 1;
            continue;
        }
        if text[i] == '"' {
            double = !double;
            i += 1;
            continue;
        }
        let prefix = prefixes.iter().find(|p| starts(i, p)).copied();
        if let Some(prefix) = prefix.filter(|p| !double || *p == "$(") {
            let mut depth = 1;
            let mut j = i + prefix.chars().count();
            let (mut inner_single, mut inner_double) = (false, false);
            let mut buf = String::new();
            let mut closed = false;
            while j < n {
                let ch = text[j];
                if ch == '\\' {
                    if j + 1 < n {
                        buf.push(ch);
                        buf.push(text[j + 1]);
                        j += 2;
                        continue;
                    }
                    break;
                }
                if inner_single {
                    if ch == '\'' {
                        inner_single = false;
                    }
                    buf.push(ch);
                    j += 1;
                    continue;
                }
                if inner_double {
                    if ch == '"' {
                        inner_double = false;
                    }
                    buf.push(ch);
                    j += 1;
                    continue;
                }
                if ch == '\'' {
                    inner_single = true;
                    buf.push(ch);
                    j += 1;
                    continue;
                }
                if ch == '"' {
                    inner_double = true;
                    buf.push(ch);
                    j += 1;
                    continue;
                }
                let nested = prefixes
                    .iter()
                    .find(|p| starts(j, p) && (!inner_double || **p == "$("))
                    .copied();
                if let Some(nested) = nested {
                    depth += 1;
                    buf.push_str(nested);
                    j += nested.chars().count();
                    continue;
                }
                if ch == ')' {
                    depth -= 1;
                    if depth == 0 {
                        subcommands.push(buf.trim().to_owned());
                        i = j + 1;
                        closed = true;
                        break;
                    }
                }
                buf.push(ch);
                j += 1;
            }
            if !closed {
                i += 2;
            }
            continue;
        }
        if text[i] == '`' {
            let mut j = i + 1;
            let mut buf = String::new();
            let mut closed = false;
            while j < n {
                let ch = text[j];
                if ch == '\\' {
                    if j + 1 < n {
                        buf.push(ch);
                        buf.push(text[j + 1]);
                        j += 2;
                        continue;
                    }
                    break;
                }
                if ch == '`' {
                    subcommands.push(buf.trim().to_owned());
                    i = j + 1;
                    closed = true;
                    break;
                }
                buf.push(ch);
                j += 1;
            }
            if !closed {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    subcommands
}

/// Python `_has_shell_expansion`.
pub fn has_shell_expansion(command: &str) -> bool {
    !extract_shell_subcommands(command).is_empty()
}

/// Python `_extended_spelling`: a Windows `\\?\`-style spelling.
pub fn extended_spelling(path: &str) -> bool {
    let p = path.replace('/', "\\");
    p.starts_with("\\\\?\\") || p.starts_with("\\\\.\\") || p.starts_with("\\??\\")
}

/// Python `_long_paths_open`: whether the platform opens paths past PATH_MAX.
pub fn long_paths_open() -> bool {
    cfg!(windows)
}

fn input_redirection_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<+[>&(]?").expect("regex"))
}

/// Python `_bash_path_candidates`.
pub fn bash_path_candidates(command: &str) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut texts = vec![command.to_owned()];
    texts.extend(extract_shell_subcommands(command));
    for text in &texts {
        candidates.extend(extract_all_paths(text));
        candidates.extend(extract_read_targets(text));
        candidates.extend(extract_stdin_redirection_targets(text));
        words.extend(shell_words(text));
    }
    let mut pieces: Vec<String> = Vec::new();
    for word in candidates.iter().chain(words.iter()) {
        if !word.contains('<') {
            continue;
        }
        for piece in input_redirection_re().split(word).skip(1) {
            if !piece.is_empty() {
                pieces.push(safe_expanduser(piece));
            }
        }
    }
    let mut unique: Vec<String> = Vec::new();
    for item in candidates.into_iter().chain(pieces) {
        if !unique.contains(&item) {
            unique.push(item);
        }
    }
    unique
}

/// Python `_policy_change_denial_reason`.
pub fn policy_change_denial_reason(pattern: &str) -> String {
    format!(
        "[kv-secrets] blocked: '{pattern}' modifies security policy. Ask the user to run the \
         policy-change command directly."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_like_python() {
        assert!(fnmatchcase("key", "k?y"));
        assert!(fnmatchcase(".secrets", ".secr*"));
        assert!(fnmatchcase("a", "[!b]"));
        assert!(!fnmatchcase("b", "[!b]"));
        assert!(fnmatchcase("^", "[^a]"));
        assert!(!fnmatchcase("b", "[^a]"));
        assert!(fnmatchcase("]", "[]]"));
        assert!(fnmatchcase("[x", "[x"));
        assert!(fnmatchcase("c", "[a-d]"));
        assert!(!fnmatchcase("", "?"));
        assert!(fnmatchcase("", "*"));
    }

    #[test]
    fn glob_rules() {
        assert!(glob_matches_private_temp(".kv-write-*.tmp"));
        assert!(glob_matches_private_temp("*"));
        assert!(glob_matches_private_temp(
            ".kv-write-????????????????????????????????.tmp"
        ));
        assert!(!glob_matches_private_temp("k?y"));
        assert!(!glob_matches_private_temp(".kv-write-*.txt"));
        assert!(glob_matches_private_temp("[[:alpha:]]*"));
        assert!(has_glob_path_to_secrets("cat .secr*/k?y"));
        assert!(has_glob_path_to_secrets("cat .secrets/drawer*/x"));
        assert!(!has_glob_path_to_secrets("cat *.txt"));
        assert!(!has_glob_path_to_secrets("ls .secr*/k?y"));
    }

    #[test]
    fn paths_and_git() {
        assert_eq!(
            extract_all_paths("cat $(cat .secrets/key) ./a,"),
            vec![".secrets/key", "./a"]
        );
        assert_eq!(extract_all_paths("echo a/b --x=~/y"), vec!["a/b"]);
        assert_eq!(path_fragments("x=/etc/passwd"), vec!["/etc/passwd"]);
        assert_eq!(path_fragments("a/etc"), Vec::<&str>::new());
        assert_eq!(
            extract_read_targets("cat a b | head -n 1 c"),
            vec!["a", "b", "1", "c"]
        );
        assert_eq!(
            extract_read_targets("git commit -F msg --file=x -L 1,2:f -- g"),
            vec!["msg", "x", "f", "g"]
        );
        assert_eq!(
            extract_stdin_redirection_targets("x < in; y < |"),
            vec!["in;"]
        );
        assert!(has_variable_path_read("A=.secrets; cat $A/key"));
        assert!(!has_variable_path_read("echo $A; cat x"));
        assert!(has_variable_path_read("git commit -F $F"));
        assert!(is_git_metadata_command(
            "GIT_X=1 env -u Y git -C . commit -m 'kv get'"
        ));
        assert!(!is_git_metadata_command("git commit -m x; kv get"));
        assert_eq!(
            strip_git_free_text_values("git commit -m 'kv get' -F f"),
            "git commit -F f"
        );
        assert_eq!(
            strip_git_free_text_values("git log --grep=kv --pretty=x -- a b"),
            "git log -- a b"
        );
        assert_eq!(
            git_file_flag_value("--fi=x"),
            (Some("--file"), Some("x".to_owned()))
        );
        assert_eq!(
            git_file_flag_value("-Fx"),
            (Some("-F"), Some("x".to_owned()))
        );
        assert_eq!(git_file_flag_value("-F"), (Some("-F"), None));
        assert_eq!(git_file_flag_value("--x"), (None, None));
        assert_eq!(
            extract_shell_subcommands("a $(b \"$(c)\") `d` <(e)"),
            vec!["b \"$(c)\"", "d", "e"]
        );
        assert_eq!(extract_shell_subcommands("\"<(x)\""), Vec::<String>::new());
        assert_eq!(bash_path_candidates("cat <in -n<f"), vec!["<in", "in", "f"]);
        assert_eq!(
            shlex_join(&["a b".to_owned(), "c'd".to_owned(), String::new()]),
            "'a b' 'c'\"'\"'d' ''"
        );
    }
}
