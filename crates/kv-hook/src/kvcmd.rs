//! Recognising protected `kv` commands in Bash text: Python `hook.py`'s
//! `_is_kv_reveal_command` and everything it rests on. Every function here can
//! only add a reason to refuse; none can clear text.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::paths::basename;
use crate::shell::{
    self, Cmd, DEPTH_REASON, GENERIC_REASONS, KV_MODULES, RESERVED_WORDS, SCAN_DEPTH, SHELL_NAMES,
    UNPARSED_REASON, UNREADABLE_REASON, command_name, is_unresolved_word, lex_partial,
    option_letters, python_kv_args,
};

pub const REVEALING_SUBCOMMANDS: &[&str] = &["get", "export", "export-key"];
pub const ADMIN_SUBCOMMANDS: &[&str] = &[
    "init",
    "setup",
    "setup-2fa",
    "2fa",
    "upgrade-security",
    "import-key",
    "provider",
    "agent",
    "recover",
    "recovery-key",
    "vault",
    "passphrase",
    "allow",
    "deny",
    "network-allow",
    "network-deny",
    "grant",
    "lock",
    "unlock",
    "history",
    "backup",
    "resume",
];
const HUMAN_ONLY_ACTIONS: &[(&str, &[&str])] = &[
    ("approvals", &["approve", "deny", "prune", "page"]),
    ("policy", &["allow", "block", "deny", "prune"]),
    ("approval-mode", &["set"]),
    (
        "env",
        &[
            "copy",
            "rename",
            "delete",
            "restore",
            "purge",
            "default",
            "keep-deleted",
        ],
    ),
];
const HUMAN_ONLY_POLICY_HTTP: &[&str] = &["add", "remove", "rm"];

pub const KEY_ACCESS_PATTERNS: &[&str] = &[".secrets/key", "kv.crypto", "kv.store", "agent.token"];
const KV_CONFIG_MUTATION_MODULE_PATTERNS: &[&str] = &[
    "kv.config",
    "from kv import config",
    "kv.env_recovery",
    "from kv import env_recovery",
    "kv.key_config",
    "from kv import key_config",
];
const KV_CONFIG_MUTATORS: &[&str] = &[
    "repair_environment_names",
    "save_config",
    "config_transaction",
    "config_write_guard",
    "commit_key_config",
    "recover_key_config",
    "recover_pending",
    "_write_config",
    "add_environment",
    "set_storage_format",
    "ensure_vault_id",
    "set_approval_mode",
    "add_network_command",
    "add_allowed_command",
    "remove_allowed_command",
];

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("regex"))
}

fn raw_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"[A-Za-z0-9_.:/~+-]+")
}

fn interpreter_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(
        &RE,
        r"\A(?:(?:python|pypy)[0-9.]*|py|node|nodejs|ruby|perl|php|deno|bun)\z",
    )
}

fn module_flag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"\A-[A-Za-z]*m(?:kv|kv\.cli|kv\.__main__)\z")
}

fn bare_m_flag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"\A-[A-Za-z]*m\z")
}

fn mkv_flag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"\A-[A-Za-z]*mkv\S*\z")
}

fn alias_definition_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r#"\balias\s+([^\s=;&|'"]+)="#)
}

fn function_definition_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"\bfunction\s+([A-Za-z_][\w.:-]*)")
}

fn name_run_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"[\w.:-]+")
}

fn parens_body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"\A\s*\(\s*\)\s*[{(]")
}

fn name_start_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"[A-Za-z_]")
}

fn agent_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"agent-[0-9a-f]{12}\.token\b")
}

fn agent_socket_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"agent-[0-9a-f]{12}\.sock\b")
}

fn config_mutator_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let mut names: Vec<&str> = KV_CONFIG_MUTATORS.to_vec();
        names.sort_unstable();
        let alternation: Vec<String> = names.iter().map(|name| regex::escape(name)).collect();
        Regex::new(&format!(r"\b({})\b", alternation.join("|"))).expect("regex")
    })
}

/// Python `_is_shell_env_assignment`.
pub fn is_shell_env_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_alphabetic() || first == '_') && name.chars().all(|c| c == '_' || c.is_alphanumeric())
}

fn human_only_action(sub: &str, rest: &[String]) -> Option<String> {
    let (_, actions) = HUMAN_ONLY_ACTIONS.iter().find(|(name, _)| *name == sub)?;
    let words: Vec<&String> = rest
        .iter()
        .filter(|token| !token.starts_with('-'))
        .collect();
    let first = words.first()?;
    if actions.contains(&first.as_str()) {
        return Some(format!("{sub} {first}"));
    }
    if sub == "policy"
        && first.as_str() == "http"
        && words.len() > 1
        && HUMAN_ONLY_POLICY_HTTP.contains(&words[1].as_str())
    {
        return Some(format!("policy http {}", words[1]));
    }
    None
}

/// Python `_kv_protected_pattern`.
pub fn kv_protected_pattern(args: &[String], prefix: &str) -> Option<String> {
    let mut rest = args;
    while rest.first().is_some_and(|first| first.starts_with('-')) {
        rest = &rest[1..];
    }
    let (sub, tail) = rest.split_first()?;
    let sub = sub.as_str();
    if REVEALING_SUBCOMMANDS.contains(&sub) || ADMIN_SUBCOMMANDS.contains(&sub) {
        return Some(format!("{prefix} {sub}"));
    }
    if sub == "sync" {
        if let Some((action, after)) = tail.split_first() {
            let has = |flag: &str| after.iter().any(|token| token == flag);
            match action.as_str() {
                "init" => return Some(format!("{prefix} sync init")),
                "login" | "attach-device" if has("--token-stdin") => {
                    return Some(format!("{prefix} sync {action} --token-stdin"));
                }
                "revoke-device" | "rotate-device-token" | "create-attach-token"
                    if has("--cloud") =>
                {
                    return Some(format!("{prefix} sync {action} --cloud"));
                }
                _ => {}
            }
        }
    }
    if let Some(nested) = human_only_action(sub, tail) {
        return Some(format!("{prefix} {nested}"));
    }
    if sub == "ls" && tail.iter().any(|token| token == "--reveal") {
        return Some(format!("{prefix} ls --reveal"));
    }
    None
}

/// Python `shlex.split` (POSIX mode, no comments).
pub fn shlex_split(text: &str) -> Result<Vec<String>, &'static str> {
    let mut tokens = Vec::new();
    let mut token: Option<String> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if let Some(done) = token.take() {
                    tokens.push(done);
                }
            }
            '\\' => {
                let Some(next) = chars.next() else {
                    return Err("No escaped character");
                };
                token.get_or_insert_with(String::new).push(next);
            }
            '\'' => {
                let word = token.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        None => return Err("No closing quotation"),
                        Some('\'') => break,
                        Some(inner) => word.push(inner),
                    }
                }
            }
            '"' => {
                let word = token.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        None => return Err("No closing quotation"),
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            None => return Err("No escaped character"),
                            Some(escaped @ ('"' | '\\')) => word.push(escaped),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                        },
                        Some(inner) => word.push(inner),
                    }
                }
            }
            other => token.get_or_insert_with(String::new).push(other),
        }
    }
    if let Some(done) = token {
        tokens.push(done);
    }
    Ok(tokens)
}

fn sync_pattern(prefix: &str, tokens: &[String], at: usize) -> Option<String> {
    // `at` indexes the token after `sync`.
    let action = tokens.get(at)?.as_str();
    let after = tokens.get(at + 1..).unwrap_or(&[]);
    let has = |flag: &str| after.iter().any(|token| token == flag);
    match action {
        "init" => Some(format!("{prefix} sync init")),
        "login" | "attach-device" if has("--token-stdin") => {
            Some(format!("{prefix} sync {action} --token-stdin"))
        }
        "revoke-device" | "rotate-device-token" | "create-attach-token" if has("--cloud") => {
            Some(format!("{prefix} sync {action} --cloud"))
        }
        _ => None,
    }
}

fn legacy_sub_pattern(prefix: &str, tokens: &[String], sub_at: usize) -> Option<String> {
    let sub = tokens.get(sub_at)?.as_str();
    if REVEALING_SUBCOMMANDS.contains(&sub) {
        return Some(format!("{prefix} {sub}"));
    }
    if sub == "sync" {
        if let Some(found) = sync_pattern(prefix, tokens, sub_at + 1) {
            return Some(found);
        }
    }
    if ADMIN_SUBCOMMANDS.contains(&sub) {
        return Some(format!("{prefix} {sub}"));
    }
    let rest = tokens.get(sub_at + 1..).unwrap_or(&[]);
    if let Some(nested) = human_only_action(sub, rest) {
        return Some(format!("{prefix} {nested}"));
    }
    if sub == "ls" && rest.iter().any(|token| token == "--reveal") {
        return Some(format!("{prefix} ls --reveal"));
    }
    None
}

/// Python `_legacy_kv_token_scan`.
pub fn legacy_kv_token_scan(command: &str) -> Option<String> {
    let tokens: Vec<String> = match shlex_split(command) {
        Ok(tokens) => tokens,
        Err(_) => command.split_whitespace().map(str::to_owned).collect(),
    };
    for (i, tok) in tokens.iter().enumerate() {
        if basename(tok) == "kv" && i + 1 < tokens.len() {
            if let Some(found) = legacy_sub_pattern("kv", &tokens, i + 1) {
                return Some(found);
            }
        }
        if tok == "-m" && i > 0 && i + 2 < tokens.len() {
            let prev = basename(&tokens[i - 1]);
            if prev.starts_with("python") && tokens[i + 1] == "kv" {
                if let Some(found) = legacy_sub_pattern("python -m kv", &tokens, i + 2) {
                    return Some(found);
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellMode {
    Body(String),
    Stdin,
    Script,
    Noexec,
}

/// Python `_shell_mode`.
pub fn shell_mode(args: &[String]) -> ShellMode {
    let (letters, i) = option_letters(args, "oO", &["--rcfile", "--init-file"], true);
    let mut noexec = false;
    for letter in &letters {
        if letter == "-n" || letter == "+n" {
            noexec = letter == "-n";
        }
    }
    if noexec {
        return ShellMode::Noexec;
    }
    if letters.iter().any(|letter| letter == "-c") {
        return match args.get(i) {
            Some(body) => ShellMode::Body(body.clone()),
            None => ShellMode::Stdin,
        };
    }
    if letters.iter().any(|letter| letter == "-s") || i >= args.len() {
        return ShellMode::Stdin;
    }
    ShellMode::Script
}

/// Python `_wrapped_start`.
fn wrapped_start(name: &str, args: &[String]) -> usize {
    if name == "env" {
        let (letters, longs) = shell::wrapper("env").unwrap_or(("", &[]));
        let mut i = 0;
        while i < args.len() {
            let tok = &args[i];
            if tok == "--" {
                return i + 1;
            }
            if is_shell_env_assignment(tok) {
                i += 1;
                continue;
            }
            if tok.starts_with('-') && tok != "-" {
                let window: Vec<String> = args[i..args.len().min(i + 2)].to_vec();
                let (_, used) = option_letters(&window, letters, longs, true);
                i += used.max(1);
                continue;
            }
            return i;
        }
        return i;
    }
    let (value_letters, value_longs) = shell::wrapper(name).unwrap_or(("", &[]));
    let (letters, i) = option_letters(args, value_letters, value_longs, true);
    if name == "command"
        && letters
            .iter()
            .any(|letter| letter == "-v" || letter == "-V")
    {
        return args.len();
    }
    (i + shell::wrapper_positionals(name)).min(args.len())
}

/// Python `_env_split_argv`.
fn env_split_argv(args: &[String]) -> Option<String> {
    for (k, tok) in args.iter().enumerate() {
        if (tok == "-S" || tok == "--split-string") && k + 1 < args.len() {
            return Some(format!("{} {}", args[k + 1], args[k + 2..].join(" ")));
        }
        if let Some(value) = tok.strip_prefix("--split-string=") {
            return Some(format!("{value} {}", args[k + 1..].join(" ")));
        }
        if let Some(value) = tok.strip_prefix("-S") {
            if !value.is_empty() {
                return Some(format!("{value} {}", args[k + 1..].join(" ")));
            }
        }
    }
    None
}

/// Python `_script_body`.
fn script_body(args: &[String]) -> Option<String> {
    for (k, tok) in args.iter().enumerate() {
        if (tok == "-c" || tok == "--command") && k + 1 < args.len() {
            return Some(args[k + 1].clone());
        }
        if let Some(value) = tok.strip_prefix("--command=") {
            return Some(value.to_owned());
        }
        if tok.starts_with('-') && !tok.starts_with("--") {
            if let Some(index) = tok[1..].find('c') {
                let rest = &tok[1 + index + 1..];
                return if rest.is_empty() {
                    args.get(k + 1).cloned()
                } else {
                    Some(rest.to_owned())
                };
            }
        }
    }
    None
}

/// Python `_scan_simple`.
fn scan_simple(words: &[String], cmd: Option<&Cmd>, depth: usize) -> Option<String> {
    if depth > SCAN_DEPTH {
        return Some(DEPTH_REASON.to_owned());
    }
    let mut words: Vec<String> = words.to_vec();
    let mut i = 0;
    let mut env_split_absent = false;
    while i < words.len() {
        while i < words.len()
            && (RESERVED_WORDS.contains(&words[i].as_str()) || is_shell_env_assignment(&words[i]))
        {
            i += 1;
        }
        if i >= words.len() {
            return None;
        }
        let word = words[i].clone();
        let name = command_name(&word);
        let args: Vec<String> = words[i + 1..].to_vec();
        if name == "kv" {
            return kv_protected_pattern(&args, "kv");
        }
        if interpreter_re().is_match(&name) || is_unresolved_word(&word) {
            if let Some(kv_args) = python_kv_args(&args) {
                return kv_protected_pattern(&kv_args, "python -m kv");
            }
            if is_unresolved_word(&word) {
                return kv_protected_pattern(&args, "kv");
            }
            return None;
        }
        if SHELL_NAMES.contains(&name.as_str()) {
            match shell_mode(&args) {
                ShellMode::Body(body) => return scan_text(&body, depth + 1),
                ShellMode::Stdin => {
                    if let Some(cmd) = cmd {
                        for operand in cmd.heredocs.iter().chain(cmd.herestrings.iter()) {
                            if let Some(found) = scan_text(&operand.text, depth + 1) {
                                return Some(found);
                            }
                        }
                    }
                }
                _ => {}
            }
            return None;
        }
        if name == "eval" {
            return scan_text(&args.join(" "), depth + 1);
        }
        if name == "script" {
            return script_body(&args).and_then(|body| scan_text(&body, depth + 1));
        }
        if name == "find" {
            for (k, tok) in args.iter().enumerate() {
                if matches!(tok.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
                    let end = (k + 1..args.len())
                        .find(|&m| args[m] == ";" || args[m] == "+")
                        .unwrap_or(args.len());
                    if let Some(found) = scan_simple(&args[k + 1..end], None, depth + 1) {
                        return Some(found);
                    }
                }
            }
            return None;
        }
        if name == "env" && !env_split_absent {
            if let Some(split) = env_split_argv(&args) {
                return scan_text(&split, depth + 1);
            }
            env_split_absent = true;
        }
        if shell::wrapper(&name).is_some() {
            let start = wrapped_start(&name, &args);
            words = args[start..].to_vec();
            i = 0;
            continue;
        }
        return None;
    }
    None
}

fn is_generic(reason: &str) -> bool {
    GENERIC_REASONS.contains(&reason)
}

/// Python `_uncertain_region`.
pub fn uncertain_region(region: &str) -> Option<String> {
    if has_kv_word(region) {
        return Some(UNPARSED_REASON.to_owned());
    }
    if !shell::is_plain_region(region) {
        return Some(UNREADABLE_REASON.to_owned());
    }
    None
}

fn tail_after(text: &[char], rest: usize) -> String {
    shell::slice(text, rest, text.len())
}

/// Python `_scan_text`.
pub fn scan_text(text: &str, depth: usize) -> Option<String> {
    if depth > SCAN_DEPTH {
        return Some(DEPTH_REASON.to_owned());
    }
    let chars = shell::chars(text);
    let (commands, extras, rest) = lex_partial(&chars);
    let mut fallback = uncertain_region(&tail_after(&chars, rest));
    for cmd in &commands {
        if let Some(found) = scan_simple(&cmd.words, Some(cmd), depth) {
            if is_generic(&found) {
                fallback = fallback.or(Some(found));
            } else {
                return Some(found);
            }
        }
    }
    for (body, _, _) in &extras.subs {
        if let Some(found) = scan_text(body, depth + 1) {
            if is_generic(&found) {
                fallback = fallback.or(Some(found));
            } else {
                return Some(found);
            }
        }
    }
    fallback
}

fn raw_tokens(text: &str) -> Vec<(String, usize)> {
    raw_token_re()
        .find_iter(text)
        .map(|m| (m.as_str().to_owned(), m.start()))
        .collect()
}

/// Python `_raw_mentions`.
pub fn raw_mentions(text: &str) -> Vec<(usize, String)> {
    let tokens = raw_tokens(text);
    let mut found = Vec::new();
    for (k, (tok, at)) in tokens.iter().enumerate() {
        let following: Vec<String> = tokens[k + 1..tokens.len().min(k + 65)]
            .iter()
            .map(|(t, _)| t.clone())
            .collect();
        let pattern = if command_name(tok) == "kv" {
            kv_protected_pattern(&following, "kv")
        } else if module_flag_re().is_match(tok) {
            kv_protected_pattern(&following, "python -m kv")
        } else if bare_m_flag_re().is_match(tok)
            && following
                .first()
                .is_some_and(|first| KV_MODULES.contains(&first.as_str()))
        {
            kv_protected_pattern(&following[1..], "python -m kv")
        } else {
            None
        };
        if let Some(pattern) = pattern {
            found.push((*at, pattern));
        }
    }
    found
}

/// Python `_has_kv_word`.
pub fn has_kv_word(text: &str) -> bool {
    raw_token_re().find_iter(text).any(|m| {
        let tok = m.as_str();
        command_name(tok) == "kv" || KV_MODULES.contains(&tok) || mkv_flag_re().is_match(tok)
    })
}

fn all_group1<'t>(regex: &Regex, text: &'t str) -> Vec<&'t str> {
    // Every position's match (Python's lookahead form), not only non-overlapping ones.
    let mut names = Vec::new();
    let mut start = 0;
    while start <= text.len() {
        let Some(caps) = regex.captures_at(text, start) else {
            break;
        };
        if let Some(group) = caps.get(1) {
            names.push(group.as_str());
        }
        let at = caps.get(0).map_or(start, |m| m.start());
        start = at + text[at..].chars().next().map_or(1, char::len_utf8);
    }
    names
}

/// Python `_definitions`.
pub fn definitions(text: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    names.extend(
        all_group1(alias_definition_re(), text)
            .into_iter()
            .map(str::to_owned),
    );
    names.extend(
        all_group1(function_definition_re(), text)
            .into_iter()
            .map(str::to_owned),
    );
    for run in name_run_re().find_iter(text) {
        if parens_body_re().is_match(&text[run.end()..]) {
            if let Some(start) = name_start_re().find(run.as_str()) {
                names.insert(run.as_str()[start.start()..].to_owned());
            }
        }
    }
    names
}

/// Python `_earlier_kv_in_pipeline`: per command, whether a command before
/// it in its pipeline has a kv word.
fn earlier_kv_in_pipeline(commands: &[Cmd]) -> Vec<bool> {
    let mut result = vec![false; commands.len()];
    let mut pipelines: Vec<usize> = commands.iter().map(|c| c.pipeline).collect();
    pipelines.sort_unstable();
    pipelines.dedup();
    for pipeline in pipelines {
        let mut members: Vec<usize> = (0..commands.len())
            .filter(|&k| commands[k].pipeline == pipeline)
            .collect();
        members.sort_by_key(|&k| commands[k].pos);
        let mut seen = false;
        let mut k = 0;
        while k < members.len() {
            let mut end = k;
            while end < members.len() && commands[members[end]].pos == commands[members[k]].pos {
                end += 1;
            }
            for &index in &members[k..end] {
                result[index] = seen;
            }
            seen = seen
                || members[k..end]
                    .iter()
                    .any(|&index| commands[index].words.iter().any(|w| has_kv_word(w)));
            k = end;
        }
    }
    result
}

/// Python `_kv_fed_to_shell`.
fn kv_fed_to_shell(commands: &[Cmd]) -> Option<String> {
    let mut earlier_kv: Option<Vec<bool>> = None;
    for (index, cmd) in commands.iter().enumerate() {
        let words = &cmd.words;
        let mut start = 0;
        while start < words.len() && is_shell_env_assignment(&words[start]) {
            start += 1;
        }
        if start >= words.len() || !SHELL_NAMES.contains(&command_name(&words[start]).as_str()) {
            continue;
        }
        if shell_mode(&words[start + 1..]) != ShellMode::Stdin {
            continue;
        }
        if cmd
            .heredocs
            .iter()
            .chain(cmd.herestrings.iter())
            .any(|operand| has_kv_word(&operand.text))
        {
            return Some("kv command piped into a shell".to_owned());
        }
        let earlier = earlier_kv.get_or_insert_with(|| earlier_kv_in_pipeline(commands));
        if earlier[index] {
            return Some("kv command piped into a shell".to_owned());
        }
    }
    None
}

/// Python `_nested_command_lists`: (lists, uncertain (reason, text)).
fn nested_command_lists(
    commands: Vec<Cmd>,
    extras: &shell::Extras,
    depth: usize,
) -> (Vec<Vec<Cmd>>, Vec<(Option<String>, String)>) {
    let mut lists = vec![commands];
    let mut uncertain = Vec::new();
    for (body, _, _) in &extras.subs {
        if depth >= SCAN_DEPTH {
            uncertain.push((Some(DEPTH_REASON.to_owned()), body.clone()));
            continue;
        }
        let chars = shell::chars(body);
        let (inner, inner_extras, rest) = lex_partial(&chars);
        if rest < chars.len() {
            uncertain.push((None, tail_after(&chars, rest)));
        }
        let (nested, nested_uncertain) = nested_command_lists(inner, &inner_extras, depth + 1);
        lists.extend(nested);
        uncertain.extend(nested_uncertain);
    }
    (lists, uncertain)
}

/// Python `_defined_name_use`.
fn defined_name_use(text: &str, defined: &BTreeSet<String>) -> Option<String> {
    if defined.is_empty() {
        return None;
    }
    let tokens: Vec<String> = raw_tokens(text).into_iter().map(|(t, _)| t).collect();
    for (k, tok) in tokens.iter().enumerate() {
        if defined.contains(tok) {
            let following = &tokens[k + 1..tokens.len().min(k + 65)];
            if let Some(pattern) = kv_protected_pattern(following, "kv") {
                return Some(pattern);
            }
        }
    }
    None
}

/// Python `_decoded_pieces`.
fn decoded_pieces(commands: &[Cmd]) -> Vec<String> {
    let mut pieces = Vec::new();
    for cmd in commands {
        pieces.push(cmd.words.join(" "));
        pieces.extend(cmd.words.iter().cloned());
        pieces.extend(
            cmd.heredocs
                .iter()
                .chain(cmd.herestrings.iter())
                .map(|o| o.text.clone()),
        );
    }
    pieces
}

/// Python `_is_kv_reveal_command`: the protected pattern Bash text mentions.
pub fn kv_reveal_pattern(command: &str) -> Option<String> {
    let text = command.replace("\\\n", "");
    let found = scan_text(&text, 0);
    if let Some(found) = &found {
        if !is_generic(found) {
            return Some(found.clone());
        }
    }
    let general = found;
    for source in [command, text.as_str()] {
        if let Some(pattern) = legacy_kv_token_scan(source) {
            return Some(pattern);
        }
    }
    if let Some((_, pattern)) = raw_mentions(&text).into_iter().next() {
        return Some(pattern);
    }
    let mut defined = definitions(&text);
    let chars = shell::chars(&text);
    let (commands, extras, rest) = lex_partial(&chars);
    let (lists, mut uncertain) = nested_command_lists(commands, &extras, 0);
    if rest < chars.len() {
        uncertain.push((None, tail_after(&chars, rest)));
    }
    let mut pieces = vec![text.clone()];
    for command_list in &lists {
        pieces.extend(decoded_pieces(command_list));
    }
    for piece in &pieces {
        if let Some((_, pattern)) = raw_mentions(piece).into_iter().next() {
            return Some(pattern);
        }
        defined.extend(definitions(piece));
    }
    if defined.contains("kv") && has_kv_word(&text) {
        return Some("kv defined as an alias or function".to_owned());
    }
    for piece in &pieces {
        if let Some(found) = defined_name_use(piece, &defined) {
            return Some(found);
        }
    }
    for command_list in &lists {
        if let Some(fed) = kv_fed_to_shell(command_list) {
            return Some(fed);
        }
    }
    if !uncertain.is_empty() && has_kv_word(&text) {
        return Some(UNPARSED_REASON.to_owned());
    }
    for (reason, region) in &uncertain {
        if let Some(why) = reason.clone().or_else(|| uncertain_region(region)) {
            return Some(why);
        }
    }
    general
}

/// Python `_has_kv_config_mutation_code`.
pub fn has_kv_config_mutation_code(command: &str) -> bool {
    KV_CONFIG_MUTATION_MODULE_PATTERNS
        .iter()
        .any(|pattern| command.contains(pattern))
        && config_mutator_re().is_match(command)
}

/// Python `_has_key_access_code`.
pub fn has_key_access_code(command: &str) -> bool {
    if KEY_ACCESS_PATTERNS
        .iter()
        .any(|pattern| command.contains(pattern))
    {
        return true;
    }
    if agent_token_re().is_match(command) || agent_socket_re().is_match(command) {
        return true;
    }
    command.contains(".secrets/")
        && [".enc", ".kvi", ".kvs", "/drawers", "/migration-backups"]
            .iter()
            .any(|pattern| command.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shlex_matches_python() {
        assert_eq!(
            shlex_split("a 'b c' \"d\\\"e\" f\\ g ''").unwrap(),
            vec!["a", "b c", "d\"e", "f g", ""]
        );
        assert_eq!(shlex_split("\"a\\nb\"").unwrap(), vec!["a\\nb"]);
        assert!(shlex_split("a 'b").is_err());
        assert!(shlex_split("a\\").is_err());
    }

    #[test]
    fn protected_patterns() {
        assert_eq!(kv_reveal_pattern("kv get X").as_deref(), Some("kv get"));
        assert_eq!(
            kv_reveal_pattern("echo hi && python3 -m kv export").as_deref(),
            Some("python -m kv export")
        );
        assert_eq!(
            kv_reveal_pattern("kv env rename a b").as_deref(),
            Some("kv env rename")
        );
        assert_eq!(
            kv_reveal_pattern("kv policy http add gh").as_deref(),
            Some("kv policy http add")
        );
        assert_eq!(
            kv_reveal_pattern("sudo -u me kv unlock").as_deref(),
            Some("kv unlock")
        );
        assert_eq!(
            kv_reveal_pattern("bash -c 'kv history list X'").as_deref(),
            Some("kv history")
        );
        assert_eq!(
            kv_reveal_pattern("echo 'kv get X' | sh").as_deref(),
            Some("kv get")
        );
        assert_eq!(
            kv_reveal_pattern("alias g=kv; g get X").as_deref(),
            Some("kv get")
        );
        assert_eq!(
            kv_reveal_pattern("kv() { :; }; kv ls").as_deref(),
            Some("kv defined as an alias or function")
        );
        assert_eq!(kv_reveal_pattern("kv ls").as_deref(), None);
        assert_eq!(
            kv_reveal_pattern("kv ls --reveal").as_deref(),
            Some("kv ls --reveal")
        );
        assert_eq!(kv_reveal_pattern("kv env create staging").as_deref(), None);
        assert_eq!(
            kv_reveal_pattern("ls; echo 'oops").as_deref(),
            Some(UNREADABLE_REASON)
        );
        assert_eq!(kv_reveal_pattern("ls; kv 'get").as_deref(), Some("kv get"));
        assert_eq!(kv_reveal_pattern("$X get Y").as_deref(), Some("kv get"));
    }

    #[test]
    fn code_patterns() {
        assert!(has_key_access_code("cat .secrets/drawers/x"));
        assert!(has_key_access_code("ls ~/.kv/agent-0123456789ab.token"));
        assert!(!has_key_access_code("cat .secrets/.gitignore"));
        assert!(has_kv_config_mutation_code(
            "python -c 'from kv import config; config.save_config()'"
        ));
        assert!(!has_kv_config_mutation_code("python -c 'save_config()'"));
        assert!(is_shell_env_assignment("FOO_1=bar"));
        assert!(!is_shell_env_assignment("1FOO=bar"));
        assert!(!is_shell_env_assignment("a-b=c"));
    }
}
