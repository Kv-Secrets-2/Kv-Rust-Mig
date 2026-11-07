//! The shell lexer of Python `kv/hook.py` (`_lex_shell`, `_lex_partial`) and
//! its word helpers, ported construct for construct. Text is handled as
//! characters so every span means what Python's string indices mean.

use std::cell::RefCell;
use std::rc::Rc;

pub const SHELL_NAMES: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash"];
pub const RESERVED_WORDS: &[&str] = &[
    "if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "fi", "done",
];
pub const KV_MODULES: &[&str] = &["kv", "kv.cli", "kv.__main__"];
/// Nesting levels 0 (the top) to 8 are read; deeper text is refused.
pub const SCAN_DEPTH: usize = 8;
pub const DEPTH_REASON: &str = "shell text nested deeper than the hook reads";
pub const UNPARSED_REASON: &str = "kv command in text the hook cannot parse";
pub const UNREADABLE_REASON: &str = "shell text the hook cannot read";
pub const GENERIC_REASONS: &[&str] = &[DEPTH_REASON, UNPARSED_REASON, UNREADABLE_REASON];
const PARTIAL_RETRIES: usize = 64;

/// Python `_WRAPPERS`: (short letters taking a value, long options taking a value).
pub const WRAPPERS: &[(&str, &str, &[&str])] = &[
    ("env", "uCS", &["--unset", "--chdir", "--split-string"]),
    ("nice", "n", &["--adjustment"]),
    ("timeout", "sk", &["--signal", "--kill-after"]),
    ("stdbuf", "ioe", &["--input", "--output", "--error"]),
    (
        "sudo",
        "ugCDhprtU",
        &[
            "--user",
            "--group",
            "--chdir",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--other-user",
            "--close-from",
        ],
    ),
    ("doas", "uC", &[]),
    (
        "xargs",
        "adEILnPs",
        &[
            "--arg-file",
            "--delimiter",
            "--eof",
            "--replace",
            "--max-lines",
            "--max-args",
            "--max-procs",
            "--max-chars",
        ],
    ),
    ("exec", "a", &[]),
    ("ionice", "cnt", &["--class", "--classdata"]),
    ("time", "fo", &["--format", "--output"]),
    ("nohup", "", &[]),
    ("setsid", "", &[]),
    ("builtin", "", &[]),
    ("command", "", &[]),
    ("chrt", "", &[]),
    ("taskset", "", &[]),
    ("unbuffer", "", &[]),
];
pub const WRAPPER_POSITIONALS: &[(&str, usize)] = &[("timeout", 1), ("chrt", 1), ("taskset", 1)];

pub fn wrapper(name: &str) -> Option<(&'static str, &'static [&'static str])> {
    WRAPPERS
        .iter()
        .find(|(wrapper, _, _)| *wrapper == name)
        .map(|(_, letters, longs)| (*letters, *longs))
}

pub fn wrapper_positionals(name: &str) -> usize {
    WRAPPER_POSITIONALS
        .iter()
        .find(|(wrapper, _)| *wrapper == name)
        .map_or(0, |(_, count)| *count)
}

/// Characters of `_RAW_TOKEN`: `[A-Za-z0-9_.:/~+-]`.
pub fn is_raw_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '/' | '~' | '+' | '-')
}

/// `_PLAIN_REGION.fullmatch`: raw-token characters, whitespace and separators only.
pub fn is_plain_region(text: &str) -> bool {
    text.chars().all(|c| {
        is_raw_token_char(c)
            || c.is_whitespace()
            || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>')
    })
}

/// Python `_command_name`: the executable a word runs.
pub fn command_name(word: &str) -> String {
    let name = word.rsplit(['\\', '/']).next().unwrap_or("");
    if name.to_lowercase().ends_with(".exe") {
        name[..name.len() - 4].to_lowercase()
    } else {
        name.to_owned()
    }
}

/// Python `_is_unresolved_word`.
pub fn is_unresolved_word(word: &str) -> bool {
    word.starts_with('$') || word.contains('`') || word.contains("$(")
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Operand {
    pub text: String,
    pub quoted: bool,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cmd {
    pub words: Vec<String>,
    pub spans: Vec<(usize, usize)>,
    pub quoted: Vec<bool>,
    pub subst: Vec<bool>,
    pub pipeline: usize,
    pub pos: usize,
    pub heredocs: Vec<Operand>,
    pub herestrings: Vec<Operand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extras {
    /// (body, start, end) of every `$( )`, backtick and process substitution body.
    pub subs: Vec<(String, usize, usize)>,
    pub comments: Vec<(usize, usize)>,
    pub redirects: Vec<(usize, usize)>,
}

/// Python `_ShellSyntax`: `at` is where the construct the lexer could not read starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSyntax {
    pub at: usize,
    pub what: &'static str,
}

pub fn chars(text: &str) -> Vec<char> {
    text.chars().collect()
}

pub fn slice(text: &[char], start: usize, end: usize) -> String {
    let end = end.min(text.len());
    if start >= end {
        return String::new();
    }
    text[start..end].iter().collect()
}

fn find(text: &[char], c: char, from: usize) -> Option<usize> {
    (from..text.len()).find(|&i| text[i] == c)
}

fn starts_with(text: &[char], at: usize, pat: &str) -> bool {
    let mut i = at;
    for p in pat.chars() {
        if i >= text.len() || text[i] != p {
            return false;
        }
        i += 1;
    }
    true
}

/// Python `str.isdigit()` for the strings the lexer tests.
fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.chars().all(char::is_numeric)
}

struct Lexer<'a> {
    text: &'a [char],
    n: usize,
    commands: Vec<Rc<RefCell<Cmd>>>,
    extras: Extras,
    pending: Vec<(Rc<RefCell<Cmd>>, String, bool, bool, usize)>,
    pipeline: usize,
    index: usize,
    cmd: Rc<RefCell<Cmd>>,
    cur: Option<(String, usize, bool, bool)>,
    pipe_open: bool,
    at: usize,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a [char]) -> Lexer<'a> {
        Lexer {
            text,
            n: text.len(),
            commands: Vec::new(),
            extras: Extras::default(),
            pending: Vec::new(),
            pipeline: 0,
            index: 0,
            cmd: Rc::new(RefCell::new(Cmd::default())),
            cur: None,
            pipe_open: false,
            at: 0,
        }
    }

    fn fail(&self, what: &'static str) -> ShellSyntax {
        ShellSyntax { at: self.at, what }
    }

    fn new_command(&self) -> Rc<RefCell<Cmd>> {
        Rc::new(RefCell::new(Cmd {
            pipeline: self.pipeline,
            pos: self.index,
            ..Cmd::default()
        }))
    }

    fn add(&mut self, chars: &str, at: usize, quoted: bool, subst: bool) {
        self.pipe_open = false;
        let cur = self
            .cur
            .get_or_insert_with(|| (String::new(), at, false, false));
        cur.0.push_str(chars);
        cur.2 |= quoted;
        cur.3 |= subst;
    }

    fn end_word(&mut self, end: usize) {
        if let Some((word, start, quoted, subst)) = self.cur.take() {
            let mut cmd = self.cmd.borrow_mut();
            cmd.words.push(word);
            cmd.spans.push((start, end));
            cmd.quoted.push(quoted);
            cmd.subst.push(subst);
        }
    }

    fn end_command(&mut self, end: usize, piped: bool) {
        self.end_word(end);
        let has_content = {
            let cmd = self.cmd.borrow();
            !cmd.words.is_empty() || !cmd.heredocs.is_empty() || !cmd.herestrings.is_empty()
        };
        if has_content {
            self.commands.push(Rc::clone(&self.cmd));
            if piped {
                self.index += 1;
            }
        }
        self.pipe_open = piped;
        if !piped {
            self.pipeline += 1;
            self.index = 0;
        }
        self.cmd = self.new_command();
    }

    /// Index just past the closer matching an opener that ends at `start`.
    fn balanced(&self, start: usize, opener: &str, closer: char) -> Result<usize, ShellSyntax> {
        let text = self.text;
        let (mut depth, mut j) = (1usize, start);
        let (mut single, mut double) = (false, false);
        while j < self.n {
            let ch = text[j];
            if ch == '\\' && !single {
                j += 2;
                continue;
            }
            if single {
                single = ch != '\'';
            } else if double {
                double = ch != '"';
            } else if ch == '\'' {
                single = true;
            } else if ch == '"' {
                double = true;
            } else if starts_with(text, j, opener) {
                depth += 1;
                j += opener.chars().count();
                continue;
            } else if ch == closer {
                depth -= 1;
                if depth == 0 {
                    return Ok(j + 1);
                }
            }
            j += 1;
        }
        Err(self.fail("unterminated substitution"))
    }

    /// A redirection or heredoc operand from `j`: (word, end, quoted).
    fn target_word(&self, mut j: usize) -> Result<(String, usize, bool), ShellSyntax> {
        let text = self.text;
        let n = self.n;
        while j < n && (text[j] == ' ' || text[j] == '\t') {
            j += 1;
        }
        let start = j;
        let mut buf = String::new();
        let mut quoted = false;
        while j < n {
            let ch = text[j];
            if ch == '\'' {
                let Some(k) = find(text, '\'', j + 1) else {
                    return Err(self.fail("unterminated quote"));
                };
                buf.push_str(&slice(text, j + 1, k));
                quoted = true;
                j = k + 1;
                continue;
            }
            if ch == '"' {
                let mut k = j + 1;
                while k < n && text[k] != '"' {
                    k += if text[k] == '\\' { 2 } else { 1 };
                }
                if k >= n {
                    return Err(self.fail("unterminated quote"));
                }
                buf.push_str(&slice(text, j + 1, k));
                quoted = true;
                j = k + 1;
                continue;
            }
            if ch == '\\' && j + 1 < n {
                buf.push(text[j + 1]);
                quoted = true;
                j += 2;
                continue;
            }
            if matches!(
                ch,
                ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
            ) {
                break;
            }
            buf.push(ch);
            j += 1;
        }
        if j == start {
            return Err(self.fail("missing redirection operand"));
        }
        Ok((buf, j, quoted))
    }

    fn ansi_c_quote(&self, i: usize) -> Result<(String, usize), ShellSyntax> {
        let text = self.text;
        let n = self.n;
        let mut j = i + 2;
        let mut buf = String::new();
        while j < n && text[j] != '\'' {
            if text[j] == '\\' && j + 1 < n {
                let window = slice(text, j + 1, j + 6);
                if let Some((value, used)) = ansi_c_numeric(&window) {
                    buf.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                    j += 1 + used;
                    continue;
                }
                match text[j + 1] {
                    'n' => buf.push('\n'),
                    't' => buf.push('\t'),
                    '\\' => buf.push('\\'),
                    '\'' => buf.push('\''),
                    '"' => buf.push('"'),
                    'a' => buf.push('\u{7}'),
                    'r' => buf.push('\r'),
                    other => {
                        buf.push('\\');
                        buf.push(other);
                    }
                }
                j += 2;
                continue;
            }
            buf.push(text[j]);
            j += 1;
        }
        if j >= n {
            return Err(self.fail("unterminated quote"));
        }
        Ok((buf, j))
    }

    fn double_quote(&mut self, i: usize) -> Result<(String, usize, bool), ShellSyntax> {
        let text = self.text;
        let n = self.n;
        let mut j = i + 1;
        let mut buf = String::new();
        let mut subst = false;
        while j < n && text[j] != '"' {
            if text[j] == '\\' && j + 1 < n {
                if matches!(text[j + 1], '$' | '`' | '"' | '\\' | '\n') {
                    buf.push(text[j + 1]);
                } else {
                    buf.push(text[j]);
                    buf.push(text[j + 1]);
                }
                j += 2;
                continue;
            }
            if starts_with(text, j, "$(") {
                let end = self.balanced(j + 2, "$(", ')')?;
                self.extras
                    .subs
                    .push((slice(text, j + 2, end - 1), j + 2, end - 1));
                buf.push_str(&slice(text, j, end));
                j = end;
                subst = true;
                continue;
            }
            if starts_with(text, j, "${") {
                let end = self.balanced(j + 2, "${", '}')?;
                buf.push_str(&slice(text, j, end));
                j = end;
                subst = true;
                continue;
            }
            if text[j] == '`' {
                let Some(k) = find(text, '`', j + 1) else {
                    return Err(self.fail("unterminated backtick"));
                };
                self.extras.subs.push((slice(text, j + 1, k), j + 1, k));
                buf.push_str(&slice(text, j, k + 1));
                j = k + 1;
                subst = true;
                continue;
            }
            buf.push(text[j]);
            j += 1;
        }
        if j >= n {
            return Err(self.fail("unterminated quote"));
        }
        Ok((buf, j, subst))
    }

    fn read_heredocs(&mut self, mut i: usize) -> Result<usize, ShellSyntax> {
        let text = self.text;
        let n = self.n;
        let pending = std::mem::take(&mut self.pending);
        for (owner, delim, strip_tabs, quoted, op_at) in pending {
            let start = i;
            let mut lines: Vec<String> = Vec::new();
            loop {
                if i >= n {
                    self.at = op_at;
                    return Err(self.fail("unterminated heredoc"));
                }
                let j = find(text, '\n', i);
                let line = slice(text, i, j.unwrap_or(n));
                let end_line = j.unwrap_or(n);
                let compared = if strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    &line
                };
                if compared == delim {
                    owner.borrow_mut().heredocs.push(Operand {
                        text: lines.join("\n"),
                        quoted,
                        start,
                        end: i,
                    });
                    i = j.map_or(n, |j| j + 1);
                    break;
                }
                lines.push(line);
                i = j.map_or(n, |_| end_line + 1);
            }
        }
        Ok(i)
    }

    fn redirection(&mut self, i: usize) -> Result<usize, ShellSyntax> {
        let text = self.text;
        let n = self.n;
        if self.cur.as_ref().is_some_and(|cur| is_digits(&cur.0)) {
            self.cur = None; // an fd number before the operator
        }
        self.end_word(i);
        if starts_with(text, i, "<(") || starts_with(text, i, ">(") {
            let end = self.balanced(i + 2, "(", ')')?;
            self.extras
                .subs
                .push((slice(text, i + 2, end - 1), i + 2, end - 1));
            self.add(&slice(text, i, end), i, false, true);
            return Ok(end);
        }
        if starts_with(text, i, "<<<") {
            let (word, end, quoted) = self.target_word(i + 3)?;
            self.cmd.borrow_mut().herestrings.push(Operand {
                text: word,
                quoted,
                start: i + 3,
                end,
            });
            self.extras.redirects.push((i, end));
            return Ok(end);
        }
        if starts_with(text, i, "<<") {
            let j = i + 2;
            let strip_tabs = j < n && text[j] == '-';
            let (word, end, quoted) = self.target_word(if strip_tabs { j + 1 } else { j })?;
            self.pending
                .push((Rc::clone(&self.cmd), word, strip_tabs, quoted, i));
            self.extras.redirects.push((i, end));
            return Ok(end);
        }
        let mut j = i + 1;
        while j < n && matches!(text[j], '<' | '>' | '&' | '|') {
            j += 1;
        }
        if text[j - 1] == '&' && j < n && (text[j].is_numeric() || text[j] == '-') {
            self.extras.redirects.push((i, j + 1));
            return Ok(j + 1); // >&2, <&-
        }
        let (_, end, _) = self.target_word(j)?;
        self.extras.redirects.push((i, end));
        Ok(end)
    }

    fn run(mut self) -> Result<(Vec<Cmd>, Extras), ShellSyntax> {
        let text = self.text;
        let n = self.n;
        let mut i = 0;
        while i < n {
            self.at = i;
            let ch = text[i];
            if ch == '\n' {
                if self.pipe_open {
                    self.end_word(i); // `a |` + newline: the pipeline goes on
                } else {
                    self.end_command(i, false);
                }
                i += 1;
                i = self.read_heredocs(i)?;
                continue;
            }
            if ch == ' ' || ch == '\t' {
                self.end_word(i);
                i += 1;
                continue;
            }
            if ch == '#' && self.cur.is_none() {
                let end = find(text, '\n', i).unwrap_or(n);
                self.extras.comments.push((i, end));
                i = end;
                continue;
            }
            if ch == '\\' {
                let escaped = slice(text, i + 1, i + 2);
                self.add(&escaped, i, true, false);
                i += 2;
                continue;
            }
            if starts_with(text, i, "$'") {
                let (word, j) = self.ansi_c_quote(i)?;
                self.add(&word, i, true, false);
                i = j + 1;
                continue;
            }
            if ch == '\'' {
                let Some(j) = find(text, '\'', i + 1) else {
                    return Err(self.fail("unterminated quote"));
                };
                self.add(&slice(text, i + 1, j), i, true, false);
                i = j + 1;
                continue;
            }
            if ch == '"' {
                let (word, j, subst) = self.double_quote(i)?;
                self.add(&word, i, true, subst);
                i = j + 1;
                continue;
            }
            if starts_with(text, i, "$(") {
                let end = self.balanced(i + 2, "$(", ')')?;
                self.extras
                    .subs
                    .push((slice(text, i + 2, end - 1), i + 2, end - 1));
                self.add(&slice(text, i, end), i, false, true);
                i = end;
                continue;
            }
            if starts_with(text, i, "${") {
                let end = self.balanced(i + 2, "${", '}')?;
                self.add(&slice(text, i, end), i, false, true);
                i = end;
                continue;
            }
            if ch == '`' {
                let Some(j) = find(text, '`', i + 1) else {
                    return Err(self.fail("unterminated backtick"));
                };
                self.extras.subs.push((slice(text, i + 1, j), i + 1, j));
                self.add(&slice(text, i, j + 1), i, false, true);
                i = j + 1;
                continue;
            }
            if ch == '<' || ch == '>' || (ch == '&' && starts_with(text, i, "&>")) {
                i = self.redirection(i)?;
                continue;
            }
            if matches!(ch, ';' | '&' | '|' | '(' | ')') {
                let piped = ch == '|' && !starts_with(text, i, "||");
                self.end_command(i, piped);
                let mut j = i + 1;
                while j < n
                    && matches!(text[j], ';' | '&' | '|')
                    && matches!(text[j - 1], ';' | '&' | '|')
                {
                    j += 1;
                }
                i = j;
                continue;
            }
            self.add(&ch.to_string(), i, false, false);
            i += 1;
        }
        if let Some((_, _, _, _, op_at)) = self.pending.first() {
            self.at = *op_at;
            return Err(self.fail("unterminated heredoc"));
        }
        self.end_command(n, false);
        let commands = self
            .commands
            .into_iter()
            .map(|cmd| {
                Rc::try_unwrap(cmd).map_or_else(|rc| rc.borrow().clone(), RefCell::into_inner)
            })
            .collect();
        Ok((commands, self.extras))
    }
}

/// `re.match(r"x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|([0-7]{1,3})", window)`:
/// (code point, characters consumed).
fn ansi_c_numeric(window: &str) -> Option<(u32, usize)> {
    let chars: Vec<char> = window.chars().collect();
    let first = *chars.first()?;
    let (radix, max, skip) = match first {
        'x' => (16, 2, 1),
        'u' => (16, 4, 1),
        '0'..='7' => (8, 3, 0),
        _ => return None,
    };
    let digits: String = chars[skip..]
        .iter()
        .take(max)
        .take_while(|c| c.is_digit(radix))
        .collect();
    if digits.is_empty() {
        return None;
    }
    let value = u32::from_str_radix(&digits, radix).ok()?;
    Some((value, skip + digits.len()))
}

/// Python `_lex_shell`.
pub fn lex_shell(text: &[char]) -> Result<(Vec<Cmd>, Extras), ShellSyntax> {
    Lexer::new(text).run()
}

/// Python `_lex_partial`: the longest prefix the lexer can read, as
/// (commands, extras, rest) where `text[rest..]` is the unread tail.
pub fn lex_partial(text: &[char]) -> (Vec<Cmd>, Extras, usize) {
    let mut end = text.len();
    for _ in 0..PARTIAL_RETRIES {
        match lex_shell(&text[..end]) {
            Ok((commands, extras)) => return (commands, extras, end),
            Err(syntax) => {
                end = syntax.at.min(end.saturating_sub(1));
            }
        }
    }
    (Vec::new(), Extras::default(), 0)
}

/// Python `_option_letters`: (option names seen, index of the first operand).
pub fn option_letters(
    args: &[String],
    value_letters: &str,
    value_longs: &[&str],
    stop_at_operand: bool,
) -> (Vec<String>, usize) {
    let mut letters = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" {
            return (letters, i + 1);
        }
        if tok.starts_with("--") {
            let name = tok.split_once('=').map_or(tok.as_str(), |(name, _)| name);
            letters.push(name.to_owned());
            i += if value_longs.contains(&name) && !tok.contains('=') {
                2
            } else {
                1
            };
            continue;
        }
        let mut chars = tok.chars();
        let sign = chars.next();
        if matches!(sign, Some('-' | '+')) && tok.chars().count() > 1 {
            let body: Vec<char> = chars.collect();
            for (k, ch) in body.iter().enumerate() {
                letters.push(format!("{}{ch}", sign.unwrap_or('-')));
                if value_letters.contains(*ch) {
                    if body[k + 1..].is_empty() {
                        i += 1; // the value is the next word
                    }
                    break;
                }
            }
            i += 1;
            continue;
        }
        if stop_at_operand {
            break;
        }
        i += 1;
    }
    (letters, i)
}

/// Python `_python_kv_args`: the kv args when python args run the kv module.
pub fn python_kv_args(args: &[String]) -> Option<Vec<String>> {
    let mut i = 0;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--" || !tok.starts_with('-') || tok == "-" {
            return None;
        }
        if tok.starts_with("--") {
            i += if tok == "--check-hash-based-pycs" {
                2
            } else {
                1
            };
            continue;
        }
        let body: Vec<char> = tok.chars().skip(1).collect();
        let mut advanced = false;
        for (k, ch) in body.iter().enumerate() {
            match ch {
                'm' => {
                    let inline: String = body[k + 1..].iter().collect();
                    let module = if inline.is_empty() {
                        args.get(i + 1).cloned().unwrap_or_default()
                    } else {
                        inline.clone()
                    };
                    let after = if inline.is_empty() {
                        args.get(i + 2..).unwrap_or(&[]).to_vec()
                    } else {
                        args.get(i + 1..).unwrap_or(&[]).to_vec()
                    };
                    return if KV_MODULES.contains(&module.as_str()) {
                        Some(after)
                    } else {
                        None
                    };
                }
                'c' => return None,
                'W' | 'X' => {
                    if body[k + 1..].is_empty() {
                        i += 1;
                    }
                    advanced = true;
                    break;
                }
                _ => {}
            }
        }
        let _ = advanced;
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<Vec<String>> {
        let (commands, _) = lex_shell(&chars(text)).unwrap();
        commands.into_iter().map(|c| c.words).collect()
    }

    #[test]
    fn splits_simple_commands() {
        assert_eq!(
            words("ls -la | grep x; echo 'a b' \"c $(d)\""),
            vec![
                vec!["ls".to_owned(), "-la".to_owned()],
                vec!["grep".to_owned(), "x".to_owned()],
                vec!["echo".to_owned(), "a b".to_owned(), "c $(d)".to_owned()],
            ]
        );
        let (commands, extras) =
            lex_shell(&chars("cat <<EOF > out 2>&1\nhello\nEOF\nkv get X")).unwrap();
        assert_eq!(commands[0].words, vec!["cat".to_owned()]);
        assert_eq!(commands[0].heredocs[0].text, "hello");
        assert_eq!(commands[1].words, vec!["kv", "get", "X"]);
        assert_eq!(extras.redirects.len(), 3);
    }

    #[test]
    fn partial_backs_off_to_the_failing_construct() {
        let text = chars("echo ok; kv get 'unterminated");
        let (commands, _, rest) = lex_partial(&text);
        assert_eq!(commands.len(), 2);
        assert_eq!(rest, 16);
        assert!(lex_shell(&chars("echo $(")).is_err());
    }

    #[test]
    fn ansi_c_and_options() {
        assert_eq!(words("echo $'a\\x41\\101\\n'")[0][1], "aAA\n");
        let args: Vec<String> = ["-u", "-Bm", "kv", "get", "X"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            python_kv_args(&args),
            Some(vec!["get".to_owned(), "X".to_owned()])
        );
        let args: Vec<String> = ["-mkv.cli", "ls"].iter().map(|s| s.to_string()).collect();
        assert_eq!(python_kv_args(&args), Some(vec!["ls".to_owned()]));
        let args: Vec<String> = ["-c", "print(1)"].iter().map(|s| s.to_string()).collect();
        assert_eq!(python_kv_args(&args), None);
        let args: Vec<String> = ["-u", "root", "--chdir=/x", "-n", "cmd"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (letters, i) = option_letters(&args, "u", &["--chdir"], true);
        assert_eq!(letters, vec!["-u", "--chdir", "-n"]);
        assert_eq!(i, 4);
        assert_eq!(command_name("/usr/bin/KV.EXE"), "kv");
    }
}
