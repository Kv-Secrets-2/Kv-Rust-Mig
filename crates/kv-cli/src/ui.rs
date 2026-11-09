//! Terminal output exactly as `kv/cli.py` prints it: the ANSI palette (disabled by
//! `NO_COLOR` or `TERM=dumb`, never by a pipe) and the `_info`/`_success`/`_error`/
//! `_warn`/`_header`/`_box`/`_cmd`/`_kv_line` line shapes.

use std::io::Write;

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct Palette {
    pub reset: &'static str,
    pub bold: &'static str,
    pub dim: &'static str,
    pub green: &'static str,
    pub yellow: &'static str,
    pub cyan: &'static str,
    pub red: &'static str,
    pub value: &'static str,
    pub muted: &'static str,
    pub white: &'static str,
    pub blue: &'static str,
}

const PLAIN: Palette = Palette {
    reset: "",
    bold: "",
    dim: "",
    green: "",
    yellow: "",
    cyan: "",
    red: "",
    value: "",
    muted: "",
    white: "",
    blue: "",
};

const ANSI: Palette = Palette {
    reset: "\x1b[0m",
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    green: "\x1b[38;2;100;200;150m",
    yellow: "\x1b[38;2;255;200;100m",
    cyan: "\x1b[38;2;140;180;255m",
    red: "\x1b[38;2;255;100;100m",
    value: "\x1b[38;2;150;220;130m",
    muted: "\x1b[38;2;120;120;140m",
    white: "\x1b[38;2;220;220;230m",
    blue: "\x1b[38;2;100;150;255m",
};

/// `kv/cli.py` decides the palette once at import time from the environment.
pub fn palette() -> Palette {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    let dumb = std::env::var_os("TERM").is_some_and(|value| value == "dumb");
    if no_color || dumb { PLAIN } else { ANSI }
}

pub fn dot_on(p: &Palette) -> String {
    format!("{}\u{25cf}{}", p.green, p.reset)
}

pub fn dot_off(p: &Palette) -> String {
    format!("{}\u{25cb}{}", p.muted, p.reset)
}

/// `print(...)`: a lost stdout must not turn into a second error (Python's `_quiet_print`
/// semantics are used everywhere the CLI prints after authentication).
pub fn out(text: &str) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(text.as_bytes());
    let _ = lock.write_all(b"\n");
    let _ = lock.flush();
}

pub fn blank() {
    out("");
}

pub fn info(msg: &str) {
    out(&format!("  {msg}"));
}

pub fn success(p: &Palette, msg: &str) {
    out(&format!("  {}\u{2713}{} {msg}", p.green, p.reset));
}

pub fn error(p: &Palette, msg: &str) {
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    let _ = writeln!(lock, "  {}\u{2717} {msg}{}", p.red, p.reset);
}

pub fn warn(p: &Palette, msg: &str) {
    out(&format!("  {}!{} {msg}", p.yellow, p.reset));
}

pub fn header(p: &Palette, msg: &str) {
    out(&format!(
        "\n  {}{}kv{} {}\u{2014}{} {msg}",
        p.bold, p.cyan, p.reset, p.dim, p.reset
    ));
}

#[allow(dead_code)]
pub enum BoxStyle {
    Info,
    Warn,
    Ok,
}

/// `_box`: width is the longest line (in characters, like Python's `len`) plus two.
pub fn boxed(p: &Palette, lines: &[&str], style: BoxStyle) {
    let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0) + 2;
    let color = match style {
        BoxStyle::Info => p.cyan,
        BoxStyle::Warn => p.yellow,
        BoxStyle::Ok => p.green,
    };
    let bar: String = "\u{2500}".repeat(width);
    out(&format!("  {color}\u{250c}{bar}\u{2510}{}", p.reset));
    for line in lines {
        let pad = (width - 2).saturating_sub(line.chars().count());
        out(&format!(
            "  {color}\u{2502}{} {line}{} {color}\u{2502}{}",
            p.reset,
            " ".repeat(pad),
            p.reset
        ));
    }
    out(&format!("  {color}\u{2514}{bar}\u{2518}{}", p.reset));
}

/// `_cmd`: the name padded to 27 columns, or followed by two spaces when longer.
pub fn cmd(p: &Palette, name: &str, desc: &str) {
    let count = name.chars().count();
    let padded = if count < 27 {
        format!("{name}{}", " ".repeat(27 - count))
    } else {
        format!("{name}  ")
    };
    out(&format!(
        "    {}{padded}{}{}{desc}{}",
        p.yellow, p.reset, p.dim, p.reset
    ));
}

pub fn kv_line(p: &Palette, key: &str, value: &str, extra: &str) {
    let mut parts = vec![format!("  {}{key}{}", p.yellow, p.reset)];
    if !value.is_empty() {
        parts.push(format!("{}{value}{}", p.value, p.reset));
    }
    if !extra.is_empty() {
        parts.push(format!("{}{extra}{}", p.muted, p.reset));
    }
    out(&parts.join("  "));
}
