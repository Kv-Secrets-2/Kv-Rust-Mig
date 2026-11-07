//! Prompts as `kv/cli.py` makes them: `input()` on stdin/stdout, `getpass.getpass` on
//! `/dev/tty`, and the owner's hidden read on the verified controlling terminal
//! (`kv/owner_terminal.py`).

use std::io::{self, BufRead, Read, Write};

#[derive(Debug)]
pub enum PromptError {
    /// Python `EOFError`: the input ended before a line did.
    Eof,
    /// `owner_terminal.TerminalRefused`: the message is the whole refusal sentence.
    Refused(String),
    Io(io::Error),
}

impl From<io::Error> for PromptError {
    fn from(error: io::Error) -> Self {
        PromptError::Io(error)
    }
}

#[cfg(target_os = "macos")]
const REMEDY: &str = "run this command directly in your own macOS terminal without redirection.";
#[cfg(all(unix, not(target_os = "macos")))]
const REMEDY: &str = "run this command directly in your own Linux terminal without redirection.";
#[cfg(not(unix))]
const REMEDY: &str = "run this command directly in your own console window without redirection.";

pub const NOT_TEXT: &str =
    "The answer was not UTF-8 text; nothing was read. Type it again in a UTF-8 terminal.";

pub fn refusal() -> String {
    format!("Owner confirmation needs stdin and stdout on the controlling terminal; {REMEDY}")
}

/// `sys.stdin.isatty()`.
pub fn stdin_is_tty() -> bool {
    #[cfg(unix)]
    {
        rustix::termios::isatty(rustix::stdio::stdin())
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// `sys.stdout.isatty()`.
pub fn stdout_is_tty() -> bool {
    #[cfg(unix)]
    {
        rustix::termios::isatty(rustix::stdio::stdout())
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Python `input(prompt)`: the prompt goes to stdout, the line comes from stdin without
/// its newline; EOF before any byte is `EOFError`.
pub fn input(prompt: &str) -> Result<String, PromptError> {
    {
        let mut out = io::stdout().lock();
        out.write_all(prompt.as_bytes())?;
        out.flush()?;
    }
    let mut line = Vec::new();
    let read = io::stdin().lock().read_until(b'\n', &mut line)?;
    if read == 0 {
        return Err(PromptError::Eof);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

#[cfg(unix)]
fn read_line_fd(fd: &impl rustix::fd::AsFd) -> Result<Vec<u8>, PromptError> {
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = rustix::io::read(fd, &mut byte).map_err(io::Error::from)?;
        if n == 0 {
            return Err(PromptError::Eof);
        }
        if byte[0] == b'\n' {
            return Ok(answer);
        }
        answer.push(byte[0]);
    }
}

#[cfg(unix)]
fn write_all_fd(fd: &impl rustix::fd::AsFd, mut data: &[u8]) -> Result<(), PromptError> {
    while !data.is_empty() {
        let written = rustix::io::write(fd, data).map_err(io::Error::from)?;
        if written == 0 {
            return Err(PromptError::Refused(refusal()));
        }
        data = &data[written..];
    }
    Ok(())
}

/// Python `getpass.getpass(prompt)`: prompt and hidden line on `/dev/tty`; without one,
/// a warning on stderr and a plain read of stdin (echo stays on), as CPython does.
pub fn getpass(prompt: &str) -> Result<String, PromptError> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        if let Ok(tty) = rustix::fs::open(
            "/dev/tty",
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            return hidden_read(&tty, prompt, true);
        }
        if stdin_is_tty() {
            // CPython: no /dev/tty, so termios on the stdin descriptor itself.
            return hidden_read(&rustix::stdio::stdin(), prompt, true);
        }
        let mut err = io::stderr().lock();
        let _ = err.write_all(b"Warning: Password input may be echoed.\n");
        let _ = err.write_all(prompt.as_bytes());
        let _ = err.flush();
        drop(err);
        let mut line = Vec::new();
        let read = io::stdin().lock().read_until(b'\n', &mut line)?;
        if read == 0 {
            return Err(PromptError::Eof);
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        Ok(String::from_utf8_lossy(&line).into_owned())
    }
    #[cfg(not(unix))]
    {
        let _ = prompt;
        Err(PromptError::Refused(refusal()))
    }
}

/// `_Terminal.read(prompt, hidden=True)`: canonical mode with signals, echo off with
/// `TCSAFLUSH`, prompt written to the terminal, newline written after a completed read.
#[cfg(unix)]
fn hidden_read(
    tty: &impl rustix::fd::AsFd,
    prompt: &str,
    lossy: bool,
) -> Result<String, PromptError> {
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
    let previous = tcgetattr(tty).map_err(|_| PromptError::Refused(refusal()))?;
    let mut settings = previous.clone();
    settings.local_modes |= LocalModes::ICANON | LocalModes::ISIG;
    settings.local_modes &= !(LocalModes::ECHO | LocalModes::ECHONL);
    tcsetattr(tty, OptionalActions::Flush, &settings)
        .map_err(|_| PromptError::Refused(refusal()))?;
    let result = (|| {
        write_all_fd(tty, prompt.as_bytes())?;
        read_line_fd(tty)
    })();
    let restored = tcsetattr(tty, OptionalActions::Now, &previous);
    let answer = result?;
    restored.map_err(|_| PromptError::Refused(refusal()))?;
    write_all_fd(tty, b"\n")?;
    if lossy {
        Ok(String::from_utf8_lossy(&answer).into_owned())
    } else {
        String::from_utf8(answer).map_err(|_| PromptError::Refused(NOT_TEXT.to_owned()))
    }
}

/// `owner_terminal._check(fd)`: stdin and stdout are one terminal, the caller's
/// controlling one, and so is the opened `/dev/tty`.
#[cfg(unix)]
fn check_controlling(tty: &impl rustix::fd::AsFd) -> Result<(), PromptError> {
    use rustix::fd::AsFd;
    use rustix::process::getpgrp;
    use rustix::termios::{isatty, tcgetpgrp, ttyname};
    use std::os::unix::fs::MetadataExt;
    let refused = || PromptError::Refused(refusal());
    let stdin = rustix::stdio::stdin();
    let stdout = rustix::stdio::stdout();
    if !isatty(stdin) || !isatty(stdout) {
        return Err(refused());
    }
    let group = getpgrp();
    for fd in [stdin.as_fd(), stdout.as_fd(), tty.as_fd()] {
        if tcgetpgrp(fd).map_err(|_| refused())? != group {
            return Err(refused());
        }
    }
    let device = rustix::fs::fstat(stdin).map_err(|_| refused())?.st_rdev;
    if rustix::fs::fstat(stdout).map_err(|_| refused())?.st_rdev != device {
        return Err(refused());
    }
    let name0 = ttyname(stdin, Vec::new()).map_err(|_| refused())?;
    let name1 = ttyname(stdout, Vec::new()).map_err(|_| refused())?;
    if name0 != name1 || name0.as_bytes() == b"/dev/ptmx" || name0.as_bytes() == b"/dev/tty" {
        return Err(refused());
    }
    let path = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(name0.as_bytes());
    let metadata = std::fs::metadata(path).map_err(|_| refused())?;
    #[allow(clippy::useless_conversion)] // st_rdev is not u64 on every platform
    let same_device = u64::try_from(device).ok() == Some(metadata.rdev());
    if !same_device {
        return Err(refused());
    }
    Ok(())
}

/// `owner_terminal.read_secret(prompt)`.
pub fn owner_read_secret(prompt: &str) -> Result<String, PromptError> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        let tty = rustix::fs::open(
            "/dev/tty",
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PromptError::Refused(refusal()))?;
        check_controlling(&tty)?;
        hidden_read(&tty, prompt, false)
    }
    #[cfg(not(unix))]
    {
        let _ = prompt;
        Err(PromptError::Refused(refusal()))
    }
}

/// Read everything on stdin (for `KEY` values piped to commands that accept them).
#[allow(dead_code)]
pub fn read_stdin() -> io::Result<String> {
    let mut text = String::new();
    io::stdin().lock().read_to_string(&mut text)?;
    Ok(text)
}
