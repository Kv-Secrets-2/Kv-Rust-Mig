//! Python's names and words for OS errors, as kv's replies quote them.

use std::io;

/// The `OSError` subclass Python raises for this error.
pub fn type_name(error: &io::Error) -> &'static str {
    if error.kind() == io::ErrorKind::TimedOut {
        return "TimeoutError";
    }
    let Some(code) = error.raw_os_error() else {
        return "OSError";
    };
    #[cfg(unix)]
    {
        use rustix::io::Errno;
        let errno = Errno::from_raw_os_error(code);
        let names = [
            (Errno::ACCESS, "PermissionError"),
            (Errno::PERM, "PermissionError"),
            (Errno::NOENT, "FileNotFoundError"),
            (Errno::NOTDIR, "NotADirectoryError"),
            (Errno::ISDIR, "IsADirectoryError"),
            (Errno::EXIST, "FileExistsError"),
            (Errno::TIMEDOUT, "TimeoutError"),
            (Errno::CONNREFUSED, "ConnectionRefusedError"),
            (Errno::CONNRESET, "ConnectionResetError"),
            (Errno::CONNABORTED, "ConnectionAbortedError"),
            (Errno::PIPE, "BrokenPipeError"),
            (Errno::AGAIN, "BlockingIOError"),
            (Errno::INTR, "InterruptedError"),
        ];
        for (candidate, name) in names {
            if errno == candidate {
                return name;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = code;
    match error.kind() {
        io::ErrorKind::NotFound => "FileNotFoundError",
        io::ErrorKind::PermissionDenied => "PermissionError",
        io::ErrorKind::ConnectionRefused => "ConnectionRefusedError",
        _ => "OSError",
    }
}

/// `str(exc)` for an OS error without a file name: `[Errno N] message`.
pub fn message(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(code) => {
            let text = io::Error::from_raw_os_error(code).to_string();
            let suffix = format!(" (os error {code})");
            let text = text.strip_suffix(&suffix).unwrap_or(&text);
            format!("[Errno {code}] {text}")
        }
        None if error.kind() == io::ErrorKind::TimedOut => "timed out".into(),
        None => error.to_string(),
    }
}
