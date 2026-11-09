//! The daemon side of the MCP server: project discovery, the authenticated
//! status check (`kv.agent.is_agent_running`) and requests through `kv-proto`.

use std::path::{Path, PathBuf};

use crate::pyerr;
use crate::pyval::PyValue;

/// `kv.config.find_project_root()` from the current directory.
pub fn find_project_root() -> Option<PathBuf> {
    let start = std::env::current_dir().ok()?;
    for path in start.ancestors() {
        if let Ok(metadata) = std::fs::symlink_metadata(path.join(".secrets"))
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
        {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// Why a daemon request did not produce a reply, as Python's exceptions say it.
#[derive(Debug, Clone, PartialEq)]
pub enum RequestError {
    /// `OutdatedServiceError`: the fixed refusal text.
    Outdated(String),
    /// Any other exception: its class name and `str(exc)`.
    Exception { type_name: String, message: String },
}

impl RequestError {
    pub fn exception(type_name: &str, message: impl Into<String>) -> Self {
        Self::Exception {
            type_name: type_name.into(),
            message: message.into(),
        }
    }
}

fn from_protocol(error: kv_proto::ProtocolError) -> RequestError {
    use kv_proto::ProtocolError;
    match error {
        ProtocolError::Message(message) if message == kv_proto::OUTDATED_SERVICE_REFUSAL => {
            RequestError::Outdated(message)
        }
        ProtocolError::Io(error) => {
            RequestError::exception(pyerr::type_name(&error), pyerr::message(&error))
        }
        ProtocolError::Json(error) => RequestError::exception("JSONDecodeError", error.to_string()),
        ProtocolError::InvalidUtf8(message) => RequestError::exception(
            "UnicodeDecodeError",
            message
                .strip_prefix("UnicodeDecodeError: ")
                .unwrap_or(&message),
        ),
        ProtocolError::RequestTooLarge | ProtocolError::ResponseTooLarge => {
            RequestError::exception("MessageTooLargeError", error.to_string())
        }
        other => RequestError::exception("RuntimeError", other.to_string()),
    }
}

/// `kv.agent.agent_request(cmd, **fields)` for this project's daemon.
pub fn request(
    root: &Path,
    cmd: &str,
    fields: &[(&str, PyValue)],
) -> Result<PyValue, RequestError> {
    let mut map = serde_json::Map::new();
    for (name, value) in fields {
        let Some(value) = value.to_json() else {
            return Err(RequestError::exception(
                "ValueError",
                "Out of range float values are not JSON compliant",
            ));
        };
        map.insert((*name).to_owned(), value);
    }
    kv_proto::agent_request(root, cmd, &map)
        .map(|reply| PyValue::from_json(&reply))
        .map_err(from_protocol)
}

#[cfg(unix)]
mod status {
    use std::io::Read;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn owned(metadata: &std::fs::Metadata) -> bool {
        metadata.uid() == rustix::process::getuid().as_raw()
    }

    fn private_dir(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && owned(&metadata)
                && metadata.mode() & 0o777 == 0o700
        })
    }

    fn private_socket(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.file_type().is_socket() && owned(&metadata) && metadata.mode() & 0o777 == 0o600
        })
    }

    fn private_text(path: &Path) -> String {
        use rustix::fs::{Mode, OFlags, open};
        let Ok(fd) = open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return String::new();
        };
        let mut file = std::fs::File::from(fd);
        let (Ok(opened), Ok(named)) = (file.metadata(), std::fs::symlink_metadata(path)) else {
            return String::new();
        };
        if !opened.is_file()
            || named.file_type().is_symlink()
            || !owned(&opened)
            || opened.mode() & 0o777 != 0o600
            || (opened.dev(), opened.ino()) != (named.dev(), named.ino())
        {
            return String::new();
        }
        let mut bytes = Vec::new();
        if Read::by_ref(&mut file)
            .take(4096)
            .read_to_end(&mut bytes)
            .is_err()
        {
            return String::new();
        }
        crate::pyval::py_strip(&String::from_utf8_lossy(&bytes)).to_owned()
    }

    pub fn is_agent_running(root: &Path) -> bool {
        let Ok(runtime) = kv_proto::runtime_dir() else {
            return false;
        };
        let (Ok(socket_path), Ok(token_path)) = (
            kv_proto::agent_socket_path(Some(root)),
            kv_proto::agent_token_path(Some(root)),
        ) else {
            return false;
        };
        if !private_dir(&runtime) || !private_socket(&socket_path) {
            return false;
        }
        let token = private_text(&token_path);
        let deadline = Instant::now() + Duration::from_secs(2);
        let Ok(mut socket) = kv_proto::connect_unix(&socket_path, Some(deadline)) else {
            return false;
        };
        let payload = serde_json::json!({"cmd": "status", "token": token});
        let Ok(payload) = kv_store::pyjson::to_vec_python(&payload, false) else {
            return false;
        };
        if kv_proto::write_all_until(&mut socket, &payload, Some(deadline)).is_err() {
            return false;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let Ok(serde_json::Value::Object(reply)) =
            kv_proto::read_complete_reply(&mut socket, deadline)
        else {
            return false;
        };
        let reply = crate::pyval::PyValue::from_json(&serde_json::Value::Object(reply));
        if reply.get("error").is_some_and(|error| error.truthy()) {
            return false;
        }
        let expected = root.to_string_lossy();
        if !expected.is_empty()
            && reply.get("root").and_then(|value| value.as_str()) != Some(&*expected)
        {
            return false;
        }
        reply.get("running").is_some_and(|running| running.truthy())
    }
}

/// `kv.agent.is_agent_running(root)`: an authenticated status reply for this project.
#[cfg(unix)]
pub fn is_agent_running(root: &Path) -> bool {
    status::is_agent_running(root)
}

#[cfg(not(unix))]
pub fn is_agent_running(_root: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_reply_utf8_preserves_python_exception_class_and_message() {
        let message = "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte";
        assert_eq!(
            from_protocol(kv_proto::ProtocolError::InvalidUtf8(format!(
                "UnicodeDecodeError: {message}"
            ))),
            RequestError::exception("UnicodeDecodeError", message),
        );
    }
}
