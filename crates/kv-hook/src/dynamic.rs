//! Layer 2 of Python `kv/hook.py`: what the daemon knows about files created
//! during `kv_run`, and the service-state evidence the hook weighs when the
//! daemon does not answer. Every unanswered question is a refusal.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

pub const DYNAMIC_UNAVAILABLE_TAIL: &str = "Retry. If this persists, ask the owner to restart kv \
    ('kv lock' then 'kv unlock'); the restart forgets files tracked before it.";

/// Python `_dynamic_unavailable`.
pub fn dynamic_unavailable(what: &str) -> String {
    format!(
        "[kv-secrets] blocked: the kv daemon is running but could not confirm {what}. \
         {DYNAMIC_UNAVAILABLE_TAIL}"
    )
}

/// Python `_service_unanswered(what, state)`.
pub fn service_unanswered(what: &str, state: &str) -> String {
    let body = match state {
        "dead" => format!(
            "kv's service did not answer — its files are left in the runtime folder and nothing \
             is listening — so kv cannot confirm {what}. 'kv lock' reports the state; 'kv unlock' \
             tries to start a fresh service and write its files over the ones left; the restart \
             forgets files tracked before it."
        ),
        "broken" => format!(
            "kv's service files are left behind and what answers on its address could not be \
             confirmed as that service, so kv cannot confirm {what}. 'kv lock' reports the state; \
             'kv unlock' tries to start a fresh service; the restart forgets files tracked before \
             it."
        ),
        "unknown" => format!(
            "nothing answers on kv's address and the runtime folder could not be fully searched \
             — so kv cannot confirm {what}. 'kv lock' reports the state; make the folder readable \
             again or run 'kv unlock' to try to start a fresh service; the restart forgets files \
             tracked before it."
        ),
        "unknown-untried" => format!(
            "an endpoint that may answer on kv's address was never tried and the runtime folder \
             could not be fully searched — so kv cannot confirm {what}. 'kv lock' reports the \
             state; make the folder readable again or run 'kv unlock' to try to start a fresh \
             service; the restart forgets files tracked before it."
        ),
        "unknown-inconclusive" => format!(
            "an endpoint on kv's address was tried but its answer could not be judged and the \
             runtime folder could not be fully searched — so kv cannot confirm {what}. 'kv lock' \
             reports the state; make the folder readable again or run 'kv unlock' to try to start \
             a fresh service; the restart forgets files tracked before it."
        ),
        "unchecked" => format!(
            "kv cannot check whether a service is still on kv's address — leftover files are in \
             the runtime folder and the socket on kv's address could not be checked — so kv \
             cannot confirm {what}. 'kv lock' reports the state; 'kv unlock' tries to start a \
             fresh service; the restart forgets files tracked before it."
        ),
        "unchecked-inconclusive" => format!(
            "kv cannot check whether a service is still on kv's address — leftover files are in \
             the runtime folder and the socket on kv's address was tried but its answer could not \
             be judged — so kv cannot confirm {what}. 'kv lock' reports the state; 'kv unlock' \
             tries to start a fresh service; the restart forgets files tracked before it."
        ),
        "dead-inconclusive" => format!(
            "kv's service did not answer — its files are left in the runtime folder and an \
             endpoint on kv's address was tried but its answer could not be judged — so kv cannot \
             confirm {what}. 'kv lock' reports the state; 'kv unlock' tries to start a fresh \
             service and write its files over the ones left; the restart forgets files tracked \
             before it."
        ),
        _ => format!(
            "a service is on kv's address but did not answer a status request, so kv cannot \
             confirm {what}. 'kv lock' reports the state; 'kv unlock' tries to start a fresh \
             service; the restart forgets files tracked before it."
        ),
    };
    format!("[kv-secrets] blocked: {body}")
}

/// What one status exchange saw (Python `_status_reply_arrived`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrived {
    /// Every endpoint that could answer refused, or was verified gone.
    Refused,
    /// An endpoint that may answer was never tried (its privacy checks refuse it).
    Untested,
    /// An endpoint was tried but its answer could not be judged.
    Unjudged,
    /// A connect happened but no reply the service really sends came back.
    NoReply,
    /// A status reply or an error reply arrived.
    Reply,
}

/// The daemon as the hook sees it.
pub trait Agent {
    /// Python `kv.agent.is_agent_running()`.
    fn is_running(&self) -> bool;
    /// Python `agent_request(cmd, **kwargs)`: `None` when the request failed.
    fn request(&self, cmd: &str, fields: &Map<String, Value>) -> Option<Value>;
    /// Python `_agent_status_check()`: (running, arrived).
    fn status_check(&self) -> (bool, Arrived);
    /// Python `_agent_service_state(arrived)`.
    fn service_state(&self, arrived: Arrived) -> String;
}

/// Python `_tracked_listing`: the files created during `kv_run`, `None` when
/// the daemon's answer cannot be trusted.
pub fn tracked_listing(agent: &dyn Agent) -> Option<Vec<String>> {
    let response = agent.request("tracked_files", &Map::new())?;
    let Value::Object(reply) = response else {
        return None;
    };
    if reply.contains_key("error") {
        return None;
    }
    let Some(Value::Array(files)) = reply.get("files") else {
        return None;
    };
    files
        .iter()
        .map(|file| file.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()
}

/// Python `_exact_tracked`.
pub fn exact_tracked(agent: &dyn Agent, path: &str) -> Option<bool> {
    let mut fields = Map::new();
    fields.insert("path".into(), Value::String(path.to_owned()));
    let response = agent.request("check_file", &fields)?;
    let Value::Object(reply) = response else {
        return None;
    };
    if reply.contains_key("error") {
        return None;
    }
    reply.get("tracked").and_then(Value::as_bool)
}

/// The real daemon of the project at `root`, reached over its Unix socket.
pub struct SocketAgent {
    pub root: PathBuf,
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

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
        String::from_utf8_lossy(&bytes).trim().to_owned()
    }

    struct Endpoints {
        runtime: PathBuf,
        socket: PathBuf,
        token: PathBuf,
        pid: PathBuf,
    }

    fn endpoints(root: &Path) -> Option<Endpoints> {
        Some(Endpoints {
            runtime: kv_proto::runtime_dir().ok()?,
            socket: kv_proto::agent_socket_path(Some(root)).ok()?,
            token: kv_proto::agent_token_path(Some(root)).ok()?,
            pid: kv_proto::agent_pid_path(Some(root)).ok()?,
        })
    }

    /// Python `_unix_socket_problem` is Some: the runtime folder or the socket fails privacy.
    fn socket_problem(points: &Endpoints) -> bool {
        !private_dir(&points.runtime) || !private_socket(&points.socket)
    }

    /// One status exchange on an already connected socket: Python's reply judgement.
    fn exchange_status(
        socket: &mut std::os::unix::net::UnixStream,
        token: &str,
        deadline: Instant,
    ) -> Option<Map<String, Value>> {
        let payload = serde_json::json!({"cmd": "status", "token": token});
        let payload = kv_store::pyjson::to_vec_python(&payload, false).ok()?;
        kv_proto::write_all_until(socket, &payload, Some(deadline)).ok()?;
        match kv_proto::read_complete_reply(socket, deadline).ok()? {
            Value::Object(reply) => Some(reply),
            _ => None,
        }
    }

    fn is_status_reply(reply: &Map<String, Value>) -> bool {
        reply.get("running") == Some(&Value::Bool(true))
            && reply.get("root").is_some_and(Value::is_string)
    }

    /// Python `_status_reply_arrived`.
    fn status_reply_arrived(points: &Endpoints) -> Arrived {
        if socket_problem(points) {
            return match std::fs::symlink_metadata(&points.socket) {
                Ok(meta) if meta.file_type().is_socket() || meta.file_type().is_symlink() => {
                    Arrived::Untested
                }
                Ok(_) => Arrived::Refused,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Arrived::Refused,
                Err(_) => Arrived::Untested,
            };
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut socket = match kv_proto::connect_unix(&points.socket, Some(deadline)) {
            Ok(socket) => socket,
            Err(error) => {
                return match error.kind() {
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => {
                        Arrived::Refused
                    }
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                        Arrived::NoReply
                    }
                    _ => Arrived::Unjudged,
                };
            }
        };
        let token = private_text(&points.token);
        match exchange_status(&mut socket, &token, deadline) {
            Some(reply)
                if is_status_reply(&reply) || reply.get("error").is_some_and(Value::is_string) =>
            {
                Arrived::Reply
            }
            _ => Arrived::NoReply,
        }
    }

    /// Python `_agent_service_files_in_use`.
    fn service_files_in_use(points: &Endpoints) -> bool {
        if !private_socket(&points.socket) {
            return false;
        }
        let deadline = Instant::now() + Duration::from_secs(4);
        let Ok(mut socket) = kv_proto::connect_unix(&points.socket, Some(deadline)) else {
            return false;
        };
        let token = private_text(&points.token);
        exchange_status(&mut socket, &token, deadline).is_some_and(|reply| is_status_reply(&reply))
    }

    /// Python `_agent_runtime_inspection`: (found, unchecked) names.
    fn runtime_inspection(points: &Endpoints) -> (Vec<String>, Vec<String>) {
        let wanted: Vec<(String, &Path)> = [&points.pid, &points.token, &points.socket]
            .into_iter()
            .map(|path| {
                (
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    path.as_path(),
                )
            })
            .collect();
        match std::fs::read_dir(&points.runtime) {
            Ok(entries) => {
                let names: Vec<String> = entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect();
                let found = wanted
                    .iter()
                    .filter(|(name, path)| names.contains(name) && !path.is_dir())
                    .map(|(name, _)| name.clone())
                    .collect();
                (found, Vec::new())
            }
            Err(_) => {
                let mut found = Vec::new();
                let mut unchecked = Vec::new();
                for (name, path) in &wanted {
                    match std::fs::symlink_metadata(path) {
                        Ok(meta) => {
                            if !meta.is_dir() {
                                found.push(name.clone());
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => unchecked.push(name.clone()),
                    }
                }
                (found, unchecked)
            }
        }
    }

    /// Python `_agent_service_state`.
    fn service_state(points: &Endpoints, arrived: Arrived) -> &'static str {
        if arrived == Arrived::NoReply {
            return "stuck";
        }
        let (found, unchecked) = runtime_inspection(points);
        let residue = found.iter().any(|name| !name.ends_with(".sock"));
        let sock_found = found.iter().any(|name| name.ends_with(".sock"));
        let sock_unknown = unchecked.iter().any(|name| name.ends_with(".sock"));
        match arrived {
            Arrived::Reply => {
                if residue {
                    "broken"
                } else if sock_found {
                    if service_files_in_use(points) {
                        "answered"
                    } else {
                        "broken"
                    }
                } else {
                    "answered"
                }
            }
            Arrived::Untested => {
                if sock_found || (sock_unknown && !found.is_empty()) {
                    "unchecked"
                } else if residue {
                    "dead"
                } else if !unchecked.is_empty() {
                    "unknown-untried"
                } else {
                    "absent"
                }
            }
            Arrived::Unjudged => {
                if sock_found || (sock_unknown && !found.is_empty()) {
                    "unchecked-inconclusive"
                } else if residue {
                    "dead-inconclusive"
                } else if !unchecked.is_empty() {
                    "unknown-inconclusive"
                } else {
                    "absent"
                }
            }
            Arrived::Refused | Arrived::NoReply => {
                if residue || (!found.is_empty() && unchecked.is_empty()) {
                    "dead"
                } else if !unchecked.is_empty() {
                    "unknown"
                } else {
                    "absent"
                }
            }
        }
    }

    impl Agent for SocketAgent {
        fn is_running(&self) -> bool {
            self.status_check().0
        }

        fn request(&self, cmd: &str, fields: &Map<String, Value>) -> Option<Value> {
            kv_proto::agent_request_with_timeout(
                &self.root,
                cmd,
                fields,
                Some(Duration::from_secs(30)),
            )
            .ok()
        }

        fn status_check(&self) -> (bool, Arrived) {
            let Some(points) = endpoints(&self.root) else {
                return (false, Arrived::Refused);
            };
            if socket_problem(&points) {
                return (false, status_reply_arrived(&points));
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut socket = match kv_proto::connect_unix(&points.socket, Some(deadline)) {
                Ok(socket) => socket,
                Err(error) => {
                    let arrived = match error.kind() {
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => {
                            Arrived::Refused
                        }
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                            Arrived::NoReply
                        }
                        _ => Arrived::Unjudged,
                    };
                    return (false, arrived);
                }
            };
            let token = private_text(&points.token);
            let Some(reply) = exchange_status(&mut socket, &token, deadline) else {
                return (false, Arrived::NoReply);
            };
            if reply
                .get("error")
                .is_some_and(|error| !error.is_null() && error != &Value::Bool(false))
            {
                return (false, Arrived::Reply);
            }
            let expected = self.root.to_string_lossy();
            let same_root = expected.is_empty()
                || reply.get("root").and_then(Value::as_str) == Some(&*expected);
            let running = reply.get("running") == Some(&Value::Bool(true));
            if !is_status_reply(&reply) {
                return (false, Arrived::NoReply);
            }
            (running && same_root, Arrived::Reply)
        }

        fn service_state(&self, arrived: Arrived) -> String {
            match endpoints(&self.root) {
                Some(points) => service_state(&points, arrived).to_owned(),
                None => "unknown".to_owned(),
            }
        }
    }
}

#[cfg(not(unix))]
impl Agent for SocketAgent {
    fn is_running(&self) -> bool {
        false
    }

    fn request(&self, _cmd: &str, _fields: &Map<String, Value>) -> Option<Value> {
        None
    }

    fn status_check(&self) -> (bool, Arrived) {
        (false, Arrived::Untested)
    }

    fn service_state(&self, _arrived: Arrived) -> String {
        "unchecked".to_owned()
    }
}
