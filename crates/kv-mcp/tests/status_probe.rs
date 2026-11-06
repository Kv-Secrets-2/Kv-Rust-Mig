//! The public status probe must recognize a complete reply before peer EOF.
#![cfg(unix)]

#[path = "../../../tests/support/harness.rs"]
mod harness;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn status_probe_child() {
    let Some(root) = std::env::var_os("KV_STATUS_TEST_ROOT") else {
        return;
    };
    assert!(kv_mcp::agent::is_agent_running(&PathBuf::from(root)));
}

#[test]
fn complete_status_reply_counts_while_peer_keeps_socket_open() {
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(harness::socket_temp_dir("status", ""));
    let runtime = directory.0.join(".kv");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.0.join("project");
    let suffix = kv_proto::project_hash(Some(&root)).unwrap();
    let token_path = runtime.join(format!("agent-{suffix}.token"));
    fs::write(&token_path, "test-token").unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    let socket_path = runtime.join(format!("agent-{suffix}.sock"));
    let listener = UnixListener::bind(&socket_path).unwrap();
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (done, hold_open) = mpsc::channel();
    let reply_root = root.clone();
    let peer = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "no status client connected"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept status client: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = kv_proto::read_request(&mut stream).unwrap().unwrap();
        assert_eq!(request["cmd"], "status");
        assert_eq!(request["token"], "test-token");
        let reply = serde_json::json!({"running":true,"root":reply_root});
        stream
            .write_all(&serde_json::to_vec(&reply).unwrap())
            .unwrap();
        // The parent releases this only after its probe process exits. An EOF
        // reader therefore times out, even though a complete reply arrived.
        let _ = hold_open.recv_timeout(Duration::from_secs(5));
    });
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "status_probe_child", "--nocapture"])
        .env("HOME", &directory.0)
        .env("KV_STATUS_TEST_ROOT", &root);
    let output = harness::output(command, &[], Duration::from_secs(4));
    let _ = done.send(());
    peer.join().unwrap();
    let output = output.unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
