//! Minimal blocking pseudo-terminal driver in Rust (no Python pty helper).

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pty_process::blocking::{Command as PtyCommand, Pty, open};

pub struct PtyOutput {
    pub status: ExitStatus,
    pub transcript: Vec<u8>,
}

impl PtyOutput {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.transcript).replace('\r', "")
    }
}

pub struct PtySession {
    child: Child,
    pty: Pty,
    transcript: Arc<Mutex<Vec<u8>>>,
    cursor: usize,
}

impl PtySession {
    pub fn spawn(
        program: &str,
        args: &[String],
        cwd: &Path,
        envs: &[(String, String)],
    ) -> Result<Self, String> {
        let (pty, pts) = open().map_err(|error| format!("open test pty: {error}"))?;
        pty.resize(pty_process::Size::new(32, 120))
            .map_err(|error| format!("size test pty: {error}"))?;
        let read_fd =
            rustix::io::dup(&pty).map_err(|error| format!("duplicate test pty reader: {error}"))?;
        let transcript = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&transcript);
        std::thread::spawn(move || {
            let mut file = File::from(read_fd);
            let mut buffer = [0u8; 4096];
            loop {
                match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => writer
                        .lock()
                        .expect("pty transcript")
                        .extend_from_slice(&buffer[..read]),
                    Err(_) => break,
                }
            }
        });

        let mut command = PtyCommand::new(program);
        command = command
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .env("TERM", "dumb");
        for (name, value) in envs {
            command = command.env(name, value);
        }
        let child = command
            .spawn(pts)
            .map_err(|error| format!("spawn {program} on test pty: {error}"))?;
        Ok(Self {
            child,
            pty,
            transcript,
            cursor: 0,
        })
    }

    fn transcript(&self) -> Vec<u8> {
        self.transcript.lock().expect("pty transcript").clone()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.transcript()).replace('\r', "")
    }

    pub fn expect(&mut self, needle: &str, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            let transcript = self.transcript();
            if self.cursor <= transcript.len() {
                let haystack = &transcript[self.cursor..];
                if let Some(position) = haystack
                    .windows(needle.len())
                    .position(|window| window == needle.as_bytes())
                {
                    self.cursor += position + needle.len();
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for {needle:?}; transcript:\n{}",
                    self.text()
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn send_line(&mut self, text: &str) -> Result<(), String> {
        self.pty
            .write_all(text.as_bytes())
            .and_then(|()| self.pty.write_all(b"\n"))
            .and_then(|()| self.pty.flush())
            .map_err(|error| format!("write to test pty: {error}"))
    }

    pub fn answer(&mut self, prompt: &str, answer: &str, timeout: Duration) -> Result<(), String> {
        self.expect(prompt, timeout)?;
        self.send_line(answer)
    }

    pub fn finish(mut self, timeout: Duration) -> Result<PtyOutput, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| format!("observe pty child: {error}"))?
            {
                // The reader thread observes end-of-file only after the child closes its
                // slave side. Give it a short bounded chance to drain bytes already written.
                let mut last_len = 0usize;
                let mut stable = 0usize;
                for _ in 0..50 {
                    let len = self.transcript().len();
                    if len == last_len {
                        stable += 1;
                        if stable == 3 {
                            break;
                        }
                    } else {
                        stable = 0;
                        last_len = len;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                return Ok(PtyOutput {
                    status,
                    transcript: self.transcript(),
                });
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err(format!(
                    "pty child did not exit before its deadline; transcript:\n{}",
                    self.text()
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub struct Interaction<'a> {
    pub prompt: &'a str,
    pub answer: &'a str,
}

pub fn run(
    program: &str,
    args: &[String],
    cwd: &Path,
    envs: &[(String, String)],
    interactions: &[Interaction<'_>],
    timeout: Duration,
) -> Result<PtyOutput, String> {
    let mut session = PtySession::spawn(program, args, cwd, envs)?;
    for interaction in interactions {
        session.answer(interaction.prompt, interaction.answer, timeout)?;
    }
    session.finish(timeout)
}
