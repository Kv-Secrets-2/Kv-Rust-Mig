//! `kv hook pre`: the Claude Code PreToolUse hook entry point.

use std::io::{Read, Write};

use crate::project::{CmdResult, Exit};

/// Reads the editor's request from stdin and prints one reply. Like Python's
/// hook it exits 0 whatever the decision; only an unwritable stdout fails.
pub fn cmd_hook(mode: &str) -> CmdResult {
    let mut raw = Vec::new();
    // A read error is unreadable input, which the pre mode refuses.
    let _ = std::io::stdin().lock().read_to_end(&mut raw);
    let reply = kv_hook::reply_for(mode, raw);
    let mut out = std::io::stdout().lock();
    if out
        .write_all(&reply.to_line())
        .and_then(|()| out.flush())
        .is_err()
    {
        return Err(Exit(1));
    }
    Ok(())
}
