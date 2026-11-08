//! The daemon's tracked-file list for the Claude Code hook (Python `agent.py`
//! `tracked_files`, `tracking_gap`, and the `check_file` / `tracked_files`
//! commands).
//!
//! A `kv_run` records the files it saw a program create in the temp folders;
//! the hook asks about them before a Read. A walk the stop latch skipped or cut
//! leaves a *tracking gap*: for those folders kv cannot tell, so it refuses
//! rather than answer "untracked".

use std::collections::BTreeSet;
use std::sync::Mutex;

use kv_sandbox::paths::{abspath, inside_secrets_as_written, path_is_or_under, resolve};
use serde_json::{Value, json};

pub(crate) const TRACKING_GAP_ERROR: &str = "kv could not finish checking the temp folders for files a run created, so it cannot confirm which files there were created during kv_run";
pub(crate) const STOPPING_LIST_ERROR: &str =
    "the agent is stopping; it no longer answers from its tracked-file list";

#[derive(Default)]
struct State {
    files: BTreeSet<String>,
    gap_roots: Vec<String>,
    gap_since: Option<f64>,
}

/// Python's `tracked_files` set, `tracking_gap` and `tracked_lock` together.
#[derive(Default)]
pub(crate) struct Tracked {
    state: Mutex<State>,
}

pub(crate) fn tracking_gap_answer() -> Value {
    json!({"error": TRACKING_GAP_ERROR, "error_code": "tracking_incomplete"})
}

pub(crate) fn stopping_list_refusal() -> Value {
    json!({"error": STOPPING_LIST_ERROR, "error_code": "agent_stopping"})
}

impl Tracked {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record files a run created (already resolved by the scanner).
    pub(crate) fn add_files<I: IntoIterator<Item = String>>(&self, files: I) {
        self.lock().files.extend(files);
    }

    /// Python `_note_tracking_gap`: a run's walk did not finish these folders;
    /// it started at `since`.
    pub(crate) fn note_gap(&self, roots: &[String], since: f64) {
        let mut state = self.lock();
        for root in roots {
            if !state.gap_roots.contains(root) {
                state.gap_roots.push(root.clone());
            }
        }
        if state.gap_since.is_none_or(|current| since < current) {
            state.gap_since = Some(since);
        }
    }

    /// The gap's start, for a later walk that can close it.
    pub(crate) fn gap_since(&self) -> Option<f64> {
        self.lock().gap_since
    }

    /// A later complete walk closed the gap.
    pub(crate) fn clear_gap(&self) {
        let mut state = self.lock();
        state.gap_roots.clear();
        state.gap_since = None;
    }

    /// Python `check_file` command. `stopping` is the lifecycle's stop latch,
    /// read by the caller.
    pub(crate) fn check_file(
        &self,
        path: &str,
        watched_vaults: &[String],
        stopping: bool,
    ) -> Value {
        if path.is_empty() || inside_secrets_as_written(path, watched_vaults) {
            let shown = if path.is_empty() {
                String::new()
            } else {
                abspath(path).unwrap_or_else(|_| path.to_owned())
            };
            return json!({"tracked": false, "path": shown});
        }
        let Ok(real_path) = resolve(path) else {
            return json!({"error": "the path could not be resolved"});
        };
        let state = self.lock();
        if stopping {
            return stopping_list_refusal();
        }
        if state.files.contains(&real_path) {
            return json!({"tracked": true, "path": real_path});
        }
        if state
            .gap_roots
            .iter()
            .any(|root| path_is_or_under(&real_path, root, true))
        {
            return tracking_gap_answer();
        }
        json!({"tracked": false, "path": real_path})
    }

    /// Python `tracked_files` command.
    pub(crate) fn tracked_files(&self, stopping: bool) -> Value {
        let state = self.lock();
        if stopping {
            return stopping_list_refusal();
        }
        if !state.gap_roots.is_empty() {
            return tracking_gap_answer();
        }
        let files: Vec<&String> = state.files.iter().collect();
        json!({"files": files, "count": files.len()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_vault_paths_are_inputs_not_observations() {
        let tracked = Tracked::new();
        let vaults = vec!["/srv/vault".to_owned()];
        assert_eq!(
            tracked.check_file("", &vaults, false),
            json!({"tracked": false, "path": ""})
        );
        let answer = tracked.check_file("/srv/vault/.secrets/key", &vaults, false);
        assert_eq!(answer["tracked"], json!(false));
        assert_eq!(answer["path"], json!("/srv/vault/.secrets/key"));
    }

    #[test]
    fn tracked_gap_and_stopping_answers() {
        let dir = tempfile::tempdir().unwrap();
        let root = resolve(dir.path().to_str().unwrap()).unwrap();
        let file = format!("{root}/out.txt");
        std::fs::write(&file, b"x").unwrap();
        let tracked = Tracked::new();
        let vaults: Vec<String> = Vec::new();
        assert_eq!(
            tracked.check_file(&file, &vaults, false),
            json!({"tracked": false, "path": file})
        );
        tracked.add_files([file.clone()]);
        assert_eq!(
            tracked.check_file(&file, &vaults, false),
            json!({"tracked": true, "path": file})
        );
        assert_eq!(
            tracked.tracked_files(false),
            json!({"files": [file.clone()], "count": 1})
        );
        tracked.note_gap(std::slice::from_ref(&root), 5.0);
        tracked.note_gap(std::slice::from_ref(&root), 3.0);
        assert_eq!(tracked.gap_since(), Some(3.0));
        let other = format!("{root}/other.txt");
        assert_eq!(
            tracked.check_file(&other, &vaults, false),
            tracking_gap_answer()
        );
        assert_eq!(tracked.tracked_files(false), tracking_gap_answer());
        assert_eq!(
            tracked.check_file(&file, &vaults, false),
            json!({"tracked": true, "path": file})
        );
        tracked.clear_gap();
        assert_eq!(
            tracked.check_file(&other, &vaults, false),
            json!({"tracked": false, "path": other})
        );
        assert_eq!(
            tracked.check_file(&file, &vaults, true),
            stopping_list_refusal()
        );
        assert_eq!(tracked.tracked_files(true), stopping_list_refusal());
    }
}
