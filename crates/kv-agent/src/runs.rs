//! The live `kv_run` programs and what a stop does to them (Python `agent.py`
//! `_runs`, `_new_run_slot`, `_register_run`, `_end_due_runs`,
//! `_fallback_run_records`, `_term_run`, `_kill_run`, `_term_sandbox_programs`).
//!
//! A slot is registered when its program has started and stays until the
//! run's reply is sent, so a drain that waits for the slots waits for the
//! whole run: the program, its capture, its leak scan and its answer. The
//! stop ends programs by their process group (the session each child leads,
//! never the service's own); under bubblewrap it TERMs the programs inside
//! the namespace and spares both wrappers, whose death would kill the
//! namespace's init at once and lose the TERM grace. Every signal goes to a
//! process saved with its identity (`/proc/<pid>/stat` start time) and only
//! while it is still that process, and only while the run's leader is
//! uncollected: a collected leader's number may already name a stranger.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::process::Child;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process, kill_process_group};
use serde_json::{Value, json};

use crate::lifecycle::{DrainOutcome, LONG_WAIT_SECONDS, Lifecycle};

/// Python `_RUN_END_RESERVE_SECONDS`: inside the owner's long wait, programs
/// are ended only once this much of it remains.
pub(crate) const RUN_END_RESERVE: Duration = Duration::from_secs(5);
/// Python `_RUN_END_GRACE_SECONDS`: TERM, then KILL after this.
pub(crate) const RUN_END_GRACE: Duration = Duration::from_secs(2);
/// Python `_SECRET_RUN_SCAN_EXTRA_SECONDS`: past the stop's deadline, a
/// secret-bearing run still scanning gets this much more for its scan.
pub(crate) const SECRET_RUN_SCAN_EXTRA: Duration = Duration::from_secs(20);
/// Python `_STOP_WAIT_POLL_SECONDS`.
const STOP_WAIT_POLL: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotState {
    Starting,
    Running,
    Finishing,
}

/// Python `_new_run_slot`'s dict.
pub(crate) struct RunSlot {
    pub(crate) run_id: Option<String>,
    pub(crate) program: String,
    pub(crate) proc: Option<Child>,
    pub(crate) state: SlotState,
    term_at: Option<Instant>,
    pub(crate) signalled: bool,
    recorded: bool,
    pub(crate) secret_scan: bool,
    scanning: bool,
    pub(crate) scanned: bool,
    pub(crate) late_sent: bool,
    pub(crate) sandboxed: Option<bool>,
    pub(crate) contained: bool,
}

pub(crate) type Slot = Arc<Mutex<RunSlot>>;

/// One entry of Python `_ended_runs` / `_fallback_run_records`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EndedRun {
    pub(crate) run_id: Option<String>,
    pub(crate) program: String,
    pub(crate) contained: bool,
}

impl EndedRun {
    fn brief(&self) -> Value {
        json!({"run_id": self.run_id, "program": self.program, "contained": self.contained})
    }
}

#[derive(Default)]
struct Inner {
    slots: Vec<Slot>,
    ended: Vec<EndedRun>,
}

/// Python `_runs`, `_ended_runs` and `_runs_lock`. Lock order: `Runs` before
/// any slot.
#[derive(Default)]
pub(crate) struct Runs {
    inner: Mutex<Inner>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn new_slot(
    run_id: Option<String>,
    program: &str,
    secret_scan: bool,
    sandboxed: Option<bool>,
    contained: bool,
) -> Slot {
    Arc::new(Mutex::new(RunSlot {
        run_id,
        program: program.to_owned(),
        proc: None,
        state: SlotState::Starting,
        term_at: None,
        signalled: false,
        recorded: false,
        secret_scan,
        scanning: false,
        scanned: false,
        late_sent: false,
        sandboxed,
        contained,
    }))
}

impl Runs {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Python `_register_run`: the program has started; the slot is live.
    pub(crate) fn register(&self, lifecycle: &Lifecycle, slot: &Slot, child: Child) {
        let mut inner = lock(&self.inner);
        {
            let mut state = lock(slot);
            state.proc = Some(child);
            state.state = SlotState::Running;
        }
        inner.slots.push(Arc::clone(slot));
        drop(inner);
        lifecycle.notify();
    }

    /// Python `_run_collected`: the program is reaped; the run is finishing.
    /// Returns whether a stop signalled it.
    pub(crate) fn collected(&self, slot: &Slot) -> bool {
        let _inner = lock(&self.inner);
        let mut state = lock(slot);
        state.state = SlotState::Finishing;
        state.signalled
    }

    /// Python `_unregister_run`: after the reply is sent.
    pub(crate) fn unregister(&self, lifecycle: &Lifecycle, slot: &Slot) {
        let mut inner = lock(&self.inner);
        inner.slots.retain(|other| !Arc::ptr_eq(other, slot));
        drop(inner);
        lifecycle.notify();
    }

    /// Python `_claim_run_record`: exactly one end record per run.
    pub(crate) fn claim_record(&self, slot: &Slot) -> bool {
        let _inner = lock(&self.inner);
        let mut state = lock(slot);
        if state.recorded {
            return false;
        }
        state.recorded = true;
        true
    }

    /// Python `_set_scanning`.
    pub(crate) fn set_scanning(&self, slot: &Slot, scanning: bool) {
        let _inner = lock(&self.inner);
        let mut state = lock(slot);
        state.scanning = scanning;
        if !scanning {
            state.scanned = true;
        }
    }

    /// Python `_secret_scans_open`: a secret-bearing run whose reply is not
    /// out yet.
    pub(crate) fn secret_scans_open(&self) -> bool {
        let inner = lock(&self.inner);
        inner.slots.iter().any(|slot| {
            let state = lock(slot);
            state.secret_scan && state.scanning
        })
    }

    /// Python `_running_brief`.
    pub(crate) fn running_brief(&self) -> Vec<Value> {
        let inner = lock(&self.inner);
        inner
            .slots
            .iter()
            .filter_map(|slot| {
                let state = lock(slot);
                (state.state == SlotState::Running)
                    .then(|| json!({"run_id": state.run_id, "program": state.program}))
            })
            .collect()
    }

    /// Python `_ended_brief`.
    pub(crate) fn ended_brief(&self) -> Vec<Value> {
        lock(&self.inner)
            .ended
            .iter()
            .map(EndedRun::brief)
            .collect()
    }

    /// The running programs, for `_count_in_flight`.
    pub(crate) fn count_running(&self) -> usize {
        let inner = lock(&self.inner);
        inner
            .slots
            .iter()
            .filter(|slot| lock(slot).state == SlotState::Running)
            .count()
    }

    /// Every live slot (Python `bool(_runs)`): a drain waits for them all.
    pub(crate) fn count_live(&self) -> usize {
        lock(&self.inner).slots.len()
    }

    /// Python `_end_due_runs`.
    pub(crate) fn end_due_runs(&self, lifecycle: &Lifecycle) {
        let (wait, remaining) = match lifecycle.stop_budget() {
            Some(budget) => budget,
            None => {
                // Any exit no decision reached takes the short wait.
                lifecycle.signal_stop();
                match lifecycle.stop_budget() {
                    Some(budget) => budget,
                    None => return,
                }
            }
        };
        if wait == LONG_WAIT_SECONDS && remaining > RUN_END_RESERVE {
            return;
        }
        let now = Instant::now();
        let mut inner = lock(&self.inner);
        let mut ended = Vec::new();
        for slot in &inner.slots {
            let mut state = lock(slot);
            if state.state != SlotState::Running || state.proc.is_none() {
                continue;
            }
            if state.signalled {
                if state
                    .term_at
                    .is_some_and(|term_at| now.duration_since(term_at) >= RUN_END_GRACE)
                {
                    let _ = kill_run(&mut state);
                }
                continue;
            }
            match term_run(&mut state) {
                Ok(true) => {}
                // Collected, an empty group, or a group it cannot reach: the
                // program finished by itself or nothing can be said about it.
                Ok(false) | Err(_) => continue,
            }
            state.signalled = true;
            state.term_at = Some(now);
            ended.push(EndedRun {
                run_id: state.run_id.clone(),
                program: state.program.clone(),
                contained: state.contained,
            });
        }
        inner.ended.extend(ended);
    }

    /// Python `_fallback_run_records`: the stop-ended programs whose own path
    /// did not record their end before the service leaves; each claimed once.
    pub(crate) fn fallback_records(&self) -> Vec<EndedRun> {
        let inner = lock(&self.inner);
        let mut claimed = Vec::new();
        for slot in &inner.slots {
            let mut state = lock(slot);
            if !state.signalled || state.recorded {
                continue;
            }
            state.recorded = true;
            claimed.push(EndedRun {
                run_id: state.run_id.clone(),
                program: state.program.clone(),
                contained: state.contained,
            });
        }
        claimed
    }

    /// The stop's drain with the runs in it (the run part of Python
    /// `_retire_trust_context`): programs are ended when the budget says so,
    /// the committed windows and the slots are waited for inside the one
    /// chosen wait, and a secret-bearing run still unanswered past it gets
    /// `SECRET_RUN_SCAN_EXTRA` for its scan.
    pub(crate) fn drain(&self, lifecycle: &Lifecycle) -> DrainOutcome {
        self.end_due_runs(lifecycle);
        let outcome = loop {
            if let Some(outcome) = lifecycle.poll_drain(STOP_WAIT_POLL, &|| self.count_live()) {
                break outcome;
            }
            self.end_due_runs(lifecycle);
        };
        self.end_due_runs(lifecycle);
        if self.count_live() > 0 && self.secret_scans_open() {
            let until = Instant::now() + SECRET_RUN_SCAN_EXTRA;
            while Instant::now() < until && self.count_live() > 0 && self.secret_scans_open() {
                std::thread::sleep(STOP_WAIT_POLL);
                self.end_due_runs(lifecycle);
            }
        }
        outcome
    }
}

fn leader_pid(child: &Child) -> io::Result<Pid> {
    let raw = i32::try_from(child.id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    Pid::from_raw(raw).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "pid is zero"))
}

fn esrch(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, what.to_owned())
}

/// Python `_kill_run`: the stop's KILL after the grace, for the whole group,
/// only while the leader is uncollected.
fn kill_run(slot: &mut RunSlot) -> io::Result<()> {
    let Some(child) = slot.proc.as_mut() else {
        return Err(esrch("the run has no process"));
    };
    if child.try_wait()?.is_some() {
        return Err(esrch("the run's leader is already collected"));
    }
    let pid = leader_pid(child)?;
    kill_process_group(pid, Signal::KILL).map_err(io::Error::from)
}

/// Python `_term_run`: TERM the program(s); `false` when the leader is
/// already collected (the run finished by itself).
fn term_run(slot: &mut RunSlot) -> io::Result<bool> {
    let sandboxed = slot.sandboxed == Some(true);
    let Some(child) = slot.proc.as_mut() else {
        return Ok(false);
    };
    if child.try_wait()?.is_some() {
        return Ok(false);
    }
    let pid = leader_pid(child)?;
    if !sandboxed {
        kill_process_group(pid, Signal::TERM)?;
        return Ok(true);
    }
    term_sandbox_programs(pid)
}

/// `/proc/<pid>/stat`'s (ppid, start time): a process's identity.
fn proc_stat(pid: i32) -> Option<(i32, u64)> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &text[text.rfind(')')? + 1..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // Field 3 (state) is `fields[0]`; ppid is field 4, starttime field 22.
    let ppid = fields.get(1)?.parse().ok()?;
    let started = fields.get(19)?.parse().ok()?;
    Some((ppid, started))
}

fn proc_identity(pid: i32) -> Option<u64> {
    proc_stat(pid).map(|(_, started)| started)
}

/// Every process's parent, for a kernel without `CONFIG_PROC_CHILDREN`.
fn proc_parents() -> BTreeMap<i32, i32> {
    let mut parents = BTreeMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return parents;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if let Some((ppid, _)) = proc_stat(pid) {
            parents.insert(pid, ppid);
        }
    }
    parents
}

fn children(pid: i32, parents: &mut Option<BTreeMap<i32, i32>>) -> io::Result<Vec<i32>> {
    match fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
        Ok(text) => Ok(text
            .split_whitespace()
            .filter_map(|value| value.parse().ok())
            .collect()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let map = parents.get_or_insert_with(proc_parents);
            Ok(map
                .iter()
                .filter(|(_, parent)| **parent == pid)
                .map(|(child, _)| *child)
                .collect())
        }
        Err(error) => Err(error),
    }
}

/// A listed child is saved with its identity only while it is provably that
/// process under that parent.
fn saved_children(
    pid: i32,
    identity: Option<u64>,
    parents: &mut Option<BTreeMap<i32, i32>>,
) -> io::Result<Vec<(i32, u64)>> {
    let mut found = Vec::new();
    for child in children(pid, parents)? {
        let Some(child_identity) = proc_identity(child) else {
            continue;
        };
        if proc_stat(child) != Some((pid, child_identity)) || proc_identity(pid) != identity {
            continue;
        }
        found.push((child, child_identity));
    }
    Ok(found)
}

fn signal_saved(pid: i32, identity: u64, signal: Signal) {
    if proc_identity(pid) != Some(identity) {
        return;
    }
    if let Some(target) = Pid::from_raw(pid) {
        let _ = kill_process(target, signal);
    }
}

/// Python `_term_sandbox_programs`: TERM every process under bubblewrap's
/// namespace init, sparing both wrappers; with none found, TERM the
/// wrapper's group.
fn term_sandbox_programs(wrapper: Pid) -> io::Result<bool> {
    let end_wrapper = || -> io::Result<bool> {
        kill_process_group(wrapper, Signal::TERM)?;
        Ok(true)
    };
    let wrapper_raw = wrapper.as_raw_nonzero().get();
    let mut parents = None;
    let inits = match saved_children(wrapper_raw, proc_identity(wrapper_raw), &mut parents) {
        Ok(inits) => inits,
        Err(_) => return end_wrapper(),
    };
    if inits.is_empty() {
        return end_wrapper();
    }
    let mut pending = inits;
    let mut descendants = Vec::new();
    while let Some((pid, identity)) = pending.pop() {
        let Ok(offspring) = saved_children(pid, Some(identity), &mut parents) else {
            continue;
        };
        pending.extend(offspring.iter().copied());
        descendants.extend(offspring);
    }
    if descendants.is_empty() {
        return end_wrapper();
    }
    for (pid, identity) in descendants {
        signal_saved(pid, identity, Signal::TERM);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::StopChoice;
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("sleep spawns")
    }

    #[test]
    fn own_stat_parses() {
        let pid = std::process::id() as i32;
        let (ppid, started) = proc_stat(pid).expect("own stat");
        assert!(ppid >= 0);
        assert!(started > 0);
        assert_eq!(proc_identity(pid), Some(started));
    }

    #[test]
    fn slots_register_count_and_unregister() {
        let lifecycle = Lifecycle::new();
        let runs = Runs::new();
        let slot = new_slot(Some("r1".into()), "sleep", false, Some(false), false);
        assert_eq!(runs.count_running(), 0);
        let child = sleeper();
        runs.register(&lifecycle, &slot, child);
        assert_eq!(runs.count_running(), 1);
        assert_eq!(
            runs.running_brief(),
            vec![json!({"run_id": "r1", "program": "sleep"})]
        );
        assert!(runs.claim_record(&slot));
        assert!(!runs.claim_record(&slot));
        assert!(!runs.collected(&slot));
        assert_eq!(runs.count_running(), 0);
        assert_eq!(runs.count_live(), 1);
        runs.unregister(&lifecycle, &slot);
        assert_eq!(runs.count_live(), 0);
        let mut state = lock(&slot);
        let mut child = state.proc.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn stop_now_terms_the_group_and_records_the_end() {
        let lifecycle = Lifecycle::new();
        let runs = Runs::new();
        let slot = new_slot(Some("r2".into()), "sleep", false, Some(false), false);
        runs.register(&lifecycle, &slot, sleeper());
        // No stop yet: nothing is due until a stop is chosen.
        lifecycle.request_stop(Some(StopChoice::Now), runs.count_running());
        runs.end_due_runs(&lifecycle);
        assert_eq!(
            runs.ended_brief(),
            vec![json!({"run_id": "r2", "program": "sleep", "contained": false})]
        );
        let status = {
            let mut state = lock(&slot);
            state.proc.as_mut().unwrap().wait().unwrap()
        };
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert!(runs.collected(&slot));
        // A collected leader is never signalled again.
        {
            let mut state = lock(&slot);
            assert!(kill_run(&mut state).is_err());
            assert_eq!(term_run(&mut state).unwrap(), false);
        }
        assert_eq!(runs.fallback_records().len(), 1);
        assert!(runs.fallback_records().is_empty());
        runs.unregister(&lifecycle, &slot);
    }

    #[test]
    fn long_wait_spares_runs_until_the_reserve() {
        let lifecycle = Lifecycle::new();
        let runs = Runs::new();
        let slot = new_slot(None, "sleep", false, Some(false), false);
        runs.register(&lifecycle, &slot, sleeper());
        lifecycle.request_stop(Some(StopChoice::Wait), runs.count_running());
        runs.end_due_runs(&lifecycle);
        assert!(runs.ended_brief().is_empty());
        let mut state = lock(&slot);
        assert!(state.proc.as_mut().unwrap().try_wait().unwrap().is_none());
        let mut child = state.proc.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn drain_ends_a_run_and_waits_for_its_slot() {
        let lifecycle = Lifecycle::new();
        let runs = Arc::new(Runs::new());
        let slot = new_slot(Some("r3".into()), "sleep", false, Some(false), false);
        runs.register(&lifecycle, &slot, sleeper());
        // The run's own path: reap under the slot lock, then leave.
        let reaper_runs = Arc::clone(&runs);
        let reaper_slot = Arc::clone(&slot);
        let reaper_lifecycle = Arc::clone(&lifecycle);
        let reaper = std::thread::spawn(move || {
            loop {
                {
                    let mut state = lock(&reaper_slot);
                    if state.proc.as_mut().unwrap().try_wait().unwrap().is_some() {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            reaper_runs.collected(&reaper_slot);
            reaper_runs.unregister(&reaper_lifecycle, &reaper_slot);
        });
        let plan = lifecycle.request_stop(None, runs.count_running());
        assert!(matches!(
            plan,
            crate::lifecycle::StopPlan::AwaitingChoice { in_flight: 1 }
        ));
        lifecycle.request_stop(Some(StopChoice::Now), runs.count_running());
        let started = Instant::now();
        let outcome = runs.drain(&lifecycle);
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_eq!(outcome.cut_off, 0);
        reaper.join().unwrap();
        assert_eq!(runs.count_live(), 0);
        assert_eq!(runs.ended_brief().len(), 1);
    }
}
