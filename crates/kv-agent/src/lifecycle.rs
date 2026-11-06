//! Admission and bounded retirement of one daemon session.
//!
//! A committed window is a provider operation or a reply, not a connection.
//! Retirement refuses new windows and keeps existing guards alive. A bounded
//! drain can leave workers running: their owners must go to `RetiredWorkers`,
//! and the caller must not close their trust pins. This is not a guarantee of
//! process termination or immediate secret erasure when DNS/I/O cannot stop.

use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SHORT_WAIT_SECONDS: u64 = 10;
const LONG_WAIT_SECONDS: u64 = 135;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Running,
    AwaitingChoice,
    Draining,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopChoice {
    Now,
    Wait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopPlan {
    AwaitingChoice { in_flight: usize },
    AlreadyStopping { wait_seconds: u64 },
    Drain { wait_seconds: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DrainOutcome {
    pub(crate) wait_seconds: u64,
    pub(crate) cut_off: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Stopping;

#[derive(Clone, Copy)]
struct Settings {
    short_wait: Duration,
    long_wait: Duration,
    choice_wait: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            short_wait: Duration::from_secs(SHORT_WAIT_SECONDS),
            long_wait: Duration::from_secs(LONG_WAIT_SECONDS),
            choice_wait: Duration::from_secs(LONG_WAIT_SECONDS),
        }
    }
}

struct State {
    phase: Phase,
    committed: usize,
    choice_deadline: Option<Instant>,
    choice_expired: bool,
    stop_deadline: Option<Instant>,
    wait_seconds: u64,
    outcome: Option<DrainOutcome>,
}

pub(crate) struct Lifecycle {
    settings: Settings,
    state: Mutex<State>,
    changed: Condvar,
}

impl Lifecycle {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_settings(Settings::default())
    }

    fn with_settings(settings: Settings) -> Arc<Self> {
        Arc::new(Self {
            settings,
            state: Mutex::new(State {
                phase: Phase::Running,
                committed: 0,
                choice_deadline: None,
                choice_expired: false,
                stop_deadline: None,
                wait_seconds: SHORT_WAIT_SECONDS,
                outcome: None,
            }),
            changed: Condvar::new(),
        })
    }

    pub(crate) fn phase(&self) -> Phase {
        let mut state = lock(&self.state);
        if self.expire_choice_locked(&mut state, Instant::now()) {
            self.changed.notify_all();
        }
        state.phase
    }

    #[cfg(test)]
    pub(crate) fn committed_count(&self) -> usize {
        lock(&self.state).committed
    }

    #[cfg(test)]
    pub(crate) fn try_commit(self: &Arc<Self>) -> Result<WorkGuard, Stopping> {
        self.commit(None)
    }

    /// The connection becomes active in the same admission step as its window.
    /// No network operation runs while the admission mutex is held.
    pub(crate) fn try_commit_for(
        self: &Arc<Self>,
        connection: &ConnectionGuard,
    ) -> Result<WorkGuard, Stopping> {
        self.commit(Some(&connection.connection))
    }

    fn commit(
        self: &Arc<Self>,
        connection: Option<&Arc<TrackedConnection>>,
    ) -> Result<WorkGuard, Stopping> {
        let mut state = lock(&self.state);
        if state.phase != Phase::Running {
            return Err(Stopping);
        }
        if let Some(connection) = connection {
            let mut connection_state = lock(&connection.state);
            if connection_state.finished || connection_state.closed {
                return Err(Stopping);
            }
            connection_state.active += 1;
        }
        state.committed += 1;
        Ok(WorkGuard {
            lifecycle: Arc::clone(self),
            connection: connection.cloned(),
        })
    }

    /// Parse and reject malformed wire choices before calling this method.
    /// Mark the stop connection as control before publishing the decision.
    pub(crate) fn request_stop(&self, choice: Option<StopChoice>) -> StopPlan {
        let mut state = lock(&self.state);
        let now = Instant::now();
        self.expire_choice_locked(&mut state, now);
        let plan = if state.choice_expired
            || state.phase == Phase::Retired
            || (choice.is_none() && state.stop_deadline.is_some())
        {
            StopPlan::AlreadyStopping {
                wait_seconds: state.wait_seconds,
            }
        } else if let Some(choice) = choice {
            self.choose_locked(&mut state, choice, now);
            StopPlan::Drain {
                wait_seconds: state.wait_seconds,
            }
        } else {
            state.phase = Phase::AwaitingChoice;
            if state.choice_deadline.is_none() {
                state.choice_deadline = Some(now + self.settings.choice_wait);
            }
            if state.committed != 0 {
                StopPlan::AwaitingChoice {
                    in_flight: state.committed,
                }
            } else {
                self.choose_locked(&mut state, StopChoice::Now, now);
                StopPlan::Drain {
                    wait_seconds: state.wait_seconds,
                }
            }
        };
        self.changed.notify_all();
        plan
    }

    fn choose_locked(&self, state: &mut State, choice: StopChoice, now: Instant) {
        if state.outcome.is_some() || state.phase == Phase::Retired {
            return;
        }
        let (duration, seconds) = match choice {
            StopChoice::Now => (self.settings.short_wait, SHORT_WAIT_SECONDS),
            StopChoice::Wait => (self.settings.long_wait, LONG_WAIT_SECONDS),
        };
        let deadline = now + duration;
        if state
            .stop_deadline
            .is_none_or(|standing| deadline < standing)
        {
            state.stop_deadline = Some(deadline);
            state.wait_seconds = seconds;
        }
        state.choice_deadline = None;
        state.phase = Phase::Draining;
    }

    fn expire_choice_locked(&self, state: &mut State, now: Instant) -> bool {
        if state.phase == Phase::AwaitingChoice
            && state
                .choice_deadline
                .is_some_and(|deadline| now >= deadline)
        {
            state.choice_expired = true;
            self.choose_locked(state, StopChoice::Now, now);
            return true;
        }
        false
    }

    pub(crate) fn expire_choice(&self) -> bool {
        let mut state = lock(&self.state);
        let expired = self.expire_choice_locked(&mut state, Instant::now());
        if expired {
            self.changed.notify_all();
        }
        expired
    }

    pub(crate) fn signal_stop(&self) {
        let mut state = lock(&self.state);
        self.choose_locked(&mut state, StopChoice::Now, Instant::now());
        self.changed.notify_all();
    }

    /// Wait for at most a polling slice, so the foreground can apply signals.
    /// The first drain result is retained for every stop answer and finalizer.
    pub(crate) fn poll_drain(&self, timeout: Duration) -> Option<DrainOutcome> {
        let until = Instant::now() + timeout;
        let mut state = lock(&self.state);
        loop {
            if let Some(outcome) = state.outcome {
                return Some(outcome);
            }
            let now = Instant::now();
            if self.expire_choice_locked(&mut state, now) {
                self.changed.notify_all();
            }
            if state
                .stop_deadline
                .is_some_and(|deadline| state.committed == 0 || now >= deadline)
            {
                let outcome = DrainOutcome {
                    wait_seconds: state.wait_seconds,
                    cut_off: state.committed,
                };
                state.outcome = Some(outcome);
                self.changed.notify_all();
                return Some(outcome);
            }
            if now >= until {
                return None;
            }
            let next = state
                .stop_deadline
                .or(state.choice_deadline)
                .map_or(until, |deadline| deadline.min(until));
            let (next_state, _) = self
                .changed
                .wait_timeout(state, next.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next_state;
        }
    }

    pub(crate) fn wait_for_drain(&self) -> DrainOutcome {
        loop {
            if let Some(outcome) = self.poll_drain(Duration::from_millis(500)) {
                return outcome;
            }
        }
    }

    /// Wait on existing windows without choosing a stop or changing its budget.
    pub(crate) fn wait_for_open_work(&self, timeout: Duration) -> usize {
        let until = Instant::now() + timeout;
        let mut state = lock(&self.state);
        loop {
            let now = Instant::now();
            if state.committed == 0 || now >= until {
                return state.committed;
            }
            let (next_state, _) = self
                .changed
                .wait_timeout(state, until.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next_state;
        }
    }

    /// Final retirement never closes pins beneath remaining committed work.
    /// Normally called after the chosen drain and the control-answer allowance.
    pub(crate) fn retire(&self) -> DrainOutcome {
        let mut state = lock(&self.state);
        let outcome = state.outcome.unwrap_or(DrainOutcome {
            wait_seconds: state.wait_seconds,
            cut_off: state.committed,
        });
        state.outcome = Some(outcome);
        state.phase = Phase::Retired;
        state.choice_deadline = None;
        self.changed.notify_all();
        outcome
    }
}

#[must_use = "keep the guard alive for the whole committed operation"]
pub(crate) struct WorkGuard {
    lifecycle: Arc<Lifecycle>,
    connection: Option<Arc<TrackedConnection>>,
}

impl Drop for WorkGuard {
    fn drop(&mut self) {
        let mut state = lock(&self.lifecycle.state);
        // A worker can finish after the cutoff before the draining thread next
        // gets CPU time. Preserve the count at that boundary, not a later zero.
        if state.outcome.is_none()
            && state
                .stop_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            state.outcome = Some(DrainOutcome {
                wait_seconds: state.wait_seconds,
                cut_off: state.committed,
            });
        }
        if let Some(connection) = &self.connection {
            let mut connection_state = lock(&connection.state);
            connection_state.active -= 1;
        }
        state.committed -= 1;
        self.lifecycle.changed.notify_all();
    }
}

struct ConnectionState {
    stream: Option<UnixStream>,
    active: usize,
    dispatching: bool,
    control: bool,
    closed: bool,
    finished: bool,
}

struct TrackedConnection {
    state: Mutex<ConnectionState>,
}

#[must_use = "keep the connection guard until the handler exits"]
pub(crate) struct ConnectionGuard {
    connection: Arc<TrackedConnection>,
}

impl ConnectionGuard {
    /// A complete frame is being dispatched. It is no longer an idle reader,
    /// but this grants no permission to commit a provider operation or reply.
    pub(crate) fn mark_dispatching(&self) -> bool {
        let mut state = lock(&self.connection.state);
        if state.closed || state.finished {
            return false;
        }
        state.dispatching = true;
        true
    }

    /// Returns false if shutdown already closed this connection.
    pub(crate) fn mark_control(&self) -> bool {
        let mut state = lock(&self.connection.state);
        if state.closed || state.finished {
            return false;
        }
        state.control = true;
        true
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut state = lock(&self.connection.state);
        state.finished = true;
        state.closed = true;
        if let Some(stream) = state.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReapOutcome {
    pub(crate) finished: usize,
    pub(crate) panicked: usize,
}

#[derive(Default)]
pub(crate) struct WorkerTracker {
    workers: Vec<JoinHandle<()>>,
    connections: Vec<Weak<TrackedConnection>>,
}

impl WorkerTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register_connection(
        &mut self,
        stream: &UnixStream,
    ) -> io::Result<ConnectionGuard> {
        let connection = Arc::new(TrackedConnection {
            state: Mutex::new(ConnectionState {
                stream: Some(stream.try_clone()?),
                active: 0,
                dispatching: false,
                control: false,
                closed: false,
                finished: false,
            }),
        });
        self.connections.push(Arc::downgrade(&connection));
        Ok(ConnectionGuard { connection })
    }

    pub(crate) fn track_worker(&mut self, worker: JoinHandle<()>) {
        self.workers.push(worker);
    }

    pub(crate) fn reap_finished(&mut self) -> ReapOutcome {
        self.connections
            .retain(|connection| connection.strong_count() != 0);
        reap_handles(&mut self.workers)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn has_control_connections(&self) -> bool {
        self.connections
            .iter()
            .filter_map(Weak::upgrade)
            .any(|connection| {
                let state = lock(&connection.state);
                state.control && !state.finished && !state.closed
            })
    }

    /// Call only after the admission gate has entered Draining/Retired.
    pub(crate) fn shutdown_idle(&self) -> usize {
        self.shutdown_matching(|state| !state.control && !state.dispatching && state.active == 0)
    }

    pub(crate) fn shutdown_non_control(&self) -> usize {
        self.shutdown_matching(|state| !state.control)
    }

    pub(crate) fn shutdown_all(&self) -> usize {
        self.shutdown_matching(|_| true)
    }

    fn shutdown_matching(&self, select: impl Fn(&ConnectionState) -> bool) -> usize {
        let mut closed = 0;
        for connection in self.connections.iter().filter_map(Weak::upgrade) {
            let mut state = lock(&connection.state);
            // Selection and closing share the phase lock with mark_control and
            // commit: no stale idle snapshot can close a newly active socket.
            if !state.closed && !state.finished && select(&state) {
                state.closed = true;
                if let Some(stream) = &state.stream {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                closed += 1;
            }
        }
        closed
    }

    pub(crate) fn into_retired(mut self) -> RetiredWorkers {
        self.reap_finished();
        RetiredWorkers {
            workers: self.workers,
        }
    }
}

fn reap_handles(workers: &mut Vec<JoinHandle<()>>) -> ReapOutcome {
    let mut outcome = ReapOutcome::default();
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            outcome.finished += 1;
            outcome.panicked += usize::from(worker.join().is_err());
        } else {
            index += 1;
        }
    }
    outcome
}

// A failed reaper spawn must not discard the only owner of unfinished handles.
// These handles stay explicitly retained; subsequent retirement reaps completed
// fallback entries. Their workers still own and eventually release their pins.
static RETIRED_WITHOUT_REAPER: Mutex<Vec<RetiredWorkers>> = Mutex::new(Vec::new());

#[must_use = "unfinished workers must be explicitly retained by the reaper"]
pub(crate) struct RetiredWorkers {
    workers: Vec<JoinHandle<()>>,
}

impl RetiredWorkers {
    #[cfg(test)]
    pub(crate) fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Return immediately after transferring ownership to a named reaper.
    /// On spawn failure, ownership stays in a process-global fallback and the
    /// returned error is diagnostic; it does not mean the workers were dropped.
    pub(crate) fn reap_in_background(self) -> io::Result<()> {
        self.reap_with_spawn(|receiver| {
            thread::Builder::new()
                .name("kv-retired-workers".into())
                .spawn(move || {
                    if let Ok(mut retired) = receiver.recv() {
                        while !retired.workers.is_empty() {
                            reap_handles(&mut retired.workers);
                            if !retired.workers.is_empty() {
                                thread::sleep(Duration::from_millis(20));
                            }
                        }
                    }
                })
        })
    }

    fn reap_with_spawn(
        self,
        spawn: impl FnOnce(mpsc::Receiver<Self>) -> io::Result<JoinHandle<()>>,
    ) -> io::Result<()> {
        {
            let mut retained = lock(&RETIRED_WITHOUT_REAPER);
            for retired in retained.iter_mut() {
                reap_handles(&mut retired.workers);
            }
            retained.retain(|retired| !retired.workers.is_empty());
        }
        if self.workers.is_empty() {
            return Ok(());
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        match spawn(receiver) {
            Ok(_reaper) => match sender.send(self) {
                Ok(()) => Ok(()),
                Err(error) => {
                    lock(&RETIRED_WITHOUT_REAPER).push(error.0);
                    Err(io::Error::other(
                        "retired-worker reaper did not accept ownership",
                    ))
                }
            },
            Err(error) => {
                lock(&RETIRED_WITHOUT_REAPER).push(self);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Barrier;

    fn short_lifecycle() -> Arc<Lifecycle> {
        Lifecycle::with_settings(Settings {
            short_wait: Duration::from_millis(80),
            long_wait: Duration::from_millis(600),
            choice_wait: Duration::from_millis(60),
        })
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !condition() {
            assert!(Instant::now() < deadline, "condition did not become true");
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn no_work_stop_uses_short_budget_and_retires_admission() {
        let lifecycle = Lifecycle::new();
        assert_eq!(lifecycle.phase(), Phase::Running);
        assert_eq!(
            lifecycle.request_stop(None),
            StopPlan::Drain { wait_seconds: 10 }
        );
        assert!(lifecycle.try_commit().is_err());
        assert_eq!(
            lifecycle.wait_for_drain(),
            DrainOutcome {
                wait_seconds: 10,
                cut_off: 0
            }
        );
        lifecycle.retire();
        assert_eq!(lifecycle.phase(), Phase::Retired);
    }

    #[test]
    fn choice_expiry_and_late_wait_keep_the_same_short_deadline() {
        let lifecycle = short_lifecycle();
        let work = lifecycle.try_commit().unwrap();
        assert_eq!(
            lifecycle.request_stop(None),
            StopPlan::AwaitingChoice { in_flight: 1 }
        );
        assert_eq!(lifecycle.phase(), Phase::AwaitingChoice);
        assert!(lifecycle.try_commit().is_err());
        // Move only the private test clock boundary; no production knobs.
        lock(&lifecycle.state).choice_deadline = Some(Instant::now());
        assert!(lifecycle.expire_choice());
        let deadline = lock(&lifecycle.state).stop_deadline;
        assert_eq!(
            lifecycle.request_stop(Some(StopChoice::Wait)),
            StopPlan::AlreadyStopping { wait_seconds: 10 }
        );
        assert_eq!(lock(&lifecycle.state).stop_deadline, deadline);
        drop(work);
        assert_eq!(lifecycle.wait_for_drain().cut_off, 0);
    }

    #[test]
    fn wait_never_extends_a_decision_and_signal_wakes_the_drain() {
        let lifecycle = short_lifecycle();
        let work = lifecycle.try_commit().unwrap();
        lifecycle.request_stop(Some(StopChoice::Wait));
        let first = lock(&lifecycle.state).stop_deadline;
        lifecycle.request_stop(Some(StopChoice::Wait));
        assert_eq!(lock(&lifecycle.state).stop_deadline, first);
        let (sender, receiver) = mpsc::channel();
        let waiting = Arc::clone(&lifecycle);
        let waiter = thread::spawn(move || sender.send(waiting.wait_for_drain()).unwrap());
        lifecycle.signal_stop();
        let shortened = lock(&lifecycle.state).stop_deadline;
        assert!(shortened < first);
        lifecycle.request_stop(Some(StopChoice::Wait));
        assert_eq!(lock(&lifecycle.state).stop_deadline, shortened);
        let outcome = receiver.recv_timeout(Duration::from_millis(400)).unwrap();
        assert_eq!(
            outcome,
            DrainOutcome {
                wait_seconds: 10,
                cut_off: 1
            }
        );
        drop(work);
        // Later completion and retirement must not rewrite the stop answer.
        assert_eq!(lifecycle.retire(), outcome);
        assert_eq!(lifecycle.wait_for_drain(), outcome);
        waiter.join().unwrap();
    }

    #[test]
    fn signal_closes_pending_choice_and_wait_cannot_reopen_it() {
        let lifecycle = short_lifecycle();
        let work = lifecycle.try_commit().unwrap();
        lifecycle.request_stop(None);
        lifecycle.signal_stop();
        assert_eq!(lifecycle.phase(), Phase::Draining);
        assert!(lock(&lifecycle.state).choice_deadline.is_none());
        assert_eq!(
            lifecycle.request_stop(Some(StopChoice::Wait)),
            StopPlan::Drain { wait_seconds: 10 }
        );
        drop(work);
        assert_eq!(lifecycle.wait_for_drain().cut_off, 0);
    }

    #[test]
    fn completion_after_deadline_cannot_erase_a_cutoff_before_polling() {
        let lifecycle = short_lifecycle();
        let work = lifecycle.try_commit().unwrap();
        lifecycle.request_stop(Some(StopChoice::Now));
        lock(&lifecycle.state).stop_deadline = Some(Instant::now());
        drop(work);
        assert_eq!(lifecycle.committed_count(), 0);
        assert_eq!(
            lifecycle.poll_drain(Duration::ZERO),
            Some(DrainOutcome {
                wait_seconds: 10,
                cut_off: 1,
            })
        );
    }

    #[test]
    fn commit_and_stop_have_one_serialized_boundary() {
        for _ in 0..40 {
            let lifecycle = short_lifecycle();
            let barrier = Arc::new(Barrier::new(2));
            let worker_state = Arc::clone(&lifecycle);
            let worker_barrier = Arc::clone(&barrier);
            let worker = thread::spawn(move || {
                worker_barrier.wait();
                worker_state.try_commit()
            });
            barrier.wait();
            lifecycle.request_stop(Some(StopChoice::Now));
            let admitted = worker.join().unwrap();
            assert_eq!(lifecycle.committed_count(), usize::from(admitted.is_ok()));
            assert!(lifecycle.try_commit().is_err());
            drop(admitted);
            assert_eq!(lifecycle.wait_for_drain().cut_off, 0);
        }
    }

    #[test]
    fn open_work_wait_does_not_change_phase_or_chosen_budget() {
        let lifecycle = short_lifecycle();
        let work = lifecycle.try_commit().unwrap();
        assert_eq!(lifecycle.wait_for_open_work(Duration::ZERO), 1);
        assert_eq!(lifecycle.phase(), Phase::Running);
        lifecycle.request_stop(Some(StopChoice::Wait));
        let deadline = lock(&lifecycle.state).stop_deadline;
        let waiting = Arc::clone(&lifecycle);
        let waiter = thread::spawn(move || waiting.wait_for_open_work(Duration::from_secs(2)));
        drop(work);
        assert_eq!(waiter.join().unwrap(), 0);
        assert_eq!(lock(&lifecycle.state).stop_deadline, deadline);
        assert_eq!(lifecycle.phase(), Phase::Draining);
    }

    #[test]
    fn idle_shutdown_preserves_dispatching_committed_and_control_connections() {
        let lifecycle = short_lifecycle();
        let mut tracker = WorkerTracker::new();
        let (mut idle_client, idle_server) = UnixStream::pair().unwrap();
        let idle = tracker.register_connection(&idle_server).unwrap();
        let (mut active_client, mut active_server) = UnixStream::pair().unwrap();
        let active = tracker.register_connection(&active_server).unwrap();
        let work = lifecycle.try_commit_for(&active).unwrap();
        let (mut control_client, mut control_server) = UnixStream::pair().unwrap();
        let control = tracker.register_connection(&control_server).unwrap();
        let (mut dispatch_client, mut dispatch_server) = UnixStream::pair().unwrap();
        let dispatch = tracker.register_connection(&dispatch_server).unwrap();
        assert!(dispatch.mark_dispatching());
        for client in [
            &idle_client,
            &active_client,
            &control_client,
            &dispatch_client,
        ] {
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
        }
        assert!(control.mark_control());
        lifecycle.request_stop(Some(StopChoice::Now));
        assert_eq!(tracker.shutdown_idle(), 1);
        let mut byte = [0];
        assert_eq!(idle_client.read(&mut byte).unwrap(), 0);
        active_server.write_all(b"a").unwrap();
        active_client.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");
        control_server.write_all(b"c").unwrap();
        control_client.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"c");
        dispatch_server.write_all(b"d").unwrap();
        dispatch_client.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"d");
        // Dispatching alone is not a committed window and cannot admit one
        // after stopping, even though its socket gets a finishing allowance.
        assert_eq!(lifecycle.committed_count(), 1);
        assert!(lifecycle.try_commit_for(&dispatch).is_err());
        assert!(tracker.has_control_connections());
        assert_eq!(tracker.shutdown_non_control(), 2);
        assert_eq!(active_client.read(&mut byte).unwrap(), 0);
        assert_eq!(dispatch_client.read(&mut byte).unwrap(), 0);
        assert_eq!(tracker.shutdown_all(), 1);
        assert_eq!(control_client.read(&mut byte).unwrap(), 0);
        assert!(!tracker.has_control_connections());
        drop((work, idle, active, control, dispatch));
    }

    #[test]
    fn completed_connection_drops_its_clone_before_periodic_reaping() {
        let mut tracker = WorkerTracker::new();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let connection = tracker.register_connection(&server).unwrap();
        drop(server);
        drop(connection);
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        // The weak entry is deliberately still in the registry.
        assert_eq!(tracker.connections.len(), 1);
        tracker.reap_finished();
        assert!(tracker.connections.is_empty());
    }

    #[test]
    fn worker_panic_releases_windows_and_closes_the_connection() {
        let lifecycle = short_lifecycle();
        let mut tracker = WorkerTracker::new();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let connection = tracker.register_connection(&server).unwrap();
        let work = lifecycle.try_commit_for(&connection).unwrap();
        tracker.track_worker(thread::spawn(move || {
            let _server = server;
            let _connection = connection;
            let _work = work;
            panic!("test worker panic");
        }));
        lifecycle.request_stop(Some(StopChoice::Wait));
        assert_eq!(lifecycle.wait_for_drain().cut_off, 0);
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        wait_until(|| tracker.workers.iter().all(JoinHandle::is_finished));
        assert_eq!(
            tracker.reap_finished(),
            ReapOutcome {
                finished: 1,
                panicked: 1
            }
        );
        assert!(tracker.is_empty());
    }

    #[test]
    fn completed_workers_are_reaped_around_an_earlier_blocked_worker() {
        let mut tracker = WorkerTracker::new();
        let (release, wait) = mpsc::channel();
        tracker.track_worker(thread::spawn(move || wait.recv().unwrap()));
        tracker.track_worker(thread::spawn(|| {}));
        wait_until(|| tracker.workers[1].is_finished());
        assert_eq!(tracker.reap_finished().finished, 1);
        assert_eq!(tracker.workers.len(), 1);
        release.send(()).unwrap();
        wait_until(|| tracker.workers[0].is_finished());
        assert_eq!(tracker.reap_finished().finished, 1);
    }

    #[test]
    fn retired_workers_keep_pins_until_their_work_finishes() {
        let mut tracker = WorkerTracker::new();
        let pin = Arc::new(());
        let retained_pin = Arc::downgrade(&pin);
        let (release, wait) = mpsc::channel();
        tracker.track_worker(thread::spawn(move || {
            let _pin = pin;
            wait.recv().unwrap();
        }));
        let retired = tracker.into_retired();
        assert_eq!(retired.worker_count(), 1);
        retired.reap_in_background().unwrap();
        assert!(retained_pin.upgrade().is_some());
        release.send(()).unwrap();
        wait_until(|| retained_pin.upgrade().is_none());
    }

    #[test]
    fn failed_reaper_spawn_retains_worker_ownership() {
        let mut tracker = WorkerTracker::new();
        let (release, wait) = mpsc::channel();
        tracker.track_worker(thread::spawn(move || wait.recv().unwrap()));
        let error = tracker
            .into_retired()
            .reap_with_spawn(|_| Err(io::Error::other("test reaper spawn failure")));
        assert!(error.is_err());
        assert!(
            lock(&RETIRED_WITHOUT_REAPER)
                .iter()
                .any(|entry| !entry.workers.is_empty())
        );
        release.send(()).unwrap();
        wait_until(|| {
            let mut retained = lock(&RETIRED_WITHOUT_REAPER);
            for entry in retained.iter_mut() {
                reap_handles(&mut entry.workers);
            }
            retained.retain(|entry| !entry.workers.is_empty());
            retained.is_empty()
        });
    }
}
