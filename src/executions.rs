//! Background script executions that outlive a single MCP call, and outlive
//! the daemon: every start and finish is written through to the database

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use rustix::process::{Pid, test_kill_process};
use tokio::{sync::watch, task::AbortHandle};

use crate::{
    durable::{Durable, Sensitivity},
    executor::{
        CompletedCall, ExecutionOutcome, Executor, ExecutorBusy, Finished, InterruptReason,
        ParkedState,
    },
    gateway::Gateway,
    snapshot::Sealed,
    store::{
        Store,
        executions::{RUNNING, StoredExecution, UnsettledExecution},
        now_ms,
        parked::StoredParked,
    },
    usage::{Caller, Classification, ExecutionRecord, Outcome},
};

/// How long past its time limit a one-off `exec` of another process is left
/// alone at boot
const EXEC_GRACE: Duration = Duration::from_secs(60);

/// How often a drain looks again at what still runs
const DRAIN_POLL: Duration = Duration::from_millis(100);

/// How often the database copy of finished results is purged at most, when
/// the purge is driven by traffic
const PURGE_EVERY: Duration = Duration::from_secs(30);

/// How often the housekeeping task purges while nobody calls
const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(60);

/// What a caller learns after waiting on an execution
#[derive(Debug, Clone)]
pub enum WaitResult {
    /// The execution finished
    Finished(Arc<ExecutionOutcome>),
    /// Still running when the wait budget ran out
    Pending,
    /// No execution with this id exists, or its result expired
    Unknown,
}

/// Why an execution could not be started
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Every worker is busy and the wait queue is full
    #[error(transparent)]
    Busy(#[from] ExecutorBusy),
    /// The daemon is shutting down
    #[error("the daemon is restarting and is not accepting new executions; retry in a few seconds")]
    Draining,
}

type Outcomes = watch::Sender<Option<Arc<ExecutionOutcome>>>;

struct Entry {
    result: watch::Receiver<Option<Arc<ExecutionOutcome>>>,
    finished_at: Option<Instant>,
    /// Approximate size of the stored result, counted once finished
    bytes: usize,
    /// Stops the task that runs the script
    task: Option<AbortHandle>,
    /// Whether the script is parked, waiting only on approvals
    parked: Arc<AtomicBool>,
}

/// What every execution task and the registry share
struct Shared {
    entries: Mutex<HashMap<String, Entry>>,
    store: Store,
    /// Set once the process stops writing for the executions it started: a
    /// task that dies afterwards is being torn down, not failing
    frozen: AtomicBool,
    draining: AtomicBool,
    last_purge: Mutex<Option<Instant>>,
}

impl Shared {
    fn entries(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        // a panic elsewhere must not take the registry down with it
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Registry of running and recently finished executions
pub struct Executions {
    gateway: Arc<Gateway>,
    executor: Arc<Executor>,
    shared: Arc<Shared>,
    ttl: Duration,
    max_retained_bytes: usize,
}

impl Executions {
    /// Creates a registry keeping finished results for `ttl`, and no more
    /// than `max_retained_bytes` of them in total, in memory and on disk
    pub fn new(
        gateway: Arc<Gateway>,
        executor: Arc<Executor>,
        ttl: Duration,
        max_retained_bytes: usize,
        store: Store,
    ) -> Self {
        Self {
            gateway,
            executor,
            shared: Arc::new(Shared {
                entries: Mutex::new(HashMap::new()),
                store,
                frozen: AtomicBool::new(false),
                draining: AtomicBool::new(false),
                last_purge: Mutex::new(None),
            }),
            ttl,
            max_retained_bytes,
        }
    }

    /// Starts `code` for `caller` in the background and returns its id
    ///
    /// Refused when every worker is busy and the wait queue is full, and
    /// while the daemon drains for a restart
    pub fn start(&self, code: String, caller: Caller) -> Result<String, StartError> {
        if self.shared.draining.load(Ordering::SeqCst) {
            return Err(StartError::Draining);
        }
        self.purge();
        let ticket = self.executor.admit()?;

        let id = uuid::Uuid::new_v4().simple().to_string();
        let started_ms = now_ms();
        // the row exists before the script runs, so a crash leaves a trace
        // that boot turns into `interrupted`
        if let Err(error) = self
            .shared
            .store
            .begin_execution(&id, started_ms, &caller, &code)
        {
            tracing::warn!(%error, "could not record the start of an execution");
        }

        let (guard, parked) = self.register(&id, started_ms, Instant::now(), &caller, &code);
        let gateway = Arc::clone(&self.gateway);
        let executor = Arc::clone(&self.executor);
        let task_id = id.clone();
        let task = tokio::spawn(async move {
            let finished = executor
                .run(ticket, &gateway, &task_id, code, caller, parked)
                .await;

            guard.finish(finished);
        });
        self.attach_task(&id, task.abort_handle());

        Ok(id)
    }

    /// Adds a running execution to the registry and returns the guard that
    /// settles it
    fn register(
        &self,
        id: &str,
        started_ms: i64,
        started: Instant,
        caller: &Caller,
        script: &str,
    ) -> (FinishGuard, Arc<AtomicBool>) {
        let (sender, receiver) = watch::channel(None);
        let sender = Arc::new(sender);
        let parked = Arc::new(AtomicBool::new(false));
        let guard = FinishGuard {
            shared: Arc::clone(&self.shared),
            sender: Some(Arc::clone(&sender)),
            max_retained_bytes: self.max_retained_bytes,
            meta: Meta {
                id: id.to_owned(),
                started_ms,
                started,
                caller: caller.clone(),
                script: script.to_owned(),
            },
        };
        self.shared.entries().insert(
            id.to_owned(),
            Entry {
                result: receiver,
                finished_at: None,
                bytes: 0,
                task: None,
                parked: Arc::clone(&parked),
            },
        );

        (guard, parked)
    }

    fn attach_task(&self, id: &str, task: AbortHandle) {
        if let Some(entry) = self.shared.entries().get_mut(id) {
            entry.task = Some(task);
        }
    }

    /// Settles what an earlier process left behind: executions parked while
    /// waiting for an approval resume, every other execution still marked
    /// running becomes `interrupted`
    ///
    /// Run once at boot, before the first execution starts
    pub fn recover(&self) {
        let unsettled = match self.shared.store.unsettled_executions() {
            Ok(unsettled) => unsettled,
            Err(error) => {
                tracing::warn!(%error, "could not list the executions a restart cut short");

                return;
            }
        };
        // a one-off `exec` of another process that is still running is not
        // ours to interrupt, within its time limit; the pid check alone would
        // keep a row forever if the pid were reused
        let exec_window = self.executor.execution_timeout() + EXEC_GRACE;
        let exec_since = now_ms().saturating_sub(millis(exec_window));
        let unsettled = unsettled
            .into_iter()
            .filter(|execution| {
                !(execution.exec
                    && execution.started_ms > exec_since
                    && execution.owner_pid.is_some_and(foreign_process_alive))
            })
            .collect::<Vec<_>>();
        let mut parked: HashMap<String, StoredParked> = match self.shared.store.parked_executions()
        {
            Ok(parked) => parked
                .into_iter()
                .map(|parked| (parked.execution_id.clone(), parked))
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "could not read the parked executions");

                HashMap::new()
            }
        };

        for execution in unsettled {
            let stored = parked.remove(&execution.id);
            let sensitive = execution.sensitive || stored.as_ref().is_some_and(|row| row.sensitive);
            let resumable = stored
                .filter(|_| !sensitive)
                .and_then(|row| self.parked_state(row));

            match resumable {
                Some((state, sealed)) => self.resume(execution, state, sealed),
                None => self.interrupt(&execution.id, sensitive),
            }
        }

        // a parked row whose execution already ended has nothing to resume
        for leftover in parked.into_keys() {
            if let Err(error) = self.shared.store.delete_parked(&leftover) {
                tracing::warn!(%error, "could not remove a stale parked row");
            }
        }
    }

    fn parked_state(&self, row: StoredParked) -> Option<(ParkedState, Sealed)> {
        let payload = row.payload?;
        match ParkedState::parse(&payload.state) {
            Ok(state) => Some((state, Sealed::from_parts(payload.dump, payload.tag))),
            Err(error) => {
                tracing::warn!(%error, execution = row.execution_id, "a parked execution is unreadable");

                None
            }
        }
    }

    fn interrupt(&self, id: &str, sensitive: bool) {
        let flagged =
            matches!(self.shared.store.stored_execution(id), Ok(Some(row)) if row.sensitive);
        let sensitive = sensitive || flagged;

        match self.shared.store.interrupt_execution(id, sensitive) {
            Ok(true) => tracing::info!(execution = id, "interrupted by a restart"),
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "could not interrupt an execution"),
        }
    }

    /// Runs a parked execution again under its old id
    fn resume(&self, execution: UnsettledExecution, state: ParkedState, sealed: Sealed) {
        let age =
            Duration::from_millis(u64::try_from(now_ms() - execution.started_ms).unwrap_or(0));
        let started = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        let caller = state.caller().clone();
        let script = state.script().to_owned();
        let state = state.reattach(self.gateway.approvals());
        let (guard, parked) = self.register(
            &execution.id,
            execution.started_ms,
            started,
            &caller,
            &script,
        );

        let gateway = Arc::clone(&self.gateway);
        let executor = Arc::clone(&self.executor);
        let id = execution.id.clone();
        let task = tokio::spawn(async move {
            let finished = executor.resume(&gateway, &id, state, sealed, parked).await;

            guard.finish(finished);
        });
        self.attach_task(&execution.id, task.abort_handle());
        tracing::info!(execution = execution.id, "resumed a parked execution");
    }

    /// Waits up to `budget` for the execution to finish
    ///
    /// An execution that is not in memory is looked up in the database, so a
    /// result survives a restart for the result TTL
    pub async fn wait(&self, id: &str, budget: Duration) -> WaitResult {
        self.purge();

        let Some(mut receiver) = self
            .shared
            .entries()
            .get(id)
            .map(|entry| entry.result.clone())
        else {
            return self.stored(id);
        };
        let finished = tokio::time::timeout(budget, receiver.wait_for(Option::is_some)).await;

        match finished {
            Ok(Ok(outcome)) => match outcome.as_ref() {
                Some(outcome) => WaitResult::Finished(Arc::clone(outcome)),
                None => WaitResult::Pending,
            },
            // the sender is gone without a result, which the guard prevents
            // unless the whole runtime is shutting down
            Ok(Err(_)) => WaitResult::Unknown,
            Err(_) => WaitResult::Pending,
        }
    }

    /// What the database says about an execution this process does not run
    fn stored(&self, id: &str) -> WaitResult {
        let row = match self.shared.store.stored_execution(id) {
            Ok(Some(row)) => row,
            Ok(None) => return WaitResult::Unknown,
            Err(error) => {
                tracing::warn!(%error, "could not read a stored execution");

                return WaitResult::Unknown;
            }
        };
        let Some(outcome) = self.stored_outcome(id, row) else {
            return WaitResult::Unknown;
        };

        WaitResult::Finished(Arc::new(outcome))
    }

    fn stored_outcome(&self, id: &str, row: StoredExecution) -> Option<ExecutionOutcome> {
        if row.outcome == RUNNING {
            // running in another process (`exec` while the daemon runs);
            // nothing here can wait for it
            return None;
        }
        if row.outcome == Outcome::Interrupted.as_str() {
            let reason = if row.sensitive {
                InterruptReason::SensitiveNotKept
            } else {
                InterruptReason::Restarted
            };

            return Some(self.interrupted(id, reason));
        }
        let ttl_ms = self.ttl.as_millis().min(i64::MAX as u128) as i64;
        if row.finished_ms.saturating_add(ttl_ms) <= now_ms() {
            return None;
        }
        // finished, but the result was withheld because the script used a
        // sensitive server
        let Some(result) = row.result else {
            return row.sensitive.then_some(ExecutionOutcome::ResultNotKept {
                outcome: row.outcome,
            });
        };

        match serde_json::from_str(&result) {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                tracing::warn!(%error, "a stored execution result is unreadable");

                None
            }
        }
    }

    /// The outcome of an execution a restart cut short, listing the upstream
    /// calls that completed before it stopped
    pub fn interrupted(&self, id: &str, reason: InterruptReason) -> ExecutionOutcome {
        let calls = match self.shared.store.upstream_calls_of(id) {
            Ok(calls) => calls
                .into_iter()
                .map(|(server, tool, status)| CompletedCall {
                    server,
                    tool,
                    status,
                })
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "could not list the upstream calls of an interrupted execution");

                Vec::new()
            }
        };

        ExecutionOutcome::Interrupted { reason, calls }
    }

    /// Stops writing for executions this process started and ends their
    /// tasks, as if the process had died: nothing they would still have
    /// recorded reaches the database
    ///
    /// Used when a daemon is replaced inside one process (tests) and after a
    /// drain, once every execution still running was marked interrupted
    pub fn halt(&self) {
        self.shared.frozen.store(true, Ordering::SeqCst);
        self.executor.freeze();
        for entry in self.shared.entries().values() {
            if let Some(task) = &entry.task {
                task.abort();
            }
        }
    }

    /// Stops admitting executions and gives running ones up to `limit` to
    /// finish; those waiting only on approvals are already parked, and stay
    /// that way for the next process to resume
    ///
    /// Whatever still runs when the time is up is marked `interrupted`
    /// (without ending its task, which the process exit does). Returns the
    /// ids that were interrupted
    pub async fn drain(&self, limit: Duration) -> Vec<String> {
        self.shared.draining.store(true, Ordering::SeqCst);

        let deadline = Instant::now() + limit;
        while !self.running_ids().is_empty() && Instant::now() < deadline {
            tokio::time::sleep(DRAIN_POLL).await;
        }

        let interrupted = self.running_ids();
        for id in &interrupted {
            self.interrupt(id, false);
        }

        interrupted
    }

    /// Executions that neither finished nor sit parked on an approval
    fn running_ids(&self) -> Vec<String> {
        self.shared
            .entries()
            .iter()
            .filter(|(_, entry)| {
                entry.finished_at.is_none() && !entry.parked.load(Ordering::SeqCst)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Purges expired and over-budget results now, in memory and in the
    /// database; the audit rows stay
    pub fn purge_now(&self) {
        self.forget_expired();
        self.purge_stored();
    }

    /// Purges once at boot and then every minute for as long as the registry
    /// lives, so results are dropped on time when no call arrives to do it
    pub fn start_housekeeping(self: &Arc<Self>) {
        self.purge_now();

        let registry = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(HOUSEKEEPING_EVERY);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(executions) = registry.upgrade() else {
                    return;
                };
                if executions.shared.frozen.load(Ordering::SeqCst) {
                    return;
                }
                executions.purge_now();
            }
        });
    }

    fn forget_expired(&self) {
        let ttl = self.ttl;
        self.shared.entries().retain(|_, entry| {
            entry
                .finished_at
                .is_none_or(|finished| finished.elapsed() < ttl)
        });
    }

    fn purge_stored(&self) {
        let ttl = self.ttl;
        let cutoff = now_ms().saturating_sub(ttl.as_millis().min(i64::MAX as u128) as i64);
        if let Err(error) = self
            .shared
            .store
            .purge_results(cutoff, self.max_retained_bytes)
        {
            tracing::warn!(%error, "could not purge stored execution results");
        }
    }

    fn purge(&self) {
        self.forget_expired();

        let due = {
            let mut last = self
                .shared
                .last_purge
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let due = last.is_none_or(|last| last.elapsed() >= PURGE_EVERY);
            if due {
                *last = Some(Instant::now());
            }

            due
        };
        if due {
            self.purge_stored();
        }
    }
}

/// What the finish record needs to know about the execution
struct Meta {
    id: String,
    started_ms: i64,
    started: Instant,
    caller: Caller,
    script: String,
}

/// Records the outcome of one execution, whether it ends normally or its task
/// dies (panic, runtime shutdown), so no entry stays "running" forever
struct FinishGuard {
    shared: Arc<Shared>,
    sender: Option<Arc<Outcomes>>,
    max_retained_bytes: usize,
    meta: Meta,
}

impl FinishGuard {
    fn finish(mut self, finished: Finished) {
        self.record(finished);
    }

    fn record(&mut self, finished: Finished) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        let Finished {
            outcome,
            sensitivity,
        } = finished;
        let bytes = retained_bytes(&outcome);

        // written before waiters wake: anything an agent was told is on disk
        if !self.shared.frozen.load(Ordering::SeqCst) {
            let record = ExecutionRecord {
                id: self.meta.id.clone(),
                started_ms: self.meta.started_ms,
                caller: self.meta.caller.clone(),
                script: self.meta.script.clone(),
                classification: outcome.classification(),
                duration: self.meta.started.elapsed(),
                result_bytes: bytes,
            };
            let result = Durable::gate(sensitivity, || {
                serde_json::to_string(&outcome).unwrap_or_else(|error| {
                    tracing::warn!(%error, "could not serialize an execution result");

                    String::new()
                })
            });
            if let Err(error) = self.shared.store.finish_execution(&record, &result) {
                tracing::warn!(%error, "could not record a finished execution");
            }
        }

        {
            let mut entries = self.shared.entries();
            // the entry is marked finished before waiters wake so it cannot
            // be purged between the two steps
            if let Some(entry) = entries.get_mut(&self.meta.id) {
                entry.finished_at = Some(Instant::now());
                entry.bytes = bytes;
            }
            evict_oldest(&mut entries, &self.meta.id, self.max_retained_bytes);
        }
        let _ = sender.send(Some(Arc::new(outcome)));
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        let message = "the execution task ended unexpectedly (internal error)";
        self.record(Finished {
            outcome: ExecutionOutcome::Failed {
                message: message.to_owned(),
                output: String::new(),
                class: Classification::new(Outcome::RuntimeError, message),
            },
            sensitivity: Sensitivity::PLAIN,
        });
    }
}

/// Drops the oldest finished results, never `keep`, until the total fits
fn evict_oldest(entries: &mut HashMap<String, Entry>, keep: &str, max_bytes: usize) {
    let mut total: usize = entries.values().map(|entry| entry.bytes).sum();
    if total <= max_bytes {
        return;
    }

    let mut finished: Vec<(Instant, String)> = entries
        .iter()
        .filter(|(id, _)| id.as_str() != keep)
        .filter_map(|(id, entry)| Some((entry.finished_at?, id.clone())))
        .collect();
    finished.sort();
    for (_, id) in finished {
        if total <= max_bytes {
            break;
        }
        if let Some(entry) = entries.remove(&id) {
            total = total.saturating_sub(entry.bytes);
        }
    }
}

/// Rough memory held by a stored outcome
fn retained_bytes(outcome: &ExecutionOutcome) -> usize {
    match outcome {
        ExecutionOutcome::Completed {
            value,
            notes,
            output,
            ..
        } => value.to_string().len() + output.len() + notes.iter().map(String::len).sum::<usize>(),
        ExecutionOutcome::TypeError { diagnostics, .. } => diagnostics.len(),
        ExecutionOutcome::Exception {
            message, output, ..
        }
        | ExecutionOutcome::Failed {
            message, output, ..
        } => message.len() + output.len(),
        ExecutionOutcome::ResultNotKept { .. } => 0,
        ExecutionOutcome::Interrupted { calls, .. } => calls
            .iter()
            .map(|call| call.server.len() + call.tool.len() + call.status.len())
            .sum(),
    }
}

/// Whether `pid` is a live process other than this one
fn foreign_process_alive(pid: i64) -> bool {
    if pid == i64::from(std::process::id()) {
        return false;
    }
    let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return false;
    };

    // EPERM means the process exists but belongs to someone else
    match test_kill_process(pid) {
        Ok(()) => true,
        Err(error) => error == rustix::io::Errno::PERM,
    }
}

fn millis(duration: Duration) -> i64 {
    duration.as_millis().min(i64::MAX as u128) as i64
}
