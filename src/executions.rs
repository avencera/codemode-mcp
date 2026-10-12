//! Background script executions that outlive a single MCP call

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use tokio::sync::watch;

use crate::{
    executor::{ExecutionOutcome, Executor, ExecutorBusy},
    gateway::Gateway,
};

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

struct Entry {
    result: watch::Receiver<Option<Arc<ExecutionOutcome>>>,
    finished_at: Option<Instant>,
    /// Approximate size of the stored result, counted once finished
    bytes: usize,
}

type Registry = Mutex<HashMap<String, Entry>>;

/// Registry of running and recently finished executions
pub struct Executions {
    gateway: Arc<Gateway>,
    executor: Arc<Executor>,
    entries: Arc<Registry>,
    ttl: Duration,
    max_retained_bytes: usize,
}

impl Executions {
    /// Creates a registry keeping finished results for `ttl`, and no more
    /// than `max_retained_bytes` of them in total
    pub fn new(
        gateway: Arc<Gateway>,
        executor: Arc<Executor>,
        ttl: Duration,
        max_retained_bytes: usize,
    ) -> Self {
        Self {
            gateway,
            executor,
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            max_retained_bytes,
        }
    }

    /// Starts `code` in the background and returns its id
    ///
    /// Refused when every worker is busy and the wait queue is full
    pub fn start(&self, code: String) -> Result<String, ExecutorBusy> {
        self.purge();
        let ticket = self.executor.admit()?;

        let id = uuid::Uuid::new_v4().simple().to_string();
        let (sender, receiver) = watch::channel(None);
        lock(&self.entries).insert(
            id.clone(),
            Entry {
                result: receiver,
                finished_at: None,
                bytes: 0,
            },
        );

        let gateway = Arc::clone(&self.gateway);
        let executor = Arc::clone(&self.executor);
        let guard = FinishGuard {
            entries: Arc::clone(&self.entries),
            id: id.clone(),
            sender: Some(sender),
            max_retained_bytes: self.max_retained_bytes,
        };
        let task_id = id.clone();
        tokio::spawn(async move {
            let outcome = executor.run(ticket, &gateway, &task_id, code).await;

            guard.finish(outcome);
        });

        Ok(id)
    }

    /// Waits up to `budget` for the execution to finish
    pub async fn wait(&self, id: &str, budget: Duration) -> WaitResult {
        self.purge();

        let Some(mut receiver) = lock(&self.entries)
            .get(id)
            .map(|entry| entry.result.clone())
        else {
            return WaitResult::Unknown;
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

    fn purge(&self) {
        let ttl = self.ttl;
        lock(&self.entries).retain(|_, entry| {
            entry
                .finished_at
                .is_none_or(|finished| finished.elapsed() < ttl)
        });
    }
}

fn lock(entries: &Registry) -> MutexGuard<'_, HashMap<String, Entry>> {
    // a panic elsewhere must not take the registry down with it
    entries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Records the outcome of one execution, whether it ends normally or its task
/// dies (panic, runtime shutdown), so no entry stays "running" forever
struct FinishGuard {
    entries: Arc<Registry>,
    id: String,
    sender: Option<watch::Sender<Option<Arc<ExecutionOutcome>>>>,
    max_retained_bytes: usize,
}

impl FinishGuard {
    fn finish(mut self, outcome: ExecutionOutcome) {
        self.record(outcome);
    }

    fn record(&mut self, outcome: ExecutionOutcome) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        let bytes = retained_bytes(&outcome);

        {
            let mut entries = lock(&self.entries);
            // the entry is marked finished before waiters wake so it cannot
            // be purged between the two steps
            if let Some(entry) = entries.get_mut(&self.id) {
                entry.finished_at = Some(Instant::now());
                entry.bytes = bytes;
            }
            evict_oldest(&mut entries, &self.id, self.max_retained_bytes);
        }
        let _ = sender.send(Some(Arc::new(outcome)));
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        self.record(ExecutionOutcome::Failed {
            message: "the execution task ended unexpectedly (internal error)".to_owned(),
            output: String::new(),
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
        ExecutionOutcome::TypeError { diagnostics } => diagnostics.len(),
        ExecutionOutcome::Exception { message, output }
        | ExecutionOutcome::Failed { message, output } => message.len() + output.len(),
    }
}
