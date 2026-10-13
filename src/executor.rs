//! Runs agent scripts in Monty workers, answering their tool calls

use std::{
    collections::{BTreeSet, HashSet},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use monty_pool::{
    Checkout, OnPrint, Pool, PoolConfig, PoolError, ReplConfig, ResumeValue, TurnEvent,
    on_print_sync,
};
use monty_types::{
    ExcType, MontyException, MontyObject, NameLookupResult, OsFunctionCall, ResourceLimits,
};
use serde_json::{Map, Value};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError},
    task::JoinSet,
};

use crate::{
    approvals::Verdict,
    bans,
    budget::Budget,
    catalog::Catalog,
    config::{Config, Limits},
    convert::{ConvertLimits, monty_to_argument, monty_to_json},
    gateway::{CallContext, Gateway, Plan, PreparedCall, ToolCallError},
    snapshot::{Sealed, Sealer},
    usage::{Caller, Classification, Outcome},
};

/// Grace added to the script budget before the pool kills a stuck worker
const WORKER_KILL_MARGIN: Duration = Duration::from_secs(30);
/// How long a queued execution waits for a free worker before giving up
const QUEUE_TIMEOUT: Duration = Duration::from_secs(60);
/// Workers reserved for validating catalog stubs, so validation never waits
/// behind (or starves) user scripts
const VALIDATION_WORKERS: usize = 2;
/// How long one validation snippet may take
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Workers are recycled after this many scripts to bound slow leaks
const CHECKOUTS_PER_WORKER: u32 = 500;

/// Failures setting up the executor
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// The snapshot key could not be prepared
    #[error(transparent)]
    Snapshot(#[from] crate::snapshot::SnapshotError),
    /// The Monty worker binary could not be located
    #[error(
        "monty worker binary not found; set `worker_path` in the config, run `codemode-mcp service install`, or put `monty` on PATH"
    )]
    WorkerNotFound,
    /// The worker pool could not start
    #[error("failed to start the monty worker pool: {0}")]
    Pool(#[from] PoolError),
}

/// Every worker is busy and the wait queue is full
#[derive(Debug, thiserror::Error)]
#[error(
    "busy: all {workers} sandbox workers are in use and {queued} executions are already \
     waiting; retry in a few seconds"
)]
pub struct ExecutorBusy {
    workers: usize,
    queued: usize,
}

/// Stub validation could not run, so nothing can be said about the stubs
#[derive(Debug, thiserror::Error)]
#[error("stub validation unavailable: {0}")]
pub struct ValidationUnavailable(String);

/// A place in line for a worker, taken when an execution is accepted
///
/// Holding it before the script starts is what makes "busy" an immediate
/// answer rather than a hidden wait
pub struct Ticket {
    slots: Arc<Semaphore>,
    state: TicketState,
}

enum TicketState {
    Ready(OwnedSemaphorePermit),
    Queued(QueuedSlot),
}

/// Counts one waiting execution while alive
struct QueuedSlot(Arc<AtomicUsize>);

impl Drop for QueuedSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Ticket {
    async fn permit(self) -> Result<OwnedSemaphorePermit, String> {
        match self.state {
            TicketState::Ready(permit) => Ok(permit),
            TicketState::Queued(_slot) => {
                match tokio::time::timeout(QUEUE_TIMEOUT, self.slots.acquire_owned()).await {
                    Ok(Ok(permit)) => Ok(permit),
                    Ok(Err(_)) => Err("the executor is shutting down".to_owned()),
                    Err(_) => Err(format!(
                        "busy: no sandbox worker became free within {QUEUE_TIMEOUT:?}; retry"
                    )),
                }
            }
        }
    }
}

/// How a script run ended
#[derive(Debug, Clone)]
pub enum ExecutionOutcome {
    /// The script finished and produced a value
    Completed {
        /// Value of the last expression, as JSON
        value: Value,
        /// Whether the value was cut short by the result size limit
        truncated: bool,
        /// Remarks about lossy conversions
        notes: Vec<String>,
        /// Text the script printed
        output: String,
    },
    /// The type checker rejected the script, so nothing ran
    TypeError {
        /// Rendered diagnostics
        diagnostics: String,
        /// Usage-log classification
        class: Classification,
    },
    /// The script raised an exception or hit a sandbox limit
    Exception {
        /// Traceback text
        message: String,
        /// Text the script printed before failing
        output: String,
        /// Usage-log classification
        class: Classification,
    },
    /// The worker or the gateway failed; not the script's fault
    Failed {
        /// What went wrong
        message: String,
        /// Text the script printed before failing
        output: String,
        /// Usage-log classification
        class: Classification,
    },
}

impl ExecutionOutcome {
    /// Usage-log classification of this outcome
    pub fn classification(&self) -> Classification {
        match self {
            Self::Completed { .. } => Classification::ok(),
            Self::TypeError { class, .. }
            | Self::Exception { class, .. }
            | Self::Failed { class, .. } => class.clone(),
        }
    }

    fn failed(message: impl Into<String>, output: String, outcome: Outcome) -> Self {
        let message = message.into();

        Self::Failed {
            class: Classification::new(outcome, message.clone()),
            message,
            output,
        }
    }
}

/// Classifies type-checker diagnostics by their rule codes: only unresolved
/// names are a `name_error`, only unresolved imports an `import_error`
pub fn classify_typing(diagnostics: &str) -> Classification {
    let mut rules = BTreeSet::new();
    let mut first_message = None;
    let mut names = Vec::new();
    for line in diagnostics.lines() {
        let Some(rest) = line.strip_prefix("error[") else {
            continue;
        };
        let Some((rule, message)) = rest.split_once("]:") else {
            continue;
        };
        rules.insert(rule.to_owned());
        let message = message.trim();
        first_message.get_or_insert_with(|| message.to_owned());
        if rule == "unresolved-reference"
            && let Some(name) = message
                .strip_prefix("Name `")
                .and_then(|rest| rest.split_once('`'))
                .map(|(name, _)| name.to_owned())
        {
            names.push(name);
        }
    }

    let rule_list = rules.iter().cloned().collect::<Vec<_>>().join(", ");
    if rules.len() == 1 && rules.contains("unresolved-reference") {
        names.dedup();

        return Classification::new(
            Outcome::NameError,
            format!("unresolved-reference: {}", names.join(", ")),
        );
    }
    if rules.len() == 1 && rules.contains("unresolved-import") {
        return Classification::new(
            Outcome::ImportError,
            format!("unresolved-import: {}", first_message.unwrap_or_default()),
        );
    }

    Classification::new(
        Outcome::TypeError,
        match first_message {
            Some(message) => format!("{rule_list}: {message}"),
            None => "type check failed".to_owned(),
        },
    )
}

/// Collects `print` output up to a byte cap
#[derive(Clone)]
struct OutputSink {
    buffer: Arc<Mutex<String>>,
    cap: usize,
}

impl OutputSink {
    fn new(cap: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(String::new())),
            cap,
        }
    }

    fn push(&self, text: &str) {
        let Ok(mut buffer) = self.buffer.lock() else {
            return;
        };
        if buffer.len() >= self.cap {
            return;
        }
        let room = self.cap - buffer.len();
        if text.len() <= room {
            buffer.push_str(text);
        } else {
            let mut end = room;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            buffer.push_str(&text[..end]);
            buffer.push_str("\n[output truncated]\n");
        }
    }

    fn take(&self) -> String {
        self.buffer
            .lock()
            .map(|mut buffer| std::mem::take(&mut *buffer))
            .unwrap_or_default()
    }
}

/// An error handed to the script by the host, remembered so the final
/// exception can be traced back to it
#[derive(Debug, Clone)]
struct Failure {
    exc_type: ExcType,
    message: String,
    outcome: Outcome,
    /// `<function>`, for redacted details
    label: String,
    sensitive: bool,
}

/// The host's answer to one suspension
struct Answer {
    value: ResumeValue,
    failure: Option<Failure>,
}

impl Answer {
    fn value(value: MontyObject) -> Self {
        Self {
            value: ResumeValue::Return(value),
            failure: None,
        }
    }

    fn error(kind: ExcType, message: String) -> Self {
        Self {
            value: ResumeValue::Error(MontyException::new(kind, Some(message))),
            failure: None,
        }
    }

    fn tool_error(error: &ToolCallError, label: &str, sensitive: bool) -> Self {
        let message = error.to_string();

        Self {
            value: ResumeValue::Error(MontyException::new(
                error.exception_type(),
                Some(message.clone()),
            )),
            failure: Some(Failure {
                exc_type: error.exception_type(),
                message,
                outcome: error.outcome(),
                label: label.to_owned(),
                sensitive,
            }),
        }
    }
}

type ToolFuture = Pin<Box<dyn Future<Output = Answer> + Send>>;

/// The Monty worker pools plus the limits every script runs under
pub struct Executor {
    pool: Pool,
    /// Separate from `pool` so stub validation has capacity of its own
    validation_pool: Pool,
    limits: Limits,
    slots: Arc<Semaphore>,
    queued: Arc<AtomicUsize>,
    sealer: Sealer,
}

impl Executor {
    /// Starts the worker pools described by `config`; `sealer` protects
    /// sessions dumped while they wait for an approval
    pub async fn new(config: &Config, sealer: Sealer) -> Result<Self, ExecutorError> {
        let worker = resolve_worker(config.worker_path.as_deref())?;
        let limits = config.limits.clone();

        let mut pool = PoolConfig::subprocess(&worker);
        pool.max_processes = limits.max_workers;
        pool.checkout_timeout = Some(QUEUE_TIMEOUT);
        pool.request_timeout =
            Some(Duration::from_secs(limits.script_time_budget_secs) + WORKER_KILL_MARGIN);
        pool.max_checkouts_per_worker = Some(CHECKOUTS_PER_WORKER);

        let mut validation = PoolConfig::subprocess(&worker);
        validation.min_processes = 0;
        validation.max_processes = VALIDATION_WORKERS;
        validation.checkout_timeout = Some(VALIDATION_TIMEOUT);
        validation.request_timeout = Some(VALIDATION_TIMEOUT);
        validation.max_checkouts_per_worker = Some(CHECKOUTS_PER_WORKER);

        Ok(Self {
            pool: Pool::new(pool).await?,
            validation_pool: Pool::new(validation).await?,
            slots: Arc::new(Semaphore::new(limits.max_workers)),
            queued: Arc::new(AtomicUsize::new(0)),
            limits,
            sealer,
        })
    }

    /// Reserves a place for one execution, or refuses it when every worker
    /// is busy and the queue is full
    pub fn admit(&self) -> Result<Ticket, ExecutorBusy> {
        let slots = Arc::clone(&self.slots);
        match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => {
                return Ok(Ticket {
                    slots,
                    state: TicketState::Ready(permit),
                });
            }
            Err(TryAcquireError::Closed) => {
                return Err(ExecutorBusy {
                    workers: self.limits.max_workers,
                    queued: 0,
                });
            }
            Err(TryAcquireError::NoPermits) => {}
        }

        let waiting = self.queued.fetch_add(1, Ordering::SeqCst);
        let slot = QueuedSlot(Arc::clone(&self.queued));
        if waiting >= self.limits.max_queued_executions {
            return Err(ExecutorBusy {
                workers: self.limits.max_workers,
                queued: waiting,
            });
        }

        Ok(Ticket {
            slots,
            state: TicketState::Queued(slot),
        })
    }

    /// Runs `code` against the catalog as it is when the run starts
    pub async fn run(
        &self,
        ticket: Ticket,
        gateway: &Arc<Gateway>,
        execution_id: &str,
        code: String,
        caller: Caller,
    ) -> ExecutionOutcome {
        // before taking a worker: a refused script costs no sandbox time
        let bans = bans::find(&code);
        if !bans.is_empty() {
            let diagnostics = bans::diagnostics(&bans);

            return ExecutionOutcome::TypeError {
                class: classify_typing(&diagnostics),
                diagnostics,
            };
        }

        let permit = match ticket.permit().await {
            Ok(permit) => permit,
            Err(message) => return ExecutionOutcome::failed(message, String::new(), Outcome::Busy),
        };

        // started after queueing, so waiting for a worker costs no budget
        let budget = Budget::new(self.limits.execution_timeout());
        let catalog = gateway.catalog();
        let output = OutputSink::new(self.limits.max_output_bytes);

        let session = match self
            .pool
            .checkout(&self.repl_config(catalog.check_stubs()))
            .await
        {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(%error, "could not start a sandbox");

                return ExecutionOutcome::failed(
                    "could not start a sandbox worker; retry shortly",
                    String::new(),
                    Outcome::Busy,
                );
            }
        };

        let inputs = tool_inputs(&catalog);
        let mut driver = Driver {
            executor: self,
            gateway: Arc::clone(gateway),
            stubs: catalog.check_stubs().to_owned(),
            context: CallContext {
                execution_id: Arc::from(execution_id),
                catalog,
                budget: budget.clone(),
                caller,
                script: Arc::from(code.as_str()),
            },
            session: Some(session),
            permit: Some(permit),
            parked: None,
            running: JoinSet::new(),
            deciding: JoinSet::new(),
            gated: BTreeSet::new(),
            output: output.clone(),
            slept: Duration::ZERO,
            max_sleep: Duration::from_secs(self.limits.max_total_sleep_secs),
            failures: Vec::new(),
            sensitive_used: false,
        };
        let finished = tokio::select! {
            result = driver.run(code, inputs) => Some(result),
            () = budget.expired() => None,
        };
        let Some(result) = finished else {
            // the worker is stuck mid-turn, so it is dropped rather than
            // reset; dropping the driver cancels the in-flight tool calls and
            // withdraws pending approvals
            drop(driver);

            return ExecutionOutcome::failed(
                format!(
                    "the execution exceeded its {:?} wall-clock limit and was stopped",
                    self.limits.execution_timeout()
                ),
                output.take(),
                Outcome::Timeout,
            );
        };

        // typing and runtime errors leave the worker healthy; finish returns it
        // to the pool, and discards it when it was already lost
        driver.release().await;

        match result {
            Ok(value) => match monty_to_json(
                value.as_ref(),
                ConvertLimits::result(self.limits.max_result_bytes),
            ) {
                Ok(converted) => ExecutionOutcome::Completed {
                    value: converted.value,
                    truncated: converted.truncated,
                    notes: converted.notes,
                    output: output.take(),
                },
                Err(error) => {
                    let message =
                        format!("ValueError: the result is not JSON-serializable: {error}");
                    // a colliding key can quote a sensitive tool's data
                    let detail = if driver.sensitive_used {
                        "ValueError".to_owned()
                    } else {
                        message.clone()
                    };

                    ExecutionOutcome::Exception {
                        class: Classification::new(Outcome::RuntimeError, detail),
                        message,
                        output: output.take(),
                    }
                }
            },
            Err(PoolError::Typing(diagnostics)) => ExecutionOutcome::TypeError {
                class: classify_typing(&diagnostics),
                diagnostics,
            },
            Err(PoolError::Runtime(exception)) => ExecutionOutcome::Exception {
                class: driver.classify_exception(&exception),
                message: exception.to_string(),
                output: output.take(),
            },
            Err(PoolError::Timeout { timeout }) => ExecutionOutcome::failed(
                format!("the sandbox worker stopped responding within {timeout:?} and was killed"),
                output.take(),
                Outcome::Timeout,
            ),
            Err(error) => {
                // pool errors can carry worker paths and protocol internals;
                // the agent gets the gist and the log keeps the rest
                tracing::warn!(%error, "execution failed in the sandbox");

                ExecutionOutcome::failed(
                    "the sandbox worker failed (internal error); retry the script",
                    output.take(),
                    Outcome::RuntimeError,
                )
            }
        }
    }

    /// Takes a worker slot back for an execution that gave its slot up while
    /// waiting for an approval
    async fn reacquire(&self) -> Result<OwnedSemaphorePermit, PoolError> {
        match tokio::time::timeout(QUEUE_TIMEOUT, Arc::clone(&self.slots).acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => Err(PoolError::Exhausted),
        }
    }

    /// Returns the tools whose generated stub the type checker rejects
    ///
    /// A single bad stub would otherwise make every script fail type checking.
    /// Fails when validation cannot run, because accepting unchecked stubs
    /// could break every script
    pub async fn rejected_stubs(
        &self,
        catalog: &Catalog,
    ) -> Result<HashSet<String>, ValidationUnavailable> {
        if catalog.entries().is_empty() {
            return Ok(HashSet::new());
        }
        if self
            .reference_all(
                catalog.check_stubs(),
                catalog.entries().iter().map(|e| e.function.as_str()),
            )
            .await?
        {
            return Ok(HashSet::new());
        }

        let mut rejected = HashSet::new();
        for entry in catalog.entries() {
            let stub = Catalog::check_stub_for(entry);
            if !self
                .reference_all(&stub, std::iter::once(entry.function.as_str()))
                .await?
            {
                rejected.insert(entry.function.clone());
            }
        }

        Ok(rejected)
    }

    /// Type checks a snippet that mentions each name, reporting whether it passed
    async fn reference_all<'a>(
        &self,
        stubs: &str,
        names: impl Iterator<Item = &'a str>,
    ) -> Result<bool, ValidationUnavailable> {
        let names: Vec<&str> = names.collect();
        let snippet = format!("[{}]", names.join(", "));
        let inputs: Vec<(String, MontyObject)> = names
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    MontyObject::function((*name).to_owned(), None),
                )
            })
            .collect();

        let mut session = self
            .validation_pool
            .checkout(&self.repl_config(stubs))
            .await
            .map_err(|error| ValidationUnavailable(error.to_string()))?;
        let mut sink = on_print_sync(|_, _| {});
        let outcome = session
            .feed(snippet, inputs, vec![], false, &mut sink)
            .await;

        let passed = match outcome {
            Err(PoolError::Typing(_)) => false,
            // type checking precedes execution, so a runtime error still means it passed
            Ok(_) | Err(PoolError::Runtime(_)) => true,
            Err(error) => return Err(ValidationUnavailable(error.to_string())),
        };
        let _ = session.finish().await;

        Ok(passed)
    }

    fn repl_config(&self, stubs: &str) -> ReplConfig {
        let mut limits = ResourceLimits::default();
        limits.max_memory = Some(self.limits.max_memory_bytes);
        limits.max_feed_duration = Some(Duration::from_secs(self.limits.script_time_budget_secs));
        limits.max_suspensions = self.limits.max_suspensions;
        limits.max_total_sleep = Some(Duration::from_secs(self.limits.max_total_sleep_secs));

        ReplConfig {
            script_name: "script.py".to_owned(),
            limits: Some(limits),
            type_check: true,
            type_check_stubs: Some(stubs.to_owned()),
            ..ReplConfig::default()
        }
    }
}

fn tool_inputs(catalog: &Catalog) -> Vec<(String, MontyObject)> {
    catalog
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.function.clone(),
                MontyObject::function(entry.function.clone(), None),
            )
        })
        .collect()
}

/// Locates the worker binary: the configured path, else the copy `service
/// install` makes, else `monty` on `PATH`
fn resolve_worker(configured: Option<&Path>) -> Result<PathBuf, ExecutorError> {
    if let Some(path) = configured {
        return if path.is_file() {
            Ok(path.to_owned())
        } else {
            Err(ExecutorError::WorkerNotFound)
        };
    }
    if let Some(home) = std::env::var_os("HOME") {
        let installed = crate::service::default_worker_path(Path::new(&home));
        if installed.is_file() {
            return Ok(installed);
        }
    }

    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join("monty"))
        .find(|candidate| candidate.is_file())
        .ok_or(ExecutorError::WorkerNotFound)
}

/// A session dumped while it waited only on approvals
struct Parked {
    sealed: Sealed,
    /// Call ids the dumped session was waiting on
    pending: Vec<u32>,
}

/// Answers the suspensions of one running script
struct Driver<'a> {
    executor: &'a Executor,
    gateway: Arc<Gateway>,
    /// Type-check stubs, for restoring a parked session
    stubs: String,
    /// Shared by every tool call of the execution, including the catalog
    /// snapshot it started with
    context: CallContext,
    /// `None` while parked
    session: Option<Checkout>,
    /// Worker slot; released while parked
    permit: Option<OwnedSemaphorePermit>,
    parked: Option<Parked>,
    running: JoinSet<(u32, Answer)>,
    /// Approval-gated calls waiting for a decision
    deciding: JoinSet<(u32, Verdict, PreparedCall)>,
    /// Call ids in `deciding`
    gated: BTreeSet<u32>,
    output: OutputSink,
    slept: Duration,
    max_sleep: Duration,
    /// Errors handed to the script, newest last
    failures: Vec<Failure>,
    /// A sensitive server answered a call, so exception text may hold its data
    sensitive_used: bool,
}

/// What to do with a tool call
enum Step {
    Ready(ToolFuture),
    Gated(PreparedCall, crate::approvals::Waiting),
}

impl Driver<'_> {
    fn session(&mut self) -> Result<&mut Checkout, PoolError> {
        self.session.as_mut().ok_or(PoolError::Finished)
    }

    async fn run(
        &mut self,
        code: String,
        inputs: Vec<(String, MontyObject)>,
    ) -> Result<MontyObject, PoolError> {
        let sink = self.output.clone();
        let mut print = on_print_sync(move |_, text| sink.push(text));

        let mut event = self
            .session()?
            .feed(code, inputs, vec![], false, &mut print)
            .await?;
        loop {
            event = match event {
                TurnEvent::Complete(value) => return Ok(value),
                TurnEvent::FunctionCall {
                    function_name,
                    args,
                    call_id,
                    allow_eager_await,
                    ..
                } => match self.plan(function_name, &args) {
                    Step::Ready(call) => {
                        self.dispatch(call_id, allow_eager_await, call, &mut print)
                            .await?
                    }
                    Step::Gated(call, waiting) => {
                        // always a future, even when awaited directly, so the
                        // session can be dumped at ResolveFutures while a
                        // person decides
                        self.gated.insert(call_id);
                        self.deciding.spawn(async move {
                            let verdict = waiting.decision().await;

                            (call_id, verdict, call)
                        });

                        self.session()?
                            .resume(ResumeValue::Future, &mut print)
                            .await?
                    }
                },
                TurnEvent::OsCall {
                    function_name,
                    call_id,
                    allow_eager_await,
                    system_sleep: Some(delay),
                    ..
                } => {
                    let call = self.sleep_call(delay);
                    // Monty names sleeps `system.async_sleep` / `system.sleep`;
                    // only the async form may be answered with a future
                    if OsFunctionCall::accepts_future(&function_name) {
                        self.dispatch(call_id, allow_eager_await, call, &mut print)
                            .await?
                    } else {
                        // `time.sleep` blocks the script, so answer it in place
                        let answer = call.await;
                        let value = self.deliver_one(answer);
                        self.session()?.resume(value, &mut print).await?
                    }
                }
                TurnEvent::OsCall { .. } => {
                    self.session()?
                        .resume(ResumeValue::NotHandled, &mut print)
                        .await?
                }
                TurnEvent::NameLookup { .. } => {
                    self.session()?
                        .resume_name_lookup(NameLookupResult::Undefined, &mut print)
                        .await?
                }
                TurnEvent::ResolveFutures { .. } => {
                    let finished = self.next_finished(&mut print).await?;

                    self.session()?.resume_futures(finished, &mut print).await?
                }
            };
        }
    }

    /// Returns the worker to the pool after the script ended
    async fn release(&mut self) {
        if let Some(session) = self.session.take()
            && let Err(error) = session.finish().await
        {
            tracing::debug!(%error, "releasing sandbox");
        }
        self.permit = None;
    }

    /// Either answers a call immediately or parks it as a future so sibling
    /// calls under `asyncio.gather` run concurrently
    async fn dispatch(
        &mut self,
        call_id: u32,
        allow_eager_await: bool,
        call: ToolFuture,
        print: OnPrint<'_>,
    ) -> Result<TurnEvent, PoolError> {
        if allow_eager_await {
            // the script awaits this call straight away, so nothing else could
            // make progress meanwhile
            let answer = call.await;
            let value = self.deliver_one(answer);

            return self
                .session()?
                .resume_futures(vec![(call_id, value)], print)
                .await;
        }

        self.running.spawn(async move { (call_id, call.await) });

        self.session()?.resume(ResumeValue::Future, print).await
    }

    /// Waits until at least one outstanding call can be answered
    ///
    /// When only approval-gated calls remain, the wall-clock budget stops and
    /// the session is dumped so the worker serves other scripts meanwhile
    async fn next_finished(
        &mut self,
        print: OnPrint<'_>,
    ) -> Result<Vec<(u32, ResumeValue)>, PoolError> {
        loop {
            if self.running.is_empty() {
                if self.deciding.is_empty() {
                    return Err(PoolError::Protocol("no futures running".into()));
                }

                let paused = self.context.budget.pause();
                self.park().await;
                let decided = match self.deciding.join_next().await {
                    Some(decided) => decided.map_err(join_failure)?,
                    None => return Err(PoolError::Protocol("no approvals pending".into())),
                };
                // restore before acting: an approved call must not reach the
                // upstream if the session can no longer take its answer
                self.unpark(&mut *print).await?;
                let ready = self.decided(decided);
                drop(paused);

                if let Some(ready) = ready {
                    return Ok(self.deliver(vec![ready]));
                }
                continue;
            }

            // a person deciding does not use the allowance, even while a
            // sibling call is still running
            let _paused = (!self.deciding.is_empty()).then(|| self.context.budget.pause());
            tokio::select! {
                Some(done) = self.running.join_next() => {
                    let mut finished = vec![done.map_err(join_failure)?];
                    while let Some(next) = self.running.try_join_next() {
                        finished.push(next.map_err(join_failure)?);
                    }

                    return Ok(self.deliver(finished));
                }
                Some(decided) = self.deciding.join_next(), if !self.deciding.is_empty() => {
                    if let Some(ready) = self.decided(decided.map_err(join_failure)?) {
                        return Ok(self.deliver(vec![ready]));
                    }
                }
                else => return Err(PoolError::Protocol("no futures running".into())),
            }
        }
    }

    /// Acts on an approval decision: an approved call starts running, a
    /// refused one is answered with an exception straight away
    fn decided(
        &mut self,
        (call_id, verdict, call): (u32, Verdict, PreparedCall),
    ) -> Option<(u32, Answer)> {
        self.gated.remove(&call_id);

        match verdict {
            Verdict::Approved { approval_id } => {
                if call.sensitive {
                    self.sensitive_used = true;
                }
                let gateway = Arc::clone(&self.gateway);
                let context = self.context.clone();
                self.running.spawn(async move {
                    let label = call.function.clone();
                    let sensitive = call.sensitive;
                    let answer = match gateway.invoke(&context, call, Some(approval_id)).await {
                        Ok(value) => Answer::value(value),
                        Err(error) => Answer::tool_error(&error, &label, sensitive),
                    };

                    (call_id, answer)
                });

                None
            }
            Verdict::Denied { reason } => {
                let error = ToolCallError::NotApproved {
                    tool: call.function.clone(),
                    reason,
                };
                let error = self.gateway.refuse(&self.context, &call, error);

                Some((call_id, Answer::tool_error(&error, &call.function, false)))
            }
        }
    }

    /// Dumps the session, seals it and gives the worker back; on any failure
    /// the worker is simply kept for the wait
    async fn park(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let bytes = match session.dump().await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::debug!(%error, "keeping the worker while waiting for approval");

                return;
            }
        };

        let sealed = self.executor.sealer.seal(bytes);
        tracing::debug!(
            bytes = sealed.len(),
            "released the worker while waiting for approval"
        );
        self.release().await;
        self.parked = Some(Parked {
            sealed,
            pending: self.gated.iter().copied().collect(),
        });
    }

    /// Restores a parked session on a fresh worker, checking it is waiting on
    /// exactly the calls it was waiting on when dumped
    async fn unpark(&mut self, print: OnPrint<'_>) -> Result<(), PoolError> {
        let Some(parked) = self.parked.take() else {
            return Ok(());
        };
        let bytes = self
            .executor
            .sealer
            .open(parked.sealed)
            .map_err(|error| PoolError::Protocol(error.to_string().into()))?;

        let permit = self.executor.reacquire().await?;
        let mut session = self
            .executor
            .pool
            .checkout(&self.executor.repl_config(&self.stubs))
            .await?;
        let (event, _) = session.restore(bytes, vec![], print).await?;
        let pending: Option<Vec<u32>> = match event {
            Some(TurnEvent::ResolveFutures {
                mut pending_call_ids,
                ..
            }) => {
                pending_call_ids.sort_unstable();

                Some(pending_call_ids)
            }
            _ => None,
        };
        if pending.as_ref() != Some(&parked.pending) {
            return Err(PoolError::Protocol(
                "the restored session is not waiting on the calls it was dumped with".into(),
            ));
        }

        self.session = Some(session);
        self.permit = Some(permit);

        Ok(())
    }

    fn deliver(&mut self, answers: Vec<(u32, Answer)>) -> Vec<(u32, ResumeValue)> {
        answers
            .into_iter()
            .map(|(call_id, answer)| (call_id, self.deliver_one(answer)))
            .collect()
    }

    fn deliver_one(&mut self, answer: Answer) -> ResumeValue {
        if let Some(failure) = answer.failure {
            self.failures.push(failure);
        }

        answer.value
    }

    /// Buckets the exception a script ended with, tracing it back to a tool
    /// failure the host handed in when the type and message match
    fn classify_exception(&self, exception: &MontyException) -> Classification {
        let exc_type = exception.exc_type();
        let message = exception.message().unwrap_or_default();
        if let Some(failure) = self
            .failures
            .iter()
            .rev()
            .find(|failure| failure.exc_type == exc_type && failure.message == message)
        {
            let detail = if failure.sensitive {
                failure.label.clone()
            } else {
                format!("{exc_type}: {message}")
            };

            return Classification::new(failure.outcome, detail);
        }

        let outcome = match exc_type {
            ExcType::NotImplementedError => Outcome::UnsupportedSyntax,
            ExcType::NameError => Outcome::NameError,
            ExcType::ImportError | ExcType::ModuleNotFoundError => Outcome::ImportError,
            ExcType::TimeoutError => Outcome::Timeout,
            _ => Outcome::RuntimeError,
        };
        // the message may quote data a sensitive tool returned
        if self.sensitive_used {
            return Classification::new(outcome, exc_type.to_string());
        }

        Classification::new(outcome, format!("{exc_type}: {message}"))
    }

    fn plan(&mut self, function: String, args: &monty_types::CallArgs) -> Step {
        if args.args().len() > 0 {
            return Step::Ready(error_future(
                ExcType::TypeError,
                format!("{function}() takes keyword arguments only"),
            ));
        }
        let mut arguments = Map::new();
        for (key, value) in args.kwargs() {
            let Some(key) = key.as_str() else {
                return Step::Ready(error_future(
                    ExcType::TypeError,
                    format!("{function}(): argument names must be strings"),
                ));
            };
            match monty_to_argument(value) {
                Ok(value) => {
                    arguments.insert(key.to_owned(), value);
                }
                Err(error) => {
                    return Step::Ready(error_future(
                        ExcType::ValueError,
                        format!("{function}(): argument `{key}`: {error}"),
                    ));
                }
            }
        }

        match self.gateway.prepare(&self.context, &function, arguments) {
            Err(error) => {
                let answer = Answer::tool_error(&error, &function, false);

                Step::Ready(Box::pin(std::future::ready(answer)))
            }
            Ok(Plan::Gated { call, waiting }) => Step::Gated(call, waiting),
            Ok(Plan::Run { call, approval_id }) => {
                if call.sensitive {
                    self.sensitive_used = true;
                }
                let gateway = Arc::clone(&self.gateway);
                let context = self.context.clone();

                Step::Ready(Box::pin(async move {
                    let sensitive = call.sensitive;
                    match gateway.invoke(&context, call, approval_id).await {
                        Ok(value) => Answer::value(value),
                        Err(error) => Answer::tool_error(&error, &function, sensitive),
                    }
                }))
            }
        }
    }

    fn sleep_call(&mut self, delay: Duration) -> ToolFuture {
        if self.slept + delay > self.max_sleep {
            return error_future(
                ExcType::RuntimeError,
                "total sleep budget exhausted".to_owned(),
            );
        }
        self.slept += delay;

        Box::pin(async move {
            tokio::time::sleep(delay).await;

            Answer::value(MontyObject::none())
        })
    }
}

fn error_future(kind: ExcType, message: String) -> ToolFuture {
    Box::pin(std::future::ready(Answer::error(kind, message)))
}

fn join_failure(error: tokio::task::JoinError) -> PoolError {
    PoolError::Protocol(format!("tool task failed: {error}").into())
}
