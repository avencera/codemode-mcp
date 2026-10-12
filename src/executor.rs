//! Runs agent scripts in Monty workers, answering their tool calls

use std::{
    collections::HashSet,
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
    budget::Budget,
    catalog::Catalog,
    config::{Config, Limits},
    convert::{ConvertLimits, json_to_monty, monty_to_argument, monty_to_json},
    gateway::{CallContext, Gateway, ToolCallError},
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
    /// The Monty worker binary could not be located
    #[error(
        "monty worker binary not found; set `worker_path` in the config or put `monty` on PATH"
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
    },
    /// The script raised an exception or hit a sandbox limit
    Exception {
        /// Traceback text
        message: String,
        /// Text the script printed before failing
        output: String,
    },
    /// The worker or the gateway failed; not the script's fault
    Failed {
        /// What went wrong
        message: String,
        /// Text the script printed before failing
        output: String,
    },
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

type ToolFuture = Pin<Box<dyn Future<Output = ResumeValue> + Send>>;

/// The Monty worker pools plus the limits every script runs under
pub struct Executor {
    pool: Pool,
    /// Separate from `pool` so stub validation has capacity of its own
    validation_pool: Pool,
    limits: Limits,
    slots: Arc<Semaphore>,
    queued: Arc<AtomicUsize>,
}

impl Executor {
    /// Starts the worker pools described by `config`
    pub async fn new(config: &Config) -> Result<Self, ExecutorError> {
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
    ) -> ExecutionOutcome {
        let _permit = match ticket.permit().await {
            Ok(permit) => permit,
            Err(message) => {
                return ExecutionOutcome::Failed {
                    message,
                    output: String::new(),
                };
            }
        };

        // started after queueing, so waiting for a worker costs no budget
        let budget = Budget::new(self.limits.execution_timeout());
        let catalog = gateway.catalog();
        let output = OutputSink::new(self.limits.max_output_bytes);

        let mut session = match self
            .pool
            .checkout(&self.repl_config(catalog.check_stubs()))
            .await
        {
            Ok(session) => session,
            Err(error) => {
                return ExecutionOutcome::Failed {
                    message: format!("could not start a sandbox: {error}"),
                    output: String::new(),
                };
            }
        };

        let inputs = tool_inputs(&catalog);
        let driver = Driver {
            gateway: Arc::clone(gateway),
            context: CallContext {
                execution_id: Arc::from(execution_id),
                catalog,
                budget: budget.clone(),
            },
            running: JoinSet::new(),
            output: output.clone(),
            slept: Duration::ZERO,
            max_sleep: Duration::from_secs(self.limits.max_total_sleep_secs),
        };
        let finished = tokio::select! {
            result = driver.run(&mut session, code, inputs) => Some(result),
            () = budget.expired() => None,
        };
        let Some(result) = finished else {
            // the worker is stuck mid-turn, so it is dropped rather than
            // reset; dropping the driver cancelled the in-flight tool calls
            drop(session);

            return ExecutionOutcome::Failed {
                message: format!(
                    "the execution exceeded its {:?} wall-clock limit and was stopped",
                    self.limits.execution_timeout()
                ),
                output: output.take(),
            };
        };

        // typing and runtime errors leave the worker healthy; finish returns it
        // to the pool, and discards it when it was already lost
        if let Err(error) = session.finish().await {
            tracing::debug!(%error, "releasing sandbox");
        }

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
                Err(error) => ExecutionOutcome::Exception {
                    message: format!("ValueError: the result is not JSON-serializable: {error}"),
                    output: output.take(),
                },
            },
            Err(PoolError::Typing(diagnostics)) => ExecutionOutcome::TypeError { diagnostics },
            Err(PoolError::Runtime(exception)) => ExecutionOutcome::Exception {
                message: exception.to_string(),
                output: output.take(),
            },
            Err(error) => ExecutionOutcome::Failed {
                message: error.to_string(),
                output: output.take(),
            },
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

/// Locates the worker binary: the configured path, else `monty` on `PATH`
fn resolve_worker(configured: Option<&Path>) -> Result<PathBuf, ExecutorError> {
    if let Some(path) = configured {
        return if path.is_file() {
            Ok(path.to_owned())
        } else {
            Err(ExecutorError::WorkerNotFound)
        };
    }

    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join("monty"))
        .find(|candidate| candidate.is_file())
        .ok_or(ExecutorError::WorkerNotFound)
}

/// Answers the suspensions of one running script
struct Driver {
    gateway: Arc<Gateway>,
    /// Shared by every tool call of the execution, including the catalog
    /// snapshot it started with
    context: CallContext,
    running: JoinSet<(u32, ResumeValue)>,
    output: OutputSink,
    slept: Duration,
    max_sleep: Duration,
}

impl Driver {
    async fn run(
        mut self,
        session: &mut Checkout,
        code: String,
        inputs: Vec<(String, MontyObject)>,
    ) -> Result<MontyObject, PoolError> {
        let sink = self.output.clone();
        let mut print = on_print_sync(move |_, text| sink.push(text));

        let mut event = session
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
                } => {
                    let call = self.tool_call(function_name, &args);

                    self.dispatch(session, call_id, allow_eager_await, call, &mut print)
                        .await?
                }
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
                        self.dispatch(session, call_id, allow_eager_await, call, &mut print)
                            .await?
                    } else {
                        // `time.sleep` blocks the script, so answer it in place
                        let value = call.await;
                        session.resume(value, &mut print).await?
                    }
                }
                TurnEvent::OsCall { .. } => {
                    session.resume(ResumeValue::NotHandled, &mut print).await?
                }
                TurnEvent::NameLookup { .. } => {
                    session
                        .resume_name_lookup(NameLookupResult::Undefined, &mut print)
                        .await?
                }
                TurnEvent::ResolveFutures { .. } => {
                    let finished = self.next_finished().await?;

                    session.resume_futures(finished, &mut print).await?
                }
            };
        }
    }

    /// Either answers a call immediately or parks it as a future so sibling
    /// calls under `asyncio.gather` run concurrently
    async fn dispatch(
        &mut self,
        session: &mut Checkout,
        call_id: u32,
        allow_eager_await: bool,
        call: ToolFuture,
        print: OnPrint<'_>,
    ) -> Result<TurnEvent, PoolError> {
        if allow_eager_await {
            // the script awaits this call straight away, so nothing else could
            // make progress meanwhile
            let value = call.await;

            return session.resume_futures(vec![(call_id, value)], print).await;
        }

        self.running.spawn(async move { (call_id, call.await) });

        session.resume(ResumeValue::Future, print).await
    }

    async fn next_finished(&mut self) -> Result<Vec<(u32, ResumeValue)>, PoolError> {
        let first = self
            .running
            .join_next()
            .await
            .ok_or_else(|| PoolError::Protocol("no futures running".into()))?;
        let mut finished = vec![first.map_err(join_failure)?];
        while let Some(next) = self.running.try_join_next() {
            finished.push(next.map_err(join_failure)?);
        }

        Ok(finished)
    }

    fn tool_call(&self, function: String, args: &monty_types::CallArgs) -> ToolFuture {
        if args.args().len() > 0 {
            return error_future(
                ExcType::TypeError,
                format!("{function}() takes keyword arguments only"),
            );
        }
        let mut arguments = Map::new();
        for (key, value) in args.kwargs() {
            let Some(key) = key.as_str() else {
                return error_future(
                    ExcType::TypeError,
                    format!("{function}(): argument names must be strings"),
                );
            };
            match monty_to_argument(value) {
                Ok(value) => {
                    arguments.insert(key.to_owned(), value);
                }
                Err(error) => {
                    return error_future(
                        ExcType::ValueError,
                        format!("{function}(): argument `{key}`: {error}"),
                    );
                }
            }
        }

        let gateway = Arc::clone(&self.gateway);
        let context = self.context.clone();

        Box::pin(async move {
            match gateway.call(&context, &function, arguments).await {
                Ok(value) => ResumeValue::Return(json_to_monty(&value)),
                Err(error) => exception(&error),
            }
        })
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

            ResumeValue::Return(MontyObject::none())
        })
    }
}

fn exception(error: &ToolCallError) -> ResumeValue {
    ResumeValue::Error(MontyException::new(
        error.exception_type(),
        Some(error.to_string()),
    ))
}

fn error_future(kind: ExcType, message: String) -> ToolFuture {
    Box::pin(std::future::ready(ResumeValue::Error(MontyException::new(
        kind,
        Some(message),
    ))))
}

fn join_failure(error: tokio::task::JoinError) -> PoolError {
    PoolError::Protocol(format!("tool task failed: {error}").into())
}
