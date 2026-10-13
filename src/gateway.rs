//! Ties upstreams, the catalog and tool policy together

use std::{
    collections::HashSet,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use monty_types::ExcType;
use rmcp::model::{CallToolResult, ContentBlock};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    approvals::{Approvals, Gate, GateRequest, Waiting},
    budget::Budget,
    catalog::{Catalog, ServerSnapshot, ToolEntry},
    config::Config,
    convert::json_to_monty,
    durable::Sensitivity,
    executor::Executor,
    oauth::OAuth,
    output::{Mismatch, OutputSpec, validate},
    policy::Policy,
    store::Store,
    upstream::{ErrorCategory, UpstreamError, UpstreamStatus, Upstreams},
    usage::{Caller, Classification, Outcome, UpstreamRecord, UsageLog},
};

/// Wait before retrying a catalog rebuild whose stub validation could not run
const REBUILD_RETRY: Duration = Duration::from_secs(5);
/// Longest upstream error text handed to a script
const MAX_ERROR_TEXT: usize = 2000;
/// Replacement for configured secrets found in upstream text
const REDACTED: &str = "[redacted]";

/// What a tool call needs to know about the execution making it
#[derive(Clone)]
pub struct CallContext {
    /// Execution the call belongs to
    pub execution_id: Arc<str>,
    /// The catalog the execution's script was type-checked against; every
    /// call of the execution resolves tools in it, even if the live catalog
    /// has moved on
    pub catalog: Arc<Catalog>,
    /// The execution's wall-clock allowance, paused while an approval is pending
    pub budget: Budget,
    /// Who started the execution
    pub caller: Caller,
    /// The script, shown on the approval page
    pub script: Arc<str>,
}

/// Why a tool call from a script failed
#[derive(Debug, thiserror::Error)]
pub enum ToolCallError {
    /// No tool has this name
    #[error("unknown tool `{0}`")]
    Unknown(String),
    /// Policy forbids the tool
    #[error("tool `{0}` is denied by policy")]
    Denied(String),
    /// The approver said no
    #[error("tool `{tool}` was not approved: {reason}")]
    NotApproved {
        /// Python name of the tool
        tool: String,
        /// Approver's explanation
        reason: String,
    },
    /// The upstream could not run the call
    #[error("{}", .0.public_message())]
    Upstream(#[from] UpstreamError),
    /// The upstream ran the tool and it reported an error
    #[error("{0}")]
    ToolFailed(String),
    /// The tool has an output schema but returned nothing structured
    #[error(
        "tool `{0}` has an output schema but returned neither structured content nor JSON text"
    )]
    MissingOutput(String),
    /// The result does not match the tool's output schema
    #[error("tool `{tool}` returned data that breaks its output schema {mismatch}")]
    OutputMismatch {
        /// Python name of the tool
        tool: String,
        /// Where and how it broke
        mismatch: Mismatch,
    },
    /// The result is too large or deep to hand to a script
    #[error("tool `{tool}` returned a result the sandbox will not accept: {reason}")]
    ResultTooLarge {
        /// Python name of the tool
        tool: String,
        /// Which limit it broke
        reason: String,
    },
}

impl ToolCallError {
    /// Python exception class a script sees for this failure
    pub fn exception_type(&self) -> ExcType {
        match self {
            Self::Unknown(_) => ExcType::NameError,
            Self::Denied(_) | Self::NotApproved { .. } => ExcType::PermissionError,
            Self::Upstream(UpstreamError::TimedOut { .. }) => ExcType::TimeoutError,
            Self::ResultTooLarge { .. } => ExcType::ValueError,
            Self::Upstream(_)
            | Self::ToolFailed(_)
            | Self::MissingOutput(_)
            | Self::OutputMismatch { .. } => ExcType::RuntimeError,
        }
    }

    /// Usage-log bucket for this failure
    pub fn outcome(&self) -> Outcome {
        match self {
            Self::Unknown(_) => Outcome::NameError,
            Self::Denied(_) | Self::NotApproved { .. } => Outcome::Denied,
            Self::Upstream(UpstreamError::TimedOut { .. }) => Outcome::Timeout,
            Self::OutputMismatch { .. } => Outcome::OutputMismatch,
            Self::Upstream(_)
            | Self::ToolFailed(_)
            | Self::MissingOutput(_)
            | Self::ResultTooLarge { .. } => Outcome::ToolError,
        }
    }
}

/// A resolved tool call that has passed policy checks
///
/// Serializable so a call waiting for an approval survives a restart; the
/// storage layer refuses it when `sensitive` is set
#[derive(Clone, Serialize, Deserialize)]
pub struct PreparedCall {
    /// Python name of the tool
    pub function: String,
    /// Server name
    pub server: String,
    /// Upstream tool name
    pub tool: String,
    /// Whether logs must omit this call's arguments and error text
    pub sensitive: bool,
    arguments: Map<String, Value>,
    output: OutputSpec,
}

/// How a call proceeds after [`Gateway::prepare`]
pub enum Plan {
    /// Run it now
    Run {
        /// The call
        call: PreparedCall,
        /// Approval or grant that allowed it, for `ask` tools
        approval_id: Option<String>,
    },
    /// Wait for a person first
    Gated {
        /// The call
        call: PreparedCall,
        /// The pending request
        waiting: Waiting,
    },
}

/// Per-server entry of the health report
#[derive(Debug, Clone, Serialize)]
pub struct PublicUpstreamReport {
    /// Server name
    pub name: String,
    /// `connecting`, `connected` or `unavailable`
    pub state: &'static str,
    /// Number of tools currently known
    pub tools: usize,
    /// Coarse failure reason when unavailable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorCategory>,
}

/// Outcome of one warm-up call, safe to print
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct WarmResult {
    /// Server name
    pub server: String,
    /// Upstream tool name
    pub tool: String,
    /// Whether the call succeeded
    pub ok: bool,
    /// Result size or failure category; never result content
    pub detail: String,
}

/// Replaces configured secrets (header values, env values, URL query
/// strings) in text that came from an upstream
#[derive(Debug, Default)]
struct Redactor(Vec<String>);

impl Redactor {
    fn new(config: &Config) -> Self {
        let mut secrets = Vec::new();
        for server in config.servers.values() {
            for value in server.headers.values().chain(server.env.values()) {
                secrets.push(value.clone());
                if let Some(token) = value.strip_prefix("Bearer ") {
                    secrets.push(token.to_owned());
                }
            }
            if let Some(url) = server.url.as_deref() {
                if let Some((_, query)) = url.split_once('?') {
                    secrets.push(query.to_owned());
                }
                // `https://user:password@host/...`
                if let Some((userinfo, _)) = url
                    .split_once("://")
                    .and_then(|(_, rest)| rest.split_once('@'))
                    .filter(|(userinfo, _)| !userinfo.contains('/'))
                {
                    secrets.push(userinfo.to_owned());
                }
            }
        }
        // short values would redact ordinary words
        secrets.retain(|secret| secret.len() >= 6);
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();

        Self(secrets)
    }

    fn apply(&self, text: &str) -> String {
        let mut text = self.0.iter().fold(text.to_owned(), |text, secret| {
            text.replace(secret.as_str(), REDACTED)
        });
        if text.len() > MAX_ERROR_TEXT {
            let mut end = MAX_ERROR_TEXT;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str("...[truncated]");
        }

        text
    }
}

/// Per-server entry of the local status report
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamReport {
    /// Server name
    pub name: String,
    /// Connection state, flattened into the object
    #[serde(flatten)]
    pub status: UpstreamStatus,
    /// Number of tools currently known
    pub tools: usize,
}

/// The tool backend: owns the upstream connections and the current catalog
pub struct Gateway {
    config: Arc<Config>,
    upstreams: Upstreams,
    catalog: RwLock<Published>,
    /// Numbers rebuilds in the order they start
    generation: AtomicU64,
    /// Lets one rebuild at a time run, so slow validation of an old snapshot
    /// cannot finish after a newer one
    rebuild_turn: Mutex<()>,
    executor: Arc<Executor>,
    approvals: Arc<Approvals>,
    log: UsageLog,
    oauth: Arc<OAuth>,
    redactor: Redactor,
    max_tool_result_bytes: usize,
    rebuild_task: RwLock<Option<JoinHandle<()>>>,
}

struct Published {
    generation: u64,
    catalog: Arc<Catalog>,
}

impl Gateway {
    /// Starts connecting to every configured server and keeps the catalog
    /// current as they come and go
    pub fn start(
        config: Arc<Config>,
        executor: Arc<Executor>,
        approvals: Arc<Approvals>,
        log: UsageLog,
        oauth: Arc<OAuth>,
        store: &Store,
    ) -> Arc<Self> {
        let upstreams = Upstreams::start(
            &config.servers,
            config.tool_timeout(),
            Some(Arc::clone(&oauth)),
            store,
        );
        let changed = upstreams.changed();
        let gateway = Arc::new(Self {
            redactor: Redactor::new(&config),
            max_tool_result_bytes: config.limits.max_tool_result_bytes,
            config,
            upstreams,
            catalog: RwLock::new(Published {
                generation: 0,
                catalog: Arc::new(Catalog::default()),
            }),
            generation: AtomicU64::new(0),
            rebuild_turn: Mutex::new(()),
            executor,
            approvals,
            log,
            oauth,
            rebuild_task: RwLock::new(None),
        });

        // the task holds only a weak reference so dropping the gateway stops it
        let weak = Arc::downgrade(&gateway);
        let task = tokio::spawn(async move {
            let mut retry = false;
            loop {
                if retry {
                    // stub validation was unavailable; try again soon even
                    // without a new change
                    tokio::select! {
                        () = changed.notified() => {}
                        () = tokio::time::sleep(REBUILD_RETRY) => {}
                    }
                } else {
                    changed.notified().await;
                }
                // let a burst of connection events collapse into one rebuild
                tokio::time::sleep(Duration::from_millis(50)).await;
                let Some(gateway) = weak.upgrade() else {
                    return;
                };
                retry = !gateway.rebuild().await;
            }
        });
        if let Ok(mut slot) = gateway.rebuild_task.write() {
            *slot = Some(task);
        }

        gateway
    }

    /// The catalog as of the last rebuild
    pub fn catalog(&self) -> Arc<Catalog> {
        let guard = self
            .catalog
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        Arc::clone(&guard.catalog)
    }

    /// Waits for the first connection attempts to finish and the catalog to
    /// reflect them
    pub async fn wait_ready(&self, limit: Duration) {
        self.upstreams.wait_settled(limit).await;
        self.rebuild().await;
    }

    /// Snapshot of every upstream for health reporting
    pub fn report(&self) -> Vec<UpstreamReport> {
        self.upstreams
            .all()
            .iter()
            .map(|upstream| UpstreamReport {
                name: upstream.name().to_owned(),
                status: upstream.status(),
                tools: upstream.tools().len(),
            })
            .collect()
    }

    /// The same report with only names, states, counts and coarse error
    /// categories, for unauthenticated endpoints
    pub fn public_report(&self) -> Vec<PublicUpstreamReport> {
        self.report()
            .into_iter()
            .map(|report| PublicUpstreamReport {
                state: report.status.state(),
                error: report.status.category(),
                name: report.name,
                tools: report.tools,
            })
            .collect()
    }

    /// The approval service
    pub fn approvals(&self) -> &Arc<Approvals> {
        &self.approvals
    }

    /// OAuth logins of remote upstreams
    pub fn oauth(&self) -> &Arc<OAuth> {
        &self.oauth
    }

    /// Reconnects one upstream, e.g. after its login changed; false when no
    /// server has this name
    pub fn reconnect(&self, server: &str) -> bool {
        let Some(upstream) = self.upstreams.get(server) else {
            return false;
        };
        upstream.request_reconnect();

        true
    }

    /// Resolves a script's tool call and applies policy, without running it
    ///
    /// Tools are resolved in the execution's own catalog snapshot, not the
    /// live one. A refused call is logged here. `prior` says whether the
    /// execution already holds data from a sensitive server, which keeps the
    /// approval request off the disk
    ///
    pub fn prepare(
        &self,
        context: &CallContext,
        function: &str,
        arguments: Map<String, Value>,
        prior: Sensitivity,
    ) -> Result<Plan, ToolCallError> {
        let entry = context
            .catalog
            .get(function)
            .ok_or_else(|| ToolCallError::Unknown(function.to_owned()))?;
        let server_config = self.config.servers.get(&entry.server);
        let call = PreparedCall {
            function: function.to_owned(),
            server: entry.server.clone(),
            tool: entry.tool.clone(),
            sensitive: server_config.is_some_and(|server| server.is_sensitive()),
            arguments: omit_none_arguments(entry, arguments),
            output: entry.output.clone(),
        };
        if entry.policy == Policy::Deny {
            return Err(self.refuse(context, &call, ToolCallError::Denied(function.to_owned())));
        }

        let upstream = self
            .upstreams
            .get(&entry.server)
            .ok_or_else(|| ToolCallError::Unknown(function.to_owned()))?;
        // before asking anyone for approval: a call that cannot run should
        // not wake a phone
        if let Err(error) = upstream.ensure_available() {
            return Err(self.refuse(context, &call, error.into()));
        }
        if entry.policy != Policy::Ask {
            return Ok(Plan::Run {
                call,
                approval_id: None,
            });
        }

        let grant_mode = server_config.map(|server| server.grant_for(&entry.tool));
        let gate = self.approvals.gate(GateRequest {
            caller: &context.caller,
            execution_id: &context.execution_id,
            server: &call.server,
            tool: &call.tool,
            arguments: &call.arguments,
            script: &context.script,
            grant_mode: grant_mode.unwrap_or_default(),
            sensitivity: Sensitivity::of(call.sensitive).or(prior),
        });

        match gate {
            Gate::Open { approval_id } => Ok(Plan::Run {
                call,
                approval_id: Some(approval_id),
            }),
            Gate::Wait(waiting) => Ok(Plan::Gated { call, waiting }),
            Gate::Closed { reason } => {
                let error = ToolCallError::NotApproved {
                    tool: function.to_owned(),
                    reason,
                };

                Err(self.refuse(context, &call, error))
            }
        }
    }

    /// Logs a call refused before it reached the upstream and returns the error
    pub fn refuse(
        &self,
        context: &CallContext,
        call: &PreparedCall,
        error: ToolCallError,
    ) -> ToolCallError {
        self.record(context, call, &Err(&error), Duration::ZERO, None);

        error
    }

    /// Runs a prepared call on its upstream, converting the result to a
    /// script value and logging the call
    pub async fn invoke(
        &self,
        context: &CallContext,
        call: PreparedCall,
        approval_id: Option<String>,
    ) -> Result<monty_types::MontyObject, ToolCallError> {
        let started = std::time::Instant::now();
        let result = self.invoke_unlogged(&call).await;
        let logged = result.as_ref().map(|_| ());
        self.record(context, &call, &logged, started.elapsed(), approval_id);

        result
    }

    async fn invoke_unlogged(
        &self,
        call: &PreparedCall,
    ) -> Result<monty_types::MontyObject, ToolCallError> {
        let upstream = self
            .upstreams
            .get(&call.server)
            .ok_or_else(|| ToolCallError::Unknown(call.function.clone()))?;
        let result = upstream
            .call_tool(&call.tool, call.arguments.clone())
            .await
            .map_err(|error| match error {
                // the upstream's own error message can echo configured secrets
                UpstreamError::Service(rmcp::service::ServiceError::McpError(_)) => {
                    ToolCallError::ToolFailed(self.redactor.apply(&error.public_message()))
                }
                error => ToolCallError::Upstream(error),
            })?;
        let value = self.tool_result_value(call, result)?;
        if let OutputSpec::Schema(schema) = &call.output {
            validate(schema, &value).map_err(|mismatch| ToolCallError::OutputMismatch {
                tool: call.function.clone(),
                mismatch,
            })?;
        }

        json_to_monty(&value, self.max_tool_result_bytes).map_err(|error| {
            ToolCallError::ResultTooLarge {
                tool: call.function.clone(),
                reason: error.to_string(),
            }
        })
    }

    fn record(
        &self,
        context: &CallContext,
        call: &PreparedCall,
        result: &Result<(), &ToolCallError>,
        duration: Duration,
        approval_id: Option<String>,
    ) {
        let classification = match result {
            Ok(()) => Classification::ok(),
            Err(error) => Classification {
                outcome: error.outcome(),
                detail: match error {
                    _ if !call.sensitive => Some(error.to_string()),
                    // the path can hold keys taken from the data (through
                    // `additionalProperties`), so only the expected type,
                    // a schema fact, is kept
                    ToolCallError::OutputMismatch { mismatch, .. } => {
                        Some(format!("expected {}", mismatch.expected))
                    }
                    _ => None,
                },
            },
        };

        self.log.upstream(UpstreamRecord {
            execution_id: Some(context.execution_id.to_string()),
            server: call.server.clone(),
            tool: call.tool.clone(),
            function: call.function.clone(),
            arguments: (!call.sensitive).then(|| Value::Object(call.arguments.clone()).to_string()),
            classification,
            duration,
            approval_id,
            output: call.output.kind(),
        });
    }

    /// Runs the configured warm-up calls of one server, or of every server
    /// that has them, directly on the upstream and without approvals
    ///
    /// Only the admin listener calls this, which only accepts loopback
    /// peers, so it runs from the Mac itself
    pub async fn warm(&self, only: Option<&str>) -> Result<Vec<WarmResult>, String> {
        if let Some(name) = only
            && !self.config.servers.contains_key(name)
        {
            return Err(format!("no server named `{name}`"));
        }

        let mut results = Vec::new();
        for (name, server) in &self.config.servers {
            if only.is_some_and(|only| only != name) {
                continue;
            }
            let Some(warm) = &server.warm else {
                if only.is_some() {
                    return Err(format!(
                        "server `{name}` has no [servers.{name}.warm] calls"
                    ));
                }
                continue;
            };
            let Some(upstream) = self.upstreams.get(name) else {
                continue;
            };

            for call in &warm.calls {
                let outcome = upstream.call_tool(&call.tool, call.arguments.clone()).await;
                let (ok, detail) = match outcome {
                    Ok(result) if result.is_error == Some(true) => {
                        (false, "the tool reported an error".to_owned())
                    }
                    Ok(result) => {
                        let bytes: usize = result
                            .content
                            .iter()
                            .filter_map(ContentBlock::as_text)
                            .map(|block| block.text.len())
                            .sum();

                        (true, format!("ok ({bytes} bytes of output, not shown)"))
                    }
                    Err(error) => (false, error.category().as_str().to_owned()),
                };
                results.push(WarmResult {
                    server: name.clone(),
                    tool: call.tool.clone(),
                    ok,
                    detail,
                });
            }
        }

        Ok(results)
    }

    /// Rebuilds the catalog from the current upstream state, returning false
    /// when stub validation could not run and the previous catalog was kept
    async fn rebuild(&self) -> bool {
        let _turn = self.rebuild_turn.lock().await;
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let snapshots: Vec<ServerSnapshot> = self
            .upstreams
            .all()
            .iter()
            .map(|upstream| ServerSnapshot {
                name: upstream.name().to_owned(),
                tools: upstream.tools(),
                available: upstream.status() == UpstreamStatus::Connected,
            })
            .collect();

        let started = std::time::Instant::now();
        let mut catalog = Catalog::build(&self.config, &snapshots, &HashSet::new());
        let built = started.elapsed();
        let rejected = match self.executor.rejected_stubs(&catalog).await {
            Ok(rejected) => rejected,
            Err(error) => {
                // fail closed: unvalidated stubs could make every script fail
                // type checking, so keep serving the last validated catalog
                tracing::warn!(%error, "keeping the previous catalog; will retry");

                return false;
            }
        };
        let validated = started.elapsed() - built;
        if !rejected.is_empty() {
            tracing::warn!(
                ?rejected,
                "type checker rejected generated stubs; using permissive signatures"
            );
            catalog = Catalog::build(&self.config, &snapshots, &rejected);
        }

        tracing::info!(
            tools = catalog.entries().len(),
            ?built,
            ?validated,
            generation,
            "catalog rebuilt"
        );
        let mut slot = self
            .catalog
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // never let an older snapshot replace a newer one
        if generation > slot.generation {
            *slot = Published {
                generation,
                catalog: Arc::new(catalog),
            };
        }

        true
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        if let Ok(slot) = self.rebuild_task.read()
            && let Some(task) = slot.as_ref()
        {
            task.abort();
        }
    }
}

/// Drops `None` arguments for optional parameters that do not accept `null`;
/// the stubs advertise `T | None = None`, where `None` means "not provided"
fn omit_none_arguments(entry: &ToolEntry, mut arguments: Map<String, Value>) -> Map<String, Value> {
    arguments.retain(|name, value| !(value.is_null() && entry.stub.omit_if_none.contains(name)));

    arguments
}

impl Gateway {
    /// Converts an MCP tool result to the value a script receives
    ///
    /// Structured content wins. Without it, text that is a JSON object or
    /// array is parsed, and anything else is the text itself. A tool
    /// configured as `output = "text"` always gives its joined text.
    /// Tool-reported errors become exceptions so scripts cannot mistake them
    /// for data
    fn tool_result_value(
        &self,
        call: &PreparedCall,
        result: CallToolResult,
    ) -> Result<Value, ToolCallError> {
        let text: Vec<String> = result
            .content
            .iter()
            .filter_map(ContentBlock::as_text)
            .map(|block| block.text.clone())
            .collect();
        // before parsing: a huge text answer must not become a huge value
        let text_bytes: usize = text.iter().map(String::len).sum();
        if text_bytes > self.max_tool_result_bytes {
            return Err(ToolCallError::ResultTooLarge {
                tool: call.function.clone(),
                reason: format!(
                    "{text_bytes} bytes of text exceed the {}-byte limit",
                    self.max_tool_result_bytes
                ),
            });
        }

        if result.is_error == Some(true) {
            let message = if text.is_empty() {
                "tool reported an error without details".to_owned()
            } else {
                self.redactor.apply(&text.join("\n"))
            };

            return Err(ToolCallError::ToolFailed(message));
        }
        if matches!(call.output, OutputSpec::Text) {
            // a text tool that sends only structured content still gives the
            // script something to read
            return Ok(Value::String(
                match (text.is_empty(), result.structured_content) {
                    (true, Some(structured)) => structured.to_string(),
                    _ => text.join("\n"),
                },
            ));
        }
        if let Some(structured) = result.structured_content {
            return Ok(structured);
        }
        if let Some(parsed) = json_from_text(&text) {
            return Ok(parsed);
        }
        if matches!(call.output, OutputSpec::Schema(_)) {
            return Err(ToolCallError::MissingOutput(call.function.clone()));
        }

        Ok(Value::String(text.join("\n")))
    }
}

/// Parses text blocks as one JSON object or array; scalars stay text because
/// a tool answering `123` or `true` as prose is more likely than as data
fn json_from_text(blocks: &[String]) -> Option<Value> {
    let joined;
    let text = match blocks {
        [only] => only.as_str(),
        _ => {
            joined = blocks.concat();
            joined.as_str()
        }
    }
    .trim();
    if !(text.starts_with('{') || text.starts_with('[')) {
        return None;
    }

    match serde_json::from_str::<Value>(text) {
        Ok(value @ (Value::Object(_) | Value::Array(_))) => Some(value),
        _ => None,
    }
}
