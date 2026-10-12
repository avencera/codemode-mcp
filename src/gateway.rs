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
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    budget::Budget,
    catalog::{Catalog, ServerSnapshot, ToolEntry},
    config::Config,
    executor::Executor,
    policy::{ApprovalDecision, ApprovalRequest, Approver, Policy},
    upstream::{UpstreamError, UpstreamStatus, Upstreams},
};

/// Wait before retrying a catalog rebuild whose stub validation could not run
const REBUILD_RETRY: Duration = Duration::from_secs(5);

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
    #[error("{0}")]
    Upstream(#[from] UpstreamError),
    /// The upstream ran the tool and it reported an error
    #[error("{0}")]
    ToolFailed(String),
    /// The tool declares an output schema but returned nothing structured
    #[error(
        "tool `{0}` declares an output schema but returned neither structured content nor JSON text"
    )]
    MissingOutput(String),
}

impl ToolCallError {
    /// Python exception class a script sees for this failure
    pub fn exception_type(&self) -> ExcType {
        match self {
            Self::Unknown(_) => ExcType::NameError,
            Self::Denied(_) | Self::NotApproved { .. } => ExcType::PermissionError,
            Self::Upstream(UpstreamError::TimedOut { .. }) => ExcType::TimeoutError,
            Self::Upstream(_) | Self::ToolFailed(_) | Self::MissingOutput(_) => {
                ExcType::RuntimeError
            }
        }
    }
}

/// Per-server entry of the health report
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
    approver: Arc<dyn Approver>,
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
        approver: Arc<dyn Approver>,
    ) -> Arc<Self> {
        let upstreams = Upstreams::start(&config.servers, config.tool_timeout());
        let changed = upstreams.changed();
        let gateway = Arc::new(Self {
            config,
            upstreams,
            catalog: RwLock::new(Published {
                generation: 0,
                catalog: Arc::new(Catalog::default()),
            }),
            generation: AtomicU64::new(0),
            rebuild_turn: Mutex::new(()),
            executor,
            approver,
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

    /// Runs one tool call on behalf of a script
    ///
    /// Tools are resolved in the execution's own catalog snapshot, not the
    /// live one
    pub async fn call(
        &self,
        context: &CallContext,
        function: &str,
        arguments: Map<String, Value>,
    ) -> Result<Value, ToolCallError> {
        let entry = context
            .catalog
            .get(function)
            .ok_or_else(|| ToolCallError::Unknown(function.to_owned()))?;
        if entry.policy == Policy::Deny {
            return Err(ToolCallError::Denied(function.to_owned()));
        }

        let upstream = self
            .upstreams
            .get(&entry.server)
            .ok_or_else(|| ToolCallError::Unknown(function.to_owned()))?;
        // before asking anyone for approval: a call that cannot run should
        // not wake a phone
        upstream.ensure_available()?;

        if entry.policy == Policy::Ask {
            let request = ApprovalRequest {
                execution_id: context.execution_id.to_string(),
                server: entry.server.clone(),
                tool: entry.tool.clone(),
                arguments: arguments.clone(),
            };
            // waiting for a human must not eat the script's wall-clock allowance
            let decision = {
                let _paused = context.budget.pause();

                self.approver.approve(&request).await
            };
            if let ApprovalDecision::Denied { reason } = decision {
                return Err(ToolCallError::NotApproved {
                    tool: function.to_owned(),
                    reason,
                });
            }
        }

        let result = upstream
            .call_tool(&entry.tool, omit_none_arguments(entry, arguments))
            .await?;

        tool_result_value(function, entry, result)
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

/// Converts an MCP tool result to the value a script receives
///
/// Structured content wins. Without it, text that is a JSON object or array
/// is parsed, and anything else is the text itself. Tool-reported errors
/// become exceptions so scripts cannot mistake them for data
fn tool_result_value(
    function: &str,
    entry: &ToolEntry,
    result: CallToolResult,
) -> Result<Value, ToolCallError> {
    let text: Vec<String> = result
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .map(|block| block.text.clone())
        .collect();

    if result.is_error == Some(true) {
        let message = if text.is_empty() {
            "tool reported an error without details".to_owned()
        } else {
            text.join("\n")
        };

        return Err(ToolCallError::ToolFailed(message));
    }
    if let Some(structured) = result.structured_content {
        return Ok(structured);
    }
    if let Some(parsed) = json_from_text(&text) {
        return Ok(parsed);
    }
    if entry.has_output_schema {
        return Err(ToolCallError::MissingOutput(function.to_owned()));
    }

    Ok(Value::String(text.join("\n")))
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
