//! The agent-facing MCP server and its HTTP wiring

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Json, Router, extract::State, middleware, routing::get};
use rmcp::{
    ServerHandler,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    app::App,
    executions::{Executions, WaitResult},
    executor::ExecutionOutcome,
    gateway::Gateway,
    guidance::{INSTRUCTIONS, TOOL_CALL_RULE, script_rules},
    host::{HostPolicy, host_guard},
};

const DEFAULT_SEARCH_LIMIT: usize = 10;
const MAX_SEARCH_LIMIT: usize = 50;
/// Agents keep a session open across long idle stretches (a person reading,
/// an approval pending), and an expired session surfaces as a 404 they
/// cannot recover from, so sessions outlive any realistic idle time
const SESSION_KEEP_ALIVE: Duration = Duration::from_secs(24 * 60 * 60);

/// Arguments of `search_tools`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    /// Keywords describing what you want to do, e.g. "search openai docs"
    pub query: String,
    /// Maximum number of results (default 10, at most 50)
    pub limit: Option<usize>,
}

/// Arguments of `describe_tools`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DescribeParams {
    /// Tool names exactly as returned by search_tools
    pub names: Vec<String>,
}

/// Arguments of `execute`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecuteParams {
    /// Python source to run; the last expression is the result
    pub code: String,
}

/// Arguments of `wait`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaitParams {
    /// The execution_id returned by a pending execute call
    pub execution_id: String,
}

/// MCP handler exposing search, describe, execute and wait
#[derive(Clone)]
pub struct CodeModeServer {
    gateway: Arc<Gateway>,
    executions: Arc<Executions>,
    wait_budget: Duration,
    max_response_bytes: usize,
}

impl CodeModeServer {
    /// Creates a handler over a running app
    pub fn new(app: &App) -> Self {
        Self {
            gateway: Arc::clone(app.gateway()),
            executions: Arc::clone(app.executions()),
            wait_budget: app.config().limits.execute_wait(),
            max_response_bytes: app.config().limits.max_response_bytes(),
        }
    }

    async fn await_outcome(&self, id: &str) -> CallToolResult {
        match self.executions.wait(id, self.wait_budget).await {
            WaitResult::Finished(outcome) => render_outcome(&outcome, self.max_response_bytes),
            WaitResult::Pending => text_result(
                &json!({
                    "status": "pending",
                    "execution_id": id,
                    "message": "Still running. Call wait with this execution_id to keep waiting.",
                })
                .to_string(),
                false,
            ),
            WaitResult::Unknown => text_result("Unknown or expired execution_id.", true),
        }
    }
}

#[tool_router]
impl CodeModeServer {
    #[tool(
        description = "Find tools by keyword. Returns ranked tool names with one-line descriptions. \
                       Tool names are the Python function names to use in execute."
    )]
    async fn search_tools(&self, Parameters(params): Parameters<SearchParams>) -> CallToolResult {
        let limit = params
            .limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .clamp(1, MAX_SEARCH_LIMIT);
        let catalog = self.gateway.catalog();
        let hits: Vec<Value> = catalog
            .search(&params.query, limit)
            .into_iter()
            .map(|entry| {
                let mut hit = json!({
                    "name": entry.function,
                    "description": entry.summary(),
                    "params": entry.params,
                });
                if !entry.available {
                    hit["available"] = Value::Bool(false);
                }
                if entry.degraded {
                    hit["degraded"] = Value::Bool(true);
                }

                hit
            })
            .collect();

        text_result(&Value::Array(hits).to_string(), false)
    }

    #[tool(
        description = "Get full documentation and typed Python signatures for tools returned by \
                       search_tools. Call this before writing a script that uses them."
    )]
    async fn describe_tools(
        &self,
        Parameters(params): Parameters<DescribeParams>,
    ) -> CallToolResult {
        let catalog = self.gateway.catalog();
        let (stubs, missing) = catalog.describe(&params.names);
        let mut text = format!("# {TOOL_CALL_RULE}\n{stubs}");
        if !missing.is_empty() {
            text.push_str("\n# Unknown tools: ");
            text.push_str(&missing.join(", "));
            for name in missing {
                let suggestions: Vec<&str> = catalog
                    .search(name, 3)
                    .into_iter()
                    .map(|entry| entry.function.as_str())
                    .collect();
                if !suggestions.is_empty() {
                    text.push_str(&format!(
                        "\n# Did you mean for `{name}`: {}",
                        suggestions.join(", ")
                    ));
                }
            }
            text.push('\n');
        }

        text_result(&text, false)
    }

    #[tool(
        description = concat!(
            "Run a Python script that calls tools found with search_tools and described with describe_tools. ",
            "Waits briefly; if the script is still running it returns {\"status\":\"pending\",\"execution_id\":...} \
             and you call wait. Type errors and exceptions come back as text so you can fix the script.\n\n",
            script_rules!()
        )
    )]
    async fn execute(&self, Parameters(params): Parameters<ExecuteParams>) -> CallToolResult {
        match self.executions.start(params.code) {
            Ok(id) => self.await_outcome(&id).await,
            Err(busy) => text_result(&busy.to_string(), true),
        }
    }

    #[tool(
        description = "Keep waiting for a pending execution started by execute. Returns its result or \
                          {\"status\":\"pending\"} again."
    )]
    async fn wait(&self, Parameters(params): Parameters<WaitParams>) -> CallToolResult {
        self.await_outcome(&params.execution_id).await
    }
}

#[tool_handler]
impl ServerHandler for CodeModeServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

fn text_result(text: &str, is_error: bool) -> CallToolResult {
    let content = vec![ContentBlock::text(text)];

    if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    }
}

/// Formats a finished execution for the agent; failures are tool results,
/// never protocol errors, so the agent can read them and retry
pub fn render_outcome(outcome: &ExecutionOutcome, max_bytes: usize) -> CallToolResult {
    let (text, is_error) = outcome_text(outcome, max_bytes);

    text_result(&text, is_error)
}

/// Text of a finished execution, capped at `max_bytes`, and whether it counts
/// as a failure
pub fn outcome_text(outcome: &ExecutionOutcome, max_bytes: usize) -> (String, bool) {
    let (text, is_error) = match outcome {
        ExecutionOutcome::Completed {
            value,
            truncated,
            notes,
            output,
        } => {
            let mut body = json!({"status": "completed", "result": value});
            if *truncated {
                body["truncated"] = Value::Bool(true);
            }
            if !notes.is_empty() {
                body["notes"] = json!(notes);
            }
            if !output.is_empty() {
                body["output"] = Value::String(output.clone());
            }

            (body.to_string(), false)
        }
        ExecutionOutcome::TypeError { diagnostics } => (
            format!(
                "Type check failed; the script did not run. Fix these and call execute again.\n\n{diagnostics}"
            ),
            true,
        ),
        ExecutionOutcome::Exception { message, output } => (
            with_output(
                &format!("The script raised an exception.\n\n{message}"),
                output,
            ),
            true,
        ),
        ExecutionOutcome::Failed { message, output } => (
            with_output(&format!("Execution failed: {message}"), output),
            true,
        ),
    };

    (cap_text(text, max_bytes), is_error)
}

/// Backstop for the size of one response: whatever the pieces added up to,
/// the agent never receives more than `max_bytes`
fn cap_text(mut text: String, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text;
    }

    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(&format!(
        "\n[response truncated: it exceeded {max_bytes} bytes]"
    ));

    text
}

fn with_output(message: &str, output: &str) -> String {
    if output.is_empty() {
        message.to_owned()
    } else {
        format!("{message}\n\nOutput before the failure:\n{output}")
    }
}

/// Handle to the running HTTP server
pub struct RunningServer {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<std::io::Result<()>>,
}

impl RunningServer {
    /// Address actually bound, useful when the config asked for port 0
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Stops accepting requests and waits for in-flight ones to finish
    pub async fn shutdown(self) -> std::io::Result<()> {
        self.shutdown.cancel();

        self.task.await.map_err(std::io::Error::other)?
    }

    /// Waits until the server stops on its own, e.g. after a signal
    pub async fn finished(self) -> std::io::Result<()> {
        self.task.await.map_err(std::io::Error::other)?
    }

    /// Token that stops the server when cancelled
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

/// Binds the configured address and serves `/mcp` and `/healthz`
pub async fn serve(app: &App) -> std::io::Result<RunningServer> {
    let listener = TcpListener::bind(app.config().listen).await?;
    let address = listener.local_addr()?;
    let shutdown = CancellationToken::new();

    let mcp_app = app.clone();
    let mut sessions = LocalSessionManager::default();
    sessions.session_config.keep_alive = Some(SESSION_KEEP_ALIVE);
    let mcp = StreamableHttpService::new(
        move || Ok(CodeModeServer::new(&mcp_app)),
        Arc::new(sessions),
        // rmcp only matches exact authorities; `host_guard` below applies
        // the real rules, so its own check is switched off
        StreamableHttpServerConfig::default()
            .disable_allowed_hosts()
            .with_cancellation_token(shutdown.child_token()),
    );
    let hosts = Arc::new(HostPolicy::new(&app.config().extra_allowed_hosts));
    let router = Router::new()
        .route("/healthz", get(healthz))
        .with_state(Arc::clone(app.gateway()))
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(hosts, host_guard));

    let token = shutdown.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { token.cancelled().await })
            .await
    });
    tracing::info!(%address, "listening");

    Ok(RunningServer {
        address,
        shutdown,
        task,
    })
}

async fn healthz(State(gateway): State<Arc<Gateway>>) -> Json<Value> {
    let upstreams = gateway.report();
    let connected = upstreams
        .iter()
        .filter(|upstream| upstream.status == crate::upstream::UpstreamStatus::Connected)
        .count();

    Json(json!({
        "status": "ok",
        "tools": gateway.catalog().entries().len(),
        "upstreams_connected": connected,
        "upstreams": upstreams,
    }))
}
