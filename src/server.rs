//! The agent-facing MCP server and its HTTP wiring

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    middleware,
    response::Response,
    routing::get,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, ContentBlock, Implementation, ProgressNotificationParam,
        ServerCapabilities, ServerConfig,
    },
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    admin,
    app::App,
    config::Config,
    executions::{Executions, StartError, WaitResult},
    executor::{CompletedCall, ExecutionOutcome, InterruptReason},
    gateway::Gateway,
    guidance::{self, INSTRUCTIONS, SESSION_RULE, TOOL_CALL_RULE, script_rules, session_rule},
    host::{HostPolicy, host_guard, is_direct_local},
    prompt::{REASON_CHARS, THREAD_CHARS, one_line},
    store::Store,
    usage::{CallRecord, Caller, Classification, Outcome, UsageLog},
    web,
};

/// Longest client name or version kept
const MAX_LABEL_CHARS: usize = 64;

const DEFAULT_SEARCH_LIMIT: usize = 10;
const MAX_SEARCH_LIMIT: usize = 50;

/// Arguments of `search_tools`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    /// Keywords describing what you want to do, e.g. "search openai docs"
    pub query: String,
    /// Maximum number of results (default 10, at most 50)
    pub limit: Option<usize>,
    /// Session value from your previous codemode result; omit on the first call
    pub session: Option<String>,
}

/// Arguments of `describe_tools`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DescribeParams {
    /// Tool names exactly as returned by search_tools
    pub names: Vec<String>,
    /// Session value from your previous codemode result; omit on the first call
    pub session: Option<String>,
}

/// Arguments of `execute`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecuteParams {
    /// Python source to run; the last expression is the result
    pub code: String,
    /// Session value from your previous codemode result; omit on the first call
    pub session: Option<String>,
    /// Short title of your current thread or task, such as "Fix login
    /// redirect"; shown to the user when a tool needs their approval
    pub thread: Option<String>,
    /// One line on why this script needs its tools, such as "read the
    /// staging env names to write .env"; shown to the user when a tool
    /// needs their approval
    pub reason: Option<String>,
}

/// Arguments of `wait`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaitParams {
    /// The execution_id returned by a pending execute call
    pub execution_id: String,
    /// Session value from your previous codemode result; omit if you have none
    pub session: Option<String>,
    /// Seconds to keep waiting before answering pending again (default 25,
    /// at most 100); use a longer wait while the user approves
    pub timeout_secs: Option<u64>,
}

/// Longest `wait` a caller may ask for, under Codex's default 120 second
/// tool timeout
const MAX_WAIT: Duration = Duration::from_secs(100);

/// MCP handler exposing search, describe, execute and wait
#[derive(Clone)]
pub struct CodeModeServer {
    gateway: Arc<Gateway>,
    executions: Arc<Executions>,
    log: UsageLog,
    store: Store,
    session_idle: Duration,
    wait_budget: Duration,
    progress_interval: Duration,
    max_response_bytes: usize,
}

/// Client of the request being handled; the app session is filled in later
/// by [`CodeModeServer::open_session`]
///
/// The server is session-less at the protocol level, so the client is read
/// from the request `_meta`, then from peer info when a handshake filled it
/// in, then from the `user-agent` header
fn caller_of(context: &RequestContext<RoleServer>) -> Caller {
    let parts = context.extensions.get::<http::request::Parts>();
    let from_handshake = || {
        // rmcp fills peer info with its own identity when it served the
        // request without a handshake
        let info = context.peer.peer_info()?;

        (info.client_info != Implementation::default()).then(|| info.client_info.clone())
    };
    let client = context
        .meta
        .client_info()
        .or_else(from_handshake)
        .map(|info| Caller {
            client_name: Some(clean_label(&info.name)),
            client_version: Some(clean_label(&info.version)),
            client_title: info.title.as_deref().map(clean_label),
            ..Caller::default()
        })
        .or_else(|| {
            let agent = parts?
                .headers
                .get(http::header::USER_AGENT)?
                .to_str()
                .ok()?;

            caller_from_user_agent(agent)
        });

    // the peer comes from axum's connect info, which `serve` enables
    let peer = context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<ConnectInfo<SocketAddr>>())
        .map(|ConnectInfo(peer)| *peer);
    let local = parts.is_some_and(|parts| is_direct_local(peer, &parts.headers));

    Caller {
        local,
        ..client.unwrap_or_default()
    }
}

/// Client name and version from the first product of a `user-agent` header,
/// e.g. `claude-code/2.1.296 (cli)`
fn caller_from_user_agent(agent: &str) -> Option<Caller> {
    let product = agent.split_whitespace().next()?;
    let (name, version) = match product.split_once('/') {
        Some((name, version)) => (name, Some(clean_label(version))),
        None => (product, None),
    };
    if name.is_empty() {
        return None;
    }

    Some(Caller {
        client_name: Some(clean_label(name)),
        client_version: version,
        ..Caller::default()
    })
}

/// Client-supplied names end up in push titles, pages and every log row, so
/// they are kept short and printable
fn clean_label(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(MAX_LABEL_CHARS)
        .collect()
}

/// An agent's thread title or reason, trimmed, on one line, and kept a
/// little past what the prompt shows so the prompt can mark it as cut;
/// `None` when blank
///
/// Cleaned here rather than where it is shown, so the page cannot be made
/// to read differently from the prompt
fn asked(text: &str, shown: usize) -> Option<String> {
    let text = text.trim();

    (!text.is_empty()).then(|| one_line(text, shown + 1))
}

/// Shown to an agent whose `session` value was rejected and replaced
const REPLACED_NOTE: &str = "the session you passed was not valid (unknown, expired or from another \
                             client); use this new one from now on";

/// The session a response hands back, so the agent passes it on its next call
struct SessionNote {
    token: String,
    replaced: bool,
}

impl SessionNote {
    /// Lines that lead a plain-text response
    fn lines(&self) -> String {
        let mut lines = format!("session: {}\n", self.token);
        if self.replaced {
            lines.push_str(&format!("note: {REPLACED_NOTE}\n"));
        }

        lines
    }

    /// Adds the session to a JSON object response
    fn insert(&self, body: &mut Value) {
        body["session"] = Value::String(self.token.clone());
        if self.replaced {
            body["session_note"] = Value::String(REPLACED_NOTE.to_owned());
        }
    }
}

/// `text` led by the session lines, when there is a session
fn tagged(session: Option<&SessionNote>, text: &str) -> String {
    match session {
        Some(session) => format!("{}{text}", session.lines()),
        None => text.to_owned(),
    }
}

/// The parts of a usage record known before the call is answered
struct Logged {
    caller: Caller,
    tool: &'static str,
    input: String,
    started: Instant,
    execution_id: Option<String>,
}

/// Pending answer, naming the approval an execution waits on, if any
pub fn pending_body(gateway: &Gateway, id: &str) -> Value {
    let approvals = gateway.approvals();
    match approvals.pending_for_execution(id) {
        Some(approval) => {
            // agents call `onepassword_authenticate`, not `onepassword.authenticate`
            let waiting_for = gateway
                .catalog()
                .entries()
                .iter()
                .find(|entry| entry.server == approval.server && entry.tool == approval.tool)
                .map_or_else(|| approval.waiting_for(), |entry| entry.function.clone());
            let others = approvals.batch(&approval.id).len().saturating_sub(1);
            let calls = match others {
                0 => waiting_for.clone(),
                1 => format!("{waiting_for} and 1 other call together"),
                others => format!("{waiting_for} and {others} other calls together"),
            };
            let message = if approvals.notification_failed(&approval.id) {
                format!(
                    "Waiting for the user to approve {}, but the phone notification could not \
                     be delivered. Give the user the approval_url to open, then call wait with \
                     this execution_id.",
                    calls
                )
            } else if approvals.asked_on_mac(&approval.id) {
                format!(
                    "Waiting for the user to approve {} on this Mac, where they are being asked \
                     now, and their phone is told if they do not answer there. Tell them and give \
                     them the approval_url, then call wait with this execution_id.",
                    calls
                )
            } else {
                format!(
                    "Waiting for the user to approve {} on their phone, or at the approval_url \
                     in a browser on this Mac. Tell them and give them the approval_url, then \
                     call wait with this execution_id.",
                    calls
                )
            };

            json!({
                "status": "pending",
                "execution_id": id,
                "approval_url": approvals.url_for(&approval.id),
                "waiting_for": waiting_for,
                "message": message,
            })
        }
        None => json!({
            "status": "pending",
            "execution_id": id,
            "message": "Still running. Call wait with this execution_id to keep waiting.",
        }),
    }
}

impl CodeModeServer {
    /// Creates a handler over a running app
    pub fn new(app: &App) -> Self {
        Self {
            gateway: Arc::clone(app.gateway()),
            executions: Arc::clone(app.executions()),
            log: app.usage().clone(),
            store: app.store().clone(),
            session_idle: app.config().session_idle(),
            wait_budget: app.config().limits.execute_wait(),
            progress_interval: app.config().limits.progress_interval(),
            max_response_bytes: app.config().limits.max_response_bytes(),
        }
    }

    /// Finds or issues the app session of a call and records it on `caller`
    ///
    /// A store failure leaves the call session-less rather than failing it
    fn open_session(&self, provided: Option<&str>, caller: &mut Caller) -> Option<SessionNote> {
        match self
            .store
            .resolve_session(provided, caller.client_name.as_deref(), self.session_idle)
        {
            Ok(resolved) => {
                caller.session = Some(resolved.hash);
                caller.session_state = resolved.state;

                Some(SessionNote {
                    token: resolved.token,
                    replaced: resolved.replaced,
                })
            }
            Err(error) => {
                tracing::warn!(%error, "cannot resolve an app session; serving the call without one");

                None
            }
        }
    }

    /// Waits up to the wait budget, sending a progress notification every
    /// `progress_interval` when the request carries a progress token
    ///
    /// Claude Code aborts an HTTP call that is idle for five minutes, and a
    /// notification counts as activity
    async fn await_outcome(
        &self,
        id: &str,
        budget: Duration,
        context: &RequestContext<RoleServer>,
        session: Option<&SessionNote>,
    ) -> (CallToolResult, Classification) {
        let wait = self.executions.wait(id, budget);
        tokio::pin!(wait);
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + self.progress_interval,
            self.progress_interval,
        );
        let mut ticks = 0.0;
        let waited = loop {
            tokio::select! {
                waited = &mut wait => break waited,
                _ = ticker.tick() => {
                    let Some(token) = context.meta.get_progress_token() else {
                        continue;
                    };
                    ticks += 1.0;
                    // a client that went away makes this fail, and the
                    // execution carries on regardless
                    let _ = context
                        .peer
                        .notify_progress(
                            ProgressNotificationParam::new(token, ticks)
                                .with_message("script still running"),
                        )
                        .await;
                }
            }
        };

        match waited {
            WaitResult::Finished(outcome) => (
                render_outcome(&outcome, self.max_response_bytes, session),
                outcome.classification(),
            ),
            WaitResult::Pending => {
                let mut body = pending_body(&self.gateway, id);
                if let Some(session) = session {
                    session.insert(&mut body);
                }
                let detail = body["waiting_for"]
                    .as_str()
                    .map(|tool| format!("waiting for approval of {tool}"));

                (
                    text_result(&body.to_string(), false),
                    Classification {
                        outcome: Outcome::Pending,
                        detail,
                    },
                )
            }
            WaitResult::Unknown => (
                text_result(&tagged(session, "Unknown or expired execution_id."), true),
                Classification::new(Outcome::RuntimeError, "unknown or expired execution_id"),
            ),
        }
    }

    fn record(&self, call: Logged, classification: Classification, result: &CallToolResult) {
        let Logged {
            caller,
            tool,
            input,
            started,
            execution_id,
        } = call;
        let result_bytes = result
            .content
            .iter()
            .filter_map(ContentBlock::as_text)
            .map(|block| block.text.len())
            .sum();

        self.log.call(CallRecord {
            caller,
            tool,
            input: Some(input),
            classification,
            duration: started.elapsed(),
            result_bytes,
            execution_id,
        });
    }
}

#[tool_router]
impl CodeModeServer {
    #[tool(
        description = "Find tools by keyword. Returns ranked tool names with one-line descriptions. \
                       Tool names are the Python function names to use in execute."
    )]
    async fn search_tools(
        &self,
        Parameters(params): Parameters<SearchParams>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let started = Instant::now();
        let mut caller = caller_of(&context);
        let session = self.open_session(params.session.as_deref(), &mut caller);
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

        let classification = Classification {
            outcome: Outcome::Ok,
            detail: Some(format!("results: {}", hits.len())),
        };
        let mut text = Value::Array(hits).to_string();
        // agents look here first for a secret, and the tools found cannot
        // read a vault item
        if guidance::asks_for_secrets(&params.query) {
            text = format!("note: {}\n{text}", guidance::ONEPASSWORD_RULE);
        }
        let result = text_result(&tagged(session.as_ref(), &text), false);
        self.record(
            Logged {
                caller,
                tool: "search_tools",
                input: params.query,
                started,
                execution_id: None,
            },
            classification,
            &result,
        );

        result
    }

    #[tool(
        description = "Get full documentation and typed Python signatures for tools returned by \
                       search_tools. Call this before writing a script that uses them."
    )]
    async fn describe_tools(
        &self,
        Parameters(params): Parameters<DescribeParams>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let started = Instant::now();
        let mut caller = caller_of(&context);
        let session = self.open_session(params.session.as_deref(), &mut caller);
        let catalog = self.gateway.catalog();
        let (stubs, missing) = catalog.describe(&params.names);
        let classification = if missing.is_empty() {
            Classification::ok()
        } else {
            Classification::new(
                Outcome::NameError,
                format!("unknown tools: {}", missing.join(", ")),
            )
        };
        let mut text = format!(
            "{}# {TOOL_CALL_RULE}\n# {SESSION_RULE}\n{stubs}",
            session.as_ref().map(SessionNote::lines).unwrap_or_default()
        );
        if !missing.is_empty() {
            text.push_str("\n# Unknown tools: ");
            text.push_str(&missing.join(", "));
            text.push_str(
                "\n# describe_tools takes names returned by search_tools, such as \
                 `server_tool`; search_tools, describe_tools, execute and wait are not \
                 callable from scripts",
            );
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

        let result = text_result(&text, false);
        self.record(
            Logged {
                caller,
                tool: "describe_tools",
                input: Value::from(params.names.clone()).to_string(),
                started,
                execution_id: None,
            },
            classification,
            &result,
        );

        result
    }

    #[tool(
        description = concat!(
            "Run a Python script that calls tools found with search_tools and described with describe_tools. ",
            "Waits briefly; if the script is still running it returns {\"status\":\"pending\",\"execution_id\":...} \
             and you call wait. Type errors and exceptions come back as text so you can fix the script. ",
            session_rule!(),
            "\n\n",
            script_rules!()
        )
    )]
    async fn execute(
        &self,
        Parameters(params): Parameters<ExecuteParams>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let started = Instant::now();
        let mut caller = caller_of(&context);
        let session = self.open_session(params.session.as_deref(), &mut caller);
        caller.thread = params
            .thread
            .as_deref()
            .and_then(|text| asked(text, THREAD_CHARS));
        caller.reason = params
            .reason
            .as_deref()
            .and_then(|text| asked(text, REASON_CHARS));
        let (result, classification, id) =
            match self.executions.start(params.code.clone(), caller.clone()) {
                Ok(id) => {
                    let (result, classification) = self
                        .await_outcome(&id, self.wait_budget, &context, session.as_ref())
                        .await;

                    (result, classification, Some(id))
                }
                Err(refused) => (
                    text_result(&tagged(session.as_ref(), &refused.to_string()), true),
                    Classification::new(
                        Outcome::Busy,
                        match refused {
                            StartError::Busy(_) => "all sandbox workers busy",
                            StartError::Draining => "the daemon is draining for a restart",
                        },
                    ),
                    None,
                ),
            };
        self.record(
            Logged {
                caller,
                tool: "execute",
                input: params.code,
                started,
                execution_id: id,
            },
            classification,
            &result,
        );

        result
    }

    #[tool(
        description = "Keep waiting for a pending execution started by execute. Returns its result or \
                          {\"status\":\"pending\"} again. It works with or without the session."
    )]
    async fn wait(
        &self,
        Parameters(params): Parameters<WaitParams>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let started = Instant::now();
        let mut caller = caller_of(&context);
        let session = self.open_session(params.session.as_deref(), &mut caller);
        let budget = params.timeout_secs.map_or(self.wait_budget, |secs| {
            Duration::from_secs(secs).min(MAX_WAIT)
        });
        let (result, classification) = self
            .await_outcome(&params.execution_id, budget, &context, session.as_ref())
            .await;
        self.record(
            Logged {
                caller,
                tool: "wait",
                input: params.execution_id.clone(),
                started,
                execution_id: Some(params.execution_id),
            },
            classification,
            &result,
        );

        result
    }
}

#[tool_handler]
impl ServerHandler for CodeModeServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

/// Mistakes agents make repeatedly, seen in the usage log, with the fix
/// spelled out so one retry is enough
const TYPE_ERROR_HINTS: &[(&str, &str)] = &[
    (
        "`return` statement outside of a function",
        "Scripts run at the top level: drop `return` and end the script with the value as a bare expression",
    ),
    (
        "Name `asyncio` used when not defined",
        "Add `import asyncio` at the top of the script",
    ),
    (
        "Name `json` used when not defined",
        "Add `import json` at the top of the script",
    ),
    (
        "has no member `JsonValue`",
        "JsonValue is predefined in every script, like the tool functions: remove it from the import",
    ),
    (
        "`dict[str, JsonValue]`, found `dict[",
        "dict is invariant, so a dict[str, str] is not a dict[str, JsonValue]: annotate the dict where you build it, or type the target JsonValue",
    ),
    (
        "`list[JsonValue]`, found `list[",
        "list is invariant, so a list[str] is not a list[JsonValue]: annotate the list where you build it, or type the target JsonValue",
    ),
    (
        "error[ban:any]",
        "Any is not allowed: use the tool's declared return type, read a `JsonValue` with json_str(r, \"$.path\") and the other json_* accessors, or annotate with `object`",
    ),
    (
        "error[ban:cast]",
        "cast is not allowed: read a `JsonValue` with json_str(r, \"$.path\") and the other json_* accessors, or use the tool's declared return type",
    ),
    (
        "error[ban:type-ignore]",
        "type: ignore is not allowed: fix the mismatch, usually with a json_* accessor such as json_str(r, \"$.path\") or the tool's declared return type",
    ),
    (
        "error[ban:json-loads]",
        "json.loads is not allowed: json_parse(text) parses JSON text into a JsonValue, which the json_* accessors read",
    ),
];

/// Result size past which a completed answer asks for less; agents have
/// returned whole documents that their client then truncated mid-result
const LARGE_RESULT_BYTES: usize = 16 * 1024;

/// Hints for known mistakes in type-check diagnostics, or an empty string
fn type_error_hints(diagnostics: &str) -> String {
    TYPE_ERROR_HINTS
        .iter()
        .filter(|(needle, _)| diagnostics.contains(needle))
        .map(|(_, hint)| format!("\nHint: {hint}"))
        .collect()
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
fn render_outcome(
    outcome: &ExecutionOutcome,
    max_bytes: usize,
    session: Option<&SessionNote>,
) -> CallToolResult {
    let (text, is_error) = outcome_text_for(outcome, max_bytes, session);

    text_result(&text, is_error)
}

/// Text of a finished execution, capped at `max_bytes`, and whether it counts
/// as a failure
pub fn outcome_text(outcome: &ExecutionOutcome, max_bytes: usize) -> (String, bool) {
    outcome_text_for(outcome, max_bytes, None)
}

/// Like [`outcome_text`] for a call under a session: a completed result
/// carries the session as a JSON field; failures are plain text and lead
/// with the session lines
fn outcome_text_for(
    outcome: &ExecutionOutcome,
    max_bytes: usize,
    session: Option<&SessionNote>,
) -> (String, bool) {
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
            let mut notes = notes.clone();
            let size = value.to_string().len();
            if size > LARGE_RESULT_BYTES {
                notes.push(format!(
                    "This result is {} KB. Return only the fields asked for, such as titles, URLs \
                     and short excerpts, so it is not truncated before it reaches you",
                    size / 1024
                ));
            }
            if !notes.is_empty() {
                body["notes"] = json!(notes);
            }
            if !output.is_empty() {
                body["output"] = Value::String(output.clone());
            }
            if let Some(session) = session {
                session.insert(&mut body);
            }

            (body.to_string(), false)
        }
        ExecutionOutcome::TypeError { diagnostics, .. } => (
            tagged(
                session,
                &format!(
                    "Type check failed; the script did not run. Fix these and call execute again.\n\n{diagnostics}{}",
                    type_error_hints(diagnostics)
                ),
            ),
            true,
        ),
        ExecutionOutcome::Exception {
            message, output, ..
        } => (
            tagged(
                session,
                &with_output(
                    &format!("The script raised an exception.\n\n{message}"),
                    output,
                ),
            ),
            true,
        ),
        ExecutionOutcome::Failed {
            message, output, ..
        } => (
            tagged(
                session,
                &with_output(&format!("Execution failed: {message}"), output),
            ),
            true,
        ),
        ExecutionOutcome::ResultNotKept { outcome } => (
            tagged(
                session,
                &format!(
                    "The script finished ({outcome}); its result is not kept across restarts \
                     because it used a sensitive server. Do not re-run it to get the result."
                ),
            ),
            outcome != "ok",
        ),
        ExecutionOutcome::Interrupted { reason, calls } => {
            (tagged(session, &interrupted_text(*reason, calls)), true)
        }
    };

    (cap_text(text, max_bytes), is_error)
}

/// What an agent reads when a restart cut its script short: what is known
/// about the upstream calls that finished, and that writes may have happened
fn interrupted_text(reason: InterruptReason, calls: &[CompletedCall]) -> String {
    let mut text = match reason {
        InterruptReason::Restarted => String::from(
            "The daemon restarted while this script was running, so its outcome is unknown.",
        ),
        InterruptReason::SensitiveNotKept => String::from(
            "The daemon restarted while this script was running. The script used a sensitive \
             server, and sensitive state is not kept across restarts, so the script was not \
             resumed and its result was not kept. Re-run the script.",
        ),
    };

    // the list comes from the usage log, which is written in batches, so a
    // kill can lose its last rows: an empty list proves nothing
    if calls.is_empty() {
        text.push_str(
            "\n\nNo upstream call was recorded as completed (this list may be incomplete).",
        );
    } else {
        text.push_str(
            "\n\nRecorded upstream calls that completed before it stopped (this list may be \
             incomplete):",
        );
        for call in calls {
            text.push_str(&format!(
                "\n- {}.{}: {}",
                call.server, call.tool, call.status
            ));
        }
    }
    text.push_str(
        "\n\nWrites may have happened: a call that was running when the daemon stopped may \
         have reached its upstream. Check the current state before running the script again.",
    );

    text
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

/// Handle to the running HTTP servers
pub struct RunningServer {
    address: SocketAddr,
    admin_address: SocketAddr,
    shutdown: CancellationToken,
    in_flight: InFlight,
    tasks: Vec<JoinHandle<std::io::Result<()>>>,
}

impl RunningServer {
    /// Address actually bound, useful when the config asked for port 0
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Address of the loopback admin listener
    pub fn admin_addr(&self) -> SocketAddr {
        self.admin_address
    }

    /// Stops accepting requests and waits for in-flight ones to finish
    pub async fn shutdown(self) -> std::io::Result<()> {
        self.shutdown.cancel();

        self.finished().await
    }

    /// Waits until both listeners stop, e.g. after a signal
    pub async fn finished(self) -> std::io::Result<()> {
        for task in self.tasks {
            task.await.map_err(std::io::Error::other)??;
        }

        Ok(())
    }

    /// Token that stops the server when cancelled
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Counter of MCP requests still being answered
    pub fn in_flight(&self) -> InFlight {
        self.in_flight.clone()
    }
}

/// Counts MCP requests in progress, so a stop can let them answer first:
/// cancelling the server drops a request whose handler has not replied, and
/// the client sees "no response message received from handler"
#[derive(Clone, Default)]
pub struct InFlight(Arc<InFlightInner>);

#[derive(Default)]
struct InFlightInner {
    count: AtomicUsize,
    idle: Notify,
}

impl InFlight {
    fn enter(&self) -> InFlightGuard {
        self.0.count.fetch_add(1, Ordering::SeqCst);

        InFlightGuard(self.clone())
    }

    /// Resolves once no request is in progress, or after `limit`
    pub async fn settled(&self, limit: Duration) {
        let _ = tokio::time::timeout(limit, async {
            loop {
                let idle = self.0.idle.notified();
                if self.0.count.load(Ordering::SeqCst) == 0 {
                    return;
                }
                idle.await;
            }
        })
        .await;
    }
}

struct InFlightGuard(InFlight);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let inner = &(self.0).0;
        if inner.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            inner.idle.notify_waiters();
        }
    }
}

async fn track_in_flight(
    State(in_flight): State<InFlight>,
    request: Request,
    next: middleware::Next,
) -> Response {
    let _guard = in_flight.enter();

    next.run(request).await
}

/// Binds the configured addresses: `/mcp`, `/healthz`, `/stats` and the
/// approval pages on `listen`, the admin API on the loopback `admin_listen`
pub async fn serve(app: &App) -> std::io::Result<RunningServer> {
    Listeners::bind(app.config()).await?.serve(app)
}

/// The two sockets, bound but not yet answering
///
/// Binding first lets the daemon fail on a taken port before it touches any
/// state, and start answering only once it has settled what the previous
/// process left behind
pub struct Listeners {
    listener: TcpListener,
    admin_listener: TcpListener,
}

impl Listeners {
    /// Binds the main and the admin listener of `config`
    pub async fn bind(config: &Config) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(config.listen).await?,
            admin_listener: TcpListener::bind(config.admin_listen).await?,
        })
    }

    /// Starts answering requests for `app`
    pub fn serve(self, app: &App) -> std::io::Result<RunningServer> {
        serve_on(app, self.listener, self.admin_listener)
    }
}

fn serve_on(
    app: &App,
    listener: TcpListener,
    admin_listener: TcpListener,
) -> std::io::Result<RunningServer> {
    let address = listener.local_addr()?;
    let admin_address = admin_listener.local_addr()?;
    // OAuth redirect URIs point at the admin listener's real port
    app.gateway().oauth().set_callback_address(admin_address);
    let shutdown = CancellationToken::new();

    let mcp_app = app.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(CodeModeServer::new(&mcp_app)),
        Arc::new(NeverSessionManager::default()),
        // rmcp only matches exact authorities; `host_guard` below applies
        // the real rules, so its own check is switched off; turning legacy
        // session mode off serves every client statelessly, so older clients
        // still `initialize` but are never given an `mcp-session-id`
        StreamableHttpServerConfig::default()
            .disable_allowed_hosts()
            .with_legacy_session_mode(false)
            .with_cancellation_token(shutdown.child_token()),
    );
    let hosts = Arc::new(HostPolicy::new(&app.config().extra_allowed_hosts));
    let in_flight = InFlight::default();
    let mcp = Router::new()
        .fallback_service(mcp)
        .layer(middleware::from_fn_with_state(
            in_flight.clone(),
            track_in_flight,
        ));
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .with_state(Arc::clone(app.gateway()))
        .merge(web::router(app))
        .nest_service("/mcp", mcp);
    if let Some(hub) = app.hub() {
        router = router.merge(crate::hub::server::router(Arc::clone(hub)));
    }
    let router = router.layer(middleware::from_fn_with_state(hosts, host_guard));

    let token = shutdown.clone();
    let main = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { token.cancelled().await })
        .await
    });
    let token = shutdown.clone();
    let admin_router = admin::router(app);
    let admin = tokio::spawn(async move {
        axum::serve(
            admin_listener,
            admin_router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { token.cancelled().await })
        .await
    });
    tracing::info!(%address, %admin_address, "listening");

    Ok(RunningServer {
        address,
        admin_address,
        shutdown,
        in_flight,
        tasks: vec![main, admin],
    })
}

/// Names, states and tool counts only: the endpoint is unauthenticated, and
/// raw connection errors can hold URLs, commands and paths
async fn healthz(State(gateway): State<Arc<Gateway>>) -> Json<Value> {
    let upstreams = gateway.public_report();
    let connected = upstreams
        .iter()
        .filter(|upstream| upstream.state == "connected")
        .count();

    // listed in the config but never used until the owner trusts them
    let untrusted: Vec<String> = gateway
        .companions()
        .untrusted()
        .iter()
        .map(|device| device.name().to_owned())
        .collect();

    Json(json!({
        "status": "ok",
        "tools": gateway.catalog().entries().len(),
        "upstreams_connected": connected,
        "upstreams": upstreams,
        "untrusted_devices": untrusted,
    }))
}
