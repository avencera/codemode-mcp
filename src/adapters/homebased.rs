//! MCP adapter for the homebased CLI
//!
//! Every tool shells out to `homebased --json ...` with an argv array, never
//! through a shell, under a timeout. Option values are passed as
//! `--flag=value` and task ids must be UUIDs, so no agent-supplied value can
//! be read as another option. Commands that stop, update or reconfigure the
//! daemon, change the fleet, use the GPU queue, run containers or write task
//! reports are left out on purpose

use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use tokio::{io::AsyncWriteExt, process::Command};

use crate::notify::{Notification, Notifier, Priority};

mod outputs;

use outputs::{
    Agent, CancelAck, DaemonStatus, FleetMachines, MessageAck, NotifyAck, SubmitAck, TaskDetail,
    TaskList, TaskLog, TaskStatus, TaskUsage,
};

/// Environment variable naming the homebased executable
pub const PROGRAM_ENV: &str = "CODEMODE_HOMEBASED_BIN";
/// Time allowed for read-only commands
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Time allowed for submits; a local submit retries a busy daemon for about 90 s
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(150);
/// Time allowed for cancels and messages
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest stdout or stderr kept from one command
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Default `task_log` tail
const DEFAULT_TAIL: u32 = 200;
/// Variables homebased reads to name the caller; the adapter acts for many
/// sessions, so inheriting one would misattribute submits and messages
const CALLER_ENV: [&str; 5] = [
    "HOMEBASED_TASK_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
    "CLAUDE_CODE_SESSION_ID",
    "CLAUDECODE",
];

const INSTRUCTIONS: &str = "Supervise long-running agent workers and commands through homebased. \
     Submits take your own session id as `thread`; results arrive later as HOMEBASED_EVENT \
     messages in that session, so never poll task_show or task_list in a loop.";

/// How urgent a notification is
#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NotifyLevel {
    /// Work cannot continue without the owner
    Blocked,
    /// The owner should look soon
    Important,
    /// Something finished
    Done,
}

/// Arguments of `task_list`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskListParams {
    /// Only tasks in these states
    pub status: Option<Vec<TaskStatus>>,
    /// Only tasks reporting to this session or thread id
    pub thread: Option<String>,
}

/// Arguments that name one task
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskIdParams {
    /// Full task UUID
    pub id: String,
}

/// Arguments of `task_log`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskLogParams {
    /// Full task UUID
    pub id: String,
    /// Last N lines (default 200)
    pub tail: Option<u32>,
}

/// Arguments of `task_usage`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskUsageParams {
    /// Window such as `24h` or `7d` (default `7d`)
    pub since: Option<String>,
    /// Only tasks from this session or thread id
    pub thread: Option<String>,
}

/// Arguments of `task_submit_agent`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubmitAgentParams {
    /// Your own session id, which receives the result events:
    /// `$CLAUDE_CODE_SESSION_ID` in Claude Code, the thread id in Codex
    pub thread: String,
    /// Short human-readable task name
    pub name: String,
    /// Existing directory the worker runs in, on the machine that runs it
    pub cwd: String,
    /// Agent CLI to run
    pub agent: Agent,
    /// Complete, self-contained instructions for the worker
    pub prompt: String,
    /// Model name for the agent CLI
    pub model: Option<String>,
    /// Reasoning-effort flags only: `--effort LEVEL` or
    /// `-c model_reasoning_effort=LEVEL`
    pub extra_args: Option<Vec<String>>,
    /// Output-inactivity timeout such as `2h` (default `1h`, minimum `30m`)
    pub timeout: Option<String>,
    /// Task UUIDs that must succeed before this task starts
    pub after: Option<Vec<String>>,
    /// Fleet machine name or id; this machine when omitted
    pub machine: Option<String>,
    /// UUID that makes retries safe; generated and returned when omitted
    pub request_id: Option<String>,
    /// Validate only; nothing starts
    pub dry_run: Option<bool>,
}

/// Arguments of `task_submit_command`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubmitCommandParams {
    /// Your own session id, which receives the result events:
    /// `$CLAUDE_CODE_SESSION_ID` in Claude Code, the thread id in Codex
    pub thread: String,
    /// Short human-readable task name
    pub name: String,
    /// Existing directory the command runs in, on the machine that runs it
    pub cwd: String,
    /// Program and arguments; no shell, no quoting
    pub command: Vec<String>,
    /// Output-inactivity timeout such as `2h` (default `1h`, minimum `30m`)
    pub timeout: Option<String>,
    /// Task UUIDs that must succeed before this task starts
    pub after: Option<Vec<String>>,
    /// Fleet machine name or id; this machine when omitted
    pub machine: Option<String>,
    /// UUID that makes retries safe; generated and returned when omitted
    pub request_id: Option<String>,
    /// Validate only; nothing starts
    pub dry_run: Option<bool>,
}

/// Arguments of `task_followup`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FollowupParams {
    /// Full UUID of the finished Codex task to resume
    pub id: String,
    /// More information for the worker
    pub message: String,
    /// Session or thread id that receives the follow-up's events
    pub thread: Option<String>,
    /// Name for the follow-up task
    pub name: Option<String>,
    /// UUID that makes retries safe; generated and returned when omitted
    pub request_id: Option<String>,
    /// Validate only; nothing starts
    pub dry_run: Option<bool>,
}

/// Arguments of `message_send`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MessageParams {
    /// Destination session or thread UUID; needs `machine`
    pub thread: Option<String>,
    /// Destination working directory (Codex threads only); needs `machine`
    pub cwd: Option<String>,
    /// Send to this task's origin session
    pub task: Option<String>,
    /// Send to this task's running Claude worker
    pub worker: Option<String>,
    /// Destination machine name or id, for `thread` and `cwd`
    pub machine: Option<String>,
    /// Message text
    pub message: String,
    /// UUID that makes retries safe; generated and returned when omitted
    pub message_id: Option<String>,
}

/// Arguments of `notify`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct NotifyParams {
    /// How urgent it is
    pub level: NotifyLevel,
    /// Headline
    pub title: String,
    /// Body text
    pub body: String,
}

/// A failure the agent sees as the tool's error text
#[derive(Debug, thiserror::Error)]
enum AdapterError {
    /// The arguments are unusable
    #[error("{0}")]
    Invalid(String),
    /// homebased could not be started
    #[error("could not run homebased ({program}): {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    /// homebased took too long and was killed
    #[error("homebased did not answer within {0:?}; the outcome is unknown")]
    Timeout(Duration),
    /// homebased answered with an error
    #[error("homebased error {code} (exit {exit}, retryable: {retryable}): {message}")]
    Homebased {
        code: String,
        message: String,
        retryable: bool,
        exit: i32,
    },
    /// Local I/O failed (temp files, pipes)
    #[error("{0}")]
    Io(String),
}

/// Name prefix of the temp dirs [`PrivateDir`] makes; followed by 32 hex digits
const PRIVATE_DIR_PREFIX: &str = "codemode-homebased-";

/// Removes the temp dirs a crashed adapter left behind
///
/// Only a directory (not a link) in the temp dir that is owned by this user,
/// has exactly the name [`PrivateDir`] gives and is older than `min_age` is
/// removed, so another user's files, a live submit and anything that merely
/// looks similar are left alone. Returns how many were removed
pub fn remove_stale_private_dirs(min_age: Duration) -> usize {
    remove_stale_private_dirs_in(&std::env::temp_dir(), min_age)
}

fn remove_stale_private_dirs_in(temp: &Path, min_age: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(temp) else {
        return 0;
    };
    let owner = rustix::process::getuid().as_raw();
    let mut removed = 0;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(suffix) = name
            .to_str()
            .and_then(|name| name.strip_prefix(PRIVATE_DIR_PREFIX))
        else {
            continue;
        };
        if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }

        // symlink_metadata: a link named like ours is never followed
        let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let old_enough = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= min_age);
        if metadata.is_dir()
            && std::os::unix::fs::MetadataExt::uid(&metadata) == owner
            && old_enough
            && std::fs::remove_dir_all(entry.path()).is_ok()
        {
            removed += 1;
        }
    }

    removed
}

/// A directory only this user can read, removed when dropped
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn create() -> Result<Self, AdapterError> {
        let path = std::env::temp_dir().join(format!(
            "{PRIVATE_DIR_PREFIX}{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| AdapterError::Io(format!("cannot create a temp dir: {error}")))?;

        Ok(Self(path))
    }

    /// Writes `text` to a new 0600 file in the directory
    fn write(&self, name: &str, text: &str) -> Result<PathBuf, AdapterError> {
        let path = self.0.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(text.as_bytes()).map(|()| file))
            .map_err(|error| AdapterError::Io(format!("cannot write a temp file: {error}")))?;
        file.flush()
            .map_err(|error| AdapterError::Io(format!("cannot write a temp file: {error}")))?;

        Ok(path)
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The value must be a UUID; also keeps it from looking like an option
fn uuid_arg(field: &str, value: &str) -> Result<String, AdapterError> {
    uuid::Uuid::parse_str(value)
        .map(|parsed| parsed.hyphenated().to_string())
        .map_err(|_| AdapterError::Invalid(format!("`{field}` must be a full UUID, got {value:?}")))
}

/// Reasoning levels the agent CLIs accept
const EFFORT_LEVELS: [&str; 6] = ["minimal", "low", "medium", "high", "xhigh", "max"];

/// Keeps only reasoning-effort flags in an agent submit's extra arguments
///
/// Agent submits are allowed without approval, while arbitrary CLI flags
/// (such as Claude's `--settings` with hooks) could run any command and
/// sidestep the approval on `task_submit_command`
fn effort_args(args: &[String]) -> Result<&[String], AdapterError> {
    let level = |value: &str| EFFORT_LEVELS.contains(&value);
    let mut rest = args;
    while let Some((first, tail)) = rest.split_first() {
        rest = match (first.as_str(), tail.first()) {
            ("--effort", Some(value)) if level(value) => &tail[1..],
            ("-c" | "--config", Some(value))
                if value
                    .strip_prefix("model_reasoning_effort=")
                    .is_some_and(level) =>
            {
                &tail[1..]
            }
            (flag, _) if flag.strip_prefix("--effort=").is_some_and(level) => tail,
            _ => {
                return Err(AdapterError::Invalid(format!(
                    "`extra_args` only accepts reasoning-effort flags (`--effort LEVEL`, \
                     `-c model_reasoning_effort=LEVEL`), got {first:?}; use \
                     task_submit_command for anything else"
                )));
            }
        };
    }

    Ok(args)
}

/// A given UUID, or a fresh one
fn request_id(field: &str, given: Option<&str>) -> Result<String, AdapterError> {
    match given {
        Some(value) => uuid_arg(field, value),
        None => Ok(uuid::Uuid::new_v4().hyphenated().to_string()),
    }
}

/// Fields every submit shares
struct SubmitBase<'a> {
    thread: &'a str,
    name: &'a str,
    cwd: &'a str,
    timeout: Option<&'a str>,
    after: Option<&'a [String]>,
    machine: Option<&'a str>,
}

impl SubmitBase<'_> {
    fn spec(&self, workload: Value) -> Result<Value, AdapterError> {
        let mut spec = json!({
            "api_version": 1,
            "thread": uuid_arg("thread", self.thread)?,
            "name": self.name,
            "cwd": self.cwd,
            "workload": workload,
        });
        if let Some(timeout) = self.timeout {
            spec["timeout"] = json!(timeout);
        }
        if let Some(after) = self.after {
            let after = after
                .iter()
                .map(|id| uuid_arg("after", id))
                .collect::<Result<Vec<_>, _>>()?;
            spec["after"] = json!(after);
        }
        if let Some(machine) = self.machine {
            spec["machine"] = json!(machine);
        }

        Ok(spec)
    }
}

struct Inner {
    program: PathBuf,
    notifier: Option<Arc<dyn Notifier>>,
}

/// The stdio MCP server; cheap to clone
#[derive(Clone)]
pub struct HomebasedAdapter(Arc<Inner>);

impl HomebasedAdapter {
    /// An adapter that runs `program` and sends `notify` through `notifier`
    pub fn new(program: PathBuf, notifier: Option<Arc<dyn Notifier>>) -> Self {
        Self(Arc::new(Inner { program, notifier }))
    }

    /// The executable from [`PROGRAM_ENV`], else `homebased` on `PATH`
    pub fn program_from_env() -> PathBuf {
        std::env::var_os(PROGRAM_ENV)
            .filter(|value| !value.is_empty())
            .map_or_else(|| PathBuf::from("homebased"), PathBuf::from)
    }

    /// Serves MCP on stdin and stdout until the client disconnects
    pub async fn serve_stdio(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let service = self.serve(rmcp::transport::stdio()).await?;
        service.waiting().await?;

        Ok(())
    }

    /// Runs `homebased --json <args>`, feeding `stdin` when given, and
    /// returns its JSON answer
    async fn run(
        &self,
        args: &[String],
        stdin: Option<String>,
        timeout: Duration,
    ) -> Result<Value, AdapterError> {
        let mut command = Command::new(&self.0.program);
        command
            .arg("--json")
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for name in CALLER_ENV {
            command.env_remove(name);
        }
        let mut child = command.spawn().map_err(|source| AdapterError::Spawn {
            program: self.0.program.display().to_string(),
            source,
        })?;

        let pipe = child.stdin.take();
        // the stdin write sits under the same timeout: a child that stops
        // reading must not hang the call
        let exchange = async move {
            if let (Some(text), Some(mut pipe)) = (stdin, pipe) {
                pipe.write_all(text.as_bytes()).await.map_err(|error| {
                    AdapterError::Io(format!("cannot write to homebased: {error}"))
                })?;
                // closing stdin ends the spec
                drop(pipe);
            }

            child
                .wait_with_output()
                .await
                .map_err(|error| AdapterError::Io(format!("homebased failed: {error}")))
        };
        let output = tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| AdapterError::Timeout(timeout))??;
        let stdout =
            String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(MAX_OUTPUT_BYTES)]);
        let stderr =
            String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(MAX_OUTPUT_BYTES)]);

        if output.status.success() {
            return Ok(serde_json::from_str(stdout.trim())
                .unwrap_or_else(|_| Value::String(stdout.trim().to_owned())));
        }

        let exit = output.status.code().unwrap_or(-1);
        let parsed: Option<Value> = serde_json::from_str(stderr.trim())
            .ok()
            .or_else(|| serde_json::from_str(stdout.trim()).ok());
        let error = parsed.as_ref().map(|value| &value["error"]);

        Err(AdapterError::Homebased {
            code: error
                .and_then(|error| error["code"].as_str())
                .unwrap_or("unknown")
                .to_owned(),
            message: error
                .and_then(|error| error["message"].as_str())
                .map_or_else(|| stderr.trim().to_owned(), str::to_owned),
            retryable: error
                .and_then(|error| error["retryable"].as_bool())
                .unwrap_or(false),
            exit,
        })
    }

    async fn submit(
        &self,
        spec: Value,
        request_id: String,
        dry_run: bool,
    ) -> Result<Value, AdapterError> {
        let mut args = vec![
            "task".to_owned(),
            "submit".to_owned(),
            "--spec=-".to_owned(),
            format!("--request-id={request_id}"),
        ];
        if dry_run {
            args.push("--dry-run".to_owned());
        }
        let answer = self
            .run(&args, Some(spec.to_string()), SUBMIT_TIMEOUT)
            .await?;

        Ok(submit_ack(answer, &request_id, dry_run))
    }
}

/// The ack of a submit or follow-up
///
/// A dry run prints the normalized spec instead of a task, so only its
/// `argv` and the flag that says nothing started are kept
fn submit_ack(answer: Value, request_id: &str, dry_run: bool) -> Value {
    let mut ack = Map::new();
    ack.insert("request_id".to_owned(), json!(request_id));
    ack.insert("dry_run".to_owned(), json!(dry_run));
    for key in ["id", "status", "argv"] {
        if let Some(value) = answer.get(key) {
            ack.insert(key.to_owned(), value.clone());
        }
    }
    // homebased may echo its own request id
    if let Some(echoed) = answer.get("request_id") {
        ack.insert("request_id".to_owned(), echoed.clone());
    }

    Value::Object(ack)
}

/// The tool's structured result, or the failure as the tool's error text
///
/// The answer is read into `T`, which drops fields the agent does not need
/// and fails loudly when homebased changes a shape the declared schema relies on
fn typed<T: DeserializeOwned>(
    outcome: Result<Value, AdapterError>,
) -> Result<Json<T>, CallToolResult> {
    let failed = |message: String| CallToolResult::error(vec![ContentBlock::text(message)]);
    let value = outcome.map_err(|error| failed(error.to_string()))?;

    serde_json::from_value(value)
        .map(Json)
        .map_err(|error| failed(format!("unexpected homebased output: {error}")))
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

#[tool_router]
impl HomebasedAdapter {
    #[tool(description = "Daemon socket state, web address and in-flight task count.")]
    async fn daemon_status(&self) -> Result<Json<DaemonStatus>, CallToolResult> {
        typed(
            self.run(&strings(&["daemon", "status"]), None, READ_TIMEOUT)
                .await,
        )
    }

    #[tool(
        description = "List tasks on this machine, newest last. Filter by status and by the \
                       session or thread the tasks report to. Do not call this in a loop to \
                       wait for a task; results arrive as HOMEBASED_EVENT messages."
    )]
    async fn task_list(
        &self,
        Parameters(params): Parameters<TaskListParams>,
    ) -> Result<Json<TaskList>, CallToolResult> {
        let outcome = async {
            let mut args = strings(&["task", "list"]);
            if let Some(statuses) = params.status.filter(|statuses| !statuses.is_empty()) {
                let joined: Vec<&str> = statuses.iter().map(|status| status.as_str()).collect();
                args.push(format!("--status={}", joined.join(",")));
            }
            if let Some(thread) = params.thread {
                args.push(format!("--thread={}", uuid_arg("thread", &thread)?));
            }

            self.run(&args, None, READ_TIMEOUT).await
        };

        typed(outcome.await)
    }

    #[tool(description = "One task's status, reports, dependencies and last event.")]
    async fn task_show(
        &self,
        Parameters(params): Parameters<TaskIdParams>,
    ) -> Result<Json<TaskDetail>, CallToolResult> {
        let outcome = async {
            let args = vec![
                "task".to_owned(),
                "show".to_owned(),
                uuid_arg("id", &params.id)?,
            ];

            self.run(&args, None, READ_TIMEOUT).await
        };

        typed(outcome.await)
    }

    #[tool(description = "The last lines of a task's output log (default 200).")]
    async fn task_log(
        &self,
        Parameters(params): Parameters<TaskLogParams>,
    ) -> Result<Json<TaskLog>, CallToolResult> {
        let outcome = async {
            let args = vec![
                "task".to_owned(),
                "log".to_owned(),
                uuid_arg("id", &params.id)?,
                format!("--tail={}", params.tail.unwrap_or(DEFAULT_TAIL)),
            ];

            self.run(&args, None, READ_TIMEOUT).await
        };

        typed(outcome.await)
    }

    #[tool(description = "Token usage of finished Claude workers, by model, day, thread and task.")]
    async fn task_usage(
        &self,
        Parameters(params): Parameters<TaskUsageParams>,
    ) -> Result<Json<TaskUsage>, CallToolResult> {
        let outcome = async {
            let mut args = strings(&["task", "usage"]);
            args.push(format!(
                "--since={}",
                params.since.as_deref().unwrap_or("7d")
            ));
            if let Some(thread) = params.thread {
                args.push(format!("--thread={}", uuid_arg("thread", &thread)?));
            }

            self.run(&args, None, READ_TIMEOUT).await
        };

        typed(outcome.await)
    }

    #[tool(description = "This machine and the known fleet machines with their reachability.")]
    async fn fleet_machines(&self) -> Result<Json<FleetMachines>, CallToolResult> {
        typed(
            self.run(&strings(&["fleet", "machines"]), None, READ_TIMEOUT)
                .await,
        )
    }

    #[tool(
        description = "Start a coding-agent worker (codex, claude, grok or opencode) with a \
                       self-contained prompt. Pass your own session id as `thread` \
                       ($CLAUDE_CODE_SESSION_ID in Claude Code, the thread id in Codex). The \
                       result arrives later as a HOMEBASED_EVENT message in that session: do \
                       not poll task_show or task_list in a loop. Returns {id, request_id, \
                       status}; retrying with the same request_id and unchanged arguments \
                       returns the same task instead of starting a second one. Chain phases \
                       with `after`."
    )]
    async fn task_submit_agent(
        &self,
        Parameters(params): Parameters<SubmitAgentParams>,
    ) -> Result<Json<SubmitAck>, CallToolResult> {
        let outcome = async {
            let request_id = request_id("request_id", params.request_id.as_deref())?;
            // homebased inlines the prompt file at submit, so the file only
            // has to outlive the submit command
            let directory = PrivateDir::create()?;
            let prompt_file = directory.write("prompt.md", &params.prompt)?;

            let mut workload = json!({
                "type": "agent",
                "agent": params.agent,
                "prompt_file": prompt_file,
            });
            if let Some(model) = &params.model {
                workload["model"] = json!(model);
            }
            if let Some(extra_args) = &params.extra_args {
                workload["extra_args"] = json!(effort_args(extra_args)?);
            }
            let spec = SubmitBase {
                thread: &params.thread,
                name: &params.name,
                cwd: &params.cwd,
                timeout: params.timeout.as_deref(),
                after: params.after.as_deref(),
                machine: params.machine.as_deref(),
            }
            .spec(workload)?;

            self.submit(spec, request_id, params.dry_run.unwrap_or(false))
                .await
        };

        typed(outcome.await)
    }

    #[tool(
        description = "Run an arbitrary non-interactive command (argv, no shell) as a task. \
                       Pass your own session id as `thread` ($CLAUDE_CODE_SESSION_ID in Claude \
                       Code, the thread id in Codex); the result arrives as a HOMEBASED_EVENT \
                       message in that session, so do not poll. Returns {id, request_id, \
                       status}; retry with the same request_id to avoid a duplicate."
    )]
    async fn task_submit_command(
        &self,
        Parameters(params): Parameters<SubmitCommandParams>,
    ) -> Result<Json<SubmitAck>, CallToolResult> {
        let outcome = async {
            if params.command.first().is_none_or(String::is_empty) {
                return Err(AdapterError::Invalid(
                    "`command` needs a non-empty program as its first element".into(),
                ));
            }
            let request_id = request_id("request_id", params.request_id.as_deref())?;
            let spec = SubmitBase {
                thread: &params.thread,
                name: &params.name,
                cwd: &params.cwd,
                timeout: params.timeout.as_deref(),
                after: params.after.as_deref(),
                machine: params.machine.as_deref(),
            }
            .spec(json!({ "type": "task", "command": params.command }))?;

            self.submit(spec, request_id, params.dry_run.unwrap_or(false))
                .await
        };

        typed(outcome.await)
    }

    #[tool(
        description = "Resume a finished Codex worker task with more information. Returns the \
                       new task id and request_id; events arrive as HOMEBASED_EVENT messages."
    )]
    async fn task_followup(
        &self,
        Parameters(params): Parameters<FollowupParams>,
    ) -> Result<Json<SubmitAck>, CallToolResult> {
        let outcome = async {
            let request_id = request_id("request_id", params.request_id.as_deref())?;
            let directory = PrivateDir::create()?;
            let message_file = directory.write("message.md", &params.message)?;

            let mut args = vec![
                "task".to_owned(),
                "followup".to_owned(),
                uuid_arg("id", &params.id)?,
                format!("--message-file={}", message_file.display()),
                format!("--request-id={request_id}"),
            ];
            if let Some(thread) = &params.thread {
                args.push(format!("--thread={}", uuid_arg("thread", thread)?));
            }
            if let Some(name) = &params.name {
                args.push(format!("--name={name}"));
            }
            if params.dry_run.unwrap_or(false) {
                args.push("--dry-run".to_owned());
            }
            let dry_run = params.dry_run.unwrap_or(false);
            let answer = self.run(&args, None, SUBMIT_TIMEOUT).await?;

            Ok(submit_ack(answer, &request_id, dry_run))
        };

        typed(outcome.await)
    }

    #[tool(description = "Cancel a task. Idempotent when the task already finished.")]
    async fn task_cancel(
        &self,
        Parameters(params): Parameters<TaskIdParams>,
    ) -> Result<Json<CancelAck>, CallToolResult> {
        let outcome = async {
            let args = vec![
                "task".to_owned(),
                "cancel".to_owned(),
                uuid_arg("id", &params.id)?,
            ];

            self.run(&args, None, WRITE_TIMEOUT).await
        };

        typed(outcome.await)
    }

    #[tool(
        description = "Send a message into another agent session. Give exactly one destination: \
                       `thread` (with `machine`), `cwd` (with `machine`, Codex only), `task` \
                       (that task's origin session) or `worker` (that task's running Claude \
                       worker). Returns a receipt with message_id; retry with the same \
                       message_id to avoid a duplicate."
    )]
    async fn message_send(
        &self,
        Parameters(params): Parameters<MessageParams>,
    ) -> Result<Json<MessageAck>, CallToolResult> {
        let outcome = async {
            let destinations = [
                ("thread", params.thread.as_deref()),
                ("cwd", params.cwd.as_deref()),
                ("task", params.task.as_deref()),
                ("worker", params.worker.as_deref()),
            ];
            let given: Vec<(&str, &str)> = destinations
                .iter()
                .filter_map(|(flag, value)| value.map(|value| (*flag, value)))
                .collect();
            let [(flag, value)] = given.as_slice() else {
                return Err(AdapterError::Invalid(
                    "give exactly one of `thread`, `cwd`, `task` or `worker`".into(),
                ));
            };
            let value = match *flag {
                "cwd" => (*value).to_owned(),
                _ => uuid_arg(flag, value)?,
            };
            let message_id = request_id("message_id", params.message_id.as_deref())?;

            let mut args = vec![
                "message".to_owned(),
                "send".to_owned(),
                format!("--{flag}={value}"),
                format!("--message={}", params.message),
                format!("--message-id={message_id}"),
            ];
            if let Some(machine) = &params.machine {
                args.push(format!("--machine={machine}"));
            }
            let answer = self.run(&args, None, WRITE_TIMEOUT).await?;

            // the CLI echoes the id; this keeps the ack usable if it ever stops
            Ok(match answer {
                Value::Object(mut ack) => {
                    ack.entry("message_id").or_insert_with(|| json!(message_id));

                    Value::Object(ack)
                }
                other => json!({ "message_id": message_id, "output": other }),
            })
        };

        typed(outcome.await)
    }

    #[tool(
        description = "Push a notification to the owner's phone. Use `blocked` only when work \
                       cannot continue without them."
    )]
    async fn notify(
        &self,
        Parameters(params): Parameters<NotifyParams>,
    ) -> Result<Json<NotifyAck>, CallToolResult> {
        let Some(notifier) = self.0.notifier.clone() else {
            return typed(Err(AdapterError::Invalid(
                "no ntfy topic is configured for codemode-mcp or homebased".into(),
            )));
        };
        let (priority, tag) = match params.level {
            NotifyLevel::Blocked => (Priority::Urgent, "no_entry"),
            NotifyLevel::Important => (Priority::High, "warning"),
            NotifyLevel::Done => (Priority::Default, "white_check_mark"),
        };
        let notification = Notification {
            // marked so it cannot pass for an approval or admin request
            title: format!("agent: {}", params.title),
            message: params.body,
            click: None,
            priority,
            tag,
        };

        typed(
            notifier
                .notify(&notification)
                .await
                .map(|()| json!({ "ok": true }))
                .map_err(|error| AdapterError::Io(error.to_string())),
        )
    }
}

#[tool_handler]
impl ServerHandler for HomebasedAdapter {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::{PRIVATE_DIR_PREFIX, remove_stale_private_dirs_in};
    use std::{os::unix::fs::symlink, time::Duration};

    #[test]
    fn stale_cleanup_removes_only_matching_old_directories() -> std::io::Result<()> {
        let temp = std::env::temp_dir().join(format!("cleanup-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&temp)?;

        let hex = "0123456789abcdef0123456789abcdef";
        let stale = temp.join(format!("{PRIVATE_DIR_PREFIX}{hex}"));
        let short = temp.join(format!("{PRIVATE_DIR_PREFIX}abc"));
        let other = temp.join(format!("other-{hex}"));
        let target = temp.join("target");
        let link = temp.join(format!(
            "{PRIVATE_DIR_PREFIX}fedcba9876543210fedcba9876543210"
        ));
        for dir in [&stale, &short, &other, &target] {
            std::fs::create_dir(dir)?;
        }
        symlink(&target, &link)?;

        // too young to be a crash leftover: a live submit may own it
        assert_eq!(
            remove_stale_private_dirs_in(&temp, Duration::from_secs(3600)),
            0
        );
        assert!(stale.exists());

        assert_eq!(remove_stale_private_dirs_in(&temp, Duration::ZERO), 1);
        assert!(!stale.exists());
        assert!(short.exists() && other.exists() && target.exists());
        assert!(link.symlink_metadata().is_ok());

        std::fs::remove_dir_all(&temp)
    }
}
