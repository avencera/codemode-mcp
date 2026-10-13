//! Result shapes of the homebased tools
//!
//! Each mirrors what `homebased --json` prints, cut down to the fields an
//! agent acts on: anything not listed is dropped, which also keeps a large
//! `task_list` small. A field homebased leaves out for some tasks is optional
//! and never `null`, so the stubs type it `NotRequired[T]` rather than
//! `NotRequired[T | None]`
//!
//! Doc comments become docstrings in the stubs every client reads, so they
//! say only what a field name does not

use rmcp::schemars;
use serde::{Deserialize, Serialize};

/// Where a task is in its life
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Held,
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Lost,
    Preempted,
}

impl TaskStatus {
    /// Name the CLI takes in `--status`
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Lost => "lost",
            Self::Preempted => "preempted",
        }
    }
}

/// Agent CLIs homebased can run
#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    /// `codex exec`
    Codex,
    /// `claude -p`
    Claude,
    /// `grok`
    Grok,
    /// `opencode run`
    Opencode,
}

// output-only enums take unknown values as `unknown`, so a new homebased
// value degrades one field instead of failing the whole tool; `TaskStatus`
// and `Agent` stay closed because they are also inputs
#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SocketState {
    Up,
    Down,
    /// A value this build does not know yet
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WorkloadKind {
    Agent,
    Task,
    Container,
    /// A value this build does not know yet
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExitKind {
    Exit,
    Signal,
    Cancelled,
    SpawnFailed,
    /// A value this build does not know yet
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityState {
    Reachable,
    Offline,
    /// A value this build does not know yet
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityState {
    Compatible,
    Incompatible,
    /// A value this build does not know yet
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Pending,
    Delivered,
    /// A value this build does not know yet
    #[serde(other)]
    Unknown,
}

/// Result of `daemon_status`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DaemonStatus {
    pub socket: SocketState,
    /// Tasks queued or running
    pub in_flight: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub web: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Workload {
    #[serde(rename = "type")]
    pub kind: WorkloadKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Agent")]
    pub agent: Option<Agent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub model: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExitReason {
    pub kind: ExitKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "i32")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "i32")]
    pub signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub message: Option<String>,
}

/// One task of `task_list`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TaskSummary {
    /// Full UUID
    pub id: String,
    pub name: String,
    pub status: TaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Workload")]
    pub workload: Option<Workload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "ExitReason")]
    pub exit_reason: Option<ExitReason>,
}

/// Result of `task_list`, oldest first
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TaskList {
    pub tasks: Vec<TaskSummary>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Report {
    pub seq: u32,
    pub outcome: String,
    pub summary: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct LastEvent {
    /// For example `TASK_SUCCEEDED`
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub next_action: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Dependency {
    pub task: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub outcome: Option<String>,
}

/// Result of `task_show`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TaskDetail {
    pub id: String,
    pub name: String,
    pub status: TaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "ExitReason")]
    pub exit_reason: Option<ExitReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "LastEvent")]
    pub last_event: Option<LastEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Vec<Dependency>")]
    pub after: Option<Vec<Dependency>>,
    /// File holding the worker's output
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub output_log: Option<String>,
    #[serde(default)]
    pub reports: Vec<Report>,
}

/// Result of `task_log`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TaskLog {
    pub id: String,
    pub log: String,
    /// Older output was cut off
    #[serde(default)]
    pub truncated: bool,
}

/// Tokens and cost of a group of tasks
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct UsageRow {
    /// Model, day or thread; absent on the totals
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub key: Option<String>,
    pub tasks: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_usd: f64,
}

/// Result of `task_usage`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TaskUsage {
    pub since: String,
    pub totals: UsageRow,
    pub by_day: Vec<UsageRow>,
    pub by_model: Vec<UsageRow>,
    pub by_thread: Vec<UsageRow>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Reachability {
    pub state: ReachabilityState,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Compatibility {
    /// `incompatible` machines refuse remote operations
    pub state: CompatibilityState,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Machine {
    /// UUID, usable as `machine` when submitting
    pub machine: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Reachability")]
    pub reachability: Option<Reachability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Compatibility")]
    pub compatibility: Option<Compatibility>,
}

/// Result of `fleet_machines`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct FleetMachines {
    /// This machine, which has no reachability
    pub local: Machine,
    pub machines: Vec<Machine>,
}

/// Result of `task_submit_agent`, `task_submit_command` and `task_followup`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SubmitAck {
    /// Pass it again to retry without starting a second task
    pub request_id: String,
    /// Validation only: nothing started, and there is no `id`
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "TaskStatus")]
    pub status: Option<TaskStatus>,
    /// What a dry run would execute
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Vec<String>")]
    pub argv: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Delivery {
    pub state: DeliveryState,
}

/// Result of `task_cancel`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CancelAck {
    pub id: String,
    /// Final status, when no delivery was needed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "TaskStatus")]
    pub status: Option<TaskStatus>,
    /// Set when the cancellation goes to another machine
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Delivery")]
    pub delivery: Option<Delivery>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Receipt {
    pub delivered_at: String,
}

/// Result of `message_send`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MessageAck {
    /// Pass it again to retry without a duplicate
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub destination_machine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub destination_thread: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Receipt")]
    pub receipt: Option<Receipt>,
}

/// Result of `notify`
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct NotifyAck {
    pub ok: bool,
}
