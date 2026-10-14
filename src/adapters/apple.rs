//! Calendar and Reminders as MCP tools, through EventKit
//!
//! Two stdio adapters, `codemode-mcp adapter calendar` and `codemode-mcp
//! adapter reminders`, each asking macOS only for its own permission. The
//! adapters check arguments and the editing rules; a backend only reads and
//! writes, so the integration tests run the same rules against an in-memory
//! store while the shipped binary uses [`eventkit`]

pub mod calendar;
pub mod dates;
#[cfg(target_os = "macos")]
pub mod eventkit;
pub mod reminders;

use jiff::{Timestamp, tz::TimeZone};
use rmcp::{
    model::{CallToolResult, ContentBlock},
    schemars,
};
use serde::Serialize;

/// Which kind of item a store serves; each needs its own macOS permission
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entity {
    /// Calendar events
    Events,
    /// Reminders
    Reminders,
}

/// A failure reading or writing the store
#[derive(Debug, Clone, thiserror::Error)]
pub enum BackendError {
    /// macOS has not granted access; the text says what the owner must do
    #[error("{0}")]
    Access(String),
    /// No item or list has this id
    #[error("{0}")]
    NotFound(String),
    /// The arguments, or the item's state, rule the call out
    #[error("{0}")]
    Invalid(String),
    /// EventKit refused or failed
    #[error("{0}")]
    Failed(String),
}

/// How often a repeating item repeats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Frequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

/// A repeat rule as the store keeps it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecurrenceRecord {
    /// Unit of the repeat
    pub frequency: Frequency,
    /// Every this many units
    pub interval: u32,
    /// Last moment an occurrence may start
    pub until: Option<Timestamp>,
    /// Number of occurrences
    pub count: Option<u32>,
}

/// The first repeat rule; the days and positions a rule may also name are
/// left out
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Recurrence {
    pub frequency: Frequency,
    /// Every this many days, weeks, months or years
    pub interval: u32,
    /// No occurrence starts after this
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub until: Option<String>,
    /// Total number of occurrences
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "u32")]
    pub count: Option<u32>,
}

impl Recurrence {
    fn from_record(record: &RecurrenceRecord, zone: &TimeZone) -> Self {
        Self {
            frequency: record.frequency,
            interval: record.interval,
            until: record.until.map(|time| dates::format_time(time, zone)),
            count: record.count,
        }
    }
}

/// The tool's error text
fn failed(message: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.to_string())])
}

/// Runs a blocking store call off the async workers; EventKit answers from
/// its own thread, so a slow fetch must not hold a tokio worker
async fn blocking<T: Send + 'static>(
    call: impl FnOnce() -> Result<T, BackendError> + Send + 'static,
) -> Result<T, CallToolResult> {
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|error| failed(format!("the store call failed: {error}")))?
        .map_err(failed)
}

/// A stamp in the form agents send back
fn stamp(time: Option<Timestamp>) -> Option<String> {
    time.map(dates::format_stamp)
}

/// The refusal for an update or delete that read an older version
fn stale(kind: &str, current: Option<Timestamp>) -> BackendError {
    BackendError::Invalid(format!(
        "the {kind} changed since you read it (last_modified is now {}); read it again and \
         retry with the new last_modified",
        stamp(current).unwrap_or_else(|| "unset".into())
    ))
}
