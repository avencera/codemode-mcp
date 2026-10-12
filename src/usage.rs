//! Usage log: one row per agent-facing call, execution and upstream call
//!
//! Records travel through a bounded channel to a writer thread, so logging
//! never blocks or fails an agent call; when the channel is full the record
//! is dropped and counted

pub mod report;

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel},
    },
    time::{Duration, Instant},
};

use rusqlite::{Connection, params};
use serde::Serialize;
use tokio::sync::oneshot;

use crate::store::{self, StoreError, now_ms};

/// Records buffered before new ones are dropped
const CHANNEL_CAPACITY: usize = 4096;
/// Records written per transaction at most
const BATCH: usize = 256;
/// How often the writer purges records past retention
const PURGE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// Longest normalized message kept in a fingerprint
const FINGERPRINT_CHARS: usize = 200;

/// How an agent-facing call, execution or upstream call ended
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Succeeded
    Ok,
    /// The type checker rejected the script
    TypeError,
    /// The script used Python Monty does not support
    UnsupportedSyntax,
    /// The script used an unknown tool or name
    NameError,
    /// The script imported a module that does not exist in the sandbox
    ImportError,
    /// The script raised an exception of its own
    RuntimeError,
    /// An upstream tool failed and the script did not handle it
    ToolError,
    /// A time limit ended the call or execution
    Timeout,
    /// Policy or a person refused a tool call
    Denied,
    /// Still running when the call returned
    Pending,
    /// No sandbox capacity was available
    Busy,
}

impl Outcome {
    /// Name stored in the database
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::TypeError => "type_error",
            Self::UnsupportedSyntax => "unsupported_syntax",
            Self::NameError => "name_error",
            Self::ImportError => "import_error",
            Self::RuntimeError => "runtime_error",
            Self::ToolError => "tool_error",
            Self::Timeout => "timeout",
            Self::Denied => "denied",
            Self::Pending => "pending",
            Self::Busy => "busy",
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An outcome with the detail worth keeping, already redacted for
/// sensitive servers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// Taxonomy bucket
    pub outcome: Outcome,
    /// Rule codes, exception type and message, or tool name
    pub detail: Option<String>,
}

impl Classification {
    /// A success
    pub fn ok() -> Self {
        Self {
            outcome: Outcome::Ok,
            detail: None,
        }
    }

    /// An outcome with detail text
    pub fn new(outcome: Outcome, detail: impl Into<String>) -> Self {
        Self {
            outcome,
            detail: Some(detail.into()),
        }
    }

    /// Groups identical mistakes: the outcome plus the detail with line
    /// numbers, literals and ids stripped; none for successes and pending
    pub fn fingerprint(&self) -> Option<String> {
        if matches!(self.outcome, Outcome::Ok | Outcome::Pending) {
            return None;
        }

        Some(match &self.detail {
            Some(detail) => format!("{}: {}", self.outcome, normalize(detail)),
            None => self.outcome.to_string(),
        })
    }
}

/// Strips what varies between otherwise identical errors: positions,
/// quoted literals, numbers and hex ids
pub fn normalize(message: &str) -> String {
    let mut out = String::with_capacity(message.len().min(FINGERPRINT_CHARS * 2));
    let mut chars = message.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' | '\'' => {
                // a quoted literal collapses to an empty pair of the same quote
                let mut closed = false;
                for next in chars.by_ref() {
                    if next == character {
                        closed = true;
                        break;
                    }
                }
                out.push(character);
                if closed {
                    out.push(character);
                }
            }
            character if character.is_ascii_alphanumeric() || character == '_' => {
                let mut word = String::from(character);
                while let Some(&next) = chars.peek() {
                    if next.is_ascii_alphanumeric() || next == '_' || next == '-' {
                        word.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push_str(&normalize_word(&word));
            }
            character if character.is_whitespace() => {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            character => out.push(character),
        }
    }

    let trimmed = out.trim();
    if trimmed.chars().count() > FINGERPRINT_CHARS {
        return trimmed.chars().take(FINGERPRINT_CHARS).collect();
    }

    trimmed.to_owned()
}

fn normalize_word(word: &str) -> String {
    let digits = word.chars().filter(char::is_ascii_digit).count();
    let hex = word
        .chars()
        .all(|character| character.is_ascii_hexdigit() || character == '-');
    if digits == word.len() {
        return "N".to_owned();
    }
    // ids: long hex runs and uuids, which always contain digits
    if hex && digits > 0 && word.len() >= 8 {
        return "<id>".to_owned();
    }

    word.to_owned()
}

/// Client name recorded for scripts run with `codemode-mcp exec`
pub const EXEC_CLIENT: &str = "codemode-mcp exec";

/// Who made an agent-facing call
#[derive(Debug, Clone, Default)]
pub struct Caller {
    /// MCP session id (`Mcp-Session-Id`); `None` for session-less callers
    pub session: Option<String>,
    /// Client name from the request `_meta`, the `initialize` request or the
    /// `user-agent` header
    pub client_name: Option<String>,
    /// Client version, from the same place as the name
    pub client_version: Option<String>,
    /// Human-readable client name when the client sent one; shown on the
    /// approval page and not logged
    pub client_title: Option<String>,
    /// Whether the request came straight from a process on this machine
    /// (loopback peer, no proxy headers); only such callers may hold client
    /// grants, because the client name is self-asserted
    pub local: bool,
}

impl Caller {
    /// Client name for display, `unknown` when the client sent none
    pub fn client_label(&self) -> &str {
        self.client_name.as_deref().unwrap_or("unknown")
    }

    /// Client title for display, falling back to the client name
    pub fn client_display(&self) -> &str {
        self.client_title
            .as_deref()
            .unwrap_or_else(|| self.client_label())
    }
}

/// One agent-facing tool call
#[derive(Debug, Clone)]
pub struct CallRecord {
    /// Who called
    pub caller: Caller,
    /// `search_tools`, `describe_tools`, `execute` or `wait`
    pub tool: &'static str,
    /// Query, described names (JSON) or script
    pub input: Option<String>,
    /// How it ended
    pub classification: Classification,
    /// Time spent answering
    pub duration: Duration,
    /// Size of the text returned
    pub result_bytes: usize,
    /// Execution the call started or waited on
    pub execution_id: Option<String>,
}

/// One finished execution
#[derive(Debug, Clone)]
pub struct ExecutionRecord {
    /// Execution id
    pub id: String,
    /// Start time, ms since the epoch
    pub started_ms: i64,
    /// Who started it
    pub caller: Caller,
    /// The script
    pub script: String,
    /// How it ended
    pub classification: Classification,
    /// Start to finish, including approval waits
    pub duration: Duration,
    /// Size of the rendered result
    pub result_bytes: usize,
}

/// One upstream tool call made by a script
#[derive(Debug, Clone)]
pub struct UpstreamRecord {
    /// Execution that made it
    pub execution_id: Option<String>,
    /// Server name
    pub server: String,
    /// Upstream tool name
    pub tool: String,
    /// Python name the script called
    pub function: String,
    /// Arguments as JSON; `None` for sensitive servers
    pub arguments: Option<String>,
    /// How it ended; detail is `None` for sensitive servers
    pub classification: Classification,
    /// Time the upstream took
    pub duration: Duration,
    /// Approval or grant that allowed the call
    pub approval_id: Option<String>,
}

/// A change to an approval request
#[derive(Debug, Clone)]
pub enum ApprovalRecord {
    /// A request was created and a notification sent
    Created {
        /// Approval id
        id: String,
        /// Who asked
        caller: Caller,
        /// Execution waiting on it
        execution_id: String,
        /// Server name
        server: String,
        /// Upstream tool name
        tool: String,
        /// `session` or `per_call`
        grant_mode: &'static str,
    },
    /// A request was answered or ran out of time
    Decided {
        /// Approval id
        id: String,
        /// `approved`, `denied`, `expired` or `abandoned`
        decision: &'static str,
        /// Session grant length when one was given
        grant_minutes: Option<i64>,
    },
}

enum Event {
    Call(CallRecord),
    Execution(ExecutionRecord),
    Upstream(UpstreamRecord),
    Approval(ApprovalRecord),
    Flush(oneshot::Sender<()>),
}

struct Shared {
    sender: SyncSender<Event>,
    dropped: AtomicU64,
}

/// Handle for recording usage; cheap to clone
#[derive(Clone)]
pub struct UsageLog(Arc<Shared>);

impl UsageLog {
    /// Opens the database in `directory`, purges records older than
    /// `retention` and starts the writer thread
    pub fn start(directory: &Path, retention: Duration) -> Result<Self, StoreError> {
        let connection = store::open(directory)?;
        let (sender, receiver) = sync_channel(CHANNEL_CAPACITY);
        let writer = Writer {
            connection,
            retention,
            last_purge: None,
        };
        std::thread::Builder::new()
            .name("codemode-usage".to_owned())
            .spawn(move || writer.run(receiver))
            .map_err(|source| StoreError::Directory {
                path: directory.to_owned(),
                source,
            })?;

        Ok(Self(Arc::new(Shared {
            sender,
            dropped: AtomicU64::new(0),
        })))
    }

    /// Records an agent-facing call
    pub fn call(&self, record: CallRecord) {
        self.send(Event::Call(record));
    }

    /// Records a finished execution
    pub fn execution(&self, record: ExecutionRecord) {
        self.send(Event::Execution(record));
    }

    /// Records an upstream call
    pub fn upstream(&self, record: UpstreamRecord) {
        self.send(Event::Upstream(record));
    }

    /// Records an approval change
    pub fn approval(&self, record: ApprovalRecord) {
        self.send(Event::Approval(record));
    }

    /// Records dropped because the writer fell behind
    pub fn dropped(&self) -> u64 {
        self.0.dropped.load(Ordering::Relaxed)
    }

    /// Waits until everything sent so far is written
    pub async fn flush(&self) {
        let (done, written) = oneshot::channel();
        let sender = self.0.sender.clone();
        // a full channel is the one case `send` blocks, so keep it off the runtime
        let queued =
            tokio::task::spawn_blocking(move || sender.send(Event::Flush(done)).is_ok()).await;
        if matches!(queued, Ok(true)) {
            let _ = written.await;
        }
    }

    fn send(&self, event: Event) {
        match self.0.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                let dropped = self.0.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped.is_power_of_two() {
                    tracing::warn!(dropped, "usage log is behind; dropping records");
                }
            }
        }
    }
}

struct Writer {
    connection: Connection,
    retention: Duration,
    last_purge: Option<Instant>,
}

impl Writer {
    fn run(mut self, receiver: Receiver<Event>) {
        self.purge_if_due();
        loop {
            let first = match receiver.recv_timeout(Duration::from_secs(60 * 60)) {
                Ok(event) => event,
                Err(RecvTimeoutError::Timeout) => {
                    self.purge_if_due();
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => return,
            };
            let mut batch = vec![first];
            while batch.len() < BATCH {
                match receiver.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }

            let mut flushes = Vec::new();
            if let Err(error) = self.write(batch, &mut flushes) {
                tracing::warn!(%error, "failed to write a batch of usage records");
            }
            for flush in flushes {
                let _ = flush.send(());
            }
            self.purge_if_due();
        }
    }

    fn write(
        &mut self,
        batch: Vec<Event>,
        flushes: &mut Vec<oneshot::Sender<()>>,
    ) -> Result<(), rusqlite::Error> {
        let transaction = self.connection.transaction()?;
        for event in batch {
            // a failed statement leaves the transaction usable, so one bad
            // record costs only itself
            let written = match event {
                Event::Call(record) => insert_call(&transaction, &record),
                Event::Execution(record) => insert_execution(&transaction, &record),
                Event::Upstream(record) => insert_upstream(&transaction, &record),
                Event::Approval(record) => write_approval(&transaction, &record),
                Event::Flush(done) => {
                    flushes.push(done);

                    Ok(())
                }
            };
            if let Err(error) = written {
                tracing::warn!(%error, "dropping a usage record that failed to write");
            }
        }

        transaction.commit()
    }

    fn purge_if_due(&mut self) {
        if self
            .last_purge
            .is_some_and(|last| last.elapsed() < PURGE_EVERY)
        {
            return;
        }
        self.last_purge = Some(Instant::now());
        let cutoff = now_ms().saturating_sub(self.retention.as_millis() as i64);
        if let Err(error) = purge(&self.connection, cutoff) {
            tracing::warn!(%error, "failed to purge old usage records");
        }
    }
}

/// Deletes usage records older than `cutoff_ms`; passkeys are kept
pub fn purge(connection: &Connection, cutoff_ms: i64) -> Result<(), rusqlite::Error> {
    connection.execute("DELETE FROM calls WHERE at_ms < ?1", params![cutoff_ms])?;
    connection.execute(
        "DELETE FROM executions WHERE started_ms < ?1",
        params![cutoff_ms],
    )?;
    connection.execute(
        "DELETE FROM upstream_calls WHERE at_ms < ?1",
        params![cutoff_ms],
    )?;
    connection.execute(
        "DELETE FROM approvals WHERE created_ms < ?1",
        params![cutoff_ms],
    )?;

    Ok(())
}

fn millis(duration: Duration) -> i64 {
    duration.as_millis().min(i64::MAX as u128) as i64
}

fn insert_call(connection: &Connection, record: &CallRecord) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO calls (at_ms, session, client_name, client_version, tool, input, outcome, \
         detail, fingerprint, duration_ms, result_bytes, execution_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            now_ms() - millis(record.duration),
            record.caller.session,
            record.caller.client_name,
            record.caller.client_version,
            record.tool,
            record.input,
            record.classification.outcome.as_str(),
            record.classification.detail,
            record.classification.fingerprint(),
            millis(record.duration),
            record.result_bytes as i64,
            record.execution_id,
        ],
    )?;

    Ok(())
}

fn insert_execution(
    connection: &Connection,
    record: &ExecutionRecord,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT OR REPLACE INTO executions (id, started_ms, finished_ms, session, client_name, \
         script, outcome, detail, fingerprint, duration_ms, result_bytes) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            record.id,
            record.started_ms,
            record.started_ms + millis(record.duration),
            record.caller.session,
            record.caller.client_name,
            record.script,
            record.classification.outcome.as_str(),
            record.classification.detail,
            record.classification.fingerprint(),
            millis(record.duration),
            record.result_bytes as i64,
        ],
    )?;

    Ok(())
}

fn insert_upstream(
    connection: &Connection,
    record: &UpstreamRecord,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO upstream_calls (at_ms, execution_id, server, tool, function, arguments, \
         outcome, detail, duration_ms, approval_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            now_ms() - millis(record.duration),
            record.execution_id,
            record.server,
            record.tool,
            record.function,
            record.arguments,
            record.classification.outcome.as_str(),
            record.classification.detail,
            millis(record.duration),
            record.approval_id,
        ],
    )?;

    Ok(())
}

fn write_approval(connection: &Connection, record: &ApprovalRecord) -> Result<(), rusqlite::Error> {
    match record {
        ApprovalRecord::Created {
            id,
            caller,
            execution_id,
            server,
            tool,
            grant_mode,
        } => connection.execute(
            "INSERT OR IGNORE INTO approvals (id, created_ms, session, client_name, \
             execution_id, server, tool, grant_mode) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                now_ms(),
                caller.session,
                caller.client_name,
                execution_id,
                server,
                tool,
                grant_mode
            ],
        )?,
        ApprovalRecord::Decided {
            id,
            decision,
            grant_minutes,
        } => connection.execute(
            "UPDATE approvals SET decided_ms = ?1, decision = ?2, grant_minutes = ?3 \
             WHERE id = ?4 AND decision IS NULL",
            params![now_ms(), decision, grant_minutes, id],
        )?,
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_ignore_positions_literals_and_ids() {
        let first = Classification::new(
            Outcome::RuntimeError,
            "KeyError: 'alpha' at line 12 (id 3f2a9c1e-77aa-4b1c-9d00-aa11bb22cc33)",
        );
        let second = Classification::new(
            Outcome::RuntimeError,
            "KeyError: 'beta' at line 7 (id 0b1c2d3e-0000-4000-8000-123456789abc)",
        );
        let other = Classification::new(Outcome::RuntimeError, "ValueError: 'alpha'");

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_ne!(first.fingerprint(), other.fingerprint());
        assert_eq!(
            first.fingerprint().as_deref(),
            Some("runtime_error: KeyError: '' at line N (id <id>)")
        );
        assert_eq!(Classification::ok().fingerprint(), None);
    }
}
