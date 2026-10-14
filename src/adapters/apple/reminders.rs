//! MCP adapter for Reminders
//!
//! Lists, reminders, due dates, priorities, notes and URLs, which is what
//! EventKit exposes. Sections, tags, subtasks, flags and smart lists are not
//! in EventKit, so they are absent here. An update or delete must send back
//! the `last_modified` the agent read; completing does not, since marking a
//! reminder done twice is harmless

use std::sync::Arc;

use jiff::{Timestamp, tz::TimeZone};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{CallToolResult, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};

use super::{
    BackendError, Recurrence, RecurrenceRecord, blocking,
    calendar::merge,
    dates::{self, When},
    failed, stale, stamp,
};

/// Reminders `list_reminders` returns when no limit is given
const DEFAULT_LIMIT: usize = 200;
/// Most reminders one `list_reminders` call returns
const MAX_LIMIT: usize = 1000;
/// Characters of notes `list_reminders` keeps
const NOTES_PREVIEW_CHARS: usize = 200;

const INSTRUCTIONS: &str = "Read and change reminders in the Mac's Reminders app. Dates without \
     a time are all-day; times without an offset are the Mac's local time. update_reminder and \
     delete_reminder need the reminder's last_modified from list_reminders or get_reminder. Tags, \
     sections, subtasks and flags are not available.";

/// A reminder list as the store reports it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListInfo {
    /// Stable identifier
    pub id: String,
    /// Name shown in Reminders
    pub title: String,
    /// Account name, such as `iCloud`
    pub source: String,
    /// Whether reminders can be added or changed
    pub writable: bool,
    /// Whether new reminders go here by default
    pub is_default: bool,
}

/// How important a reminder is
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    None,
    High,
    Medium,
    Low,
}

impl Priority {
    /// From EventKit's 0-9 scale: 0 none, 1-4 high, 5 medium, 6-9 low
    pub fn from_level(level: usize) -> Self {
        match level {
            0 => Self::None,
            1..=4 => Self::High,
            5 => Self::Medium,
            _ => Self::Low,
        }
    }

    /// The level Reminders itself writes for each choice
    pub fn level(self) -> usize {
        match self {
            Self::None => 0,
            Self::High => 1,
            Self::Medium => 5,
            Self::Low => 9,
        }
    }
}

/// A reminder as the store reports it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReminderRecord {
    pub id: String,
    pub list_id: String,
    /// List name
    pub list: String,
    /// Whether the list accepts changes
    pub writable: bool,
    pub title: String,
    pub notes: Option<String>,
    pub url: Option<String>,
    pub due: Option<When>,
    pub priority: Priority,
    pub completed: bool,
    pub completed_at: Option<Timestamp>,
    pub recurrence: Option<RecurrenceRecord>,
    pub created: Option<Timestamp>,
    pub last_modified: Option<Timestamp>,
}

/// The fields `create_reminder` and `update_reminder` set; everything else
/// on an existing reminder is left as it is
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReminderDraft {
    pub list_id: String,
    pub title: String,
    pub notes: Option<String>,
    pub url: Option<String>,
    /// A due time also gets an alert at that time, as Reminders adds one
    pub due: Option<When>,
    pub priority: Priority,
}

/// Which reminders a fetch returns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReminderQuery {
    /// Not yet done; a bound limits them to reminders due in `[from, until)`
    Incomplete {
        from: Option<Timestamp>,
        until: Option<Timestamp>,
    },
    /// Done; a bound limits them to reminders completed in `[from, until)`
    Completed {
        from: Option<Timestamp>,
        until: Option<Timestamp>,
    },
    /// Everything
    All,
}

/// Reads and writes reminders; implementations block, and the adapter calls
/// them off the async workers
pub trait RemindersBackend: Send + Sync + 'static {
    /// Every reminder list
    fn lists(&self) -> Result<Vec<ListInfo>, BackendError>;

    /// Reminders matching `query`; `list_ids` limits the lists searched
    fn reminders(
        &self,
        query: ReminderQuery,
        list_ids: Option<&[String]>,
    ) -> Result<Vec<ReminderRecord>, BackendError>;

    /// One reminder by id
    fn reminder(&self, id: &str) -> Result<Option<ReminderRecord>, BackendError>;

    /// Creates a reminder, or rewrites the drafted fields of reminder `id`
    fn save_reminder(
        &self,
        id: Option<&str>,
        draft: ReminderDraft,
    ) -> Result<ReminderRecord, BackendError>;

    /// Marks reminder `id` done or not done
    fn set_completed(&self, id: &str, completed: bool) -> Result<ReminderRecord, BackendError>;

    /// Deletes reminder `id`
    fn remove_reminder(&self, id: &str) -> Result<(), BackendError>;
}

/// Which reminders `list_reminders` returns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum StatusFilter {
    #[default]
    Incomplete,
    Completed,
    All,
}

/// Arguments of `list_reminders`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListRemindersParams {
    /// Only these lists, by id from list_reminder_lists
    pub list_ids: Option<Vec<String>>,
    /// Default `incomplete`
    pub status: Option<StatusFilter>,
    /// Incomplete only: due on or after this date or time; reminders with no
    /// due date are left out once a bound is given
    pub due_from: Option<String>,
    /// Incomplete only: due on or before this date (whole day) or before
    /// this time
    pub due_until: Option<String>,
    /// Completed only: completed on or after this date or time
    pub completed_from: Option<String>,
    /// Completed only: completed on or before this date (whole day) or
    /// before this time
    pub completed_until: Option<String>,
    /// Most reminders returned (default 200, at most 1000)
    pub limit: Option<u32>,
}

/// Arguments that name one reminder
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReminderIdParams {
    /// Reminder id from list_reminders
    pub id: String,
}

/// Arguments of `create_reminder`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateReminderParams {
    pub title: String,
    /// List id from list_reminder_lists; the default list when omitted
    pub list_id: Option<String>,
    pub notes: Option<String>,
    /// A date, or a time, which also sets an alert at that time
    pub due: Option<String>,
    /// Default `none`
    pub priority: Option<Priority>,
    pub url: Option<String>,
}

/// A reminder field `update_reminder` can clear
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClearableReminderField {
    Due,
    Notes,
    Url,
}

/// Arguments of `update_reminder`; omitted fields stay as they are, and an
/// empty string clears a text field
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateReminderParams {
    /// Reminder id from list_reminders
    pub id: String,
    /// The reminder's last_modified as you read it
    pub last_modified: Option<String>,
    pub title: Option<String>,
    /// Move to this list
    pub list_id: Option<String>,
    pub notes: Option<String>,
    /// A date, or a time, which also sets an alert at that time
    pub due: Option<String>,
    pub priority: Option<Priority>,
    pub url: Option<String>,
    /// Fields to empty
    pub clear: Option<Vec<ClearableReminderField>>,
}

/// Arguments of `complete_reminder`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CompleteReminderParams {
    /// Reminder id from list_reminders
    pub id: String,
    /// `false` marks it not done again (default `true`)
    pub completed: Option<bool>,
}

/// Arguments of `delete_reminder`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteReminderParams {
    /// Reminder id from list_reminders
    pub id: String,
    /// The reminder's last_modified as you read it
    pub last_modified: Option<String>,
}

/// One reminder list
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct List {
    pub id: String,
    pub title: String,
    /// Account, such as `iCloud`
    pub source: String,
    /// Whether reminders can be added or changed
    pub writable: bool,
    /// Where create_reminder puts reminders when no list is given
    pub is_default: bool,
}

/// Result of `list_reminder_lists`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListList {
    pub lists: Vec<List>,
}

/// A reminder; list_reminders cuts `notes` to 200 characters and leaves out
/// the fields from `url` on, get_reminder fills them
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Reminder {
    pub id: String,
    pub list_id: String,
    /// List name
    pub list: String,
    pub title: String,
    pub completed: bool,
    pub priority: Priority,
    /// Repeats; completing it moves it to its next due date and keeps the
    /// finished occurrence as a separate completed reminder
    pub recurring: bool,
    /// Whether update_reminder and delete_reminder accept it
    pub editable: bool,
    /// `YYYY-MM-DD`, or local time with its offset
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub due: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub notes: Option<String>,
    /// Pass back unchanged to update_reminder and delete_reminder
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub last_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Recurrence")]
    pub recurrence: Option<Recurrence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub created: Option<String>,
}

impl Reminder {
    fn new(record: ReminderRecord, zone: &TimeZone, detail: bool) -> Self {
        let notes = if detail {
            record.notes
        } else {
            record.notes.map(|notes| preview(&notes))
        };

        Self {
            id: record.id,
            list_id: record.list_id,
            list: record.list,
            title: record.title,
            completed: record.completed,
            priority: record.priority,
            recurring: record.recurrence.is_some(),
            editable: record.writable,
            due: record.due.map(|due| due.format(zone)),
            completed_at: record
                .completed_at
                .map(|time| dates::format_time(time, zone)),
            notes,
            last_modified: stamp(record.last_modified),
            url: record.url.filter(|_| detail),
            recurrence: record
                .recurrence
                .filter(|_| detail)
                .map(|rule| Recurrence::from_record(&rule, zone)),
            created: record
                .created
                .filter(|_| detail)
                .map(|time| dates::format_time(time, zone)),
        }
    }
}

/// The first [`NOTES_PREVIEW_CHARS`] characters, marked when cut
fn preview(notes: &str) -> String {
    match notes.char_indices().nth(NOTES_PREVIEW_CHARS) {
        Some((cut, _)) => format!("{}…", &notes[..cut]),
        None => notes.to_owned(),
    }
}

/// Result of `list_reminders`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReminderList {
    /// Not done first, by due date (undated last); then done, latest first
    pub reminders: Vec<Reminder>,
    /// More matched than `limit`
    pub truncated: bool,
    /// IANA zone the times are given in
    pub time_zone: String,
}

/// Result of `delete_reminder`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Deleted {
    pub id: String,
}

/// The list to write to: `wanted`, else the default, refusing a read-only
/// one
fn target_list(
    backend: &dyn RemindersBackend,
    wanted: Option<&str>,
) -> Result<ListInfo, BackendError> {
    let lists = backend.lists()?;
    let found = match wanted {
        Some(id) => lists
            .into_iter()
            .find(|list| list.id == id)
            .ok_or_else(|| BackendError::NotFound(format!("no reminder list has id {id:?}")))?,
        None => lists
            .into_iter()
            .find(|list| list.is_default)
            .ok_or_else(|| {
                BackendError::Invalid("there is no default reminder list; pass `list_id`".into())
            })?,
    };
    if !found.writable {
        return Err(BackendError::Invalid(format!(
            "list {:?} is read-only",
            found.title
        )));
    }

    Ok(found)
}

/// The reminder `id`, refused when its list is read-only
fn writable_reminder(
    backend: &dyn RemindersBackend,
    id: &str,
) -> Result<ReminderRecord, BackendError> {
    let reminder = backend
        .reminder(id)?
        .ok_or_else(|| BackendError::NotFound(format!("no reminder has id {id:?}")))?;
    if !reminder.writable {
        return Err(BackendError::Invalid(format!(
            "list {:?} is read-only",
            reminder.list
        )));
    }

    Ok(reminder)
}

/// [`writable_reminder`], also refused unless the agent read its current
/// version
fn editable_reminder(
    backend: &dyn RemindersBackend,
    id: &str,
    last_modified: Option<&str>,
) -> Result<ReminderRecord, BackendError> {
    let reminder = writable_reminder(backend, id)?;
    if !dates::stamp_matches(last_modified, reminder.last_modified) {
        return Err(stale("reminder", reminder.last_modified));
    }

    Ok(reminder)
}

/// Optional text, with an empty string meaning none
fn text(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

/// Sort key: not done before done; not done by due date, undated last; done
/// by completion, latest first
fn order(reminder: &ReminderRecord, zone: &TimeZone) -> (bool, i64) {
    if reminder.completed {
        let completed = reminder
            .completed_at
            .map_or(0, |time| -time.as_millisecond());

        (true, completed)
    } else {
        let due = reminder
            .due
            .and_then(|due| due.start(zone).ok())
            .map_or(i64::MAX, Timestamp::as_millisecond);

        (false, due)
    }
}

struct Inner {
    backend: Arc<dyn RemindersBackend>,
    zone: TimeZone,
}

/// The stdio MCP server; cheap to clone
#[derive(Clone)]
pub struct RemindersAdapter(Arc<Inner>);

impl RemindersAdapter {
    /// An adapter over `backend`, reading and writing times in `zone`
    pub fn new(backend: Arc<dyn RemindersBackend>, zone: TimeZone) -> Self {
        Self(Arc::new(Inner { backend, zone }))
    }

    /// Serves MCP on stdin and stdout until the client disconnects
    pub async fn serve_stdio(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let service = self.serve(rmcp::transport::stdio()).await?;
        service.waiting().await?;

        Ok(())
    }

    fn parse(&self, field: &str, value: Option<&str>) -> Result<Option<When>, CallToolResult> {
        value
            .map(|text| When::parse(field, text, &self.0.zone))
            .transpose()
            .map_err(failed)
    }

    async fn call<T: Send + 'static>(
        &self,
        work: impl FnOnce(&dyn RemindersBackend, &TimeZone) -> Result<T, BackendError> + Send + 'static,
    ) -> Result<T, CallToolResult> {
        let inner = Arc::clone(&self.0);

        blocking(move || work(inner.backend.as_ref(), &inner.zone)).await
    }
}

#[tool_router]
impl RemindersAdapter {
    #[tool(description = "Every reminder list, with its account and whether it accepts changes.")]
    async fn list_reminder_lists(&self) -> Result<Json<ListList>, CallToolResult> {
        self.call(|backend, _| {
            let lists = backend
                .lists()?
                .into_iter()
                .map(|info| List {
                    id: info.id,
                    title: info.title,
                    source: info.source,
                    writable: info.writable,
                    is_default: info.is_default,
                })
                .collect();

            Ok(Json(ListList { lists }))
        })
        .await
    }

    #[tool(
        description = "Reminders, not done ones by default, sorted by due date. Filter by \
                          list, by due date (not done) or by completion date (done). Notes are \
                          cut to 200 characters; get_reminder has all of them."
    )]
    async fn list_reminders(
        &self,
        Parameters(params): Parameters<ListRemindersParams>,
    ) -> Result<Json<ReminderList>, CallToolResult> {
        let zone = &self.0.zone;
        let from = |field: &str, value: Option<&str>| {
            self.parse(field, value)?
                .map(|when| when.start(zone).map_err(failed))
                .transpose()
        };
        let until = |field: &str, value: Option<&str>| {
            self.parse(field, value)?
                .map(|when| when.end_exclusive(zone).map_err(failed))
                .transpose()
        };
        let status = params.status.unwrap_or_default();
        let due_given = params.due_from.is_some() || params.due_until.is_some();
        let completed_given = params.completed_from.is_some() || params.completed_until.is_some();
        let query = match status {
            StatusFilter::Incomplete if completed_given => {
                return Err(failed(
                    "`completed_from`/`completed_until` need status `completed`",
                ));
            }
            StatusFilter::Completed if due_given => {
                return Err(failed("`due_from`/`due_until` need status `incomplete`"));
            }
            StatusFilter::All if due_given || completed_given => {
                return Err(failed(
                    "date bounds need status `incomplete` or `completed`",
                ));
            }
            StatusFilter::Incomplete => ReminderQuery::Incomplete {
                from: from("due_from", params.due_from.as_deref())?,
                until: until("due_until", params.due_until.as_deref())?,
            },
            StatusFilter::Completed => ReminderQuery::Completed {
                from: from("completed_from", params.completed_from.as_deref())?,
                until: until("completed_until", params.completed_until.as_deref())?,
            },
            StatusFilter::All => ReminderQuery::All,
        };
        let limit = params
            .limit
            .map_or(DEFAULT_LIMIT, |limit| limit as usize)
            .clamp(1, MAX_LIMIT);

        self.call(move |backend, zone| {
            let mut reminders = backend.reminders(query, params.list_ids.as_deref())?;
            reminders.sort_by_cached_key(|reminder| order(reminder, zone));
            let truncated = reminders.len() > limit;
            reminders.truncate(limit);

            Ok(Json(ReminderList {
                reminders: reminders
                    .into_iter()
                    .map(|record| Reminder::new(record, zone, false))
                    .collect(),
                truncated,
                time_zone: zone.iana_name().unwrap_or("local").to_owned(),
            }))
        })
        .await
    }

    #[tool(description = "One reminder with its full notes, URL and repeat rule.")]
    async fn get_reminder(
        &self,
        Parameters(params): Parameters<ReminderIdParams>,
    ) -> Result<Json<Reminder>, CallToolResult> {
        self.call(move |backend, zone| {
            let record = backend.reminder(&params.id)?.ok_or_else(|| {
                BackendError::NotFound(format!("no reminder has id {:?}", params.id))
            })?;

            Ok(Json(Reminder::new(record, zone, true)))
        })
        .await
    }

    #[tool(
        description = "Add a reminder. A due time also sets an alert at that time; a due \
                          date alone does not. Returns the new reminder with its id."
    )]
    async fn create_reminder(
        &self,
        Parameters(params): Parameters<CreateReminderParams>,
    ) -> Result<Json<Reminder>, CallToolResult> {
        let due = self.parse("due", params.due.as_deref())?;

        self.call(move |backend, zone| {
            if params.title.trim().is_empty() {
                return Err(BackendError::Invalid("`title` is empty".into()));
            }
            let list = target_list(backend, params.list_id.as_deref())?;
            let draft = ReminderDraft {
                list_id: list.id,
                title: params.title,
                notes: text(params.notes),
                url: text(params.url),
                due,
                priority: params.priority.unwrap_or(Priority::None),
            };

            Ok(Json(Reminder::new(
                backend.save_reminder(None, draft)?,
                zone,
                true,
            )))
        })
        .await
    }

    #[tool(
        description = "Change a reminder; omitted fields stay, an empty string clears one. \
                          Pass the last_modified you \
                          read: if the reminder changed since, this fails and you must read it \
                          again. Use complete_reminder to mark it done."
    )]
    async fn update_reminder(
        &self,
        Parameters(params): Parameters<UpdateReminderParams>,
    ) -> Result<Json<Reminder>, CallToolResult> {
        let due = self.parse("due", params.due.as_deref())?;

        self.call(move |backend, zone| {
            let reminder = editable_reminder(backend, &params.id, params.last_modified.as_deref())?;
            let list_id = match params.list_id.as_deref() {
                Some(id) if id != reminder.list_id => target_list(backend, Some(id))?.id,
                _ => reminder.list_id.clone(),
            };
            let clear = params.clear.unwrap_or_default();
            let cleared = |field: ClearableReminderField| clear.contains(&field);
            let title = match params.title {
                Some(title) if title.trim().is_empty() => {
                    return Err(BackendError::Invalid("`title` is empty".into()));
                }
                Some(title) => title,
                None => reminder.title.clone(),
            };
            let draft = ReminderDraft {
                list_id,
                title,
                notes: if cleared(ClearableReminderField::Notes) {
                    None
                } else {
                    merge(params.notes, reminder.notes)
                },
                url: if cleared(ClearableReminderField::Url) {
                    None
                } else {
                    merge(params.url, reminder.url)
                },
                due: if cleared(ClearableReminderField::Due) {
                    None
                } else {
                    due.or(reminder.due)
                },
                priority: params.priority.unwrap_or(reminder.priority),
            };

            Ok(Json(Reminder::new(
                backend.save_reminder(Some(&reminder.id), draft)?,
                zone,
                true,
            )))
        })
        .await
    }

    #[tool(
        description = "Mark a reminder done, or not done with completed=false. A repeating \
                          reminder is returned still open with its next due date; the finished \
                          occurrence becomes a separate completed reminder with a new id."
    )]
    async fn complete_reminder(
        &self,
        Parameters(params): Parameters<CompleteReminderParams>,
    ) -> Result<Json<Reminder>, CallToolResult> {
        self.call(move |backend, zone| {
            let reminder = writable_reminder(backend, &params.id)?;
            let record = backend.set_completed(&reminder.id, params.completed.unwrap_or(true))?;

            Ok(Json(Reminder::new(record, zone, true)))
        })
        .await
    }

    #[tool(
        description = "Delete a reminder, all of its repeats included. Pass the \
                          last_modified you read: if the reminder changed since, this fails."
    )]
    async fn delete_reminder(
        &self,
        Parameters(params): Parameters<DeleteReminderParams>,
    ) -> Result<Json<Deleted>, CallToolResult> {
        self.call(move |backend, _| {
            let reminder = editable_reminder(backend, &params.id, params.last_modified.as_deref())?;
            backend.remove_reminder(&reminder.id)?;

            Ok(Json(Deleted { id: reminder.id }))
        })
        .await
    }
}

#[tool_handler]
impl ServerHandler for RemindersAdapter {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_cut_on_character_boundaries() {
        let long = "é".repeat(NOTES_PREVIEW_CHARS + 5);
        let cut = preview(&long);

        assert_eq!(cut.chars().count(), NOTES_PREVIEW_CHARS + 1);
        assert!(cut.ends_with('…'));
        assert_eq!(preview("short"), "short");
    }
}
