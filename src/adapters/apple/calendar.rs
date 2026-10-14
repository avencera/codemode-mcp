//! MCP adapter for Calendar
//!
//! Reads every calendar macOS Calendar shows: iCloud, Google, Exchange,
//! subscribed and birthdays. A repeating event is changed one occurrence at a
//! time, or from one occurrence on, never as a whole by accident: its
//! updates and deletes must name the `occurrence`. An update or delete must
//! send back the `last_modified` the agent read, so a change made since then
//! fails instead of being overwritten

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
    dates::{self, When},
    stale, stamp,
};

/// Longest window `list_events` reads; EventKit quietly cuts a longer one
const MAX_WINDOW_DAYS: i64 = 4 * 365;

const INSTRUCTIONS: &str = "Read and change events in the Mac's Calendar app, across its iCloud, \
     Google and Exchange accounts. Times without an offset are the Mac's local time. \
     update_event and delete_event need the event's last_modified from list_events or \
     get_event, and for a repeating event its `occurrence`.";

/// A calendar as the store reports it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarInfo {
    /// Stable identifier
    pub id: String,
    /// Name shown in Calendar
    pub title: String,
    /// Account name, such as `iCloud` or a Google account
    pub source: String,
    /// Whether events can be added or changed
    pub writable: bool,
    /// Whether new events go here by default
    pub is_default: bool,
}

/// Whether an event will happen
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EventStatus {
    None,
    Confirmed,
    Tentative,
    Canceled,
}

/// How the event shows on free/busy lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Busy,
    Free,
    Tentative,
    Unavailable,
    NotSupported,
}

/// An invitee's answer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantStatus {
    Unknown,
    Pending,
    Accepted,
    Declined,
    Tentative,
    Delegated,
    Completed,
    InProcess,
}

/// An organizer or attendee
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Person {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub email: Option<String>,
    pub status: ParticipantStatus,
    /// Whether this is the Mac's owner
    pub is_me: bool,
}

/// An event, or one occurrence of a repeating event, as the store reports it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    /// Identifier shared by every occurrence of a repeating event
    pub id: String,
    pub calendar_id: String,
    /// Calendar name
    pub calendar: String,
    /// Whether the calendar accepts changes
    pub writable: bool,
    pub title: String,
    pub start: Timestamp,
    /// For an all-day event, a moment on its last day
    pub end: Timestamp,
    pub all_day: bool,
    pub location: Option<String>,
    pub notes: Option<String>,
    pub url: Option<String>,
    /// IANA name; none for all-day and floating events
    pub time_zone: Option<String>,
    pub status: EventStatus,
    pub availability: Availability,
    pub organizer: Option<Person>,
    pub attendees: Vec<Person>,
    pub recurrence: Option<RecurrenceRecord>,
    /// An occurrence of a repeating event that was changed on its own
    pub detached: bool,
    /// For a repeating event, the start this occurrence had in the series
    /// before any change; it names the occurrence
    pub occurrence: Option<Timestamp>,
    pub created: Option<Timestamp>,
    pub last_modified: Option<Timestamp>,
}

impl EventRecord {
    /// Part of a repeating series
    fn recurring(&self) -> bool {
        self.recurrence.is_some() || self.detached
    }
}

/// The fields `update_event` and `create_event` set; everything else on an
/// existing event is left as it is
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDraft {
    pub calendar_id: String,
    pub title: String,
    pub start: Timestamp,
    /// For an all-day event, 23:59:59 on its last day
    pub end: Timestamp,
    pub all_day: bool,
    pub location: Option<String>,
    pub notes: Option<String>,
    pub url: Option<String>,
}

/// How far a change to a repeating event reaches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Span {
    /// Only the named occurrence, or a one-off event
    This,
    /// The named occurrence and every later one
    Future,
}

/// The event or occurrence a change applies to
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventTarget {
    pub id: String,
    /// Names the occurrence of a repeating event; none for a one-off event
    pub occurrence: Option<Timestamp>,
    pub span: Span,
}

/// Reads and writes events; implementations block, and the adapter calls
/// them off the async workers
pub trait CalendarBackend: Send + Sync + 'static {
    /// Every event calendar
    fn calendars(&self) -> Result<Vec<CalendarInfo>, BackendError>;

    /// Events overlapping `[start, end)`, repeating ones expanded into
    /// occurrences; `calendar_ids` limits the calendars searched
    fn events(
        &self,
        start: Timestamp,
        end: Timestamp,
        calendar_ids: Option<&[String]>,
    ) -> Result<Vec<EventRecord>, BackendError>;

    /// One event by id: the occurrence named by `occurrence`, else a one-off
    /// event or a repeating event's first occurrence
    fn event(
        &self,
        id: &str,
        occurrence: Option<Timestamp>,
    ) -> Result<Option<EventRecord>, BackendError>;

    /// Creates an event, or rewrites the drafted fields of `target`
    fn save_event(
        &self,
        target: Option<&EventTarget>,
        draft: EventDraft,
    ) -> Result<EventRecord, BackendError>;

    /// Deletes `target`
    fn remove_event(&self, target: &EventTarget) -> Result<(), BackendError>;
}

/// Arguments of `list_events`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListEventsParams {
    /// Window start: a date (its midnight) or a time
    pub start: String,
    /// Window end: a date (the whole day is included) or a time (excluded)
    pub end: String,
    /// Only these calendars, by id from list_calendars
    pub calendar_ids: Option<Vec<String>>,
}

/// Arguments that name one event
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EventIdParams {
    /// Event id from list_events
    pub id: String,
    /// A repeating event's `occurrence` from list_events; its first
    /// occurrence when omitted
    pub occurrence: Option<String>,
}

/// Arguments of `create_event`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateEventParams {
    pub title: String,
    /// A date for an all-day event, else a time
    pub start: String,
    /// The last day for an all-day event (inclusive), else the end time;
    /// the same form as `start`
    pub end: String,
    /// Calendar id from list_calendars; the default calendar when omitted
    pub calendar_id: Option<String>,
    pub location: Option<String>,
    pub notes: Option<String>,
    pub url: Option<String>,
}

/// An event field `update_event` can clear
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClearableEventField {
    Location,
    Notes,
    Url,
}

/// Arguments of `update_event`; omitted fields stay as they are, and an
/// empty string clears a text field
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateEventParams {
    /// Event id from list_events
    pub id: String,
    /// The event's last_modified as you read it
    pub last_modified: Option<String>,
    /// Required for a repeating event: the `occurrence` from list_events
    pub occurrence: Option<String>,
    /// With `occurrence`: also change every later occurrence
    pub and_future: Option<bool>,
    pub title: Option<String>,
    /// A date for an all-day event, else a time; to switch between all-day
    /// and timed, pass both `start` and `end`
    pub start: Option<String>,
    /// The last day for an all-day event (inclusive), else the end time
    pub end: Option<String>,
    /// Move to this calendar; not for a repeating event
    pub calendar_id: Option<String>,
    pub location: Option<String>,
    pub notes: Option<String>,
    pub url: Option<String>,
    /// Fields to empty
    pub clear: Option<Vec<ClearableEventField>>,
}

/// Arguments of `delete_event`
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteEventParams {
    /// Event id from list_events
    pub id: String,
    /// The event's last_modified as you read it
    pub last_modified: Option<String>,
    /// Required for a repeating event: the `occurrence` from list_events
    pub occurrence: Option<String>,
    /// With `occurrence`: also delete every later occurrence
    pub and_future: Option<bool>,
}

/// One calendar
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Calendar {
    pub id: String,
    pub title: String,
    /// Account, such as `iCloud`
    pub source: String,
    /// Whether events can be added or changed
    pub writable: bool,
    /// Where create_event puts events when no calendar is given
    pub is_default: bool,
}

/// Result of `list_calendars`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CalendarList {
    pub calendars: Vec<Calendar>,
}

/// An event; list_events leaves out the fields from `notes` on, get_event
/// fills them
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Event {
    /// Shared by every occurrence of a repeating event
    pub id: String,
    pub calendar_id: String,
    /// Calendar name
    pub calendar: String,
    pub title: String,
    /// `YYYY-MM-DD` for an all-day event, else local time with its offset
    pub start: String,
    /// The last day (inclusive) for an all-day event, else the end time
    pub end: String,
    pub all_day: bool,
    pub status: EventStatus,
    /// Part of a repeating series; changes need `occurrence`
    pub recurring: bool,
    /// Whether update_event and delete_event accept it
    pub editable: bool,
    /// For a repeating event, names this occurrence: pass it to get_event,
    /// update_event and delete_event
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub occurrence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub location: Option<String>,
    /// Pass back unchanged to update_event and delete_event
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub last_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub url: Option<String>,
    /// The event's own IANA time zone, when it has one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub time_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Availability")]
    pub availability: Option<Availability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Person")]
    pub organizer: Option<Person>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Vec<Person>")]
    pub attendees: Option<Vec<Person>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Recurrence")]
    pub recurrence: Option<Recurrence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub created: Option<String>,
}

impl Event {
    fn new(record: EventRecord, zone: &TimeZone, detail: bool) -> Self {
        let (start, end) = if record.all_day {
            (
                dates::day_of(record.start, zone).to_string(),
                // an all-day event ends at 23:59:59 or at the next midnight
                // depending on the account; both end on the same day
                dates::day_of(dates::just_before(record.end).max(record.start), zone).to_string(),
            )
        } else {
            (
                dates::format_time(record.start, zone),
                dates::format_time(record.end, zone),
            )
        };
        let recurring = record.recurring();
        let occurrence = record.occurrence.filter(|_| recurring).map(|time| {
            if record.all_day {
                dates::day_of(time, zone).to_string()
            } else {
                dates::format_time(time, zone)
            }
        });

        Self {
            editable: record.writable,
            recurring,
            occurrence,
            id: record.id,
            calendar_id: record.calendar_id,
            calendar: record.calendar,
            title: record.title,
            start,
            end,
            all_day: record.all_day,
            status: record.status,
            location: record.location,
            last_modified: stamp(record.last_modified),
            notes: record.notes.filter(|_| detail),
            url: record.url.filter(|_| detail),
            time_zone: record.time_zone.filter(|_| detail),
            availability: detail.then_some(record.availability),
            organizer: record.organizer.filter(|_| detail),
            attendees: (detail && !record.attendees.is_empty()).then_some(record.attendees),
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

/// Result of `list_events`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct EventList {
    /// Sorted by start
    pub events: Vec<Event>,
    /// IANA zone the times are given in
    pub time_zone: String,
}

/// Result of `delete_event`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Deleted {
    pub id: String,
    /// The occurrence deleted, as given
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub occurrence: Option<String>,
}

/// An event's start and end, checked to be the same form and in order
fn span(
    start: When,
    end: When,
    zone: &TimeZone,
) -> Result<(Timestamp, Timestamp, bool), BackendError> {
    let invalid = |text: String| BackendError::Invalid(text);

    match (start, end) {
        (When::Date(first), When::Date(last)) => {
            if last < first {
                return Err(invalid("`end` is before `start`".into()));
            }
            let start = dates::start_of_day(first, zone).map_err(invalid)?;
            let end = When::Date(last).end_exclusive(zone).map_err(invalid)?;

            Ok((start, dates::just_before(end), true))
        }
        (When::Time(start), When::Time(end)) => {
            if end <= start {
                return Err(invalid("`end` must be after `start`".into()));
            }

            Ok((start, end, false))
        }
        _ => Err(invalid(
            "`start` and `end` must both be dates (an all-day event) or both be times".into(),
        )),
    }
}

/// The calendar to write to: `wanted`, else the default, refusing a
/// read-only one
fn target_calendar(
    backend: &dyn CalendarBackend,
    wanted: Option<&str>,
) -> Result<CalendarInfo, BackendError> {
    let calendars = backend.calendars()?;
    let found = match wanted {
        Some(id) => calendars
            .into_iter()
            .find(|calendar| calendar.id == id)
            .ok_or_else(|| BackendError::NotFound(format!("no calendar has id {id:?}")))?,
        None => calendars
            .into_iter()
            .find(|calendar| calendar.is_default)
            .ok_or_else(|| {
                BackendError::Invalid("there is no default calendar; pass `calendar_id`".into())
            })?,
    };
    if !found.writable {
        return Err(BackendError::Invalid(format!(
            "calendar {:?} is read-only",
            found.title
        )));
    }

    Ok(found)
}

/// The event or occurrence an update or delete names, as parsed arguments
struct Change<'a> {
    id: &'a str,
    occurrence: Option<When>,
    and_future: bool,
    last_modified: Option<&'a str>,
}

/// The event or occurrence `change` names, refused unless it may be changed
/// and the agent read its current version
fn editable_event(
    backend: &dyn CalendarBackend,
    change: &Change<'_>,
    zone: &TimeZone,
) -> Result<(EventRecord, EventTarget), BackendError> {
    let id = change.id;
    let occurrence = change
        .occurrence
        .map(|when| when.start(zone).map_err(BackendError::Invalid))
        .transpose()?;
    if change.and_future && occurrence.is_none() {
        return Err(BackendError::Invalid(
            "`and_future` needs `occurrence`".into(),
        ));
    }
    // check what the id names first, so a wrong id or a one-off event is
    // reported as such rather than as a missing occurrence
    if occurrence.is_some() {
        let named = backend
            .event(id, None)?
            .ok_or_else(|| BackendError::NotFound(format!("no event has id {id:?}")))?;
        if !named.recurring() {
            return Err(BackendError::Invalid(
                "this event does not repeat; leave out `occurrence`".into(),
            ));
        }
    }
    let event = backend.event(id, occurrence)?.ok_or_else(|| {
        BackendError::NotFound(match occurrence {
            Some(_) => format!("event {id:?} has no occurrence at that `occurrence`"),
            None => format!("no event has id {id:?}"),
        })
    })?;
    if event.recurring() && occurrence.is_none() {
        return Err(BackendError::Invalid(
            "this event repeats; pass the `occurrence` from list_events to change one \
             occurrence, and `and_future=true` to change it and every later one"
                .into(),
        ));
    }
    if !event.writable {
        return Err(BackendError::Invalid(format!(
            "calendar {:?} is read-only",
            event.calendar
        )));
    }
    if !dates::stamp_matches(change.last_modified, event.last_modified) {
        return Err(stale("event", event.last_modified));
    }
    let target = EventTarget {
        id: event.id.clone(),
        occurrence,
        span: if change.and_future {
            Span::Future
        } else {
            Span::This
        },
    };

    Ok((event, target))
}

/// Optional text, with an empty string meaning none
fn text(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

/// An update's new text over the old: omitted keeps the old, an empty
/// string clears it
pub(super) fn merge(new: Option<String>, old: Option<String>) -> Option<String> {
    match new {
        Some(new) => text(Some(new)),
        None => old,
    }
}

struct Inner {
    backend: Arc<dyn CalendarBackend>,
    zone: TimeZone,
}

/// The stdio MCP server; cheap to clone
#[derive(Clone)]
pub struct CalendarAdapter(Arc<Inner>);

impl CalendarAdapter {
    /// An adapter over `backend`, reading and writing times in `zone`
    pub fn new(backend: Arc<dyn CalendarBackend>, zone: TimeZone) -> Self {
        Self(Arc::new(Inner { backend, zone }))
    }

    /// Serves MCP on stdin and stdout until the client disconnects
    pub async fn serve_stdio(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let service = self.serve(rmcp::transport::stdio()).await?;
        service.waiting().await?;

        Ok(())
    }

    fn parse(&self, field: &str, value: &str) -> Result<When, BackendError> {
        When::parse(field, value, &self.0.zone).map_err(BackendError::Invalid)
    }

    fn parse_optional(
        &self,
        field: &str,
        value: Option<&str>,
    ) -> Result<Option<When>, CallToolResult> {
        value
            .map(|text| self.parse(field, text))
            .transpose()
            .map_err(super::failed)
    }

    async fn call<T: Send + 'static>(
        &self,
        work: impl FnOnce(&dyn CalendarBackend, &TimeZone) -> Result<T, BackendError> + Send + 'static,
    ) -> Result<T, CallToolResult> {
        let inner = Arc::clone(&self.0);

        blocking(move || work(inner.backend.as_ref(), &inner.zone)).await
    }
}

#[tool_router]
impl CalendarAdapter {
    #[tool(
        description = "Every calendar in the Calendar app, with its account and whether it \
                          accepts changes."
    )]
    async fn list_calendars(&self) -> Result<Json<CalendarList>, CallToolResult> {
        self.call(|backend, _| {
            let calendars = backend
                .calendars()?
                .into_iter()
                .map(|info| Calendar {
                    id: info.id,
                    title: info.title,
                    source: info.source,
                    writable: info.writable,
                    is_default: info.is_default,
                })
                .collect();

            Ok(Json(CalendarList { calendars }))
        })
        .await
    }

    #[tool(
        description = "Events between `start` and `end`, sorted by start, with each \
                          occurrence of a repeating event listed on its own. Dates cover whole \
                          days, so start=end=2026-10-14 lists that day. Notes, attendees and \
                          other details come from get_event."
    )]
    async fn list_events(
        &self,
        Parameters(params): Parameters<ListEventsParams>,
    ) -> Result<Json<EventList>, CallToolResult> {
        let window = (|| {
            let start = self.parse("start", &params.start)?;
            let end = self.parse("end", &params.end)?;
            let zone = &self.0.zone;

            Ok::<_, BackendError>((
                start.start(zone).map_err(BackendError::Invalid)?,
                end.end_exclusive(zone).map_err(BackendError::Invalid)?,
            ))
        })();
        let (start, end) = window.map_err(super::failed)?;
        if end <= start {
            return Err(super::failed("`end` must be after `start`"));
        }
        if (end.as_second() - start.as_second()) / 86_400 > MAX_WINDOW_DAYS {
            return Err(super::failed(
                "the window is longer than 4 years; list it in parts",
            ));
        }

        self.call(move |backend, zone| {
            let mut events = backend.events(start, end, params.calendar_ids.as_deref())?;
            events.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.title.cmp(&b.title)));

            Ok(Json(EventList {
                events: events
                    .into_iter()
                    .map(|record| Event::new(record, zone, false))
                    .collect(),
                time_zone: zone.iana_name().unwrap_or("local").to_owned(),
            }))
        })
        .await
    }

    #[tool(
        description = "One event with its notes, URL, organizer, attendees and repeat rule. \
                          For a repeating event, pass `occurrence` for one occurrence; without \
                          it this is the first."
    )]
    async fn get_event(
        &self,
        Parameters(params): Parameters<EventIdParams>,
    ) -> Result<Json<Event>, CallToolResult> {
        let occurrence = self.parse_optional("occurrence", params.occurrence.as_deref())?;

        self.call(move |backend, zone| {
            let occurrence = occurrence
                .map(|when| when.start(zone).map_err(BackendError::Invalid))
                .transpose()?;
            let Some(record) = backend.event(&params.id, occurrence)? else {
                let id = &params.id;
                let message = match occurrence {
                    Some(_) if backend.event(id, None)?.is_some() => {
                        format!("event {id:?} has no occurrence at that `occurrence`")
                    }
                    _ => format!("no event has id {id:?}"),
                };

                return Err(BackendError::NotFound(message));
            };

            Ok(Json(Event::new(record, zone, true)))
        })
        .await
    }

    #[tool(
        description = "Add a one-off event. Dates make an all-day event (end is its last \
                          day); times make a timed one. Returns the new event with its id. \
                          Repeating events cannot be created here."
    )]
    async fn create_event(
        &self,
        Parameters(params): Parameters<CreateEventParams>,
    ) -> Result<Json<Event>, CallToolResult> {
        let start = self.parse("start", &params.start).map_err(super::failed)?;
        let end = self.parse("end", &params.end).map_err(super::failed)?;

        self.call(move |backend, zone| {
            let (start, end, all_day) = span(start, end, zone)?;
            let calendar = target_calendar(backend, params.calendar_id.as_deref())?;
            if params.title.trim().is_empty() {
                return Err(BackendError::Invalid("`title` is empty".into()));
            }
            let draft = EventDraft {
                calendar_id: calendar.id,
                title: params.title,
                start,
                end,
                all_day,
                location: text(params.location),
                notes: text(params.notes),
                url: text(params.url),
            };

            Ok(Json(Event::new(
                backend.save_event(None, draft)?,
                zone,
                true,
            )))
        })
        .await
    }

    #[tool(
        description = "Change an event; omitted fields stay, an empty string clears one. \
                          Pass the last_modified you read: if the event changed since, this \
                          fails and you must read it again. For a repeating event pass its \
                          `occurrence` to change that one, plus and_future=true to change it \
                          and every later one."
    )]
    async fn update_event(
        &self,
        Parameters(params): Parameters<UpdateEventParams>,
    ) -> Result<Json<Event>, CallToolResult> {
        let parse = |field: &str, value: &Option<String>| {
            value
                .as_deref()
                .map(|text| self.parse(field, text))
                .transpose()
        };
        let start = parse("start", &params.start).map_err(super::failed)?;
        let end = parse("end", &params.end).map_err(super::failed)?;
        let occurrence = self.parse_optional("occurrence", params.occurrence.as_deref())?;

        self.call(move |backend, zone| {
            let change = Change {
                id: &params.id,
                occurrence,
                and_future: params.and_future.unwrap_or(false),
                last_modified: params.last_modified.as_deref(),
            };
            let (event, target) = editable_event(backend, &change, zone)?;
            // an all-day event's stored end is a moment on its last day, so
            // it maps back to that day; a timed event keeps its times as they are
            let (current_start, current_end) = if event.all_day {
                let last = dates::just_before(event.end).max(event.start);
                (
                    When::Date(dates::day_of(event.start, zone)),
                    When::Date(dates::day_of(last, zone)),
                )
            } else {
                (When::Time(event.start), When::Time(event.end))
            };
            let start = start.unwrap_or(current_start);
            let end = end.unwrap_or(current_end);
            let one_form = matches!(
                (start, end),
                (When::Date(_), When::Date(_)) | (When::Time(_), When::Time(_))
            );
            if !one_form && (params.start.is_none() || params.end.is_none()) {
                return Err(BackendError::Invalid(
                    "the event is all-day and the new value is a time, or the reverse; to switch \
                     between all-day and timed, pass both `start` and `end`"
                        .into(),
                ));
            }
            let (start, end, all_day) = span(start, end, zone)?;
            let calendar_id = match params.calendar_id.as_deref() {
                Some(id) if id != event.calendar_id && target.occurrence.is_some() => {
                    return Err(BackendError::Invalid(
                        "a repeating event changes calendar as a whole; do it in Calendar".into(),
                    ));
                }
                Some(id) if id != event.calendar_id => target_calendar(backend, Some(id))?.id,
                _ => event.calendar_id.clone(),
            };
            let clear = params.clear.unwrap_or_default();
            let keep = |field: ClearableEventField, new: Option<String>, old: Option<String>| {
                if clear.contains(&field) {
                    None
                } else {
                    merge(new, old)
                }
            };
            let title = match params.title {
                Some(title) if title.trim().is_empty() => {
                    return Err(BackendError::Invalid("`title` is empty".into()));
                }
                Some(title) => title,
                None => event.title.clone(),
            };
            let draft = EventDraft {
                calendar_id,
                title,
                start,
                end,
                all_day,
                location: keep(
                    ClearableEventField::Location,
                    params.location,
                    event.location,
                ),
                notes: keep(ClearableEventField::Notes, params.notes, event.notes),
                url: keep(ClearableEventField::Url, params.url, event.url),
            };

            Ok(Json(Event::new(
                backend.save_event(Some(&target), draft)?,
                zone,
                true,
            )))
        })
        .await
    }

    #[tool(
        description = "Delete an event. Pass the last_modified you read: if the event \
                          changed since, this fails. For a repeating event pass its `occurrence` \
                          to delete that one, plus and_future=true to delete it and every later \
                          one."
    )]
    async fn delete_event(
        &self,
        Parameters(params): Parameters<DeleteEventParams>,
    ) -> Result<Json<Deleted>, CallToolResult> {
        let occurrence = self.parse_optional("occurrence", params.occurrence.as_deref())?;

        self.call(move |backend, zone| {
            let change = Change {
                id: &params.id,
                occurrence,
                and_future: params.and_future.unwrap_or(false),
                last_modified: params.last_modified.as_deref(),
            };
            let (event, target) = editable_event(backend, &change, zone)?;
            backend.remove_event(&target)?;

            Ok(Json(Deleted {
                id: event.id,
                occurrence: params.occurrence,
            }))
        })
        .await
    }
}

#[tool_handler]
impl ServerHandler for CalendarAdapter {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}
