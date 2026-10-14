//! Stand-in for EventKit in the calendar and reminders adapter tests
//!
//! Runs the real adapter (`calendar` or `reminders` as the only argument)
//! over an in-memory store seeded with a few items. Each save moves the
//! item's `last_modified` one second on, so stale tokens are easy to make

use std::sync::{Arc, Mutex};

use codemode_mcp::adapters::apple::{
    BackendError, Frequency, RecurrenceRecord,
    calendar::{
        Availability, CalendarAdapter, CalendarBackend, CalendarInfo, EventDraft, EventRecord,
        EventStatus,
    },
    dates::{self, When},
    reminders::{
        ListInfo, Priority, ReminderDraft, ReminderQuery, ReminderRecord, RemindersAdapter,
        RemindersBackend,
    },
};
use jiff::{Timestamp, civil::date, tz::TimeZone};

struct State {
    calendars: Vec<CalendarInfo>,
    events: Vec<EventRecord>,
    lists: Vec<ListInfo>,
    reminders: Vec<ReminderRecord>,
    next_id: u32,
    clock: Timestamp,
}

impl State {
    /// A later moment each time
    fn tick(&mut self) -> Timestamp {
        self.clock += jiff::SignedDuration::from_secs(1);
        self.clock
    }

    fn id(&mut self, prefix: &str) -> String {
        self.next_id += 1;
        format!("{prefix}-{}", self.next_id)
    }
}

struct Fake {
    state: Mutex<State>,
    zone: TimeZone,
}

fn time(text: &str) -> Timestamp {
    text.parse().unwrap_or(Timestamp::UNIX_EPOCH)
}

fn calendar(id: &str, title: &str, source: &str, writable: bool, is_default: bool) -> CalendarInfo {
    CalendarInfo {
        id: id.into(),
        title: title.into(),
        source: source.into(),
        writable,
        is_default,
    }
}

fn event(id: &str, calendar: &CalendarInfo, title: &str, start: &str, end: &str) -> EventRecord {
    EventRecord {
        id: id.into(),
        calendar_id: calendar.id.clone(),
        calendar: calendar.title.clone(),
        writable: calendar.writable,
        title: title.into(),
        start: time(start),
        end: time(end),
        all_day: false,
        location: None,
        notes: None,
        url: None,
        time_zone: Some("America/Chicago".into()),
        status: EventStatus::Confirmed,
        availability: Availability::Busy,
        organizer: None,
        attendees: Vec::new(),
        recurrence: None,
        detached: false,
        created: Some(time("2026-10-01T12:00:00Z")),
        last_modified: Some(time("2026-10-01T12:00:00.250Z")),
    }
}

fn reminder(id: &str, list: &ListInfo, title: &str, due: Option<When>) -> ReminderRecord {
    ReminderRecord {
        id: id.into(),
        list_id: list.id.clone(),
        list: list.title.clone(),
        writable: list.writable,
        title: title.into(),
        notes: None,
        url: None,
        due,
        priority: Priority::None,
        completed: false,
        completed_at: None,
        recurrence: None,
        created: Some(time("2026-10-01T12:00:00Z")),
        last_modified: Some(time("2026-10-01T12:00:00.250Z")),
    }
}

impl Fake {
    fn seeded() -> Self {
        let home = calendar("cal-home", "Home", "iCloud", true, true);
        let holidays = calendar(
            "cal-holidays",
            "US Holidays",
            "Subscribed Calendars",
            false,
            false,
        );
        let mut dentist = event(
            "ev-dentist",
            &home,
            "Dentist",
            "2026-10-14T14:00:00Z",
            "2026-10-14T15:00:00Z",
        );
        dentist.location = Some("12 Main St".into());
        dentist.notes = Some("Bring the insurance card".into());
        let mut standup = event(
            "ev-standup",
            &home,
            "Standup",
            "2026-10-13T13:30:00Z",
            "2026-10-13T13:45:00Z",
        );
        standup.recurrence = Some(RecurrenceRecord {
            frequency: Frequency::Weekly,
            interval: 1,
            until: None,
            count: None,
        });
        // stored like EventKit stores all-day events: 23:59:59 local on the
        // last day
        let mut holiday = event(
            "ev-holiday",
            &holidays,
            "Columbus Day",
            "2026-10-12T05:00:00Z",
            "2026-10-13T04:59:59Z",
        );
        holiday.all_day = true;
        holiday.time_zone = None;

        let groceries = ListInfo {
            id: "list-groceries".into(),
            title: "Groceries".into(),
            source: "iCloud".into(),
            writable: true,
            is_default: true,
        };
        let shared = ListInfo {
            id: "list-shared".into(),
            title: "Shared".into(),
            source: "Exchange".into(),
            writable: false,
            is_default: false,
        };
        let mut milk = reminder(
            "rem-milk",
            &groceries,
            "Milk",
            Some(When::Date(date(2026, 10, 15))),
        );
        milk.priority = Priority::High;
        milk.notes = Some("x".repeat(250));
        let call = reminder(
            "rem-call",
            &groceries,
            "Call the plumber",
            Some(When::Time(time("2026-10-14T23:00:00Z"))),
        );
        let undated = reminder("rem-undated", &groceries, "Fix the gate", None);
        let mut done = reminder("rem-done", &groceries, "Eggs", None);
        done.completed = true;
        done.completed_at = Some(time("2026-10-13T17:00:00Z"));
        let locked = reminder("rem-locked", &shared, "Team offsite", None);

        Self {
            state: Mutex::new(State {
                calendars: vec![home, holidays],
                events: vec![dentist, standup, holiday],
                lists: vec![groceries, shared],
                reminders: vec![milk, call, undated, done, locked],
                next_id: 0,
                clock: time("2026-10-14T00:00:00.500Z"),
            }),
            zone: dates::local_zone(),
        }
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>, BackendError> {
        self.state
            .lock()
            .map_err(|_| BackendError::Failed("fake store poisoned".into()))
    }
}

impl CalendarBackend for Fake {
    fn calendars(&self) -> Result<Vec<CalendarInfo>, BackendError> {
        Ok(self.state()?.calendars.clone())
    }

    fn events(
        &self,
        start: Timestamp,
        end: Timestamp,
        calendar_ids: Option<&[String]>,
    ) -> Result<Vec<EventRecord>, BackendError> {
        let state = self.state()?;
        if let Some(ids) = calendar_ids {
            for id in ids {
                if !state.calendars.iter().any(|calendar| &calendar.id == id) {
                    return Err(BackendError::NotFound(format!(
                        "no calendar or list has id {id:?}"
                    )));
                }
            }
        }

        Ok(state
            .events
            .iter()
            .filter(|event| event.start < end && event.end > start)
            .filter(|event| calendar_ids.is_none_or(|ids| ids.contains(&event.calendar_id)))
            .cloned()
            .collect())
    }

    fn event(&self, id: &str) -> Result<Option<EventRecord>, BackendError> {
        Ok(self
            .state()?
            .events
            .iter()
            .find(|event| event.id == id)
            .cloned())
    }

    fn save_event(&self, id: Option<&str>, draft: EventDraft) -> Result<EventRecord, BackendError> {
        let mut state = self.state()?;
        let calendar = state
            .calendars
            .iter()
            .find(|calendar| calendar.id == draft.calendar_id)
            .cloned()
            .ok_or_else(|| BackendError::NotFound("no such calendar".into()))?;
        let now = state.tick();
        let id = match id {
            Some(id) => id.to_owned(),
            None => {
                let id = state.id("ev");
                let mut fresh = event(
                    &id,
                    &calendar,
                    "",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                );
                fresh.created = Some(now);
                state.events.push(fresh);
                id
            }
        };
        let event = state
            .events
            .iter_mut()
            .find(|event| event.id == id)
            .ok_or_else(|| BackendError::NotFound(format!("no event has id {id:?}")))?;
        event.calendar_id = calendar.id;
        event.calendar = calendar.title;
        event.writable = calendar.writable;
        event.title = draft.title;
        event.start = draft.start;
        event.end = draft.end;
        event.all_day = draft.all_day;
        event.location = draft.location;
        event.notes = draft.notes;
        event.url = draft.url;
        event.last_modified = Some(now);

        Ok(event.clone())
    }

    fn remove_event(&self, id: &str) -> Result<(), BackendError> {
        let mut state = self.state()?;
        let before = state.events.len();
        state.events.retain(|event| event.id != id);
        if state.events.len() == before {
            return Err(BackendError::NotFound(format!("no event has id {id:?}")));
        }

        Ok(())
    }
}

impl RemindersBackend for Fake {
    fn lists(&self) -> Result<Vec<ListInfo>, BackendError> {
        Ok(self.state()?.lists.clone())
    }

    fn reminders(
        &self,
        query: ReminderQuery,
        list_ids: Option<&[String]>,
    ) -> Result<Vec<ReminderRecord>, BackendError> {
        let state = self.state()?;
        let within =
            |time: Option<Timestamp>, from: Option<Timestamp>, until: Option<Timestamp>| {
                if from.is_none() && until.is_none() {
                    return true;
                }
                time.is_some_and(|time| {
                    from.is_none_or(|from| time >= from) && until.is_none_or(|until| time < until)
                })
            };

        Ok(state
            .reminders
            .iter()
            .filter(|reminder| list_ids.is_none_or(|ids| ids.contains(&reminder.list_id)))
            .filter(|reminder| match query {
                ReminderQuery::Incomplete { from, until } => {
                    let due = reminder.due.and_then(|due| due.start(&self.zone).ok());
                    !reminder.completed && within(due, from, until)
                }
                ReminderQuery::Completed { from, until } => {
                    reminder.completed && within(reminder.completed_at, from, until)
                }
                ReminderQuery::All => true,
            })
            .cloned()
            .collect())
    }

    fn reminder(&self, id: &str) -> Result<Option<ReminderRecord>, BackendError> {
        Ok(self
            .state()?
            .reminders
            .iter()
            .find(|reminder| reminder.id == id)
            .cloned())
    }

    fn save_reminder(
        &self,
        id: Option<&str>,
        draft: ReminderDraft,
    ) -> Result<ReminderRecord, BackendError> {
        let mut state = self.state()?;
        let list = state
            .lists
            .iter()
            .find(|list| list.id == draft.list_id)
            .cloned()
            .ok_or_else(|| BackendError::NotFound("no such list".into()))?;
        let now = state.tick();
        let id = match id {
            Some(id) => id.to_owned(),
            None => {
                let id = state.id("rem");
                let mut fresh = reminder(&id, &list, "", None);
                fresh.created = Some(now);
                state.reminders.push(fresh);
                id
            }
        };
        let reminder = state
            .reminders
            .iter_mut()
            .find(|reminder| reminder.id == id)
            .ok_or_else(|| BackendError::NotFound(format!("no reminder has id {id:?}")))?;
        reminder.list_id = list.id;
        reminder.list = list.title;
        reminder.writable = list.writable;
        reminder.title = draft.title;
        reminder.notes = draft.notes;
        reminder.url = draft.url;
        reminder.due = draft.due;
        reminder.priority = draft.priority;
        reminder.last_modified = Some(now);

        Ok(reminder.clone())
    }

    fn set_completed(&self, id: &str, completed: bool) -> Result<ReminderRecord, BackendError> {
        let mut state = self.state()?;
        let now = state.tick();
        let reminder = state
            .reminders
            .iter_mut()
            .find(|reminder| reminder.id == id)
            .ok_or_else(|| BackendError::NotFound(format!("no reminder has id {id:?}")))?;
        reminder.completed = completed;
        reminder.completed_at = completed.then_some(now);
        reminder.last_modified = Some(now);

        Ok(reminder.clone())
    }

    fn remove_reminder(&self, id: &str) -> Result<(), BackendError> {
        let mut state = self.state()?;
        let before = state.reminders.len();
        state.reminders.retain(|reminder| reminder.id != id);
        if state.reminders.len() == before {
            return Err(BackendError::NotFound(format!("no reminder has id {id:?}")));
        }

        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fake = Arc::new(Fake::seeded());
    let zone = dates::local_zone();

    match std::env::args().nth(1).as_deref() {
        Some("calendar") => CalendarAdapter::new(fake, zone).serve_stdio().await,
        Some("reminders") => RemindersAdapter::new(fake, zone).serve_stdio().await,
        _ => Err("usage: codemode-fake-eventkit calendar|reminders".into()),
    }
}
