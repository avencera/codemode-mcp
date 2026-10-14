//! The EventKit backends of the calendar and reminders adapters
//!
//! `EKEventStore` and the objects it hands out are not thread-safe, so one
//! thread owns the store and runs every call while the caller blocks on the
//! answer. EventKit's methods are `unsafe` in the bindings only because they
//! cannot check argument types; every call here passes objects of the
//! declared types that belong to the store thread's own store
//!
//! macOS asks the owner once per entity type. The prompt names the
//! responsible process, which for an adapter the daemon started is the
//! daemon's own signed binary, so the grant survives rebuilds signed with the
//! same identity. In a test run of this code, a request made straight after
//! the store was created never reached the privacy service; the store is
//! queried first, and a request still unanswered after
//! [`REQUEST_RETRY_AFTER`] is sent again

use std::{
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use block2::RcBlock;
use jiff::{
    Timestamp,
    civil::{Date, DateTime},
    tz::TimeZone,
};
use objc2::{rc::Retained, runtime::Bool};
use objc2_event_kit::{
    EKAlarm, EKAuthorizationStatus, EKCalendar, EKCalendarItem, EKEntityType, EKEvent,
    EKEventAvailability, EKEventStatus, EKEventStore, EKParticipant, EKParticipantStatus,
    EKRecurrenceFrequency, EKRecurrenceRule, EKReminder, EKSpan,
};
use objc2_foundation::{
    NSArray, NSCalendar, NSCalendarIdentifierGregorian, NSDate, NSDateComponentUndefined,
    NSDateComponents, NSError, NSString, NSTimeZone, NSURL,
};

use super::{
    BackendError, Entity, Frequency, RecurrenceRecord,
    calendar::{
        Availability, CalendarBackend, CalendarInfo, EventDraft, EventRecord, EventStatus,
        ParticipantStatus, Person,
    },
    dates::{self, When},
    reminders::{
        ListInfo, Priority, ReminderDraft, ReminderQuery, ReminderRecord, RemindersBackend,
    },
};

/// Longest a caller waits for the store thread
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest a reminders fetch may take
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// An access request still unanswered after this is sent again
const REQUEST_RETRY_AFTER: Duration = Duration::from_secs(30);

/// EventKit's name for the entity type
fn kind(entity: Entity) -> EKEntityType {
    match entity {
        Entity::Events => EKEntityType::Event,
        Entity::Reminders => EKEntityType::Reminder,
    }
}

/// The name System Settings uses
fn setting(entity: Entity) -> &'static str {
    match entity {
        Entity::Events => "Calendars",
        Entity::Reminders => "Reminders",
    }
}

type Job = Box<dyn FnOnce(&mut Store) + Send>;

/// An access request sent to macOS and not yet answered
struct Request {
    sent: Instant,
    answered: Arc<AtomicBool>,
}

/// The store thread's state
struct Store {
    entity: Entity,
    store: Retained<EKEventStore>,
    /// Whether `store` was made with access; one made before the grant holds
    /// no calendars until it is replaced
    with_access: bool,
    request: Option<Request>,
}

impl Store {
    fn new(entity: Entity) -> Self {
        let mut store = Self {
            entity,
            store: unsafe { EKEventStore::new() },
            with_access: false,
            request: None,
        };
        // ask at startup, so the prompt appears when the daemon starts the
        // adapter rather than on the first call
        if store.status() == EKAuthorizationStatus::NotDetermined {
            store.request_access();
        }

        store
    }

    fn status(&self) -> EKAuthorizationStatus {
        unsafe { EKEventStore::authorizationStatusForEntityType(kind(self.entity)) }
    }

    /// Runs `work` against a store that has full access, or explains what
    /// the owner must do
    fn with_access<T>(
        &mut self,
        work: impl FnOnce(&EKEventStore) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let setting = setting(self.entity);
        let status = self.status();
        if status == EKAuthorizationStatus::FullAccess {
            if !self.with_access {
                self.store = unsafe { EKEventStore::new() };
                self.with_access = true;
            }

            return work(&self.store);
        }

        let message = match status {
            EKAuthorizationStatus::NotDetermined => {
                self.request_access();
                format!(
                    "macOS is asking on the Mac whether codemode-mcp may use your {}; click \
                     Allow there, then try again",
                    setting.to_lowercase()
                )
            }
            EKAuthorizationStatus::Denied => format!(
                "macOS denied codemode-mcp access to your {}; turn it on in System Settings > \
                 Privacy & Security > {setting}, then try again",
                setting.to_lowercase()
            ),
            EKAuthorizationStatus::WriteOnly => format!(
                "codemode-mcp can only add {}; give it full access in System Settings > \
                 Privacy & Security > {setting}",
                setting.to_lowercase()
            ),
            _ => format!(
                "access to your {} is restricted on this Mac, for example by a management \
                 profile",
                setting.to_lowercase()
            ),
        };

        Err(BackendError::Access(message))
    }

    /// Shows the macOS prompt, unless a recent request is still waiting
    fn request_access(&mut self) {
        let waiting = self.request.as_ref().is_some_and(|request| {
            !request.answered.load(Ordering::Acquire)
                && request.sent.elapsed() < REQUEST_RETRY_AFTER
        });
        if waiting {
            return;
        }

        // a request sent before the store has settled was lost in testing
        let _ = unsafe { self.store.calendarsForEntityType(kind(self.entity)) };

        let answered = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&answered);
        let entity = self.entity;
        let completion = RcBlock::new(move |granted: Bool, error: *mut NSError| {
            flag.store(true, Ordering::Release);
            let error =
                unsafe { error.as_ref() }.map(|error| error.localizedDescription().to_string());
            tracing::info!(
                ?entity,
                granted = granted.as_bool(),
                ?error,
                "EventKit access answered"
            );
        });
        unsafe {
            match self.entity {
                Entity::Events => self
                    .store
                    .requestFullAccessToEventsWithCompletion(RcBlock::as_ptr(&completion)),
                Entity::Reminders => self
                    .store
                    .requestFullAccessToRemindersWithCompletion(RcBlock::as_ptr(&completion)),
            }
        }
        tracing::info!(?entity, "EventKit access requested");

        self.request = Some(Request {
            sent: Instant::now(),
            answered,
        });
    }
}

/// One EventKit store on its own thread
pub struct EventKit {
    jobs: mpsc::Sender<Job>,
    zone: TimeZone,
}

impl EventKit {
    /// Starts the store thread for `entity`; times without a zone are read
    /// in `zone`
    pub fn start(entity: Entity, zone: TimeZone) -> std::io::Result<Self> {
        let (jobs, queue) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name(format!("eventkit-{entity:?}").to_lowercase())
            .spawn(move || {
                let mut store = Store::new(entity);
                for job in queue {
                    job(&mut store);
                }
            })?;

        Ok(Self { jobs, zone })
    }

    /// Runs `work` on the store thread with access checked, and waits for
    /// its answer
    fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&EKEventStore, &TimeZone) -> Result<T, BackendError> + Send + 'static,
    ) -> Result<T, BackendError> {
        let (answer, receiver) = mpsc::sync_channel(1);
        let zone = self.zone.clone();
        let job: Job = Box::new(move |store| {
            // a binding panics when EventKit returns nil where it promised an
            // object; the thread must survive it, or every later call fails
            // while the process stays up and the daemon never restarts it
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                store.with_access(|store| work(store, &zone))
            }))
            .unwrap_or_else(|_| {
                Err(BackendError::Failed(
                    "EventKit returned something unexpected; see the daemon log".into(),
                ))
            });
            let _ = answer.send(outcome);
        });
        if self.jobs.send(job).is_err() {
            return Err(BackendError::Failed(
                "the EventKit thread has stopped".into(),
            ));
        }

        receiver.recv_timeout(CALL_TIMEOUT).map_err(|_| {
            BackendError::Failed(format!(
                "EventKit did not answer within {}s; the outcome is unknown",
                CALL_TIMEOUT.as_secs()
            ))
        })?
    }
}

fn ns(text: &str) -> Retained<NSString> {
    NSString::from_str(text)
}

/// `zone` as Foundation's zone, else the system's
fn mac_zone(zone: &TimeZone) -> Retained<NSTimeZone> {
    zone.iana_name()
        .and_then(|name| NSTimeZone::timeZoneWithName(&ns(name)))
        .unwrap_or_else(NSTimeZone::systemTimeZone)
}

fn ns_date(time: Timestamp) -> Retained<NSDate> {
    NSDate::dateWithTimeIntervalSince1970(dates::to_unix_seconds(time))
}

fn timestamp(date: &NSDate) -> Timestamp {
    dates::from_unix_seconds(date.timeIntervalSince1970())
}

/// Text that is present and not blank
fn present(text: Option<Retained<NSString>>) -> Option<String> {
    text.map(|text| text.to_string())
        .filter(|text| !text.trim().is_empty())
}

fn ns_url(url: Option<&str>) -> Result<Option<Retained<NSURL>>, BackendError> {
    url.map(|url| {
        NSURL::URLWithString(&ns(url))
            .ok_or_else(|| BackendError::Invalid(format!("`url` is not a URL: {url:?}")))
    })
    .transpose()
}

fn ns_failure(action: &str, error: &NSError) -> BackendError {
    BackendError::Failed(format!(
        "EventKit could not {action}: {}",
        error.localizedDescription()
    ))
}

/// The calendars with these ids, all of which must exist
fn calendars_by_id(
    store: &EKEventStore,
    ids: Option<&[String]>,
) -> Result<Option<Retained<NSArray<EKCalendar>>>, BackendError> {
    let Some(ids) = ids else {
        return Ok(None);
    };
    let calendars = ids
        .iter()
        .map(|id| {
            unsafe { store.calendarWithIdentifier(&ns(id)) }
                .ok_or_else(|| BackendError::NotFound(format!("no calendar or list has id {id:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(NSArray::from_retained_slice(&calendars)))
}

fn calendar_info(calendar: &EKCalendar, default_id: Option<&str>) -> CalendarInfo {
    let id = unsafe { calendar.calendarIdentifier() }.to_string();

    CalendarInfo {
        is_default: default_id == Some(id.as_str()),
        id,
        title: unsafe { calendar.title() }.to_string(),
        source: unsafe { calendar.source() }
            .map(|source| unsafe { source.title() }.to_string())
            .unwrap_or_default(),
        writable: unsafe { calendar.allowsContentModifications() },
    }
}

fn recurrence(item: &EKCalendarItem) -> Option<RecurrenceRecord> {
    let rules = unsafe { item.recurrenceRules() }?;
    let rule: Retained<EKRecurrenceRule> = rules.firstObject()?;
    let frequency = match unsafe { rule.frequency() } {
        EKRecurrenceFrequency::Daily => Frequency::Daily,
        EKRecurrenceFrequency::Weekly => Frequency::Weekly,
        EKRecurrenceFrequency::Monthly => Frequency::Monthly,
        _ => Frequency::Yearly,
    };
    let end = unsafe { rule.recurrenceEnd() };

    Some(RecurrenceRecord {
        frequency,
        interval: u32::try_from(unsafe { rule.interval() }).unwrap_or(1),
        until: end
            .as_ref()
            .and_then(|end| unsafe { end.endDate() })
            .map(|date| timestamp(&date)),
        count: end
            .and_then(|end| u32::try_from(unsafe { end.occurrenceCount() }).ok())
            .filter(|count| *count > 0),
    })
}

fn person(participant: &EKParticipant) -> Person {
    let address = unsafe { participant.URL() }
        .absoluteString()
        .map(|url| url.to_string());

    Person {
        name: present(unsafe { participant.name() }),
        email: address
            .as_deref()
            .and_then(|url| url.strip_prefix("mailto:"))
            .map(str::to_owned),
        status: match unsafe { participant.participantStatus() } {
            EKParticipantStatus::Pending => ParticipantStatus::Pending,
            EKParticipantStatus::Accepted => ParticipantStatus::Accepted,
            EKParticipantStatus::Declined => ParticipantStatus::Declined,
            EKParticipantStatus::Tentative => ParticipantStatus::Tentative,
            EKParticipantStatus::Delegated => ParticipantStatus::Delegated,
            EKParticipantStatus::Completed => ParticipantStatus::Completed,
            EKParticipantStatus::InProcess => ParticipantStatus::InProcess,
            _ => ParticipantStatus::Unknown,
        },
        is_me: unsafe { participant.isCurrentUser() },
    }
}

/// An event as a record; `None` for an unsaved event, which has no id
fn event_record(event: &EKEvent) -> Option<EventRecord> {
    let id = unsafe { event.eventIdentifier() }?.to_string();
    let calendar = unsafe { event.calendar() };

    Some(EventRecord {
        id,
        calendar_id: calendar
            .as_ref()
            .map(|calendar| unsafe { calendar.calendarIdentifier() }.to_string())
            .unwrap_or_default(),
        calendar: calendar
            .as_ref()
            .map(|calendar| unsafe { calendar.title() }.to_string())
            .unwrap_or_default(),
        writable: calendar
            .as_ref()
            .is_some_and(|calendar| unsafe { calendar.allowsContentModifications() }),
        title: unsafe { event.title() }.to_string(),
        start: unsafe { timestamp(&event.startDate()) },
        end: unsafe { timestamp(&event.endDate()) },
        all_day: unsafe { event.isAllDay() },
        location: present(unsafe { event.location() }),
        notes: present(unsafe { event.notes() }),
        url: unsafe { event.URL() }.and_then(|url| present(url.absoluteString())),
        time_zone: unsafe { event.timeZone() }.map(|zone| zone.name().to_string()),
        status: match unsafe { event.status() } {
            EKEventStatus::Confirmed => EventStatus::Confirmed,
            EKEventStatus::Tentative => EventStatus::Tentative,
            EKEventStatus::Canceled => EventStatus::Canceled,
            _ => EventStatus::None,
        },
        availability: match unsafe { event.availability() } {
            EKEventAvailability::Busy => Availability::Busy,
            EKEventAvailability::Free => Availability::Free,
            EKEventAvailability::Tentative => Availability::Tentative,
            EKEventAvailability::Unavailable => Availability::Unavailable,
            _ => Availability::NotSupported,
        },
        organizer: unsafe { event.organizer() }.map(|organizer| person(&organizer)),
        attendees: unsafe { event.attendees() }
            .map(|attendees| attendees.iter().map(|attendee| person(&attendee)).collect())
            .unwrap_or_default(),
        recurrence: recurrence(event),
        detached: unsafe { event.isDetached() },
        created: unsafe { event.creationDate() }.map(|date| timestamp(&date)),
        last_modified: unsafe { event.lastModifiedDate() }.map(|date| timestamp(&date)),
    })
}

impl CalendarBackend for EventKit {
    fn calendars(&self) -> Result<Vec<CalendarInfo>, BackendError> {
        self.run(|store, _| {
            let default = unsafe { store.defaultCalendarForNewEvents() }
                .map(|calendar| unsafe { calendar.calendarIdentifier() }.to_string());
            let calendars = unsafe { store.calendarsForEntityType(EKEntityType::Event) };

            Ok(calendars
                .iter()
                .map(|calendar| calendar_info(&calendar, default.as_deref()))
                .collect())
        })
    }

    fn events(
        &self,
        start: Timestamp,
        end: Timestamp,
        calendar_ids: Option<&[String]>,
    ) -> Result<Vec<EventRecord>, BackendError> {
        let calendar_ids = calendar_ids.map(<[String]>::to_vec);

        self.run(move |store, _| {
            let calendars = calendars_by_id(store, calendar_ids.as_deref())?;
            let predicate = unsafe {
                store.predicateForEventsWithStartDate_endDate_calendars(
                    &ns_date(start),
                    &ns_date(end),
                    calendars.as_deref(),
                )
            };
            let events = unsafe { store.eventsMatchingPredicate(&predicate) };

            Ok(events
                .iter()
                .filter_map(|event| event_record(&event))
                .collect())
        })
    }

    fn event(&self, id: &str) -> Result<Option<EventRecord>, BackendError> {
        let id = id.to_owned();

        self.run(move |store, _| {
            Ok(unsafe { store.eventWithIdentifier(&ns(&id)) }
                .and_then(|event| event_record(&event)))
        })
    }

    fn save_event(&self, id: Option<&str>, draft: EventDraft) -> Result<EventRecord, BackendError> {
        let id = id.map(str::to_owned);

        self.run(move |store, zone| {
            let event = match &id {
                Some(id) => unsafe { store.eventWithIdentifier(&ns(id)) }
                    .ok_or_else(|| BackendError::NotFound(format!("no event has id {id:?}")))?,
                None => unsafe { EKEvent::eventWithEventStore(store) },
            };
            let calendar = unsafe { store.calendarWithIdentifier(&ns(&draft.calendar_id)) }
                .ok_or_else(|| {
                    BackendError::NotFound(format!("no calendar has id {:?}", draft.calendar_id))
                })?;
            let url = ns_url(draft.url.as_deref())?;

            unsafe {
                event.setCalendar(Some(&calendar));
                event.setTitle(Some(&ns(&draft.title)));
                event.setAllDay(draft.all_day);
                // timed events are pinned to the Mac's zone rather than left
                // to EventKit's default; all-day events float
                let event_zone = (!draft.all_day).then(|| mac_zone(zone));
                event.setTimeZone(event_zone.as_deref());
                event.setStartDate(Some(&ns_date(draft.start)));
                event.setEndDate(Some(&ns_date(draft.end)));
                event.setLocation(draft.location.as_deref().map(ns).as_deref());
                event.setNotes(draft.notes.as_deref().map(ns).as_deref());
                event.setURL(url.as_deref());
                store
                    .saveEvent_span_commit_error(&event, EKSpan::ThisEvent, true)
                    .map_err(|error| ns_failure("save the event", &error))?;
            }

            event_record(&event)
                .ok_or_else(|| BackendError::Failed("the saved event has no id".into()))
        })
    }

    fn remove_event(&self, id: &str) -> Result<(), BackendError> {
        let id = id.to_owned();

        self.run(move |store, _| {
            let event = unsafe { store.eventWithIdentifier(&ns(&id)) }
                .ok_or_else(|| BackendError::NotFound(format!("no event has id {id:?}")))?;

            unsafe { store.removeEvent_span_commit_error(&event, EKSpan::ThisEvent, true) }
                .map_err(|error| ns_failure("delete the event", &error))
        })
    }
}

/// A due date or time from date components; a time without a zone is read
/// in `zone`
fn due_from_components(components: &NSDateComponents, zone: &TimeZone) -> Option<When> {
    let field = |value: isize| (value != NSDateComponentUndefined).then_some(value);
    let small = |value: isize| i8::try_from(value).ok();

    let year = i16::try_from(field(components.year())?).ok()?;
    let month = small(field(components.month())?)?;
    let day = small(field(components.day())?)?;
    let date = Date::new(year, month, day).ok()?;
    let Some(hour) = field(components.hour()) else {
        return Some(When::Date(date));
    };

    let minute = field(components.minute()).unwrap_or(0);
    let second = field(components.second()).unwrap_or(0);
    let local = DateTime::new(
        year,
        month,
        day,
        small(hour)?,
        small(minute)?,
        small(second)?,
        0,
    )
    .ok()?;
    let zone = components
        .timeZone()
        .and_then(|zone| TimeZone::get(&zone.name().to_string()).ok())
        .unwrap_or_else(|| zone.clone());

    local
        .to_zoned(zone)
        .ok()
        .map(|zoned| When::Time(zoned.timestamp()))
}

/// Date components for a due date or time, the way Reminders writes them:
/// local fields plus the zone for a time
fn due_components(due: When, zone: &TimeZone) -> Retained<NSDateComponents> {
    let components = NSDateComponents::new();
    // the fields are Gregorian, whatever calendar the Mac displays
    let gregorian = NSCalendar::calendarWithIdentifier(unsafe { NSCalendarIdentifierGregorian });
    components.setCalendar(gregorian.as_deref());
    let set_date = |date: Date| {
        components.setYear(date.year().into());
        components.setMonth(date.month().into());
        components.setDay(date.day().into());
    };

    match due {
        When::Date(date) => set_date(date),
        When::Time(time) => {
            let local = time.to_zoned(zone.clone());
            set_date(local.date());
            components.setHour(local.hour().into());
            components.setMinute(local.minute().into());
            components.setSecond(local.second().into());
            components.setTimeZone(Some(&mac_zone(zone)));
        }
    }

    components
}

fn reminder_record(reminder: &EKReminder, zone: &TimeZone) -> ReminderRecord {
    let list = unsafe { reminder.calendar() };

    ReminderRecord {
        id: unsafe { reminder.calendarItemIdentifier() }.to_string(),
        list_id: list
            .as_ref()
            .map(|list| unsafe { list.calendarIdentifier() }.to_string())
            .unwrap_or_default(),
        list: list
            .as_ref()
            .map(|list| unsafe { list.title() }.to_string())
            .unwrap_or_default(),
        writable: list
            .as_ref()
            .is_some_and(|list| unsafe { list.allowsContentModifications() }),
        title: unsafe { reminder.title() }.to_string(),
        notes: present(unsafe { reminder.notes() }),
        url: unsafe { reminder.URL() }.and_then(|url| present(url.absoluteString())),
        due: unsafe { reminder.dueDateComponents() }
            .and_then(|components| due_from_components(&components, zone)),
        priority: Priority::from_level(unsafe { reminder.priority() }),
        completed: unsafe { reminder.isCompleted() },
        completed_at: unsafe { reminder.completionDate() }.map(|date| timestamp(&date)),
        recurrence: recurrence(reminder),
        created: unsafe { reminder.creationDate() }.map(|date| timestamp(&date)),
        last_modified: unsafe { reminder.lastModifiedDate() }.map(|date| timestamp(&date)),
    }
}

fn reminder_by_id(store: &EKEventStore, id: &str) -> Option<Retained<EKReminder>> {
    unsafe { store.calendarItemWithIdentifier(&ns(id)) }?
        .downcast::<EKReminder>()
        .ok()
}

/// Replaces the reminder's fixed-time alerts with one at `due`, when it is
/// a time; Reminders alerts through these, not through the due date itself
fn set_due_alarm(reminder: &EKReminder, due: Option<When>) {
    unsafe {
        if let Some(alarms) = reminder.alarms() {
            for alarm in alarms.iter() {
                if alarm.absoluteDate().is_some() {
                    reminder.removeAlarm(&alarm);
                }
            }
        }
        if let Some(When::Time(time)) = due {
            reminder.addAlarm(&EKAlarm::alarmWithAbsoluteDate(&ns_date(time)));
        }
    }
}

impl RemindersBackend for EventKit {
    fn lists(&self) -> Result<Vec<ListInfo>, BackendError> {
        self.run(|store, _| {
            let default = unsafe { store.defaultCalendarForNewReminders() }
                .map(|list| unsafe { list.calendarIdentifier() }.to_string());
            let lists = unsafe { store.calendarsForEntityType(EKEntityType::Reminder) };

            Ok(lists
                .iter()
                .map(|list| {
                    let info = calendar_info(&list, default.as_deref());

                    ListInfo {
                        id: info.id,
                        title: info.title,
                        source: info.source,
                        writable: info.writable,
                        is_default: info.is_default,
                    }
                })
                .collect())
        })
    }

    fn reminders(
        &self,
        query: ReminderQuery,
        list_ids: Option<&[String]>,
    ) -> Result<Vec<ReminderRecord>, BackendError> {
        let list_ids = list_ids.map(<[String]>::to_vec);

        self.run(move |store, zone| {
            let lists = calendars_by_id(store, list_ids.as_deref())?;
            let lists = lists.as_deref();
            let date = |time: Option<Timestamp>| time.map(ns_date);
            let predicate = unsafe {
                match query {
                    ReminderQuery::Incomplete { from, until } => store
                        .predicateForIncompleteRemindersWithDueDateStarting_ending_calendars(
                            date(from).as_deref(),
                            date(until).as_deref(),
                            lists,
                        ),
                    ReminderQuery::Completed { from, until } => store
                        .predicateForCompletedRemindersWithCompletionDateStarting_ending_calendars(
                            date(from).as_deref(),
                            date(until).as_deref(),
                            lists,
                        ),
                    ReminderQuery::All => store.predicateForRemindersInCalendars(lists),
                }
            };

            // the fetch answers on EventKit's own queue; the records are
            // built there, so no EventKit object crosses threads
            let (answer, receiver) = mpsc::sync_channel(1);
            let zone = zone.clone();
            let completion = RcBlock::new(move |reminders: *mut NSArray<EKReminder>| {
                let records = unsafe { reminders.as_ref() }
                    .map(|reminders| {
                        reminders
                            .iter()
                            .map(|reminder| reminder_record(&reminder, &zone))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let _ = answer.try_send(records);
            });
            let fetch = unsafe {
                store.fetchRemindersMatchingPredicate_completion(&predicate, &completion)
            };

            receiver.recv_timeout(FETCH_TIMEOUT).map_err(|_| {
                unsafe { store.cancelFetchRequest(&fetch) };
                BackendError::Failed(format!(
                    "EventKit did not return the reminders within {}s",
                    FETCH_TIMEOUT.as_secs()
                ))
            })
        })
    }

    fn reminder(&self, id: &str) -> Result<Option<ReminderRecord>, BackendError> {
        let id = id.to_owned();

        self.run(move |store, zone| {
            Ok(reminder_by_id(store, &id).map(|reminder| reminder_record(&reminder, zone)))
        })
    }

    fn save_reminder(
        &self,
        id: Option<&str>,
        draft: ReminderDraft,
    ) -> Result<ReminderRecord, BackendError> {
        let id = id.map(str::to_owned);

        self.run(move |store, zone| {
            let reminder = match &id {
                Some(id) => reminder_by_id(store, id)
                    .ok_or_else(|| BackendError::NotFound(format!("no reminder has id {id:?}")))?,
                None => unsafe { EKReminder::reminderWithEventStore(store) },
            };
            let list =
                unsafe { store.calendarWithIdentifier(&ns(&draft.list_id)) }.ok_or_else(|| {
                    BackendError::NotFound(format!("no reminder list has id {:?}", draft.list_id))
                })?;
            let url = ns_url(draft.url.as_deref())?;
            // alerts are only touched when the due date changes, so an alert
            // the owner set by hand survives an unrelated edit
            let due_changed = id.is_none() || reminder_record(&reminder, zone).due != draft.due;

            unsafe {
                reminder.setCalendar(Some(&list));
                reminder.setTitle(Some(&ns(&draft.title)));
                reminder.setNotes(draft.notes.as_deref().map(ns).as_deref());
                reminder.setURL(url.as_deref());
                reminder.setPriority(draft.priority.level());
                if due_changed {
                    let components = draft.due.map(|due| due_components(due, zone));
                    reminder.setDueDateComponents(components.as_deref());
                    set_due_alarm(&reminder, draft.due);
                }
                store
                    .saveReminder_commit_error(&reminder, true)
                    .map_err(|error| ns_failure("save the reminder", &error))?;
            }

            Ok(reminder_record(&reminder, zone))
        })
    }

    fn set_completed(&self, id: &str, completed: bool) -> Result<ReminderRecord, BackendError> {
        let id = id.to_owned();

        self.run(move |store, zone| {
            let reminder = reminder_by_id(store, &id)
                .ok_or_else(|| BackendError::NotFound(format!("no reminder has id {id:?}")))?;

            unsafe {
                reminder.setCompleted(completed);
                store
                    .saveReminder_commit_error(&reminder, true)
                    .map_err(|error| ns_failure("save the reminder", &error))?;
            }

            Ok(reminder_record(&reminder, zone))
        })
    }

    fn remove_reminder(&self, id: &str) -> Result<(), BackendError> {
        let id = id.to_owned();

        self.run(move |store, _| {
            let reminder = reminder_by_id(store, &id)
                .ok_or_else(|| BackendError::NotFound(format!("no reminder has id {id:?}")))?;

            unsafe { store.removeReminder_commit_error(&reminder, true) }
                .map_err(|error| ns_failure("delete the reminder", &error))
        })
    }
}
