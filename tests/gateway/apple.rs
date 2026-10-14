//! The calendar and reminders adapters behind the gateway, driven by real
//! scripts against an in-memory store in place of EventKit
//!
//! Times are checked in America/Chicago, which the fake's environment sets,
//! so local text such as `2026-10-15T12:00` has one meaning

use std::{error::Error, time::Duration};

use codemode_mcp::approvals::Choice;
use serde_json::{Value, json};

use super::harness::{Harness, Setup, TestResult, approval_id, call, text_of};

/// Write tools that ask, as in the starter config
const WRITES: [(&str, &[&str]); 2] = [
    (
        "calendar",
        &["create_event", "update_event", "delete_event"],
    ),
    (
        "reminders",
        &[
            "create_reminder",
            "update_reminder",
            "complete_reminder",
            "delete_reminder",
        ],
    ),
];

/// Catches a tool error as its text, so one script can try many calls
const ATTEMPT: &str = r#"async def attempt(call) -> str:
    try:
        await call
        return "ok"
    except Exception as error:
        return str(error)
"#;

fn servers() -> String {
    let mut config = String::new();
    for (server, tools) in WRITES {
        config.push_str(&format!(
            "[servers.{server}]\n\
             command = \"{fake}\"\n\
             args = [\"{server}\"]\n\
             env = {{ TZ = \"America/Chicago\" }}\n\
             sensitive = false\n",
            fake = env!("CARGO_BIN_EXE_codemode-fake-eventkit"),
        ));
        for tool in tools {
            config.push_str(&format!(
                "[servers.{server}.tools.{tool}]\npolicy = \"ask\"\n"
            ));
        }
    }

    config
}

/// A gateway with both adapters and a passkey, which approvals need
async fn harness() -> Result<Option<Harness>, Box<dyn Error>> {
    let extra = servers();
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        notify: true,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(None);
    };
    harness.enroll_passkey().await?;

    Ok(Some(harness))
}

/// Runs a script, approving each pending write with a session grant, and
/// returns its result and how many approvals it took
async fn run_approving(harness: &Harness, script: &str) -> Result<(Value, usize), Box<dyn Error>> {
    let mut body = harness.execute_body(script).await?;
    let mut approvals = 0;

    while body["status"] == "pending" {
        harness.app.approvals().decide(
            &approval_id(&body)?,
            Choice::Session(Duration::from_secs(900)),
        )?;
        approvals += 1;
        if approvals > 10 {
            return Err(format!("still pending after {approvals} approvals: {body}").into());
        }

        let execution = body["execution_id"]
            .as_str()
            .ok_or("no execution_id")?
            .to_owned();
        let result = call(
            &harness.client,
            "wait",
            json!({ "execution_id": execution }),
        )
        .await?;
        body = serde_json::from_str(&text_of(&result))?;
    }
    assert!(body.get("result").is_some(), "{body}");

    Ok((body["result"].clone(), approvals))
}

fn titles(listed: &Value, key: &str) -> Vec<String> {
    listed[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["title"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn calendar_reads_and_guarded_writes() -> TestResult {
    let Some(harness) = harness().await? else {
        return Ok(());
    };

    // reads run without an approval
    let body = harness
        .execute_json(
            r#"import asyncio
calendars, listed, dentist = await asyncio.gather(
    calendar_list_calendars(),
    calendar_list_events(start="2026-10-12", end="2026-10-14"),
    calendar_get_event(id="ev-dentist"),
)
[calendars, listed, dentist]"#,
        )
        .await?;
    let [calendars, listed, dentist] = body["result"].as_array().ok_or("no result")?.as_slice()
    else {
        return Err(format!("unexpected result {body}").into());
    };
    assert_eq!(calendars["calendars"][0]["is_default"], true, "{calendars}");
    assert_eq!(calendars["calendars"][1]["writable"], false, "{calendars}");

    assert_eq!(listed["time_zone"], "America/Chicago", "{listed}");
    assert_eq!(
        titles(listed, "events"),
        ["Columbus Day", "Standup", "Dentist"]
    );
    let events = &listed["events"];
    // an all-day event shows its days, whatever moment the store keeps
    assert_eq!(events[0]["start"], "2026-10-12", "{listed}");
    assert_eq!(events[0]["end"], "2026-10-12", "{listed}");
    assert_eq!(events[0]["editable"], false, "{listed}");
    assert_eq!(events[1]["recurring"], true, "{listed}");
    assert_eq!(events[1]["editable"], true, "{listed}");
    assert_eq!(
        events[1]["occurrence"], "2026-10-13T08:30:00-05:00",
        "{listed}"
    );
    assert!(events[2].get("occurrence").is_none(), "{listed}");
    assert_eq!(events[2]["start"], "2026-10-14T09:00:00-05:00", "{listed}");
    // details stay out of the list
    assert!(events[2].get("notes").is_none(), "{listed}");
    assert_eq!(events[2]["location"], "12 Main St", "{listed}");

    assert_eq!(dentist["notes"], "Bring the insurance card", "{dentist}");
    assert_eq!(dentist["availability"], "busy", "{dentist}");
    assert_eq!(
        dentist["last_modified"], "2026-10-01T12:00:00.250Z",
        "{dentist}"
    );

    let script = format!(
        r#"{ATTEMPT}
created = await calendar_create_event(
    title="Lunch", start="2026-10-15T12:00", end="2026-10-15T13:00", location="Cafe",
)
trip = await calendar_create_event(title="Trip", start="2026-10-20", end="2026-10-22")
moved = await calendar_update_event(
    id=created["id"], last_modified=created.get("last_modified"),
    start="2026-10-15T12:30", end="2026-10-15T13:30", clear=["location"],
)
errors = [
    await attempt(calendar_update_event(
        id=created["id"], last_modified=created.get("last_modified"), title="Late lunch",
    )),
    await attempt(calendar_delete_event(id="ev-standup", last_modified="2026-10-01T12:00:00.250Z")),
    await attempt(calendar_delete_event(id="ev-holiday", last_modified="2026-10-01T12:00:00.250Z")),
    await attempt(calendar_create_event(title="Bad", start="2026-10-15", end="2026-10-15T10:00")),
    await attempt(calendar_update_event(
        id="ev-dentist", last_modified="2026-10-01T12:00:00.250Z", start="2026-10-14",
    )),
    await attempt(calendar_create_event(title="Bad", start="2026-10-15T10:00", end="2026-10-15T09:00")),
    await attempt(calendar_update_event(
        id="ev-dentist", last_modified="2026-10-01T12:00:00.250Z", start="2026-10-14T11:00",
    )),
]
retitled = await calendar_update_event(
    id="ev-dentist", last_modified="2026-10-01T12:00:00.250Z", title="Dentist checkup", notes="",
)
deleted = await calendar_delete_event(id=created["id"], last_modified=moved.get("last_modified"))
remaining = await calendar_list_events(start="2026-10-15", end="2026-10-22")
[created, trip, moved, errors, retitled, deleted, remaining]"#
    );
    let (result, approvals) = run_approving(&harness, &script).await?;
    assert!(approvals >= 1, "writes ran without an approval");
    let [created, trip, moved, errors, retitled, deleted, remaining] =
        result.as_array().ok_or("no result")?.as_slice()
    else {
        return Err(format!("unexpected result {result}").into());
    };

    assert_eq!(created["start"], "2026-10-15T12:00:00-05:00", "{created}");
    assert_eq!(created["end"], "2026-10-15T13:00:00-05:00", "{created}");
    assert_eq!(created["calendar"], "Home", "{created}");
    assert_eq!(created["location"], "Cafe", "{created}");
    assert_eq!(created["editable"], true, "{created}");

    assert_eq!(trip["all_day"], true, "{trip}");
    assert_eq!(trip["start"], "2026-10-20", "{trip}");
    assert_eq!(trip["end"], "2026-10-22", "{trip}");

    assert_eq!(moved["start"], "2026-10-15T12:30:00-05:00", "{moved}");
    assert_eq!(moved["title"], "Lunch", "{moved}");
    assert!(moved.get("location").is_none(), "{moved}");

    let errors: Vec<&str> = errors
        .as_array()
        .ok_or("no errors")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(errors.len(), 7, "{errors:?}");
    assert!(
        errors[0].contains("changed since you read it"),
        "{errors:?}"
    );
    assert!(errors[1].contains("pass the `occurrence`"), "{errors:?}");
    assert!(
        errors[2].contains("\"US Holidays\" is read-only"),
        "{errors:?}"
    );
    assert!(errors[3].contains("both be dates"), "{errors:?}");
    assert!(
        errors[4].contains("pass both `start` and `end`"),
        "{errors:?}"
    );
    assert!(errors[5].contains("must be after"), "{errors:?}");
    // a start moved past the end is not a switch between all-day and timed
    assert!(errors[6].contains("must be after"), "{errors:?}");
    assert!(!errors[6].contains("pass both"), "{errors:?}");

    // a partial update keeps the times it was not given, and "" clears
    assert_eq!(retitled["title"], "Dentist checkup", "{retitled}");
    assert_eq!(retitled["start"], "2026-10-14T09:00:00-05:00", "{retitled}");
    assert_eq!(retitled["end"], "2026-10-14T10:00:00-05:00", "{retitled}");
    assert!(retitled.get("notes").is_none(), "{retitled}");
    assert_eq!(retitled["location"], "12 Main St", "{retitled}");

    assert_eq!(deleted["id"], created["id"], "{deleted}");
    // the weekly standup's next occurrence falls in the window too
    assert_eq!(titles(remaining, "events"), ["Trip", "Standup"]);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn repeating_events_change_one_occurrence_or_the_rest() -> TestResult {
    let Some(harness) = harness().await? else {
        return Ok(());
    };

    // the standup repeats weekly from Tuesday 2026-10-13 08:30 local
    let script = format!(
        r#"{ATTEMPT}
listed = await calendar_list_events(start="2026-10-13", end="2026-10-27")
standups = [e for e in listed["events"] if e["title"] == "Standup"]
second = standups[1]
moved = await calendar_update_event(
    id="ev-standup", occurrence=second.get("occurrence"), last_modified=second.get("last_modified"),
    start="2026-10-20T10:00", end="2026-10-20T10:15",
)
fetched = await calendar_get_event(id="ev-standup", occurrence=second.get("occurrence"))
# a changed occurrence has its own id, which names it without `occurrence`
by_own_id = await calendar_get_event(id=moved["id"])
renotes = await calendar_update_event(
    id=moved["id"], occurrence=moved.get("occurrence"), last_modified=moved.get("last_modified"),
    notes="moved for the offsite",
)
skipped = await calendar_delete_event(
    id="ev-standup", occurrence=standups[2].get("occurrence"),
    last_modified=standups[2].get("last_modified"),
)
# deleting an occurrence changes the series, so tokens read before it are stale
stale = await attempt(calendar_update_event(
    id="ev-standup", occurrence="2026-11-03T08:30", and_future=True,
    last_modified=standups[0].get("last_modified"), title="Sync",
))
relisted = await calendar_list_events(start="2026-11-03", end="2026-11-03")
renamed = await calendar_update_event(
    id="ev-standup", occurrence="2026-11-03T08:30", and_future=True,
    last_modified=relisted["events"][0].get("last_modified"), title="Sync",
)
first = await calendar_list_events(start="2026-10-13", end="2026-10-13")
first_token = first["events"][0].get("last_modified")
errors = [
    await attempt(calendar_update_event(
        id="ev-standup", last_modified="2026-10-01T12:00:00.250Z", title="x",
    )),
    await attempt(calendar_update_event(
        id="ev-dentist", occurrence="2026-10-14T09:00", last_modified="2026-10-01T12:00:00.250Z",
        title="x",
    )),
    await attempt(calendar_delete_event(
        id="ev-dentist", and_future=True, last_modified="2026-10-01T12:00:00.250Z",
    )),
    await attempt(calendar_update_event(
        id="ev-standup", occurrence="2026-10-14T08:30", last_modified="2026-10-01T12:00:00.250Z",
        title="x",
    )),
    await attempt(calendar_update_event(
        id="ev-standup", occurrence="2026-10-13T08:30", last_modified=first_token,
        calendar_id="cal-holidays", title="x",
    )),
    await attempt(calendar_get_event(id="ev-nope", occurrence="2026-10-13T08:30")),
    await attempt(calendar_get_event(id="ev-standup", occurrence="2026-10-14T08:30")),
]
same_calendar = await calendar_update_event(
    id="ev-standup", occurrence="2026-10-13T08:30", last_modified=first_token,
    calendar_id="cal-home", title="Standup",
)
after = await calendar_list_events(start="2026-10-13", end="2026-11-10")
[moved, fetched, skipped, renamed, errors, [[e["title"], e["start"]] for e in after["events"] if e["title"] != "Dentist"], by_own_id, renotes, stale, same_calendar]"#
    );
    let (result, _) = run_approving(&harness, &script).await?;
    let [
        moved,
        fetched,
        skipped,
        renamed,
        errors,
        after,
        by_own_id,
        renotes,
        stale,
        same_calendar,
    ] = result.as_array().ok_or("no result")?.as_slice()
    else {
        return Err(format!("unexpected result {result}").into());
    };

    // one occurrence moved keeps its name in the series
    assert_eq!(moved["start"], "2026-10-20T10:00:00-05:00", "{moved}");
    assert_eq!(moved["occurrence"], "2026-10-20T08:30:00-05:00", "{moved}");
    assert_eq!(moved["recurring"], true, "{moved}");
    assert_eq!(fetched["start"], "2026-10-20T10:00:00-05:00", "{fetched}");
    assert!(
        moved["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ev-standup/RID=")),
        "{moved}"
    );
    assert_eq!(
        by_own_id["start"], "2026-10-20T10:00:00-05:00",
        "{by_own_id}"
    );
    assert_eq!(renotes["notes"], "moved for the offsite", "{renotes}");
    assert_eq!(renotes["start"], "2026-10-20T10:00:00-05:00", "{renotes}");
    assert!(
        stale
            .as_str()
            .is_some_and(|text| text.contains("changed since you read it")),
        "{stale}"
    );
    assert_eq!(same_calendar["calendar"], "Home", "{same_calendar}");
    assert_eq!(
        skipped["occurrence"], "2026-10-27T08:30:00-05:00",
        "{skipped}"
    );
    assert_eq!(renamed["title"], "Sync", "{renamed}");
    assert_eq!(renamed["start"], "2026-11-03T08:30:00-06:00", "{renamed}");

    let errors: Vec<&str> = errors
        .as_array()
        .ok_or("no errors")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(errors.len(), 7, "{errors:?}");
    assert!(errors[0].contains("pass the `occurrence`"), "{errors:?}");
    assert!(errors[1].contains("does not repeat"), "{errors:?}");
    assert!(
        errors[2].contains("`and_future` needs `occurrence`"),
        "{errors:?}"
    );
    assert!(errors[3].contains("no occurrence"), "{errors:?}");
    assert!(
        errors[4].contains("changes calendar as a whole"),
        "{errors:?}"
    );
    assert!(
        errors[5].contains("no event has id \"ev-nope\""),
        "{errors:?}"
    );
    assert!(errors[6].contains("no occurrence"), "{errors:?}");

    // the 27th is gone, the 20th moved, and the series is renamed from Nov 3
    assert_eq!(
        after,
        &json!([
            ["Standup", "2026-10-13T08:30:00-05:00"],
            ["Standup", "2026-10-20T10:00:00-05:00"],
            // local time holds across the end of daylight saving on Nov 1
            ["Sync", "2026-11-03T08:30:00-06:00"],
            ["Sync", "2026-11-10T08:30:00-06:00"],
        ]),
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn reminders_reads_filters_and_guarded_writes() -> TestResult {
    let Some(harness) = harness().await? else {
        return Ok(());
    };

    let script = format!(
        r#"import asyncio
{ATTEMPT}
lists, still_open, due_soon, done, everything, milk = await asyncio.gather(
    reminders_list_reminder_lists(),
    reminders_list_reminders(),
    reminders_list_reminders(due_until="2026-10-14"),
    reminders_list_reminders(status="completed"),
    reminders_list_reminders(status="all", limit=2),
    reminders_get_reminder(id="rem-milk"),
)
mixed = await attempt(reminders_list_reminders(status="completed", due_from="2026-10-14"))
[lists, still_open, due_soon, done, everything, milk, mixed]"#
    );
    let body = harness.execute_json(&script).await?;
    let [lists, still_open, due_soon, done, everything, milk, mixed] =
        body["result"].as_array().ok_or("no result")?.as_slice()
    else {
        return Err(format!("unexpected result {body}").into());
    };
    assert_eq!(lists["lists"][0]["is_default"], true, "{lists}");

    // by due date, undated last
    assert_eq!(
        titles(still_open, "reminders"),
        ["Call the plumber", "Milk", "Fix the gate", "Team offsite"]
    );
    let open = &still_open["reminders"];
    assert_eq!(open[0]["due"], "2026-10-14T18:00:00-05:00", "{still_open}");
    assert_eq!(open[1]["due"], "2026-10-15", "{still_open}");
    assert_eq!(open[1]["priority"], "high", "{still_open}");
    let preview = open[1]["notes"].as_str().ok_or("no notes")?;
    assert_eq!(preview.chars().count(), 201, "{preview}");
    assert!(preview.ends_with('…'), "{preview}");
    assert_eq!(open[3]["editable"], false, "{still_open}");
    assert_eq!(still_open["truncated"], false, "{still_open}");

    assert_eq!(titles(due_soon, "reminders"), ["Call the plumber"]);
    assert_eq!(titles(done, "reminders"), ["Eggs"]);
    assert_eq!(
        done["reminders"][0]["completed_at"], "2026-10-13T12:00:00-05:00",
        "{done}"
    );
    assert_eq!(everything["reminders"].as_array().map(Vec::len), Some(2));
    assert_eq!(everything["truncated"], true, "{everything}");
    assert_eq!(milk["notes"].as_str().map(str::len), Some(250), "{milk}");
    assert!(
        mixed
            .as_str()
            .is_some_and(|text| text.contains("need status `incomplete`")),
        "{mixed}"
    );

    let script = format!(
        r#"{ATTEMPT}
created = await reminders_create_reminder(title="Bread", due="2026-10-16T09:00", priority="medium")
completed = await reminders_complete_reminder(id=created["id"])
reopened = await reminders_complete_reminder(id=created["id"], completed=False)
updated = await reminders_update_reminder(
    id="rem-milk", last_modified="2026-10-01T12:00:00.250Z", clear=["due"], notes="2%",
)
errors = [
    await attempt(reminders_update_reminder(
        id="rem-milk", last_modified="2026-10-01T12:00:00.250Z", title="Oat milk",
    )),
    await attempt(reminders_complete_reminder(id="rem-locked")),
    await attempt(reminders_create_reminder(title="Y", list_id="list-shared")),
    await attempt(reminders_create_reminder(title="Z", due="next week")),
]
deleted = await reminders_delete_reminder(id=created["id"], last_modified=reopened.get("last_modified"))
[created, completed, reopened, updated, errors, deleted]"#
    );
    let (result, approvals) = run_approving(&harness, &script).await?;
    assert!(approvals >= 1, "writes ran without an approval");
    let [created, completed, reopened, updated, errors, deleted] =
        result.as_array().ok_or("no result")?.as_slice()
    else {
        return Err(format!("unexpected result {result}").into());
    };

    assert_eq!(created["list"], "Groceries", "{created}");
    assert_eq!(created["due"], "2026-10-16T09:00:00-05:00", "{created}");
    assert_eq!(created["priority"], "medium", "{created}");
    assert_eq!(completed["completed"], true, "{completed}");
    assert!(completed.get("completed_at").is_some(), "{completed}");
    assert_eq!(reopened["completed"], false, "{reopened}");
    assert!(reopened.get("completed_at").is_none(), "{reopened}");

    assert!(updated.get("due").is_none(), "{updated}");
    assert_eq!(updated["notes"], "2%", "{updated}");
    assert_eq!(updated["priority"], "high", "{updated}");

    let errors: Vec<&str> = errors
        .as_array()
        .ok_or("no errors")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(errors.len(), 4, "{errors:?}");
    assert!(
        errors[0].contains("changed since you read it"),
        "{errors:?}"
    );
    assert!(errors[1].contains("\"Shared\" is read-only"), "{errors:?}");
    assert!(errors[2].contains("\"Shared\" is read-only"), "{errors:?}");
    assert!(errors[3].contains("must be a date"), "{errors:?}");
    assert_eq!(deleted["id"], created["id"], "{deleted}");

    harness.stop().await
}
