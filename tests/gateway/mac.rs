//! Asking on the Mac while the owner is at it: a Touch ID prompt naming the
//! agent's thread and reason whose fingerprint grants 60 minutes, the page
//! behind its other button, escalation to the phone, and admin requests
//! that stay passkey-only

use std::{sync::Arc, time::Duration};

use codemode_mcp::{approvals::Choice, mac::TouchId};
use serde_json::{Value, json};

use super::harness::{FakeMac, Harness, ORIGIN, Setup, TestResult, approval_id, call, text_of};

const ADD: &str = "int(await fixture_add(a=1, b=2))";
/// A tool that asks on every call, so a fingerprint approves it once
const PER_CALL: &str = "await fixture_json_text()";

/// A harness whose `add` tool asks, and whose phone is told after
/// `escalate_after_secs`; that must outlast `execute_wait_secs` (2), so a
/// pending answer comes back before the phone is told
async fn mac_harness(
    mac: &Arc<FakeMac>,
    escalate_after_secs: u64,
) -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    let extra = format!("[notify.mac]\nescalate_after_secs = {escalate_after_secs}");
    Harness::with(Setup {
        server: "tools.add.policy = \"ask\"\n\
                 tools.json_text.policy = \"ask\"\n\
                 tools.json_text.grant = \"per_call\"",
        extra: &extra,
        notify: true,
        mac: Some(Arc::clone(mac)),
        ..Setup::default()
    })
    .await
}

/// Runs `code` the way an agent would, with a thread title, a reason and
/// the session from its last answer
async fn execute(
    harness: &Harness,
    code: &str,
    session: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut arguments = json!({
        "code": code,
        // a direction override, which neither the prompt nor the page shows
        "thread": "Fix login\u{202e} redirect",
        "reason": "add two numbers",
    });
    if let Some(session) = session {
        arguments["session"] = json!(session);
    }

    Ok(serde_json::from_str(&text_of(
        &call(&harness.client, "execute", arguments).await?,
    ))?)
}

/// Polls `check` for up to five seconds
async fn eventually(check: impl Fn() -> bool) -> bool {
    for _ in 0..50 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    check()
}

fn execution_id(pending: &Value) -> String {
    pending["execution_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fingerprint_at_the_mac_grants_the_session_an_hour() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some(harness) = mac_harness(&mac, 3).await? else {
        return Ok(());
    };
    let _passkey = harness.enroll_passkey().await?;

    // the prompt names the grant, then the agent's thread and reason
    mac.set_present(true);
    mac.set_answer(Some(TouchId::Approved));
    let body = execute(&harness, ADD, None).await?;
    assert_eq!(body["result"], 3, "{body}");
    let shown = mac.shown();
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert!(
        shown[0].starts_with(
            "touch_id approve fixture.add and all fixture tools not marked per-call, for 60 min, asked by \""
        ),
        "{shown:?}"
    );
    assert!(
        shown[0].ends_with(r#" in "Fix login? redirect": "add two numbers""#),
        "{shown:?}"
    );

    // the session's next call runs without asking anywhere
    mac.set_answer(None);
    let session = body["session"].as_str().unwrap_or_default().to_owned();
    let again = execute(&harness, ADD, Some(&session)).await?;
    assert_eq!(again["result"], 3, "{again}");
    assert_eq!(mac.shown().len(), 1);

    // a tool that asks on every call is approved once, inside the grant too
    mac.set_answer(Some(TouchId::Approved));
    let body = execute(&harness, PER_CALL, Some(&session)).await?;
    assert_eq!(body["result"], json!([1, 2, {"k": "v"}]), "{body}");
    let shown = mac.shown();
    assert!(
        shown[1].starts_with("touch_id approve fixture.json_text once, asked by \""),
        "{shown:?}"
    );
    execute(&harness, PER_CALL, Some(&session)).await?;
    assert_eq!(mac.shown().len(), 3);
    assert!(harness.notifier.tool_requests().is_empty());

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn unanswered_or_reviewed_prompts_reach_the_phone() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some(harness) = mac_harness(&mac, 3).await? else {
        return Ok(());
    };
    let _passkey = harness.enroll_passkey().await?;
    let approvals = harness.app.gateway().approvals();
    mac.set_present(true);

    // an unanswered prompt reaches the phone after the delay, and leaves
    // the screen once the request is answered elsewhere
    mac.set_answer(None);
    let pending = execute(&harness, ADD, None).await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let message = pending["message"].as_str().unwrap_or_default();
    assert!(message.contains("on this Mac"), "{message}");
    let id = approval_id(&pending)?;
    // the page shows the agent's words, labelled as its own
    let html = harness
        .http
        .get(format!("{}/approve/{id}", harness.base()))
        .send()
        .await?
        .text()
        .await?;
    assert!(
        html.contains("Thread: Fix login? redirect<br>Reason: add two numbers"),
        "{html}"
    );
    assert!(eventually(|| harness.notifier.tool_requests().len() == 1).await);
    approvals.decide(&id, Choice::Once)?;
    let done = harness.wait_done(&execution_id(&pending)).await?;
    assert_eq!(done.is_error, Some(false), "{}", text_of(&done));
    assert!(eventually(|| mac.shown().last().is_some_and(|last| last == "dismissed")).await);

    // Open Page, pressed just before the delay runs out, opens the page
    // here; the phone is told only if the request is still waiting a full
    // delay after that
    mac.set_answer(Some(TouchId::Review));
    mac.set_answer_after(Duration::from_millis(2500));
    let pending = execute(&harness, ADD, None).await?;
    let id = approval_id(&pending)?;
    assert!(
        eventually(|| mac.shown().last() == Some(&format!("open {ORIGIN}/approve/{id}"))).await
    );
    // past the first deadline, and short of the restarted one
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(harness.notifier.tool_requests().len(), 1);
    assert!(eventually(|| harness.notifier.tool_requests().len() == 2).await);
    mac.set_answer_after(Duration::ZERO);
    approvals.decide(&id, Choice::Deny)?;
    harness.wait_done(&execution_id(&pending)).await?;

    // away from the Mac, the phone is told at once and nothing shows here
    mac.set_present(false);
    let before = mac.shown().len();
    let pending = execute(&harness, ADD, None).await?;
    let message = pending["message"].as_str().unwrap_or_default();
    assert!(message.contains("on their phone"), "{message}");
    assert!(eventually(|| harness.notifier.tool_requests().len() == 3).await);
    assert_eq!(mac.shown().len(), before);
    approvals.decide(&approval_id(&pending)?, Choice::Deny)?;
    harness.wait_done(&execution_id(&pending)).await?;

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn leaving_the_mac_tells_the_phone_without_waiting() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    // a delay no test waits out, so only leaving can tell the phone
    let Some(harness) = mac_harness(&mac, 600).await? else {
        return Ok(());
    };
    let _passkey = harness.enroll_passkey().await?;
    let approvals = harness.app.gateway().approvals();

    // a prompt the system takes down (the screen locked) tells the phone at
    // once, and the agent is no longer pointed at the Mac
    mac.set_present(true);
    mac.set_answer(Some(TouchId::Away));
    let pending = execute(&harness, ADD, None).await?;
    let message = pending["message"].as_str().unwrap_or_default();
    assert!(message.contains("on their phone"), "{message}");
    assert_eq!(harness.notifier.tool_requests().len(), 1);
    approvals.decide(&approval_id(&pending)?, Choice::Deny)?;
    harness.wait_done(&execution_id(&pending)).await?;

    // so does walking away while the prompt is still up
    mac.set_answer(None);
    let pending = execute(&harness, ADD, None).await?;
    let id = approval_id(&pending)?;
    assert!(approvals.asked_on_mac(&id));
    mac.set_present(false);
    assert!(eventually(|| harness.notifier.tool_requests().len() == 2).await);
    assert!(!approvals.asked_on_mac(&id));
    approvals.decide(&id, Choice::Deny)?;
    harness.wait_done(&execution_id(&pending)).await?;

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_requests_never_offer_touch_id() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some(harness) = mac_harness(&mac, 3).await? else {
        return Ok(());
    };
    let _passkey = harness.enroll_passkey().await?;
    mac.set_present(true);
    mac.set_answer(Some(TouchId::Approved));

    // adding a passkey takes an existing passkey, so the Mac only points at
    // the page, and the phone is told at once in case the owner did not ask
    let (_, enrolled) = harness.request_enrollment("tablet").await?;
    assert!(enrolled["approval_url"].is_string(), "{enrolled}");
    assert!(
        eventually(|| mac
            .shown()
            .iter()
            .any(|shown| shown.starts_with("notify codemode: ")))
        .await
    );
    assert!(
        !mac.shown()
            .iter()
            .any(|shown| shown.starts_with("touch_id") || shown.starts_with("open "))
    );
    assert!(
        eventually(|| harness
            .notifier
            .sent()
            .iter()
            .any(|sent| sent.title.contains("tablet")))
        .await
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn one_fingerprint_approves_per_call_calls_started_together() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some(harness) = Harness::with(Setup {
        server: "tools.add.policy = \"ask\"\n\
                 tools.add.grant = \"per_call\"",
        extra: "[notify.mac]\nescalate_after_secs = 3",
        notify: true,
        mac: Some(Arc::clone(&mac)),
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let _passkey = harness.enroll_passkey().await?;
    mac.set_present(true);
    mac.set_answer(Some(TouchId::Approved));

    let body = execute(
        &harness,
        "import asyncio\n\
         sums = await asyncio.gather(fixture_add(a=1, b=2), fixture_add(a=3, b=4), fixture_add(a=5, b=6))\n\
         [int(total) for total in sums]",
        None,
    )
    .await?;
    assert_eq!(body["result"], json!([3, 7, 11]), "{body}");
    let shown = mac.shown();
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert!(
        shown[0].starts_with("touch_id approve fixture.add ×3 once, asked by \""),
        "{shown:?}"
    );
    assert!(harness.notifier.tool_requests().is_empty());

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_needs_the_owner_here_is_refused_at_once_while_they_are_away() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some(harness) = Harness::with(Setup {
        server: "policy = \"ask\"\nneeds_owner_here = true",
        notify: true,
        mac: Some(Arc::clone(&mac)),
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    harness.enroll_passkey().await?;

    // away: refused without a prompt, a push or an approval to wait on
    let away = text_of(
        &call(
            &harness.client,
            "execute",
            json!({ "code": ADD, "reason": "add two numbers" }),
        )
        .await?,
    );
    assert!(away.contains("codemode-mcp op inject"), "{away}");
    assert!(!away.contains("approval_url"), "{away}");
    assert!(mac.shown().is_empty());
    assert!(harness.notifier.tool_requests().is_empty());

    // at the Mac the call is asked for as usual
    mac.set_present(true);
    mac.set_answer(Some(TouchId::Approved));
    let here = text_of(
        &call(
            &harness.client,
            "execute",
            json!({ "code": ADD, "reason": "add two numbers" }),
        )
        .await?,
    );
    assert!(here.contains("\"result\":3"), "{here}");

    harness.stop().await
}
