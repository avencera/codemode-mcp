//! Asking on the Mac while the owner is at it: Touch ID, escalation to the
//! phone, the review path, and admin requests that stay passkey-only

use std::{sync::Arc, time::Duration};

use codemode_mcp::{approvals::Choice, mac::TouchId};
use serde_json::Value;

use super::harness::{FakeMac, Harness, ORIGIN, Setup, TestResult, approval_id, text_of};

async fn mac_harness(mac: &Arc<FakeMac>) -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    Harness::with(Setup {
        // the summary leaves `b` out, which the prompt must still name
        server: "tools.add.policy = \"ask\"\ntools.add.summary = \"add {a}\"",
        // longer than `execute_wait_secs` (2), so a pending answer comes back
        // before the phone is told
        extra: "[notify.mac]\nescalate_after_secs = 3",
        notify: true,
        mac: Some(Arc::clone(mac)),
        ..Setup::default()
    })
    .await
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
async fn tool_calls_are_asked_on_the_mac_while_the_owner_is_there() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some(harness) = mac_harness(&mac).await? else {
        return Ok(());
    };
    let _passkey = harness.enroll_passkey().await?;
    const ADD: &str = "int(await fixture_add(a=1, b=2))";

    // a fingerprint approves the call once, and the phone never hears of it
    mac.set_present(true);
    mac.set_answer(Some(TouchId::Approved));
    let body = harness.execute_json(ADD).await?;
    assert_eq!(body["result"], 3, "{body}");
    let shown = mac.shown();
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert!(
        shown[0].starts_with("touch_id approve one call of fixture.add by client \""),
        "{shown:?}"
    );
    // a fingerprint approves without the page, so the prompt summarizes the
    // arguments, naming any the tool's summary leaves out
    assert!(shown[0].ends_with(": add 1 (also b)"), "{shown:?}");
    assert!(harness.notifier.tool_requests().is_empty());

    // an unanswered prompt reaches the phone after the delay, and leaves the
    // screen once the request is answered elsewhere
    mac.set_answer(None);
    let pending = harness.execute_body(ADD).await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let message = pending["message"].as_str().unwrap_or_default();
    assert!(message.contains("on this Mac"), "{message}");
    assert!(eventually(|| harness.notifier.tool_requests().len() == 1).await);
    let id = approval_id(&pending)?;
    harness
        .app
        .gateway()
        .approvals()
        .decide(&id, Choice::Once)?;
    let done = harness.wait_done(&execution_id(&pending)).await?;
    assert_eq!(done.is_error, Some(false), "{}", text_of(&done));
    assert!(eventually(|| mac.shown().last().is_some_and(|last| last == "dismissed")).await);

    // pressing Review opens the page here; the phone is told only if the
    // request is still waiting a full delay later
    mac.set_answer(Some(TouchId::Review));
    let pending = harness.execute_body(ADD).await?;
    let id = approval_id(&pending)?;
    assert_eq!(
        mac.shown().last(),
        Some(&format!("open {ORIGIN}/approve/{id}"))
    );
    assert_eq!(harness.notifier.tool_requests().len(), 1);
    assert!(eventually(|| harness.notifier.tool_requests().len() == 2).await);
    harness
        .app
        .gateway()
        .approvals()
        .decide(&id, Choice::Deny)?;
    harness.wait_done(&execution_id(&pending)).await?;

    // a prompt the system takes down (the screen locked) tells the phone at
    // once, and the agent is no longer pointed at the Mac
    mac.set_answer(Some(TouchId::Away));
    let pending = harness.execute_body(ADD).await?;
    let message = pending["message"].as_str().unwrap_or_default();
    assert!(message.contains("on their phone"), "{message}");
    assert_eq!(harness.notifier.tool_requests().len(), 3);
    harness
        .app
        .gateway()
        .approvals()
        .decide(&approval_id(&pending)?, Choice::Deny)?;
    harness.wait_done(&execution_id(&pending)).await?;

    // away from the Mac, the phone is told at once and nothing shows here
    mac.set_present(false);
    let before = mac.shown().len();
    let pending = harness.execute_body(ADD).await?;
    let message = pending["message"].as_str().unwrap_or_default();
    assert!(message.contains("on their phone"), "{message}");
    assert!(eventually(|| harness.notifier.tool_requests().len() == 4).await);
    assert_eq!(mac.shown().len(), before);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_requests_never_offer_touch_id() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some(harness) = mac_harness(&mac).await? else {
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
            .any(|shown| shown.starts_with("touch_id"))
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
