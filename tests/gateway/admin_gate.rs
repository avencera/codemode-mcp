//! Passkey administration behind existing passkeys, and the binding of
//! passkey assertions to one request and one decision

use std::time::Duration;

use codemode_mcp::approvals::Choice;
use serde_json::{Value, json};

use super::harness::{Harness, ORIGIN, Setup, TestResult, approval_id, text_of};

async fn gated_harness() -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    Harness::with(Setup {
        server: "tools.add.policy = \"ask\"",
        notify: true,
        ..Setup::default()
    })
    .await
}

fn path_of(url: &Value) -> Result<String, Box<dyn std::error::Error>> {
    let url = url.as_str().ok_or_else(|| format!("not a url: {url}"))?;

    Ok(url.trim_start_matches(ORIGIN).to_owned())
}

async fn passkey_count(harness: &Harness) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(harness.app.passkeys().store().passkey_count()?)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_passkey_needs_approval_from_the_first() -> TestResult {
    let Some(harness) = gated_harness().await? else {
        return Ok(());
    };

    // two links minted while no passkey exists: once one is used, the other
    // must not add a second passkey without approval
    let (spare, _) = harness.request_enrollment("spare").await?;
    let mut phone = harness.enroll_passkey().await?;
    let stale = harness
        .http
        .get(format!("{}{spare}", harness.base()))
        .send()
        .await?;
    assert_eq!(stale.status().as_u16(), 404);
    let (status, _) = harness
        .post_json(&format!("{spare}/options"), &json!({}))
        .await?;
    assert_eq!(status, 410);
    assert!(
        harness
            .notifier
            .sent()
            .iter()
            .any(|sent| sent.title.contains("first passkey") && sent.click.is_none())
    );

    let (path, enrolled) = harness.request_enrollment("tablet").await?;
    let approval = path_of(&enrolled["approval_url"])?;

    // unusable until approved
    let page = harness
        .http
        .get(format!("{}{path}", harness.base()))
        .send()
        .await?;
    assert_eq!(page.status().as_u16(), 409);
    let (status, body) = harness
        .post_json(&format!("{path}/options"), &json!({}))
        .await?;
    assert_eq!(status, 409, "{body}");

    // the phone hears about it and sees what it would approve
    let id = approval.rsplit('/').next().unwrap_or_default().to_owned();
    assert!(harness.notifier.sent().iter().any(|sent| {
        sent.title.contains("Enroll a new passkey named \"tablet\"")
            && sent.click.as_deref() == Some(&format!("{ORIGIN}{approval}"))
    }));
    let html = harness
        .http
        .get(format!("{}{approval}", harness.base()))
        .send()
        .await?
        .text()
        .await?;
    assert!(
        html.contains("Enroll a new passkey named &quot;tablet&quot;"),
        "{html}"
    );
    // the code the CLI printed is on the page and in the notification
    let code = enrolled["code"].as_str().ok_or("no code")?;
    assert_eq!(code.len(), 6);
    assert!(html.contains(code), "{html}");
    assert!(
        harness
            .notifier
            .sent()
            .iter()
            .any(|sent| sent.message.contains(&format!("Code {code}")))
    );
    let (status, _) = harness
        .admin_json("/admin/enroll", &json!({ "label": "iPhone\" (you asked)" }))
        .await?;
    assert_eq!(status, 400);
    assert!(!html.contains("15 min"), "{html}");
    let (status, _) = harness
        .post_json(
            &format!("/approve/{id}/options"),
            &json!({ "choice": "client15" }),
        )
        .await?;
    assert_eq!(status, 400);

    let (status, body) = harness
        .approve_with_passkey(&mut phone, &id, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    harness.register_at(&path).await?;
    assert_eq!(passkey_count(&harness).await?, 2);

    // a denied request leaves its link dead
    let (path, enrolled) = harness.request_enrollment("intruder").await?;
    let denied = path_of(&enrolled["approval_url"])?;
    let (status, _) = harness
        .post_json(&format!("{denied}/deny"), &json!({}))
        .await?;
    assert_eq!(status, 200);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let page = harness
        .http
        .get(format!("{}{path}", harness.base()))
        .send()
        .await?;
    assert_eq!(page.status().as_u16(), 404);
    assert_eq!(passkey_count(&harness).await?, 2);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_passkey_needs_approval_and_never_the_last() -> TestResult {
    let Some(harness) = gated_harness().await? else {
        return Ok(());
    };
    let mut phone = harness.enroll_passkey().await?;
    let id = harness.app.passkeys().store().list_passkeys()?[0].id;

    let (status, _) = harness
        .admin_json("/admin/passkey/remove", &json!({ "id": id + 100 }))
        .await?;
    assert_eq!(status, 404);

    // the only passkey can't go: first enrollment would reopen
    let (status, body) = harness
        .admin_json("/admin/passkey/remove", &json!({ "id": id }))
        .await?;
    assert_eq!(status, 409, "{body}");
    assert_eq!(passkey_count(&harness).await?, 1);

    // a replacement enrolled with the first passkey's approval
    let (path, enrolled) = harness.request_enrollment("replacement").await?;
    let approval = path_of(&enrolled["approval_url"])?;
    let request = approval.rsplit('/').next().unwrap_or_default().to_owned();
    let (status, body) = harness
        .approve_with_passkey(&mut phone, &request, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    let mut replacement = harness.register_at(&path).await?;
    assert_eq!(passkey_count(&harness).await?, 2);

    // denied: nothing happens
    let (status, body) = harness
        .admin_json("/admin/passkey/remove", &json!({ "id": id }))
        .await?;
    assert_eq!(status, 200, "{body}");
    assert!(
        harness
            .notifier
            .sent()
            .iter()
            .any(|sent| sent.title.contains("Remove the passkey named"))
    );
    let approval = path_of(&body["approval_url"])?;
    let (status, _) = harness
        .post_json(&format!("{approval}/deny"), &json!({}))
        .await?;
    assert_eq!(status, 200);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(passkey_count(&harness).await?, 2);

    // approved by the replacement: the first one goes
    let (_, body) = harness
        .admin_json("/admin/passkey/remove", &json!({ "id": id }))
        .await?;
    let approval = path_of(&body["approval_url"])?;
    let request = approval.rsplit('/').next().unwrap_or_default().to_owned();
    let (status, body) = harness
        .approve_with_passkey(&mut replacement, &request, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    for _ in 0..50 {
        if passkey_count(&harness).await? == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(passkey_count(&harness).await?, 1);

    // and now the replacement is the last one
    let last = harness.app.passkeys().store().list_passkeys()?[0].id;
    let (status, _) = harness
        .admin_json("/admin/passkey/remove", &json!({ "id": last }))
        .await?;
    assert_eq!(status, 409);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn assertions_approve_one_request_once_and_grants_stay_with_their_client() -> TestResult {
    let Some(harness) = gated_harness().await? else {
        return Ok(());
    };
    let mut phone = harness.enroll_passkey().await?;
    let first = harness
        .execute_body("int(await fixture_add(a=1, b=2))")
        .await?;
    let second = harness
        .execute_body("int(await fixture_add(a=5, b=5))")
        .await?;
    let (a, b) = (approval_id(&first)?, approval_id(&second)?);

    // an assertion started for `a` cannot approve `b`, and is used up
    let (status, started) = harness
        .post_json(
            &format!("/approve/{a}/options"),
            &json!({ "choice": "once" }),
        )
        .await?;
    assert_eq!(status, 200, "{started}");
    let options = serde_json::from_value(started["options"].clone())?;
    let credential = phone
        .do_authentication(webauthn_rs::prelude::Url::parse(ORIGIN)?, options)
        .map_err(|error| format!("assertion failed: {error:?}"))?;
    let confirm = json!({ "ceremony": started["ceremony"], "credential": credential });
    let (status, _) = harness
        .post_json(&format!("/approve/{b}/confirm"), &confirm)
        .await?;
    assert_eq!(status, 403);
    let (status, _) = harness
        .post_json(&format!("/approve/{a}/confirm"), &confirm)
        .await?;
    assert_eq!(status, 410);
    assert!(harness.app.approvals().info(&a).is_some());
    assert!(harness.app.approvals().info(&b).is_some());

    // a grant covers a second connection of the same client but not another
    // client
    harness
        .app
        .approvals()
        .decide(&a, Choice::Client(Duration::from_secs(15 * 60)))?;
    let same = harness.second_client().await?;
    let covered = super::harness::execute(&same, "int(await fixture_add(a=2, b=2))").await?;
    let covered: Value = serde_json::from_str(&text_of(&covered))?;
    assert_eq!(covered["result"], 4, "{covered}");
    same.cancel().await?;
    let other = harness.client_as("someone-else/2").await?;
    let pending = super::harness::execute(&other, "int(await fixture_add(a=3, b=3))").await?;
    let pending: Value = serde_json::from_str(&text_of(&pending))?;
    assert_eq!(pending["status"], "pending", "{pending}");
    other.cancel().await?;

    // decided requests cannot be decided again
    assert!(harness.app.approvals().decide(&a, Choice::Once).is_err());

    harness.stop().await
}
