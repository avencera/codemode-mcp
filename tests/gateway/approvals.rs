//! Approval flow end to end: notification, passkey page, grants, denial,
//! expiry, budget pause and the worker release while waiting

use std::time::Duration;

use axum::{
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::{Request, StatusCode},
};
use codemode_mcp::{
    admin,
    approvals::{Choice, NO_PASSKEY},
};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::harness::{
    DEFAULT_CLIENT, Harness, ORIGIN, Setup, TestResult, approval_id, execute, text_of,
};

/// `add` asks with session grants; `json_text` asks on every call
const ASK_TOOLS: &str = "tools.add.policy = \"ask\"\n\
                         tools.json_text.policy = \"ask\"\n\
                         tools.json_text.grant = \"per_call\"";

async fn approval_harness(
    limits: &str,
    extra: &str,
) -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    Harness::with(Setup {
        limits,
        server: ASK_TOOLS,
        extra,
        notify: true,
        ..Setup::default()
    })
    .await
}

fn execution_id(pending: &Value) -> String {
    pending["execution_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn approve_once_through_the_passkey_page() -> TestResult {
    let Some(harness) = approval_harness("", "").await? else {
        return Ok(());
    };
    let mut passkey = harness.enroll_passkey().await?;

    let pending = harness
        .execute_body("# <script>alert(1)</script>\nint(await fixture_add(a=1, b=2))")
        .await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    assert_eq!(pending["waiting_for"], "fixture_add", "{pending}");
    let id = approval_id(&pending)?;
    assert_eq!(
        pending["approval_url"],
        format!("{ORIGIN}/approve/{id}"),
        "{pending}"
    );

    // the notification names the client and tool, and nothing else
    let sent = harness.notifier.tool_requests();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].title.starts_with("codemode: "), "{}", sent[0].title);
    assert!(
        sent[0].title.ends_with(" wants fixture.add"),
        "{}",
        sent[0].title
    );
    assert_eq!(sent[0].click, Some(format!("{ORIGIN}/approve/{id}")));
    assert!(!sent[0].message.contains("\"a\""), "{}", sent[0].message);

    let page = harness
        .http
        .get(format!("{}/approve/{id}", harness.base()))
        .send()
        .await?;
    assert_eq!(page.status().as_u16(), 200);
    let html = page.text().await?;
    assert!(html.contains("Approve once"), "{html}");
    assert!(
        html.contains(&format!("Approve {DEFAULT_CLIENT} for 15 min")),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="key">&quot;a&quot;</span>: <span class="num">1</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="com"># &lt;script&gt;alert(1)&lt;/script&gt;</span>"#),
        "{html}"
    );
    assert!(!html.contains("<script>alert"), "{html}");

    let missing = harness
        .http
        .get(format!("{}/approve/0123456789abcdef", harness.base()))
        .send()
        .await?;
    assert_eq!(missing.status().as_u16(), 404);

    let (status, body) = harness
        .approve_with_passkey(&mut passkey, &id, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    let done = harness.wait_done(&execution_id(&pending)).await?;
    let done: Value = serde_json::from_str(&text_of(&done))?;
    assert_eq!(done["result"], 3, "{done}");

    // an answered request cannot be answered again
    let (status, _) = harness
        .approve_with_passkey(&mut passkey, &id, "once")
        .await?;
    assert_eq!(status, 410);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn client_grants_cover_the_client_and_per_call_tools_ask_again() -> TestResult {
    let Some(harness) = approval_harness("", "").await? else {
        return Ok(());
    };
    harness.enroll_passkey().await?;
    let approvals = harness.app.approvals();

    let first = harness
        .execute_body("int(await fixture_add(a=1, b=2))")
        .await?;
    approvals.decide(
        &approval_id(&first)?,
        Choice::Client(Duration::from_secs(15 * 60)),
    )?;
    let done: Value =
        serde_json::from_str(&text_of(&harness.wait_done(&execution_id(&first)).await?))?;
    assert_eq!(done["result"], 3, "{done}");

    // the grant covers the next call of the same client without asking
    let second = harness
        .execute_json("int(await fixture_add(a=2, b=2))")
        .await?;
    assert_eq!(second["result"], 4, "{second}");
    assert_eq!(harness.notifier.tool_requests().len(), 1);

    // a per-call tool asks even inside a granted client, and refuses a
    // client grant
    let per_call = harness.execute_body("await fixture_json_text()").await?;
    assert_eq!(per_call["waiting_for"], "fixture_json_text", "{per_call}");
    let id = approval_id(&per_call)?;
    let (status, _) = harness
        .post_json(
            &format!("/approve/{id}/options"),
            &json!({ "choice": "client15" }),
        )
        .await?;
    assert_eq!(status, 400);
    approvals.decide(&id, Choice::Once)?;
    let done: Value = serde_json::from_str(&text_of(
        &harness.wait_done(&execution_id(&per_call)).await?,
    ))?;
    assert_eq!(done["result"], json!([1, 2, {"k": "v"}]), "{done}");

    // and asks again on the next call; deny needs no passkey
    let again = harness.execute_body("await fixture_json_text()").await?;
    let id = approval_id(&again)?;
    let (status, body) = harness
        .post_json(&format!("/approve/{id}/deny"), &json!({}))
        .await?;
    assert_eq!(status, 200, "{body}");
    let denied = harness.wait_done(&execution_id(&again)).await?;
    let text = text_of(&denied);
    assert_eq!(denied.is_error, Some(true), "{text}");
    assert!(text.contains("PermissionError"), "{text}");
    assert!(text.contains("denied on the approval page"), "{text}");
    assert_eq!(harness.notifier.tool_requests().len(), 3);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn denial_and_expiry_raise_python_exceptions() -> TestResult {
    let Some(harness) = approval_harness("", "[approvals]\ntimeout_secs = 3").await? else {
        return Ok(());
    };
    harness.enroll_passkey().await?;
    let script = "try:\n    await fixture_add(a=1, b=1)\n    outcome = \"ran\"\n\
                  except OSError as error:\n    outcome = f\"{type(error).__name__}: {error}\"\noutcome";

    let pending = harness.execute_body(script).await?;
    harness
        .app
        .approvals()
        .decide(&approval_id(&pending)?, Choice::Deny)?;
    let denied: Value =
        serde_json::from_str(&text_of(&harness.wait_done(&execution_id(&pending)).await?))?;
    assert!(
        denied["result"]
            .as_str()
            .is_some_and(|message| message.starts_with("PermissionError: ")
                && message.contains("denied on the approval page")),
        "{denied}"
    );

    // nobody answers this one
    let pending = harness.execute_body(script).await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let expired: Value =
        serde_json::from_str(&text_of(&harness.wait_done(&execution_id(&pending)).await?))?;
    assert!(
        expired["result"]
            .as_str()
            .is_some_and(|message| message.contains("expired after 1 min")),
        "{expired}"
    );
    // an expired request takes no decision
    assert!(
        harness
            .app
            .approvals()
            .decide(&approval_id(&pending)?, Choice::Once)
            .is_err()
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_waits_release_the_worker_and_pause_the_budget() -> TestResult {
    // one worker, and a wall-clock budget shorter than the approval wait
    let Some(harness) = approval_harness("max_workers = 1\nexecution_timeout_secs = 3", "").await?
    else {
        return Ok(());
    };
    harness.enroll_passkey().await?;

    let pending = harness
        .execute_body(
            "import asyncio\n\
             x = 41\n\
             approved, echoed = await asyncio.gather(\n\
                 fixture_add(a=x, b=1),\n\
                 fixture_slow_echo(text=\"side\", delay_ms=200),\n\
             )\n\
             [x, int(approved), echoed[\"echoed\"]]",
        )
        .await?;
    assert_eq!(pending["status"], "pending", "{pending}");

    // the only worker was handed back while the script waits for a person
    let other = harness.execute_json("1 + 1").await?;
    assert_eq!(other["result"], 2, "{other}");

    tokio::time::sleep(Duration::from_secs(4)).await;
    harness
        .app
        .approvals()
        .decide(&approval_id(&pending)?, Choice::Once)?;
    let done = harness.wait_done(&execution_id(&pending)).await?;
    let text = text_of(&done);
    assert_eq!(done.is_error, Some(false), "{text}");
    let done: Value = serde_json::from_str(&text)?;
    assert_eq!(done["result"], json!([41, 42, "side"]), "{done}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn ask_without_a_passkey_is_denied_with_the_enroll_hint() -> TestResult {
    let Some(harness) = approval_harness("", "").await? else {
        return Ok(());
    };

    let result = execute(&harness.client, "int(await fixture_add(a=1, b=2))").await?;
    let text = text_of(&result);

    assert_eq!(result.is_error, Some(true), "{text}");
    assert!(text.contains(NO_PASSKEY), "{text}");
    assert!(harness.notifier.sent().is_empty());

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_routes_refuse_non_loopback_and_proxied_peers() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let status_from = |peer: [u8; 4], header: Option<(&'static str, &'static str)>| {
        let router = admin::router(&harness.app)
            .layer(MockConnectInfo(std::net::SocketAddr::from((peer, 40000))));
        let mut request = Request::post("/admin/enroll").header("content-type", "application/json");
        if let Some((name, value)) = header {
            request = request.header(name, value);
        }

        async move {
            let request = request.body(Body::from(r#"{"label":"x"}"#))?;

            Ok::<_, Box<dyn std::error::Error>>(router.oneshot(request).await?.status())
        }
    };

    for (peer, header) in [
        ([192, 168, 1, 20], None),
        ([100, 64, 1, 2], None),
        ([127, 0, 0, 1], Some(("x-forwarded-for", "100.64.1.2"))),
        // DNS rebinding: a local browser on an attacker's name
        ([127, 0, 0, 1], Some(("host", "evil.example.com:7682"))),
    ] {
        assert_eq!(
            status_from(peer, header).await?,
            StatusCode::FORBIDDEN,
            "{peer:?} {header:?}"
        );
    }
    assert_eq!(
        status_from([127, 0, 0, 1], Some(("host", "127.0.0.1:7682"))).await?,
        StatusCode::OK
    );

    // the main listener does not serve the admin routes at all
    let response = harness
        .http
        .post(format!("{}/admin/enroll", harness.base()))
        .send()
        .await?;
    assert_eq!(response.status().as_u16(), 404);

    harness.stop().await
}

/// Headers a proxy in front of the daemon adds, one request each
const PROXY_HEADER_SETS: [(&str, &str); 3] = [
    ("x-forwarded-for", "100.64.0.9"),
    ("tailscale-user-login", "someone@example.com"),
    ("x-real-ip", "100.64.0.9"),
];

#[tokio::test(flavor = "multi_thread")]
async fn proxied_callers_never_match_a_client_grant() -> TestResult {
    let Some(harness) = approval_harness("", "").await? else {
        return Ok(());
    };
    harness.enroll_passkey().await?;
    let approvals = harness.app.approvals();

    let first = harness
        .execute_body("int(await fixture_add(a=1, b=2))")
        .await?;
    approvals.decide(
        &approval_id(&first)?,
        Choice::Client(Duration::from_secs(15 * 60)),
    )?;
    harness.wait_done(&execution_id(&first)).await?;

    // the local caller rides the grant
    harness
        .execute_json("int(await fixture_add(a=2, b=2))")
        .await?;
    assert_eq!(harness.notifier.tool_requests().len(), 1);

    // the same client name behind a proxy is asked every time
    for (name, value) in PROXY_HEADER_SETS {
        let proxied = harness.proxied_client(&[(name, value)]).await?;
        let pending = execute(&proxied, "int(await fixture_add(a=3, b=3))").await?;
        let pending: Value = serde_json::from_str(&text_of(&pending))?;
        assert_eq!(pending["status"], "pending", "{name}: {pending}");
        approvals.decide(&approval_id(&pending)?, Choice::Once)?;
        proxied.cancel().await?;
    }
    assert_eq!(
        harness.notifier.tool_requests().len(),
        1 + PROXY_HEADER_SETS.len()
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn proxied_requests_cannot_create_client_grants() -> TestResult {
    let Some(harness) = approval_harness("", "").await? else {
        return Ok(());
    };
    let mut passkey = harness.enroll_passkey().await?;
    let approvals = harness.app.approvals();
    let proxied = harness
        .proxied_client(&[("x-forwarded-for", "100.64.0.9")])
        .await?;

    let result = execute(&proxied, "int(await fixture_add(a=1, b=2))").await?;
    let pending: Value = serde_json::from_str(&text_of(&result))?;
    let id = approval_id(&pending)?;

    // the page offers only a one-time approval and says why
    let html = harness
        .http
        .get(format!("{}/approve/{id}", harness.base()))
        .send()
        .await?
        .text()
        .await?;
    assert!(html.contains("Approve once"), "{html}");
    assert!(!html.contains("data-choice=\"client"), "{html}");
    assert!(
        html.contains("did not come straight from this machine"),
        "{html}"
    );

    // bypassing the page does not help, at either step
    for choice in ["client15", "client60"] {
        let (status, _) = harness
            .post_json(
                &format!("/approve/{id}/options"),
                &json!({ "choice": choice }),
            )
            .await?;
        assert_eq!(status, 400, "{choice}");
    }
    assert!(
        approvals
            .decide(&id, Choice::Client(Duration::from_secs(900)))
            .is_err()
    );

    // once still works, and leaves no grant behind
    let (status, body) = harness
        .approve_with_passkey(&mut passkey, &id, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    harness.wait_done(&execution_id(&pending)).await?;
    let next = harness
        .execute_body("int(await fixture_add(a=2, b=2))")
        .await?;
    assert_eq!(next["status"], "pending", "{next}");

    proxied.cancel().await?;
    harness.stop().await
}
