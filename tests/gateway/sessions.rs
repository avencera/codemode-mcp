//! App sessions: issued on the first call, passed back by the agent, bound
//! to a client, persisted, used as approval grant keys and never stored raw

use std::{error::Error, path::Path, time::Duration};

use codemode_mcp::{
    app::App,
    server::serve,
    store::{
        self,
        sessions::{hash_token, short_hash},
    },
    usage::report::{Reporter, render_stats},
};
use serde_json::{Value, json};

use super::harness::{
    Client, DEFAULT_CLIENT, Harness, Setup, TestResult, approval_id, call, config_for, connect_as,
    monty_worker, temp_state_dir, text_of,
};

/// `add` asks with session grants; `json_text` asks on every call
const ASK_TOOLS: &str = "tools.add.policy = \"ask\"\n\
                         tools.json_text.policy = \"ask\"\n\
                         tools.json_text.grant = \"per_call\"";

/// The session a response hands back: a JSON field, or a first line
fn session_of(text: &str) -> Result<String, Box<dyn Error>> {
    if let Some(line) = text
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("session: "))
    {
        return Ok(line.to_owned());
    }
    let body: Value = serde_json::from_str(text)?;

    Ok(body["session"]
        .as_str()
        .ok_or_else(|| format!("no session in {text}"))?
        .to_owned())
}

/// Runs `code`, passing `session` when given; returns the response text
async fn run(client: &Client, code: &str, session: Option<&str>) -> Result<String, Box<dyn Error>> {
    let mut arguments = json!({ "code": code });
    if let Some(session) = session {
        arguments["session"] = json!(session);
    }

    Ok(text_of(&call(client, "execute", arguments).await?))
}

/// Logged (session label, session_state) of a call
type LoggedCall = (Option<String>, Option<String>);

/// Every call's session label and state, oldest first
fn logged(directory: &Path) -> Result<Vec<LoggedCall>, Box<dyn Error>> {
    let connection = store::open(directory)?;

    Ok(connection
        .query_map(
            "SELECT session, session_state FROM calls ORDER BY id",
            (),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?
        .into_iter()
        .collect())
}

fn label(token: &str) -> Option<String> {
    Some(short_hash(&hash_token(token)).to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn passing_the_session_back_reuses_it() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let client = &harness.client;

    let first = run(client, "1 + 1", None).await?;
    let token = session_of(&first)?;
    assert!(token.starts_with("cs_") && token.len() == 29, "{token}");
    let body: Value = serde_json::from_str(&first)?;
    assert_eq!(body["session_note"], Value::Null, "{body}");

    let second: Value = serde_json::from_str(&run(client, "2 + 2", Some(&token)).await?)?;
    assert_eq!(second["session"], token, "{second}");
    assert_eq!(second["session_note"], Value::Null, "{second}");

    // search and describe lead with the session line
    let searched = text_of(
        &call(
            client,
            "search_tools",
            json!({ "query": "add", "session": token }),
        )
        .await?,
    );
    assert_eq!(
        searched.lines().next(),
        Some(format!("session: {token}").as_str()),
        "{searched}"
    );
    let described = text_of(
        &call(
            client,
            "describe_tools",
            json!({ "names": ["fixture_add"], "session": token }),
        )
        .await?,
    );
    assert_eq!(
        described.lines().next(),
        Some(format!("session: {token}").as_str()),
        "{described}"
    );

    // plain-text failures lead with the line too
    let failed = run(client, "return 1", Some(&token)).await?;
    assert_eq!(session_of(&failed)?, token, "{failed}");

    harness.app.usage().flush().await;
    let calls = logged(harness.app.state_dir())?;
    let states: Vec<_> = calls.iter().map(|(_, state)| state.as_deref()).collect();
    assert_eq!(
        states,
        [
            Some("minted"),
            Some("reused"),
            Some("reused"),
            Some("reused"),
            Some("reused")
        ]
    );
    assert!(calls.iter().all(|(session, _)| *session == label(&token)));
    let connection = store::open(harness.app.state_dir())?;
    let minted: i64 =
        connection.query_row("SELECT COUNT(*) FROM sessions", (), |row| row.get(0))?;
    assert_eq!(minted, 1);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_expired_and_foreign_sessions_are_replaced_with_a_note() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let unknown: Value =
        serde_json::from_str(&run(&harness.client, "1", Some("cs_notarealtoken")).await?)?;
    assert_ne!(unknown["session"], "cs_notarealtoken", "{unknown}");
    assert!(
        unknown["session_note"]
            .as_str()
            .is_some_and(|note| note.contains("not valid")),
        "{unknown}"
    );

    // a token minted for one client does not work for another
    let mine = session_of(&run(&harness.client, "1", None).await?)?;
    let other = harness.client_as("other-agent/1.0").await?;
    let foreign: Value = serde_json::from_str(&run(&other, "1", Some(&mine)).await?)?;
    assert_ne!(foreign["session"], mine, "{foreign}");
    assert!(foreign["session_note"].is_string(), "{foreign}");
    // plain-text responses say so on a second line
    let text = run(&other, "return 1", Some(&mine)).await?;
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("session: cs_"), "{text}");
    assert!(lines[1].starts_with("note: "), "{text}");
    // the owner still has it
    let still: Value = serde_json::from_str(&run(&harness.client, "1", Some(&mine)).await?)?;
    assert_eq!(still["session"], mine, "{still}");
    other.cancel().await?;

    // idle past the configured time expires it
    let connection = store::open(harness.app.state_dir())?;
    connection.execute(
        "UPDATE sessions SET last_seen_ms = last_seen_ms - ?1 WHERE hash = ?2",
        turso::params![25 * 60 * 60 * 1000_i64, hash_token(&mine)],
    )?;
    let expired: Value = serde_json::from_str(&run(&harness.client, "1", Some(&mine)).await?)?;
    assert_ne!(expired["session"], mine, "{expired}");
    assert!(expired["session_note"].is_string(), "{expired}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_grant_from_a_proxied_request_covers_only_that_session() -> TestResult {
    let Some(harness) = Harness::with(Setup {
        server: ASK_TOOLS,
        notify: true,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let mut passkey = harness.enroll_passkey().await?;
    let proxied = harness
        .proxied_client(&[("x-forwarded-for", "100.64.0.9")])
        .await?;
    let add = "int(await fixture_add(a=1, b=2))";

    let pending: Value = serde_json::from_str(&run(&proxied, add, None).await?)?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let session = session_of(&pending.to_string())?;
    let id = approval_id(&pending)?;

    let html = harness
        .http
        .get(format!("{}/approve/{id}", harness.base()))
        .send()
        .await?
        .text()
        .await?;
    assert!(html.contains("data-choice=\"session15\""), "{html}");
    assert!(html.contains("Approve this session for 60 min"), "{html}");
    // proxied: no client grant
    assert!(!html.contains("data-choice=\"client"), "{html}");

    let (status, body) = harness
        .approve_with_passkey(&mut passkey, &id, "session15")
        .await?;
    assert_eq!(status, 200, "{body}");
    let done = text_of(
        &call(
            &proxied,
            "wait",
            json!({ "execution_id": pending["execution_id"], "session": session }),
        )
        .await?,
    );
    let done: Value = serde_json::from_str(&done)?;
    assert_eq!(done["result"], 3, "{done}");
    assert_eq!(done["session"], session, "{done}");
    assert_eq!(harness.notifier.tool_requests().len(), 1);

    // later calls carrying the session are covered, even through the proxy
    let covered: Value = serde_json::from_str(&run(&proxied, add, Some(&session)).await?)?;
    assert_eq!(covered["result"], 3, "{covered}");
    assert_eq!(harness.notifier.tool_requests().len(), 1);

    // the same client without the session is asked
    let without: Value = serde_json::from_str(&run(&proxied, add, None).await?)?;
    assert_eq!(without["status"], "pending", "{without}");
    assert_ne!(without["session"], session.as_str(), "{without}");
    harness.app.approvals().decide(
        &approval_id(&without)?,
        codemode_mcp::approvals::Choice::Deny,
    )?;

    // another session of the same client is asked too
    let other_session = session_of(&run(&proxied, "1", None).await?)?;
    let other: Value = serde_json::from_str(&run(&proxied, add, Some(&other_session)).await?)?;
    assert_eq!(other["status"], "pending", "{other}");
    assert_eq!(other["session"], other_session, "{other}");
    assert_eq!(harness.notifier.tool_requests().len(), 3);

    // a per-call tool refuses session grants at the options step
    let per_call: Value =
        serde_json::from_str(&run(&proxied, "await fixture_json_text()", Some(&session)).await?)?;
    let per_call_id = approval_id(&per_call)?;
    let (status, _) = harness
        .post_json(
            &format!("/approve/{per_call_id}/options"),
            &json!({ "choice": "session15" }),
        )
        .await?;
    assert_eq!(status, 400);

    proxied.cancel().await?;
    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn the_raw_token_is_never_stored_logged_or_reported() -> TestResult {
    let Some(harness) = Harness::with(Setup {
        server: ASK_TOOLS,
        notify: true,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let mut passkey = harness.enroll_passkey().await?;

    let pending: Value = serde_json::from_str(
        &run(&harness.client, "int(await fixture_add(a=1, b=2))", None).await?,
    )?;
    let token = session_of(&pending.to_string())?;
    let id = approval_id(&pending)?;
    let page = harness
        .http
        .get(format!("{}/approve/{id}", harness.base()))
        .send()
        .await?
        .text()
        .await?;
    let (status, body) = harness
        .approve_with_passkey(&mut passkey, &id, "session60")
        .await?;
    assert_eq!(status, 200, "{body}");
    harness
        .wait_done(pending["execution_id"].as_str().unwrap_or_default())
        .await?;
    run(&harness.client, "1 + 1", Some(&token)).await?;
    harness.app.usage().flush().await;

    let hash = hash_token(&token);
    let directory = harness.app.state_dir().clone();
    let mut stored = Vec::new();
    for entry in std::fs::read_dir(&directory)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("codemode.sqlite"))
        {
            stored.extend(std::fs::read(path)?);
        }
    }
    let contains = |haystack: &[u8], needle: &str| {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    };
    assert!(
        !contains(&stored, &token),
        "raw token in the database files"
    );
    assert!(contains(&stored, &hash), "the hash should be stored");

    let stats_html = harness
        .http
        .get(format!("{}/stats", harness.base()))
        .send()
        .await?
        .text()
        .await?;
    assert!(!stats_html.contains(&token), "{stats_html}");
    assert!(!page.contains(&token), "{page}");

    let connection = store::open_read_only(&directory)?;
    let reporter = Reporter::new(&connection, Duration::from_secs(60 * 60));
    let review = reporter.review(&["fixture_".to_owned()])?;
    assert!(!review.contains(&token), "{review}");
    assert!(!render_stats(&reporter.stats()?).contains(&token));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_survive_an_app_restart() -> TestResult {
    let Some(worker) = monty_worker()? else {
        return Ok(());
    };
    let directory = temp_state_dir();
    let setup = Setup::default();

    let app = App::start_with(config_for(&worker, &directory, &setup)?, None).await?;
    let server = serve(&app).await?;
    let base = format!("http://127.0.0.1:{}", server.local_addr().port());
    let client = connect_as(&base, &format!("{DEFAULT_CLIENT}/1.0")).await?;
    let token = session_of(&run(&client, "1 + 1", None).await?)?;
    client.cancel().await?;
    server.shutdown().await?;
    app.usage().flush().await;
    drop(app);

    let app = App::start_with(config_for(&worker, &directory, &setup)?, None).await?;
    let server = serve(&app).await?;
    let base = format!("http://127.0.0.1:{}", server.local_addr().port());
    let client = connect_as(&base, &format!("{DEFAULT_CLIENT}/1.0")).await?;
    let again: Value = serde_json::from_str(&run(&client, "2 + 2", Some(&token)).await?)?;
    assert_eq!(again["session"], token, "{again}");
    assert_eq!(again["session_note"], Value::Null, "{again}");
    app.usage().flush().await;
    let states: Vec<_> = logged(&directory)?
        .into_iter()
        .map(|(_, state)| state)
        .collect();
    assert_eq!(
        states,
        [Some("minted".to_owned()), Some("reused".to_owned())]
    );

    client.cancel().await?;
    server.shutdown().await?;
    let _ = std::fs::remove_dir_all(&directory);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn review_groups_by_session_and_counts_sessions_used_once() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let client = &harness.client;

    // one agent: a search, then two failures and a success under its session
    let first = text_of(&call(client, "search_tools", json!({ "query": "add" })).await?);
    let first_token = session_of(&first)?;
    for _ in 0..2 {
        run(client, "return 1", Some(&first_token)).await?;
    }
    run(client, "1 + 1", Some(&first_token)).await?;
    // it forgets the session while the first one is still active
    let second_token = session_of(&run(client, "3 + 3", None).await?)?;
    assert_ne!(first_token, second_token);
    harness.app.usage().flush().await;

    let connection = store::open(harness.app.state_dir())?;
    let reporter = Reporter::new(&connection, Duration::from_secs(60 * 60));
    let stats = reporter.stats()?;
    let stats_client = stats
        .clients
        .iter()
        .find(|entry| entry.client == DEFAULT_CLIENT)
        .ok_or("no stats for the harness client")?;
    // two sessions are two runs, where the gap heuristic would merge them
    assert_eq!(stats_client.runs, 2);
    assert_eq!(stats_client.sessions_minted, 2);
    assert_eq!(stats_client.session_calls, 3);
    // the dropped session got a single call
    assert_eq!(stats_client.sessions_used_once, 1);
    assert!(
        render_stats(&stats).contains("2 minted, 3 calls with a passed session, 1 used once"),
        "{}",
        render_stats(&stats)
    );

    let review = reporter.review(&["fixture_".to_owned()])?;
    let first_label = short_hash(&hash_token(&first_token)).to_owned();
    assert!(
        review.contains(&format!("run `{first_label}`: 2 failed, then succeeded")),
        "{review}"
    );
    assert!(
        review.contains(&format!("| {DEFAULT_CLIENT} | 2 | 3 | 1 |")),
        "{review}"
    );

    harness.stop().await
}
