//! Usage logging: outcome classification, sensitive-server redaction and the
//! review report

use std::{collections::HashMap, time::Duration};

use codemode_mcp::{
    store,
    usage::{
        ApprovalRecord, CallRecord, Caller, Classification, ExecutionRecord, Outcome,
        UpstreamRecord, UsageLog, report::Reporter,
    },
};

use super::harness::{Harness, Setup, TestResult, execute, temp_state_dir};

#[tokio::test(flavor = "multi_thread")]
async fn outcomes_are_classified_and_sensitive_servers_redacted() -> TestResult {
    let fixture = env!("CARGO_BIN_EXE_codemode-fixture");
    let secret = format!("[servers.secret]\ncommand = \"{fixture}\"\nsensitive = true");
    let Some(harness) = Harness::with(Setup {
        top: "tool_timeout_secs = 1",
        limits: "max_workers = 1\nmax_queued_executions = 0",
        // an `ask` tool would make the server sensitive by default; this test
        // needs one server that keeps its arguments
        server: "sensitive = false\ntools.wide.policy = \"ask\"",
        extra: &secret,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let marker = std::env::temp_dir().join(format!("codemode-hang-{}", uuid::Uuid::new_v4()));

    let cases: Vec<(String, &str)> = vec![
        ("1 + 1".into(), "ok"),
        ("await fixture_add(a=\"one\", b=2)".into(), "type_error"),
        (
            "class A: ...\nclass B(A): ...\nB()".into(),
            "unsupported_syntax",
        ),
        ("await fixture_nope(a=1)".into(), "name_error"),
        ("import foo_mod\n1".into(), "import_error"),
        ("raise ValueError(\"bad 12\")".into(), "runtime_error"),
        ("await fixture_declared_output()".into(), "tool_error"),
        (
            format!(
                "await fixture_hang(marker={:?})",
                marker.display().to_string()
            ),
            "timeout",
        ),
        ("await fixture_wide()".into(), "denied"),
        ("int(await secret_add(a=1, b=2))".into(), "ok"),
        ("await secret_declared_output()".into(), "tool_error"),
        (
            "value = await secret_json_text()\nraise ValueError(str(value))".into(),
            "runtime_error",
        ),
    ];
    for (script, _) in &cases {
        execute(&harness.client, script).await?;
    }

    // pending, then busy while the slow script holds the only worker
    // a sleep, not a tool call, so the 1 s tool timeout does not apply
    let slow = "import asyncio\nawait asyncio.sleep(3)\n1";
    execute(&harness.client, slow).await?;
    execute(&harness.client, "2 + 2").await?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let _ = std::fs::remove_file(&marker);

    harness.app.usage().flush().await;
    let connection = store::open(harness.app.state_dir())?;
    let mut statement =
        connection.prepare("SELECT script, outcome, detail, fingerprint FROM executions")?;
    let executions: HashMap<String, (String, Option<String>, Option<String>)> = statement
        .query_map([], |row| {
            Ok((row.get(0)?, (row.get(1)?, row.get(2)?, row.get(3)?)))
        })?
        .collect::<Result<_, _>>()?;

    for (script, expected) in &cases {
        let (outcome, detail, _) = executions
            .get(script)
            .ok_or_else(|| format!("no execution logged for {script:?}"))?;
        assert_eq!(outcome, expected, "{script:?}: {detail:?}");
    }
    let detail = |script: &str| {
        executions
            .get(script)
            .and_then(|(_, detail, _)| detail.clone())
            .unwrap_or_default()
    };
    assert!(
        detail("await fixture_add(a=\"one\", b=2)").contains("invalid-argument-type"),
        "{}",
        detail("await fixture_add(a=\"one\", b=2)")
    );
    assert_eq!(
        detail("await fixture_nope(a=1)"),
        "unresolved-reference: fixture_nope"
    );
    assert_eq!(
        executions["raise ValueError(\"bad 12\")"].2.as_deref(),
        Some("runtime_error: ValueError: bad N")
    );

    // a sensitive server's failure keeps only the tool name, and exceptions
    // after reading its data keep only the type
    assert_eq!(
        detail("await secret_declared_output()"),
        "secret_declared_output"
    );
    assert_eq!(
        detail("value = await secret_json_text()\nraise ValueError(str(value))"),
        "ValueError"
    );

    let call_outcomes: Vec<String> = connection
        .prepare("SELECT outcome FROM calls WHERE tool = 'execute'")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    assert!(
        call_outcomes.iter().any(|outcome| outcome == "pending"),
        "{call_outcomes:?}"
    );
    assert!(
        call_outcomes.iter().any(|outcome| outcome == "busy"),
        "{call_outcomes:?}"
    );

    let secret_calls: Vec<(Option<String>, Option<String>)> = connection
        .prepare("SELECT arguments, detail FROM upstream_calls WHERE server = 'secret'")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(secret_calls.len(), 3, "{secret_calls:?}");
    assert!(
        secret_calls
            .iter()
            .all(|(arguments, detail)| arguments.is_none() && detail.is_none())
    );
    let fixture_arguments: Option<String> = connection.query_row(
        "SELECT arguments FROM upstream_calls WHERE function = 'fixture_hang'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        fixture_arguments.is_some_and(|arguments| arguments.contains("marker")),
        "non-sensitive arguments are kept"
    );

    harness.stop().await
}

fn caller(session: &str, client: &str) -> Caller {
    Caller {
        session: Some(session.to_owned()),
        client_name: Some(client.to_owned()),
        client_version: Some("1.0".to_owned()),
    }
}

fn search(session: &str, query: &str, results: usize) -> CallRecord {
    CallRecord {
        caller: caller(session, "claude-code"),
        tool: "search_tools",
        input: Some(query.to_owned()),
        classification: Classification {
            outcome: Outcome::Ok,
            detail: Some(format!("results: {results}")),
        },
        duration: Duration::from_millis(2),
        result_bytes: 10,
        execution_id: None,
    }
}

fn execution(
    id: &str,
    started_ms: i64,
    caller: Caller,
    script: &str,
    classification: Classification,
) -> ExecutionRecord {
    ExecutionRecord {
        id: id.to_owned(),
        started_ms,
        caller,
        script: script.to_owned(),
        classification,
        duration: Duration::from_millis(30),
        result_bytes: 20,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn review_renders_sections_from_a_seeded_database() -> TestResult {
    let directory = temp_state_dir();
    let log = UsageLog::start(&directory, Duration::from_secs(90 * 24 * 60 * 60))?;
    let now = store::now_ms();
    let claude = || caller("s1", "claude-code");

    log.call(search("s1", "send email", 0));
    log.call(search("s1", "openai docs", 3));
    log.call(search("s1", "openai docs", 3));
    log.call(CallRecord {
        caller: claude(),
        tool: "describe_tools",
        input: Some("[\"fixture_add\"]".to_owned()),
        classification: Classification::ok(),
        duration: Duration::from_millis(1),
        result_bytes: 100,
        execution_id: None,
    });
    log.execution(execution(
        "e1",
        now - 3000,
        claude(),
        "await fixture_sendmail(to=\"x\")",
        Classification::new(Outcome::NameError, "unresolved-reference: fixture_sendmail"),
    ));
    log.execution(execution(
        "e2",
        now - 2000,
        claude(),
        "await fixture_add(a=\"1\", b=2)",
        Classification::new(
            Outcome::TypeError,
            "invalid-argument-type: Argument to function `fixture_add` is incorrect",
        ),
    ));
    log.execution(execution(
        "e3",
        now - 1000,
        claude(),
        "await fixture_add(a=1, b=2)",
        Classification::ok(),
    ));
    for function in ["fixture_add", "fixture_slow_echo"] {
        log.upstream(UpstreamRecord {
            execution_id: Some("e3".to_owned()),
            server: "fixture".to_owned(),
            tool: function.trim_start_matches("fixture_").to_owned(),
            function: function.to_owned(),
            arguments: None,
            classification: Classification::ok(),
            duration: Duration::from_millis(40),
            approval_id: None,
        });
    }
    log.execution(execution(
        "e4",
        now - 500,
        caller("s2", "codex"),
        "raise ValueError(\"nope 7\")",
        Classification::new(Outcome::RuntimeError, "ValueError: nope 7"),
    ));
    for (index, decision) in ["approved", "denied", "expired"].into_iter().enumerate() {
        let id = format!("a{index}");
        log.approval(ApprovalRecord::Created {
            id: id.clone(),
            caller: claude(),
            execution_id: "e3".to_owned(),
            server: "op".to_owned(),
            tool: "list_environments".to_owned(),
            grant_mode: "session",
        });
        log.approval(ApprovalRecord::Decided {
            id,
            decision,
            grant_minutes: None,
        });
    }
    log.flush().await;

    let connection = store::open(&directory)?;
    let reporter = Reporter::new(&connection, Duration::from_secs(7 * 24 * 60 * 60));
    let review = reporter.review(&["fixture_".to_owned()])?;
    let section = |heading: &str| {
        let start = review.find(heading).unwrap_or(review.len());
        let rest = &review[start..];
        let end = rest[heading.len()..]
            .find("\n## ")
            .map_or(rest.len(), |end| end + heading.len());

        rest[..end].to_owned()
    };

    let clients = section("## Per-client summary");
    assert!(clients.contains("| claude-code | 1 | 4 |"), "{clients}");
    assert!(clients.contains("| 33% | 3.0 |"), "{clients}");

    let fingerprints = section("## Top error fingerprints");
    assert!(
        fingerprints.contains("await fixture_sendmail(to=\"x\")"),
        "{fingerprints}"
    );
    assert!(
        fingerprints.contains("Error: unresolved-reference: fixture_sendmail"),
        "{fingerprints}"
    );

    let retries = section("## Sessions with the most failed executes");
    let first = retries.find("1. **name_error**").ok_or(retries.clone())?;
    let third = retries.find("3. **ok**").ok_or(retries.clone())?;
    assert!(first < third, "{retries}");
    assert!(retries.contains("2 failed, then succeeded"), "{retries}");
    assert!(retries.contains("1 failed, abandoned"), "{retries}");

    let hallucinated = section("## Hallucinated tool names");
    assert!(
        hallucinated.contains("| `fixture_sendmail` | 1 |"),
        "{hallucinated}"
    );

    let undescribed = section("## Executes that called tools never described");
    assert!(undescribed.contains("`fixture_slow_echo`"), "{undescribed}");
    assert!(!undescribed.contains("`fixture_add`"), "{undescribed}");

    assert!(
        section("## Empty searches").contains("`send email`"),
        "{review}"
    );
    assert!(
        section("## Repeated searches").contains("| `openai docs` | 2 |"),
        "{review}"
    );

    let approvals = section("## Approvals");
    assert!(approvals.contains("- Requested: 3"), "{approvals}");
    assert!(approvals.contains("- Denied: 1"), "{approvals}");
    assert!(approvals.contains("- Expired: 1"), "{approvals}");

    let _ = std::fs::remove_dir_all(&directory);

    Ok(())
}

/// Stateless 2026-07-28 clients carry no session id, which approval grants and
/// the log key on, so they are turned away and fall back to `initialize`
#[tokio::test(flavor = "multi_thread")]
async fn calls_are_logged_with_their_session_and_stateless_clients_are_refused() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let discover = harness
        .http
        .post(format!("{}/mcp", harness.base()))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "server/discover")
        .body(
            r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientInfo":{"name":"x","version":"1"},
                "io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        )
        .send()
        .await?;
    assert_eq!(discover.status().as_u16(), 400);
    assert!(
        discover
            .text()
            .await?
            .contains("Unsupported protocol version")
    );

    execute(&harness.client, "1 + 1").await?;
    harness.app.usage().flush().await;
    let connection = store::open(harness.app.state_dir())?;
    let (session, client): (Option<String>, Option<String>) = connection.query_row(
        "select session, client_name from calls where tool = 'execute'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert!(session.is_some_and(|session| !session.is_empty()));
    assert_eq!(client.as_deref(), Some("rmcp"));

    harness.stop().await
}
