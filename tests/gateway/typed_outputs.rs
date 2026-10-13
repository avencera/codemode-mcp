//! Typed tool results: stubs without `Any`, narrowing of untyped results,
//! output overrides, the runtime schema check, the escape-hatch bans, the
//! homebased adapter's declared outputs and the strictness review

use std::{error::Error, time::Duration};

use codemode_mcp::{
    output::validate,
    store,
    usage::{
        CallRecord, Caller, Classification, ExecutionRecord, Outcome, UpstreamRecord,
        report::Reporter,
    },
};
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

use super::harness::{Harness, Seed, Setup, TestResult, call, execute, temp_state_dir, text_of};

/// Whether `text` uses `Any` as a word, ignoring names that merely contain it
fn mentions_any(text: &str) -> bool {
    text.split(|character: char| !character.is_alphanumeric() && character != '_')
        .any(|word| word == "Any")
}

async fn described(harness: &Harness, names: &[&str]) -> Result<String, Box<dyn Error>> {
    let result = call(&harness.client, "describe_tools", json!({ "names": names })).await?;

    Ok(text_of(&result))
}

#[tokio::test(flavor = "multi_thread")]
async fn stubs_are_typed_or_json_value_and_never_any() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let stubs = harness.app.gateway().catalog().check_stubs().to_owned();
    assert!(
        !mentions_any(&stubs),
        "the check stubs mention Any:\n{stubs}"
    );
    assert!(
        stubs.contains("type JsonValue ="),
        "the header declares the recursive alias:\n{stubs}"
    );

    let typed = described(&harness, &["fixture_slow_echo"]).await?;
    assert!(
        typed.contains("TypedDict") && typed.contains("echoed"),
        "a tool with an output schema returns its generated type:\n{typed}"
    );
    assert!(!typed.contains("-> JsonValue"), "{typed}");

    let untyped = described(&harness, &["fixture_json_text", "fixture_odd_names"]).await?;
    assert!(
        untyped.contains("fixture_json_text() -> JsonValue"),
        "a tool without an output schema returns JsonValue:\n{untyped}"
    );
    assert!(
        untyped.contains("Unpack["),
        "names that are not identifiers go through a typed dict:\n{untyped}"
    );
    assert!(!mentions_any(&untyped), "{untyped}");
    assert!(!mentions_any(&typed), "{typed}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn json_value_results_narrow_with_isinstance() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let body = harness
        .execute_json(
            "found = \"\"\n\
             data = await fixture_open_args(a=\"1\", k=\"v\")\n\
             if isinstance(data, dict):\n    \
                 value = data.get(\"k\")\n    \
                 if isinstance(value, str):\n        \
                     found = value\n\
             found",
        )
        .await?;
    assert_eq!(body["result"], "v", "{body}");

    // without the narrowing the checker refuses, which is the point of
    // `JsonValue` over `Any`
    let result = execute(
        &harness.client,
        "data = await fixture_open_args(a=\"1\")\ndata[\"a\"]",
    )
    .await?;
    assert_eq!(result.is_error, Some(true), "{}", text_of(&result));
    assert!(text_of(&result).contains("error["), "{}", text_of(&result));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn output_overrides_change_the_return_type_and_obey_precedence() -> TestResult {
    let Some(harness) = Harness::start(
        "",
        "tools.json_text.output = \"text\"\n\
         tools.open_args.output_schema = { type = \"object\", required = [\"a\"], properties = { a = { type = \"string\" } } }\n\
         tools.slow_echo.output_schema = { type = \"object\", required = [\"echoed\"], properties = { echoed = { type = \"integer\" } } }",
    )
    .await?
    else {
        return Ok(());
    };

    // `output = "text"` hands the script a str that was never parsed; this
    // only type-checks when the return type is `str`
    let body = harness
        .execute_json("text = await fixture_json_text()\ntext.startswith(\"[1, 2\")")
        .await?;
    assert_eq!(body["result"], true, "{body}");

    // an `output_schema` override types the result like a declared schema
    let body = harness
        .execute_json("data = await fixture_open_args(a=\"x\")\ndata[\"a\"]")
        .await?;
    assert_eq!(body["result"], "x", "{body}");

    // the upstream declares its own schema for slow_echo, so the override
    // that says `echoed` is an integer is ignored
    let body = harness
        .execute_json("echo = await fixture_slow_echo(text=\"hi\", delay_ms=0)\necho[\"echoed\"]")
        .await?;
    assert_eq!(body["result"], "hi", "{body}");

    harness.stop().await?;

    // `force_output_schema` makes the config win, and the real result then
    // breaks it
    let Some(harness) = Harness::start(
        "",
        "tools.slow_echo.output_schema = { type = \"object\", required = [\"echoed\"], properties = { echoed = { type = \"integer\" } } }\n\
         tools.slow_echo.force_output_schema = true",
    )
    .await?
    else {
        return Ok(());
    };
    let result = execute(
        &harness.client,
        "await fixture_slow_echo(text=\"hi\", delay_ms=0)",
    )
    .await?;
    assert_eq!(result.is_error, Some(true), "{}", text_of(&result));
    assert!(
        text_of(&result).contains("$.echoed"),
        "{}",
        text_of(&result)
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_result_that_breaks_its_schema_raises_and_is_logged() -> TestResult {
    let fixture = env!("CARGO_BIN_EXE_codemode-fixture");
    let secret = format!("[servers.secret]\ncommand = \"{fixture}\"\nsensitive = true");
    let Some(harness) = Harness::with(Setup {
        extra: &secret,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    let body = harness
        .execute_json(
            "message = \"\"\n\
             try:\n    await fixture_mismatched_output()\n\
             except RuntimeError as error:\n    message = str(error)\n\
             message",
        )
        .await?;
    let message = body["result"].as_str().ok_or("no message")?;
    assert!(message.contains("fixture_mismatched_output"), "{message}");
    assert!(message.contains("$.items[1].name"), "{message}");
    assert!(message.contains("expected string"), "{message}");
    assert!(message.contains("integer 7"), "{message}");

    // uncaught, it fails the execute and names the same place
    let result = execute(&harness.client, "await secret_mismatched_output()").await?;
    assert_eq!(result.is_error, Some(true), "{}", text_of(&result));

    harness.app.usage().flush().await;
    let connection = store::open(harness.app.state_dir())?;
    let rows: Vec<(String, String, Option<String>, String)> = connection
        .query_map(
            "SELECT server, outcome, detail, output FROM upstream_calls ORDER BY at_ms",
            (),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?
        .into_iter()
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");

    let (_, outcome, detail, output) = &rows[0];
    assert_eq!(outcome, "output_mismatch");
    assert_eq!(output, "schema");
    assert!(
        detail
            .as_deref()
            .is_some_and(|detail| detail.contains("$.items[1].name")),
        "{detail:?}"
    );

    // a sensitive server keeps only the expected type: the path can carry
    // keys from the data, and the value is the data
    let (server, outcome, detail, _) = &rows[1];
    assert_eq!(server, "secret");
    assert_eq!(outcome, "output_mismatch");
    let detail = detail.as_deref().ok_or("no detail")?;
    assert!(detail.starts_with("expected "), "{detail}");
    assert!(!detail.contains("items"), "{detail}");
    assert!(!detail.contains('7'), "{detail}");

    let uncaught: String = connection.query_row(
        "SELECT outcome FROM executions WHERE script LIKE '%secret_mismatched_output%'",
        (),
        |row| row.get(0),
    )?;
    assert_eq!(uncaught, "output_mismatch");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn escape_hatches_are_rejected_before_the_checker() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let cases = [
        (
            "from typing import Any\nvalue: Any = 1\nvalue",
            "ban:any",
            "Any is not allowed",
        ),
        (
            "import typing as t\nvalue: t.Any = 1\nvalue",
            "ban:any",
            "Any is not allowed",
        ),
        (
            "from typing import Any as Anything\ndef f(x: Anything) -> int:\n    return 1\nf(1)",
            "ban:any",
            "Any is not allowed",
        ),
        (
            "from typing import cast\ncast(int, 1)",
            "ban:cast",
            "cast is not allowed",
        ),
        (
            "value = 1  # type: ignore\nvalue",
            "ban:type-ignore",
            "type: ignore is not allowed",
        ),
        (
            "value = 1  # noqa # ty: ignore[invalid-assignment]\nvalue",
            "ban:type-ignore",
            "type: ignore is not allowed",
        ),
    ];
    for (script, rule, hint) in cases {
        let result = execute(&harness.client, script).await?;
        let text = text_of(&result);
        assert_eq!(result.is_error, Some(true), "{script}: {text}");
        assert!(text.contains(&format!("error[{rule}]")), "{script}: {text}");
        assert!(text.contains(hint), "{script}: {text}");
    }

    // text that only looks like a directive is data
    let body = harness
        .execute_json("note = \"# type: ignore\"\nnote")
        .await?;
    assert_eq!(body["result"], "# type: ignore", "{body}");

    // an import nobody uses switches nothing off, so it costs no retry
    let body = harness
        .execute_json("from typing import Any\nvalue = 1\nvalue")
        .await?;
    assert_eq!(body["result"], 1, "{body}");

    harness.app.usage().flush().await;
    let connection = store::open(harness.app.state_dir())?;
    let logged: Vec<(String, String)> = connection.query_map("SELECT outcome, COALESCE(fingerprint, '') FROM executions WHERE outcome = 'type_error'", (), |row| Ok((row.get(0)?, row.get(1)?)))?.into_iter().collect();
    assert_eq!(logged.len(), cases.len(), "{logged:?}");
    for rule in ["ban:any", "ban:cast", "ban:type-ignore"] {
        assert!(
            logged
                .iter()
                .any(|(_, fingerprint)| fingerprint.contains(rule)),
            "{rule} missing from {logged:?}"
        );
    }

    harness.stop().await
}

/// The twelve tools the homebased adapter offers, with arguments that make
/// the fake homebased answer
fn adapter_calls() -> Vec<(&'static str, Value)> {
    let task = "01a10000-0000-7000-8000-000000000001";
    let thread = "11111111-2222-4333-8444-555555555555";

    vec![
        ("daemon_status", json!({})),
        ("task_list", json!({})),
        ("task_show", json!({ "id": task })),
        ("task_log", json!({ "id": task })),
        ("task_usage", json!({})),
        ("fleet_machines", json!({})),
        (
            "task_submit_agent",
            json!({
                "thread": thread, "name": "review", "cwd": "/tmp",
                "agent": "claude", "prompt": "Review the diff.",
            }),
        ),
        (
            "task_submit_agent",
            json!({
                "thread": thread, "name": "review", "cwd": "/tmp",
                "agent": "claude", "prompt": "Review the diff.", "dry_run": true,
            }),
        ),
        (
            "task_submit_command",
            json!({ "thread": thread, "name": "build", "cwd": "/tmp", "command": ["true"] }),
        ),
        (
            "task_followup",
            json!({ "id": task, "message": "Continue." }),
        ),
        ("task_cancel", json!({ "id": task })),
        ("message_send", json!({ "task": task, "message": "hi" })),
    ]
}

/// What the homebased adapter answers is what it declared: every tool has an
/// output schema, and the answers built from real `homebased --json` captures
/// pass the same check the gateway applies before a script sees them
#[tokio::test(flavor = "multi_thread")]
async fn homebased_outputs_follow_their_declared_schemas() -> TestResult {
    let command =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_codemode-mcp")).configure(|command| {
            command.args([
                "--config",
                "/nonexistent/codemode.toml",
                "adapter",
                "homebased",
                "--homebased-bin",
                env!("CARGO_BIN_EXE_codemode-fake-homebased"),
            ]);
        });
    let client = ().serve(TokioChildProcess::new(command)?).await?;

    let tools = client.list_all_tools().await?;
    assert_eq!(tools.len(), 12, "{tools:?}");
    for tool in &tools {
        assert!(
            tool.output_schema.is_some(),
            "{} declares no output schema",
            tool.name
        );
    }

    for (name, arguments) in adapter_calls() {
        let schema = tools
            .iter()
            .find(|tool| tool.name == name)
            .and_then(|tool| tool.output_schema.clone())
            .ok_or_else(|| format!("no schema for {name}"))?;
        let Value::Object(arguments) = arguments else {
            return Err("arguments must be an object".into());
        };
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            client.call_tool(CallToolRequestParams::new(name).with_arguments(arguments)),
        )
        .await??;
        assert_eq!(result.is_error, Some(false), "{name}: {}", text_of(&result));

        let structured = result
            .structured_content
            .ok_or_else(|| format!("{name} returned no structured content"))?;
        validate(&schema, &structured)
            .map_err(|mismatch| format!("{name}: {mismatch} in {structured}"))?;
    }
    client.cancel().await?;

    Ok(())
}

fn claude(session: &str) -> Caller {
    Caller {
        session: Some(session.to_owned()),
        client_name: Some("claude-code".to_owned()),
        client_version: Some("1.0".to_owned()),
        ..Caller::default()
    }
}

fn run(
    log: &Seed,
    id: &str,
    at_ms: i64,
    session: &str,
    script: &str,
    classification: Classification,
) {
    log.execution(ExecutionRecord {
        id: id.to_owned(),
        started_ms: at_ms,
        caller: claude(session),
        script: script.to_owned(),
        classification,
        duration: Duration::from_millis(10),
        result_bytes: 10,
    });
}

fn upstream(log: &Seed, execution: &str, tool: &str, outcome: Outcome, output: &'static str) {
    log.upstream(UpstreamRecord {
        execution_id: Some(execution.to_owned()),
        server: "fixture".to_owned(),
        tool: tool.to_owned(),
        function: format!("fixture_{tool}"),
        arguments: None,
        classification: Classification {
            outcome,
            detail: None,
        },
        duration: Duration::from_millis(5),
        approval_id: None,
        output,
    });
}

fn type_error(rule: &str) -> Classification {
    Classification::new(Outcome::TypeError, format!("{rule}: something is wrong"))
}

fn section(review: &str) -> &str {
    let start = review.find("## Type strictness").unwrap_or(review.len());
    let rest = &review[start..];
    let end = rest["## Type strictness".len()..]
        .find("\n## ")
        .map_or(rest.len(), |end| end + "## Type strictness".len());

    &rest[..end]
}

/// Seeds a database, reads the review's strictness section and returns it
async fn strictness_of(seed: impl FnOnce(&Seed, i64)) -> Result<String, Box<dyn Error>> {
    let directory = temp_state_dir();
    let log = Seed::start(&directory)?;
    seed(&log, store::now_ms() - 60 * 60 * 1000);
    log.flush().await;

    let connection = store::open(&directory)?;
    let reporter = Reporter::new(&connection, Duration::from_secs(7 * 24 * 60 * 60));
    let review = reporter.review(&[])?;
    let _ = std::fs::remove_dir_all(&directory);

    Ok(section(&review).to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn review_counts_strictness_signals_per_client() -> TestResult {
    let strictness = strictness_of(|log, base| {
        // run s1: the same rule twice, then success; only the second error is fixed
        run(
            log,
            "a1",
            base,
            "s1",
            "await fixture_add(a=\"1\", b=2)",
            type_error("invalid-argument-type"),
        );
        run(
            log,
            "a2",
            base + 1000,
            "s1",
            "await fixture_add(a=\"1\", b=3)",
            type_error("invalid-argument-type"),
        );
        run(
            log,
            "a3",
            base + 2000,
            "s1",
            "await fixture_add(a=1, b=3)",
            Classification::ok(),
        );
        // run s2: a ban that is never followed by a success
        run(
            log,
            "b1",
            base + 3000,
            "s2",
            "from typing import Any",
            type_error("ban:any"),
        );
        // run s3: a probe, a runtime error a typed result would prevent, json.loads
        run(
            log,
            "c1",
            base + 4000,
            "s3",
            "await fixture_json_text()",
            Classification::ok(),
        );
        upstream(log, "c1", "json_text", Outcome::Ok, "untyped");
        upstream(log, "c1", "json_text", Outcome::Ok, "untyped");
        run(
            log,
            "c2",
            base + 5000,
            "s3",
            "data = await fixture_json_text()\ndata[\"k\"]",
            Classification::new(Outcome::RuntimeError, "KeyError: 'k'"),
        );
        run(
            log,
            "c3",
            base + 6000,
            "s3",
            "import json\njson.loads(\"[1]\")",
            Classification::ok(),
        );
        run(
            log,
            "c4",
            base + 7000,
            "s3",
            "await fixture_mismatched_output()",
            Classification::new(Outcome::OutputMismatch, "x"),
        );
        upstream(
            log,
            "c4",
            "mismatched_output",
            Outcome::OutputMismatch,
            "schema",
        );
        // another client's calls stay out of this client's numbers
        log.call(CallRecord {
            caller: Caller {
                client_name: Some("codex".to_owned()),
                ..Caller::default()
            },
            tool: "search_tools",
            input: Some("x".to_owned()),
            classification: Classification::ok(),
            duration: Duration::from_millis(1),
            result_bytes: 1,
            execution_id: None,
        });
    })
    .await?;

    assert!(strictness.contains("### claude-code"), "{strictness}");
    assert!(
        strictness.contains("| `invalid-argument-type` | 2 | 1 | 50% |"),
        "{strictness}"
    );
    assert!(
        strictness.contains("| `ban:any` | 1 | 0 | 100% |"),
        "{strictness}"
    );
    assert!(
        strictness.contains("Runs abandoned after a type error: 1 of 2 (50%)"),
        "{strictness}"
    );
    assert!(
        strictness.contains("`output_mismatch` by tool: `fixture.mismatched_output` (1)"),
        "{strictness}"
    );
    assert!(
        strictness.contains("Runtime errors typing should have caught: 1"),
        "{strictness}"
    );
    assert!(strictness.contains("Probe executes: 1"), "{strictness}");
    assert!(
        strictness.contains("Scripts using `json.loads`: 1"),
        "{strictness}"
    );
    assert!(
        strictness.contains("`fixture.json_text` (2)"),
        "{strictness}"
    );
    assert!(
        strictness.contains("**Verdict:** Looks balanced"),
        "every count is under its threshold:\n{strictness}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn review_verdict_names_the_side_that_is_off() -> TestResult {
    use codemode_mcp::usage::report::{MIN_RULE_ERRORS, PROBE_LIMIT};

    let strict = strictness_of(|log, base| {
        for index in 0..MIN_RULE_ERRORS {
            run(
                log,
                &format!("e{index}"),
                base + index * 1000,
                &format!("s{index}"),
                "await fixture_add(a=\"1\", b=2)",
                type_error("invalid-argument-type"),
            );
        }
    })
    .await?;
    assert!(
        strict.contains(
            "**Verdict:** Looks too strict: `invalid-argument-type` errors are 100% unresolved"
        ),
        "{strict}"
    );

    let loose = strictness_of(|log, base| {
        for index in 0..PROBE_LIMIT {
            let id = format!("p{index}");
            run(
                log,
                &id,
                base + index * 1000,
                "s1",
                "await fixture_json_text()",
                Classification::ok(),
            );
            upstream(log, &id, "json_text", Outcome::Ok, "untyped");
        }
    })
    .await?;
    assert!(
        loose.contains(&format!(
            "**Verdict:** Looks too loose: {PROBE_LIMIT} probe executes, top untyped: `fixture.json_text`"
        )),
        "{loose}"
    );

    Ok(())
}

#[test]
fn validator_agrees_with_the_stub_types() -> TestResult {
    let schema = |value: Value| -> Result<serde_json::Map<String, Value>, Box<dyn Error>> {
        value
            .as_object()
            .cloned()
            .ok_or_else(|| "schema is not an object".into())
    };

    // a nullable reference is `X | None` in the stub
    let nullable_ref = schema(json!({
        "$defs": {"X": {"type": "object", "properties": {"id": {"type": "string"}}}},
        "type": "object",
        "properties": {"a": {"$ref": "#/$defs/X", "nullable": true}},
    }))?;
    assert!(validate(&nullable_ref, &json!({"a": null})).is_ok());
    assert!(validate(&nullable_ref, &json!({"a": 1})).is_err());

    // `properties` or `items` alone make a TypedDict or list in the stub
    let implied_object =
        schema(json!({"properties": {"a": {"type": "string"}}, "required": ["a"]}))?;
    assert!(validate(&implied_object, &json!("oops")).is_err());
    assert!(validate(&implied_object, &json!({"a": "x"})).is_ok());
    let implied_array = schema(json!({"items": {"type": "string"}}))?;
    assert!(validate(&implied_array, &json!({"a": "x"})).is_err());
    assert!(validate(&implied_array, &json!(["x"])).is_ok());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_scripts_cannot_take_the_daemon_down() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    // the deepest nesting that fits under the size cap: overflowed a tokio
    // worker stack when the host parsed it there
    let deep = format!("x = 1{}\nx", "+1".repeat(32 * 1024 - 8));
    let result = execute(&harness.client, &deep).await?;
    assert!(!text_of(&result).is_empty());

    let oversized = format!("x = 1{}\nx", "+1".repeat(40 * 1024));
    let result = execute(&harness.client, &oversized).await?;
    let text = text_of(&result);
    assert_eq!(result.is_error, Some(true), "{text}");
    assert!(
        text.contains("scripts are limited to 65536 bytes"),
        "{text}"
    );

    // still serving
    let body = harness.execute_json("1 + 1").await?;
    assert_eq!(body["result"], 2, "{body}");

    harness.stop().await
}

#[test]
fn self_referring_schema_branches_stay_bounded() -> TestResult {
    // every level offers two branches that both refer back to the root, so
    // an unbounded check would visit about 2^32 nodes
    let schema = json!({"anyOf": [{"$ref": "#"}, {"$ref": "#"}], "type": "string"});
    let schema = schema
        .as_object()
        .cloned()
        .ok_or("schema is not an object")?;
    let started = std::time::Instant::now();
    let _ = validate(&schema, &json!(1));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    Ok(())
}
