//! End-to-end checks: a real HTTP server, a real Monty worker and a stdio
//! MCP fixture as the only upstream

use std::{
    error::Error,
    path::PathBuf,
    time::{Duration, Instant},
};

use codemode_mcp::{
    app::App,
    config::Config,
    server::{RunningServer, serve},
};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    service::{RoleClient, RunningService},
    transport::StreamableHttpClientTransport,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

type TestResult = Result<(), Box<dyn Error>>;
type Client = RunningService<RoleClient, ()>;

/// The Monty worker the tests run scripts in
///
/// A missing worker fails the test instead of skipping it, so a broken setup
/// cannot pass silently; `CODEMODE_SKIP_MONTY=1` opts out on purpose
fn monty_worker() -> Result<Option<PathBuf>, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".tools/bin/monty");
    if path.exists() {
        return Ok(Some(path));
    }
    if std::env::var("CODEMODE_SKIP_MONTY").as_deref() == Ok("1") {
        eprintln!("skipping: {} is missing", path.display());

        return Ok(None);
    }

    Err(format!(
        "{} is missing (see docs/design.md for how to fetch the Monty worker); \
         set CODEMODE_SKIP_MONTY=1 to skip these tests",
        path.display()
    )
    .into())
}

/// Config for one fixture upstream; `limits` and `server` add lines to the
/// `[limits]` and `[servers.fixture]` tables
fn config_for_fixture(
    worker: &std::path::Path,
    limits: &str,
    server: &str,
) -> Result<Config, Box<dyn Error>> {
    let text = format!(
        r#"
        listen = "127.0.0.1:0"
        worker_path = "{worker}"

        [limits]
        execute_wait_secs = 2
        {limits}

        [servers.fixture]
        command = "{fixture}"
        {server}
        "#,
        worker = worker.display(),
        fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
    );

    Ok(Config::parse(
        &text,
        std::path::Path::new("test-config.toml"),
    )?)
}

/// A running app, HTTP server and MCP client wired to the fixture upstream
struct Harness {
    app: App,
    server: RunningServer,
    client: Client,
}

impl Harness {
    /// `None` when the Monty worker is missing and skipping was requested
    async fn start(limits: &str, server: &str) -> Result<Option<Self>, Box<dyn Error>> {
        let Some(worker) = monty_worker()? else {
            return Ok(None);
        };

        let app = App::start(config_for_fixture(&worker, limits, server)?).await?;
        app.gateway().wait_ready(Duration::from_secs(30)).await;
        let server = serve(&app).await?;
        let url = format!("http://127.0.0.1:{}/mcp", server.local_addr().port());
        let client: Client = ().serve(StreamableHttpClientTransport::from_uri(url)).await?;

        Ok(Some(Self {
            app,
            server,
            client,
        }))
    }

    async fn execute_json(&self, code: &str) -> Result<Value, Box<dyn Error>> {
        let result = execute(&self.client, code).await?;
        assert_eq!(result.is_error, Some(false), "{}", text_of(&result));

        Ok(serde_json::from_str(&text_of(&result))?)
    }

    async fn stop(self) -> TestResult {
        self.client.cancel().await?;
        self.server.shutdown().await?;

        Ok(())
    }
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text())
        .map(|block| block.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn call(
    client: &Client,
    tool: &'static str,
    arguments: Value,
) -> Result<CallToolResult, Box<dyn Error>> {
    let Value::Object(arguments) = arguments else {
        return Err("arguments must be an object".into());
    };

    Ok(client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(arguments))
        .await?)
}

async fn execute(client: &Client, code: &str) -> Result<CallToolResult, Box<dyn Error>> {
    call(client, "execute", json!({ "code": code })).await
}

#[tokio::test(flavor = "multi_thread")]
async fn scripts_run_against_the_fixture_upstream() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let client = &harness.client;

    // search finds the fixture tool
    let found = call(
        client,
        "search_tools",
        json!({ "query": "add two integers" }),
    )
    .await?;
    assert!(
        text_of(&found).contains("fixture_add"),
        "search result: {}",
        text_of(&found)
    );

    // describe returns a typed stub carrying the documentation
    let described = call(
        client,
        "describe_tools",
        json!({ "names": ["fixture_slow_echo"] }),
    )
    .await?;
    let described = text_of(&described);
    assert!(
        described.contains("async def fixture_slow_echo("),
        "describe output: {described}"
    );
    assert!(
        described.contains("delay_ms"),
        "describe output: {described}"
    );

    // a plain call returns the tool's value
    let sum = execute(client, "int(await fixture_add(a=1, b=2))").await?;
    assert_eq!(sum.is_error, Some(false), "sum: {}", text_of(&sum));
    let body: Value = serde_json::from_str(&text_of(&sum))?;
    assert_eq!(body["result"], json!(3), "sum: {body}");

    // type errors come back as text the agent can act on
    let bad = execute(client, "x: int = await fixture_add(a=\"one\", b=2)\nx").await?;
    assert_eq!(bad.is_error, Some(true));
    assert!(
        text_of(&bad).contains("Type check failed"),
        "type error: {}",
        text_of(&bad)
    );

    // constructs Monty does not support are reported the same way
    let unsupported = execute(client, "class A: ...\nclass B(A): ...\nB()").await?;
    assert_eq!(
        unsupported.is_error,
        Some(true),
        "unsupported: {}",
        text_of(&unsupported)
    );
    assert!(!text_of(&unsupported).is_empty());

    // concurrent calls overlap instead of adding up
    let started = Instant::now();
    let both = execute(
        client,
        "import asyncio\n\
         a, b = await asyncio.gather(\n\
             fixture_slow_echo(text=\"a\", delay_ms=900),\n\
             fixture_slow_echo(text=\"b\", delay_ms=900),\n\
         )\n\
         [a[\"echoed\"], b[\"echoed\"]]",
    )
    .await?;
    let elapsed = started.elapsed();
    assert_eq!(both.is_error, Some(false), "gather: {}", text_of(&both));
    let body: Value = serde_json::from_str(&text_of(&both))?;
    assert_eq!(body["result"], json!(["a", "b"]));
    assert!(
        elapsed < Duration::from_millis(1700),
        "gather took {elapsed:?}, calls ran one after another"
    );

    // a script slower than the wait budget goes pending and can be awaited
    let slow = execute(
        client,
        "await fixture_slow_echo(text=\"late\", delay_ms=3500)",
    )
    .await?;
    let pending: Value = serde_json::from_str(&text_of(&slow))?;
    assert_eq!(pending["status"], "pending", "slow: {pending}");
    let id = pending["execution_id"]
        .as_str()
        .ok_or("pending result has no execution_id")?
        .to_owned();

    let mut finished = None;
    for _ in 0..5 {
        let result = call(client, "wait", json!({ "execution_id": id })).await?;
        let body: Value = serde_json::from_str(&text_of(&result))?;
        if body["status"] != "pending" {
            finished = Some(body);
            break;
        }
    }
    let finished = finished.ok_or("execution never finished")?;
    assert_eq!(finished["result"]["echoed"], "late", "finished: {finished}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn async_sleeps_run_concurrently() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let started = Instant::now();
    let body = harness
        .execute_json(
            "import asyncio\n\
             await asyncio.gather(asyncio.sleep(1), asyncio.sleep(1))\n\
             \"slept\"",
        )
        .await?;
    let elapsed = started.elapsed();

    assert_eq!(body["result"], "slept", "{body}");
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_millis(1700),
        "two one-second sleeps took {elapsed:?}"
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn huge_shared_results_are_truncated_not_expanded() -> TestResult {
    let Some(harness) = Harness::start("max_result_bytes = 20000", "").await? else {
        return Ok(());
    };

    // 2^30 leaves when expanded, a few dozen nodes in memory
    let started = Instant::now();
    let result = execute(&harness.client, "x=[1]\nfor i in range(30): x=[x,x]\nx").await?;
    let text = text_of(&result);

    assert_eq!(result.is_error, Some(false), "{text}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(text.len() < 60_000, "response was {} bytes", text.len());
    let body: Value = serde_json::from_str(&text)?;
    assert_eq!(body["truncated"], true, "{text}");
    assert!(
        body["notes"].to_string().contains("truncated"),
        "notes: {}",
        body["notes"]
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn ask_policy_fails_closed_without_an_approver() -> TestResult {
    let Some(harness) = Harness::start("", "[servers.fixture.tools.add]\npolicy = \"ask\"").await?
    else {
        return Ok(());
    };

    let denied = execute(&harness.client, "int(await fixture_add(a=1, b=2))").await?;
    let text = text_of(&denied);
    assert_eq!(denied.is_error, Some(true), "{text}");
    assert!(
        text.contains("requires approval; approvals are not configured"),
        "{text}"
    );
    assert!(text.contains("PermissionError"), "{text}");

    // other tools of the server are unaffected
    let body = harness.execute_json("await fixture_json_text()").await?;
    assert_eq!(body["result"], json!([1, 2, {"k": "v"}]));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn integers_beyond_i64_survive_both_directions() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let result = execute(
        &harness.client,
        "wide = await fixture_wide()\n\
         big: int = wide[\"n\"]\n\
         echoed = await fixture_echo_wide(n=big)\n\
         {\"echoed\": echoed[\"n\"], \"times_ten\": big * 10}",
    )
    .await?;
    let text = text_of(&result);

    assert_eq!(result.is_error, Some(false), "{text}");
    // textual comparison: a float round trip would print 1.8446744073709552e19
    assert!(text.contains("\"echoed\":18446744073709551615"), "{text}");
    assert!(
        text.contains("\"times_ten\":184467440737095516150"),
        "{text}"
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn root_ref_open_and_awkward_schemas_are_callable() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let body = harness
        .execute_json(
            "by_ref = await fixture_ref_root(query=\"q\")\n\
             open_args = await fixture_open_args(a=\"1\", extra=2)\n\
             odd = await fixture_odd_names(**{\"page-size\": 5})\n\
             {\"ref\": by_ref[\"query\"], \"extra\": open_args[\"extra\"], \"odd\": odd[\"page-size\"]}",
        )
        .await?;
    assert_eq!(
        body["result"],
        json!({"ref": "q", "extra": 2, "odd": 5}),
        "{body}"
    );

    // a tool that declares an output schema and delivers none raises, by name
    let body = harness
        .execute_json(
            "message = \"\"\n\
             try:\n    await fixture_declared_output()\n\
             except RuntimeError as error:\n    message = str(error)\n\
             message",
        )
        .await?;
    assert!(
        body["result"]
            .as_str()
            .is_some_and(|message| message.contains("fixture_declared_output")),
        "{body}"
    );

    // describe explains how to pass awkward names
    let described = call(
        &harness.client,
        "describe_tools",
        json!({ "names": ["fixture_odd_names"] }),
    )
    .await?;
    assert!(
        text_of(&described).contains("**{\"page-size\": value}"),
        "{}",
        text_of(&described)
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn wall_clock_limit_stops_the_script_and_cancels_the_upstream_call() -> TestResult {
    let Some(harness) = Harness::start("execution_timeout_secs = 1", "").await? else {
        return Ok(());
    };
    let marker = std::env::temp_dir().join(format!("codemode-cancel-{}", uuid::Uuid::new_v4()));
    let code = format!(
        "await fixture_hang(marker={:?})",
        marker.display().to_string()
    );

    let result = execute(&harness.client, &code).await?;
    let text = text_of(&result);
    assert_eq!(result.is_error, Some(true), "{text}");
    assert!(text.contains("wall-clock limit"), "{text}");

    // the fixture only writes the marker after it sees notifications/cancelled
    let mut seen = false;
    for _ in 0..50 {
        if marker.exists() {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = std::fs::remove_file(&marker);
    assert!(seen, "the upstream never saw a cancellation");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn full_queue_answers_busy_immediately() -> TestResult {
    let Some(harness) = Harness::start("max_workers = 1\nmax_queued_executions = 0", "").await?
    else {
        return Ok(());
    };

    let running = harness
        .app
        .executions()
        .start("await fixture_slow_echo(text=\"x\", delay_ms=1500)".to_owned())?;

    let busy = execute(&harness.client, "1").await?;
    assert_eq!(busy.is_error, Some(true));
    assert!(text_of(&busy).contains("busy"), "{}", text_of(&busy));

    // once the first script is done there is room again
    let _ = harness
        .app
        .executions()
        .wait(&running, Duration::from_secs(10))
        .await;
    let body = harness.execute_json("1 + 1").await?;
    assert_eq!(body["result"], 2);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn unexpected_host_headers_are_forbidden() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let address = harness.server.local_addr();

    let status_for = |host: &'static str| async move {
        let mut stream = TcpStream::connect(address).await?;
        let request = format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;

        Ok::<_, Box<dyn Error>>(response.lines().next().unwrap_or_default().to_owned())
    };

    assert!(status_for("evil.example.com").await?.contains("403"));
    assert!(status_for("100.64.1.2:7681").await?.contains("200"));
    assert!(
        status_for("mac.tailnet-name.ts.net")
            .await?
            .contains("200")
    );

    harness.stop().await
}
