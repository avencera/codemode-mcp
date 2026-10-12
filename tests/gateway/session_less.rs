//! Session-less serving: 2026-07-28 requests and older `initialize` clients
//! both work over HTTP without an `mcp-session-id`, callers are identified
//! by their client, and long waits send progress notifications

use codemode_mcp::store;
use rmcp::{
    model::{
        CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation, ProtocolVersion,
    },
    service::{ClientLifecycleMode, ClientServiceExt},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Value, json};

use super::harness::{Harness, TestResult, text_of};

/// What a raw MCP POST answered
struct Reply {
    status: u16,
    session_header: Option<String>,
    messages: Vec<Value>,
}

impl Reply {
    /// The JSON-RPC response, as opposed to notifications
    fn response(&self) -> Option<&Value> {
        self.messages
            .iter()
            .find(|message| message.get("id").is_some())
    }

    fn notifications(&self, method: &str) -> Vec<&Value> {
        self.messages
            .iter()
            .filter(|message| message["method"] == method)
            .collect()
    }
}

/// Posts one JSON-RPC message with the headers a client of `version` sends
async fn post(
    harness: &Harness,
    version: &str,
    user_agent: Option<&str>,
    body: &Value,
) -> Result<Reply, Box<dyn std::error::Error>> {
    let mut request = harness
        .http
        .post(format!("{}/mcp", harness.base()))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", version);
    if let Some(method) = body["method"].as_str() {
        request = request.header("mcp-method", method);
    }
    if body["method"] == "tools/call" {
        request = request.header("mcp-name", body["params"]["name"].as_str().unwrap_or(""));
    }
    if let Some(agent) = user_agent {
        request = request.header("user-agent", agent);
    }

    let response = request.body(body.to_string()).send().await?;
    let status = response.status().as_u16();
    let session_header = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let text = response.text().await?;
    let messages = match serde_json::from_str::<Value>(&text) {
        Ok(message) => vec![message],
        // an event stream: one JSON message per `data:` line
        Err(_) => text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str(data.trim()).ok())
            .collect(),
    };

    Ok(Reply {
        status,
        session_header,
        messages,
    })
}

/// A 2026-07-28 request body with the per-request `_meta` the protocol requires
fn modern(id: u32, method: &str, params: Value, client: &str, progress: Option<&str>) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": client, "version": "9.9"},
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    if let Some(token) = progress {
        params["_meta"]["progressToken"] = json!(token);
    }

    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn execute_call(id: u32, code: &str, client: &str, progress: Option<&str>) -> Value {
    modern(
        id,
        "tools/call",
        json!({"name": "execute", "arguments": {"code": code}}),
        client,
        progress,
    )
}

/// The `result` text of a tool call reply
fn tool_text(reply: &Reply) -> Result<String, Box<dyn std::error::Error>> {
    let response = reply.response().ok_or("no response")?;
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .ok_or_else(|| format!("no tool text in {response}"))?;

    Ok(text.to_owned())
}

async fn logged_calls(
    harness: &Harness,
) -> Result<Vec<(Option<String>, Option<String>, Option<String>)>, Box<dyn std::error::Error>> {
    harness.app.usage().flush().await;
    let connection = store::open(harness.app.state_dir())?;
    let mut statement = connection.prepare(
        "SELECT session, client_name, client_version FROM calls WHERE tool = 'execute' ORDER BY id",
    )?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;

    Ok(rows)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_2026_07_28_request_flow_works_without_a_session() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let discover = post(
        &harness,
        "2026-07-28",
        None,
        &modern(1, "server/discover", json!({}), "claude-code", None),
    )
    .await?;
    assert_eq!(discover.status, 200, "{:?}", discover.messages);
    assert_eq!(discover.session_header, None);

    let reply = post(
        &harness,
        "2026-07-28",
        Some("claude-code/2.1.296 (cli)"),
        &execute_call(2, "1 + 1", "claude-code", None),
    )
    .await?;
    assert_eq!(reply.status, 200, "{:?}", reply.messages);
    assert_eq!(reply.session_header, None);
    let body: Value = serde_json::from_str(&tool_text(&reply)?)?;
    assert_eq!(body["result"], 2, "{body}");

    // `_meta` clientInfo wins over the user-agent and there is no session
    let calls = logged_calls(&harness).await?;
    assert_eq!(
        calls,
        vec![(None, Some("claude-code".to_owned()), Some("9.9".to_owned()))]
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rmcp_client_can_discover_and_call_without_a_session() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let config = StreamableHttpClientTransportConfig::with_uri(format!("{}/mcp", harness.base()));
    let info = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("discover-client", "4.2"),
    );
    let client = info
        .serve_with_lifecycle(
            StreamableHttpClientTransport::from_config(config),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let arguments = json!({ "code": "3 + 4" });
    let Value::Object(arguments) = arguments else {
        return Err("arguments must be an object".into());
    };
    let result = client
        .call_tool(CallToolRequestParams::new("execute").with_arguments(arguments))
        .await?;
    let body: Value = serde_json::from_str(&text_of(&result))?;
    assert_eq!(body["result"], 7, "{body}");
    client.cancel().await?;

    let calls = logged_calls(&harness).await?;
    assert_eq!(
        calls,
        vec![(
            None,
            Some("discover-client".to_owned()),
            Some("4.2".to_owned())
        )]
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_initialize_client_works_and_gets_no_session_id() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };

    let initialize = post(
        &harness,
        "2025-11-25",
        Some("legacy-agent/3.1"),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "legacy-agent", "version": "3.1"},
        }}),
    )
    .await?;
    assert_eq!(initialize.status, 200, "{:?}", initialize.messages);
    assert_eq!(initialize.session_header, None);
    let result = &initialize.response().ok_or("no initialize result")?["result"];
    assert_eq!(result["protocolVersion"], "2025-11-25", "{result}");

    // later requests carry no session and no clientInfo; the user-agent
    // identifies the client
    let reply = post(
        &harness,
        "2025-11-25",
        Some("legacy-agent/3.1"),
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "execute", "arguments": {"code": "5 + 5"}}}),
    )
    .await?;
    assert_eq!(reply.status, 200, "{:?}", reply.messages);
    let body: Value = serde_json::from_str(&tool_text(&reply)?)?;
    assert_eq!(body["result"], 10, "{body}");

    let calls = logged_calls(&harness).await?;
    assert_eq!(
        calls,
        vec![(
            None,
            Some("legacy-agent".to_owned()),
            Some("3.1".to_owned())
        )]
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_wait_sends_progress_notifications_to_a_client_with_a_token() -> TestResult {
    let Some(harness) = Harness::start("progress_interval_ms = 300", "").await? else {
        return Ok(());
    };
    let script = "await fixture_slow_echo(text=\"x\", delay_ms=1500)";

    let with_token = post(
        &harness,
        "2026-07-28",
        None,
        &execute_call(1, script, "claude-code", Some("tok-1")),
    )
    .await?;
    let progress = with_token.notifications("notifications/progress");
    assert!(!progress.is_empty(), "{:?}", with_token.messages);
    assert!(
        progress
            .iter()
            .all(|message| message["params"]["progressToken"] == "tok-1"),
        "{progress:?}"
    );
    let body: Value = serde_json::from_str(&tool_text(&with_token)?)?;
    assert_eq!(body["status"], "completed", "{body}");

    // a client that sent no token gets none
    let without_token = post(
        &harness,
        "2026-07-28",
        None,
        &execute_call(2, script, "claude-code", None),
    )
    .await?;
    assert!(
        without_token
            .notifications("notifications/progress")
            .is_empty(),
        "{:?}",
        without_token.messages
    );

    harness.stop().await
}
