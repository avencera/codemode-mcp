//! HTTP contract tests without sending real phone notifications or alarms

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use color_eyre::eyre::{Result, eyre};
use jiff::{SignedDuration, Timestamp};
use reqwest::Method;
use rmcp::{
    ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{CallToolRequestParams, CallToolResult},
};
use serde_json::{Value, json};

use super::{
    AlertKind, AlertParams, CancelParams, DelayParams, ScheduleParams, SuperalertAdapter,
    SwitchParams, TriggerKind, TriggerParams,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone)]
struct Recorded {
    method: Method,
    path: String,
    header: Option<String>,
    body: Value,
}

struct Fake {
    url: String,
    calls: Arc<Mutex<Vec<Recorded>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Fake {
    async fn start() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .fallback(record)
            .with_state(Arc::clone(&calls));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { url, calls, task })
    }

    fn adapter(&self) -> Result<SuperalertAdapter> {
        SuperalertAdapter::new(
            &format!("{}alert", self.url),
            &format!("{}ntfy", self.url),
            Some("private-topic".into()),
        )
    }

    fn calls(&self) -> Result<Vec<Recorded>> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .map_err(|_| eyre!("request lock poisoned"))
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn record(
    State(calls): State<Arc<Mutex<Vec<Recorded>>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let record = Recorded {
        method: method.clone(),
        path: uri.path().into(),
        header: headers
            .get("x-superalert")
            .and_then(|header| header.to_str().ok())
            .map(str::to_owned),
        body: body.clone(),
    };
    match calls.lock() {
        Ok(mut calls) => calls.push(record),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }

    if body["title"] == "refuse" {
        return (
            StatusCode::CONFLICT,
            "private-topic secret in upstream error",
        )
            .into_response();
    }
    if body["title"] == "unreadable" {
        return (StatusCode::OK, "not JSON private-topic").into_response();
    }
    if uri.path().starts_with("/redirect/") {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", "/alert/api/ack")],
        )
            .into_response();
    }
    if uri.path() == "/ntfy/" {
        let time = body["delay"]
            .as_str()
            .and_then(|delay| delay.parse::<i64>().ok())
            .unwrap_or(1_800_000_000);
        return axum::Json(json!({"id": "ntfy123", "time": time, "topic": "private-topic"}))
            .into_response();
    }
    if uri.path() == "/alert/api/alert" && body["deliver_at"].is_string() {
        return (
            StatusCode::CREATED,
            axum::Json(json!({
                "id": 42, "deliver_at": body["deliver_at"], "title": body["title"],
                "body": body["body"], "source": body["source"],
            })),
        )
            .into_response();
    }
    if uri.path() == "/alert/api/status" {
        return axum::Json(json!({"scheduled": [{"id": 42}], "critical": false})).into_response();
    }
    if uri.path() == "/alert/api/arm" {
        return axum::Json(json!({"armed_until": "2026-10-22T21:00:00-05:00"})).into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

fn alert(title: &str) -> AlertParams {
    AlertParams {
        title: title.into(),
        body: " Meeting details ".into(),
        source: " codex ".into(),
    }
}

#[tokio::test]
async fn regular_and_super_alerts_use_distinct_services() -> TestResult {
    let fake = Fake::start().await?;
    let adapter = fake.adapter()?;
    let Json(regular) = adapter
        .alert(Parameters(alert(" Phone ")))
        .await
        .map_err(tool_error)?;
    let Json(alarm) = adapter
        .super_alert(Parameters(alert(" Alarm ")))
        .await
        .map_err(tool_error)?;
    assert_eq!(regular.id.as_deref(), Some("ntfy123"));
    assert!(!regular.scheduled);
    assert!(alarm.id.is_none());
    assert!(!alarm.scheduled);
    let calls = fake.calls()?;
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].path, "/ntfy/");
    assert_eq!(
        calls[0].body,
        json!({"topic": "private-topic", "title": "Phone", "message": "Meeting details", "priority": 3})
    );
    assert_eq!(calls[1].path, "/alert/api/alert");
    assert_eq!(calls[1].header.as_deref(), Some("1"));
    assert_eq!(
        calls[1].body,
        json!({"title": "Alarm", "body": "Meeting details", "source": "codex"})
    );
    Ok(())
}

#[tokio::test]
async fn delayed_alerts_are_scheduled_by_the_correct_server_and_can_be_cancelled() -> TestResult {
    let fake = Fake::start().await?;
    let adapter = fake.adapter()?;
    let before = Timestamp::now().as_second();
    for kind in [AlertKind::Regular, AlertKind::Super] {
        let Json(receipt) = adapter
            .delay_alert(Parameters(DelayParams {
                alert: alert("Later"),
                kind,
                delay_seconds: 1800,
            }))
            .await
            .map_err(tool_error)?;
        assert!(receipt.scheduled);
        assert!(
            receipt
                .deliver_at
                .as_deref()
                .is_some_and(|time| time.contains("America/Chicago"))
        );
        adapter
            .cancel_alert(Parameters(CancelParams {
                kind,
                id: receipt.id.ok_or("missing id")?,
            }))
            .await
            .map_err(tool_error)?;
    }
    let calls = fake.calls()?;
    let delay = calls[0].body["delay"]
        .as_str()
        .ok_or("missing ntfy delay")?
        .parse::<i64>()?;
    assert!(delay >= before + 1800 && delay <= Timestamp::now().as_second() + 1800);
    assert_eq!(calls[1].method, Method::DELETE);
    assert_eq!(calls[1].path, "/ntfy/private-topic/ntfy123");
    let at: Timestamp = calls[2].body["deliver_at"]
        .as_str()
        .ok_or("missing time")?
        .parse()?;
    assert!(at.as_second() >= before + 1800);
    assert_eq!(calls[3].path, "/alert/api/scheduled/42");
    assert_eq!(calls[3].method, Method::DELETE);
    Ok(())
}

#[tokio::test]
async fn mcp_schedule_schema_accepts_flat_arguments_and_returns_typed_receipts() -> TestResult {
    let fake = Fake::start().await?;
    let (server_io, client_io) = tokio::io::duplex(8192);
    let adapter = fake.adapter()?;
    let task = tokio::spawn(async move {
        let service = adapter
            .serve(server_io)
            .await
            .map_err(|error| error.to_string())?;
        service.waiting().await.map_err(|error| error.to_string())?;
        Ok::<_, String>(())
    });
    let client = ().serve(client_io).await?;
    let tools = client.list_all_tools().await?;
    let tool = tools
        .iter()
        .find(|tool| tool.name == "schedule_alert")
        .ok_or("no schedule tool")?;
    assert!(tool.output_schema.is_some());
    for name in ["title", "body", "source", "kind", "deliver_at"] {
        assert!(
            tool.input_schema["properties"].get(name).is_some(),
            "missing {name}: {tool:?}"
        );
    }
    let at = Timestamp::now().checked_add(SignedDuration::from_hours(1))?;
    let result = client.call_tool(CallToolRequestParams::new("schedule_alert").with_arguments(
        json!({"title": "Meeting", "body": "Join now", "source": "codex", "kind": "super", "deliver_at": at.to_string()}).as_object().ok_or("arguments not object")?.clone(),
    )).await?;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let receipt = result.structured_content.ok_or("no structured receipt")?;
    assert_eq!(receipt["id"], "42");
    assert_eq!(receipt["kind"], "super");
    assert_eq!(receipt["scheduled"], true);
    client.cancel().await?;
    task.await??;
    Ok(())
}

#[tokio::test]
async fn invalid_requests_do_not_send_anything() -> TestResult {
    let fake = Fake::start().await?;
    let adapter = fake.adapter()?;
    for time in [
        "tomorrow",
        "2026-10-22T10:30:00",
        "2000-01-01T00:00:00-06:00",
        "2099-01-01T00:00:00-06:00",
    ] {
        assert!(
            adapter
                .schedule_alert(Parameters(ScheduleParams {
                    alert: alert("Meeting"),
                    kind: AlertKind::Super,
                    deliver_at: time.into()
                }))
                .await
                .is_err()
        );
    }
    for delay_seconds in [0, u32::MAX] {
        assert!(
            adapter
                .delay_alert(Parameters(DelayParams {
                    alert: alert("Meeting"),
                    kind: AlertKind::Super,
                    delay_seconds
                }))
                .await
                .is_err()
        );
    }
    for title in [" ".to_owned(), "é".repeat(121)] {
        assert!(
            adapter
                .super_alert(Parameters(alert(&title)))
                .await
                .is_err()
        );
    }
    assert!(
        adapter
            .cancel_alert(Parameters(CancelParams {
                kind: AlertKind::Regular,
                id: "../api/ack".into()
            }))
            .await
            .is_err()
    );
    assert!(
        adapter
            .cancel_alert(Parameters(CancelParams {
                kind: AlertKind::Super,
                id: "../ack".into()
            }))
            .await
            .is_err()
    );
    let no_topic = SuperalertAdapter::new(&fake.url, &fake.url, None)?;
    assert!(no_topic.alert(Parameters(alert("Meeting"))).await.is_err());
    assert!(fake.calls()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn control_calls_keep_the_api_prefix_and_action_header() -> TestResult {
    let fake = Fake::start().await?;
    let adapter = fake.adapter()?;
    adapter.acknowledge().await.map_err(tool_error)?;
    adapter.arm().await.map_err(tool_error)?;
    adapter.disarm().await.map_err(tool_error)?;
    adapter.reset().await.map_err(tool_error)?;
    adapter
        .set_critical(Parameters(SwitchParams { on: true }))
        .await
        .map_err(tool_error)?;
    adapter
        .set_trigger(Parameters(TriggerParams {
            kind: TriggerKind::Person,
            on: false,
        }))
        .await
        .map_err(tool_error)?;
    let status = adapter.status().await.map_err(tool_error)?;
    assert_eq!(
        status.structured_content.ok_or("no status")?["scheduled"][0]["id"],
        42
    );
    let calls = fake.calls()?;
    assert_eq!(
        calls
            .iter()
            .map(|call| call.path.as_str())
            .collect::<Vec<_>>(),
        [
            "/alert/api/ack",
            "/alert/api/arm",
            "/alert/api/disarm",
            "/alert/api/reset",
            "/alert/api/critical",
            "/alert/api/triggers",
            "/alert/api/status"
        ]
    );
    assert!(calls.iter().all(|call| call.header.as_deref() == Some("1")));
    assert_eq!(calls[4].body, json!({"on": true}));
    assert_eq!(calls[5].body, json!({"kind": "person", "on": false}));
    assert_eq!(calls[6].method, Method::GET);
    Ok(())
}

#[tokio::test]
async fn errors_hide_the_topic_and_redirects_do_not_replay_actions() -> TestResult {
    let fake = Fake::start().await?;
    let adapter = fake.adapter()?;
    for title in ["refuse", "unreadable"] {
        let result = adapter.alert(Parameters(alert(title))).await;
        let Err(error) = result else {
            return Err("expected an error".into());
        };
        let text = serde_json::to_string(&error)?;
        assert!(!text.contains("private-topic"), "{text}");
    }
    let redirect = SuperalertAdapter::new(&format!("{}redirect", fake.url), &fake.url, None)?;
    assert!(redirect.acknowledge().await.is_err());
    let calls = fake.calls()?;
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].path, "/redirect/api/ack");
    Ok(())
}

fn tool_error(error: CallToolResult) -> Box<dyn std::error::Error> {
    format!("{error:?}").into()
}
