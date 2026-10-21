//! The shipped Superalert stdio adapter, Python stubs and Monty against fake HTTP services

use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::post};
use jiff::{SignedDuration, Timestamp};
use serde_json::{Value, json};

use super::harness::{Harness, Setup, TestResult, call, text_of};

#[tokio::test(flavor = "multi_thread")]
async fn superalert_tools_run_as_typed_python_calls() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let api = Router::new()
        .route("/alert/api/alert", post(|Json(body): Json<Value>| async move {
            if body.get("deliver_at").is_some() {
                return (StatusCode::CREATED, Json(json!({"id": 7, "deliver_at": body["deliver_at"]}))).into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }))
        .route("/ntfy/", post(|Json(body): Json<Value>| async move {
            Json(json!({"id": "abc123", "time": body["delay"].as_str().and_then(|text| text.parse::<i64>().ok()).unwrap_or(1_800_000_000), "topic": body["topic"]}))
        }));
    let server = tokio::spawn(async move { axum::serve(listener, api).await });
    let extra = format!(
        r#"[servers.superalert]
command = {binary:?}
args = ["adapter", "superalert", "--url", "{base}/alert"]
env = {{ SUPERALERT_NTFY_SERVER = "{base}/ntfy", SUPERALERT_NTFY_TOPIC = "test-private-topic" }}
sensitive = false
"#,
        binary = env!("CARGO_BIN_EXE_codemode-mcp"),
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        server.abort();
        return Ok(());
    };
    let described = call(
        &harness.client,
        "describe_tools",
        json!({"names": ["superalert_schedule_alert", "superalert_delay_alert"]}),
    )
    .await?;
    let stubs = text_of(&described);
    assert!(stubs.contains("deliver_at: str"), "{stubs}");
    assert!(stubs.contains("delay_seconds: int"), "{stubs}");
    assert!(stubs.contains("regular"), "{stubs}");
    assert!(!stubs.contains("test-private-topic"), "{stubs}");
    let at = Timestamp::now().checked_add(SignedDuration::from_hours(1))?;
    let script = format!(
        r#"
phone = await superalert_alert(title="Phone", body="Details")
now = await superalert_super_alert(title="Alarm", source="test")
later = await superalert_schedule_alert(kind="super", title="Meeting", deliver_at="{at}")
reminder = await superalert_delay_alert(kind="regular", title="Soon", delay_seconds=1800)
[phone, now, later, reminder]
"#
    );
    let result = harness.execute_body(&script).await?;
    let receipts = result["result"]
        .as_array()
        .ok_or_else(|| format!("no receipts: {result}"))?;
    assert_eq!(receipts.len(), 4);
    assert_eq!(receipts[0]["id"], "abc123");
    assert_eq!(receipts[0]["kind"], "regular");
    assert_eq!(receipts[1]["scheduled"], false);
    assert_eq!(receipts[2]["id"], "7");
    assert_eq!(receipts[2]["scheduled"], true);
    assert_eq!(receipts[3]["kind"], "regular");
    assert_eq!(receipts[3]["scheduled"], true);
    assert!(!result.to_string().contains("test-private-topic"));
    harness.stop().await?;
    server.abort();
    Ok(())
}
