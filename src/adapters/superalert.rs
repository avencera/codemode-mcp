//! Phone notifications on Superalert's ntfy topic and full-device Superalert alarms
//!
//! Regular notifications stay at priority 3, so they never start the Mac alarm
//! Scheduling belongs to ntfy or Superalert, never to a sleeping MCP process

use std::{path::PathBuf, sync::Arc, time::Duration};

use color_eyre::eyre::{Result, bail, eyre};
use jiff::{SignedDuration, Timestamp, tz::TimeZone};
use reqwest::{Method, StatusCode, Url};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const DEFAULT_URL: &str = "https://lookout.camel-scylla.ts.net/alert/";
const MAX_AHEAD: i64 = 366 * 24 * 60 * 60;

#[derive(Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum AlertKind {
    /// Normal-priority phone notification; no full-device alarm
    Regular,
    /// Full-volume alarm on all devices, repeated until acknowledged
    Super,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct AlertParams {
    /// Required title, at most 120 characters
    title: String,
    /// Message text, at most 1000 characters
    #[serde(default)]
    body: String,
    /// Sender shown on the Superalert dashboard, at most 40 characters
    #[serde(default)]
    source: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ScheduleParams {
    #[serde(flatten)]
    alert: AlertParams,
    /// regular for a phone notification, super for a full-device alarm
    kind: AlertKind,
    /// Future RFC 3339 time with an explicit offset, e.g. 2026-10-22T10:30:00-05:00
    deliver_at: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DelayParams {
    #[serde(flatten)]
    alert: AlertParams,
    /// regular for a phone notification, super for a full-device alarm
    kind: AlertKind,
    /// Seconds from now; positive, at most 366 days; ntfy has its own narrower limits
    delay_seconds: u32,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CancelParams {
    /// The kind returned by the scheduling call
    kind: AlertKind,
    /// The id returned by the scheduling call
    id: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SwitchParams {
    /// Whether to enable critical alerts
    on: bool,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum TriggerKind {
    Chime,
    Person,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct TriggerParams {
    /// Doorbell press (chime) or person detection
    kind: TriggerKind,
    /// Whether this event can sound the alarm while armed
    on: bool,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
struct AlertReceipt {
    kind: AlertKind,
    /// Use with cancel_alert; absent for an immediate super alert
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    id: Option<String>,
    scheduled: bool,
    /// Confirmed delivery time in America/Chicago, including its UTC offset
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    deliver_at: Option<String>,
}

#[derive(Deserialize)]
struct Pending {
    id: u64,
    deliver_at: Timestamp,
}

#[derive(Deserialize)]
struct NtfyReceipt {
    id: String,
    time: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
struct Done {
    ok: bool,
}

#[derive(Default, Deserialize)]
struct LocalSettings {
    superalert_url: Option<String>,
    ntfy_server: Option<String>,
    ntfy_topic: Option<String>,
}

struct Inner {
    client: reqwest::Client,
    base: Url,
    ntfy: Url,
    topic: Option<String>,
}

/// A stdio MCP adapter for Superalert and its normal-priority phone notifications
#[derive(Clone)]
pub struct SuperalertAdapter(Arc<Inner>);

impl SuperalertAdapter {
    /// Connects to the dashboard base `url` and ntfy server, using `topic` for regular alerts
    ///
    /// No request is sent at construction; without a topic only regular alert calls fail
    pub fn new(url: &str, ntfy_server: &str, topic: Option<String>) -> Result<Self> {
        let base = base_url(url)?;
        let ntfy = base_url(ntfy_server)?;
        if topic.as_ref().is_some_and(|topic| {
            topic.is_empty()
                || topic.len() > 64
                || !topic
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        }) {
            bail!(
                "Superalert ntfy topic must have 1-64 ASCII letters, digits, underscores or hyphens"
            );
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .retry(reqwest::retry::never())
            // redirects must not replay an alarm or send the topic to another host
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self(Arc::new(Inner {
            client,
            base,
            ntfy,
            topic,
        })))
    }

    /// Reads Mac app settings, with SUPERALERT_URL, SUPERALERT_NTFY_SERVER and
    /// SUPERALERT_NTFY_TOPIC overrides; an explicit `url` overrides both sources
    pub fn from_local(url: Option<&str>) -> Result<Self> {
        let settings = local_settings()?;
        let env_url = std::env::var("SUPERALERT_URL").ok();
        let ntfy_server = std::env::var("SUPERALERT_NTFY_SERVER").ok();
        let topic = std::env::var("SUPERALERT_NTFY_TOPIC")
            .ok()
            .or(settings.ntfy_topic);

        Self::new(
            url.or(env_url.as_deref())
                .or(settings.superalert_url.as_deref())
                .unwrap_or(DEFAULT_URL),
            ntfy_server
                .as_deref()
                .or(settings.ntfy_server.as_deref())
                .unwrap_or("https://ntfy.sh"),
            topic,
        )
    }

    /// Serves MCP on stdin and stdout until the client disconnects
    pub async fn serve_stdio(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.serve(rmcp::transport::stdio())
            .await?
            .waiting()
            .await?;
        Ok(())
    }

    fn topic(&self) -> Result<&str, CallToolResult> {
        self.0.topic.as_deref().ok_or_else(|| {
            failed("regular alerts need the Superalert Mac settings or SUPERALERT_NTFY_TOPIC")
        })
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<&Value>,
    ) -> Result<reqwest::Response, CallToolResult> {
        let mut request = self
            .0
            .client
            .request(method, url)
            .header("x-superalert", "1");
        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await.map_err(transport_error)?;
        if !response.status().is_success() {
            // upstream error bodies and URLs may contain the private ntfy topic
            return Err(failed(format!(
                "alert service returned HTTP {}; check the request and service status",
                response.status().as_u16()
            )));
        }

        Ok(response)
    }

    async fn api(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<reqwest::Response, CallToolResult> {
        let url = self
            .0
            .base
            .join(path)
            .map_err(|_| failed("invalid Superalert API path"))?;
        self.request(method, url, body).await
    }

    async fn action(&self, path: &str, body: Option<&Value>) -> Result<Json<Done>, CallToolResult> {
        self.api(Method::POST, path, body).await?;
        Ok(Json(Done { ok: true }))
    }

    async fn send(
        &self,
        kind: AlertKind,
        alert: AlertParams,
        at: Option<Timestamp>,
    ) -> Result<Json<AlertReceipt>, CallToolResult> {
        let alert = alert.validate()?;
        match kind {
            AlertKind::Super => self.send_super(alert, at).await,
            AlertKind::Regular => self.send_regular(alert, at).await,
        }
    }

    async fn send_super(
        &self,
        alert: AlertParams,
        at: Option<Timestamp>,
    ) -> Result<Json<AlertReceipt>, CallToolResult> {
        let mut body = json!({"title": alert.title, "body": alert.body, "source": alert.source});
        if let Some(at) = at {
            body["deliver_at"] = json!(at.to_string());
        }

        let response = self.api(Method::POST, "api/alert", Some(&body)).await?;
        let pending = match response.status() {
            StatusCode::CREATED => Some(decode::<Pending>(response).await?),
            StatusCode::NO_CONTENT => None,
            _ => return Err(failed("unexpected Superalert response")),
        };
        // a timestamp can become past while the request is in flight; report what the server did
        Ok(Json(AlertReceipt {
            kind: AlertKind::Super,
            scheduled: pending.is_some(),
            id: pending.as_ref().map(|pending| pending.id.to_string()),
            deliver_at: pending
                .map(|pending| central(pending.deliver_at))
                .transpose()?,
        }))
    }

    async fn send_regular(
        &self,
        alert: AlertParams,
        at: Option<Timestamp>,
    ) -> Result<Json<AlertReceipt>, CallToolResult> {
        let mut body = json!({
            "topic": self.topic()?, "title": alert.title,
            "message": if alert.body.is_empty() { &alert.title } else { &alert.body },
            "priority": 3,
        });
        if let Some(at) = at {
            body["delay"] = json!(at.as_second().to_string());
        }

        let response = self
            .request(Method::POST, self.0.ntfy.clone(), Some(&body))
            .await?;
        let receipt: NtfyReceipt = decode(response).await?;
        let deliver_at = if at.is_some() {
            Some(central(
                Timestamp::from_second(receipt.time)
                    .map_err(|_| failed("invalid ntfy delivery time"))?,
            )?)
        } else {
            None
        };

        Ok(Json(AlertReceipt {
            kind: AlertKind::Regular,
            id: Some(receipt.id),
            scheduled: at.is_some(),
            deliver_at,
        }))
    }
}

impl AlertParams {
    fn validate(self) -> Result<Self, CallToolResult> {
        let alert = Self {
            title: self.title.trim().into(),
            body: self.body.trim().into(),
            source: self.source.trim().into(),
        };
        if alert.title.is_empty() || alert.title.chars().count() > 120 {
            return Err(failed("title must have 1-120 characters"));
        }
        if alert.body.chars().count() > 1000 || alert.source.chars().count() > 40 {
            return Err(failed(
                "body must have at most 1000 characters; source at most 40",
            ));
        }

        Ok(alert)
    }
}

#[tool_router]
impl SuperalertAdapter {
    #[tool(
        description = "Send a regular phone notification on the existing Superalert ntfy topic at normal priority. Does not sound the full-device alarm."
    )]
    async fn alert(
        &self,
        Parameters(alert): Parameters<AlertParams>,
    ) -> Result<Json<AlertReceipt>, CallToolResult> {
        self.send(AlertKind::Regular, alert, None).await
    }

    #[tool(
        description = "Sound a full Superalert alarm on every phone and Mac now, at full volume, repeating until acknowledged. Replaces any sounding alarm."
    )]
    async fn super_alert(
        &self,
        Parameters(alert): Parameters<AlertParams>,
    ) -> Result<Json<AlertReceipt>, CallToolResult> {
        self.send(AlertKind::Super, alert, None).await
    }

    #[tool(
        description = "Schedule a regular phone notification or full Superalert alarm for a future RFC 3339 time with an explicit offset. Runs on the server and survives MCP restarts. Regular alerts use ntfy's scheduling limits (normally 10 seconds to 3 days); super alerts allow at most 366 days. Returns an id for cancel_alert."
    )]
    async fn schedule_alert(
        &self,
        Parameters(params): Parameters<ScheduleParams>,
    ) -> Result<Json<AlertReceipt>, CallToolResult> {
        let at = params
            .deliver_at
            .parse::<Timestamp>()
            .map_err(|_| failed("deliver_at must be RFC 3339 with an explicit UTC offset"))?;
        future(at)?;
        self.send(params.kind, params.alert, Some(at)).await
    }

    #[tool(
        description = "Send a regular phone notification or full Superalert alarm after delay_seconds. Scheduling is server-side, not a local sleep. Returns an id for cancel_alert. Regular alerts use ntfy's scheduling limits (normally 10 seconds to 3 days)."
    )]
    async fn delay_alert(
        &self,
        Parameters(params): Parameters<DelayParams>,
    ) -> Result<Json<AlertReceipt>, CallToolResult> {
        if params.delay_seconds == 0 || i64::from(params.delay_seconds) > MAX_AHEAD {
            return Err(failed(
                "delay_seconds must be positive and at most 366 days",
            ));
        }
        let at = Timestamp::now()
            .checked_add(SignedDuration::from_secs(i64::from(params.delay_seconds)))
            .map_err(|_| failed("delay is out of range"))?;
        self.send(params.kind, params.alert, Some(at)).await
    }

    #[tool(
        description = "Cancel an alert using its kind and id from schedule_alert or delay_alert. For super alerts this removes a pending alarm only; use acknowledge to stop a sounding alarm. Regular cancellation uses ntfy's delete API."
    )]
    async fn cancel_alert(
        &self,
        Parameters(params): Parameters<CancelParams>,
    ) -> Result<Json<Done>, CallToolResult> {
        match params.kind {
            AlertKind::Super => {
                let id = params
                    .id
                    .parse::<u64>()
                    .map_err(|_| failed("super alert id must be an unsigned integer"))?;
                self.api(Method::DELETE, &format!("api/scheduled/{id}"), None)
                    .await?;
            }
            AlertKind::Regular => {
                if params.id.is_empty()
                    || !params.id.bytes().all(|byte| byte.is_ascii_alphanumeric())
                {
                    return Err(failed(
                        "regular alert id must contain only ASCII letters and digits",
                    ));
                }
                let url = self
                    .0
                    .ntfy
                    .join(&format!("{}/{}", self.topic()?, params.id))
                    .map_err(|_| failed("invalid ntfy cancellation path"))?;
                self.request(Method::DELETE, url, None).await?;
            }
        }

        Ok(Json(Done { ok: true }))
    }

    #[tool(
        description = "Read Superalert's current alarm, pending super alerts, doorbell state, device readiness and settings. Does not list regular notifications scheduled in ntfy.",
        annotations(read_only_hint = true)
    )]
    async fn status(&self) -> Result<CallToolResult, CallToolResult> {
        let response = self.api(Method::GET, "api/status", None).await?;
        let value: Value = decode(response).await?;
        if !value.is_object() {
            return Err(failed("invalid Superalert status response"));
        }
        Ok(CallToolResult::structured(value))
    }

    #[tool(
        description = "Acknowledge (Got it) and silence the current full Superalert alarm across devices. Leaves other-app scheduled alerts unchanged."
    )]
    async fn acknowledge(&self) -> Result<Json<Done>, CallToolResult> {
        self.action("api/ack", None).await
    }

    #[tool(
        description = "Arm doorbell alerts until the server's configured cutoff. Does not create an other-app alarm."
    )]
    async fn arm(&self) -> Result<CallToolResult, CallToolResult> {
        let response = self.api(Method::POST, "api/arm", None).await?;
        Ok(CallToolResult::structured(decode::<Value>(response).await?))
    }

    #[tool(
        description = "Turn doorbell alerts off and stop the current alarm. Leaves pending other-app alerts unchanged."
    )]
    async fn disarm(&self) -> Result<Json<Done>, CallToolResult> {
        self.action("api/disarm", None).await
    }

    #[tool(
        description = "Stop the alarm, disarm the doorbell, and clear recent events and warnings. Does not cancel scheduled alerts or change critical-alert settings."
    )]
    async fn reset(&self) -> Result<Json<Done>, CallToolResult> {
        self.action("api/reset", None).await
    }

    #[tool(
        description = "Enable or disable escalation to critical Pushover alerts for unanswered alarms. Requires Pushover to be configured on the server."
    )]
    async fn set_critical(
        &self,
        Parameters(params): Parameters<SwitchParams>,
    ) -> Result<Json<Done>, CallToolResult> {
        self.action("api/critical", Some(&json!({"on": params.on})))
            .await
    }

    #[tool(
        description = "Enable or disable a doorbell event as an alarm trigger while armed: chime for a button press, person for person detection."
    )]
    async fn set_trigger(
        &self,
        Parameters(params): Parameters<TriggerParams>,
    ) -> Result<Json<Done>, CallToolResult> {
        self.action(
            "api/triggers",
            Some(&json!({"kind": params.kind, "on": params.on})),
        )
        .await
    }
}

#[tool_handler]
impl ServerHandler for SuperalertAdapter {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Regular alerts are normal-priority phone notifications through ntfy on the existing Superalert topic. Super alerts sound every device until acknowledged. Use schedule_alert for an explicit future time, or delay_alert for a relative delay; choose kind regular or super. Never retry an uncertain send automatically, as it can duplicate an alert. status lists scheduled super alerts only. Delivery times in receipts use America/Chicago.",
        )
    }
}

fn base_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).map_err(|_| eyre!("alert service URL is invalid"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("alert service URL must use HTTP(S), with no credentials, query or fragment");
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

fn local_settings() -> Result<LocalSettings> {
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(LocalSettings::default());
    };
    let path = PathBuf::from(home).join("Library/Application Support/superalert/mac.toml");
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LocalSettings::default());
        }
        Err(_) => bail!("cannot read Superalert Mac settings"),
    };
    // TOML errors can quote the secret topic's source line
    toml::from_str(&text).map_err(|_| eyre!("cannot parse Superalert Mac settings"))
}

fn future(at: Timestamp) -> Result<(), CallToolResult> {
    let ahead = at.duration_since(Timestamp::now());
    if ahead <= SignedDuration::ZERO || ahead > SignedDuration::from_secs(MAX_AHEAD) {
        return Err(failed(
            "deliver_at must be in the future and at most 366 days away",
        ));
    }
    Ok(())
}

fn central(at: Timestamp) -> Result<String, CallToolResult> {
    let zone = TimeZone::get("America/Chicago").map_err(|_| {
        failed("Central time zone data is unavailable; delivery may have succeeded")
    })?;
    Ok(at.to_zoned(zone).to_string())
}

fn failed(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

fn transport_error(error: reqwest::Error) -> CallToolResult {
    failed(if error.is_timeout() {
        "alert request timed out; delivery is unknown, check before retrying"
    } else {
        "alert request failed; delivery is unknown, check before retrying"
    })
}

async fn decode<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, CallToolResult> {
    response
        .json()
        .await
        .map_err(|_| failed("invalid alert service response; delivery may have succeeded"))
}

#[cfg(test)]
mod tests;
