//! Waking a phone through APNs with the owner's App Store Connect key
//!
//! The push names the request, the reference and the gateway, never a value.
//! It is time-sensitive, so it breaks through a Focus, and expires with the
//! read it asks about

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use companion_wire::{
    ASK_TIMEOUT,
    mobile::{PushEnvironment, PushToken, RequestId, push_keys},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use tokio::sync::Mutex;

use crate::config::{ApnsConfig, expand_home};

/// Apple accepts a provider token for an hour and refuses new ones more
/// often than every 20 minutes
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);
/// How long one push request may take
const PUSH_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest `.p8` file accepted
const KEY_FILE_LIMIT: u64 = 8 * 1024;
/// The notification category the app registers its actions under
const CATEGORY: &str = "READ_REQUEST";

/// Why a push was not delivered; never holds the device or provider token
#[derive(Debug, thiserror::Error)]
pub enum PushFailure {
    /// The `.p8` key could not be used
    #[error("the APNs key is unusable: {0}")]
    Key(String),
    /// The request did not complete
    #[error("the APNs request failed: {0}")]
    Request(&'static str),
    /// APNs refused the push
    #[error("APNs answered HTTP {status}: {reason}")]
    Refused {
        /// HTTP status
        status: u16,
        /// Apple's reason code
        reason: String,
    },
    /// The token is no longer valid for the app, e.g. it was deleted
    #[error("the device token is no longer valid")]
    Gone,
}

/// What a push says
#[derive(Debug, Clone)]
pub struct Alert {
    /// The read it asks about
    pub request: RequestId,
    /// The reference to read
    pub reference: String,
    /// The gateway Mac's short name
    pub gateway: String,
}

/// Sends pushes to the phones; cheap to clone
#[derive(Clone)]
pub struct Apns(std::sync::Arc<Inner>);

struct Inner {
    client: reqwest::Client,
    config: ApnsConfig,
    /// The provider token and when it was made
    token: Mutex<Option<(String, SystemTime)>>,
}

impl Apns {
    /// A sender signing with the key `config` names
    pub fn new(config: ApnsConfig) -> Self {
        Self(std::sync::Arc::new(Inner {
            client: reqwest::Client::new(),
            config,
            token: Mutex::new(None),
        }))
    }

    /// Sends `alert` to `token`
    pub async fn push(&self, token: &PushToken, alert: &Alert) -> Result<(), PushFailure> {
        let provider = self.provider_token().await?;
        let base = match (&self.0.config.server, token.environment) {
            (Some(server), _) => server.trim_end_matches('/').to_owned(),
            (None, PushEnvironment::Production) => "https://api.push.apple.com".to_owned(),
            (None, PushEnvironment::Development) => "https://api.sandbox.push.apple.com".to_owned(),
        };
        if !token.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PushFailure::Gone);
        }
        let expires = SystemTime::now()
            .checked_add(ASK_TIMEOUT)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |since| since.as_secs());
        let body = json!({
            "aps": {
                "alert": {
                    "title": "Approve a 1Password read",
                    "subtitle": format!("codemode-mcp on {}", alert.gateway),
                    "body": alert.reference,
                },
                "sound": "default",
                "interruption-level": "time-sensitive",
                "category": CATEGORY,
                "thread-id": "reads",
            },
            push_keys::REQUEST: alert.request.as_str(),
            push_keys::REFERENCE: alert.reference,
            push_keys::GATEWAY: alert.gateway,
        });

        let response = self
            .0
            .client
            .post(format!("{base}/3/device/{}", token.token))
            .timeout(PUSH_TIMEOUT)
            .bearer_auth(provider)
            .header("apns-topic", &self.0.config.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", expires.to_string())
            .header("apns-collapse-id", alert.request.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                PushFailure::Request(if error.is_timeout() {
                    "timed out"
                } else if error.is_connect() {
                    "could not connect"
                } else {
                    "transport error"
                })
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let reason = response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|body| body["reason"].as_str().map(str::to_owned))
            .unwrap_or_default();
        if status.as_u16() == 410 || matches!(reason.as_str(), "BadDeviceToken" | "Unregistered") {
            return Err(PushFailure::Gone);
        }
        if reason == "ExpiredProviderToken" {
            *self.0.token.lock().await = None;
        }

        Err(PushFailure::Refused {
            status: status.as_u16(),
            reason,
        })
    }

    /// The signed JWT APNs takes as the bearer, made again when it is near
    /// the end of its hour
    async fn provider_token(&self) -> Result<String, PushFailure> {
        let mut cached = self.0.token.lock().await;
        let now = SystemTime::now();
        if let Some((token, made)) = cached.as_ref()
            && now
                .duration_since(*made)
                .is_ok_and(|age| age < TOKEN_LIFETIME)
        {
            return Ok(token.clone());
        }

        let config = &self.0.config;
        let pem = read_key(&expand_home(&config.key_file))?;
        let key =
            EncodingKey::from_ec_pem(&pem).map_err(|error| PushFailure::Key(error.to_string()))?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(config.key_id.clone());
        let issued = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PushFailure::Key("the clock is before 1970".to_owned()))?
            .as_secs();
        let claims = json!({ "iss": config.team_id, "iat": issued });
        let token = jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|error| PushFailure::Key(error.to_string()))?;
        *cached = Some((token.clone(), now));

        Ok(token)
    }
}

fn read_key(path: &std::path::Path) -> Result<Vec<u8>, PushFailure> {
    use std::io::Read;

    let file = std::fs::File::open(path)
        .map_err(|error| PushFailure::Key(format!("cannot open {}: {error}", path.display())))?;
    let mut pem = Vec::new();
    file.take(KEY_FILE_LIMIT + 1)
        .read_to_end(&mut pem)
        .map_err(|error| PushFailure::Key(error.to_string()))?;
    if pem.len() as u64 > KEY_FILE_LIMIT {
        return Err(PushFailure::Key("the key file is too large".to_owned()));
    }

    Ok(pem)
}
