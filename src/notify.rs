//! Push notifications for approval requests and adapter messages

use std::{future::Future, io::Read, pin::Pin, time::Duration};

use serde_json::json;

use crate::config::{NtfyConfig, expand_home};

/// Boxed future so [`Notifier`] stays usable as a trait object
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How long one ntfy request may take
const NTFY_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest token file accepted
const TOKEN_FILE_LIMIT: u64 = 4096;

/// Why a notification was not delivered; never carries the topic or token
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    /// The token file could not be used
    #[error("ntfy token file unusable: {0}")]
    Token(&'static str),
    /// The request did not complete
    #[error("ntfy request failed: {0}")]
    Request(&'static str),
    /// The server refused the message
    #[error("ntfy returned HTTP {0}")]
    Status(u16),
}

/// ntfy priority levels used here
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// ntfy 3
    Default,
    /// ntfy 4
    High,
    /// ntfy 5
    Urgent,
}

impl Priority {
    fn ntfy_level(self) -> u8 {
        match self {
            Self::Default => 3,
            Self::High => 4,
            Self::Urgent => 5,
        }
    }
}

/// One push notification
#[derive(Debug, Clone)]
pub struct Notification {
    /// Headline
    pub title: String,
    /// Body text
    pub message: String,
    /// Page opened when the notification is tapped
    pub click: Option<String>,
    /// How loudly the phone announces it
    pub priority: Priority,
    /// ntfy tag (an emoji short code)
    pub tag: &'static str,
}

/// Delivers notifications to the owner's phone
pub trait Notifier: Send + Sync + 'static {
    /// Sends `notification`
    fn notify<'a>(
        &'a self,
        notification: &'a Notification,
    ) -> BoxFuture<'a, Result<(), NotifyError>>;
}

/// Posts to an ntfy topic, as homebased does
pub struct Ntfy {
    client: reqwest::Client,
    config: NtfyConfig,
}

impl Ntfy {
    /// A notifier for `config`
    pub fn new(config: NtfyConfig) -> Self {
        // a bearer token sent over plain HTTP can be read by anyone on the path
        if config.token_file.is_some() && config.server.starts_with("http://") {
            tracing::warn!(
                server = %config.server,
                "an ntfy token is configured for a plain http:// server; it is sent unencrypted"
            );
        }

        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    async fn send(&self, notification: &Notification) -> Result<(), NotifyError> {
        let token = match &self.config.token_file {
            Some(path) => Some(read_token(&expand_home(path))?),
            None => None,
        };
        let mut body = json!({
            "topic": self.config.topic,
            "title": notification.title,
            "message": notification.message,
            "priority": notification.priority.ntfy_level(),
            "tags": [notification.tag],
        });
        if let Some(click) = &notification.click {
            body["click"] = json!(click);
        }

        // the topic travels in the body, so URLs in errors never reveal it
        let mut request = self
            .client
            .post(format!("{}/", self.config.server.trim_end_matches('/')))
            .timeout(NTFY_TIMEOUT)
            .json(&body);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|error| {
            NotifyError::Request(if error.is_timeout() {
                "timed out"
            } else if error.is_connect() {
                "could not connect"
            } else {
                "transport error"
            })
        })?;
        if !response.status().is_success() {
            return Err(NotifyError::Status(response.status().as_u16()));
        }

        Ok(())
    }
}

impl Notifier for Ntfy {
    fn notify<'a>(
        &'a self,
        notification: &'a Notification,
    ) -> BoxFuture<'a, Result<(), NotifyError>> {
        Box::pin(self.send(notification))
    }
}

fn read_token(path: &std::path::Path) -> Result<String, NotifyError> {
    let file = std::fs::File::open(path).map_err(|_| NotifyError::Token("cannot open"))?;
    let metadata = file
        .metadata()
        .map_err(|_| NotifyError::Token("cannot stat"))?;
    if !metadata.is_file() {
        return Err(NotifyError::Token("not a regular file"));
    }

    let mut text = String::new();
    file.take(TOKEN_FILE_LIMIT + 1)
        .read_to_string(&mut text)
        .map_err(|_| NotifyError::Token("not readable text"))?;
    if text.len() as u64 > TOKEN_FILE_LIMIT {
        return Err(NotifyError::Token("too large"));
    }
    let token = text.trim();
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err(NotifyError::Token("must hold one non-empty token"));
    }

    Ok(token.to_owned())
}
