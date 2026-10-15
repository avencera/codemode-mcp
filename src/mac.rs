//! Asking the owner on the Mac the daemon runs on: whether they are at it,
//! a Touch ID prompt, a local notification and the approval page
//!
//! Presence only decides where a request is shown first. Approval still
//! takes something an agent on the same Mac cannot produce: a fingerprint
//! on the Touch ID sensor, or a passkey assertion on the approval page

#[cfg(target_os = "macos")]
mod macos;

use std::time::Duration;

#[cfg(target_os = "macos")]
pub use macos::MacOs;

use crate::{config::MacConfig, notify::BoxFuture};

/// Why something could not be shown on the Mac
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MacError(pub String);

/// How a Touch ID prompt ended
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchId {
    /// The owner's fingerprint matched
    Approved,
    /// The owner pressed the prompt's other button to read the request on
    /// the approval page, for another choice
    Review,
    /// The prompt was taken down by the system, for example because the
    /// screen locked, so the owner is likely away
    Away,
    /// Touch ID cannot be used: no sensor, none enrolled, or locked out
    Unavailable,
}

/// A local notification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacNotification {
    /// Headline
    pub title: String,
    /// Body text
    pub message: String,
    /// Page opened when the notification is clicked
    pub click: String,
}

/// The Mac the daemon runs on
pub trait Mac: Send + Sync + 'static {
    /// Whether the owner is at the Mac: the screen is unlocked and there was
    /// keyboard or mouse input within `idle`
    fn present(&self, idle: Duration) -> BoxFuture<'_, bool>;

    /// Asks for a fingerprint, showing `reason` and `cancel` as the title of
    /// the cancel button; dropping the future takes the prompt down
    fn touch_id<'a>(&'a self, reason: &'a str, cancel: &'a str) -> BoxFuture<'a, TouchId>;

    /// Shows `notification` in Notification Center
    fn notify<'a>(
        &'a self,
        notification: &'a MacNotification,
    ) -> BoxFuture<'a, Result<(), MacError>>;

    /// Opens `url` in the default browser
    fn open<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), MacError>>;
}

/// The Mac and how requests are asked on it
#[derive(Clone)]
pub struct OnMac {
    /// The Mac itself
    pub mac: std::sync::Arc<dyn Mac>,
    /// Idle limit, escalation delay and whether Touch ID is used
    pub config: MacConfig,
}
