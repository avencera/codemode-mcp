//! The real Mac: CoreGraphics for presence, LocalAuthentication for Touch
//! ID, `terminal-notifier` for notifications and `open` for the page

use std::{ffi::c_void, path::Path, sync::Mutex, time::Duration};

use block2::RcBlock;
use objc2::{rc::Retained, runtime::Bool};
use objc2_core_foundation::{CFBoolean, CFString, CFType};
use objc2_core_graphics::{
    CGEventSource, CGEventSourceStateID, CGEventType, CGSessionCopyCurrentDictionary,
};
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};
use tokio::{process::Command, sync::oneshot};

use super::{Mac, MacError, MacNotification, TouchId};
use crate::notify::BoxFuture;

/// Where Homebrew installs `terminal-notifier` on Apple silicon and Intel;
/// a LaunchAgent's `PATH` holds neither
const TERMINAL_NOTIFIER: [&str; 2] = [
    "/opt/homebrew/bin/terminal-notifier",
    "/usr/local/bin/terminal-notifier",
];
/// `kCGAnyInputEventType`: the most recent input of any kind
const ANY_INPUT: CGEventType = CGEventType(u32::MAX);
/// Cancel button of the Touch ID prompt; pressing it opens the approval page
const REVIEW_TITLE: &str = "Review…";
/// Pause after a prompt closes before the next queued one may show
const PROMPT_GAP: Duration = Duration::from_secs(1);

/// The Mac the daemon runs on
#[derive(Default)]
pub struct MacOs {
    /// One Touch ID prompt at a time; a second request waits its turn
    prompt: tokio::sync::Mutex<()>,
}

impl MacOs {
    /// The Mac, as seen from a LaunchAgent in the owner's login session
    pub fn new() -> Self {
        Self::default()
    }
}

/// Whether the login session's screen is locked; a session that cannot be
/// read counts as locked, so the request goes to the phone
fn screen_locked() -> bool {
    let Some(session) = CGSessionCopyCurrentDictionary() else {
        return true;
    };
    // the key is present only while the screen is locked
    let key = CFString::from_static_str("CGSSessionScreenIsLocked");
    let value = unsafe { session.value((&*key as *const CFString).cast::<c_void>()) };
    let value = unsafe { value.cast::<CFType>().as_ref() };

    value
        .and_then(CFType::downcast_ref::<CFBoolean>)
        .is_some_and(CFBoolean::as_bool)
}

fn idle() -> Duration {
    let seconds = CGEventSource::seconds_since_last_event_type(
        CGEventSourceStateID::CombinedSessionState,
        ANY_INPUT,
    );

    Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX)
}

/// An `LAContext` that can cross threads, and is invalidated when dropped
/// so a prompt nobody waits for leaves the screen
struct Context(Retained<LAContext>);

// SAFETY: LAContext is not main-thread-only, and Apple documents
// `invalidate` as the way to end an evaluation from elsewhere; the context
// is only messaged from the task that owns this wrapper
unsafe impl Send for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        // ends a prompt still showing; after the reply it does nothing
        unsafe { self.0.invalidate() };
    }
}

/// How an evaluation ended
type Reply = Result<(), LAError>;

fn evaluate(reason: &str) -> Result<(Context, oneshot::Receiver<Reply>), TouchId> {
    let context = Context(unsafe { LAContext::new() });
    let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
    // biometrics only: a password field could be typed into by anything that
    // drives the keyboard, a fingerprint cannot
    unsafe {
        context
            .0
            .setLocalizedFallbackTitle(Some(&NSString::from_str("")));
        context
            .0
            .setLocalizedCancelTitle(Some(&NSString::from_str(REVIEW_TITLE)));
    }
    if let Err(error) = unsafe { context.0.canEvaluatePolicy_error(policy) } {
        tracing::info!(code = error.code(), "Touch ID is not available");

        return Err(TouchId::Unavailable);
    }

    let (sender, receiver) = oneshot::channel::<Reply>();
    // the block must be `Fn`, and a sender is used once
    let sender = Mutex::new(Some(sender));
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let reply = if success.as_bool() {
            Ok(())
        } else {
            let code = unsafe { error.as_ref() }.map_or(0, |error| error.code());
            Err(LAError(code))
        };
        let sender = sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(sender) = sender {
            let _ = sender.send(reply);
        }
    });
    let reason = NSString::from_str(reason);
    unsafe {
        context
            .0
            .evaluatePolicy_localizedReason_reply(policy, &reason, &reply);
    }

    Ok((context, receiver))
}

/// What a finished evaluation means; only a matched fingerprint approves
fn answer_for(reply: Reply) -> TouchId {
    match reply {
        Ok(()) => TouchId::Approved,
        Err(LAError::UserCancel | LAError::UserFallback) => TouchId::Review,
        Err(LAError::SystemCancel | LAError::AppCancel) => TouchId::Away,
        Err(error) => {
            tracing::info!(code = error.0, "Touch ID prompt failed");

            TouchId::Unavailable
        }
    }
}

impl Mac for MacOs {
    fn present(&self, idle_limit: Duration) -> BoxFuture<'_, bool> {
        Box::pin(async move { !screen_locked() && idle() < idle_limit })
    }

    fn touch_id<'a>(&'a self, reason: &'a str) -> BoxFuture<'a, TouchId> {
        Box::pin(async move {
            let _turn = self.prompt.lock().await;
            let (context, receiver) = match evaluate(reason) {
                Ok(started) => started,
                Err(answer) => return answer,
            };
            // a sender dropped without a reply counts as a failed prompt
            let reply = receiver.await.unwrap_or(Err(LAError(0)));
            drop(context);
            // a second prompt right behind the first could catch a touch
            // meant for the one that just closed
            tokio::time::sleep(PROMPT_GAP).await;

            answer_for(reply)
        })
    }

    fn notify<'a>(
        &'a self,
        notification: &'a MacNotification,
    ) -> BoxFuture<'a, Result<(), MacError>> {
        Box::pin(async move {
            let program = TERMINAL_NOTIFIER
                .iter()
                .find(|path| Path::new(path).is_file())
                .ok_or_else(|| {
                    MacError(
                        "terminal-notifier is not installed; run `brew install \
                         terminal-notifier`"
                            .to_owned(),
                    )
                })?;
            let status = Command::new(program)
                .args(["-title", &notification.title])
                .args(["-message", &notification.message])
                .args(["-open", &notification.click])
                .args(["-sound", "default"])
                .status()
                .await
                .map_err(|error| MacError(format!("terminal-notifier did not start: {error}")))?;
            if !status.success() {
                return Err(MacError(format!("terminal-notifier exited with {status}")));
            }

            Ok(())
        })
    }

    fn open<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), MacError>> {
        Box::pin(async move {
            let status = Command::new("/usr/bin/open")
                .arg(url)
                .status()
                .await
                .map_err(|error| MacError(format!("open did not start: {error}")))?;
            if !status.success() {
                return Err(MacError(format!("open exited with {status}")));
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use objc2_local_authentication::LAError;

    use super::{TouchId, answer_for};

    #[test]
    fn only_a_matched_fingerprint_approves() {
        assert_eq!(answer_for(Ok(())), TouchId::Approved);

        let failures = [
            LAError::AuthenticationFailed,
            LAError::UserCancel,
            LAError::UserFallback,
            LAError::SystemCancel,
            LAError::PasscodeNotSet,
            LAError::BiometryNotAvailable,
            LAError::BiometryNotEnrolled,
            LAError::BiometryLockout,
            LAError::AppCancel,
            LAError::InvalidContext,
            LAError::NotInteractive,
            LAError(0),
            LAError(-1000),
        ];
        for error in failures {
            assert_ne!(answer_for(Err(error)), TouchId::Approved, "{error:?}");
        }
    }
}
