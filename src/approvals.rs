//! Approval requests for `ask` tools: pending requests, session grants,
//! notifications and expiry
//!
//! The web page (after a passkey assertion) and tests both answer requests
//! through [`Approvals::decide`], so there is one decision path

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

use serde_json::{Map, Value};
use tokio::sync::oneshot;

use crate::{
    notify::{Notification, Notifier},
    policy::GrantMode,
    store::Store,
    usage::{ApprovalRecord, Caller, UsageLog},
};

/// Reason given when an `ask` call arrives before any passkey exists
pub const NO_PASSKEY: &str = "no passkey enrolled; run `codemode-mcp passkey enroll`";
/// Reason given when no notification channel is configured
pub const NO_NOTIFIER: &str = "approvals are not configured: add a [notify.ntfy] section \
     (or one in homebased's config) so requests can reach your phone";
/// Reason given by `codemode-mcp exec`, which serves no approval page
pub const NO_APPROVAL_PAGE: &str = "`codemode-mcp exec` cannot ask for approval; run the script \
     through the daemon's execute tool instead";
/// Session grant lengths offered on the approval page, in minutes
pub const SESSION_GRANT_MINUTES: [u64; 2] = [15, 60];

/// What the owner chose on the approval page
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Run this call only
    Once,
    /// Run this call and cover the session for the given time
    Session(Duration),
    /// Refuse the call
    Deny,
}

impl Choice {
    /// Parses the page's button values: `once`, `session15`, `session60`, `deny`
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "once" => Some(Self::Once),
            "deny" => Some(Self::Deny),
            other => {
                let minutes: u64 = other.strip_prefix("session")?.parse().ok()?;
                SESSION_GRANT_MINUTES
                    .contains(&minutes)
                    .then(|| Self::Session(Duration::from_secs(minutes * 60)))
            }
        }
    }
}

/// The answer an execution receives
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Run the call; the id is recorded with the upstream call
    Approved {
        /// Approval that allowed the call
        approval_id: String,
    },
    /// Refuse the call
    Denied {
        /// Shown to the script in the exception
        reason: String,
    },
}

/// Everything the approval page shows about one request
#[derive(Debug, Clone)]
pub struct ApprovalInfo {
    /// Approval id
    pub id: String,
    /// Who asked
    pub caller: Caller,
    /// Execution waiting on the answer
    pub execution_id: String,
    /// Server name
    pub server: String,
    /// Upstream tool name
    pub tool: String,
    /// Arguments the script passed
    pub arguments: Map<String, Value>,
    /// The script making the call
    pub script: Arc<str>,
    /// Whether a session grant may be given
    pub grant_mode: GrantMode,
    /// When the request is denied automatically
    pub expires_at: Instant,
}

impl ApprovalInfo {
    /// Time until automatic denial
    pub fn time_left(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// `<server>.<tool>`
    pub fn waiting_for(&self) -> String {
        format!("{}.{}", self.server, self.tool)
    }
}

/// A call that needs a decision
pub struct GateRequest<'a> {
    /// Who is asking
    pub caller: &'a Caller,
    /// Execution making the call
    pub execution_id: &'a str,
    /// Server name
    pub server: &'a str,
    /// Upstream tool name
    pub tool: &'a str,
    /// Call arguments
    pub arguments: &'a Map<String, Value>,
    /// The execution's script
    pub script: &'a Arc<str>,
    /// The tool's grant mode
    pub grant_mode: GrantMode,
}

/// Whether a call may run now
pub enum Gate {
    /// A session grant covers the call
    Open {
        /// Approval that created the grant
        approval_id: String,
    },
    /// The call cannot be approved at all
    Closed {
        /// Shown to the script
        reason: String,
    },
    /// A request was created; wait for its decision
    Wait(Waiting),
}

/// A pending request owned by the waiting execution; dropping it withdraws
/// the request
pub struct Waiting {
    id: String,
    url: String,
    waiting_for: String,
    receiver: Option<oneshot::Receiver<Verdict>>,
    approvals: Weak<Approvals>,
}

impl Waiting {
    /// Approval id
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Page where the request is answered
    pub fn url(&self) -> &str {
        &self.url
    }

    /// `<server>.<tool>`
    pub fn waiting_for(&self) -> &str {
        &self.waiting_for
    }

    /// Waits for the decision
    pub async fn decision(mut self) -> Verdict {
        let Some(receiver) = self.receiver.take() else {
            return Verdict::Denied {
                reason: "the approval request was withdrawn".to_owned(),
            };
        };

        receiver.await.unwrap_or_else(|_| Verdict::Denied {
            reason: "the approval request was withdrawn".to_owned(),
        })
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if let Some(approvals) = self.approvals.upgrade() {
            approvals.settle(&self.id, None, "abandoned", None);
        }
    }
}

/// Why a decision could not be applied
#[derive(Debug, thiserror::Error)]
pub enum DecideError {
    /// No pending request has this id (unknown, decided or expired)
    #[error("no pending approval with this id")]
    NotFound,
    /// A session grant was chosen for a per-call tool, or for a caller
    /// without an MCP session
    #[error("this request can only be approved once")]
    SessionNotAllowed,
}

struct Pending {
    info: Arc<ApprovalInfo>,
    sender: oneshot::Sender<Verdict>,
}

struct Grant {
    approval_id: String,
    expires_at: Instant,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
    /// Keyed by (MCP session, server)
    grants: HashMap<(String, String), Grant>,
    /// Pending requests whose notification could not be delivered
    unnotified: HashSet<String>,
}

/// The approval service
pub struct Approvals {
    base_url: String,
    timeout: Duration,
    notifier: Option<Arc<dyn Notifier>>,
    /// Why requests are refused when there is no notifier
    unavailable: &'static str,
    store: Store,
    log: UsageLog,
    state: Mutex<State>,
}

impl Approvals {
    /// Creates the service; without a notifier every request is refused
    /// with `unavailable` (usually [`NO_NOTIFIER`])
    pub fn new(
        base_url: &str,
        timeout: Duration,
        notifier: Option<Arc<dyn Notifier>>,
        unavailable: &'static str,
        store: Store,
        log: UsageLog,
    ) -> Arc<Self> {
        Arc::new(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            timeout,
            notifier,
            unavailable,
            store,
            log,
            state: Mutex::new(State::default()),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Link to the page for approval `id`
    pub fn url_for(&self, id: &str) -> String {
        format!("{}/approve/{id}", self.base_url)
    }

    /// Decides how a call of an `ask` tool proceeds, creating and announcing
    /// a request when no grant covers it
    pub fn gate(self: &Arc<Self>, request: GateRequest<'_>) -> Gate {
        if let Some(approval_id) = self.granted(&request) {
            return Gate::Open { approval_id };
        }
        let Some(notifier) = self.notifier.clone() else {
            return Gate::Closed {
                reason: self.unavailable.to_owned(),
            };
        };
        match self.store.passkey_count() {
            Ok(0) => {
                return Gate::Closed {
                    reason: NO_PASSKEY.to_owned(),
                };
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "cannot read passkeys; refusing the approval request");

                return Gate::Closed {
                    reason: "the approval store is unavailable".to_owned(),
                };
            }
        }

        let id = random_id();
        let info = Arc::new(ApprovalInfo {
            id: id.clone(),
            caller: request.caller.clone(),
            execution_id: request.execution_id.to_owned(),
            server: request.server.to_owned(),
            tool: request.tool.to_owned(),
            arguments: request.arguments.clone(),
            script: Arc::clone(request.script),
            grant_mode: request.grant_mode,
            expires_at: Instant::now() + self.timeout,
        });
        let (sender, receiver) = oneshot::channel();
        self.state().pending.insert(
            id.clone(),
            Pending {
                info: Arc::clone(&info),
                sender,
            },
        );
        self.log.approval(ApprovalRecord::Created {
            id: id.clone(),
            caller: info.caller.clone(),
            execution_id: info.execution_id.clone(),
            server: info.server.clone(),
            tool: info.tool.clone(),
            grant_mode: info.grant_mode.as_str(),
        });

        let url = self.url_for(&id);
        // arguments stay on the passkey page; the notification names the
        // client and tool only
        let notification = Notification {
            title: format!(
                "codemode: {} wants {}",
                info.caller.client_label(),
                info.waiting_for()
            ),
            message: format!(
                "Tap to review. Denied automatically in {} min.",
                self.timeout.as_secs().div_ceil(60)
            ),
            click: url.clone(),
        };
        let weak = Arc::downgrade(self);
        let notified = id.clone();
        tokio::spawn(async move {
            if let Err(error) = notifier.notify(&notification).await {
                tracing::warn!(%error, "approval notification failed");
                // the agent's pending answer then says so, so the user can be
                // sent to the link directly
                if let Some(approvals) = weak.upgrade() {
                    let mut state = approvals.state();
                    if state.pending.contains_key(&notified) {
                        state.unnotified.insert(notified);
                    }
                }
            }
        });

        let weak = Arc::downgrade(self);
        let expiring = id.clone();
        let timeout = self.timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            if let Some(approvals) = weak.upgrade() {
                let reason = format!(
                    "the approval request expired after {} min without a decision",
                    timeout.as_secs().div_ceil(60)
                );
                approvals.settle(&expiring, Some(Verdict::Denied { reason }), "expired", None);
            }
        });

        Gate::Wait(Waiting {
            waiting_for: info.waiting_for(),
            id,
            url,
            receiver: Some(receiver),
            approvals: Arc::downgrade(self),
        })
    }

    fn granted(&self, request: &GateRequest<'_>) -> Option<String> {
        if request.grant_mode != GrantMode::Session {
            return None;
        }
        let session = request.caller.session.as_ref()?;
        let mut state = self.state();
        // sessions end without telling us, so expired grants are swept here
        let now = Instant::now();
        state.grants.retain(|_, grant| grant.expires_at > now);

        state
            .grants
            .get(&(session.clone(), request.server.to_owned()))
            .map(|grant| grant.approval_id.clone())
    }

    /// A pending request, for the approval page
    pub fn info(&self, id: &str) -> Option<Arc<ApprovalInfo>> {
        self.state()
            .pending
            .get(id)
            .map(|pending| Arc::clone(&pending.info))
    }

    /// Whether the notification for a pending request failed
    pub fn notification_failed(&self, id: &str) -> bool {
        self.state().unnotified.contains(id)
    }

    /// The first pending request of an execution, for the `pending` answer
    pub fn pending_for_execution(&self, execution_id: &str) -> Option<Arc<ApprovalInfo>> {
        self.state()
            .pending
            .values()
            .filter(|pending| pending.info.execution_id == execution_id)
            .min_by_key(|pending| pending.info.expires_at)
            .map(|pending| Arc::clone(&pending.info))
    }

    /// Applies the owner's choice to a pending request
    ///
    /// A session grant also answers the session's other pending requests for
    /// session-grant tools of the same server
    pub fn decide(&self, id: &str, choice: Choice) -> Result<(), DecideError> {
        let info = self.info(id).ok_or(DecideError::NotFound)?;

        match choice {
            Choice::Deny => {
                let verdict = Verdict::Denied {
                    reason: "denied on the approval page".to_owned(),
                };
                if !self.settle(id, Some(verdict), "denied", None) {
                    return Err(DecideError::NotFound);
                }
            }
            Choice::Once => {
                let verdict = Verdict::Approved {
                    approval_id: id.to_owned(),
                };
                if !self.settle(id, Some(verdict), "approved", None) {
                    return Err(DecideError::NotFound);
                }
            }
            Choice::Session(length) => {
                let Some(session) = &info.caller.session else {
                    return Err(DecideError::SessionNotAllowed);
                };
                if info.grant_mode != GrantMode::Session {
                    return Err(DecideError::SessionNotAllowed);
                }
                let minutes = Some((length.as_secs() / 60) as i64);
                let verdict = Verdict::Approved {
                    approval_id: id.to_owned(),
                };
                if !self.settle(id, Some(verdict), "approved", minutes) {
                    return Err(DecideError::NotFound);
                }
                self.grant(session, &info.server, id, length);
            }
        }

        Ok(())
    }

    fn grant(&self, session: &str, server: &str, approval_id: &str, length: Duration) {
        let covered: Vec<String> = {
            let mut state = self.state();
            state.grants.insert(
                (session.to_owned(), server.to_owned()),
                Grant {
                    approval_id: approval_id.to_owned(),
                    expires_at: Instant::now() + length,
                },
            );

            state
                .pending
                .values()
                .filter(|pending| {
                    pending.info.caller.session.as_deref() == Some(session)
                        && pending.info.server == server
                        && pending.info.grant_mode == GrantMode::Session
                })
                .map(|pending| pending.info.id.clone())
                .collect()
        };

        for id in covered {
            let verdict = Verdict::Approved {
                approval_id: approval_id.to_owned(),
            };
            self.settle(&id, Some(verdict), "approved", None);
        }
    }

    /// Removes a pending request and delivers `verdict`; false when it was
    /// already gone
    fn settle(
        &self,
        id: &str,
        verdict: Option<Verdict>,
        decision: &'static str,
        grant_minutes: Option<i64>,
    ) -> bool {
        let pending = {
            let mut state = self.state();
            state.unnotified.remove(id);

            state.pending.remove(id)
        };
        let Some(pending) = pending else {
            return false;
        };
        if let Some(verdict) = verdict {
            let _ = pending.sender.send(verdict);
        }
        self.log.approval(ApprovalRecord::Decided {
            id: id.to_owned(),
            decision,
            grant_minutes,
        });

        true
    }
}

/// 128 random bits as hex; approval ids double as capabilities for viewing
/// the request, so they must not be guessable
pub fn random_id() -> String {
    hex(&rand::random::<[u8; 16]>())
}

/// 256 random bits as hex, for one-time tokens
pub fn random_token() -> String {
    hex(&rand::random::<[u8; 32]>())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
