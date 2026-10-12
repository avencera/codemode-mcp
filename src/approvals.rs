//! Approval requests for `ask` tools: pending requests, client grants,
//! notifications and expiry
//!
//! The web page (after a passkey assertion) and tests both answer requests
//! through [`Approvals::decide`], so there is one decision path. Admin
//! actions (adding or removing a passkey) use the same requests and page,
//! so only an existing passkey can authorize them

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

use serde_json::{Map, Value};
use tokio::sync::oneshot;

use crate::{
    notify::{Notification, Notifier, Priority},
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
/// Client grant lengths offered on the approval page, in minutes
pub const CLIENT_GRANT_MINUTES: [u64; 2] = [15, 60];

/// What the owner chose on the approval page
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Run this call only
    Once,
    /// Run this call and cover every session of the same client for the
    /// given time
    Client(Duration),
    /// Refuse the call
    Deny,
}

impl Choice {
    /// Parses the page's button values: `once`, `client15`, `client60`, `deny`
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "once" => Some(Self::Once),
            "deny" => Some(Self::Deny),
            other => {
                let minutes: u64 = other.strip_prefix("client")?.parse().ok()?;
                CLIENT_GRANT_MINUTES
                    .contains(&minutes)
                    .then(|| Self::Client(Duration::from_secs(minutes * 60)))
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

/// Client name recorded for admin requests made through the CLI
pub const ADMIN_CLIENT: &str = "codemode-mcp cli";
/// Server name recorded for admin requests
pub const ADMIN_SERVER: &str = "codemode-mcp";

/// What a request asks permission for
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalKind {
    /// A script's call of an `ask` tool
    ToolCall,
    /// A change to codemode-mcp itself, such as enrolling a passkey
    Admin {
        /// Headline on the page, e.g. `Enroll a new passkey named "iPad"`
        title: String,
    },
}

/// An admin action that needs an existing passkey's approval
pub struct AdminRequest {
    /// Action name recorded as the tool, e.g. `passkey.enroll`
    pub action: &'static str,
    /// Headline on the approval page and in the notification
    pub title: String,
    /// Details shown on the page
    pub details: Map<String, Value>,
    /// Short code the CLI prints and the page and notification repeat, so
    /// the owner can tell their own request from a look-alike
    pub code: String,
}

/// Everything the approval page shows about one request
#[derive(Debug, Clone)]
pub struct ApprovalInfo {
    /// Approval id
    pub id: String,
    /// Tool call or admin action
    pub kind: ApprovalKind,
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
    /// Whether a client grant may be given
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
    /// A client grant covers the call
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
    /// No pending request has this id (unknown, decided or expired,
    /// including one past its expiry whose timer has not fired yet)
    #[error("no pending approval with this id")]
    NotFound,
    /// A client grant was chosen for a per-call tool, or for a caller that
    /// did not identify its client
    #[error("this request can only be approved once")]
    GrantNotAllowed,
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
    /// Keyed by (client name, server)
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

        let info = ApprovalInfo {
            id: random_id(),
            kind: ApprovalKind::ToolCall,
            caller: request.caller.clone(),
            execution_id: request.execution_id.to_owned(),
            server: request.server.to_owned(),
            tool: request.tool.to_owned(),
            arguments: request.arguments.clone(),
            script: Arc::clone(request.script),
            grant_mode: request.grant_mode,
            expires_at: Instant::now() + self.timeout,
        };
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
            click: Some(self.url_for(&info.id)),
            priority: Priority::High,
            tag: "lock",
        };

        Gate::Wait(self.open(info, Some((notifier, notification))))
    }

    /// Asks for approval of an admin action; the request is answered on the
    /// same page as tool calls, and approving it takes a passkey assertion
    ///
    /// The notification goes out whenever a notifier exists, so an
    /// unexpected request is visible on the phone. Without one the caller
    /// must hand the link to the owner itself
    pub fn request_admin(self: &Arc<Self>, request: AdminRequest) -> Waiting {
        let info = ApprovalInfo {
            id: random_id(),
            kind: ApprovalKind::Admin {
                title: request.title.clone(),
            },
            caller: Caller {
                client_name: Some(ADMIN_CLIENT.to_owned()),
                client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                ..Caller::default()
            },
            execution_id: String::new(),
            server: ADMIN_SERVER.to_owned(),
            tool: request.action.to_owned(),
            arguments: request.details,
            script: Arc::from(""),
            grant_mode: GrantMode::PerCall,
            expires_at: Instant::now() + self.timeout,
        };
        let notification = Notification {
            title: format!("codemode: {}", request.title),
            message: format!(
                "Code {}. Requested on the Mac; approve only if you started this and the \
                 code matches. Denied automatically in {} min.",
                request.code,
                self.timeout.as_secs().div_ceil(60)
            ),
            click: Some(self.url_for(&info.id)),
            priority: Priority::Urgent,
            tag: "warning",
        };
        let notifier = self.notifier.clone();

        self.open(info, notifier.map(|notifier| (notifier, notification)))
    }

    /// Whether requests reach the phone
    pub fn can_notify(&self) -> bool {
        self.notifier.is_some()
    }

    /// Sends a notification that needs no answer, when a notifier exists
    pub fn announce(&self, notification: Notification) {
        let Some(notifier) = self.notifier.clone() else {
            tracing::warn!(title = %notification.title, "no notifier; announcement not sent");

            return;
        };

        tokio::spawn(async move {
            if let Err(error) = notifier.notify(&notification).await {
                tracing::warn!(%error, "announcement failed");
            }
        });
    }

    /// Registers a pending request, announces it and schedules its expiry
    fn open(
        self: &Arc<Self>,
        info: ApprovalInfo,
        notify: Option<(Arc<dyn Notifier>, Notification)>,
    ) -> Waiting {
        let info = Arc::new(info);
        let id = info.id.clone();
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

        if let Some((notifier, notification)) = notify {
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
        }

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

        Waiting {
            waiting_for: info.waiting_for(),
            url: self.url_for(&id),
            id,
            receiver: Some(receiver),
            approvals: Arc::downgrade(self),
        }
    }

    fn granted(&self, request: &GateRequest<'_>) -> Option<String> {
        if request.grant_mode != GrantMode::Session {
            return None;
        }
        let client = request.caller.client_name.as_ref()?;
        let mut state = self.state();
        // clients end without telling us, so expired grants are swept here
        let now = Instant::now();
        state.grants.retain(|_, grant| grant.expires_at > now);

        state
            .grants
            .get(&(client.clone(), request.server.to_owned()))
            .map(|grant| grant.approval_id.clone())
    }

    /// A pending request that has not expired, for the approval page
    pub fn info(&self, id: &str) -> Option<Arc<ApprovalInfo>> {
        // the expiry timer may lag the deadline slightly; the deadline wins
        self.state()
            .pending
            .get(id)
            .filter(|pending| !pending.info.time_left().is_zero())
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
            .filter(|pending| {
                pending.info.kind == ApprovalKind::ToolCall
                    && pending.info.execution_id == execution_id
            })
            .min_by_key(|pending| pending.info.expires_at)
            .map(|pending| Arc::clone(&pending.info))
    }

    /// Applies the owner's choice to a pending request
    ///
    /// A client grant also answers the client's other pending requests for
    /// grantable tools of the same server
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
            Choice::Client(length) => {
                let Some(client) = &info.caller.client_name else {
                    return Err(DecideError::GrantNotAllowed);
                };
                if info.grant_mode != GrantMode::Session || info.kind != ApprovalKind::ToolCall {
                    return Err(DecideError::GrantNotAllowed);
                }
                let minutes = Some((length.as_secs() / 60) as i64);
                let verdict = Verdict::Approved {
                    approval_id: id.to_owned(),
                };
                if !self.settle(id, Some(verdict), "approved", minutes) {
                    return Err(DecideError::NotFound);
                }
                self.grant(client, &info.server, id, length);
            }
        }

        Ok(())
    }

    fn grant(&self, client: &str, server: &str, approval_id: &str, length: Duration) {
        let covered: Vec<String> = {
            let mut state = self.state();
            state.grants.insert(
                (client.to_owned(), server.to_owned()),
                Grant {
                    approval_id: approval_id.to_owned(),
                    expires_at: Instant::now() + length,
                },
            );

            state
                .pending
                .values()
                .filter(|pending| {
                    pending.info.kind == ApprovalKind::ToolCall
                        && pending.info.caller.client_name.as_deref() == Some(client)
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

/// Six characters for a person to compare between the CLI and the phone
pub fn confirmation_code() -> String {
    random_id()[..6].to_uppercase()
}

/// 256 random bits as hex, for one-time tokens
pub fn random_token() -> String {
    hex(&rand::random::<[u8; 32]>())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
