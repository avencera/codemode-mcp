//! Approval requests for `ask` tools: pending requests, client grants,
//! notifications and expiry
//!
//! The web page (after a passkey assertion) and tests both answer requests
//! through [`Approvals::decide`], so there is one decision path. Admin
//! actions (adding or removing a passkey) use the same requests and page,
//! so only an existing passkey can authorize them

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::{
    durable::{Durable, Sensitivity},
    mac::{MacNotification, OnMac, TouchId},
    notify::{Notification, Notifier, Priority},
    policy::GrantMode,
    prompt::{Asker, calls_text, prompt_text},
    store::{
        Store,
        approvals::{NewApproval, StoredApproval, StoredGrant},
        now_ms,
        sessions::SessionState,
    },
    usage::Caller,
};

/// Reason given when an `ask` call arrives before any passkey exists
pub const NO_PASSKEY: &str = "no passkey enrolled; run `codemode-mcp passkey enroll --label NAME`";
/// Reason given when no notification channel is configured
pub const NO_NOTIFIER: &str = "approvals are not configured: add a [notify.ntfy] section \
     (or one in homebased's config) so requests can reach your phone";
/// Reason given by `codemode-mcp exec`, which serves no approval page
pub const NO_APPROVAL_PAGE: &str = "`codemode-mcp exec` cannot ask for approval; run the script \
     through the daemon's execute tool instead";
/// Stored kind of a grant that covers every session of a client
const CLIENT_GRANT: &str = "client";
/// Stored kind of a grant that covers one app session
const SESSION_GRANT: &str = "session";
/// Shown to a script whose request was refused on the page
const DENIED: &str = "denied on the approval page";
/// Shown to a script whose request is no longer there
pub const WITHDRAWN: &str = "the approval request was withdrawn";
/// How often a request waiting on the Mac checks that the owner is still
/// there
const PRESENCE_CHECK: Duration = Duration::from_secs(2);
/// Grant lengths offered on the approval page, in minutes
pub const GRANT_MINUTES: [u64; 2] = [15, 60];
/// How long a per-call request waits before it is announced, so the calls
/// a script makes together under `asyncio.gather` join it and are asked
/// for as one batch; they all arrive within a few milliseconds
const BATCH_WINDOW: Duration = Duration::from_millis(250);

/// What the owner chose on the approval page
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Run this call only
    Once,
    /// Run this call and cover every session of the same client for the
    /// given time
    Client(Duration),
    /// Run this call and cover later calls of the same app session for the
    /// given time
    Session(Duration),
    /// Refuse the call
    Deny,
}

impl Choice {
    /// The page's button value for this choice
    pub fn as_text(self) -> String {
        match self {
            Self::Once => "once".to_owned(),
            Self::Deny => "deny".to_owned(),
            Self::Client(length) => format!("client{}", length.as_secs() / 60),
            Self::Session(length) => format!("session{}", length.as_secs() / 60),
        }
    }

    /// Parses the page's button values: `once`, `session15`, `session60`,
    /// `client15`, `client60`, `deny`
    pub fn parse(text: &str) -> Option<Self> {
        let length = |minutes: &str| {
            let minutes: u64 = minutes.parse().ok()?;

            GRANT_MINUTES
                .contains(&minutes)
                .then(|| Duration::from_secs(minutes * 60))
        };

        match text {
            "once" => Some(Self::Once),
            "deny" => Some(Self::Deny),
            other => match other.strip_prefix("session") {
                Some(minutes) => length(minutes).map(Self::Session),
                None => length(other.strip_prefix("client")?).map(Self::Client),
            },
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalKind {
    /// A script's call of an `ask` tool
    ToolCall,
    /// A change to codemode-mcp itself, such as enrolling a passkey
    Admin {
        /// Headline on the page, e.g. `Enroll a new passkey named "iPad"`
        title: String,
    },
}

/// What an approved admin request does; stored with the request so an
/// approval decided after a restart still performs it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminAction {
    /// Let the enrollment link with this token hash be used
    EnrollPasskey {
        /// SHA-256 of the link's token
        enrollment_hash: String,
    },
    /// Remove a passkey
    RemovePasskey {
        /// Row id from `passkey list`
        id: i64,
        /// Enrollment time that pins the row, in case its id was reused
        created_ms: i64,
    },
}

impl AdminAction {
    /// Name recorded as the tool, e.g. `passkey.enroll`
    pub fn name(&self) -> &'static str {
        match self {
            Self::EnrollPasskey { .. } => "passkey.enroll",
            Self::RemovePasskey { .. } => "passkey.remove",
        }
    }
}

/// An admin action that needs an existing passkey's approval
pub struct AdminRequest {
    /// What approving it does
    pub action: AdminAction,
    /// Headline on the approval page and in the notification
    pub title: String,
    /// Details shown on the page
    pub details: Map<String, Value>,
    /// Short code the CLI prints and the page and notification repeat, so
    /// the owner can tell their own request from a look-alike
    pub code: String,
}

/// Everything the approval page shows about one request
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// When the request is denied automatically, ms since the epoch; a wall
    /// clock time because it must mean the same to the next process
    pub expires_ms: i64,
    /// The first request of the batch this one joined, when it is a per-call
    /// request made together with others of the same execution; one
    /// decision answers the whole batch
    #[serde(default)]
    pub batch: Option<String>,
    /// Creation order within this process, so a batch lists its calls in the
    /// order the script made them, though many share a millisecond
    #[serde(default)]
    pub order: u64,
}

impl ApprovalInfo {
    /// Time until automatic denial
    pub fn time_left(&self) -> Duration {
        Duration::from_millis(self.expires_ms.saturating_sub(now_ms()).max(0) as u64)
    }

    /// `<server>.<tool>`
    pub fn waiting_for(&self) -> String {
        format!("{}.{}", self.server, self.tool)
    }

    /// Id of the batch this request belongs to: the first request's id, its
    /// own when it started one or stands alone
    pub fn batch_id(&self) -> &str {
        self.batch.as_deref().unwrap_or(&self.id)
    }

    /// Whether this request may join or start a batch: a tool call that asks
    /// on every call. Grants already cover the other kinds of call
    fn batchable(&self) -> bool {
        self.kind == ApprovalKind::ToolCall && self.grant_mode == GrantMode::PerCall
    }

    /// Whether a session grant may answer this request: a `session` tool
    /// call under an app session. The unguessable token is the credential,
    /// so proxied and remote callers qualify too
    pub fn session_grant_allowed(&self) -> bool {
        self.kind == ApprovalKind::ToolCall
            && self.grant_mode == GrantMode::Session
            && self.caller.session.is_some()
    }

    /// Whether a client grant may answer this request: a `session` tool call
    /// that did not pass a valid session, from a named client that reached
    /// the daemon directly from this machine
    pub fn client_grant_allowed(&self) -> bool {
        self.kind == ApprovalKind::ToolCall
            && self.grant_mode == GrantMode::Session
            && self.caller.session_state != SessionState::Reused
            && self.caller.client_name.is_some()
            && self.caller.local
    }

    /// What a fingerprint at the Mac approves: the longest grant of the
    /// narrowest kind allowed, so a tool that asks on every call is
    /// approved once
    pub fn fingerprint_choice(&self) -> Choice {
        let longest = Duration::from_secs(GRANT_MINUTES[GRANT_MINUTES.len() - 1] * 60);
        if self.session_grant_allowed() {
            Choice::Session(longest)
        } else if self.client_grant_allowed() {
            Choice::Client(longest)
        } else {
            Choice::Once
        }
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
    /// Whether the call or its execution holds data from a sensitive
    /// server, so the request must not reach the disk
    pub sensitivity: Sensitivity,
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
    /// Shared with the service, which can be gone by the time this is read
    frozen: Arc<AtomicBool>,
}

impl Waiting {
    /// A wait that already has its answer
    fn answered(
        approvals: &Arc<Approvals>,
        id: &str,
        waiting_for: String,
        verdict: Verdict,
    ) -> Self {
        let (sender, receiver) = oneshot::channel();
        let _ = sender.send(verdict);

        Self {
            waiting_for,
            url: approvals.url_for(id),
            id: id.to_owned(),
            receiver: Some(receiver),
            approvals: Arc::downgrade(approvals),
            frozen: Arc::clone(&approvals.frozen),
        }
    }

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
                reason: WITHDRAWN.to_owned(),
            };
        };

        match receiver.await {
            Ok(verdict) => verdict,
            // a frozen service is being torn down, which says nothing about
            // the request; answering "withdrawn" would make the waiter act on it
            Err(_) if self.frozen.load(Ordering::SeqCst) => std::future::pending().await,
            Err(_) => Verdict::Denied {
                reason: WITHDRAWN.to_owned(),
            },
        }
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
    /// A grant was chosen for a per-call tool, a session grant for a request
    /// without a session, or a client grant for a caller that did not
    /// identify its client, had a session, or did not come straight from
    /// this machine
    #[error("this request can only be approved once")]
    GrantNotAllowed,
}

struct Pending {
    info: Arc<ApprovalInfo>,
    sender: oneshot::Sender<Verdict>,
    /// Cancels the request's token when it leaves the map in any way,
    /// including a service dropped without settling it, so a phone push
    /// still waiting is dropped
    _settled: DropGuard,
}

struct Grant {
    approval_id: String,
    expires_ms: i64,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
    /// Keyed by (client name, server)
    grants: HashMap<(String, String), Grant>,
    /// Keyed by (session hash, server)
    session_grants: HashMap<(String, String), Grant>,
    /// Pending requests whose notification could not be delivered
    unnotified: HashSet<String>,
    /// Pending requests asked on the Mac, because the owner was at it
    on_mac: HashSet<String>,
    /// Batches still open to the per-call requests of their execution,
    /// keyed by execution id, holding the first request's id; a batch closes
    /// once it is announced, shown on the page or decided, so a decision
    /// never covers a call the owner was not shown
    forming: HashMap<String, String>,
}

/// The approval service
pub struct Approvals {
    base_url: String,
    timeout: Duration,
    notifier: Option<Arc<dyn Notifier>>,
    /// The Mac, when requests are asked there first while the owner is at it
    on_mac: Option<OnMac>,
    /// Why requests are refused when there is no notifier
    unavailable: &'static str,
    store: Store,
    state: Mutex<State>,
    /// Set once the process stops writing, because another daemon took over
    /// the database (tests) or this one is shutting down after a drain
    frozen: Arc<AtomicBool>,
    /// Next [`ApprovalInfo::order`]
    order: AtomicU64,
}

impl Approvals {
    /// Creates the service; without a notifier every request is refused
    /// with `unavailable` (usually [`NO_NOTIFIER`])
    pub fn new(
        base_url: &str,
        timeout: Duration,
        notifier: Option<Arc<dyn Notifier>>,
        on_mac: Option<OnMac>,
        unavailable: &'static str,
        store: Store,
    ) -> Arc<Self> {
        let mut state = State::default();
        match store.live_grants() {
            Ok(grants) => {
                for grant in grants {
                    let restored = Grant {
                        approval_id: grant.approval_id,
                        expires_ms: grant.expires_ms,
                    };
                    let key = (grant.subject, grant.server);
                    match grant.kind.as_str() {
                        CLIENT_GRANT => state.grants.insert(key, restored),
                        _ => state.session_grants.insert(key, restored),
                    };
                }
            }
            Err(error) => tracing::warn!(%error, "could not load the stored grants"),
        }

        Arc::new(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            timeout,
            notifier,
            on_mac,
            unavailable,
            store,
            state: Mutex::new(state),
            frozen: Arc::new(AtomicBool::new(false)),
            order: AtomicU64::new(0),
        })
    }

    /// Stops this service from writing to the database, as if the process had
    /// died; see `Executions::halt`
    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::SeqCst);
    }

    /// Runs a database write unless the service is frozen; a failure is
    /// logged, because the in-memory state stays authoritative for the
    /// running process
    fn persist(
        &self,
        what: &str,
        write: impl FnOnce(&Store) -> Result<(), crate::store::StoreError>,
    ) {
        if self.frozen.load(Ordering::SeqCst) {
            return;
        }
        if let Err(error) = write(&self.store) {
            tracing::warn!(%error, "could not persist {what}");
        }
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
            expires_ms: self.expiry(),
            batch: None,
            order: self.order.fetch_add(1, Ordering::SeqCst),
        };

        Gate::Wait(self.open(info, request.sensitivity, None, Some(notifier)))
    }

    fn expiry(&self) -> i64 {
        now_ms().saturating_add(self.timeout.as_millis().min(i64::MAX as u128) as i64)
    }

    /// The notification announcing a request and the rest of its batch;
    /// arguments stay on the passkey page, so it names the client and tools
    /// only
    fn notification_for(&self, info: &ApprovalInfo) -> Notification {
        let minutes = info.time_left().as_secs().div_ceil(60);
        match &info.kind {
            ApprovalKind::ToolCall => Notification {
                title: format!(
                    "codemode: {} wants {}",
                    info.caller.client_label(),
                    calls_text(&self.calls(info))
                ),
                message: format!("Tap to review. Denied automatically in {minutes} min."),
                click: Some(self.url_for(&info.id)),
                priority: Priority::High,
                tag: "lock",
            },
            ApprovalKind::Admin { title } => Notification {
                title: format!("codemode: {title}"),
                message: format!(
                    "Code {}. Requested on the Mac; approve only if you started this and the \
                     code matches. Denied automatically in {minutes} min.",
                    info.arguments
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or("-")
                ),
                click: Some(self.url_for(&info.id)),
                priority: Priority::Urgent,
                tag: "warning",
            },
        }
    }

    /// Asks for approval of an admin action; the request is answered on the
    /// same page as tool calls, and approving it takes a passkey assertion
    ///
    /// The notification goes out whenever a notifier exists, so an
    /// unexpected request is visible on the phone. Without one the caller
    /// must hand the link to the owner itself
    pub fn request_admin(self: &Arc<Self>, request: AdminRequest) -> Waiting {
        let title = request.title;
        let mut details = request.details;
        // the code is part of the details, so the page, the notification and
        // a notification retried after a restart all show the same one
        details.insert("code".to_owned(), Value::String(request.code));
        let info = ApprovalInfo {
            id: random_id(),
            kind: ApprovalKind::Admin { title },
            caller: Caller {
                client_name: Some(ADMIN_CLIENT.to_owned()),
                client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                ..Caller::default()
            },
            execution_id: String::new(),
            server: ADMIN_SERVER.to_owned(),
            tool: request.action.name().to_owned(),
            arguments: details,
            script: Arc::from(""),
            grant_mode: GrantMode::PerCall,
            expires_ms: self.expiry(),
            batch: None,
            order: self.order.fetch_add(1, Ordering::SeqCst),
        };
        let notifier = self.notifier.clone();

        self.open(info, Sensitivity::PLAIN, Some(request.action), notifier)
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

    /// Registers a pending request, stores it, announces it and schedules its
    /// expiry
    ///
    /// A per-call request joins the open batch of its execution, if any, and
    /// is then announced only as part of that batch; otherwise it opens a
    /// batch and is announced once [`BATCH_WINDOW`] has passed
    fn open(
        self: &Arc<Self>,
        mut info: ApprovalInfo,
        sensitivity: Sensitivity,
        action: Option<AdminAction>,
        notifier: Option<Arc<dyn Notifier>>,
    ) -> Waiting {
        let id = info.id.clone();
        let (sender, receiver) = oneshot::channel();
        let settled = CancellationToken::new();
        let info = {
            // one lock, so a batch cannot close between the check and the insert
            let mut state = self.state();
            if info.batchable() {
                match state.forming.get(&info.execution_id) {
                    Some(first) if state.pending.contains_key(first) => {
                        info.batch = Some(first.clone());
                    }
                    _ => {
                        state.forming.insert(info.execution_id.clone(), id.clone());
                    }
                }
            }
            let info = Arc::new(info);
            state.pending.insert(
                id.clone(),
                Pending {
                    info: Arc::clone(&info),
                    sender,
                    _settled: settled.clone().drop_guard(),
                },
            );

            info
        };
        let joined = info.batch.is_some();

        let payload = Durable::gate(sensitivity, || {
            serde_json::to_string(&*info).unwrap_or_else(|error| {
                tracing::warn!(%error, "could not serialize an approval request");

                String::new()
            })
        });
        let action = action.and_then(|action| serde_json::to_string(&action).ok());
        self.persist("a new approval request", |store| {
            store.create_approval(
                &NewApproval {
                    id: &info.id,
                    created_ms: now_ms(),
                    expires_ms: info.expires_ms,
                    caller: &info.caller,
                    execution_id: &info.execution_id,
                    server: &info.server,
                    tool: &info.tool,
                    grant_mode: info.grant_mode.as_str(),
                    action: action.as_deref(),
                    // the batch's first request carries the notification
                    notify: notifier.is_some() && !joined,
                },
                &payload,
            )
        });

        match notifier {
            Some(_) if joined => {}
            Some(notifier) if info.batchable() => {
                let weak = Arc::downgrade(self);
                let first = Arc::clone(&info);
                tokio::spawn(async move {
                    tokio::time::sleep(BATCH_WINDOW).await;
                    if let Some(approvals) = weak.upgrade() {
                        approvals.close_batch(&first);
                        approvals.ask(&first, notifier, settled);
                    }
                });
            }
            Some(notifier) => self.ask(&info, notifier, settled),
            None => {}
        }
        self.expire_after(&id, self.timeout);

        Waiting {
            waiting_for: info.waiting_for(),
            url: self.url_for(&id),
            id,
            receiver: Some(receiver),
            approvals: Arc::downgrade(self),
            frozen: Arc::clone(&self.frozen),
        }
    }

    /// Announces a new request: while the owner is at the Mac a tool call
    /// shows a Touch ID prompt there, whose fingerprint approves it with
    /// [`ApprovalInfo::fingerprint_choice`] and whose other button opens the
    /// approval page, and the phone is told only once it has waited
    /// `escalate_after_secs` or the owner leaves; otherwise the phone is told
    /// at once
    ///
    /// An admin request reaches the phone at once, so one the owner did not
    /// start is seen wherever they are, and only shows a notification on the
    /// Mac, since only a passkey may change who can approve
    fn ask(
        self: &Arc<Self>,
        info: &Arc<ApprovalInfo>,
        phone: Arc<dyn Notifier>,
        settled: CancellationToken,
    ) {
        let Some(on_mac) = self.on_mac.clone() else {
            self.notify(phone, info);

            return;
        };
        let weak = Arc::downgrade(self);
        let info = Arc::clone(info);
        tokio::spawn(async move {
            let idle = on_mac.config.idle();
            let present = on_mac.mac.present(idle).await;
            let Some(approvals) = weak.upgrade() else {
                return;
            };
            {
                // one lock, so a request settled in between leaves no mark
                let mut state = approvals.state();
                if !state.pending.contains_key(&info.id) {
                    return;
                }
                if present && info.kind == ApprovalKind::ToolCall {
                    state.on_mac.insert(info.id.clone());
                }
            }
            let url = approvals.url_for(&info.id);
            let notification = approvals.notification_for(&info);
            let calls = approvals.calls(&info);

            if let ApprovalKind::Admin { .. } = &info.kind {
                approvals.notify(phone, &info);
                drop(approvals);
                if present {
                    let local = MacNotification {
                        title: notification.title,
                        message: notification.message,
                        click: url,
                    };
                    if let Err(error) = on_mac.mac.notify(&local).await {
                        tracing::warn!(%error, "Mac notification failed");
                    }
                }

                return;
            }
            if !present {
                approvals.notify(phone, &info);

                return;
            }
            drop(approvals);

            // `now` tells the phone without waiting; `restart` starts the
            // delay over, because the owner opened the page here
            let now = CancellationToken::new();
            let restart = tokio::sync::Notify::new();

            let phone_later = async {
                let delay = on_mac.config.escalate_after();
                let deadline = tokio::time::sleep(delay);
                tokio::pin!(deadline);
                let mut check = tokio::time::interval_at(
                    tokio::time::Instant::now() + PRESENCE_CHECK,
                    PRESENCE_CHECK,
                );
                loop {
                    tokio::select! {
                        biased;
                        () = settled.cancelled() => return,
                        () = now.cancelled() => break,
                        () = restart.notified() => {
                            deadline.as_mut().reset(tokio::time::Instant::now() + delay);
                        }
                        () = &mut deadline => break,
                        _ = check.tick() => {
                            // a locked screen or an owner who walked away
                            // should not hold the phone back
                            if !on_mac.mac.present(idle).await {
                                break;
                            }
                        }
                    }
                }

                if let Some(approvals) = weak.upgrade() {
                    // the owner may have left, so the pending answer stops
                    // pointing the agent at the Mac
                    let pending = {
                        let mut state = approvals.state();
                        state.on_mac.remove(&info.id);

                        state.pending.contains_key(&info.id)
                    };
                    // it may have been decided while presence was checked
                    if pending {
                        approvals.notify(phone, &info);
                    }
                }
            };

            let ask_here = async {
                let answer = if on_mac.config.touch_id {
                    let reason = touch_id_reason(&info, &calls);
                    // dropping the prompt's future takes it off the screen
                    tokio::select! {
                        answer = on_mac.mac.touch_id(&reason) => answer,
                        () = settled.cancelled() => return,
                    }
                } else {
                    TouchId::Unavailable
                };

                match answer {
                    TouchId::Approved => {
                        // the page or the phone may have answered first
                        if let Some(approvals) = weak.upgrade()
                            && let Err(error) =
                                approvals.decide(&info.id, info.fingerprint_choice())
                        {
                            tracing::debug!(%error, "Touch ID approval came too late");
                        }
                    }
                    TouchId::Review => {
                        // before opening the page, so a press just ahead of
                        // the deadline still holds the phone back
                        restart.notify_one();
                        if let Err(error) = on_mac.mac.open(&url).await {
                            tracing::warn!(%error, "could not open the approval page");
                            now.cancel();
                        }
                    }
                    TouchId::Away => now.cancel(),
                    TouchId::Unavailable => {
                        let local = MacNotification {
                            title: notification.title,
                            message: "Click to review.".to_owned(),
                            click: url.clone(),
                        };
                        if let Err(error) = on_mac.mac.notify(&local).await {
                            tracing::warn!(%error, "Mac notification failed");
                            now.cancel();
                        }
                    }
                }
            };

            tokio::join!(phone_later, ask_here);
        });
    }

    /// Sends the notification of a pending request; a failure is remembered,
    /// so the agent's pending answer can hand the user the link and the next
    /// boot can try again
    fn notify(self: &Arc<Self>, notifier: Arc<dyn Notifier>, info: &ApprovalInfo) {
        let notification = self.notification_for(info);
        let weak = Arc::downgrade(self);
        let id = info.id.clone();
        tokio::spawn(async move {
            // answered while this task waited to run, as when a fingerprint
            // lands right at the escalation deadline
            if weak
                .upgrade()
                .is_none_or(|approvals| !approvals.state().pending.contains_key(&id))
            {
                return;
            }
            let sent = notifier.notify(&notification).await;
            let Some(approvals) = weak.upgrade() else {
                return;
            };

            match sent {
                Err(error) => {
                    tracing::warn!(%error, "approval notification failed");
                    let pending = {
                        let mut state = approvals.state();
                        let pending = state.pending.contains_key(&id);
                        if pending {
                            state.unnotified.insert(id.clone());
                        }

                        pending
                    };
                    if pending {
                        approvals.persist("a failed notification", |store| {
                            store.set_unnotified(&id, true)
                        });
                    }
                }
                Ok(()) => {
                    approvals.state().unnotified.remove(&id);
                    // the row was written as undelivered before the send
                    approvals.persist("a delivered notification", |store| {
                        store.set_unnotified(&id, false)
                    });
                }
            }
        });
    }

    /// Denies request `id` once `delay` has passed without a decision
    fn expire_after(self: &Arc<Self>, id: &str, delay: Duration) {
        let weak = Arc::downgrade(self);
        let expiring = id.to_owned();
        let timeout = self.timeout;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Some(approvals) = weak.upgrade() {
                let verdict = Verdict::Denied {
                    reason: expiry_reason(timeout),
                };
                approvals.settle(&expiring, Some(verdict), "expired", None);
            }
        });
    }

    /// Puts a stored request back in play for the execution or admin action
    /// that was waiting on it
    ///
    /// A request still pending and unexpired is registered again, with its
    /// expiry re-armed from the stored deadline. An answered request, an
    /// expired one, and one that cannot be restored (it is sensitive, or
    /// older than request storage) give a wait that already holds the
    /// matching verdict. `None` when no such request exists
    pub fn reattach(self: &Arc<Self>, id: &str) -> Option<Waiting> {
        let stored = match self.store.approval(id) {
            Ok(stored) => stored?,
            Err(error) => {
                tracing::warn!(%error, "could not read a stored approval request");

                return None;
            }
        };
        let answered = |waiting_for: String, verdict: Verdict| {
            Some(Waiting::answered(self, id, waiting_for, verdict))
        };
        let withdrawn = || Verdict::Denied {
            reason: WITHDRAWN.to_owned(),
        };

        if let Some(decision) = stored.decision.as_deref() {
            let verdict = match decision {
                "approved" => Verdict::Approved {
                    approval_id: stored.approved_by.clone().unwrap_or_else(|| id.to_owned()),
                },
                "denied" => Verdict::Denied {
                    reason: DENIED.to_owned(),
                },
                "expired" => Verdict::Denied {
                    reason: expiry_reason(self.timeout),
                },
                _ => withdrawn(),
            };

            return answered(String::new(), verdict);
        }

        let info = stored
            .payload
            .as_deref()
            .filter(|_| !stored.sensitive)
            .and_then(|payload| serde_json::from_str::<ApprovalInfo>(payload).ok());
        let Some(info) = info else {
            self.persist("a withdrawn approval request", |store| {
                store.abandon_approval(id).map(|_| ())
            });

            return answered(String::new(), withdrawn());
        };

        let remaining = info.expires_ms.saturating_sub(now_ms());
        if remaining <= 0 {
            self.persist("an expired approval request", |store| {
                store.decide_approval(id, "expired", None, None).map(|_| ())
            });

            return answered(
                info.waiting_for(),
                Verdict::Denied {
                    reason: expiry_reason(self.timeout),
                },
            );
        }

        let info = Arc::new(info);
        let (sender, receiver) = oneshot::channel();
        {
            let mut state = self.state();
            state.pending.insert(
                id.to_owned(),
                Pending {
                    info: Arc::clone(&info),
                    sender,
                    _settled: CancellationToken::new().drop_guard(),
                },
            );
            if stored.unnotified {
                state.unnotified.insert(id.to_owned());
            }
        }
        self.expire_after(id, Duration::from_millis(remaining as u64));

        Some(Waiting {
            waiting_for: info.waiting_for(),
            url: self.url_for(id),
            id: id.to_owned(),
            receiver: Some(receiver),
            approvals: Arc::downgrade(self),
            frozen: Arc::clone(&self.frozen),
        })
    }

    /// Restores the admin requests whose action has not been carried out,
    /// each with the action to perform once its wait ends
    pub fn restore_admin_actions(self: &Arc<Self>) -> Vec<(Waiting, AdminAction)> {
        let open = match self.store.open_admin_actions() {
            Ok(open) => open,
            Err(error) => {
                tracing::warn!(%error, "could not read the stored admin requests");

                return Vec::new();
            }
        };

        open.into_iter()
            .filter_map(|stored| {
                let action = stored
                    .action
                    .as_deref()
                    .and_then(|action| serde_json::from_str(action).ok())?;

                Some((self.reattach(&stored.id)?, action))
            })
            .collect()
    }

    /// Withdraws the stored requests that are still pending but that nothing
    /// was restored for: their execution did not survive the restart
    pub fn abandon_orphans(&self) {
        let pending = match self.store.pending_approvals() {
            Ok(pending) => pending,
            Err(error) => {
                tracing::warn!(%error, "could not read the stored approvals");

                return;
            }
        };
        for stored in pending {
            if !self.state().pending.contains_key(&stored.id) {
                self.persist("a withdrawn approval request", |store| {
                    store.abandon_approval(&stored.id).map(|_| ())
                });
            }
        }
    }

    /// Sends again the notifications that failed before the restart
    pub fn renotify(self: &Arc<Self>) {
        let Some(notifier) = self.notifier.clone() else {
            return;
        };
        let retry: Vec<Arc<ApprovalInfo>> = {
            let state = self.state();
            state
                .unnotified
                .iter()
                .filter_map(|id| state.pending.get(id))
                .map(|pending| Arc::clone(&pending.info))
                .collect()
        };
        for info in retry {
            self.notify(Arc::clone(&notifier), &info);
        }
    }

    /// Whether a stored request was withdrawn, and whether that was because
    /// it involved a sensitive server; for the approval page
    pub fn withdrawn(&self, id: &str) -> Option<bool> {
        let stored: StoredApproval = self.store.approval(id).ok()??;

        (stored.decision.as_deref() == Some("abandoned")).then_some(stored.sensitive)
    }

    /// Takes the payload of an execution's pending requests off the disk
    /// once the execution has used a sensitive server
    pub fn withhold_execution(&self, execution_id: &str) {
        self.persist("withheld approval requests", |store| {
            store.withhold_execution_approvals(execution_id)
        });
    }

    fn granted(&self, request: &GateRequest<'_>) -> Option<String> {
        if request.grant_mode != GrantMode::Session {
            return None;
        }
        let mut state = self.state();
        // clients end without telling us, so expired grants are swept here
        let now = now_ms();
        state.grants.retain(|_, grant| grant.expires_ms > now);
        state
            .session_grants
            .retain(|_, grant| grant.expires_ms > now);

        if let Some(session) = request.caller.session.as_ref()
            && let Some(grant) = state
                .session_grants
                .get(&(session.clone(), request.server.to_owned()))
        {
            return Some(grant.approval_id.clone());
        }
        // a caller that passed a valid session is covered by session grants
        // alone, because the token is its credential
        if request.caller.session_state == SessionState::Reused {
            return None;
        }
        // a non-local caller may be impersonating the client that holds the
        // grant, so it never matches one
        if !request.caller.local {
            return None;
        }
        let client = request.caller.client_name.as_ref()?;

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

    /// Whether the notification for a pending request, or for the batch it
    /// joined, failed
    pub fn notification_failed(&self, id: &str) -> bool {
        let state = self.state();

        state.unnotified.contains(batch_of(&state, id))
    }

    /// Whether a pending request, or the batch it joined, was asked on the
    /// Mac rather than only on the phone
    pub fn asked_on_mac(&self, id: &str) -> bool {
        let state = self.state();

        state.on_mac.contains(batch_of(&state, id))
    }

    /// The pending requests one decision on request `id` answers: its batch,
    /// first request first, or just the request itself; empty when it is
    /// not pending
    pub fn batch(&self, id: &str) -> Vec<Arc<ApprovalInfo>> {
        let state = self.state();
        let Some(pending) = state.pending.get(id) else {
            return Vec::new();
        };
        let batch = pending.info.batch_id();
        let mut members: Vec<Arc<ApprovalInfo>> = state
            .pending
            .values()
            .filter(|pending| pending.info.batch_id() == batch)
            .map(|pending| Arc::clone(&pending.info))
            .collect();
        members.sort_by_key(|info| (info.batch.is_some(), info.order));

        members
    }

    /// Each tool the batch of `info` calls, with its count; `info`'s own
    /// call once the request has left
    fn calls(&self, info: &ApprovalInfo) -> Vec<(String, usize)> {
        let batch = self.batch(&info.id);
        if batch.is_empty() {
            return vec![(info.waiting_for(), 1)];
        }

        tool_counts(&batch)
    }

    /// Closes the batch of `info` to later requests, as when it is shown on
    /// the page, so approving it covers only the calls shown
    pub fn close_batch(&self, info: &ApprovalInfo) {
        let mut state = self.state();
        if state.forming.get(&info.execution_id).map(String::as_str) == Some(info.batch_id()) {
            state.forming.remove(&info.execution_id);
        }
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
            // the batch's first request, whose page and prompt name the rest
            .min_by_key(|pending| (pending.info.expires_ms, pending.info.batch.is_some()))
            .map(|pending| Arc::clone(&pending.info))
    }

    /// Applies the owner's choice to a pending request
    ///
    /// Approving once or denying answers the request's whole batch. A client
    /// or session grant also answers the other pending requests of that
    /// client or session for grantable tools of the same server
    pub fn decide(&self, id: &str, choice: Choice) -> Result<(), DecideError> {
        let info = self.info(id).ok_or(DecideError::NotFound)?;
        self.close_batch(&info);
        let others: Vec<String> = self
            .batch(id)
            .into_iter()
            .map(|member| member.id.clone())
            .filter(|member| member != id)
            .collect();

        match choice {
            Choice::Deny => {
                let verdict = Verdict::Denied {
                    reason: DENIED.to_owned(),
                };
                if !self.settle(id, Some(verdict.clone()), "denied", None) {
                    return Err(DecideError::NotFound);
                }
                for other in others {
                    self.settle(&other, Some(verdict.clone()), "denied", None);
                }
            }
            Choice::Once => {
                let verdict = Verdict::Approved {
                    approval_id: id.to_owned(),
                };
                if !self.settle(id, Some(verdict.clone()), "approved", None) {
                    return Err(DecideError::NotFound);
                }
                for other in others {
                    self.settle(&other, Some(verdict.clone()), "approved", None);
                }
            }
            Choice::Client(length) => {
                let Some(client) = info
                    .caller
                    .client_name
                    .as_ref()
                    .filter(|_| info.client_grant_allowed())
                else {
                    return Err(DecideError::GrantNotAllowed);
                };
                let minutes = Some((length.as_secs() / 60) as i64);
                let verdict = Verdict::Approved {
                    approval_id: id.to_owned(),
                };
                if !self.settle(id, Some(verdict), "approved", minutes) {
                    return Err(DecideError::NotFound);
                }
                self.grant(client, &info.server, id, length);
            }
            Choice::Session(length) => {
                let Some(session) = info
                    .caller
                    .session
                    .as_ref()
                    .filter(|_| info.session_grant_allowed())
                else {
                    return Err(DecideError::GrantNotAllowed);
                };
                let minutes = Some((length.as_secs() / 60) as i64);
                let verdict = Verdict::Approved {
                    approval_id: id.to_owned(),
                };
                if !self.settle(id, Some(verdict), "approved", minutes) {
                    return Err(DecideError::NotFound);
                }
                self.grant_session(session, &info.server, id, length);
            }
        }

        Ok(())
    }

    fn grant_session(&self, session: &str, server: &str, approval_id: &str, length: Duration) {
        let expires_ms = self.grant_end(length);
        self.persist("a session grant", |store| {
            store.put_grant(&StoredGrant {
                kind: SESSION_GRANT.to_owned(),
                subject: session.to_owned(),
                server: server.to_owned(),
                approval_id: approval_id.to_owned(),
                expires_ms,
            })
        });
        let covered: Vec<String> = {
            let mut state = self.state();
            state.session_grants.insert(
                (session.to_owned(), server.to_owned()),
                Grant {
                    approval_id: approval_id.to_owned(),
                    expires_ms,
                },
            );

            state
                .pending
                .values()
                .filter(|pending| {
                    pending.info.session_grant_allowed()
                        && pending.info.caller.session.as_deref() == Some(session)
                        && pending.info.server == server
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

    fn grant(&self, client: &str, server: &str, approval_id: &str, length: Duration) {
        let expires_ms = self.grant_end(length);
        self.persist("a client grant", |store| {
            store.put_grant(&StoredGrant {
                kind: CLIENT_GRANT.to_owned(),
                subject: client.to_owned(),
                server: server.to_owned(),
                approval_id: approval_id.to_owned(),
                expires_ms,
            })
        });
        let covered: Vec<String> = {
            let mut state = self.state();
            state.grants.insert(
                (client.to_owned(), server.to_owned()),
                Grant {
                    approval_id: approval_id.to_owned(),
                    expires_ms,
                },
            );

            state
                .pending
                .values()
                .filter(|pending| {
                    pending.info.client_grant_allowed()
                        && pending.info.caller.client_name.as_deref() == Some(client)
                        && pending.info.server == server
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

    fn grant_end(&self, length: Duration) -> i64 {
        now_ms().saturating_add(length.as_millis().min(i64::MAX as u128) as i64)
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
            state.on_mac.remove(id);
            state.forming.retain(|_, first| first != id);

            state.pending.remove(id)
        };
        let Some(pending) = pending else {
            return false;
        };
        let approved_by = match &verdict {
            Some(Verdict::Approved { approval_id }) => Some(approval_id.as_str()),
            _ => None,
        };
        // stored before the execution hears of it, so whatever it does next
        // happens after the decision is on record
        self.persist("an approval decision", |store| {
            store
                .decide_approval(id, decision, grant_minutes, approved_by)
                .map(|_| ())
        });
        if let Some(verdict) = verdict {
            let _ = pending.sender.send(verdict);
        }

        true
    }
}

/// Text of the Touch ID prompt: the calls of the batch, what a fingerprint
/// grants, and who asks and why
///
/// Unlike the phone notification, which crosses the ntfy server, the prompt
/// stays on the Mac, so it may carry the agent's thread title and reason
fn touch_id_reason(info: &ApprovalInfo, calls: &[(String, usize)]) -> String {
    let client = info.caller.client_label();
    let grant = match info.fingerprint_choice() {
        Choice::Session(length) => {
            format!(
                "and all {} tools not marked per-call, for {} min",
                info.server,
                length.as_secs() / 60
            )
        }
        Choice::Client(length) => format!(
            "and all {} tools not marked per-call, for {} min in every session of this client",
            info.server,
            length.as_secs() / 60
        ),
        Choice::Once | Choice::Deny => "once".to_owned(),
    };

    prompt_text(
        calls,
        &grant,
        Asker {
            client,
            thread: info.caller.thread.as_deref(),
            reason: info.caller.reason.as_deref(),
        },
    )
}

/// Id of the batch request `id` belongs to, or `id` when it is not pending
fn batch_of<'a>(state: &'a State, id: &'a str) -> &'a str {
    state
        .pending
        .get(id)
        .map_or(id, |pending| pending.info.batch_id())
}

/// Each tool of a batch with how many of its calls it holds, in the order
/// they were made
pub fn tool_counts(batch: &[Arc<ApprovalInfo>]) -> Vec<(String, usize)> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for info in batch {
        let tool = info.waiting_for();
        match counts.iter_mut().find(|(seen, _)| *seen == tool) {
            Some((_, count)) => *count += 1,
            None => counts.push((tool, 1)),
        }
    }

    counts
}

/// What a script reads when its request ran out of time
fn expiry_reason(timeout: Duration) -> String {
    format!(
        "the approval request expired after {} min without a decision",
        timeout.as_secs().div_ceil(60)
    )
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

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
