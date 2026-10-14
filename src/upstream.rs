//! Long-lived MCP client connections to the configured upstream servers

use std::{
    collections::HashMap,
    process::Stdio,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use http::{HeaderName, HeaderValue};
use rmcp::{
    ClientHandler, ServiceExt,
    model::{
        CallToolRequest, CallToolRequestParams, CallToolResult, CancelledNotification,
        CancelledNotificationParam, ClientRequest, RequestId, ServerResult, Tool,
    },
    service::{
        NotificationContext, Peer, PeerRequestOptions, RoleClient, RunningService, ServiceError,
    },
    transport::{
        StreamableHttpClientTransport, TokioChildProcess,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::{Mutex, Notify, watch},
    task::JoinHandle,
};

use crate::{
    config::{ServerConfig, Transport},
    oauth::OAuth,
    store::Store,
};

/// Time allowed for the initialize handshake plus the first tool listing
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A connection that survived this long is considered healthy, so the next
/// failure starts the backoff over
const HEALTHY_AFTER: Duration = Duration::from_secs(30);
/// How often a server waiting for an OAuth login is retried anyway, in case
/// it starts accepting anonymous clients
const NEEDS_LOGIN_RETRY: Duration = Duration::from_secs(30 * 60);

/// Failures talking to an upstream server
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The server is not connected; the call was not sent
    #[error("server `{server}` is unavailable ({}); the call was not sent", .category.as_str())]
    Unavailable {
        /// Server name
        server: String,
        /// Coarse reason, safe to show to scripts
        category: ErrorCategory,
    },
    /// The child process could not be started
    #[error("failed to start `{command}`: {source}")]
    Spawn {
        /// Executable that failed
        command: String,
        /// Underlying error
        source: std::io::Error,
    },
    /// A configured header is not valid HTTP
    #[error("invalid header `{0}`")]
    Header(String),
    /// The MCP handshake failed
    #[error("initialize failed: {0}")]
    Initialize(String),
    /// The handshake or first listing exceeded [`CONNECT_TIMEOUT`]
    #[error("timed out connecting after {0:?}")]
    ConnectTimeout(Duration),
    /// A protocol-level failure before or after the server answered
    #[error("{0}")]
    Service(#[from] ServiceError),
    /// The call was sent but the connection failed before an answer arrived
    #[error(
        "connection to `{server}` failed while the call was running ({source}); \
         outcome unknown, the tool may or may not have run"
    )]
    Interrupted {
        /// Server name
        server: String,
        /// What went wrong
        source: ServiceError,
    },
    /// The call outlived its timeout and was cancelled
    #[error(
        "tool call timed out after {timeout:?} and was cancelled; \
         outcome unknown, the tool may still have run"
    )]
    TimedOut {
        /// Timeout that elapsed
        timeout: Duration,
    },
    /// The server asked for something other than a tool result
    #[error("server asked for interactive input, which is not supported")]
    InputRequired,
    /// The server refuses anonymous clients and has no usable OAuth login
    #[error("server `{0}` needs an OAuth login: run `codemode-mcp oauth login {0}`")]
    NeedsLogin(String),
    /// The OAuth client could not be prepared (discovery or stored login)
    #[error("oauth: {0}")]
    OAuth(String),
}

impl UpstreamError {
    /// Coarse kind of failure, safe to show anywhere
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::Unavailable { category, .. } => *category,
            Self::Spawn { .. } => ErrorCategory::Spawn,
            Self::Header(_) => ErrorCategory::Configuration,
            Self::Initialize(_) => ErrorCategory::Initialize,
            Self::ConnectTimeout(_) | Self::TimedOut { .. } => ErrorCategory::Timeout,
            Self::Service(_) | Self::InputRequired => ErrorCategory::Protocol,
            Self::Interrupted { .. } => ErrorCategory::ConnectionClosed,
            Self::NeedsLogin(_) => ErrorCategory::NeedsLogin,
            Self::OAuth(_) => ErrorCategory::Transport,
        }
    }

    /// Message for scripts and agents: transport errors can embed URLs with
    /// query strings, commands, paths or header values, so only the coarse
    /// category and the server name are kept. MCP errors are the upstream's
    /// own answer to the call and keep their message
    pub fn public_message(&self) -> String {
        match self {
            Self::Unavailable { .. }
            | Self::TimedOut { .. }
            | Self::InputRequired
            | Self::NeedsLogin(_) => self.to_string(),
            Self::Service(ServiceError::McpError(error)) => {
                format!("the server returned an error: {}", error.message)
            }
            Self::Service(_) => "the server answered with an unexpected response".to_owned(),
            Self::Interrupted { server, .. } => format!(
                "connection to `{server}` failed while the call was running; \
                 outcome unknown, the tool may or may not have run"
            ),
            Self::Spawn { .. }
            | Self::Header(_)
            | Self::Initialize(_)
            | Self::OAuth(_)
            | Self::ConnectTimeout(_) => {
                format!(
                    "the server could not be reached ({})",
                    self.category().as_str()
                )
            }
        }
    }
}

/// Coarse failure kinds reported on `/healthz` and to scripts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// The child process could not be started
    Spawn,
    /// The configuration is unusable (e.g. a bad header)
    Configuration,
    /// The MCP handshake failed
    Initialize,
    /// Connecting or a call took too long
    Timeout,
    /// The connection dropped
    ConnectionClosed,
    /// Sending failed before the server saw the request
    Transport,
    /// The server spoke the protocol wrongly
    Protocol,
    /// Still connecting
    Connecting,
    /// The server needs an OAuth login
    NeedsLogin,
}

impl Serialize for ErrorCategory {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl ErrorCategory {
    /// Stable name
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn_failed",
            Self::Configuration => "configuration",
            Self::Initialize => "initialize_failed",
            Self::Timeout => "timeout",
            Self::ConnectionClosed => "connection_closed",
            Self::Transport => "transport",
            Self::Protocol => "protocol",
            Self::Connecting => "connecting",
            Self::NeedsLogin => "needs_login",
        }
    }
}

/// Connection state of one upstream
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpstreamStatus {
    /// First attempt in progress
    Connecting,
    /// Connected and serving tools
    Connected,
    /// Refused anonymous access; waits for `codemode-mcp oauth login`
    NeedsLogin,
    /// Not connected; a retry is scheduled
    Unavailable {
        /// Why the last attempt or connection failed; may hold URLs, paths
        /// or commands, so it is for local logs and the CLI only
        error: String,
        /// Coarse reason, safe to publish
        category: ErrorCategory,
    },
}

impl UpstreamStatus {
    /// `connecting`, `connected`, `needs_login` or `unavailable`
    pub fn state(&self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::NeedsLogin => "needs_login",
            Self::Unavailable { .. } => "unavailable",
        }
    }

    /// Coarse reason when not connected
    pub fn category(&self) -> Option<ErrorCategory> {
        match self {
            Self::Unavailable { category, .. } => Some(*category),
            Self::NeedsLogin => Some(ErrorCategory::NeedsLogin),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Inner {
    peer: Option<Peer<RoleClient>>,
    tools: Vec<Tool>,
    instructions: Option<String>,
}

/// One upstream server with its supervisor task
pub struct Upstream {
    name: String,
    config: ServerConfig,
    call_timeout: Duration,
    inner: RwLock<Inner>,
    status: watch::Sender<UpstreamStatus>,
    changed: Arc<Notify>,
    /// Counts connections so refreshes started on an old one are dropped
    epoch: AtomicU64,
    /// Counts `tools/list_changed` notifications so superseded refreshes are skipped
    refresh_seq: AtomicU64,
    /// Serializes tool-list refreshes so a stale response never overwrites a newer one
    refresh_turn: Mutex<()>,
    /// Logins for `oauth = true` servers
    oauth: Option<Arc<OAuth>>,
    /// Where the last tool list is kept for the next start
    store: Store,
    /// Set while tools restored from the database have not yet reached the
    /// catalog, which only a connection event would otherwise rebuild
    cache_unshown: AtomicBool,
    /// Wakes the supervisor to drop the connection and connect again
    /// Counts reconnect requests; the supervisor compares against the
    /// value it last saw
    reconnect: watch::Sender<u64>,
}

impl Upstream {
    /// Server name from the config
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Current connection state
    pub fn status(&self) -> UpstreamStatus {
        self.status.borrow().clone()
    }

    /// Last tool list received, kept while the server is down so scripts get a
    /// precise "unavailable" error instead of a missing name
    pub fn tools(&self) -> Vec<Tool> {
        self.read().tools.clone()
    }

    /// Instructions the server sent when it last connected, kept like the
    /// tool list while it is down
    pub fn instructions(&self) -> Option<String> {
        self.read().instructions.clone()
    }

    /// Resolves once the first connection attempt has either succeeded or failed
    pub async fn settled(&self) {
        let mut receiver = self.status.subscribe();
        // the sender lives in `self`, so the channel cannot close while we wait
        let _ = receiver
            .wait_for(|status| *status != UpstreamStatus::Connecting)
            .await;
    }

    /// Fails unless the server is connected right now
    ///
    /// Checked before asking for approval so nobody is bothered about a call
    /// that cannot run
    pub fn ensure_available(&self) -> Result<(), UpstreamError> {
        self.connected_peer().map(|_| ())
    }

    fn connected_peer(&self) -> Result<Peer<RoleClient>, UpstreamError> {
        self.read()
            .peer
            .clone()
            .ok_or_else(|| UpstreamError::Unavailable {
                server: self.name.clone(),
                category: self
                    .status()
                    .category()
                    .unwrap_or(ErrorCategory::Connecting),
            })
    }

    /// Calls a tool once; never retried because the tool may not be idempotent
    ///
    /// A timeout, or dropping the returned future, sends
    /// `notifications/cancelled` to the server
    pub async fn call_tool(
        &self,
        tool: &str,
        arguments: Map<String, Value>,
    ) -> Result<CallToolResult, UpstreamError> {
        let peer = self.connected_peer()?;

        let params = CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments);
        let request = ClientRequest::CallToolRequest(CallToolRequest::new(params));
        let handle = peer
            .send_request_with_option(request, PeerRequestOptions::with_timeout(self.call_timeout))
            .await
            .map_err(|error| {
                tracing::debug!(server = %self.name, %error, "sending the call failed");

                UpstreamError::Unavailable {
                    server: self.name.clone(),
                    category: ErrorCategory::Transport,
                }
            })?;

        // from here on the server may be running the tool
        let mut cancel = CancelOnDrop::new(handle.peer.clone(), handle.id.clone());
        let response = handle.await_response().await;
        // a timeout already sent its own cancellation
        cancel.disarm();

        match response {
            Ok(ServerResult::CallToolResult(result)) => Ok(result),
            Ok(ServerResult::InputRequiredResult(_)) => Err(UpstreamError::InputRequired),
            Ok(_) => Err(ServiceError::UnexpectedResponse.into()),
            Err(ServiceError::Timeout { timeout }) => Err(UpstreamError::TimedOut { timeout }),
            Err(error @ ServiceError::McpError(_)) => Err(error.into()),
            Err(source) => Err(UpstreamError::Interrupted {
                server: self.name.clone(),
                source,
            }),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        // a poisoned lock only means a panic elsewhere; the data is still valid
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drops the current connection (if any) and connects again at once,
    /// e.g. after an OAuth login or logout
    pub fn request_reconnect(&self) {
        self.reconnect.send_modify(|count| *count += 1);
    }

    /// Without a login the server's tools are not usable, so they leave the
    /// catalog instead of lingering as unavailable
    fn mark_needs_login(&self) {
        {
            let mut inner = self.write();
            inner.peer = None;
            inner.tools.clear();
        }
        if let Err(error) = self.store.forget_tool_cache(&self.name) {
            tracing::warn!(server = %self.name, %error, "could not forget a cached tool list");
        }
        self.status.send_replace(UpstreamStatus::NeedsLogin);
        self.changed.notify_one();
    }

    fn mark_unavailable(&self, error: String, category: ErrorCategory) {
        // only a connected server turning unavailable changes what the
        // catalog shows; repeated failed reconnects do not
        let was_connected = self.status() == UpstreamStatus::Connected;
        self.write().peer = None;
        self.status
            .send_replace(UpstreamStatus::Unavailable { error, category });
        if was_connected || self.cache_unshown.swap(false, Ordering::SeqCst) {
            self.changed.notify_one();
        }
    }

    /// Fetches the tool list and stores it, returning whether it differs
    ///
    /// Refreshes run one at a time. Passing the `ticket` of a list-changed
    /// notification skips the refresh when a newer notification has arrived,
    /// and a refresh belonging to an earlier connection is dropped
    async fn refresh_tools(
        &self,
        peer: &Peer<RoleClient>,
        epoch: u64,
        ticket: Option<u64>,
    ) -> Result<bool, ServiceError> {
        let _turn = self.refresh_turn.lock().await;
        if ticket.is_some_and(|ticket| self.refresh_seq.load(Ordering::SeqCst) != ticket)
            || self.epoch.load(Ordering::SeqCst) != epoch
        {
            return Ok(false);
        }

        let tools = peer.list_all_tools().await?;
        let mut inner = self.write();
        let changed = inner.tools != tools;
        if changed {
            tracing::info!(server = %self.name, count = tools.len(), "tool list changed");
            inner.tools = tools;
            self.remember_tools(&inner.tools);
        }

        Ok(changed)
    }

    /// Keeps the tool list for the next start
    fn remember_tools(&self, tools: &[Tool]) {
        let written = serde_json::to_string(tools)
            .map_err(|error| error.to_string())
            .and_then(|json| {
                self.store
                    .put_tool_cache(&self.name, &json)
                    .map_err(|error| error.to_string())
            });
        if let Err(error) = written {
            tracing::warn!(server = %self.name, %error, "could not cache the tool list");
        }
    }

    /// The tool list the previous process saw, if it left one
    fn cached_tools(store: &Store, name: &str) -> Vec<Tool> {
        let cached = match store.tool_cache(name) {
            Ok(cached) => cached,
            Err(error) => {
                tracing::warn!(server = name, %error, "could not read the cached tool list");

                return Vec::new();
            }
        };

        cached
            .and_then(|json| match serde_json::from_str(&json) {
                Ok(tools) => Some(tools),
                Err(error) => {
                    tracing::warn!(server = name, %error, "the cached tool list is unreadable");

                    None
                }
            })
            .unwrap_or_default()
    }

    async fn supervise(self: Arc<Self>) {
        let mut backoff = BACKOFF_START;
        let mut requests = self.reconnect.subscribe();

        loop {
            // a request made before this attempt is answered by it; a
            // counter, unlike a Notify permit, cannot fire twice for one
            requests.borrow_and_update();
            let mut delay = backoff;
            match self.connect().await {
                Ok(service) => {
                    let connected_at = Instant::now();
                    tracing::info!(server = %self.name, "connected");
                    let token = service.cancellation_token();
                    let mut watched = requests.clone();
                    let watcher = tokio::spawn(async move {
                        if watched.changed().await.is_ok() {
                            token.cancel();
                        }
                    });
                    let reason = service.waiting().await;
                    watcher.abort();
                    let error = format!("connection closed ({reason:?})");
                    tracing::warn!(server = %self.name, %error, "upstream disconnected");
                    self.mark_unavailable(error, ErrorCategory::ConnectionClosed);

                    // only a connection that stayed up counts as recovery, so
                    // a server that accepts and immediately drops us still backs off
                    if connected_at.elapsed() >= HEALTHY_AFTER {
                        backoff = BACKOFF_START;
                    }
                }
                Err(UpstreamError::NeedsLogin(_)) => {
                    tracing::warn!(server = %self.name, "upstream needs an OAuth login");
                    self.mark_needs_login();
                    delay = NEEDS_LOGIN_RETRY;
                }
                Err(error) => {
                    tracing::warn!(server = %self.name, %error, "upstream connection failed");
                    self.mark_unavailable(error.to_string(), error.category());
                }
            }

            let requested = if requests.has_changed().unwrap_or(false) {
                true
            } else {
                tracing::info!(server = %self.name, ?delay, "reconnecting");
                tokio::select! {
                    () = tokio::time::sleep(delay) => false,
                    changed = requests.changed() => changed.is_ok(),
                }
            };
            backoff = if requested {
                BACKOFF_START
            } else {
                (backoff * 2).min(BACKOFF_MAX)
            };
            // a timed retry of a server waiting for a login stays
            // `needs_login`; a requested reconnect (after login or logout)
            // shows that it is trying
            if requested || self.status() != UpstreamStatus::NeedsLogin {
                self.status.send_replace(UpstreamStatus::Connecting);
            }
        }
    }

    async fn connect(
        self: &Arc<Self>,
    ) -> Result<RunningService<RoleClient, UpstreamHandler>, UpstreamError> {
        tokio::time::timeout(CONNECT_TIMEOUT, self.connect_unbounded())
            .await
            .map_err(|_| UpstreamError::ConnectTimeout(CONNECT_TIMEOUT))?
    }

    async fn connect_unbounded(
        self: &Arc<Self>,
    ) -> Result<RunningService<RoleClient, UpstreamHandler>, UpstreamError> {
        let epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let handler = UpstreamHandler {
            upstream: Arc::clone(self),
            epoch,
        };
        let service = match self.config.transport() {
            Some(Transport::Stdio { command }) => {
                let transport = self.spawn_child(command)?;

                handler
                    .serve(transport)
                    .await
                    .map_err(|error| UpstreamError::Initialize(error.to_string()))?
            }
            Some(Transport::Http { url }) => {
                let config = self.http_config(url)?;
                let authorized =
                    match &self.oauth {
                        Some(oauth) if self.config.oauth => oauth
                            .authorized_client(&self.name)
                            .await
                            .map_err(|error| UpstreamError::OAuth(error.to_string()))?,
                        _ => None,
                    };
                // without a login an OAuth server is tried anonymously; a
                // 401 then means it needs one
                let served = match authorized {
                    Some(client) => {
                        handler
                            .serve(StreamableHttpClientTransport::with_client(client, config))
                            .await
                    }
                    None => {
                        handler
                            .serve(StreamableHttpClientTransport::from_config(config))
                            .await
                    }
                };

                served.map_err(|error| {
                    if self.config.oauth && error.is_authorization_required() {
                        UpstreamError::NeedsLogin(self.name.clone())
                    } else {
                        UpstreamError::Initialize(error.to_string())
                    }
                })?
            }
            None => {
                return Err(UpstreamError::Initialize(
                    "server has neither command nor url".into(),
                ));
            }
        };

        let peer = service.peer().clone();
        self.refresh_tools(&peer, epoch, None).await?;
        let instructions = peer.peer_info().and_then(|info| info.instructions.clone());
        {
            let mut inner = self.write();
            inner.peer = Some(peer);
            inner.instructions = instructions;
        }
        // availability flipped, so the catalog needs a rebuild even when the
        // tool list is identical to the one kept from before
        self.status.send_replace(UpstreamStatus::Connected);
        self.changed.notify_one();

        Ok(service)
    }

    fn spawn_child(&self, command: &str) -> Result<TokioChildProcess, UpstreamError> {
        let mut process = Command::new(command);
        process.args(&self.config.args).envs(&self.config.env);
        if let Some(directory) = &self.config.cwd {
            process.current_dir(directory);
        }

        // stderr is captured so a chatty server cannot scribble over our own logs
        let (transport, stderr) = TokioChildProcess::builder(process)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| UpstreamError::Spawn {
                command: command.to_owned(),
                source,
            })?;

        if let Some(stderr) = stderr {
            let server = self.name.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(%server, "stderr: {line}");
                }
            });
        }

        Ok(transport)
    }

    fn http_config(&self, url: &str) -> Result<StreamableHttpClientTransportConfig, UpstreamError> {
        let mut config = StreamableHttpClientTransportConfig::with_uri(url.to_owned());
        let mut headers: HashMap<HeaderName, HeaderValue> = HashMap::new();

        for (name, value) in &self.config.headers {
            // rmcp reserves the authorization header for its own bearer handling
            if name.eq_ignore_ascii_case("authorization") {
                let token = value.strip_prefix("Bearer ").ok_or_else(|| {
                    UpstreamError::Header(
                        "authorization (only `Bearer <token>` is supported)".into(),
                    )
                })?;
                config = config.auth_header(token);

                continue;
            }
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| UpstreamError::Header(name.clone()))?;
            let header_value =
                HeaderValue::from_str(value).map_err(|_| UpstreamError::Header(name.clone()))?;
            headers.insert(header_name, header_value);
        }

        Ok(config.custom_headers(headers))
    }
}

/// Receives server notifications for one connection of one upstream
struct UpstreamHandler {
    upstream: Arc<Upstream>,
    epoch: u64,
}

impl ClientHandler for UpstreamHandler {
    async fn on_tool_list_changed(&self, context: NotificationContext<RoleClient>) {
        let upstream = Arc::clone(&self.upstream);
        let epoch = self.epoch;
        let ticket = upstream.refresh_seq.fetch_add(1, Ordering::SeqCst) + 1;

        // listing tools needs the service loop that is delivering this
        // notification, so the refresh must not run inline
        tokio::spawn(async move {
            match upstream
                .refresh_tools(&context.peer, epoch, Some(ticket))
                .await
            {
                Ok(true) => upstream.changed.notify_one(),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(server = %upstream.name, %error, "tool list refresh failed");
                }
            }
        });
    }
}

/// Sends `notifications/cancelled` for a request unless disarmed, so a call
/// abandoned by its caller does not keep running upstream
struct CancelOnDrop {
    peer: Peer<RoleClient>,
    id: RequestId,
    armed: bool,
}

impl CancelOnDrop {
    fn new(peer: Peer<RoleClient>, id: RequestId) -> Self {
        Self {
            peer,
            id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };

        let peer = self.peer.clone();
        let notification = CancelledNotification::new(CancelledNotificationParam::new(
            Some(self.id.clone()),
            Some("the caller stopped waiting for this call".to_owned()),
        ));
        runtime.spawn(async move {
            let _ = peer.send_notification(notification.into()).await;
        });
    }
}

/// All configured upstreams and the tasks keeping them connected
pub struct Upstreams {
    upstreams: Vec<Arc<Upstream>>,
    tasks: Vec<JoinHandle<()>>,
    changed: Arc<Notify>,
}

impl Upstreams {
    /// Starts one supervisor per server; connections proceed concurrently in
    /// the background so a slow or broken server never delays the others
    pub fn start(
        servers: &std::collections::BTreeMap<String, ServerConfig>,
        call_timeout: Duration,
        oauth: Option<Arc<OAuth>>,
        store: &Store,
    ) -> Self {
        let changed = Arc::new(Notify::new());
        let mut upstreams = Vec::new();
        let mut tasks = Vec::new();

        for (name, config) in servers {
            let (status, _) = watch::channel(UpstreamStatus::Connecting);
            // a server that stays down shows these, unavailable, until it
            // connects and lists its tools again
            let tools = Upstream::cached_tools(store, name);
            let upstream = Arc::new(Upstream {
                name: name.clone(),
                config: config.clone(),
                call_timeout,
                cache_unshown: AtomicBool::new(!tools.is_empty()),
                inner: RwLock::new(Inner {
                    peer: None,
                    tools,
                    instructions: None,
                }),
                status,
                changed: Arc::clone(&changed),
                epoch: AtomicU64::new(0),
                refresh_seq: AtomicU64::new(0),
                refresh_turn: Mutex::new(()),
                oauth: oauth.clone(),
                store: store.clone(),
                reconnect: watch::channel(0).0,
            });
            tasks.push(tokio::spawn(Arc::clone(&upstream).supervise()));
            upstreams.push(upstream);
        }

        Self {
            upstreams,
            tasks,
            changed,
        }
    }

    /// Every upstream, in config order
    pub fn all(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }

    /// Finds an upstream by server name
    pub fn get(&self, name: &str) -> Option<&Arc<Upstream>> {
        self.upstreams.iter().find(|upstream| upstream.name == name)
    }

    /// Signalled whenever any upstream connects, disconnects or changes tools
    pub fn changed(&self) -> Arc<Notify> {
        Arc::clone(&self.changed)
    }

    /// Waits until every upstream finished its first attempt, or `limit` passes
    pub async fn wait_settled(&self, limit: Duration) {
        let all = await_all(self.upstreams.iter().map(|upstream| upstream.settled()));
        let _ = tokio::time::timeout(limit, all).await;
    }
}

impl Drop for Upstreams {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Awaits each future in turn; they are independent waits, so the total is the longest one
async fn await_all<F: std::future::Future<Output = ()>>(futures: impl IntoIterator<Item = F>) {
    let mut set = Vec::new();
    for future in futures {
        set.push(Box::pin(future));
    }
    for future in set {
        future.await;
    }
}
