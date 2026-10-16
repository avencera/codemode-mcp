//! Shared test harness: a real HTTP server, a real Monty worker and a stdio
//! MCP fixture as the upstream, with a temporary state directory

use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use codemode_mcp::{
    app::App,
    config::Config,
    durable::{Durable, Sensitivity},
    logins::{FieldRule, FillError, FocusedField},
    mac::{Mac, MacError, MacNotification, TouchId},
    notify::{BoxFuture, Notification, Notifier, NotifyError},
    server::{RunningServer, serve},
    store::{self, DaemonLock, Store, approvals::NewApproval},
    usage::{Caller, ExecutionRecord, UsageLog},
};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    service::{RoleClient, RunningService},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Value, json};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

pub type TestResult = Result<(), Box<dyn Error>>;
pub type Client = RunningService<RoleClient, ()>;

/// Origin the soft authenticator claims; the server is reached on loopback,
/// but WebAuthn only checks the origin inside the signed client data
pub const ORIGIN: &str = "https://localhost:8443";

/// The Monty worker the tests run scripts in
///
/// A missing worker fails the test instead of skipping it, so a broken setup
/// cannot pass silently; `CODEMODE_SKIP_MONTY=1` opts out on purpose
pub fn monty_worker() -> Result<Option<PathBuf>, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".tools/bin/monty");
    if path.exists() {
        return Ok(Some(path));
    }
    if std::env::var("CODEMODE_SKIP_MONTY").as_deref() == Ok("1") {
        eprintln!("skipping: {} is missing", path.display());

        return Ok(None);
    }

    Err(format!(
        "{} is missing (see docs/design.md for how to fetch the Monty worker); \
         set CODEMODE_SKIP_MONTY=1 to skip these tests",
        path.display()
    )
    .into())
}

/// Client name the default harness client identifies itself as, through its
/// `user-agent` header since a stateless server never sees its `initialize`
pub const DEFAULT_CLIENT: &str = "harness-client";

/// An MCP client whose requests carry `user_agent`; it still sends
/// `initialize` and tolerates a server that issues no session id
pub async fn connect_as(base: &str, user_agent: &str) -> Result<Client, Box<dyn Error>> {
    connect_with_headers(base, user_agent, &[]).await
}

/// Like [`connect_as`], with extra headers on every request, e.g. what
/// `tailscale serve` adds
pub async fn connect_with_headers(
    base: &str,
    user_agent: &str,
    headers: &[(&str, &str)],
) -> Result<Client, Box<dyn Error>> {
    let mut config = StreamableHttpClientTransportConfig::with_uri(format!("{base}/mcp"));
    config.allow_stateless = true;
    config.custom_headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_str(user_agent)?,
    );
    for (name, value) in headers {
        config.custom_headers.insert(
            http::HeaderName::from_bytes(name.as_bytes())?,
            http::HeaderValue::from_str(value)?,
        );
    }

    Ok(
        ().serve(StreamableHttpClientTransport::from_config(config))
            .await?,
    )
}

/// A fresh state directory under the system temp dir
pub fn temp_state_dir() -> PathBuf {
    std::env::temp_dir().join(format!("codemode-test-{}", uuid::Uuid::new_v4().simple()))
}

/// A usage log and the store beside it, for seeding the review's inputs
///
/// Executions and approvals are written by the store since they became
/// durable; calls and upstream rows still go through the usage log, which
/// this derefs to
pub struct Seed {
    log: UsageLog,
    store: Store,
}

impl Seed {
    /// Opens both on `directory`
    pub fn start(directory: &Path) -> Result<Self, Box<dyn Error>> {
        let log = UsageLog::start(
            directory,
            Duration::from_secs(90 * 24 * 60 * 60),
            Duration::from_secs(24 * 60 * 60),
        )?;
        let store = Store::open(directory)?;

        Ok(Self { log, store })
    }

    /// Stores a finished execution
    pub fn execution(&self, record: ExecutionRecord) {
        let result = Durable::gate(Sensitivity::PLAIN, String::new);
        if let Err(failure) = self.store.finish_execution(&record, &result) {
            panic!("seeding an execution failed: {failure}");
        }
    }

    /// Stores an approval that was created and then decided
    pub fn approval(&self, id: &str, caller: &Caller, execution_id: &str, decision: &str) {
        let now = store::now_ms();
        let request = NewApproval {
            id,
            created_ms: now,
            expires_ms: now + 60_000,
            caller,
            execution_id,
            server: "op",
            tool: "list_environments",
            grant_mode: "session",
            action: None,
            notify: false,
        };
        let created = self
            .store
            .create_approval(&request, &Durable::gate(Sensitivity::PLAIN, String::new));
        let decided = created.and_then(|()| self.store.decide_approval(id, decision, None, None));
        if let Err(failure) = decided {
            panic!("seeding an approval failed: {failure}");
        }
    }
}

impl std::ops::Deref for Seed {
    type Target = UsageLog;

    fn deref(&self) -> &UsageLog {
        &self.log
    }
}

/// What a harness is built from
#[derive(Default)]
pub struct Setup<'a> {
    /// Lines for `[limits]`
    pub limits: &'a str,
    /// Lines for `[servers.fixture]`
    pub server: &'a str,
    /// Extra top-level lines and tables, after the fixture table
    pub extra: &'a str,
    /// Lines placed before any table
    pub top: &'a str,
    /// Install a recording notifier; without one every `ask` call is refused
    pub notify: bool,
    /// The Mac requests are asked on while the owner is at it; without one
    /// they go to the phone only
    pub mac: Option<Arc<FakeMac>>,
}

/// Config with one fixture upstream
pub fn config_for(
    worker: &Path,
    state_dir: &Path,
    setup: &Setup<'_>,
) -> Result<Config, Box<dyn Error>> {
    let text = format!(
        r#"
        listen = "127.0.0.1:0"
        admin_listen = "127.0.0.1:0"
        worker_path = "{worker}"
        state_dir = "{state}"
        public_origin = "{ORIGIN}"
        {top}

        [notify]
        homebased_config = "/nonexistent/homebased.toml"

        [limits]
        execute_wait_secs = 2
        {limits}

        [servers.fixture]
        command = "{fixture}"
        # plain-text sums keep `int(await fixture_add(...))` type-checking
        tools.add.output = "text"
        {server}

        {extra}
        "#,
        worker = worker.display(),
        state = state_dir.display(),
        fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
        top = setup.top,
        limits = setup.limits,
        server = setup.server,
        extra = setup.extra,
    );

    // loaded from a file, as the daemon is, so an invite can list a new
    // companion in it
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join("config.toml");
    std::fs::write(&path, text)?;

    Ok(Config::load(&path)?)
}

/// Remembers every notification instead of sending it
#[derive(Default)]
pub struct RecordingNotifier(Mutex<Vec<Notification>>);

impl RecordingNotifier {
    pub fn sent(&self) -> Vec<Notification> {
        self.0.lock().map(|sent| sent.clone()).unwrap_or_default()
    }

    /// Notifications about tool calls, leaving out passkey admin requests
    pub fn tool_requests(&self) -> Vec<Notification> {
        self.sent()
            .into_iter()
            .filter(|notification| notification.title.contains(" wants "))
            .collect()
    }
}

impl Notifier for RecordingNotifier {
    fn notify<'a>(
        &'a self,
        notification: &'a Notification,
    ) -> BoxFuture<'a, Result<(), NotifyError>> {
        if let Ok(mut sent) = self.0.lock() {
            sent.push(notification.clone());
        }

        Box::pin(std::future::ready(Ok(())))
    }
}

/// A Mac whose owner's presence and Touch ID answer the test sets, and
/// which records what was shown on it
#[derive(Default)]
pub struct FakeMac {
    present: std::sync::atomic::AtomicBool,
    /// Whether notifications fail, as without terminal-notifier
    notify_fails: std::sync::atomic::AtomicBool,
    /// `None` leaves the prompt up until it is taken down
    answer: Mutex<Option<TouchId>>,
    /// How long a prompt stays up before it answers
    answer_after: Mutex<Duration>,
    /// A file that must exist before a prompt answers
    answer_once: Mutex<Option<PathBuf>>,
    /// A file each notification creates, so a test can change the world
    /// while one is up
    on_notify: Mutex<Option<PathBuf>>,
    shown: Mutex<Vec<String>>,
    cancel_titles: Mutex<Vec<String>>,
    /// The field with keyboard focus; `None` is a screen with none
    focused: Mutex<Option<FocusedField>>,
    /// Everything `fill` typed, in order
    typed: Mutex<String>,
}

impl FakeMac {
    /// Whether the owner counts as at the Mac
    pub fn set_present(&self, present: bool) {
        self.present
            .store(present, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether later notifications fail to show
    pub fn set_notify_fails(&self, fails: bool) {
        self.notify_fails
            .store(fails, std::sync::atomic::Ordering::SeqCst);
    }

    /// How later Touch ID prompts end; `None` leaves them up until they are
    /// taken down
    pub fn set_answer(&self, answer: Option<TouchId>) {
        if let Ok(mut slot) = self.answer.lock() {
            *slot = answer;
        }
    }

    /// How long later prompts stay up before answering
    pub fn set_answer_after(&self, delay: Duration) {
        if let Ok(mut slot) = self.answer_after.lock() {
            *slot = delay;
        }
    }

    /// Hold later prompts until `path` exists, for up to ten seconds, so a
    /// test can order an answer after something else has started
    pub fn set_answer_once(&self, path: PathBuf) {
        if let Ok(mut slot) = self.answer_once.lock() {
            *slot = Some(path);
        }
    }

    /// Create `path` whenever a notification shows
    pub fn set_on_notify(&self, path: PathBuf) {
        if let Ok(mut slot) = self.on_notify.lock() {
            *slot = Some(path);
        }
    }

    /// What was shown, in order: `touch_id <reason>`, `dismissed`,
    /// `notify <title>`, `open <url>`
    pub fn shown(&self) -> Vec<String> {
        self.shown
            .lock()
            .map(|shown| shown.clone())
            .unwrap_or_default()
    }

    /// The cancel button title of each Touch ID prompt, in order
    pub fn cancel_titles(&self) -> Vec<String> {
        self.cancel_titles
            .lock()
            .map(|titles| titles.clone())
            .unwrap_or_default()
    }

    /// Gives `field` keyboard focus
    pub fn set_focused(&self, field: FocusedField) {
        if let Ok(mut slot) = self.focused.lock() {
            *slot = Some(field);
        }
    }

    /// What `fill` typed so far
    pub fn typed(&self) -> String {
        self.typed
            .lock()
            .map(|typed| typed.clone())
            .unwrap_or_default()
    }

    fn focused(&self) -> Result<FocusedField, FillError> {
        self.focused
            .lock()
            .ok()
            .and_then(|focused| focused.clone())
            .ok_or_else(|| FillError::Refused("no element has keyboard focus".to_owned()))
    }

    fn record(&self, entry: String) {
        if let Ok(mut shown) = self.shown.lock() {
            shown.push(entry);
        }
    }
}

/// Records `dismissed` when a prompt's future is dropped before it answered
struct Prompt<'a>(&'a FakeMac);

impl Drop for Prompt<'_> {
    fn drop(&mut self) {
        self.0.record("dismissed".to_owned());
    }
}

impl Mac for FakeMac {
    fn present(&self, _idle: Duration) -> BoxFuture<'_, bool> {
        let present = self.present.load(std::sync::atomic::Ordering::SeqCst);

        Box::pin(std::future::ready(present))
    }

    fn touch_id<'a>(&'a self, reason: &'a str, cancel: &'a str) -> BoxFuture<'a, TouchId> {
        self.record(format!("touch_id {reason}"));
        if let Ok(mut titles) = self.cancel_titles.lock() {
            titles.push(cancel.to_owned());
        }
        let answer = self.answer.lock().ok().and_then(|answer| *answer);
        let delay = self
            .answer_after
            .lock()
            .map(|delay| *delay)
            .unwrap_or_default();
        let gate = self.answer_once.lock().ok().and_then(|path| path.clone());

        Box::pin(async move {
            let prompt = Prompt(self);
            match answer {
                Some(answer) => {
                    if let Some(gate) = gate {
                        for _ in 0..500 {
                            if gate.exists() {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }

                    tokio::time::sleep(delay).await;
                    std::mem::forget(prompt);

                    answer
                }
                None => std::future::pending().await,
            }
        })
    }

    fn notify<'a>(
        &'a self,
        notification: &'a MacNotification,
    ) -> BoxFuture<'a, Result<(), MacError>> {
        if self.notify_fails.load(std::sync::atomic::Ordering::SeqCst) {
            return Box::pin(std::future::ready(Err(MacError(
                "terminal-notifier is not installed".to_owned(),
            ))));
        }
        self.record(format!("notify {}", notification.title));
        if let Some(path) = self.on_notify.lock().ok().and_then(|path| path.clone()) {
            let _ = std::fs::write(path, b"");
        }

        Box::pin(std::future::ready(Ok(())))
    }

    fn open<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), MacError>> {
        self.record(format!("open {url}"));

        Box::pin(std::future::ready(Ok(())))
    }

    fn focused_field(&self) -> BoxFuture<'_, Result<FocusedField, FillError>> {
        Box::pin(std::future::ready(self.focused()))
    }

    fn fill<'a>(
        &'a self,
        text: &'a str,
        rule: &'a FieldRule,
    ) -> BoxFuture<'a, Result<String, FillError>> {
        let filled = self.focused().and_then(|field| rule.check(&field));
        if filled.is_ok()
            && let Ok(mut typed) = self.typed.lock()
        {
            typed.push_str(text);
        }

        Box::pin(std::future::ready(filled))
    }
}

/// A running app, HTTP server and MCP client wired to the fixture upstream
pub struct Harness {
    pub app: App,
    pub server: RunningServer,
    pub client: Client,
    pub notifier: Arc<RecordingNotifier>,
    pub mac: Option<Arc<FakeMac>>,
    pub http: reqwest::Client,
    state_dir: PathBuf,
    config: Config,
    notifying: bool,
    /// Held as `serve` holds it, so a second daemon on the directory is refused
    _lock: DaemonLock,
}

/// Takes the state directory's lock as `serve` does
///
/// A test that spawns a process while another test releases its lock can leave
/// the lock held for a moment: the child has inherited the descriptor between
/// fork and exec. A real daemon is refused at once; here a short wait keeps
/// unrelated tests from failing each other
async fn take_lock(state_dir: &Path) -> Result<DaemonLock, Box<dyn Error>> {
    let mut attempts = 0;
    loop {
        match DaemonLock::acquire(state_dir) {
            Err(store::StoreError::Owned(_)) if attempts < 50 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            other => return Ok(other?),
        }
    }
}

/// What is left of a daemon that was dropped without a clean stop
pub struct Left {
    config: Config,
    state_dir: PathBuf,
    notifier: Arc<RecordingNotifier>,
    mac: Option<Arc<FakeMac>>,
    notifying: bool,
}

impl Left {
    /// Starts a daemon on what the dropped one left behind
    pub async fn boot(self) -> Result<Harness, Box<dyn Error>> {
        Harness::boot(
            self.config,
            self.state_dir,
            self.notifier,
            self.mac,
            self.notifying,
            true,
        )
        .await
    }
}

/// How a restarted daemon was stopped
#[derive(Clone, Copy)]
pub enum Stop {
    /// Killed: whatever was in flight leaves no trace beyond what was
    /// already written
    Crash,
    /// SIGTERM: running executions get `limits.drain_secs` to finish
    Drain,
}

impl Harness {
    /// `None` when the Monty worker is missing and skipping was requested
    pub async fn start(limits: &str, server: &str) -> Result<Option<Self>, Box<dyn Error>> {
        Self::with(Setup {
            limits,
            server,
            ..Setup::default()
        })
        .await
    }

    pub async fn with(setup: Setup<'_>) -> Result<Option<Self>, Box<dyn Error>> {
        let Some(worker) = monty_worker()? else {
            return Ok(None);
        };
        let state_dir = temp_state_dir();
        let config = config_for(&worker, &state_dir, &setup)?;

        let notifier = Arc::new(RecordingNotifier::default());

        Ok(Some(
            Self::boot(config, state_dir, notifier, setup.mac, setup.notify, false).await?,
        ))
    }

    async fn boot(
        config: Config,
        state_dir: PathBuf,
        notifier: Arc<RecordingNotifier>,
        mac: Option<Arc<FakeMac>>,
        notifying: bool,
        recover: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let lock = take_lock(&state_dir).await?;
        let installed: Option<Arc<dyn Notifier>> = if notifying {
            Some(Arc::clone(&notifier) as Arc<dyn Notifier>)
        } else {
            None
        };
        let installed_mac = mac.clone().map(|mac| mac as Arc<dyn Mac>);
        let app = App::start_with(config.clone(), installed, installed_mac).await?;
        if recover {
            app.recover();
        }
        app.gateway().wait_ready(Duration::from_secs(30)).await;
        let server = serve(&app).await?;
        let base = format!("http://127.0.0.1:{}", server.local_addr().port());
        let client = connect_as(&base, &format!("{DEFAULT_CLIENT}/1.0")).await?;

        Ok(Self {
            app,
            server,
            client,
            notifier,
            mac,
            http: reqwest::Client::new(),
            state_dir,
            config,
            notifying,
            _lock: lock,
        })
    }

    /// Stops the listeners and lets go of the app without halting it, as a
    /// process that returns early does; the tasks are still running, so the
    /// caller decides how they end (dropping their runtime)
    pub async fn forget(self) -> Result<Left, Box<dyn Error>> {
        let Self {
            app,
            server,
            client,
            notifier,
            mac,
            state_dir,
            config,
            notifying,
            ..
        } = self;
        let _ = client.cancel().await;
        server.shutdown().await?;
        drop(app);

        Ok(Left {
            config,
            state_dir,
            notifier,
            mac,
            notifying,
        })
    }

    /// Stops the daemon and starts another on the same state directory, the
    /// way a deploy, a crash or a reboot does; the new one recovers what the
    /// old one left behind
    pub async fn restart(self, how: Stop) -> Result<Self, Box<dyn Error>> {
        self.restart_with(how, |_| {}).await
    }

    /// Like [`Harness::restart`], with the new daemon's config changed first
    pub async fn restart_with(
        self,
        how: Stop,
        change: impl FnOnce(&mut Config),
    ) -> Result<Self, Box<dyn Error>> {
        let Self {
            app,
            server,
            client,
            notifier,
            mac,
            state_dir,
            mut config,
            notifying,
            _lock: lock,
            ..
        } = self;

        match how {
            Stop::Crash => app.halt(),
            Stop::Drain => {
                app.drain().await;
                app.shutdown().await;
            }
        }
        let _ = client.cancel().await;
        server.shutdown().await?;
        drop(app);
        // a dead process holds no lock
        drop(lock);
        change(&mut config);

        Self::boot(config, state_dir, notifier, mac, notifying, true).await
    }

    /// Another connection from the same client as the harness client
    pub async fn second_client(&self) -> Result<Client, Box<dyn Error>> {
        self.client_as(&format!("{DEFAULT_CLIENT}/1.0")).await
    }

    /// A connection whose `user-agent` names another client
    pub async fn client_as(&self, user_agent: &str) -> Result<Client, Box<dyn Error>> {
        connect_as(&self.base(), user_agent).await
    }

    /// A connection from the harness client's name whose requests also carry
    /// `headers`, as if a proxy had forwarded them
    pub async fn proxied_client(&self, headers: &[(&str, &str)]) -> Result<Client, Box<dyn Error>> {
        connect_with_headers(&self.base(), &format!("{DEFAULT_CLIENT}/1.0"), headers).await
    }

    /// Runs a script that must succeed and returns the parsed response
    pub async fn execute_json(&self, code: &str) -> Result<Value, Box<dyn Error>> {
        let result = execute(&self.client, code).await?;
        assert_eq!(result.is_error, Some(false), "{}", text_of(&result));

        Ok(serde_json::from_str(&text_of(&result))?)
    }

    /// Calls `execute` and parses the response, which must be JSON
    pub async fn execute_body(&self, code: &str) -> Result<Value, Box<dyn Error>> {
        let result = execute(&self.client, code).await?;

        Ok(serde_json::from_str(&text_of(&result))?)
    }

    /// Calls `wait` until the execution is no longer pending
    pub async fn wait_done(&self, id: &str) -> Result<CallToolResult, Box<dyn Error>> {
        for _ in 0..30 {
            let result = call(&self.client, "wait", json!({ "execution_id": id })).await?;
            let pending = serde_json::from_str::<Value>(&text_of(&result))
                .is_ok_and(|body| body["status"] == "pending");
            if !pending {
                return Ok(result);
            }
        }

        Err("execution never finished".into())
    }

    /// Base URL of the main listener
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.server.local_addr().port())
    }

    /// Base URL of the admin listener
    pub fn admin_base(&self) -> String {
        format!("http://127.0.0.1:{}", self.server.admin_addr().port())
    }

    pub async fn post_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<(u16, Value), Box<dyn Error>> {
        let response = self
            .http
            .post(format!("{}{path}", self.base()))
            .json(body)
            .send()
            .await?;
        let status = response.status().as_u16();
        let body = response.json::<Value>().await.unwrap_or(Value::Null);

        Ok((status, body))
    }

    /// Posts JSON to the admin listener
    pub async fn admin_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<(u16, Value), Box<dyn Error>> {
        let mut request = self
            .http
            .post(format!("{}{path}", self.admin_base()))
            .json(body);
        // the invite routes need the owner's proof, as the CLI makes it
        if path.starts_with("/admin/companion/invite") {
            request = request.header(
                codemode_mcp::admin::OWNER_PROOF_HEADER,
                self.owner_proof(path).await?,
            );
        }
        let response = request.send().await?;
        let status = response.status().as_u16();

        Ok((status, response.json().await.unwrap_or(Value::Null)))
    }

    /// A single-use proof for one owner request to `path`, made as the CLI
    /// makes it, after checking the daemon's own proof
    pub async fn owner_proof(&self, path: &str) -> Result<String, Box<dyn Error>> {
        use codemode_mcp::admin::{OWNER_TOKEN_FILE, daemon_proof_matches, request_proof};

        let token = std::fs::read_to_string(self.state_dir.join(OWNER_TOKEN_FILE))?;
        let token = token.trim();
        let client_nonce = uuid::Uuid::new_v4().simple().to_string();
        let challenge: Value = self
            .http
            .post(format!("{}/admin/owner/challenge", self.admin_base()))
            .json(&json!({ "client_nonce": client_nonce }))
            .send()
            .await?
            .json()
            .await?;
        let server_nonce = challenge["server_nonce"]
            .as_str()
            .ok_or("no server nonce")?;
        let proof = challenge["proof"].as_str().ok_or("no daemon proof")?;
        assert!(
            daemon_proof_matches(token, &client_nonce, server_nonce, proof),
            "the daemon's proof does not match the token"
        );

        Ok(format!(
            "{server_nonce}:{}",
            request_proof(token, server_nonce, path)
        ))
    }

    /// Asks the admin listener for an enrollment link; returns the link's
    /// path on the main listener and the admin response
    pub async fn request_enrollment(&self, label: &str) -> Result<(String, Value), Box<dyn Error>> {
        let (status, enrolled) = self
            .admin_json("/admin/enroll", &json!({ "label": label }))
            .await?;
        assert_eq!(status, 200, "{enrolled}");
        let url = enrolled["url"].as_str().ok_or("no enrollment url")?;
        assert!(url.starts_with(ORIGIN), "{url}");

        Ok((url.trim_start_matches(ORIGIN).to_owned(), enrolled))
    }

    /// Enrolls the first software passkey through the admin and enrollment routes
    pub async fn enroll_passkey(&self) -> Result<SoftPasskey, Box<dyn Error>> {
        let (path, enrolled) = self.request_enrollment("test <phone>").await?;
        assert!(enrolled["approval_url"].is_null(), "{enrolled}");

        self.register_at(&path).await
    }

    /// Registers a new software passkey on an enrollment page that is ready
    pub async fn register_at(&self, path: &str) -> Result<SoftPasskey, Box<dyn Error>> {
        let page = self
            .http
            .get(format!("{}{path}", self.base()))
            .send()
            .await?;
        assert_eq!(page.status().as_u16(), 200);

        let (status, started) = self
            .post_json(&format!("{path}/options"), &json!({}))
            .await?;
        assert_eq!(status, 200, "{started}");
        let options: CreationChallengeResponse =
            serde_json::from_value(started["options"].clone())?;

        let mut authenticator = SoftPasskey::new(true);
        let credential = authenticator
            .do_registration(Url::parse(ORIGIN)?, options)
            .map_err(|error| format!("registration failed: {error:?}"))?;
        let (status, finished) = self
            .post_json(
                &format!("{path}/finish"),
                &json!({ "ceremony": started["ceremony"], "credential": credential }),
            )
            .await?;
        assert_eq!(status, 200, "{finished}");

        Ok(authenticator)
    }

    /// Approves `approval_id` the way the page does: options, a passkey
    /// assertion, then confirm
    pub async fn approve_with_passkey(
        &self,
        authenticator: &mut SoftPasskey,
        approval_id: &str,
        choice: &str,
    ) -> Result<(u16, Value), Box<dyn Error>> {
        let (status, started) = self
            .post_json(
                &format!("/approve/{approval_id}/options"),
                &json!({ "choice": choice }),
            )
            .await?;
        if status != 200 {
            return Ok((status, started));
        }
        let options: RequestChallengeResponse = serde_json::from_value(started["options"].clone())?;
        let credential = authenticator
            .do_authentication(Url::parse(ORIGIN)?, options)
            .map_err(|error| format!("assertion failed: {error:?}"))?;

        self.post_json(
            &format!("/approve/{approval_id}/confirm"),
            &json!({ "ceremony": started["ceremony"], "credential": credential }),
        )
        .await
    }

    /// Whether any file under the daemon's state directory holds `needle`
    pub fn state_holds(&self, needle: &str) -> bool {
        fn holds(directory: &Path, needle: &[u8]) -> bool {
            let Ok(entries) = std::fs::read_dir(directory) else {
                return false;
            };

            entries.flatten().any(|entry| {
                let path = entry.path();
                let Ok(kind) = entry.file_type() else {
                    return false;
                };
                if kind.is_dir() {
                    return holds(&path, needle);
                }

                // reading a socket or fifo would block
                kind.is_file()
                    && std::fs::read(&path).is_ok_and(|bytes| {
                        bytes.windows(needle.len()).any(|window| window == needle)
                    })
            })
        }

        holds(&self.state_dir, needle.as_bytes())
    }

    pub async fn stop(self) -> TestResult {
        self.client.cancel().await?;
        self.server.shutdown().await?;
        let _ = std::fs::remove_dir_all(&self.state_dir);

        Ok(())
    }
}

pub fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text())
        .map(|block| block.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

pub async fn call(
    client: &Client,
    tool: &'static str,
    arguments: Value,
) -> Result<CallToolResult, Box<dyn Error>> {
    let Value::Object(arguments) = arguments else {
        return Err("arguments must be an object".into());
    };

    Ok(client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(arguments))
        .await?)
}

pub async fn execute(client: &Client, code: &str) -> Result<CallToolResult, Box<dyn Error>> {
    call(client, "execute", json!({ "code": code })).await
}

/// Approval id from a pending body's `approval_url`
pub fn approval_id(pending: &Value) -> Result<String, Box<dyn Error>> {
    let url = pending["approval_url"]
        .as_str()
        .ok_or_else(|| format!("no approval_url in {pending}"))?;

    Ok(url.rsplit('/').next().unwrap_or_default().to_owned())
}
