//! TOML configuration for the daemon and its upstream servers

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;

use crate::{
    policy::{GrantMode, Policy},
    stubs::is_brand_name,
};

/// Origin the approval and enrollment pages are reached through; its host is
/// the WebAuthn relying party id
const DEFAULT_PUBLIC_ORIGIN: &str = "https://mac.tailnet-name.ts.net:8443";
/// ntfy server used when a notify section names none
const DEFAULT_NTFY_SERVER: &str = "https://ntfy.sh";

/// Reasons a configuration file could not be loaded
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read
    #[error("failed to read config {path}: {source}")]
    Read {
        /// Path that was read
        path: PathBuf,
        /// Underlying I/O error
        source: std::io::Error,
    },
    /// The file is not valid TOML or has unknown fields
    #[error("failed to parse config {path}: {source}")]
    Parse {
        /// Path that was parsed
        path: PathBuf,
        /// Underlying TOML error
        source: toml::de::Error,
    },
    /// The file parsed but a value is unusable
    #[error("invalid config: {0}")]
    Invalid(String),
    /// No home directory is known, so the default path cannot be derived
    #[error("cannot locate the default config path because $HOME is not set")]
    NoHome,
}

/// Top-level daemon configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the HTTP server binds to
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Host names accepted in the `Host` header on top of the built-in rules
    /// (loopback, private and Tailscale addresses, `*.ts.net`, `*.local` and
    /// single-label names)
    #[serde(default)]
    pub extra_allowed_hosts: Vec<String>,
    /// Path of the Monty worker binary; when unset, the copy `service
    /// install` makes (`~/.local/share/codemode-mcp/monty`), else `monty`
    /// on `$PATH`
    #[serde(default)]
    pub worker_path: Option<PathBuf>,
    /// How long one upstream tool call may run before it is cancelled
    #[serde(default = "default_tool_timeout_secs")]
    pub tool_timeout_secs: u64,
    /// Address of the admin listener the CLI talks to; must be loopback
    /// because the main listener is reachable through `tailscale serve`,
    /// whose proxied requests also arrive from a loopback peer
    #[serde(default = "default_admin_listen")]
    pub admin_listen: SocketAddr,
    /// Directory for the database and the snapshot key; defaults to
    /// `$XDG_STATE_HOME/codemode-mcp` or `~/.local/state/codemode-mcp`
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// HTTPS origin phones use to reach the approval pages
    #[serde(default = "default_public_origin")]
    pub public_origin: String,
    /// Days of usage records kept before they are purged
    #[serde(default = "default_log_retention_days")]
    pub log_retention_days: u64,
    /// Hours an app session may sit idle before it expires
    #[serde(default = "default_session_idle_hours")]
    pub session_idle_hours: u64,
    /// Approval behaviour
    #[serde(default)]
    pub approvals: ApprovalsConfig,
    /// Where approval notifications go
    #[serde(default)]
    pub notify: NotifyConfig,
    /// Sandbox and execution limits
    #[serde(default)]
    pub limits: Limits,
    /// Upstream MCP servers by name
    #[serde(default)]
    pub servers: BTreeMap<String, ServerConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            extra_allowed_hosts: Vec::new(),
            worker_path: None,
            tool_timeout_secs: default_tool_timeout_secs(),
            admin_listen: default_admin_listen(),
            state_dir: None,
            public_origin: default_public_origin(),
            log_retention_days: default_log_retention_days(),
            session_idle_hours: default_session_idle_hours(),
            approvals: ApprovalsConfig::default(),
            notify: NotifyConfig::default(),
            limits: Limits::default(),
            servers: BTreeMap::new(),
        }
    }
}

impl Config {
    /// Default location of the configuration file
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let home = std::env::var_os("HOME").ok_or(ConfigError::NoHome)?;

        Ok(PathBuf::from(home).join(".config/codemode-mcp/config.toml"))
    }

    /// Reads and validates the file at `path`
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;

        Self::parse(&text, path)
    }

    /// Parses and validates configuration text; `path` is used in errors only
    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        config.validate()?;

        Ok(config)
    }

    /// Upstream call timeout as a duration
    pub fn tool_timeout(&self) -> Duration {
        Duration::from_secs(self.tool_timeout_secs)
    }

    /// Directory holding the database and snapshot key
    pub fn state_dir(&self) -> Result<PathBuf, ConfigError> {
        if let Some(directory) = &self.state_dir {
            return Ok(expand_home(directory));
        }
        if let Some(state) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(state).join("codemode-mcp"));
        }
        let home = std::env::var_os("HOME").ok_or(ConfigError::NoHome)?;

        Ok(PathBuf::from(home).join(".local/state/codemode-mcp"))
    }

    /// Public origin without a trailing slash, for building page links
    pub fn public_base(&self) -> &str {
        self.public_origin.trim_end_matches('/')
    }

    /// How long usage records are kept
    pub fn log_retention(&self) -> Duration {
        Duration::from_secs(self.log_retention_days.saturating_mul(24 * 60 * 60))
    }

    /// How long an app session may sit idle before it expires
    pub fn session_idle(&self) -> Duration {
        Duration::from_secs(self.session_idle_hours.saturating_mul(60 * 60))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.tool_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "tool_timeout_secs must be positive".into(),
            ));
        }
        if !self.admin_listen.ip().is_loopback() {
            return Err(ConfigError::Invalid(
                "admin_listen must be a loopback address".into(),
            ));
        }
        if !(self.public_origin.starts_with("https://")
            || self.public_origin.starts_with("http://"))
        {
            return Err(ConfigError::Invalid(
                "public_origin must be an http(s) origin".into(),
            ));
        }
        if self.log_retention_days == 0 {
            return Err(ConfigError::Invalid(
                "log_retention_days must be positive".into(),
            ));
        }
        if self.session_idle_hours == 0 {
            return Err(ConfigError::Invalid(
                "session_idle_hours must be positive".into(),
            ));
        }
        if self.approvals.timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "approvals.timeout_secs must be positive".into(),
            ));
        }
        if let Some(ntfy) = &self.notify.ntfy {
            ntfy.validate()?;
        }
        if self.notify.mac.idle_secs == 0 {
            return Err(ConfigError::Invalid(
                "notify.mac.idle_secs must be positive; set notify.mac.enabled = false to ask \
                 on the phone only"
                    .into(),
            ));
        }
        self.limits.validate()?;

        for (name, server) in &self.servers {
            if name.is_empty() {
                return Err(ConfigError::Invalid(
                    "server names must not be empty".into(),
                ));
            }
            server.validate(name)?;
        }

        Ok(())
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 7681))
}

fn default_tool_timeout_secs() -> u64 {
    120
}

fn default_admin_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 7682))
}

fn default_public_origin() -> String {
    DEFAULT_PUBLIC_ORIGIN.to_owned()
}

fn default_log_retention_days() -> u64 {
    90
}

fn default_session_idle_hours() -> u64 {
    24
}

/// Expands a leading `~/` to `$HOME`
pub fn expand_home(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => path.to_owned(),
    }
}

/// Approval settings
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalsConfig {
    /// Seconds a pending approval waits before it is denied automatically
    pub timeout_secs: u64,
}

impl Default for ApprovalsConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10 * 60,
        }
    }
}

impl ApprovalsConfig {
    /// Pending-approval lifetime as a duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

/// Notification settings
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NotifyConfig {
    /// ntfy target; when absent the `[notify.ntfy]` section of homebased's
    /// config is used
    pub ntfy: Option<NtfyConfig>,
    /// homebased config read for the fallback ntfy section
    pub homebased_config: Option<PathBuf>,
    /// Asking on the Mac itself while the owner is at it
    pub mac: MacConfig,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            ntfy: None,
            homebased_config: std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".config/homebased/config.toml")),
            mac: MacConfig::default(),
        }
    }
}

/// How requests reach the owner while they are at the Mac
///
/// A tool call made while the screen is unlocked and recently used shows a
/// Touch ID prompt on the Mac before the phone is told, and an admin
/// request shows a notification there; one made while the owner is away
/// goes to the phone at once
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MacConfig {
    /// Whether to ask on the Mac at all; off means phone only
    pub enabled: bool,
    /// Seconds without keyboard or mouse input after which the owner counts
    /// as away
    pub idle_secs: u64,
    /// Seconds a request may wait on the Mac before the phone is told too
    pub escalate_after_secs: u64,
    /// Whether a tool call shows a Touch ID prompt, whose fingerprint
    /// approves it for 60 minutes; off shows a notification that opens the
    /// page
    pub touch_id: bool,
}

impl Default for MacConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_secs: 5 * 60,
            escalate_after_secs: 60,
            touch_id: true,
        }
    }
}

impl MacConfig {
    /// Input idle time after which the owner counts as away
    pub fn idle(&self) -> Duration {
        Duration::from_secs(self.idle_secs)
    }

    /// Delay before a request asked on the Mac also goes to the phone
    pub fn escalate_after(&self) -> Duration {
        Duration::from_secs(self.escalate_after_secs)
    }
}

impl NotifyConfig {
    /// The ntfy target: this config's own section, else homebased's
    ///
    /// A missing or unreadable homebased config means no notifier; its other
    /// sections are ignored
    pub fn resolve_ntfy(&self) -> Result<Option<NtfyConfig>, ConfigError> {
        if let Some(ntfy) = &self.ntfy {
            return Ok(Some(ntfy.clone()));
        }
        let Some(path) = &self.homebased_config else {
            return Ok(None);
        };
        let path = expand_home(path);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(ConfigError::Read { path, source }),
        };

        #[derive(Deserialize)]
        struct Homebased {
            #[serde(default)]
            notify: Option<HomebasedNotify>,
        }
        #[derive(Deserialize)]
        struct HomebasedNotify {
            #[serde(default)]
            ntfy: Option<NtfyConfig>,
        }

        let parsed: Homebased =
            toml::from_str(&text).map_err(|source| ConfigError::Parse { path, source })?;
        let ntfy = parsed.notify.and_then(|notify| notify.ntfy);
        if let Some(ntfy) = &ntfy {
            ntfy.validate()?;
        }

        Ok(ntfy)
    }
}

/// An ntfy topic, in the same shape homebased uses
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    /// Server base URL
    #[serde(default = "default_ntfy_server")]
    pub server: String,
    /// Topic name; a secret, so never logged
    pub topic: String,
    /// File holding a bearer token
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

// hand-written so the topic and token path never reach logs through `{:?}`
impl std::fmt::Debug for NtfyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NtfyConfig")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

fn default_ntfy_server() -> String {
    DEFAULT_NTFY_SERVER.to_owned()
}

impl NtfyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let topic_ok = !self.topic.is_empty()
            && self.topic.len() <= 64
            && self
                .topic
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character));
        if !topic_ok {
            return Err(ConfigError::Invalid(
                "notify.ntfy.topic must be 1-64 ASCII letters, digits, `_` or `-`".into(),
            ));
        }
        if !(self.server.starts_with("https://") || self.server.starts_with("http://")) {
            return Err(ConfigError::Invalid(
                "notify.ntfy.server must be an http(s) URL".into(),
            ));
        }

        Ok(())
    }
}

/// Sandbox and scheduling limits for script executions
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Heap budget for one script, in bytes
    pub max_memory_bytes: usize,
    /// Interpreter CPU time one script may use; time spent waiting on tools
    /// does not count
    pub script_time_budget_secs: u64,
    /// Wall-clock cap for one execution, including time spent in tool calls
    /// but not time spent waiting for an approval
    pub execution_timeout_secs: u64,
    /// Host round trips (tool calls, sleeps, name lookups) one script may use
    pub max_suspensions: usize,
    /// Total time one script may spend in `asyncio.sleep` or `time.sleep`
    pub max_total_sleep_secs: u64,
    /// How long `execute` and `wait` block before answering `pending`
    pub execute_wait_secs: u64,
    /// How often a waiting `execute` or `wait` sends an MCP progress
    /// notification, which keeps clients with an idle timeout connected
    pub progress_interval_ms: u64,
    /// Concurrent Monty worker processes, each able to use up to
    /// `max_memory_bytes`
    pub max_workers: usize,
    /// Executions that may wait for a free worker before new ones are
    /// refused with a "busy" error
    pub max_queued_executions: usize,
    /// How long finished results stay available to `wait`
    pub result_ttl_secs: u64,
    /// How long a stopping daemon lets running executions finish before it
    /// interrupts them; ones waiting only on approvals are parked at once and
    /// resume after the restart. Named like the other durations, not
    /// `drain`; zero skips the wait
    pub drain_secs: u64,
    /// Largest script `execute` accepts, in bytes; agent scripts are glue
    /// of a few hundred bytes, and the cap bounds how deeply a script can
    /// nest before the host parses it
    pub max_script_bytes: usize,
    /// Cap on captured `print` output per execution, in bytes
    pub max_output_bytes: usize,
    /// Cap on the JSON result of one execution, in bytes; the rest is cut
    /// off and marked truncated
    pub max_result_bytes: usize,
    /// Cap on one upstream tool result handed to a script; larger results
    /// raise an exception at the call site
    pub max_tool_result_bytes: usize,
    /// Total size of finished results kept for `wait`; the oldest are
    /// dropped first
    pub max_retained_result_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024,
            script_time_budget_secs: 30,
            execution_timeout_secs: 10 * 60,
            max_suspensions: 1000,
            max_total_sleep_secs: 300,
            execute_wait_secs: 25,
            progress_interval_ms: 15_000,
            max_workers: 16,
            max_queued_executions: 64,
            result_ttl_secs: 30 * 60,
            drain_secs: 20,
            max_output_bytes: 64 * 1024,
            max_result_bytes: 256 * 1024,
            max_script_bytes: 64 * 1024,
            max_tool_result_bytes: 4 * 1024 * 1024,
            max_retained_result_bytes: 32 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Wait budget as a duration
    pub fn execute_wait(&self) -> Duration {
        Duration::from_secs(self.execute_wait_secs)
    }

    /// Progress notification interval as a duration
    pub fn progress_interval(&self) -> Duration {
        Duration::from_millis(self.progress_interval_ms)
    }

    /// Result retention as a duration
    pub fn result_ttl(&self) -> Duration {
        Duration::from_secs(self.result_ttl_secs)
    }

    /// Drain period as a duration
    pub fn drain(&self) -> Duration {
        Duration::from_secs(self.drain_secs)
    }

    /// Wall-clock cap per execution as a duration
    pub fn execution_timeout(&self) -> Duration {
        Duration::from_secs(self.execution_timeout_secs)
    }

    /// Cap on the text of one response to the agent: the result and the
    /// printed output, plus room for the envelope and diagnostics
    pub fn max_response_bytes(&self) -> usize {
        self.max_result_bytes
            .saturating_add(self.max_output_bytes)
            .saturating_add(16 * 1024)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let positive = [
            ("max_memory_bytes", self.max_memory_bytes as u64),
            ("script_time_budget_secs", self.script_time_budget_secs),
            ("execution_timeout_secs", self.execution_timeout_secs),
            ("max_suspensions", self.max_suspensions as u64),
            ("max_workers", self.max_workers as u64),
            ("max_result_bytes", self.max_result_bytes as u64),
            ("max_tool_result_bytes", self.max_tool_result_bytes as u64),
            (
                "max_retained_result_bytes",
                self.max_retained_result_bytes as u64,
            ),
            ("execute_wait_secs", self.execute_wait_secs),
            ("progress_interval_ms", self.progress_interval_ms),
        ];
        for (field, value) in positive {
            if value == 0 {
                return Err(ConfigError::Invalid(format!(
                    "limits.{field} must be positive"
                )));
            }
        }

        Ok(())
    }
}

/// One upstream MCP server
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Executable for a stdio server
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments for a stdio server
    #[serde(default)]
    pub args: Vec<String>,
    /// Extra environment for a stdio server
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Working directory for a stdio server
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Endpoint of a Streamable HTTP server
    #[serde(default)]
    pub url: Option<String>,
    /// Static headers sent with every HTTP request
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Whether a `url` server signs in with OAuth (`codemode-mcp oauth
    /// login <server>`); until then it is used anonymously, or reported as
    /// `needs_login` when it refuses anonymous clients
    #[serde(default)]
    pub oauth: bool,
    /// OAuth scopes to request; the server's advertised scopes when empty
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Client name sent during dynamic client registration
    #[serde(default)]
    pub client_name: Option<String>,
    /// Default policy for every tool of this server
    #[serde(default)]
    pub policy: Policy,
    /// Whether usage logs keep only tool names and outcomes for this server;
    /// defaults to true when `policy` is `ask`
    #[serde(default)]
    pub sensitive: Option<bool>,
    /// Per-tool overrides keyed by the upstream tool name
    #[serde(default)]
    pub tools: BTreeMap<String, ToolOverride>,
    /// Calls `codemode-mcp op warm` runs to front-load prompts on the Mac
    #[serde(default)]
    pub warm: Option<WarmConfig>,
    /// Arguments the gateway passes to every tool of this server that takes
    /// them; they disappear from the stubs, so scripts cannot get them wrong
    #[serde(default)]
    pub arguments: serde_json::Map<String, serde_json::Value>,
    /// Calls made once on each new connection, before the first other call
    /// on it, such as a login that grants the scopes the other tools check;
    /// they run inside that call, so it needs no approval of its own
    #[serde(default)]
    pub setup: Vec<WarmCall>,
    /// Other names agents search for this server by, such as `1password`
    /// for `onepassword`
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// Per-tool settings that override the server defaults
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOverride {
    /// Policy for this tool; the server policy when unset
    #[serde(default)]
    pub policy: Option<Policy>,
    /// How far one approval of this tool reaches; `session` when unset
    #[serde(default)]
    pub grant: Option<GrantMode>,
    /// How the result reaches scripts; see [`OutputMode`]
    #[serde(default)]
    pub output: Option<OutputMode>,
    /// JSON Schema of the result, used as if the upstream had declared it
    ///
    /// An upstream-declared schema wins over this one unless
    /// `force_output_schema` is set, so a schema written for a server that
    /// later documents its own stops applying without an edit here
    #[serde(default)]
    pub output_schema: Option<serde_json::Map<String, serde_json::Value>>,
    /// Use `output_schema` even when the upstream declares its own
    #[serde(default)]
    pub force_output_schema: bool,
    /// Branded types for string parameters, by parameter name
    ///
    /// A parameter listed here is typed as the named `NewType` of `str`, so
    /// only a value some tool returned with the same type passes the type
    /// check. Pair it with `x-codemode-type` in the `output_schema` of the
    /// tool that produces the value
    #[serde(default)]
    pub param_types: BTreeMap<String, String>,
}

/// How a tool's result is handed to scripts when the config overrides the default
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputMode {
    /// The result is the tool's text blocks joined with newlines, typed
    /// `str` and never parsed as JSON, whatever the upstream declares
    Text,
}

impl ToolOverride {
    fn validate(&self, server: &str, tool: &str) -> Result<(), ConfigError> {
        let at = format!("servers.{server}.tools.{tool}");
        if self.output.is_some() && self.output_schema.is_some() {
            return Err(ConfigError::Invalid(format!(
                "{at}: `output` and `output_schema` cannot be combined; text results have no schema"
            )));
        }
        if self.force_output_schema && self.output_schema.is_none() {
            return Err(ConfigError::Invalid(format!(
                "{at}: `force_output_schema` needs `output_schema`"
            )));
        }
        for (param, brand) in &self.param_types {
            if !is_brand_name(brand) {
                return Err(ConfigError::Invalid(format!(
                    "{at}: `param_types.{param}` must name a type that is a Python identifier starting with a capital letter, got `{brand}`"
                )));
            }
        }

        Ok(())
    }
}

/// Warm-up calls for one server
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmConfig {
    /// Calls made in order
    pub calls: Vec<WarmCall>,
}

/// One warm-up call
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmCall {
    /// Upstream tool name
    pub tool: String,
    /// Arguments passed as-is
    #[serde(default)]
    pub arguments: serde_json::Map<String, serde_json::Value>,
}

/// How to reach a server, derived from [`ServerConfig`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport<'a> {
    /// Spawn a child process and speak MCP over its stdio
    Stdio {
        /// Executable
        command: &'a str,
    },
    /// Connect to a Streamable HTTP endpoint
    Http {
        /// Endpoint URL
        url: &'a str,
    },
}

impl ServerConfig {
    /// The transport this server uses; validation guarantees exactly one
    pub fn transport(&self) -> Option<Transport<'_>> {
        match (&self.command, &self.url) {
            (Some(command), None) => Some(Transport::Stdio { command }),
            (None, Some(url)) => Some(Transport::Http { url }),
            _ => None,
        }
    }

    /// Policy for a tool, preferring a per-tool override
    pub fn policy_for(&self, tool: &str) -> Policy {
        self.tools
            .get(tool)
            .and_then(|tool| tool.policy)
            .unwrap_or(self.policy)
    }

    /// The per-tool override for an upstream tool name
    pub fn tool_override(&self, tool: &str) -> Option<&ToolOverride> {
        self.tools.get(tool)
    }

    /// Grant mode for a tool whose policy is `ask`
    pub fn grant_for(&self, tool: &str) -> GrantMode {
        self.tools
            .get(tool)
            .and_then(|tool| tool.grant)
            .unwrap_or_default()
    }

    /// Whether logs must leave out this server's arguments, results and
    /// error text; unless set explicitly, true when the server or any of its
    /// tools asks for approval
    pub fn is_sensitive(&self) -> bool {
        self.sensitive.unwrap_or_else(|| {
            self.policy == Policy::Ask
                || self
                    .tools
                    .values()
                    .any(|tool| tool.policy == Some(Policy::Ask))
        })
    }

    fn validate(&self, name: &str) -> Result<(), ConfigError> {
        for (tool, tool_override) in &self.tools {
            tool_override.validate(name, tool)?;
        }

        match (&self.command, &self.url) {
            (Some(_), Some(_)) => Err(ConfigError::Invalid(format!(
                "servers.{name}: set either `command` or `url`, not both"
            ))),
            (None, None) => Err(ConfigError::Invalid(format!(
                "servers.{name}: one of `command` or `url` is required"
            ))),
            (Some(_), None) if !self.headers.is_empty() => Err(ConfigError::Invalid(format!(
                "servers.{name}: `headers` only applies to `url` servers"
            ))),
            (None, Some(_))
                if !self.args.is_empty() || !self.env.is_empty() || self.cwd.is_some() =>
            {
                Err(ConfigError::Invalid(format!(
                    "servers.{name}: `args`, `env` and `cwd` only apply to `command` servers"
                )))
            }
            (Some(_), None) if self.oauth => Err(ConfigError::Invalid(format!(
                "servers.{name}: `oauth` only applies to `url` servers"
            ))),
            _ if !self.oauth && (!self.scopes.is_empty() || self.client_name.is_some()) => {
                Err(ConfigError::Invalid(format!(
                    "servers.{name}: `scopes` and `client_name` need `oauth = true`"
                )))
            }
            // the OAuth client owns the authorization header
            _ if self.oauth
                && self
                    .headers
                    .keys()
                    .any(|header| header.eq_ignore_ascii_case("authorization")) =>
            {
                Err(ConfigError::Invalid(format!(
                    "servers.{name}: an `authorization` header cannot be combined with `oauth`"
                )))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("test.toml"))
    }

    #[test]
    fn parses_both_transports_and_overrides() -> Result<(), ConfigError> {
        let config = parse(
            r#"
            listen = "127.0.0.1:9000"

            [servers.docs]
            url = "https://example.com/mcp"
            headers = { "x-team" = "a" }

            [servers.op]
            command = "op-mcp"
            args = ["--stdio"]
            policy = "ask"

            [servers.op.tools.delete_item]
            policy = "deny"

            [servers.op.tools.create_environment]
            grant = "per_call"
            "#,
        )?;

        assert_eq!(config.listen.port(), 9000);
        assert_eq!(
            config.servers["docs"].transport(),
            Some(Transport::Http {
                url: "https://example.com/mcp"
            })
        );
        assert_eq!(config.servers["op"].policy_for("list"), Policy::Ask);
        assert_eq!(config.servers["op"].policy_for("delete_item"), Policy::Deny);
        assert_eq!(
            config.servers["op"].policy_for("create_environment"),
            Policy::Ask
        );
        assert_eq!(
            config.servers["op"].grant_for("create_environment"),
            GrantMode::PerCall
        );
        assert_eq!(config.servers["op"].grant_for("list"), GrantMode::Session);
        assert!(config.servers["op"].is_sensitive());
        assert!(!config.servers["docs"].is_sensitive());

        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_and_ambiguous_servers() {
        assert!(parse("surprise = 1").is_err());
        assert!(parse("[servers.a]\ncommand = \"x\"\nurl = \"http://y\"").is_err());
        assert!(parse("[servers.a]\npolicy = \"allow\"").is_err());
        assert!(parse("admin_listen = \"0.0.0.0:7682\"").is_err());
        assert!(parse("[servers.a]\ncommand = \"x\"\noauth = true").is_err());
        assert!(parse("[servers.a]\nurl = \"https://y\"\nscopes = [\"s\"]").is_err());
        assert!(
            parse("[servers.a]\nurl = \"https://y\"\noauth = true\nheaders = { Authorization = \"Bearer abcdef\" }")
                .is_err()
        );
    }
}
