//! TOML configuration for the daemon and its upstream servers

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use companion_wire::mobile::SealKey;
use iroh::EndpointId;
use serde::Deserialize;

use crate::{
    policy::{GrantMode, Policy},
    stubs::is_brand_name,
};

/// ntfy server used when a notify section names none
const DEFAULT_NTFY_SERVER: &str = "https://ntfy.sh";
/// Authorization URL parameters rmcp sets; overriding one would break
/// PKCE, the CSRF check or the token exchange
const RESERVED_AUTHORIZATION_PARAMS: [&str; 8] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource",
];

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
    /// HTTPS origin phones use to reach the approval and enrollment pages,
    /// such as the `tailscale serve` address; its host is the WebAuthn
    /// relying party id. Unset, the pages are only reachable on this machine
    #[serde(default)]
    pub public_origin: Option<String>,
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
    /// How `{{ op://... }}` references in server `headers` and `env` are read
    #[serde(default)]
    pub secrets: SecretsConfig,
    /// Reading 1Password references for another Mac; only set on the
    /// companion Mac
    #[serde(default)]
    pub companion: Option<CompanionConfig>,
    /// Upstream MCP servers by name
    #[serde(default)]
    pub servers: BTreeMap<String, ServerConfig>,
    /// 1Password logins a `builtin = "logins"` server may type into a page
    /// on their sites, by name
    #[serde(default)]
    pub logins: BTreeMap<String, LoginConfig>,
    /// The file this was loaded from; `None` when parsed from text, and then
    /// nothing can be written back
    #[serde(skip)]
    path: Option<PathBuf>,
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
            public_origin: None,
            log_retention_days: default_log_retention_days(),
            session_idle_hours: default_session_idle_hours(),
            approvals: ApprovalsConfig::default(),
            notify: NotifyConfig::default(),
            limits: Limits::default(),
            secrets: SecretsConfig::default(),
            companion: None,
            servers: BTreeMap::new(),
            logins: BTreeMap::new(),
            path: None,
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

        let mut config = Self::parse(&text, path)?;
        config.path = Some(path.to_owned());

        Ok(config)
    }

    /// The file this was loaded from, which a companion registering with an
    /// invite is appended to
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
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

    /// Origin of the approval and enrollment pages: `public_origin`, else
    /// `http://localhost:<listen port>`, which WebAuthn accepts without TLS
    pub fn public_origin(&self) -> String {
        match &self.public_origin {
            Some(origin) => origin.clone(),
            None => format!("http://localhost:{}", self.listen.port()),
        }
    }

    /// [`Config::public_origin`] without a trailing slash, for building page
    /// links
    pub fn public_base(&self) -> String {
        self.public_origin().trim_end_matches('/').to_owned()
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
        if let Some(origin) = &self.public_origin
            && !(origin.starts_with("https://") || origin.starts_with("http://"))
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
        self.secrets.validate()?;
        if let Some(companion) = &self.companion {
            companion.validate()?;
        }

        for (name, server) in &self.servers {
            if name.is_empty() {
                return Err(ConfigError::Invalid(
                    "server names must not be empty".into(),
                ));
            }
            server.validate(name)?;
        }
        for (name, login) in &self.logins {
            login.validate(name)?;
        }

        Ok(())
    }
}

/// The tools of the `logins` builtin, which per-tool settings may name
const LOGINS_TOOLS: [&str; 2] = ["fill", "list"];

/// Longest login name; the approval page and prompts show it
const MAX_LOGIN_NAME_CHARS: usize = 63;

/// A 1Password login the `logins` server may type into the focused field
/// of a page on one of its sites
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginConfig {
    /// Hosts the login may be typed on: `github.com` is that host only,
    /// and `*.github.com` any host under it
    pub sites: Vec<String>,
    /// Reference of the username, such as `op://Personal/GitHub/username`
    #[serde(default)]
    pub username: Option<String>,
    /// Reference of the password
    #[serde(default)]
    pub password: Option<String>,
}

impl LoginConfig {
    /// The references the login reads, for a companion's or phone's allow
    /// list
    pub fn references(&self) -> impl Iterator<Item = &str> {
        self.username
            .iter()
            .chain(self.password.iter())
            .map(String::as_str)
    }

    fn validate(&self, name: &str) -> Result<(), ConfigError> {
        let at = format!("logins.{name}");
        // agents pass the name and the approval page shows it
        let plain = name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if name.is_empty() || name.chars().count() > MAX_LOGIN_NAME_CHARS || !plain {
            return Err(ConfigError::Invalid(format!(
                "{at}: login names must be 1 to {MAX_LOGIN_NAME_CHARS} lowercase letters, digits, \
                 `-` or `_`"
            )));
        }
        if self.sites.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "{at}: `sites` must name at least one host, such as \"github.com\""
            )));
        }
        for site in &self.sites {
            if !is_site(site) {
                return Err(ConfigError::Invalid(format!(
                    "{at}: `{site}` in `sites` must be a lowercase host name with a dot, such as \
                     \"github.com\" or \"*.github.com\", without a scheme, port or path"
                )));
            }
        }
        if self.username.is_none() && self.password.is_none() {
            return Err(ConfigError::Invalid(format!(
                "{at}: set `username`, `password` or both"
            )));
        }
        for (field, reference) in [("username", &self.username), ("password", &self.password)] {
            if let Some(reference) = reference
                && !crate::secrets::is_reference(reference)
            {
                return Err(ConfigError::Invalid(format!(
                    "{at}.{field}: must be an op://vault/item/field reference, without braces"
                )));
            }
        }

        Ok(())
    }
}

/// A host a login may be typed on: lowercase labels joined by dots, after
/// an optional `*.` for the hosts under it
fn is_site(site: &str) -> bool {
    let host = site.strip_prefix("*.").unwrap_or(site);
    let labels: Vec<&str> = host.split('.').collect();

    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// The 1Password CLI that reads `{{ op://vault/item/field }}` references in
/// server `headers` and `env` when a server first connects, and the
/// companion Macs that can read them when the owner is elsewhere
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// `op` executable; it reads through the 1Password app, which asks on
    /// the Mac
    #[serde(default = "default_op")]
    pub op: String,
    /// Whether the iroh endpoint uses n0's relays and DNS discovery; off, it
    /// dials only the companions' `addrs`
    #[serde(default = "default_discovery")]
    pub discovery: bool,
    /// File holding this gateway's iroh secret key (hex, mode 0600), created
    /// when missing; unset, the login keychain holds it
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
    /// Fixed address for the gateway's iroh endpoint instead of a random
    /// port; with discovery off a phone dials it, so it must stay the same
    /// across restarts
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// Other Macs that can read references for this one
    #[serde(default)]
    pub companions: Vec<CompanionPeer>,
    /// Phones that answer reads by opening values sealed to them; the
    /// gateway accepts phone connections only from these ids
    #[serde(default)]
    pub phones: Vec<PhonePeer>,
    /// The APNs key that wakes the phones; without it a phone answers only
    /// while its app is open
    #[serde(default)]
    pub apns: Option<ApnsConfig>,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            op: default_op(),
            discovery: default_discovery(),
            identity_file: None,
            listen: None,
            companions: Vec::new(),
            phones: Vec::new(),
            apns: None,
        }
    }
}

/// Longest name of a Mac, as `gateway_name` and `secrets.companions` give it
pub const MAX_MAC_NAME_CHARS: usize = 63;

/// Whether `name` can name a Mac in a Touch ID prompt or an error: short,
/// and on one line without control, invisible or direction-changing
/// characters, so a pairing ticket cannot make the prompt say something else
pub fn is_mac_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.chars().count() <= MAX_MAC_NAME_CHARS
        && crate::prompt::one_line(name, usize::MAX) == name
}

impl SecretsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        require_absolute_identity("secrets", self.identity_file.as_deref())?;

        // companions and phones share one namespace: read errors name the
        // source that failed
        let mut names = std::collections::BTreeSet::new();
        for companion in &self.companions {
            if !is_mac_name(&companion.name) {
                return Err(ConfigError::Invalid(format!(
                    "secrets.companions names must be 1 to {MAX_MAC_NAME_CHARS} characters on one line"
                )));
            }
            if !names.insert(companion.name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "secrets.companions has the name \"{}\" twice",
                    companion.name
                )));
            }
            if !self.discovery && companion.addrs.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "secrets.companions \"{}\" needs `addrs` because secrets.discovery is off",
                    companion.name
                )));
            }
        }
        for phone in &self.phones {
            if !is_mac_name(&phone.name) {
                return Err(ConfigError::Invalid(format!(
                    "secrets.phones names must be 1 to {MAX_MAC_NAME_CHARS} characters on one line"
                )));
            }
            if !names.insert(phone.name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "secrets.phones has the name \"{}\", which another phone or companion has",
                    phone.name
                )));
            }
        }
        if let Some(apns) = &self.apns {
            apns.validate()?;
        }

        Ok(())
    }
}

/// A phone the gateway wakes with a push and that dials back to answer
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhonePeer {
    /// Name shown in logs and errors
    pub name: String,
    /// The phone's iroh endpoint id; connections from any other id are
    /// refused
    pub id: EndpointId,
    /// The phone's Secure Enclave P-256 public key (base64 of the
    /// uncompressed point), which values are sealed to
    pub seal_key: SealKey,
}

/// The App Store Connect key the gateway signs APNs requests with
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsConfig {
    /// The `.p8` file Apple issued (PKCS#8 PEM); read on each new token, so
    /// a replaced file is used without a restart
    pub key_file: PathBuf,
    /// The key's id, as App Store Connect shows it
    pub key_id: String,
    /// The team the key and the app belong to
    pub team_id: String,
    /// The app's bundle id
    #[serde(default = "default_apns_topic")]
    pub topic: String,
    /// Base URL used for both environments instead of Apple's hosts, e.g. a
    /// test double; unset in normal use
    #[serde(default)]
    pub server: Option<String>,
}

impl ApnsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let is_id =
            |text: &str| text.len() == 10 && text.bytes().all(|byte| byte.is_ascii_alphanumeric());
        if !is_id(&self.key_id) || !is_id(&self.team_id) {
            return Err(ConfigError::Invalid(
                "secrets.apns key_id and team_id are 10 letters or digits".into(),
            ));
        }
        if !expand_home(&self.key_file).is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "secrets.apns.key_file must be an absolute path (or start with ~/), got {}",
                self.key_file.display()
            )));
        }

        Ok(())
    }
}

fn default_apns_topic() -> String {
    "com.avencera.codemode-mcp.companion".to_owned()
}

/// A companion Mac the gateway asks to read references
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionPeer {
    /// Name shown in logs and errors
    pub name: String,
    /// The companion's iroh endpoint id, from `codemode-mcp companion id`
    pub id: EndpointId,
    /// Direct addresses to dial before discovery, e.g. `100.64.0.5:7678`
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
}

/// The companion role of this Mac: reads references for one gateway after a
/// Touch ID prompt on this Mac
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionConfig {
    /// The only endpoint id this companion answers
    pub gateway: EndpointId,
    /// Name of the gateway Mac, shown in the Touch ID prompt
    #[serde(default = "default_gateway_name")]
    pub gateway_name: String,
    /// The references this companion may read, matched exactly
    #[serde(default)]
    pub allow: Vec<String>,
    /// Fixed address to bind instead of a random port
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// Whether the iroh endpoint publishes to n0's DNS and uses its relays
    #[serde(default = "default_discovery")]
    pub discovery: bool,
    /// File holding this companion's iroh secret key (hex, mode 0600),
    /// created when missing; unset, the login keychain holds it
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
    /// `op` executable
    #[serde(default = "default_op")]
    pub op: String,
}

impl CompanionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        require_absolute_identity("companion", self.identity_file.as_deref())?;

        if !is_mac_name(&self.gateway_name) {
            return Err(ConfigError::Invalid(format!(
                "companion.gateway_name must be 1 to {MAX_MAC_NAME_CHARS} characters on one line"
            )));
        }
        for reference in &self.allow {
            if !crate::secrets::is_reference(reference.trim()) {
                return Err(ConfigError::Invalid(
                    "companion.allow entries must be op://vault/item/field references".into(),
                ));
            }
        }

        Ok(())
    }

    /// Whether `reference` is on the allow list; both sides are trimmed
    pub fn allows(&self, reference: &str) -> bool {
        let reference = reference.trim();

        self.allow.iter().any(|allowed| allowed.trim() == reference)
    }
}

fn default_discovery() -> bool {
    true
}

fn default_gateway_name() -> String {
    "main".to_owned()
}

fn default_idle_secs() -> u64 {
    10 * 60
}

fn default_op() -> String {
    "op".to_owned()
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

fn default_log_retention_days() -> u64 {
    90
}

fn default_session_idle_hours() -> u64 {
    24
}

/// Rejects a relative `identity_file`: a LaunchAgent runs elsewhere than the
/// shell that wrote the path, so it would find or create a different key
fn require_absolute_identity(section: &str, file: Option<&Path>) -> Result<(), ConfigError> {
    match file {
        Some(file) if !expand_home(file).is_absolute() => Err(ConfigError::Invalid(format!(
            "{section}.identity_file must be an absolute path (or start with ~/), got {}",
            file.display()
        ))),
        _ => Ok(()),
    }
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
    /// Start a stdio server on its first call instead of at boot, and stop
    /// it after `idle_secs` without calls, for servers that are rarely used
    #[serde(default)]
    pub lazy: bool,
    /// Seconds a `lazy` server may go without calls before it is stopped
    #[serde(default = "default_idle_secs")]
    pub idle_secs: u64,
    /// Endpoint of a Streamable HTTP server; may hold `{{ op://... }}`
    /// references for a URL that carries a key, and is then never shown
    /// resolved
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
    /// Id of a client registered ahead of time, for authorization servers
    /// without dynamic client registration, such as Google's
    #[serde(default)]
    pub client_id: Option<String>,
    /// Secret of the `client_id` client; may hold `{{ op://... }}`
    /// references, read at login and stored with the tokens
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Extra query parameters for the authorization URL, such as Google's
    /// `access_type = "offline"`, without which it issues no refresh token
    #[serde(default)]
    pub authorization_params: BTreeMap<String, String>,
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
    /// A server the daemon serves itself instead of `command` or `url`
    #[serde(default)]
    pub builtin: Option<Builtin>,
}

/// A server served inside the daemon, which holds what it needs: the
/// 1Password reader and the Mac's screen
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Builtin {
    /// Types a `[logins]` username or password into the focused field of a
    /// page on the login's sites
    Logins,
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
        /// Endpoint URL as configured, which may hold `{{ op://... }}`
        /// references; read them with `OnePassword::resolve_url`
        url: &'a str,
    },
    /// Serve it inside the daemon
    Builtin(Builtin),
}

impl ServerConfig {
    /// The transport this server uses; validation guarantees exactly one
    pub fn transport(&self) -> Option<Transport<'_>> {
        match (&self.command, &self.url, self.builtin) {
            (Some(command), None, None) => Some(Transport::Stdio { command }),
            (None, Some(url), None) => Some(Transport::Http { url }),
            (None, None, Some(builtin)) => Some(Transport::Builtin(builtin)),
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
        for (table, values) in [("headers", &self.headers), ("env", &self.env)] {
            for (key, value) in values {
                crate::secrets::check(value).map_err(|error| {
                    ConfigError::Invalid(format!("servers.{name}.{table}.{key}: {error}"))
                })?;
            }
        }
        if let Some(secret) = &self.client_secret {
            crate::secrets::check(secret).map_err(|error| {
                ConfigError::Invalid(format!("servers.{name}.client_secret: {error}"))
            })?;
        }
        if let Some(url) = &self.url {
            crate::secrets::UrlTemplate::parse(url)
                .map_err(|error| ConfigError::Invalid(format!("servers.{name}.url: {error}")))?;
        }

        if self.builtin.is_some() {
            return self.validate_builtin(name);
        }

        match (&self.command, &self.url) {
            (Some(_), Some(_)) => Err(ConfigError::Invalid(format!(
                "servers.{name}: set either `command` or `url`, not both"
            ))),
            (None, None) => Err(ConfigError::Invalid(format!(
                "servers.{name}: one of `command`, `url` or `builtin` is required"
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
            (None, Some(_)) if self.lazy => Err(ConfigError::Invalid(format!(
                "servers.{name}: `lazy` only applies to `command` servers"
            ))),
            _ if self.idle_secs == 0 => Err(ConfigError::Invalid(format!(
                "servers.{name}: `idle_secs` must be positive"
            ))),
            _ if !self.oauth
                && (!self.scopes.is_empty()
                    || self.client_name.is_some()
                    || self.client_id.is_some()
                    || self.client_secret.is_some()
                    || !self.authorization_params.is_empty()) =>
            {
                Err(ConfigError::Invalid(format!(
                    "servers.{name}: `scopes`, `client_name`, `client_id`, `client_secret` and `authorization_params` need `oauth = true`"
                )))
            }
            _ if self.client_secret.is_some() && self.client_id.is_none() => Err(
                ConfigError::Invalid(format!("servers.{name}: `client_secret` needs `client_id`")),
            ),
            // the name is only sent when registering, which a known id skips
            _ if self.client_name.is_some() && self.client_id.is_some() => {
                Err(ConfigError::Invalid(format!(
                    "servers.{name}: `client_name` only applies without `client_id`"
                )))
            }
            _ if self
                .authorization_params
                .keys()
                .any(|key| RESERVED_AUTHORIZATION_PARAMS.contains(&key.as_str())) =>
            {
                Err(ConfigError::Invalid(format!(
                    "servers.{name}: `authorization_params` cannot set {}, which the OAuth flow sets itself",
                    RESERVED_AUTHORIZATION_PARAMS.join(", ")
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

    /// A builtin runs in the daemon, so nothing about starting or reaching
    /// a process applies
    fn validate_builtin(&self, name: &str) -> Result<(), ConfigError> {
        if self.command.is_some() || self.url.is_some() {
            return Err(ConfigError::Invalid(format!(
                "servers.{name}: set one of `command`, `url` or `builtin`"
            )));
        }
        let process = !self.args.is_empty()
            || !self.env.is_empty()
            || self.cwd.is_some()
            || self.lazy
            || !self.headers.is_empty()
            || self.oauth
            || !self.scopes.is_empty()
            || self.client_name.is_some()
            || self.client_id.is_some()
            || self.client_secret.is_some()
            || !self.authorization_params.is_empty()
            || !self.setup.is_empty()
            || self.warm.is_some();
        if process {
            return Err(ConfigError::Invalid(format!(
                "servers.{name}: a `builtin` server takes no `args`, `env`, `cwd`, `lazy`, \
                 `headers`, OAuth settings, `setup` or `warm`"
            )));
        }

        match self.builtin {
            Some(Builtin::Logins) => self.validate_logins(name),
            None => Ok(()),
        }
    }

    /// Every fill must ask, once per call: a default `allow`, or a session
    /// grant, would let an agent type a password as often as it likes
    fn validate_logins(&self, name: &str) -> Result<(), ConfigError> {
        if let Some(tool) = self
            .tools
            .keys()
            .find(|tool| !LOGINS_TOOLS.contains(&tool.as_str()))
        {
            return Err(ConfigError::Invalid(format!(
                "servers.{name}.tools.{tool}: the logins server has only {}",
                LOGINS_TOOLS.join(" and ")
            )));
        }
        if self.policy_for("fill") != Policy::Ask || self.grant_for("fill") != GrantMode::PerCall {
            return Err(ConfigError::Invalid(format!(
                "servers.{name}: the logins server's `fill` must ask on every call; set \
                 `policy = \"ask\"` and `tools.fill.grant = \"per_call\"`"
            )));
        }

        Ok(())
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
        assert!(parse("[servers.a]\nurl = \"not a url\"").is_err());
        // a url that is one reference is refused, with or without oauth
        for oauth in ["", "\noauth = true"] {
            let refused = parse(&format!(
                "[servers.a]\nurl = \"{{{{ op://Dev/zoho/credential }}}}\"{oauth}"
            ));
            assert!(
                matches!(&refused, Err(ConfigError::Invalid(message)) if message.contains("https://host/mcp/{{ op://Vault/Item/key }}")),
                "{refused:?}"
            );
        }
        assert!(parse("[servers.a]\nurl = \"{{ op://Dev/zoho\"").is_err());
        assert!(
            parse("[servers.a]\nurl = \"https://h/{{ op://Dev/zoho/key }}/m\"\noauth = true")
                .is_ok()
        );
        assert!(parse("admin_listen = \"0.0.0.0:7682\"").is_err());
        for host in [
            "https://{{ op://Dev/zoho/key }}.example.com/m",
            "https:///{{ op://Dev/zoho/key }}/m/{{ op://Dev/zoho/key }}",
        ] {
            assert!(
                parse(&format!("[servers.a]\nurl = \"{host}\"")).is_err(),
                "{host}"
            );
        }
        assert!(
            parse("[servers.a]\nurl = \"https://h.com?key={{ op://Dev/zoho/key }}\"\noauth = true")
                .is_ok()
        );
        assert!(parse("[servers.a]\ncommand = \"x\"\noauth = true").is_err());
        assert!(parse("[servers.a]\nurl = \"https://y\"\nscopes = [\"s\"]").is_err());
        assert!(parse("[servers.a]\nurl = \"https://y\"\nclient_id = \"c\"").is_err());
        assert!(
            parse("[servers.a]\nurl = \"https://y\"\noauth = true\nclient_secret = \"s\"").is_err()
        );
        assert!(
            parse("[servers.a]\nurl = \"https://y\"\noauth = true\nclient_id = \"c\"\nclient_name = \"n\"")
                .is_err()
        );
        assert!(
            parse("[servers.a]\nurl = \"https://y\"\noauth = true\nauthorization_params = { state = \"x\" }")
                .is_err()
        );
        assert!(
            parse("[servers.a]\nurl = \"https://y\"\noauth = true\nheaders = { Authorization = \"Bearer abcdef\" }")
                .is_err()
        );
    }

    #[test]
    fn companion_settings_are_checked_when_the_config_loads() {
        // ids must be points on the curve, so a made-up hex string will not do
        let id = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let peer = |name: &str| format!("{{ name = \"{name}\", id = \"{id}\" }}");
        let secrets = |entries: &[String], extra: &str| {
            parse(&format!(
                "[secrets]\n{extra}\ncompanions = [{}]",
                entries.join(", ")
            ))
        };

        assert!(secrets(&[peer("mba")], "").is_ok());
        assert!(secrets(&[peer("mba"), peer("mba")], "").is_err());
        assert!(secrets(&[peer(" ")], "").is_err());
        // with discovery off a companion can only be reached at known addresses
        assert!(secrets(&[peer("mba")], "discovery = false").is_err());
        assert!(parse("[secrets]\ncompanions = [{ name = \"mba\", id = \"not-an-id\" }]").is_err());

        let companion = |allow: &str| {
            parse(&format!(
                "[companion]\ngateway = \"{id}\"\nallow = [{allow}]"
            ))
        };
        assert!(companion("\"op://Dev/Context7/credential\"").is_ok());
        assert!(companion("\"op://Dev/Context7\"").is_err());
        assert!(companion("\"sk-live-123\"").is_err());

        // names and references from a ticket reach the companion's Touch ID
        // prompt, so none may pass for the prompt's own wording
        let named = |name: &str| {
            parse(&format!(
                "[companion]\ngateway = \"{id}\"\ngateway_name = \"{name}\""
            ))
        };
        assert!(named("Praveens-Mac-mini").is_ok());
        assert!(named("main\\napprove to continue").is_err());
        assert!(named("main\\u202e").is_err());
        assert!(named("").is_err());
        assert!(named(&"m".repeat(64)).is_err());
        assert!(secrets(&[peer("mba\\nok")], "").is_err());
        assert!(companion("\"op://Dev/Context7\\u202e/credential\"").is_err());
        assert!(companion(&format!("\"op://Dev/{}/credential\"", "x".repeat(300))).is_err());
    }

    #[test]
    fn logins_take_plain_hosts_and_bare_references() {
        let login = |body: &str| {
            parse(&format!(
                "[servers.logins]\nbuiltin = \"logins\"\npolicy = \"ask\"\n\
                 tools.fill.grant = \"per_call\"\n\n[logins.github]\n{body}"
            ))
        };
        let password = "password = \"op://Personal/GitHub/password\"";

        assert!(
            login(&format!(
                "sites = [\"github.com\", \"*.github.io\"]\n{password}"
            ))
            .is_ok()
        );
        for site in [
            "https://github.com",
            "github.com/login",
            "github.com:443",
            "GitHub.com",
            "com",
            ".github.com",
            "*.com",
            "*github.com",
            "*.*.github.com",
        ] {
            assert!(
                login(&format!("sites = [\"{site}\"]\n{password}")).is_err(),
                "{site}"
            );
        }
        assert!(login(&format!("sites = []\n{password}")).is_err());
        assert!(login("sites = [\"github.com\"]").is_err());
        assert!(
            login("sites = [\"github.com\"]\npassword = \"{{ op://Personal/GitHub/password }}\"")
                .is_err()
        );
        assert!(parse("[servers.logins]\nbuiltin = \"logins\"\ncommand = \"x\"").is_err());
        assert!(parse("[servers.logins]\nbuiltin = \"logins\"\nlazy = true").is_err());
        // a fill must ask on every call
        assert!(parse("[servers.logins]\nbuiltin = \"logins\"").is_err());
        assert!(parse("[servers.logins]\nbuiltin = \"logins\"\npolicy = \"ask\"").is_err());
        assert!(
            parse(
                "[servers.logins]\nbuiltin = \"logins\"\npolicy = \"ask\"\n\
                 tools.fill.grant = \"per_call\"\ntools.fil.grant = \"per_call\""
            )
            .is_err()
        );
    }
}
