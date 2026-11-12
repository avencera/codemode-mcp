//! An agent-browser session's active page, as the `browser` builtin reads and
//! fills it over CDP
//!
//! agent-browser is asked only where a session's browser is (`get cdp-url`,
//! which never launches one), which tab is active (`tab list`), which
//! sessions it has (`session list`), and, for the owner's New session on the
//! phone, to start one (`open`); every
//! value goes straight to the page over CDP, so none passes through an
//! agent-browser command, its argv or the activity it streams to its
//! dashboard. The focused element is read in an isolated world, where the
//! page's own scripts cannot replace the DOM getters the check relies on

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use companion_wire::{
    mobile::LoginField,
    takeover::{Key, RunningSession},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::cdp::{Browser, CdpError, Session};
use crate::{companion::SessionList, logins::site_of};

/// How long an agent-browser lookup may take
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

/// How long starting a session may take, launching its browser included
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// How long closing a session may take: agent-browser asks the browser to
/// close, which takes up to 30 seconds to fail when its link to the browser
/// is gone, then waits 5 more before killing it
const CLOSE_TIMEOUT: Duration = Duration::from_secs(45);

/// How long listing the sessions may wait on agent-browser for the list,
/// then for each session; a session that takes longer is left out, so the
/// phone, which waits 30 seconds, still gets the rest
const LIST_TIMEOUT: Duration = Duration::from_secs(5);
const LIST_SESSION_TIMEOUT: Duration = Duration::from_secs(8);

/// agent-browser's answer to `get cdp-url` for a session without a browser,
/// one never launched or one that closed
const NOT_LAUNCHED: &str = "Browser not launched";

/// A file every Chrome profile directory holds, which tells a saved session
/// from agent-browser's other directories beside it
const PROFILE_MARKER: &str = "Local State";

/// Most frames a focused element may sit in, nested
const MAX_FRAME_DEPTH: usize = 8;

/// Name of the isolated world the checks run in
const WORLD: &str = "codemode-mcp";

/// Places agent-browser is installed when the daemon's `PATH`, which launchd
/// keeps short, does not have it
const INSTALLED: [&str; 3] = [
    "/opt/homebrew/bin/agent-browser",
    "/usr/local/bin/agent-browser",
    ".local/bin/agent-browser",
];

/// Why the page could not be read or filled; never holds a value
#[derive(Debug, Clone, thiserror::Error)]
pub enum PageError {
    /// The session or its browser could not be found
    #[error("{0}")]
    NoBrowser(String),
    /// CDP failed
    #[error(transparent)]
    Cdp(#[from] CdpError),
    /// The page or field is not one this value may go into
    #[error("{0}")]
    Refused(String),
}

/// An agent-browser session name: letters, digits, `-` and `_`, so it can
/// never pass as a flag
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionName(String);

impl SessionName {
    /// Checks `name`
    pub fn parse(name: &str) -> Result<Self, PageError> {
        let name = name.trim();
        let valid = (1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if !valid {
            return Err(PageError::Refused(format!(
                "`{}` is not an agent-browser session name (letters, digits, - and _)",
                crate::prompt::one_line(name, 64)
            )));
        }

        Ok(Self(name.to_owned()))
    }

    /// The name
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The agent-browser program that knows where each session's browser is
#[derive(Debug, Clone)]
pub struct AgentBrowser {
    program: PathBuf,
    /// Where sessions keep their Chrome profiles, one directory per session
    /// named after it, such as `~/.agent-browser/github`
    profiles: Option<PathBuf>,
    /// Where a removed session's profile goes, such as `~/.Trash`
    trash: Option<PathBuf>,
    /// One start at a time, so a second start of a session sees the browser
    /// the first launched instead of launching over it
    starts: Arc<tokio::sync::Mutex<()>>,
}

/// What agent-browser says of a session's browser
enum Launch {
    /// It runs, taking CDP at this loopback address
    Running(String),
    /// It is not running: never launched, or closed since
    NotLaunched,
}

/// What a listing found of one session
enum Listed {
    Running(RunningSession),
    NotLaunched,
    /// agent-browser did not say in time or said something else, so the
    /// session is neither listed nor offered to start, which could relaunch
    /// a browser that runs
    Unknown(String),
}

#[derive(Deserialize)]
struct CdpUrlReply {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<CdpUrlData>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct CdpUrlData {
    #[serde(rename = "cdpUrl")]
    cdp_url: String,
}

#[derive(Deserialize)]
struct SessionsReply {
    #[serde(default)]
    data: Option<SessionsData>,
}

#[derive(Deserialize)]
struct SessionsData {
    #[serde(default)]
    sessions: Vec<String>,
}

#[derive(Deserialize)]
struct TabList {
    #[serde(default)]
    data: Option<TabData>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Deserialize)]
struct TabData {
    #[serde(default)]
    tabs: Vec<Tab>,
}

#[derive(Deserialize)]
struct Tab {
    #[serde(default)]
    active: bool,
    #[serde(rename = "targetId")]
    target_id: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    title: Option<String>,
}

impl AgentBrowser {
    /// agent-browser from the daemon's `PATH`, or where Homebrew or npm put
    /// it; its sessions keep no profiles until [`AgentBrowser::with_profiles`]
    /// says where
    pub fn find(home: Option<&Path>) -> Self {
        let on_path = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join("agent-browser"))
                .find(|candidate| candidate.is_file())
        });
        let installed = || {
            INSTALLED
                .iter()
                .map(|place| match (place.starts_with('/'), home) {
                    (true, _) => PathBuf::from(place),
                    (false, Some(home)) => home.join(place),
                    (false, None) => PathBuf::from(place),
                })
                .find(|candidate| candidate.is_file())
        };

        Self {
            program: on_path
                .or_else(installed)
                .unwrap_or_else(|| PathBuf::from("agent-browser")),
            profiles: None,
            trash: None,
            starts: Arc::default(),
        }
    }

    /// A specific agent-browser binary
    pub fn at(program: PathBuf) -> Self {
        Self {
            program,
            profiles: None,
            trash: None,
            starts: Arc::default(),
        }
    }

    /// Keeps each session's profile in `profiles`, one directory per
    /// session, and moves a removed one to `trash`
    #[must_use]
    pub fn with_profiles(mut self, profiles: PathBuf, trash: PathBuf) -> Self {
        self.profiles = Some(profiles);
        self.trash = Some(trash);
        self
    }

    async fn output(
        &self,
        args: &[&OsStr],
        timeout: Duration,
    ) -> Result<std::process::Output, PageError> {
        tokio::time::timeout(
            timeout,
            tokio::process::Command::new(&self.program)
                .args(args)
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| PageError::NoBrowser("agent-browser did not answer in time".to_owned()))?
        .map_err(|error| {
            PageError::NoBrowser(format!("could not run {}: {error}", self.program.display()))
        })
    }

    async fn run(&self, session: &SessionName, args: &[&str]) -> Result<Vec<u8>, PageError> {
        let mut all = vec![OsStr::new("--session"), OsStr::new(session.as_str())];
        all.extend(args.iter().map(OsStr::new));
        let output = self.output(&all, LOOKUP_TIMEOUT).await?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let detail = crate::prompt::one_line(detail.trim(), 200);

            return Err(PageError::NoBrowser(format!(
                "agent-browser session `{session}` has no running browser ({detail}); start it \
                 with `agent-browser --session {session} open <url>` first"
            )));
        }

        Ok(output.stdout)
    }

    /// Connects to `session`'s browser and attaches to its active tab;
    /// never starts a browser
    pub async fn open(&self, session: &SessionName) -> Result<Page, PageError> {
        let url = self.devtools(session).await?;
        let target = self.active_tab(session).await?.target_id;

        let browser = Browser::connect(&url).await?;
        let session = browser.attach(&target).await?;

        Ok(Page { session })
    }

    /// Where `session`'s browser takes CDP; an error when it has none
    /// running
    async fn devtools(&self, session: &SessionName) -> Result<String, PageError> {
        match self.launch(session, LOOKUP_TIMEOUT).await? {
            Launch::Running(url) => Ok(url),
            Launch::NotLaunched => Err(PageError::NoBrowser(format!(
                "agent-browser session `{session}` has no running browser; start it with \
                 `agent-browser --session {session} open <url>` first"
            ))),
        }
    }

    /// Whether `session`'s browser runs, from `get cdp-url`, which never
    /// launches one. Anything but a plain answer is an error, so a caller
    /// never takes a slow or odd answer for a browser that is not running
    async fn launch(&self, session: &SessionName, timeout: Duration) -> Result<Launch, PageError> {
        let args = ["--session", session.as_str(), "--json", "get", "cdp-url"].map(OsStr::new);
        let output = self.output(&args, timeout).await?;
        let reply: CdpUrlReply = serde_json::from_slice(&output.stdout).map_err(|_| {
            let detail = String::from_utf8_lossy(&output.stderr);
            PageError::NoBrowser(format!(
                "agent-browser did not say whether `{session}` runs ({})",
                crate::prompt::one_line(detail.trim(), 200)
            ))
        })?;

        match (reply.success, reply.data, reply.error) {
            (true, Some(data), _) => {
                // only a browser on this Mac; agent-browser can also point at
                // a remote one, whose page this daemon has no business filling
                if !is_loopback_devtools(&data.cdp_url) {
                    return Err(PageError::NoBrowser(format!(
                        "agent-browser session `{session}` is not a browser on this Mac"
                    )));
                }

                Ok(Launch::Running(data.cdp_url))
            }
            (false, _, Some(error)) if error == NOT_LAUNCHED => Ok(Launch::NotLaunched),
            (_, _, error) => Err(PageError::NoBrowser(format!(
                "agent-browser did not say whether `{session}` runs ({})",
                crate::prompt::one_line(error.as_deref().unwrap_or("no answer"), 200)
            ))),
        }
    }

    /// The sessions with a browser running and the saved profiles of the
    /// others, each by name
    pub async fn sessions(&self) -> Result<SessionList, PageError> {
        let listed = self
            .output(
                &[
                    OsStr::new("--json"),
                    OsStr::new("session"),
                    OsStr::new("list"),
                ],
                LIST_TIMEOUT,
            )
            .await?;
        if !listed.status.success() {
            return Err(PageError::NoBrowser(
                "agent-browser could not list its sessions".to_owned(),
            ));
        }
        let listed: SessionsReply = serde_json::from_slice(&listed.stdout).map_err(|_| {
            PageError::NoBrowser("agent-browser's session list could not be read".to_owned())
        })?;
        let names = listed
            .data
            .map(|data| data.sessions)
            .unwrap_or_default()
            .iter()
            .filter_map(|name| SessionName::parse(name).ok())
            .collect::<Vec<_>>();

        // a listed session may have no browser, such as one whose browser
        // closed; it shows as saved when it has a profile
        let listed = futures_util::future::join_all(names.iter().map(|session| async move {
            tokio::time::timeout(LIST_SESSION_TIMEOUT, self.listed(session))
                .await
                .unwrap_or_else(|_| Listed::Unknown(session.to_string()))
        }))
        .await;
        let mut running = Vec::new();
        let mut unknown = Vec::new();
        for session in listed {
            match session {
                Listed::Running(session) => running.push(session),
                Listed::NotLaunched => {}
                Listed::Unknown(name) => unknown.push(name),
            }
        }
        running.sort_by(|left, right| left.name.cmp(&right.name));
        let saved = self
            .saved()
            .await
            .into_iter()
            .filter(|name| running.iter().all(|session| session.name != *name))
            .filter(|name| !unknown.contains(name))
            .collect();

        Ok(SessionList { running, saved })
    }

    /// Whether `session`'s browser runs, and its active tab when it does
    async fn listed(&self, session: &SessionName) -> Listed {
        let name = session.to_string();
        match self.launch(session, LIST_TIMEOUT).await {
            Ok(Launch::Running(_)) => {}
            Ok(Launch::NotLaunched) => return Listed::NotLaunched,
            Err(_) => return Listed::Unknown(name),
        }
        // the browser runs, so listing its tabs launches nothing
        let tab = self.active_tab(session).await.ok();
        let (url, title) = tab.map(|tab| (tab.url, tab.title)).unwrap_or_default();

        Listed::Running(RunningSession {
            name,
            url: url.filter(|url| !url.is_empty()),
            title: title.filter(|title| !title.is_empty()),
        })
    }

    /// The names of the sessions with a saved profile, sorted
    async fn saved(&self) -> Vec<String> {
        let Some(profiles) = &self.profiles else {
            return Vec::new();
        };
        let Ok(mut entries) = tokio::fs::read_dir(profiles).await else {
            return Vec::new();
        };
        let mut saved = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let profile = tokio::fs::try_exists(entry.path().join(PROFILE_MARKER)).await;
            if profile.unwrap_or(false) && SessionName::parse(&name).is_ok() {
                saved.push(name);
            }
        }
        saved.sort();

        saved
    }

    /// Starts `session` at `url`, an `https` address: loads it in the
    /// session's browser when one runs, or launches the session's browser
    /// with its saved profile, so a site it signed in to before still is
    pub async fn start(&self, session: &SessionName, url: &str) -> Result<(), PageError> {
        let address = reqwest::Url::parse(url)
            .ok()
            .filter(|address| address.scheme() == "https" && address.host_str().is_some())
            .ok_or_else(|| {
                PageError::Refused("a session starts only at an https address".to_owned())
            })?;
        let _turn = self.starts.lock().await;
        // an error here refuses the start: a browser that did not answer may
        // be running, and launch options would relaunch it
        let launch = self.launch(session, LOOKUP_TIMEOUT).await?;

        let mut args: Vec<OsString> = vec!["--session".into(), session.as_str().into()];
        // launch options only for a browser that is not running: given them,
        // agent-browser relaunches a running one, and its page is lost
        if matches!(launch, Launch::NotLaunched) {
            if let Some(profiles) = &self.profiles {
                let profile = profiles.join(session.as_str());
                usable_profile(&profile).await?;
                args.push("--profile".into());
                args.push(profile.into());
            }
            args.extend(["--engine".into(), "chrome".into()]);
        }
        args.extend(["open".into(), address.as_str().into()]);
        let args = args.iter().map(OsString::as_os_str).collect::<Vec<_>>();
        let output = self.output(&args, START_TIMEOUT).await?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);

            return Err(PageError::NoBrowser(format!(
                "agent-browser could not start `{session}` ({})",
                crate::prompt::one_line(detail.trim(), 200)
            )));
        }

        Ok(())
    }

    /// Quits `session`'s browser; its saved profile stays, so starting the
    /// session again finds its sign-ins
    pub async fn close(&self, session: &SessionName) -> Result<(), PageError> {
        // after any start under way, so a close cannot land between its check
        // and its launch
        let _turn = self.starts.lock().await;
        let args = ["--session", session.as_str(), "--json", "close"].map(OsStr::new);
        let output = self.output(&args, CLOSE_TIMEOUT).await?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);

            return Err(PageError::NoBrowser(format!(
                "agent-browser could not close `{session}` ({})",
                crate::prompt::one_line(detail.trim(), 200)
            )));
        }

        Ok(())
    }

    /// Moves `session`'s saved profile to the trash, under a name no other
    /// removal there has, so its sign-ins can still be put back by hand.
    /// Refused while its browser runs, or when agent-browser does not say
    pub async fn remove(&self, session: &SessionName) -> Result<(), PageError> {
        let (Some(profiles), Some(trash)) = (&self.profiles, &self.trash) else {
            return Err(PageError::Refused(
                "this gateway keeps no session profiles".to_owned(),
            ));
        };
        // no start may launch the browser on the profile while it moves
        let _turn = self.starts.lock().await;
        if let Launch::Running(_) = self.launch(session, LOOKUP_TIMEOUT).await? {
            return Err(PageError::Refused(format!(
                "`{session}` is running; close it first"
            )));
        }
        let profile = profiles.join(session.as_str());
        let marked = tokio::fs::try_exists(profile.join(PROFILE_MARKER)).await;
        if !marked.unwrap_or(false) {
            return Err(PageError::Refused(format!(
                "`{session}` has no saved browser profile"
            )));
        }

        tokio::fs::create_dir_all(trash).await.map_err(|error| {
            PageError::Refused(format!("could not make {}: {error}", trash.display()))
        })?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let moved = trash.join(format!("agent-browser {session} {stamp}"));
        tokio::fs::rename(&profile, &moved).await.map_err(|error| {
            PageError::Refused(format!(
                "could not move `{session}` to {}: {error}",
                trash.display()
            ))
        })
    }

    /// `session`'s active tab
    async fn active_tab(&self, session: &SessionName) -> Result<Tab, PageError> {
        let tabs = self.run(session, &["--json", "tab", "list"]).await?;
        let tabs: TabList = serde_json::from_slice(&tabs).map_err(|_| {
            PageError::NoBrowser("agent-browser's tab list could not be read".to_owned())
        })?;
        if let Some(error) = tabs.error.filter(|error| !error.is_null()) {
            return Err(PageError::NoBrowser(format!(
                "agent-browser could not list the tabs of `{session}`: {}",
                crate::prompt::one_line(&error.to_string(), 200)
            )));
        }
        tabs.data
            .map(|data| data.tabs)
            .unwrap_or_default()
            .into_iter()
            .find(|tab| tab.active)
            .ok_or_else(|| {
                PageError::NoBrowser(format!(
                    "agent-browser session `{session}` has no active tab"
                ))
            })
    }
}

/// Refuses `profile` when it is a directory with files that is not a
/// Chrome profile, such as agent-browser's own `sessions` or `tmp` beside
/// the profiles, which Chrome would otherwise fill in
async fn usable_profile(profile: &Path) -> Result<(), PageError> {
    let Ok(mut entries) = tokio::fs::read_dir(profile).await else {
        return Ok(());
    };
    let empty = matches!(entries.next_entry().await, Ok(None));
    let marked = tokio::fs::try_exists(profile.join(PROFILE_MARKER))
        .await
        .unwrap_or(false);
    if empty || marked {
        return Ok(());
    }

    Err(PageError::Refused(format!(
        "{} holds files that are not a browser profile; pick another name",
        profile.display()
    )))
}

/// Whether `url` is a DevTools endpoint on this Mac: `ws` to a loopback
/// host with a port and no user info, compared parsed rather than by prefix,
/// so `ws://127.0.0.1:1@elsewhere/` is not taken for one
fn is_loopback_devtools(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };

    url.scheme() == "ws"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_some()
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
}

/// What the focused element is
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Element {
    /// Lowercase tag name, such as `input`
    pub tag: String,
    /// An input's lowercase `type`, such as `password`; empty otherwise
    #[serde(rename = "type")]
    pub input_type: String,
    /// The `autocomplete` attribute, lowercase
    pub autocomplete: String,
    /// The `inputmode` attribute, lowercase
    pub inputmode: String,
    /// The `name`, lowercase
    pub name: String,
    /// The `id`, lowercase
    pub id: String,
    /// `maxLength`, or -1 when unset
    pub max_length: i64,
    /// Whether it takes text
    pub editable: bool,
}

impl Element {
    fn names(&self) -> [&str; 2] {
        [&self.name, &self.id]
    }

    fn hinted(&self, words: &[&str]) -> bool {
        self.names()
            .iter()
            .any(|name| words.iter().any(|word| name.contains(word)))
    }

    fn text_input(&self) -> bool {
        self.tag == "input"
            && matches!(
                self.input_type.as_str(),
                "text" | "email" | "tel" | "number" | ""
            )
    }

    /// Whether it hides its text
    pub fn secure(&self) -> bool {
        self.tag == "input" && self.input_type == "password"
    }

    /// Whether it asks for digits
    pub fn numeric(&self) -> bool {
        matches!(self.inputmode.as_str(), "numeric" | "decimal" | "tel")
            || matches!(self.input_type.as_str(), "number" | "tel")
    }

    /// The login field it looks like, if any: a password field; a field for
    /// a one-time code; or a username or email field
    pub fn login_field(&self) -> Option<LoginField> {
        if !self.editable {
            return None;
        }
        if self.secure() {
            return Some(LoginField::Password);
        }
        if !self.text_input() {
            return None;
        }
        let tokens: Vec<&str> = self.autocomplete.split_whitespace().collect();
        if tokens.contains(&"one-time-code") {
            return Some(LoginField::Code);
        }
        if tokens
            .iter()
            .any(|token| matches!(*token, "username" | "email"))
            || self.input_type == "email"
        {
            return Some(LoginField::Username);
        }
        // a numeric field of code length, or one named for a code
        let code_length = (4..=10).contains(&self.max_length);
        let code_named = self.hinted(&["otp", "totp", "2fa", "mfa", "code", "token"]);
        if code_named && (self.numeric() || code_length) {
            return Some(LoginField::Code);
        }
        if self.hinted(&["user", "login", "email", "account", "identifier"]) {
            return Some(LoginField::Username);
        }

        None
    }
}

/// The element with focus and where it is
#[derive(Debug, Clone)]
pub struct Focused {
    /// What it is
    pub element: Element,
    /// Origin of the frame holding it
    pub origin: String,
    /// Origins of every frame from the page down to it, the page excluded
    pub frames: Vec<String>,
    /// The element in the isolated world it was read in, valid until the
    /// page changes
    object: String,
}

/// The page and its focused element
#[derive(Debug, Clone)]
pub struct PageState {
    /// The top-level page's address
    pub url: String,
    /// Its title
    pub title: String,
    /// The focused element, when one takes focus
    pub focus: Option<Focused>,
}

impl PageState {
    /// The top-level page's host, when it is `https` on the default port
    fn https_host(&self) -> Result<String, PageError> {
        let refuse = |reason: String| Err(PageError::Refused(reason));
        let Ok(url) = reqwest::Url::parse(&self.url) else {
            return refuse("the page's address could not be read".to_owned());
        };
        if url.scheme() != "https" {
            return refuse(format!("the page is not https ({}:)", url.scheme()));
        }
        if let Some(port) = url.port() {
            return refuse(format!("the page is on port {port}, not 443"));
        }
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return refuse("the page has no host".to_owned());
        };
        if host.ends_with('.') {
            return refuse(format!("the page's host {host} ends with a dot"));
        }

        Ok(host)
    }

    /// Whether `field` may be filled here for `site`: the page is `https` on
    /// that site, the focused element is that kind of field, and no frame
    /// around it is on another site. Answers the page's host
    pub fn check(&self, field: LoginField, site: &str) -> Result<String, PageError> {
        let refuse = |reason: String| Err(PageError::Refused(reason));
        let host = self.https_host()?;
        let page_site = site_of(&host);
        if page_site != site {
            return refuse(format!(
                "the page is on {host}, not on {site}; navigate there first"
            ));
        }
        let Some(focused) = &self.focus else {
            return refuse(format!(
                "nothing on the page has keyboard focus; click the {} field first",
                field.label()
            ));
        };
        for origin in &focused.frames {
            let same_site = reqwest::Url::parse(origin)
                .ok()
                .filter(|url| url.scheme() == "https" && url.port().is_none())
                .and_then(|url| url.host_str().map(site_of))
                .is_some_and(|frame_site| frame_site == page_site);
            if !same_site {
                return refuse(format!(
                    "the focused field is in a frame from {}, not {site}",
                    crate::prompt::one_line(origin, 120)
                ));
            }
        }

        match (field, focused.element.login_field()) {
            (wanted, Some(found)) if wanted == found => Ok(host),
            (LoginField::Password, _) => refuse(
                "the focused element is not a password field; click the password field first"
                    .to_owned(),
            ),
            (LoginField::Username, _) => refuse(
                "the focused element is not a username or email field; click it first".to_owned(),
            ),
            (LoginField::Code, _) => refuse(
                "the focused element is not a one-time code field (autocomplete=one-time-code, or \
                 a numeric code field); click it first"
                    .to_owned(),
            ),
        }
    }
}

/// Answers whether the element the function runs on has focus in its
/// document, and each frame around it that this world can see has focus in
/// its parent's
macro_rules! has_focus {
    () => {
        r#"
  let el = this;
  while (el) {
    if (el.ownerDocument.activeElement !== el) return false;
    let owner = null;
    try { owner = el.ownerDocument.defaultView.frameElement; } catch (e) {}
    el = owner;
  }
  return true;
"#
    };
}

/// Focuses and selects the checked element, then answers whether it has
/// focus
const FOCUS_AND_SELECT: &str = concat!(
    "function () {\n",
    "  if (typeof this.focus === 'function') this.focus();\n",
    "  if (typeof this.select === 'function') this.select();",
    has_focus!(),
    "}"
);

/// Answers whether the checked element still has focus
const STILL_FOCUSED: &str = concat!("function () {", has_focus!(), "}");

/// Finds the deepest focused element through same-origin frames; stops at a
/// frame it cannot enter and answers that frame's element
const WALK: &str = r#"(() => {
  let el = document.activeElement;
  while (el && (el.tagName === 'IFRAME' || el.tagName === 'FRAME')) {
    let doc = null;
    try { doc = el.contentDocument; } catch (e) {}
    if (!doc) return el;
    el = doc.activeElement;
  }
  if (!el || el === el.ownerDocument.body || el === el.ownerDocument.documentElement) return null;
  return el;
})()"#;

/// Describes the element it is called on, with the origins of the frames
/// around it that this world can see, innermost first
const DESCRIBE: &str = r#"function () {
  const el = this;
  const tag = el.tagName.toLowerCase();
  const attr = (name) => (el.getAttribute(name) || '').toLowerCase();
  const origins = [];
  let view = el.ownerDocument.defaultView;
  while (view) {
    origins.push(view.origin);
    let owner = null;
    try { owner = view.frameElement; } catch (e) {}
    if (!owner) break;
    view = owner.ownerDocument.defaultView;
  }
  return {
    tag,
    frame: tag === 'iframe' || tag === 'frame',
    type: tag === 'input' ? String(el.type || 'text').toLowerCase() : '',
    autocomplete: attr('autocomplete'),
    inputmode: attr('inputmode'),
    name: String(el.getAttribute('name') || '').toLowerCase(),
    id: String(el.id || '').toLowerCase(),
    maxLength: typeof el.maxLength === 'number' ? el.maxLength : -1,
    editable: !!(el.isContentEditable || ((tag === 'input' || tag === 'textarea') && !el.disabled && !el.readOnly)),
    origins,
  };
}"#;

#[derive(Deserialize)]
struct Described {
    frame: bool,
    origins: Vec<String>,
    #[serde(flatten)]
    element: Element,
}

/// An agent-browser session's active tab, attached over CDP
pub struct Page {
    session: Session,
}

impl Page {
    /// The CDP session of the page
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// The connection the page is on
    pub fn browser(&self) -> &Browser {
        self.session.browser()
    }

    /// Every frame's id and address
    async fn frames(&self) -> Result<(String, Vec<(String, String)>), PageError> {
        let tree = self.session.call("Page.getFrameTree", json!({})).await?;
        let root = &tree["frameTree"];
        let main = root["frame"]["id"].as_str().unwrap_or_default().to_owned();
        let mut frames = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let frame = &node["frame"];
            if let (Some(id), Some(url)) = (frame["id"].as_str(), frame["url"].as_str()) {
                let url = match frame["urlFragment"].as_str() {
                    Some(fragment) => format!("{url}{fragment}"),
                    None => url.to_owned(),
                };
                frames.push((id.to_owned(), url));
            }
            if let Some(children) = node["childFrames"].as_array() {
                stack.extend(children);
            }
        }

        Ok((main, frames))
    }

    async fn world(&self, frame: &str) -> Result<i64, PageError> {
        let world = self
            .session
            .call(
                "Page.createIsolatedWorld",
                json!({ "frameId": frame, "worldName": WORLD }),
            )
            .await?;

        world["executionContextId"]
            .as_i64()
            .ok_or_else(|| PageError::Refused("the page's frame could not be read".to_owned()))
    }

    /// The page's address, title and focused element, read now
    pub async fn state(&self) -> Result<PageState, PageError> {
        let (main, frames) = self.frames().await?;
        // the address and the focused element come from one world, which
        // belongs to one document: a navigation in between ends the world,
        // and the reads after it fail rather than mix two pages
        let top = self.world(&main).await?;
        let href = self
            .session
            .call(
                "Runtime.evaluate",
                json!({ "expression": "location.href", "contextId": top, "returnByValue": true }),
            )
            .await?;
        let url = href["result"]["value"]
            .as_str()
            .ok_or_else(|| PageError::Refused("the page's address could not be read".to_owned()))?
            .to_owned();
        let info = self
            .session
            .browser()
            .call(
                None,
                "Target.getTargetInfo",
                json!({ "targetId": self.session.target() }),
            )
            .await?;
        let title = info["targetInfo"]["title"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let mut frame = main;
        let mut world = Some(top);
        let mut outer: Vec<String> = Vec::new();
        for _ in 0..MAX_FRAME_DEPTH {
            let context = match world.take() {
                Some(context) => context,
                None => self.world(&frame).await?,
            };
            let found = self
                .session
                .call(
                    "Runtime.evaluate",
                    json!({ "expression": WALK, "contextId": context, "returnByValue": false }),
                )
                .await?;
            let Some(object) = found["result"]["objectId"].as_str().map(str::to_owned) else {
                return Ok(PageState {
                    url,
                    title,
                    focus: None,
                });
            };
            let described = self
                .session
                .call(
                    "Runtime.callFunctionOn",
                    json!({ "functionDeclaration": DESCRIBE, "objectId": object, "returnByValue": true }),
                )
                .await?;
            let described: Described = serde_json::from_value(described["result"]["value"].clone())
                .map_err(|_| {
                    PageError::Refused("the focused element could not be read".to_owned())
                })?;

            // the origins this world sees, outermost first, the page's own
            // dropped when this is the top frame
            let mut seen = described.origins.clone();
            seen.reverse();
            if outer.is_empty() && !seen.is_empty() {
                seen.remove(0);
            }
            outer.extend(seen);

            if !described.frame {
                let origin = described.origins.first().cloned().unwrap_or_default();

                return Ok(PageState {
                    url,
                    title,
                    focus: Some(Focused {
                        element: described.element,
                        origin,
                        frames: outer,
                        object,
                    }),
                });
            }

            // a frame this world cannot enter: its address comes from the
            // browser, and its own world is read next
            let node = self
                .session
                .call("DOM.describeNode", json!({ "objectId": object }))
                .await?;
            let inner = node["node"]["frameId"].as_str().map(str::to_owned);
            let Some((inner, inner_url)) = inner.and_then(|inner| {
                frames
                    .iter()
                    .find(|(id, _)| *id == inner)
                    .map(|(id, url)| (id.clone(), url.clone()))
            }) else {
                // out of process, so on another site
                return Ok(PageState {
                    url,
                    title,
                    focus: Some(Focused {
                        element: Element::default(),
                        origin: "another site".to_owned(),
                        frames: [outer, vec!["a frame from another site".to_owned()]].concat(),
                        object,
                    }),
                });
            };
            let origin = reqwest::Url::parse(&inner_url)
                .map(|url| url.origin().ascii_serialization())
                .unwrap_or(inner_url);
            outer.push(origin);
            frame = inner;
        }

        Err(PageError::Refused(
            "the focused element is nested in too many frames".to_owned(),
        ))
    }

    /// Replaces the text of the focused element `focused` with `text`, as if
    /// typed, then presses Return when `submit`
    pub async fn replace_text(
        &self,
        focused: &Focused,
        text: &str,
        submit: bool,
    ) -> Result<(), PageError> {
        // the checked element itself is focused and selected, so the insert
        // replaces what an agent may have typed and goes where was checked,
        // even if page script moved focus since the check
        if !self.holds_focus(focused, FOCUS_AND_SELECT).await? {
            return Err(PageError::Refused(
                "the checked field could not take focus, so nothing was filled".to_owned(),
            ));
        }
        self.insert_text(text).await?;
        if !self.holds_focus(focused, STILL_FOCUSED).await? {
            return Err(PageError::Refused(
                "focus left the checked field while it was filled, so the value may have gone \
                 into another field on the page; check the page, clear that field, and fill again"
                    .to_owned(),
            ));
        }
        if submit {
            self.press(Key::Enter).await?;
        }

        Ok(())
    }

    /// Runs `function` on the element `focused` checked; it answers whether
    /// that element has focus, through every same-origin frame around it
    async fn holds_focus(&self, focused: &Focused, function: &str) -> Result<bool, PageError> {
        let answer = self
            .session
            .call(
                "Runtime.callFunctionOn",
                json!({
                    "functionDeclaration": function,
                    "objectId": focused.object,
                    "returnByValue": true,
                }),
            )
            .await?;

        Ok(answer["result"]["value"].as_bool() == Some(true))
    }

    /// Inserts `text` at the caret of whatever has focus
    pub async fn insert_text(&self, text: &str) -> Result<(), PageError> {
        self.session
            .call("Input.insertText", json!({ "text": text }))
            .await?;

        Ok(())
    }

    /// Presses and releases `key`
    pub async fn press(&self, key: Key) -> Result<(), PageError> {
        let (name, code, text, modifiers) = key_event(key);
        let mut down = json!({
            "type": if text.is_empty() { "rawKeyDown" } else { "keyDown" },
            "key": name,
            "code": name,
            "windowsVirtualKeyCode": code,
            "nativeVirtualKeyCode": code,
            "modifiers": modifiers,
        });
        if !text.is_empty() {
            down["text"] = json!(text);
        }
        self.session.call("Input.dispatchKeyEvent", down).await?;
        self.session
            .call(
                "Input.dispatchKeyEvent",
                json!({
                    "type": "keyUp",
                    "key": name,
                    "code": name,
                    "windowsVirtualKeyCode": code,
                    "nativeVirtualKeyCode": code,
                    "modifiers": modifiers,
                }),
            )
            .await?;

        Ok(())
    }
}

/// `key`'s name, virtual key code, text and modifiers (8 is Shift), as
/// `Input.dispatchKeyEvent` takes them
fn key_event(key: Key) -> (&'static str, i64, &'static str, i64) {
    match key {
        Key::Enter => ("Enter", 13, "\r", 0),
        Key::Tab => ("Tab", 9, "", 0),
        Key::ShiftTab => ("Tab", 9, "", 8),
        Key::Backspace => ("Backspace", 8, "", 0),
        Key::Escape => ("Escape", 27, "", 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(input_type: &str, autocomplete: &str, name: &str) -> Element {
        Element {
            tag: "input".to_owned(),
            input_type: input_type.to_owned(),
            autocomplete: autocomplete.to_owned(),
            name: name.to_owned(),
            max_length: -1,
            editable: true,
            ..Element::default()
        }
    }

    fn page(url: &str, element: Element, frames: Vec<String>) -> PageState {
        PageState {
            url: url.to_owned(),
            title: String::new(),
            focus: Some(Focused {
                element,
                origin: String::new(),
                frames,
                object: String::new(),
            }),
        }
    }

    #[test]
    fn fields_are_told_apart_as_github_marks_them() {
        assert_eq!(
            input("text", "username", "login").login_field(),
            Some(LoginField::Username)
        );
        assert_eq!(
            input("password", "current-password", "password").login_field(),
            Some(LoginField::Password)
        );
        let mut code = input("text", "one-time-code", "app_otp");
        code.inputmode = "numeric".to_owned();
        assert_eq!(code.login_field(), Some(LoginField::Code));
        // a search box is none of them
        assert_eq!(input("search", "off", "q").login_field(), None);
        assert_eq!(input("text", "", "q").login_field(), None);
    }

    #[test]
    fn the_check_holds_the_page_to_its_site_and_the_field_to_its_kind() {
        let username = input("text", "username", "login");
        let github = "https://github.com/login";
        assert_eq!(
            page(github, username.clone(), vec![])
                .check(LoginField::Username, "github.com")
                .ok(),
            Some("github.com".to_owned())
        );

        let refused =
            |state: PageState, field: LoginField| state.check(field, "github.com").is_err();
        assert!(refused(
            page("http://github.com/login", username.clone(), vec![]),
            LoginField::Username
        ));
        assert!(refused(
            page("https://github.com.evil.example/", username.clone(), vec![]),
            LoginField::Username
        ));
        assert!(refused(
            page("https://github.com:8443/", username.clone(), vec![]),
            LoginField::Username
        ));
        assert!(refused(
            page(github, username.clone(), vec![]),
            LoginField::Password
        ));
        assert!(refused(
            page(
                github,
                username.clone(),
                vec!["https://evil.example".to_owned()]
            ),
            LoginField::Username
        ));
        // a frame on the same site is fine
        assert!(
            page(github, username, vec!["https://auth.github.com".to_owned()])
                .check(LoginField::Username, "github.com")
                .is_ok()
        );
    }
}

#[cfg(test)]
mod endpoint {
    use super::is_loopback_devtools;

    #[test]
    fn only_a_loopback_devtools_endpoint_is_taken() {
        assert!(is_loopback_devtools(
            "ws://127.0.0.1:9222/devtools/browser/abc"
        ));
        assert!(is_loopback_devtools(
            "ws://localhost:9222/devtools/browser/abc"
        ));
        assert!(is_loopback_devtools("ws://[::1]:9222/devtools/browser/abc"));
        assert!(!is_loopback_devtools(
            "ws://127.0.0.1:1@elsewhere.example/devtools"
        ));
        assert!(!is_loopback_devtools(
            "ws://localhost:9222.elsewhere.example/"
        ));
        assert!(!is_loopback_devtools("wss://127.0.0.1:9222/devtools"));
        assert!(!is_loopback_devtools("ws://127.0.0.1/devtools"));
        assert!(!is_loopback_devtools("ws://10.0.0.2:9222/devtools"));
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Reads the page of the agent-browser session named by
    /// `CODEMODE_BROWSER_SESSION`; run by hand with `--ignored`
    #[tokio::test]
    #[ignore = "needs a running agent-browser session"]
    async fn reads_a_live_session() -> Result<(), PageError> {
        let name =
            std::env::var("CODEMODE_BROWSER_SESSION").unwrap_or_else(|_| "github".to_owned());
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let page = AgentBrowser::find(home.as_deref())
            .open(&SessionName::parse(&name)?)
            .await?;
        let state = page.state().await?;
        eprintln!(
            "url={} title={} focus={:?}",
            state.url,
            state.title,
            state.focus.map(|focus| (focus.element, focus.frames))
        );

        Ok(())
    }

    /// Fills a dummy username into the focused username field of the
    /// session named by `CODEMODE_BROWSER_SESSION`, which must show
    /// `https://github.com/login` with that field focused, and checks the
    /// refusals around it; run by hand with `--ignored`
    #[tokio::test]
    #[ignore = "needs an agent-browser session on github.com/login"]
    async fn fills_a_live_username_field() -> Result<(), PageError> {
        const DUMMY: &str = "codemode-check";
        let name =
            std::env::var("CODEMODE_BROWSER_SESSION").unwrap_or_else(|_| "cmtest".to_owned());
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let page = AgentBrowser::find(home.as_deref())
            .open(&SessionName::parse(&name)?)
            .await?;
        let state = page.state().await?;

        assert_eq!(
            state.check(LoginField::Username, "github.com")?,
            "github.com"
        );
        assert!(state.check(LoginField::Password, "github.com").is_err());
        assert!(state.check(LoginField::Username, "gitlab.com").is_err());
        let Some(focused) = &state.focus else {
            return Err(PageError::Refused("nothing has focus".to_owned()));
        };
        page.replace_text(focused, DUMMY, false).await?;
        // twice, so a second fill replaces rather than appends
        page.replace_text(focused, DUMMY, false).await?;

        let value = page
            .session()
            .call(
                "Runtime.evaluate",
                serde_json::json!({
                    "expression": "document.activeElement.value",
                    "returnByValue": true,
                }),
            )
            .await?;
        assert_eq!(value["result"]["value"].as_str(), Some(DUMMY));

        Ok(())
    }
}
