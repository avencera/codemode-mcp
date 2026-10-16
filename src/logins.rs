//! The `logins` builtin server: types a 1Password username, password or
//! one-time code into the focused field of a page on the login's sites, so
//! an agent driving the Mac can sign in without the value entering its
//! context
//!
//! The daemon decides where a value may go, from what Accessibility and the
//! code signature of the app report rather than what the agent says: only
//! into a known browser that other programs cannot script, a password only
//! into a password field, which shows bullets, and any of them only on an
//! `https` page whose host is one of the login's `sites`. The gateway runs
//! that check before asking the owner, shows them the host, and the server
//! types only on that host. The value is read through the same 1Password
//! reader as server secrets, so a companion Mac or a phone can answer it,
//! and the tool answers with the host it filled on, never the value

pub mod totp;

use std::{collections::BTreeMap, sync::Arc};

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig as McpServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    config::{Builtin, LoginConfig, ServerConfig},
    mac::Mac,
    secrets::{OnePassword, Redactor},
};
use totp::Totp;

const INSTRUCTIONS: &str = "Signs in to websites on this Mac with logins from 1Password, \
     without showing you the username, password or one-time code. Click the field first, so it \
     has keyboard focus, then call fill. A password goes only into a password field, and a \
     username or one-time code only into a text field, on an https page whose host is one of the \
     login's sites, in Safari, Chrome, Firefox, Edge, Brave or Arc. The answer says which host it \
     filled; the value itself is never returned.";

/// The argument the gateway puts on every `fill` call, replacing any the
/// agent passed: what it found at the focused field before asking the
/// owner, so the page shows it and the server types only on its host
pub const CHECKED: &str = "checked";

/// What kind of field has keyboard focus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FieldKind {
    /// A password field, which shows bullets instead of its text
    Secure,
    /// A one-line text field
    Text,
    /// Anything else, such as a text area, a button or no element at all
    #[default]
    Other,
}

/// Whether a browser setting that lets other programs script its pages is on
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Setting {
    /// Off, or the browser has no such setting
    #[default]
    Off,
    /// On
    On,
    /// It could not be confirmed off: the file holding it needs Full Disk
    /// Access, or it holds only the last value the browser saved, which a
    /// change made seconds ago may not have reached yet
    Unknown,
}

/// What other programs on the Mac could do with the browser's pages, as
/// far as the daemon could tell
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exposure {
    /// The browser was started with a remote debugging port or pipe, through
    /// which any program on the Mac can read its pages and run script in them
    pub remote_debugging: Setting,
    /// "Allow JavaScript from Apple Events", which lets any program that may
    /// send the browser Apple Events run script in its pages
    pub apple_events_javascript: Setting,
}

/// The element with keyboard focus, as Accessibility and the code signature
/// of the app that owns it report it
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FocusedField {
    /// Kind of field
    pub kind: FieldKind,
    /// Addresses of the pages around the field, innermost first: a field in
    /// a frame lists the frame, then each page holding it. Empty outside a
    /// web page
    pub pages: Vec<String>,
    /// Name of the browser that owns the field, such as `Safari`, when its
    /// code signature is one the daemon knows; `None` for any other app
    pub browser: Option<String>,
    /// What other programs could do with that browser
    pub exposure: Exposure,
}

impl FocusedField {
    /// The settings that could not be read, for the owner to weigh before
    /// approving; a setting known to be on refuses the fill instead
    pub fn unchecked(&self) -> Vec<String> {
        let browser = self.browser.as_deref().unwrap_or("the app");
        let mut notes = Vec::new();
        if self.exposure.remote_debugging == Setting::Unknown {
            notes.push(format!(
                "could not check whether {browser} was started with remote debugging"
            ));
        }
        if self.exposure.apple_events_javascript == Setting::Unknown {
            notes.push(format!(
                "could not confirm that {browser} blocks JavaScript from Apple Events"
            ));
        }

        notes
    }
}

/// Which login field to fill
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoginField {
    Username,
    Password,
    /// The current code from the login's one-time password
    OneTimeCode,
}

impl LoginField {
    /// The field as messages and the owner's prompt name it
    fn label(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::OneTimeCode => "one-time code",
        }
    }
}

/// Where one login field may be typed: the browser, the kind of field and
/// the sites
#[derive(Debug, Clone)]
pub struct FieldRule {
    /// The field being filled
    pub field: LoginField,
    /// Hosts a page must be on: `github.com` is that host only, and
    /// `*.github.com` any host under it
    pub sites: Vec<String>,
    /// What the owner approved: the field must still be on that host, in
    /// that browser, with nothing unchecked they were not told of; `None`
    /// before the owner was asked
    pub approved: Option<Checked>,
}

/// Whether `host` is `site`, or under it for a `*.` site
fn site_matches(site: &str, host: &str) -> bool {
    match site.strip_prefix("*.") {
        Some(parent) => host
            .strip_suffix(parent)
            .is_some_and(|label| label.len() > 1 && label.ends_with('.')),
        None => host == site,
    }
}

impl FieldRule {
    /// The innermost page's host when `focused` may take this field
    ///
    /// The gateway checks this before asking the owner, so a wrong field
    /// never puts a prompt in front of them, the server again before reading
    /// the value, and the Mac before each character it types. Every page
    /// around the field must pass; a frame the browser does not report as a
    /// page of its own is not among them, so its host goes unchecked
    pub fn check(&self, focused: &FocusedField) -> Result<String, FillError> {
        let refuse = |reason: String| Err(FillError::Refused(reason));
        // a page's address and the field's kind come from the app that owns
        // the field, so they mean something only from a browser known by its
        // code signature
        let Some(browser) = &focused.browser else {
            return refuse(
                "the focused field is not in a browser codemode-mcp can verify by its code \
                 signature (Safari, Chrome, Firefox, Edge, Brave or Arc)"
                    .to_owned(),
            );
        };
        if focused.exposure.remote_debugging == Setting::On {
            return refuse(format!(
                "{browser} was started with remote debugging, which lets any program on this Mac \
                 read and script its pages; quit it, open it normally and fill again"
            ));
        }
        if focused.exposure.apple_events_javascript == Setting::On {
            return refuse(format!(
                "{browser} allows JavaScript from Apple Events, which lets other programs on this \
                 Mac script its pages; turn that off in its developer menu and fill again"
            ));
        }
        match (self.field, focused.kind) {
            (LoginField::Password, FieldKind::Secure)
            | (LoginField::Username | LoginField::OneTimeCode, FieldKind::Text) => {}
            (LoginField::Password, _) => {
                return refuse(
                    "the focused element is not a password field; click the password field first"
                        .to_owned(),
                );
            }
            (LoginField::Username, FieldKind::Secure) => {
                return refuse(
                    "the focused element is a password field; click the username field first"
                        .to_owned(),
                );
            }
            (LoginField::Username, FieldKind::Other) => {
                return refuse(
                    "the focused element is not a text field; click the username field first"
                        .to_owned(),
                );
            }
            (LoginField::OneTimeCode, _) => {
                return refuse(
                    "the focused element is not a one-line text field; click the field for the \
                     code first"
                        .to_owned(),
                );
            }
        }

        let Some((innermost, outer)) = focused.pages.split_first() else {
            return refuse("the focused field is not on a web page".to_owned());
        };
        let host = self.page_host(innermost)?;
        for page in outer {
            self.page_host(page)?;
        }
        if let Some(approved) = &self.approved {
            if approved.host != host {
                return refuse(format!(
                    "the focused field is now on {host}, but the owner approved filling on {}; \
                     fill again to ask for {host}",
                    approved.host
                ));
            }
            // the same host in another browser, or one whose settings could
            // no longer be read, is not what the owner saw
            let unseen = focused
                .unchecked()
                .into_iter()
                .any(|note| !approved.unchecked.contains(&note));
            if approved.browser != *browser || unseen {
                return refuse(format!(
                    "the focused field is now in {browser}, not as the owner approved in {}; \
                     fill again to ask",
                    approved.browser
                ));
            }
        }

        Ok(host)
    }

    /// The host of one page around the field, when it is one of the sites
    fn page_host(&self, page: &str) -> Result<String, FillError> {
        let refuse = |reason: String| Err(FillError::Refused(reason));
        let Ok(url) = reqwest::Url::parse(page) else {
            return refuse("the page's address could not be read".to_owned());
        };
        if url.scheme() != "https" {
            return refuse(format!("the page is not https ({}:)", url.scheme()));
        }
        // the parser leaves the port out when it is 443
        if let Some(port) = url.port() {
            return refuse(format!("the page is on port {port}, not 443"));
        }
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return refuse("the page has no host".to_owned());
        };
        if !self.sites.iter().any(|site| site_matches(site, &host)) {
            return refuse(format!(
                "the page is on {host}, which is not one of this login's sites ({})",
                self.sites.join(", ")
            ));
        }

        Ok(host)
    }
}

/// Why a field was not filled; no variant carries the value
#[derive(Debug, Clone, thiserror::Error)]
pub enum FillError {
    /// The Mac cannot type for the daemon; the text says what to do
    #[error("{0}")]
    Unavailable(String),
    /// The focused field is not one this login may go into
    #[error("{0}")]
    Refused(String),
    /// Focus left the field part way through, so it holds part of the value
    #[error(
        "keyboard focus left the field while it was being filled; clear the field and fill again"
    )]
    Interrupted,
    /// Accessibility or the keyboard events failed
    #[error("{0}")]
    Failed(String),
}

/// The answer to `fill`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Filled {
    /// Login that was filled
    pub login: String,
    /// Field that was filled
    pub field: LoginField,
    /// Host of the page that took it
    pub host: String,
}

/// One login as `list` shows it
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct LoginInfo {
    /// Name to pass to `fill`
    pub name: String,
    /// Hosts the login may be filled on, subdomains included
    pub sites: Vec<String>,
    /// Fields the login has
    pub fields: Vec<LoginField>,
}

/// The answer to `list`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct LoginList {
    pub logins: Vec<LoginInfo>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FillParams {
    /// Name of the login, from `list`
    pub login: String,
    /// Which of its fields to type into the focused field
    pub field: LoginField,
    /// Set by the gateway, never the agent, so it stays out of the schema
    #[serde(default)]
    #[schemars(skip)]
    pub checked: Option<Checked>,
}

/// What the gateway found at the focused field before asking the owner,
/// under [`CHECKED`] in the call's arguments
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Checked {
    /// Host of the page; the server types only while the field is on it
    pub host: String,
    /// Browser that owns the field
    pub browser: String,
    /// Settings that could not be read, which the owner saw
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unchecked: Vec<String>,
}

/// The reference of `login`'s `field` and the rule for where it may go
fn target(
    logins: &BTreeMap<String, LoginConfig>,
    name: &str,
    field: LoginField,
) -> Result<(String, FieldRule), String> {
    let Some(login) = logins.get(name) else {
        return Err(format!("no login named `{name}`; call list for the names"));
    };
    let reference = match field {
        LoginField::Username => login.username.as_ref(),
        LoginField::Password => login.password.as_ref(),
        LoginField::OneTimeCode => login.totp.as_ref(),
    };
    let Some(reference) = reference else {
        return Err(format!("the login `{name}` has no {}", field.label()));
    };
    let rule = FieldRule {
        field,
        sites: login.sites.clone(),
        approved: None,
    };

    Ok((reference.clone(), rule))
}

/// The check the gateway runs on a `logins` server's `fill` call before
/// asking the owner; cheap to clone
#[derive(Clone)]
pub struct FillCheck {
    logins: Arc<BTreeMap<String, LoginConfig>>,
    mac: Option<Arc<dyn Mac>>,
}

impl FillCheck {
    /// A check of the focused field on `mac` against `logins`
    pub fn new(logins: Arc<BTreeMap<String, LoginConfig>>, mac: Option<Arc<dyn Mac>>) -> Self {
        Self { logins, mac }
    }

    /// For a `fill` call of a `logins` server, checks the focused field
    /// against the login's rule, records what it found under [`CHECKED`] in
    /// `arguments`, and answers what the owner is asked to approve, such as
    /// `password for github into github.com in Safari`; `None` for any
    /// other call
    ///
    /// A refusal ends the call before anyone is asked. Whatever the agent
    /// passed under [`CHECKED`] is dropped either way
    pub async fn prepare(
        &self,
        server: Option<&ServerConfig>,
        tool: &str,
        arguments: &mut Map<String, Value>,
    ) -> Result<Option<String>, FillError> {
        let Some(server) = server.filter(|server| server.builtin == Some(Builtin::Logins)) else {
            return Ok(None);
        };
        if tool != "fill" {
            return Ok(None);
        }
        arguments.remove(CHECKED);
        // the server's fixed arguments, such as a `login`, are what the call
        // runs with, so the check and the owner see them too
        for (name, value) in &server.arguments {
            if name != CHECKED && !arguments.contains_key(name) {
                arguments.insert(name.clone(), value.clone());
            }
        }

        #[derive(Deserialize)]
        struct Call {
            login: String,
            field: LoginField,
        }
        let call: Call =
            serde_json::from_value(Value::Object(arguments.clone())).map_err(|error| {
                FillError::Refused(format!("fill needs `login` and `field`: {error}"))
            })?;
        let (_, rule) =
            target(&self.logins, &call.login, call.field).map_err(FillError::Refused)?;
        let Some(mac) = &self.mac else {
            return Err(FillError::Unavailable(
                "filling needs the Mac's screen, which this process cannot reach".to_owned(),
            ));
        };
        let focused = mac.focused_field().await?;
        let host = rule.check(&focused)?;
        let browser = focused.browser.clone().unwrap_or_default();
        let unchecked = focused.unchecked();

        let mut summary = format!(
            "{} for {} into {host} in {browser}",
            call.field.label(),
            call.login
        );
        for note in &unchecked {
            summary.push_str("; ");
            summary.push_str(note);
        }
        let checked = Checked {
            host,
            browser,
            unchecked,
        };
        arguments.insert(
            CHECKED.to_owned(),
            serde_json::to_value(&checked).unwrap_or(Value::Null),
        );

        Ok(Some(summary))
    }
}

/// One fill at a time across every `logins` server and reconnect, so two
/// calls never check, prompt and type over each other
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Inner {
    logins: Arc<BTreeMap<String, LoginConfig>>,
    onepassword: OnePassword,
    redactor: Arc<Redactor>,
    mac: Option<Arc<dyn Mac>>,
}

/// The MCP server, served in process over an in-memory pipe; cheap to clone
#[derive(Clone)]
pub struct LoginsServer(Arc<Inner>);

impl LoginsServer {
    /// A server for `logins`, reading values through `onepassword` and
    /// typing them on `mac`; passwords read are added to `redactor`
    pub fn new(
        logins: Arc<BTreeMap<String, LoginConfig>>,
        onepassword: OnePassword,
        redactor: Arc<Redactor>,
        mac: Option<Arc<dyn Mac>>,
    ) -> Self {
        Self(Arc::new(Inner {
            logins,
            onepassword,
            redactor,
            mac,
        }))
    }

    /// Serves MCP on `io` until the other end closes it
    pub async fn serve_on<T>(self, io: T) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let service = self.serve(io).await?;
        service.waiting().await?;

        Ok(())
    }
}

/// The tool's error text
fn failed(message: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.to_string())])
}

#[tool_router]
impl LoginsServer {
    #[tool(description = "The logins you may fill, with their sites and fields.")]
    async fn list(&self) -> Json<LoginList> {
        let logins = self
            .0
            .logins
            .iter()
            .map(|(name, login)| LoginInfo {
                name: name.clone(),
                sites: login.sites.clone(),
                fields: [
                    login.username.as_ref().map(|_| LoginField::Username),
                    login.password.as_ref().map(|_| LoginField::Password),
                    login.totp.as_ref().map(|_| LoginField::OneTimeCode),
                ]
                .into_iter()
                .flatten()
                .collect(),
            })
            .collect();

        Json(LoginList { logins })
    }

    #[tool(
        description = "Types a login's username, password or current one-time code into the \
                          field that has keyboard focus, without returning it. Click an empty \
                          field first. A password goes only into a password field, a username or \
                          one-time code only into a text field, and any of them only on an https \
                          page of one of the login's sites, in a browser known by its code \
                          signature."
    )]
    async fn fill(
        &self,
        Parameters(params): Parameters<FillParams>,
    ) -> Result<Json<Filled>, CallToolResult> {
        let (reference, mut rule) =
            target(&self.0.logins, &params.login, params.field).map_err(failed)?;
        // the gateway sets this after its own check and the owner approves
        // that host; a call that skipped it has nothing approved to type on
        let Some(checked) = params.checked else {
            return Err(failed(
                "fill runs only through the gateway's approval, which checks the field first",
            ));
        };
        rule.approved = Some(checked);
        let Some(mac) = &self.0.mac else {
            return Err(failed(
                "filling needs the Mac's screen, which this process cannot reach",
            ));
        };

        let _turn = TURN.lock().await;
        // again before the read: the page may have moved on while the owner
        // decided, and the Mac checks again before each character
        let focused = mac.focused_field().await.map_err(failed)?;
        rule.check(&focused).map_err(failed)?;

        let value = self
            .0
            .onepassword
            .read_reference(&reference)
            .await
            .map_err(failed)?;
        let text = match params.field {
            LoginField::OneTimeCode => {
                // the seed makes every later code, so no server's answer may
                // show it, whole or in part, even in a form the parser
                // refuses; the URI around it is redacted whole only, since
                // its label is often an email address
                self.0.redactor.add([value.clone()]);
                let totp = Totp::parse(&value).map_err(failed)?;
                self.0.redactor.add_keys([totp.encoded().to_owned()]);

                totp.now()
            }
            field => {
                // a line break or tab would act on the page, such as
                // submitting the form, instead of landing in the field
                if value.is_empty() || value.chars().any(char::is_control) {
                    return Err(failed(format!(
                        "the {} in 1Password is empty or holds a control character such as a \
                         line break, so it was not typed",
                        field.label()
                    )));
                }
                // a username such as an email address also appears in other
                // servers' results, which redacting it would garble; neither
                // is ever returned here
                if field == LoginField::Password {
                    self.0.redactor.add([value.clone()]);
                }

                value
            }
        };
        let host = mac.fill(&text, &rule).await.map_err(failed)?;

        Ok(Json(Filled {
            login: params.login,
            field: params.field,
            host,
        }))
    }
}

#[tool_handler]
impl ServerHandler for LoginsServer {
    fn get_info(&self) -> McpServerConfig {
        McpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(field: LoginField) -> FieldRule {
        FieldRule {
            field,
            sites: vec!["github.com".to_owned(), "*.github.io".to_owned()],
            approved: None,
        }
    }

    fn page(kind: FieldKind, url: &str) -> FocusedField {
        FocusedField {
            kind,
            pages: vec![url.to_owned()],
            browser: Some("Safari".to_owned()),
            ..FocusedField::default()
        }
    }

    #[test]
    fn a_password_goes_only_into_a_password_field_on_its_sites() {
        let password = rule(LoginField::Password);
        let host = |focused: FocusedField| password.check(&focused).ok();

        assert_eq!(
            host(page(FieldKind::Secure, "https://github.com/login")),
            Some("github.com".to_owned())
        );
        assert_eq!(
            host(page(FieldKind::Secure, "https://GitHub.com:443/login")),
            Some("github.com".to_owned())
        );
        assert_eq!(
            host(page(FieldKind::Secure, "https://me.github.io/x")),
            Some("me.github.io".to_owned())
        );
        for refused in [
            page(FieldKind::Secure, "https://gist.github.com/login"),
            page(FieldKind::Secure, "https://github.io/login"),
            page(FieldKind::Secure, "https://evilgithub.io/login"),
            page(FieldKind::Secure, "https://github.com:8443/login"),
            page(FieldKind::Secure, "https://github.com./login"),
            page(FieldKind::Text, "https://github.com/login"),
            page(FieldKind::Other, "https://github.com/login"),
            page(FieldKind::Secure, "http://github.com/login"),
            page(FieldKind::Secure, "https://github.com.evil.example/login"),
            page(FieldKind::Secure, "https://notgithub.com/login"),
            page(
                FieldKind::Secure,
                "https://evil.example/?u=https://github.com",
            ),
            page(FieldKind::Secure, "https://github.com@evil.example/"),
            FocusedField {
                pages: Vec::new(),
                ..page(FieldKind::Secure, "https://github.com/login")
            },
            // a frame on the site inside a page that is not
            FocusedField {
                pages: vec![
                    "https://github.com/login".to_owned(),
                    "https://evil.example/".to_owned(),
                ],
                ..page(FieldKind::Secure, "https://github.com/login")
            },
        ] {
            assert!(host(refused.clone()).is_none(), "{refused:?}");
        }
    }

    #[test]
    fn a_username_goes_only_into_a_text_field() {
        let username = rule(LoginField::Username);

        assert!(
            username
                .check(&page(FieldKind::Text, "https://github.com/login"))
                .is_ok()
        );
        assert!(
            username
                .check(&page(FieldKind::Secure, "https://github.com/login"))
                .is_err()
        );
    }
}
