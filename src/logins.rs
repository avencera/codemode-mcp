//! The `logins` builtin server: types a 1Password username, password or
//! one-time code into the focused field of a web page, so an agent driving
//! the Mac can sign in on any site without the value entering its context
//!
//! The daemon decides where a value may go, from what Accessibility and the
//! code signature of the app report rather than what the agent says: only
//! into a known browser that other programs cannot script, a password only
//! into a password field, which shows bullets, and any of them only on an
//! `https` page. The login is the 1Password Login item saved for the page's
//! site, matched by registrable domain as 1Password's own autofill matches
//! it, so a look-alike host finds none. The agent may name another item, and
//! the owner is then warned that it is not saved for the page; with the
//! owner away from this Mac, where 1Password cannot be searched, the owner
//! picks the login on their phone instead. The gateway runs that check
//! before asking the owner and shows them the item and host, the server
//! types only on that host, and the tool answers with the host it filled
//! on, never the value

pub mod totp;

use std::sync::Arc;

use companion_wire::wire::MAX_DESCRIPTION_CHARS;
use rmcp::{
    RoleServer, ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig as McpServerConfig},
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    companion::{ProgramAsk, ProgramRead, ProgramTarget},
    config::{Builtin, ServerConfig},
    mac::Mac,
    prompt,
    secrets::{LoginPart, OnePassword, Redactor, SavedLogin, is_reference},
};
use totp::Totp;

const INSTRUCTIONS: &str = "Signs in to websites on this Mac with logins from 1Password, \
     without showing you the username, password or one-time code. Click the field first, so it \
     has keyboard focus, then call fill. It uses the 1Password login saved for the page's site; \
     when the page has several or none, pass `item` as an op://vault/item reference, and the \
     user is warned when that item is not saved for the page. A password goes only into a \
     password field, and a username or one-time code only into a text field, on an https page \
     in Safari, Chrome, Firefox, Edge, Brave or Arc. The answer says which host it filled; the \
     value itself is never returned.";

/// The argument the gateway puts on every `fill` call, replacing any the
/// agent passed: what it found at the focused field before asking the
/// owner, so the page shows it and the server types only on its host
pub const CHECKED: &str = "checked";

/// Most saved logins a refusal names when a page has several
const MAX_NAMED_LOGINS: usize = 10;

/// What a fill the caller stopped waiting for answers; nothing was typed
const CANCELLED: &str = "the call was cancelled before anything was typed";

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

    /// The part of a Login item that holds it
    fn part(self) -> LoginPart {
        match self {
            Self::Username => LoginPart::Username,
            Self::Password => LoginPart::Password,
            Self::OneTimeCode => LoginPart::OneTimePassword,
        }
    }

    /// The label 1Password gives the field in a new Login item, for a
    /// reference built without opening the item
    fn default_label(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::OneTimeCode => "one-time password",
        }
    }
}

/// The sites the pages around a field must be on
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Sites {
    /// Any `https` host: for the check that finds the field's host, an item
    /// the owner approved for a page it is not saved for, or a value picked
    /// on the phone. The host the owner approved still binds the fill
    Any,
    /// Hosts on one of these registrable domains, such as `apple.com`: the
    /// sites of the websites the item is saved for
    Domains(Vec<String>),
}

/// The site `host` is on: its registrable domain by the public suffix list,
/// such as `apple.com` for `idmsa.apple.com`, so `me.github.io` and
/// `you.github.io` are different sites. An address, a one-label host such as
/// a router's, or a public suffix itself is a site of its own
pub fn site_of(host: &str) -> String {
    let address = host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok();
    let registrable = if address { None } else { psl::domain_str(host) };

    registrable.unwrap_or(host).to_ascii_lowercase()
}

/// The sites of `hosts` as messages name them, such as `apple.com` or
/// `github.com and evil.example`
fn sites_named(hosts: &[String]) -> String {
    let mut sites: Vec<String> = hosts.iter().map(|host| site_of(host)).collect();
    sites.dedup();

    sites.join(" and ")
}

/// The sites `login` is saved for, without repeats
fn sites_of(login: &SavedLogin) -> Vec<String> {
    let mut sites: Vec<String> = login.hosts.iter().map(|host| site_of(host)).collect();
    sites.sort();
    sites.dedup();

    sites
}

/// Where one login field may be typed: the browser, the kind of field and
/// the sites
#[derive(Debug, Clone)]
pub struct FieldRule {
    /// The field being filled
    pub field: LoginField,
    /// Sites every page around the field must be on
    pub sites: Sites,
    /// What the owner approved: the field must still be on that host, in
    /// that browser, with nothing unchecked they were not told of; `None`
    /// before the owner was asked
    pub approved: Option<Checked>,
}

impl FieldRule {
    /// The innermost page's host when `focused` may take this field
    ///
    /// The gateway checks this before asking the owner, so a wrong field
    /// never puts a prompt in front of them, the server again before reading
    /// the value, and the Mac before each character it types
    pub fn check(&self, focused: &FocusedField) -> Result<String, FillError> {
        let mut hosts = self.hosts(focused)?;

        Ok(hosts.swap_remove(0))
    }

    /// The host of every page around `focused`, innermost first, when it may
    /// take this field; never empty. Every page must pass; a frame the
    /// browser does not report as a page of its own is not among them, so
    /// its host goes unchecked
    pub fn hosts(&self, focused: &FocusedField) -> Result<Vec<String>, FillError> {
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

        if focused.pages.is_empty() {
            return refuse("the focused field is not on a web page".to_owned());
        }
        let hosts = focused
            .pages
            .iter()
            .map(|page| self.page_host(page))
            .collect::<Result<Vec<String>, FillError>>()?;
        let host = &hosts[0];
        if let Some(approved) = &self.approved {
            if approved.host != *host {
                return refuse(format!(
                    "the focused field is now on {host}, but the owner approved filling on {}; \
                     fill again to ask for {host}",
                    approved.host
                ));
            }
            // a frame the owner approved may not move into another page
            if approved.around[..] != hosts[1..] {
                return refuse(
                    "the pages around the focused field changed since the owner approved; fill \
                     again to ask"
                        .to_owned(),
                );
            }
            // the same host in another browser, or one whose settings could
            // no longer be read, is not what the owner saw
            if approved.browser != *browser {
                return refuse(format!(
                    "the focused field is now in {browser}, not as the owner approved in {}; \
                     fill again to ask",
                    approved.browser
                ));
            }
            let unseen: Vec<String> = focused
                .unchecked()
                .into_iter()
                .filter(|note| !approved.unchecked.contains(note))
                .collect();
            if !unseen.is_empty() {
                return refuse(format!(
                    "{browser} changed since the owner approved: {}; fill again to ask",
                    unseen.join("; ")
                ));
            }
        }

        Ok(hosts)
    }

    /// The host of one page around the field, when it is on the sites
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
        // the same host to DNS, but not to the owner reading the prompt
        if host.ends_with('.') {
            return refuse(format!("the page's host {host} ends with a dot"));
        }
        if let Sites::Domains(domains) = &self.sites
            && !domains.contains(&site_of(&host))
        {
            return refuse(format!(
                "the page is on {host}, which is not a site this login is saved for ({})",
                domains.join(", ")
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
    /// Accessibility, 1Password or the keyboard events failed
    #[error("{0}")]
    Failed(String),
}

/// The answer to `fill`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Filled {
    /// Field that was filled
    pub field: LoginField,
    /// Host of the page that took it
    pub host: String,
    /// The 1Password item it came from, such as `GitHub (Personal)`; left
    /// out when the owner picked it on their phone
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FillParams {
    /// Which field of the login to type into the focused field
    pub field: LoginField,
    /// The 1Password item to use, as `op://vault/item`, when the page has
    /// several saved logins or none; left out, the one saved for the page's
    /// site. The gateway resolves it into `checked`
    #[serde(default)]
    pub item: Option<String>,
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
    /// Hosts of the pages around that one, innermost first, which must not
    /// change either
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub around: Vec<String>,
    /// Browser that owns the field
    pub browser: String,
    /// What the owner is warned of about the login, such as that it is not
    /// saved for the page, so the approval page shows it too
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// Settings that could not be read, which the owner saw
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unchecked: Vec<String>,
    /// Where the value comes from, as the owner was shown it
    pub source: Source,
}

/// Where a fill's value comes from
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// A field of a 1Password item, read like any reference
    Item {
        /// The field's reference
        reference: String,
        /// The item as the owner was shown it, such as `GitHub (Personal)`
        name: String,
        /// Sites the pages must stay on while it is typed
        sites: Sites,
    },
    /// The owner picks the value on their phone
    Phone,
}

impl Source {
    fn sites(&self) -> Sites {
        match self {
            Self::Item { sites, .. } => sites.clone(),
            Self::Phone => Sites::Any,
        }
    }
}

/// The vault and item of an `op://vault/item` reference; a field after
/// them is left out, since the field to fill says which one
fn item_ref(text: &str) -> Result<(&str, &str), FillError> {
    let mut segments = text
        .trim()
        .strip_prefix("op://")
        .map(|path| path.split('/'))
        .into_iter()
        .flatten();
    // a query such as `?attribute=otp` would read a code, not the seed
    let plain = |segment: &&str| !segment.trim().is_empty() && !segment.contains('?');
    match (segments.next().filter(plain), segments.next().filter(plain)) {
        (Some(vault), Some(item)) => Ok((vault, item)),
        _ => Err(FillError::Refused(format!(
            "`item` must be an op://vault/item reference, not {}",
            prompt::one_line(text, 80)
        ))),
    }
}

/// The logins `vault` and `item` name, as an `item` reference picks them:
/// by vault name or ID and by title or ID, ignoring case
fn named<'a>(logins: &'a [SavedLogin], vault: &str, item: &str) -> Vec<&'a SavedLogin> {
    logins
        .iter()
        .filter(|login| {
            (login.vault.eq_ignore_ascii_case(vault) || login.vault_id.eq_ignore_ascii_case(vault))
                && (login.title.eq_ignore_ascii_case(item) || login.id.eq_ignore_ascii_case(item))
        })
        .collect()
}

/// `login` as a reference an agent can pass back as `item`: by vault name
/// and title when that picks it alone among `logins`, otherwise by IDs
fn item_text(login: &SavedLogin, logins: &[SavedLogin]) -> String {
    let by_name = format!("op://{}/{}", login.vault, login.title);
    let picks_it = item_ref(&by_name).is_ok_and(|(vault, item)| {
        matches!(named(logins, vault, item).as_slice(), [only] if only.id == login.id)
    });
    if picks_it {
        return by_name;
    }

    format!(
        "op://{}/{}",
        first_set(&login.vault_id, &login.vault),
        login.id
    )
}

fn first_set<'a>(first: &'a str, second: &'a str) -> &'a str {
    if first.is_empty() { second } else { first }
}

/// `login` as the owner is shown it, such as `GitHub (Personal)`
fn item_name(login: &SavedLogin) -> String {
    let title = prompt::one_line(&login.title, 80);
    if login.vault.is_empty() {
        title
    } else {
        format!("{title} ({})", prompt::one_line(&login.vault, 40))
    }
}

/// The check the gateway runs on a `logins` server's `fill` call before
/// asking the owner; cheap to clone
#[derive(Clone)]
pub struct FillCheck {
    onepassword: OnePassword,
    mac: Option<Arc<dyn Mac>>,
}

impl FillCheck {
    /// A check of the focused field on `mac`, finding its login through
    /// `onepassword`
    pub fn new(onepassword: OnePassword, mac: Option<Arc<dyn Mac>>) -> Self {
        Self { onepassword, mac }
    }

    /// For a `fill` call of a `logins` server, checks the focused field,
    /// finds the login it gets, records both under [`CHECKED`] in
    /// `arguments`, and answers what the owner is asked to approve, such as
    /// `password from GitHub (Personal) into github.com in Safari`; `None`
    /// for any other call
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
        // the server's fixed arguments, such as an `item`, are what the call
        // runs with, so the check and the owner see them too
        for (name, value) in &server.arguments {
            if name != CHECKED && !arguments.contains_key(name) {
                arguments.insert(name.clone(), value.clone());
            }
        }

        #[derive(Deserialize)]
        struct Call {
            field: LoginField,
            #[serde(default)]
            item: Option<String>,
        }
        let call: Call = serde_json::from_value(Value::Object(arguments.clone()))
            .map_err(|error| FillError::Refused(format!("fill needs `field`: {error}")))?;
        let Some(mac) = &self.mac else {
            return Err(FillError::Unavailable(
                "filling needs the Mac's screen, which this process cannot reach".to_owned(),
            ));
        };
        let focused = mac.focused_field().await?;
        let any = FieldRule {
            field: call.field,
            sites: Sites::Any,
            approved: None,
        };
        let hosts = any.hosts(&focused)?;
        let host = hosts[0].clone();
        let (source, warning) = self
            .source(call.field, call.item.as_deref(), &hosts)
            .await?;
        let browser = focused.browser.clone().unwrap_or_default();
        let unchecked = focused.unchecked();

        // the host and browser come from the screen, so they lead, ahead of
        // a name the agent may have written
        let label = call.field.label();
        let mut summary = match &source {
            Source::Item { name, .. } => format!("{label} into {host} in {browser} from {name}"),
            Source::Phone => format!("{label} into {host} in {browser}, picked on the phone"),
        };
        for note in warning.iter().chain(&unchecked) {
            summary.push_str("; ");
            summary.push_str(note);
        }
        let checked = Checked {
            host,
            around: hosts[1..].to_vec(),
            browser,
            warning,
            unchecked,
            source,
        };
        arguments.insert(
            CHECKED.to_owned(),
            serde_json::to_value(&checked).unwrap_or(Value::Null),
        );

        Ok(Some(summary))
    }

    /// Whether this Mac's 1Password may be searched: the owner is at it, or
    /// there is no Mac to find them at, as for any read
    async fn at_mac(&self) -> bool {
        match self.onepassword.on_mac() {
            Some(on_mac) => on_mac.mac.present(on_mac.config.idle()).await,
            None => true,
        }
    }

    /// Where `field`'s value comes from for pages on `hosts`, innermost
    /// first, and anything the owner must be warned of
    async fn source(
        &self,
        field: LoginField,
        item: Option<&str>,
        hosts: &[String],
    ) -> Result<(Source, Option<String>), FillError> {
        if !self.at_mac().await {
            return self.source_away(field, item);
        }

        let logins = self.onepassword.saved_logins().await.map_err(|error| {
            FillError::Failed(format!("could not list the logins in 1Password: {error}"))
        })?;
        // every page around the field is on one of the item's sites, so a
        // site's sign-in frame inside another site's page finds nothing
        let saved_for_page = |login: &SavedLogin| {
            let sites = sites_of(login);
            hosts
                .iter()
                .all(|host| sites.contains(&site_of(host)))
                .then_some(sites)
        };
        let site = sites_named(hosts);
        let (login, sites, warning) = match item {
            Some(text) => {
                let (vault, title) = item_ref(text)?;
                let login = match named(&logins, vault, title).as_slice() {
                    [login] => *login,
                    [] => {
                        return Err(FillError::Refused(format!(
                            "1Password on this Mac has no Login item {}",
                            prompt::one_line(text, 80)
                        )));
                    }
                    several => {
                        let names: Vec<String> = several
                            .iter()
                            .map(|login| item_text(login, &logins))
                            .collect();
                        return Err(FillError::Refused(format!(
                            "several Login items match {}; pass one by its ID: {}",
                            prompt::one_line(text, 80),
                            names.join(", ")
                        )));
                    }
                };
                match saved_for_page(login) {
                    Some(sites) => (login, Sites::Domains(sites), None),
                    // the owner's call, so the prompt says so
                    None => (
                        login,
                        Sites::Any,
                        Some(format!("this item is NOT saved for {site}")),
                    ),
                }
            }
            None => {
                let matched: Vec<(&SavedLogin, Vec<String>)> = logins
                    .iter()
                    .filter_map(|login| saved_for_page(login).map(|sites| (login, sites)))
                    .collect();
                match matched.as_slice() {
                    [(login, sites)] => (*login, Sites::Domains(sites.clone()), None),
                    [] => {
                        return Err(FillError::Refused(format!(
                            "no 1Password login is saved for {site}; pass the one to use as \
                             `item` (op://vault/item), and the user will be warned that it is \
                             not saved for this site"
                        )));
                    }
                    several => {
                        let among: Vec<&SavedLogin> =
                            several.iter().map(|(login, _)| *login).collect();
                        let mut names: Vec<String> = among
                            .iter()
                            .take(MAX_NAMED_LOGINS)
                            .map(|login| item_text(login, &logins))
                            .collect();
                        if among.len() > MAX_NAMED_LOGINS {
                            names.push(format!("{} more", among.len() - MAX_NAMED_LOGINS));
                        }
                        return Err(FillError::Refused(format!(
                            "{} 1Password logins are saved for {site}; pass the one to use as \
                             `item`: {}",
                            among.len(),
                            names.join(", ")
                        )));
                    }
                }
            }
        };

        let name = item_name(login);
        let reference = self
            .onepassword
            .login_reference(login, field.part())
            .await
            .map_err(|error| FillError::Failed(format!("could not open {name}: {error}")))?
            .filter(|reference| is_reference(reference))
            .ok_or_else(|| FillError::Refused(format!("{name} has no {}", field.label())))?;

        Ok((
            Source::Item {
                reference,
                name,
                sites,
            },
            warning,
        ))
    }

    /// [`Self::source`] with the owner away from this Mac, whose 1Password
    /// is then not searched: a named item is read by its usual field label,
    /// unchecked, and otherwise the owner picks the login on their phone
    fn source_away(
        &self,
        field: LoginField,
        item: Option<&str>,
    ) -> Result<(Source, Option<String>), FillError> {
        if let Some(text) = item {
            let (vault, title) = item_ref(text)?;
            let reference = format!("op://{vault}/{title}/{}", field.default_label());
            if !is_reference(&reference) {
                return Err(FillError::Refused(format!(
                    "`item` must be an op://vault/item reference, not {}",
                    prompt::one_line(text, 80)
                )));
            }

            return Ok((
                Source::Item {
                    reference,
                    // the agent's words, quoted so a prompt cannot read
                    // them as its own
                    name: format!(
                        "\"{}\"",
                        prompt::one_line(&format!("op://{vault}/{title}"), 80)
                    ),
                    sites: Sites::Any,
                },
                Some(
                    "the sites this item is saved for were not checked, since the owner is away \
                     from this Mac"
                        .to_owned(),
                ),
            ));
        }

        let phones = self
            .onepassword
            .companions()
            .is_some_and(|companions| !companions.phones().is_empty());
        if !phones {
            return Err(FillError::Refused(
                "the user is away from this Mac, so 1Password cannot be searched for this site, \
                 and no phone is paired to pick the login on; pass `item` as op://vault/item, or \
                 wait for the user"
                    .to_owned(),
            ));
        }

        Ok((Source::Phone, None))
    }
}

/// Whether `value` is a one-time code itself, as the owner enters one on
/// the phone, rather than the seed 1Password holds
fn is_code(value: &str) -> bool {
    (6..=8).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// One fill at a time across every `logins` server and reconnect, so two
/// calls never check, prompt and type over each other
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Inner {
    onepassword: OnePassword,
    redactor: Arc<Redactor>,
    mac: Option<Arc<dyn Mac>>,
}

/// The MCP server, served in process over an in-memory pipe; cheap to clone
#[derive(Clone)]
pub struct LoginsServer(Arc<Inner>);

impl LoginsServer {
    /// A server reading values through `onepassword` and typing them on
    /// `mac`; passwords read are added to `redactor`
    pub fn new(
        onepassword: OnePassword,
        redactor: Arc<Redactor>,
        mac: Option<Arc<dyn Mac>>,
    ) -> Self {
        Self(Arc::new(Inner {
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

    /// The value `checked` approved for `field`, and the item it came from
    async fn value(
        &self,
        field: LoginField,
        checked: &Checked,
    ) -> Result<(String, Option<String>), CallToolResult> {
        match &checked.source {
            Source::Item {
                reference, name, ..
            } => {
                let value = self
                    .0
                    .onepassword
                    .read_reference(reference)
                    .await
                    .map_err(failed)?;

                Ok((value, Some(name.clone())))
            }
            Source::Phone => Ok((self.pick_on_phone(field, checked).await?, None)),
        }
    }

    /// Asks the phones for `field`'s value on the approved page; the owner
    /// picks it there with 1Password's AutoFill
    async fn pick_on_phone(
        &self,
        field: LoginField,
        checked: &Checked,
    ) -> Result<String, CallToolResult> {
        let site = site_of(&checked.host);
        let description = prompt::one_line(
            &format!("{} for {site}", field.label()),
            MAX_DESCRIPTION_CHARS,
        );
        let ask = ProgramAsk {
            targets: vec![ProgramTarget::Describe(description)],
            reason: Some(format!("sign in on {}", checked.host)),
            destination: Some(format!(
                "the {} field on {} in {}",
                field.label(),
                checked.host,
                checked.browser
            )),
            keep: None,
            phones_only: true,
            keep_scope: None,
        };

        match self.0.onepassword.read_for_program(&ask).await {
            Ok(ProgramRead::Values(read)) => read
                .values
                .first()
                .and_then(|value| value.as_text())
                .map(str::to_owned)
                .ok_or_else(|| failed("the phone did not answer with text")),
            Ok(ProgramRead::Found(_)) => {
                Err(failed("the phone answered with items instead of the value"))
            }
            Err(error) => Err(failed(error)),
        }
    }

    /// What is typed for `field` from `value`: a one-time code is made from
    /// its seed, unless the owner entered the code itself on the phone, and
    /// anything else must be one line
    fn typed(
        &self,
        field: LoginField,
        value: String,
        source: &Source,
    ) -> Result<String, CallToolResult> {
        match field {
            // only from the phone: 1Password holds a seed, which a short
            // numeric one would otherwise be typed as, in plain sight
            LoginField::OneTimeCode if *source == Source::Phone && is_code(&value) => Ok(value),
            LoginField::OneTimeCode => {
                // the seed makes every later code, so no server's answer may
                // show it, whole or in part, even in a form the parser
                // refuses; the URI around it is redacted whole only, since
                // its label is often an email address
                self.0.redactor.add([value.clone()]);
                let totp = Totp::parse(&value).map_err(failed)?;
                self.0.redactor.add_keys([totp.encoded().to_owned()]);

                Ok(totp.now())
            }
            field => {
                // a line break or tab would act on the page, such as
                // submitting the form, instead of landing in the field
                if value.is_empty() || value.chars().any(char::is_control) {
                    return Err(failed(format!(
                        "the {} is empty or holds a control character such as a line break, so \
                         it was not typed",
                        field.label()
                    )));
                }
                // a username such as an email address also appears in other
                // servers' results, which redacting it would garble; neither
                // is ever returned here
                if field == LoginField::Password {
                    self.0.redactor.add([value.clone()]);
                }

                Ok(value)
            }
        }
    }
}

/// The tool's error text
fn failed(message: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.to_string())])
}

#[tool_router]
impl LoginsServer {
    #[tool(
        description = "Types the username, password or current one-time code of the 1Password \
                          login saved for the focused page's site into the field that has \
                          keyboard focus, without returning it. Click an empty field first. A \
                          password goes only into a password field, and a username or one-time \
                          code only into a text field, on an https page in a browser known by \
                          its code signature. When the page has several saved logins or none, \
                          pass `item` as op://vault/item; the user is warned when it is not \
                          saved for the page."
    )]
    async fn fill(
        &self,
        Parameters(params): Parameters<FillParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Filled>, CallToolResult> {
        // the gateway sets this after its own check and the owner approves
        // that host and login; a call that skipped it has nothing approved
        let Some(checked) = params.checked else {
            return Err(failed(
                "fill runs only through the gateway's approval, which checks the field first",
            ));
        };
        let rule = FieldRule {
            field: params.field,
            sites: checked.source.sites(),
            approved: Some(checked.clone()),
        };
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

        // a phone pick can outlast the agent's wait; one it gave up on is
        // not typed into whatever has focus by the time the owner answers
        let (value, item) = tokio::select! {
            value = self.value(params.field, &checked) => value?,
            () = context.ct.cancelled() => return Err(failed(CANCELLED)),
        };
        let text = self.typed(params.field, value, &checked.source)?;
        if context.ct.is_cancelled() {
            return Err(failed(CANCELLED));
        }
        let host = mac.fill(&text, &rule).await.map_err(failed)?;

        Ok(Json(Filled {
            field: params.field,
            host,
            item,
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
            sites: Sites::Domains(vec!["github.com".to_owned(), "me.github.io".to_owned()]),
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
        // a site's hosts share its login, as 1Password fills them
        assert_eq!(
            host(page(FieldKind::Secure, "https://gist.github.com/login")),
            Some("gist.github.com".to_owned())
        );
        assert_eq!(
            host(page(FieldKind::Secure, "https://me.github.io/x")),
            Some("me.github.io".to_owned())
        );
        for refused in [
            // another user's site under a public suffix
            page(FieldKind::Secure, "https://you.github.io/login"),
            page(FieldKind::Secure, "https://evilgithub.com/login"),
            page(FieldKind::Secure, "https://github.com:8443/login"),
            page(FieldKind::Secure, "https://github.com./login"),
            page(FieldKind::Text, "https://github.com/login"),
            page(FieldKind::Other, "https://github.com/login"),
            page(FieldKind::Secure, "http://github.com/login"),
            page(FieldKind::Secure, "https://github.com.evil.example/login"),
            page(
                FieldKind::Secure,
                "https://evil.example/?u=https://github.com",
            ),
            page(FieldKind::Secure, "https://github.com@evil.example/"),
            page(FieldKind::Secure, "https://140.82.112.3/login"),
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
    fn a_suggested_item_picks_the_same_login_back() {
        let login = |id: &str, title: &str, vault: &str| SavedLogin {
            id: id.to_owned(),
            title: title.to_owned(),
            // 1Password IDs are letters and digits
            vault_id: format!("{}id", vault.to_lowercase().replace('/', "")),
            vault: vault.to_owned(),
            hosts: Vec::new(),
        };
        let logins = [
            login("a1", "GitLab", "Personal"),
            login("a2", "gitlab", "Personal"),
            login("a3", "Work?", "Personal"),
            login("a4", "GitLab", "Work"),
            login("a5", "Team", "Ops/EU"),
        ];

        let suggested: Vec<String> = logins
            .iter()
            .map(|login| item_text(login, &logins))
            .collect();
        // titles that differ only in case, or that `item` cannot hold, go by
        // IDs
        assert_eq!(
            suggested,
            [
                "op://personalid/a1",
                "op://personalid/a2",
                "op://personalid/a3",
                "op://Work/GitLab",
                "op://opseuid/a5",
            ]
        );
    }

    #[test]
    fn an_item_reference_names_a_vault_and_an_item() {
        assert_eq!(
            item_ref("op://Personal/GitHub").ok(),
            Some(("Personal", "GitHub"))
        );
        assert_eq!(
            item_ref("op://Personal/GitHub/password").ok(),
            Some(("Personal", "GitHub"))
        );
        for refused in [
            "Personal/GitHub",
            "op://Personal",
            "op:///GitHub",
            "op://Personal/GitHub?attribute=otp",
        ] {
            assert!(item_ref(refused).is_err(), "{refused}");
        }
    }
}
