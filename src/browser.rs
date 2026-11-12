//! The `browser` builtin server: signs agents in to websites in their
//! agent-browser sessions, and hands a step to the owner's phone when only
//! they can do it
//!
//! `fill` puts a 1Password username, password or one-time code into the
//! focused field of a session's page over CDP, without the value reaching
//! the agent, agent-browser or a file. The gateway checks the page before
//! asking the owner: `https` on the site the agent names, a field of that
//! kind, and no frame from another site around it. Where the value comes
//! from follows the owner: at this Mac, 1Password here finds the login
//! saved for the site and reads it by reference, so a code is made fresh
//! from its seed; away, the phone is asked at once, for the whole sign-in
//! (see [`sign_in`]). Companion Macs report no presence, so they are asked
//! as for any program read
//!
//! `handoff` asks the owner to take the session over on their phone, for a
//! passkey, a captcha or anything else that cannot be filled, and waits for
//! their Done or Cancel. The takeover itself is in [`takeover`]
//!
//! Anything that can drive the browser over CDP, the agent included, could
//! also read a filled field or script the page before a fill; that is the
//! same-user boundary the design leaves out of scope. What this adds is that
//! the value never enters the agent's context, transcript, or a command
//! line, file or log on the way in

mod awake;
pub mod cdp;
mod handoff;
pub mod page;
mod sign_in;
pub mod takeover;

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use companion_wire::{
    mobile::{HandoffAnswer, LoginField, SignIn},
    takeover::{EndReason, FillOffer, GatewayFrame, GatewayMessage, PhoneMessage},
    wire::{MAX_DESCRIPTION_CHARS, MAX_REASON_CHARS},
};
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
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::{
    companion::{
        Companions, HandoffOffer, ProgramAsk, ProgramRead, ProgramTarget, SessionList, SignInAsk,
        TakeoverHost, TakeoverOpen,
    },
    config::{Builtin, PhonePeer, ServerConfig},
    logins::{find_login, is_code, item_name, site_of, totp::Totp},
    prompt,
    secrets::{LoginPart, OnePassword, Redactor},
    store::{Store, site_logins::SiteLogin},
};
use handoff::Handoffs;
use page::{AgentBrowser, PageError, SessionName};
use sign_in::SignIns;

const INSTRUCTIONS: &str = "Signs in to websites in agent-browser sessions on this Mac without \
     showing you the username, password or one-time code, and hands a step to the user's phone \
     when only they can do it. For a login form: open the page in the session, click the field \
     so it has focus, then call fill with the session, the kind of field and the site, such as \
     `github.com`; pass submit=true on the last field. The value comes from the user's \
     1Password, approved by them, and goes straight into the page. For a passkey, a captcha, a \
     consent screen or anything else fill cannot do, call handoff with the session and what the \
     user should do; it returns once they tap Done or Cancel on their phone. Never type a \
     password or code with agent-browser yourself.";

/// The argument the gateway puts on every `fill` call, replacing any the
/// agent passed: what it found on the page before asking the owner
pub const CHECKED: &str = "checked";

/// How long a handoff waits for the owner unless the agent asks otherwise
const HANDOFF_MINUTES: u64 = 30;

/// Longest a handoff may wait
const MAX_HANDOFF_MINUTES: u64 = 120;

/// Least time a `browser` server call is given: the longest handoff, and
/// time to read the page after it
pub const BROWSER_CALL_TIMEOUT: Duration = Duration::from_secs(MAX_HANDOFF_MINUTES * 60 + 60);

/// What a fill the caller stopped waiting for answers; nothing was filled
const CANCELLED: &str = "the call was cancelled before anything was filled";

/// Which field of a login to fill
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A username or email field
    Username,
    /// A password field
    Password,
    /// A one-time code field; the code is made fresh from the login's seed
    Code,
}

impl From<Kind> for LoginField {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Username => Self::Username,
            Kind::Password => Self::Password,
            Kind::Code => Self::Code,
        }
    }
}

/// The site a `site` argument names: its registrable domain, from a host
/// such as `github.com` or an address such as `https://github.com/login`
fn site_named(text: &str) -> Result<String, String> {
    let text = text.trim().to_ascii_lowercase();
    let host = match reqwest::Url::parse(&text) {
        Ok(url) if url.has_host() => url.host_str().unwrap_or_default().to_owned(),
        _ => text,
    };
    let host = host.trim_end_matches('.');
    let valid = !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.');
    if !valid {
        return Err(format!(
            "`site` must be a host such as github.com, not {}",
            prompt::one_line(host, 80)
        ));
    }

    Ok(site_of(host))
}

/// What is typed for `field` from `value`: a code is made from its seed,
/// unless it is a code already, and anything else must be one line. A
/// password and a seed are added to `redactor`, so no server's answer
/// shows them
pub(crate) fn login_value(
    field: LoginField,
    value: Zeroizing<String>,
    redactor: &Redactor,
) -> Result<Zeroizing<String>, String> {
    // a password may start or end with a space, so only a code and a
    // username are trimmed
    let value = match field {
        LoginField::Password => value,
        _ => Zeroizing::new(value.trim().to_owned()),
    };
    match field {
        LoginField::Code if is_code(&value) => Ok(value),
        LoginField::Code => {
            redactor.add([value.to_string()]);
            let totp = Totp::parse(&value).map_err(|error| error.to_string())?;
            redactor.add_keys([totp.encoded().to_owned()]);

            Ok(Zeroizing::new(totp.now()))
        }
        field => {
            // a line break or tab would act on the page, such as submitting
            // the form, instead of landing in the field
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(format!(
                    "the {} is empty or holds a control character such as a line break, so it \
                     was not filled",
                    field.label()
                ));
            }
            // a username such as an email address also appears in other
            // servers' results, which redacting it would garble
            if field == LoginField::Password {
                redactor.add([value.to_string()]);
            }

            Ok(value)
        }
    }
}

/// Where a fill's value comes from, as the owner was shown it
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// A field of a 1Password item, read by reference
    Item {
        /// The field's reference
        reference: String,
        /// The item as the owner was shown it, such as `GitHub (Personal)`
        item: String,
    },
    /// The owner's phone, for the whole sign-in
    Phone,
}

/// What the gateway found on the page before asking the owner, under
/// [`CHECKED`] in the call's arguments
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Checked {
    /// Host of the page; the fill goes in only while the page is on it
    pub host: String,
    /// The page's site
    pub site: String,
    /// Where the value comes from
    pub source: Source,
}

/// The shared state of every `browser` server: the sign-ins and handoffs in
/// progress and what they read values through; cheap to share
pub struct Browsers {
    agent_browser: AgentBrowser,
    handoffs: Arc<Handoffs>,
    sign_ins: SignIns,
    onepassword: OnePassword,
    redactor: Arc<Redactor>,
    store: Option<Store>,
    /// One fill at a time, so two never check and fill over each other
    turn: tokio::sync::Mutex<()>,
}

impl Browsers {
    /// The state, reading values through `onepassword` and remembering each
    /// site's login in `store`; it runs the takeovers the phones open
    pub fn new(
        onepassword: OnePassword,
        redactor: Arc<Redactor>,
        store: Option<Store>,
        agent_browser: AgentBrowser,
    ) -> Arc<Self> {
        let browsers = Arc::new(Self {
            agent_browser,
            handoffs: Arc::default(),
            sign_ins: SignIns::default(),
            onepassword,
            redactor,
            store,
            turn: tokio::sync::Mutex::new(()),
        });
        if let Some(companions) = browsers.onepassword.companions() {
            let host: Arc<dyn TakeoverHost> = browsers.clone();
            companions.host_takeovers(Arc::downgrade(&host));
        }

        browsers
    }

    /// Whether 1Password on this Mac may be searched: the owner is at it, or
    /// there is no Mac to find them at
    async fn owner_here(&self) -> bool {
        match self.onepassword.on_mac() {
            Some(on_mac) => on_mac.mac.present(on_mac.config.idle()).await,
            None => true,
        }
    }

    fn phones(&self) -> Vec<PhonePeer> {
        self.onepassword
            .companions()
            .map(|companions| companions.phones())
            .unwrap_or_default()
    }

    fn site_login(&self, site: &str) -> Option<SiteLogin> {
        self.store.as_ref()?.site_login(site).ok().flatten()
    }

    /// For a `fill` call of a `browser` server, checks the page, finds where
    /// the value comes from, records both under [`CHECKED`] in `arguments`,
    /// and answers what the owner is asked to approve, such as `password
    /// into github.com (browser session github) from GitHub (Personal)`;
    /// `None` for any other call
    ///
    /// A refusal ends the call before anyone is asked. Whatever the agent
    /// passed under [`CHECKED`] is dropped either way
    pub async fn prepare(
        &self,
        server: Option<&ServerConfig>,
        tool: &str,
        arguments: &mut Map<String, Value>,
    ) -> Result<Option<String>, String> {
        let Some(server) = server.filter(|server| server.builtin == Some(Builtin::Browser)) else {
            return Ok(None);
        };
        if tool != "fill" {
            return Ok(None);
        }
        arguments.remove(CHECKED);
        // the server's fixed arguments, such as a `session`, replace the
        // script's when the call runs, so the check and the owner see them
        // too rather than the page the script named
        for (name, value) in &server.arguments {
            if name != CHECKED {
                arguments.insert(name.clone(), value.clone());
            }
        }

        #[derive(Deserialize)]
        struct Call {
            session: String,
            kind: Kind,
            site: String,
            #[serde(default)]
            item: Option<String>,
        }
        let call: Call = serde_json::from_value(Value::Object(arguments.clone()))
            .map_err(|error| format!("fill needs `session`, `kind` and `site`: {error}"))?;
        let session = SessionName::parse(&call.session).map_err(|error| error.to_string())?;
        let site = site_named(&call.site)?;
        let field = LoginField::from(call.kind);
        let page = self
            .agent_browser
            .open(&session)
            .await
            .map_err(|error| error.to_string())?;
        let host = page
            .state()
            .await
            .and_then(|state| state.check(field, &site))
            .map_err(|error| error.to_string())?;

        let label = field.label();
        let (source, summary) = if self.owner_here().await {
            self.source_here(field, call.item.as_deref(), &host, &site)
                .await
                .map(|(source, item, warning)| {
                    let mut summary =
                        format!("{label} into {host} (browser session {session}) from {item}");
                    if let Some(warning) = warning {
                        summary.push_str("; ");
                        summary.push_str(&warning);
                    }

                    (source, summary)
                })?
        } else {
            if self.phones().is_empty() {
                return Err(
                    "the user is away from this Mac, so 1Password cannot be searched here, and \
                     no phone is paired to pick the login on; wait for the user"
                        .to_owned(),
                );
            }
            let known = self
                .site_login(&site)
                .map(|login| match login.account {
                    Some(account) => format!(" ({} · {account})", login.item),
                    None => format!(" ({})", login.item),
                })
                .unwrap_or_default();

            (
                Source::Phone,
                format!(
                    "{label} into {host} (browser session {session}), from the user's phone{known}"
                ),
            )
        };

        let checked = Checked { host, site, source };
        arguments.insert(
            CHECKED.to_owned(),
            serde_json::to_value(&checked).unwrap_or(Value::Null),
        );

        Ok(Some(summary))
    }

    /// The 1Password field for `field` on `host`, found on this Mac, with the
    /// item's name and any warning; the site's login is remembered for when
    /// the owner is away
    async fn source_here(
        &self,
        field: LoginField,
        item: Option<&str>,
        host: &str,
        site: &str,
    ) -> Result<(Source, String, Option<String>), String> {
        let (login, _, warning) = find_login(&self.onepassword, item, &[host.to_owned()])
            .await
            .map_err(|error| error.to_string())?;
        let name = item_name(&login);
        let [username, password, code] = self
            .onepassword
            .login_references(
                &login,
                [
                    LoginPart::Username,
                    LoginPart::Password,
                    LoginPart::OneTimePassword,
                ],
            )
            .await
            .map_err(|error| format!("could not open {name}: {error}"))?;
        let reference = match field {
            LoginField::Username => username.clone(),
            LoginField::Password => password.clone(),
            LoginField::Code => code.clone(),
        }
        .filter(|reference| crate::secrets::is_reference(reference))
        .ok_or_else(|| format!("{name} has no {}", field.label()))?;

        // only an item saved for the site stands for it later
        if warning.is_none()
            && let Some(store) = &self.store
        {
            let remembered = SiteLogin {
                site: site.to_owned(),
                item: name.clone(),
                account: login.account.clone(),
                username,
                password,
                code,
            };
            if let Err(error) = store.put_site_login(&remembered) {
                tracing::warn!(%error, site, "could not remember the site's login");
            }
        }

        Ok((
            Source::Item {
                reference,
                item: name.clone(),
            },
            name,
            warning,
        ))
    }

    /// The value for `field`, read by reference or asked of the phone
    async fn value(
        &self,
        session: &SessionName,
        field: LoginField,
        checked: &Checked,
    ) -> Result<Zeroizing<String>, String> {
        match &checked.source {
            Source::Item { reference, .. } => self
                .onepassword
                .read_reference(reference)
                .await
                .map(Zeroizing::new)
                .map_err(|error| error.to_string()),
            Source::Phone => match self.sign_ins.take(session, &checked.site, field) {
                Some(value) => Ok(value),
                None => self.ask_phone(session, field, &checked.site).await,
            },
        }
    }

    /// Asks the phone for the sign-in `field` belongs to: the username and
    /// password together, with the code's seed when every phone holds a
    /// sealed copy of it, or the code alone. Answers `field`'s value and
    /// keeps the others for their fills
    async fn ask_phone(
        &self,
        session: &SessionName,
        field: LoginField,
        site: &str,
    ) -> Result<Zeroizing<String>, String> {
        let known = self.site_login(site);
        let reference = |field: LoginField| {
            known.as_ref().and_then(|login| match field {
                LoginField::Username => login.username.clone(),
                LoginField::Password => login.password.clone(),
                LoginField::Code => login.code.clone(),
            })
        };
        let phones = self.phones();
        // a code the owner enters now could expire before its page comes,
        // so it is asked with the rest only when a seed opens instead
        let sealed_seed = reference(LoginField::Code).is_some_and(|code| {
            let companions = self.onepassword.companions();
            !phones.is_empty()
                && phones.iter().all(|phone| {
                    companions
                        .is_some_and(|companions| companions.phone_seal(phone, &code).is_some())
                })
        });
        let fields: Vec<LoginField> = match field {
            LoginField::Code => vec![LoginField::Code],
            _ if sealed_seed => vec![LoginField::Username, LoginField::Password, LoginField::Code],
            _ => vec![LoginField::Username, LoginField::Password],
        };
        let targets: Vec<ProgramTarget> = fields
            .iter()
            .map(|&field| match reference(field) {
                Some(reference) => ProgramTarget::Reference(reference),
                None => ProgramTarget::Describe(prompt::one_line(
                    &format!("{} for {site}", field.label()),
                    MAX_DESCRIPTION_CHARS,
                )),
            })
            .collect();
        // a Mac can read a reference but cannot enter a value
        let phones_only = targets
            .iter()
            .any(|target| matches!(target, ProgramTarget::Describe(_)));
        let ask = ProgramAsk {
            targets,
            reason: Some(prompt::one_line(
                &format!("sign in to {site} in browser session {session}"),
                MAX_REASON_CHARS,
            )),
            destination: Some(format!("the {site} sign-in in browser session {session}")),
            keep: None,
            phones_only,
            keep_scope: None,
            sign_in: Some(SignInAsk {
                sign_in: SignIn {
                    site: site.to_owned(),
                    account: known.as_ref().and_then(|login| login.account.clone()),
                    session: Some(session.to_string()),
                },
                fields: fields.clone(),
            }),
        };

        let read = match self.onepassword.read_for_program(&ask).await {
            Ok(ProgramRead::Values(read)) => read,
            Ok(ProgramRead::Found(_)) => {
                return Err("a Mac answered with items instead of the values".to_owned());
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut values: HashMap<LoginField, Zeroizing<String>> = HashMap::new();
        for (field, value) in fields.into_iter().zip(read.values) {
            let Some(text) = value.as_text() else {
                continue;
            };
            values.insert(field, Zeroizing::new(text.to_owned()));
            // the value's bytes are wiped as it drops
            drop(Zeroizing::new(value.into_bytes()));
        }
        let wanted = values
            .remove(&field)
            .ok_or_else(|| format!("the phone sent no {}", field.label()))?;
        self.sign_ins.hold(session, site, values);

        Ok(wanted)
    }

    /// What a takeover offers to fill, owning what it reads from
    fn offers(&self) -> Offers {
        Offers {
            store: self.store.clone(),
            companions: self.onepassword.companions().cloned(),
        }
    }
}

/// What a takeover reads its fill offers from; cheap to clone
#[derive(Clone)]
struct Offers {
    store: Option<Store>,
    companions: Option<Arc<Companions>>,
}

impl Offers {
    /// The fills `phone` could open on `site`: the remembered login's fields
    /// that it holds sealed copies of
    fn for_phone(&self, phone: &PhonePeer, site: &str) -> Vec<FillOffer> {
        let login = self
            .store
            .as_ref()
            .and_then(|store| store.site_login(site).ok().flatten());
        let (Some(login), Some(companions)) = (login, &self.companions) else {
            return Vec::new();
        };
        [
            (LoginField::Username, &login.username),
            (LoginField::Password, &login.password),
            (LoginField::Code, &login.code),
        ]
        .into_iter()
        .filter_map(|(field, reference)| {
            let reference = reference.as_ref()?;
            let sealed = companions.phone_seal(phone, reference)?;

            Some(FillOffer {
                field,
                reference: reference.clone(),
                sealed,
                item: login.item.clone(),
                account: login.account.clone(),
                site: site.to_owned(),
            })
        })
        .collect()
    }
}

#[async_trait]
impl TakeoverHost for Browsers {
    async fn takeover(
        &self,
        phone: PhonePeer,
        open: TakeoverOpen,
        input: mpsc::Receiver<PhoneMessage>,
        output: mpsc::Sender<GatewayFrame>,
    ) {
        let end = |reason: EndReason, message: String| {
            let output = output.clone();
            async move {
                let ended = GatewayMessage::Ended {
                    reason,
                    message: Some(message),
                };
                let _ = output.send(GatewayFrame::Message(ended)).await;
            }
        };
        let session = match SessionName::parse(&open.session) {
            Ok(session) => session,
            Err(error) => return end(EndReason::BrowserGone, error.to_string()).await,
        };
        let handoff = match &open.handoff {
            Some(id) => match self.handoffs.get(id) {
                Some(handoff) if handoff.session == session => Some(handoff),
                Some(_) => {
                    return end(
                        EndReason::HandoffOver,
                        "the handoff is for another session".to_owned(),
                    )
                    .await;
                }
                None => {
                    return end(EndReason::HandoffOver, "the handoff is over".to_owned()).await;
                }
            },
            None => None,
        };
        if let Some(url) = &open.start {
            tracing::info!(phone = %phone.name, %session, "starting a session for a phone");
            if let Err(error) = self.agent_browser.start(&session, url).await {
                tracing::warn!(phone = %phone.name, %session, %error, "the session did not start");
                return end(EndReason::BrowserGone, error.to_string()).await;
            }
        }
        let page = match self.agent_browser.open(&session).await {
            Ok(page) => page,
            Err(error) => {
                tracing::warn!(phone = %phone.name, %session, %error, "no browser to take over");
                return end(EndReason::BrowserGone, error.to_string()).await;
            }
        };

        let offers = self.offers();
        let offers_phone = phone.clone();
        let context = takeover::Context {
            offers: Box::new(move |site: &str| offers.for_phone(&offers_phone, site)),
            handoff_over: handoff.as_ref().map(|handoff| handoff.over()),
            redactor: Arc::clone(&self.redactor),
        };
        let outcome = takeover::run(page, open.viewport, input, output, context).await;
        tracing::info!(phone = %phone.name, %session, ?outcome, "takeover finished");
        if let (Some(answer), Some(handoff)) = (outcome.answer(), handoff) {
            handoff.finish(answer);
        }
    }

    async fn sessions(&self) -> Result<SessionList, String> {
        self.agent_browser
            .sessions()
            .await
            .map_err(|error| error.to_string())
    }

    async fn close_session(&self, session: &str) -> Result<(), String> {
        let session = SessionName::parse(session).map_err(|error| error.to_string())?;

        self.agent_browser.close(&session).await.map_err(|error| {
            tracing::warn!(%session, %error, "the session did not close");
            error.to_string()
        })
    }
}

/// The answer to `fill`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Filled {
    /// Always true; a fill that did not happen is an error
    pub filled: bool,
    /// The page the field was on
    pub url: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FillParams {
    /// The agent-browser session, such as `github`
    pub session: String,
    /// Which field has focus: `username` (or email), `password` or `code`
    /// (a one-time code)
    pub kind: Kind,
    /// The site the page must be on, such as `github.com`
    pub site: String,
    /// Press Return after filling, to submit the form
    #[serde(default)]
    pub submit: bool,
    /// The 1Password item to use, as `op://vault/item`, when the site has
    /// several saved logins or none; only used while the user is at this Mac
    #[serde(default)]
    pub item: Option<String>,
    /// Set by the gateway, never the agent, so it stays out of the schema
    #[serde(default)]
    #[schemars(skip)]
    pub checked: Option<Checked>,
}

/// The answer to `handoff`
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct HandedOff {
    /// `done` when the user finished, `cancelled` when they would not
    pub outcome: HandoffOutcome,
    /// The page the session shows now
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// How a handoff ended
#[derive(Debug, Clone, Copy, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandoffOutcome {
    /// The user tapped Done
    Done,
    /// The user tapped Cancel
    Cancelled,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HandoffParams {
    /// The agent-browser session, such as `github`
    pub session: String,
    /// What the user should do, such as `approve the passkey prompt`; shown
    /// on their phone as your words
    pub reason: String,
    /// How long to wait for them, in minutes; 30 by default, at most 120
    #[serde(default)]
    pub minutes: Option<u64>,
}

/// The MCP server, served in process over an in-memory pipe; cheap to clone
#[derive(Clone)]
pub struct BrowserServer(Arc<Browsers>);

impl BrowserServer {
    /// A server over the shared state
    pub fn new(browsers: Arc<Browsers>) -> Self {
        Self(browsers)
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

    async fn url(&self, session: &SessionName) -> Option<String> {
        let page = self.0.agent_browser.open(session).await.ok()?;

        page.state().await.ok().map(|state| state.url)
    }
}

/// The tool's error text
fn failed(message: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.to_string())])
}

#[tool_router]
impl BrowserServer {
    #[tool(
        description = "Fills the focused field of an agent-browser session's page with the \
                          user's 1Password username, password or current one-time code for \
                          `site`, without returning it. Click the field first. The page must be \
                          https on `site`, and the field must be that kind: a username or email \
                          field, a password field, or a one-time code field. Pass submit=true \
                          to press Return after it. Returns only whether it filled and the \
                          page's URL."
    )]
    async fn fill(
        &self,
        Parameters(params): Parameters<FillParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Filled>, CallToolResult> {
        let Some(checked) = params.checked else {
            return Err(failed(
                "the gateway did not check this call, so nothing was filled",
            ));
        };
        let session = SessionName::parse(&params.session).map_err(failed)?;
        let field = LoginField::from(params.kind);
        let site = site_named(&params.site).map_err(failed)?;
        if site != checked.site {
            return Err(failed("the site changed since the user approved"));
        }

        let _turn = self.0.turn.lock().await;
        // a phone pick can outlast the agent's wait; one it gave up on is
        // not filled into whatever has focus by the time the owner answers
        let value = tokio::select! {
            value = self.0.value(&session, field, &checked) => value.map_err(failed)?,
            () = context.ct.cancelled() => return Err(failed(CANCELLED)),
        };
        let value = login_value(field, value, &self.0.redactor).map_err(failed)?;

        // read again: the page may have moved on while the owner decided
        let page = self.0.agent_browser.open(&session).await.map_err(failed)?;
        let state = page.state().await.map_err(failed)?;
        let host = state.check(field, &site).map_err(failed)?;
        if host != checked.host {
            return Err(failed(format!(
                "the page is now on {host}, but the user approved filling on {}; fill again",
                checked.host
            )));
        }
        let Some(focused) = &state.focus else {
            return Err(failed("nothing has focus"));
        };
        if context.ct.is_cancelled() {
            return Err(failed(CANCELLED));
        }
        page.replace_text(focused, &value, params.submit)
            .await
            .map_err(|error| match error {
                PageError::Refused(reason) => failed(reason),
                // a CDP error never names the value
                other => failed(other),
            })?;
        drop(value);

        Ok(Json(Filled {
            filled: true,
            url: state.url,
        }))
    }

    #[tool(
        description = "Asks the user to do one step in an agent-browser session on their phone, \
                          such as a passkey, a captcha or a consent screen, and waits until they \
                          tap Done or Cancel there. `reason` says what they should do and is \
                          shown as your words. Waits up to `minutes` (30 by default, at most \
                          120). Returns the outcome and the page's URL afterwards."
    )]
    async fn handoff(
        &self,
        Parameters(params): Parameters<HandoffParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<HandedOff>, CallToolResult> {
        let session = SessionName::parse(&params.session).map_err(failed)?;
        let Some(companions) = self.0.onepassword.companions().cloned() else {
            return Err(failed("no phone is paired, so nobody can take over"));
        };
        if companions.phones().is_empty() {
            return Err(failed(
                "no phone is paired, so nobody can take over (`codemode-mcp companion invite`)",
            ));
        }
        let reason = prompt::one_line(params.reason.trim(), MAX_REASON_CHARS);
        let minutes = params
            .minutes
            .unwrap_or(HANDOFF_MINUTES)
            .clamp(1, MAX_HANDOFF_MINUTES);
        // fails early, before the phone is woken, when the session is gone
        let page = self.0.agent_browser.open(&session).await.map_err(failed)?;
        let url = page.state().await.ok().map(|state| state.url);
        drop(page);

        let open = self.0.handoffs.open(
            session.clone(),
            (!reason.is_empty()).then(|| reason.clone()),
        );
        let handoff = Arc::clone(&open.handoff);
        let offer = HandoffOffer {
            id: handoff.id.clone(),
            session: session.to_string(),
            reason: handoff.reason.clone(),
            url,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(minutes * 60);
        let offered = async {
            match companions.offer_handoff(&offer, deadline).await {
                Ok(answer) => answer,
                // a phone too old for the request can still open the
                // takeover from the push, so keep waiting
                Err(error) => {
                    tracing::warn!(%error, "no phone took the handoff request");
                    std::future::pending().await
                }
            }
        };

        let answer = tokio::select! {
            answer = handoff.answered() => answer,
            answer = offered => answer,
            () = tokio::time::sleep_until(deadline) => {
                return Err(failed(format!("the user did not finish within {minutes} minutes")));
            }
            () = context.ct.cancelled() => return Err(failed("the call was cancelled")),
        };
        handoff.finish(answer);
        drop(open);

        Ok(Json(HandedOff {
            outcome: match answer {
                HandoffAnswer::Done => HandoffOutcome::Done,
                HandoffAnswer::Cancelled => HandoffOutcome::Cancelled,
            },
            url: self.url(&session).await,
        }))
    }
}

#[tool_handler]
impl ServerHandler for BrowserServer {
    fn get_info(&self) -> McpServerConfig {
        McpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_site_is_named_by_its_registrable_domain() {
        assert_eq!(site_named("github.com").ok(), Some("github.com".to_owned()));
        assert_eq!(
            site_named("https://Gist.GitHub.com/login").ok(),
            Some("github.com".to_owned())
        );
        assert_eq!(
            site_named("me.github.io").ok(),
            Some("me.github.io".to_owned())
        );
        assert!(site_named("").is_err());
        assert!(site_named("github.com/../evil").is_err());
    }

    #[test]
    fn a_seed_becomes_a_code_and_control_characters_are_refused() {
        let redactor = Redactor::default();
        let code = login_value(
            LoginField::Code,
            Zeroizing::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_owned()),
            &redactor,
        );
        assert!(code.is_ok_and(|code| is_code(&code)));
        assert_eq!(
            login_value(
                LoginField::Code,
                Zeroizing::new(" 123456 ".to_owned()),
                &redactor
            )
            .ok()
            .map(|code| code.to_string()),
            Some("123456".to_owned())
        );
        assert_eq!(
            login_value(
                LoginField::Password,
                Zeroizing::new(" hunter2 ".to_owned()),
                &redactor
            )
            .ok()
            .map(|value| value.to_string()),
            Some(" hunter2 ".to_owned()),
            "a password keeps its spaces"
        );
        assert!(
            login_value(
                LoginField::Password,
                Zeroizing::new("hunter2\n".to_owned()),
                &redactor
            )
            .is_err(),
            "a line break would submit the form"
        );
        assert!(
            login_value(
                LoginField::Password,
                Zeroizing::new("hun\tter2".to_owned()),
                &redactor
            )
            .is_err()
        );
    }
}
