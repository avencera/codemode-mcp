//! The `browser` builtin server: signs agents in to websites in their
//! agent-browser sessions, and hands a step to the owner's phone when only
//! they can do it
//!
//! `fill` puts a 1Password username, password or one-time code into the
//! focused field of a session's page over CDP, without the value reaching
//! the agent, agent-browser or a file. The gateway checks the page before
//! asking the owner: `https` on the site the agent names, a field of that
//! kind, and no frame from another site around it. Where the value comes
//! from follows the owner (see [`vault`]): at this Mac, 1Password here
//! finds the login saved for the site and reads it by reference, so a code
//! is made fresh from its seed; away, the phone is asked at once, for the
//! whole sign-in (see [`sign_in`]). Companion Macs report no presence, so
//! they are asked as for any program read
//!
//! `handoff` asks the owner to take the session over on their phone, for a
//! passkey, a captcha or anything else that cannot be filled, and waits for
//! their Done or Cancel. The takeover itself is in [`takeover`]
//!
//! On a spoke the sessions and the page checks are the spoke's own, and the
//! rest is the hub's ([`Values::Hub`]): the hub finds the value's source
//! and holds it under a grant, the owner approves the call naming the
//! spoke on the hub, and only then does the hub send the value, once. Its
//! phones are offered the spoke's handoffs and dial the spoke to take a
//! session over (see [`crate::companion::spoke`])
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
pub mod vault;

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use companion_wire::{
    mobile::{HandoffAnswer, LoginField},
    takeover::{EndReason, GatewayFrame, GatewayMessage, PhoneMessage},
    totp::{Totp, is_code},
    wire::MAX_REASON_CHARS,
};
use iroh::EndpointId;
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
use tokio::{sync::mpsc, time::Instant};
use zeroize::Zeroizing;

use crate::{
    companion::{HandoffOffer, SessionList, TakeoverHost, TakeoverOpen, TakeoverPhone},
    config::{Builtin, ServerConfig},
    hub::{FillGrant, FillSource, HandoffCall, HandoffReply, client::HubClient},
    logins::site_of,
    prompt,
    secrets::Redactor,
};
use handoff::{Handoff, Handoffs};
use page::{AgentBrowser, PageError, SessionName};
use takeover::OffersFor;
use vault::{FillAt, Vault};

const INSTRUCTIONS: &str = "Signs in to websites in agent-browser sessions on this machine without \
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
pub(crate) const MAX_HANDOFF_MINUTES: u64 = 120;

/// Least time a `browser` server call is given: the longest handoff, and
/// time to read the page after it
pub const BROWSER_CALL_TIMEOUT: Duration = Duration::from_secs(MAX_HANDOFF_MINUTES * 60 + 60);

/// What a fill the caller stopped waiting for answers; nothing was filled
const CANCELLED: &str = "the call was cancelled before anything was filled";

/// How long a spoke waits before offering a handoff to its hub again, after
/// the hub could not be reached
const HANDOFF_RETRY: Duration = Duration::from_secs(5);

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
pub(crate) fn site_named(text: &str) -> Result<String, String> {
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
    /// The hub, which holds the source of a spoke's fill under `grant` and
    /// sends the value once the owner approved the call naming it
    Hub {
        /// The grant's id
        grant: String,
    },
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

/// The machine a browser session runs on, as the machine that holds
/// 1Password sees it
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Machine {
    /// This one
    Here,
    /// A spoke, by the id the hub trusts it under
    Spoke {
        /// The spoke's id
        id: String,
        /// Its name, as the owner knows it
        name: String,
    },
}

/// A browser session on its machine
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionAt {
    /// Where it runs
    pub machine: Machine,
    /// Its agent-browser name
    pub session: SessionName,
}

impl SessionAt {
    /// `session` on this machine
    pub fn here(session: SessionName) -> Self {
        Self {
            machine: Machine::Here,
            session,
        }
    }
}

impl std::fmt::Display for SessionAt {
    /// As the owner reads it, such as `browser session github on code`
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.machine {
            Machine::Here => write!(formatter, "browser session {}", self.session),
            Machine::Spoke { name, .. } => {
                write!(formatter, "browser session {} on {name}", self.session)
            }
        }
    }
}

/// Where a machine's `browser` servers get their values and reach the
/// owner's phones
pub enum Values {
    /// This machine's own vault and phones: the hub, or a gateway with no
    /// hub
    Here(Arc<Vault>),
    /// The hub's, for the fills the owner approves there: a spoke
    Hub(Arc<HubClient>),
}

impl Values {
    /// The vault, on the machine that holds 1Password
    pub fn vault(&self) -> Option<&Arc<Vault>> {
        match self {
            Self::Here(vault) => Some(vault),
            Self::Hub(_) => None,
        }
    }
}

/// The shared state of every `browser` server: the sign-ins and handoffs in
/// progress and what they read values through; cheap to share
pub struct Browsers {
    agent_browser: AgentBrowser,
    handoffs: Arc<Handoffs>,
    values: Values,
    redactor: Arc<Redactor>,
    /// One fill at a time, so two never check and fill over each other
    turn: tokio::sync::Mutex<()>,
}

impl Browsers {
    /// The state, reading values through `values`; on the machine that
    /// holds 1Password it runs the takeovers the phones open, and a spoke
    /// serves them on its own endpoint instead (see
    /// [`crate::companion::spoke`])
    pub fn new(values: Values, redactor: Arc<Redactor>, agent_browser: AgentBrowser) -> Arc<Self> {
        let browsers = Arc::new(Self {
            agent_browser,
            handoffs: Arc::default(),
            values,
            redactor,
            turn: tokio::sync::Mutex::new(()),
        });
        let companions = browsers.values.vault().and_then(|vault| vault.companions());
        if let Some(companions) = companions {
            let host: Arc<dyn TakeoverHost> = browsers.clone();
            companions.host_takeovers(Arc::downgrade(&host));
        }

        browsers
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

        let (source, summary) = match &self.values {
            Values::Here(vault) => {
                let at = SessionAt::here(session);
                let fill = FillAt {
                    at: &at,
                    field,
                    item: call.item.as_deref(),
                    host: &host,
                    site: &site,
                };

                vault.source(&fill).await?
            }
            Values::Hub(hub) => {
                let fill = FillSource {
                    session: session.to_string(),
                    field,
                    host: host.clone(),
                    site: site.clone(),
                    item: call.item,
                };
                match hub
                    .fill_source(&fill)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    FillGrant::Granted { grant, summary } => (Source::Hub { grant }, summary),
                    FillGrant::Refused(reason) => return Err(reason),
                }
            }
        };

        let checked = Checked { host, site, source };
        arguments.insert(
            CHECKED.to_owned(),
            serde_json::to_value(&checked).unwrap_or(Value::Null),
        );

        Ok(Some(summary))
    }

    /// The value for `field`, read by reference or asked of the phone here,
    /// or sent by the hub for the fill the owner approved there
    async fn value(
        &self,
        session: &SessionName,
        field: LoginField,
        checked: &Checked,
    ) -> Result<Zeroizing<String>, String> {
        match (&self.values, &checked.source) {
            (Values::Here(vault), source) => {
                let at = SessionAt::here(session.clone());

                vault.value(&at, field, &checked.site, source).await
            }
            (Values::Hub(hub), Source::Hub { grant }) => hub.fill_value(grant).await,
            // a spoke never reads 1Password itself for a fill
            (Values::Hub(_), _) => Err("this fill was not approved on the hub".to_owned()),
        }
    }

    /// What a takeover by the phone `phone` offers to fill on a site
    fn offers(&self, phone: EndpointId) -> OffersFor {
        match &self.values {
            Values::Here(vault) => {
                let vault = Arc::clone(vault);
                Box::new(move |site: String| {
                    let offers = vault.offers_for(phone, &site);
                    Box::pin(std::future::ready(offers))
                })
            }
            Values::Hub(hub) => {
                let hub = Arc::clone(hub);
                Box::new(move |site: String| {
                    let hub = Arc::clone(&hub);
                    Box::pin(async move {
                        hub.fill_offers(phone, &site).await.unwrap_or_else(|error| {
                            tracing::debug!(%error, "the hub sent no fill offers");
                            Vec::new()
                        })
                    })
                })
            }
        }
    }

    /// Offers `handoff` to the owner's phones until one answers on the
    /// offer; a phone that answers with a takeover instead is seen by the
    /// caller, which then drops this. Fails only when it could not be
    /// offered at all
    async fn offer_handoff(
        &self,
        handoff: &Handoff,
        url: Option<String>,
        deadline: Instant,
    ) -> Result<HandoffAnswer, String> {
        let hub = match &self.values {
            Values::Here(vault) => {
                let Some(companions) = vault.companions() else {
                    return std::future::pending().await;
                };
                let offer = HandoffOffer {
                    id: handoff.id.clone(),
                    session: handoff.session.to_string(),
                    reason: handoff.reason.clone(),
                    url,
                    machine: None,
                };

                return match companions.offer_handoff(&offer, deadline).await {
                    Ok(answer) => Ok(answer),
                    // a phone too old for the request can still open the
                    // takeover from the push, so keep waiting
                    Err(error) => {
                        tracing::warn!(%error, "no phone took the handoff request");
                        std::future::pending().await
                    }
                };
            }
            Values::Hub(hub) => hub,
        };

        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let call = HandoffCall {
                id: handoff.id.clone(),
                session: handoff.session.to_string(),
                reason: handoff.reason.clone(),
                url: url.clone(),
                expires_in_ms: u64::try_from(left.as_millis()).unwrap_or(u64::MAX),
            };
            match hub.offer_handoff(&call).await {
                Ok(HandoffReply::Answered(answer)) => return Ok(answer),
                Ok(HandoffReply::Refused(reason)) => return Err(reason),
                // the hub restarted or the link dropped; a takeover can
                // still answer it here meanwhile
                Err(error) => {
                    tracing::warn!(%error, "could not offer the handoff through the hub");
                    tokio::time::sleep(HANDOFF_RETRY).await;
                }
            }
        }
    }
}

#[async_trait]
impl TakeoverHost for Browsers {
    async fn takeover(
        &self,
        phone: TakeoverPhone,
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

        let context = takeover::Context {
            offers: self.offers(phone.id),
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

    async fn remove_session(&self, session: &str) -> Result<(), String> {
        let session = SessionName::parse(session).map_err(|error| error.to_string())?;

        self.agent_browser.remove(&session).await.map_err(|error| {
            tracing::warn!(%session, %error, "the session was not removed");
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
    /// several saved logins or none; only used while the user is at the Mac
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
        // on the hub the phones are here to check; a spoke's hub refuses
        // as soon as it is offered
        if let Values::Here(vault) = &self.0.values
            && vault.phones().is_empty()
        {
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
        let deadline = Instant::now() + Duration::from_secs(minutes * 60);
        let offered = self.0.offer_handoff(&handoff, url, deadline);

        let answer = tokio::select! {
            answer = handoff.answered() => answer,
            offered = offered => offered.map_err(failed)?,
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
