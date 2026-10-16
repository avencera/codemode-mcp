//! The `logins` builtin server: types a 1Password username or password into
//! the focused field of a page on the login's sites, so an agent driving the
//! Mac can sign in without the value entering its context
//!
//! The daemon decides where a value may go, from what Accessibility reports
//! rather than what the agent says: a password only into a password field,
//! which shows bullets, and either only on an `https` page whose host is one
//! of the login's `sites`. The value is read through the same 1Password
//! reader as server secrets, so a companion Mac or a phone can answer it,
//! and the tool answers with the host it filled on, never the value

use std::{collections::BTreeMap, sync::Arc};

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::LoginConfig,
    mac::Mac,
    secrets::{OnePassword, Redactor},
};

const INSTRUCTIONS: &str = "Signs in to websites on this Mac with logins from 1Password, \
     without showing you the username or password. Click the field first, so it has keyboard \
     focus, then call fill. A password goes only into a password field, and a username only into a \
     text field, on an https page whose host is one of the login's sites. The answer says which \
     host it filled; the value itself is never returned.";

/// What kind of field has keyboard focus
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// A password field, which shows bullets instead of its text
    Secure,
    /// A one-line text field
    Text,
    /// Anything else, such as a text area, a button or no element at all
    Other,
}

/// The element with keyboard focus, as Accessibility reports it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusedField {
    /// Kind of field
    pub kind: FieldKind,
    /// Addresses of the pages around the field, innermost first: a field in
    /// a frame lists the frame, then each page holding it. Empty outside a
    /// web page
    pub pages: Vec<String>,
}

/// Which login field to fill
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LoginField {
    Username,
    Password,
}

impl LoginField {
    fn name(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
        }
    }
}

/// Where one login field may be typed: the kind of field and the sites
#[derive(Debug, Clone)]
pub struct FieldRule {
    /// The field being filled
    pub field: LoginField,
    /// Hosts a page must be on: `github.com` is that host only, and
    /// `*.github.com` any host under it
    pub sites: Vec<String>,
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
    /// The server checks this before reading the value, so a wrong field
    /// never asks the owner for anything, and the Mac again right before
    /// typing. Every page around the field must pass, so a frame from
    /// elsewhere inside a login page is refused even when the browser does
    /// not report the frame as a page of its own
    pub fn check(&self, focused: &FocusedField) -> Result<String, FillError> {
        let refuse = |reason: String| Err(FillError::Refused(reason));
        match (self.field, focused.kind) {
            (LoginField::Password, FieldKind::Secure) | (LoginField::Username, FieldKind::Text) => {
            }
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
        }

        let Some((innermost, outer)) = focused.pages.split_first() else {
            return refuse("the focused field is not on a web page".to_owned());
        };
        let host = self.page_host(innermost)?;
        for page in outer {
            self.page_host(page)?;
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
                ]
                .into_iter()
                .flatten()
                .collect(),
            })
            .collect();

        Json(LoginList { logins })
    }

    #[tool(
        description = "Types a login's username or password into the field that has keyboard \
                          focus, without returning it. Click an empty field first. A password goes \
                          only into a password field, a username only into a text field, and \
                          either only on an https page of one of the login's sites."
    )]
    async fn fill(
        &self,
        Parameters(params): Parameters<FillParams>,
    ) -> Result<Json<Filled>, CallToolResult> {
        let Some(login) = self.0.logins.get(&params.login) else {
            return Err(failed(format!(
                "no login named `{}`; call list for the names",
                params.login
            )));
        };
        let reference = match params.field {
            LoginField::Username => login.username.as_deref(),
            LoginField::Password => login.password.as_deref(),
        };
        let Some(reference) = reference else {
            return Err(failed(format!(
                "the login `{}` has no {}",
                params.login,
                params.field.name()
            )));
        };
        let Some(mac) = &self.0.mac else {
            return Err(failed(
                "filling needs the Mac's screen, which this process cannot reach",
            ));
        };
        let rule = FieldRule {
            field: params.field,
            sites: login.sites.clone(),
        };

        let _turn = TURN.lock().await;
        // before the read, so a wrong field never puts a prompt in front of
        // the owner; the Mac checks again right before typing
        let focused = mac.focused_field().await.map_err(failed)?;
        rule.check(&focused).map_err(failed)?;

        let value = self
            .0
            .onepassword
            .read_reference(reference)
            .await
            .map_err(failed)?;
        // a line break or tab would act on the page, such as submitting the
        // form, instead of landing in the field
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(failed(format!(
                "the {} in 1Password is empty or holds a control character such as a line \
                 break, so it was not typed",
                params.field.name()
            )));
        }
        // a username such as an email address also appears in other
        // servers' results, which redacting it would garble; neither is
        // ever returned here
        if params.field == LoginField::Password {
            self.0.redactor.add([value.clone()]);
        }
        let host = mac.fill(&value, &rule).await.map_err(failed)?;

        Ok(Json(Filled {
            login: params.login,
            field: params.field,
            host,
        }))
    }
}

#[tool_handler]
impl ServerHandler for LoginsServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
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
        }
    }

    fn page(kind: FieldKind, url: &str) -> FocusedField {
        FocusedField {
            kind,
            pages: vec![url.to_owned()],
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
                kind: FieldKind::Secure,
                pages: Vec::new(),
            },
            // a frame on the site inside a page that is not
            FocusedField {
                kind: FieldKind::Secure,
                pages: vec![
                    "https://github.com/login".to_owned(),
                    "https://evil.example/".to_owned(),
                ],
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
