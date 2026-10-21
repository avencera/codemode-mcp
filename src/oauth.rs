//! OAuth sign-in for remote upstreams, on top of rmcp's authorization client
//!
//! A login runs discovery, dynamic client registration (unless the config
//! names a client registered ahead of time) and an authorization code flow
//! with PKCE. A registered client sends the browser back to
//! `/oauth/callback/<server>` on `public_origin` when one is configured, so
//! the sign-in can finish on a phone; a client registered ahead of time, or
//! a gateway without `public_origin`, uses the loopback admin listener, so
//! that flow completes on the Mac.
//!
//! rmcp keeps the client registration in memory and stores only the client
//! id with the tokens. Here the registration and the tokens are written
//! together, in one transaction, when the callback succeeds: a flow that is
//! abandoned halfway leaves an existing login untouched. Flows in progress
//! (PKCE verifier, CSRF state, registration) are kept in SQLite for
//! [`FLOW_TTL`], so a daemon restart mid-login does not strand the browser

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use rmcp::transport::auth::{
    AuthClient, AuthError, AuthorizationManager, AuthorizationMetadataSource, CredentialStore,
    InMemoryCredentialStore, OAuthClientConfig, StateStore, StoredAuthorizationState,
    StoredCredentials, VendorExtraTokenFields,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::Config,
    secrets::{OnePassword, Redactor, SecretError, approved::Consumer},
    store::{Store, StoreError},
};

/// How long a started login may take before its state is discarded
pub const FLOW_TTL: Duration = Duration::from_secs(10 * 60);
/// Client name used for registration when the config names none
const DEFAULT_CLIENT_NAME: &str = "codemode-mcp";
/// OAuth error codes echoed when the server's `url` cannot be read: RFC 6749
/// sections 4.1.2.1 and 5.2, and the ones later specs added
const STANDARD_ERROR_CODES: [&str; 14] = [
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
    "invalid_client",
    "invalid_grant",
    "unsupported_grant_type",
    "invalid_target",
    "interaction_required",
    "login_required",
    "consent_required",
];

/// Why an OAuth operation failed; messages are safe to print locally
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// No server with this name is configured
    #[error("no server named `{0}`")]
    UnknownServer(String),
    /// The server is configured without `oauth = true`
    #[error("server `{0}` is not configured with `oauth = true`")]
    NotOAuth(String),
    /// The admin listener has not bound yet, so no redirect URI exists
    #[error("the admin listener is not running")]
    NoCallback,
    /// The server publishes no OAuth metadata
    #[error("server `{0}` publishes no OAuth metadata")]
    NoMetadata(String),
    /// The callback does not match a login in progress
    #[error("this sign-in is unknown or expired; run `codemode-mcp oauth login` again")]
    UnknownFlow,
    /// The authorization server reported an error on the callback
    #[error("the authorization server refused the sign-in: {0}")]
    Refused(String),
    /// The authorization server took too long
    #[error("the authorization server did not answer in time")]
    TimedOut,
    /// The configured client secret could not be read from 1Password
    #[error(transparent)]
    Secret(#[from] SecretError),
    /// rmcp's OAuth client failed
    #[error("{0}")]
    Auth(#[from] AuthError),
    /// Something the authorization server returned holds a secret read for
    /// the server's `url`, so it was not stored
    #[error(
        "what the authorization server returned for `{0}` contains a secret from the server's url; nothing was stored"
    )]
    HoldsKey(String),
    /// The authorization link holds part of a secret `url` outside the
    /// `resource` parameter, so it is not shown
    #[error(
        "the authorization link for `{0}` contains a secret from the server's url; the login was not started"
    )]
    LinkHoldsUrl(String),
    /// A failure whose text could have carried a secret `url`, with it
    /// replaced
    #[error("{0}")]
    Scrubbed(String),
    /// The database failed
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A stored value could not be decoded
    #[error("corrupt stored OAuth value: {0}")]
    Corrupt(String),
}

/// The registered client, persisted next to the tokens; rmcp itself keeps
/// only the client id
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientRegistration {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    redirect_uri: String,
    #[serde(default)]
    scopes: Vec<String>,
}

impl ClientRegistration {
    fn from_config(config: &OAuthClientConfig) -> Self {
        Self {
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            redirect_uri: config.redirect_uri.clone(),
            scopes: config.scopes.clone(),
        }
    }

    fn to_config(&self) -> OAuthClientConfig {
        let mut config = OAuthClientConfig::new(&self.client_id, &self.redirect_uri)
            .with_scopes(self.scopes.clone());
        if let Some(secret) = &self.client_secret {
            config = config.with_client_secret(secret);
        }

        config
    }
}

/// Whether any string or object key in `value` holds a key, by its decoded
/// content, as is or percent-decoded
///
/// Every OAuth write goes through this: the provider controls much of what
/// is stored (issuer, scopes, vendor token fields, a registration's secret).
/// The strings are checked rather than the serialized text, because JSON
/// escaping (`\"`, `\\`) can split a key that the string holds whole
fn holds_key(value: &impl Serialize, keys: &[String]) -> bool {
    fn holds(value: &Value, keys: &[String]) -> bool {
        match value {
            Value::String(text) => Redactor::holds_any(text, keys),
            Value::Array(items) => items.iter().any(|item| holds(item, keys)),
            Value::Object(fields) => fields
                .iter()
                .any(|(name, field)| Redactor::holds_any(name, keys) || holds(field, keys)),
            // a key of digits only can come back as a number
            Value::Number(number) => Redactor::holds_any(&number.to_string(), keys),
            Value::Null | Value::Bool(_) => false,
        }
    }

    // an unserializable value cannot be checked, so it counts as holding one
    serde_json::to_value(value).map_or(true, |value| holds(&value, keys))
}

/// The credentials ready to be stored, or `None` when they hold a key
///
/// The vendor fields of the token response are not used by anything here, so
/// they are dropped before the check: an echoed `resource` is not a reason to
/// refuse a login, and the check covers exactly what will be stored
fn storable(mut credentials: StoredCredentials, keys: &[String]) -> Option<StoredCredentials> {
    if let Some(token) = credentials.token_response.as_mut() {
        token.set_extra_fields(VendorExtraTokenFields::default());
    }

    (!holds_key(&credentials, keys)).then_some(credentials)
}

fn store_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::CredentialStoreError(error.to_string())
}

/// Tokens of one server's completed login, refreshed in place
struct SqliteCredentialStore {
    store: Store,
    server: String,
    /// Values read for the server's `url`, which nothing stored may hold
    keys: Vec<String>,
}

#[async_trait]
impl CredentialStore for SqliteCredentialStore {
    async fn load(&self) -> Result<Option<StoredCredentials>, AuthError> {
        let Some((_, credentials)) = self.store.oauth_login(&self.server).map_err(store_error)?
        else {
            return Ok(None);
        };

        serde_json::from_str(&credentials)
            .map(Some)
            .map_err(store_error)
    }

    async fn save(&self, credentials: StoredCredentials) -> Result<(), AuthError> {
        let Some(credentials) = storable(credentials, &self.keys) else {
            return Err(store_error(OAuthError::HoldsKey(self.server.clone())));
        };
        let json = serde_json::to_string(&credentials).map_err(store_error)?;

        self.store
            .update_oauth_credentials(&self.server, &json)
            .map_err(store_error)
    }

    async fn clear(&self) -> Result<(), AuthError> {
        self.store
            .remove_oauth_login(&self.server)
            .map(|_| ())
            .map_err(store_error)
    }
}

/// PKCE and CSRF state of one server's flows in progress
struct SqliteStateStore {
    store: Store,
    server: String,
    /// Values read for the server's `url`, which nothing stored may hold
    keys: Vec<String>,
}

fn flow_ttl_ms() -> i64 {
    FLOW_TTL.as_millis() as i64
}

#[async_trait]
impl StateStore for SqliteStateStore {
    async fn save(
        &self,
        csrf_token: &str,
        state: StoredAuthorizationState,
    ) -> Result<(), AuthError> {
        if holds_key(&state, &self.keys) {
            return Err(store_error(OAuthError::HoldsKey(self.server.clone())));
        }
        let json = serde_json::to_string(&state).map_err(store_error)?;

        self.store
            .save_oauth_pending(&self.server, csrf_token, &json, flow_ttl_ms())
            .map_err(store_error)
    }

    async fn load(&self, csrf_token: &str) -> Result<Option<StoredAuthorizationState>, AuthError> {
        let Some((state, _)) = self
            .store
            .oauth_pending(&self.server, csrf_token, flow_ttl_ms())
            .map_err(store_error)?
        else {
            return Ok(None);
        };

        serde_json::from_str(&state).map(Some).map_err(store_error)
    }

    async fn delete(&self, csrf_token: &str) -> Result<(), AuthError> {
        self.store
            .delete_oauth_pending(&self.server, csrf_token)
            .map_err(store_error)
    }
}

/// How a server's login obtains its client
#[derive(Debug, Clone)]
enum ClientSource {
    /// Dynamic client registration under this client name
    Register(String),
    /// A client registered ahead of time; the secret may hold `op://`
    /// references
    Known { id: String, secret: Option<String> },
}

/// OAuth settings of one configured server
#[derive(Debug, Clone)]
struct OAuthServer {
    /// The server as configured, which its values must be approved for
    consumer: Consumer,
    /// As configured: it may hold references and is read only when used
    url: String,
    scopes: Vec<String>,
    client: ClientSource,
    authorization_params: BTreeMap<String, String>,
}

/// Login state of one server, safe to print
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStatus {
    /// Server name
    pub server: String,
    /// Whether tokens are stored
    pub logged_in: bool,
    /// Scopes the authorization server granted
    pub scopes: Vec<String>,
    /// When the access token expires, ms since the epoch, if known
    pub expires_at_ms: Option<i64>,
    /// Whether a refresh token is stored, so expiry renews automatically
    pub refreshable: bool,
}

/// What a callback carries back from the authorization server
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Callback {
    /// Authorization code
    pub code: Option<String>,
    /// CSRF state
    pub state: Option<String>,
    /// RFC 9207 issuer
    pub iss: Option<String>,
    /// Error code when the user or server refused
    pub error: Option<String>,
    /// Human-readable error
    pub error_description: Option<String>,
}

/// Logins of every `oauth = true` server
pub struct OAuth {
    store: Store,
    /// Reads client secrets at login and `url` references
    onepassword: OnePassword,
    /// Keeps a resolved `url` out of error text; rmcp's errors print it
    redactor: Arc<Redactor>,
    servers: BTreeMap<String, OAuthServer>,
    /// Every configured server, to tell unknown names from non-OAuth ones
    configured: BTreeSet<String>,
    /// `http://127.0.0.1:<admin port>`, set once the admin listener binds
    callback_base: RwLock<Option<String>>,
    /// The configured `public_origin` without a trailing slash; the default
    /// `localhost` origin is not reachable from a phone, so it is not used
    public_base: Option<String>,
}

impl OAuth {
    /// The OAuth servers of `config`, with logins kept in `store` and client
    /// secrets read through `onepassword`
    pub fn new(config: &Config, store: Store, onepassword: OnePassword) -> Arc<Self> {
        let servers = config
            .servers
            .iter()
            .filter(|(_, server)| server.oauth)
            .filter_map(|(name, server)| {
                let client = match &server.client_id {
                    Some(id) => ClientSource::Known {
                        id: id.clone(),
                        secret: server.client_secret.clone(),
                    },
                    None => ClientSource::Register(
                        server
                            .client_name
                            .clone()
                            .unwrap_or_else(|| DEFAULT_CLIENT_NAME.to_owned()),
                    ),
                };

                Some((
                    name.clone(),
                    OAuthServer {
                        consumer: Consumer::of(name, server),
                        url: server.url.clone()?,
                        scopes: server.scopes.clone(),
                        client,
                        authorization_params: server.authorization_params.clone(),
                    },
                ))
            })
            .collect();

        Arc::new(Self {
            store,
            onepassword,
            redactor: Redactor::shared(config),
            servers,
            configured: config.servers.keys().cloned().collect(),
            callback_base: RwLock::new(None),
            public_base: config.public_origin.as_ref().map(|_| config.public_base()),
        })
    }

    /// Records the admin listener's address; redirect URIs point at it
    pub fn set_callback_address(&self, admin: SocketAddr) {
        let base = format!("http://127.0.0.1:{}", admin.port());
        if let Ok(mut slot) = self.callback_base.write() {
            *slot = Some(base);
        }
    }

    /// Redirect URI for `server`
    ///
    /// A client registered ahead of time keeps the loopback URI, since the
    /// provider only accepts the redirect URIs it was registered with
    fn redirect_uri(&self, server: &str, client: &ClientSource) -> Result<String, OAuthError> {
        let base = match (client, &self.public_base) {
            (ClientSource::Register(_), Some(public)) => public.clone(),
            _ => self
                .callback_base
                .read()
                .ok()
                .and_then(|slot| slot.clone())
                .ok_or(OAuthError::NoCallback)?,
        };

        Ok(format!("{base}/oauth/callback/{server}"))
    }

    /// The page on `public_origin` that starts a sign-in to `server` and
    /// works from any device that reaches it; `None` without a
    /// `public_origin`, or when that sign-in can only finish on the Mac
    pub fn login_page(&self, server: &str) -> Option<String> {
        let public = self.public_base.as_ref()?;
        let configured = self.servers.get(server)?;

        matches!(configured.client, ClientSource::Register(_))
            .then(|| format!("{public}/oauth/login/{server}"))
    }

    /// Names of the OAuth servers
    pub fn servers(&self) -> impl Iterator<Item = &str> {
        self.servers.keys().map(String::as_str)
    }

    fn server(&self, name: &str) -> Result<&OAuthServer, OAuthError> {
        self.servers.get(name).ok_or_else(|| {
            if self.configured.contains(name) {
                OAuthError::NotOAuth(name.to_owned())
            } else {
                OAuthError::UnknownServer(name.to_owned())
            }
        })
    }

    /// The server's `url` with its references read, and the parts of it an
    /// issuer must not hold
    ///
    /// The same reader every connection uses, so the placement and value
    /// rules hold before any HTTP request. Nothing is stored under it:
    /// logins, flows and registrations are all keyed by the server name, so
    /// a key in the URL never reaches the database
    async fn resolved_url(
        &self,
        server: &OAuthServer,
    ) -> Result<(String, Vec<String>), OAuthError> {
        let resolved = self
            .onepassword
            .resolve_url(Some(&server.consumer), &server.url)
            .await?;
        self.redactor.add(resolved.secrets);
        self.redactor.add_keys(resolved.fragile);

        Ok((resolved.url, resolved.keys))
    }

    /// Replaces a secret `url` in the text of a failure
    fn scrub(&self, error: OAuthError) -> OAuthError {
        match error {
            OAuthError::Auth(_) | OAuthError::Refused(_) | OAuthError::Corrupt(_) => {
                OAuthError::Scrubbed(self.redactor.apply(&error.to_string()))
            }
            other => other,
        }
    }

    /// A manager with discovered metadata; refuses servers that publish none
    async fn discovered(
        &self,
        name: &str,
    ) -> Result<(AuthorizationManager, Vec<String>), OAuthError> {
        let server = self.server(name)?;
        let (url, keys) = self.resolved_url(server).await?;
        let mut manager = AuthorizationManager::new(url.as_str()).await?;
        let resolution = manager.resolve_metadata().await?;
        if resolution.source == AuthorizationMetadataSource::LegacyEndpointFallback {
            return Err(OAuthError::NoMetadata(name.to_owned()));
        }
        // the endpoints as the provider wrote them, before rmcp parses and
        // normalizes them (`\` becomes `/`), which could hide a key
        let metadata = resolution.metadata;
        let endpoints = [
            Some(metadata.authorization_endpoint.as_str()),
            Some(metadata.token_endpoint.as_str()),
            metadata.registration_endpoint.as_deref(),
        ];
        if endpoints
            .into_iter()
            .flatten()
            .any(|endpoint| Redactor::holds_any(endpoint, &keys))
        {
            return Err(OAuthError::LinkHoldsUrl(name.to_owned()));
        }
        manager.set_metadata(metadata);
        manager.set_state_store(SqliteStateStore {
            store: self.store.clone(),
            server: name.to_owned(),
            keys: keys.clone(),
        });

        Ok((manager, keys))
    }

    /// Starts a login: discovery, client registration and a PKCE
    /// authorization URL for the browser
    pub async fn start_login(&self, name: &str) -> Result<String, OAuthError> {
        self.begin_login(name)
            .await
            .map_err(|error| self.scrub(error))
    }

    async fn begin_login(&self, name: &str) -> Result<String, OAuthError> {
        let server = self.server(name)?.clone();
        let redirect_uri = self.redirect_uri(name, &server.client)?;
        let (mut manager, keys) = self.discovered(name).await?;

        let defaults: Vec<&str> = server.scopes.iter().map(String::as_str).collect();
        let scopes = manager.select_scopes(None, &defaults);
        let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
        let registered = match &server.client {
            ClientSource::Register(client_name) => {
                manager
                    .register_client(client_name, &redirect_uri, &scopes)
                    .await?
            }
            ClientSource::Known { id, secret } => {
                let mut config = OAuthClientConfig::new(id, &redirect_uri)
                    .with_scopes(scopes.iter().map(|scope| (*scope).to_owned()).collect());
                if let Some(secret) = secret {
                    config = config.with_client_secret(self.read_secret(&server, secret).await?);
                }
                manager.configure_client(config.clone())?;

                config
            }
        };
        let url = manager.get_authorization_url(&scopes).await?;
        let url = with_params(&url, &server.authorization_params)?;
        let url = checked_link(&url, &keys, name)?;

        // the state store row exists now; attach the registration to it so
        // the callback can rebuild the client
        let csrf = reqwest::Url::parse(&url)
            .ok()
            .and_then(|parsed| {
                parsed
                    .query_pairs()
                    .find(|(key, _)| key == "state")
                    .map(|(_, value)| value.into_owned())
            })
            .ok_or_else(|| OAuthError::Corrupt("authorization URL has no state".into()))?;
        let registration = ClientRegistration::from_config(&registered);
        if holds_key(&registration, &keys) {
            self.store.delete_oauth_pending(name, &csrf)?;

            return Err(OAuthError::HoldsKey(name.to_owned()));
        }
        let client = serde_json::to_string(&registration)
            .map_err(|error| OAuthError::Corrupt(error.to_string()))?;
        if !self.store.set_oauth_pending_client(name, &csrf, &client)? {
            return Err(OAuthError::Corrupt("the login state was not stored".into()));
        }

        Ok(url)
    }

    /// What to say about a refused callback
    ///
    /// After a restart the redactor knows nothing of a templated `url` until
    /// it is read, and the provider's text may hold it, so it is read first,
    /// but only for a callback that answers a login in progress: anyone who
    /// reaches the callback could otherwise raise a 1Password prompt. When
    /// the url is not read, the text is not echoed: only the error code, if
    /// it is a standard OAuth error code
    async fn refusal(
        &self,
        server: &OAuthServer,
        pending: bool,
        error: &str,
        description: Option<&str>,
    ) -> String {
        // only the redactor's learning matters here
        if !server.url.contains("{{") || (pending && self.resolved_url(server).await.is_ok()) {
            return description.unwrap_or(error).to_owned();
        }

        if STANDARD_ERROR_CODES.contains(&error) {
            format!("the authorization server reported `{error}`")
        } else {
            "the authorization server reported an error".to_owned()
        }
    }

    /// `server`'s client `secret` with its `op://` references read from
    /// 1Password
    async fn read_secret(&self, server: &OAuthServer, secret: &str) -> Result<String, OAuthError> {
        let values = BTreeMap::from([(String::new(), secret.to_owned())]);
        let mut resolved = self
            .onepassword
            .resolve(Some(&server.consumer), &values)
            .await?;

        resolved
            .values
            .remove("")
            .ok_or_else(|| OAuthError::Corrupt("the client secret was not resolved".into()))
    }

    /// Completes a login from the browser's callback and stores the
    /// registration with the tokens
    pub async fn finish_login(&self, name: &str, callback: &Callback) -> Result<(), OAuthError> {
        self.complete_login(name, callback)
            .await
            .map_err(|error| self.scrub(error))
    }

    async fn complete_login(&self, name: &str, callback: &Callback) -> Result<(), OAuthError> {
        let server = self.server(name)?;
        if let Some(error) = &callback.error {
            let mut pending = false;
            if let Some(csrf) = &callback.state {
                pending = self
                    .store
                    .oauth_pending(name, csrf, flow_ttl_ms())?
                    .is_some();
                self.store.delete_oauth_pending(name, csrf)?;
            }

            return Err(OAuthError::Refused(
                self.refusal(
                    server,
                    pending,
                    error,
                    callback.error_description.as_deref(),
                )
                .await,
            ));
        }
        let (Some(code), Some(csrf)) = (&callback.code, &callback.state) else {
            return Err(OAuthError::UnknownFlow);
        };
        let Some((_, Some(client))) = self.store.oauth_pending(name, csrf, flow_ttl_ms())? else {
            return Err(OAuthError::UnknownFlow);
        };
        let registration: ClientRegistration = serde_json::from_str(&client)
            .map_err(|error| OAuthError::Corrupt(error.to_string()))?;

        let (mut manager, keys) = self.discovered(name).await?;
        // the tokens land here first and reach SQLite only together with
        // the registration
        let staging = InMemoryCredentialStore::new();
        manager.set_credential_store(staging.clone());
        manager.configure_client(registration.to_config())?;
        manager
            .exchange_code_for_token_with_issuer(code, csrf, callback.iss.as_deref())
            .await?;

        let credentials = staging
            .load()
            .await?
            .ok_or_else(|| OAuthError::Corrupt("no tokens after the exchange".into()))?;
        // fail closed: the credentials are stored verbatim
        let credentials =
            storable(credentials, &keys).ok_or_else(|| OAuthError::HoldsKey(name.to_owned()))?;
        let credentials = serde_json::to_string(&credentials)
            .map_err(|error| OAuthError::Corrupt(error.to_string()))?;
        self.store.save_oauth_login(name, &client, &credentials)?;

        Ok(())
    }

    /// An HTTP client that signs requests with the stored tokens and
    /// refreshes them as they expire; `None` when the server has no login
    pub async fn authorized_client(
        &self,
        name: &str,
    ) -> Result<Option<AuthClient<reqwest::Client>>, OAuthError> {
        self.signed_client(name)
            .await
            .map_err(|error| self.scrub(error))
    }

    async fn signed_client(
        &self,
        name: &str,
    ) -> Result<Option<AuthClient<reqwest::Client>>, OAuthError> {
        let server = self.server(name)?;
        let Some((client, _)) = self.store.oauth_login(name)? else {
            return Ok(None);
        };
        let registration: ClientRegistration = serde_json::from_str(&client)
            .map_err(|error| OAuthError::Corrupt(error.to_string()))?;

        let (url, keys) = self.resolved_url(server).await?;
        let mut manager = AuthorizationManager::new(url.as_str()).await?;
        manager.set_credential_store(SqliteCredentialStore {
            store: self.store.clone(),
            server: name.to_owned(),
            keys,
        });
        // false when the tokens were dropped, e.g. after the issuer changed
        if !manager.initialize_from_store().await? {
            return Ok(None);
        }
        // restores the client secret, which rmcp does not persist
        manager.configure_client(registration.to_config())?;

        Ok(Some(AuthClient::new(reqwest::Client::new(), manager)))
    }

    /// Login state of every OAuth server
    pub fn status(&self) -> Result<Vec<LoginStatus>, OAuthError> {
        let mut statuses = Vec::new();
        for name in self.servers.keys() {
            let Some((_, credentials)) = self.store.oauth_login(name)? else {
                statuses.push(LoginStatus {
                    server: name.clone(),
                    logged_in: false,
                    scopes: Vec::new(),
                    expires_at_ms: None,
                    refreshable: false,
                });
                continue;
            };
            // read as plain JSON so token values never pass through a typed
            // value that might be printed
            let value: Value = serde_json::from_str(&credentials)
                .map_err(|error| OAuthError::Corrupt(error.to_string()))?;
            let token = &value["token_response"];
            let expires_at_ms = match (
                value["token_received_at"].as_i64(),
                token["expires_in"].as_i64(),
            ) {
                (Some(received), Some(seconds)) => Some((received + seconds) * 1000),
                _ => None,
            };

            statuses.push(LoginStatus {
                server: name.clone(),
                logged_in: token.is_object(),
                scopes: value["granted_scopes"]
                    .as_array()
                    .map(|scopes| {
                        scopes
                            .iter()
                            .filter_map(|scope| scope.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
                expires_at_ms,
                refreshable: token["refresh_token"].is_string(),
            });
        }

        Ok(statuses)
    }

    /// Forgets a server's login, returning whether one existed
    pub fn logout(&self, name: &str) -> Result<bool, OAuthError> {
        self.server(name)?;

        Ok(self.store.remove_oauth_login(name)?)
    }
}

/// The authorization link to show, or an error when it holds a key
///
/// rmcp sets `resource` to the server's URL, which holds a key when the key
/// is embedded in it. The parameter is kept unless its value holds a key:
/// stripping it can make an RFC 8707 server, which also sees `resource` on
/// the token request, reject the login, but a key in a link that agents and
/// the CLI print is worse. Anything else in the link that holds a key refuses
/// the login
fn checked_link(link: &str, keys: &[String], server: &str) -> Result<String, OAuthError> {
    if keys.is_empty() {
        return Ok(link.to_owned());
    }
    let parsed =
        reqwest::Url::parse(link).map_err(|error| OAuthError::Corrupt(error.to_string()))?;
    let resource_holds_key = parsed
        .query_pairs()
        .filter(|(name, _)| name == "resource")
        .any(|(_, value)| Redactor::holds_any(&value, keys));
    let link = if resource_holds_key {
        without_param(link, "resource")?
    } else {
        link.to_owned()
    };
    if Redactor::holds_any(&link, keys) {
        return Err(OAuthError::LinkHoldsUrl(server.to_owned()));
    }

    Ok(link)
}

/// `url` without the query parameter `name`
fn without_param(url: &str, name: &str) -> Result<String, OAuthError> {
    let mut parsed =
        reqwest::Url::parse(url).map_err(|error| OAuthError::Corrupt(error.to_string()))?;
    let kept: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    parsed.query_pairs_mut().clear().extend_pairs(kept);

    Ok(parsed.into())
}

/// `url` with `params` added to its query, replacing any of the same name
fn with_params(url: &str, params: &BTreeMap<String, String>) -> Result<String, OAuthError> {
    if params.is_empty() {
        return Ok(url.to_owned());
    }
    let mut parsed =
        reqwest::Url::parse(url).map_err(|error| OAuthError::Corrupt(error.to_string()))?;
    let kept: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(key, _)| !params.contains_key(key.as_ref()))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    parsed
        .query_pairs_mut()
        .clear()
        .extend_pairs(kept)
        .extend_pairs(params);

    Ok(parsed.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::holds_key;

    #[test]
    fn strings_are_checked_by_their_decoded_content_not_their_json_escapes() {
        // JSON escaping turns the quote into `\"`, which splits the key in
        // the serialized text but not in the string
        let keys = [r#"abc"def"ghi123"#.to_owned()];

        assert!(holds_key(
            &json!({ "client_secret": r#"abc"def%22ghi123"# }),
            &keys
        ));
        assert!(holds_key(
            &json!({ "nested": [r#"ABC"DEF"GHI123"#] }),
            &keys
        ));
        assert!(holds_key(&json!({ r#"abc"def"ghi123"#: 1 }), &keys));
        assert!(!holds_key(
            &json!({ "client_secret": "unrelated-value" }),
            &keys
        ));
    }
}
