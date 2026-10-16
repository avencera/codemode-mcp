//! OAuth against a small local authorization server and an MCP endpoint
//! that refuses anonymous clients: discovery, registration or a client
//! registered ahead of time, PKCE, the loopback callback, refresh and logout

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Form, Json, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rmcp::{
    ServerHandler,
    model::{ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::harness::{Harness, Setup, TestResult};

/// The protected MCP server's only tool
#[derive(Clone)]
pub(super) struct Locked;

#[tool_router]
impl Locked {
    #[tool(description = "Says hello to signed-in clients.")]
    async fn hello(&self) -> String {
        "hello".to_owned()
    }
}

#[tool_handler]
impl ServerHandler for Locked {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[derive(Default)]
struct Issued {
    /// PKCE challenge of each authorization code handed out
    codes: Mutex<HashMap<String, String>>,
    tokens: AtomicUsize,
    refreshes: AtomicUsize,
}

/// The client the mock's token endpoint accepts
#[derive(Clone, Copy)]
enum Client {
    /// A public client registered dynamically as `mock-client`
    Registered,
    /// `known-client`, registered ahead of time with a secret it sends with
    /// HTTP Basic auth, as Google's clients do; the mock offers no
    /// registration endpoint, as Google's authorization server does not
    Known,
}

impl Client {
    fn id(self) -> &'static str {
        match self {
            Self::Registered => "mock-client",
            Self::Known => "known-client",
        }
    }
}

/// Ways the mock authorization server departs from a plain one
#[derive(Clone, Default)]
struct Quirks {
    /// Appended to the `resource` its protected-resource metadata names
    resource_suffix: Option<String>,
    /// Path of its authorization endpoint, `/authorize` by default
    authorize_path: Option<String>,
    /// Path of the resource its protected-resource metadata names, `/mcp`
    /// by default
    resource_path: Option<String>,
    /// Its whole authorization endpoint, which replaces the path
    authorize_url: Option<String>,
    /// Added to the token response of an authorization code grant
    login_extra: Option<Value>,
    /// Added to the token response of a refresh grant
    refresh_extra: Option<Value>,
    /// Its `scopes_supported`, `mcp:tools` by default
    scopes_supported: Option<Vec<String>>,
    /// Secret its registration endpoint hands out with the client
    register_secret: Option<String>,
}

#[derive(Clone)]
struct Mock {
    base: String,
    client: Client,
    issued: Arc<Issued>,
    /// Appended to the issuer the metadata names
    issuer_path: String,
    /// Makes registration fail with this text in the error
    register_echo: Option<String>,
    quirks: Quirks,
}

async fn require_token(State(mock): State<Mock>, request: Request, next: Next) -> Response {
    let authorized = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("Bearer tok-"));
    if authorized {
        return next.run(request).await;
    }

    let challenge = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\"",
        mock.base
    );
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }

    response
}

async fn protected_resource(State(mock): State<Mock>) -> Json<Value> {
    Json(json!({
        "resource": format!(
            "{}{}{}",
            mock.base,
            mock.quirks.resource_path.as_deref().unwrap_or("/mcp"),
            mock.quirks.resource_suffix.as_deref().unwrap_or_default()
        ),
        "authorization_servers": [format!("{}{}", mock.base, mock.issuer_path)],
    }))
}

async fn authorization_server(State(mock): State<Mock>) -> Json<Value> {
    let mut metadata = json!({
        "issuer": format!("{}{}", mock.base, mock.issuer_path),
        "authorization_endpoint": mock.quirks.authorize_url.clone().unwrap_or_else(|| format!(
            "{}{}",
            mock.base,
            mock.quirks.authorize_path.as_deref().unwrap_or("/authorize")
        )),
        "token_endpoint": format!("{}/token", mock.base),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": mock.quirks.scopes_supported.clone().unwrap_or_else(|| vec!["mcp:tools".to_owned()]),
    });
    if let Client::Registered = mock.client {
        metadata["registration_endpoint"] = json!(format!("{}/register", mock.base));
    }

    Json(metadata)
}

async fn register(State(mock): State<Mock>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if let Some(echo) = &mock.register_echo {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_client_metadata",
                "error_description": format!("cannot register for {echo}"),
            })),
        );
    }

    let mut client = json!({
        "client_id": "mock-client",
        "redirect_uris": body["redirect_uris"],
        "token_endpoint_auth_method": "none",
    });
    if let Some(secret) = &mock.quirks.register_secret {
        client["client_secret"] = json!(secret);
    }

    (StatusCode::CREATED, Json(client))
}

async fn token(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let grant = form.get("grant_type").map(String::as_str);
    let valid = match grant {
        Some("authorization_code") => form
            .get("code")
            .and_then(|code| lock(&mock.issued.codes).remove(code))
            .is_some_and(|_| form.get("code_verifier").is_some_and(|v| v.len() >= 43)),
        Some("refresh_token") => {
            mock.issued.refreshes.fetch_add(1, Ordering::SeqCst);
            form.get("refresh_token")
                .is_some_and(|token| token.starts_with("refresh-"))
        }
        _ => false,
    };
    let client_valid = match mock.client {
        Client::Registered => form.get("client_id").map(String::as_str) == Some("mock-client"),
        // base64 of `known-client:known-secret`
        Client::Known => {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                == Some("Basic a25vd24tY2xpZW50Omtub3duLXNlY3JldA==")
        }
    };
    if !valid || !client_valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }

    let n = mock.issued.tokens.fetch_add(1, Ordering::SeqCst);
    // short-lived, so every use goes through rmcp's refresh
    let mut body = json!({
        "access_token": format!("tok-{n}"),
        "token_type": "Bearer",
        "expires_in": 5,
        "refresh_token": format!("refresh-{n}"),
        "scope": "mcp:tools",
    });
    let extra = match grant {
        Some("refresh_token") => &mock.quirks.refresh_extra,
        _ => &mock.quirks.login_extra,
    };
    if let (Some(Value::Object(extra)), Value::Object(fields)) = (extra, &mut body) {
        fields.extend(extra.clone());
    }

    Json(body).into_response()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Starts the mock and returns its base URL
async fn start_mock(client: Client) -> Result<Mock, Box<dyn std::error::Error>> {
    start_mock_with(client, String::new(), None).await
}

/// A mock whose issuer carries `issuer_path` and whose registration, when
/// `register_echo` is set, fails with that text
async fn start_mock_with(
    client: Client,
    issuer_path: String,
    register_echo: Option<String>,
) -> Result<Mock, Box<dyn std::error::Error>> {
    start_mock_quirky(client, issuer_path, register_echo, Quirks::default()).await
}

async fn start_mock_quirky(
    client: Client,
    issuer_path: String,
    register_echo: Option<String>,
    quirks: Quirks,
) -> Result<Mock, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mock = Mock {
        base: format!("http://127.0.0.1:{}", listener.local_addr()?.port()),
        client,
        issued: Arc::new(Issued::default()),
        issuer_path,
        register_echo,
        quirks,
    };

    let mcp = StreamableHttpService::new(
        || Ok(Locked),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().disable_allowed_hosts(),
    );
    let protected = Router::new()
        .route_service("/", mcp.clone())
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(mock.clone(), require_token));
    let router = Router::new()
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server),
        )
        .route(
            "/.well-known/oauth-authorization-server/{*issuer_path}",
            get(authorization_server),
        )
        .route("/register", post(register))
        .route("/token", post(token))
        .with_state(mock.clone())
        .merge(protected);
    tokio::spawn(async move { axum::serve(listener, router).await });

    Ok(mock)
}

async fn health_of(harness: &Harness, server: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let health: Value = harness
        .http
        .get(format!("{}/healthz", harness.base()))
        .send()
        .await?
        .json()
        .await?;

    health["upstreams"]
        .as_array()
        .and_then(|upstreams| upstreams.iter().find(|upstream| upstream["name"] == server))
        .cloned()
        .ok_or_else(|| format!("no {server} in {health}").into())
}

async fn wait_for_state(
    harness: &Harness,
    server: &str,
    state: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    for _ in 0..100 {
        let upstream = health_of(harness, server).await?;
        if upstream["state"] == state {
            return Ok(upstream);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(format!("{server} never reached {state}").into())
}

fn query_value(url: &str, key: &str) -> Option<String> {
    reqwest::Url::parse(url).ok().and_then(|url| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
    })
}

/// Starts a login and plays the authorization server's part of the
/// browser redirect: issues a code for the PKCE challenge. Returns the
/// callback URL and the authorization URL
async fn begin_login(
    harness: &Harness,
    mock: &Mock,
    server: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let (status, body) = harness
        .admin_json("/admin/oauth/login", &json!({ "server": server }))
        .await?;
    assert_eq!(status, 200, "{body}");
    let url = body["authorization_url"].as_str().ok_or("no url")?;
    assert!(
        url.starts_with(&format!("{}/authorize?", mock.base)),
        "{url}"
    );
    assert_eq!(
        query_value(url, "client_id").as_deref(),
        Some(mock.client.id())
    );
    assert_eq!(
        query_value(url, "code_challenge_method").as_deref(),
        Some("S256")
    );
    let challenge = query_value(url, "code_challenge").ok_or("no challenge")?;
    let redirect = query_value(url, "redirect_uri").ok_or("no redirect")?;
    assert_eq!(
        redirect,
        format!("{}/oauth/callback/{server}", harness.admin_base())
    );
    let state = query_value(url, "state").ok_or("no state")?;

    let code = format!("code-{}", uuid::Uuid::new_v4().simple());
    lock(&mock.issued.codes).insert(code.clone(), challenge);

    Ok((
        format!("{redirect}?code={code}&state={state}"),
        url.to_owned(),
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_unlocks_a_server_that_refuses_anonymous_clients() -> TestResult {
    let mock = start_mock(Client::Registered).await?;
    let extra = format!(
        "[servers.locked]\nurl = \"{}/mcp\"\noauth = true\nclient_name = \"codemode test\"",
        mock.base
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    // anonymous access is refused: needs_login, and no tools in the catalog
    let upstream = wait_for_state(&harness, "locked", "needs_login").await?;
    assert_eq!(upstream["tools"], 0, "{upstream}");
    assert!(
        harness
            .app
            .gateway()
            .catalog()
            .entries()
            .iter()
            .all(|entry| entry.server != "locked")
    );

    // a forged callback finds no flow
    let forged = harness
        .http
        .get(format!(
            "{}/oauth/callback/locked?code=x&state=forged",
            harness.admin_base()
        ))
        .send()
        .await?;
    assert_eq!(forged.status().as_u16(), 400);

    let (callback, _) = begin_login(&harness, &mock, "locked").await?;
    let page = harness.http.get(&callback).send().await?;
    assert_eq!(page.status().as_u16(), 200);
    assert!(page.text().await?.contains("You can close this tab"));

    let upstream = wait_for_state(&harness, "locked", "connected").await?;
    assert_eq!(upstream["tools"], 1, "{upstream}");
    let called = harness.execute_json("await locked_hello()").await?;
    assert_eq!(called["result"], "hello", "{called}");

    // tokens expire within rmcp's refresh margin, so the call refreshed and
    // the rotated refresh token was stored
    assert!(mock.issued.refreshes.load(Ordering::SeqCst) > 0);
    let (status, status_body) = harness
        .admin_json("/admin/oauth/status", &json!(null))
        .await?;
    assert_eq!(status, 200, "{status_body}");
    let login = &status_body["servers"][0];
    assert_eq!(login["logged_in"], true, "{status_body}");
    assert_eq!(login["refreshable"], true, "{status_body}");
    assert_eq!(login["scopes"], json!(["mcp:tools"]), "{status_body}");
    let (_, stored) = harness
        .app
        .passkeys()
        .store()
        .oauth_login("locked")?
        .ok_or("no stored login")?;
    assert!(
        !stored.contains("\"refresh-0\""),
        "refresh token not rotated"
    );

    // an abandoned second login leaves the working one alone
    let (_abandoned, _) = begin_login(&harness, &mock, "locked").await?;
    let (_, again) = harness
        .admin_json("/admin/oauth/status", &json!(null))
        .await?;
    assert_eq!(again["servers"][0]["logged_in"], true, "{again}");
    let called = harness.execute_json("await locked_hello()").await?;
    assert_eq!(called["result"], "hello", "{called}");

    // logout drops the tokens and the server needs a login again
    let (status, body) = harness
        .admin_json("/admin/oauth/logout", &json!({ "server": "locked" }))
        .await?;
    assert_eq!((status, body["removed"].clone()), (200, json!(true)));
    wait_for_state(&harness, "locked", "needs_login").await?;
    let (status, _) = harness
        .admin_json("/admin/oauth/login", &json!({ "server": "fixture" }))
        .await?;
    assert_eq!(status, 404);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_uses_a_client_registered_ahead_of_time() -> TestResult {
    let mock = start_mock(Client::Known).await?;
    let extra = format!(
        "[servers.known]\n\
         url = \"{}/mcp\"\n\
         oauth = true\n\
         client_id = \"known-client\"\n\
         client_secret = \"known-secret\"\n\
         authorization_params = {{ access_type = \"offline\", prompt = \"consent\" }}",
        mock.base
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    wait_for_state(&harness, "known", "needs_login").await?;

    let (callback, url) = begin_login(&harness, &mock, "known").await?;
    assert_eq!(query_value(&url, "access_type").as_deref(), Some("offline"));
    assert_eq!(query_value(&url, "prompt").as_deref(), Some("consent"));
    let page = harness.http.get(&callback).send().await?;
    assert_eq!(page.status().as_u16(), 200);

    // the token endpoint takes only the secret, so a working refresh shows
    // the stored login kept it
    wait_for_state(&harness, "known", "connected").await?;
    let called = harness.execute_json("await known_hello()").await?;
    assert_eq!(called["result"], "hello", "{called}");
    assert!(mock.issued.refreshes.load(Ordering::SeqCst) > 0);

    harness.stop().await
}

/// Config of a `locked` server whose `url` embeds the key `reference` names
/// in the query of `base`'s MCP endpoint
fn op_url_config(op: &std::path::Path, base: &str, reference: &str) -> String {
    format!(
        "[secrets]\nop = \"{op}\"\n\n\
         [servers.locked]\n\
         url = \"{base}/mcp?api_key={{{{ {reference} }}}}\"\n\
         oauth = true\n\
         client_name = \"codemode test\"",
        op = op.display()
    )
}

async fn locked_harness(
    op: &std::path::Path,
    base: &str,
    reference: &str,
) -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    let extra = op_url_config(op, base, reference);
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(None);
    };
    wait_for_state(&harness, "locked", "needs_login").await?;

    Ok(Some(harness))
}

const URL_KEY_REFERENCE: &str = "op://Dev/urlkey/credential";

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_resolves_a_url_with_an_embedded_key_without_storing_it() -> TestResult {
    let mock = start_mock(Client::Registered).await?;
    let (op, _) = super::secrets::fake_op()?;
    let key = super::secrets::URL_KEY;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    let (callback, url) = begin_login(&harness, &mock, "locked").await?;
    // the CLI prints this link; the resource is the public identifier the
    // server's metadata names, so it stays
    assert!(!url.contains(key), "{url}");
    assert_eq!(
        query_value(&url, "resource"),
        Some(format!("{}/mcp", mock.base)),
        "{url}"
    );
    let page = harness.http.get(&callback).send().await?;
    assert_eq!(page.status().as_u16(), 200);

    wait_for_state(&harness, "locked", "connected").await?;
    let called = harness.execute_json("await locked_hello()").await?;
    assert_eq!(called["result"], "hello", "{called}");
    assert!(!harness.state_holds(key));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_failure_that_echoes_the_resolved_url_comes_back_scrubbed() -> TestResult {
    let key = super::secrets::URL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_with(
        Client::Registered,
        String::new(),
        Some("the url http://example.invalid/mcp/zk-9f3a71c2d8b4e6/sse".into()),
    )
    .await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    let (status, body) = harness
        .admin_json("/admin/oauth/login", &json!({ "server": "locked" }))
        .await?;
    assert_eq!(status, 502, "{body}");
    let text = body["error"].as_str().unwrap_or_default();
    assert!(text.contains("[redacted]"), "{body}");
    assert!(!text.contains(key), "{body}");

    harness.stop().await
}

/// A login that must be refused with nothing stored; the answer names no key
async fn assert_login_refused(harness: &Harness, key: &str, fragment: &str) -> TestResult {
    let (status, body) = harness
        .admin_json("/admin/oauth/login", &json!({ "server": "locked" }))
        .await?;
    assert_ne!(status, 200, "{body}");
    assert!(body.to_string().contains(fragment), "{body}");
    assert!(!body.to_string().contains(key), "{body}");

    let (_, status) = harness
        .admin_json("/admin/oauth/status", &Value::Null)
        .await?;
    assert_eq!(status["servers"][0]["logged_in"], false, "{status}");
    assert!(!harness.state_holds(key));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_refuses_an_issuer_that_holds_the_key() -> TestResult {
    let key = super::secrets::URL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_with(Client::Registered, format!("/{key}"), None).await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    // the pending flow stores the expected issuer, so the login is refused
    // before the browser is sent anywhere
    assert_login_refused(&harness, key, "secret from the server's url").await?;

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_refuses_pending_state_whose_scopes_hold_the_key() -> TestResult {
    let key = super::secrets::URL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            scopes_supported: Some(vec![format!("mcp:{key}")]),
            ..Quirks::default()
        },
    )
    .await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    assert_login_refused(&harness, key, "secret from the server's url").await?;

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_refuses_a_registration_whose_client_secret_holds_the_key() -> TestResult {
    let key = super::secrets::URL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            register_secret: Some(format!("secret-{key}")),
            ..Quirks::default()
        },
    )
    .await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    assert_login_refused(&harness, key, "secret from the server's url").await?;

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_strips_a_resource_that_holds_the_key() -> TestResult {
    let key = super::secrets::URL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            resource_suffix: Some(format!("?api_key={key}")),
            ..Quirks::default()
        },
    )
    .await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    let (_, link) = begin_login(&harness, &mock, "locked").await?;
    assert!(query_value(&link, "resource").is_none(), "{link}");
    assert!(!link.contains(key), "{link}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_accepts_an_issuer_with_a_public_realm_holding_digits() -> TestResult {
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_with(
        Client::Registered,
        "/realms/production-us-east-1".into(),
        None,
    )
    .await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    let (callback, _) = begin_login(&harness, &mock, "locked").await?;
    let page = harness.http.get(&callback).send().await?;
    assert_eq!(page.status().as_u16(), 200);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_refuses_a_link_that_holds_a_percent_encoded_key() -> TestResult {
    let key = super::secrets::SYMBOL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            // the key as a form-encoded query carries it
            authorize_path: Some("/authorize?hint=zk%2B9f3a71c2%3Dd8b4e6".into()),
            ..Quirks::default()
        },
    )
    .await?;
    let Some(harness) = path_key_harness(
        &op,
        &mock.base,
        "op://Dev/symbolkey/credential",
        "needs_login",
    )
    .await?
    else {
        return Ok(());
    };

    assert_login_refused(&harness, key, "authorization link").await?;

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_refuses_a_token_response_whose_stored_fields_hold_the_url() -> TestResult {
    let key = super::secrets::URL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            login_extra: Some(json!({ "scope": format!("mcp:{key}") })),
            ..Quirks::default()
        },
    )
    .await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    let (callback, _) = begin_login(&harness, &mock, "locked").await?;
    let page = harness.http.get(&callback).send().await?;
    assert_eq!(page.status().as_u16(), 400);
    assert!(!page.text().await?.contains(key));

    let (_, status) = harness
        .admin_json("/admin/oauth/status", &Value::Null)
        .await?;
    assert_eq!(status["servers"][0]["logged_in"], false, "{status}");
    assert!(!harness.state_holds(key));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_drops_a_vendor_field_that_echoes_the_url_and_connects() -> TestResult {
    let key = super::secrets::URL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            login_extra: Some(json!({ "resource": format!("https://example.invalid/mcp/{key}") })),
            ..Quirks::default()
        },
    )
    .await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    let (callback, _) = begin_login(&harness, &mock, "locked").await?;
    let page = harness.http.get(&callback).send().await?;
    assert_eq!(page.status().as_u16(), 200);
    assert!(!harness.state_holds(key));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_refresh_that_echoes_the_url_is_stored_without_it() -> TestResult {
    let key = super::secrets::URL_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            refresh_extra: Some(
                json!({ "resource": format!("https://example.invalid/mcp/{key}") }),
            ),
            ..Quirks::default()
        },
    )
    .await?;
    let Some(harness) = locked_harness(&op, &mock.base, URL_KEY_REFERENCE).await? else {
        return Ok(());
    };

    let (callback, _) = begin_login(&harness, &mock, "locked").await?;
    let page = harness.http.get(&callback).send().await?;
    assert_eq!(page.status().as_u16(), 200);

    // the daemon reconnects with the new login, and the 5 second token is
    // inside rmcp's refresh margin
    for _ in 0..100 {
        if mock.issued.refreshes.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(mock.issued.refreshes.load(Ordering::SeqCst) > 0);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_, stored) = harness
        .app
        .passkeys()
        .store()
        .oauth_login("locked")?
        .ok_or("no stored login")?;
    assert!(
        !stored.contains("\"refresh-0\""),
        "the refresh was stored: {stored}"
    );
    assert!(!stored.contains(key));
    assert!(!harness.state_holds(key));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_callback_error_does_not_echo_a_url_that_cannot_be_read() -> TestResult {
    let key = "zk-b41d90e7a3c258";
    // no url file, so the fake `op` fails to read the reference
    let (op, log) = super::secrets::fake_op()?;
    let reference = "op://Dev/unreadable/credential";
    let Some(harness) = Harness::with(Setup {
        extra: &op_url_config(&op, "http://127.0.0.1:9", reference),
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let reads_before = super::secrets::reads(&log, reference);

    let description = format!("bad resource http://127.0.0.1:9/mcp/{key}/sse");
    let mut callback =
        reqwest::Url::parse(&format!("{}/oauth/callback/locked", harness.admin_base()))?;
    callback
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("error_description", &description);
    let page = harness.http.get(callback).send().await?;
    assert_eq!(page.status().as_u16(), 400);
    let text = page.text().await?;
    assert!(text.contains("access_denied"), "{text}");
    assert!(!text.contains(key), "{text}");
    // no login is in progress, so the callback must not raise a 1Password
    // prompt by reading the url
    assert_eq!(super::secrets::reads(&log, reference), reads_before);

    // an error code that is not a standard one may be the key itself
    let mut callback =
        reqwest::Url::parse(&format!("{}/oauth/callback/locked", harness.admin_base()))?;
    callback.query_pairs_mut().append_pair("error", key);
    let page = harness.http.get(callback).send().await?;
    assert_eq!(page.status().as_u16(), 400);
    let text = page.text().await?;
    assert!(!text.contains(key), "{text}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_connects_with_a_query_only_url() -> TestResult {
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            resource_path: Some("/".into()),
            ..Quirks::default()
        },
    )
    .await?;
    let (op, _) = super::secrets::fake_op()?;
    let key = super::secrets::URL_KEY;
    let extra = format!(
        "[secrets]\nop = \"{op}\"\n\n\
         [servers.locked]\n\
         url = \"{base}?api_key={{{{ {URL_KEY_REFERENCE} }}}}\"\n\
         oauth = true\n\
         client_name = \"codemode test\"",
        op = op.display(),
        base = mock.base,
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    wait_for_state(&harness, "locked", "needs_login").await?;

    let (callback, url) = begin_login(&harness, &mock, "locked").await?;
    assert!(!url.contains(key), "{url}");
    let page = harness.http.get(&callback).send().await?;
    assert_eq!(page.status().as_u16(), 200);
    wait_for_state(&harness, "locked", "connected").await?;
    assert!(!harness.state_holds(key));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_refuses_a_link_that_lowercases_the_key_into_a_host() -> TestResult {
    let key = super::secrets::MIXED_KEY;
    let (op, _) = super::secrets::fake_op()?;
    let mock = start_mock_quirky(
        Client::Registered,
        String::new(),
        None,
        Quirks {
            // rmcp lowercases a host, so the key no longer matches as read
            authorize_url: Some(format!(
                "https://{}.auth.example.invalid/authorize",
                key.to_lowercase()
            )),
            ..Quirks::default()
        },
    )
    .await?;
    let Some(harness) = path_key_harness(
        &op,
        &mock.base,
        "op://Dev/mixedkey/credential",
        "needs_login",
    )
    .await?
    else {
        return Ok(());
    };

    assert_login_refused(&harness, key, "secret from the server's url").await?;

    harness.stop().await
}

/// Starts a daemon whose `url` embeds `reference` in its path
async fn path_key_harness(
    op: &std::path::Path,
    base: &str,
    reference: &str,
    state: &str,
) -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    let extra = format!(
        "[secrets]\nop = \"{op}\"\n\n\
         [servers.locked]\n\
         url = \"{base}/mcp/{{{{ {reference} }}}}\"\n\
         oauth = true\n\
         client_name = \"codemode test\"",
        op = op.display()
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(None);
    };
    wait_for_state(&harness, "locked", state).await?;

    Ok(Some(harness))
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_login_accepts_a_path_key_holding_a_colon() -> TestResult {
    let mock = start_mock(Client::Registered).await?;
    let (op, _) = super::secrets::fake_op()?;
    let Some(harness) = path_key_harness(
        &op,
        &mock.base,
        "op://Dev/colonkey/credential",
        "needs_login",
    )
    .await?
    else {
        return Ok(());
    };

    let (_, url) = begin_login(&harness, &mock, "locked").await?;
    assert!(!url.contains("9f3a71c2d8b4e6"), "{url}");

    harness.stop().await
}
