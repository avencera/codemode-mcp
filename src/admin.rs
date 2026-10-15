//! Admin API for the local CLI, served on its own loopback listener
//!
//! `tailscale serve` proxies phone traffic from 127.0.0.1 to the main
//! listener, so a peer check there would let the tailnet in. The admin
//! routes live on a separate listener that the proxy never targets, and
//! still check the socket peer (never the `Host` header) and refuse
//! anything that looks proxied

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    app::App,
    approvals::{AdminAction, AdminRequest, Approvals, Verdict, Waiting, confirmation_code},
    gateway::{Gateway, WarmResult},
    host::is_direct_local,
    notify::{Notification, Priority},
    oauth::{Callback, LoginStatus, OAuthError},
    passkeys::{PasskeyError, Passkeys},
    upstream::UpstreamStatus,
    web::escape,
};

/// Discovery, registration and the code exchange each make a few HTTP
/// calls that rmcp does not bound
const OAUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone)]
struct AdminState {
    passkeys: Arc<Passkeys>,
    approvals: Arc<Approvals>,
    gateway: Arc<Gateway>,
    public_base: String,
}

/// Body of `POST /admin/enroll`
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// Label the new passkey gets, shown on the approval page
    pub label: String,
}

/// Answer of `POST /admin/enroll`
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// One-time enrollment page
    pub url: String,
    /// Page where an existing passkey approves the enrollment; `None` for
    /// the first passkey, whose link works at once
    pub approval_url: Option<String>,
    /// Code repeated on the approval page and in the notification
    pub code: Option<String>,
    /// Whether a notification went out
    pub notified: bool,
}

/// Body of `POST /admin/passkey/remove`
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveRequest {
    /// Id from `passkey list`
    pub id: i64,
}

/// Answer of `POST /admin/passkey/remove`
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveResponse {
    /// Label of the passkey that will be removed
    pub label: String,
    /// Page where an existing passkey approves the removal
    pub approval_url: String,
    /// Code repeated on the approval page and in the notification
    pub code: String,
    /// Whether a notification went out
    pub notified: bool,
}

/// Body of the `POST /admin/oauth/*` requests that name a server
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthServerRequest {
    /// Server name from the config
    pub server: String,
}

/// Answer of `POST /admin/oauth/login`
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthLoginResponse {
    /// Page to open in a browser on this Mac
    pub authorization_url: String,
}

/// One server in the answer of `POST /admin/oauth/status`
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStatusEntry {
    /// Stored login
    #[serde(flatten)]
    pub login: LoginStatus,
    /// Connection state of the upstream
    pub state: String,
}

/// Answer of `POST /admin/oauth/status`
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStatusResponse {
    /// Every `oauth = true` server
    pub servers: Vec<OAuthStatusEntry>,
}

/// Answer of `POST /admin/oauth/logout`
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthLogoutResponse {
    /// Whether a login was stored
    pub removed: bool,
}

/// Body of `POST /admin/warm`
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WarmRequest {
    /// Only this server; every server with warm calls when absent
    pub server: Option<String>,
}

/// Answer of `POST /admin/warm`
#[derive(Debug, Serialize, Deserialize)]
pub struct WarmResponse {
    /// One entry per call made
    pub results: Vec<WarmResult>,
}

/// Admin routes; serve them with connect info so the peer can be checked
pub fn router(app: &App) -> Router {
    let state = AdminState {
        passkeys: Arc::clone(app.passkeys()),
        approvals: Arc::clone(app.approvals()),
        gateway: Arc::clone(app.gateway()),
        public_base: app.config().public_base(),
    };

    Router::new()
        .route("/admin/enroll", post(enroll))
        .route("/admin/passkey/remove", post(remove_passkey))
        .route("/admin/warm", post(warm))
        .route("/admin/oauth/login", post(oauth_login))
        .route("/admin/oauth/status", post(oauth_status))
        .route("/admin/oauth/logout", post(oauth_logout))
        // the browser on this Mac lands here after signing in; the CSRF
        // state must match a login started through `/admin/oauth/login`
        .route("/oauth/callback/{server}", get(oauth_callback))
        .with_state(state)
        .layer(middleware::from_fn(loopback_only))
}

/// Refuses peers that are not loopback and requests that were proxied; a
/// router served without connect info rejects every request
async fn loopback_only(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    // a loopback Host blocks DNS rebinding from a page in a local browser
    let host_ok = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_none_or(is_loopback_host);
    if !is_direct_local(Some(peer), request.headers()) || !host_ok {
        return (
            StatusCode::FORBIDDEN,
            "forbidden: admin API is loopback-only",
        )
            .into_response();
    }

    next.run(request).await
}

/// `localhost`, `127.0.0.1` or `[::1]`, with or without a port
fn is_loopback_host(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or(rest, |(address, _)| address),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };

    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn passkey_failure(failure: &PasskeyError) -> Response {
    match failure {
        PasskeyError::Label => error(StatusCode::BAD_REQUEST, &failure.to_string()),
        _ => {
            tracing::warn!(error = %failure, "admin passkey request failed");

            error(StatusCode::INTERNAL_SERVER_ERROR, "passkey storage failed")
        }
    }
}

/// Creates an enrollment link; every request is announced on the phone,
/// and once a passkey exists the link also needs that passkey's approval
async fn enroll(State(state): State<AdminState>, Json(request): Json<EnrollRequest>) -> Response {
    let created = match state.passkeys.create_enrollment(&request.label) {
        Ok(created) => created,
        Err(failure) => return passkey_failure(&failure),
    };
    let label = request.label.trim().to_owned();
    let url = format!("{}/enroll/{}", state.public_base, created.token);

    if !created.needs_approval {
        // the link is a capability, so it never goes into the notification
        state.approvals.announce(Notification {
            title: format!("codemode: first passkey \"{label}\" is being enrolled"),
            message: "An enrollment link was created on the Mac. If this was not you, \
                      check the Mac before anyone uses it."
                .to_owned(),
            click: None,
            priority: Priority::Urgent,
            tag: "warning",
        });

        return Json(EnrollResponse {
            url,
            approval_url: None,
            code: None,
            notified: state.approvals.can_notify(),
        })
        .into_response();
    }

    let code = confirmation_code();
    let mut details = Map::new();
    details.insert("label".to_owned(), Value::String(label.clone()));
    let action = AdminAction::EnrollPasskey {
        enrollment_hash: created.hash,
    };
    let waiting = state.approvals.request_admin(AdminRequest {
        action: action.clone(),
        title: format!("Enroll a new passkey named \"{label}\""),
        details,
        code: code.clone(),
    });
    let approval_url = waiting.url().to_owned();
    attach_action(Arc::clone(&state.passkeys), waiting, action);

    Json(EnrollResponse {
        url,
        approval_url: Some(approval_url),
        code: Some(code),
        notified: state.approvals.can_notify(),
    })
    .into_response()
}

/// Refusal for removing the only passkey
const LAST_PASSKEY: &str = "cannot remove the last passkey; enroll a replacement first \
                            (`codemode-mcp passkey enroll --label NAME`), then remove this one";

/// Asks an existing passkey to approve removing one; the passkey is removed
/// only once approved, and never the last one
async fn remove_passkey(
    State(state): State<AdminState>,
    Json(request): Json<RemoveRequest>,
) -> Response {
    let passkey = match state.passkeys.store().passkey(request.id) {
        Ok(Some(passkey)) => passkey,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                &format!("no passkey with id {}", request.id),
            );
        }
        Err(failure) => return passkey_failure(&PasskeyError::Store(failure)),
    };

    // with no passkey left, first enrollment would reopen to any local caller
    match state.passkeys.store().passkey_count() {
        Ok(count) if count <= 1 => return error(StatusCode::CONFLICT, LAST_PASSKEY),
        Ok(_) => {}
        Err(failure) => return passkey_failure(&PasskeyError::Store(failure)),
    }

    let label = passkey.label;
    let code = confirmation_code();
    let mut details = Map::new();
    details.insert("id".to_owned(), json!(request.id));
    details.insert("label".to_owned(), Value::String(label.clone()));
    let action = AdminAction::RemovePasskey {
        id: request.id,
        created_ms: passkey.created_ms,
    };
    let waiting = state.approvals.request_admin(AdminRequest {
        action: action.clone(),
        title: format!("Remove the passkey named \"{label}\""),
        details,
        code: code.clone(),
    });
    let approval_url = waiting.url().to_owned();
    attach_action(Arc::clone(&state.passkeys), waiting, action);

    Json(RemoveResponse {
        label,
        approval_url,
        code,
        notified: state.approvals.can_notify(),
    })
    .into_response()
}

/// Carries out `action` once the request's wait ends, then records that it is
/// done; used for new requests and for those restored after a restart
pub fn attach_action(passkeys: Arc<Passkeys>, waiting: Waiting, action: AdminAction) {
    tokio::spawn(async move {
        let request = waiting.id().to_owned();
        let verdict = waiting.decision().await;
        perform(&passkeys, &action, &verdict);

        if let Err(failure) = passkeys.store().complete_action(&request) {
            tracing::warn!(error = %failure, "could not record a finished admin action");
        }
    });
}

fn perform(passkeys: &Passkeys, action: &AdminAction, verdict: &Verdict) {
    match (action, verdict) {
        (AdminAction::EnrollPasskey { enrollment_hash }, Verdict::Approved { .. }) => {
            passkeys.approve_enrollment(enrollment_hash);
        }
        (AdminAction::EnrollPasskey { enrollment_hash }, Verdict::Denied { .. }) => {
            passkeys.drop_enrollment(enrollment_hash);
        }
        (AdminAction::RemovePasskey { id, created_ms }, Verdict::Approved { .. }) => {
            // another removal may have been approved while this one waited
            if !matches!(passkeys.store().passkey_count(), Ok(count) if count > 1) {
                tracing::warn!(id, "refused to remove the last passkey");

                return;
            }

            // the enrollment time pins the row, in case its id was reused
            match passkeys.store().remove_passkey(*id, *created_ms) {
                Ok(true) => tracing::info!(id, "passkey removed after approval"),
                Ok(false) => tracing::info!(id, "passkey was already gone"),
                Err(failure) => tracing::warn!(id, error = %failure, "passkey removal failed"),
            }
        }
        (AdminAction::RemovePasskey { .. }, Verdict::Denied { .. }) => {}
    }
}

fn oauth_failure(failure: &OAuthError) -> Response {
    let status = match failure {
        OAuthError::UnknownServer(_) | OAuthError::NotOAuth(_) => StatusCode::NOT_FOUND,
        OAuthError::UnknownFlow | OAuthError::Refused(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_GATEWAY,
    };

    error(status, &failure.to_string())
}

async fn oauth_login(
    State(state): State<AdminState>,
    Json(request): Json<OAuthServerRequest>,
) -> Response {
    let started = tokio::time::timeout(
        OAUTH_TIMEOUT,
        state.gateway.oauth().start_login(&request.server),
    )
    .await
    .unwrap_or(Err(OAuthError::TimedOut));
    match started {
        Ok(authorization_url) => Json(OAuthLoginResponse { authorization_url }).into_response(),
        Err(failure) => {
            tracing::warn!(server = %request.server, error = %failure, "oauth login failed to start");

            oauth_failure(&failure)
        }
    }
}

async fn oauth_status(State(state): State<AdminState>) -> Response {
    let logins = match state.gateway.oauth().status() {
        Ok(logins) => logins,
        Err(failure) => return oauth_failure(&failure),
    };
    let report = state.gateway.report();
    let servers = logins
        .into_iter()
        .map(|login| {
            let state = report
                .iter()
                .find(|upstream| upstream.name == login.server)
                .map_or(UpstreamStatus::Connecting.state(), |upstream| {
                    upstream.status.state()
                })
                .to_owned();

            OAuthStatusEntry { login, state }
        })
        .collect();

    Json(OAuthStatusResponse { servers }).into_response()
}

async fn oauth_logout(
    State(state): State<AdminState>,
    Json(request): Json<OAuthServerRequest>,
) -> Response {
    match state.gateway.oauth().logout(&request.server) {
        Ok(removed) => {
            state.gateway.reconnect(&request.server);

            Json(OAuthLogoutResponse { removed }).into_response()
        }
        Err(failure) => oauth_failure(&failure),
    }
}

async fn oauth_callback(
    State(state): State<AdminState>,
    Path(server): Path<String>,
    Query(callback): Query<Callback>,
) -> Response {
    let finished = tokio::time::timeout(
        OAUTH_TIMEOUT,
        state.gateway.oauth().finish_login(&server, &callback),
    )
    .await
    .unwrap_or(Err(OAuthError::TimedOut));
    let (status, title, message) = match finished {
        Ok(()) => {
            tracing::info!(%server, "oauth login completed");
            state.gateway.reconnect(&server);

            (
                StatusCode::OK,
                "Signed in",
                format!("codemode-mcp is signed in to {server}. You can close this tab."),
            )
        }
        Err(failure) => {
            tracing::warn!(%server, error = %failure, "oauth callback failed");

            (
                StatusCode::BAD_REQUEST,
                "Sign-in failed",
                format!("Signing in to {server} failed: {failure}"),
            )
        }
    };
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"referrer\" content=\"no-referrer\"><title>{title}</title></head>\
         <body style=\"font-family: -apple-system, system-ui, sans-serif; margin: 40px\">\
         <h1>{title}</h1><p>{message}</p></body></html>",
        title = escape(title),
        message = escape(&message),
    );

    (
        status,
        [
            (
                axum::http::header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'",
            ),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        Html(html),
    )
        .into_response()
}

async fn warm(State(state): State<AdminState>, Json(request): Json<WarmRequest>) -> Response {
    match state.gateway.warm(request.server.as_deref()).await {
        Ok(results) => Json(WarmResponse { results }).into_response(),
        Err(message) => error(StatusCode::BAD_REQUEST, &message),
    }
}
