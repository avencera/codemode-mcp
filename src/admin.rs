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
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    app::App,
    gateway::{Gateway, WarmResult},
    passkeys::Passkeys,
};

/// Headers proxies add; a request carrying one did not come straight from
/// a local process
const PROXY_HEADERS: [&str; 4] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "tailscale-user-login",
];

#[derive(Clone)]
struct AdminState {
    passkeys: Arc<Passkeys>,
    gateway: Arc<Gateway>,
    public_base: String,
}

/// Answer of `POST /admin/enroll`
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// One-time enrollment page
    pub url: String,
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
        gateway: Arc::clone(app.gateway()),
        public_base: app.config().public_base().to_owned(),
    };

    Router::new()
        .route("/admin/enroll", post(enroll))
        .route("/admin/warm", post(warm))
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
    if !peer.ip().to_canonical().is_loopback() || proxied(request.headers()) || !host_ok {
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

fn proxied(headers: &HeaderMap) -> bool {
    PROXY_HEADERS
        .iter()
        .any(|header| headers.contains_key(*header))
}

async fn enroll(State(state): State<AdminState>) -> Json<EnrollResponse> {
    let token = state.passkeys.create_enrollment();

    Json(EnrollResponse {
        url: format!("{}/enroll/{token}", state.public_base),
    })
}

async fn warm(State(state): State<AdminState>, Json(request): Json<WarmRequest>) -> Response {
    match state.gateway.warm(request.server.as_deref()).await {
        Ok(results) => Json(WarmResponse { results }).into_response(),
        Err(message) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
        }
    }
}
