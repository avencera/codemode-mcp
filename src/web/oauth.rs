//! OAuth sign-in pages on the main listener, so a sign-in can start and
//! finish on any device that reaches `public_origin`, such as a phone
//!
//! The page that starts a sign-in only renders a button: link previews and
//! prefetching fetch with GET, and a started sign-in registers a client and
//! may read the server's `url` from 1Password, so only the POST starts one

use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};

use super::{WebState, escape, page};
use crate::{
    gateway::Gateway,
    oauth::{Callback, OAuthError},
};

/// How long starting or finishing a sign-in may take: discovery,
/// registration, a 1Password read of the `url` and the token exchange
pub const OAUTH_TIMEOUT: Duration = Duration::from_secs(60);
/// Lets the form post to this page and the browser follow the redirect to
/// the authorization server, which some browsers check against
/// `form-action` too
const LOGIN_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; \
     base-uri 'none'; form-action 'self' https:; frame-ancestors 'none'";

/// `GET /oauth/login/{server}`: what the sign-in is for, and a button
pub(super) async fn login_page(
    State(state): State<WebState>,
    Path(server): Path<String>,
) -> Response {
    let oauth = state.gateway.oauth();
    if oauth.login_page(&server).is_none() {
        return unknown_server(&server);
    }
    let signed_in = oauth.status().is_ok_and(|logins| {
        logins
            .iter()
            .any(|login| login.server == server && login.logged_in)
    });
    let note = if signed_in {
        "codemode-mcp is already signed in to this server; signing in again replaces that login."
    } else {
        "codemode-mcp opens the server's sign-in page, then brings you back here."
    };
    let title = format!("Sign in to {server}");
    let server = escape(&server);
    let mut response = page(
        StatusCode::OK,
        &title,
        &format!(
            "<main><h1>{heading}</h1><p class=\"meta\">{note}</p>\
             <form method=\"post\" action=\"/oauth/login/{server}\"><div class=\"buttons\">\
             <button class=\"approve\" type=\"submit\">Continue</button></div></form></main>",
            heading = escape(&title),
            note = escape(note),
        ),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(LOGIN_CONTENT_SECURITY_POLICY),
    );

    response
}

/// `POST /oauth/login/{server}`: starts the sign-in and sends the browser
/// to the authorization server
pub(super) async fn login_start(
    State(state): State<WebState>,
    Path(server): Path<String>,
    headers: HeaderMap,
) -> Response {
    // another site's form could otherwise start a sign-in in the owner's
    // browser; browsers that send no `Sec-Fetch-Site` are let through
    let site = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok());
    if site.is_some_and(|site| site != "same-origin" && site != "none") {
        return failed(
            StatusCode::FORBIDDEN,
            &server,
            "the request came from another site",
        );
    }
    let oauth = state.gateway.oauth();
    if oauth.login_page(&server).is_none() {
        return unknown_server(&server);
    }

    let started = tokio::time::timeout(OAUTH_TIMEOUT, oauth.start_login(&server))
        .await
        .unwrap_or(Err(OAuthError::TimedOut));
    match started {
        Ok(authorization_url) => Redirect::to(&authorization_url).into_response(),
        Err(failure) => {
            tracing::warn!(%server, error = %failure, "oauth login failed to start");

            failed(StatusCode::BAD_GATEWAY, &server, &failure.to_string())
        }
    }
}

/// `GET /oauth/callback/{server}` on the main listener
pub(super) async fn callback(
    State(state): State<WebState>,
    Path(server): Path<String>,
    Query(callback): Query<Callback>,
) -> Response {
    finish(&state.gateway, &server, &callback).await
}

/// Completes a sign-in from the authorization server's redirect, on either
/// listener, and reconnects the server
pub async fn finish(gateway: &Gateway, server: &str, callback: &Callback) -> Response {
    let finished = tokio::time::timeout(
        OAUTH_TIMEOUT,
        gateway.oauth().finish_login(server, callback),
    )
    .await
    .unwrap_or(Err(OAuthError::TimedOut));
    match finished {
        Ok(()) => {
            tracing::info!(%server, "oauth login completed");
            gateway.reconnect(server);
            let server = escape(server);

            page(
                StatusCode::OK,
                "Signed in",
                &format!(
                    "<main><h1>Signed in</h1>\
                     <p>codemode-mcp is signed in to {server}. You can close this tab.</p></main>"
                ),
            )
        }
        Err(failure) => {
            tracing::warn!(%server, error = %failure, "oauth callback failed");

            failed(StatusCode::BAD_REQUEST, server, &failure.to_string())
        }
    }
}

fn failed(status: StatusCode, server: &str, reason: &str) -> Response {
    page(
        status,
        "Sign-in failed",
        &format!(
            "<main><h1>Sign-in failed</h1><p>{}</p></main>",
            escape(&format!("Signing in to {server} failed: {reason}"))
        ),
    )
}

fn unknown_server(server: &str) -> Response {
    page(
        StatusCode::NOT_FOUND,
        "Not found",
        &format!(
            "<main><h1>Not found</h1><p>{}</p></main>",
            escape(&format!(
                "No server named {server} signs in from this page; on the gateway's Mac, run `codemode-mcp oauth login {server}`."
            ))
        ),
    )
}
