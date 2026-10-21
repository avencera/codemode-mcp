//! OAuth sign-in pages on the main listener, so a sign-in can start and
//! finish on any device that reaches `public_origin`, such as a phone
//!
//! Whoever starts a sign-in decides which account the gateway's tokens
//! belong to, and the main listener is reachable from the network, so a
//! sign-in starts only after a passkey assertion, as an approval does. The
//! page itself starts nothing, and the JSON bodies keep other sites' forms
//! out

use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use webauthn_rs::prelude::PublicKeyCredential;

use super::{WebState, escape, json_error, page, passkey_error};
use crate::{
    approvals::Choice,
    gateway::Gateway,
    oauth::{Callback, OAuthError},
};

/// How long starting or finishing a sign-in may take: discovery,
/// registration, a 1Password read of the `url` and the token exchange
pub const OAUTH_TIMEOUT: Duration = Duration::from_secs(60);

/// What a passkey assertion started here is bound to, so it cannot approve
/// a tool call or another server's sign-in; approval ids never hold `:`
fn subject(server: &str) -> String {
    format!("oauth-login:{server}")
}

/// `GET /oauth/login/{server}`: what the sign-in is for, and a button
pub(super) async fn login_page(
    State(state): State<WebState>,
    Path(server): Path<String>,
) -> Response {
    let oauth = state.gateway.oauth();
    if oauth.login_page(&server).is_none() {
        return unknown_server();
    }
    let signed_in = oauth.status().is_ok_and(|logins| {
        logins
            .iter()
            .any(|login| login.server == server && login.logged_in)
    });
    let note = if signed_in {
        "codemode-mcp is already signed in to this server; signing in again replaces that login."
    } else {
        "Confirm with your passkey, then sign in on the server's page; you come back here when it is done."
    };
    let title = format!("Sign in to {server}");

    page(
        StatusCode::OK,
        &title,
        &format!(
            r#"<main data-kind="signin" data-base="/oauth/login/{server}">
<h1>{heading}</h1>
<p class="meta">{note}</p>
<div class="buttons"><button class="approve" id="signin">Continue with passkey</button></div>
<p id="status" role="status"></p>
</main>
<script src="/assets/webauthn.js"></script>"#,
            server = escape(&server),
            heading = escape(&title),
            note = escape(note),
        ),
    )
}

/// `POST /oauth/login/{server}/options`: a passkey challenge for this
/// sign-in
pub(super) async fn login_options(
    State(state): State<WebState>,
    Path(server): Path<String>,
    // a JSON body keeps cross-site form posts out
    Json(_body): Json<Value>,
) -> Response {
    if state.gateway.oauth().login_page(&server).is_none() {
        return json_error(StatusCode::NOT_FOUND, "no such sign-in");
    }

    match state
        .passkeys
        .start_authentication(&subject(&server), Choice::Once)
    {
        Ok((ceremony, options)) => {
            Json(json!({ "ceremony": ceremony, "options": options })).into_response()
        }
        Err(error) => passkey_error(&error),
    }
}

#[derive(Deserialize)]
pub(super) struct ConfirmBody {
    ceremony: String,
    credential: PublicKeyCredential,
}

/// `POST /oauth/login/{server}/confirm`: verifies the assertion, starts the
/// sign-in and answers the authorization URL for the page to open
pub(super) async fn login_confirm(
    State(state): State<WebState>,
    Path(server): Path<String>,
    Json(body): Json<ConfirmBody>,
) -> Response {
    let passkeys = Arc::clone(&state.passkeys);
    // SQLite reads and signature checks are blocking work
    let verified = tokio::task::spawn_blocking(move || {
        passkeys.finish_authentication(&body.ceremony, &body.credential)
    })
    .await;
    let started_for = match verified {
        Ok(Ok((started_for, _))) => started_for,
        Ok(Err(error)) => return passkey_error(&error),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "verification failed"),
    };
    if started_for != subject(&server) {
        return json_error(
            StatusCode::FORBIDDEN,
            "this assertion is for another request",
        );
    }

    let started = tokio::time::timeout(OAUTH_TIMEOUT, state.gateway.oauth().start_login(&server))
        .await
        .unwrap_or(Err(OAuthError::TimedOut));
    match started {
        Ok(authorization_url) => {
            Json(json!({ "authorization_url": authorization_url })).into_response()
        }
        Err(failure) => {
            tracing::warn!(%server, error = %failure, "oauth login failed to start");

            json_error(StatusCode::BAD_GATEWAY, &failure.to_string())
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
    if !gateway.oauth().servers().any(|name| name == server) {
        return unknown_server();
    }
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

/// Names nothing from the request, so a crafted link cannot put its own
/// text on this origin
fn unknown_server() -> Response {
    page(
        StatusCode::NOT_FOUND,
        "Not found",
        "<main><h1>Not found</h1><p>No server signs in from this page. On the gateway's Mac, \
         `codemode-mcp oauth status` lists the servers that sign in.</p></main>",
    )
}
