//! Server-rendered approval, enrollment and stats pages
//!
//! Approving needs a passkey assertion; denying does not, since refusing a
//! call can only make things safer. Every value that came from an agent, an
//! upstream or the database is HTML-escaped

use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::{
    app::App,
    approvals::{Approvals, Choice, DecideError, SESSION_GRANT_MINUTES},
    passkeys::{PasskeyError, Passkeys},
    policy::GrantMode,
    store,
    usage::report::{Reporter, Stats, human_duration, parse_since, percent},
};

/// Browser-side WebAuthn helpers
const WEBAUTHN_JS: &str = include_str!("../assets/webauthn.js");
/// Inline styles only; scripts come from `/assets/webauthn.js`
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; \
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
/// Window `/stats` shows without a `since` parameter
const DEFAULT_STATS_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone)]
struct WebState {
    approvals: Arc<Approvals>,
    passkeys: Arc<Passkeys>,
    state_dir: PathBuf,
}

/// Routes for the main listener
pub fn router(app: &App) -> Router {
    let state = WebState {
        approvals: Arc::clone(app.approvals()),
        passkeys: Arc::clone(app.passkeys()),
        state_dir: app.state_dir().clone(),
    };

    Router::new()
        .route("/approve/{id}", get(approve_page))
        .route("/approve/{id}/options", post(approve_options))
        .route("/approve/{id}/confirm", post(approve_confirm))
        .route("/approve/{id}/deny", post(approve_deny))
        .route("/enroll/{token}", get(enroll_page))
        .route("/enroll/{token}/options", post(enroll_options))
        .route("/enroll/{token}/finish", post(enroll_finish))
        .route("/assets/webauthn.js", get(webauthn_js))
        .route("/stats", get(stats_page))
        .with_state(state)
}

/// Escapes text for HTML element content and quoted attributes
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }

    out
}

fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<style>
:root {{ color-scheme: light dark; font-family: -apple-system, system-ui, sans-serif; }}
body {{ margin: 0; padding: env(safe-area-inset-top) 16px 32px; max-width: 720px; margin-inline: auto; line-height: 1.4; }}
h1 {{ font-size: 1.35rem; margin: 20px 0 8px; overflow-wrap: anywhere; }}
h2 {{ font-size: 1rem; margin: 20px 0 6px; }}
.meta {{ color: #777; font-size: .9rem; overflow-wrap: anywhere; }}
pre {{ background: rgba(127,127,127,.12); padding: 12px; border-radius: 10px; overflow-x: auto; font-size: .85rem; white-space: pre-wrap; overflow-wrap: anywhere; }}
.buttons {{ display: grid; gap: 12px; margin-top: 24px; }}
button {{ font-size: 1.1rem; padding: 16px; border-radius: 14px; border: 0; font-weight: 600; min-height: 56px; }}
button.approve {{ background: #1f7a3a; color: #fff; }}
button.session {{ background: #2457a6; color: #fff; }}
button.deny {{ background: #b3261e; color: #fff; }}
button:disabled {{ opacity: .5; }}
input {{ font-size: 1.1rem; padding: 12px; border-radius: 10px; border: 1px solid #999; width: 100%; box-sizing: border-box; }}
#status {{ margin-top: 20px; font-weight: 600; min-height: 1.4em; }}
table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
td, th {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid rgba(127,127,127,.3); vertical-align: top; overflow-wrap: anywhere; }}
</style>
</head>
<body>
{body}
</body>
</html>"#,
        title = escape(title),
    );

    let mut response = (status, Html(html)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    response
}

fn not_found(what: &str) -> Response {
    page(
        StatusCode::NOT_FOUND,
        "Not found",
        &format!(
            "<h1>Not found</h1><p>{}</p>",
            escape(&format!(
                "This {what} does not exist, was already answered, or has expired."
            ))
        ),
    )
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn passkey_error(error: &PasskeyError) -> Response {
    let status = match error {
        PasskeyError::UnknownToken | PasskeyError::UnknownCeremony => StatusCode::GONE,
        PasskeyError::Label => StatusCode::BAD_REQUEST,
        PasskeyError::Rejected => StatusCode::FORBIDDEN,
        PasskeyError::NoPasskeys => StatusCode::CONFLICT,
        PasskeyError::Busy => StatusCode::TOO_MANY_REQUESTS,
        PasskeyError::Config(_) | PasskeyError::Store(_) => {
            tracing::warn!(%error, "passkey operation failed");

            StatusCode::INTERNAL_SERVER_ERROR
        }
    };

    json_error(status, &error.to_string())
}

fn decide_error(error: &DecideError) -> Response {
    let status = match error {
        DecideError::NotFound => StatusCode::GONE,
        DecideError::SessionNotAllowed => StatusCode::BAD_REQUEST,
    };

    json_error(status, &error.to_string())
}

async fn approve_page(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    let Some(info) = state.approvals.info(&id) else {
        return not_found("approval request");
    };

    let arguments = serde_json::to_string_pretty(&Value::Object(info.arguments.clone()))
        .unwrap_or_else(|_| "{}".to_owned());
    let session_buttons = if info.grant_mode == GrantMode::Session && info.caller.session.is_some()
    {
        SESSION_GRANT_MINUTES
            .iter()
            .map(|minutes| {
                format!(
                    r#"<button class="session" data-choice="session{minutes}">Approve for this session, {minutes} min</button>"#
                )
            })
            .collect::<String>()
    } else {
        String::new()
    };
    let grant_note = match info.grant_mode {
        GrantMode::Session => {
            "A session approval covers this server's read tools for the agent session."
        }
        GrantMode::PerCall => "This tool needs approval for every call.",
    };
    let title = format!(
        "{} wants {}",
        info.caller.client_label(),
        info.waiting_for()
    );
    let body = format!(
        r#"<main data-kind="approve" data-base="/approve/{id}">
<h1>{title}</h1>
<p class="meta">Client {client} {version}<br>Session {session}<br>Execution {execution}</p>
<p class="meta">Denied automatically in <span id="left" data-seconds="{left}">{left_text}</span>. {grant_note}</p>
<h2>Arguments</h2>
<pre>{arguments}</pre>
<h2>Script</h2>
<pre>{script}</pre>
<div class="buttons">
<button class="approve" data-choice="once">Approve once</button>
{session_buttons}
<button class="deny" data-choice="deny">Deny</button>
</div>
<p id="status" role="status"></p>
</main>
<script src="/assets/webauthn.js"></script>"#,
        id = escape(&info.id),
        title = escape(&title),
        client = escape(info.caller.client_label()),
        version = escape(info.caller.client_version.as_deref().unwrap_or("")),
        session = escape(info.caller.session.as_deref().unwrap_or("none")),
        execution = escape(&info.execution_id),
        left = info.time_left().as_secs(),
        left_text = escape(&human_duration(info.time_left().as_millis() as i64)),
        arguments = escape(&arguments),
        script = escape(&info.script),
    );

    page(StatusCode::OK, &title, &body)
}

#[derive(Deserialize)]
struct ChoiceBody {
    choice: String,
}

async fn approve_options(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(body): Json<ChoiceBody>,
) -> Response {
    let Some(info) = state.approvals.info(&id) else {
        return decide_error(&DecideError::NotFound);
    };
    let choice = match Choice::parse(&body.choice) {
        Some(Choice::Deny) | None => return json_error(StatusCode::BAD_REQUEST, "unknown choice"),
        Some(choice) => choice,
    };
    if matches!(choice, Choice::Session(_))
        && (info.grant_mode != GrantMode::Session || info.caller.session.is_none())
    {
        return decide_error(&DecideError::SessionNotAllowed);
    }

    match state.passkeys.start_authentication(&id, choice) {
        Ok((ceremony, options)) => {
            Json(json!({ "ceremony": ceremony, "options": options })).into_response()
        }
        Err(error) => passkey_error(&error),
    }
}

#[derive(Deserialize)]
struct ConfirmBody {
    ceremony: String,
    credential: PublicKeyCredential,
}

async fn approve_confirm(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(body): Json<ConfirmBody>,
) -> Response {
    let passkeys = Arc::clone(&state.passkeys);
    // SQLite reads and signature checks are blocking work
    let verified = tokio::task::spawn_blocking(move || {
        passkeys.finish_authentication(&body.ceremony, &body.credential)
    })
    .await;
    let (approval_id, choice) = match verified {
        Ok(Ok(verified)) => verified,
        Ok(Err(error)) => return passkey_error(&error),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "verification failed"),
    };
    // the assertion was started for one approval; it cannot approve another
    if approval_id != id {
        return json_error(
            StatusCode::FORBIDDEN,
            "this assertion is for another request",
        );
    }

    match state.approvals.decide(&id, choice) {
        Ok(()) => Json(json!({ "ok": true, "message": "Approved." })).into_response(),
        Err(error) => decide_error(&error),
    }
}

async fn approve_deny(
    State(state): State<WebState>,
    Path(id): Path<String>,
    // a JSON body keeps cross-site form posts out
    Json(_body): Json<Value>,
) -> Response {
    match state.approvals.decide(&id, Choice::Deny) {
        Ok(()) => Json(json!({ "ok": true, "message": "Denied." })).into_response(),
        Err(error) => decide_error(&error),
    }
}

async fn enroll_page(State(state): State<WebState>, Path(token): Path<String>) -> Response {
    if !state.passkeys.enrollment_valid(&token) {
        return not_found("enrollment link");
    }

    let body = format!(
        r#"<main data-kind="enroll" data-base="/enroll/{token}">
<h1>Add a passkey for codemode-mcp approvals</h1>
<p class="meta">The passkey approves sensitive tool calls from this device. This link works once and expires in 10 minutes.</p>
<label for="label">Label</label>
<input id="label" maxlength="64" placeholder="e.g. iPhone" autocomplete="off">
<div class="buttons"><button class="approve" id="enroll">Create passkey</button></div>
<p id="status" role="status"></p>
</main>
<script src="/assets/webauthn.js"></script>"#,
        token = escape(&token),
    );

    page(StatusCode::OK, "Add a passkey", &body)
}

#[derive(Deserialize)]
struct LabelBody {
    label: String,
}

async fn enroll_options(
    State(state): State<WebState>,
    Path(token): Path<String>,
    Json(body): Json<LabelBody>,
) -> Response {
    let passkeys = Arc::clone(&state.passkeys);
    let started =
        tokio::task::spawn_blocking(move || passkeys.start_registration(&token, &body.label)).await;

    match started {
        Ok(Ok((ceremony, options))) => {
            Json(json!({ "ceremony": ceremony, "options": options })).into_response()
        }
        Ok(Err(error)) => passkey_error(&error),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "registration failed"),
    }
}

#[derive(Deserialize)]
struct RegisterBody {
    ceremony: String,
    credential: RegisterPublicKeyCredential,
}

async fn enroll_finish(
    State(state): State<WebState>,
    Path(token): Path<String>,
    Json(body): Json<RegisterBody>,
) -> Response {
    let passkeys = Arc::clone(&state.passkeys);
    let finished = tokio::task::spawn_blocking(move || {
        passkeys.finish_registration(&token, &body.ceremony, &body.credential)
    })
    .await;

    match finished {
        Ok(Ok(id)) => Json(json!({
            "ok": true,
            "id": id,
            "message": "Passkey added. You can close this page.",
        }))
        .into_response(),
        Ok(Err(error)) => passkey_error(&error),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "registration failed"),
    }
}

async fn webauthn_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        WEBAUTHN_JS,
    )
        .into_response()
}

#[derive(Deserialize)]
struct StatsQuery {
    since: Option<String>,
}

async fn stats_page(State(state): State<WebState>, Query(query): Query<StatsQuery>) -> Response {
    let window = match query.since.as_deref().map(parse_since) {
        Some(Ok(window)) => window,
        Some(Err(message)) => {
            return page(
                StatusCode::BAD_REQUEST,
                "Usage",
                &format!("<h1>Usage</h1><p>{}</p>", escape(&message)),
            );
        }
        None => DEFAULT_STATS_WINDOW,
    };

    let directory = state.state_dir.clone();
    let stats = tokio::task::spawn_blocking(move || {
        let connection = store::open_read_only(&directory).map_err(|error| error.to_string())?;

        Reporter::new(&connection, window)
            .stats()
            .map_err(|error| error.to_string())
    })
    .await;
    let error = match stats {
        Ok(Ok(stats)) => {
            return page(
                StatusCode::OK,
                "codemode-mcp usage",
                &stats_html(&stats, window),
            );
        }
        Ok(Err(error)) => error,
        Err(error) => error.to_string(),
    };
    // database errors can name state paths, so they stay in the local log
    tracing::warn!(%error, "usage stats unavailable");

    page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Usage",
        "<h1>Usage</h1><p>Usage data is unavailable.</p>",
    )
}

fn stats_html(stats: &Stats, window: Duration) -> String {
    let mut clients = String::new();
    for client in &stats.clients {
        clients.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&client.client),
            client.sessions,
            client.calls,
            client.executions,
            escape(&percent(client.success_rate())),
            client
                .mean_attempts
                .map_or_else(|| "-".to_owned(), |mean| format!("{mean:.1}")),
        ));
    }
    let fingerprints: String = stats
        .fingerprints
        .iter()
        .map(|(fingerprint, count)| {
            format!(
                "<tr><td>{count}</td><td><code>{}</code></td></tr>",
                escape(fingerprint)
            )
        })
        .collect();
    let slow: String = stats
        .slow_tools
        .iter()
        .map(|tool| {
            format!(
                "<tr><td>{}</td><td>{:.0} ms</td><td>{} ms</td><td>{}</td></tr>",
                escape(&tool.tool),
                tool.mean_ms,
                tool.max_ms,
                tool.calls
            )
        })
        .collect();
    let approvals = &stats.approvals;

    format!(
        r#"<h1>codemode-mcp usage</h1>
<p class="meta">Last {window}. Use <code>?since=1d</code> to change the window.</p>
<h2>Clients</h2>
<table><tr><th>Client</th><th>Sessions</th><th>Calls</th><th>Executions</th><th>Success</th><th>Attempts to success</th></tr>{clients}</table>
<h2>Top error fingerprints</h2>
<table><tr><th>Count</th><th>Fingerprint</th></tr>{fingerprints}</table>
<h2>Slowest upstream tools</h2>
<table><tr><th>Tool</th><th>Mean</th><th>Max</th><th>Calls</th></tr>{slow}</table>
<h2>Approvals</h2>
<p>{requested} requested, {approved} approved, {denied} denied, {expired} expired; median wait {wait}</p>"#,
        window = escape(&human_duration(window.as_millis() as i64)),
        requested = approvals.requested,
        approved = approvals.approved,
        denied = approvals.denied,
        expired = approvals.expired,
        wait = escape(
            &approvals
                .median_wait_ms
                .map_or_else(|| "-".to_owned(), human_duration)
        ),
    )
}
