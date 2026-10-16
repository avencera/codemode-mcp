//! Admin API for the local CLI, served on its own loopback listener
//!
//! `tailscale serve` proxies phone traffic from 127.0.0.1 to the main
//! listener, so a peer check there would let the tailnet in. The admin
//! routes live on a separate listener that the proxy never targets, and
//! still check the socket peer (never the `Host` header) and refuse
//! anything that looks proxied

use std::{
    io::Write,
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::HeaderMap,
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use hmac::{KeyInit, Mac};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    app::App,
    approvals::{AdminAction, AdminRequest, Approvals, Verdict, Waiting, confirmation_code},
    companion::{self, CompanionFailure, Ticket},
    config::Config,
    gateway::{Gateway, WarmResult},
    host::is_direct_local,
    notify::{Notification, Priority},
    oauth::{Callback, LoginStatus, OAuthError},
    passkeys::{PasskeyError, Passkeys},
    secrets,
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
    config: Arc<Config>,
    public_base: String,
    /// What the invite routes require; `None` when the token file could not
    /// be set up, and then they refuse
    owner: Option<Arc<Owner>>,
}

/// File in the state directory holding the token the invite routes require
pub const OWNER_TOKEN_FILE: &str = "admin.token";

/// Header carrying a request's owner proof, `<server nonce>:<hex HMAC>`
pub const OWNER_PROOF_HEADER: &str = "x-codemode-owner-proof";

/// How long a challenge's nonce can be used
const CHALLENGE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(60);
/// Most nonces outstanding at once; the oldest goes first
const MAX_CHALLENGES: usize = 64;
/// Longest client nonce accepted
const MAX_NONCE_CHARS: usize = 128;

/// Body of `POST /admin/owner/challenge`
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// Random text the daemon must prove it can answer
    pub client_nonce: String,
}

/// Answer of `POST /admin/owner/challenge`
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Single-use nonce for one owner request
    pub server_nonce: String,
    /// [`daemon_proof`] of both nonces
    pub proof: String,
}

/// The daemon's proof that it holds the owner token, so the CLI never
/// trusts another program that took the admin port while the daemon was down
pub fn daemon_proof(token: &str, client_nonce: &str, server_nonce: &str) -> String {
    owner_mac(token, &["daemon", client_nonce, server_nonce])
        .map(|mac| hex::encode(mac.finalize().into_bytes()))
        .unwrap_or_default()
}

/// Whether `proof` is [`daemon_proof`] of the nonces, compared in constant
/// time
pub fn daemon_proof_matches(
    token: &str,
    client_nonce: &str,
    server_nonce: &str,
    proof: &str,
) -> bool {
    proof_matches(token, &["daemon", client_nonce, server_nonce], proof)
}

/// A request's proof that its sender holds the owner token, bound to one
/// server nonce and the route, so the token itself never crosses the socket
/// and a proof cannot be replayed
pub fn request_proof(token: &str, server_nonce: &str, path: &str) -> String {
    owner_mac(token, &["request", server_nonce, path])
        .map(|mac| hex::encode(mac.finalize().into_bytes()))
        .unwrap_or_default()
}

/// HMAC-SHA256 under `token` of `parts`, each ended by a NUL so no two
/// lists of parts read the same
fn owner_mac(token: &str, parts: &[&str]) -> Option<hmac::Hmac<sha2::Sha256>> {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(token.as_bytes()).ok()?;
    mac.update(b"codemode-mcp owner\0");
    for part in parts {
        mac.update(part.as_bytes());
        mac.update(b"\0");
    }

    Some(mac)
}

fn proof_matches(token: &str, parts: &[&str], proof: &str) -> bool {
    let Ok(proof) = hex::decode(proof) else {
        return false;
    };

    // verify_slice compares in constant time
    owner_mac(token, parts).is_some_and(|mac| mac.verify_slice(&proof).is_ok())
}

/// The owner token and the challenges handed out for it
struct Owner {
    token: String,
    nonces: std::sync::Mutex<Vec<(String, std::time::Instant)>>,
}

impl Owner {
    fn challenge(&self, client_nonce: &str) -> ChallengeResponse {
        let server_nonce = hex::encode(rand::random::<[u8; 16]>());
        let mut nonces = self
            .nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        nonces.retain(|(_, issued)| issued.elapsed() < CHALLENGE_LIFETIME);
        if nonces.len() >= MAX_CHALLENGES {
            nonces.remove(0);
        }
        nonces.push((server_nonce.clone(), std::time::Instant::now()));

        ChallengeResponse {
            proof: daemon_proof(&self.token, client_nonce, &server_nonce),
            server_nonce,
        }
    }

    /// Whether `header` proves the owner sent this request to `path`; its
    /// nonce is used up either way
    fn verify(&self, header: &str, path: &str) -> bool {
        let Some((server_nonce, proof)) = header.split_once(':') else {
            return false;
        };
        let issued = {
            let mut nonces = self
                .nonces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let found = nonces.iter().position(|(nonce, _)| nonce == server_nonce);
            found.map(|index| nonces.remove(index).1)
        };

        issued.is_some_and(|issued| issued.elapsed() < CHALLENGE_LIFETIME)
            && proof_matches(&self.token, &["request", server_nonce, path], proof)
    }
}

/// The token in `state_dir`, created when missing
///
/// The admin listener only checks that a caller is on this Mac, which any
/// account is. An invite adds a source of secret values, so its routes also
/// need this token, which only the owner's account can read (mode 0600)
pub fn owner_token(state_dir: &std::path::Path) -> std::io::Result<String> {
    let path = state_dir.join(OWNER_TOKEN_FILE);
    match std::fs::read_to_string(&path) {
        Ok(token) => {
            // a copy restored with wider permissions is narrowed again
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

            return Ok(token.trim().to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let token = hex::encode(rand::random::<[u8; 32]>());
    // written whole beside it, then linked into place: two daemons starting
    // together keep one token, and neither reads a half-written file
    let temp = state_dir.join(format!(
        ".{OWNER_TOKEN_FILE}.{}",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| file.write_all(token.as_bytes()))
        .and_then(|()| std::fs::hard_link(&temp, &path));
    let _ = std::fs::remove_file(&temp);
    match written {
        Ok(()) => Ok(token),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(std::fs::read_to_string(&path)?.trim().to_owned())
        }
        Err(error) => Err(error),
    }
}

impl AdminState {
    /// The refusal for a request to `path` without a valid owner proof
    fn not_owner(&self, headers: &HeaderMap, path: &str) -> Option<Response> {
        let Some(owner) = &self.owner else {
            return Some(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the daemon could not set up its owner token; see its log",
            ));
        };
        let proof = headers
            .get(OWNER_PROOF_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !owner.verify(proof, path) {
            return Some(error(
                StatusCode::FORBIDDEN,
                "this needs a proof made with the owner token in the daemon's state directory; \
                 run the CLI as the user that runs the daemon",
            ));
        }

        None
    }
}

/// Hands out a single-use nonce for an owner request, with the daemon's
/// proof that it holds the token
async fn owner_challenge(
    State(state): State<AdminState>,
    Json(request): Json<ChallengeRequest>,
) -> Response {
    let Some(owner) = &state.owner else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the daemon could not set up its owner token; see its log",
        );
    };
    let nonce = &request.client_nonce;
    if nonce.is_empty() || nonce.len() > MAX_NONCE_CHARS {
        return error(
            StatusCode::BAD_REQUEST,
            "client_nonce must be 1 to 128 characters",
        );
    }

    Json(owner.challenge(nonce)).into_response()
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

/// Answer of `POST /admin/companion/invite`
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteResponse {
    /// This gateway's endpoint id
    pub gateway: EndpointId,
    /// Short host name of this Mac
    pub gateway_name: String,
    /// Sorted, deduplicated references in the configured servers' `headers`
    /// and `env`
    pub references: Vec<String>,
}

impl InviteResponse {
    /// The ticket that carries this answer to the companion Mac
    pub fn ticket(self) -> Ticket {
        Ticket {
            gateway: self.gateway,
            gateway_name: self.gateway_name,
            references: self.references,
        }
    }
}

/// Body of `POST /admin/companion/invite/open`
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct InviteOpenRequest {
    /// Seconds the invite stays open; at most ten minutes, the default
    #[serde(default)]
    pub valid_secs: Option<u64>,
}

/// Answer of `POST /admin/companion/invite/open`
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteOpenResponse {
    /// Names the invite to `POST /admin/companion/invite/status`
    pub invite: String,
    /// The `cmcp2` ticket the other Mac pairs with
    pub ticket: String,
    /// Short host name of this Mac
    pub gateway_name: String,
    /// Seconds the invite stays open
    pub valid_secs: u64,
}

/// Body of `POST /admin/companion/invite/status`
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteStatusRequest {
    /// From [`InviteOpenResponse::invite`]
    pub invite: String,
}

/// Body of `POST /admin/companion/check`, which asks every companion and phone
#[derive(Debug, Serialize, Deserialize)]
pub struct CompanionCheckRequest {
    /// The reference to ask the companions for
    pub reference: String,
}

/// Body of `POST /admin/companion/check/one`
///
/// A route of its own rather than a field on [`CompanionCheckRequest`]: a
/// daemon from before it answers 404 instead of ignoring the name and asking
/// every device
#[derive(Debug, Serialize, Deserialize)]
pub struct CompanionCheckOneRequest {
    /// The reference to ask for
    pub reference: String,
    /// The companion or phone to ask, by its name in `secrets.companions` or
    /// `secrets.phones`
    pub companion: String,
}

/// What one companion did with a check; never the value
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionCheckResult {
    /// The companion read it
    Ok {
        /// Length of the value in bytes
        bytes: usize,
    },
    /// The companion did not
    Error {
        /// Why, from the companion or the connection
        message: String,
    },
}

/// One companion in the answer of `POST /admin/companion/check`
#[derive(Debug, Serialize, Deserialize)]
pub struct CompanionCheckEntry {
    /// Name from `secrets.companions`
    pub name: String,
    /// How it answered
    pub result: CompanionCheckResult,
}

/// Answer of `POST /admin/companion/check`
#[derive(Debug, Serialize, Deserialize)]
pub struct CompanionCheckResponse {
    /// One entry per configured companion
    pub companions: Vec<CompanionCheckEntry>,
}

/// Body of `POST /admin/companion/create`
#[derive(Serialize, Deserialize)]
pub struct CompanionCreateRequest {
    /// The companion to ask; unset, the only one listed
    #[serde(default)]
    pub companion: Option<String>,
    /// The item and its value
    #[serde(flatten)]
    pub item: companion::NewItem,
}

impl std::fmt::Debug for CompanionCreateRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompanionCreateRequest")
            .field("companion", &self.companion)
            .field("item", &self.item)
            .finish()
    }
}

/// Answer of `POST /admin/companion/create`; never the value
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionCreateResponse {
    /// The companion created the item
    Created {
        /// Companion name
        companion: String,
        /// 1Password's id for the new item
        id: String,
        /// `op://vault/title/field` for the value
        reference: String,
    },
    /// Nothing was created
    Refused {
        /// Why, in the companion's words or the connection's
        message: String,
    },
    /// No answer came, so the item may or may not exist
    Unconfirmed {
        /// What went wrong
        message: String,
    },
}

/// Admin routes; serve them with connect info so the peer can be checked
pub fn router(app: &App) -> Router {
    let state = AdminState {
        passkeys: Arc::clone(app.passkeys()),
        approvals: Arc::clone(app.approvals()),
        gateway: Arc::clone(app.gateway()),
        config: Arc::clone(app.config()),
        public_base: app.config().public_base(),
        owner: match owner_token(app.state_dir()) {
            Ok(token) => Some(Arc::new(Owner {
                token,
                nonces: std::sync::Mutex::default(),
            })),
            Err(failure) => {
                tracing::error!(error = %failure, "could not set up the owner token");

                None
            }
        },
    };

    Router::new()
        .route("/admin/enroll", post(enroll))
        .route("/admin/passkey/remove", post(remove_passkey))
        .route("/admin/warm", post(warm))
        .route("/admin/owner/challenge", post(owner_challenge))
        .route("/admin/companion/invite", post(companion_invite))
        .route("/admin/companion/invite/open", post(companion_invite_open))
        .route(
            "/admin/companion/invite/status",
            post(companion_invite_status),
        )
        .route("/admin/companion/check", post(companion_check))
        .route("/admin/companion/check/one", post(companion_check_one))
        .route("/admin/companion/create", post(companion_create))
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

/// This gateway's id and the references its servers use, in `headers`,
/// `env`, `url` and OAuth `client_secret`, for a companion Mac to pair with
async fn companion_invite(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    // the ticket lists every reference the servers use
    if let Some(refused) = state.not_owner(&headers, "/admin/companion/invite") {
        return refused;
    }
    let gateway = match state.gateway.companions().id().await {
        Ok(id) => id,
        Err(failure) => {
            tracing::warn!(error = %failure, "could not load the gateway identity");

            return error(StatusCode::INTERNAL_SERVER_ERROR, &failure.to_string());
        }
    };

    Json(InviteResponse {
        gateway,
        gateway_name: companion::short_hostname(),
        references: config_references(&state.config),
    })
    .into_response()
}

/// Opens an invite that one Mac can register with over iroh
async fn companion_invite_open(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(request): Json<InviteOpenRequest>,
) -> Response {
    if let Some(refused) = state.not_owner(&headers, "/admin/companion/invite/open") {
        return refused;
    }
    let lifetime = request.valid_secs.map_or(
        companion::MAX_INVITE_LIFETIME,
        std::time::Duration::from_secs,
    );
    if lifetime.is_zero() || lifetime > companion::MAX_INVITE_LIFETIME {
        return error(
            StatusCode::BAD_REQUEST,
            &format!(
                "valid_secs must be 1 to {}",
                companion::MAX_INVITE_LIFETIME.as_secs()
            ),
        );
    }
    let gateway_name = companion::short_hostname();
    let opened = state
        .gateway
        .companions()
        .open_invite(
            gateway_name.clone(),
            config_references(&state.config),
            lifetime,
        )
        .await;

    match opened {
        Ok(opened) => Json(InviteOpenResponse {
            invite: opened.id,
            ticket: opened.ticket.encode(),
            gateway_name,
            valid_secs: opened.lifetime.as_secs(),
        })
        .into_response(),
        Err(failure) => {
            tracing::warn!(error = %failure, "could not open an invite");

            error(StatusCode::INTERNAL_SERVER_ERROR, &failure.to_string())
        }
    }
}

async fn companion_invite_status(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(request): Json<InviteStatusRequest>,
) -> Response {
    if let Some(refused) = state.not_owner(&headers, "/admin/companion/invite/status") {
        return refused;
    }
    match state.gateway.companions().invite_status(&request.invite) {
        Some(status) => Json(status).into_response(),
        None => error(StatusCode::NOT_FOUND, "no such invite"),
    }
}

/// Sorted, deduplicated references in the servers' `headers`, `env`, `url`
/// and `client_secret`, and in `[logins]`: what a companion is allowed to read
fn config_references(config: &Config) -> Vec<String> {
    let mut references = std::collections::BTreeSet::new();
    for server in config.servers.values() {
        let values = server.headers.values().chain(server.env.values());
        for value in values
            .chain(server.client_secret.as_ref())
            .chain(server.url.as_ref())
        {
            // validated at load, so a malformed value cannot be here
            for reference in secrets::references(value).unwrap_or_default() {
                references.insert(reference.to_owned());
            }
        }
    }
    for login in config.logins.values() {
        references.extend(login.references().map(str::to_owned));
    }

    references.into_iter().collect()
}

/// Asks a companion Mac to create one item; the value is passed on and
/// kept nowhere
async fn companion_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(request): Json<CompanionCreateRequest>,
) -> Response {
    // the body holds a secret and the route writes to 1Password
    if let Some(refused) = state.not_owner(&headers, "/admin/companion/create") {
        return refused;
    }

    // refused here too, so a bad name never reaches a companion's prompt
    if let Err(message) = crate::secrets::check_new_item(&request.item) {
        return Json(CompanionCreateResponse::Refused { message }).into_response();
    }

    let answer = state
        .gateway
        .companions()
        .create(request.companion.as_deref(), &request.item)
        .await;

    Json(match answer {
        Ok((companion, created)) => CompanionCreateResponse::Created {
            companion,
            id: created.id,
            reference: created.reference,
        },
        Err(CompanionFailure::Refused { message, .. }) => {
            CompanionCreateResponse::Refused { message }
        }
        Err(failure @ CompanionFailure::CreateUnconfirmed { .. }) => {
            CompanionCreateResponse::Unconfirmed {
                message: failure.to_string(),
            }
        }
        Err(failure) => CompanionCreateResponse::Refused {
            message: failure.to_string(),
        },
    })
    .into_response()
}

/// Asks the companions, and only them, to read a reference; local `op` and
/// the cache are skipped, and the value never leaves the daemon
async fn companion_check(
    State(state): State<AdminState>,
    Json(request): Json<CompanionCheckRequest>,
) -> Response {
    check_companions(&state, &request.reference, None).await
}

/// [`companion_check`] for one named companion or phone
async fn companion_check_one(
    State(state): State<AdminState>,
    Json(request): Json<CompanionCheckOneRequest>,
) -> Response {
    check_companions(&state, &request.reference, Some(&request.companion)).await
}

async fn check_companions(state: &AdminState, reference: &str, only: Option<&str>) -> Response {
    let reference = reference.trim();
    if !secrets::is_reference(reference) {
        return error(
            StatusCode::BAD_REQUEST,
            "the reference must look like op://vault/item/field",
        );
    }
    let companions = state.gateway.companions();
    let names = companions.names();
    if names.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "no companions or phones are configured under [secrets]",
        );
    }
    if let Some(only) = only.filter(|only| !names.iter().any(|name| name == only)) {
        return error(
            StatusCode::BAD_REQUEST,
            &format!(
                "no companion or phone named {only}; configured: {}",
                names.join(", ")
            ),
        );
    }

    let companions = state
        .gateway
        .companions()
        .check(reference, only)
        .await
        .into_iter()
        .map(|outcome| CompanionCheckEntry {
            name: outcome.name,
            result: match outcome.result {
                Ok(bytes) => CompanionCheckResult::Ok { bytes },
                Err(failure) => CompanionCheckResult::Error {
                    message: failure.to_string(),
                },
            },
        })
        .collect();

    Json(CompanionCheckResponse { companions }).into_response()
}
