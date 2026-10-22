//! Companions: other Macs that read 1Password references for the gateway
//!
//! The gateway's `op read` needs a Touch ID answer on the Mac that runs it.
//! When the owner is on another Mac, that Mac runs `codemode-mcp companion
//! serve`: the gateway asks it over iroh, it asks Touch ID on its own screen
//! naming the reference, runs its own `op read` and sends the value back.
//! 1Password stays the only source of truth, and no value is stored on
//! either side beyond the gateway's in-memory cache

mod apns;
mod client;
mod find;
mod identity;
mod invite;
mod join;
mod pair;
mod phone;
mod program;
mod server;
mod trust;

/// The wire types, shared with the phone's core
pub use companion_wire::{mobile, ticket, wire};

pub use client::{CheckOutcome, CompanionFailure, Companions};
pub use companion_wire::{
    ALPN, ASK_TIMEOUT, MAX_BODY_BYTES, MAX_PHONE_READ_BYTES, MOBILE_ALPN, PAIR_ALPN,
};
pub use find::{FindAsk, FindBatches, ProgramFound};
pub use identity::{IdentityError, Role, load_or_create};
pub use invite::{InviteStatus, MAX_INVITE_LIFETIME, OpenedInvite};
pub use join::{JoinError, Joined, Joining, join};
pub use pair::{PairError, Paired, Pairing, companion_id, pair};
pub use program::{
    ProgramAsk, ProgramRead, ProgramReadError, ProgramTarget, ProgramValues, checked_query,
};
pub use server::{CompanionHandle, ServeError, serve};
pub use ticket::{
    AnyTicket, INVITE_PREFIX, InviteSecret, InviteTicket, TICKET_PREFIX, Ticket, TicketError,
};
pub use trust::{Device, DeviceTrust, ListedDevice};
pub use wire::{
    CompanionCreateRequest, CompanionCreateResponse, CompanionErrorCode, CompanionFault,
    CompanionFindRequest, CompanionFindResponse, CompanionProgramRequest, CompanionRequest,
    CompanionResponse, CreatedItem, FindQuery, Found, FoundField, FoundItem, MALFORMED_REQUEST,
    MAX_FIND_QUERIES, NewItem, PairCheck, PairRequest, PairResponse, ProgramBatch, ProgramValue,
    Registered, Registration,
};

use std::time::Duration;

use crate::{
    config::{MAX_MAC_NAME_CHARS, is_mac_name},
    prompt,
};

use iroh::{
    Endpoint,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use serde::{Serialize, de::DeserializeOwned};

/// Port a companion listens on when the gateway has discovery off and
/// dials it directly
pub const DIRECT_PORT: u16 = 7678;

/// How long a peer may take to finish the handshake
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Closes its connection when dropped
///
/// Dropping a connection handle does not tell the other side, so a request
/// that is given up (another source answered first, or the process is
/// stopping) would leave a Touch ID prompt up on the companion's screen
struct Hangup(Connection);

impl Drop for Hangup {
    fn drop(&mut self) {
        self.0.close(0_u32.into(), b"done");
    }
}

/// Sends `request` on a new stream of `connection` and reads the one answer
async fn ask<R: DeserializeOwned>(
    connection: &Connection,
    request: &impl Serialize,
) -> Result<R, String> {
    let request = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    send.write_all(&request)
        .await
        .map_err(|error| error.to_string())?;
    send.finish().map_err(|error| error.to_string())?;
    let body = receive
        .read_to_end(MAX_BODY_BYTES)
        .await
        .map_err(|error| error.to_string())?;

    serde_json::from_slice(&body).map_err(|error| format!("malformed answer: {error}"))
}

/// Reads one request from `receive`; `None` when it is unreadable, too
/// large or not a `T`
async fn read_request<T: DeserializeOwned>(receive: &mut RecvStream) -> Option<T> {
    let body = receive.read_to_end(MAX_BODY_BYTES).await.ok()?;

    serde_json::from_slice(&body).ok()
}

/// Writes `response` and ends the stream; `false` when the peer is gone
async fn answer(send: &mut SendStream, response: &impl Serialize) -> bool {
    let Ok(bytes) = serde_json::to_vec(response) else {
        return false;
    };

    send.write_all(&bytes).await.is_ok() && send.finish().is_ok()
}

/// An iroh endpoint as `secret_key`; the companion answers [`ALPN`]. The
/// gateway advertises none, so incoming connections to it are refused during
/// the handshake instead of queueing unaccepted, except [`PAIR_ALPN`] while
/// an invite is open
///
/// With `discovery` it uses n0's relays and DNS lookup, so peers find each
/// other by id alone. Without, it has neither and peers must dial known
/// addresses; it also never waits for a relay, which would never come
async fn bind_endpoint(
    role: Role,
    secret_key: iroh::SecretKey,
    discovery: bool,
    listen: Option<std::net::SocketAddr>,
) -> Result<Endpoint, String> {
    let builder = if discovery {
        Endpoint::builder(presets::N0)
    } else {
        Endpoint::builder(presets::Minimal)
    };
    let mut builder = builder.secret_key(secret_key);
    if role == Role::Companion {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    if let Some(listen) = listen {
        builder = builder
            .bind_addr(listen)
            .map_err(|error| format!("cannot listen on {listen}: {error}"))?;
    }

    builder
        .bind()
        .await
        .map_err(|error| format!("cannot bind the iroh endpoint: {error}"))
}

/// This host's name up to the first dot, which names the Mac in tickets and
/// in the companion's own config; anything the config would refuse as a
/// Mac name is replaced, so pairing never fails on an odd host name
pub fn short_hostname() -> String {
    let full = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned();
    let short = full.split('.').next().unwrap_or_default();
    let name = prompt::one_line(short, MAX_MAC_NAME_CHARS);

    if is_mac_name(&name) {
        name
    } else {
        "main".to_owned()
    }
}
