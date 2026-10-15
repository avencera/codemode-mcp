//! Companions: other Macs that read 1Password references for the gateway
//!
//! The gateway's `op read` needs a Touch ID answer on the Mac that runs it.
//! When the owner is on another Mac, that Mac runs `codemode-mcp companion
//! serve`: the gateway asks it over iroh, it asks Touch ID on its own screen
//! naming the reference, runs its own `op read` and sends the value back.
//! 1Password stays the only source of truth, and no value is stored on
//! either side beyond the gateway's in-memory cache

mod client;
mod identity;
mod pair;
mod server;
mod ticket;
mod wire;

pub use client::{CheckOutcome, CompanionFailure, Companions};
pub use identity::{IdentityError, Role, load_or_create};
pub use pair::{PairError, Paired, Pairing, companion_id, pair};
pub use server::{CompanionHandle, ServeError, serve};
pub use ticket::{TICKET_PREFIX, Ticket, TicketError};
pub use wire::{CompanionErrorCode, CompanionFault, CompanionRequest, CompanionResponse};

use std::time::Duration;

use crate::{
    config::{MAX_MAC_NAME_CHARS, is_mac_name},
    prompt,
};

use iroh::{
    Endpoint,
    endpoint::{Connection, presets},
};

/// Protocol name of the companion exchange
pub const ALPN: &[u8] = b"codemode-mcp/companion/1";

/// Longest request or response body; references and the values read for
/// them are far below this
const MAX_BODY_BYTES: usize = 64 * 1024;
/// How long one companion request may take, including the owner's Touch ID
/// answer on the other Mac; the gateway gives up after it and the companion
/// takes its prompt down
pub const ASK_TIMEOUT: Duration = Duration::from_secs(120);

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

/// An iroh endpoint as `secret_key`; the companion answers [`ALPN`], the
/// gateway only dials, so it advertises none and incoming connections to it
/// are refused during the handshake instead of queueing unaccepted
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
