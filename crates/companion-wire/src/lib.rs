//! What the codemode-mcp gateway, its companion Macs and its paired phones
//! send each other over iroh
//!
//! Shared by the gateway and the phone's core, so both read one definition of
//! the wire, the tickets and the seal format without the phone depending on
//! the gateway

pub mod mobile;
#[cfg(feature = "seal")]
pub mod seal;
pub mod ticket;
pub mod wire;

use std::time::Duration;

/// Protocol name of the companion exchange, which the gateway dials
pub const ALPN: &[u8] = b"codemode-mcp/companion/1";

/// Protocol name of pairing, which the gateway accepts only while an invite
/// is open
pub const PAIR_ALPN: &[u8] = b"codemode-mcp/pair/1";

/// Protocol name of the phone exchange, which the phone dials and the
/// gateway accepts only from the phones its config lists
pub const MOBILE_ALPN: &[u8] = b"codemode-mcp/mobile/1";

/// Longest request or response body; references and the values read for
/// them are far below this
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// How long one companion or phone request may take, including the owner's
/// answer on the other device; the gateway gives up after it and the other
/// device takes its prompt down
pub const ASK_TIMEOUT: Duration = Duration::from_secs(120);
