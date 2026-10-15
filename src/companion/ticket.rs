//! The one-line tickets `companion invite` prints and `companion pair` reads
//!
//! An invite ticket registers the new Mac with the running gateway over
//! iroh. A manual ticket carries everything the companion's config needs,
//! for pairing when the gateway cannot be reached

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

/// Start of every manual ticket; the digit is the format version
pub const TICKET_PREFIX: &str = "cmcp1";

/// Start of every invite ticket
pub const INVITE_PREFIX: &str = "cmcp2";

/// Bytes of an invite's secret
const SECRET_BYTES: usize = 16;

/// Bytes of an endpoint id
const ID_BYTES: usize = 32;

/// Why a ticket could not be read
#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    /// The text starts with neither prefix
    #[error("not a companion ticket: it should start with `{INVITE_PREFIX}` or `{TICKET_PREFIX}`")]
    Prefix,
    /// The text after the prefix is not base64url
    #[error("the ticket is not valid base64url: {0}")]
    Encoding(base64::DecodeError),
    /// The decoded text is not the ticket's JSON
    #[error("the ticket content is malformed: {0}")]
    Content(serde_json::Error),
    /// The decoded bytes are not an invite
    #[error("the ticket content is malformed: {0}")]
    Invite(&'static str),
}

/// What a companion needs to know about its gateway, for pairing by hand
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    /// The gateway's endpoint id
    pub gateway: EndpointId,
    /// Short host name of the gateway Mac
    pub gateway_name: String,
    /// References found in the gateway's server config, sorted
    pub references: Vec<String>,
}

impl Ticket {
    /// `cmcp1` followed by the base64url (no padding) of the JSON
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_vec(self)?;

        Ok(format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
    }

    /// Reads a ticket as [`Ticket::encode`] wrote it
    pub fn decode(text: &str) -> Result<Self, TicketError> {
        let body = text
            .trim()
            .strip_prefix(TICKET_PREFIX)
            .ok_or(TicketError::Prefix)?;
        let json = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(TicketError::Encoding)?;

        serde_json::from_slice(&json).map_err(TicketError::Content)
    }
}

/// The single-use secret of an invite
///
/// It only lets one Mac register within the invite's lifetime; reading a
/// reference still takes a Touch ID approval on that Mac
#[derive(Clone, PartialEq, Eq)]
pub struct InviteSecret([u8; SECRET_BYTES]);

impl InviteSecret {
    /// A fresh random secret
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// The secret as lowercase hex, as the pairing request carries it
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Reads [`InviteSecret::to_hex`]; `None` for anything else
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = hex::decode(text).ok()?;

        Some(Self(bytes.try_into().ok()?))
    }

    /// The raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for InviteSecret {
    // the secret stays out of logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InviteSecret(..)")
    }
}

/// An invite to register with a running gateway
///
/// Binary rather than JSON, and without the references, which the gateway
/// sends at registration, so the install one-liner holding it stays small
/// enough for a QR code that scans off a terminal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteTicket {
    /// The gateway's endpoint id
    pub gateway: EndpointId,
    /// Proves the companion was given this ticket
    pub secret: InviteSecret,
    /// Where to dial the gateway; only set when it has discovery off
    pub addrs: Vec<SocketAddr>,
}

impl InviteTicket {
    /// `cmcp2` followed by the base64url (no padding) of the id, the secret
    /// and each address as a 4 or 6 tag, the IP and the port
    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(ID_BYTES + SECRET_BYTES + 7 * self.addrs.len());
        bytes.extend_from_slice(self.gateway.as_bytes());
        bytes.extend_from_slice(self.secret.as_bytes());
        for addr in &self.addrs {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    bytes.push(4);
                    bytes.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    bytes.push(6);
                    bytes.extend_from_slice(&ip.octets());
                }
            }
            bytes.extend_from_slice(&addr.port().to_be_bytes());
        }

        format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Reads a ticket as [`InviteTicket::encode`] wrote it
    pub fn decode(text: &str) -> Result<Self, TicketError> {
        let body = text
            .trim()
            .strip_prefix(INVITE_PREFIX)
            .ok_or(TicketError::Prefix)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(TicketError::Encoding)?;

        let short = TicketError::Invite("it is cut short");
        let (id, rest) = bytes.split_at_checked(ID_BYTES).ok_or(short)?;
        let id: [u8; ID_BYTES] = id.try_into().map_err(|_| TicketError::Invite("bad id"))?;
        let gateway = EndpointId::from_bytes(&id)
            .map_err(|_| TicketError::Invite("the gateway id is not a valid key"))?;
        let (secret, mut rest) = rest
            .split_at_checked(SECRET_BYTES)
            .ok_or(TicketError::Invite("it is cut short"))?;
        let secret = InviteSecret(
            secret
                .try_into()
                .map_err(|_| TicketError::Invite("bad secret"))?,
        );

        let mut addrs = Vec::new();
        while let Some((&tag, after)) = rest.split_first() {
            let (ip, after): (IpAddr, &[u8]) = match tag {
                4 => {
                    let (octets, after) = after
                        .split_first_chunk::<4>()
                        .ok_or(TicketError::Invite("an address is cut short"))?;
                    (Ipv4Addr::from(*octets).into(), after)
                }
                6 => {
                    let (octets, after) = after
                        .split_first_chunk::<16>()
                        .ok_or(TicketError::Invite("an address is cut short"))?;
                    (Ipv6Addr::from(*octets).into(), after)
                }
                _ => return Err(TicketError::Invite("an address has an unknown kind")),
            };
            let (port, after) = after
                .split_first_chunk::<2>()
                .ok_or(TicketError::Invite("an address is cut short"))?;
            addrs.push(SocketAddr::new(ip, u16::from_be_bytes(*port)));
            rest = after;
        }

        Ok(Self {
            gateway,
            secret,
            addrs,
        })
    }
}

/// Either kind of ticket, as `companion pair` takes it
#[derive(Debug, Clone)]
pub enum AnyTicket {
    /// Registers with the running gateway
    Invite(InviteTicket),
    /// Pairs without reaching the gateway
    Manual(Ticket),
}

impl AnyTicket {
    /// Reads either kind, by its prefix
    pub fn decode(text: &str) -> Result<Self, TicketError> {
        if text.trim().starts_with(INVITE_PREFIX) {
            InviteTicket::decode(text).map(Self::Invite)
        } else {
            Ticket::decode(text).map(Self::Manual)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InviteSecret, InviteTicket, TicketError};

    #[test]
    fn an_invite_round_trips_with_both_address_kinds() -> Result<(), TicketError> {
        let ticket = InviteTicket {
            gateway: iroh::SecretKey::from_bytes(&[3; 32]).public(),
            secret: InviteSecret::generate(),
            addrs: vec![
                "100.64.0.5:7678".parse().map_err(|_| TicketError::Prefix)?,
                "[fd7a:115c:a1e0::5]:51000"
                    .parse()
                    .map_err(|_| TicketError::Prefix)?,
            ],
        };

        assert_eq!(InviteTicket::decode(&ticket.encode())?, ticket);

        // a truncated ticket is refused rather than read short
        let encoded = ticket.encode();
        assert!(InviteTicket::decode(&encoded[..encoded.len() - 3]).is_err());

        Ok(())
    }
}
