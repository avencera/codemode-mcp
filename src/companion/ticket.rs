//! The one-line ticket `companion invite` prints and `companion pair` reads

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

/// Start of every ticket; the digit is the format version
pub const TICKET_PREFIX: &str = "cmcp1";

/// Why a ticket could not be read
#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    /// The text does not start with [`TICKET_PREFIX`]
    #[error("not a companion ticket: it should start with `{TICKET_PREFIX}`")]
    Prefix,
    /// The text after the prefix is not base64url
    #[error("the ticket is not valid base64url: {0}")]
    Encoding(base64::DecodeError),
    /// The decoded text is not the ticket's JSON
    #[error("the ticket content is malformed: {0}")]
    Content(serde_json::Error),
}

/// What a companion needs to know about its gateway
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
