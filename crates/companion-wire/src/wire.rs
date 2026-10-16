//! What gateway and companion send each other: one JSON request and one JSON
//! response per bidirectional stream
//!
//! A phone answers the same [`CompanionResponse`]; its own request and
//! registration are in [`crate::mobile`]

use std::net::SocketAddr;

use iroh_base::EndpointId;
use serde::{Deserialize, Serialize};

use crate::mobile::PhoneRegistration;

/// Asks a companion to read one reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionRequest {
    /// The `op://` reference to read
    pub reference: String,
}

/// Why a companion did not send a value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionErrorCode {
    /// The reference is not on the companion's allow list, or the request
    /// was malformed
    NotAllowed,
    /// The owner did not approve on the companion Mac
    Denied,
    /// `op read` failed on the companion Mac
    ReadFailed,
}

impl CompanionErrorCode {
    /// The name on the wire
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::Denied => "denied",
            Self::ReadFailed => "read_failed",
        }
    }
}

/// A refusal or failure, with text that never holds a value
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionFault {
    /// Category
    pub code: CompanionErrorCode,
    /// What happened
    pub message: String,
}

/// A companion's answer: `{"value": "..."}` or `{"error": {...}}`
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionResponse {
    /// The value 1Password holds
    Value(String),
    /// Nothing was read
    Error(CompanionFault),
}

impl std::fmt::Debug for CompanionResponse {
    // the value stays out of logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(_) => formatter.write_str("Value(..)"),
            Self::Error(fault) => formatter.debug_tuple("Error").field(fault).finish(),
        }
    }
}

/// What a new companion sends the gateway on the pairing protocol: first a
/// registration, then optionally a check once its agent is running
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairRequest {
    /// List this Mac under `secrets.companions`
    Register(Box<Registration>),
    /// Read one reference through this Mac, to show the pairing works
    Check,
}

/// A new companion introducing itself
#[derive(Serialize, Deserialize)]
pub struct Registration {
    /// The invite's secret, as hex
    pub secret: String,
    /// The endpoint id the companion's agent answers on; unproven here, but
    /// only the holder of its key answers the gateway's dials
    pub id: EndpointId,
    /// Short host name of the companion Mac
    pub name: String,
    /// Where the gateway dials it; needed only when the gateway has
    /// discovery off
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
    /// Set by a phone, which dials the gateway instead of being dialed and
    /// opens sealed values instead of running `op`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<PhoneRegistration>,
}

impl std::fmt::Debug for Registration {
    // the secret stays out of logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Registration")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("addrs", &self.addrs)
            .field("phone", &self.phone)
            .finish_non_exhaustive()
    }
}

/// The gateway's answer on the pairing protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairResponse {
    /// The companion is listed and the daemon already uses it
    Registered(Registered),
    /// How the check went
    Checked(PairCheck),
    /// Nothing was done
    Refused {
        /// Why
        message: String,
    },
}

/// What the companion's config needs from the gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registered {
    /// Short host name of the gateway Mac, shown in Touch ID and Face ID
    /// prompts
    pub gateway_name: String,
    /// The name the gateway lists the companion under
    pub name: String,
    /// References in the gateway's server config, sorted; the companion's
    /// allow list
    pub references: Vec<String>,
    /// Whether the companion was listed before this registration
    pub already_listed: bool,
}

/// The outcome of reading one reference through a new companion; never the
/// value
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairCheck {
    /// The companion read it and sent it back
    Read {
        /// The reference read
        reference: String,
        /// Byte length of the value
        bytes: usize,
    },
    /// The companion did not send a value
    Failed {
        /// The reference asked for
        reference: String,
        /// Why
        message: String,
    },
    /// No server uses a reference, so there is nothing to read
    Skipped,
    /// A new phone has nothing to open yet: no reference was read since the
    /// gateway started, so nothing is sealed to it
    NothingSealed,
}
