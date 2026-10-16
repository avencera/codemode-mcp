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
    /// An item with that title is already in the vault; nothing was written
    AlreadyExists,
    /// `op` could not create the item on the companion Mac
    CreateFailed,
    /// `op` may have created the item but did not confirm it, so the vault
    /// needs checking before trying again
    CreateUnconfirmed,
}

impl CompanionErrorCode {
    /// The name on the wire
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::Denied => "denied",
            Self::ReadFailed => "read_failed",
            Self::AlreadyExists => "already_exists",
            Self::CreateFailed => "create_failed",
            Self::CreateUnconfirmed => "create_unconfirmed",
        }
    }
}

/// What a companion that predates [`CompanionCreateRequest`] answers to it,
/// as a [`CompanionErrorCode::NotAllowed`] fault: the request has no
/// `reference`, so it is "malformed" to that companion
pub const MALFORMED_REQUEST: &str = "malformed request";

/// Category of an item created when the request names none
pub const DEFAULT_CATEGORY: &str = "API_CREDENTIAL";

/// Label of the field that holds the secret when the request names none
pub const DEFAULT_FIELD: &str = "credential";

/// Asks a companion to create one item in 1Password, sent as
/// `{"create": {...}}`
///
/// There is no request to edit or delete an item, and a companion refuses
/// to create one whose title is already in the vault
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionCreateRequest {
    /// The item to create
    pub create: NewItem,
}

impl std::fmt::Debug for CompanionCreateRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("CompanionCreateRequest")
            .field(&self.create)
            .finish()
    }
}

/// An item for a companion to create
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewItem {
    /// Vault the item goes in
    pub vault: String,
    /// Title of the item; the companion refuses a title already in use
    pub title: String,
    /// 1Password category such as `API_CREDENTIAL`; unset, that one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Label of the one field that holds the value; unset, `credential`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The secret to store
    pub value: String,
}

impl std::fmt::Debug for NewItem {
    // the value stays out of logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewItem")
            .field("vault", &self.vault)
            .field("title", &self.title)
            .field("category", &self.category)
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}

impl NewItem {
    /// The category, with the default filled in
    pub fn category(&self) -> &str {
        self.category.as_deref().unwrap_or(DEFAULT_CATEGORY)
    }

    /// The field label, with the default filled in
    pub fn field(&self) -> &str {
        self.field.as_deref().unwrap_or(DEFAULT_FIELD)
    }
}

/// The item a companion created; never the value
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedItem {
    /// 1Password's id for the new item
    pub id: String,
    /// `op://vault/title/field` for the value just stored
    pub reference: String,
}

/// A companion's answer to a [`CompanionCreateRequest`]: `{"created": {...}}`
/// or `{"error": {...}}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionCreateResponse {
    /// The item exists now
    Created(CreatedItem),
    /// Nothing was written
    Error(CompanionFault),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CompanionCreateRequest {
        CompanionCreateRequest {
            create: NewItem {
                vault: "Personal".to_owned(),
                title: "Zoho".to_owned(),
                category: None,
                field: None,
                value: "hunter2-secret".to_owned(),
            },
        }
    }

    #[test]
    fn debug_output_never_holds_the_value() {
        assert!(!format!("{:?}", request()).contains("hunter2"));
    }

    #[test]
    fn a_companion_from_before_creating_cannot_read_the_request() {
        // it parses requests as `CompanionRequest`, which needs `reference`,
        // and answers MALFORMED_REQUEST to anything else
        let body = serde_json::to_vec(&request()).unwrap_or_default();

        assert!(serde_json::from_slice::<CompanionRequest>(&body).is_err());
    }
}
