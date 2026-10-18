//! What gateway and companion send each other: one JSON request and one JSON
//! response per bidirectional stream
//!
//! A phone answers the same [`CompanionResponse`]; its own request and
//! registration are in [`crate::mobile`]

use std::net::SocketAddr;

use base64::{Engine, engine::general_purpose::STANDARD};
use iroh_base::EndpointId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::mobile::PhoneRegistration;

/// Asks a companion to read one reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionRequest {
    /// The `op://` reference to read
    pub reference: String,
}

/// Most values one program read asks for, so one prompt stays readable and
/// the answer stays well inside [`crate::MAX_BODY_BYTES`]
pub const MAX_PROGRAM_ITEMS: usize = 20;

/// Longest reason a program may give, in characters; prompts show it quoted
pub const MAX_REASON_CHARS: usize = 160;

/// Longest description of an item a program cannot name, in characters
pub const MAX_DESCRIPTION_CHARS: usize = 80;

/// Longest destination a program may name, in characters
pub const MAX_DESTINATION_CHARS: usize = 256;

/// Longest a program may ask to keep approved values, in seconds
pub const MAX_KEEP_SECS: u64 = 60 * 60;

/// Asks a companion Mac for values a program on the gateway Mac wants
/// (`codemode-mcp op read`, `op inject`, `op run`), sent as
/// `{"program_read": {...}}`; answered with
/// [`CompanionResponse::Values`] in the order of `references`
///
/// One Touch ID prompt covers the batch and names every reference. The value
/// goes to that program, so the prompt says so. A companion from before this
/// answers [`MALFORMED_REQUEST`], since the request has no `reference`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionProgramRequest {
    /// The batch
    pub program_read: ProgramBatch,
}

/// The references one program read asks a companion Mac for
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramBatch {
    /// `op://` references, at most [`MAX_PROGRAM_ITEMS`]
    pub references: Vec<String>,
    /// Why the program wants them, in its own words, at most
    /// [`MAX_REASON_CHARS`]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Where the values go, such as the file the gateway writes them to or
    /// the command whose environment gets them; prompts show it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// How long the gateway may hand the same values out again without
    /// asking, at most [`MAX_KEEP_SECS`]; prompts say so. Unset, every
    /// request asks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_secs: Option<u64>,
}

/// Longest query a find may give, in characters; prompts show it quoted
pub const MAX_FIND_QUERY_CHARS: usize = 80;

/// Most items one find answers with; the rest are only counted
pub const MAX_FOUND_ITEMS: usize = 10;

/// Asks a Mac which 1Password items match a query, for a program that does
/// not know the exact reference, sent as `{"find": {...}}`; answered with
/// [`CompanionFindResponse`]
///
/// The answer names items and their fields' references, never a value, so
/// the program then reads the one it wants with its own approval. A
/// companion from before this answers [`MALFORMED_REQUEST`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionFindRequest {
    /// The search
    pub find: FindQuery,
}

/// One search of item titles
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindQuery {
    /// Words to look for in item titles, vault names, tags and categories,
    /// at most [`MAX_FIND_QUERY_CHARS`]
    pub query: String,
    /// Why the program is looking, in its own words, at most
    /// [`MAX_REASON_CHARS`]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A Mac's answer to a [`CompanionFindRequest`]: `{"found": {...}}` or
/// `{"error": {...}}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionFindResponse {
    /// The items that matched
    Found(Found),
    /// Nothing was searched
    Error(CompanionFault),
}

/// The items a find matched, best first; never a value
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    /// At most [`MAX_FOUND_ITEMS`] items
    pub items: Vec<FoundItem>,
    /// How many more items matched but were left out
    pub more: usize,
}

/// One item a find matched
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundItem {
    /// Name of the vault it is in
    pub vault: String,
    /// The item's title
    pub title: String,
    /// 1Password category, such as `LOGIN` or `DOCUMENT`
    pub category: String,
    /// Its fields and attached files
    pub fields: Vec<FoundField>,
}

/// One field or attached file of a found item, named by its reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundField {
    /// The `op://` reference that reads it
    pub reference: String,
    /// Its label, or the file's name
    pub label: String,
    /// 1Password's field type in lowercase, such as `concealed` or `otp`, or
    /// `file` for an attachment
    pub kind: String,
    /// The section it is in, when it is in one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

/// Why a companion did not send a value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionErrorCode {
    /// The request was malformed or named no reference, or asked for an
    /// item in a vault the companion does not create in
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

/// One value of a program read: the bytes 1Password holds
///
/// UTF-8 text goes on the wire as a JSON string, as it always has, so
/// gateways, companions and phones from before binary values still read
/// each other's text. Other bytes, such as a `.p12` file attached to an
/// item, go as `{"base64": "..."}`, which those older peers refuse as a
/// malformed answer rather than misread
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProgramValue(Vec<u8>);

impl ProgramValue {
    /// The bytes as 1Password holds them
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The value as text, when it is UTF-8
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Whether the value holds no bytes
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The bytes as 1Password holds them
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<String> for ProgramValue {
    fn from(text: String) -> Self {
        Self(text.into_bytes())
    }
}

impl From<Vec<u8>> for ProgramValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for ProgramValue {
    // the value stays out of logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "ProgramValue({} bytes)", self.0.len())
    }
}

/// [`ProgramValue`] as it is written on the wire
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum WireValue<'a> {
    Text(std::borrow::Cow<'a, str>),
    Binary { base64: String },
}

impl Serialize for ProgramValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(&self.0) {
            Ok(text) => WireValue::Text(text.into()),
            Err(_) => WireValue::Binary {
                base64: STANDARD.encode(&self.0),
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProgramValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match WireValue::deserialize(deserializer)? {
            WireValue::Text(text) => Ok(Self::from(text.into_owned())),
            WireValue::Binary { base64 } => STANDARD
                .decode(base64)
                .map(Self)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// A companion's answer: `{"value": "..."}`, `{"values": [...]}` or
/// `{"error": {...}}`
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionResponse {
    /// The value 1Password holds, for a config read, which is always text
    Value(String),
    /// The values of a program read, one per item in the order asked
    Values(Vec<ProgramValue>),
    /// Nothing was read
    Error(CompanionFault),
}

impl std::fmt::Debug for CompanionResponse {
    // the values stay out of logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(_) => formatter.write_str("Value(..)"),
            Self::Values(values) => write!(formatter, "Values({} values)", values.len()),
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
    /// References in the gateway's server config, sorted; the pairing check
    /// reads one. Companions and phones from before every read was asked
    /// for by name kept them as an allow list
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
    fn text_stays_a_string_on_the_wire_and_other_bytes_go_as_base64() {
        let values = [
            ProgramValue::from("hunter2".to_owned()),
            ProgramValue::from(vec![0x30, 0x82, 0x00, 0xff]),
        ];
        let body =
            serde_json::to_value(CompanionResponse::Values(values.to_vec())).unwrap_or_default();

        // peers from before binary values read the text as they always did
        assert_eq!(
            body,
            serde_json::json!({ "values": ["hunter2", { "base64": "MIIA/w==" }] })
        );
        assert_eq!(
            serde_json::from_value::<CompanionResponse>(body).ok(),
            Some(CompanionResponse::Values(values.to_vec()))
        );
    }

    #[test]
    fn a_companion_from_before_creating_cannot_read_the_request() {
        // it parses requests as `CompanionRequest`, which needs `reference`,
        // and answers MALFORMED_REQUEST to anything else
        let body = serde_json::to_vec(&request()).unwrap_or_default();

        assert!(serde_json::from_slice::<CompanionRequest>(&body).is_err());
    }
}
