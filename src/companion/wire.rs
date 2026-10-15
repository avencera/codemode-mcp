//! What gateway and companion send each other: one JSON request and one JSON
//! response per bidirectional stream

use serde::{Deserialize, Serialize};

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
