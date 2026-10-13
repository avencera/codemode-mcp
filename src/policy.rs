//! Per-tool policy and grant modes

use serde::{Deserialize, Serialize};

/// What the gateway does when a script calls a tool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Run the call immediately
    #[default]
    Allow,
    /// Run the call once a person approves it
    Ask,
    /// Refuse the call
    Deny,
}

/// How far one approval of an `ask` tool reaches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantMode {
    /// An approval may cover every `session` tool of the server for every
    /// session of the same client for a while
    #[default]
    Session,
    /// Every call needs its own approval
    PerCall,
}

impl GrantMode {
    /// Name used in storage and on the approval page
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::PerCall => "per_call",
        }
    }
}
