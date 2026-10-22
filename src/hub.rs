//! Hub and spokes: one Mac holds 1Password, the passkeys, the sign-ins and
//! the approvals, and codemode-mcp on other machines uses them through it
//!
//! A spoke names its hub in `[hub]` and starts every exchange; the hub never
//! dials a spoke. The tailnet is the trust boundary: the hub answers these
//! routes only for Tailscale peers (and processes on itself), and a spoke
//! only once the owner has trusted it on the hub, a choice kept until
//! `spokes remove`. A spoke is a full gateway with its own sandbox and
//! servers; the hub's servers join its catalog, calls to them run on the
//! hub under the hub's policy, and the spoke's own `ask` approvals and
//! `op://` reads are decided on the hub too
//!
//! Every route is JSON over HTTP under [`API`], spoke to hub, on the hub's
//! main listener. Each answer carries the hub's catalog version in
//! [`CATALOG_HEADER`], so a spoke refetches the catalog when it changes

pub mod client;
pub mod server;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    approvals::RemoteGate, catalog::ExportedTool, gateway::ToolCallError, policy::GrantMode,
    usage::Caller,
};

/// Prefix of every hub route
pub const API: &str = "/hub/v1";
/// Header naming the spoke that sends a request
pub const SPOKE_HEADER: &str = "x-codemode-spoke";
/// Header carrying the hub's catalog version on every answer
pub const CATALOG_HEADER: &str = "x-codemode-catalog";

/// Body of `POST /hub/v1/register`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Register {
    /// The spoke's own id, kept in its state directory
    pub id: String,
    /// Its host name, shown wherever the owner is asked
    pub name: String,
    /// Its codemode-mcp version
    pub version: String,
}

/// Answer of `POST /hub/v1/register`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Registration {
    /// The owner trusts this spoke
    Trusted {
        /// Where the hub's approval pages are, for links the spoke hands out
        public_base: String,
    },
    /// The owner was asked to trust it and has not answered yet; `url` and
    /// `code` are empty while another request from the same address is
    /// open, and the spoke is asked about once that one is answered
    Pending {
        /// The request's page
        url: String,
        /// Words the hub's prompt repeats, so the owner can tell this
        /// request from a look-alike
        code: String,
    },
    /// The owner refused; asking again starts a new request
    Denied {
        /// Why
        reason: String,
    },
}

/// Answer of `GET /hub/v1/catalog`: the hub's servers a spoke may call
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HubCatalog {
    /// Changes whenever anything below does
    pub version: String,
    /// The servers, by name
    pub servers: Vec<HubServer>,
}

/// One server of the hub
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HubServer {
    /// Its name on the hub, which is its name on every spoke
    pub name: String,
    /// What it said in its handshake
    pub instructions: Option<String>,
    /// Whether the hub can call it now
    pub available: bool,
    /// Whether its results and arguments stay out of logs and off disk
    pub sensitive: bool,
    /// Other names search finds it by
    pub aliases: Vec<String>,
    /// Its tools
    pub tools: Vec<ExportedTool>,
}

/// Body of `POST /hub/v1/gate`: asks the hub whether a call may run now
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCall {
    /// Who made the call on the spoke
    pub caller: Caller,
    /// The spoke's execution
    pub execution_id: String,
    /// Its script, for the approval page
    pub script: String,
    /// Server name
    pub server: String,
    /// Tool name
    pub tool: String,
    /// Arguments
    pub arguments: Map<String, Value>,
    /// A tool of the hub's own, decided by the hub's policy; otherwise one
    /// of the spoke's own `ask` tools, decided by the fields below
    pub hub_tool: bool,
    /// The spoke's grant mode for its own tool
    pub grant_mode: GrantMode,
    /// Whether the request must stay off disk
    pub sensitive: bool,
    /// What the spoke found the call would do
    pub summary: Option<String>,
}

/// Answer of `POST /hub/v1/gate`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAnswer {
    /// How the hub decided
    Gate(RemoteGate),
    /// The hub refused a call of its own tool before asking anyone
    Refused(HubError),
}

/// Body of `POST /hub/v1/call`: runs a tool of the hub
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardedCall {
    /// Who made the call on the spoke
    pub caller: Caller,
    /// The spoke's execution
    pub execution_id: String,
    /// Its script
    pub script: String,
    /// Server name
    pub server: String,
    /// Tool name
    pub tool: String,
    /// Arguments
    pub arguments: Map<String, Value>,
    /// The hub's request the owner approved, for an `ask` tool
    pub approval: Option<String>,
    /// Whether the spoke keeps the result off its disk and out of its logs;
    /// the hub refuses a call it holds sensitive that the spoke does not
    #[serde(default)]
    pub sensitive: bool,
}

/// Answer of `POST /hub/v1/call`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallAnswer {
    /// The result, checked against the tool's output already
    Value(Value),
    /// Why it did not run or failed
    Error(HubError),
}

/// A failure the hub reports, as a spoke's script should see it
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct HubError {
    /// Which kind of failure
    pub kind: HubErrorKind,
    /// What happened, safe to show the script
    pub message: String,
}

/// Kinds of [`HubError`], each raising its own exception in a script
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HubErrorKind {
    /// No such tool
    Unknown,
    /// Policy or the owner refused it
    Denied,
    /// It ran out of time
    TimedOut,
    /// The result was too large for the sandbox
    TooLarge,
    /// Anything else
    Failed,
}

impl From<&ToolCallError> for HubError {
    fn from(error: &ToolCallError) -> Self {
        let kind = match error {
            ToolCallError::Unknown(_) => HubErrorKind::Unknown,
            ToolCallError::Denied(_) | ToolCallError::NotApproved { .. } => HubErrorKind::Denied,
            ToolCallError::Upstream(
                crate::upstream::UpstreamError::TimedOut { .. }
                | crate::upstream::UpstreamError::Busy { .. },
            ) => HubErrorKind::TimedOut,
            ToolCallError::ResultTooLarge { .. } => HubErrorKind::TooLarge,
            ToolCallError::Hub(error) => error.kind,
            _ => HubErrorKind::Failed,
        };

        Self {
            kind,
            message: error.to_string(),
        }
    }
}

/// Body of `POST /hub/v1/approvals/wait`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitFor {
    /// The hub's request id
    pub id: String,
}

/// Answer of `POST /hub/v1/approvals/wait`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitAnswer {
    /// The verdict, or `None` while the request is still pending
    pub verdict: Option<crate::approvals::Verdict>,
}

/// Body of `POST /hub/v1/op/read`: the `op` read of a program on the spoke
#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramReadCall {
    /// What the program asked its spoke for
    pub request: crate::admin::OpReadRequest,
    /// Ask only the phones
    pub phones_only: bool,
}

/// Body of `POST /hub/v1/op/config`: the references in one of the spoke's
/// own server configs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigRead {
    /// The server's name on the spoke
    pub server: String,
    /// The spoke's digest of where the server sends its values; a change
    /// asks the owner again
    pub digest: String,
    /// The references, each read once
    pub references: Vec<String>,
}

/// Answer of `POST /hub/v1/op/config`
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigAnswer {
    /// One value per reference, in order
    Values(Vec<String>),
    /// Why there are none
    Error(String),
}

impl std::fmt::Debug for ConfigAnswer {
    // the values stay out of logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Values(values) => formatter
                .debug_tuple("Values")
                .field(&values.len())
                .finish(),
            Self::Error(message) => formatter.debug_tuple("Error").field(message).finish(),
        }
    }
}

/// Answer of a refused hub route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refusal {
    /// Why
    pub error: String,
}
