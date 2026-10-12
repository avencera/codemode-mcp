//! Per-tool policy and the approval seam

use std::{future::Future, pin::Pin};

use serde::Deserialize;
use serde_json::{Map, Value};

/// What the gateway does when a script calls a tool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Run the call immediately
    #[default]
    Allow,
    /// Run the call once the [`Approver`] says yes
    Ask,
    /// Refuse the call
    Deny,
}

/// A tool call waiting for an approval decision
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Execution the call belongs to
    pub execution_id: String,
    /// Upstream server name
    pub server: String,
    /// Tool name as the upstream knows it
    pub tool: String,
    /// Arguments the script passed
    pub arguments: Map<String, Value>,
}

/// The answer to an [`ApprovalRequest`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Run the call
    Approved,
    /// Refuse the call; the reason is shown to the script as an exception
    Denied {
        /// Why the call was refused
        reason: String,
    },
}

/// Boxed future so [`Approver`] stays usable as a trait object
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Decides whether a tool call whose policy is `ask` may proceed
///
/// An implementation may take as long as it needs; the surrounding execution
/// stays suspended and reports `pending` to the agent meanwhile
pub trait Approver: Send + Sync + 'static {
    /// Waits for a decision on `request`
    fn approve<'a>(&'a self, request: &'a ApprovalRequest) -> BoxFuture<'a, ApprovalDecision>;
}

/// Refuses every request that needs approval
///
/// The default until an approval flow is configured, so a policy of `ask`
/// fails closed instead of running the call unattended
#[derive(Debug, Clone, Copy, Default)]
pub struct NoApprover;

impl NoApprover {
    /// Reason given to the script when an `ask` call is refused
    pub const REASON: &'static str = "requires approval; approvals are not configured";
}

impl Approver for NoApprover {
    fn approve<'a>(&'a self, _request: &'a ApprovalRequest) -> BoxFuture<'a, ApprovalDecision> {
        Box::pin(std::future::ready(ApprovalDecision::Denied {
            reason: Self::REASON.to_owned(),
        }))
    }
}
