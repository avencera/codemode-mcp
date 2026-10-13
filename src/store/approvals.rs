//! Approval requests and grants that outlive the process
//!
//! A request is written when it is created and updated when it is decided,
//! so a restart can serve its page again, re-arm its expiry and hand the
//! verdict to the execution waiting on it. Requests of sensitive executions
//! keep their metadata (who, which tool, when) but not their payload

use turso::{Row, params};

use super::{Store, StoreError, now_ms};
use crate::{durable::Durable, usage::Caller};

/// A request to store
pub struct NewApproval<'a> {
    /// Approval id
    pub id: &'a str,
    /// When it was created, ms since the epoch
    pub created_ms: i64,
    /// When it is denied automatically, ms since the epoch
    pub expires_ms: i64,
    /// Who asked
    pub caller: &'a Caller,
    /// Execution waiting on it; empty for admin requests
    pub execution_id: &'a str,
    /// Server name
    pub server: &'a str,
    /// Upstream tool name or admin action name
    pub tool: &'a str,
    /// `session` or `per_call`
    pub grant_mode: &'a str,
    /// Serialized admin action to perform once approved
    pub action: Option<&'a str>,
    /// Whether a notification is about to be sent: the row starts out marked
    /// undelivered, so a crash before the send finishes is retried at boot
    pub notify: bool,
}

/// A stored request
#[derive(Debug, Clone)]
pub struct StoredApproval {
    /// Approval id
    pub id: String,
    /// When it was created, ms since the epoch
    pub created_ms: i64,
    /// When it is denied automatically; `None` for rows from before requests
    /// survived restarts
    pub expires_ms: Option<i64>,
    /// `approved`, `denied`, `expired` or `abandoned`; `None` while pending
    pub decision: Option<String>,
    /// Approval whose grant allowed this one, which may be another request
    pub approved_by: Option<String>,
    /// Whether the payload was withheld because of a sensitive server
    pub sensitive: bool,
    /// Serialized request details; `None` when withheld
    pub payload: Option<String>,
    /// Serialized admin action, for admin requests
    pub action: Option<String>,
    /// Whether the admin action was carried out
    pub action_done: bool,
    /// Whether the notification could not be delivered
    pub unnotified: bool,
    /// Execution waiting on it
    pub execution_id: Option<String>,
}

const COLUMNS: &str = "id, created_ms, expires_ms, decision, approved_by, sensitive, payload, \
                       action, action_done, unnotified, execution_id";

fn stored_approval(row: &Row) -> Result<StoredApproval, turso::Error> {
    let flag = |index: usize| -> Result<bool, turso::Error> {
        Ok(row.get::<Option<i64>>(index)?.is_some_and(|flag| flag != 0))
    };

    Ok(StoredApproval {
        id: row.get(0)?,
        created_ms: row.get(1)?,
        expires_ms: row.get(2)?,
        decision: row.get(3)?,
        approved_by: row.get(4)?,
        sensitive: flag(5)?,
        payload: row.get(6)?,
        action: row.get(7)?,
        action_done: flag(8)?,
        unnotified: flag(9)?,
        execution_id: row.get(10)?,
    })
}

/// A stored grant
#[derive(Debug, Clone)]
pub struct StoredGrant {
    /// `client` or `session`
    pub kind: String,
    /// Client name or session hash
    pub subject: String,
    /// Server it covers
    pub server: String,
    /// Approval that created it
    pub approval_id: String,
    /// When it ends, ms since the epoch
    pub expires_ms: i64,
}

impl Store {
    /// Stores a new request; the payload is written only when it is not
    /// sensitive
    pub fn create_approval(
        &self,
        approval: &NewApproval<'_>,
        payload: &Durable<String>,
    ) -> Result<(), StoreError> {
        self.connection().execute(
            "INSERT OR IGNORE INTO approvals (id, created_ms, expires_ms, session, client_name, \
             execution_id, server, tool, grant_mode, sensitive, payload, action, unnotified) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                approval.id,
                approval.created_ms,
                approval.expires_ms,
                approval.caller.session_label(),
                approval.caller.client_name.as_deref(),
                approval.execution_id,
                approval.server,
                approval.tool,
                approval.grant_mode,
                i64::from(payload.withheld()),
                payload.payload().map(String::as_str),
                approval.action,
                approval.notify.then_some(1_i64),
            ],
        )?;

        Ok(())
    }

    /// Records the decision of a pending request; false when it was decided
    /// already
    pub fn decide_approval(
        &self,
        id: &str,
        decision: &str,
        grant_minutes: Option<i64>,
        approved_by: Option<&str>,
    ) -> Result<bool, StoreError> {
        let changed = self.connection().execute(
            "UPDATE approvals SET decided_ms = ?1, decision = ?2, grant_minutes = ?3, \
             approved_by = ?4, unnotified = NULL WHERE id = ?5 AND decision IS NULL",
            params![now_ms(), decision, grant_minutes, approved_by, id],
        )?;

        Ok(changed > 0)
    }

    /// Notes whether the notification of a pending request failed
    pub fn set_unnotified(&self, id: &str, unnotified: bool) -> Result<(), StoreError> {
        self.connection().execute(
            "UPDATE approvals SET unnotified = ?1 WHERE id = ?2 AND decision IS NULL",
            params![unnotified.then_some(1_i64), id],
        )?;

        Ok(())
    }

    /// One request
    pub fn approval(&self, id: &str) -> Result<Option<StoredApproval>, StoreError> {
        Ok(self.connection().query_optional(
            &format!("SELECT {COLUMNS} FROM approvals WHERE id = ?1"),
            params![id],
            stored_approval,
        )?)
    }

    /// Requests nobody has decided yet
    pub fn pending_approvals(&self) -> Result<Vec<StoredApproval>, StoreError> {
        Ok(self.connection().query_map(
            &format!("SELECT {COLUMNS} FROM approvals WHERE decision IS NULL ORDER BY created_ms"),
            (),
            stored_approval,
        )?)
    }

    /// Admin requests whose action has not been carried out, decided or not
    pub fn open_admin_actions(&self) -> Result<Vec<StoredApproval>, StoreError> {
        Ok(self.connection().query_map(
            &format!(
                "SELECT {COLUMNS} FROM approvals WHERE action IS NOT NULL \
                 AND action_done IS NULL ORDER BY created_ms"
            ),
            (),
            stored_approval,
        )?)
    }

    /// Notes that the action of an admin request was carried out (or ruled
    /// out by its verdict), so a restart does not repeat it
    pub fn complete_action(&self, id: &str) -> Result<(), StoreError> {
        self.connection().execute(
            "UPDATE approvals SET action_done = 1 WHERE id = ?1",
            params![id],
        )?;

        Ok(())
    }

    /// Drops the payload of the pending requests of an execution that has
    /// just touched a sensitive server
    pub fn withhold_execution_approvals(&self, execution_id: &str) -> Result<(), StoreError> {
        self.connection().execute(
            "UPDATE approvals SET payload = NULL, sensitive = 1 \
             WHERE execution_id = ?1 AND decision IS NULL",
            params![execution_id],
        )?;

        Ok(())
    }

    /// Withdraws a pending request that cannot be restored, returning
    /// whether it was still pending
    pub fn abandon_approval(&self, id: &str) -> Result<bool, StoreError> {
        self.decide_approval(id, "abandoned", None, None)
    }

    /// Stores a grant, replacing the one for the same subject and server
    pub fn put_grant(&self, grant: &StoredGrant) -> Result<(), StoreError> {
        self.connection().execute(
            "INSERT OR REPLACE INTO grants (kind, subject, server, approval_id, expires_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                grant.kind.as_str(),
                grant.subject.as_str(),
                grant.server.as_str(),
                grant.approval_id.as_str(),
                grant.expires_ms
            ],
        )?;

        Ok(())
    }

    /// Grants that have not ended; the rest are deleted
    pub fn live_grants(&self) -> Result<Vec<StoredGrant>, StoreError> {
        let now = now_ms();
        let connection = self.connection();
        connection.execute("DELETE FROM grants WHERE expires_ms <= ?1", params![now])?;

        Ok(connection.query_map(
            "SELECT kind, subject, server, approval_id, expires_ms FROM grants",
            (),
            |row| {
                Ok(StoredGrant {
                    kind: row.get(0)?,
                    subject: row.get(1)?,
                    server: row.get(2)?,
                    approval_id: row.get(3)?,
                    expires_ms: row.get(4)?,
                })
            },
        )?)
    }
}
