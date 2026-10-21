//! The spokes a hub trusts
//!
//! A row is written once the owner approves a spoke and stays until `spokes
//! remove`; the hub answers only spokes that have one

use turso::{Row, params};

use super::{Store, StoreError, now_ms};

/// A trusted spoke
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSpoke {
    /// The spoke's own id
    pub id: String,
    /// Its host name, as the owner trusted it
    pub name: String,
    /// The codemode-mcp version it last reported
    pub version: Option<String>,
    /// When the owner trusted it, ms since the epoch
    pub trusted_ms: i64,
    /// The approval that trusted it
    pub approval_id: Option<String>,
    /// When it last registered, ms since the epoch
    pub last_seen_ms: Option<i64>,
    /// The tailnet address the owner trusted it at, the only one it is
    /// answered from
    pub address: Option<String>,
}

const COLUMNS: &str = "id, name, version, trusted_ms, approval_id, last_seen_ms, address";

fn stored_spoke(row: &Row) -> Result<StoredSpoke, turso::Error> {
    Ok(StoredSpoke {
        id: row.get(0)?,
        name: row.get(1)?,
        version: row.get(2)?,
        trusted_ms: row.get(3)?,
        approval_id: row.get(4)?,
        last_seen_ms: row.get(5)?,
        address: row.get(6)?,
    })
}

impl Store {
    /// Trusts a spoke, replacing an earlier row for the same id
    pub fn trust_spoke(&self, spoke: &StoredSpoke) -> Result<(), StoreError> {
        self.connection().execute(
            &format!(
                "INSERT OR REPLACE INTO spokes ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            ),
            params![
                spoke.id.as_str(),
                spoke.name.as_str(),
                spoke.version.as_deref(),
                spoke.trusted_ms,
                spoke.approval_id.as_deref(),
                spoke.last_seen_ms,
                spoke.address.as_deref(),
            ],
        )?;

        Ok(())
    }

    /// Notes a registration of a trusted spoke: when, and which version it
    /// runs. Its name and address stay the ones the owner trusted
    pub fn spoke_seen(&self, id: &str, version: &str) -> Result<(), StoreError> {
        self.connection().execute(
            "UPDATE spokes SET version = ?1, last_seen_ms = ?2 WHERE id = ?3",
            params![version, now_ms(), id],
        )?;

        Ok(())
    }

    /// Every trusted spoke, oldest first
    pub fn spokes(&self) -> Result<Vec<StoredSpoke>, StoreError> {
        Ok(self.connection().query_map(
            &format!("SELECT {COLUMNS} FROM spokes ORDER BY trusted_ms"),
            (),
            stored_spoke,
        )?)
    }

    /// Forgets a spoke; false when none had this id
    pub fn remove_spoke(&self, id: &str) -> Result<bool, StoreError> {
        let removed = self
            .connection()
            .execute("DELETE FROM spokes WHERE id = ?1", params![id])?;

        Ok(removed > 0)
    }
}
