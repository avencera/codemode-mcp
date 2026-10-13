//! Each upstream's last tool list, so a server that is down at boot still
//! shows its tools (as unavailable) instead of vanishing from the catalog
//!
//! Tool names and schemas come from the server's own listing, not from any
//! call's data, so they are not subject to the sensitive exception

use turso::params;

use super::{Store, StoreError, now_ms};

impl Store {
    /// Remembers the tool list of `server` as serialized JSON
    pub fn put_tool_cache(&self, server: &str, tools: &str) -> Result<(), StoreError> {
        self.connection().execute(
            "INSERT OR REPLACE INTO tool_cache (server, tools, updated_ms) VALUES (?1, ?2, ?3)",
            params![server, tools, now_ms()],
        )?;

        Ok(())
    }

    /// The remembered tool list of `server`
    pub fn tool_cache(&self, server: &str) -> Result<Option<String>, StoreError> {
        Ok(self.connection().query_optional(
            "SELECT tools FROM tool_cache WHERE server = ?1",
            params![server],
            |row| row.get(0),
        )?)
    }

    /// Forgets the tool list of `server`, e.g. once it needs a login
    pub fn forget_tool_cache(&self, server: &str) -> Result<(), StoreError> {
        self.connection()
            .execute("DELETE FROM tool_cache WHERE server = ?1", params![server])?;

        Ok(())
    }
}
