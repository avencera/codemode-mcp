//! Executions parked while they wait for an approval, so a restart can pick
//! them up again
//!
//! The row holds the sealed session dump and everything the driver needs to
//! be rebuilt. A parked execution that touched a sensitive server is stored
//! with a `sensitive` flag and no payload (see `durable`)

use turso::{Value, params};

use super::{Store, StoreError};
use crate::durable::Durable;

/// What is stored of a parked execution that may be stored
#[derive(Debug, Clone)]
pub struct ParkedPayload {
    /// Serialized driver state
    pub state: String,
    /// The sealed session dump
    pub dump: Vec<u8>,
    /// Authentication tag of the dump
    pub tag: Vec<u8>,
}

/// A stored parked execution
#[derive(Debug, Clone)]
pub struct StoredParked {
    /// Execution id
    pub execution_id: String,
    /// Whether the payload was withheld because of a sensitive server
    pub sensitive: bool,
    /// The payload; `None` when withheld
    pub payload: Option<ParkedPayload>,
}

impl Store {
    /// Stores a parked execution, replacing an earlier row of the same
    /// execution
    pub fn put_parked(
        &self,
        execution_id: &str,
        parked_ms: i64,
        payload: &Durable<ParkedPayload>,
    ) -> Result<(), StoreError> {
        let stored = payload.payload();
        self.connection().execute(
            "INSERT OR REPLACE INTO parked (execution_id, parked_ms, sensitive, state, dump, tag) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                execution_id,
                parked_ms,
                i64::from(payload.withheld()),
                stored.map(|stored| stored.state.as_str()),
                stored.map(|stored| stored.dump.clone()),
                stored.map(|stored| stored.tag.clone()),
            ],
        )?;

        Ok(())
    }

    /// Every parked execution
    pub fn parked_executions(&self) -> Result<Vec<StoredParked>, StoreError> {
        Ok(self.connection().query_map(
            "SELECT execution_id, sensitive, state, dump, tag FROM parked",
            (),
            |row| {
                let state: Option<String> = row.get(2)?;
                let dump = row.get_value(3)?;
                let tag = row.get_value(4)?;
                let payload = match (state, dump, tag) {
                    (Some(state), Value::Blob(dump), Value::Blob(tag)) => {
                        Some(ParkedPayload { state, dump, tag })
                    }
                    _ => None,
                };

                Ok(StoredParked {
                    execution_id: row.get(0)?,
                    sensitive: row.get::<Option<i64>>(1)?.is_some_and(|flag| flag != 0),
                    payload,
                })
            },
        )?)
    }

    /// Forgets a parked execution, once it runs again or ends; true when this
    /// call removed the row
    ///
    /// The delete is the claim on a restored session: whoever removes the row
    /// may act on the verdict, and a process that finds it gone must not
    pub fn delete_parked(&self, execution_id: &str) -> Result<bool, StoreError> {
        let removed = self.connection().execute(
            "DELETE FROM parked WHERE execution_id = ?1",
            params![execution_id],
        )?;

        Ok(removed > 0)
    }
}
