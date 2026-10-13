//! Passkey enrollment links and WebAuthn ceremonies that outlive the process
//!
//! A link is stored as the SHA-256 of its token, the same way sessions are,
//! because the token is a bearer secret for adding an approver. A ceremony
//! is the server-side state of one registration or assertion: it never
//! leaves the server, and it is bound to the enrollment or approval it was
//! started for

use turso::params;

use super::{Store, StoreError, now_ms};

/// A stored enrollment link
#[derive(Debug, Clone)]
pub struct StoredEnrollment {
    /// Label the passkey gets
    pub label: String,
    /// `first_passkey`, `awaiting_approval` or `approved`
    pub gate: String,
    /// When the link stops working, ms since the epoch
    pub expires_ms: i64,
}

/// A stored ceremony
#[derive(Debug, Clone)]
pub struct StoredCeremony {
    /// `register` or `authenticate`
    pub kind: String,
    /// Enrollment token hash for a registration, approval id for an assertion
    pub subject: String,
    /// The choice an assertion applies, as the page names it
    pub choice: Option<String>,
    /// Serialized WebAuthn state
    pub state: String,
}

impl Store {
    /// Stores an enrollment link and forgets the ones that ran out
    pub fn put_enrollment(
        &self,
        hash: &str,
        label: &str,
        gate: &str,
        expires_ms: i64,
    ) -> Result<(), StoreError> {
        self.connection().transaction(|transaction| {
            transaction.execute(
                "DELETE FROM enrollments WHERE expires_ms <= ?1",
                params![now_ms()],
            )?;
            transaction.execute(
                "INSERT OR REPLACE INTO enrollments (hash, label, gate, expires_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![hash, label, gate, expires_ms],
            )?;

            Ok(())
        })
    }

    /// A link that has not run out
    pub fn enrollment(&self, hash: &str) -> Result<Option<StoredEnrollment>, StoreError> {
        Ok(self.connection().query_optional(
            "SELECT label, gate, expires_ms FROM enrollments \
             WHERE hash = ?1 AND expires_ms > ?2",
            params![hash, now_ms()],
            |row| {
                Ok(StoredEnrollment {
                    label: row.get(0)?,
                    gate: row.get(1)?,
                    expires_ms: row.get(2)?,
                })
            },
        )?)
    }

    /// Moves a link from `from` to `to` and restarts its lifetime; false when
    /// the link is unknown, ran out, or is not in `from`
    pub fn advance_enrollment(
        &self,
        hash: &str,
        from: &str,
        to: &str,
        expires_ms: i64,
    ) -> Result<bool, StoreError> {
        let changed = self.connection().execute(
            "UPDATE enrollments SET gate = ?1, expires_ms = ?2 \
             WHERE hash = ?3 AND gate = ?4 AND expires_ms > ?5",
            params![to, expires_ms, hash, from, now_ms()],
        )?;

        Ok(changed > 0)
    }

    /// Removes a link, returning it if it had not run out
    pub fn take_enrollment(&self, hash: &str) -> Result<Option<StoredEnrollment>, StoreError> {
        self.connection().transaction(|transaction| {
            let found = transaction.query_optional(
                "SELECT label, gate, expires_ms FROM enrollments \
                 WHERE hash = ?1 AND expires_ms > ?2",
                params![hash, now_ms()],
                |row| {
                    Ok(StoredEnrollment {
                        label: row.get(0)?,
                        gate: row.get(1)?,
                        expires_ms: row.get(2)?,
                    })
                },
            )?;
            transaction.execute("DELETE FROM enrollments WHERE hash = ?1", params![hash])?;

            Ok(found)
        })
    }

    /// Removes the links of one gate, e.g. every first-passkey link once a
    /// passkey exists
    pub fn remove_enrollments_with_gate(&self, gate: &str) -> Result<(), StoreError> {
        self.connection()
            .execute("DELETE FROM enrollments WHERE gate = ?1", params![gate])?;

        Ok(())
    }

    /// Stores a ceremony; false when `max` are already in progress
    pub fn put_ceremony(
        &self,
        id: &str,
        ceremony: &StoredCeremony,
        expires_ms: i64,
        max: usize,
    ) -> Result<bool, StoreError> {
        self.connection().transaction(|transaction| {
            transaction.execute(
                "DELETE FROM ceremonies WHERE expires_ms <= ?1",
                params![now_ms()],
            )?;
            let count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM ceremonies", (), |row| row.get(0))?;
            if count >= max as i64 {
                return Ok(false);
            }
            transaction.execute(
                "INSERT INTO ceremonies (id, kind, subject, choice, state, expires_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id,
                    ceremony.kind.as_str(),
                    ceremony.subject.as_str(),
                    ceremony.choice.as_deref(),
                    ceremony.state.as_str(),
                    expires_ms
                ],
            )?;

            Ok(true)
        })
    }

    /// Removes a ceremony, returning it if it had not run out; a ceremony
    /// answers one request
    pub fn take_ceremony(&self, id: &str) -> Result<Option<StoredCeremony>, StoreError> {
        self.connection().transaction(|transaction| {
            let found = transaction.query_optional(
                "SELECT kind, subject, choice, state FROM ceremonies \
                 WHERE id = ?1 AND expires_ms > ?2",
                params![id, now_ms()],
                |row| {
                    Ok(StoredCeremony {
                        kind: row.get(0)?,
                        subject: row.get(1)?,
                        choice: row.get(2)?,
                        state: row.get(3)?,
                    })
                },
            )?;
            transaction.execute("DELETE FROM ceremonies WHERE id = ?1", params![id])?;

            Ok(found)
        })
    }
}
