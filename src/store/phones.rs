//! Values sealed to each paired phone, and where to push to wake it
//!
//! Only ciphertext is stored: the key that opens it is in the phone's Secure
//! Enclave

use companion_wire::mobile::{PushEnvironment, PushToken, Sealed};
use turso::params;

use super::{Store, StoreError, now_ms};

impl Store {
    /// Keeps `sealed` as the phone's copy of `reference`, replacing an older
    /// one, so a rotated secret is current after its next real read
    pub fn put_seal(
        &self,
        phone: &str,
        reference: &str,
        sealed: &Sealed,
    ) -> Result<(), StoreError> {
        let sealed = serde_json::to_string(sealed)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        self.connection().execute(
            "INSERT OR REPLACE INTO phone_seals (phone, reference, sealed, sealed_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            params![phone, reference, sealed, now_ms()],
        )?;

        Ok(())
    }

    /// The phone's copy of `reference`, when the gateway has read it since
    /// the phone was paired
    pub fn seal(&self, phone: &str, reference: &str) -> Result<Option<Sealed>, StoreError> {
        let text: Option<String> = self.connection().query_optional(
            "SELECT sealed FROM phone_seals WHERE phone = ?1 AND reference = ?2",
            params![phone, reference],
            |row| row.get(0),
        )?;

        text.map(|text| {
            serde_json::from_str(&text).map_err(|error| StoreError::Corrupt(error.to_string()))
        })
        .transpose()
    }

    /// Pushes go to `token` from now on; `None` stops them
    pub fn put_push_token(&self, phone: &str, token: Option<&PushToken>) -> Result<(), StoreError> {
        let connection = self.connection();
        match token {
            Some(token) => {
                let environment = match token.environment {
                    PushEnvironment::Development => "development",
                    PushEnvironment::Production => "production",
                };
                connection.execute(
                    "INSERT OR REPLACE INTO phone_push (phone, token, environment, updated_ms) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![phone, token.token.as_str(), environment, now_ms()],
                )?;
            }
            None => {
                connection.execute("DELETE FROM phone_push WHERE phone = ?1", params![phone])?;
            }
        }

        Ok(())
    }

    /// Forgets `token` if it is still the phone's, as when APNs no longer
    /// knows it; a newer token the phone sent meanwhile stays
    pub fn drop_push_token(&self, phone: &str, token: &str) -> Result<(), StoreError> {
        self.connection().execute(
            "DELETE FROM phone_push WHERE phone = ?1 AND token = ?2",
            params![phone, token],
        )?;

        Ok(())
    }

    /// Where to push to wake the phone
    pub fn push_token(&self, phone: &str) -> Result<Option<PushToken>, StoreError> {
        let row: Option<(String, String)> = self.connection().query_optional(
            "SELECT token, environment FROM phone_push WHERE phone = ?1",
            params![phone],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        Ok(row.map(|(token, environment)| PushToken {
            token,
            environment: if environment == "production" {
                PushEnvironment::Production
            } else {
                PushEnvironment::Development
            },
        }))
    }

    /// Drops everything kept for the phone: its sealed copies and its token
    pub fn forget_phone(&self, phone: &str) -> Result<(), StoreError> {
        self.connection().transaction(|transaction| {
            transaction.execute("DELETE FROM phone_seals WHERE phone = ?1", params![phone])?;
            transaction.execute("DELETE FROM phone_push WHERE phone = ?1", params![phone])?;

            Ok(())
        })
    }
}
