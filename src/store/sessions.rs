//! App sessions: random handles the server issues and agents pass back
//!
//! The raw token is a bearer secret for approval grants, so only its SHA-256
//! is stored or logged; people see the first eight hex characters

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::{Store, StoreError, now_ms};
use crate::approvals::hex;

/// Prefix of every token, so an agent can tell it from other ids
const TOKEN_PREFIX: &str = "cs_";
/// Longest value looked up; real tokens are 29 characters
const MAX_TOKEN_CHARS: usize = 64;
/// A client counts as having an active session when one was seen this recently
const ACTIVE_WINDOW_MS: i64 = 60 * 60 * 1000;
/// Hex characters of the hash shown to people and written to the usage log
const SHORT_CHARS: usize = 8;
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// How a call got its session, kept per call for the reuse numbers
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SessionState {
    /// The call has no session (`codemode-mcp exec`, tests)
    #[default]
    Absent,
    /// The caller passed a valid session
    Reused,
    /// The server issued a new session
    Minted,
    /// The server issued a new session although the same client had an
    /// active one within the last hour: the agent forgot to pass it back
    Reminted,
}

impl SessionState {
    /// Name stored in the database; `None` for [`SessionState::Absent`]
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Absent => None,
            Self::Reused => Some("reused"),
            Self::Minted => Some("minted"),
            Self::Reminted => Some("reminted"),
        }
    }
}

/// The session a call runs under
#[derive(Debug, Clone)]
pub struct ResolvedSession {
    /// Raw token to hand back to the agent; never stored
    pub token: String,
    /// SHA-256 of the token as hex, the key for grants and the database
    pub hash: String,
    /// How the session was obtained
    pub state: SessionState,
    /// Whether a value the caller passed was rejected and replaced
    pub replaced: bool,
}

/// SHA-256 of a token as 64 hex characters
pub fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// First eight hex characters of a hash (or fewer, for a short label)
pub fn short_hash(hash: &str) -> &str {
    hash.get(..SHORT_CHARS).unwrap_or(hash)
}

/// 128 random bits as `cs_` plus 26 lowercase base32 characters
fn new_token() -> String {
    let bytes: [u8; 16] = rand::random();
    let mut token = String::from(TOKEN_PREFIX);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            token.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        token.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }

    token
}

impl Store {
    /// Finds the session for `provided`, or issues a new one
    ///
    /// A provided value is valid when its hash is known, it was minted for
    /// the same `client`, and it was seen within `idle`; a valid one has its
    /// last-seen time refreshed. Anything else is replaced by a new session
    pub fn resolve_session(
        &self,
        provided: Option<&str>,
        client: Option<&str>,
        idle: Duration,
    ) -> Result<ResolvedSession, StoreError> {
        let now = now_ms();
        let provided = provided.map(str::trim).filter(|value| !value.is_empty());
        let mut connection = self.connection();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(token) = provided
            && token.starts_with(TOKEN_PREFIX)
            && token.chars().count() <= MAX_TOKEN_CHARS
        {
            let hash = hash_token(token);
            let known: Option<(Option<String>, i64)> = transaction
                .query_row(
                    "SELECT client, last_seen_ms FROM sessions WHERE hash = ?1",
                    params![hash],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let idle_ms = idle.as_millis().min(i64::MAX as u128) as i64;
            if let Some((owner, last_seen)) = known
                && owner.as_deref() == client
                && now.saturating_sub(last_seen) < idle_ms
            {
                transaction.execute(
                    "UPDATE sessions SET last_seen_ms = ?1 WHERE hash = ?2",
                    params![now, hash],
                )?;
                transaction.commit()?;

                return Ok(ResolvedSession {
                    token: token.to_owned(),
                    hash,
                    state: SessionState::Reused,
                    replaced: false,
                });
            }
        }

        let forgot: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM sessions WHERE client IS ?1 AND last_seen_ms >= ?2)",
            params![client, now - ACTIVE_WINDOW_MS],
            |row| row.get(0),
        )?;
        let token = new_token();
        let hash = hash_token(&token);
        transaction.execute(
            "INSERT INTO sessions (hash, client, created_ms, last_seen_ms) \
             VALUES (?1, ?2, ?3, ?3)",
            params![hash, client, now],
        )?;
        transaction.commit()?;

        Ok(ResolvedSession {
            token,
            hash,
            state: if forgot {
                SessionState::Reminted
            } else {
                SessionState::Minted
            },
            replaced: provided.is_some(),
        })
    }
}

/// Deletes sessions not seen since `cutoff_ms`
pub fn purge(connection: &Connection, cutoff_ms: i64) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM sessions WHERE last_seen_ms < ?1",
        params![cutoff_ms],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_cs_plus_26_base32_characters() {
        let token = new_token();

        assert_eq!(token.len(), 29);
        assert!(token.starts_with("cs_"));
        assert!(
            token[3..]
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        );
        assert_ne!(token, new_token());
    }
}
