//! Carries the values the daemon read for its own config across a restart,
//! so a planned restart or update does not ask the owner again
//!
//! A daemon that stops cleanly seals its cache with AES-256-GCM under a
//! fresh random key, writes the ciphertext to [`FILE`] in the state
//! directory and puts the key in the login keychain, where only the signed
//! binary reads it without a prompt. The next daemon takes both, deletes
//! both, and uses the values only when they are younger than [`MAX_AGE`].
//! A crash leaves nothing, and that daemon asks again as before. Values a
//! program asked for (`codemode-mcp op`) are never in the cache, so never
//! here
//!
//! The keychain is used only by the installed service binary with no
//! `secrets.identity_file`: a keychain item is bound to the code that made
//! it, so a test or checkout build writing it would leave the service a
//! keychain prompt. Any other daemon puts the key in [`KEY_FILE`] beside the
//! ciphertext, mode 0600, which keeps the values from other users but not
//! from this one

use std::{
    collections::HashMap,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};

use super::key_store::{KeyStore, KeychainItem};

/// The sealed values, in the state directory
pub const FILE: &str = "secrets.handoff";
/// The key, when there is no keychain
pub const KEY_FILE: &str = "secrets.handoff.key";
/// How old a handoff may be and still be used; a restart takes seconds, and
/// a reboot within this window is still a planned stop
pub const MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// How far ahead of this clock a handoff's time may be, for clocks that
/// disagree by moments
const CLOCK_SKEW_MS: u64 = 60_000;

/// The key's keychain item
const KEYCHAIN_ITEM: KeychainItem = KeychainItem {
    service: "dev.praveen.codemode-mcp.handoff",
    account: "daemon",
};

/// Bound into the ciphertext with the time it was written, so a handoff
/// cannot be passed off as another format or a later one
const AAD_PREFIX: &str = "codemode-mcp/handoff/1";

/// What [`FILE`] holds
#[derive(Serialize, Deserialize)]
struct Envelope {
    /// When it was written, in Unix milliseconds
    written_at_ms: u64,
    /// Hex
    nonce: String,
    /// Hex, with the tag
    ciphertext: String,
}

/// Where the key is kept: the keychain for the installed service binary
/// using it for its identity too, otherwise a file in `state_dir`
pub fn key_store(state_dir: &Path, identity_in_keychain: bool) -> KeyStore {
    KeyStore::for_state(state_dir, identity_in_keychain, KEYCHAIN_ITEM, KEY_FILE)
}

/// Seals `values` for the next daemon on `state_dir`; nothing is written when
/// there are none
pub fn hand_off(
    state_dir: &Path,
    store: &KeyStore,
    values: &HashMap<String, String>,
) -> Result<usize, String> {
    if values.is_empty() {
        return Ok(0);
    }
    let key: [u8; 32] = rand::random();
    let nonce: [u8; NONCE_LEN] = rand::random();
    let written_at_ms = now_ms();
    let mut sealed = serde_json::to_vec(values).map_err(|error| error.to_string())?;
    cipher(&key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(written_at_ms)),
            &mut sealed,
        )
        .map_err(|_| "sealing failed".to_owned())?;
    let envelope = Envelope {
        written_at_ms,
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(sealed),
    };

    store.put(&key)?;
    let path = state_dir.join(FILE);
    let _ = std::fs::remove_file(&path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| error.to_string())?;
    file.write_all(&serde_json::to_vec(&envelope).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;

    Ok(values.len())
}

/// The values the last daemon on `state_dir` handed off, removing the
/// handoff whether or not it could be used; empty when there is none or it
/// is older than [`MAX_AGE`]
pub fn take_over(state_dir: &Path, store: &KeyStore) -> Result<HashMap<String, String>, String> {
    let path = state_dir.join(FILE);
    let text = match std::fs::read(&path) {
        Ok(text) => text,
        // a key left without its file is replaced by the next handoff
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error.to_string()),
    };
    // used once, whatever happens next
    let _ = std::fs::remove_file(&path);
    let key = store.take()?;

    let envelope: Envelope = serde_json::from_slice(&text).map_err(|error| error.to_string())?;
    // a clock set back since the handoff makes its age unknowable, so one
    // from the future is refused like a stale one
    let now = now_ms();
    if envelope.written_at_ms > now.saturating_add(CLOCK_SKEW_MS) {
        return Err("the handoff is dated in the future".to_owned());
    }
    let age = Duration::from_millis(now.saturating_sub(envelope.written_at_ms));
    if age > MAX_AGE {
        return Err(format!("the handoff is {}s old", age.as_secs()));
    }
    let Some(key) = key else {
        return Err("the handoff's key is gone".to_owned());
    };
    let nonce: [u8; NONCE_LEN] = hex::decode(&envelope.nonce)
        .ok()
        .and_then(|nonce| nonce.try_into().ok())
        .ok_or("the nonce is malformed")?;
    let mut sealed = hex::decode(&envelope.ciphertext).map_err(|error| error.to_string())?;
    let opened = cipher(&key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(envelope.written_at_ms)),
            &mut sealed,
        )
        .map_err(|_| "the handoff does not open with its key".to_owned())?;

    serde_json::from_slice(opened).map_err(|error| error.to_string())
}

fn cipher(key: &[u8; 32]) -> Result<LessSafeKey, String> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| "bad key".to_owned())
}

fn aad(written_at_ms: u64) -> Vec<u8> {
    format!("{AAD_PREFIX}\n{written_at_ms}").into_bytes()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
