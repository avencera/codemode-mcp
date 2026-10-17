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
//! Each value goes with a digest of every server config it was filled
//! into ([`Consumers`]). The next daemon drops a value when one of its own
//! servers using that reference is not among them, so editing a server's
//! command, url or environment to send a value somewhere new asks the owner
//! again instead of handing it over silently
//!
//! The keychain is used only by the installed service binary with no
//! `secrets.identity_file`: a keychain item is bound to the code that made
//! it, so a test or checkout build writing it would leave the service a
//! keychain prompt. Any other daemon puts the key in [`KEY_FILE`] beside the
//! ciphertext, mode 0600, which keeps the values from other users but not
//! from this one

use std::{
    collections::{BTreeSet, HashMap},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    digest::{SHA256, digest},
};
use serde::{Deserialize, Serialize};

use crate::config::{Config, ServerConfig};

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

/// Keychain service of the key
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "dev.praveen.codemode-mcp.handoff";
/// Keychain account of the key
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "daemon";
/// `errSecItemNotFound`
#[cfg(target_os = "macos")]
const KEYCHAIN_NOT_FOUND: i32 = -25300;

/// Bound into the ciphertext with the format version and the time it was
/// written, so a handoff cannot be passed off as another format or a later
/// one
const AAD_PREFIX: &str = "codemode-mcp/handoff";

/// The format this daemon writes: [`Sealed`]
const VERSION: u8 = 2;

/// What [`FILE`] holds
#[derive(Serialize, Deserialize)]
struct Envelope {
    /// The format, 1 when absent: the values alone, as 0.6 wrote them
    #[serde(default = "first_version")]
    version: u8,
    /// When it was written, in Unix milliseconds
    written_at_ms: u64,
    /// Hex
    nonce: String,
    /// Hex, with the tag
    ciphertext: String,
}

/// What the ciphertext of a [`VERSION`] handoff holds
#[derive(Serialize, Deserialize)]
struct Sealed {
    values: HashMap<String, String>,
    consumers: Consumers,
}

/// For each reference in the servers' config, a digest of each server that
/// fills it in, covering everything that decides where its value goes: the
/// server's name, command, arguments, working directory, environment, url,
/// headers and OAuth client. A policy or tool setting is left out, so
/// editing one asks for nothing
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Consumers(HashMap<String, BTreeSet<String>>);

impl Consumers {
    /// The consumers of every reference in `config`'s servers
    pub fn of(config: &Config) -> Self {
        let mut consumers = Self::default();
        for (name, server) in &config.servers {
            let digest = consumer_digest(name, server);
            let texts = server
                .env
                .values()
                .chain(server.headers.values())
                .chain(&server.url)
                .chain(&server.client_secret);
            // a malformed value fails the server's own read, which reads
            // nothing; it has no reference to bind here
            let references = texts.flat_map(|text| super::references(text).unwrap_or_default());
            for reference in references {
                consumers
                    .0
                    .entry(reference.to_owned())
                    .or_default()
                    .insert(digest.clone());
            }
        }

        consumers
    }

    /// Whether every server in `self` using `reference` is one that `handed`
    /// gave its value to
    fn all_known_to(&self, handed: &Self, reference: &str) -> bool {
        let Some(now) = self.0.get(reference) else {
            return true;
        };

        handed
            .0
            .get(reference)
            .is_some_and(|before| now.is_subset(before))
    }
}

/// Hex SHA-256 of what decides where `server`'s values go
fn consumer_digest(name: &str, server: &ServerConfig) -> String {
    /// Borrowed, so the digest covers exactly these fields
    #[derive(Serialize)]
    struct Placement<'a> {
        name: &'a str,
        command: &'a Option<String>,
        args: &'a [String],
        cwd: &'a Option<PathBuf>,
        env: &'a std::collections::BTreeMap<String, String>,
        url: &'a Option<String>,
        headers: &'a std::collections::BTreeMap<String, String>,
        client_id: &'a Option<String>,
        client_secret: &'a Option<String>,
    }

    let placement = Placement {
        name,
        command: &server.command,
        args: &server.args,
        cwd: &server.cwd,
        env: &server.env,
        url: &server.url,
        headers: &server.headers,
        client_id: &server.client_id,
        client_secret: &server.client_secret,
    };
    // serializing borrowed strings, maps and paths cannot fail
    let bytes = serde_json::to_vec(&placement).unwrap_or_default();

    hex::encode(digest(&SHA256, &bytes))
}

/// Where the key is kept
#[derive(Debug, Clone)]
pub enum KeyStore {
    /// The login keychain
    Keychain,
    /// A file, for systems without a keychain
    File(PathBuf),
}

impl KeyStore {
    /// The keychain for the installed service binary using it for its
    /// identity too, otherwise a file in `state_dir`
    pub fn for_state(state_dir: &Path, identity_in_keychain: bool) -> Self {
        let installed = crate::service::ServicePaths::from_env(state_dir).is_ok_and(|paths| {
            let running = std::env::current_exe().and_then(std::fs::canonicalize);
            let installed = std::fs::canonicalize(&paths.binary);

            matches!((running, installed), (Ok(running), Ok(installed)) if running == installed)
        });
        if identity_in_keychain && installed {
            Self::Keychain
        } else {
            Self::File(state_dir.join(KEY_FILE))
        }
    }

    fn put(&self, key: &[u8; 32]) -> Result<(), String> {
        match self {
            Self::Keychain => keychain_put(key),
            Self::File(path) => {
                let _ = std::fs::remove_file(path);
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|error| error.to_string())?;

                file.write_all(key).map_err(|error| error.to_string())
            }
        }
    }

    /// The key, removed from the store
    fn take(&self) -> Result<Option<[u8; 32]>, String> {
        match self {
            Self::Keychain => keychain_take(),
            Self::File(path) => {
                let bytes = match std::fs::read(path) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(error) => return Err(error.to_string()),
                };
                let _ = std::fs::remove_file(path);

                bytes
                    .try_into()
                    .map(Some)
                    .map_err(|_| "the key is not 32 bytes".to_owned())
            }
        }
    }
}

/// Seals `values` for the next daemon on `state_dir`, each with the
/// `consumers` it was filled into; nothing is written when there are none
pub fn hand_off(
    state_dir: &Path,
    store: &KeyStore,
    values: &HashMap<String, String>,
    consumers: Consumers,
) -> Result<usize, String> {
    if values.is_empty() {
        return Ok(0);
    }
    let key: [u8; 32] = rand::random();
    let nonce: [u8; NONCE_LEN] = rand::random();
    let written_at_ms = now_ms();
    let sealed = Sealed {
        values: values.clone(),
        consumers,
    };
    let mut sealed = serde_json::to_vec(&sealed).map_err(|error| error.to_string())?;
    cipher(&key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(VERSION, written_at_ms)),
            &mut sealed,
        )
        .map_err(|_| "sealing failed".to_owned())?;
    let envelope = Envelope {
        version: VERSION,
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

/// What [`take_over`] found
#[derive(Debug, Default)]
pub struct TakenOver {
    /// The values `consumers` may have
    pub values: HashMap<String, String>,
    /// References whose value was dropped, since a server now using it was
    /// changed or added since the handoff
    pub dropped: Vec<String>,
}

/// The values the last daemon on `state_dir` handed off for servers that
/// `consumers` still names the same way, removing the handoff whether or
/// not it could be used; empty when there is none or it is older than
/// [`MAX_AGE`]
pub fn take_over(
    state_dir: &Path,
    store: &KeyStore,
    consumers: &Consumers,
) -> Result<TakenOver, String> {
    let path = state_dir.join(FILE);
    let text = match std::fs::read(&path) {
        Ok(text) => text,
        // a key left without its file is replaced by the next handoff
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TakenOver::default());
        }
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
            Aad::from(aad(envelope.version, envelope.written_at_ms)),
            &mut sealed,
        )
        .map_err(|_| "the handoff does not open with its key".to_owned())?;
    let sealed = match envelope.version {
        // the one restart from 0.6, which named no consumers: that daemon
        // gave every value to the servers it had, so they are taken as
        // today's, as upgrading should not ask again
        1 => {
            let values: HashMap<String, String> =
                serde_json::from_slice(opened).map_err(|error| error.to_string())?;

            return Ok(TakenOver {
                values,
                dropped: Vec::new(),
            });
        }
        VERSION => serde_json::from_slice::<Sealed>(opened).map_err(|error| error.to_string())?,
        version => return Err(format!("the handoff is format {version}, not {VERSION}")),
    };

    let mut taken = TakenOver::default();
    for (reference, value) in sealed.values {
        if consumers.all_known_to(&sealed.consumers, &reference) {
            taken.values.insert(reference, value);
        } else {
            taken.dropped.push(reference);
        }
    }
    taken.dropped.sort();

    Ok(taken)
}

fn cipher(key: &[u8; 32]) -> Result<LessSafeKey, String> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| "bad key".to_owned())
}

fn aad(version: u8, written_at_ms: u64) -> Vec<u8> {
    format!("{AAD_PREFIX}/{version}\n{written_at_ms}").into_bytes()
}

const fn first_version() -> u8 {
    1
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(target_os = "macos")]
fn keychain_put(key: &[u8; 32]) -> Result<(), String> {
    use security_framework::passwords::set_generic_password;

    set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn keychain_take() -> Result<Option<[u8; 32]>, String> {
    use security_framework::passwords::{delete_generic_password, get_generic_password};

    let stored = match get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
        Ok(stored) => stored,
        Err(error) if error.code() == KEYCHAIN_NOT_FOUND => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let _ = delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);

    stored
        .try_into()
        .map(Some)
        .map_err(|_| "the key is not 32 bytes".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn keychain_put(_key: &[u8; 32]) -> Result<(), String> {
    Err("this system has no login keychain".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn keychain_take() -> Result<Option<[u8; 32]>, String> {
    Ok(None)
}
