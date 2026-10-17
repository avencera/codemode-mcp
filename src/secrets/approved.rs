//! Which server configs the owner approved each config reference for
//!
//! A value read for a server's config goes wherever that config sends it:
//! its command and environment, its url, its headers. Anything of this user
//! can edit the config file, so a value is handed to a server only while
//! the server stands as it did when the owner approved the value for it.
//! Each approval is a (reference, [`Consumer`]) pair whose digest covers
//! everything that decides where the value goes; editing a policy or tool
//! setting leaves it alone
//!
//! The pairs sit in [`FILE`] in the state directory, each with an HMAC under
//! a key derived from the device trust key, so nothing without that key can
//! add one. They outlive restarts and crashes, so a changed server keeps
//! needing approval until it gets one. On the start that sets device trust
//! up, every server the config lists then is approved, before the key is
//! kept, so upgrading asks nothing and a stop part way does it all again

use std::{
    collections::{BTreeMap, HashSet},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use aws_lc_rs::digest::{SHA256, digest};
use hmac::{Hmac, KeyInit, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::{Config, ServerConfig};

/// The approvals, in the state directory
pub const FILE: &str = "secrets.approved";

/// Bound into every tag, so a tag cannot be passed off as another format or
/// another use of the key
const DOMAIN: &str = "codemode-mcp/approved-consumer/1";

/// What the key is derived for from the device trust key
pub const KEY_DOMAIN: &str = "codemode-mcp/approved-consumer-key/1";

/// A configured server as far as where its values go
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Consumer {
    /// The server's name, for prompts
    pub name: String,
    /// Hex SHA-256 of what decides where its values go
    digest: String,
}

impl Consumer {
    /// The server `name` as `server` configures it: its name, command,
    /// arguments, working directory, environment, url, headers and OAuth
    /// client
    pub fn of(name: &str, server: &ServerConfig) -> Self {
        /// Borrowed, so the digest covers exactly these fields
        #[derive(Serialize)]
        struct Placement<'a> {
            name: &'a str,
            command: &'a Option<String>,
            args: &'a [String],
            cwd: &'a Option<PathBuf>,
            env: &'a BTreeMap<String, String>,
            url: &'a Option<String>,
            headers: &'a BTreeMap<String, String>,
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

        Self {
            name: name.to_owned(),
            digest: hex::encode(digest(&SHA256, &bytes)),
        }
    }
}

/// Every reference `server` fills in, wherever its config holds one
fn server_references(server: &ServerConfig) -> impl Iterator<Item = &str> {
    server
        .env
        .values()
        .chain(server.headers.values())
        .chain(&server.url)
        .chain(&server.client_secret)
        // a malformed value fails the server's own read, which reads
        // nothing; it has nothing to approve
        .flat_map(|text| super::references(text).unwrap_or_default())
}

/// One approval in [`FILE`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    reference: String,
    consumer: String,
    /// Hex HMAC of the pair
    tag: String,
}

/// What [`FILE`] holds
#[derive(Debug, Default, Serialize, Deserialize)]
struct Entries {
    entries: Vec<Entry>,
}

/// The approved pairs and the key that vouches for them
pub struct Approved {
    /// `None` gates nothing: a one-off run, which reads like `op` itself
    gate: Option<Gate>,
}

struct Gate {
    /// `None` when the trust key could not be read, so nothing is approved
    /// and every read asks
    key: Option<Hmac<Sha256>>,
    path: PathBuf,
    /// The pairs whose tags verified, as (reference, consumer digest)
    pairs: Mutex<HashSet<(String, String)>>,
}

impl std::fmt::Debug for Approved {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Approved")
            .field("gated", &self.gate.is_some())
            .finish()
    }
}

impl Approved {
    /// Approves everything, for a process that is not the daemon
    pub fn ungated() -> Self {
        Self { gate: None }
    }

    /// The approvals on `state_dir` under `key`
    pub fn open(state_dir: &Path, key: Option<[u8; 32]>) -> Self {
        let key = key.and_then(|key| Hmac::<Sha256>::new_from_slice(&key).ok());
        let path = state_dir.join(FILE);
        let pairs = match &key {
            Some(key) => load(&path)
                .entries
                .into_iter()
                .filter(|entry| verifies(key, entry))
                .map(|entry| (entry.reference, entry.consumer))
                .collect(),
            None => {
                tracing::warn!("without the device trust key every config secret read asks");
                HashSet::new()
            }
        };

        Self {
            gate: Some(Gate {
                key,
                path,
                pairs: Mutex::new(pairs),
            }),
        }
    }

    /// Approves every server `config` lists for the references it uses,
    /// under `key`, as the start that sets device trust up does; an error
    /// when they cannot be kept, which has that set-up done again
    pub fn approve_config(
        state_dir: &Path,
        key: Option<[u8; 32]>,
        config: &Config,
    ) -> Result<(), String> {
        let key = key
            .and_then(|key| Hmac::<Sha256>::new_from_slice(&key).ok())
            .ok_or("no key to approve the config's servers under")?;
        let path = state_dir.join(FILE);
        // under a new key nothing older verifies, so it starts afresh
        let mut entries = Entries::default();
        for (name, server) in &config.servers {
            let consumer = Consumer::of(name, server);
            for reference in server_references(server) {
                entries.entries.push(Entry {
                    reference: reference.to_owned(),
                    consumer: consumer.digest.clone(),
                    tag: hex::encode(tag(&key, reference, &consumer.digest)),
                });
            }
        }

        save(&path, &entries)
    }

    /// Whether `consumer` may be given the value of `reference` without
    /// asking
    pub fn allows(&self, consumer: &Consumer, reference: &str) -> bool {
        let Some(gate) = &self.gate else {
            return true;
        };

        gate.pairs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(reference.to_owned(), consumer.digest.clone()))
    }

    /// Records that the owner approved `reference` for `consumer`; a failure
    /// to write is logged, and the next daemon asks again
    pub fn approve(&self, consumer: &Consumer, reference: &str) {
        let Some(Gate {
            key: Some(key),
            path,
            pairs,
        }) = &self.gate
        else {
            return;
        };

        let mut pairs = pairs.lock().unwrap_or_else(PoisonError::into_inner);
        if !pairs.insert((reference.to_owned(), consumer.digest.clone())) {
            return;
        }
        let mut entries = load(path);
        entries.entries.retain(|entry| verifies(key, entry));
        entries.entries.push(Entry {
            reference: reference.to_owned(),
            consumer: consumer.digest.clone(),
            tag: hex::encode(tag(key, reference, &consumer.digest)),
        });
        if let Err(error) = save(path, &entries) {
            tracing::warn!(%error, server = %consumer.name, "could not keep a secret approval");
        }
    }
}

fn tag(key: &Hmac<Sha256>, reference: &str, consumer: &str) -> Vec<u8> {
    let mut mac = key.clone();
    mac.update(format!("{DOMAIN}\n{reference}\n{consumer}").as_bytes());

    mac.finalize().into_bytes().to_vec()
}

fn verifies(key: &Hmac<Sha256>, entry: &Entry) -> bool {
    hex::decode(&entry.tag).is_ok_and(|bytes| {
        let mut mac = key.clone();
        mac.update(format!("{DOMAIN}\n{}\n{}", entry.reference, entry.consumer).as_bytes());
        // compares in constant time
        mac.verify_slice(&bytes).is_ok()
    })
}

/// The entries; none when the file is missing or unreadable, which only
/// makes reads ask again
fn load(path: &Path) -> Entries {
    match std::fs::read(path) {
        Ok(text) => serde_json::from_slice(&text).unwrap_or_else(|error| {
            tracing::warn!(%error, "the secret approvals are malformed");

            Entries::default()
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Entries::default(),
        Err(error) => {
            tracing::warn!(%error, "cannot read the secret approvals");

            Entries::default()
        }
    }
}

/// Replaces the file in one rename, so a crash leaves the old one
fn save(path: &Path, entries: &Entries) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(entries).map_err(|error| error.to_string())?;
    let temp = path.with_extension(format!("tmp-{}", hex::encode(rand::random::<[u8; 4]>())));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(&text)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }

    written.map_err(|error| format!("cannot write {}: {error}", path.display()))
}
