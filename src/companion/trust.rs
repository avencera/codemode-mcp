//! Device trust: which of the listed companions and phones the gateway uses
//!
//! The config file lists the devices, but any process of this user can
//! append to it, and a phone listed there gets every value sealed to it. So
//! a device is used only with a trust record: HMAC-SHA256, under a key the
//! daemon keeps to itself, of what identifies it (its kind, its endpoint id
//! and, for a phone, the key values are sealed to). The records sit in
//! [`RECORDS_FILE`] in the state directory, where anyone can read them but
//! nobody without the key can forge one. A record is written only after the
//! owner approves with Touch ID at the gateway Mac: when opening the invite
//! the device pairs with, or with `codemode-mcp companion trust <name>`
//!
//! The key is kept like the restart handoff's: the installed service binary
//! keeps it in the login keychain, which other processes cannot read without
//! a prompt; other builds keep it in [`KEY_FILE`], which guards nothing
//! against this user and serves checkout builds and tests. Unlike the
//! handoff's, the keychain is used whatever `secrets.identity_file` says,
//! since a config edit that moved the key to a file would leave no key and
//! so trust the whole config again
//!
//! A daemon that finds no key and no records makes a key and trusts every
//! device the config lists at that moment, so upgrading changes nothing for
//! the owner. With records but no key, the key was lost or removed, which
//! must not trust the config as it now stands: that daemon makes a new key
//! and trusts nothing until the owner trusts each device again

use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, PoisonError},
};

use hmac::{Hmac, KeyInit, Mac as _};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{ASK_TIMEOUT, CompanionFailure, Companions, pair::read_config};
use crate::{
    config::{CompanionPeer, Config, PhonePeer, SecretsConfig},
    mac::TouchId,
    secrets::key_store::{KeyStore, KeychainItem},
};

/// The trust records, in the state directory
pub const RECORDS_FILE: &str = "devices.trust";
/// The key, for builds other than the installed service binary
pub const KEY_FILE: &str = "devices.trust.key";

/// The key's keychain item
const KEYCHAIN_ITEM: KeychainItem = KeychainItem {
    service: "dev.praveen.codemode-mcp.device-trust",
    account: "daemon",
};

/// Bound into every record, so a record cannot be passed off as another
/// format or another use of the key
const DOMAIN: &str = "codemode-mcp/device-trust/1";

/// Cancel button of the gateway Mac's Touch ID prompt
const CANCEL_TITLE: &str = "Deny";

/// A companion Mac or a phone the config lists
#[derive(Debug, Clone)]
pub enum Device {
    /// Reads references with its own `op`
    Mac(CompanionPeer),
    /// Opens values sealed to it
    Phone(PhonePeer),
}

impl Device {
    /// The name the config lists it under
    pub fn name(&self) -> &str {
        match self {
            Self::Mac(peer) => &peer.name,
            Self::Phone(phone) => &phone.name,
        }
    }

    /// Its iroh endpoint id
    pub fn id(&self) -> EndpointId {
        match self {
            Self::Mac(peer) => peer.id,
            Self::Phone(phone) => phone.id,
        }
    }

    /// `mac` or `phone`
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Mac(_) => "mac",
            Self::Phone(_) => "phone",
        }
    }

    /// A digest of what a record covers, shown wherever the owner approves
    /// or reviews a device, so two devices listed under one name read
    /// differently; six words, 66 bits, too many to grind a matching key for
    pub fn fingerprint(&self) -> String {
        crate::words::words(&Sha256::digest(self.identity().as_bytes()), 6)
    }

    /// What a record covers; the name and a Mac's addresses are left out,
    /// since iroh proves the endpoint id whatever address it is dialed at
    fn identity(&self) -> String {
        let seal_key = match self {
            Self::Mac(_) => String::new(),
            Self::Phone(phone) => phone.seal_key.to_base64(),
        };

        format!("{DOMAIN}\n{}\n{}\n{seal_key}", self.kind(), self.id())
    }

    /// Every device `config` lists, companions first
    fn listed(config: &SecretsConfig) -> Vec<Self> {
        config
            .companions
            .iter()
            .cloned()
            .map(Self::Mac)
            .chain(config.phones.iter().cloned().map(Self::Phone))
            .collect()
    }
}

/// One trusted device in [`RECORDS_FILE`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    kind: String,
    id: EndpointId,
    /// Hex HMAC of the device's identity
    tag: String,
}

/// What [`RECORDS_FILE`] holds; records made under another key (a checkout
/// build's file key beside the service's keychain key) stay beside each
/// other and simply do not verify under this one
#[derive(Debug, Default, Serialize, Deserialize)]
struct Records {
    records: Vec<Record>,
}

/// The trust key and the records it vouches for
pub struct DeviceTrust {
    /// `None` when the key could not be read or made, so nothing is trusted
    key: Option<Hmac<Sha256>>,
    records: PathBuf,
    /// One read-modify-write of the records at a time
    writing: std::sync::Mutex<()>,
}

impl DeviceTrust {
    /// The trust on `state_dir`; with `may_create`, a missing key is made and
    /// every device `listed` names is trusted. Only the daemon may create:
    /// a one-off run without a key trusts nothing
    pub fn open(state_dir: &Path, listed: &SecretsConfig, may_create: bool) -> Self {
        let store = KeyStore::for_state(state_dir, true, KEYCHAIN_ITEM, KEY_FILE);

        Self::open_with(&store, state_dir.join(RECORDS_FILE), listed, may_create)
    }

    fn open_with(
        store: &KeyStore,
        records: PathBuf,
        listed: &SecretsConfig,
        may_create: bool,
    ) -> Self {
        let with_key = |key: &[u8; 32]| Self {
            key: Hmac::<Sha256>::new_from_slice(key).ok(),
            records: records.clone(),
            writing: std::sync::Mutex::new(()),
        };
        let none = || Self {
            key: None,
            records: records.clone(),
            writing: std::sync::Mutex::new(()),
        };

        match store.read() {
            Ok(Some(key)) => with_key(&key),
            Ok(None) if may_create => {
                let key: [u8; 32] = rand::random();
                let trust = with_key(&key);
                let devices = if trust.load().records.is_empty() {
                    Device::listed(listed)
                } else {
                    tracing::warn!(
                        "the device trust key is gone but its records are not, so no device is \
                         trusted; approve each with `codemode-mcp companion trust <name>`"
                    );
                    Vec::new()
                };
                // records first: a key stored without them would leave every
                // device untrusted, while records without a key are redone
                for device in &devices {
                    if let Err(error) = trust.trust(device) {
                        tracing::warn!(%error, "could not set up device trust");

                        return none();
                    }
                }
                if let Err(error) = store.put(&key) {
                    tracing::warn!(%error, "could not keep the device trust key");

                    return none();
                }
                let names: Vec<&str> = devices.iter().map(Device::name).collect();
                tracing::info!(
                    devices = %names.join(", "),
                    "set up device trust, trusting the companions and phones the config lists"
                );

                trust
            }
            Ok(None) => none(),
            Err(error) => {
                tracing::warn!(%error, "cannot read the device trust key");

                none()
            }
        }
    }

    /// Whether the key could be read, so records can be checked at all
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Whether a record vouches for `device` as it is listed now
    pub fn is_trusted(&self, device: &Device) -> bool {
        let Some(key) = &self.key else {
            return false;
        };
        let identity = device.identity();

        self.load().records.iter().any(|record| {
            record.kind == device.kind()
                && record.id == device.id()
                && hex::decode(&record.tag).is_ok_and(|tag| {
                    let mut mac = key.clone();
                    mac.update(identity.as_bytes());
                    // compares in constant time
                    mac.verify_slice(&tag).is_ok()
                })
        })
    }

    /// Writes the record that makes `device` trusted
    pub fn trust(&self, device: &Device) -> Result<(), String> {
        let Some(key) = &self.key else {
            return Err("the device trust key is unavailable".to_owned());
        };
        let mut mac = key.clone();
        mac.update(device.identity().as_bytes());
        let record = Record {
            kind: device.kind().to_owned(),
            id: device.id(),
            tag: hex::encode(mac.finalize().into_bytes()),
        };

        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut records = self.load();
        if records.records.contains(&record) {
            return Ok(());
        }
        records.records.push(record);

        self.save(&records)
    }

    /// Drops every record of the device `id`, under any key
    pub fn forget(&self, id: EndpointId) -> Result<(), String> {
        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut records = self.load();
        let before = records.records.len();
        records.records.retain(|record| record.id != id);
        if records.records.len() == before {
            return Ok(());
        }

        self.save(&records)
    }

    /// The records; none when the file is missing or unreadable, which
    /// leaves every device untrusted rather than failing the daemon
    fn load(&self) -> Records {
        let text = match std::fs::read(&self.records) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Records::default();
            }
            Err(error) => {
                tracing::warn!(%error, "cannot read the device trust records");

                return Records::default();
            }
        };

        serde_json::from_slice(&text).unwrap_or_else(|error| {
            tracing::warn!(%error, "the device trust records are malformed");

            Records::default()
        })
    }

    /// Replaces the records file in one rename, so a crash leaves the old one
    fn save(&self, records: &Records) -> Result<(), String> {
        let text = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        let temp = self
            .records
            .with_extension(format!("tmp-{}", hex::encode(rand::random::<[u8; 4]>())));
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .and_then(|mut file| {
                file.write_all(&text)?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&temp, &self.records));
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }

        written.map_err(|error| {
            format!(
                "cannot write the device trust records to {}: {error}",
                self.records.display()
            )
        })
    }
}

impl std::fmt::Debug for DeviceTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceTrust")
            .field("has_key", &self.has_key())
            .field("records", &self.records)
            .finish()
    }
}

/// A device the config lists and how the gateway treats it
#[derive(Debug, Clone)]
pub struct ListedDevice {
    /// The device as listed
    pub device: Device,
    /// Whether the gateway uses it
    pub trusted: bool,
}

impl Companions {
    /// Every listed device, trusted ones first in configuration order
    pub fn devices(&self) -> Vec<ListedDevice> {
        let trusted = self
            .peers()
            .into_iter()
            .map(Device::Mac)
            .chain(self.phones().into_iter().map(Device::Phone))
            .map(|device| ListedDevice {
                device,
                trusted: true,
            });
        let untrusted = self.untrusted().into_iter().map(|device| ListedDevice {
            device,
            trusted: false,
        });

        trusted.chain(untrusted).collect()
    }

    /// The listed devices without a valid trust record, which are never used
    pub fn untrusted(&self) -> Vec<Device> {
        self.untrusted
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Stops listing the device `id` as untrusted, once it is used
    pub(super) fn drop_untrusted(&self, id: EndpointId) {
        self.untrusted
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|device| device.id() != id);
    }

    /// Asks the owner to approve `reason` with Touch ID at the gateway Mac;
    /// refused at once while they are not at it. `action` names what needs
    /// the approval in a refusal
    pub(super) async fn ask_owner(
        &self,
        reason: &str,
        action: &str,
    ) -> Result<(), CompanionFailure> {
        let refused = |why: &str| {
            Err(CompanionFailure::NotApproved(format!(
                "{action} needs Touch ID at the gateway Mac: {why}"
            )))
        };
        let Some(on_mac) = &self.on_mac else {
            return refused("this daemon has no Mac to ask on");
        };
        if !on_mac.mac.present(on_mac.config.idle()).await {
            return refused("the owner is not at it");
        }

        // a prompt nobody answers is taken down before the CLI gives up
        let answer = tokio::time::timeout(ASK_TIMEOUT, on_mac.mac.touch_id(reason, CANCEL_TITLE))
            .await
            .unwrap_or(TouchId::Away);
        match answer {
            TouchId::Approved => Ok(()),
            // its other button is Deny
            TouchId::Review => refused("it was denied"),
            TouchId::Away => refused("the prompt went unanswered"),
            TouchId::Unavailable => refused("Touch ID is unavailable"),
        }
    }

    /// Trusts the listed device called `name` once the owner approves with
    /// Touch ID at the gateway Mac, and starts using it without a restart;
    /// the config file is read again, so a device added since the daemon
    /// started is found too
    pub async fn trust_device(self: &Arc<Self>, name: &str) -> Result<Device, CompanionFailure> {
        let device = self.trust_candidate(name)?;
        // the kind is named, so a prompt the owner did not ask for, raised by
        // something holding the admin token, reads as what it is
        let kind = match device {
            Device::Mac(_) => "Mac",
            Device::Phone(_) => "phone",
        };
        self.ask_owner(
            &format!(
                "Trust the {kind} “{name}” ({}) to answer and receive codemode-mcp secrets",
                device.fingerprint()
            ),
            "trusting a device",
        )
        .await?;

        let _turn = self.registering.lock().await;
        // the list may have changed while the prompt was up: the device must
        // still be listed exactly as the prompt named it
        if !self
            .trust_candidate(name)
            .is_ok_and(|listed| listed.identity() == device.identity())
        {
            return Err(CompanionFailure::Trust(format!(
                "{name} changed or was removed while the prompt was up; try again"
            )));
        }
        if self.devices().iter().any(|listed| {
            listed.trusted && (listed.device.name() == name || listed.device.id() == device.id())
        }) {
            return Err(CompanionFailure::Trust(format!(
                "{name} is already trusted"
            )));
        }
        self.trust.trust(&device).map_err(CompanionFailure::Trust)?;
        tracing::info!(device = %name, kind = device.kind(), "device trusted");
        match &device {
            Device::Mac(peer) => self.add_peer(peer.clone()),
            Device::Phone(phone) => {
                self.add_phone(phone.clone());
                self.backfill(phone).await;
                if let Err(error) = self.listen_for_phones().await {
                    tracing::warn!(%error, "the phone cannot reach this gateway until the next read");
                }
            }
        }

        Ok(device)
    }

    /// The untrusted device called `name`, as the config file lists it now
    fn trust_candidate(&self, name: &str) -> Result<Device, CompanionFailure> {
        if self
            .devices()
            .iter()
            .any(|listed| listed.trusted && listed.device.name() == name)
        {
            return Err(CompanionFailure::Trust(format!(
                "{name} is already trusted"
            )));
        }
        // the file as it is now decides, so a device removed from it since
        // the daemon started cannot be trusted; without a file, what the
        // daemon started with
        let listed = match &self.config_path {
            Some(path) => {
                let text = read_config(path).map_err(|error| {
                    CompanionFailure::Trust(format!("cannot read {}: {error}", path.display()))
                })?;
                let config = Config::parse(&text, path)
                    .map_err(|error| CompanionFailure::Trust(error.to_string()))?;

                Device::listed(&config.secrets)
            }
            None => self.untrusted(),
        };

        let mut named: Vec<Device> = listed
            .into_iter()
            .filter(|device| device.name() == name)
            .collect();
        // one device listed twice is still one device; only the full
        // identity says two entries are the same
        let mut seen = std::collections::HashSet::new();
        named.retain(|device| seen.insert(device.identity()));
        // the prompt names one device, so a name standing for two is refused
        // rather than trusting whichever comes first
        match named.len() {
            0 => Err(CompanionFailure::Trust(format!(
                "no companion or phone named {name} is listed under [secrets]"
            ))),
            1 => Ok(named.remove(0)),
            _ => Err(CompanionFailure::Trust(format!(
                "several devices are listed as {name}; rename all but one"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phone(seal: u8) -> Device {
        let mut point = [seal; 65];
        point[0] = 0x04;

        Device::Phone(PhonePeer {
            name: "iphone".to_owned(),
            id: iroh::SecretKey::from_bytes(&[7; 32]).public(),
            seal_key: companion_wire::mobile::SealKey::from_bytes(&point)
                .unwrap_or_else(|| unreachable!("a 65-byte point tagged 0x04")),
        })
    }

    #[test]
    fn a_record_vouches_only_for_the_key_it_was_made_with() {
        let directory = std::env::temp_dir().join(format!(
            "codemode-trust-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&directory).unwrap_or_else(|error| panic!("{error}"));
        let records = directory.join(RECORDS_FILE);
        let store = KeyStore::File(directory.join(KEY_FILE));
        let none = SecretsConfig::default();

        let trust = DeviceTrust::open_with(&store, records.clone(), &none, true);
        assert!(trust.has_key());
        assert!(!trust.is_trusted(&phone(1)));
        trust
            .trust(&phone(1))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(trust.is_trusted(&phone(1)));
        // the same id listed with another seal key is someone else
        assert!(!trust.is_trusted(&phone(2)));

        // a record written by hand under another key does not verify
        let other = KeyStore::File(directory.join("other.key"));
        let forger = DeviceTrust::open_with(&other, directory.join("forged"), &none, true);
        forger
            .trust(&phone(2))
            .unwrap_or_else(|error| panic!("{error}"));
        let forged = std::fs::read_to_string(directory.join("forged"))
            .unwrap_or_else(|error| panic!("{error}"));
        std::fs::write(&records, forged).unwrap_or_else(|error| panic!("{error}"));
        let reopened = DeviceTrust::open_with(&store, records.clone(), &none, true);
        assert!(!reopened.is_trusted(&phone(2)));
        assert!(!reopened.is_trusted(&phone(1)));

        // with records left, a lost key trusts nothing the config lists
        let _ = std::fs::remove_file(directory.join(KEY_FILE));
        let listed = SecretsConfig {
            phones: vec![match phone(3) {
                Device::Phone(peer) => peer,
                Device::Mac(_) => unreachable!("a phone"),
            }],
            ..SecretsConfig::default()
        };
        let rekeyed = DeviceTrust::open_with(&store, records, &listed, true);
        assert!(rekeyed.has_key());
        assert!(!rekeyed.is_trusted(&phone(3)));

        let _ = std::fs::remove_dir_all(&directory);
    }
}
