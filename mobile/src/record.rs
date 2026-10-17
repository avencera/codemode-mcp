//! What a pairing leaves on the phone: the gateway it answers and the
//! phone's iroh key, both in the Keychain

use std::net::SocketAddr;

use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use serde::{Deserialize, Serialize};

use crate::ffi::{GatewayInfo, Platform, PlatformError};

/// Keychain item holding the [`GatewayRecord`] as JSON
const GATEWAY_ITEM: &str = "gateway";
/// Keychain item holding the phone's iroh secret key
const IROH_KEY_ITEM: &str = "iroh-key";

/// The paired gateway
///
/// Records from before the allow list went also carry `allow`; serde skips
/// the unknown field, so they still load
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRecord {
    /// The only endpoint this phone dials and answers
    pub id: EndpointId,
    /// The gateway Mac's short name, shown in prompts
    pub name: String,
    /// The name the gateway lists this phone under
    pub phone_name: String,
    /// Where to dial; empty when the gateway uses discovery
    pub addrs: Vec<SocketAddr>,
}

impl GatewayRecord {
    /// The record the last pairing saved, if it is readable
    pub fn load(platform: &dyn Platform) -> Option<Self> {
        let bytes = platform.load_secret(GATEWAY_ITEM.to_owned())?;

        serde_json::from_slice(&bytes).ok()
    }

    /// Keeps the record for the next launch
    pub fn save(&self, platform: &dyn Platform) -> Result<(), PlatformError> {
        let bytes = serde_json::to_vec(self).map_err(|error| PlatformError::Failed {
            message: error.to_string(),
        })?;

        platform.save_secret(GATEWAY_ITEM.to_owned(), bytes)
    }

    /// Forgets the gateway, the iroh key and the Secure Enclave key
    pub fn forget(platform: &dyn Platform) {
        platform.delete_secret(GATEWAY_ITEM.to_owned());
        platform.delete_secret(IROH_KEY_ITEM.to_owned());
        platform.delete_seal_key();
    }

    /// Whether to use n0's relays and DNS: only when the gateway does,
    /// which its invite shows by carrying no addresses
    pub fn discovery(&self) -> bool {
        self.addrs.is_empty()
    }

    /// The gateway as iroh dials it
    pub fn endpoint_addr(&self) -> EndpointAddr {
        EndpointAddr::from_parts(self.id, self.addrs.iter().copied().map(TransportAddr::Ip))
    }

    /// What the UI shows
    pub fn info(&self) -> GatewayInfo {
        GatewayInfo {
            name: self.name.clone(),
            id: self.id.to_string(),
            phone_name: self.phone_name.clone(),
        }
    }
}

/// The phone's iroh key, as the last pairing made it
pub fn load_key(platform: &dyn Platform) -> Option<SecretKey> {
    let bytes: [u8; 32] = platform
        .load_secret(IROH_KEY_ITEM.to_owned())?
        .try_into()
        .ok()?;

    Some(SecretKey::from_bytes(&bytes))
}

/// A new iroh key, kept in the Keychain; each pairing makes one, so an
/// unpaired phone's old id is dead
pub fn create_key(platform: &dyn Platform) -> Result<SecretKey, PlatformError> {
    let key = SecretKey::generate();
    platform.save_secret(IROH_KEY_ITEM.to_owned(), key.to_bytes().to_vec())?;

    Ok(key)
}
