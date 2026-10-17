//! A 32-byte key the daemon keeps for itself: the restart handoff's and the
//! device trust key
//!
//! The installed service binary keeps it in the login keychain, where only
//! that signed binary reads it without a prompt. Any other build keeps it in
//! a file in the state directory, mode 0600, which keeps it from other users
//! but not from this one: a keychain item is bound to the code that made it,
//! so a test or checkout build writing it would leave the service a keychain
//! prompt

use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// `errSecItemNotFound`
#[cfg(target_os = "macos")]
const KEYCHAIN_NOT_FOUND: i32 = -25300;

/// Names a key's login keychain item
#[derive(Debug, Clone, Copy)]
pub struct KeychainItem {
    /// Keychain service
    pub service: &'static str,
    /// Keychain account
    pub account: &'static str,
}

/// Where a key is kept
#[derive(Debug, Clone)]
pub enum KeyStore {
    /// The login keychain
    Keychain(KeychainItem),
    /// A file, for builds other than the installed service binary
    File(PathBuf),
}

impl KeyStore {
    /// `item` in the keychain when `keychain` is allowed and this is the
    /// installed service binary, otherwise `file` in `state_dir`
    pub fn for_state(state_dir: &Path, keychain: bool, item: KeychainItem, file: &str) -> Self {
        if keychain && is_installed_binary(state_dir) {
            Self::Keychain(item)
        } else {
            Self::File(state_dir.join(file))
        }
    }

    /// Stores `key`, replacing any earlier one
    pub fn put(&self, key: &[u8; 32]) -> Result<(), String> {
        match self {
            Self::Keychain(item) => keychain_put(*item, key),
            Self::File(path) => {
                let _ = std::fs::remove_file(path);
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|error| error.to_string())?;
                file.write_all(key).map_err(|error| error.to_string())?;

                file.sync_all().map_err(|error| error.to_string())
            }
        }
    }

    /// The key, left in the store; `None` when there is none
    pub fn read(&self) -> Result<Option<[u8; 32]>, String> {
        let bytes = match self {
            Self::Keychain(item) => keychain_read(*item)?,
            Self::File(path) => match std::fs::read(path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.to_string()),
            },
        };

        bytes
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| "the key is not 32 bytes".to_owned())
            })
            .transpose()
    }

    /// The key, removed from the store
    pub fn take(&self) -> Result<Option<[u8; 32]>, String> {
        // one that cannot be read stays, and the next `put` replaces it
        let key = self.read()?;
        match self {
            Self::Keychain(item) => keychain_delete(*item),
            Self::File(path) => {
                let _ = std::fs::remove_file(path);
            }
        }

        Ok(key)
    }
}

/// Whether this process runs the binary `service install` put in place
fn is_installed_binary(state_dir: &Path) -> bool {
    crate::service::ServicePaths::from_env(state_dir).is_ok_and(|paths| {
        let running = std::env::current_exe().and_then(std::fs::canonicalize);
        let installed = std::fs::canonicalize(&paths.binary);

        matches!((running, installed), (Ok(running), Ok(installed)) if running == installed)
    })
}

#[cfg(target_os = "macos")]
fn keychain_put(item: KeychainItem, key: &[u8; 32]) -> Result<(), String> {
    use security_framework::passwords::set_generic_password;

    set_generic_password(item.service, item.account, key).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn keychain_read(item: KeychainItem) -> Result<Option<Vec<u8>>, String> {
    use security_framework::passwords::get_generic_password;

    match get_generic_password(item.service, item.account) {
        Ok(stored) => Ok(Some(stored)),
        Err(error) if error.code() == KEYCHAIN_NOT_FOUND => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn keychain_delete(item: KeychainItem) {
    use security_framework::passwords::delete_generic_password;

    let _ = delete_generic_password(item.service, item.account);
}

#[cfg(not(target_os = "macos"))]
fn keychain_put(_item: KeychainItem, _key: &[u8; 32]) -> Result<(), String> {
    Err("this system has no login keychain".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn keychain_read(_item: KeychainItem) -> Result<Option<Vec<u8>>, String> {
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
fn keychain_delete(_item: KeychainItem) {}
