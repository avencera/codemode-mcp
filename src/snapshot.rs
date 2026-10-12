//! Integrity protection for dumped sandbox sessions
//!
//! Monty does not authenticate its dumps, and a tampered dump may restore
//! with arbitrary limits or host-callback requests, so every dump is sealed
//! with an HMAC-SHA256 under a per-install key before it leaves the worker
//! and checked before it is restored

use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// File in the state directory holding the key
const KEY_FILE: &str = "snapshot.key";
const KEY_BYTES: usize = 32;

/// Failures preparing the key or opening a sealed dump
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// The key file could not be read or created
    #[error("snapshot key {path}: {source}")]
    Key {
        /// Key file
        path: PathBuf,
        /// Underlying error
        source: std::io::Error,
    },
    /// The key file exists but is not a valid key
    #[error("snapshot key {0} is malformed")]
    MalformedKey(PathBuf),
    /// The dump does not match its tag
    #[error("snapshot failed its integrity check")]
    Tampered,
}

/// A dump with its authentication tag
pub struct Sealed {
    bytes: Vec<u8>,
    tag: Vec<u8>,
}

impl Sealed {
    /// Size of the dump
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the dump is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Seals and opens dumps with the install's key
pub struct Sealer(Hmac<Sha256>);

impl Sealer {
    /// Reads the key from `state_dir`, creating it (mode 0600) on first use
    pub fn load_or_create(state_dir: &Path) -> Result<Self, SnapshotError> {
        let path = state_dir.join(KEY_FILE);
        let key_error = |source| SnapshotError::Key {
            path: path.clone(),
            source,
        };

        match std::fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() != KEY_BYTES {
                    return Err(SnapshotError::MalformedKey(path));
                }

                return Self::from_key(&bytes, path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(key_error(error)),
        }

        let key: [u8; KEY_BYTES] = rand::random();
        // create_new: two daemons racing on first start must not overwrite
        // each other's key
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(key_error)?;
        file.write_all(&key).map_err(key_error)?;

        Self::from_key(&key, path)
    }

    fn from_key(key: &[u8], path: PathBuf) -> Result<Self, SnapshotError> {
        Hmac::<Sha256>::new_from_slice(key)
            .map(Self)
            .map_err(|_| SnapshotError::MalformedKey(path))
    }

    /// Tags `bytes`
    pub fn seal(&self, bytes: Vec<u8>) -> Sealed {
        let tag = self.mac(&bytes).finalize().into_bytes().to_vec();

        Sealed { bytes, tag }
    }

    /// Returns the dump when its tag is valid
    pub fn open(&self, sealed: Sealed) -> Result<Vec<u8>, SnapshotError> {
        // verify_slice compares in constant time
        self.mac(&sealed.bytes)
            .verify_slice(&sealed.tag)
            .map_err(|_| SnapshotError::Tampered)?;

        Ok(sealed.bytes)
    }

    fn mac(&self, bytes: &[u8]) -> Hmac<Sha256> {
        let mut mac = self.0.clone();
        mac.update(bytes);

        mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tampered_dumps_are_refused_and_the_key_persists() -> Result<(), SnapshotError> {
        let directory =
            std::env::temp_dir().join(format!("codemode-seal-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).map_err(|source| SnapshotError::Key {
            path: directory.clone(),
            source,
        })?;

        let sealer = Sealer::load_or_create(&directory)?;
        let sealed = sealer.seal(b"dump".to_vec());
        let mut tampered = sealer.seal(b"dump".to_vec());
        tampered.bytes[0] ^= 1;
        let reloaded = Sealer::load_or_create(&directory)?;

        assert_eq!(reloaded.open(sealed)?, b"dump");
        assert!(matches!(
            sealer.open(tampered),
            Err(SnapshotError::Tampered)
        ));
        let _ = std::fs::remove_dir_all(&directory);

        Ok(())
    }
}
