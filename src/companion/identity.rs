//! The iroh secret key each role signs in with
//!
//! The default store is the login keychain: an item created by the signed
//! binary is readable without a prompt only by that binary's code identity,
//! and any other program that asks gets a keychain prompt. An
//! `identity_file` replaces it for tests and for systems without a keychain

use std::{
    io::{ErrorKind, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use iroh::SecretKey;

use crate::config::expand_home;

/// Keychain service of both roles' keys
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "dev.praveen.codemode-mcp.iroh";

/// `errSecItemNotFound`
#[cfg(target_os = "macos")]
const KEYCHAIN_NOT_FOUND: i32 = -25300;

/// `errSecDuplicateItem`
#[cfg(target_os = "macos")]
const KEYCHAIN_DUPLICATE: i32 = -25299;

/// Which key: the gateway's or a companion's; a Mac may be both
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The Mac whose daemon asks companions
    Gateway,
    /// A Mac that answers the gateway
    Companion,
}

impl Role {
    /// Keychain account name
    #[cfg(target_os = "macos")]
    fn account(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Companion => "companion",
        }
    }
}

/// Why a key could not be loaded or created
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// A file operation on the identity file failed
    #[error("identity file {path}: {source}")]
    File {
        /// The identity file
        path: PathBuf,
        /// Underlying error
        source: std::io::Error,
    },
    /// The identity file can be read by other users
    #[error("identity file {0} must not be accessible to group or others; run chmod 600 on it")]
    Permissions(PathBuf),
    /// The stored key is not 32 bytes of hex
    #[error("the stored identity key is not 64 hex digits")]
    Malformed,
    /// The identity file exists but is empty or not 32 bytes of hex
    #[error("identity file {0} is empty or not 64 hex digits; delete it to create a new key")]
    MalformedFile(PathBuf),
    /// The keychain refused
    #[error("keychain: {0}")]
    Keychain(String),
    /// There is no keychain on this system
    #[error("this system has no login keychain; set `identity_file` instead")]
    NoKeychain,
}

/// The key for `role`: from `file` when given, else from the login keychain,
/// created on first use
pub fn load_or_create(role: Role, file: Option<&Path>) -> Result<SecretKey, IdentityError> {
    match file {
        Some(path) => from_file(&expand_home(path)),
        None => from_keychain(role),
    }
}

fn decode(text: &str) -> Result<SecretKey, IdentityError> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(text.trim(), &mut bytes).map_err(|_| IdentityError::Malformed)?;

    Ok(SecretKey::from_bytes(&bytes))
}

fn encode(key: &SecretKey) -> String {
    hex::encode(key.to_bytes())
}

fn from_file(path: &Path) -> Result<SecretKey, IdentityError> {
    let file_error = |source| IdentityError::File {
        path: path.to_owned(),
        source,
    };

    // an existing key is only read, so its directory need not be writable
    match std::fs::metadata(path) {
        Ok(_) => return read_file(path),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(file_error(error)),
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(file_error)?;
    }

    // a key is written whole to a private temp file and then linked into
    // place: the link fails when the target exists, so a reader never sees a
    // half-written file and two creators never replace each other's key
    let key = SecretKey::generate();
    let mut temp_name = path.as_os_str().to_owned();
    // unique per creator, threads of one process included; the public half
    // is no secret
    let unique: String = key.public().to_string().chars().take(16).collect();
    temp_name.push(format!(".{unique}.tmp"));
    let temp = PathBuf::from(temp_name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .map_err(file_error)?;
    let written = file
        .write_all(encode(&key).as_bytes())
        .and_then(|()| file.sync_all());
    let linked = written.and_then(|()| std::fs::hard_link(&temp, path));
    // best effort: a leftover temp file holds only a key nobody uses
    let _ = std::fs::remove_file(&temp);

    match linked {
        Ok(()) => Ok(key),
        // another run created it first
        Err(error) if error.kind() == ErrorKind::AlreadyExists => read_file(path),
        Err(error) => Err(file_error(error)),
    }
}

/// The key in an existing file, refused when other users can read it
fn read_file(path: &Path) -> Result<SecretKey, IdentityError> {
    let file_error = |source| IdentityError::File {
        path: path.to_owned(),
        source,
    };

    let mode = std::fs::metadata(path)
        .map_err(file_error)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(IdentityError::Permissions(path.to_owned()));
    }

    decode(&std::fs::read_to_string(path).map_err(file_error)?).map_err(|error| match error {
        IdentityError::Malformed => IdentityError::MalformedFile(path.to_owned()),
        other => other,
    })
}

#[cfg(target_os = "macos")]
fn from_keychain(role: Role) -> Result<SecretKey, IdentityError> {
    use security_framework::{os::macos::keychain::SecKeychain, passwords::get_generic_password};

    let account = role.account();
    let keychain_error =
        |error: security_framework::base::Error| IdentityError::Keychain(error.to_string());
    let read = || -> Result<Option<SecretKey>, IdentityError> {
        match get_generic_password(KEYCHAIN_SERVICE, account) {
            Ok(stored) => decode(&String::from_utf8_lossy(&stored)).map(Some),
            Err(error) if error.code() == KEYCHAIN_NOT_FOUND => Ok(None),
            Err(error) => Err(keychain_error(error)),
        }
    };

    if let Some(key) = read()? {
        return Ok(key);
    }

    // add-only: an existing item is never updated, so two first-time
    // creators cannot replace each other's key
    let key = SecretKey::generate();
    let added = SecKeychain::default()
        .map_err(keychain_error)?
        .add_generic_password(KEYCHAIN_SERVICE, account, encode(&key).as_bytes());
    match added {
        Ok(()) => Ok(key),
        Err(error) if error.code() == KEYCHAIN_DUPLICATE => read()?.ok_or_else(|| {
            IdentityError::Keychain("the item vanished after a duplicate error".into())
        }),
        Err(error) => Err(keychain_error(error)),
    }
}

#[cfg(not(target_os = "macos"))]
fn from_keychain(_role: Role) -> Result<SecretKey, IdentityError> {
    Err(IdentityError::NoKeychain)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::{IdentityError, Role, load_or_create};

    #[test]
    fn an_existing_key_file_is_read_only_when_private() -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            std::env::temp_dir().join(format!("codemode-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory)?;
        let path = directory.join("companion.key");
        load_or_create(Role::Companion, Some(&path))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;

        let loaded = load_or_create(Role::Companion, Some(&path));
        assert!(
            matches!(loaded, Err(IdentityError::Permissions(_))),
            "{loaded:?}"
        );

        // an existing key loads from a directory this process cannot write
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let created = load_or_create(Role::Companion, Some(&path))?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))?;
        let loaded = load_or_create(Role::Companion, Some(&path));
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        assert_eq!(loaded?.public(), created.public());

        std::fs::remove_dir_all(&directory)?;

        Ok(())
    }
}
