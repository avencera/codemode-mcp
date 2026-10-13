//! SQLite-format state, kept with turso: usage records, approvals,
//! enrolled passkeys and OAuth logins

pub mod schema;
pub mod sessions;
pub mod sql;

use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use turso::params;

use self::sql::Connection;

/// File name of the database inside the state directory
pub const DATABASE_FILE: &str = "codemode.sqlite";
/// How long a writer waits on a locked database before failing
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Failures reading or writing the database
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database reported an error
    #[error("database error: {0}")]
    Database(#[from] turso::Error),
    /// The state directory could not be created
    #[error("failed to prepare state directory {path}: {source}")]
    Directory {
        /// Directory that failed
        path: PathBuf,
        /// Underlying error
        source: std::io::Error,
    },
    /// A newer build created this database
    #[error("database schema version {0} is newer than this build supports")]
    SchemaTooNew(i64),
    /// A stored value could not be decoded
    #[error("corrupt stored value: {0}")]
    Corrupt(String),
}

/// Milliseconds since the Unix epoch
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

/// Creates the state directory, readable by the owner only
pub fn prepare_state_dir(directory: &Path) -> Result<(), StoreError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|source| StoreError::Directory {
            path: directory.to_owned(),
            source,
        })
}

/// Opens (creating and migrating if needed) the database in `directory`
pub fn open(directory: &Path) -> Result<Connection, StoreError> {
    prepare_state_dir(directory)?;
    let path = directory.join(DATABASE_FILE);
    // turso always journals to a WAL, so there is no journal mode to set
    let connection = Connection::open(&path, false, BUSY_TIMEOUT)?;
    // the database holds scripts and passkeys, so only the owner may read
    // it; unlike SQLite, turso creates the WAL and its coordination file
    // with the default mode rather than the database's
    for suffix in ["", "-wal", "-tshm"] {
        let mut file = path.clone().into_os_string();
        file.push(suffix);
        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
    }
    connection.execute_batch("PRAGMA foreign_keys = ON")?;
    connection.transaction(schema::migrate)?;

    Ok(connection)
}

/// Opens an existing database without creating or migrating it; for
/// report pages. Inside a process that already has the database open,
/// turso hands back that writable instance, so read-only is a promise of
/// the callers rather than of the open
pub fn open_read_only(directory: &Path) -> Result<Connection, StoreError> {
    Ok(Connection::open(
        &directory.join(DATABASE_FILE),
        true,
        BUSY_TIMEOUT,
    )?)
}

/// One enrolled passkey as listed to the owner
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PasskeyRecord {
    /// Row id, used by `passkey remove`
    pub id: i64,
    /// Name given at enrollment
    pub label: String,
    /// Enrollment time, ms since the epoch
    pub created_ms: i64,
    /// Last successful approval, ms since the epoch
    pub last_used_ms: Option<i64>,
}

/// Shared connection for the few synchronous reads and writes the daemon
/// makes outside the usage log (passkeys)
#[derive(Clone)]
pub struct Store(Arc<Mutex<Connection>>);

impl Store {
    /// Opens the database in `directory`
    pub fn open(directory: &Path) -> Result<Self, StoreError> {
        Ok(Self(Arc::new(Mutex::new(open(directory)?))))
    }

    fn connection(&self) -> MutexGuard<'_, Connection> {
        // a poisoned lock only means a panic elsewhere; the connection is fine
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Stores a newly registered passkey and returns its id; with
    /// `only_if_none`, stores nothing and returns `None` when any passkey
    /// already exists
    pub fn add_passkey(
        &self,
        label: &str,
        credential: &str,
        only_if_none: bool,
    ) -> Result<Option<i64>, StoreError> {
        self.connection().transaction(|transaction| {
            if only_if_none {
                let count: i64 =
                    transaction.query_row("SELECT COUNT(*) FROM passkeys", (), |row| row.get(0))?;
                if count > 0 {
                    return Ok(None);
                }
            }
            transaction.execute(
                "INSERT INTO passkeys (label, created_ms, credential) VALUES (?1, ?2, ?3)",
                params![label, now_ms(), credential],
            )?;

            Ok(Some(transaction.last_insert_rowid()))
        })
    }

    /// Every enrolled passkey, oldest first
    pub fn list_passkeys(&self) -> Result<Vec<PasskeyRecord>, StoreError> {
        Ok(self.connection().query_map(
            "SELECT id, label, created_ms, last_used_ms FROM passkeys ORDER BY id",
            (),
            passkey_record,
        )?)
    }

    /// Stored credential JSON of every passkey with its id
    pub fn passkey_credentials(&self) -> Result<Vec<(i64, String)>, StoreError> {
        Ok(self
            .connection()
            .query_map("SELECT id, credential FROM passkeys", (), |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?)
    }

    /// Number of enrolled passkeys
    pub fn passkey_count(&self) -> Result<usize, StoreError> {
        let count: i64 =
            self.connection()
                .query_row("SELECT COUNT(*) FROM passkeys", (), |row| row.get(0))?;

        Ok(count.max(0) as usize)
    }

    /// Records a successful use, storing the updated credential (counter)
    pub fn touch_passkey(&self, id: i64, credential: Option<&str>) -> Result<(), StoreError> {
        let connection = self.connection();
        match credential {
            Some(credential) => connection.execute(
                "UPDATE passkeys SET last_used_ms = ?1, credential = ?2 WHERE id = ?3",
                params![now_ms(), credential, id],
            )?,
            None => connection.execute(
                "UPDATE passkeys SET last_used_ms = ?1 WHERE id = ?2",
                params![now_ms(), id],
            )?,
        };

        Ok(())
    }

    /// Deletes the passkey with this id and enrollment time, returning
    /// whether it existed; the time guards against a reused row id
    pub fn remove_passkey(&self, id: i64, created_ms: i64) -> Result<bool, StoreError> {
        let removed = self.connection().execute(
            "DELETE FROM passkeys WHERE id = ?1 AND created_ms = ?2",
            params![id, created_ms],
        )?;

        Ok(removed > 0)
    }

    /// Client registration and credentials JSON of a server's OAuth login
    pub fn oauth_login(&self, server: &str) -> Result<Option<(String, String)>, StoreError> {
        Ok(self.connection().query_optional(
            "SELECT client, credentials FROM oauth_logins WHERE server = ?1",
            params![server],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    }

    /// Stores a completed login and forgets the server's flows in progress
    pub fn save_oauth_login(
        &self,
        server: &str,
        client: &str,
        credentials: &str,
    ) -> Result<(), StoreError> {
        self.connection().transaction(|transaction| {
            transaction.execute(
                "INSERT INTO oauth_logins (server, client, credentials, updated_ms) \
                     VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT (server) DO UPDATE SET client = ?2, credentials = ?3, \
                     updated_ms = ?4",
                params![server, client, credentials, now_ms()],
            )?;
            transaction.execute(
                "DELETE FROM oauth_pending WHERE server = ?1",
                params![server],
            )?;

            Ok(())
        })
    }

    /// Replaces the credentials of an existing login (a refresh); does
    /// nothing when the server was logged out meanwhile
    pub fn update_oauth_credentials(
        &self,
        server: &str,
        credentials: &str,
    ) -> Result<(), StoreError> {
        self.connection().execute(
            "UPDATE oauth_logins SET credentials = ?2, updated_ms = ?3 WHERE server = ?1",
            params![server, credentials, now_ms()],
        )?;

        Ok(())
    }

    /// Deletes a server's login and flows in progress, returning whether a
    /// login existed
    pub fn remove_oauth_login(&self, server: &str) -> Result<bool, StoreError> {
        self.connection().transaction(|transaction| {
            let removed = transaction.execute(
                "DELETE FROM oauth_logins WHERE server = ?1",
                params![server],
            )?;
            transaction.execute(
                "DELETE FROM oauth_pending WHERE server = ?1",
                params![server],
            )?;

            Ok(removed > 0)
        })
    }

    /// Stores the PKCE state of a flow in progress, dropping flows older
    /// than `max_age_ms`
    pub fn save_oauth_pending(
        &self,
        server: &str,
        csrf: &str,
        state: &str,
        max_age_ms: i64,
    ) -> Result<(), StoreError> {
        let connection = self.connection();
        let now = now_ms();
        connection.execute(
            "DELETE FROM oauth_pending WHERE created_ms < ?1",
            params![now - max_age_ms],
        )?;
        connection.execute(
            "INSERT OR REPLACE INTO oauth_pending (csrf, server, state, client, created_ms) \
             VALUES (?1, ?2, ?3, NULL, ?4)",
            params![csrf, server, state, now],
        )?;

        Ok(())
    }

    /// Attaches the client registration to a flow in progress
    pub fn set_oauth_pending_client(
        &self,
        server: &str,
        csrf: &str,
        client: &str,
    ) -> Result<bool, StoreError> {
        let updated = self.connection().execute(
            "UPDATE oauth_pending SET client = ?3 WHERE server = ?1 AND csrf = ?2",
            params![server, csrf, client],
        )?;

        Ok(updated > 0)
    }

    /// PKCE state and client registration of a flow younger than `max_age_ms`
    pub fn oauth_pending(
        &self,
        server: &str,
        csrf: &str,
        max_age_ms: i64,
    ) -> Result<Option<(String, Option<String>)>, StoreError> {
        Ok(self.connection().query_optional(
            "SELECT state, client FROM oauth_pending \
             WHERE server = ?1 AND csrf = ?2 AND created_ms >= ?3",
            params![server, csrf, now_ms() - max_age_ms],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    }

    /// Forgets one flow in progress
    pub fn delete_oauth_pending(&self, server: &str, csrf: &str) -> Result<(), StoreError> {
        self.connection().execute(
            "DELETE FROM oauth_pending WHERE server = ?1 AND csrf = ?2",
            params![server, csrf],
        )?;

        Ok(())
    }

    /// One passkey, if it exists
    pub fn passkey(&self, id: i64) -> Result<Option<PasskeyRecord>, StoreError> {
        Ok(self.connection().query_optional(
            "SELECT id, label, created_ms, last_used_ms FROM passkeys WHERE id = ?1",
            params![id],
            passkey_record,
        )?)
    }
}

fn passkey_record(row: &turso::Row) -> Result<PasskeyRecord, turso::Error> {
    Ok(PasskeyRecord {
        id: row.get(0)?,
        label: row.get(1)?,
        created_ms: row.get(2)?,
        last_used_ms: row.get(3)?,
    })
}
