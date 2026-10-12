//! SQLite state: usage records, approvals and enrolled passkeys

pub mod schema;

use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

/// File name of the database inside the state directory
pub const DATABASE_FILE: &str = "codemode.sqlite";
/// How long a writer waits on a locked database before failing
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Failures reading or writing the database
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite reported an error
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
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
    let mut connection = Connection::open(&path)?;
    // the database holds scripts and passkeys, so only the owner may read it
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    schema::migrate(&transaction)?;
    transaction.commit()?;

    Ok(connection)
}

/// Opens an existing database read-only, without migrating; for report
/// pages that must never contend with the writer
pub fn open_read_only(directory: &Path) -> Result<Connection, StoreError> {
    let connection = Connection::open_with_flags(
        directory.join(DATABASE_FILE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(BUSY_TIMEOUT)?;

    Ok(connection)
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

    /// Stores a newly registered passkey and returns its id
    pub fn add_passkey(&self, label: &str, credential: &str) -> Result<i64, StoreError> {
        let connection = self.connection();
        connection.execute(
            "INSERT INTO passkeys (label, created_ms, credential) VALUES (?1, ?2, ?3)",
            params![label, now_ms(), credential],
        )?;

        Ok(connection.last_insert_rowid())
    }

    /// Every enrolled passkey, oldest first
    pub fn list_passkeys(&self) -> Result<Vec<PasskeyRecord>, StoreError> {
        let connection = self.connection();
        let mut statement = connection
            .prepare("SELECT id, label, created_ms, last_used_ms FROM passkeys ORDER BY id")?;
        let rows = statement.query_map([], |row| {
            Ok(PasskeyRecord {
                id: row.get(0)?,
                label: row.get(1)?,
                created_ms: row.get(2)?,
                last_used_ms: row.get(3)?,
            })
        })?;

        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Stored credential JSON of every passkey with its id
    pub fn passkey_credentials(&self) -> Result<Vec<(i64, String)>, StoreError> {
        let connection = self.connection();
        let mut statement = connection.prepare("SELECT id, credential FROM passkeys")?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;

        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Number of enrolled passkeys
    pub fn passkey_count(&self) -> Result<usize, StoreError> {
        let count: i64 =
            self.connection()
                .query_row("SELECT COUNT(*) FROM passkeys", [], |row| row.get(0))?;

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

    /// Deletes a passkey, returning whether it existed
    pub fn remove_passkey(&self, id: i64) -> Result<bool, StoreError> {
        let removed = self
            .connection()
            .execute("DELETE FROM passkeys WHERE id = ?1", params![id])?;

        Ok(removed > 0)
    }

    /// Label of a passkey, if it exists
    pub fn passkey_label(&self, id: i64) -> Result<Option<String>, StoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT label FROM passkeys WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?)
    }
}
