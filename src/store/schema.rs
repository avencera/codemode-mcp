//! Numbered schema migrations tracked in `PRAGMA user_version`

use super::{StoreError, sql::Connection};

/// Version a fully migrated database reports
pub const SCHEMA_VERSION: i64 = 4;

type Migration = fn(&Connection) -> Result<(), turso::Error>;

/// Steps from version `n` to `n + 1`, applied in order; a fresh database
/// runs all of them
const MIGRATIONS: [Migration; 4] = [
    create_tables,
    create_oauth_tables,
    create_sessions,
    add_call_output,
];

const _: () = assert!(MIGRATIONS.len() as i64 == SCHEMA_VERSION);

/// Brings the database up to [`SCHEMA_VERSION`]; runs inside the caller's
/// transaction so a failure leaves the old version in place
pub fn migrate(connection: &Connection) -> Result<(), StoreError> {
    let version: i64 = connection.query_row("PRAGMA user_version", (), |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew(version));
    }

    for (index, migration) in MIGRATIONS.iter().enumerate().skip(version.max(0) as usize) {
        migration(connection)?;
        connection.execute_batch(&format!("PRAGMA user_version = {}", index + 1))?;
    }

    Ok(())
}

/// How each upstream call's result was typed for the script (`schema`,
/// `text` or `untyped`), so the review can rank tools that still return a
/// `JsonValue` without knowing the catalog
fn add_call_output(connection: &Connection) -> Result<(), turso::Error> {
    connection.execute_batch("ALTER TABLE upstream_calls ADD COLUMN output TEXT;")
}

/// App sessions issued by the server. Only the SHA-256 of a token is kept,
/// because the token is a bearer secret for approval grants. `session_state`
/// on `calls` records how each call got its session (`reused`, `minted`,
/// or `reminted` when the client already had a recent one), for the
/// session-reuse numbers
fn create_sessions(connection: &Connection) -> Result<(), turso::Error> {
    connection.execute_batch(
        r#"
        CREATE TABLE sessions (
            hash TEXT PRIMARY KEY,
            client TEXT,
            created_ms INTEGER NOT NULL,
            last_seen_ms INTEGER NOT NULL
        );
        CREATE INDEX sessions_client ON sessions (client, last_seen_ms);

        ALTER TABLE calls ADD COLUMN session_state TEXT;
        "#,
    )
}

/// OAuth logins of remote upstreams: the client registration and the
/// tokens are written together when a login completes, so an abandoned
/// flow never replaces a working login. Flows in progress live in
/// `oauth_pending`, keyed by their CSRF state
fn create_oauth_tables(connection: &Connection) -> Result<(), turso::Error> {
    connection.execute_batch(
        r#"
        CREATE TABLE oauth_logins (
            server TEXT PRIMARY KEY,
            client TEXT NOT NULL,
            credentials TEXT NOT NULL,
            updated_ms INTEGER NOT NULL
        );

        CREATE TABLE oauth_pending (
            csrf TEXT PRIMARY KEY,
            server TEXT NOT NULL,
            state TEXT NOT NULL,
            client TEXT,
            created_ms INTEGER NOT NULL
        );
        "#,
    )
}

fn create_tables(connection: &Connection) -> Result<(), turso::Error> {
    connection.execute_batch(
        r#"
        CREATE TABLE calls (
            id INTEGER PRIMARY KEY,
            at_ms INTEGER NOT NULL,
            session TEXT,
            client_name TEXT,
            client_version TEXT,
            tool TEXT NOT NULL,
            input TEXT,
            outcome TEXT NOT NULL,
            detail TEXT,
            fingerprint TEXT,
            duration_ms INTEGER NOT NULL,
            result_bytes INTEGER NOT NULL,
            execution_id TEXT
        );
        CREATE INDEX calls_at ON calls (at_ms);
        CREATE INDEX calls_session ON calls (session, at_ms);

        CREATE TABLE executions (
            id TEXT PRIMARY KEY,
            started_ms INTEGER NOT NULL,
            finished_ms INTEGER NOT NULL,
            session TEXT,
            client_name TEXT,
            script TEXT NOT NULL,
            outcome TEXT NOT NULL,
            detail TEXT,
            fingerprint TEXT,
            duration_ms INTEGER NOT NULL,
            result_bytes INTEGER NOT NULL
        );
        CREATE INDEX executions_started ON executions (started_ms);
        CREATE INDEX executions_session ON executions (session, started_ms);

        CREATE TABLE upstream_calls (
            id INTEGER PRIMARY KEY,
            at_ms INTEGER NOT NULL,
            execution_id TEXT,
            server TEXT NOT NULL,
            tool TEXT NOT NULL,
            function TEXT NOT NULL,
            arguments TEXT,
            outcome TEXT NOT NULL,
            detail TEXT,
            duration_ms INTEGER NOT NULL,
            approval_id TEXT
        );
        CREATE INDEX upstream_calls_at ON upstream_calls (at_ms);
        CREATE INDEX upstream_calls_execution ON upstream_calls (execution_id);

        CREATE TABLE approvals (
            id TEXT PRIMARY KEY,
            created_ms INTEGER NOT NULL,
            decided_ms INTEGER,
            session TEXT,
            client_name TEXT,
            execution_id TEXT,
            server TEXT NOT NULL,
            tool TEXT NOT NULL,
            grant_mode TEXT NOT NULL,
            decision TEXT,
            grant_minutes INTEGER
        );
        CREATE INDEX approvals_created ON approvals (created_ms);

        CREATE TABLE passkeys (
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            created_ms INTEGER NOT NULL,
            last_used_ms INTEGER,
            credential TEXT NOT NULL
        );
        "#,
    )
}
