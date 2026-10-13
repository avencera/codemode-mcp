//! Blocking access to turso
//!
//! turso's default IO reads and writes the file inside `poll`, so its futures
//! finish on the calling thread without a runtime. Blocking on them keeps the
//! store usable from synchronous code and from the usage writer thread

use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::Path,
    thread,
    time::{Duration, Instant},
};

use turso::{Builder, Database, Error, IntoParams, Row};

/// Longest pause between attempts on a locked database
const MAX_BACKOFF: Duration = Duration::from_millis(100);

/// One turso connection with a blocking API
pub struct Connection {
    connection: turso::Connection,
    busy_timeout: Duration,
    // keeps the shared database open for as long as the connection lives
    _database: Database,
}

impl Connection {
    /// Opens `path`, creating it unless `read_only`; statements that find
    /// the database locked retry for up to `busy_timeout`
    ///
    /// Every open uses turso's multiprocess WAL: without it the first process
    /// locks the file exclusively, and the CLI reads the database while the
    /// daemon writes it
    pub fn open(path: &Path, read_only: bool, busy_timeout: Duration) -> Result<Self, Error> {
        let name = path
            .to_str()
            .ok_or_else(|| Error::Misuse(format!("{} is not UTF-8", path.display())))?;
        let database = block_on(
            Builder::new_local(name)
                .read_only(read_only)
                .experimental_multiprocess_wal(true)
                .build(),
        )?;

        // no turso busy handler: it wakes the task right away instead of
        // sleeping, so blocking on it would spin a core; `retry` sleeps
        Ok(Self {
            connection: database.connect()?,
            busy_timeout,
            _database: database,
        })
    }

    /// Runs one statement that returns no rows, returning the rows changed
    pub fn execute(&self, sql: &str, params: impl IntoParams) -> Result<u64, Error> {
        let params = params.into_params()?;

        self.retry(|| block_on(self.connection.execute(sql, params.clone())))
    }

    /// Runs `;`-separated statements without parameters
    pub fn execute_batch(&self, sql: &str) -> Result<(), Error> {
        self.retry(|| block_on(self.connection.execute_batch(sql)))
    }

    /// Maps every row of a query
    pub fn query_map<T>(
        &self,
        sql: &str,
        params: impl IntoParams,
        map: impl FnMut(&Row) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        self.rows(sql, params)?.iter().map(map).collect()
    }

    /// Maps the first row of a query, if there is one
    pub fn query_optional<T>(
        &self,
        sql: &str,
        params: impl IntoParams,
        map: impl FnOnce(&Row) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        self.rows(sql, params)?.first().map(map).transpose()
    }

    /// Maps the first row of a query, failing with
    /// [`Error::QueryReturnedNoRows`] when there is none
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: impl IntoParams,
        map: impl FnOnce(&Row) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.query_optional(sql, params, map)?
            .ok_or(Error::QueryReturnedNoRows)
    }

    /// Row id of the last successful insert on this connection
    pub fn last_insert_rowid(&self) -> i64 {
        self.connection.last_insert_rowid()
    }

    /// Runs `body` in a transaction that holds the write lock from the
    /// start, committing when it succeeds and rolling back when it fails
    /// or panics
    ///
    /// Taking the lock up front means only `BEGIN` can find the database
    /// locked, and a failed `BEGIN` is safe to retry. Rolling back right
    /// away matters: an open transaction keeps the lock from every other
    /// connection and process
    pub fn transaction<T, E: From<Error>>(
        &self,
        body: impl FnOnce(&Self) -> Result<T, E>,
    ) -> Result<T, E> {
        if !self.connection.is_autocommit()? {
            // a rollback that failed earlier left a transaction open
            self.rollback();
        }
        self.execute_batch("BEGIN IMMEDIATE")?;

        let finished = match catch_unwind(AssertUnwindSafe(|| body(self))) {
            Ok(finished) => finished,
            Err(panic) => {
                self.rollback();
                resume_unwind(panic);
            }
        };
        let finished = finished.and_then(|value| {
            self.execute_batch("COMMIT")?;

            Ok(value)
        });
        if finished.is_err() && !matches!(self.connection.is_autocommit(), Ok(true)) {
            self.rollback();
        }

        finished
    }

    fn rollback(&self) {
        if let Err(error) = block_on(self.connection.execute_batch("ROLLBACK")) {
            tracing::warn!(%error, "failed to roll back a transaction");
        }
    }

    /// Every row of a query, read to the end before any is mapped so a
    /// locked read can start over
    fn rows(&self, sql: &str, params: impl IntoParams) -> Result<Vec<Row>, Error> {
        let params = params.into_params()?;

        self.retry(|| {
            block_on(async {
                let mut rows = self.connection.query(sql, params.clone()).await?;
                let mut all = Vec::new();
                while let Some(row) = rows.next().await? {
                    all.push(row);
                }

                Ok(all)
            })
        })
    }

    /// Repeats `attempt` while the database is locked, sleeping between
    /// tries, for up to the busy timeout
    ///
    /// Only statements that took no lock yet are retried: those outside a
    /// transaction and `BEGIN`, since `transaction` locks up front
    fn retry<T>(&self, mut attempt: impl FnMut() -> Result<T, Error>) -> Result<T, Error> {
        let deadline = Instant::now() + self.busy_timeout;
        let mut backoff = Duration::from_millis(1);
        loop {
            match attempt() {
                Err(Error::Busy(_)) if Instant::now() + backoff < deadline => {
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                result => return result,
            }
        }
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    futures_executor::block_on(future)
}

#[cfg(test)]
mod tests {
    use turso::params;

    use super::*;

    // the usage writer and the store both depend on these engine semantics
    #[test]
    fn failures_panics_and_locks_keep_the_database_writable() -> Result<(), Error> {
        let directory =
            std::env::temp_dir().join(format!("codemode-sql-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&directory).map_err(|error| Error::Error(error.to_string()))?;
        let path = directory.join("test.sqlite");
        let first = Connection::open(&path, false, Duration::from_secs(1))?;
        let second = Connection::open(&path, false, Duration::from_secs(1))?;
        first.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY)")?;

        // a duplicate key fails alone; the rows around it still commit
        first.transaction(|transaction| {
            transaction.execute("INSERT INTO items (id) VALUES (?1)", params![1])?;
            assert!(
                transaction
                    .execute("INSERT INTO items (id) VALUES (?1)", params![1])
                    .is_err()
            );
            transaction.execute("INSERT INTO items (id) VALUES (?1)", params![2])
        })?;

        // a failed body rolls back and frees the write lock for others
        let failed: Result<(), Error> = first.transaction(|transaction| {
            transaction.execute("INSERT INTO items (id) VALUES (?1)", params![3])?;

            Err(Error::Error("abandoned".to_owned()))
        });
        assert!(failed.is_err());
        second.execute("INSERT INTO items (id) VALUES (?1)", params![4])?;

        // so does a panicking one
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            first.transaction(|transaction| -> Result<(), Error> {
                transaction.execute("INSERT INTO items (id) VALUES (?1)", params![5])?;
                panic!("body panicked");
            })
        }));
        assert!(panicked.is_err());

        // a writer that finds the lock taken waits for it instead of failing
        thread::scope(|scope| -> Result<(), Error> {
            let (locked, wait) = std::sync::mpsc::channel();
            let holder = scope.spawn(move || {
                first.transaction(|transaction| {
                    transaction.execute("INSERT INTO items (id) VALUES (?1)", params![6])?;
                    let _ = locked.send(());
                    thread::sleep(Duration::from_millis(200));

                    Ok::<_, Error>(())
                })
            });
            let _ = wait.recv();
            second.execute("INSERT INTO items (id) VALUES (?1)", params![7])?;

            holder.join().unwrap_or_else(|panic| resume_unwind(panic))
        })?;

        let ids = second.query_map("SELECT id FROM items ORDER BY id", (), |row| {
            row.get::<i64>(0)
        })?;
        let _ = std::fs::remove_dir_all(&directory);

        assert_eq!(ids, [1, 2, 4, 6, 7]);

        Ok(())
    }
}
