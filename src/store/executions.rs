//! Executions that outlive the process: the row written when a script
//! starts, its outcome when it ends, and what a restart makes of the rest

use turso::params;

use super::{Store, StoreError, now_ms};
use crate::{
    durable::Durable,
    usage::{Caller, EXEC_CLIENT, ExecutionRecord, Outcome},
};

/// `outcome` of an execution that has not finished
pub const RUNNING: &str = "running";

/// An execution still marked `running`
#[derive(Debug, Clone)]
pub struct UnsettledExecution {
    /// Execution id
    pub id: String,
    /// When it started, ms since the epoch
    pub started_ms: i64,
    /// Whether it used a sensitive server
    pub sensitive: bool,
    /// Whether it is a one-off `exec` run of the CLI
    pub exec: bool,
    /// Process that started it; `None` for rows from before it was recorded
    pub owner_pid: Option<i64>,
}

/// What the database holds about one execution
#[derive(Debug, Clone)]
pub struct StoredExecution {
    /// `running`, `interrupted` or an [`Outcome`] name
    pub outcome: String,
    /// When it ended (its start while running), ms since the epoch
    pub finished_ms: i64,
    /// Serialized outcome; `None` when the TTL passed or it was withheld
    pub result: Option<String>,
    /// Whether the payload was withheld because the script used a sensitive
    /// server
    pub sensitive: bool,
}

impl Store {
    /// Records that an execution started; it stays `running` until
    /// [`Store::finish_execution`] or a restart settles it
    pub fn begin_execution(
        &self,
        id: &str,
        started_ms: i64,
        caller: &Caller,
        script: &str,
    ) -> Result<(), StoreError> {
        self.connection().execute(
            "INSERT OR IGNORE INTO executions (id, started_ms, finished_ms, session, \
             client_name, script, outcome, duration_ms, result_bytes, owner_pid) \
             VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7)",
            params![
                id,
                started_ms,
                caller.session_label(),
                caller.client_name.as_deref(),
                script,
                RUNNING,
                i64::from(std::process::id())
            ],
        )?;

        Ok(())
    }

    /// Stores how an execution ended, with its serialized outcome unless the
    /// execution used a sensitive server
    ///
    /// A row that already ended (`interrupted` by a drain, or finished by
    /// another process) is left as it is: the first terminal outcome wins.
    /// An execution whose start was never recorded gets its row here
    pub fn finish_execution(
        &self,
        record: &ExecutionRecord,
        result: &Durable<String>,
    ) -> Result<(), StoreError> {
        let duration = record.duration.as_millis().min(i64::MAX as u128) as i64;
        self.connection().transaction(|transaction| {
            let changed = transaction.execute(
                "UPDATE executions SET finished_ms = ?1, outcome = ?2, detail = ?3, \
                 fingerprint = ?4, duration_ms = ?5, result_bytes = ?6, result = ?7, \
                 sensitive = ?8 WHERE id = ?9 AND outcome = ?10",
                params![
                    record.started_ms + duration,
                    record.classification.outcome.as_str(),
                    record.classification.detail.as_deref(),
                    record.classification.fingerprint(),
                    duration,
                    record.result_bytes as i64,
                    result.payload().map(String::as_str),
                    i64::from(result.withheld()),
                    record.id.as_str(),
                    RUNNING,
                ],
            )?;
            if changed == 0 {
                transaction.execute(
                    "INSERT OR IGNORE INTO executions (id, started_ms, finished_ms, session, \
                     client_name, script, outcome, detail, fingerprint, duration_ms, \
                     result_bytes, result, sensitive) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        record.id.as_str(),
                        record.started_ms,
                        record.started_ms + duration,
                        record.caller.session_label(),
                        record.caller.client_name.as_deref(),
                        record.script.as_str(),
                        record.classification.outcome.as_str(),
                        record.classification.detail.as_deref(),
                        record.classification.fingerprint(),
                        duration,
                        record.result_bytes as i64,
                        result.payload().map(String::as_str),
                        i64::from(result.withheld()),
                    ],
                )?;
            }
            // a finished execution has nothing left to resume
            transaction.execute(
                "DELETE FROM parked WHERE execution_id = ?1",
                params![record.id.as_str()],
            )?;

            Ok(())
        })
    }

    /// Ends a running execution as `interrupted`, returning whether it was
    /// still running
    pub fn interrupt_execution(&self, id: &str, sensitive: bool) -> Result<bool, StoreError> {
        let now = now_ms();
        let reason = if sensitive {
            crate::executor::InterruptReason::SensitiveNotKept
        } else {
            crate::executor::InterruptReason::Restarted
        };
        let changed = self.connection().execute(
            "UPDATE executions SET outcome = ?1, detail = ?2, fingerprint = NULL, \
             finished_ms = ?3, duration_ms = ?3 - started_ms, sensitive = ?4 \
             WHERE id = ?5 AND outcome = ?6",
            params![
                Outcome::Interrupted.as_str(),
                reason.detail(),
                now,
                i64::from(sensitive),
                id,
                RUNNING
            ],
        )?;

        self.connection()
            .execute("DELETE FROM parked WHERE execution_id = ?1", params![id])?;

        Ok(changed > 0)
    }

    /// Executions marked `running`, which a restarting daemon must settle
    /// unless a live process of another owner still runs them
    pub fn unsettled_executions(&self) -> Result<Vec<UnsettledExecution>, StoreError> {
        Ok(self.connection().query_map(
            "SELECT id, started_ms, sensitive, COALESCE(client_name, '') = ?2, owner_pid \
             FROM executions WHERE outcome = ?1",
            params![RUNNING, EXEC_CLIENT],
            |row| {
                Ok(UnsettledExecution {
                    id: row.get(0)?,
                    started_ms: row.get(1)?,
                    sensitive: row.get::<Option<i64>>(2)?.is_some_and(|flag| flag != 0),
                    exec: row.get::<i64>(3)? != 0,
                    owner_pid: row.get(4)?,
                })
            },
        )?)
    }

    /// Notes that a running execution used a sensitive server, so a restart
    /// reports it as not kept instead of as a plain interruption
    pub fn flag_sensitive_execution(&self, id: &str) -> Result<(), StoreError> {
        self.connection().execute(
            "UPDATE executions SET sensitive = 1 WHERE id = ?1 AND outcome = ?2",
            params![id, RUNNING],
        )?;

        Ok(())
    }

    /// One execution's stored outcome
    pub fn stored_execution(&self, id: &str) -> Result<Option<StoredExecution>, StoreError> {
        Ok(self.connection().query_optional(
            "SELECT outcome, finished_ms, result, sensitive FROM executions WHERE id = ?1",
            params![id],
            |row| {
                Ok(StoredExecution {
                    outcome: row.get(0)?,
                    finished_ms: row.get(1)?,
                    result: row.get(2)?,
                    sensitive: row.get::<Option<i64>>(3)?.is_some_and(|flag| flag != 0),
                })
            },
        )?)
    }

    /// Server, tool and outcome of the upstream calls an execution made, in
    /// the order they were logged
    pub fn upstream_calls_of(&self, id: &str) -> Result<Vec<(String, String, String)>, StoreError> {
        Ok(self.connection().query_map(
            "SELECT server, tool, outcome FROM upstream_calls WHERE execution_id = ?1 \
             ORDER BY id",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?)
    }

    /// Drops the result payload of executions that ended before `cutoff_ms`
    /// and then the oldest ones until the rest fit in `max_bytes`; the audit
    /// rows stay
    pub fn purge_results(&self, cutoff_ms: i64, max_bytes: usize) -> Result<(), StoreError> {
        self.connection().transaction(|transaction| {
            transaction.execute(
                "UPDATE executions SET result = NULL WHERE result IS NOT NULL AND finished_ms < ?1",
                params![cutoff_ms],
            )?;
            let mut total: i64 = transaction.query_row(
                "SELECT COALESCE(SUM(LENGTH(result)), 0) FROM executions WHERE result IS NOT NULL",
                (),
                |row| row.get(0),
            )?;
            if total <= max_bytes as i64 {
                return Ok(());
            }

            let oldest: Vec<(String, i64)> = transaction.query_map(
                "SELECT id, LENGTH(result) FROM executions WHERE result IS NOT NULL \
                 ORDER BY finished_ms",
                (),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            for (id, bytes) in oldest {
                if total <= max_bytes as i64 {
                    break;
                }
                transaction.execute(
                    "UPDATE executions SET result = NULL WHERE id = ?1",
                    params![id],
                )?;
                total -= bytes;
            }

            Ok(())
        })
    }
}
