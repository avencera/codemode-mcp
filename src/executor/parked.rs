//! Executions that wait for an approval across a restart
//!
//! While a script waits only on approvals its session is dumped and its
//! worker freed ([`Driver::park`]). The dump and everything needed to
//! rebuild the driver are written to the database at that point, so a daemon
//! that restarts finds the execution again, re-attaches its approvals and
//! restores it onto a fresh worker once a verdict arrives
//!
//! Tool calls the script makes after it resumes resolve against the live
//! catalog: the snapshot it started with does not survive a restart

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use monty_pool::{OnPrint, PoolError, on_print_sync};
use monty_types::MontyObject;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use super::{Driver, Executor, Failure, Finished, Gated, OutputSink, Parked};
use crate::{
    approvals::{Approvals, Verdict, WITHDRAWN, Waiting},
    budget::Budget,
    durable::{Durable, Sensitivity},
    gateway::{CallContext, Gateway, PreparedCall},
    snapshot::Sealed,
    store::{now_ms, parked::ParkedPayload},
    usage::Caller,
};

/// How long a resumed execution waits for the upstreams to settle before it
/// acts on a verdict
const READY_WAIT: Duration = Duration::from_secs(30);

/// A call waiting for a decision when the session was dumped
#[derive(Serialize, Deserialize)]
struct StoredGate {
    call_id: u32,
    call: PreparedCall,
    approval_id: String,
}

/// What a driver needs, besides the session dump, to carry on after a restart
#[derive(Serialize, Deserialize)]
pub struct ParkedState {
    /// Stubs the session was type-checked with
    stubs: String,
    /// Who started the execution
    caller: Caller,
    /// The script, shown on approval pages
    script: String,
    /// Wall-clock allowance already used
    spent_ms: u64,
    /// Sleep allowance already used
    slept_ms: u64,
    /// Output printed so far
    output: String,
    /// Errors handed to the script so far
    failures: Vec<Failure>,
    /// Call ids the dumped session was waiting on
    pending: Vec<u32>,
    /// The approval-gated calls among them
    gated: Vec<StoredGate>,
}

impl ParkedState {
    /// Who started the execution
    pub fn caller(&self) -> &Caller {
        &self.caller
    }

    /// The script
    pub fn script(&self) -> &str {
        &self.script
    }

    /// Puts the approvals the execution waits on back in play
    ///
    /// Done at boot, before anything asks which stored requests nobody
    /// restored, and apart from [`Executor::resume`], which may wait for the
    /// upstreams
    pub fn reattach(mut self, approvals: &Arc<Approvals>) -> Reattached {
        let waits = std::mem::take(&mut self.gated)
            .into_iter()
            .map(|stored| {
                let waiting = approvals.reattach(&stored.approval_id);

                (stored, waiting)
            })
            .collect();

        Reattached { state: self, waits }
    }

    /// Reads the state back from its stored form
    pub fn parse(state: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(state)
    }
}

/// A [`ParkedState`] whose approvals are waiting again
pub struct Reattached {
    state: ParkedState,
    waits: Vec<(StoredGate, Option<Waiting>)>,
}

impl Driver<'_> {
    /// Notes that the execution holds data of a sensitive server, which keeps
    /// it and its approval requests out of the database from now on
    pub(super) fn mark_sensitive(&mut self) {
        if self.sensitive_used {
            return;
        }
        self.sensitive_used = true;

        let id = &self.context.execution_id;
        if !self.executor.frozen.load(Ordering::SeqCst)
            && let Err(error) = self.executor.store.flag_sensitive_execution(id)
        {
            tracing::warn!(%error, "could not flag a sensitive execution");
        }
        self.gateway.approvals().withhold_execution(id);
    }

    /// Writes the parked session to the database, unless the execution holds
    /// sensitive data, in which case only the fact that it is parked is kept
    pub(super) fn persist_parked(&self, sealed: &Sealed) {
        if self.executor.frozen.load(Ordering::SeqCst) {
            return;
        }
        let sensitivity = Sensitivity::of(
            self.sensitive_used || self.gated.values().any(|gated| gated.call.sensitive),
        );
        let payload = Durable::gate(sensitivity, || {
            let (dump, tag) = sealed.parts();
            let state = ParkedState {
                stubs: self.stubs.clone(),
                caller: self.context.caller.clone(),
                script: self.context.script.to_string(),
                spent_ms: millis(self.context.budget.spent()),
                slept_ms: millis(self.slept),
                output: self.output.peek(),
                failures: self.failures.clone(),
                pending: self.gated.keys().copied().collect(),
                gated: self
                    .gated
                    .iter()
                    .map(|(call_id, gated)| StoredGate {
                        call_id: *call_id,
                        call: gated.call.clone(),
                        approval_id: gated.approval_id.clone(),
                    })
                    .collect(),
            };

            ParkedPayload {
                state: serde_json::to_string(&state).unwrap_or_else(|error| {
                    // an unreadable row is settled as interrupted at boot
                    tracing::warn!(%error, "could not serialize a parked execution");

                    String::new()
                }),
                dump: dump.to_vec(),
                tag: tag.to_vec(),
            }
        });

        let id = &self.context.execution_id;
        let store = &self.executor.store;
        if sensitivity.is_sensitive()
            && let Err(error) = store.flag_sensitive_execution(id)
        {
            tracing::warn!(%error, "could not flag a sensitive execution");
        }
        if let Err(error) = store.put_parked(id, now_ms(), &payload) {
            tracing::warn!(%error, "could not store a parked execution");
        }
    }

    /// Removes the stored copy of a session that is running again; false when
    /// the execution must not carry on
    ///
    /// Removing the row is the claim on the restored session. A resumed
    /// execution that finds the row already gone lost the claim to another
    /// process, which will act on the verdict; a frozen executor is being torn
    /// down and must not start any call either
    pub(super) fn forget_parked(&self) -> bool {
        self.parked_flag.store(false, Ordering::SeqCst);
        if self.executor.frozen.load(Ordering::SeqCst) {
            return false;
        }

        match self
            .executor
            .store
            .delete_parked(&self.context.execution_id)
        {
            Ok(removed) => removed || !self.resumed,
            Err(error) => {
                tracing::warn!(%error, "could not remove a resumed execution's parked row");

                true
            }
        }
    }

    /// Carries on a restored execution: waits for a verdict, restores the
    /// session and runs the script to its end
    async fn resume(&mut self) -> Result<MontyObject, PoolError> {
        let sink = self.output.clone();
        let mut print = on_print_sync(move |_, text| sink.push(text));
        let print: OnPrint<'_> = &mut print;

        let finished = self.next_finished(&mut *print).await?;
        let event = self
            .session()?
            .resume_futures(finished, &mut *print)
            .await?;

        self.drive(event, print).await
    }
}

impl Executor {
    /// Resumes an execution parked before a restart
    ///
    /// Its approvals are re-attached; the session is restored on a fresh
    /// worker when a verdict arrives. `parked` tells the registry whether the
    /// session is waiting
    pub async fn resume(
        &self,
        gateway: &Arc<Gateway>,
        execution_id: &str,
        reattached: Reattached,
        sealed: Sealed,
        parked: Arc<AtomicBool>,
    ) -> Finished {
        let Reattached { state, waits } = reattached;
        let ParkedState {
            stubs,
            caller,
            script,
            spent_ms,
            slept_ms,
            output,
            failures,
            pending,
            gated: _,
        } = state;

        // parked from the start, so a drain during the wait for the upstreams
        // leaves the execution (and its row) for the next boot
        parked.store(true, Ordering::SeqCst);

        // calls after the resume resolve in the live catalog, which needs the
        // upstreams back first
        gateway.wait_ready(READY_WAIT).await;

        let budget = Budget::resumed(
            self.limits.execution_timeout(),
            Duration::from_millis(spent_ms),
        );
        let sink = OutputSink::resumed(self.limits.max_output_bytes, output);

        let mut driver = Driver {
            executor: self,
            gateway: Arc::clone(gateway),
            stubs,
            context: CallContext {
                execution_id: Arc::from(execution_id),
                catalog: gateway.catalog(),
                budget: budget.clone(),
                caller,
                script: Arc::from(script),
            },
            session: None,
            permit: None,
            parked: Some(Parked { sealed, pending }),
            parked_flag: parked,
            running: JoinSet::new(),
            deciding: JoinSet::new(),
            gated: BTreeMap::new(),
            output: sink.clone(),
            slept: Duration::from_millis(slept_ms),
            max_sleep: Duration::from_secs(self.limits.max_total_sleep_secs),
            failures,
            sensitive_used: false,
            resumed: true,
        };
        for (stored, waiting) in waits {
            driver.gated.insert(
                stored.call_id,
                Gated {
                    call: stored.call.clone(),
                    approval_id: stored.approval_id,
                },
            );
            driver.deciding.spawn(async move {
                let verdict = match waiting {
                    Some(waiting) => waiting.decision().await,
                    None => Verdict::Denied {
                        reason: WITHDRAWN.to_owned(),
                    },
                };

                (stored.call_id, verdict, stored.call)
            });
        }

        let finished = tokio::select! {
            result = driver.resume() => Some(result),
            () = budget.expired() => None,
        };

        self.conclude(driver, finished, &sink).await
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
