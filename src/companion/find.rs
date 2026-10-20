//! Items a program on the gateway Mac looks for, through `codemode-mcp op
//! find` and the `secrets` builtin's `find_references`, approved on a Mac
//!
//! A find answers references, labels and types, never a value, so a
//! program that does not know an item can then read the one it wants with
//! its own approval. It is asked like a program read: this Mac first while
//! the owner is there, the companion Macs [`PHONE_GRACE`] later or at once,
//! and a Deny takes only its own Mac out. Phones are not asked, since the
//! app cannot search 1Password
//!
//! Finds with the same reason that arrive within [`FIND_BATCH_WINDOW`] of
//! the first are asked as one, up to [`MAX_FIND_QUERIES`], so the searches a
//! script starts together under `asyncio.gather` need one approval

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use companion_wire::wire::{
    CompanionFindRequest, CompanionFindResponse, FindQuery, Found, MAX_FIND_QUERIES,
};
use tokio::{
    sync::{oneshot, watch},
    task::JoinSet,
};

use super::{
    ASK_TIMEOUT, CompanionErrorCode, CompanionFailure, Companions, MALFORMED_REQUEST,
    ProgramReadError,
    program::{Miss, checked_query, clean_reason, first_answer},
};
use crate::{
    config::CompanionPeer,
    mac::TouchId,
    prompt,
    secrets::{OnePassword, PHONE_GRACE},
};

/// Cancel button of the gateway Mac's own prompt
const CANCEL_TITLE: &str = "Deny";

/// How long the first find of a batch waits for others before anyone is
/// asked; the calls a script makes together arrive within a few
/// milliseconds
const FIND_BATCH_WINDOW: Duration = Duration::from_millis(250);

/// What a program looks for, as the admin route and the `secrets` builtin
/// server pass it on
#[derive(Debug, Clone, Default)]
pub struct FindAsk {
    /// Words to look for in item titles, vaults, tags and categories
    pub query: String,
    /// Why, shown quoted as the program's claim
    pub reason: Option<String>,
}

/// The items a find matched and the Mac that searched
#[derive(Debug)]
pub struct ProgramFound {
    /// `this Mac`, or the name of the companion that answered
    pub source: String,
    /// The items, best first
    pub found: Found,
}

/// The finds waiting to be asked together, by their cleaned reason
///
/// Keying by reason keeps one script's searches together without letting an
/// unrelated program's find ride on the same approval or fall with its Deny
#[derive(Default)]
pub struct FindBatches(Mutex<HashMap<Option<String>, Arc<Forming>>>);

/// One batch still taking finds; it leaves the map when it is asked or full
#[derive(Default)]
struct Forming(Mutex<Vec<Waiting>>);

/// One find of a batch and where its answer goes
struct Waiting {
    query: String,
    answer: oneshot::Sender<Result<ProgramFound, ProgramReadError>>,
}

impl FindBatches {
    fn forming(&self) -> MutexGuard<'_, HashMap<Option<String>, Arc<Forming>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Forming {
    fn waiting(&self) -> MutexGuard<'_, Vec<Waiting>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl OnePassword {
    /// Searches 1Password for `ask.query` on behalf of a program, with its
    /// reason shown in every prompt; see the module docs for who is asked
    /// and which finds share a prompt
    pub async fn find_for_program(&self, ask: &FindAsk) -> Result<ProgramFound, ProgramReadError> {
        let query = checked_query(&ask.query).map_err(ProgramReadError::Invalid)?;
        let reason = clean_reason(ask.reason.as_deref());
        let (answer, answered) = oneshot::channel();
        let waiting = Waiting { query, answer };

        let opened = {
            // one lock, so a batch cannot be taken for asking between the
            // check and the push
            let mut forming = self.find_batches().forming();
            match forming.get(&reason).cloned() {
                Some(batch) => {
                    let mut queued = batch.waiting();
                    queued.push(waiting);
                    if queued.len() >= MAX_FIND_QUERIES {
                        forming.remove(&reason);
                    }

                    None
                }
                None => {
                    let batch = Arc::new(Forming(Mutex::new(vec![waiting])));
                    forming.insert(reason.clone(), Arc::clone(&batch));

                    Some(batch)
                }
            }
        };
        // the batch is asked on its own task, so a caller that gives up
        // cannot strand the others that joined it
        if let Some(batch) = opened {
            let onepassword = self.clone();
            tokio::spawn(async move { onepassword.ask_batch(&batch, reason).await });
        }

        answered.await.unwrap_or_else(|_| {
            Err(ProgramReadError::Failed(
                "the find ended before it was answered".to_owned(),
            ))
        })
    }

    /// Waits out the window, then asks once for every find that joined
    /// `batch` and hands each its own items
    async fn ask_batch(&self, batch: &Arc<Forming>, reason: Option<String>) {
        tokio::time::sleep(FIND_BATCH_WINDOW).await;
        let mut waiting = {
            let mut forming = self.find_batches().forming();
            // a full batch already left the map, and a newer one may hold
            // its place
            if forming
                .get(&reason)
                .is_some_and(|current| Arc::ptr_eq(current, batch))
            {
                forming.remove(&reason);
            }

            std::mem::take(&mut *batch.waiting())
        };

        // gathered calls arrive in no set order, so the prompt lists them
        // sorted, and the same words twice are searched once
        let mut queries: Vec<String> = waiting.iter().map(|find| find.query.clone()).collect();
        queries.sort();
        queries.dedup();
        // every caller giving up takes the prompts down, as a lone find's did
        let all_gone = async {
            for find in &mut waiting {
                find.answer.closed().await;
            }
        };
        let answer = tokio::select! {
            answer = self.find_each(&queries, reason.as_deref()) => answer,
            () = all_gone => return,
        };

        for find in waiting {
            let own = match &answer {
                Ok((source, found)) => queries
                    .iter()
                    .position(|query| *query == find.query)
                    .and_then(|index| found.get(index))
                    .map(|found| ProgramFound {
                        source: source.clone(),
                        found: found.clone(),
                    })
                    .ok_or_else(|| ProgramReadError::Failed("the search was not answered".into())),
                Err(error) => Err(error.clone()),
            };
            let _ = find.answer.send(own);
        }
    }

    /// Asks every device that can search for all of `queries` at once,
    /// answering the first Mac's items for each, in order
    async fn find_each(
        &self,
        queries: &[String],
        reason: Option<&str>,
    ) -> Result<(String, Vec<Found>), ProgramReadError> {
        let companions = self.companions().cloned();
        let local = match self.on_mac() {
            Some(on_mac) => {
                on_mac.config.touch_id && on_mac.mac.present(on_mac.config.idle()).await
            }
            None => false,
        };
        let peers = companions
            .as_ref()
            .map(|companions| companions.peers())
            .unwrap_or_default();
        if !local && peers.is_empty() {
            return Err(ProgramReadError::Failed(
                "nobody can approve this: the owner is away from this Mac and no companion Mac is \
                 paired; a phone cannot search 1Password"
                    .to_owned(),
            ));
        }

        let mut sources: JoinSet<(String, Result<Vec<Found>, Miss>)> = JoinSet::new();
        // set once this Mac has failed, so the companions need not sit out
        // the rest of the grace
        let (local_failed, grace_over) = watch::channel(!local);
        let local_failed = Arc::new(local_failed);
        if local {
            let local_failed = Arc::clone(&local_failed);
            let onepassword = self.clone();
            let queries = queries.to_vec();
            let reason = reason.map(str::to_owned);
            sources.spawn(async move {
                let found = onepassword
                    .find_here_each(&queries, reason.as_deref())
                    .await;
                if found.is_err() {
                    local_failed.send_replace(true);
                }

                ("this Mac".to_owned(), found)
            });
        }
        let grace = if local { PHONE_GRACE } else { Duration::ZERO };
        if let Some(companions) = &companions {
            for peer in peers {
                let companions = Arc::clone(companions);
                let request = FindQuery {
                    query: queries[0].clone(),
                    also: queries[1..].to_vec(),
                    reason: reason.map(str::to_owned),
                };
                let mut grace_over = grace_over.clone();
                sources.spawn(async move {
                    let _ =
                        tokio::time::timeout(grace, grace_over.wait_for(|failed| *failed)).await;
                    let found = companions
                        .find_mac(&peer, request)
                        .await
                        .map_err(|failure| Miss::from_failure(&peer.name, failure));

                    (peer.name, found)
                });
            }
        }

        // dropping the set on any exit takes the other prompts down
        first_answer(&mut sources, ASK_TIMEOUT + grace, "find").await
    }

    /// Asks on this Mac: its own Touch ID prompt naming the query, then the
    /// local `op`
    pub(super) async fn find_here(&self, query: &str, reason: Option<&str>) -> Result<Found, Miss> {
        let mut found = self.find_here_each(&[query.to_owned()], reason).await?;

        Ok(found.pop().unwrap_or_default())
    }

    /// Asks on this Mac with one Touch ID prompt naming every query, then
    /// searches for each with the local `op`
    async fn find_here_each(
        &self,
        queries: &[String],
        reason: Option<&str>,
    ) -> Result<Vec<Found>, Miss> {
        let Some(on_mac) = self.on_mac() else {
            return Err(Miss::Failed("this Mac: no Touch ID".to_owned()));
        };
        let text = prompt::find_prompt_text(queries, "this Mac", reason);
        match on_mac.mac.touch_id(&text, CANCEL_TITLE).await {
            TouchId::Approved => {}
            TouchId::Review => return Err(Miss::Denied("this Mac: not approved".to_owned())),
            TouchId::Away => {
                return Err(Miss::Failed(
                    "this Mac: the prompt was taken down, the owner seems away".to_owned(),
                ));
            }
            TouchId::Unavailable => {
                return Err(Miss::Failed("this Mac: Touch ID is unavailable".to_owned()));
            }
        }

        self.find_local_each(queries)
            .await
            .map_err(|error| Miss::Failed(format!("this Mac: {error}")))
    }
}

impl Companions {
    /// Asks the companion Mac `peer` to search for `find.query` and each of
    /// `find.also`, answering their items in that order
    pub(super) async fn find_mac(
        &self,
        peer: &CompanionPeer,
        find: FindQuery,
    ) -> Result<Vec<Found>, CompanionFailure> {
        let asked = 1 + find.also.len();
        let request = serde_json::to_vec(&CompanionFindRequest { find }).map_err(|error| {
            CompanionFailure::Exchange {
                name: peer.name.clone(),
                detail: error.to_string(),
            }
        })?;
        let body = tokio::time::timeout(ASK_TIMEOUT, self.send(peer, &request))
            .await
            .unwrap_or_else(|_| {
                Err(CompanionFailure::TimedOut {
                    name: peer.name.clone(),
                    timeout: ASK_TIMEOUT,
                })
            })?;

        let exchange = |detail: &str| CompanionFailure::Exchange {
            name: peer.name.clone(),
            detail: detail.to_owned(),
        };
        match serde_json::from_slice(&body) {
            Ok(CompanionFindResponse::Found(found)) if asked == 1 => Ok(vec![found]),
            // a companion from before batched finds searched only the first
            // query, so its items cannot stand for the others
            Ok(CompanionFindResponse::Found(_)) => Err(exchange(
                "this companion predates several finds in one prompt; run `codemode-mcp update` \
                 on that Mac",
            )),
            Ok(CompanionFindResponse::FoundEach(found)) if found.len() == asked => Ok(found),
            Ok(CompanionFindResponse::FoundEach(found)) => Err(exchange(&format!(
                "malformed answer: {} searches answered for {asked} asked",
                found.len()
            ))),
            // a companion from before finds sees no reference in the request
            // and says so the way it says any unreadable request
            Ok(CompanionFindResponse::Error(fault))
                if fault.code == CompanionErrorCode::NotAllowed
                    && fault.message == MALFORMED_REQUEST =>
            {
                Err(exchange(
                    "this companion predates finding items; run `codemode-mcp update` on that Mac",
                ))
            }
            Ok(CompanionFindResponse::Error(fault)) => Err(CompanionFailure::Refused {
                code: fault.code,
                message: fault.message,
            }),
            Err(error) => Err(exchange(&format!("malformed answer: {error}"))),
        }
    }
}
