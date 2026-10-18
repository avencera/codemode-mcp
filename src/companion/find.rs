//! Items a program on the gateway Mac looks for, through `codemode-mcp op
//! find` and the `secrets` builtin's `find_references`, approved on a Mac
//!
//! A find answers references, labels and types, never a value, so a
//! program that does not know an item can then read the one it wants with
//! its own approval. It is asked like a program read: this Mac first while
//! the owner is there, the companion Macs [`PHONE_GRACE`] later or at once,
//! and a Deny anywhere ends it. Phones are not asked, since the app cannot
//! search 1Password

use std::{sync::Arc, time::Duration};

use companion_wire::wire::{CompanionFindRequest, CompanionFindResponse, FindQuery, Found};
use tokio::{sync::watch, task::JoinSet};

use super::{
    ASK_TIMEOUT, CompanionErrorCode, CompanionFailure, Companions, MALFORMED_REQUEST,
    ProgramReadError,
    program::{Miss, checked_query, clean_reason},
};
use crate::{
    config::CompanionPeer,
    mac::TouchId,
    prompt,
    secrets::{OnePassword, PHONE_GRACE},
};

/// Cancel button of the gateway Mac's own prompt
const CANCEL_TITLE: &str = "Deny";

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

impl OnePassword {
    /// Searches 1Password for `ask.query` on behalf of a program, with its
    /// reason shown in every prompt; see the module docs for who is asked
    pub async fn find_for_program(&self, ask: &FindAsk) -> Result<ProgramFound, ProgramReadError> {
        let query = checked_query(&ask.query).map_err(ProgramReadError::Invalid)?;
        let reason = clean_reason(ask.reason.as_deref());
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

        let mut sources: JoinSet<(String, Result<Found, Miss>)> = JoinSet::new();
        // set once this Mac has failed, so the companions need not sit out
        // the rest of the grace
        let (local_failed, grace_over) = watch::channel(!local);
        let local_failed = Arc::new(local_failed);
        if local {
            let local_failed = Arc::clone(&local_failed);
            let onepassword = self.clone();
            let query = query.clone();
            let reason = reason.clone();
            sources.spawn(async move {
                let found = onepassword.find_here(&query, reason.as_deref()).await;
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
                    query: query.clone(),
                    reason: reason.clone(),
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
        let first = async {
            let mut failures = Vec::new();
            while let Some(finished) = sources.join_next().await {
                match finished {
                    Ok((source, Ok(found))) => return Ok(ProgramFound { source, found }),
                    Ok((_, Err(Miss::Denied(message)))) => {
                        return Err(ProgramReadError::Denied(message));
                    }
                    Ok((_, Err(Miss::Failed(message)))) => failures.push(message),
                    Err(error) => failures.push(format!("a find stopped unexpectedly: {error}")),
                }
            }

            Err(ProgramReadError::Failed(failures.join("; ")))
        };

        tokio::time::timeout(ASK_TIMEOUT + grace, first)
            .await
            .unwrap_or_else(|_| {
                Err(ProgramReadError::Failed(format!(
                    "nobody approved within {:?}",
                    ASK_TIMEOUT + grace
                )))
            })
    }

    /// Asks on this Mac: its own Touch ID prompt naming the query, then the
    /// local `op`
    async fn find_here(&self, query: &str, reason: Option<&str>) -> Result<Found, Miss> {
        let Some(on_mac) = self.on_mac() else {
            return Err(Miss::Failed("this Mac: no Touch ID".to_owned()));
        };
        let text = prompt::find_prompt_text(query, "this Mac", reason);
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

        self.find_local(query)
            .await
            .map_err(|error| Miss::Failed(format!("this Mac: {error}")))
    }
}

impl Companions {
    /// Asks the companion Mac `peer` to search
    async fn find_mac(
        &self,
        peer: &CompanionPeer,
        find: FindQuery,
    ) -> Result<Found, CompanionFailure> {
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

        match serde_json::from_slice(&body) {
            Ok(CompanionFindResponse::Found(found)) => Ok(found),
            // a companion from before finds sees no reference in the request
            // and says so the way it says any unreadable request
            Ok(CompanionFindResponse::Error(fault))
                if fault.code == CompanionErrorCode::NotAllowed
                    && fault.message == MALFORMED_REQUEST =>
            {
                Err(CompanionFailure::Exchange {
                    name: peer.name.clone(),
                    detail: "this companion predates finding items; run `codemode-mcp update` \
                             on that Mac"
                        .to_owned(),
                })
            }
            Ok(CompanionFindResponse::Error(fault)) => Err(CompanionFailure::Refused {
                code: fault.code,
                message: fault.message,
            }),
            Err(error) => Err(CompanionFailure::Exchange {
                name: peer.name.clone(),
                detail: format!("malformed answer: {error}"),
            }),
        }
    }
}
