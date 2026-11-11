//! Handoffs waiting for the owner: an agent asked them to do a step in a
//! browser session on their phone

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use companion_wire::mobile::{HandoffAnswer, RequestId};
use tokio::sync::watch;

use super::page::SessionName;

/// One handoff
#[derive(Debug)]
pub struct Handoff {
    /// The id pushes, requests and takeovers name
    pub id: RequestId,
    /// The session to take over
    pub session: SessionName,
    /// The agent's reason, one line
    pub reason: Option<String>,
    answer: watch::Sender<Option<HandoffAnswer>>,
}

impl Handoff {
    /// Ends the handoff with `answer`, unless it already has one
    pub fn finish(&self, answer: HandoffAnswer) {
        self.answer.send_if_modified(|current| {
            let first = current.is_none();
            if first {
                *current = Some(answer);
            }

            first
        });
    }

    /// Waits for the owner's answer
    pub async fn answered(&self) -> HandoffAnswer {
        let mut answer = self.answer.subscribe();
        let answered = answer.wait_for(Option::is_some).await;

        // the sender lives as long as `self`
        answered
            .ok()
            .and_then(|answer| *answer)
            .unwrap_or(HandoffAnswer::Cancelled)
    }

    /// Becomes true once the handoff is answered or given up
    pub fn over(&self) -> watch::Receiver<bool> {
        let mut answer = self.answer.subscribe();
        let (over, receiver) = watch::channel(answer.borrow().is_some());
        tokio::spawn(async move {
            // also ends when the handoff is dropped
            let _ = answer.wait_for(Option::is_some).await;
            over.send_replace(true);
        });

        receiver
    }
}

/// The handoffs in progress, by id
#[derive(Debug, Default)]
pub struct Handoffs(Mutex<HashMap<RequestId, Arc<Handoff>>>);

impl Handoffs {
    /// Starts a handoff of `session`; it is forgotten once the returned
    /// guard drops
    pub fn open(self: &Arc<Self>, session: SessionName, reason: Option<String>) -> Open {
        let handoff = Arc::new(Handoff {
            id: RequestId::generate(),
            session,
            reason,
            answer: watch::channel(None).0,
        });
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handoff.id.clone(), Arc::clone(&handoff));

        Open {
            handoffs: Arc::clone(self),
            handoff,
        }
    }

    /// The handoff `id`, while it is in progress
    pub fn get(&self, id: &RequestId) -> Option<Arc<Handoff>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }
}

/// A handoff in progress; dropping it gives up on it
pub struct Open {
    handoffs: Arc<Handoffs>,
    /// The handoff
    pub handoff: Arc<Handoff>,
}

impl Drop for Open {
    fn drop(&mut self) {
        // a takeover still open on it ends as the handoff is over
        self.handoff.finish(HandoffAnswer::Cancelled);
        self.handoffs
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.handoff.id);
    }
}
