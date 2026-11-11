//! The handoffs the gateway asked this phone for, kept by the app actor
//!
//! A handoff needs no actor of its own: the owner answers it with one tap
//! (Cancel), or takes the browser over, which ends it on the takeover's own
//! connection. The table keeps each handoff's current stream, so one offered
//! again after a reconnect replaces it under the same id, and a Cancel made
//! while the link is down goes once the gateway offers the handoff again

use std::collections::HashMap;

use companion_wire::mobile::HandoffAnswer;
use tokio::sync::oneshot;

use crate::{app::StreamEnd, ffi::HandoffStatus};

/// One handoff still open on the gateway's side
struct Entry {
    /// Its current stream's number
    seq: u64,
    /// Where its answer goes; `None` while the link is down
    responder: Option<oneshot::Sender<HandoffAnswer>>,
    /// The owner's answer, kept until the stream reports it delivered, so a
    /// link that drops while it goes loses nothing
    answer: Option<HandoffAnswer>,
}

impl Entry {
    /// Hands the answer to the current stream; it stays kept for the next
    /// one until the stream says it arrived
    fn send(&mut self) {
        let Some(answer) = self.answer else {
            return;
        };
        let Some(responder) = self.responder.take() else {
            return;
        };
        // the stream's task is gone when the link dropped before its end
        // reached the app; the gateway offers the handoff again
        let _ = responder.send(answer);
    }
}

/// Whether an offered handoff is new to this phone
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// First offered: show it and start its deadline
    New,
    /// Offered again on a new link; it already shows
    Again,
}

/// The handoffs whose streams are still open, by id
#[derive(Default)]
pub struct Handoffs {
    open: HashMap<String, Entry>,
}

impl Handoffs {
    /// Takes the handoff `id` offered on stream `seq`, replacing the stream
    /// of one offered before; an answer the old stream never confirmed goes
    /// again
    pub fn offer(
        &mut self,
        id: &str,
        seq: u64,
        responder: oneshot::Sender<HandoffAnswer>,
    ) -> Offer {
        if let Some(entry) = self.open.get_mut(id) {
            entry.seq = seq;
            entry.responder = Some(responder);
            entry.send();

            return Offer::Again;
        }

        self.open.insert(
            id.to_owned(),
            Entry {
                seq,
                responder: Some(responder),
                answer: None,
            },
        );

        Offer::New
    }

    /// The owner tapped Cancel: answers [`HandoffAnswer::Cancelled`] now, or
    /// on the next offer while the link is down; the new status, if it
    /// changed
    pub fn cancel(&mut self, id: &str) -> Option<HandoffStatus> {
        let entry = self.open.get_mut(id)?;
        if entry.answer.is_some() {
            return None;
        }
        entry.answer = Some(HandoffAnswer::Cancelled);
        entry.send();

        Some(HandoffStatus::Cancelled)
    }

    /// Stream `seq` of handoff `id` ended; the new status, if it changed
    pub fn stream_ended(&mut self, id: &str, seq: u64, end: StreamEnd) -> Option<HandoffStatus> {
        let entry = self.open.get_mut(id)?;
        if entry.seq != seq {
            return None;
        }

        match end {
            StreamEnd::Delivered => {
                self.open.remove(id);

                None
            }
            // the gateway stopped it: a takeover ended it, another phone
            // answered, or the agent stopped waiting; a Cancel from here
            // keeps its own status
            StreamEnd::Withdrawn => {
                let answered = self
                    .open
                    .remove(id)
                    .is_some_and(|entry| entry.answer.is_some());

                (!answered).then_some(HandoffStatus::Over)
            }
            StreamEnd::Interrupted => {
                entry.responder = None;

                None
            }
        }
    }

    /// The gateway's deadline for `id` passed; whether it was still open
    pub fn expire(&mut self, id: &str) -> bool {
        self.open.remove(id).is_some()
    }

    /// A takeover ended `id` on its own connection; the gateway stops the
    /// stream next, which is nothing more to report
    pub fn finish(&mut self, id: &str) {
        self.open.remove(id);
    }

    /// Forgets every handoff, as unpairing does
    pub fn clear(&mut self) {
        self.open.clear();
    }
}
