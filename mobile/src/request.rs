//! The request actor: one per read the gateway sends, from its arrival to
//! approve, deny, expire or withdraw
//!
//! The owner answers by opening the sealed copy with Face ID, or by entering
//! the value (pasted or filled in) when there is no copy or it is stale.
//! Face ID blocks until the owner answers, so it runs on a blocking thread
//! and its result comes back as a message; the actor stays free to take the
//! prompt down if the read expires or is withdrawn meanwhile

use std::time::Duration;

use companion_wire::{
    MAX_BODY_BYTES,
    mobile::{PhoneRead, seal_info},
    wire::{CompanionErrorCode, CompanionFault, CompanionResponse},
};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use tokio::sync::oneshot;

use crate::{
    app::{AppMsg, StreamEnd},
    ffi::{OpenError, OpenRequest, Platform, ReadStatus},
    record::GatewayRecord,
};

/// A value Face ID opened or the owner entered; kept out of `Debug`, logs
/// and crash reports
pub struct Secret(pub(crate) String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret(..)")
    }
}

/// What a request actor is told
pub enum RequestMsg {
    /// The owner tapped Approve
    Approve,
    /// The owner entered the value
    Answer(Secret),
    /// The owner tapped Deny
    Deny,
    /// The gateway's deadline passed
    Expire,
    /// The stream with this number ended without an answer
    StreamEnded {
        /// Which stream
        seq: u64,
        /// How
        end: StreamEnd,
    },
    /// The gateway offered the read again on a new link
    Replace {
        /// The new stream's number
        seq: u64,
        /// Where its answer goes
        responder: oneshot::Sender<CompanionResponse>,
    },
    /// Face ID finished
    Opened(Result<Secret, OpenError>),
}

/// What a request actor starts with
pub struct RequestArgs {
    /// The read
    pub read: PhoneRead,
    /// Its stream's number
    pub seq: u64,
    /// Where its answer goes
    pub responder: oneshot::Sender<CompanionResponse>,
    /// The gateway it came from
    pub record: GatewayRecord,
    /// For Face ID
    pub platform: std::sync::Arc<dyn Platform>,
    /// Where status changes go
    pub app: ActorRef<AppMsg>,
}

pub struct RequestState {
    read: PhoneRead,
    seq: u64,
    /// `None` while the link is down; the gateway offers the read again
    responder: Option<oneshot::Sender<CompanionResponse>>,
    /// An answer made while the link was down, sent once it is back
    unsent: Option<CompanionResponse>,
    record: GatewayRecord,
    platform: std::sync::Arc<dyn Platform>,
    app: ActorRef<AppMsg>,
    status: ReadStatus,
}

impl RequestState {
    fn set(&mut self, status: ReadStatus) {
        self.status = status.clone();
        let _ = self.app.cast(AppMsg::ReadChanged {
            id: self.read.id.to_string(),
            status,
        });
    }

    /// Sends `response` now, or once the link is back; true when it went
    fn respond(&mut self, response: CompanionResponse) -> bool {
        match self.responder.take() {
            Some(responder) => {
                let _ = responder.send(response);

                true
            }
            None => {
                self.unsent = Some(response);

                false
            }
        }
    }

    /// Sends `value` unless it is over the gateway's limit, and stops once
    /// it went
    fn send_value(&mut self, myself: &ActorRef<RequestMsg>, value: String) {
        let response = CompanionResponse::Value(value);
        // the gateway reads at most MAX_BODY_BYTES
        let fits = serde_json::to_vec(&response).is_ok_and(|bytes| bytes.len() <= MAX_BODY_BYTES);
        let (response, status) = if fits {
            (response, ReadStatus::Approved)
        } else {
            let message = "the value is too large to send";
            (
                Self::fault(CompanionErrorCode::ReadFailed, message),
                ReadStatus::Failed {
                    message: message.to_owned(),
                },
            )
        };
        let sent = self.respond(response);
        self.set(status);
        if sent {
            myself.stop(None);
        }
    }

    fn fault(code: CompanionErrorCode, message: &str) -> CompanionResponse {
        CompanionResponse::Error(CompanionFault {
            code,
            message: message.to_owned(),
        })
    }
}

pub struct RequestActor;

impl Actor for RequestActor {
    type Msg = RequestMsg;
    type State = RequestState;
    type Arguments = RequestArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        myself.send_after(Duration::from_millis(args.read.expires_in_ms), || {
            RequestMsg::Expire
        });

        Ok(RequestState {
            read: args.read,
            seq: args.seq,
            responder: Some(args.responder),
            unsent: None,
            record: args.record,
            platform: args.platform,
            app: args.app,
            status: ReadStatus::Waiting,
        })
    }

    async fn post_start(
        &self,
        myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        // refused before the owner sees it: only exact allow list matches
        // are ever shown
        if !state.record.allows(&state.read.reference) {
            tracing::warn!(reference = %state.read.reference, "refused a reference off the allow list");
            state.respond(RequestState::fault(
                CompanionErrorCode::NotAllowed,
                "the reference is not on this phone's allow list",
            ));
            state.set(ReadStatus::NotAllowed);
            myself.stop(None);

            return Ok(());
        }
        state.set(ReadStatus::Waiting);

        Ok(())
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            RequestMsg::Approve => {
                // without a sealed copy there is nothing for Face ID to open
                let Some(sealed) = &state.read.sealed else {
                    return Ok(());
                };
                if state.status != ReadStatus::Waiting {
                    return Ok(());
                }
                let request = OpenRequest {
                    id: state.read.id.to_string(),
                    reference: state.read.reference.clone(),
                    gateway_name: state.record.name.clone(),
                    info: seal_info(&state.record.id, &state.read.reference),
                    enc: sealed.enc.clone(),
                    ciphertext: sealed.ciphertext.clone(),
                };
                state.set(ReadStatus::Approving);

                let platform = std::sync::Arc::clone(&state.platform);
                let myself = myself.clone();
                tokio::spawn(async move {
                    let opened = tokio::task::spawn_blocking(move || platform.open_sealed(request))
                        .await
                        .unwrap_or_else(|error| {
                            Err(OpenError::Failed {
                                message: error.to_string(),
                            })
                        })
                        .map(Secret);
                    let _ = myself.cast(RequestMsg::Opened(opened));
                });
            }
            RequestMsg::Opened(opened) => {
                if state.status != ReadStatus::Approving {
                    return Ok(());
                }
                let (response, status) = match opened {
                    Ok(Secret(value)) => {
                        state.send_value(&myself, value);

                        return Ok(());
                    }
                    Err(OpenError::Denied) => (
                        RequestState::fault(
                            CompanionErrorCode::Denied,
                            "not approved on this phone",
                        ),
                        ReadStatus::Denied,
                    ),
                    Err(OpenError::Failed { message }) => (
                        RequestState::fault(CompanionErrorCode::ReadFailed, &message),
                        ReadStatus::Failed { message },
                    ),
                };
                let sent = state.respond(response);
                state.set(status);
                if sent {
                    myself.stop(None);
                }
            }
            RequestMsg::Answer(Secret(value)) => {
                if state.status.is_finished() {
                    return Ok(());
                }
                // the entered value wins over a Face ID prompt still up
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.read.id.to_string());
                }
                state.send_value(&myself, value);
            }
            RequestMsg::Deny => {
                if state.status.is_finished() {
                    return Ok(());
                }
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.read.id.to_string());
                }
                let sent = state.respond(RequestState::fault(
                    CompanionErrorCode::Denied,
                    "not approved on this phone",
                ));
                state.set(ReadStatus::Denied);
                if sent {
                    myself.stop(None);
                }
            }
            RequestMsg::Expire => {
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.read.id.to_string());
                }
                // the gateway has given up, so the value is not sent late
                state.responder = None;
                state.unsent = None;
                if !state.status.is_finished() {
                    state.set(ReadStatus::Expired);
                }
                myself.stop(None);
            }
            RequestMsg::StreamEnded { seq, end } => {
                if seq != state.seq {
                    return Ok(());
                }
                match end {
                    StreamEnd::Withdrawn => {
                        if state.status == ReadStatus::Approving {
                            state.platform.cancel_open(state.read.id.to_string());
                        }
                        state.unsent = None;
                        if !state.status.is_finished() {
                            state.set(ReadStatus::Withdrawn);
                        }
                        myself.stop(None);
                    }
                    StreamEnd::Interrupted => state.responder = None,
                }
            }
            RequestMsg::Replace { seq, responder } => {
                state.seq = seq;
                state.responder = Some(responder);
                if let Some(response) = state.unsent.take() {
                    state.respond(response);
                    myself.stop(None);
                }
            }
        }

        Ok(())
    }
}
