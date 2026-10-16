//! The request actor: one per read the gateway sends, from its arrival to
//! approve, deny, expire or withdraw
//!
//! The owner answers by opening the sealed copy with Face ID, or by entering
//! the value (pasted or filled in) when there is no copy or it is stale. A
//! reference off the allow list waits until the owner allows it.
//! Face ID blocks until the owner answers, so it runs on a blocking thread
//! and its result comes back as a message; the actor stays free to take the
//! prompt down if the read expires or is withdrawn meanwhile

use std::time::Duration;

use companion_wire::{
    MAX_BODY_BYTES,
    mobile::{PhoneRead, seal_info},
    wire::{CompanionErrorCode, CompanionFault, CompanionResponse},
};
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
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
    /// The owner tapped Approve; replies whether Face ID was asked, so
    /// the app keeps to one prompt at a time
    Approve(RpcReplyPort<bool>),
    /// The owner put the reference on the allow list, or took it off
    Listed(bool),
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
    /// The answer handed to the current stream, kept until it is delivered
    /// in case the link drops while it goes
    in_flight: Option<CompanionResponse>,
    record: GatewayRecord,
    platform: std::sync::Arc<dyn Platform>,
    app: ActorRef<AppMsg>,
    status: ReadStatus,
    /// The reference is on the allow list, or the owner allowed it; until
    /// then the read cannot be answered
    listed: bool,
}

impl RequestState {
    fn set(&mut self, status: ReadStatus) {
        self.status = status.clone();
        let _ = self.app.cast(AppMsg::ReadChanged {
            id: self.read.id.to_string(),
            status,
        });
    }

    /// Hands `response` to the current stream, or keeps it for the next
    /// one; the actor stops once the stream reports it delivered
    fn respond(&mut self, response: CompanionResponse) {
        let unsent = match self.responder.take() {
            // the stream's task is gone when the link dropped before its end
            // reached this actor; the gateway offers the read again
            Some(responder) => match responder.send(response.clone()) {
                Ok(()) => {
                    self.in_flight = Some(response);

                    return;
                }
                Err(response) => response,
            },
            None => response,
        };
        self.unsent = Some(unsent);
    }

    /// Sends `value` unless it is over the gateway's limit
    fn send_value(&mut self, value: String) {
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
        self.respond(response);
        self.set(status);
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

        let listed = args.record.allows(&args.read.reference);

        Ok(RequestState {
            listed,
            read: args.read,
            seq: args.seq,
            responder: Some(args.responder),
            unsent: None,
            in_flight: None,
            record: args.record,
            platform: args.platform,
            app: args.app,
            status: ReadStatus::Waiting,
        })
    }

    async fn post_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
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
            RequestMsg::Listed(listed) => {
                state.listed = listed;
                // taken off the list mid-prompt: the prompt goes, and what it
                // opens is not sent
                if !listed && state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.read.id.to_string());
                }
            }
            RequestMsg::Approve(reply) => {
                // without a sealed copy there is nothing for Face ID to open
                let Some(sealed) = &state.read.sealed else {
                    let _ = reply.send(false);

                    return Ok(());
                };
                if !state.listed || state.status != ReadStatus::Waiting {
                    let _ = reply.send(false);

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
                let _ = reply.send(true);

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
                    Ok(Secret(value)) if state.listed => {
                        state.send_value(value);

                        return Ok(());
                    }
                    // opened after the reference left the allow list: dropped
                    Ok(_) | Err(OpenError::Denied) => (
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
                state.respond(response);
                state.set(status);
            }
            RequestMsg::Answer(Secret(value)) => {
                if state.status.is_finished() || !state.listed {
                    return Ok(());
                }
                // the entered value wins over a Face ID prompt still up
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.read.id.to_string());
                }
                state.send_value(value);
            }
            RequestMsg::Deny => {
                if state.status.is_finished() {
                    return Ok(());
                }
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.read.id.to_string());
                }
                state.respond(RequestState::fault(
                    CompanionErrorCode::Denied,
                    "not approved on this phone",
                ));
                state.set(ReadStatus::Denied);
            }
            RequestMsg::Expire => {
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.read.id.to_string());
                }
                // the gateway has given up, so the value is not sent late; an
                // answer still waiting for the link never went, whatever the
                // screen said
                state.responder = None;
                state.in_flight = None;
                if state.unsent.take().is_some() || !state.status.is_finished() {
                    state.set(ReadStatus::Expired);
                }
                myself.stop(None);
            }
            RequestMsg::StreamEnded { seq, end } => {
                if seq != state.seq {
                    return Ok(());
                }
                match end {
                    StreamEnd::Delivered => myself.stop(None),
                    StreamEnd::Withdrawn => {
                        if state.status == ReadStatus::Approving {
                            state.platform.cancel_open(state.read.id.to_string());
                        }
                        if state.unsent.take().is_some() || !state.status.is_finished() {
                            state.set(ReadStatus::Withdrawn);
                        }
                        myself.stop(None);
                    }
                    StreamEnd::Interrupted => {
                        state.responder = None;
                        if let Some(response) = state.in_flight.take() {
                            state.unsent = Some(response);
                        }
                    }
                }
            }
            RequestMsg::Replace { seq, responder } => {
                state.seq = seq;
                state.responder = Some(responder);
                if let Some(response) = state.unsent.take() {
                    state.respond(response);
                }
            }
        }

        Ok(())
    }
}
