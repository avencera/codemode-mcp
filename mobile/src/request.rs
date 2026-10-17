//! The request actor: one per read the gateway sends, from its arrival to
//! approve, deny, expire or withdraw
//!
//! The owner answers by opening the sealed copy with Face ID, or by entering
//! the value (pasted or filled in) when there is no copy or it is stale. The
//! prompt names the reference, and that one approval is all a read needs. A
//! program read carries several items: one Face ID opens every sealed one,
//! the owner enters the rest, and the values go together.
//! Face ID blocks until the owner answers, so it runs on a blocking thread
//! and its result comes back as a message; the actor stays free to take the
//! prompt down if the read expires or is withdrawn meanwhile

use std::{collections::HashMap, time::Duration};

use companion_wire::{
    MAX_BODY_BYTES,
    mobile::{PhoneProgramRead, PhoneRead, ProgramItem, RequestId, seal_info},
    wire::{CompanionErrorCode, CompanionFault, CompanionResponse, MAX_KEEP_SECS},
};
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use tokio::sync::oneshot;

use crate::{
    app::{AppMsg, StreamEnd},
    ffi::{OpenBatch, OpenError, OpenRequest, Platform, ReadStatus, SealedItem},
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

/// What the gateway asked: one value for its own config, or the values a
/// program on the gateway Mac wants
pub enum Asked {
    /// One read, answered with a value
    Read(PhoneRead),
    /// A program's batch, answered with a value per item
    Program(PhoneProgramRead),
}

impl Asked {
    /// The id the push named
    pub fn id(&self) -> &RequestId {
        match self {
            Self::Read(read) => &read.id,
            Self::Program(program) => &program.id,
        }
    }

    /// Milliseconds until the gateway gives up
    pub fn expires_in_ms(&self) -> u64 {
        match self {
            Self::Read(read) => read.expires_in_ms,
            Self::Program(program) => program.expires_in_ms,
        }
    }

    /// Waits no longer than `longest` milliseconds
    pub fn cap_expiry(&mut self, longest: u64) {
        let expires_in_ms = match self {
            Self::Read(read) => &mut read.expires_in_ms,
            Self::Program(program) => &mut program.expires_in_ms,
        };
        *expires_in_ms = (*expires_in_ms).min(longest);
    }
}

/// How long a program read lets the gateway hand its values out again,
/// clamped to the wire's limit; a zero keep is no keep
pub fn keep_secs(program: &PhoneProgramRead) -> Option<u64> {
    program
        .keep_secs
        .filter(|secs| *secs > 0)
        .map(|secs| secs.min(MAX_KEEP_SECS))
}

/// What a request actor is told
pub enum RequestMsg {
    /// The owner tapped Approve; replies whether Face ID was asked, so
    /// the app keeps to one prompt at a time
    Approve(RpcReplyPort<bool>),
    /// The owner entered the value
    Answer(Secret),
    /// The owner approved a program read with these entered values, keyed
    /// by item index; replies whether Face ID was asked
    AnswerProgram {
        /// The values entered
        entered: HashMap<u32, Secret>,
        /// Whether it was
        reply: RpcReplyPort<bool>,
    },
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
    /// Face ID finished opening a program read's sealed items
    OpenedBatch(Result<Vec<Secret>, OpenError>),
}

/// What a request actor starts with
pub struct RequestArgs {
    /// The read
    pub asked: Asked,
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
    asked: Asked,
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
    /// The values the owner entered for a program read, by item index, held
    /// while Face ID opens the rest
    entered: HashMap<usize, Secret>,
}

impl RequestState {
    fn id(&self) -> String {
        self.asked.id().to_string()
    }

    fn set(&mut self, status: ReadStatus) {
        self.status = status.clone();
        let _ = self.app.cast(AppMsg::ReadChanged {
            id: self.id(),
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

    /// Sends a value or values unless the answer is over the gateway's limit
    fn send(&mut self, response: CompanionResponse) {
        // the gateway reads at most MAX_BODY_BYTES
        let fits = serde_json::to_vec(&response).is_ok_and(|bytes| bytes.len() <= MAX_BODY_BYTES);
        let (response, status) = if fits {
            (response, ReadStatus::Approved)
        } else {
            let message = match response {
                CompanionResponse::Values(_) => "the values are too large to send together",
                _ => "the value is too large to send",
            };
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

    /// Answers why Face ID opened nothing
    fn refuse(&mut self, error: OpenError) {
        let (response, status) = match error {
            OpenError::Denied => (
                Self::fault(CompanionErrorCode::Denied, "not approved on this phone"),
                ReadStatus::Denied,
            ),
            OpenError::Failed { message } => (
                Self::fault(CompanionErrorCode::ReadFailed, &message),
                ReadStatus::Failed { message },
            ),
        };
        self.respond(response);
        self.set(status);
    }

    /// Sends a program read's values when the owner entered every one Face
    /// ID cannot open, asking Face ID once for the rest first; answers
    /// whether Face ID was asked
    fn answer_program(
        &mut self,
        myself: &ActorRef<RequestMsg>,
        entered: HashMap<u32, Secret>,
    ) -> bool {
        let Asked::Program(program) = &self.asked else {
            return false;
        };
        if self.status != ReadStatus::Waiting {
            return false;
        }

        let count = program.items.len();
        // an empty field or an index past the items enters nothing
        let mut entered: HashMap<usize, Secret> = entered
            .into_iter()
            .filter_map(|(index, value)| Some((usize::try_from(index).ok()?, value)))
            .filter(|(index, Secret(value))| *index < count && !value.is_empty())
            .collect();
        let mut sealed = Vec::new();
        for (index, item) in program.items.iter().enumerate() {
            if entered.contains_key(&index) {
                continue;
            }
            match item {
                ProgramItem::Reference {
                    reference,
                    sealed: Some(copy),
                } => sealed.push(SealedItem {
                    reference: reference.clone(),
                    info: seal_info(&self.record.id, reference),
                    enc: copy.enc.clone(),
                    ciphertext: copy.ciphertext.clone(),
                }),
                // nothing to open and nothing entered: the batch cannot go
                _ => return false,
            }
        }

        if sealed.is_empty() {
            let values = (0..count).filter_map(|index| entered.remove(&index));
            self.send(CompanionResponse::Values(
                values.map(|Secret(value)| value).collect(),
            ));

            return false;
        }

        let batch = OpenBatch {
            id: self.id(),
            gateway_name: self.record.name.clone(),
            total: u32::try_from(count).unwrap_or(u32::MAX),
            keep_secs: keep_secs(program),
            items: sealed,
        };
        self.entered = entered;
        self.set(ReadStatus::Approving);

        let platform = std::sync::Arc::clone(&self.platform);
        let myself = myself.clone();
        tokio::spawn(async move {
            let opened = tokio::task::spawn_blocking(move || platform.open_sealed_batch(batch))
                .await
                .unwrap_or_else(|error| {
                    Err(OpenError::Failed {
                        message: error.to_string(),
                    })
                })
                .map(|values| values.into_iter().map(Secret).collect());
            let _ = myself.cast(RequestMsg::OpenedBatch(opened));
        });

        true
    }

    /// Sends a program read's values, each item's entered one or else the
    /// next one Face ID opened
    fn send_program(&mut self, opened: Vec<Secret>) {
        let Asked::Program(program) = &self.asked else {
            return;
        };
        let mut entered = std::mem::take(&mut self.entered);
        let expected = program.items.len() - entered.len();
        if opened.len() != expected {
            let message = format!(
                "Face ID opened {} values where {expected} were sealed",
                opened.len()
            );
            self.refuse(OpenError::Failed { message });

            return;
        }

        let mut opened = opened.into_iter();
        let values = (0..program.items.len())
            .filter_map(|index| entered.remove(&index).or_else(|| opened.next()))
            .map(|Secret(value)| value)
            .collect();
        self.send(CompanionResponse::Values(values));
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
        myself.send_after(Duration::from_millis(args.asked.expires_in_ms()), || {
            RequestMsg::Expire
        });

        Ok(RequestState {
            asked: args.asked,
            seq: args.seq,
            responder: Some(args.responder),
            unsent: None,
            in_flight: None,
            record: args.record,
            platform: args.platform,
            app: args.app,
            status: ReadStatus::Waiting,
            entered: HashMap::new(),
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
            RequestMsg::Approve(reply) => {
                let read = match &state.asked {
                    Asked::Read(read) => read,
                    // approved with nothing entered: Face ID opens them all
                    Asked::Program(_) => {
                        let started = state.answer_program(&myself, HashMap::new());
                        let _ = reply.send(started);

                        return Ok(());
                    }
                };
                // without a sealed copy there is nothing for Face ID to open
                let Some(sealed) = &read.sealed else {
                    let _ = reply.send(false);

                    return Ok(());
                };
                if state.status != ReadStatus::Waiting {
                    let _ = reply.send(false);

                    return Ok(());
                }
                let request = OpenRequest {
                    id: read.id.to_string(),
                    reference: read.reference.clone(),
                    gateway_name: state.record.name.clone(),
                    info: seal_info(&state.record.id, &read.reference),
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
                match opened {
                    Ok(Secret(value)) => state.send(CompanionResponse::Value(value)),
                    Err(error) => state.refuse(error),
                }
            }
            RequestMsg::OpenedBatch(opened) => {
                if state.status != ReadStatus::Approving {
                    return Ok(());
                }
                match opened {
                    Ok(values) => state.send_program(values),
                    Err(error) => {
                        state.entered.clear();
                        state.refuse(error);
                    }
                }
            }
            RequestMsg::Answer(Secret(value)) => {
                let single = matches!(state.asked, Asked::Read(_));
                if !single || state.status.is_finished() {
                    return Ok(());
                }
                // the entered value wins over a Face ID prompt still up
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.id());
                }
                state.send(CompanionResponse::Value(value));
            }
            RequestMsg::AnswerProgram { entered, reply } => {
                let started = state.answer_program(&myself, entered);
                let _ = reply.send(started);
            }
            RequestMsg::Deny => {
                if state.status.is_finished() {
                    return Ok(());
                }
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.id());
                }
                state.entered.clear();
                state.respond(RequestState::fault(
                    CompanionErrorCode::Denied,
                    "not approved on this phone",
                ));
                state.set(ReadStatus::Denied);
            }
            RequestMsg::Expire => {
                if state.status == ReadStatus::Approving {
                    state.platform.cancel_open(state.id());
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
                            state.platform.cancel_open(state.id());
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
                // an answer the old stream never confirmed goes again: the
                // gateway offers a read anew only when it did not get one
                if let Some(response) = state.unsent.take().or_else(|| state.in_flight.take()) {
                    state.respond(response);
                }
            }
        }

        Ok(())
    }
}
