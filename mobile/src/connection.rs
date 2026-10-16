//! The connection actor: owns the phone's iroh endpoint, dials the gateway,
//! hands each read the gateway sends to the app actor, and dials again when
//! the link drops while the app is in the foreground
//!
//! Dials, accepts and stream answers run in spawned tasks that report back
//! as messages, so a handler never waits on the network

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use companion_wire::{
    ASK_TIMEOUT, MAX_PHONE_READ_BYTES, MOBILE_ALPN,
    mobile::{PhoneRead, PhoneRequest, PhoneResponse, RequestId},
    wire::CompanionResponse,
};
use iroh::{
    Endpoint, SecretKey,
    endpoint::{Connection, SendStream},
};
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use tokio::sync::oneshot;

use crate::{
    app::{AppMsg, Incoming, StreamEnd},
    ffi::ConnectionState,
    net,
    record::GatewayRecord,
};

/// Longest wait between dials while the gateway cannot be reached
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// A link that drops sooner than this counts as a failed dial, so the next
/// dial backs off
const STABLE_LINK: Duration = Duration::from_secs(10);

/// How long the gateway may take to send a read once it opened its stream
const READ_WINDOW: Duration = Duration::from_secs(10);

/// Numbers each stream the gateway opens, so a read offered again after a
/// reconnect is told apart from the stream it replaces
static STREAMS: AtomicU64 = AtomicU64::new(0);

/// What the connection actor is asked
pub enum ConnMsg {
    /// Keep a link to the gateway up
    Connect,
    /// Dial again after a failed dial, unless the link is no longer wanted
    Retry,
    /// Hang up and stay down, as the app goes to the background
    Disconnect,
    /// A dial finished
    Dialed(Result<Connection, String>),
    /// The link with this stable id dropped, and why
    Lost(usize, String),
    /// Sends one request of the phone's own on the current link
    Request(PhoneRequest, RpcReplyPort<Result<PhoneResponse, String>>),
}

/// What the connection actor starts with
pub struct ConnArgs {
    /// The phone's iroh key
    pub key: SecretKey,
    /// The gateway to dial
    pub record: GatewayRecord,
    /// Where reads and link changes go
    pub app: ActorRef<AppMsg>,
}

pub struct ConnState {
    endpoint: Endpoint,
    record: GatewayRecord,
    app: ActorRef<AppMsg>,
    connection: Option<Connection>,
    /// When the current link came up
    linked_at: Instant,
    dialing: bool,
    /// Whether the app wants a link, i.e. it is in the foreground
    wanted: bool,
    /// Dials that failed or links that dropped at once, in a row, for the
    /// backoff
    failures: u32,
}

pub struct ConnectionActor;

impl ConnectionActor {
    fn dial(myself: &ActorRef<ConnMsg>, state: &mut ConnState) {
        if state.dialing || state.connection.is_some() {
            return;
        }
        state.dialing = true;
        let _ = state
            .app
            .cast(AppMsg::Connection(ConnectionState::Connecting));

        let endpoint = state.endpoint.clone();
        let address = state.record.endpoint_addr();
        let myself = myself.clone();
        tokio::spawn(async move {
            let dialed =
                tokio::time::timeout(net::DIAL_TIMEOUT, endpoint.connect(address, MOBILE_ALPN))
                    .await
                    .map_err(|_| "the gateway did not answer in time".to_owned())
                    .and_then(|connected| connected.map_err(|error| error.to_string()));
            let _ = myself.cast(ConnMsg::Dialed(dialed));
        });
    }

    /// Counts a failure and dials again after the backoff
    fn retry_later(myself: &ActorRef<ConnMsg>, state: &mut ConnState, error: String) {
        state.failures = state.failures.saturating_add(1);
        let delay = backoff(state.failures);
        tracing::info!(%error, ?delay, "no link to the gateway");
        let _ = state
            .app
            .cast(AppMsg::Connection(ConnectionState::Retrying {
                in_secs: u32::try_from(delay.as_secs()).unwrap_or(u32::MAX),
                error,
            }));
        myself.send_after(delay, || ConnMsg::Retry);
    }
}

impl Actor for ConnectionActor {
    type Msg = ConnMsg;
    type State = ConnState;
    type Arguments = ConnArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let endpoint = net::bind(args.key, args.record.discovery()).await?;

        Ok(ConnState {
            endpoint,
            record: args.record,
            app: args.app,
            connection: None,
            linked_at: Instant::now(),
            dialing: false,
            wanted: false,
            failures: 0,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ConnMsg::Connect => {
                state.wanted = true;
                Self::dial(&myself, state);
            }
            // a retry queued before the app went to the background must not
            // bring the link back
            ConnMsg::Retry if state.wanted => Self::dial(&myself, state),
            ConnMsg::Retry => {}
            ConnMsg::Disconnect => {
                state.wanted = false;
                // the next foreground starts with a quick dial
                state.failures = 0;
                if let Some(connection) = state.connection.take() {
                    connection.close(0_u32.into(), b"background");
                }
                let _ = state.app.cast(AppMsg::Connection(ConnectionState::Offline));
            }
            ConnMsg::Dialed(Ok(connection)) => {
                state.dialing = false;
                if !state.wanted {
                    connection.close(0_u32.into(), b"background");

                    return Ok(());
                }
                state.connection = Some(connection.clone());
                state.linked_at = Instant::now();
                let _ = state
                    .app
                    .cast(AppMsg::Connection(ConnectionState::Connected));

                tokio::spawn(accept_reads(connection.clone(), state.app.clone()));
                let myself = myself.clone();
                tokio::spawn(async move {
                    let reason = connection.closed().await;
                    let _ = myself.cast(ConnMsg::Lost(connection.stable_id(), reason.to_string()));
                });
            }
            ConnMsg::Dialed(Err(error)) => {
                state.dialing = false;
                if !state.wanted {
                    return Ok(());
                }
                Self::retry_later(&myself, state, error);
            }
            ConnMsg::Lost(stable_id, reason) => {
                let ours = state
                    .connection
                    .as_ref()
                    .is_some_and(|connection| connection.stable_id() == stable_id);
                if !ours {
                    return Ok(());
                }
                state.connection = None;
                if !state.wanted {
                    let _ = state.app.cast(AppMsg::Connection(ConnectionState::Offline));
                } else if state.linked_at.elapsed() >= STABLE_LINK {
                    state.failures = 0;
                    Self::dial(&myself, state);
                } else {
                    // a gateway that no longer lists this phone, while it
                    // still lists another, accepts the dial and then closes
                    // the link; dialing again at once would spin
                    Self::retry_later(&myself, state, reason);
                }
            }
            ConnMsg::Request(request, reply) => match state.connection.clone() {
                Some(connection) => {
                    tokio::spawn(async move {
                        let _ = reply.send(net::ask(&connection, &request).await);
                    });
                }
                None => {
                    let _ = reply.send(Err("not connected to the gateway".to_owned()));
                }
            },
        }

        Ok(())
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        // closing waits for the gateway to hear it, bounded so a dead link
        // cannot hold the actor
        let _ = tokio::time::timeout(Duration::from_secs(2), state.endpoint.close()).await;

        Ok(())
    }
}

/// 1, 2, 4… seconds, up to [`MAX_BACKOFF`]
fn backoff(failures: u32) -> Duration {
    Duration::from_secs(1_u64 << failures.saturating_sub(1).min(5)).min(MAX_BACKOFF)
}

/// Hands each read the gateway opens a stream for to the app actor
async fn accept_reads(connection: Connection, app: ActorRef<AppMsg>) {
    while let Ok((send, mut receive)) = connection.accept_bi().await {
        let app = app.clone();
        tokio::spawn(async move {
            let body =
                tokio::time::timeout(READ_WINDOW, receive.read_to_end(MAX_PHONE_READ_BYTES)).await;
            let Ok(Ok(body)) = body else {
                return;
            };
            let Ok(mut read) = serde_json::from_slice::<PhoneRead>(&body) else {
                tracing::warn!("the gateway sent a read this phone cannot parse");

                return;
            };
            // the gateway never waits longer than this, so neither does the
            // phone's prompt
            read.expires_in_ms = read
                .expires_in_ms
                .min(u64::try_from(ASK_TIMEOUT.as_millis()).unwrap_or(u64::MAX));
            let id = read.id.clone();
            let seq = STREAMS.fetch_add(1, Ordering::Relaxed);
            let (responder, answered) = oneshot::channel();
            let incoming = Incoming {
                read,
                seq,
                responder,
            };
            if app.cast(AppMsg::Incoming(Box::new(incoming))).is_err() {
                return;
            }

            answer(send, answered, id, seq, app).await;
        });
    }
}

/// Writes the read's answer, or tells the app the gateway stopped wanting
/// it; a read the phone gives up on (it expired) is reset
async fn answer(
    mut send: SendStream,
    answered: oneshot::Receiver<CompanionResponse>,
    id: RequestId,
    seq: u64,
    app: ActorRef<AppMsg>,
) {
    tokio::select! {
        stopped = send.stopped() => {
            // STOP_SENDING means the gateway gave the read up; an error means
            // the link dropped, and the gateway offers the read again on the
            // next one
            let end = if stopped.is_ok() {
                StreamEnd::Withdrawn
            } else {
                StreamEnd::Interrupted
            };
            let _ = app.cast(AppMsg::StreamEnded { id, seq, end });
        }
        answer = answered => match answer {
            Ok(response) => {
                // the request keeps its answer until this says it arrived,
                // so a link that drops mid-write loses nothing
                let delivered = match serde_json::to_vec(&response) {
                    Ok(bytes) => {
                        send.write_all(&bytes).await.is_ok()
                            && send.finish().is_ok()
                            && send.stopped().await.is_ok()
                    }
                    Err(_) => false,
                };
                let end = if delivered {
                    StreamEnd::Delivered
                } else {
                    StreamEnd::Interrupted
                };
                let _ = app.cast(AppMsg::StreamEnded { id, seq, end });
            }
            Err(_) => {
                let _ = send.reset(0_u32.into());
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::backoff;

    #[test]
    fn dials_back_off_to_half_a_minute() {
        let delays: Vec<Duration> = (1..=8).map(backoff).collect();
        assert_eq!(delays[0], Duration::from_secs(1));
        assert_eq!(delays[3], Duration::from_secs(8));
        assert_eq!(delays[7], Duration::from_secs(30));
    }
}
