//! The connection actor: owns the phone's iroh endpoint, dials the gateway,
//! hands each read the gateway sends to the app actor, and dials again when
//! the link drops while the app is in the foreground
//!
//! Dials, accepts and stream answers run in spawned tasks that report back
//! as messages, so a handler never waits on the network

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use companion_wire::{
    MAX_BODY_BYTES, MOBILE_ALPN,
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

/// Numbers each stream the gateway opens, so a read offered again after a
/// reconnect is told apart from the stream it replaces
static STREAMS: AtomicU64 = AtomicU64::new(0);

/// What the connection actor is asked
pub enum ConnMsg {
    /// Keep a link to the gateway up
    Connect,
    /// Hang up and stay down, as the app goes to the background
    Disconnect,
    /// A dial finished
    Dialed(Result<Connection, String>),
    /// The link with this stable id dropped
    Lost(usize),
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
    dialing: bool,
    /// Whether the app wants a link, i.e. it is in the foreground
    wanted: bool,
    /// Dials that failed in a row, for the backoff
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
            ConnMsg::Disconnect => {
                state.wanted = false;
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
                state.failures = 0;
                state.connection = Some(connection.clone());
                let _ = state
                    .app
                    .cast(AppMsg::Connection(ConnectionState::Connected));

                tokio::spawn(accept_reads(connection.clone(), state.app.clone()));
                let myself = myself.clone();
                tokio::spawn(async move {
                    connection.closed().await;
                    let _ = myself.cast(ConnMsg::Lost(connection.stable_id()));
                });
            }
            ConnMsg::Dialed(Err(error)) => {
                state.dialing = false;
                if !state.wanted {
                    return Ok(());
                }
                state.failures = state.failures.saturating_add(1);
                let delay = backoff(state.failures);
                tracing::info!(%error, ?delay, "dial failed");
                let _ = state
                    .app
                    .cast(AppMsg::Connection(ConnectionState::Retrying {
                        in_secs: u32::try_from(delay.as_secs()).unwrap_or(u32::MAX),
                        error,
                    }));
                myself.send_after(delay, || ConnMsg::Connect);
            }
            ConnMsg::Lost(stable_id) => {
                let ours = state
                    .connection
                    .as_ref()
                    .is_some_and(|connection| connection.stable_id() == stable_id);
                if !ours {
                    return Ok(());
                }
                state.connection = None;
                if state.wanted {
                    Self::dial(&myself, state);
                } else {
                    let _ = state.app.cast(AppMsg::Connection(ConnectionState::Offline));
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
            let Ok(body) = receive.read_to_end(MAX_BODY_BYTES).await else {
                return;
            };
            let Ok(read) = serde_json::from_slice::<PhoneRead>(&body) else {
                tracing::warn!("the gateway sent a read this phone cannot parse");

                return;
            };
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
                let Ok(bytes) = serde_json::to_vec(&response) else {
                    return;
                };
                if send.write_all(&bytes).await.is_ok() {
                    let _ = send.finish();
                    // the value is gone from this task once the gateway has it
                    let _ = send.stopped().await;
                }
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
