//! The gateway's side of takeovers and handoffs: the link a phone dials to
//! drive a browser session, and the handoff requests offered to phones
//!
//! A takeover connection on [`companion_wire::takeover::TAKEOVER_ALPN`] is let in only from a listed,
//! trusted phone, like the phone's own connection. It carries one stream of
//! frames (see [`companion_wire::takeover`]); what the frames do to the
//! browser is up to the [`TakeoverHost`] the daemon registers

use std::{
    sync::{Arc, PoisonError, Weak},
    time::Duration,
};

use async_trait::async_trait;
use companion_wire::{
    mobile::{HandoffAnswer, PhoneHandoff, PhoneHandoffRequest, RequestId, Sealed},
    takeover::{
        GatewayFrame, HEADER_BYTES, PhoneMessage, Viewport, decode_phone, encode_message,
        encode_screen, read_header,
    },
};
use iroh::endpoint::{Connection, RecvStream};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};
use zeroize::Zeroizing;

use super::{CompanionFailure, Companions, apns::Subject};
use crate::config::PhonePeer;

/// How long a phone may take to open its stream and say what it takes over
const OPEN_WINDOW: Duration = Duration::from_secs(30);

/// Messages from the phone waiting for the browser
const INPUT_BACKLOG: usize = 64;

/// Frames waiting for the link to the phone; images are paced by the
/// phone's acknowledgements, so few wait
const OUTPUT_BACKLOG: usize = 16;

/// What a phone opened a takeover with
#[derive(Debug, Clone)]
pub struct TakeoverOpen {
    /// The browser session it asks for
    pub session: String,
    /// The handoff it answers
    pub handoff: Option<RequestId>,
    /// Its screen area for the page
    pub viewport: Viewport,
}

/// Runs the takeovers phones open
#[async_trait]
pub trait TakeoverHost: Send + Sync {
    /// Runs one takeover by `phone` until it ends; `input` closes when the
    /// phone's link drops, and closing `output` ends the link
    async fn takeover(
        &self,
        phone: PhonePeer,
        open: TakeoverOpen,
        input: mpsc::Receiver<PhoneMessage>,
        output: mpsc::Sender<GatewayFrame>,
    );
}

/// What a handoff offered to the phones shows
#[derive(Debug, Clone)]
pub struct HandoffOffer {
    /// The handoff's id
    pub id: RequestId,
    /// The session to take over
    pub session: String,
    /// The agent's reason, one line
    pub reason: Option<String>,
    /// The page the session shows
    pub url: Option<String>,
}

/// Reads one frame's kind and body, at most the protocol's limits
/// One frame's kind and body; the body is wiped when dropped, since a
/// phone's message may hold typed text or a login value
async fn read_frame(receive: &mut RecvStream) -> Result<(u8, Zeroizing<Vec<u8>>), String> {
    let mut header = [0_u8; HEADER_BYTES];
    receive
        .read_exact(&mut header)
        .await
        .map_err(|error| error.to_string())?;
    let (kind, length) = read_header(header).map_err(|error| error.to_string())?;
    let mut body = Zeroizing::new(vec![0_u8; length]);
    receive
        .read_exact(&mut body)
        .await
        .map_err(|error| error.to_string())?;

    Ok((kind, body))
}

impl Companions {
    /// Lets `host` run the takeovers phones open from now on
    pub fn host_takeovers(&self, host: Weak<dyn TakeoverHost>) {
        *self
            .takeovers
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(host);
    }

    fn takeover_host(&self) -> Option<Arc<dyn TakeoverHost>> {
        self.takeovers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade)
    }

    /// The copy of `reference` sealed to `phone`, when the gateway has one
    pub fn phone_seal(&self, phone: &PhonePeer, reference: &str) -> Option<Sealed> {
        self.store
            .as_ref()
            .and_then(|store| store.seal(&phone.id.to_string(), reference).ok().flatten())
    }

    /// Serves a takeover connection a phone dialed: refused unless the phone
    /// is listed, then one takeover until either side ends it
    pub(super) async fn takeover_connection(&self, connection: Connection) {
        let remote = connection.remote_id();
        let Some(phone) = self.phones().into_iter().find(|phone| phone.id == remote) else {
            tracing::warn!(%remote, "refused a takeover from a phone that is not paired");
            connection.close(1_u32.into(), b"not paired");

            return;
        };
        let Some(host) = self.takeover_host() else {
            connection.close(1_u32.into(), b"no browser");

            return;
        };
        let Ok(Ok((mut send, mut receive))) =
            tokio::time::timeout(OPEN_WINDOW, connection.accept_bi()).await
        else {
            return;
        };
        let opened = tokio::time::timeout(OPEN_WINDOW, read_frame(&mut receive)).await;
        let open = match opened {
            Ok(Ok((kind, body))) => match decode_phone(kind, &body) {
                Ok(PhoneMessage::Open {
                    session,
                    handoff,
                    viewport,
                }) => TakeoverOpen {
                    session,
                    handoff,
                    viewport,
                },
                _ => {
                    connection.close(1_u32.into(), b"expected open");

                    return;
                }
            },
            _ => {
                connection.close(1_u32.into(), b"expected open");

                return;
            }
        };
        tracing::info!(phone = %phone.name, session = %open.session, "takeover opened");

        let (input, input_receiver) = mpsc::channel(INPUT_BACKLOG);
        let (output, mut output_receiver) = mpsc::channel::<GatewayFrame>(OUTPUT_BACKLOG);
        let mut tasks = JoinSet::new();
        // the phone's messages, until it hangs up or sends something
        // unreadable; dropping `input` tells the host
        tasks.spawn(async move {
            loop {
                let message = match read_frame(&mut receive).await {
                    Ok((kind, body)) => decode_phone(kind, &body),
                    Err(_) => break,
                };
                let Ok(message) = message else {
                    break;
                };
                if input.send(message).await.is_err() {
                    break;
                }
            }
        });
        tasks.spawn(async move {
            while let Some(frame) = output_receiver.recv().await {
                let bytes = match &frame {
                    GatewayFrame::Message(message) => encode_message(message),
                    GatewayFrame::Screen(screen) => encode_screen(screen),
                };
                let Ok(bytes) = bytes else {
                    continue;
                };
                if send.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            let _ = send.finish();
            let _ = send.stopped().await;
        });

        let name = phone.name.clone();
        host.takeover(phone, open, input_receiver, output).await;
        // the writer sends what is left, then the link closes
        let _ = tokio::time::timeout(OPEN_WINDOW, async {
            while let Some(finished) = tasks.join_next().await {
                if finished.is_ok() {
                    tasks.abort_all();
                }
            }
        })
        .await;
        connection.close(0_u32.into(), b"ended");
        tracing::info!(phone = %name, "takeover ended");
    }

    /// Offers `handoff` to every phone, pushing to wake them, until one
    /// answers on its request or `deadline` passes; a phone that answers
    /// with a takeover instead is seen by the caller, which then drops this
    pub async fn offer_handoff(
        self: &Arc<Self>,
        handoff: &HandoffOffer,
        deadline: Instant,
    ) -> Result<HandoffAnswer, CompanionFailure> {
        let phones = self.phones();
        if phones.is_empty() {
            return Err(CompanionFailure::Handoff(
                "no phone is paired (`codemode-mcp companion invite`)".to_owned(),
            ));
        }

        let mut asks = JoinSet::new();
        for phone in phones {
            let companions = Arc::clone(self);
            let handoff = handoff.clone();
            asks.spawn(async move {
                let subject = Subject::Handoff {
                    session: handoff.session.clone(),
                    reason: handoff
                        .reason
                        .clone()
                        .unwrap_or_else(|| "An agent needs you".to_owned()),
                };
                let encode = |expires_in_ms| {
                    serde_json::to_vec(&PhoneHandoffRequest {
                        handoff: PhoneHandoff {
                            id: handoff.id.clone(),
                            session: handoff.session.clone(),
                            reason: handoff.reason.clone(),
                            url: handoff.url.clone(),
                            expires_in_ms,
                        },
                    })
                    .map_err(|error| error.to_string())
                };

                companions
                    .ask_until::<HandoffAnswer>(&phone, &handoff.id, subject, deadline, encode)
                    .await
            });
        }

        let mut failure = None;
        while let Some(asked) = asks.join_next().await {
            match asked {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(error)) => failure = Some(error),
                Err(error) => {
                    failure = Some(CompanionFailure::Handoff(format!(
                        "a phone's request stopped unexpectedly: {error}"
                    )));
                }
            }
        }

        Err(failure
            .unwrap_or_else(|| CompanionFailure::Handoff("no phone took the handoff".to_owned())))
    }
}
